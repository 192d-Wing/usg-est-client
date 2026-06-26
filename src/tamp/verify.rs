// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! TAMP message signature verification and anti-replay (RFC 5934 §5).
//!
//! A received TAMP management message is honored only if its CMS `SignedData`
//! signature verifies against a trust anchor that the client already holds in
//! its [`TrustAnchorStore`], and its sequence number is fresh. This module
//! performs the cryptographic half:
//!
//! 1. resolve the `SignerInfo` to a trust anchor in the store (by Subject Key
//!    Identifier, or by issuer/serial for certificate trust anchors);
//! 2. if signed attributes are present, enforce that the `content-type`
//!    attribute equals the `eContentType` and the `message-digest` attribute
//!    equals the digest of the `eContent` (RFC 5652 §5.4);
//! 3. verify the signature with the trust anchor's public key, using the
//!    FIPS-validated provider under the `fips` feature (mirroring
//!    [`crate::validation`]).
//!
//! The returned [`VerifiedMessage`] names the signing trust anchor's key id so
//! the caller can enforce sequence-number replay protection via
//! [`TrustAnchorStore::accept_seq_num`].
//!
//! # Security
//!
//! NIST SP 800-53: SI-7 (integrity of signed updates), SC-13 (cryptographic
//! protection), SC-12 (key establishment). A failure here MUST be treated as an
//! attempt to tamper with the device's roots of trust and audited accordingly.

use cms::signed_data::{SignerIdentifier, SignerInfo};
use const_oid::ObjectIdentifier;
use der::Encode;
use der::asn1::{OctetString, SetOfVec};
use spki::SubjectPublicKeyInfoOwned;
use x509_cert::attr::Attribute;

use crate::error::{EstError, Result};

use super::oid::TampContentType;
use super::store::TrustAnchorStore;
use super::wrapper::TampMessage;

// Digest algorithm OIDs (NIST hash arc 2.16.840.1.101.3.4.2).
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const OID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

// CMS signed attribute OIDs (RFC 5652 §11).
const OID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const OID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");

// Signature algorithm OIDs.
const RSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const RSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const RSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");

/// Maximum number of `SignerInfo`s to verify in one inbound message.
///
/// A legitimate TAMP message carries one (occasionally a few) signers. Capping
/// the count bounds the work an attacker-supplied `SignedData` can force: without
/// it, a message with thousands of signers — each driving a digest over a large
/// `eContent` — is a CPU-amplification vector (the digest is also cached per
/// algorithm; see [`cached_digest`]).
const MAX_SIGNERS: usize = 16;

/// A TAMP message whose signature has been verified against the trust anchor
/// store.
#[derive(Clone, Debug)]
pub struct VerifiedMessage {
    /// The (recognized) TAMP message kind.
    pub content_type: TampContentType,
    /// The DER of the inner TAMP message (`eContent`), ready to decode.
    pub econtent: Vec<u8>,
    /// Key id of the trust anchor whose key verified the signature. Use this to
    /// key sequence-number replay checks.
    pub signer_key_id: Vec<u8>,
}

/// Verify a parsed TAMP message against the trust anchor store.
///
/// Tries each `SignerInfo` until one verifies against a trust anchor. Returns an
/// error if the message has no signer, no signer resolves to a known trust
/// anchor, or every signature fails. This does **not** perform the
/// sequence-number replay check — the caller does that with the returned
/// `signer_key_id` once it has decoded the message's sequence number.
pub fn verify_message(msg: &TampMessage, store: &TrustAnchorStore) -> Result<VerifiedMessage> {
    let content_type = msg.require_known_type()?;

    let signers = &msg.signed_data.signer_infos.0;
    if signers.as_slice().is_empty() {
        return Err(EstError::tamp(
            "TAMP message has no SignerInfo; unsigned management messages are rejected",
        ));
    }
    if signers.as_slice().len() > MAX_SIGNERS {
        return Err(EstError::tamp(format!(
            "TAMP message carries {} SignerInfos, exceeding the limit of {MAX_SIGNERS}",
            signers.as_slice().len()
        )));
    }

    // Cache eContent digests per algorithm OID so a multi-signer message hashes
    // the (possibly large) eContent at most once per distinct algorithm.
    let mut digest_cache: Vec<(ObjectIdentifier, Vec<u8>)> = Vec::new();

    let mut last_err: Option<EstError> = None;
    for signer in signers.iter() {
        match verify_one(
            signer,
            &msg.econtent_type,
            &msg.econtent,
            store,
            &mut digest_cache,
        ) {
            Ok(signer_key_id) => {
                return Ok(VerifiedMessage {
                    content_type,
                    econtent: msg.econtent.clone(),
                    signer_key_id,
                });
            }
            Err(e) => {
                tracing::debug!("TAMP signer verification failed: {e}");
                last_err = Some(e);
            }
        }
    }

    Err(last_err
        .unwrap_or_else(|| EstError::tamp("no SignerInfo verified against a known trust anchor")))
}

/// Verify a single `SignerInfo`; on success returns the signing TA's key id.
fn verify_one(
    signer: &SignerInfo,
    econtent_type: &ObjectIdentifier,
    econtent: &[u8],
    store: &TrustAnchorStore,
    digest_cache: &mut Vec<(ObjectIdentifier, Vec<u8>)>,
) -> Result<Vec<u8>> {
    // 1. Resolve the signer to a trust anchor we already hold.
    let (key_id, spki) = resolve_signer(&signer.sid, store)?;

    // 1b. The digestAlgorithm must match the hash bound to the signatureAlgorithm
    // (RFC 5652 §5.4 pairs them). Rejecting a mismatch keeps the integrity hash
    // that message-digest is checked under from being decoupled from the hash the
    // signature actually validates.
    check_digest_matches_sig(signer.digest_alg.oid, signer.signature_algorithm.oid)?;

    // 2. Determine the bytes that were signed.
    //
    // We REQUIRE signed attributes on inbound management messages. Without them,
    // the signature would cover only the eContent octets, leaving the message's
    // eContentType unbound by the signature (and skipping the message-digest
    // check). Requiring signed attributes forces the content-type + message-digest
    // binding (RFC 5652 §5.4) on every message that can mutate the trust store.
    // This client always emits signed attributes on its own messages, so the
    // requirement is symmetric.
    let signed_attrs = signer.signed_attrs.as_ref().ok_or_else(|| {
        EstError::tamp(
            "TAMP SignerInfo has no signed attributes; the content-type/message-digest \
             binding is mandatory and the message is rejected",
        )
    })?;
    validate_signed_attrs(signed_attrs, signer, econtent_type, econtent, digest_cache)?;
    // RFC 5652 §5.4: the signature is computed over the DER encoding of the
    // SignedAttributes value with the universal SET OF tag (not the IMPLICIT
    // [0] tag carried in the SignerInfo).
    let signed_bytes = signed_attrs
        .to_der()
        .map_err(|e| EstError::tamp(format!("re-encode signed attributes: {e}")))?;

    // 3. Cryptographically verify.
    let signature = signer.signature.as_bytes();
    verify_signature(
        &spki,
        signer.signature_algorithm.oid,
        &signed_bytes,
        signature,
    )?;

    Ok(key_id)
}

/// Map a `SignerIdentifier` to a trust anchor's `(key_id, public key)`.
fn resolve_signer(
    sid: &SignerIdentifier,
    store: &TrustAnchorStore,
) -> Result<(Vec<u8>, SubjectPublicKeyInfoOwned)> {
    match sid {
        SignerIdentifier::SubjectKeyIdentifier(ski) => {
            let key_id = ski.0.as_bytes();
            let entry = store.find_by_key_id(key_id).ok_or_else(|| {
                EstError::tamp("signer key identifier does not match any trust anchor")
            })?;
            Ok((entry.key_id.clone(), entry.public_key()?))
        }
        SignerIdentifier::IssuerAndSerialNumber(isn) => {
            // Match a certificate trust anchor by issuer + serial number.
            for entry in store.iter() {
                if let Some((issuer, serial)) = cert_issuer_serial(&entry.anchor)
                    && issuer == isn.issuer
                    && serial == isn.serial_number
                {
                    return Ok((entry.key_id.clone(), entry.public_key()?));
                }
            }
            Err(EstError::tamp(
                "signer issuer/serial does not match any certificate trust anchor",
            ))
        }
    }
}

/// Extract `(issuer, serialNumber)` from a certificate-style trust anchor.
fn cert_issuer_serial(
    anchor: &x509_cert::anchor::TrustAnchorChoice,
) -> Option<(
    x509_cert::name::Name,
    x509_cert::serial_number::SerialNumber,
)> {
    use x509_cert::anchor::TrustAnchorChoice;
    match anchor {
        TrustAnchorChoice::Certificate(cert) => Some((
            cert.tbs_certificate().issuer().clone(),
            cert.tbs_certificate().serial_number().clone(),
        )),
        TrustAnchorChoice::TbsCertificate(tbs) => {
            Some((tbs.issuer().clone(), tbs.serial_number().clone()))
        }
        TrustAnchorChoice::TaInfo(_) => None,
    }
}

/// Enforce that the SignerInfo digestAlgorithm matches the hash implied by its
/// signatureAlgorithm (RFC 5652 §5.4 binds the two together).
fn check_digest_matches_sig(digest_alg: ObjectIdentifier, sig_alg: ObjectIdentifier) -> Result<()> {
    let expected = match sig_alg {
        RSA_SHA256 | ECDSA_SHA256 => OID_SHA256,
        RSA_SHA384 | ECDSA_SHA384 => OID_SHA384,
        RSA_SHA512 => OID_SHA512,
        other => {
            return Err(EstError::tamp(format!(
                "unsupported TAMP signature algorithm: {other}"
            )));
        }
    };
    if digest_alg != expected {
        return Err(EstError::tamp(format!(
            "SignerInfo digestAlgorithm {digest_alg} does not match the hash implied by \
             signatureAlgorithm {sig_alg}"
        )));
    }
    Ok(())
}

/// Enforce the mandatory CMS signed attributes (RFC 5652 §5.4).
fn validate_signed_attrs(
    signed_attrs: &SetOfVec<Attribute>,
    signer: &SignerInfo,
    econtent_type: &ObjectIdentifier,
    econtent: &[u8],
    digest_cache: &mut Vec<(ObjectIdentifier, Vec<u8>)>,
) -> Result<()> {
    // content-type attribute must equal the eContentType.
    let ct_attr = find_attr(signed_attrs, &OID_CONTENT_TYPE)
        .ok_or_else(|| EstError::tamp("signed attributes missing content-type"))?;
    let ct_val: ObjectIdentifier = ct_attr
        .values
        .as_slice()
        .first()
        .ok_or_else(|| EstError::tamp("empty content-type attribute"))?
        .decode_as()
        .map_err(|e| EstError::tamp(format!("decode content-type attribute: {e}")))?;
    if ct_val != *econtent_type {
        return Err(EstError::tamp(format!(
            "signed content-type {ct_val} does not match eContentType {econtent_type}"
        )));
    }

    // message-digest attribute must equal the digest of eContent under the
    // SignerInfo's digestAlgorithm.
    let md_attr = find_attr(signed_attrs, &OID_MESSAGE_DIGEST)
        .ok_or_else(|| EstError::tamp("signed attributes missing message-digest"))?;
    let md_val: OctetString = md_attr
        .values
        .as_slice()
        .first()
        .ok_or_else(|| EstError::tamp("empty message-digest attribute"))?
        .decode_as()
        .map_err(|e| EstError::tamp(format!("decode message-digest attribute: {e}")))?;

    let computed = cached_digest(digest_cache, signer.digest_alg.oid, econtent)?;
    if md_val.as_bytes() != computed {
        return Err(EstError::tamp(
            "message-digest attribute does not match eContent digest",
        ));
    }
    Ok(())
}

fn find_attr<'a>(attrs: &'a SetOfVec<Attribute>, oid: &ObjectIdentifier) -> Option<&'a Attribute> {
    attrs.as_slice().iter().find(|a| a.oid == *oid)
}

/// Return the digest of `data` under `alg`, computing it at most once per
/// algorithm across a multi-signer message (`cache` is shared by all signers).
fn cached_digest<'a>(
    cache: &'a mut Vec<(ObjectIdentifier, Vec<u8>)>,
    alg: ObjectIdentifier,
    data: &[u8],
) -> Result<&'a [u8]> {
    let pos = match cache.iter().position(|(o, _)| *o == alg) {
        Some(p) => p,
        None => {
            let d = digest(alg, data)?;
            cache.push((alg, d));
            cache.len() - 1
        }
    };
    Ok(cache[pos].1.as_slice())
}

/// Compute a digest under the named algorithm, routed through the FIPS-aware
/// [`crate::fips_crypto`] layer (validated module under `fips`, else `sha2`).
fn digest(alg: ObjectIdentifier, data: &[u8]) -> Result<Vec<u8>> {
    match alg {
        OID_SHA256 => Ok(crate::fips_crypto::sha256(data).to_vec()),
        OID_SHA384 => Ok(crate::fips_crypto::sha384(data).to_vec()),
        OID_SHA512 => Ok(crate::fips_crypto::sha512(data).to_vec()),
        other => Err(EstError::tamp(format!(
            "unsupported message-digest algorithm: {other}"
        ))),
    }
}

/// Verify a signature with a trust anchor's public key.
///
/// Under `fips`, verification runs inside the aws-lc-rs FIPS module; otherwise
/// it uses the RustCrypto verifiers. Mirrors `validation::verify_signature`.
fn verify_signature(
    spki: &SubjectPublicKeyInfoOwned,
    sig_alg: ObjectIdentifier,
    signed_bytes: &[u8],
    signature: &[u8],
) -> Result<()> {
    match sig_alg {
        RSA_SHA256 | RSA_SHA384 | RSA_SHA512 | ECDSA_SHA256 | ECDSA_SHA384 => {
            #[cfg(feature = "fips")]
            {
                verify_fips(sig_alg, spki, signed_bytes, signature)
            }
            #[cfg(not(feature = "fips"))]
            {
                verify_rustcrypto(sig_alg, spki, signed_bytes, signature)
            }
        }
        other => Err(EstError::tamp(format!(
            "unsupported TAMP signature algorithm: {other}"
        ))),
    }
}

#[cfg(feature = "fips")]
fn verify_fips(
    sig_alg: ObjectIdentifier,
    spki: &SubjectPublicKeyInfoOwned,
    signed_bytes: &[u8],
    signature: &[u8],
) -> Result<()> {
    use aws_lc_rs::signature::{
        self, ECDSA_P256_SHA256_ASN1, ECDSA_P384_SHA384_ASN1, RSA_PKCS1_2048_8192_SHA256,
        RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512, UnparsedPublicKey,
    };

    let key_bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| EstError::tamp("public key BIT STRING not byte-aligned"))?;

    let alg: &'static dyn signature::VerificationAlgorithm = match sig_alg {
        RSA_SHA256 => &RSA_PKCS1_2048_8192_SHA256,
        RSA_SHA384 => &RSA_PKCS1_2048_8192_SHA384,
        RSA_SHA512 => &RSA_PKCS1_2048_8192_SHA512,
        ECDSA_SHA256 => &ECDSA_P256_SHA256_ASN1,
        ECDSA_SHA384 => &ECDSA_P384_SHA384_ASN1,
        other => {
            return Err(EstError::tamp(format!(
                "unsupported TAMP signature algorithm for FIPS verification: {other}"
            )));
        }
    };

    UnparsedPublicKey::new(alg, key_bytes)
        .verify(signed_bytes, signature)
        .map_err(|_| EstError::tamp("TAMP signature verification failed (FIPS)"))
}

#[cfg(not(feature = "fips"))]
fn verify_rustcrypto(
    sig_alg: ObjectIdentifier,
    spki: &SubjectPublicKeyInfoOwned,
    signed_bytes: &[u8],
    signature: &[u8],
) -> Result<()> {
    let key_bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| EstError::tamp("public key BIT STRING not byte-aligned"))?;

    match sig_alg {
        RSA_SHA256 | RSA_SHA384 | RSA_SHA512 => {
            use rsa::pkcs1::DecodeRsaPublicKey;
            use rsa::pkcs1v15::{Signature, VerifyingKey};
            use rsa::signature::Verifier;
            use sha2::{Sha256, Sha384, Sha512};

            let public_key = rsa::RsaPublicKey::from_pkcs1_der(key_bytes)
                .map_err(|e| EstError::tamp(format!("parse RSA public key: {e}")))?;
            let sig = Signature::try_from(signature)
                .map_err(|e| EstError::tamp(format!("invalid RSA signature: {e}")))?;
            let ok = match sig_alg {
                RSA_SHA256 => VerifyingKey::<Sha256>::new(public_key).verify(signed_bytes, &sig),
                RSA_SHA384 => VerifyingKey::<Sha384>::new(public_key).verify(signed_bytes, &sig),
                _ => VerifyingKey::<Sha512>::new(public_key).verify(signed_bytes, &sig),
            };
            ok.map_err(|_| EstError::tamp("TAMP RSA signature verification failed"))
        }
        ECDSA_SHA256 => {
            use p256::ecdsa::signature::Verifier;
            use p256::ecdsa::{Signature, VerifyingKey};
            let vk = VerifyingKey::from_sec1_bytes(key_bytes)
                .map_err(|e| EstError::tamp(format!("parse P-256 key: {e}")))?;
            let sig = Signature::from_der(signature)
                .map_err(|e| EstError::tamp(format!("invalid ECDSA signature: {e}")))?;
            vk.verify(signed_bytes, &sig)
                .map_err(|_| EstError::tamp("TAMP ECDSA P-256 verification failed"))
        }
        ECDSA_SHA384 => {
            use p384::ecdsa::signature::Verifier;
            use p384::ecdsa::{Signature, VerifyingKey};
            let vk = VerifyingKey::from_sec1_bytes(key_bytes)
                .map_err(|e| EstError::tamp(format!("parse P-384 key: {e}")))?;
            let sig = Signature::from_der(signature)
                .map_err(|e| EstError::tamp(format!("invalid ECDSA signature: {e}")))?;
            vk.verify(signed_bytes, &sig)
                .map_err(|_| EstError::tamp("TAMP ECDSA P-384 verification failed"))
        }
        other => Err(EstError::tamp(format!(
            "unsupported TAMP signature algorithm: {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tamp::store::TrustAnchorStore;

    #[test]
    fn unsigned_message_is_rejected() {
        // Build a TampMessage with no signer infos via the wrapper assembler.
        use crate::tamp::asn1::{
            TampMsgRef, TampStatusQuery, TampVersion, TargetIdentifier, TerseOrVerbose,
        };
        let q = TampStatusQuery {
            version: TampVersion::V2,
            terse: TerseOrVerbose::Verbose,
            query: TampMsgRef {
                target: TargetIdentifier::AllModules(der::asn1::Null),
                seq_num: 1,
            },
        };
        let cms = crate::tamp::wrapper::assemble_signed_data(
            crate::tamp::oid::ID_CT_TAMP_STATUS_QUERY,
            &q.to_der().unwrap(),
            SetOfVec::new(),
            None,
            vec![],
        )
        .unwrap();
        let msg = TampMessage::parse(&cms).unwrap();
        let store = TrustAnchorStore::new();
        let err = verify_message(&msg, &store).unwrap_err();
        assert!(matches!(err, EstError::Tamp(_)));
    }

    #[test]
    fn digest_selects_algorithm() {
        // SHA-256("abc") known prefix.
        let d = digest(OID_SHA256, b"abc").unwrap();
        assert_eq!(&d[..4], &[0xba, 0x78, 0x16, 0xbf]);
        // SHA-384 / SHA-512 produce the right lengths.
        assert_eq!(digest(OID_SHA384, b"abc").unwrap().len(), 48);
        assert_eq!(digest(OID_SHA512, b"abc").unwrap().len(), 64);
        assert!(digest(crate::tamp::oid::ID_CT_TAMP_ERROR, b"x").is_err());
    }
}
