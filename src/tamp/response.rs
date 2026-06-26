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

//! Client-originated TAMP messages and CMS signing (RFC 5934).
//!
//! A managed TAMP client sends three kinds of message, all CMS `SignedData`:
//! - [`TAMPStatusQuery`](super::asn1::TampStatusQuery) — to pull status;
//! - the `*Confirm` messages — acknowledging an applied update; and
//! - [`TAMPError`](super::asn1::TampError) — reporting a rejected message.
//!
//! [`TampSigner`] signs a TAMP message body into a CMS `SignedData` using the
//! client's identity key (reusing the EST [`ClientIdentity`](crate::ClientIdentity)
//! by default). Signed attributes carry the mandatory `content-type` and
//! `message-digest` (RFC 5652 §5.4) so the receiver — and our own
//! [`super::verify`] — can validate them.
//!
//! # FIPS note
//!
//! The digest and message-digest hashing run through the FIPS-aware
//! [`crate::fips_crypto`] layer (the aws-lc-rs FIPS module under `fips`). The
//! signature operation itself uses the RustCrypto signers (`rsa`, `p256`,
//! `p384`) on **every** build — TAMP message signing is not yet routed through
//! the validated module. A FIPS deployment's validated boundary therefore
//! covers TAMP TLS, verification, and hashing, but not TAMP signing; see
//! `docs/docs/tamp.md`.

use cms::cert::CertificateChoices;
use cms::content_info::CmsVersion;
use cms::signed_data::{CertificateSet, SignedAttributes, SignerIdentifier, SignerInfo};
use const_oid::ObjectIdentifier;
use der::asn1::{Any, OctetString, SetOfVec};
use der::{Decode, DecodePem, Encode};
use spki::AlgorithmIdentifierOwned;
use x509_cert::Certificate;
use x509_cert::attr::Attribute;

use crate::config::ClientIdentity;
use crate::error::{EstError, Result};

use super::asn1::{
    StatusCode, TampError, TampMsgRef, TampStatusQuery, TampUpdateConfirm, TampVersion,
    TerseOrVerbose, UpdateConfirm,
};
use super::oid::TampContentType;
use super::wrapper;

// Algorithm OIDs.
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const RSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const OID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const OID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");

// ===========================================================================
// Message body builders (the unsigned eContent)
// ===========================================================================

/// Build the DER body of a `TAMPStatusQuery`.
pub fn build_status_query(query: TampMsgRef, terse: bool) -> Result<Vec<u8>> {
    let msg = TampStatusQuery {
        version: TampVersion::V2,
        terse: if terse {
            TerseOrVerbose::Terse
        } else {
            TerseOrVerbose::Verbose
        },
        query,
    };
    msg.to_der()
        .map_err(|e| EstError::tamp(format!("encode TAMPStatusQuery: {e}")))
}

/// Build the DER body of a `TAMPUpdateConfirm`.
pub fn build_update_confirm(update: TampMsgRef, confirm: UpdateConfirm) -> Result<Vec<u8>> {
    let msg = TampUpdateConfirm {
        version: TampVersion::V2,
        update,
        confirm,
    };
    msg.to_der()
        .map_err(|e| EstError::tamp(format!("encode TAMPUpdateConfirm: {e}")))
}

/// Build the DER body of a `TAMPError`.
pub fn build_error(
    msg_type: ObjectIdentifier,
    status: StatusCode,
    msg_ref: Option<TampMsgRef>,
) -> Result<Vec<u8>> {
    let msg = TampError {
        version: TampVersion::V2,
        msg_type,
        status,
        msg_ref,
    };
    msg.to_der()
        .map_err(|e| EstError::tamp(format!("encode TAMPError: {e}")))
}

// ===========================================================================
// Signing
// ===========================================================================

/// The parsed signing key behind a [`TampSigner`].
enum SigningKey {
    Rsa(Box<rsa::pkcs1v15::SigningKey<sha2::Sha256>>),
    P256(Box<p256::ecdsa::SigningKey>),
    P384(Box<p384::ecdsa::SigningKey>),
}

/// Signs TAMP messages into CMS `SignedData` using the client's identity.
pub struct TampSigner {
    key: SigningKey,
    cert: Certificate,
}

impl TampSigner {
    /// Build a signer from the EST [`ClientIdentity`] (PEM certificate + key).
    pub fn from_client_identity(identity: &ClientIdentity) -> Result<Self> {
        Self::from_pem(&identity.cert_pem, &identity.key_pem)
    }

    /// Build a signer from a PEM certificate and PEM PKCS#8 private key.
    pub fn from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<Self> {
        let cert = parse_first_cert(cert_pem)?;
        let key = parse_signing_key(key_pem)?;
        Ok(Self { key, cert })
    }

    fn sig_alg_oid(&self) -> ObjectIdentifier {
        match self.key {
            SigningKey::Rsa(_) => RSA_SHA256,
            SigningKey::P256(_) => ECDSA_SHA256,
            SigningKey::P384(_) => ECDSA_SHA384,
        }
    }

    /// Digest algorithm paired with the signature (SHA-256, or SHA-384 for P-384).
    fn digest_alg_oid(&self) -> ObjectIdentifier {
        match self.key {
            SigningKey::P384(_) => OID_SHA384,
            _ => OID_SHA256,
        }
    }

    fn digest(&self, data: &[u8]) -> Vec<u8> {
        match self.key {
            SigningKey::P384(_) => crate::fips_crypto::sha384(data).to_vec(),
            _ => crate::fips_crypto::sha256(data).to_vec(),
        }
    }

    fn sign_bytes(&self, data: &[u8]) -> Result<Vec<u8>> {
        match &self.key {
            SigningKey::Rsa(k) => {
                use rsa::signature::{SignatureEncoding, Signer};
                Ok(k.sign(data).to_bytes().as_ref().to_vec())
            }
            SigningKey::P256(k) => {
                use p256::ecdsa::signature::Signer;
                let sig: p256::ecdsa::Signature = k.sign(data);
                Ok(sig.to_der().as_bytes().to_vec())
            }
            SigningKey::P384(k) => {
                use p384::ecdsa::signature::Signer;
                let sig: p384::ecdsa::Signature = k.sign(data);
                Ok(sig.to_der().as_bytes().to_vec())
            }
        }
    }

    /// Sign a TAMP message body into a complete CMS `SignedData` `ContentInfo`.
    ///
    /// `content_type` selects the `eContentType`; `econtent_der` is the DER body
    /// from one of the `build_*` functions.
    pub fn sign_message(
        &self,
        content_type: TampContentType,
        econtent_der: &[u8],
    ) -> Result<Vec<u8>> {
        let econtent_type = content_type.oid();
        let digest_alg = AlgorithmIdentifierOwned {
            oid: self.digest_alg_oid(),
            parameters: None,
        };

        // Mandatory signed attributes (RFC 5652 §5.4): content-type + message-digest.
        let ct_attr = make_attr(OID_CONTENT_TYPE, any_from(&econtent_type)?)?;
        let md_value = OctetString::new(self.digest(econtent_der))
            .map_err(|e| EstError::tamp(format!("wrap message digest: {e}")))?;
        let md_attr = make_attr(OID_MESSAGE_DIGEST, any_from(&md_value)?)?;

        let signed_attrs: SignedAttributes = SetOfVec::try_from(vec![ct_attr, md_attr])
            .map_err(|e| EstError::tamp(format!("build signed attributes: {e}")))?;

        // The signature is over the DER of SignedAttributes with the SET OF tag.
        let to_sign = signed_attrs
            .to_der()
            .map_err(|e| EstError::tamp(format!("encode signed attributes: {e}")))?;
        let signature = self.sign_bytes(&to_sign)?;

        let sid = SignerIdentifier::from(&self.cert);
        let cms_version = match &sid {
            SignerIdentifier::SubjectKeyIdentifier(_) => CmsVersion::V3,
            SignerIdentifier::IssuerAndSerialNumber(_) => CmsVersion::V1,
        };

        let signer_info = SignerInfo {
            version: cms_version,
            sid,
            digest_alg: digest_alg.clone(),
            signed_attrs: Some(signed_attrs),
            signature_algorithm: AlgorithmIdentifierOwned {
                oid: self.sig_alg_oid(),
                parameters: None,
            },
            signature: der::asn1::OctetString::new(signature)
                .map_err(|e| EstError::tamp(format!("wrap signature: {e}")))?,
            unsigned_attrs: None,
        };

        let digest_algorithms = SetOfVec::try_from(vec![digest_alg])
            .map_err(|e| EstError::tamp(format!("build digestAlgorithms: {e}")))?;

        let cert_choice = CertificateChoices::Certificate(self.cert.clone());
        let certificates = Some(CertificateSet(
            SetOfVec::try_from(vec![cert_choice])
                .map_err(|e| EstError::tamp(format!("build certificate set: {e}")))?,
        ));

        wrapper::assemble_signed_data(
            econtent_type,
            econtent_der,
            digest_algorithms,
            certificates,
            vec![signer_info],
        )
    }
}

/// Build a single-valued CMS `Attribute`.
fn make_attr(oid: ObjectIdentifier, value: Any) -> Result<Attribute> {
    Ok(Attribute {
        oid,
        values: SetOfVec::try_from(vec![value])
            .map_err(|e| EstError::tamp(format!("build attribute values: {e}")))?,
    })
}

/// Encode any DER-encodable value into a CMS attribute `Any`.
fn any_from<T: Encode>(value: &T) -> Result<Any> {
    let der = value
        .to_der()
        .map_err(|e| EstError::tamp(format!("encode attribute value: {e}")))?;
    Any::from_der(&der).map_err(|e| EstError::tamp(format!("wrap attribute value: {e}")))
}

/// Parse the first certificate from a PEM bundle.
fn parse_first_cert(cert_pem: &[u8]) -> Result<Certificate> {
    Certificate::from_pem(cert_pem)
        .map_err(|e| EstError::tamp(format!("parse client certificate PEM: {e}")))
}

/// Parse an unencrypted PKCS#8 private key (PEM) into a [`SigningKey`].
///
/// Dispatches by trying each supported key type in turn; the PKCS#8 algorithm /
/// named-curve mismatch makes the wrong decoders fail cleanly, so the first
/// success identifies the key type.
fn parse_signing_key(key_pem: &[u8]) -> Result<SigningKey> {
    let pem = std::str::from_utf8(key_pem)
        .map_err(|_| EstError::tamp("client key PEM is not valid UTF-8"))?;
    let (label, doc) = pkcs8::SecretDocument::from_pem(pem)
        .map_err(|e| EstError::tamp(format!("decode private key PEM: {e}")))?;
    if label != "PRIVATE KEY" {
        return Err(EstError::tamp(format!(
            "expected an unencrypted PKCS#8 PRIVATE KEY PEM block, found {label}"
        )));
    }
    let der = doc.as_bytes();

    // All three key crates share the same `pkcs8` version, so one import of the
    // `DecodePrivateKey` trait brings `from_pkcs8_der` into scope for each type.
    use pkcs8::DecodePrivateKey as _;

    if let Ok(sk) = rsa::RsaPrivateKey::from_pkcs8_der(der) {
        return Ok(SigningKey::Rsa(Box::new(rsa::pkcs1v15::SigningKey::new(
            sk,
        ))));
    }
    if let Ok(sk) = p256::ecdsa::SigningKey::from_pkcs8_der(der) {
        return Ok(SigningKey::P256(Box::new(sk)));
    }
    if let Ok(sk) = p384::ecdsa::SigningKey::from_pkcs8_der(der) {
        return Ok(SigningKey::P384(Box::new(sk)));
    }
    Err(EstError::tamp(
        "unsupported TAMP signing key: expected PKCS#8 RSA, P-256, or P-384",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tamp::asn1::{TampVersion, TargetIdentifier};
    use crate::tamp::store::TrustAnchorStore;
    use crate::tamp::verify::verify_message;
    use crate::tamp::wrapper::TampMessage;

    #[test]
    fn status_query_body_round_trips() {
        let q = TampMsgRef {
            target: TargetIdentifier::AllModules(der::asn1::Null),
            seq_num: 5,
        };
        let der = build_status_query(q, false).unwrap();
        let back = TampStatusQuery::from_der(&der).unwrap();
        assert_eq!(back.version, TampVersion::V2);
        assert_eq!(back.query.seq_num, 5);
    }

    // End-to-end: sign a TAMP message with a generated identity, then verify it
    // against a store that trusts that identity's certificate. This exercises the
    // full crypto path across response.rs (signing) and verify.rs (verification),
    // including the signed-attributes content-type/message-digest checks.
    #[cfg(feature = "csr-gen")]
    #[test]
    fn sign_then_verify_round_trip() {
        use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
        use x509_cert::anchor::TrustAnchorChoice;

        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "TAMP Test Trust Anchor");
        params.distinguished_name = dn;
        let key_pair = KeyPair::generate().unwrap(); // ECDSA P-256 by default
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        // Trust the generated certificate as an anchor.
        let x509 = Certificate::from_der(cert.der().as_ref()).unwrap();
        let mut store = TrustAnchorStore::new();
        store
            .upsert(TrustAnchorChoice::Certificate(x509), true)
            .unwrap();
        let ta_key_id = store.iter().next().unwrap().key_id.clone();

        // Sign a status query as that identity.
        let signer = TampSigner::from_pem(cert_pem.as_bytes(), key_pem.as_bytes()).unwrap();
        let body = build_status_query(
            TampMsgRef {
                target: TargetIdentifier::AllModules(der::asn1::Null),
                seq_num: 1,
            },
            false,
        )
        .unwrap();
        let cms = signer
            .sign_message(TampContentType::StatusQuery, &body)
            .unwrap();

        // Verify against the store.
        let msg = TampMessage::parse(&cms).unwrap();
        let verified = verify_message(&msg, &store).unwrap();
        assert_eq!(verified.content_type, TampContentType::StatusQuery);
        assert_eq!(verified.signer_key_id, ta_key_id);
        assert_eq!(verified.econtent, body);

        // An empty store (no trust anchor) must reject the same message.
        let empty = TrustAnchorStore::new();
        assert!(verify_message(&msg, &empty).is_err());
    }

    // A tampered message body must fail verification (signature is over the
    // signed attributes whose message-digest binds the eContent).
    #[cfg(feature = "csr-gen")]
    #[test]
    fn tampered_content_fails_verification() {
        use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
        use x509_cert::anchor::TrustAnchorChoice;

        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "TAMP Test TA");
        params.distinguished_name = dn;
        let key_pair = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        let x509 = Certificate::from_der(cert.der().as_ref()).unwrap();
        let mut store = TrustAnchorStore::new();
        store
            .upsert(TrustAnchorChoice::Certificate(x509), true)
            .unwrap();

        let signer =
            TampSigner::from_pem(cert.pem().as_bytes(), key_pair.serialize_pem().as_bytes())
                .unwrap();
        let body = build_status_query(
            TampMsgRef {
                target: TargetIdentifier::AllModules(der::asn1::Null),
                seq_num: 1,
            },
            false,
        )
        .unwrap();
        let cms = signer
            .sign_message(TampContentType::StatusQuery, &body)
            .unwrap();

        // Parse, then corrupt the encapsulated content and re-verify: must fail.
        let mut msg = TampMessage::parse(&cms).unwrap();
        if let Some(last) = msg.econtent.last_mut() {
            *last ^= 0xFF;
        }
        assert!(
            verify_message(&msg, &store).is_err(),
            "verification must reject a tampered eContent"
        );
    }
}
