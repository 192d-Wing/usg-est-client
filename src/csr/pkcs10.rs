// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! Manual PKCS#10 Certificate Signing Request construction for HSM integration.
//!
//! This module provides low-level PKCS#10 construction capabilities needed for
//! generating CSRs with keys stored in Hardware Security Modules. Unlike rcgen,
//! which requires the private key material to be accessible, this module allows
//! signing the CSR using an external signing callback (HSM KeyProvider).
//!
//! # PKCS#10 Structure (RFC 2986)
//!
//! ```text
//! CertificationRequest ::= SEQUENCE {
//!     certificationRequestInfo CertificationRequestInfo,
//!     signatureAlgorithm       AlgorithmIdentifier,
//!     signature                BIT STRING
//! }
//!
//! CertificationRequestInfo ::= SEQUENCE {
//!     version       INTEGER { v1(0) },
//!     subject       Name,
//!     subjectPKInfo SubjectPublicKeyInfo,
//!     attributes    [0] Attributes
//! }
//! ```

use der::asn1::{BitString, OctetString, SetOfVec};
use der::{Decode, Encode};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::attr::Attribute;
use x509_cert::ext::Extension;
use x509_cert::name::Name;
use x509_cert::request::{CertReq, CertReqInfo, ExtensionReq, Version};

use crate::error::{EstError, Result};
use crate::hsm::KeyAlgorithm;

/// Build a CertReqInfo structure from parameters.
///
/// This creates the "to-be-signed" portion of the CSR, including:
/// - Version (always v1/0)
/// - Subject distinguished name
/// - Subject public key info
/// - Attributes (including extension requests for SANs and key usage)
pub(super) fn build_cert_req_info(
    subject: Name,
    public_key: SubjectPublicKeyInfoOwned,
    attributes: Vec<Attribute>,
) -> Result<CertReqInfo> {
    // Convert attributes to SetOfVec
    let attrs = if attributes.is_empty() {
        // Empty attributes list
        SetOfVec::new()
    } else {
        let mut set = SetOfVec::new();
        for attr in attributes {
            set.insert(attr)
                .map_err(|e| EstError::operational(format!("Failed to add attribute: {}", e)))?;
        }
        set
    };

    // Build CertReqInfo
    // Note: CertReqInfo.attributes is just SetOfVec, not ContextSpecific wrapped
    let info = CertReqInfo {
        version: Version::V1,
        subject,
        public_key,
        attributes: attrs,
    };

    Ok(info)
}

/// Encode the CertReqInfo to DER and compute the appropriate digest for signing.
///
/// The hash algorithm is selected based on the key algorithm:
/// - ECDSA P-256 → SHA-256
/// - ECDSA P-384 → SHA-384
/// - RSA → SHA-256
///
/// Returns a tuple of (DER-encoded CertReqInfo, digest bytes)
pub(super) fn encode_and_hash(
    info: &CertReqInfo,
    key_algorithm: KeyAlgorithm,
) -> Result<(Vec<u8>, Vec<u8>)> {
    // Encode CertReqInfo to DER
    let tbs_der = info
        .to_der()
        .map_err(|e| EstError::operational(format!("Failed to encode CertReqInfo: {}", e)))?;

    // Select hash algorithm based on key algorithm
    let digest = match key_algorithm {
        KeyAlgorithm::EcdsaP256 => {
            // SHA-256 for P-256
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&tbs_der);
            hasher.finalize().to_vec()
        }
        KeyAlgorithm::EcdsaP384 => {
            // SHA-384 for P-384
            use sha2::{Digest, Sha384};
            let mut hasher = Sha384::new();
            hasher.update(&tbs_der);
            hasher.finalize().to_vec()
        }
        KeyAlgorithm::Rsa { bits: _ } => {
            // SHA-256 for RSA (most common)
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&tbs_der);
            hasher.finalize().to_vec()
        }
    };

    Ok((tbs_der, digest))
}

/// Assemble the final CertificationRequest from components.
///
/// Takes the CertReqInfo, signature algorithm, and signature bytes to produce
/// a complete PKCS#10 CSR ready for submission.
///
/// # Arguments
///
/// * `info` - The CertReqInfo (to-be-signed data)
/// * `algorithm` - The signature algorithm identifier
/// * `signature_bytes` - The signature over the DER-encoded CertReqInfo
///
/// # Returns
///
/// A complete CertReq structure that can be encoded to DER.
pub(super) fn assemble_cert_req(
    info: CertReqInfo,
    algorithm: AlgorithmIdentifierOwned,
    signature_bytes: Vec<u8>,
) -> Result<CertReq> {
    // Convert signature bytes to BitString
    // For ECDSA and RSA signatures, they should already be DER-encoded
    let signature = BitString::from_bytes(&signature_bytes)
        .map_err(|e| EstError::operational(format!("Failed to create signature BitString: {}", e)))?;

    // Assemble the final CertReq
    let cert_req = CertReq {
        info,
        algorithm,
        signature,
    };

    Ok(cert_req)
}

/// Helper to create an extension request attribute for SANs and key usage.
///
/// This creates a PKCS#9 extensionRequest attribute containing the requested
/// X.509 extensions.
pub(super) fn create_extension_request_attribute(
    extensions: Vec<Extension>,
) -> Result<Attribute> {
    if extensions.is_empty() {
        return Err(EstError::operational(
            "Cannot create extension request with no extensions",
        ));
    }

    // Create ExtensionReq containing all extensions
    let ext_req = ExtensionReq::from(extensions);

    // Encode ExtensionReq to DER
    let ext_req_der = ext_req
        .to_der()
        .map_err(|e| EstError::operational(format!("Failed to encode ExtensionReq: {}", e)))?;

    // Create attribute with OID 1.2.840.113549.1.9.14 (extensionRequest)
    let oid = const_oid::db::rfc5912::ID_EXTENSION_REQ;

    // Create attribute values set containing the ExtensionReq
    let mut values = SetOfVec::new();
    values
        .insert(der::Any::from_der(&ext_req_der).map_err(|e| {
            EstError::operational(format!("Failed to parse ExtensionReq as ANY: {}", e))
        })?)
        .map_err(|e| EstError::operational(format!("Failed to insert extension value: {}", e)))?;

    Ok(Attribute { oid, values })
}

/// Helper to create a KeyUsage extension from flags.
pub(super) fn create_key_usage_extension(
    digital_signature: bool,
    key_encipherment: bool,
    key_agreement: bool,
) -> Result<Extension> {
    // Build KeyUsages byte array
    // KeyUsage is a BIT STRING where bit 0 = digitalSignature, bit 2 = keyEncipherment, bit 4 = keyAgreement
    let mut byte = 0u8;

    if digital_signature {
        byte |= 0x80; // bit 0 (high bit)
    }
    if key_encipherment {
        byte |= 0x20; // bit 2
    }
    if key_agreement {
        byte |= 0x08; // bit 4
    }

    // Create BitString - KeyUsages wraps a BitString
    let bitstring = BitString::from_bytes(&[byte])
        .map_err(|e| EstError::operational(format!("Failed to create BitString: {}", e)))?;

    // Encode the BitString to DER
    let key_usage_der = bitstring
        .to_der()
        .map_err(|e| EstError::operational(format!("Failed to encode KeyUsage: {}", e)))?;

    // Create Extension with OID 2.5.29.15 (keyUsage)
    let ext = Extension {
        extn_id: const_oid::db::rfc5280::ID_CE_KEY_USAGE,
        critical: true,
        extn_value: OctetString::new(key_usage_der)
            .map_err(|e| EstError::operational(format!("Failed to create OctetString: {}", e)))?,
    };

    Ok(ext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Decode;
    use spki::SubjectPublicKeyInfoRef;

    #[test]
    fn test_build_cert_req_info() {
        // Create a minimal subject
        let subject = Name::from_str("CN=test").unwrap();

        // Create a dummy public key (this would come from the HSM in practice)
        let public_key_der = include_bytes!("../../tests/fixtures/p256-pub.der");
        let spki = SubjectPublicKeyInfoRef::from_der(public_key_der).unwrap();
        let public_key = spki.to_owned();

        // Build CertReqInfo with no attributes
        let info = build_cert_req_info(subject, public_key, vec![]).unwrap();

        // Verify structure
        assert_eq!(info.version, Version::V1);
        assert!(info.attributes.value.is_empty());
    }

    #[test]
    fn test_encode_and_hash_p256() {
        let subject = Name::from_str("CN=test").unwrap();
        let public_key_der = include_bytes!("../../tests/fixtures/p256-pub.der");
        let spki = SubjectPublicKeyInfoRef::from_der(public_key_der).unwrap();
        let public_key = spki.to_owned();

        let info = build_cert_req_info(subject, public_key, vec![]).unwrap();

        let (tbs_der, digest) = encode_and_hash(&info, KeyAlgorithm::EcdsaP256).unwrap();

        // Verify we got DER bytes
        assert!(!tbs_der.is_empty());

        // SHA-256 produces 32 bytes
        assert_eq!(digest.len(), 32);
    }

    #[test]
    fn test_encode_and_hash_p384() {
        let subject = Name::from_str("CN=test").unwrap();
        let public_key_der = include_bytes!("../../tests/fixtures/p256-pub.der");
        let spki = SubjectPublicKeyInfoRef::from_der(public_key_der).unwrap();
        let public_key = spki.to_owned();

        let info = build_cert_req_info(subject, public_key, vec![]).unwrap();

        let (_tbs_der, digest) = encode_and_hash(&info, KeyAlgorithm::EcdsaP384).unwrap();

        // SHA-384 produces 48 bytes
        assert_eq!(digest.len(), 48);
    }

    #[test]
    fn test_create_key_usage_extension() {
        let ext = create_key_usage_extension(true, true, false).unwrap();

        // Verify OID
        assert_eq!(ext.extn_id, const_oid::db::rfc5280::ID_CE_KEY_USAGE);

        // Verify critical flag
        assert!(ext.critical);

        // Verify we can decode the value
        assert!(!ext.extn_value.as_bytes().is_empty());
    }
}
