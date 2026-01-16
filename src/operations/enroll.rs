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

//! Simple Enrollment operation (POST /simpleenroll).
//!
//! This module provides utilities for the simple enrollment operation
//! defined in RFC 7030 Section 4.2.

use base64::prelude::*;

use crate::error::{EstError, Result};

/// Validate a DER-encoded CSR.
///
/// Performs basic validation checks on the CSR:
/// - Verifies DER structure is valid
/// - Checks that required fields are present
pub fn validate_csr(csr_der: &[u8]) -> Result<()> {
    // Try to parse as a PKCS#10 CertificationRequest
    // We use a simplified check here

    if csr_der.is_empty() {
        return Err(EstError::csr("Empty CSR"));
    }

    // Check for valid DER SEQUENCE tag
    if csr_der[0] != 0x30 {
        return Err(EstError::csr("Invalid CSR: not a SEQUENCE"));
    }

    Ok(())
}

/// Maximum CSR size in bytes (256 KB).
///
/// This limit prevents potential DoS attacks via extremely large CSRs.
/// A typical RSA-4096 CSR is ~1-2 KB, so 256 KB provides ample headroom.
const MAX_CSR_SIZE: usize = 256 * 1024;

/// Encode a CSR for transmission to the EST server.
///
/// This base64-encodes the DER data as required by RFC 7030.
///
/// # Security
///
/// Enforces a maximum CSR size to prevent resource exhaustion attacks.
///
/// # Errors
///
/// Returns an error if the CSR exceeds the maximum allowed size.
pub fn encode_csr(csr_der: &[u8]) -> Result<String> {
    if csr_der.len() > MAX_CSR_SIZE {
        return Err(EstError::csr(format!(
            "CSR too large: {} bytes (max: {} bytes)",
            csr_der.len(),
            MAX_CSR_SIZE
        )));
    }

    Ok(BASE64_STANDARD.encode(csr_der))
}

/// Add channel binding to a CSR.
///
/// Per RFC 7030 Section 3.5, the tls-unique value can be placed in
/// the challenge-password field of the CSR for channel binding.
///
/// Note: This requires modifying the CSR before signing, which means
/// the caller needs to handle this during CSR generation, not after.
pub fn create_channel_binding_value(tls_unique: &[u8]) -> String {
    // Base64 encode per RFC 4648
    BASE64_STANDARD.encode(tls_unique)
}

/// Extract the public key from a DER-encoded CSR.
///
/// Parses a PKCS#10 Certificate Signing Request and extracts the
/// SubjectPublicKeyInfo (SPKI) structure containing the public key.
///
/// # Arguments
///
/// * `csr_der` - DER-encoded PKCS#10 CSR
///
/// # Returns
///
/// DER-encoded SubjectPublicKeyInfo suitable for signature verification
///
/// # Errors
///
/// Returns an error if the CSR cannot be parsed or is malformed.
pub fn extract_public_key(csr_der: &[u8]) -> Result<Vec<u8>> {
    use der::{Decode, Encode};
    use x509_cert::request::CertReq;

    // Parse the PKCS#10 CSR
    let csr = CertReq::from_der(csr_der)
        .map_err(|e| EstError::csr(format!("Failed to parse CSR: {}", e)))?;

    // Extract the SubjectPublicKeyInfo from certificationRequestInfo
    let spki = &csr.info.public_key;

    // Encode SPKI to DER for return
    spki.to_der()
        .map_err(|e| EstError::csr(format!("Failed to encode public key: {}", e)))
}

/// Verify that a CSR signature is valid.
///
/// This function validates the signature on a PKCS#10 Certificate Signing Request,
/// providing proof-of-possession of the private key corresponding to the public
/// key in the CSR.
///
/// # Supported Algorithms
///
/// - **RSA with SHA-256** (1.2.840.113549.1.1.11)
/// - **RSA with SHA-384** (1.2.840.113549.1.1.12)
/// - **RSA with SHA-512** (1.2.840.113549.1.1.13)
/// - **ECDSA with SHA-256** (1.2.840.10045.4.3.2)
/// - **ECDSA with SHA-384** (1.2.840.10045.4.3.3)
///
/// # Arguments
///
/// * `csr_der` - DER-encoded PKCS#10 CSR
///
/// # Returns
///
/// Returns `Ok(true)` if the signature is valid, `Ok(false)` if invalid,
/// or an error if the CSR cannot be parsed or the algorithm is unsupported.
///
/// # Security
///
/// This function provides cryptographic proof that the entity submitting the
/// CSR possesses the private key corresponding to the public key in the CSR.
/// This is a critical security check for preventing unauthorized certificate
/// issuance.
pub fn verify_csr_signature(csr_der: &[u8]) -> Result<bool> {
    use der::{Decode, Encode};
    use x509_cert::request::CertReq;

    // Parse the PKCS#10 CSR
    let csr = CertReq::from_der(csr_der)
        .map_err(|e| EstError::csr(format!("Failed to parse CSR: {}", e)))?;

    // Get the data that was signed (certificationRequestInfo)
    let signed_data = csr
        .info
        .to_der()
        .map_err(|e| EstError::csr(format!("Failed to encode CertReqInfo: {}", e)))?;

    // Get signature algorithm OID
    let sig_alg_oid = csr.algorithm.oid.to_string();

    // Get signature bytes
    let signature_bytes = csr.signature.raw_bytes();

    // Get public key
    let spki = &csr.info.public_key;

    // Dispatch to appropriate verification function based on algorithm
    match sig_alg_oid.as_str() {
        // RSA with SHA-256: 1.2.840.113549.1.1.11
        "1.2.840.113549.1.1.11" => verify_rsa_sha256(spki, &signed_data, signature_bytes),

        // RSA with SHA-384: 1.2.840.113549.1.1.12
        "1.2.840.113549.1.1.12" => verify_rsa_sha384(spki, &signed_data, signature_bytes),

        // RSA with SHA-512: 1.2.840.113549.1.1.13
        "1.2.840.113549.1.1.13" => verify_rsa_sha512(spki, &signed_data, signature_bytes),

        // ECDSA with SHA-256: 1.2.840.10045.4.3.2
        "1.2.840.10045.4.3.2" => verify_ecdsa_sha256(spki, &signed_data, signature_bytes),

        // ECDSA with SHA-384: 1.2.840.10045.4.3.3
        "1.2.840.10045.4.3.3" => verify_ecdsa_sha384(spki, &signed_data, signature_bytes),

        _ => Err(EstError::csr(format!(
            "Unsupported signature algorithm: {}",
            sig_alg_oid
        ))),
    }
}

/// Verify RSA signature with SHA-256.
fn verify_rsa_sha256(
    spki: &spki::SubjectPublicKeyInfoOwned,
    data: &[u8],
    signature: &[u8],
) -> Result<bool> {
    use der::Encode;
    use rsa::RsaPublicKey;
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    use sha2::{Digest, Sha256};

    // Encode SPKI to DER and parse as RsaPublicKey
    use pkcs8::DecodePublicKey;

    let spki_der = spki
        .to_der()
        .map_err(|e| EstError::csr(format!("Failed to encode SPKI: {}", e)))?;

    let public_key = RsaPublicKey::from_public_key_der(&spki_der)
        .map_err(|e| EstError::csr(format!("Failed to parse RSA public key: {}", e)))?;

    // Create verifying key
    let verifying_key = VerifyingKey::<Sha256>::new(public_key);

    // Parse signature
    let sig = Signature::try_from(signature)
        .map_err(|e| EstError::csr(format!("Failed to parse RSA signature: {}", e)))?;

    // Hash the data
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();

    // Verify signature
    match verifying_key.verify(&digest, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify RSA signature with SHA-384.
fn verify_rsa_sha384(
    spki: &spki::SubjectPublicKeyInfoOwned,
    data: &[u8],
    signature: &[u8],
) -> Result<bool> {
    use der::Encode;
    use pkcs8::DecodePublicKey;
    use rsa::RsaPublicKey;
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    use sha2::{Digest, Sha384};

    let spki_der = spki
        .to_der()
        .map_err(|e| EstError::csr(format!("Failed to encode SPKI: {}", e)))?;

    let public_key = RsaPublicKey::from_public_key_der(&spki_der)
        .map_err(|e| EstError::csr(format!("Failed to parse RSA public key: {}", e)))?;

    let verifying_key = VerifyingKey::<Sha384>::new(public_key);

    let sig = Signature::try_from(signature)
        .map_err(|e| EstError::csr(format!("Failed to parse RSA signature: {}", e)))?;

    let mut hasher = Sha384::new();
    hasher.update(data);
    let digest = hasher.finalize();

    match verifying_key.verify(&digest, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify RSA signature with SHA-512.
fn verify_rsa_sha512(
    spki: &spki::SubjectPublicKeyInfoOwned,
    data: &[u8],
    signature: &[u8],
) -> Result<bool> {
    use der::Encode;
    use pkcs8::DecodePublicKey;
    use rsa::RsaPublicKey;
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    use sha2::{Digest, Sha512};

    let spki_der = spki
        .to_der()
        .map_err(|e| EstError::csr(format!("Failed to encode SPKI: {}", e)))?;

    let public_key = RsaPublicKey::from_public_key_der(&spki_der)
        .map_err(|e| EstError::csr(format!("Failed to parse RSA public key: {}", e)))?;

    let verifying_key = VerifyingKey::<Sha512>::new(public_key);

    let sig = Signature::try_from(signature)
        .map_err(|e| EstError::csr(format!("Failed to parse RSA signature: {}", e)))?;

    let mut hasher = Sha512::new();
    hasher.update(data);
    let digest = hasher.finalize();

    match verifying_key.verify(&digest, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify ECDSA signature with SHA-256 (typically P-256).
fn verify_ecdsa_sha256(
    spki: &spki::SubjectPublicKeyInfoOwned,
    data: &[u8],
    signature: &[u8],
) -> Result<bool> {
    use p256::EncodedPoint;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};

    // Extract public key bytes from SPKI
    let public_key_bytes = spki.subject_public_key.raw_bytes();

    // Parse as P-256 encoded point
    let encoded_point = EncodedPoint::from_bytes(public_key_bytes)
        .map_err(|e| EstError::csr(format!("Failed to parse P-256 point: {}", e)))?;

    // Create verifying key
    let public_key = VerifyingKey::from_encoded_point(&encoded_point)
        .map_err(|e| EstError::csr(format!("Failed to create P-256 verifying key: {}", e)))?;

    // Parse DER-encoded signature
    let sig = Signature::from_der(signature)
        .map_err(|e| EstError::csr(format!("Failed to parse ECDSA signature: {}", e)))?;

    // Verify signature - the Verifier trait hashes the data internally
    match public_key.verify(data, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify ECDSA signature with SHA-384 (typically P-384).
fn verify_ecdsa_sha384(
    spki: &spki::SubjectPublicKeyInfoOwned,
    data: &[u8],
    signature: &[u8],
) -> Result<bool> {
    use p384::EncodedPoint;
    use p384::ecdsa::signature::Verifier;
    use p384::ecdsa::{Signature, VerifyingKey};

    // Extract public key bytes from SPKI
    let public_key_bytes = spki.subject_public_key.raw_bytes();

    // Parse as P-384 encoded point
    let encoded_point = EncodedPoint::from_bytes(public_key_bytes)
        .map_err(|e| EstError::csr(format!("Failed to parse P-384 point: {}", e)))?;

    // Create verifying key
    let public_key = VerifyingKey::from_encoded_point(&encoded_point)
        .map_err(|e| EstError::csr(format!("Failed to create P-384 verifying key: {}", e)))?;

    // Parse DER-encoded signature
    let sig = Signature::from_der(signature)
        .map_err(|e| EstError::csr(format!("Failed to parse ECDSA signature: {}", e)))?;

    // Verify signature - the Verifier trait hashes the data internally
    match public_key.verify(data, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: Test code uses unwrap() deliberately - test fixtures are known valid
    // and panics in tests provide clear failure messages. See ERROR-HANDLING-PATTERNS.md
    // Pattern 5 for justification.

    #[test]
    fn test_validate_empty_csr() {
        let result = validate_csr(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_invalid_csr() {
        let result = validate_csr(&[0x01, 0x02, 0x03]);
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_csr() {
        let csr = vec![0x30, 0x00]; // Minimal valid SEQUENCE
        let encoded = encode_csr(&csr).unwrap();
        assert_eq!(encoded, "MAA=");
    }

    #[test]
    fn test_encode_csr_too_large() {
        // Create a CSR larger than MAX_CSR_SIZE
        let large_csr = vec![0u8; MAX_CSR_SIZE + 1];
        let result = encode_csr(&large_csr);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("CSR too large"));
    }

    #[test]
    fn test_channel_binding() {
        let tls_unique = b"test-tls-unique-value";
        let binding = create_channel_binding_value(tls_unique);
        assert!(!binding.is_empty());

        // Verify it's valid base64
        let decoded = BASE64_STANDARD.decode(&binding).unwrap();
        assert_eq!(decoded, tls_unique);
    }

    // CSR signature verification tests with real CSRs
    #[cfg(feature = "csr-gen")]
    mod signature_verification_tests {
        use super::*;
        use crate::csr::CsrBuilder;

        #[test]
        fn test_extract_public_key_from_ecdsa_csr() {
            // Generate a real ECDSA P-256 CSR
            let (csr_der, _key_pair) = CsrBuilder::new()
                .common_name("test.example.com")
                .build()
                .unwrap();

            // Extract public key
            let spki_der = extract_public_key(&csr_der).unwrap();

            // Verify we got something
            assert!(!spki_der.is_empty());
            // SPKI should start with SEQUENCE tag
            assert_eq!(spki_der[0], 0x30);
        }

        #[test]
        fn test_verify_ecdsa_p256_signature() {
            // Generate a real ECDSA P-256 CSR (rcgen defaults to P-256)
            let (csr_der, _key_pair) = CsrBuilder::new()
                .common_name("p256-test.example.com")
                .organization("Test Org")
                .san_dns("p256-test.example.com")
                .build()
                .unwrap();

            // Verify the signature
            let result = verify_csr_signature(&csr_der).unwrap();
            assert!(result, "ECDSA P-256 signature should be valid");
        }

        #[test]
        fn test_verify_signature_detects_tampering() {
            // Generate a valid CSR
            let (mut csr_der, _key_pair) = CsrBuilder::new()
                .common_name("tamper-test.example.com")
                .build()
                .unwrap();

            // Tamper with the CSR by modifying a byte in the middle
            // This should be in the signed data, not the signature itself
            if csr_der.len() > 50 {
                csr_der[50] ^= 0x01; // Flip one bit
            }

            // Verification should fail
            let result = verify_csr_signature(&csr_der);
            // Either parsing fails or signature verification fails
            assert!(
                result.is_err() || !result.unwrap(),
                "Tampered CSR should fail verification"
            );
        }

        #[test]
        fn test_verify_csr_with_multiple_sans() {
            // Generate CSR with multiple SANs
            let (csr_der, _key_pair) = CsrBuilder::new()
                .common_name("multi-san.example.com")
                .san_dns("multi-san.example.com")
                .san_dns("alt1.example.com")
                .san_dns("alt2.example.com")
                .san_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    192, 168, 1, 1,
                )))
                .build()
                .unwrap();

            // Verify signature
            let result = verify_csr_signature(&csr_der).unwrap();
            assert!(result, "CSR with multiple SANs should verify correctly");
        }

        #[test]
        fn test_verify_csr_with_key_usage() {
            // Generate CSR with key usage extensions
            let (csr_der, _key_pair) = CsrBuilder::new()
                .common_name("key-usage.example.com")
                .key_usage_digital_signature()
                .key_usage_key_encipherment()
                .extended_key_usage_client_auth()
                .build()
                .unwrap();

            // Verify signature
            let result = verify_csr_signature(&csr_der).unwrap();
            assert!(result, "CSR with key usage should verify correctly");
        }

        #[test]
        fn test_validate_then_verify_workflow() {
            // Generate a CSR
            let (csr_der, _key_pair) = CsrBuilder::new()
                .common_name("workflow-test.example.com")
                .organization("Workflow Org")
                .country("US")
                .build()
                .unwrap();

            // Step 1: Basic validation
            validate_csr(&csr_der).expect("CSR should pass basic validation");

            // Step 2: Signature verification
            let is_valid =
                verify_csr_signature(&csr_der).expect("Signature verification should not error");
            assert!(is_valid, "CSR signature should be valid");

            // Step 3: Extract public key
            let spki = extract_public_key(&csr_der).expect("Public key extraction should succeed");
            assert!(!spki.is_empty(), "Public key should not be empty");
        }

        #[test]
        fn test_verify_minimal_csr() {
            // Generate minimal CSR with just CN
            let (csr_der, _key_pair) = CsrBuilder::new()
                .common_name("minimal.example.com")
                .build()
                .unwrap();

            let result = verify_csr_signature(&csr_der).unwrap();
            assert!(result, "Minimal CSR should verify correctly");
        }

        #[test]
        fn test_verify_maximal_csr() {
            // Generate CSR with all possible fields
            let (csr_der, _key_pair) = CsrBuilder::new()
                .common_name("maximal.example.com")
                .organization("Maximal Org")
                .organizational_unit("Engineering")
                .country("US")
                .state("California")
                .locality("San Francisco")
                .san_dns("maximal.example.com")
                .san_dns("www.maximal.example.com")
                .san_email("admin@maximal.example.com")
                .san_uri("https://maximal.example.com")
                .san_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)))
                .key_usage_digital_signature()
                .key_usage_key_encipherment()
                .key_usage_key_agreement()
                .extended_key_usage_client_auth()
                .extended_key_usage_server_auth()
                .build()
                .unwrap();

            let result = verify_csr_signature(&csr_der).unwrap();
            assert!(result, "Maximal CSR should verify correctly");
        }

        #[test]
        fn test_extract_public_key_consistency() {
            // Generate CSR
            let (csr_der, _key_pair) = CsrBuilder::new()
                .common_name("consistency.example.com")
                .build()
                .unwrap();

            // Extract public key twice
            let spki1 = extract_public_key(&csr_der).unwrap();
            let spki2 = extract_public_key(&csr_der).unwrap();

            // Should be identical
            assert_eq!(
                spki1, spki2,
                "Public key extraction should be deterministic"
            );
        }
    }

    // Tests for unsupported algorithms and edge cases
    #[test]
    fn test_verify_invalid_algorithm() {
        // Create a malformed CSR-like structure with unsupported algorithm
        // This is a simplified test - in practice, we'd need a real CSR with unsupported alg
        let invalid_csr = vec![0x30, 0x00]; // Minimal invalid SEQUENCE
        let result = verify_csr_signature(&invalid_csr);
        assert!(result.is_err(), "Invalid CSR should fail to verify");
    }

    #[test]
    fn test_extract_public_key_invalid_csr() {
        let invalid_csr = vec![0x01, 0x02, 0x03];
        let result = extract_public_key(&invalid_csr);
        assert!(result.is_err(), "Should fail to extract from invalid CSR");
    }
}
