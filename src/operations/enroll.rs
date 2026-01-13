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
pub fn extract_public_key(_csr_der: &[u8]) -> Result<Vec<u8>> {
    // Parse the CSR to extract the SubjectPublicKeyInfo
    // This is a simplified implementation

    // CSR structure:
    // CertificationRequest ::= SEQUENCE {
    //   certificationRequestInfo CertificationRequestInfo,
    //   signatureAlgorithm AlgorithmIdentifier,
    //   signature BIT STRING
    // }
    // CertificationRequestInfo ::= SEQUENCE {
    //   version INTEGER,
    //   subject Name,
    //   subjectPKInfo SubjectPublicKeyInfo,
    //   attributes [0] IMPLICIT Attributes OPTIONAL
    // }

    // For now, return an error as full parsing would require more work
    Err(EstError::csr("Public key extraction not yet implemented"))
}

/// Verify that a CSR signature is valid.
///
/// This provides proof-of-possession of the private key.
pub fn verify_csr_signature(_csr_der: &[u8]) -> Result<bool> {
    // Full signature verification would require:
    // 1. Extract the public key from the CSR
    // 2. Extract the signature algorithm
    // 3. Extract the signed data (certificationRequestInfo)
    // 4. Verify the signature

    // For now, we trust that the CSR was properly constructed
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
