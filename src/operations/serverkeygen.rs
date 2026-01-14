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

//! Server-side Key Generation operation (POST /serverkeygen).
//!
//! This module provides utilities for the server-side key generation
//! operation defined in RFC 7030 Section 4.4.

use crate::error::{EstError, Result};

/// Check if a private key response is encrypted.
///
/// Per RFC 7030 Section 4.4.2, the server may return the private key
/// encrypted using CMS EnvelopedData.
pub fn is_key_encrypted(key_data: &[u8]) -> bool {
    // EnvelopedData OID: 1.2.840.113549.1.7.3
    // Check for the OID in the first few bytes
    // A more robust check would fully parse the CMS structure

    if key_data.len() < 20 {
        return false;
    }

    // Look for EnvelopedData OID bytes
    let enveloped_data_oid = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x03];

    for window in key_data.windows(enveloped_data_oid.len()) {
        if window == enveloped_data_oid {
            return true;
        }
    }

    false
}

/// Decrypt an encrypted private key.
///
/// This handles CMS EnvelopedData decryption when the server has
/// encrypted the private key for secure transport.
pub fn decrypt_private_key(_encrypted_key: &[u8], _decryption_key: &[u8]) -> Result<Vec<u8>> {
    // Full implementation would require:
    // 1. Parse CMS EnvelopedData
    // 2. Extract RecipientInfo
    // 3. Decrypt the content encryption key
    // 4. Decrypt the private key

    Err(EstError::not_supported(
        "Encrypted private key decryption not yet implemented",
    ))
}

/// Parse a PKCS#8 private key.
pub fn parse_pkcs8_key(key_data: &[u8]) -> Result<PrivateKeyInfo> {
    // Parse the DER-encoded PKCS#8 structure
    // For now, just wrap the raw bytes
    // Full parsing would use the pkcs8 crate

    Ok(PrivateKeyInfo {
        algorithm: Vec::new(), // Would extract from parsed structure
        private_key: key_data.to_vec(),
    })
}

/// Private key information extracted from server keygen response.
#[derive(Debug, Clone)]
pub struct PrivateKeyInfo {
    /// Algorithm identifier (DER-encoded).
    pub algorithm: Vec<u8>,

    /// Private key bytes.
    pub private_key: Vec<u8>,
}

impl PrivateKeyInfo {
    /// Export the private key in PEM format.
    pub fn to_pem(&self) -> String {
        use base64::prelude::*;

        let b64 = BASE64_STANDARD.encode(&self.private_key);

        // Wrap at 64 characters
        let wrapped: Vec<&str> = b64
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();

        format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            wrapped.join("\n")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: Test code uses unwrap() deliberately - test fixtures are known valid
    // and panics in tests provide clear failure messages. See ERROR-HANDLING-PATTERNS.md
    // Pattern 5 for justification.

    #[test]
    fn test_is_key_encrypted() {
        // Unencrypted key (plain PKCS#8)
        let plain_key = vec![0x30, 0x82, 0x01, 0x00]; // SEQUENCE
        assert!(!is_key_encrypted(&plain_key));

        // Too short
        let short = vec![0x30];
        assert!(!is_key_encrypted(&short));
    }

    #[test]
    fn test_private_key_pem() {
        let key_info = PrivateKeyInfo {
            algorithm: vec![],
            private_key: vec![0x30, 0x82, 0x01, 0x00],
        };

        let pem = key_info.to_pem();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(pem.ends_with("-----END PRIVATE KEY-----\n"));
    }
}
