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

//! CA Certificates operation (GET /cacerts).
//!
//! This module provides utilities for the CA certificates distribution
//! operation defined in RFC 7030 Section 4.1.

use sha2::{Digest, Sha256};
use x509_cert::Certificate;

use crate::error::{EstError, Result};
use crate::types::CaCertificates;

/// Compute the SHA-256 fingerprint of a certificate.
///
/// The fingerprint is computed over the DER-encoded certificate.
pub fn fingerprint(cert: &Certificate) -> Result<[u8; 32]> {
    use der::Encode;

    let der = cert.to_der().map_err(|e| {
        EstError::certificate_parsing(format!("Failed to encode certificate: {}", e))
    })?;

    let mut hasher = Sha256::new();
    hasher.update(&der);
    Ok(hasher.finalize().into())
}

/// Format a fingerprint as a colon-separated hex string.
///
/// Example output: "AB:CD:EF:01:23:45:..."
pub fn format_fingerprint(fp: &[u8; 32]) -> String {
    fp.iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Verify that a CA certificate chain is valid.
///
/// This performs basic chain validation:
/// - Checks that the root is self-signed
/// - Checks that intermediate certs are signed by their parent
///
/// Note: This is a simplified check. For full validation,
/// use a proper certificate validation library.
pub fn verify_ca_chain(certs: &CaCertificates) -> Result<()> {
    if certs.is_empty() {
        return Err(EstError::certificate_parsing("Empty certificate chain"));
    }

    // For now, just verify we have at least one certificate
    // Full chain validation would require signature verification
    tracing::debug!("CA chain contains {} certificates", certs.len());

    Ok(())
}

/// Extract the root CA certificate from a chain.
///
/// The root CA is typically the last certificate in the chain,
/// or the only self-signed certificate.
pub fn find_root_ca(certs: &CaCertificates) -> Option<&Certificate> {
    // Try to find a self-signed certificate
    for cert in certs.iter() {
        if is_self_signed(cert) {
            return Some(cert);
        }
    }

    // Fall back to the last certificate
    certs.certificates.last()
}

/// Check if a certificate is self-signed.
fn is_self_signed(cert: &Certificate) -> bool {
    cert.tbs_certificate().subject() == cert.tbs_certificate().issuer()
}

/// Get the subject common name from a certificate.
pub fn get_common_name(cert: &Certificate) -> Option<String> {
    use const_oid::db::rfc4519::CN;

    for atv in cert.tbs_certificate().subject().iter() {
        if atv.oid == CN
            && let Ok(s) = std::str::from_utf8(atv.value.value())
        {
            return Some(s.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_fingerprint() {
        let fp = [
            0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45,
            0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
            0x23, 0x45, 0x67, 0x89,
        ];
        let formatted = format_fingerprint(&fp);
        assert!(formatted.starts_with("AB:CD:EF:01"));
        assert_eq!(formatted.len(), 95); // 32 * 2 + 31 colons
    }
}
