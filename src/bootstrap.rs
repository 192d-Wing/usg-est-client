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

//! Bootstrap/TOFU (Trust On First Use) mode for EST clients.
//!
//! This module provides utilities for bootstrapping EST clients when
//! the CA certificate is not known in advance. Per RFC 7030 Section 4.1.1,
//! the client can fetch CA certificates without prior trust and then
//! verify them out-of-band (e.g., by comparing fingerprints).

use sha2::{Digest, Sha256};
use url::Url;
use x509_cert::Certificate;

use crate::error::{EstError, Result};
use crate::types::{CaCertificates, operations, parse_certs_only};

/// Bootstrap client for initial CA certificate discovery.
///
/// This client fetches CA certificates from an EST server without
/// verifying the server's TLS certificate. The fetched certificates
/// should be verified out-of-band before use.
///
/// # Security Warning
///
/// This mode disables TLS server verification and should only be used
/// for initial bootstrapping. The received certificates MUST be verified
/// using out-of-band methods (e.g., fingerprint comparison) before being
/// trusted.
///
/// # Example
///
/// ```no_run
/// use usg_est_client::bootstrap::BootstrapClient;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let client = BootstrapClient::new("https://est.example.com")?;
///
/// let (certs, fingerprints) = client.fetch_ca_certs().await?;
///
/// // Display fingerprints for out-of-band verification
/// for (cert, fp) in certs.iter().zip(fingerprints.iter()) {
///     println!("Certificate: {}", BootstrapClient::get_subject_cn(cert).unwrap_or_default());
///     println!("Fingerprint: {}", BootstrapClient::format_fingerprint(fp));
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct BootstrapClient {
    /// EST server URL.
    server_url: Url,

    /// Optional CA label.
    ca_label: Option<String>,
}

impl BootstrapClient {
    /// Create a new bootstrap client.
    pub fn new(server_url: impl AsRef<str>) -> Result<Self> {
        let url = Url::parse(server_url.as_ref())?;
        Ok(Self {
            server_url: url,
            ca_label: None,
        })
    }

    /// Create a new bootstrap client with a CA label.
    pub fn with_ca_label(server_url: impl AsRef<str>, ca_label: impl Into<String>) -> Result<Self> {
        let url = Url::parse(server_url.as_ref())?;
        Ok(Self {
            server_url: url,
            ca_label: Some(ca_label.into()),
        })
    }

    /// Fetch CA certificates without TLS verification.
    ///
    /// Returns the certificates and their SHA-256 fingerprints.
    ///
    /// # Security Warning
    ///
    /// The returned certificates are NOT verified. You MUST verify them
    /// using out-of-band methods before trusting them.
    pub async fn fetch_ca_certs(&self) -> Result<(CaCertificates, Vec<[u8; 32]>)> {
        let url = self.build_url(operations::CACERTS);
        tracing::warn!(
            "Fetching CA certificates in bootstrap mode (no TLS verification): {}",
            url
        );

        // Build client with TLS verification disabled
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| EstError::tls(format!("Failed to build bootstrap client: {}", e)))?;

        let response = client.get(url).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let message = response.text().await.unwrap_or_default();
            return Err(EstError::server_error(status.as_u16(), message));
        }

        let body = response.bytes().await?;
        let certs = parse_certs_only(&body)?;

        // Compute fingerprints
        let fingerprints = certs
            .iter()
            .map(Self::compute_fingerprint)
            .collect::<Result<Vec<_>>>()?;

        Ok((CaCertificates::new(certs), fingerprints))
    }

    /// Build the URL for an EST operation.
    fn build_url(&self, operation: &str) -> Url {
        let mut url = self.server_url.clone();

        let path = if let Some(ref label) = self.ca_label {
            format!("/.well-known/est/{}/{}", label, operation)
        } else {
            format!("/.well-known/est/{}", operation)
        };

        url.set_path(&path);
        url
    }

    /// Compute the SHA-256 fingerprint of a certificate.
    pub fn compute_fingerprint(cert: &Certificate) -> Result<[u8; 32]> {
        use der::Encode;

        let der = cert
            .to_der()
            .map_err(|e| EstError::certificate_parsing(format!("Failed to encode cert: {}", e)))?;

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

    /// Parse a fingerprint from a colon-separated hex string.
    pub fn parse_fingerprint(s: &str) -> Result<[u8; 32]> {
        let bytes: Vec<u8> = s
            .split(':')
            .map(|hex| {
                u8::from_str_radix(hex.trim(), 16)
                    .map_err(|_| EstError::bootstrap_verification("Invalid fingerprint format"))
            })
            .collect::<Result<Vec<_>>>()?;

        if bytes.len() != 32 {
            return Err(EstError::bootstrap_verification(
                "Fingerprint must be 32 bytes (SHA-256)",
            ));
        }

        let mut fp = [0u8; 32];
        fp.copy_from_slice(&bytes);
        Ok(fp)
    }

    /// Verify a certificate against an expected fingerprint.
    pub fn verify_fingerprint(cert: &Certificate, expected: &[u8; 32]) -> Result<bool> {
        let actual = Self::compute_fingerprint(cert)?;
        Ok(&actual == expected)
    }

    /// Get the common name from a certificate's subject.
    pub fn get_subject_cn(cert: &Certificate) -> Option<String> {
        use const_oid::db::rfc4519::CN;

        for rdn in cert.tbs_certificate.subject.0.iter() {
            for atv in rdn.0.iter() {
                if atv.oid == CN
                    && let Ok(s) = std::str::from_utf8(atv.value.value())
                {
                    return Some(s.to_string());
                }
            }
        }
        None
    }

    /// Interactive verification helper.
    ///
    /// This provides a callback-based verification flow where the caller
    /// can prompt the user to verify fingerprints.
    pub async fn fetch_and_verify<F>(&self, verify_callback: F) -> Result<CaCertificates>
    where
        F: Fn(&Certificate, &[u8; 32]) -> bool,
    {
        let (certs, fingerprints) = self.fetch_ca_certs().await?;

        for (cert, fp) in certs.iter().zip(fingerprints.iter()) {
            if !verify_callback(cert, fp) {
                return Err(EstError::bootstrap_verification(format!(
                    "Fingerprint verification failed for: {}",
                    Self::get_subject_cn(cert).unwrap_or_else(|| "unknown".to_string())
                )));
            }
        }

        Ok(certs)
    }
}

/// Verify a list of certificates against expected fingerprints.
pub fn verify_all_fingerprints(certs: &CaCertificates, expected: &[[u8; 32]]) -> Result<bool> {
    if certs.len() != expected.len() {
        return Ok(false);
    }

    for (cert, exp_fp) in certs.iter().zip(expected.iter()) {
        if !BootstrapClient::verify_fingerprint(cert, exp_fp)? {
            return Ok(false);
        }
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: Test code uses unwrap() deliberately - test fixtures are known valid
    // and panics in tests provide clear failure messages. See ERROR-HANDLING-PATTERNS.md
    // Pattern 5 for justification.

    #[test]
    fn test_format_fingerprint() {
        let fp = [0xABu8; 32];
        let formatted = BootstrapClient::format_fingerprint(&fp);
        assert!(formatted.starts_with("AB:AB:AB"));
        assert_eq!(formatted.len(), 95); // 32 * 2 + 31 colons
    }

    #[test]
    fn test_parse_fingerprint() {
        let s = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:\
                 AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89";
        let fp = BootstrapClient::parse_fingerprint(s).unwrap();
        assert_eq!(fp[0], 0xAB);
        assert_eq!(fp[1], 0xCD);
    }

    #[test]
    fn test_parse_fingerprint_invalid() {
        // Too short
        let result = BootstrapClient::parse_fingerprint("AB:CD");
        assert!(result.is_err());

        // Invalid hex
        let result = BootstrapClient::parse_fingerprint("ZZ:ZZ:ZZ");
        assert!(result.is_err());
    }

    #[test]
    fn test_url_building() {
        let client = BootstrapClient::new("https://est.example.com").unwrap();
        let url = client.build_url("cacerts");
        assert_eq!(
            url.as_str(),
            "https://est.example.com/.well-known/est/cacerts"
        );

        let client_with_label =
            BootstrapClient::with_ca_label("https://est.example.com", "myca").unwrap();
        let url = client_with_label.build_url("cacerts");
        assert_eq!(
            url.as_str(),
            "https://est.example.com/.well-known/est/myca/cacerts"
        );
    }
}
