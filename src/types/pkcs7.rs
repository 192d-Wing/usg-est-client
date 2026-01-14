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

//! PKCS#7/CMS parsing utilities.
//!
//! This module provides functions for parsing PKCS#7/CMS structures
//! used in EST responses, particularly the "certs-only" SignedData format.

use base64::prelude::*;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::{Decode, Encode};
use x509_cert::Certificate;

use crate::error::{EstError, Result};

/// Collection of CA certificates returned from the /cacerts endpoint.
#[derive(Debug, Clone)]
pub struct CaCertificates {
    /// The CA certificates.
    pub certificates: Vec<Certificate>,
}

impl CaCertificates {
    /// Create a new CA certificates collection.
    pub fn new(certificates: Vec<Certificate>) -> Self {
        Self { certificates }
    }

    /// Returns true if the collection is empty.
    pub fn is_empty(&self) -> bool {
        self.certificates.is_empty()
    }

    /// Returns the number of certificates.
    pub fn len(&self) -> usize {
        self.certificates.len()
    }

    /// Get the first (root) certificate, if any.
    pub fn root(&self) -> Option<&Certificate> {
        self.certificates.first()
    }

    /// Iterate over the certificates.
    pub fn iter(&self) -> impl Iterator<Item = &Certificate> {
        self.certificates.iter()
    }
}

impl IntoIterator for CaCertificates {
    type Item = Certificate;
    type IntoIter = std::vec::IntoIter<Certificate>;

    fn into_iter(self) -> Self::IntoIter {
        self.certificates.into_iter()
    }
}

impl<'a> IntoIterator for &'a CaCertificates {
    type Item = &'a Certificate;
    type IntoIter = std::slice::Iter<'a, Certificate>;

    fn into_iter(self) -> Self::IntoIter {
        self.certificates.iter()
    }
}

/// Parse a PKCS#7 certs-only response.
///
/// This parses the CMS SignedData structure used in EST responses for
/// /cacerts, /simpleenroll, and /simplereenroll endpoints.
///
/// The response body should be base64-encoded DER.
pub fn parse_certs_only(body: &[u8]) -> Result<Vec<Certificate>> {
    // Decode base64
    let der_bytes = decode_base64(body)?;

    // Parse ContentInfo
    let content_info = ContentInfo::from_der(&der_bytes)
        .map_err(|e| EstError::cms_parsing(format!("Failed to parse ContentInfo: {}", e)))?;

    // Extract SignedData
    let signed_data = extract_signed_data(&content_info)?;

    // Extract certificates
    extract_certificates(&signed_data)
}

/// Parse a PKCS#7 response that may contain a single certificate.
///
/// Used for enrollment responses where we expect exactly one certificate.
#[allow(dead_code)]
pub fn parse_single_certificate(body: &[u8]) -> Result<Certificate> {
    let mut certs = parse_certs_only(body)?;

    match certs.len() {
        0 => Err(EstError::cms_parsing("No certificate in response")),
        1 => Ok(certs.remove(0)),
        n => {
            // Return the first certificate (the issued one)
            // Additional certificates are typically the CA chain
            tracing::debug!("Response contains {} certificates, using first", n);
            Ok(certs.remove(0))
        }
    }
}

/// Decode base64 data, handling various line ending formats.
fn decode_base64(data: &[u8]) -> Result<Vec<u8>> {
    // Strip whitespace and decode
    let cleaned: Vec<u8> = data
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();

    BASE64_STANDARD.decode(&cleaned).map_err(EstError::Base64)
}

/// Extract SignedData from ContentInfo.
fn extract_signed_data(content_info: &ContentInfo) -> Result<SignedData> {
    // OID for SignedData: 1.2.840.113549.1.7.2
    const SIGNED_DATA_OID: &str = "1.2.840.113549.1.7.2";

    let oid_str = content_info.content_type.to_string();
    if oid_str != SIGNED_DATA_OID {
        return Err(EstError::cms_parsing(format!(
            "Expected SignedData OID, got {}",
            oid_str
        )));
    }

    let content = content_info
        .content
        .to_der()
        .map_err(|e| EstError::cms_parsing(format!("Failed to encode content: {}", e)))?;

    SignedData::from_der(&content)
        .map_err(|e| EstError::cms_parsing(format!("Failed to parse SignedData: {}", e)))
}

/// Extract certificates from SignedData.
fn extract_certificates(signed_data: &SignedData) -> Result<Vec<Certificate>> {
    let cert_set = match &signed_data.certificates {
        Some(certs) => certs,
        None => return Ok(Vec::new()),
    };

    let mut certificates = Vec::new();

    for cert_choice in cert_set.0.iter() {
        // CertificateChoices can be Certificate, ExtendedCertificate, or AttributeCertificate
        // We only handle standard X.509 certificates
        let cert_der = cert_choice
            .to_der()
            .map_err(|e| EstError::cms_parsing(format!("Failed to encode certificate: {}", e)))?;

        match Certificate::from_der(&cert_der) {
            Ok(cert) => certificates.push(cert),
            Err(e) => {
                tracing::warn!("Skipping non-X.509 certificate: {}", e);
            }
        }
    }

    Ok(certificates)
}

/// Encode a certificate to base64 DER format.
#[allow(dead_code)]
pub fn encode_certificate_base64(cert: &Certificate) -> Result<String> {
    let der = cert.to_der().map_err(|e| {
        EstError::certificate_parsing(format!("Failed to encode certificate: {}", e))
    })?;

    Ok(BASE64_STANDARD.encode(&der))
}

/// Encode DER data to base64 with line wrapping.
///
/// Per RFC 7030, responses use base64 Content-Transfer-Encoding.
#[allow(dead_code)]
pub fn encode_base64_wrapped(data: &[u8], line_length: usize) -> String {
    let encoded = BASE64_STANDARD.encode(data);

    // Wrap lines
    encoded
        .as_bytes()
        .chunks(line_length)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<_>>()
        .join("\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: Test code uses unwrap() deliberately - test fixtures are known valid
    // and panics in tests provide clear failure messages. See ERROR-HANDLING-PATTERNS.md
    // Pattern 5 for justification.

    #[test]
    fn test_decode_base64_with_whitespace() {
        let data = b"SGVs\nbG8g\r\nV29ybGQ=";
        let decoded = decode_base64(data).unwrap();
        assert_eq!(decoded, b"Hello World");
    }

    #[test]
    fn test_encode_base64_wrapped() {
        let data = b"Hello World, this is a test of base64 encoding with line wrapping";
        let encoded = encode_base64_wrapped(data, 20);
        assert!(encoded.contains("\r\n"));
    }

    #[test]
    fn test_ca_certificates_iteration() {
        let certs = CaCertificates::new(vec![]);
        assert!(certs.is_empty());
        assert_eq!(certs.len(), 0);
    }
}
