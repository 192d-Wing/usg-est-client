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

//! TLS configuration helpers for the EST client.
//!
//! This module provides functions for building TLS configurations
//! compatible with RFC 7030 requirements.

use std::sync::Arc;

use rustls::ClientConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

use crate::config::{ClientIdentity, EstClientConfig, TrustAnchors};
use crate::error::{EstError, Result};

// Minimum TLS version required by RFC 7030.
//
// RFC 7030 Section 3.3.1 states: "TLS 1.1 [RFC4346] (or a later version) MUST be used"
// We use TLS 1.2 as the minimum since TLS 1.1 is deprecated.

/// Build a reqwest Client with the appropriate TLS configuration.
pub fn build_http_client(config: &EstClientConfig) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(config.timeout)
        .tls_backend_rustls();

    // Configure TLS based on trust anchors
    match &config.trust_anchors {
        TrustAnchors::WebPki => {
            // Use built-in roots provided by the rustls backend
            builder = builder.tls_backend_rustls();
        }
        TrustAnchors::Explicit(ca_certs) => {
            let mut certs = Vec::with_capacity(ca_certs.len());
            for ca_pem in ca_certs {
                let cert = reqwest::Certificate::from_pem(ca_pem)
                    .map_err(|e| EstError::tls(format!("Failed to parse CA certificate: {}", e)))?;
                certs.push(cert);
            }
            builder = builder.tls_backend_rustls().tls_certs_only(certs);
        }
        TrustAnchors::Bootstrap(_) => {
            // Bootstrap mode still needs some trust for the initial connection
            // The actual verification happens after fetching certificates
            builder = builder
                .tls_backend_rustls()
                .tls_certs_only(Vec::new())
                .danger_accept_invalid_certs(true);
        }
        TrustAnchors::InsecureAcceptAny => {
            builder = builder
                .tls_backend_rustls()
                .tls_certs_only(Vec::new())
                .danger_accept_invalid_certs(true);
        }
    }

    // Configure client certificate authentication
    if let Some(ref identity) = config.client_identity {
        let identity = build_reqwest_identity(identity)?;
        builder = builder.identity(identity);
    }

    // Add HTTP Basic auth if configured
    if let Some(ref http_auth) = config.http_auth {
        // Note: reqwest handles basic auth per-request, not at client level
        // We'll add the header in the request methods instead
        let _ = http_auth; // Acknowledge the field, auth is handled per-request
    }

    // Enforce minimum TLS version
    builder = builder.min_tls_version(reqwest::tls::Version::TLS_1_2);

    // Add additional headers
    let mut headers = reqwest::header::HeaderMap::new();
    for (name, value) in &config.additional_headers {
        if let (Ok(name), Ok(value)) = (
            reqwest::header::HeaderName::try_from(name.as_str()),
            reqwest::header::HeaderValue::try_from(value.as_str()),
        ) {
            headers.insert(name, value);
        }
    }
    builder = builder.default_headers(headers);

    builder
        .build()
        .map_err(|e| EstError::tls(format!("Failed to build HTTP client: {}", e)))
}

/// Build a reqwest Identity from PEM-encoded certificate and key.
fn build_reqwest_identity(identity: &ClientIdentity) -> Result<reqwest::Identity> {
    // Combine cert and key into a single PEM buffer for reqwest
    let mut pem_data = identity.cert_pem.clone();
    pem_data.extend_from_slice(b"\n");
    pem_data.extend_from_slice(&identity.key_pem);

    reqwest::Identity::from_pem(&pem_data)
        .map_err(|e| EstError::tls(format!("Failed to create client identity: {}", e)))
}

/// Build a rustls ClientConfig for advanced TLS operations.
///
/// This is used when we need more control over TLS, such as for
/// channel binding or certificate fingerprinting.
pub fn build_rustls_config(config: &EstClientConfig) -> Result<Arc<ClientConfig>> {
    let root_store = build_root_store(&config.trust_anchors)?;

    let builder = ClientConfig::builder().with_root_certificates(root_store);

    let tls_config = if let Some(ref identity) = config.client_identity {
        let (certs, key) = parse_client_identity(identity)?;
        builder
            .with_client_auth_cert(certs, key)
            .map_err(|e| EstError::tls(format!("Failed to configure client auth: {}", e)))?
    } else {
        builder.with_no_client_auth()
    };

    Ok(Arc::new(tls_config))
}

/// Build a rustls RootCertStore from trust anchor configuration.
fn build_root_store(trust_anchors: &TrustAnchors) -> Result<rustls::RootCertStore> {
    let mut root_store = rustls::RootCertStore::empty();

    match trust_anchors {
        TrustAnchors::WebPki => {
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        TrustAnchors::Explicit(ca_certs) => {
            for ca_pem in ca_certs {
                let certs = parse_pem_certificates(ca_pem)?;
                for cert in certs {
                    root_store
                        .add(cert)
                        .map_err(|e| EstError::tls(format!("Failed to add CA cert: {}", e)))?;
                }
            }
        }
        TrustAnchors::Bootstrap(_) | TrustAnchors::InsecureAcceptAny => {
            // Empty root store - verification is handled differently
        }
    }

    Ok(root_store)
}

/// Parse PEM-encoded certificates.
///
/// # Security
///
/// This function logs warnings for any invalid certificates found in the PEM data
/// to help detect potential issues with certificate chains.
pub fn parse_pem_certificates(pem_data: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    use tracing::warn;

    let mut certs = Vec::new();
    let mut cert_count = 0;
    let mut error_count = 0;

    for result in CertificateDer::pem_slice_iter(pem_data) {
        cert_count += 1;
        match result {
            Ok(cert) => certs.push(cert),
            Err(e) => {
                error_count += 1;
                warn!(
                    certificate_index = cert_count,
                    error = %e,
                    "Failed to parse certificate from PEM data"
                );
            }
        }
    }

    if error_count > 0 {
        warn!(
            valid_certificates = certs.len(),
            invalid_certificates = error_count,
            "Some certificates in PEM data could not be parsed"
        );
    }

    if certs.is_empty() {
        return Err(EstError::invalid_pem(
            "No valid certificates found in PEM data",
        ));
    }

    Ok(certs)
}

/// Parse a PEM-encoded private key.
pub fn parse_pem_private_key(pem_data: &[u8]) -> Result<PrivateKeyDer<'static>> {
    // Try to parse as PKCS#8, PKCS#1, or SEC1 format
    PrivateKeyDer::from_pem_slice(pem_data)
        .map_err(|e| EstError::invalid_pem(format!("Failed to parse private key PEM: {}", e)))
}

/// Parse client identity from PEM data.
fn parse_client_identity(
    identity: &ClientIdentity,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let certs = parse_pem_certificates(&identity.cert_pem)?;
    let key = parse_pem_private_key(&identity.key_pem)?;
    Ok((certs, key))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test PEM certificate (self-signed, for testing only)
    const TEST_CERT_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpegGZk6MAoGCCqGSM49BAMCMBQxEjAQBgNVBAMMCWxvY2Fs
aG9zdDAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBQxEjAQBgNVBAMM
CWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHpCKhniVsMP7mq5
RFBmRFU3FWLG37xCBsFGbofKbCb3BQDBgbM+cLzvU1K/W+XU0j9KNLRKzpPOZhZT
0ey8LZqjUzBRMB0GA1UdDgQWBBQn6H4PvSHYznjDjZJPYKzLcl3Z3zAfBgNVHSME
GDAWgBQn6H4PvSHYznjDjZJPYKzLcl3Z3zAPBgNVHRMBAf8EBTADAQH/MAoGCCqG
SM49BAMCA0gAMEUCIQC9Yz5aKJh3VJSTXKQMl5BTIJWZb5a1Y5LVBxQrJdoYewIg
MfKu7DVxg+Q4IVsBsP7oVNRDX6qYIexKMPREQ8MzCHM=
-----END CERTIFICATE-----";

    const TEST_KEY_PEM: &[u8] = b"-----BEGIN EC PRIVATE KEY-----
MHQCAQEEILVq8H9rE4bJBqXKLm/a3XpNdrXqAR3xjNYq/8U1N4zQoAcGBSuBBAAK
oUQDQgAEekIqGeJWww/uarlEUGZEVTcVYsbfvEIGwUZuh8psJvcFAMGBsz5wvO9T
Ur9b5dTSP0o0tErOk85mFlPR7Lwtmg==
-----END EC PRIVATE KEY-----";

    #[test]
    fn test_parse_pem_certificates() {
        let certs = parse_pem_certificates(TEST_CERT_PEM).unwrap();
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn test_parse_pem_private_key() {
        let key = parse_pem_private_key(TEST_KEY_PEM).unwrap();
        assert!(matches!(key, PrivateKeyDer::Sec1(_)));
    }

    #[test]
    fn test_invalid_pem() {
        let result = parse_pem_certificates(b"not valid pem");
        assert!(result.is_err());
    }
}
