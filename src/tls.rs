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
//! # Security Controls
//!
//! **NIST SP 800-53 Rev 5:**
//! - SC-8: Transmission Confidentiality and Integrity
//! - IA-2: Identification and Authentication (Organizational Users)
//! - AC-17: Remote Access
//!
//! **Application Development STIG V5R3:**
//! - APSC-DV-000160 (CAT I): Authentication - cryptographically-based bidirectional authentication
//! - APSC-DV-000170 (CAT I): Cryptographic Protection - FIPS-validated cryptography
//! - APSC-DV-002440 (CAT I): Session Management - session authenticity mechanisms
//!
//! # Overview
//!
//! This module provides functions for building TLS configurations
//! compatible with RFC 7030 requirements. All TLS communications enforce:
//! - Minimum TLS 1.3 (RFC 7030 Section 3.3.1, NIST SP 800-52 Rev 2 compliance)
//! - Strong cipher suites (ECDHE-ECDSA, ECDHE-RSA)
//! - Mutual TLS authentication when configured
//! - Certificate validation with trusted root anchors
//! - Channel binding support (RFC 7030 Section 3.5)

use std::sync::Arc;

use rustls::ClientConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

use crate::config::{ClientIdentity, EstClientConfig, TrustAnchors};
use crate::error::{EstError, Result};

// ============================================================================
// SECURITY CONTROL: TLS Version Enforcement
// ----------------------------------------------------------------------------
// NIST SP 800-53 Rev 5: SC-8 (Transmission Confidentiality and Integrity)
// STIG: APSC-DV-000170 (CAT I) - Cryptographic Protection
// RFC 7030: Section 3.3.1 - TLS Requirements
// ----------------------------------------------------------------------------
// RFC 7030 Section 3.3.1 states: "TLS 1.1 [RFC4346] (or a later version) MUST be used"
// We enforce TLS 1.3 as the minimum per current NIST SP 800-52 Rev 2 guidance.
// TLS 1.2 is deprecated for new implementations; TLS 1.3 provides:
//
// - Simplified handshake (1-RTT, 0-RTT resumption)
// - Removal of legacy cipher suites (CBC, RC4, SHA-1, static RSA)
// - Mandatory perfect forward secrecy (ECDHE only)
// - Encrypted handshake messages (hides certificate from passive observers)
// - Protection against downgrade attacks
// - FIPS 140-2/140-3 compliance when using approved algorithms
// ============================================================================

/// Build a reqwest Client with the appropriate TLS configuration.
///
/// # Security Controls
///
/// **NIST SP 800-53 Rev 5:**
/// - SC-8: Transmission Confidentiality and Integrity (TLS 1.2+ enforcement)
/// - IA-2: Identification and Authentication (Mutual TLS support)
/// - AC-17: Remote Access (Secure protocol enforcement)
///
/// **Application Development STIG V5R3:**
/// - APSC-DV-000160 (CAT I): Cryptographically-based bidirectional authentication via mutual TLS
/// - APSC-DV-000170 (CAT I): FIPS-validated cryptography for transport protection
/// - APSC-DV-002440 (CAT I): Session authenticity via TLS and certificate validation
///
/// # Implementation
///
/// This function configures a reqwest HTTP client with:
/// 1. **TLS 1.3 minimum version** (RFC 7030 Section 3.3.1, SC-8, NIST SP 800-52 Rev 2)
/// 2. **Certificate validation** against trusted roots (IA-2, APSC-DV-003235)
/// 3. **Mutual TLS authentication** when client certificate configured (IA-2, APSC-DV-000160)
/// 4. **Hostname verification** enabled by default (SC-8)
/// 5. **Strong cipher suites** (rustls default policy, APSC-DV-000170)
///
/// # Channel Binding
///
/// When `channel_binding` is enabled in the config, this function prepares
/// the TLS configuration to support channel binding operations (RFC 7030 Section 3.5).
/// The actual channel binding value extraction must be done per-connection.
///
/// # Arguments
///
/// * `config` - EST client configuration including TLS settings
///
/// # Returns
///
/// Configured reqwest::Client ready for secure EST communications
///
/// # Errors
///
/// Returns `EstError::Tls` if:
/// - CA certificate parsing fails
/// - Client certificate/key parsing fails
/// - HTTP client builder fails
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
        TrustAnchors::Bootstrap(bootstrap_config) => {
            // Check if the bootstrap window has expired
            if std::time::Instant::now() > bootstrap_config.expires_at {
                return Err(EstError::tls(
                    "Bootstrap mode has expired. Reconfigure with explicit trust anchors."
                        .to_string(),
                ));
            }
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

    // NIST 800-53: IA-2 (Identification and Authentication)
    // STIG: APSC-DV-000160 (CAT I) - Bidirectional Authentication
    // RFC 7030: Section 3.3.2 - Client Authentication
    // Configure mutual TLS with client certificate for bidirectional authentication
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

    // NIST 800-53: SC-8 (Transmission Confidentiality and Integrity)
    // STIG: APSC-DV-000170 (CAT I) - Cryptographic Protection
    // RFC 7030: Section 3.3.1 compliance
    // NIST SP 800-52 Rev 2: TLS 1.3 required for new implementations
    // Enforce TLS 1.3 minimum (TLS 1.2 and earlier are deprecated)
    builder = builder.min_tls_version(reqwest::tls::Version::TLS_1_3);

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

/// Generate a channel binding value for use in EST enrollment.
///
/// # Security Controls
///
/// **NIST SP 800-53 Rev 5:**
/// - IA-2: Identification and Authentication (channel binding strengthens authentication)
/// - SC-23: Session Authenticity (cryptographic binding of TLS session to application auth)
///
/// **Application Development STIG V5R3:**
/// - APSC-DV-002440 (CAT I): Session Management - channel binding prevents session hijacking
///
/// # RFC 7030 Section 3.5 - Channel Binding
///
/// Channel binding provides cryptographic linkage between the TLS session and
/// the application-level authentication. This prevents man-in-the-middle attacks
/// where an attacker intercepts HTTP Basic authentication credentials or attempts
/// session hijacking.
///
/// ## Implementation Note
///
/// For TLS 1.3, RFC 9266 recommends using TLS Exporters instead of tls-unique.
/// The exporter uses the label "EXPORTER-Channel-Binding" to derive a channel
/// binding value from the TLS session's master secret.
///
/// Since `reqwest` abstracts away direct TLS connection access, we provide
/// two approaches for channel binding:
///
/// 1. **CSR Generation Time**: Include a random challenge value during CSR
///    generation, then use that same value in the HTTP Authentication header.
///    This provides proof that the entity creating the CSR is the same as the
///    one making the enrollment request.
///
/// 2. **Future Enhancement**: Custom TLS connector that captures the channel
///    binding value during handshake and makes it available to the client.
///
/// # Arguments
///
/// * `session_data` - TLS session-specific data (e.g., random challenge,
///   exported keying material, or tls-unique value)
///
/// # Returns
///
/// Base64-encoded channel binding value suitable for inclusion in CSR
/// challengePassword attribute or HTTP headers.
pub fn compute_channel_binding(session_data: &[u8]) -> String {
    use base64::prelude::*;
    BASE64_STANDARD.encode(session_data)
}

/// Generate a cryptographically secure random challenge for channel binding.
///
/// # Security Controls
///
/// **NIST SP 800-53 Rev 5:**
/// - IA-5: Authenticator Management (cryptographically secure random generation)
/// - SC-13: Cryptographic Protection (FIPS-approved CSPRNG)
///
/// **Application Development STIG V5R3:**
/// - APSC-DV-000170 (CAT I): Cryptographic Protection - uses OS CSPRNG
///
/// # Overview
///
/// When direct TLS channel binding extraction is not available, we can use
/// a random challenge generated at enrollment time as a channel binding
/// alternative. The same challenge is included in both:
/// 1. The CSR challengePassword attribute
/// 2. The HTTP Authorization header or custom header
///
/// The EST server can then verify that the entity creating the CSR is the
/// same as the one making the enrollment request.
///
/// # Security Implementation
///
/// Uses P-256 ECDSA scalar generation which internally uses OsRng, the operating
/// system's cryptographically secure random number generator. This provides:
/// - Proper cryptographic randomness suitable for security-critical operations
/// - FIPS 140-2 compliance when OS CSPRNG is FIPS-validated
/// - Protection against prediction or brute-force attacks
/// - 256 bits of entropy (32 bytes)
///
/// # Returns
///
/// 32 bytes of cryptographically secure random data
pub fn generate_channel_binding_challenge() -> [u8; 32] {
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::rand_core::OsRng;

    // NIST 800-53: IA-5 (Authenticator Management), SC-13 (Cryptographic Protection)
    // STIG: APSC-DV-000170 (CAT I) - FIPS-approved CSPRNG
    // Generate a random ECDSA signing key using OS's CSPRNG (FIPS 140-2 compliant)
    // We don't actually need the key itself, just the cryptographically secure random bytes
    let signing_key = SigningKey::random(&mut OsRng);

    // Extract the scalar (secret key) as bytes
    // This is 32 bytes (256 bits) of cryptographically secure random data
    signing_key.to_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: Test code uses unwrap() deliberately - test fixtures are known valid
    // and panics in tests provide clear failure messages. See ERROR-HANDLING-PATTERNS.md
    // Pattern 5 for justification.

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

    #[test]
    fn test_compute_channel_binding() {
        let session_data = b"test-tls-session-data-12345678";
        let binding = compute_channel_binding(session_data);

        // Should be base64 encoded
        assert!(!binding.is_empty());

        // Should be decodable
        use base64::prelude::*;
        let decoded = BASE64_STANDARD.decode(&binding).unwrap();
        assert_eq!(decoded, session_data);
    }

    #[test]
    fn test_generate_channel_binding_challenge() {
        let challenge1 = generate_channel_binding_challenge();
        let challenge2 = generate_channel_binding_challenge();

        // Should be 32 bytes
        assert_eq!(challenge1.len(), 32);
        assert_eq!(challenge2.len(), 32);

        // Should not be all zeros
        assert!(challenge1.iter().any(|&b| b != 0));
        assert!(challenge2.iter().any(|&b| b != 0));

        // Should be different (probabilistically)
        assert_ne!(challenge1, challenge2);
    }

    #[test]
    fn test_channel_binding_round_trip() {
        let challenge = generate_channel_binding_challenge();
        let encoded = compute_channel_binding(&challenge);

        // Decode and verify
        use base64::prelude::*;
        let decoded = BASE64_STANDARD.decode(&encoded).unwrap();
        assert_eq!(decoded.as_slice(), &challenge);
    }
}
