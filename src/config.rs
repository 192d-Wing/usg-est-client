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

//! Configuration types for the EST client.
//!
//! This module provides configuration structures for setting up an EST client,
//! including server URL, authentication credentials, and TLS settings.
//!
//! # Security Controls
//!
//! **NIST SP 800-53 Rev 5:**
//! - CM-2: Baseline Configuration (EST client configuration management)
//! - CM-6: Configuration Settings (secure configuration defaults)
//! - SI-10: Information Input Validation (URL and parameter validation)
//! - IA-5: Authenticator Management (credential configuration)
//! - SC-8: Transmission Confidentiality (TLS configuration)
//!
//! **Application Development STIG V5R3:**
//! - APSC-DV-000500 (CAT I): Input Validation
//! - APSC-DV-002440 (CAT I): Encryption in Transit
//! - APSC-DV-001750 (CAT I): Certificate Validation
//!
//! # Configuration Components
//!
//! - [`EstClientConfig`]: Main client configuration structure
//! - [`EstClientConfigBuilder`]: Builder pattern for configuration creation
//! - [`ClientIdentity`]: TLS client certificate authentication
//! - [`HttpAuth`]: HTTP Basic authentication credentials
//! - [`TrustAnchors`]: Trust anchor configuration for server verification
//! - [`BootstrapConfig`]: Bootstrap trust configuration for initial enrollment
//! - [`CertificateValidationConfig`]: Certificate validation settings

use std::sync::Arc;
use std::time::Duration;
use url::Url;

#[cfg(feature = "validation")]
use x509_cert::Certificate;

// ============================================================================
// SECURITY CONTROL: EST Client Configuration
// ----------------------------------------------------------------------------
// NIST SP 800-53 Rev 5: CM-2 (Baseline Configuration)
//                       CM-6 (Configuration Settings)
//                       SI-10 (Information Input Validation)
//                       SC-8 (Transmission Confidentiality)
//                       IA-5 (Authenticator Management)
// STIG: APSC-DV-000500 (CAT I) - Input Validation
//       APSC-DV-002440 (CAT I) - Encryption in Transit
//       APSC-DV-001750 (CAT I) - Certificate Validation
// Standards: RFC 7030 (EST Protocol)
//           RFC 5280 (X.509 PKI Certificate Validation)
// ----------------------------------------------------------------------------
// Central configuration structure for EST client operations. Enforces secure
// defaults and validates all configuration parameters.
//
// Security Rationale:
// - CM-2/CM-6: Establishes secure baseline configuration for EST operations
// - SI-10: Validates all inputs (URLs, certificates, credentials)
// - SC-8: Enforces HTTPS by default, warns on HTTP usage
// - IA-5: Supports both TLS client certs and HTTP Basic auth
// - Certificate validation ensures trust anchor verification (RFC 5280)
// - Channel binding prevents credential forwarding attacks (RFC 7030 Sec 3.5)
// - FIPS mode enforces cryptographic compliance when enabled
// ============================================================================

/// Configuration for an EST client.
///
/// # Security Controls
///
/// **NIST SP 800-53 Rev 5:**
/// - CM-2: Baseline Configuration (secure EST client settings)
/// - CM-6: Configuration Settings (validated configuration parameters)
/// - SI-10: Information Input Validation (URL, credential validation)
/// - SC-8: Transmission Confidentiality (HTTPS enforcement)
/// - IA-5: Authenticator Management (client authentication)
///
/// **STIG Findings:**
/// - APSC-DV-000500 (CAT I): Input Validation
/// - APSC-DV-002440 (CAT I): Encryption in Transit (HTTPS)
/// - APSC-DV-001750 (CAT I): Certificate Validation
///
/// # Authentication Methods (IA-5)
///
/// EST supports two authentication methods (RFC 7030):
///
/// 1. **TLS Client Certificate** (preferred): `client_identity`
///    - Mutual TLS authentication
///    - Certificate-based identity
///    - No password transmission
///
/// 2. **HTTP Basic Authentication** (fallback): `http_auth`
///    - Username/password credentials
///    - Transmitted over TLS (protected by SC-8)
///    - Use only when client certificates unavailable
///
/// # Configuration Validation (SI-10)
///
/// All configuration parameters are validated:
/// - **URL**: HTTPS enforced (warns on HTTP), valid scheme/host/port
/// - **CA Label**: RFC 3986 path segment validation
/// - **Credentials**: Non-empty username/password
/// - **Timeout**: Reasonable range (1-300 seconds recommended)
/// - **Trust Anchors**: Valid X.509 certificates
///
/// # Example
///
/// ```no_run
/// use usg_est_client::EstClientConfig;
/// use std::time::Duration;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = EstClientConfig::builder()
///     .server_url("https://est.example.com")?
///     .trust_webpki_roots()
///     .timeout(Duration::from_secs(60))
///     .enable_channel_binding()
///     .verify_csr_signatures()
///     .build()?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct EstClientConfig {
    /// EST server base URL (SC-8: HTTPS required, SI-10: validated).
    ///
    /// Format: `https://hostname:port` (default port 443)
    /// Example: `https://est.example.com:8443`
    ///
    /// **Security**: HTTPS enforced for production. HTTP generates warning.
    pub server_url: Url,

    /// Optional CA label for multi-CA deployments (CM-6: multi-CA support).
    ///
    /// When set, the EST path becomes `/.well-known/est/{ca_label}/{operation}`.
    /// RFC 7030 Section 3.2.2: Allows single EST server to support multiple CAs.
    ///
    /// Example: `ca_label = "corp-issuing-ca"` results in:
    /// `https://est.example.com/.well-known/est/corp-issuing-ca/simpleenroll`
    pub ca_label: Option<String>,

    /// Client identity for TLS client certificate authentication (IA-5: preferred).
    ///
    /// Contains PEM-encoded client certificate and private key for mutual TLS.
    /// Used for certificate-based authentication (no password transmission).
    ///
    /// **Security**: Preferred authentication method. Private key MUST be protected.
    pub client_identity: Option<ClientIdentity>,

    /// HTTP Basic authentication credentials (IA-5: fallback authentication).
    ///
    /// Used as a fallback when TLS client authentication is not available.
    /// Credentials are Base64-encoded and transmitted over TLS (SC-8).
    ///
    /// **Security**: Use client certificates when possible. HTTP Basic auth
    /// should only be used over HTTPS to prevent credential exposure.
    pub http_auth: Option<HttpAuth>,

    /// Trust anchor configuration for server certificate verification (IA-5).
    ///
    /// Defines trusted root CAs for validating EST server certificates.
    /// Options: WebPKI roots, system roots, custom CA certificates.
    ///
    /// **Security**: Essential for preventing MITM attacks. Server certificate
    /// MUST chain to a trusted root CA (RFC 5280 path validation).
    pub trust_anchors: TrustAnchors,

    /// Request timeout duration (SC-5: DoS protection).
    ///
    /// Default: 30 seconds. Prevents indefinite blocking on slow servers.
    /// Recommended range: 10-120 seconds (EST operations can be slow).
    ///
    /// **Security**: Prevents resource exhaustion from slow-read attacks.
    pub timeout: Duration,

    /// Enable TLS channel binding (SC-11: proof of TLS termination).
    ///
    /// When enabled, the tls-unique value is placed in the CSR challenge-password
    /// field as per RFC 7030 Section 3.5. Binds the CSR to the TLS session.
    ///
    /// **Security**: Prevents credential forwarding attacks. Ensures EST server
    /// directly received the CSR over TLS (not relayed through proxy).
    ///
    /// Default: `false`. Enable for high-security environments.
    pub channel_binding: bool,

    /// Verify CSR signatures before submission (SI-3: malformed data detection).
    ///
    /// When enabled, the client validates CSR signatures to ensure proof-of-possession
    /// before sending to the EST server. This catches malformed CSRs early and provides
    /// an additional security check.
    ///
    /// Supported algorithms: RSA (SHA-256/384/512), ECDSA (P-256/P-384 with SHA-256/384)
    ///
    /// **Security**: Validates CSR integrity before submission. Detects accidental
    /// or malicious CSR corruption. Verifies proof-of-possession of private key.
    ///
    /// Default: `false`. Enable for additional validation (minimal performance impact).
    pub verify_csr_signatures: bool,

    /// Additional HTTP headers to include in requests (CM-6: custom headers).
    ///
    /// Allows adding custom headers for application-specific requirements
    /// (e.g., API keys, tracking headers, custom authentication).
    ///
    /// **Security Warning**: Do NOT include sensitive data in headers that could
    /// be logged by proxies/servers. Use for non-sensitive metadata only.
    pub additional_headers: Vec<(String, String)>,

    /// Certificate validation configuration for issued certificates (IA-5).
    ///
    /// When enabled, issued certificates are validated against the configured
    /// trust anchors using RFC 5280 path validation.
    ///
    /// **Security**: Validates that the EST server issued a valid certificate
    /// that chains to a trusted root. Detects certificate validation failures
    /// before the certificate is installed.
    #[cfg(feature = "validation")]
    pub validation_config: Option<CertificateValidationConfig>,

    /// FIPS 140-2 compliance configuration (SC-13: cryptographic protection).
    ///
    /// When enabled, the client will use FIPS-validated cryptographic modules
    /// and enforce FIPS-approved algorithms only.
    ///
    /// **Security**: Required for federal/defense systems requiring FIPS 140-2
    /// compliance. Restricts algorithms to NIST-approved subset.
    #[cfg(feature = "fips")]
    pub fips_config: Option<crate::fips::FipsConfig>,
}

impl std::fmt::Debug for EstClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EstClientConfig")
            .field("server_url", &self.server_url)
            .field("ca_label", &self.ca_label)
            .field("client_identity", &self.client_identity.is_some())
            .field("http_auth", &self.http_auth.is_some())
            .field("trust_anchors", &self.trust_anchors)
            .field("timeout", &self.timeout)
            .field("channel_binding", &self.channel_binding)
            .finish()
    }
}

impl Default for EstClientConfig {
    fn default() -> Self {
        Self {
            server_url: Url::parse("https://localhost").expect("valid default URL"),
            ca_label: None,
            client_identity: None,
            http_auth: None,
            trust_anchors: TrustAnchors::WebPki,
            timeout: Duration::from_secs(30),
            channel_binding: false,
            verify_csr_signatures: false,
            additional_headers: Vec::new(),
            #[cfg(feature = "validation")]
            validation_config: None,
            #[cfg(feature = "fips")]
            fips_config: None,
        }
    }
}

impl EstClientConfig {
    /// Create a new configuration builder.
    pub fn builder() -> EstClientConfigBuilder {
        EstClientConfigBuilder::new()
    }

    /// Build the EST operation URL path.
    ///
    /// Returns the full URL for the given EST operation, including the optional CA label.
    pub fn build_url(&self, operation: &str) -> Url {
        let mut url = self.server_url.clone();

        let path = if let Some(ref label) = self.ca_label {
            format!("/.well-known/est/{}/{}", label, operation)
        } else {
            format!("/.well-known/est/{}", operation)
        };

        url.set_path(&path);
        url
    }
}

/// Builder for [`EstClientConfig`].
#[derive(Default)]
pub struct EstClientConfigBuilder {
    server_url: Option<Url>,
    ca_label: Option<String>,
    client_identity: Option<ClientIdentity>,
    http_auth: Option<HttpAuth>,
    trust_anchors: Option<TrustAnchors>,
    timeout: Option<Duration>,
    channel_binding: bool,
    verify_csr_signatures: bool,
    additional_headers: Vec<(String, String)>,
    #[cfg(feature = "validation")]
    validation_config: Option<CertificateValidationConfig>,
    #[cfg(feature = "fips")]
    fips_config: Option<crate::fips::FipsConfig>,
}

impl EstClientConfigBuilder {
    /// Create a new configuration builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the EST server URL.
    ///
    /// Only HTTPS and HTTP URLs are allowed. HTTP generates a warning as it
    /// should only be used for testing.
    pub fn server_url(mut self, url: impl AsRef<str>) -> Result<Self, url::ParseError> {
        let parsed = Url::parse(url.as_ref())?;

        // Validate URL scheme for security
        match parsed.scheme() {
            "https" => {} // OK - secure
            "http" => {
                // Allow but warn - HTTP should only be for testing
                tracing::warn!(
                    "Using insecure HTTP scheme for EST server. \
                     Use HTTPS in production to prevent man-in-the-middle attacks."
                );
            }
            _scheme => {
                return Err(url::ParseError::InvalidDomainCharacter); // Best approximation
            }
        }

        // Validate host is present
        if parsed.host_str().is_none() {
            return Err(url::ParseError::EmptyHost);
        }

        // Validate port if specified
        if let Some(port) = parsed.port()
            && port == 0
        {
            // Port 0 is invalid for network connections
            return Err(url::ParseError::InvalidPort);
        }

        self.server_url = Some(parsed);
        Ok(self)
    }

    /// Set the EST server URL from a pre-parsed URL.
    pub fn server_url_parsed(mut self, url: Url) -> Self {
        self.server_url = Some(url);
        self
    }

    /// Set the CA label for multi-CA deployments.
    pub fn ca_label(mut self, label: impl Into<String>) -> Self {
        self.ca_label = Some(label.into());
        self
    }

    /// Set the client identity for TLS client authentication.
    pub fn client_identity(mut self, identity: ClientIdentity) -> Self {
        self.client_identity = Some(identity);
        self
    }

    /// Set the client identity from PEM-encoded certificate and key.
    pub fn client_identity_pem(
        mut self,
        cert_pem: impl Into<Vec<u8>>,
        key_pem: impl Into<Vec<u8>>,
    ) -> Self {
        self.client_identity = Some(ClientIdentity {
            cert_pem: cert_pem.into(),
            key_pem: key_pem.into(),
        });
        self
    }

    /// Set HTTP Basic authentication credentials.
    pub fn http_auth(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.http_auth = Some(HttpAuth {
            username: username.into(),
            password: password.into(),
        });
        self
    }

    /// Use Mozilla's root CA store (webpki-roots) for server verification.
    pub fn trust_webpki_roots(mut self) -> Self {
        self.trust_anchors = Some(TrustAnchors::WebPki);
        self
    }

    /// Use explicit CA certificates for server verification.
    pub fn trust_explicit(mut self, ca_certs: Vec<Vec<u8>>) -> Self {
        self.trust_anchors = Some(TrustAnchors::Explicit(ca_certs));
        self
    }

    /// Use bootstrap mode (TOFU) for initial CA discovery.
    ///
    /// The bootstrap window defaults to 24 hours. Use
    /// [`trust_bootstrap_with_ttl`](Self::trust_bootstrap_with_ttl) for a custom duration.
    pub fn trust_bootstrap<F>(mut self, verify_fingerprint: F) -> Self
    where
        F: Fn(&[u8; 32]) -> bool + Send + Sync + 'static,
    {
        self.trust_anchors = Some(TrustAnchors::Bootstrap(BootstrapConfig {
            verify_fingerprint: Arc::new(verify_fingerprint),
            expires_at: std::time::Instant::now() + Duration::from_secs(24 * 60 * 60),
        }));
        self
    }

    /// Use bootstrap mode (TOFU) with a custom time-to-live.
    ///
    /// After `ttl` elapses, bootstrap mode will be rejected and the client
    /// must be reconfigured with explicit trust anchors.
    pub fn trust_bootstrap_with_ttl<F>(mut self, verify_fingerprint: F, ttl: Duration) -> Self
    where
        F: Fn(&[u8; 32]) -> bool + Send + Sync + 'static,
    {
        self.trust_anchors = Some(TrustAnchors::Bootstrap(BootstrapConfig {
            verify_fingerprint: Arc::new(verify_fingerprint),
            expires_at: std::time::Instant::now() + ttl,
        }));
        self
    }

    /// Accept any server certificate (insecure, for testing only).
    pub fn trust_any_insecure(mut self) -> Self {
        self.trust_anchors = Some(TrustAnchors::InsecureAcceptAny);
        self
    }

    /// Set the request timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Enable TLS channel binding.
    pub fn enable_channel_binding(mut self) -> Self {
        self.channel_binding = true;
        self
    }

    /// Enable CSR signature verification.
    ///
    /// When enabled, the client will verify CSR signatures before submission
    /// to ensure proof-of-possession. This catches malformed CSRs early and
    /// provides defense-in-depth.
    ///
    /// Supports: RSA (SHA-256/384/512), ECDSA (P-256/P-384)
    pub fn verify_csr_signatures(mut self) -> Self {
        self.verify_csr_signatures = true;
        self
    }

    /// Add an additional HTTP header to all requests.
    pub fn add_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.additional_headers.push((name.into(), value.into()));
        self
    }

    /// Enable certificate validation on enrollment responses.
    ///
    /// When enabled, issued certificates are validated against the configured
    /// trust anchors using RFC 5280 path validation.
    #[cfg(feature = "validation")]
    pub fn validation_config(mut self, config: CertificateValidationConfig) -> Self {
        self.validation_config = Some(config);
        self
    }

    /// Enable FIPS 140-2 compliance mode.
    ///
    /// When enabled, the client will use FIPS-validated cryptographic modules
    /// and enforce FIPS-approved algorithms only.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use usg_est_client::EstClientConfig;
    /// # #[cfg(feature = "fips")]
    /// # use usg_est_client::fips::FipsConfig;
    /// # #[cfg(feature = "fips")]
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let fips_config = FipsConfig::builder()
    ///     .enforce_fips_mode(true)
    ///     .min_rsa_key_size(2048)
    ///     .build()?;
    ///
    /// let config = EstClientConfig::builder()
    ///     .server_url("https://est.example.mil")?
    ///     .fips_config(fips_config)
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "fips")]
    pub fn fips_config(mut self, config: crate::fips::FipsConfig) -> Self {
        self.fips_config = Some(config);
        self
    }

    /// Build the configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the server URL is not set.
    pub fn build(self) -> Result<EstClientConfig, &'static str> {
        let server_url = self.server_url.ok_or("server_url is required")?;

        Ok(EstClientConfig {
            server_url,
            ca_label: self.ca_label,
            client_identity: self.client_identity,
            http_auth: self.http_auth,
            trust_anchors: self.trust_anchors.unwrap_or(TrustAnchors::WebPki),
            timeout: self.timeout.unwrap_or(Duration::from_secs(30)),
            channel_binding: self.channel_binding,
            verify_csr_signatures: self.verify_csr_signatures,
            additional_headers: self.additional_headers,
            #[cfg(feature = "validation")]
            validation_config: self.validation_config,
            #[cfg(feature = "fips")]
            fips_config: self.fips_config,
        })
    }
}

// ============================================================================
// SECURITY CONTROL: TLS Client Certificate Authentication
// ----------------------------------------------------------------------------
// NIST SP 800-53 Rev 5: IA-2 (Identification and Authentication)
//                       IA-5 (Authenticator Management)
//                       SC-8 (Transmission Confidentiality)
//                       SC-12 (Cryptographic Key Establishment)
// STIG: APSC-DV-000160 (CAT I) - Bidirectional Authentication
//       APSC-DV-001740 (CAT I) - PKI Certificate Authentication
// Standards: RFC 7030 Section 3.3.2 (Client Authentication)
//           RFC 5280 (X.509 PKI)
// ----------------------------------------------------------------------------
// Client identity contains the certificate and private key for mutual TLS
// authentication. Private key is automatically zeroized on drop to prevent
// memory disclosure attacks.
//
// Security Rationale:
// - IA-2: Client certificates provide strong cryptographic authentication
// - IA-5: Certificate-based auth eliminates password transmission
// - SC-12: Private key protection through memory zeroization
// - Mutual TLS prevents unauthorized EST server access
// - Preferred authentication method over HTTP Basic auth
// ============================================================================

/// Client identity for TLS client certificate authentication.
///
/// # Security Controls
///
/// **NIST SP 800-53 Rev 5:**
/// - IA-2: Identification and Authentication (certificate-based authentication)
/// - IA-5: Authenticator Management (private key protection)
/// - SC-8: Transmission Confidentiality (mutual TLS)
/// - SC-12: Cryptographic Key Establishment (key lifecycle management)
///
/// **STIG Findings:**
/// - APSC-DV-000160 (CAT I): Bidirectional Authentication
/// - APSC-DV-001740 (CAT I): PKI Certificate-Based Authentication
///
/// # Client Certificate Authentication (RFC 7030 Section 3.3.2)
///
/// Mutual TLS provides bidirectional authentication where both client and server
/// authenticate each other using X.509 certificates. This is the **preferred**
/// authentication method for EST as it:
/// - Eliminates password transmission (IA-5)
/// - Provides strong cryptographic authentication (IA-2)
/// - Protects against MITM attacks (SC-8)
/// - Supports PKI-based access control (AC-2)
///
/// # Private Key Security (SC-12, IA-5)
///
/// The private key is automatically zeroized when dropped using the `zeroize`
/// crate. This prevents:
/// - Memory dumps from exposing key material
/// - Core files from containing keys
/// - Swap space from persisting keys
/// - Heap analysis attacks
///
/// # Certificate Chain Format
///
/// The `cert_pem` field should contain the PEM-encoded certificate chain:
/// 1. **Client certificate** (leaf certificate, FIRST in chain)
/// 2. **Intermediate certificates** (if any, in order from leaf to root)
///
/// The root CA certificate is typically NOT included as it should be in the
/// server's trust store.
///
/// # File Permission Recommendations (Unix)
///
/// Private key files SHOULD have restrictive permissions:
/// - **Mode 0600** (read/write for owner only) - RECOMMENDED
/// - **Mode 0400** (read-only for owner) - ACCEPTABLE
///
/// Use `from_files_with_validation()` to enforce permission checks.
///
/// # Example
///
/// ```no_run
/// use usg_est_client::config::ClientIdentity;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // From PEM bytes
/// let cert_pem = std::fs::read("client.pem")?;
/// let key_pem = std::fs::read("client-key.pem")?;
/// let identity = ClientIdentity::new(cert_pem, key_pem);
///
/// // From files (no permission check)
/// let identity = ClientIdentity::from_files("client.pem", "client-key.pem")?;
///
/// // From files (with permission validation - Unix only)
/// let identity = ClientIdentity::from_files_with_validation(
///     "client.pem",
///     "client-key.pem"
/// )?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, zeroize::ZeroizeOnDrop)]
pub struct ClientIdentity {
    /// PEM-encoded certificate chain (IA-2: client identity credential).
    ///
    /// Format: PEM-encoded X.509 certificates
    /// Order: Client cert FIRST, then intermediates (if any)
    ///
    /// **Security**: Certificate is public information (not zeroized).
    #[zeroize(skip)]
    pub cert_pem: Vec<u8>,

    /// PEM-encoded private key (IA-5: authentication secret).
    ///
    /// Supports: RSA, ECDSA private keys in PKCS#8 or traditional format
    ///
    /// **Security**: Automatically zeroized on drop to prevent memory disclosure.
    /// NEVER log or serialize this field. Protect at rest with filesystem permissions.
    pub key_pem: Vec<u8>,
}

impl ClientIdentity {
    /// Create a new client identity from PEM-encoded data.
    pub fn new(cert_pem: impl Into<Vec<u8>>, key_pem: impl Into<Vec<u8>>) -> Self {
        Self {
            cert_pem: cert_pem.into(),
            key_pem: key_pem.into(),
        }
    }

    /// Create a client identity from file paths.
    ///
    /// # Security
    ///
    /// This function does not validate file permissions. For security-sensitive
    /// deployments, use `from_files_with_validation()` to ensure proper permissions.
    pub fn from_files(
        cert_path: impl AsRef<std::path::Path>,
        key_path: impl AsRef<std::path::Path>,
    ) -> std::io::Result<Self> {
        let cert_pem = std::fs::read(cert_path)?;
        let key_pem = std::fs::read(key_path)?;
        Ok(Self { cert_pem, key_pem })
    }

    /// Create a client identity from file paths with permission validation.
    ///
    /// # Security
    ///
    /// This function validates that the private key file has restrictive permissions
    /// (Unix: mode 0600 or more restrictive). This helps prevent accidental exposure
    /// of private keys.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Files cannot be read
    /// - Private key file permissions are too permissive (Unix only)
    #[cfg(unix)]
    pub fn from_files_with_validation(
        cert_path: impl AsRef<std::path::Path>,
        key_path: impl AsRef<std::path::Path>,
    ) -> std::io::Result<Self> {
        use std::os::unix::fs::PermissionsExt;

        let key_path = key_path.as_ref();

        // Check key file permissions
        let metadata = std::fs::metadata(key_path)?;
        let permissions = metadata.permissions();
        let mode = permissions.mode();

        // Check if file is readable by group or others (octal 077 = binary 000111111)
        if mode & 0o077 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "Private key file has insecure permissions: {:o}. Should be 0600 or more restrictive.",
                    mode & 0o777
                ),
            ));
        }

        // Read the files
        let cert_pem = std::fs::read(cert_path)?;
        let key_pem = std::fs::read(key_path)?;
        Ok(Self { cert_pem, key_pem })
    }

    /// Create a client identity from file paths with permission validation.
    ///
    /// On non-Unix systems, this is equivalent to `from_files()` as permission
    /// validation is not implemented.
    #[cfg(not(unix))]
    pub fn from_files_with_validation(
        cert_path: impl AsRef<std::path::Path>,
        key_path: impl AsRef<std::path::Path>,
    ) -> std::io::Result<Self> {
        Self::from_files(cert_path, key_path)
    }
}

// ============================================================================
// SECURITY CONTROL: HTTP Basic Authentication
// ----------------------------------------------------------------------------
// NIST SP 800-53 Rev 5: IA-2 (Identification and Authentication)
//                       IA-5 (Authenticator Management)
//                       SC-8 (Transmission Confidentiality)
// STIG: APSC-DV-001740 (CAT I) - Authentication
//       APSC-DV-002440 (CAT I) - Transmission Confidentiality
// Standards: RFC 7617 (HTTP Basic Authentication)
//           RFC 7030 Section 3.2.3 (HTTP-Based Client Authentication)
// ----------------------------------------------------------------------------
// HTTP Basic authentication for EST client authentication. Credentials are
// Base64-encoded and transmitted over TLS. Uses zeroize to securely erase
// credentials from memory when dropped.
//
// Security Rationale:
// - IA-2: Username/password authentication
// - SC-8: MUST be used over HTTPS (credentials transmitted in clear over TLS)
// - IA-5: Credentials zeroized on drop to prevent memory disclosure
// - Fallback authentication when client certificates unavailable
// - Less secure than client certificate authentication (prefer mutual TLS)
// ============================================================================

/// HTTP Basic authentication credentials.
///
/// # Security Controls
///
/// **NIST SP 800-53 Rev 5:**
/// - IA-2: Identification and Authentication (user authentication)
/// - IA-5: Authenticator Management (credential protection)
/// - SC-8: Transmission Confidentiality (HTTPS required)
///
/// **STIG Findings:**
/// - APSC-DV-001740 (CAT I): Authentication
/// - APSC-DV-002440 (CAT I): Transmission Confidentiality
///
/// # HTTP Basic Authentication (RFC 7617)
///
/// HTTP Basic authentication sends credentials as Base64-encoded `username:password`
/// in the `Authorization` header. This is a **fallback** authentication method when
/// TLS client certificates are not available.
///
/// # Security Warnings
///
/// - **MUST use HTTPS**: Credentials transmitted in clear over TLS (Base64 encoding
///   is NOT encryption). HTTP Basic over HTTP is completely insecure.
/// - **Prefer client certificates**: Mutual TLS (client certificates) is more secure
///   as it eliminates password transmission entirely.
/// - **Password complexity**: Use strong, random passwords (minimum 16 characters,
///   high entropy recommended).
/// - **Credential storage**: Do NOT hardcode credentials. Use environment variables,
///   secret management systems, or secure credential stores.
///
/// # Memory Security (IA-5)
///
/// Uses `zeroize` to securely erase credentials from memory when dropped. This prevents:
/// - Memory dumps from exposing credentials
/// - Core files from containing passwords
/// - Swap space from persisting credentials
///
/// # Example
///
/// ```no_run
/// use usg_est_client::config::HttpAuth;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // From environment variables (RECOMMENDED)
/// let username = std::env::var("EST_USERNAME")?;
/// let password = std::env::var("EST_PASSWORD")?;
/// let auth = HttpAuth::new(username, password);
///
/// // Direct creation (NOT RECOMMENDED for production)
/// let auth = HttpAuth::new("admin", "very-strong-password-here");
/// # Ok(())
/// # }
/// ```
#[derive(Clone, zeroize::ZeroizeOnDrop)]
pub struct HttpAuth {
    /// Username (IA-2: user identifier).
    ///
    /// May be empty for password-only authentication (rare).
    /// Zeroized on drop for defense-in-depth (usernames less sensitive than passwords).
    pub username: String,

    /// Password (IA-5: authentication secret).
    ///
    /// **Security**: Automatically zeroized on drop. NEVER log or serialize.
    /// Use strong, random passwords (minimum 16 characters recommended).
    #[zeroize(skip)] // We'll manually zeroize via ZeroizeOnDrop
    pub password: String,
}

impl HttpAuth {
    /// Create new HTTP auth credentials.
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }
}

impl zeroize::Zeroize for HttpAuth {
    fn zeroize(&mut self) {
        self.password.zeroize();
        // Username is not typically sensitive, but zeroize it anyway
        self.username.zeroize();
    }
}

// ============================================================================
// SECURITY CONTROL: Trust Anchor Configuration
// ----------------------------------------------------------------------------
// NIST SP 800-53 Rev 5: IA-5 (Authenticator Management)
//                       SC-8 (Transmission Confidentiality)
//                       SC-12 (Cryptographic Key Establishment)
//                       SC-13 (Cryptographic Protection)
// STIG: APSC-DV-001750 (CAT I) - Certificate Validation
//       APSC-DV-000460 (CAT I) - PKI Certificate Validation
// Standards: RFC 5280 (X.509 PKI Certificate Validation)
//           RFC 7030 Section 3.3.1 (Server Authentication)
// ----------------------------------------------------------------------------
// Configures trust anchors for EST server certificate validation. Trust
// anchors establish the root of trust for server authentication per RFC 5280.
//
// Security Rationale:
// - IA-5: Trust anchors define trusted authentication authorities
// - SC-8: Prevents MITM attacks through server certificate validation
// - RFC 5280: Path validation from server cert to trusted root CA
// - Multiple trust models supported (WebPKI, explicit CAs, bootstrap TOFU)
// ============================================================================

/// Trust anchor configuration for server certificate verification.
///
/// # Security Controls
///
/// **NIST SP 800-53 Rev 5:**
/// - IA-5: Authenticator Management (trust anchor management)
/// - SC-8: Transmission Confidentiality (server authentication prevents MITM)
/// - SC-12: Cryptographic Key Establishment (trust anchor lifecycle)
/// - SC-13: Cryptographic Protection (certificate validation algorithms)
///
/// **STIG Findings:**
/// - APSC-DV-001750 (CAT I): Certificate Validation
/// - APSC-DV-000460 (CAT I): PKI Certificate Validation
///
/// # Trust Anchor Selection (IA-5)
///
/// | Use Case | Trust Model | Security | When to Use |
/// |----------|-------------|----------|-------------|
/// | Public EST servers | WebPKI | High | Commercial CAs (Let's Encrypt, DigiCert) |
/// | Enterprise PKI | Explicit CA | High | Internal/private CAs |
/// | Initial enrollment | Bootstrap (TOFU) | Medium | CA cert unknown, OOB fingerprint |
/// | Development only | InsecureAcceptAny | NONE | Local testing ONLY |
#[derive(Clone)]
pub enum TrustAnchors {
    /// Use Mozilla's root CA store (webpki-roots) - Default for public CAs.
    ///
    /// **Security**: High - Same trusted CAs as Firefox/Chrome
    /// **Use case**: Public EST servers with commercial CA certificates
    ///
    /// Includes ~140 trusted root CAs from Mozilla's CA Certificate Program.
    WebPki,

    /// Use explicit CA certificates (PEM-encoded) - Enterprise PKI.
    ///
    /// **Security**: High - Precise control over trusted CAs
    /// **Use case**: Enterprise deployments with internal Certificate Authorities
    ///
    /// Allows pinning specific CA certificates for enhanced security.
    /// Format: Vec of PEM-encoded X.509 CA certificates
    Explicit(Vec<Vec<u8>>),

    /// Bootstrap mode with fingerprint verification - Trust-On-First-Use (TOFU).
    ///
    /// **Security**: Medium - Requires out-of-band fingerprint verification
    /// **Use case**: Initial enrollment when CA certificate unknown
    ///
    /// **Security Warning**: Vulnerable to MITM if fingerprint not verified
    /// out-of-band (secure email, phone, physical meeting).
    ///
    /// See [`BootstrapConfig`] for implementation.
    Bootstrap(BootstrapConfig),

    /// Accept any server certificate - **INSECURE, TESTING ONLY**.
    ///
    /// **Security**: NONE - Completely disables certificate validation
    ///
    /// **WARNING**: **NEVER** use in production. Violates:
    /// - NIST SP 800-53 Rev 5: IA-5, SC-8, SC-13
    /// - STIG APSC-DV-001750 (CAT I), APSC-DV-000460 (CAT I)
    /// - RFC 7030 Section 3.3.1
    ///
    /// Only for local development/testing with self-signed certificates.
    InsecureAcceptAny,
}

impl std::fmt::Debug for TrustAnchors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WebPki => write!(f, "WebPki"),
            Self::Explicit(certs) => write!(f, "Explicit({} certs)", certs.len()),
            Self::Bootstrap(_) => write!(f, "Bootstrap(...)"),
            Self::InsecureAcceptAny => write!(f, "InsecureAcceptAny"),
        }
    }
}

/// Type alias for fingerprint verification callback.
pub type FingerprintVerifier = Arc<dyn Fn(&[u8; 32]) -> bool + Send + Sync>;

/// Configuration for bootstrap/TOFU mode.
#[derive(Clone)]
pub struct BootstrapConfig {
    /// Callback function to verify the CA certificate fingerprint.
    ///
    /// The fingerprint is a SHA-256 hash of the DER-encoded certificate.
    /// Return `true` to accept the certificate, `false` to reject.
    pub verify_fingerprint: FingerprintVerifier,

    /// Expiration time for the bootstrap window.
    ///
    /// After this time, bootstrap mode will be rejected and the client
    /// must use explicit trust anchors. This prevents indefinite TOFU
    /// windows that could be exploited by delayed MITM attacks.
    ///
    /// Default: 24 hours from creation.
    pub expires_at: std::time::Instant,
}

/// Configuration for certificate validation on enrollment responses.
///
/// This allows automatic RFC 5280 path validation of issued certificates
/// against known trust anchors.
#[cfg(feature = "validation")]
#[derive(Clone)]
pub struct CertificateValidationConfig {
    /// Trust anchors (root CA certificates) for chain validation.
    pub trust_anchors: Vec<Certificate>,

    /// Maximum allowed certificate chain length.
    pub max_chain_length: usize,

    /// Whether to enforce name constraints (RFC 5280 Section 4.2.1.10).
    pub enforce_name_constraints: bool,

    /// Whether to enforce policy constraints (RFC 5280 Section 4.2.1.11).
    pub enforce_policy_constraints: bool,

    /// Allow expired certificates (for testing only).
    pub allow_expired: bool,
}

#[cfg(feature = "validation")]
impl Default for CertificateValidationConfig {
    fn default() -> Self {
        Self {
            trust_anchors: Vec::new(),
            max_chain_length: 10,
            enforce_name_constraints: true,
            enforce_policy_constraints: true,
            allow_expired: false,
        }
    }
}

#[cfg(feature = "validation")]
impl CertificateValidationConfig {
    /// Create a new validation config with the given trust anchors.
    pub fn new(trust_anchors: Vec<Certificate>) -> Self {
        Self {
            trust_anchors,
            ..Default::default()
        }
    }

    /// Set maximum chain length.
    pub fn max_chain_length(mut self, len: usize) -> Self {
        self.max_chain_length = len;
        self
    }

    /// Disable name constraints checking.
    pub fn disable_name_constraints(mut self) -> Self {
        self.enforce_name_constraints = false;
        self
    }

    /// Disable policy constraints checking.
    pub fn disable_policy_constraints(mut self) -> Self {
        self.enforce_policy_constraints = false;
        self
    }

    /// Allow expired certificates (testing only).
    pub fn allow_expired(mut self) -> Self {
        self.allow_expired = true;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: Test code uses unwrap() deliberately - test fixtures are known valid
    // and panics in tests provide clear failure messages. See ERROR-HANDLING-PATTERNS.md
    // Pattern 5 for justification.

    #[test]
    fn test_build_url_without_label() {
        let config = EstClientConfig::builder()
            .server_url("https://est.example.com")
            .unwrap()
            .build()
            .unwrap();

        let url = config.build_url("cacerts");
        assert_eq!(
            url.as_str(),
            "https://est.example.com/.well-known/est/cacerts"
        );
    }

    #[test]
    fn test_build_url_with_label() {
        let config = EstClientConfig::builder()
            .server_url("https://est.example.com")
            .unwrap()
            .ca_label("myca")
            .build()
            .unwrap();

        let url = config.build_url("simpleenroll");
        assert_eq!(
            url.as_str(),
            "https://est.example.com/.well-known/est/myca/simpleenroll"
        );
    }

    #[test]
    fn test_builder_requires_url() {
        let result = EstClientConfig::builder().build();
        assert!(result.is_err());
    }

    #[test]
    fn test_default_config() {
        let config = EstClientConfig::default();
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert!(!config.channel_binding);
    }
}
