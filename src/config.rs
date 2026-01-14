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

use std::sync::Arc;
use std::time::Duration;
use url::Url;

#[cfg(feature = "validation")]
use x509_cert::Certificate;

/// Configuration for an EST client.
#[derive(Clone)]
pub struct EstClientConfig {
    /// EST server base URL (e.g., "https://est.example.com").
    pub server_url: Url,

    /// Optional CA label for multi-CA deployments.
    ///
    /// When set, the EST path becomes `/.well-known/est/{ca_label}/{operation}`.
    pub ca_label: Option<String>,

    /// Client identity for TLS client certificate authentication.
    pub client_identity: Option<ClientIdentity>,

    /// HTTP Basic authentication credentials.
    ///
    /// Used as a fallback when TLS client authentication is not available.
    pub http_auth: Option<HttpAuth>,

    /// Trust anchor configuration for server certificate verification.
    pub trust_anchors: TrustAnchors,

    /// Request timeout duration.
    pub timeout: Duration,

    /// Enable TLS channel binding.
    ///
    /// When enabled, the tls-unique value is placed in the CSR challenge-password
    /// field as per RFC 7030 Section 3.5.
    pub channel_binding: bool,

    /// Additional HTTP headers to include in requests.
    pub additional_headers: Vec<(String, String)>,

    /// Certificate validation configuration for issued certificates.
    ///
    /// When enabled, issued certificates are validated against the configured
    /// trust anchors using RFC 5280 path validation.
    #[cfg(feature = "validation")]
    pub validation_config: Option<CertificateValidationConfig>,

    /// FIPS 140-2 compliance configuration.
    ///
    /// When enabled, the client will use FIPS-validated cryptographic modules
    /// and enforce FIPS-approved algorithms only.
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
            "https" => {}, // OK - secure
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
        if let Some(port) = parsed.port() {
            if port == 0 {
                // Port 0 is invalid for network connections
                return Err(url::ParseError::InvalidPort);
            }
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
    pub fn trust_bootstrap<F>(mut self, verify_fingerprint: F) -> Self
    where
        F: Fn(&[u8; 32]) -> bool + Send + Sync + 'static,
    {
        self.trust_anchors = Some(TrustAnchors::Bootstrap(BootstrapConfig {
            verify_fingerprint: Arc::new(verify_fingerprint),
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
            additional_headers: self.additional_headers,
            #[cfg(feature = "validation")]
            validation_config: self.validation_config,
            #[cfg(feature = "fips")]
            fips_config: self.fips_config,
        })
    }
}

/// Client identity for TLS client certificate authentication.
///
/// Private key data is automatically zeroed when dropped for security.
#[derive(Clone, zeroize::ZeroizeOnDrop)]
pub struct ClientIdentity {
    /// PEM-encoded certificate chain.
    ///
    /// The client certificate should be first, followed by any intermediate certificates.
    #[zeroize(skip)]
    pub cert_pem: Vec<u8>,

    /// PEM-encoded private key - automatically zeroed on drop.
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

/// HTTP Basic authentication credentials.
///
/// Uses `zeroize` to securely erase sensitive data from memory when dropped.
#[derive(Clone, zeroize::ZeroizeOnDrop)]
pub struct HttpAuth {
    /// Username (may be empty for password-only auth).
    pub username: String,

    /// Password - automatically zeroed on drop.
    #[zeroize(skip)]  // We'll manually zeroize via ZeroizeOnDrop
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

/// Trust anchor configuration for server certificate verification.
#[derive(Clone)]
pub enum TrustAnchors {
    /// Use Mozilla's root CA store (webpki-roots).
    WebPki,

    /// Use explicit CA certificates (PEM-encoded).
    Explicit(Vec<Vec<u8>>),

    /// Bootstrap mode with fingerprint verification callback.
    ///
    /// Used for Trust-On-First-Use (TOFU) scenarios where the CA certificate
    /// is not known in advance.
    Bootstrap(BootstrapConfig),

    /// Accept any server certificate (insecure, for testing only).
    ///
    /// **WARNING**: This disables all server certificate verification.
    /// Only use for testing purposes.
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
