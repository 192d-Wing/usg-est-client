// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! Auto-enrollment configuration structures.
//!
//! This module defines the TOML configuration schema for machine certificate
//! auto-enrollment, designed to replace Windows ADCS auto-enrollment.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::error::EstError;
use crate::{EstClientConfig, EstClientConfigBuilder};

use super::expand::expand_variables;

/// Complete auto-enrollment configuration.
///
/// This struct represents the full TOML configuration file structure
/// for automated machine certificate enrollment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutoEnrollConfig {
    /// EST server configuration.
    pub server: ServerConfig,

    /// TLS trust configuration.
    #[serde(default)]
    pub trust: TrustConfig,

    /// Authentication configuration.
    #[serde(default)]
    pub authentication: AuthenticationConfig,

    /// Certificate subject and extensions configuration.
    pub certificate: CertificateConfig,

    /// Automatic renewal configuration.
    #[serde(default)]
    pub renewal: RenewalConfig,

    /// Certificate storage configuration.
    #[serde(default)]
    pub storage: StorageConfig,

    /// Logging configuration.
    #[serde(default)]
    pub logging: LoggingConfig,

    /// Windows Service configuration.
    #[serde(default)]
    pub service: ServiceConfig,
}

impl AutoEnrollConfig {
    /// Parse configuration from a TOML string.
    ///
    /// # Errors
    ///
    /// Returns an error if the TOML is invalid or missing required fields.
    pub fn from_toml(toml_str: &str) -> Result<Self, EstError> {
        toml::from_str(toml_str).map_err(|e| EstError::config(format!("Invalid TOML: {e}")))
    }

    /// Serialize configuration to a TOML string.
    pub fn to_toml(&self) -> Result<String, EstError> {
        toml::to_string_pretty(self).map_err(|e| EstError::config(format!("TOML serialize: {e}")))
    }

    /// Expand all variable references in the configuration.
    ///
    /// Variables like `${COMPUTERNAME}` and `${USERDNSDOMAIN}` are replaced
    /// with their actual values from the environment.
    pub fn expand_variables(&mut self) -> Result<(), EstError> {
        // Expand server section
        self.server.url = expand_variables(&self.server.url)?;
        if let Some(ref mut label) = self.server.ca_label {
            *label = expand_variables(label)?;
        }

        // Expand trust section
        if let Some(ref mut path) = self.trust.ca_bundle_path {
            let expanded = expand_variables(&path.to_string_lossy())?;
            *path = PathBuf::from(expanded);
        }

        // Expand authentication section
        if let Some(ref mut username) = self.authentication.username {
            *username = expand_variables(username)?;
        }

        // Expand certificate section
        self.certificate.common_name = expand_variables(&self.certificate.common_name)?;
        if let Some(ref mut org) = self.certificate.organization {
            *org = expand_variables(org)?;
        }
        if let Some(ref mut ou) = self.certificate.organizational_unit {
            *ou = expand_variables(ou)?;
        }
        if let Some(ref mut san) = self.certificate.san {
            san.dns = san
                .dns
                .iter()
                .map(|s| expand_variables(s))
                .collect::<Result<Vec<_>, _>>()?;
        }

        // Expand storage section
        if let Some(ref mut store) = self.storage.windows_store {
            *store = expand_variables(store)?;
        }
        if let Some(ref mut path) = self.storage.cert_path {
            let expanded = expand_variables(&path.to_string_lossy())?;
            *path = PathBuf::from(expanded);
        }
        // key_path is deprecated and ignored (CNG used instead)

        // Expand logging section
        if let Some(ref mut path) = self.logging.path {
            let expanded = expand_variables(&path.to_string_lossy())?;
            *path = PathBuf::from(expanded);
        }

        Ok(())
    }

    /// Validate the configuration for completeness and consistency.
    ///
    /// # Errors
    ///
    /// Returns an error describing any validation failures.
    pub fn validate(&self) -> Result<(), EstError> {
        let mut errors = Vec::new();

        // Validate server URL
        if self.server.url.is_empty() {
            errors.push("server.url is required".to_string());
        } else if !self.server.url.starts_with("https://") {
            errors.push("server.url must use HTTPS".to_string());
        }

        // Validate trust configuration
        match self.trust.mode {
            TrustMode::Explicit => {
                if self.trust.ca_bundle_path.is_none() {
                    errors.push(
                        "trust.ca_bundle_path is required when trust.mode is 'explicit'"
                            .to_string(),
                    );
                }
            }
            TrustMode::Bootstrap => {
                if self.trust.bootstrap_fingerprint.is_none() {
                    errors.push(
                        "trust.bootstrap_fingerprint is required when trust.mode is 'bootstrap'"
                            .to_string(),
                    );
                }
            }
            TrustMode::WebPki | TrustMode::Insecure => {}
        }

        // Validate authentication
        match self.authentication.method {
            AuthMethod::HttpBasic => {
                if self.authentication.username.is_none() {
                    errors.push(
                        "authentication.username is required for http_basic method".to_string(),
                    );
                }
                if self.authentication.password_source.is_none() {
                    errors.push(
                        "authentication.password_source is required for http_basic method"
                            .to_string(),
                    );
                }
            }
            AuthMethod::ClientCert => {
                let has_store = self.authentication.cert_store.is_some();
                let has_files = self.authentication.cert_path.is_some()
                    && self.authentication.key_path.is_some();
                if !has_store && !has_files {
                    errors.push(
                        "authentication requires either cert_store or (cert_path + key_path)"
                            .to_string(),
                    );
                }
            }
            AuthMethod::Auto | AuthMethod::None => {}
        }

        // Validate certificate configuration
        if self.certificate.common_name.is_empty() {
            errors.push("certificate.common_name is required".to_string());
        }

        // Validate renewal configuration
        if self.renewal.enabled {
            if self.renewal.threshold_days == 0 {
                errors
                    .push("renewal.threshold_days must be > 0 when renewal is enabled".to_string());
            }
            if self.renewal.check_interval_hours == 0 {
                errors.push(
                    "renewal.check_interval_hours must be > 0 when renewal is enabled".to_string(),
                );
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(EstError::config(format!(
                "Configuration validation failed:\n  - {}",
                errors.join("\n  - ")
            )))
        }
    }

    /// Convert to an EST client configuration.
    ///
    /// This creates an `EstClientConfig` that can be used with `EstClient::new()`.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration cannot be converted (e.g., invalid URL).
    pub fn to_est_client_config(&self) -> Result<EstClientConfig, EstError> {
        let mut builder = EstClientConfigBuilder::new();

        // Set server URL
        builder = builder
            .server_url(&self.server.url)
            .map_err(|e| EstError::config(format!("Invalid server URL: {e}")))?;

        // Set CA label if present
        if let Some(ref label) = self.server.ca_label {
            builder = builder.ca_label(label);
        }

        // Set timeout
        builder = builder.timeout(Duration::from_secs(self.server.timeout_seconds));

        // Set trust anchors
        builder = match self.trust.mode {
            TrustMode::WebPki => builder.trust_webpki_roots(),
            TrustMode::Explicit => {
                if let Some(ref path) = self.trust.ca_bundle_path {
                    let ca_pem =
                        std::fs::read(path).map_err(|e| EstError::config(format!("{e}")))?;
                    builder.trust_explicit(vec![ca_pem])
                } else {
                    return Err(EstError::config(
                        "ca_bundle_path required for explicit trust",
                    ));
                }
            }
            TrustMode::Bootstrap => {
                let expected_fp = self
                    .trust
                    .bootstrap_fingerprint
                    .clone()
                    .ok_or_else(|| EstError::config("bootstrap_fingerprint required"))?;
                builder.trust_bootstrap(move |fp: &[u8; 32]| {
                    let fp_hex = fp.iter().map(|b| format!("{b:02x}")).collect::<String>();
                    fp_hex.eq_ignore_ascii_case(&expected_fp.replace(':', ""))
                })
            }
            TrustMode::Insecure => builder.trust_any_insecure(),
        };

        // Set authentication
        match self.authentication.method {
            AuthMethod::HttpBasic => {
                if let (Some(username), Some(_password_source)) = (
                    &self.authentication.username,
                    &self.authentication.password_source,
                ) {
                    // For now, we'll use an empty password - real implementation would
                    // fetch from credential manager or environment
                    let password = self.resolve_password()?;
                    builder = builder.http_auth(username.clone(), password);
                }
            }
            AuthMethod::ClientCert => {
                if let (Some(cert_path), Some(key_path)) = (
                    &self.authentication.cert_path,
                    &self.authentication.key_path,
                ) {
                    let cert_pem =
                        std::fs::read(cert_path).map_err(|e| EstError::config(format!("{e}")))?;
                    let key_pem =
                        std::fs::read(key_path).map_err(|e| EstError::config(format!("{e}")))?;
                    builder = builder.client_identity_pem(cert_pem, key_pem);
                }
                // Windows cert store handling would go here for Windows builds
            }
            AuthMethod::Auto | AuthMethod::None => {}
        }

        // Enable channel binding if configured
        if self.server.channel_binding.unwrap_or(false) {
            builder = builder.enable_channel_binding();
        }

        builder
            .build()
            .map_err(|e| EstError::config(format!("Failed to build config: {e}")))
    }

    /// Resolve the password from the configured source.
    ///
    /// Supported password sources:
    /// - `env:VAR_NAME` - Read from environment variable
    /// - `credential_manager` - Read from Windows Credential Manager (Windows only)
    /// - `credential_manager:target` - Read from Windows Credential Manager with specific target name
    /// - `file:/path/to/file` - Read from file (trimmed)
    fn resolve_password(&self) -> Result<String, EstError> {
        let source = self
            .authentication
            .password_source
            .as_ref()
            .ok_or_else(|| EstError::config("password_source not configured"))?;

        if let Some(var_name) = source.strip_prefix("env:") {
            std::env::var(var_name)
                .map_err(|_| EstError::config(format!("Environment variable {var_name} not set")))
        } else if source == "credential_manager" {
            // Use EST server URL as the credential target name
            let target_name = &self.server.url;
            self.read_credential_manager(target_name)
        } else if let Some(target) = source.strip_prefix("credential_manager:") {
            // Use explicit target name
            self.read_credential_manager(target)
        } else if let Some(path) = source.strip_prefix("file:") {
            std::fs::read_to_string(path)
                .map(|s| s.trim().to_string())
                .map_err(|e| EstError::config(format!("Failed to read password file: {e}")))
        } else {
            Err(EstError::config(format!(
                "Unknown password_source: {source}"
            )))
        }
    }

    /// Read password from Windows Credential Manager.
    ///
    /// This uses the Windows CredRead API to retrieve a stored credential.
    /// The credential is identified by the target name (typically the server URL).
    #[cfg(windows)]
    fn read_credential_manager(&self, target_name: &str) -> Result<String, EstError> {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::ERROR_NOT_FOUND;
        use windows::Win32::Security::Credentials::{
            CredFree, CredReadW, CREDENTIALW, CRED_TYPE_GENERIC,
        };

        tracing::debug!(
            "Reading credential from Windows Credential Manager: {}",
            target_name
        );

        // Convert target name to wide string
        let target_wide: Vec<u16> = target_name.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            let mut pcredential: *mut CREDENTIALW = std::ptr::null_mut();

            // Call CredReadW to retrieve the credential
            let result = CredReadW(
                PCWSTR::from_raw(target_wide.as_ptr()),
                CRED_TYPE_GENERIC,
                0, // flags (reserved, must be 0)
                &mut pcredential,
            );

            if result.is_err() {
                let error = result.unwrap_err();
                if error.code() == ERROR_NOT_FOUND.to_hresult() {
                    return Err(EstError::config(format!(
                        "Credential not found in Windows Credential Manager: {}",
                        target_name
                    )));
                }
                return Err(EstError::config(format!(
                    "Failed to read from Windows Credential Manager: {}",
                    error
                )));
            }

            // Extract password from credential
            let credential = &*pcredential;
            let password_bytes =
                std::slice::from_raw_parts(credential.CredentialBlob, credential.CredentialBlobSize as usize);

            // Password is stored as UTF-8 bytes
            let password = String::from_utf8(password_bytes.to_vec()).map_err(|_| {
                EstError::config("Invalid UTF-8 in credential password")
            })?;

            // Free the credential memory
            CredFree(pcredential as *const _);

            tracing::debug!("Successfully read credential from Windows Credential Manager");
            Ok(password)
        }
    }

    /// Non-Windows stub for credential manager.
    #[cfg(not(windows))]
    fn read_credential_manager(&self, target_name: &str) -> Result<String, EstError> {
        Err(EstError::config(
            "Windows Credential Manager is only available on Windows",
        ))
    }
}

/// EST server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// EST server URL (must be HTTPS).
    pub url: String,

    /// Optional CA label for multi-CA deployments.
    #[serde(default)]
    pub ca_label: Option<String>,

    /// Request timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,

    /// Enable TLS channel binding (RFC 7030 Section 3.5).
    #[serde(default)]
    pub channel_binding: Option<bool>,
}

fn default_timeout() -> u64 {
    60
}

/// TLS trust configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct TrustConfig {
    /// Trust verification mode.
    #[serde(default)]
    pub mode: TrustMode,

    /// Path to CA certificate bundle (PEM format).
    /// Required when mode is "explicit".
    #[serde(default)]
    pub ca_bundle_path: Option<PathBuf>,

    /// Expected CA certificate fingerprint for bootstrap mode.
    /// Format: "sha256:AB:CD:EF:..." or just hex digits.
    #[serde(default)]
    pub bootstrap_fingerprint: Option<String>,
}

/// Trust verification mode.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustMode {
    /// Use system/Mozilla root CA certificates.
    #[default]
    WebPki,

    /// Use explicit CA certificates from a file.
    Explicit,

    /// Bootstrap mode (TOFU) with fingerprint verification.
    Bootstrap,

    /// Accept any certificate (INSECURE - testing only).
    Insecure,
}

/// Authentication configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AuthenticationConfig {
    /// Authentication method.
    #[serde(default)]
    pub method: AuthMethod,

    /// Username for HTTP Basic authentication.
    /// Supports variable expansion (e.g., "${COMPUTERNAME}").
    #[serde(default)]
    pub username: Option<String>,

    /// Password source for HTTP Basic authentication.
    /// Values: "credential_manager", "env:VAR_NAME", "file:/path/to/file"
    #[serde(default)]
    pub password_source: Option<String>,

    /// Windows certificate store for client certificate auth.
    /// Format: "StoreLocation\\StoreName" (e.g., "LocalMachine\\My").
    #[serde(default)]
    pub cert_store: Option<String>,

    /// Certificate thumbprint to use from the store.
    /// Use "auto" to select based on subject or issuer.
    #[serde(default)]
    pub cert_thumbprint: Option<String>,

    /// Path to client certificate file (PEM format).
    #[serde(default)]
    pub cert_path: Option<PathBuf>,

    /// Path to client private key file (PEM format).
    #[serde(default)]
    pub key_path: Option<PathBuf>,
}

/// Authentication method.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    /// No authentication (server allows anonymous enrollment).
    #[default]
    None,

    /// HTTP Basic authentication.
    HttpBasic,

    /// TLS client certificate authentication.
    ClientCert,

    /// Automatic: use client cert if available, fall back to HTTP Basic.
    Auto,
}

/// Certificate configuration (subject, SANs, extensions).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateConfig {
    /// Common Name (CN) for the certificate subject.
    /// Supports variable expansion.
    pub common_name: String,

    /// Organization (O) for the certificate subject.
    #[serde(default)]
    pub organization: Option<String>,

    /// Organizational Unit (OU) for the certificate subject.
    #[serde(default)]
    pub organizational_unit: Option<String>,

    /// Country (C) for the certificate subject.
    #[serde(default)]
    pub country: Option<String>,

    /// State/Province (ST) for the certificate subject.
    #[serde(default)]
    pub state: Option<String>,

    /// Locality (L) for the certificate subject.
    #[serde(default)]
    pub locality: Option<String>,

    /// Subject Alternative Names configuration.
    #[serde(default)]
    pub san: Option<SanConfig>,

    /// Key generation configuration.
    #[serde(default)]
    pub key: Option<KeyConfig>,

    /// Certificate extensions configuration.
    #[serde(default)]
    pub extensions: Option<ExtensionsConfig>,
}

/// Subject Alternative Names configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SanConfig {
    /// DNS names to include as SANs.
    /// Supports variable expansion.
    #[serde(default)]
    pub dns: Vec<String>,

    /// IP addresses to include as SANs.
    #[serde(default)]
    pub ip: Vec<IpAddr>,

    /// Email addresses to include as SANs.
    #[serde(default)]
    pub email: Vec<String>,

    /// URIs to include as SANs.
    #[serde(default)]
    pub uri: Vec<String>,

    /// Automatically include detected IP addresses.
    #[serde(default)]
    pub include_ip: bool,
}

/// Key generation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyConfig {
    /// Key algorithm.
    #[serde(default)]
    pub algorithm: KeyAlgorithm,

    /// Key storage provider.
    #[serde(default)]
    pub provider: KeyProvider,

    /// Mark private key as non-exportable (Windows CNG).
    #[serde(default = "default_true")]
    pub non_exportable: bool,

    /// Enable TPM key attestation.
    #[serde(default)]
    pub attestation: bool,
}

impl Default for KeyConfig {
    fn default() -> Self {
        Self {
            algorithm: KeyAlgorithm::default(),
            provider: KeyProvider::default(),
            non_exportable: true,
            attestation: false,
        }
    }
}

fn default_true() -> bool {
    true
}

/// Supported key algorithms.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyAlgorithm {
    /// ECDSA with P-256 curve (recommended).
    #[default]
    #[serde(rename = "ecdsa-p256")]
    EcdsaP256,

    /// ECDSA with P-384 curve.
    #[serde(rename = "ecdsa-p384")]
    EcdsaP384,

    /// RSA 2048-bit.
    #[serde(rename = "rsa-2048")]
    Rsa2048,

    /// RSA 3072-bit.
    #[serde(rename = "rsa-3072")]
    Rsa3072,

    /// RSA 4096-bit.
    #[serde(rename = "rsa-4096")]
    Rsa4096,
}

/// Key storage provider.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyProvider {
    /// Software key storage (in-memory or file-based).
    #[default]
    Software,

    /// Windows CNG (Cryptography Next Generation).
    Cng,

    /// TPM 2.0 via platform crypto provider.
    Tpm,

    /// PKCS#11 hardware security module.
    Pkcs11,
}

/// Certificate extensions configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ExtensionsConfig {
    /// Key usage flags.
    #[serde(default)]
    pub key_usage: Vec<KeyUsage>,

    /// Extended key usage OIDs.
    #[serde(default)]
    pub extended_key_usage: Vec<ExtendedKeyUsage>,
}

/// Key usage flags.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyUsage {
    /// Digital signature.
    DigitalSignature,

    /// Non-repudiation / content commitment.
    NonRepudiation,

    /// Key encipherment.
    KeyEncipherment,

    /// Data encipherment.
    DataEncipherment,

    /// Key agreement.
    KeyAgreement,

    /// Certificate signing.
    KeyCertSign,

    /// CRL signing.
    CrlSign,

    /// Encipher only (with key agreement).
    EncipherOnly,

    /// Decipher only (with key agreement).
    DecipherOnly,
}

/// Extended key usage purposes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExtendedKeyUsage {
    /// TLS server authentication.
    ServerAuth,

    /// TLS client authentication.
    ClientAuth,

    /// Code signing.
    CodeSigning,

    /// Email protection (S/MIME).
    EmailProtection,

    /// Timestamping.
    TimeStamping,

    /// OCSP signing.
    OcspSigning,

    /// Smart card logon (Windows).
    SmartCardLogon,
}

/// Renewal configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenewalConfig {
    /// Enable automatic renewal.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Days before expiration to trigger renewal.
    #[serde(default = "default_threshold_days")]
    pub threshold_days: u32,

    /// Hours between expiration checks.
    #[serde(default = "default_check_interval")]
    pub check_interval_hours: u32,

    /// Maximum retry attempts for failed renewals.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Minutes between retry attempts (base value for exponential backoff).
    #[serde(default = "default_retry_delay")]
    pub retry_delay_minutes: u32,
}

impl Default for RenewalConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold_days: 30,
            check_interval_hours: 6,
            max_retries: 5,
            retry_delay_minutes: 30,
        }
    }
}

fn default_threshold_days() -> u32 {
    30
}

fn default_check_interval() -> u32 {
    6
}

fn default_max_retries() -> u32 {
    5
}

fn default_retry_delay() -> u32 {
    30
}

/// Certificate storage configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    /// Windows certificate store location.
    /// Format: "StoreLocation\\StoreName" (e.g., "LocalMachine\\My").
    #[serde(default)]
    pub windows_store: Option<String>,

    /// Friendly name for the certificate in Windows store.
    #[serde(default)]
    pub friendly_name: Option<String>,

    /// CNG storage provider name (Windows only).
    /// Examples: "Microsoft Software Key Storage Provider" (default),
    ///           "Microsoft Platform Crypto Provider" (TPM),
    ///           "Microsoft Smart Card Key Storage Provider"
    #[serde(default)]
    #[cfg(windows)]
    pub cng_provider: Option<String>,

    /// Path to save certificate (PEM format).
    #[serde(default)]
    pub cert_path: Option<PathBuf>,

    /// Path to save private key (PEM format).
    /// DEPRECATED: Private keys are now stored in Windows CNG.
    /// This field is ignored and will be removed in a future version.
    #[serde(default)]
    #[deprecated(
        since = "1.1.0",
        note = "Private keys are now stored in Windows CNG. This field is ignored."
    )]
    pub key_path: Option<PathBuf>,

    /// Path to save certificate chain (PEM format).
    #[serde(default)]
    pub chain_path: Option<PathBuf>,

    /// Archive old certificates instead of deleting.
    #[serde(default)]
    pub archive_old: bool,
}

/// Logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    /// Log level: "debug", "info", "warn", "error".
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Log file path.
    #[serde(default)]
    pub path: Option<PathBuf>,

    /// Enable Windows Event Log integration.
    #[serde(default)]
    pub windows_event_log: bool,

    /// Enable structured JSON logging.
    #[serde(default)]
    pub json_format: bool,

    /// Maximum log file size in MB before rotation.
    #[serde(default)]
    pub max_size_mb: Option<u32>,

    /// Number of rotated log files to keep.
    #[serde(default)]
    pub max_files: Option<u32>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            path: None,
            windows_event_log: false,
            json_format: false,
            max_size_mb: None,
            max_files: None,
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

/// Windows Service configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    /// Service start type: "automatic", "delayed", "manual", "disabled".
    #[serde(default = "default_start_type")]
    pub start_type: String,

    /// Service account: "LocalSystem", "NetworkService", or custom account.
    #[serde(default)]
    pub run_as: Option<String>,

    /// Service dependencies (other service names).
    #[serde(default)]
    pub dependencies: Vec<String>,

    /// Enable health check HTTP endpoint.
    #[serde(default)]
    pub health_check_port: Option<u16>,
}

fn default_start_type() -> String {
    "automatic".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minimal_config_parsing() {
        let toml = r#"
[server]
url = "https://est.example.com"

[certificate]
common_name = "test.example.com"
"#;

        let config = AutoEnrollConfig::from_toml(toml).unwrap();
        assert_eq!(config.server.url, "https://est.example.com");
        assert_eq!(config.certificate.common_name, "test.example.com");
        assert_eq!(config.server.timeout_seconds, 60);
        assert!(config.renewal.enabled);
    }

    #[test]
    fn test_full_config_parsing() {
        let toml = r#"
[server]
url = "https://est.example.com"
ca_label = "machines"
timeout_seconds = 120

[trust]
mode = "explicit"
ca_bundle_path = "/path/to/ca.pem"

[authentication]
method = "http_basic"
username = "machine01"
password_source = "env:EST_PASSWORD"

[certificate]
common_name = "machine01.example.com"
organization = "Example Corp"
organizational_unit = "IT"
country = "US"

[certificate.san]
dns = ["machine01.example.com", "machine01"]

[certificate.key]
algorithm = "ecdsa-p256"
provider = "software"
non_exportable = true

[certificate.extensions]
key_usage = ["digital_signature", "key_encipherment"]
extended_key_usage = ["client_auth"]

[renewal]
enabled = true
threshold_days = 30
check_interval_hours = 6

[storage]
cert_path = "/path/to/cert.pem"
key_path = "/path/to/key.pem"

[logging]
level = "info"
"#;

        let config = AutoEnrollConfig::from_toml(toml).unwrap();
        assert_eq!(config.server.ca_label, Some("machines".to_string()));
        assert_eq!(config.trust.mode, TrustMode::Explicit);
        assert_eq!(config.authentication.method, AuthMethod::HttpBasic);
        assert_eq!(
            config.certificate.key.as_ref().unwrap().algorithm,
            KeyAlgorithm::EcdsaP256
        );
    }

    #[test]
    fn test_validation_missing_url() {
        let toml = r#"
[server]
url = ""

[certificate]
common_name = "test"
"#;

        let config = AutoEnrollConfig::from_toml(toml).unwrap();
        let result = config.validate();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("server.url is required")
        );
    }

    #[test]
    fn test_validation_http_basic_without_credentials() {
        let toml = r#"
[server]
url = "https://est.example.com"

[authentication]
method = "http_basic"

[certificate]
common_name = "test"
"#;

        let config = AutoEnrollConfig::from_toml(toml).unwrap();
        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("username is required"));
    }

    #[test]
    fn test_key_algorithm_deserialization() {
        // Test that kebab-case works for deserialization
        let algo: KeyAlgorithm = serde_json::from_str("\"ecdsa-p256\"").unwrap();
        assert_eq!(algo, KeyAlgorithm::EcdsaP256);

        let algo: KeyAlgorithm = serde_json::from_str("\"rsa-2048\"").unwrap();
        assert_eq!(algo, KeyAlgorithm::Rsa2048);
    }

    // ===== Additional Phase 11.8 Tests =====

    #[test]
    fn test_invalid_toml_syntax() {
        let toml = r#"
[server
url = "https://est.example.com"
"#;

        let result = AutoEnrollConfig::from_toml(toml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid TOML"));
    }

    #[test]
    fn test_unknown_field_rejected() {
        // deny_unknown_fields should reject unknown keys
        let toml = r#"
[server]
url = "https://est.example.com"
unknown_field = "value"

[certificate]
common_name = "test"
"#;

        let result = AutoEnrollConfig::from_toml(toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_required_section() {
        // Missing [certificate] section should fail
        let toml = r#"
[server]
url = "https://est.example.com"
"#;

        let result = AutoEnrollConfig::from_toml(toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_validation_http_url_rejected() {
        let toml = r#"
[server]
url = "http://est.example.com"

[certificate]
common_name = "test"
"#;

        let config = AutoEnrollConfig::from_toml(toml).unwrap();
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("HTTPS"));
    }

    #[test]
    fn test_validation_explicit_trust_without_ca_bundle() {
        let toml = r#"
[server]
url = "https://est.example.com"

[trust]
mode = "explicit"

[certificate]
common_name = "test"
"#;

        let config = AutoEnrollConfig::from_toml(toml).unwrap();
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ca_bundle_path"));
    }

    #[test]
    fn test_validation_bootstrap_trust_without_fingerprint() {
        let toml = r#"
[server]
url = "https://est.example.com"

[trust]
mode = "bootstrap"

[certificate]
common_name = "test"
"#;

        let config = AutoEnrollConfig::from_toml(toml).unwrap();
        let result = config.validate();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("bootstrap_fingerprint")
        );
    }

    #[test]
    fn test_validation_client_cert_without_paths() {
        let toml = r#"
[server]
url = "https://est.example.com"

[authentication]
method = "client_cert"

[certificate]
common_name = "test"
"#;

        let config = AutoEnrollConfig::from_toml(toml).unwrap();
        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("cert_store") || err.contains("cert_path"));
    }

    #[test]
    fn test_validation_missing_common_name() {
        let toml = r#"
[server]
url = "https://est.example.com"

[certificate]
common_name = ""
"#;

        let config = AutoEnrollConfig::from_toml(toml).unwrap();
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("common_name"));
    }

    #[test]
    fn test_validation_renewal_zero_threshold() {
        let toml = r#"
[server]
url = "https://est.example.com"

[certificate]
common_name = "test"

[renewal]
enabled = true
threshold_days = 0
"#;

        let config = AutoEnrollConfig::from_toml(toml).unwrap();
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("threshold_days"));
    }

    #[test]
    fn test_validation_renewal_zero_check_interval() {
        let toml = r#"
[server]
url = "https://est.example.com"

[certificate]
common_name = "test"

[renewal]
enabled = true
threshold_days = 30
check_interval_hours = 0
"#;

        let config = AutoEnrollConfig::from_toml(toml).unwrap();
        let result = config.validate();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("check_interval_hours")
        );
    }

    #[test]
    fn test_valid_config_with_webpki_trust() {
        let toml = r#"
[server]
url = "https://est.example.com"

[trust]
mode = "web_pki"

[certificate]
common_name = "test.example.com"
"#;

        let config = AutoEnrollConfig::from_toml(toml).unwrap();
        assert!(config.validate().is_ok());
        assert_eq!(config.trust.mode, TrustMode::WebPki);
    }

    #[test]
    fn test_valid_config_with_insecure_trust() {
        let toml = r#"
[server]
url = "https://est.example.com"

[trust]
mode = "insecure"

[certificate]
common_name = "test.example.com"
"#;

        let config = AutoEnrollConfig::from_toml(toml).unwrap();
        assert!(config.validate().is_ok());
        assert_eq!(config.trust.mode, TrustMode::Insecure);
    }

    #[test]
    fn test_all_key_algorithms() {
        for (algo_str, expected) in [
            ("ecdsa-p256", KeyAlgorithm::EcdsaP256),
            ("ecdsa-p384", KeyAlgorithm::EcdsaP384),
            ("rsa-2048", KeyAlgorithm::Rsa2048),
            ("rsa-3072", KeyAlgorithm::Rsa3072),
            ("rsa-4096", KeyAlgorithm::Rsa4096),
        ] {
            let algo: KeyAlgorithm = serde_json::from_str(&format!("\"{algo_str}\"")).unwrap();
            assert_eq!(algo, expected);
        }
    }

    #[test]
    fn test_all_key_providers() {
        for (provider_str, expected) in [
            ("software", KeyProvider::Software),
            ("cng", KeyProvider::Cng),
            ("tpm", KeyProvider::Tpm),
            ("pkcs11", KeyProvider::Pkcs11),
        ] {
            let provider: KeyProvider =
                serde_json::from_str(&format!("\"{provider_str}\"")).unwrap();
            assert_eq!(provider, expected);
        }
    }

    #[test]
    fn test_all_trust_modes() {
        for (mode_str, expected) in [
            ("web_pki", TrustMode::WebPki),
            ("explicit", TrustMode::Explicit),
            ("bootstrap", TrustMode::Bootstrap),
            ("insecure", TrustMode::Insecure),
        ] {
            let mode: TrustMode = serde_json::from_str(&format!("\"{mode_str}\"")).unwrap();
            assert_eq!(mode, expected);
        }
    }

    #[test]
    fn test_all_auth_methods() {
        for (method_str, expected) in [
            ("none", AuthMethod::None),
            ("http_basic", AuthMethod::HttpBasic),
            ("client_cert", AuthMethod::ClientCert),
            ("auto", AuthMethod::Auto),
        ] {
            let method: AuthMethod = serde_json::from_str(&format!("\"{method_str}\"")).unwrap();
            assert_eq!(method, expected);
        }
    }

    #[test]
    fn test_key_usage_deserialization() {
        for usage_str in [
            "digital_signature",
            "non_repudiation",
            "key_encipherment",
            "data_encipherment",
            "key_agreement",
            "key_cert_sign",
            "crl_sign",
            "encipher_only",
            "decipher_only",
        ] {
            let result: Result<KeyUsage, _> = serde_json::from_str(&format!("\"{usage_str}\""));
            assert!(result.is_ok(), "Failed to parse KeyUsage: {usage_str}");
        }
    }

    #[test]
    fn test_extended_key_usage_deserialization() {
        for eku_str in [
            "server_auth",
            "client_auth",
            "code_signing",
            "email_protection",
            "time_stamping",
            "ocsp_signing",
            "smart_card_logon",
        ] {
            let result: Result<ExtendedKeyUsage, _> =
                serde_json::from_str(&format!("\"{eku_str}\""));
            assert!(
                result.is_ok(),
                "Failed to parse ExtendedKeyUsage: {eku_str}"
            );
        }
    }

    #[test]
    fn test_san_config_with_ip_addresses() {
        let toml = r#"
[server]
url = "https://est.example.com"

[certificate]
common_name = "test"

[certificate.san]
dns = ["test.example.com"]
ip = ["192.168.1.1", "10.0.0.1"]
include_ip = true
"#;

        let config = AutoEnrollConfig::from_toml(toml).unwrap();
        let san = config.certificate.san.unwrap();
        assert_eq!(san.dns.len(), 1);
        assert_eq!(san.ip.len(), 2);
        assert!(san.include_ip);
    }

    #[test]
    fn test_san_config_with_email_and_uri() {
        let toml = r#"
[server]
url = "https://est.example.com"

[certificate]
common_name = "test"

[certificate.san]
email = ["admin@example.com"]
uri = ["https://example.com/id"]
"#;

        let config = AutoEnrollConfig::from_toml(toml).unwrap();
        let san = config.certificate.san.unwrap();
        assert_eq!(san.email.len(), 1);
        assert_eq!(san.uri.len(), 1);
    }

    #[test]
    fn test_storage_config_all_fields() {
        let toml = r#"
[server]
url = "https://est.example.com"

[certificate]
common_name = "test"

[storage]
windows_store = "LocalMachine\\My"
friendly_name = "EST Certificate"
cert_path = "/etc/est/cert.pem"
key_path = "/etc/est/key.pem"
chain_path = "/etc/est/chain.pem"
archive_old = true
"#;

        let config = AutoEnrollConfig::from_toml(toml).unwrap();
        assert_eq!(
            config.storage.windows_store,
            Some("LocalMachine\\My".to_string())
        );
        assert_eq!(
            config.storage.friendly_name,
            Some("EST Certificate".to_string())
        );
        assert!(config.storage.archive_old);
    }

    #[test]
    fn test_logging_config_all_fields() {
        let toml = r#"
[server]
url = "https://est.example.com"

[certificate]
common_name = "test"

[logging]
level = "debug"
path = "/var/log/est.log"
windows_event_log = true
json_format = true
max_size_mb = 10
max_files = 5
"#;

        let config = AutoEnrollConfig::from_toml(toml).unwrap();
        assert_eq!(config.logging.level, "debug");
        assert!(config.logging.windows_event_log);
        assert!(config.logging.json_format);
        assert_eq!(config.logging.max_size_mb, Some(10));
        assert_eq!(config.logging.max_files, Some(5));
    }

    #[test]
    fn test_service_config_all_fields() {
        let toml = r#"
[server]
url = "https://est.example.com"

[certificate]
common_name = "test"

[service]
start_type = "delayed"
run_as = "NetworkService"
dependencies = ["Tcpip", "Dnscache"]
health_check_port = 8080
"#;

        let config = AutoEnrollConfig::from_toml(toml).unwrap();
        assert_eq!(config.service.start_type, "delayed");
        assert_eq!(config.service.run_as, Some("NetworkService".to_string()));
        assert_eq!(config.service.dependencies.len(), 2);
        assert_eq!(config.service.health_check_port, Some(8080));
    }

    #[test]
    fn test_config_round_trip() {
        let toml = r#"
[server]
url = "https://est.example.com"
timeout_seconds = 120

[certificate]
common_name = "test.example.com"
organization = "Test Org"
"#;

        let config = AutoEnrollConfig::from_toml(toml).unwrap();
        let serialized = config.to_toml().unwrap();
        let reparsed = AutoEnrollConfig::from_toml(&serialized).unwrap();

        assert_eq!(config.server.url, reparsed.server.url);
        assert_eq!(
            config.server.timeout_seconds,
            reparsed.server.timeout_seconds
        );
        assert_eq!(
            config.certificate.common_name,
            reparsed.certificate.common_name
        );
        assert_eq!(
            config.certificate.organization,
            reparsed.certificate.organization
        );
    }

    #[test]
    fn test_default_values() {
        let toml = r#"
[server]
url = "https://est.example.com"

[certificate]
common_name = "test"
"#;

        let config = AutoEnrollConfig::from_toml(toml).unwrap();

        // Server defaults
        assert_eq!(config.server.timeout_seconds, 60);
        assert!(config.server.ca_label.is_none());
        assert!(config.server.channel_binding.is_none());

        // Trust defaults
        assert_eq!(config.trust.mode, TrustMode::WebPki);

        // Auth defaults
        assert_eq!(config.authentication.method, AuthMethod::None);

        // Renewal defaults
        assert!(config.renewal.enabled);
        assert_eq!(config.renewal.threshold_days, 30);
        assert_eq!(config.renewal.check_interval_hours, 6);
        assert_eq!(config.renewal.max_retries, 5);
        assert_eq!(config.renewal.retry_delay_minutes, 30);

        // Logging defaults
        assert_eq!(config.logging.level, "info");
        assert!(!config.logging.windows_event_log);
        assert!(!config.logging.json_format);

        // Service defaults (uses Default trait when section is missing)
        // The #[serde(default)] uses ServiceConfig::default() which has empty strings
        assert!(config.service.run_as.is_none());
        assert!(config.service.dependencies.is_empty());
    }

    #[test]
    fn test_service_section_defaults() {
        // When [service] section exists, serde defaults apply
        let toml = r#"
[server]
url = "https://est.example.com"

[certificate]
common_name = "test"

[service]
"#;

        let config = AutoEnrollConfig::from_toml(toml).unwrap();
        // With the section present, serde defaults for individual fields apply
        assert_eq!(config.service.start_type, "automatic");
    }

    #[test]
    fn test_key_config_defaults() {
        let key_config = KeyConfig::default();
        assert_eq!(key_config.algorithm, KeyAlgorithm::EcdsaP256);
        assert_eq!(key_config.provider, KeyProvider::Software);
        assert!(key_config.non_exportable);
        assert!(!key_config.attestation);
    }

    #[test]
    fn test_valid_config_with_http_basic_auth() {
        let toml = r#"
[server]
url = "https://est.example.com"

[authentication]
method = "http_basic"
username = "testuser"
password_source = "env:EST_PASSWORD"

[certificate]
common_name = "test"
"#;

        let config = AutoEnrollConfig::from_toml(toml).unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_valid_config_with_client_cert_files() {
        let toml = r#"
[server]
url = "https://est.example.com"

[authentication]
method = "client_cert"
cert_path = "/path/to/cert.pem"
key_path = "/path/to/key.pem"

[certificate]
common_name = "test"
"#;

        let config = AutoEnrollConfig::from_toml(toml).unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_valid_config_with_client_cert_store() {
        let toml = r#"
[server]
url = "https://est.example.com"

[authentication]
method = "client_cert"
cert_store = "LocalMachine\\My"
cert_thumbprint = "auto"

[certificate]
common_name = "test"
"#;

        let config = AutoEnrollConfig::from_toml(toml).unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_valid_config_with_explicit_trust() {
        let toml = r#"
[server]
url = "https://est.example.com"

[trust]
mode = "explicit"
ca_bundle_path = "/path/to/ca-bundle.pem"

[certificate]
common_name = "test"
"#;

        let config = AutoEnrollConfig::from_toml(toml).unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_valid_config_with_bootstrap_trust() {
        let toml = r#"
[server]
url = "https://est.example.com"

[trust]
mode = "bootstrap"
bootstrap_fingerprint = "sha256:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90"

[certificate]
common_name = "test"
"#;

        let config = AutoEnrollConfig::from_toml(toml).unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_resolve_password_env_var() {
        // SAFETY: This is a test, no other threads are accessing this variable
        unsafe {
            std::env::set_var("TEST_EST_PASSWORD_12345", "secret123");
        }

        let toml = r#"
[server]
url = "https://est.example.com"

[authentication]
method = "http_basic"
username = "testuser"
password_source = "env:TEST_EST_PASSWORD_12345"

[certificate]
common_name = "test"
"#;

        let config = AutoEnrollConfig::from_toml(toml).unwrap();
        let password = config.resolve_password().unwrap();
        assert_eq!(password, "secret123");

        unsafe {
            std::env::remove_var("TEST_EST_PASSWORD_12345");
        }
    }

    #[test]
    fn test_resolve_password_missing_env_var() {
        let toml = r#"
[server]
url = "https://est.example.com"

[authentication]
method = "http_basic"
username = "testuser"
password_source = "env:DEFINITELY_NOT_SET_XYZ987654"

[certificate]
common_name = "test"
"#;

        let config = AutoEnrollConfig::from_toml(toml).unwrap();
        let result = config.resolve_password();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not set"));
    }

    #[test]
    fn test_resolve_password_unknown_source() {
        let toml = r#"
[server]
url = "https://est.example.com"

[authentication]
method = "http_basic"
username = "testuser"
password_source = "unknown_source_type"

[certificate]
common_name = "test"
"#;

        let config = AutoEnrollConfig::from_toml(toml).unwrap();
        let result = config.resolve_password();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unknown"));
    }

    #[test]
    fn test_validation_disabled_renewal_allows_zero_values() {
        let toml = r#"
[server]
url = "https://est.example.com"

[certificate]
common_name = "test"

[renewal]
enabled = false
threshold_days = 0
check_interval_hours = 0
"#;

        let config = AutoEnrollConfig::from_toml(toml).unwrap();
        // When renewal is disabled, zero values should be allowed
        assert!(config.validate().is_ok());
    }
}
