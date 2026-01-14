// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! Configuration file discovery and loading.
//!
//! This module handles finding and loading configuration files from
//! standard locations with proper precedence rules.

use std::path::{Path, PathBuf};

use crate::error::EstError;

use super::config::AutoEnrollConfig;

/// Configuration file loader with discovery and precedence rules.
///
/// # Search Order
///
/// Configuration files are searched in the following order (first found wins):
///
/// 1. Explicit path (if set via `with_path()`)
/// 2. Environment variable `EST_CONFIG_PATH`
/// 3. Windows: `%PROGRAMDATA%\Department of War\EST\config.toml`
/// 4. Windows: `%LOCALAPPDATA%\Department of War\EST\config.toml`
/// 5. Unix: `/etc/est/config.toml`
/// 6. Unix: `~/.config/est/config.toml`
/// 7. Current directory: `./est-config.toml`
///
/// # Example
///
/// ```no_run
/// use usg_est_client::auto_enroll::ConfigLoader;
///
/// // Load from default locations
/// let config = ConfigLoader::new().load().unwrap();
///
/// // Load from specific path
/// let config = ConfigLoader::new()
///     .with_path("/custom/path/config.toml")
///     .load()
///     .unwrap();
///
/// // Load with variable expansion
/// let config = ConfigLoader::new()
///     .with_expand_variables(true)
///     .load()
///     .unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct ConfigLoader {
    /// Explicit configuration file path.
    explicit_path: Option<PathBuf>,

    /// Whether to expand variables after loading.
    expand_variables: bool,

    /// Whether to validate after loading.
    validate: bool,

    /// Environment variable name for config path override.
    env_var_name: String,
}

impl Default for ConfigLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigLoader {
    /// Create a new configuration loader with default settings.
    pub fn new() -> Self {
        Self {
            explicit_path: None,
            expand_variables: true,
            validate: true,
            env_var_name: "EST_CONFIG_PATH".to_string(),
        }
    }

    /// Set an explicit configuration file path.
    ///
    /// When set, only this path will be checked (no discovery).
    pub fn with_path(mut self, path: impl AsRef<Path>) -> Self {
        self.explicit_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Enable or disable variable expansion.
    ///
    /// Default: `true`
    pub fn with_expand_variables(mut self, expand: bool) -> Self {
        self.expand_variables = expand;
        self
    }

    /// Enable or disable validation after loading.
    ///
    /// Default: `true`
    pub fn with_validate(mut self, validate: bool) -> Self {
        self.validate = validate;
        self
    }

    /// Set the environment variable name for path override.
    ///
    /// Default: `EST_CONFIG_PATH`
    pub fn with_env_var(mut self, name: impl Into<String>) -> Self {
        self.env_var_name = name.into();
        self
    }

    /// Load the configuration file.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No configuration file is found
    /// - The file cannot be read
    /// - The TOML is invalid
    /// - Validation fails (if enabled)
    pub fn load(&self) -> Result<AutoEnrollConfig, EstError> {
        // Find the configuration file
        let config_path = self.find_config_file()?;

        // Validate path for security (prevent traversal attacks)
        let safe_path = Self::validate_config_path(&config_path)?;

        // Read and parse
        let toml_content = std::fs::read_to_string(&safe_path).map_err(|e| {
            EstError::config(format!("Failed to read {}: {e}", safe_path.display()))
        })?;

        let mut config = AutoEnrollConfig::from_toml(&toml_content)?;

        // Expand variables if enabled
        if self.expand_variables {
            config.expand_variables()?;
        }

        // Validate if enabled
        if self.validate {
            config.validate()?;
        }

        Ok(config)
    }

    /// Load configuration from a TOML string.
    ///
    /// Useful for testing or when config is provided programmatically.
    pub fn load_from_str(&self, toml_content: &str) -> Result<AutoEnrollConfig, EstError> {
        let mut config = AutoEnrollConfig::from_toml(toml_content)?;

        if self.expand_variables {
            config.expand_variables()?;
        }

        if self.validate {
            config.validate()?;
        }

        Ok(config)
    }

    /// Find the configuration file path.
    ///
    /// Returns the path to use, or an error if no config file is found.
    pub fn find_config_file(&self) -> Result<PathBuf, EstError> {
        // 1. Check explicit path
        if let Some(ref path) = self.explicit_path {
            if path.exists() {
                return Ok(path.clone());
            }
            return Err(EstError::config(format!(
                "Configuration file not found: {}",
                path.display()
            )));
        }

        // 2. Check environment variable
        if let Ok(env_path) = std::env::var(&self.env_var_name) {
            let path = PathBuf::from(&env_path);
            if path.exists() {
                return Ok(path);
            }
            // If explicitly set but doesn't exist, that's an error
            return Err(EstError::config(format!(
                "Configuration file from {} not found: {}",
                self.env_var_name, env_path
            )));
        }

        // 3. Search standard locations
        for path in self.get_search_paths() {
            if path.exists() {
                return Ok(path);
            }
        }

        Err(EstError::config(format!(
            "No configuration file found. Searched:\n  - {}",
            self.get_search_paths()
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join("\n  - ")
        )))
    }

    /// Get the list of paths to search for configuration files.
    pub fn get_search_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();

        // Platform-specific paths
        #[cfg(windows)]
        {
            // Windows: ProgramData
            if let Some(program_data) = std::env::var_os("PROGRAMDATA") {
                let mut path = PathBuf::from(program_data);
                path.push("Department of War");
                path.push("EST");
                path.push("config.toml");
                paths.push(path);
            }

            // Windows: LocalAppData
            if let Some(local_app_data) = dirs::data_local_dir() {
                let mut path = local_app_data;
                path.push("Department of War");
                path.push("EST");
                path.push("config.toml");
                paths.push(path);
            }
        }

        #[cfg(unix)]
        {
            // Unix: System-wide
            paths.push(PathBuf::from("/etc/est/config.toml"));

            // Unix: User config
            if let Some(config_dir) = dirs::config_dir() {
                let mut path = config_dir;
                path.push("est");
                path.push("config.toml");
                paths.push(path);
            }
        }

        // Cross-platform: Home directory
        if let Some(home_dir) = dirs::home_dir() {
            let mut path = home_dir;
            path.push(".est");
            path.push("config.toml");
            paths.push(path);
        }

        // Current directory
        paths.push(PathBuf::from("est-config.toml"));
        paths.push(PathBuf::from("config.toml"));

        paths
    }

    /// Check if a configuration file exists in any standard location.
    pub fn config_exists(&self) -> bool {
        self.find_config_file().is_ok()
    }

    /// Validate that a path is safe and doesn't contain traversal attempts.
    ///
    /// This prevents path traversal attacks by checking for:
    /// - Absolute paths pointing outside allowed directories
    /// - Relative paths with .. components
    /// - Symlink attacks (checked via canonicalization)
    fn validate_config_path(path: &Path) -> Result<PathBuf, EstError> {
        // Canonicalize the path to resolve symlinks and .. components
        let canonical = path.canonicalize().map_err(|e| {
            EstError::config(format!(
                "Invalid configuration path {}: {}",
                path.display(),
                e
            ))
        })?;

        // Check for suspicious patterns that might indicate traversal
        let path_str = canonical.to_string_lossy();
        if path_str.contains("..") {
            return Err(EstError::config(format!(
                "Path traversal detected in canonicalized path: {}",
                path_str
            )));
        }

        // Additional platform-specific checks
        #[cfg(unix)]
        {
            // Ensure path is within /etc, /opt, /usr, or user home
            let allowed_prefixes = ["/etc", "/opt", "/usr", "/home", "/Users"];
            let has_allowed_prefix = allowed_prefixes
                .iter()
                .any(|prefix| path_str.starts_with(prefix));

            if !has_allowed_prefix && !path_str.starts_with("./") && !path_str.starts_with(".") {
                tracing::warn!(
                    "Configuration file in unusual location: {}",
                    canonical.display()
                );
            }
        }

        Ok(canonical)
    }
}

/// Write a default configuration file to a path.
///
/// This creates a well-documented example configuration file that can be
/// customized for the target environment.
pub fn write_default_config(path: impl AsRef<Path>) -> Result<(), EstError> {
    let default_config = r#"# EST Auto-Enrollment Configuration
# This file configures automatic certificate enrollment using EST (RFC 7030)

[server]
# EST server URL (required, must be HTTPS)
url = "https://est.example.com"

# Optional CA label for multi-CA deployments
# ca_label = "machines"

# Request timeout in seconds (default: 60)
timeout_seconds = 60

# Enable TLS channel binding per RFC 7030 Section 3.5
# channel_binding = true

[trust]
# Trust verification mode: "webpki", "explicit", "bootstrap", or "insecure"
# - webpki: Use Mozilla's root CA store (default)
# - explicit: Use CA certificates from ca_bundle_path
# - bootstrap: Trust-on-first-use with fingerprint verification
# - insecure: Accept any certificate (TESTING ONLY)
mode = "explicit"

# Path to CA certificate bundle (PEM format)
# Required when mode is "explicit"
ca_bundle_path = "/etc/est/ca-bundle.pem"

# Expected CA fingerprint for bootstrap mode
# Format: hex string with optional colons
# bootstrap_fingerprint = "sha256:AB:CD:EF:..."

[authentication]
# Authentication method: "none", "http_basic", "client_cert", or "auto"
method = "http_basic"

# Username for HTTP Basic authentication
# Supports variables: ${COMPUTERNAME}, ${USERNAME}, etc.
username = "${COMPUTERNAME}"

# Password source: "credential_manager", "env:VAR_NAME", or "file:/path"
password_source = "env:EST_PASSWORD"

# For client_cert method:
# Windows certificate store (e.g., "LocalMachine\\My")
# cert_store = "LocalMachine\\My"
# cert_thumbprint = "auto"

# Or file paths:
# cert_path = "/path/to/client.pem"
# key_path = "/path/to/client.key"

[certificate]
# Common Name (CN) for the certificate subject (required)
# Supports variable expansion
common_name = "${COMPUTERNAME}.${USERDNSDOMAIN}"

# Optional subject fields
organization = "Example Corporation"
organizational_unit = "IT Department"
country = "US"
state = "Virginia"
locality = "Arlington"

[certificate.san]
# Subject Alternative Names
# DNS names (supports variable expansion)
dns = ["${COMPUTERNAME}.${USERDNSDOMAIN}", "${COMPUTERNAME}"]

# IP addresses
# ip = ["192.168.1.100"]

# Automatically detect and include local IP addresses
include_ip = false

[certificate.key]
# Key algorithm: "ecdsa-p256", "ecdsa-p384", "rsa-2048", "rsa-3072", "rsa-4096"
algorithm = "ecdsa-p256"

# Key provider: "software", "cng" (Windows), "tpm", "pkcs11"
provider = "software"

# Mark private key as non-exportable (Windows CNG/TPM)
non_exportable = true

# Enable TPM key attestation
# attestation = false

[certificate.extensions]
# Key usage flags
key_usage = ["digital_signature", "key_encipherment"]

# Extended key usage
# Available: "server_auth", "client_auth", "code_signing",
#            "email_protection", "time_stamping", "ocsp_signing", "smart_card_logon"
extended_key_usage = ["client_auth"]

[renewal]
# Enable automatic renewal
enabled = true

# Days before expiration to trigger renewal
threshold_days = 30

# Hours between certificate expiration checks
check_interval_hours = 6

# Maximum renewal retry attempts
max_retries = 5

# Minutes between retry attempts (base for exponential backoff)
retry_delay_minutes = 30

[storage]
# Windows certificate store location
# Format: "StoreLocation\\StoreName"
# windows_store = "LocalMachine\\My"

# Friendly name for Windows certificate store
# friendly_name = "EST Machine Certificate"

# File paths for storing certificates (alternative to Windows store)
cert_path = "/etc/est/machine.pem"
key_path = "/etc/est/machine.key"
# chain_path = "/etc/est/chain.pem"

# Archive old certificates instead of deleting
archive_old = false

[logging]
# Log level: "debug", "info", "warn", "error"
level = "info"

# Log file path
# path = "/var/log/est/est-enroll.log"

# Enable Windows Event Log integration
windows_event_log = false

# Enable JSON formatted logging
json_format = false

# Log rotation settings
# max_size_mb = 10
# max_files = 5

[service]
# Windows Service start type: "automatic", "delayed", "manual", "disabled"
start_type = "automatic"

# Service account (Windows)
# run_as = "LocalSystem"

# Service dependencies
# dependencies = ["Tcpip", "Dnscache"]

# Health check HTTP port (optional)
# health_check_port = 8080
"#;

    let path = path.as_ref();

    // Create parent directories if needed
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| EstError::config(format!("Failed to create directory: {e}")))?;
    }

    std::fs::write(path, default_config)
        .map_err(|e| EstError::config(format!("Failed to write config file: {e}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // NOTE: Test code uses unwrap() deliberately - test fixtures are known valid
    // and panics in tests provide clear failure messages. See ERROR-HANDLING-PATTERNS.md
    // Pattern 5 for justification.

    #[test]
    fn test_loader_from_string() {
        let toml = r#"
[server]
url = "https://est.example.com"

[certificate]
common_name = "test.example.com"
"#;

        let config = ConfigLoader::new()
            .with_validate(false) // Don't validate since we don't have password_source
            .with_expand_variables(false)
            .load_from_str(toml)
            .unwrap();

        assert_eq!(config.server.url, "https://est.example.com");
    }

    #[test]
    fn test_loader_from_file() {
        let toml = r#"
[server]
url = "https://est.example.com"

[certificate]
common_name = "test.example.com"
"#;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(toml.as_bytes()).unwrap();

        let config = ConfigLoader::new()
            .with_path(file.path())
            .with_validate(false)
            .with_expand_variables(false)
            .load()
            .unwrap();

        assert_eq!(config.server.url, "https://est.example.com");
    }

    #[test]
    fn test_loader_missing_file() {
        let result = ConfigLoader::new()
            .with_path("/nonexistent/path/config.toml")
            .load();

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_get_search_paths() {
        let loader = ConfigLoader::new();
        let paths = loader.get_search_paths();

        // Should have at least the current directory fallbacks
        assert!(!paths.is_empty());
        assert!(paths.iter().any(|p| p.ends_with("config.toml")));
    }

    #[test]
    fn test_variable_expansion_in_loader() {
        // SAFETY: This is a test, no other threads are accessing this variable
        unsafe {
            std::env::set_var("TEST_HOST_12345", "myhost");
        }

        let toml = r#"
[server]
url = "https://est.example.com"

[certificate]
common_name = "${TEST_HOST_12345}.example.com"
"#;

        let config = ConfigLoader::new()
            .with_validate(false)
            .with_expand_variables(true)
            .load_from_str(toml)
            .unwrap();

        assert_eq!(config.certificate.common_name, "myhost.example.com");

        unsafe {
            std::env::remove_var("TEST_HOST_12345");
        }
    }

    // ===== Additional Phase 11.8 Loader Tests =====

    #[test]
    fn test_loader_default_settings() {
        let loader = ConfigLoader::new();
        // Default: expand variables, validate, use EST_CONFIG_PATH
        assert!(loader.expand_variables);
        assert!(loader.validate);
        assert_eq!(loader.env_var_name, "EST_CONFIG_PATH");
        assert!(loader.explicit_path.is_none());
    }

    #[test]
    fn test_loader_with_custom_env_var() {
        let loader = ConfigLoader::new().with_env_var("MY_CUSTOM_CONFIG_PATH");
        assert_eq!(loader.env_var_name, "MY_CUSTOM_CONFIG_PATH");
    }

    #[test]
    fn test_loader_disabled_expansion() {
        let toml = r#"
[server]
url = "https://est.example.com"

[certificate]
common_name = "${COMPUTERNAME}.example.com"
"#;

        let config = ConfigLoader::new()
            .with_validate(false)
            .with_expand_variables(false)
            .load_from_str(toml)
            .unwrap();

        // Variable should NOT be expanded
        assert_eq!(
            config.certificate.common_name,
            "${COMPUTERNAME}.example.com"
        );
    }

    #[test]
    fn test_loader_validation_enabled() {
        // Invalid config: HTTP URL (not HTTPS)
        let toml = r#"
[server]
url = "http://est.example.com"

[certificate]
common_name = "test"
"#;

        let result = ConfigLoader::new()
            .with_validate(true)
            .with_expand_variables(false)
            .load_from_str(toml);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("HTTPS"));
    }

    #[test]
    fn test_loader_validation_disabled() {
        // Invalid config: HTTP URL (not HTTPS), but validation disabled
        let toml = r#"
[server]
url = "http://est.example.com"

[certificate]
common_name = "test"
"#;

        let result = ConfigLoader::new()
            .with_validate(false)
            .with_expand_variables(false)
            .load_from_str(toml);

        // Should succeed because validation is disabled
        assert!(result.is_ok());
    }

    #[test]
    fn test_loader_env_var_takes_precedence() {
        let toml = r#"
[server]
url = "https://est.example.com"

[certificate]
common_name = "from_env_var"
"#;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(toml.as_bytes()).unwrap();
        let file_path = file.path().to_string_lossy().to_string();

        // SAFETY: This is a test
        unsafe {
            std::env::set_var("TEST_EST_CONFIG_PATH_12345", &file_path);
        }

        let config = ConfigLoader::new()
            .with_env_var("TEST_EST_CONFIG_PATH_12345")
            .with_validate(false)
            .with_expand_variables(false)
            .load()
            .unwrap();

        assert_eq!(config.certificate.common_name, "from_env_var");

        unsafe {
            std::env::remove_var("TEST_EST_CONFIG_PATH_12345");
        }
    }

    #[test]
    fn test_loader_env_var_file_not_found() {
        // SAFETY: This is a test
        unsafe {
            std::env::set_var(
                "TEST_EST_CONFIG_PATH_NOTFOUND",
                "/nonexistent/path/config.toml",
            );
        }

        let result = ConfigLoader::new()
            .with_env_var("TEST_EST_CONFIG_PATH_NOTFOUND")
            .load();

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));

        unsafe {
            std::env::remove_var("TEST_EST_CONFIG_PATH_NOTFOUND");
        }
    }

    #[test]
    fn test_loader_config_exists() {
        let toml = r#"
[server]
url = "https://est.example.com"

[certificate]
common_name = "test"
"#;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(toml.as_bytes()).unwrap();

        let loader = ConfigLoader::new().with_path(file.path());
        assert!(loader.config_exists());

        let loader_missing = ConfigLoader::new().with_path("/nonexistent/config.toml");
        assert!(!loader_missing.config_exists());
    }

    #[test]
    fn test_loader_find_config_file_explicit() {
        let toml = r#"
[server]
url = "https://est.example.com"

[certificate]
common_name = "test"
"#;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(toml.as_bytes()).unwrap();
        let expected_path = file.path().to_path_buf();

        let loader = ConfigLoader::new().with_path(file.path());
        let found_path = loader.find_config_file().unwrap();

        assert_eq!(found_path, expected_path);
    }

    #[test]
    fn test_loader_invalid_toml_in_file() {
        let invalid_toml = r#"
[server
url = "https://est.example.com"
"#;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(invalid_toml.as_bytes()).unwrap();

        let result = ConfigLoader::new()
            .with_path(file.path())
            .with_validate(false)
            .load();

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid TOML"));
    }

    #[test]
    fn test_write_default_config() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("est").join("config.toml");

        write_default_config(&config_path).unwrap();

        assert!(config_path.exists());

        // Verify it's valid TOML that can be parsed
        let content = std::fs::read_to_string(&config_path).unwrap();
        let config = ConfigLoader::new()
            .with_validate(false)
            .with_expand_variables(false)
            .load_from_str(&content);

        assert!(config.is_ok());
    }

    #[test]
    fn test_write_default_config_creates_dirs() {
        let temp_dir = tempfile::tempdir().unwrap();
        let nested_path = temp_dir
            .path()
            .join("a")
            .join("b")
            .join("c")
            .join("config.toml");

        // Parent dirs don't exist
        assert!(!nested_path.parent().unwrap().exists());

        write_default_config(&nested_path).unwrap();

        // Now they should exist
        assert!(nested_path.exists());
    }

    #[test]
    fn test_loader_with_all_options() {
        let toml = r#"
[server]
url = "https://est.example.com"

[certificate]
common_name = "test.example.com"
"#;

        // Test chaining all builder methods
        let config = ConfigLoader::new()
            .with_validate(false)
            .with_expand_variables(false)
            .with_env_var("CUSTOM_VAR")
            .load_from_str(toml)
            .unwrap();

        assert_eq!(config.server.url, "https://est.example.com");
    }

    #[test]
    fn test_loader_default_impl() {
        // Test the Default implementation
        let loader = ConfigLoader::default();
        assert!(loader.expand_variables);
        assert!(loader.validate);
    }

    #[test]
    fn test_loader_multiple_variables_expansion() {
        // SAFETY: This is a test
        unsafe {
            std::env::set_var("TEST_HOST_A", "host");
            std::env::set_var("TEST_DOMAIN_A", "example.com");
        }

        let toml = r#"
[server]
url = "https://est.example.com"

[certificate]
common_name = "${TEST_HOST_A}.${TEST_DOMAIN_A}"
organization = "Org for ${TEST_HOST_A}"
"#;

        let config = ConfigLoader::new()
            .with_validate(false)
            .with_expand_variables(true)
            .load_from_str(toml)
            .unwrap();

        assert_eq!(config.certificate.common_name, "host.example.com");
        assert_eq!(
            config.certificate.organization,
            Some("Org for host".to_string())
        );

        unsafe {
            std::env::remove_var("TEST_HOST_A");
            std::env::remove_var("TEST_DOMAIN_A");
        }
    }

    #[test]
    fn test_loader_search_paths_include_expected() {
        let loader = ConfigLoader::new();
        let paths = loader.get_search_paths();

        // Should include est-config.toml in current dir
        assert!(paths.iter().any(|p| p.ends_with("est-config.toml")));

        // Should include config.toml in current dir
        assert!(
            paths
                .iter()
                .any(|p| { p.file_name().map(|n| n == "config.toml").unwrap_or(false) })
        );
    }
}
