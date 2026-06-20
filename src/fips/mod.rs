// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! FIPS 140 cryptographic support (aws-lc-rs FIPS module).
//!
//! This module provides FIPS-mode configuration and policy enforcement for
//! deployments that require FIPS 140-validated cryptography.
//!
//! # Overview
//!
//! The Federal Information Processing Standard (FIPS) 140 is a U.S. government
//! standard specifying security requirements for cryptographic modules. For
//! deployment on DoD networks, systems must use FIPS 140-validated cryptographic
//! modules.
//!
//! Under the `fips` feature this crate links the **aws-lc-rs FIPS** cryptographic
//! module and routes TLS, key generation, signing, and certificate-signature
//! verification through it. On Windows, FIPS comes from the CNG FIPS module
//! instead (see [`crate::windows`] and `CngKeyProvider::new_fips`).
//!
//! ## FIPS mode
//!
//! When FIPS mode is enabled, this library:
//!
//! - Uses the aws-lc-rs FIPS module as the rustls TLS crypto provider
//! - Performs PKI operations (keygen, signing, verification) in the FIPS module
//! - Enforces FIPS-approved algorithms and minimum key sizes (RSA 2048+, P-256+)
//!
//! ## Requirements
//!
//! The `fips` feature builds the aws-lc-rs FIPS module (`aws-lc-fips-sys`), which
//! compiles on Linux x86_64/aarch64 (build deps: Go and cmake).
//!
//! ## Example
//!
//! ```no_run
//! use usg_est_client::{EstClient, EstClientConfig};
//! use usg_est_client::fips::FipsConfig;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create FIPS-compliant configuration
//! let fips_config = FipsConfig::builder()
//!     .enforce_fips_mode(true)
//!     .min_rsa_key_size(2048)
//!     .min_ecc_key_size(256)
//!     .build()?;
//!
//! let config = EstClientConfig::builder()
//!     .server_url("https://est.example.mil")?
//!     .fips_config(fips_config)
//!     .build()?;
//!
//! let client = EstClient::new(config).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## FIPS validation caveat
//!
//! Building with the `fips` feature links the aws-lc-rs FIPS module, but a build
//! is **not by itself a CMVP-validated operating environment**. FIPS 140
//! validation attaches to a specific module version operated per its Security
//! Policy; the exact CMVP-validated aws-lc version and operating conditions must
//! be confirmed for an ATO. The `aws-lc-rs` dependency is pinned to an exact
//! version for this reason.
//!
//! See: <https://csrc.nist.gov/projects/cryptographic-module-validation-program>
//!
//! ## References
//!
//! - [FIPS 140-3 Standard](https://csrc.nist.gov/pubs/fips/140-3/final)
//! - [NIST CMVP](https://csrc.nist.gov/projects/cryptographic-module-validation-program)

pub mod algorithms;

use crate::error::{EstError, Result};
use std::fmt;

/// FIPS 140 configuration for cryptographic operations.
///
/// Controls FIPS mode enforcement and algorithm restrictions.
#[derive(Debug, Clone)]
pub struct FipsConfig {
    /// Require FIPS mode to be enabled.
    pub enforce_fips_mode: bool,

    /// Minimum RSA key size in bits (default: 2048).
    pub min_rsa_key_size: u32,

    /// Minimum ECC key size in bits (default: 256 for P-256).
    pub min_ecc_key_size: u32,

    /// Block non-FIPS algorithms.
    pub block_non_fips_algorithms: bool,

    /// Require TLS 1.2 minimum (FIPS requirement).
    pub require_tls_12_minimum: bool,
}

impl Default for FipsConfig {
    fn default() -> Self {
        Self {
            enforce_fips_mode: false,
            min_rsa_key_size: 2048,
            min_ecc_key_size: 256,
            block_non_fips_algorithms: true,
            require_tls_12_minimum: true,
        }
    }
}

impl FipsConfig {
    /// Create a new FIPS configuration builder.
    pub fn builder() -> FipsConfigBuilder {
        FipsConfigBuilder::default()
    }

    /// Validate that FIPS mode is properly configured.
    ///
    /// This checks that:
    /// - Minimum key sizes meet FIPS requirements
    /// - When enforcement is required, the aws-lc-rs FIPS module is available
    ///   and active
    pub fn validate(&self) -> Result<()> {
        #[cfg(feature = "fips")]
        {
            // Validate minimum key sizes (always required for FIPS compliance)
            if self.min_rsa_key_size < 2048 {
                return Err(EstError::FipsInvalidConfig(
                    "FIPS requires RSA key size >= 2048 bits".to_string(),
                ));
            }

            if self.min_ecc_key_size < 256 {
                return Err(EstError::FipsInvalidConfig(
                    "FIPS requires ECC key size >= 256 bits (P-256)".to_string(),
                ));
            }

            // Only check FIPS availability and mode when enforcement is required
            if self.enforce_fips_mode {
                // Check the build is linked against the FIPS module
                if !is_fips_capable()? {
                    return Err(EstError::FipsNotAvailable(
                        "aws-lc-rs FIPS module is not available; the build is not \
                         linked against the FIPS module"
                            .to_string(),
                    ));
                }

                // Check the FIPS provider is the active rustls default
                if !is_fips_enabled()? {
                    return Err(EstError::FipsNotEnabled(
                        "FIPS mode is required but the FIPS crypto provider is not \
                         active; call enable_fips_mode() at startup"
                            .to_string(),
                    ));
                }
            }

            Ok(())
        }

        #[cfg(not(feature = "fips"))]
        {
            if self.enforce_fips_mode {
                Err(EstError::FipsNotAvailable(
                    "FIPS mode requires the 'fips' feature flag".to_string(),
                ))
            } else {
                Ok(())
            }
        }
    }
}

/// Builder for FIPS configuration.
#[derive(Debug, Default)]
pub struct FipsConfigBuilder {
    enforce_fips_mode: bool,
    min_rsa_key_size: u32,
    min_ecc_key_size: u32,
    block_non_fips_algorithms: bool,
    require_tls_12_minimum: bool,
}

impl FipsConfigBuilder {
    /// Enforce FIPS mode (default: false).
    ///
    /// When enabled, operations will fail if FIPS mode is not active.
    pub fn enforce_fips_mode(mut self, enforce: bool) -> Self {
        self.enforce_fips_mode = enforce;
        self
    }

    /// Set minimum RSA key size in bits (default: 2048).
    ///
    /// FIPS 140 requires RSA keys to be at least 2048 bits.
    pub fn min_rsa_key_size(mut self, bits: u32) -> Self {
        self.min_rsa_key_size = bits;
        self
    }

    /// Set minimum ECC key size in bits (default: 256).
    ///
    /// FIPS 140 requires ECC keys to be at least 256 bits (P-256 curve).
    pub fn min_ecc_key_size(mut self, bits: u32) -> Self {
        self.min_ecc_key_size = bits;
        self
    }

    /// Block non-FIPS algorithms (default: true).
    ///
    /// When enabled, attempts to use non-FIPS algorithms will fail.
    pub fn block_non_fips_algorithms(mut self, block: bool) -> Self {
        self.block_non_fips_algorithms = block;
        self
    }

    /// Require TLS 1.2 minimum (default: true).
    ///
    /// FIPS 140 requires TLS 1.2 or higher.
    pub fn require_tls_12_minimum(mut self, require: bool) -> Self {
        self.require_tls_12_minimum = require;
        self
    }

    /// Build the FIPS configuration.
    pub fn build(self) -> Result<FipsConfig> {
        let config = FipsConfig {
            enforce_fips_mode: self.enforce_fips_mode,
            min_rsa_key_size: if self.min_rsa_key_size == 0 {
                2048
            } else {
                self.min_rsa_key_size
            },
            min_ecc_key_size: if self.min_ecc_key_size == 0 {
                256
            } else {
                self.min_ecc_key_size
            },
            block_non_fips_algorithms: self.block_non_fips_algorithms,
            require_tls_12_minimum: self.require_tls_12_minimum,
        };

        // Validate configuration
        config.validate()?;

        Ok(config)
    }
}

impl fmt::Display for FipsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FipsConfig {{ enforce: {}, min_rsa: {}, min_ecc: {}, block_non_fips: {} }}",
            self.enforce_fips_mode,
            self.min_rsa_key_size,
            self.min_ecc_key_size,
            self.block_non_fips_algorithms
        )
    }
}

/// Check whether the build is linked against the aws-lc-rs FIPS module.
#[cfg(feature = "fips")]
fn is_fips_capable() -> Result<bool> {
    // The default aws-lc-rs provider reports FIPS mode when the crate is built
    // with the `fips` feature (i.e. linked against aws-lc-fips-sys).
    Ok(rustls::crypto::aws_lc_rs::default_provider().fips())
}

/// Check whether the FIPS crypto provider is currently active process-wide.
#[cfg(feature = "fips")]
fn is_fips_enabled() -> Result<bool> {
    Ok(crate::fips_tls::is_fips_active())
}

/// Enable FIPS mode by installing the aws-lc-rs FIPS provider as the process-wide
/// rustls default.
///
/// This is **fail-closed**: it returns an error if the compiled-in provider is
/// not actually in FIPS mode, so a misconfigured build cannot silently fall back
/// to non-validated cryptography. The call is idempotent.
///
/// # Errors
///
/// Returns an error if the build is not linked against the FIPS module or a
/// non-FIPS provider was already installed as the default.
#[cfg(feature = "fips")]
pub fn enable_fips_mode() -> Result<()> {
    crate::fips_tls::install_fips_provider()
}

/// Get FIPS module information.
#[cfg(feature = "fips")]
pub fn fips_module_info() -> FipsModuleInfo {
    FipsModuleInfo {
        module: "aws-lc-rs FIPS module".to_string(),
        fips_enabled: crate::fips_tls::is_fips_active(),
        fips_capable: is_fips_capable().unwrap_or(false),
    }
}

/// FIPS module information.
#[derive(Debug, Clone)]
pub struct FipsModuleInfo {
    /// Identifier of the active FIPS cryptographic module.
    pub module: String,
    /// Whether FIPS mode is currently active.
    pub fips_enabled: bool,
    /// Whether the build is linked against the FIPS module.
    pub fips_capable: bool,
}

impl fmt::Display for FipsModuleInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "FIPS Module: {}", self.module)?;
        writeln!(f, "FIPS Capable: {}", self.fips_capable)?;
        writeln!(f, "FIPS Enabled: {}", self.fips_enabled)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fips_config_builder() {
        let config = FipsConfig::builder()
            .enforce_fips_mode(false)
            .min_rsa_key_size(2048)
            .min_ecc_key_size(256)
            .build();

        #[cfg(feature = "fips")]
        {
            // With FIPS feature enabled, building should succeed
            assert!(config.is_ok());
            let config = config.unwrap();
            assert_eq!(config.min_rsa_key_size, 2048);
            assert_eq!(config.min_ecc_key_size, 256);
        }

        #[cfg(not(feature = "fips"))]
        {
            // Without FIPS feature, should succeed if not enforcing
            assert!(config.is_ok());
        }
    }

    #[test]
    fn test_fips_config_enforced_without_feature() {
        let _config = FipsConfig::builder().enforce_fips_mode(true).build();

        #[cfg(not(feature = "fips"))]
        {
            // Should fail when enforcing FIPS without feature
            assert!(_config.is_err());
        }
    }

    #[test]
    fn test_fips_config_minimum_key_sizes() {
        // RSA key size below 2048 should fail
        let config = FipsConfig::builder()
            .enforce_fips_mode(false)
            .min_rsa_key_size(1024)
            .build();

        assert!(config.is_err());

        // ECC key size below 256 should fail
        let config = FipsConfig::builder()
            .enforce_fips_mode(false)
            .min_ecc_key_size(192)
            .build();

        assert!(config.is_err());
    }

    #[test]
    fn test_fips_config_display() {
        let config = FipsConfig::default();
        let display = format!("{}", config);
        assert!(display.contains("enforce: false"));
        assert!(display.contains("min_rsa: 2048"));
        assert!(display.contains("min_ecc: 256"));
    }

    #[cfg(feature = "fips")]
    #[test]
    fn test_fips_module_info() {
        let info = fips_module_info();
        assert!(!info.module.is_empty());
        println!("{}", info);
    }
}
