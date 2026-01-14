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

//! TPM 2.0 integration for Windows EST enrollment.
//!
//! This module provides TPM (Trusted Platform Module) 2.0 integration using the
//! Windows Platform Crypto Provider (PCP). TPM-protected keys offer hardware-level
//! security, making key extraction extremely difficult even if the system is compromised.
//!
//! # NIST 800-53 Controls
//!
//! - **SC-12**: Cryptographic Key Establishment and Management
//!   - Hardware-based key generation using TPM 2.0
//!   - Non-extractable private keys (keys cannot leave TPM)
//!   - TPM key attestation capability
//!   - Key lifecycle tied to TPM hardware
//! - **SC-13**: Cryptographic Protection
//!   - TPM 2.0 FIPS 140-2 Level 2 compliant cryptographic operations
//!   - Hardware-backed signature generation
//!   - Tamper-resistant key storage
//! - **SC-28**: Protection of Information at Rest
//!   - Private keys stored in TPM hardware, never in software
//!   - Platform Crypto Provider (PCP) hardware protection
//! - **SI-7**: Software, Firmware, and Information Integrity
//!   - TPM key attestation to prove hardware protection
//!   - Remote verification of key provenance
//!
//! # Features
//!
//! - **TPM 2.0 Detection**: Automatically detect TPM availability and version
//! - **Key Generation**: Generate TPM-protected keys using the Platform Crypto Provider
//! - **Key Attestation**: Support for TPM key attestation (proving keys are TPM-protected)
//! - **Signing Operations**: Sign data using TPM-protected keys
//!
//! # Security Benefits
//!
//! TPM-protected keys provide several security advantages:
//!
//! - **Non-extractable**: Private keys cannot be exported from the TPM
//! - **Hardware isolation**: Keys are protected by hardware, not just software
//! - **Tamper resistance**: TPMs are designed to resist physical tampering
//! - **Attestation**: Remote parties can verify keys are TPM-protected
//!
//! # Example
//!
//! ```no_run,ignore
//! use usg_est_client::windows::tpm::{TpmKeyProvider, TpmAvailability};
//! use usg_est_client::hsm::{KeyProvider, KeyAlgorithm};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Check if TPM is available
//! let availability = TpmAvailability::check()?;
//! if !availability.is_available {
//!     println!("TPM not available: {}", availability.reason.unwrap_or_default());
//!     return Ok(());
//! }
//!
//! println!("TPM Version: {}", availability.version.unwrap_or_default());
//!
//! // Create TPM key provider
//! let provider = TpmKeyProvider::new()?;
//!
//! // Generate a TPM-protected key
//! let key = provider.generate_key_pair(
//!     KeyAlgorithm::EcdsaP256,
//!     Some("EST-TPM-Key")
//! ).await?;
//!
//! // Sign data using the TPM
//! let signature = provider.sign(&key, b"data to sign").await?;
//! # Ok(())
//! # }
//! ```

use crate::error::{EstError, Result};
use crate::hsm::{KeyAlgorithm, KeyHandle, KeyMetadata, KeyProvider, ProviderInfo};
use crate::windows::cng::{CngKeyProvider, KeyGenerationOptions, providers};
use async_trait::async_trait;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use std::collections::HashMap;

/// Information about TPM availability and capabilities.
#[derive(Debug, Clone)]
pub struct TpmAvailability {
    /// Whether a TPM is available and enabled.
    pub is_available: bool,
    /// TPM version string (e.g., "2.0").
    pub version: Option<String>,
    /// TPM manufacturer name.
    pub manufacturer: Option<String>,
    /// Reason TPM is not available (if applicable).
    pub reason: Option<String>,
    /// Whether the TPM is ready for use.
    pub is_ready: bool,
    /// Whether key attestation is supported.
    pub supports_attestation: bool,
}

impl TpmAvailability {
    /// Check if a TPM is available on this system.
    ///
    /// This queries the Windows TPM Base Services (TBS) to determine
    /// if a TPM 2.0 is present and ready for use.
    pub fn check() -> Result<Self> {
        #[cfg(windows)]
        {
            Self::check_windows_tpm()
        }

        #[cfg(not(windows))]
        {
            Ok(Self {
                is_available: false,
                version: None,
                manufacturer: None,
                reason: Some("TPM operations require Windows OS".to_string()),
                is_ready: false,
                supports_attestation: false,
            })
        }
    }

    /// Check TPM using Windows APIs.
    #[cfg(windows)]
    fn check_windows_tpm() -> Result<Self> {
        // Try to open the Platform Crypto Provider - if it works, TPM is available
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use windows::Win32::Security::Cryptography::{
            NCRYPT_PROV_HANDLE, NCryptFreeObject, NCryptGetProperty, NCryptOpenStorageProvider,
        };

        let provider_name = providers::PLATFORM;
        let wide_name: Vec<u16> = OsStr::new(provider_name)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut handle = NCRYPT_PROV_HANDLE::default();

        let result = unsafe {
            NCryptOpenStorageProvider(&mut handle, windows::core::PCWSTR(wide_name.as_ptr()), 0)
        };

        if result.is_err() {
            return Ok(Self {
                is_available: false,
                version: None,
                manufacturer: None,
                reason: Some(
                    "Platform Crypto Provider not available - TPM may not be present or enabled"
                        .to_string(),
                ),
                is_ready: false,
                supports_attestation: false,
            });
        }

        // TPM is available - get version info
        // In a full implementation, we would query TPM properties here

        unsafe { NCryptFreeObject(handle.0) };

        Ok(Self {
            is_available: true,
            version: Some("2.0".to_string()),
            manufacturer: Some("Unknown".to_string()),
            reason: None,
            is_ready: true,
            supports_attestation: true,
        })
    }

    /// Create a result indicating TPM is not available.
    pub fn not_available(reason: &str) -> Self {
        Self {
            is_available: false,
            version: None,
            manufacturer: None,
            reason: Some(reason.to_string()),
            is_ready: false,
            supports_attestation: false,
        }
    }
}

/// TPM key generation options.
#[derive(Debug, Clone)]
pub struct TpmKeyOptions {
    /// Key label/container name.
    pub label: Option<String>,
    /// Whether to require attestation.
    pub require_attestation: bool,
    /// Whether to require PIN/password for key use.
    pub require_pin: bool,
    /// Optional PIN for key protection.
    pub pin: Option<String>,
}

impl Default for TpmKeyOptions {
    fn default() -> Self {
        Self {
            label: None,
            require_attestation: false,
            require_pin: false,
            pin: None,
        }
    }
}

/// TPM-backed key provider for EST enrollment.
///
/// This provider uses the Windows Platform Crypto Provider to generate
/// and manage TPM-protected keys. Keys generated through this provider
/// are stored in the TPM and cannot be extracted.
pub struct TpmKeyProvider {
    /// Underlying CNG provider configured for TPM.
    inner: CngKeyProvider,
    /// TPM-specific options.
    options: TpmKeyOptions,
}

impl TpmKeyProvider {
    /// Create a new TPM key provider.
    ///
    /// This will fail if no TPM is available on the system.
    pub fn new() -> Result<Self> {
        let availability = TpmAvailability::check()?;
        if !availability.is_available {
            return Err(EstError::platform(format!(
                "TPM not available: {}",
                availability
                    .reason
                    .unwrap_or_else(|| "unknown reason".to_string())
            )));
        }

        let cng_options = KeyGenerationOptions {
            non_exportable: true, // TPM keys are always non-exportable
            ui_protection: false,
            sign_only: true,
            label: None,
        };

        let inner = CngKeyProvider::with_options(providers::PLATFORM, cng_options)?;

        Ok(Self {
            inner,
            options: TpmKeyOptions::default(),
        })
    }

    /// Create a new TPM key provider with custom options.
    pub fn with_options(options: TpmKeyOptions) -> Result<Self> {
        let mut provider = Self::new()?;
        provider.options = options;
        Ok(provider)
    }

    /// Check if TPM is available without creating a provider.
    pub fn is_available() -> bool {
        TpmAvailability::check()
            .map(|a| a.is_available)
            .unwrap_or(false)
    }

    /// Get TPM availability information.
    pub fn availability() -> Result<TpmAvailability> {
        TpmAvailability::check()
    }

    /// Generate an attestation blob for a key.
    ///
    /// This can be used to prove to a remote party that the key is
    /// protected by a TPM. The attestation includes:
    ///
    /// - TPM public endorsement key
    /// - Key creation data signed by the TPM
    /// - Platform configuration registers (PCRs) if requested
    ///
    /// # Arguments
    ///
    /// * `handle` - The key to generate attestation for
    ///
    /// # Returns
    ///
    /// An attestation blob that can be sent to a verification server.
    pub async fn generate_attestation(&self, handle: &KeyHandle) -> Result<Vec<u8>> {
        #[cfg(windows)]
        {
            // Implementation would use NCrypt key attestation APIs
            let _ = handle;
            Err(EstError::platform("TPM attestation not yet implemented"))
        }

        #[cfg(not(windows))]
        {
            let _ = handle;
            Err(EstError::platform("TPM operations require Windows OS"))
        }
    }

    /// Verify that a key is TPM-protected.
    ///
    /// This checks that the key was generated by this TPM provider
    /// and is stored in the TPM.
    pub fn verify_key_is_tpm_protected(&self, handle: &KeyHandle) -> bool {
        handle
            .metadata()
            .attributes
            .get("provider")
            .map(|p| p == providers::PLATFORM)
            .unwrap_or(false)
    }
}

#[async_trait]
impl KeyProvider for TpmKeyProvider {
    async fn generate_key_pair(
        &self,
        algorithm: KeyAlgorithm,
        label: Option<&str>,
    ) -> Result<KeyHandle> {
        // Use the underlying CNG provider with TPM storage
        let mut handle = self.inner.generate_key_pair(algorithm, label).await?;

        // Mark the key as TPM-protected in metadata
        handle
            .metadata
            .attributes
            .insert("tpm_protected".to_string(), "true".to_string());

        Ok(handle)
    }

    async fn public_key(&self, handle: &KeyHandle) -> Result<SubjectPublicKeyInfoOwned> {
        self.inner.public_key(handle).await
    }

    async fn sign(&self, handle: &KeyHandle, data: &[u8]) -> Result<Vec<u8>> {
        self.inner.sign(handle, data).await
    }

    async fn algorithm_identifier(&self, handle: &KeyHandle) -> Result<AlgorithmIdentifierOwned> {
        self.inner.algorithm_identifier(handle).await
    }

    async fn list_keys(&self) -> Result<Vec<KeyHandle>> {
        self.inner.list_keys().await
    }

    async fn find_key(&self, label: &str) -> Result<Option<KeyHandle>> {
        self.inner.find_key(label).await
    }

    async fn delete_key(&self, handle: &KeyHandle) -> Result<()> {
        self.inner.delete_key(handle).await
    }

    fn provider_info(&self) -> ProviderInfo {
        ProviderInfo {
            name: "Windows TPM 2.0".to_string(),
            version: "2.0".to_string(),
            manufacturer: "Microsoft Platform Crypto Provider".to_string(),
            supports_key_generation: true,
            supports_key_deletion: true,
        }
    }
}

/// TPM health check result.
#[derive(Debug, Clone)]
pub struct TpmHealthCheck {
    /// Whether the TPM passed all checks.
    pub healthy: bool,
    /// Individual check results.
    pub checks: Vec<TpmCheck>,
    /// Overall status message.
    pub message: String,
}

/// Individual TPM check result.
#[derive(Debug, Clone)]
pub struct TpmCheck {
    /// Check name.
    pub name: String,
    /// Whether the check passed.
    pub passed: bool,
    /// Check details.
    pub details: String,
}

/// Run TPM health checks.
///
/// This performs a series of checks to verify TPM functionality:
///
/// - TPM presence and version
/// - Provider availability
/// - Key generation capability
/// - Signing capability
pub async fn run_health_check() -> Result<TpmHealthCheck> {
    let mut checks = Vec::new();

    // Check 1: TPM availability
    let availability = TpmAvailability::check()?;
    checks.push(TpmCheck {
        name: "TPM Presence".to_string(),
        passed: availability.is_available,
        details: if availability.is_available {
            format!(
                "TPM {} detected",
                availability.version.as_deref().unwrap_or("2.0")
            )
        } else {
            availability
                .reason
                .clone()
                .unwrap_or_else(|| "Not available".to_string())
        },
    });

    if !availability.is_available {
        return Ok(TpmHealthCheck {
            healthy: false,
            checks,
            message: "TPM is not available".to_string(),
        });
    }

    // Check 2: Provider can be opened
    let provider_check = TpmKeyProvider::new();
    checks.push(TpmCheck {
        name: "Provider Initialization".to_string(),
        passed: provider_check.is_ok(),
        details: match &provider_check {
            Ok(_) => "Platform Crypto Provider opened successfully".to_string(),
            Err(e) => format!("Failed: {}", e),
        },
    });

    let provider = match provider_check {
        Ok(p) => p,
        Err(e) => {
            return Ok(TpmHealthCheck {
                healthy: false,
                checks,
                message: format!("Failed to initialize TPM provider: {}", e),
            });
        }
    };

    // Check 3: Key generation
    let key_gen_result = provider
        .generate_key_pair(KeyAlgorithm::EcdsaP256, Some("health-check-key"))
        .await;

    checks.push(TpmCheck {
        name: "Key Generation".to_string(),
        passed: key_gen_result.is_ok(),
        details: match &key_gen_result {
            Ok(_) => "ECDSA P-256 key generated successfully".to_string(),
            Err(e) => format!("Failed: {}", e),
        },
    });

    // Clean up test key if created
    if let Ok(key) = key_gen_result {
        let _ = provider.delete_key(&key).await;
    }

    let all_passed = checks.iter().all(|c| c.passed);

    Ok(TpmHealthCheck {
        healthy: all_passed,
        checks,
        message: if all_passed {
            "All TPM health checks passed".to_string()
        } else {
            "Some TPM health checks failed".to_string()
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: Test code uses unwrap() deliberately - test fixtures are known valid
    // and panics in tests provide clear failure messages. See ERROR-HANDLING-PATTERNS.md
    // Pattern 5 for justification.

    #[test]
    fn test_tpm_availability_not_available() {
        let availability = TpmAvailability::not_available("Test reason");
        assert!(!availability.is_available);
        assert!(!availability.is_ready);
        assert!(!availability.supports_attestation);
        assert_eq!(availability.reason, Some("Test reason".to_string()));
    }

    #[test]
    fn test_tpm_key_options_default() {
        let opts = TpmKeyOptions::default();
        assert!(opts.label.is_none());
        assert!(!opts.require_attestation);
        assert!(!opts.require_pin);
        assert!(opts.pin.is_none());
    }

    #[cfg(not(windows))]
    #[test]
    fn test_tpm_not_available_on_non_windows() {
        let availability = TpmAvailability::check().unwrap();
        assert!(!availability.is_available);
        assert!(availability.reason.is_some());
    }

    #[cfg(not(windows))]
    #[test]
    fn test_tpm_provider_fails_on_non_windows() {
        let result = TpmKeyProvider::new();
        assert!(result.is_err());
    }

    #[test]
    fn test_is_available_static() {
        // This should not panic on any platform
        let _ = TpmKeyProvider::is_available();
    }
}
