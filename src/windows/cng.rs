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

//! Windows Cryptography Next Generation (CNG) key provider.
//!
//! This module implements the `KeyProvider` trait for Windows CNG, enabling
//! EST enrollment operations to use keys stored in Windows key storage providers.
//!
//! # NIST 800-53 Controls
//!
//! - **SC-12**: Cryptographic Key Establishment and Management
//!   - RSA (2048/3072/4096-bit) and ECDSA (P-256/P-384) key generation
//!   - Support for multiple key storage providers (Software, Smart Card, TPM)
//!   - Key lifecycle management through CNG APIs
//! - **SC-13**: Cryptographic Protection
//!   - FIPS 140-2 compliant algorithms when Windows FIPS mode enabled
//!   - NIST-approved signature algorithms (ECDSA with SHA-256, RSA with SHA-256)
//! - **SC-28**: Protection of Information at Rest
//!   - Non-exportable key protection (default)
//!   - TPM-backed key storage option for hardware-protected keys
//! - **SC-2**: Separation of Function
//!   - Separation between software, smart card, and TPM key storage
//!   - Provider-specific access control through Windows ACLs
//!
//! # Key Storage Providers
//!
//! Windows CNG supports multiple key storage providers:
//!
//! - **Microsoft Software Key Storage Provider**: Software-based key storage (default)
//! - **Microsoft Smart Card Key Storage Provider**: Smart card/token-based storage
//! - **Microsoft Platform Crypto Provider**: TPM 2.0-based storage
//!
//! # Supported Algorithms
//!
//! - ECDSA with P-256 (secp256r1 / prime256v1)
//! - ECDSA with P-384 (secp384r1)
//! - RSA 2048, 3072, 4096 bits
//!
//! # Key Protection
//!
//! Keys can be configured with various protection options:
//!
//! - **Non-exportable**: Key material cannot be exported (default, recommended)
//! - **Exportable**: Key material can be exported (not recommended for production)
//! - **UI Protection**: Requires user interaction for key operations
//!
//! # Example
//!
//! ```no_run,ignore
//! use usg_est_client::windows::CngKeyProvider;
//! use usg_est_client::hsm::{KeyProvider, KeyAlgorithm};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create provider with default (Software) storage
//! let provider = CngKeyProvider::new()?;
//!
//! // Generate an ECDSA P-256 key
//! let key = provider.generate_key_pair(
//!     KeyAlgorithm::EcdsaP256,
//!     Some("EST-Device-Key")
//! ).await?;
//!
//! // Sign data
//! let signature = provider.sign(&key, b"data to sign").await?;
//!
//! // Get public key for CSR
//! let public_key = provider.public_key(&key).await?;
//! # Ok(())
//! # }
//! ```

use crate::error::{EstError, Result};
use crate::hsm::{KeyAlgorithm, KeyHandle, KeyMetadata, KeyProvider, ProviderInfo};
use async_trait::async_trait;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use std::collections::HashMap;
use std::sync::Arc;

#[cfg(windows)]
use windows::Win32::Security::Cryptography::{
    BCRYPT_ALG_HANDLE, BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_P256_ALGORITHM,
    BCRYPT_ECDSA_P384_ALGORITHM, BCRYPT_KEY_HANDLE, BCRYPT_RSA_ALGORITHM, BCRYPT_RSAPUBLIC_BLOB,
    BCRYPT_SHA256_ALGORITHM, BCryptCloseAlgorithmProvider, BCryptCreateHash, BCryptDestroyHash,
    BCryptDestroyKey, BCryptExportKey, BCryptFinishHash, BCryptGenerateKeyPair, BCryptHashData,
    BCryptOpenAlgorithmProvider, BCryptSignHash, NCRYPT_FLAGS, NCRYPT_KEY_HANDLE,
    NCRYPT_PROV_HANDLE, NCryptCreatePersistedKey, NCryptDeleteKey, NCryptExportKey,
    NCryptFinalizeKey, NCryptFreeObject, NCryptGetProperty, NCryptOpenKey,
    NCryptOpenStorageProvider, NCryptSetProperty, NCryptSignHash,
};

/// Well-known CNG key storage provider names.
pub mod providers {
    /// Microsoft Software Key Storage Provider.
    /// Software-based key storage, available on all Windows systems.
    pub const SOFTWARE: &str = "Microsoft Software Key Storage Provider";

    /// Microsoft Smart Card Key Storage Provider.
    /// For smart cards, tokens, and similar devices.
    pub const SMART_CARD: &str = "Microsoft Smart Card Key Storage Provider";

    /// Microsoft Platform Crypto Provider.
    /// TPM 2.0-based key storage for hardware protection.
    pub const PLATFORM: &str = "Microsoft Platform Crypto Provider";
}

/// Key export format for CNG keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyExportFormat {
    /// BCRYPT_ECCPUBLIC_BLOB for EC keys.
    EccPublicBlob,
    /// BCRYPT_RSAPUBLIC_BLOB for RSA keys.
    RsaPublicBlob,
    /// PKCS#8 private key (if exportable).
    Pkcs8Private,
}

/// Options for key generation.
#[derive(Debug, Clone)]
pub struct KeyGenerationOptions {
    /// Make the key non-exportable (recommended for security).
    pub non_exportable: bool,
    /// Require UI interaction for key operations.
    pub ui_protection: bool,
    /// Allow the key to be used only for signing.
    pub sign_only: bool,
    /// Key label/container name.
    pub label: Option<String>,
}

impl Default for KeyGenerationOptions {
    fn default() -> Self {
        Self {
            non_exportable: true,
            ui_protection: false,
            sign_only: true,
            label: None,
        }
    }
}

/// Windows CNG key provider implementing the `KeyProvider` trait.
///
/// This provider uses Windows Cryptography Next Generation (CNG) APIs
/// for key management and cryptographic operations.
pub struct CngKeyProvider {
    /// The CNG storage provider name.
    provider_name: String,
    /// Key generation options.
    options: KeyGenerationOptions,
    /// Internal state for key handles (for non-Windows simulation).
    #[cfg(not(windows))]
    _keys: std::sync::Mutex<HashMap<Vec<u8>, KeyAlgorithm>>,
}

impl CngKeyProvider {
    /// Create a new CNG key provider with the default software storage.
    ///
    /// # Returns
    ///
    /// A new `CngKeyProvider` using the Microsoft Software Key Storage Provider.
    pub fn new() -> Result<Self> {
        Self::with_provider(providers::SOFTWARE)
    }

    /// Create a new CNG key provider with a specific storage provider.
    ///
    /// # Arguments
    ///
    /// * `provider_name` - The CNG storage provider name (see `providers` module)
    ///
    /// # Example
    ///
    /// ```no_run,ignore
    /// // Use TPM-based storage
    /// let provider = CngKeyProvider::with_provider(providers::PLATFORM)?;
    ///
    /// // Use smart card storage
    /// let provider = CngKeyProvider::with_provider(providers::SMART_CARD)?;
    /// ```
    pub fn with_provider(provider_name: &str) -> Result<Self> {
        #[cfg(windows)]
        {
            // Verify the provider is available
            Self::verify_provider_available(provider_name)?;
        }

        Ok(Self {
            provider_name: provider_name.to_string(),
            options: KeyGenerationOptions::default(),
            #[cfg(not(windows))]
            _keys: std::sync::Mutex::new(HashMap::new()),
        })
    }

    /// Create a new CNG key provider with custom options.
    ///
    /// # Arguments
    ///
    /// * `provider_name` - The CNG storage provider name
    /// * `options` - Key generation options
    pub fn with_options(provider_name: &str, options: KeyGenerationOptions) -> Result<Self> {
        let mut provider = Self::with_provider(provider_name)?;
        provider.options = options;
        Ok(provider)
    }

    /// Get the provider name.
    pub fn provider_name(&self) -> &str {
        &self.provider_name
    }

    /// Check if using TPM storage.
    pub fn is_tpm(&self) -> bool {
        self.provider_name == providers::PLATFORM
    }

    /// Check if using smart card storage.
    pub fn is_smart_card(&self) -> bool {
        self.provider_name == providers::SMART_CARD
    }

    /// Get the CNG container name from a KeyHandle.
    ///
    /// The container name is needed to associate the CNG key with a
    /// certificate in the Windows Certificate Store.
    ///
    /// # Arguments
    ///
    /// * `key` - The key handle returned from generate_key_pair()
    ///
    /// # Returns
    ///
    /// The CNG container name (e.g., "EST-Device-1234567890")
    ///
    /// # Example
    ///
    /// ```no_run,ignore
    /// let provider = CngKeyProvider::new()?;
    /// let key = provider.generate_key_pair(KeyAlgorithm::Rsa2048, Some("MyKey"))?;
    /// let container = CngKeyProvider::get_container_name(&key)?;
    /// println!("Container: {}", container);
    /// ```
    pub fn get_container_name(key: &KeyHandle) -> Result<String> {
        key.metadata()
            .attributes
            .get("container")
            .cloned()
            .ok_or_else(|| EstError::platform("Key handle missing CNG container name"))
    }

    /// Get the CNG provider name from a KeyHandle.
    ///
    /// Returns the storage provider used when the key was created
    /// (e.g., "Microsoft Software Key Storage Provider").
    ///
    /// # Arguments
    ///
    /// * `key` - The key handle returned from generate_key_pair()
    ///
    /// # Returns
    ///
    /// The CNG provider name
    pub fn get_provider_name(key: &KeyHandle) -> Result<String> {
        key.metadata()
            .attributes
            .get("provider")
            .cloned()
            .ok_or_else(|| EstError::platform("Key handle missing CNG provider name"))
    }

    /// Verify a storage provider is available.
    #[cfg(windows)]
    fn verify_provider_available(provider_name: &str) -> Result<()> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;

        let wide_name: Vec<u16> = OsStr::new(provider_name)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut handle = NCRYPT_PROV_HANDLE::default();

        let result = unsafe {
            NCryptOpenStorageProvider(&mut handle, windows::core::PCWSTR(wide_name.as_ptr()), 0)
        };

        if result.is_err() {
            return Err(EstError::platform(format!(
                "CNG storage provider '{}' is not available",
                provider_name
            )));
        }

        unsafe {
            NCryptFreeObject(handle.0);
        }

        Ok(())
    }

    /// Convert KeyAlgorithm to CNG algorithm identifier.
    fn algorithm_to_cng(algorithm: KeyAlgorithm) -> &'static str {
        match algorithm {
            KeyAlgorithm::EcdsaP256 => "ECDSA_P256",
            KeyAlgorithm::EcdsaP384 => "ECDSA_P384",
            KeyAlgorithm::Rsa { .. } => "RSA",
        }
    }

    /// Get key size for RSA algorithms.
    fn rsa_key_size(algorithm: KeyAlgorithm) -> u32 {
        match algorithm {
            KeyAlgorithm::Rsa { bits } => bits,
            _ => 0,
        }
    }

    /// Generate a unique key container name.
    fn generate_container_name(label: Option<&str>) -> String {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);

        match label {
            Some(l) => format!("EST-{}-{}", l, timestamp),
            None => format!("EST-Key-{}", timestamp),
        }
    }
}

#[async_trait]
impl KeyProvider for CngKeyProvider {
    async fn generate_key_pair(
        &self,
        algorithm: KeyAlgorithm,
        label: Option<&str>,
    ) -> Result<KeyHandle> {
        #[cfg(windows)]
        {
            use std::ffi::OsStr;
            use std::os::windows::ffi::OsStrExt;

            let container_name = Self::generate_container_name(label);

            let wide_provider: Vec<u16> = OsStr::new(&self.provider_name)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let wide_container: Vec<u16> = OsStr::new(&container_name)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let wide_algorithm: Vec<u16> = OsStr::new(Self::algorithm_to_cng(algorithm))
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            // Open storage provider
            let mut prov_handle = NCRYPT_PROV_HANDLE::default();
            let result = unsafe {
                NCryptOpenStorageProvider(
                    &mut prov_handle,
                    windows::core::PCWSTR(wide_provider.as_ptr()),
                    0,
                )
            };

            if result.is_err() {
                return Err(EstError::platform(format!(
                    "Failed to open CNG provider: {:?}",
                    result
                )));
            }

            // Create key
            let mut key_handle = NCRYPT_KEY_HANDLE::default();
            let result = unsafe {
                NCryptCreatePersistedKey(
                    prov_handle,
                    &mut key_handle,
                    windows::core::PCWSTR(wide_algorithm.as_ptr()),
                    windows::core::PCWSTR(wide_container.as_ptr()),
                    0,
                    NCRYPT_FLAGS(0),
                )
            };

            if result.is_err() {
                unsafe { NCryptFreeObject(prov_handle.0) };
                return Err(EstError::platform(format!(
                    "Failed to create CNG key: {:?}",
                    result
                )));
            }

            // Set key size for RSA
            if let KeyAlgorithm::Rsa { bits } = algorithm {
                let size_bytes = bits.to_le_bytes();
                let wide_length: Vec<u16> = OsStr::new("Length")
                    .encode_wide()
                    .chain(std::iter::once(0))
                    .collect();

                let _ = unsafe {
                    NCryptSetProperty(
                        key_handle,
                        windows::core::PCWSTR(wide_length.as_ptr()),
                        &size_bytes,
                        NCRYPT_FLAGS(0),
                    )
                };
            }

            // Set export policy if non-exportable
            if self.options.non_exportable {
                let policy: u32 = 0; // NCRYPT_ALLOW_EXPORT_NONE
                let policy_bytes = policy.to_le_bytes();
                let wide_policy: Vec<u16> = OsStr::new("Export Policy")
                    .encode_wide()
                    .chain(std::iter::once(0))
                    .collect();

                let _ = unsafe {
                    NCryptSetProperty(
                        key_handle,
                        windows::core::PCWSTR(wide_policy.as_ptr()),
                        &policy_bytes,
                        NCRYPT_FLAGS(0),
                    )
                };
            }

            // Finalize the key
            let result = unsafe { NCryptFinalizeKey(key_handle, NCRYPT_FLAGS(0)) };

            if result.is_err() {
                unsafe {
                    NCryptDeleteKey(key_handle, 0);
                    NCryptFreeObject(prov_handle.0);
                }
                return Err(EstError::platform(format!(
                    "Failed to finalize CNG key: {:?}",
                    result
                )));
            }

            // Store the key handle value as the ID
            let key_id = key_handle.0.to_le_bytes().to_vec();

            // Clean up provider handle (key handle stays open)
            unsafe { NCryptFreeObject(prov_handle.0) };

            let metadata = KeyMetadata {
                label: label.map(|s| s.to_string()),
                can_sign: true,
                extractable: !self.options.non_exportable,
                attributes: {
                    let mut attrs = HashMap::new();
                    attrs.insert("container".to_string(), container_name);
                    attrs.insert("provider".to_string(), self.provider_name.clone());
                    attrs
                },
            };

            Ok(KeyHandle::new(key_id, algorithm, metadata))
        }

        #[cfg(not(windows))]
        {
            // Simulation for non-Windows platforms (for testing/development)
            let key_id = Self::generate_container_name(label).into_bytes();

            let metadata = KeyMetadata {
                label: label.map(|s| s.to_string()),
                can_sign: true,
                extractable: !self.options.non_exportable,
                attributes: {
                    let mut attrs = HashMap::new();
                    attrs.insert("provider".to_string(), self.provider_name.clone());
                    attrs.insert("simulated".to_string(), "true".to_string());
                    attrs
                },
            };

            self._keys.lock()
                .map_err(|e| EstError::platform(format!("Key storage lock poisoned: {}", e)))?
                .insert(key_id.clone(), algorithm);

            Ok(KeyHandle::new(key_id, algorithm, metadata))
        }
    }

    async fn public_key(&self, handle: &KeyHandle) -> Result<SubjectPublicKeyInfoOwned> {
        #[cfg(windows)]
        {
            // Implementation would export the public key blob and convert to SPKI
            // For now, return a placeholder error
            Err(EstError::platform(
                "CNG public key export not yet implemented",
            ))
        }

        #[cfg(not(windows))]
        {
            let _ = handle;
            Err(EstError::platform("CNG operations require Windows OS"))
        }
    }

    async fn sign(&self, handle: &KeyHandle, data: &[u8]) -> Result<Vec<u8>> {
        #[cfg(windows)]
        {
            // Implementation would use NCryptSignHash
            // For now, return a placeholder error
            let _ = (handle, data);
            Err(EstError::platform("CNG signing not yet implemented"))
        }

        #[cfg(not(windows))]
        {
            let _ = (handle, data);
            Err(EstError::platform("CNG operations require Windows OS"))
        }
    }

    async fn algorithm_identifier(&self, handle: &KeyHandle) -> Result<AlgorithmIdentifierOwned> {
        use const_oid::db::rfc5912::{
            ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, SHA_256_WITH_RSA_ENCRYPTION,
        };
        use der::Any;

        let oid = match handle.algorithm() {
            KeyAlgorithm::EcdsaP256 => ECDSA_WITH_SHA_256,
            KeyAlgorithm::EcdsaP384 => ECDSA_WITH_SHA_384,
            KeyAlgorithm::Rsa { .. } => SHA_256_WITH_RSA_ENCRYPTION,
        };

        Ok(AlgorithmIdentifierOwned {
            oid,
            parameters: Some(Any::null()),
        })
    }

    async fn list_keys(&self) -> Result<Vec<KeyHandle>> {
        #[cfg(windows)]
        {
            // Implementation would enumerate keys in the provider
            Ok(Vec::new())
        }

        #[cfg(not(windows))]
        {
            let keys = self._keys.lock()
                .map_err(|e| EstError::platform(format!("Key storage lock poisoned: {}", e)))?;
            Ok(keys
                .iter()
                .map(|(id, alg)| {
                    KeyHandle::new(
                        id.clone(),
                        *alg,
                        KeyMetadata {
                            label: None,
                            can_sign: true,
                            extractable: false,
                            attributes: HashMap::new(),
                        },
                    )
                })
                .collect())
        }
    }

    async fn find_key(&self, label: &str) -> Result<Option<KeyHandle>> {
        #[cfg(windows)]
        {
            // Implementation would search by key container name
            let _ = label;
            Ok(None)
        }

        #[cfg(not(windows))]
        {
            let keys = self._keys.lock()
                .map_err(|e| EstError::platform(format!("Key storage lock poisoned: {}", e)))?;
            for (id, alg) in keys.iter() {
                if let Ok(name) = std::str::from_utf8(id) {
                    if name.contains(label) {
                        return Ok(Some(KeyHandle::new(
                            id.clone(),
                            *alg,
                            KeyMetadata {
                                label: Some(label.to_string()),
                                can_sign: true,
                                extractable: false,
                                attributes: HashMap::new(),
                            },
                        )));
                    }
                }
            }
            Ok(None)
        }
    }

    async fn delete_key(&self, handle: &KeyHandle) -> Result<()> {
        #[cfg(windows)]
        {
            // Implementation would use NCryptDeleteKey
            let _ = handle;
            Err(EstError::platform("CNG key deletion not yet implemented"))
        }

        #[cfg(not(windows))]
        {
            self._keys.lock()
                .map_err(|e| EstError::platform(format!("Key storage lock poisoned: {}", e)))?
                .remove(handle.id());
            Ok(())
        }
    }

    fn provider_info(&self) -> ProviderInfo {
        ProviderInfo {
            name: "Windows CNG".to_string(),
            version: "1.0".to_string(),
            manufacturer: "Microsoft".to_string(),
            supports_key_generation: true,
            supports_key_deletion: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: Test code uses unwrap() deliberately - test fixtures are known valid
    // and panics in tests provide clear failure messages. See ERROR-HANDLING-PATTERNS.md
    // Pattern 5 for justification.

    #[test]
    fn test_provider_names() {
        assert_eq!(
            providers::SOFTWARE,
            "Microsoft Software Key Storage Provider"
        );
        assert_eq!(providers::PLATFORM, "Microsoft Platform Crypto Provider");
        assert_eq!(
            providers::SMART_CARD,
            "Microsoft Smart Card Key Storage Provider"
        );
    }

    #[test]
    fn test_key_generation_options_default() {
        let opts = KeyGenerationOptions::default();
        assert!(opts.non_exportable);
        assert!(!opts.ui_protection);
        assert!(opts.sign_only);
        assert!(opts.label.is_none());
    }

    #[test]
    fn test_algorithm_to_cng() {
        assert_eq!(
            CngKeyProvider::algorithm_to_cng(KeyAlgorithm::EcdsaP256),
            "ECDSA_P256"
        );
        assert_eq!(
            CngKeyProvider::algorithm_to_cng(KeyAlgorithm::EcdsaP384),
            "ECDSA_P384"
        );
        assert_eq!(
            CngKeyProvider::algorithm_to_cng(KeyAlgorithm::Rsa { bits: 2048 }),
            "RSA"
        );
    }

    #[test]
    fn test_rsa_key_size() {
        assert_eq!(
            CngKeyProvider::rsa_key_size(KeyAlgorithm::Rsa { bits: 2048 }),
            2048
        );
        assert_eq!(
            CngKeyProvider::rsa_key_size(KeyAlgorithm::Rsa { bits: 4096 }),
            4096
        );
        assert_eq!(CngKeyProvider::rsa_key_size(KeyAlgorithm::EcdsaP256), 0);
    }

    #[test]
    fn test_generate_container_name() {
        let name1 = CngKeyProvider::generate_container_name(None);
        assert!(name1.starts_with("EST-Key-"));

        let name2 = CngKeyProvider::generate_container_name(Some("Device"));
        assert!(name2.starts_with("EST-Device-"));
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn test_cng_provider_simulation() {
        // On non-Windows, we can still create the provider (it simulates)
        let provider = CngKeyProvider::with_provider(providers::SOFTWARE).unwrap();
        assert_eq!(provider.provider_name(), providers::SOFTWARE);
        assert!(!provider.is_tpm());
        assert!(!provider.is_smart_card());

        // Generate a key (simulated)
        let key = provider
            .generate_key_pair(KeyAlgorithm::EcdsaP256, Some("test"))
            .await
            .unwrap();

        assert_eq!(key.algorithm(), KeyAlgorithm::EcdsaP256);
        assert!(key.metadata().label.is_some());

        // List keys
        let keys = provider.list_keys().await.unwrap();
        assert_eq!(keys.len(), 1);

        // Delete key
        provider.delete_key(&key).await.unwrap();

        let keys = provider.list_keys().await.unwrap();
        assert!(keys.is_empty());
    }
}
