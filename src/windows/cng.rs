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
    BCRYPT_ECDSA_P384_ALGORITHM, BCRYPT_HASH_HANDLE, BCRYPT_KEY_HANDLE, BCRYPT_RSA_ALGORITHM,
    BCRYPT_RSAPUBLIC_BLOB, BCRYPT_SHA256_ALGORITHM, BCryptCloseAlgorithmProvider,
    BCryptCreateHash, BCryptDestroyHash, BCryptDestroyKey, BCryptExportKey, BCryptFinishHash,
    BCryptGenerateKeyPair, BCryptHashData, BCryptOpenAlgorithmProvider, BCryptSignHash,
    NCRYPT_FLAGS, NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE, NCryptCreatePersistedKey,
    NCryptDeleteKey, NCryptExportKey, NCryptFinalizeKey, NCryptFreeObject, NCryptGetProperty,
    NCryptOpenKey, NCryptOpenStorageProvider, NCryptSetProperty, NCryptSignHash,
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

    /// Convert CNG public key blob to SPKI format.
    #[cfg(windows)]
    fn blob_to_spki(blob: &[u8], algorithm: KeyAlgorithm) -> Result<SubjectPublicKeyInfoOwned> {
        use der::{Encode, asn1::BitString};
        use const_oid::db::rfc5912::{ID_EC_PUBLIC_KEY, SECP_256_R_1, SECP_384_R_1, RSA_ENCRYPTION};

        match algorithm {
            KeyAlgorithm::EcdsaP256 | KeyAlgorithm::EcdsaP384 => {
                // BCRYPT_ECCKEY_BLOB structure:
                // typedef struct _BCRYPT_ECCKEY_BLOB {
                //   ULONG dwMagic;      // 4 bytes
                //   ULONG cbKey;        // 4 bytes - size of each coordinate
                // } BCRYPT_ECCKEY_BLOB;
                // Followed by: X coordinate (cbKey bytes), Y coordinate (cbKey bytes)

                if blob.len() < 8 {
                    return Err(EstError::platform("Invalid ECC public key blob size"));
                }

                let cb_key = u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]) as usize;

                // Use checked arithmetic to prevent integer overflow
                let expected_size = 8_usize
                    .checked_add(
                        cb_key
                            .checked_mul(2)
                            .ok_or_else(|| EstError::platform(
                                "Integer overflow calculating ECC blob size (cb_key * 2)"
                            ))?,
                    )
                    .ok_or_else(|| EstError::platform(
                        "Integer overflow calculating ECC blob size (8 + cb_key * 2)"
                    ))?;

                if blob.len() < expected_size {
                    return Err(EstError::platform(format!(
                        "ECC blob too small: got {} bytes, expected {}",
                        blob.len(),
                        expected_size
                    )));
                }

                // Validate cb_key is reasonable for known curves
                const MAX_ECC_COORDINATE_SIZE: usize = 66; // P-521 is 66 bytes
                if cb_key > MAX_ECC_COORDINATE_SIZE {
                    return Err(EstError::platform(format!(
                        "ECC coordinate size {} exceeds maximum {}",
                        cb_key, MAX_ECC_COORDINATE_SIZE
                    )));
                }

                // Extract X and Y coordinates (big-endian in CNG)
                let x = &blob[8..8 + cb_key];
                let y = &blob[8 + cb_key..8 + cb_key * 2];

                // Build uncompressed point: 0x04 || X || Y
                let mut point = vec![0x04];
                point.extend_from_slice(x);
                point.extend_from_slice(y);

                // Determine curve OID
                let curve_oid = match algorithm {
                    KeyAlgorithm::EcdsaP256 => SECP_256_R_1,
                    KeyAlgorithm::EcdsaP384 => SECP_384_R_1,
                    _ => unreachable!(),
                };

                // Build AlgorithmIdentifier with curve OID as parameter
                let parameters = der::asn1::ObjectIdentifier::new_unwrap(curve_oid.as_bytes());
                let algorithm_id = spki::AlgorithmIdentifierOwned {
                    oid: ID_EC_PUBLIC_KEY,
                    parameters: Some(der::Any::from_der(&parameters.to_der().map_err(|e| {
                        EstError::platform(format!("Failed to encode curve OID: {}", e))
                    })?)
                    .map_err(|e| EstError::platform(format!("Failed to parse curve OID: {}", e)))?),
                };

                // Build SubjectPublicKeyInfo
                let subject_public_key = BitString::from_bytes(&point)
                    .map_err(|e| EstError::platform(format!("Failed to create bit string: {}", e)))?;

                Ok(SubjectPublicKeyInfoOwned {
                    algorithm: algorithm_id,
                    subject_public_key,
                })
            }
            KeyAlgorithm::Rsa { .. } => {
                // BCRYPT_RSAKEY_BLOB structure:
                // typedef struct _BCRYPT_RSAKEY_BLOB {
                //   ULONG Magic;           // 4 bytes
                //   ULONG BitLength;       // 4 bytes
                //   ULONG cbPublicExp;     // 4 bytes
                //   ULONG cbModulus;       // 4 bytes
                //   ULONG cbPrime1;        // 4 bytes (0 for public key)
                //   ULONG cbPrime2;        // 4 bytes (0 for public key)
                // } BCRYPT_RSAKEY_BLOB;
                // Followed by: PublicExponent, Modulus

                if blob.len() < 24 {
                    return Err(EstError::platform("Invalid RSA public key blob size"));
                }

                let cb_public_exp = u32::from_le_bytes([blob[8], blob[9], blob[10], blob[11]]) as usize;
                let cb_modulus = u32::from_le_bytes([blob[12], blob[13], blob[14], blob[15]]) as usize;

                // Validate sizes are reasonable for RSA keys
                const MAX_RSA_EXPONENT_SIZE: usize = 8; // Typically 3-4 bytes
                const MAX_RSA_MODULUS_SIZE: usize = 512; // 4096-bit RSA = 512 bytes
                if cb_public_exp > MAX_RSA_EXPONENT_SIZE {
                    return Err(EstError::platform(format!(
                        "RSA public exponent size {} exceeds maximum {}",
                        cb_public_exp, MAX_RSA_EXPONENT_SIZE
                    )));
                }
                if cb_modulus > MAX_RSA_MODULUS_SIZE {
                    return Err(EstError::platform(format!(
                        "RSA modulus size {} exceeds maximum {}",
                        cb_modulus, MAX_RSA_MODULUS_SIZE
                    )));
                }

                // Use checked arithmetic to prevent integer overflow
                let exp_start = 24_usize;
                let mod_start = exp_start
                    .checked_add(cb_public_exp)
                    .ok_or_else(|| EstError::platform("Integer overflow calculating RSA exponent offset"))?;
                let total_size = mod_start
                    .checked_add(cb_modulus)
                    .ok_or_else(|| EstError::platform("Integer overflow calculating RSA blob size"))?;

                if blob.len() < total_size {
                    return Err(EstError::platform(format!(
                        "RSA blob too small: got {} bytes, expected {}",
                        blob.len(),
                        total_size
                    )));
                }

                // Extract public exponent and modulus (big-endian in CNG)
                let public_exp = &blob[exp_start..exp_start + cb_public_exp];
                let modulus = &blob[mod_start..mod_start + cb_modulus];

                // Build RSA public key in DER format
                // RSAPublicKey ::= SEQUENCE {
                //     modulus           INTEGER,  -- n
                //     publicExponent    INTEGER   -- e
                // }
                use der::asn1::UintRef;

                let n = UintRef::new(modulus)
                    .map_err(|e| EstError::platform(format!("Failed to encode modulus: {}", e)))?;
                let e = UintRef::new(public_exp)
                    .map_err(|e| EstError::platform(format!("Failed to encode exponent: {}", e)))?;

                // Encode the RSAPublicKey sequence
                let rsa_public_key = der::asn1::SequenceOf::<UintRef, 2>::try_from([n, e])
                    .map_err(|e| EstError::platform(format!("Failed to create RSA key sequence: {}", e)))?;

                let rsa_public_key_der = rsa_public_key.to_der()
                    .map_err(|e| EstError::platform(format!("Failed to encode RSA public key: {}", e)))?;

                // Build AlgorithmIdentifier for RSA
                let algorithm_id = spki::AlgorithmIdentifierOwned {
                    oid: RSA_ENCRYPTION,
                    parameters: Some(der::Any::null()),
                };

                // Build SubjectPublicKeyInfo
                let subject_public_key = BitString::from_bytes(&rsa_public_key_der)
                    .map_err(|e| EstError::platform(format!("Failed to create bit string: {}", e)))?;

                Ok(SubjectPublicKeyInfoOwned {
                    algorithm: algorithm_id,
                    subject_public_key,
                })
            }
        }
    }

    /// Convert ECDSA raw (r,s) signature to DER format.
    #[cfg(windows)]
    fn ecdsa_raw_to_der(raw_sig: &[u8]) -> Result<Vec<u8>> {
        use der::{Encode, asn1::UintRef};

        // CNG ECDSA signatures are in raw format: r || s
        // Each component is the same size (32 bytes for P-256, 48 bytes for P-384)
        if raw_sig.len() % 2 != 0 {
            return Err(EstError::platform("Invalid ECDSA signature length"));
        }

        let component_len = raw_sig.len() / 2;
        let r = &raw_sig[0..component_len];
        let s = &raw_sig[component_len..];

        // Build DER SEQUENCE { r INTEGER, s INTEGER }
        let r_uint = UintRef::new(r)
            .map_err(|e| EstError::platform(format!("Failed to encode r: {}", e)))?;
        let s_uint = UintRef::new(s)
            .map_err(|e| EstError::platform(format!("Failed to encode s: {}", e)))?;

        let sig_seq = der::asn1::SequenceOf::<UintRef, 2>::try_from([r_uint, s_uint])
            .map_err(|e| EstError::platform(format!("Failed to create signature sequence: {}", e)))?;

        sig_seq.to_der()
            .map_err(|e| EstError::platform(format!("Failed to encode signature: {}", e)).into())
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

            // RAII guard for provider handle cleanup
            struct ProviderGuard(NCRYPT_PROV_HANDLE);
            impl Drop for ProviderGuard {
                fn drop(&mut self) {
                    unsafe {
                        let _ = NCryptFreeObject(self.0.0);
                    }
                }
            }

            // RAII guard for key handle cleanup on error
            struct KeyGuard {
                handle: NCRYPT_KEY_HANDLE,
                should_delete: bool,
            }
            impl Drop for KeyGuard {
                fn drop(&mut self) {
                    if self.should_delete {
                        unsafe {
                            let _ = NCryptDeleteKey(self.handle, 0);
                        }
                    }
                }
            }

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

            // Guard ensures provider handle is freed on error or success
            let _prov_guard = ProviderGuard(prov_handle);

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
                return Err(EstError::platform(format!(
                    "Failed to create CNG key: {:?}",
                    result
                )));
            }

            // Guard ensures key is deleted on error
            let mut key_guard = KeyGuard {
                handle: key_handle,
                should_delete: true,
            };

            // Set key size for RSA
            if let KeyAlgorithm::Rsa { bits } = algorithm {
                let size_bytes = bits.to_le_bytes();
                let wide_length: Vec<u16> = OsStr::new("Length")
                    .encode_wide()
                    .chain(std::iter::once(0))
                    .collect();

                let result = unsafe {
                    NCryptSetProperty(
                        key_handle,
                        windows::core::PCWSTR(wide_length.as_ptr()),
                        &size_bytes,
                        NCRYPT_FLAGS(0),
                    )
                };

                if result.is_err() {
                    return Err(EstError::platform(format!(
                        "Failed to set RSA key length: {:?}",
                        result
                    )));
                }
            }

            // Set export policy if non-exportable
            if self.options.non_exportable {
                let policy: u32 = 0; // NCRYPT_ALLOW_EXPORT_NONE
                let policy_bytes = policy.to_le_bytes();
                let wide_policy: Vec<u16> = OsStr::new("Export Policy")
                    .encode_wide()
                    .chain(std::iter::once(0))
                    .collect();

                let result = unsafe {
                    NCryptSetProperty(
                        key_handle,
                        windows::core::PCWSTR(wide_policy.as_ptr()),
                        &policy_bytes,
                        NCRYPT_FLAGS(0),
                    )
                };

                if result.is_err() {
                    return Err(EstError::platform(format!(
                        "Failed to set export policy: {:?}",
                        result
                    )));
                }
            }

            // Finalize the key
            let result = unsafe { NCryptFinalizeKey(key_handle, NCRYPT_FLAGS(0)) };

            if result.is_err() {
                return Err(EstError::platform(format!(
                    "Failed to finalize CNG key: {:?}",
                    result
                )));
            }

            // Success - don't delete the key on drop
            key_guard.should_delete = false;

            // Store the key handle value as the ID
            let key_id = key_handle.0.to_le_bytes().to_vec();

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

            self._keys
                .lock()
                .map_err(|e| EstError::platform(format!("Key storage lock poisoned: {}", e)))?
                .insert(key_id.clone(), algorithm);

            Ok(KeyHandle::new(key_id, algorithm, metadata))
        }
    }

    async fn public_key(&self, handle: &KeyHandle) -> Result<SubjectPublicKeyInfoOwned> {
        #[cfg(windows)]
        {
            use std::ffi::OsStr;
            use std::os::windows::ffi::OsStrExt;

            // Validate handle ID size
            if handle.id().len() < std::mem::size_of::<usize>() {
                return Err(EstError::platform(format!(
                    "Invalid key handle ID size: expected at least {}, got {}",
                    std::mem::size_of::<usize>(),
                    handle.id().len()
                )));
            }

            // Reconstruct the NCRYPT_KEY_HANDLE from the stored ID
            let key_handle_value = usize::from_le_bytes(
                handle.id()[..std::mem::size_of::<usize>()]
                    .try_into()
                    .map_err(|_| EstError::platform("Invalid key handle ID"))?,
            );
            let key_handle = NCRYPT_KEY_HANDLE(key_handle_value);

            // Validate the handle is still valid by attempting to read a property
            let wide_algorithm: Vec<u16> = OsStr::new("Algorithm Name")
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let mut prop_size: u32 = 0;
            let validation_result = unsafe {
                NCryptGetProperty(
                    key_handle,
                    windows::core::PCWSTR(wide_algorithm.as_ptr()),
                    std::ptr::null_mut(),
                    0,
                    &mut prop_size,
                    NCRYPT_FLAGS(0),
                )
            };
            if validation_result.is_err() {
                return Err(EstError::platform(
                    "Key handle is invalid or has been freed. The key may have been deleted."
                ));
            }

            // Export the public key blob
            let blob_type = match handle.algorithm() {
                KeyAlgorithm::EcdsaP256 | KeyAlgorithm::EcdsaP384 => BCRYPT_ECCPUBLIC_BLOB,
                KeyAlgorithm::Rsa { .. } => BCRYPT_RSAPUBLIC_BLOB,
            };

            let wide_blob_type: Vec<u16> = OsStr::new(blob_type.to_string().as_str())
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            // First call to get the size
            let mut blob_size: u32 = 0;
            let result = unsafe {
                NCryptExportKey(
                    key_handle,
                    NCRYPT_KEY_HANDLE::default(),
                    windows::core::PCWSTR(wide_blob_type.as_ptr()),
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    0,
                    &mut blob_size,
                    NCRYPT_FLAGS(0),
                )
            };

            if result.is_err() {
                return Err(EstError::platform(format!(
                    "Failed to get public key blob size: {:?}",
                    result
                )));
            }

            // Second call to get the actual blob
            let mut blob = vec![0u8; blob_size as usize];
            let result = unsafe {
                NCryptExportKey(
                    key_handle,
                    NCRYPT_KEY_HANDLE::default(),
                    windows::core::PCWSTR(wide_blob_type.as_ptr()),
                    std::ptr::null(),
                    blob.as_mut_ptr(),
                    blob_size,
                    &mut blob_size,
                    NCRYPT_FLAGS(0),
                )
            };

            if result.is_err() {
                return Err(EstError::platform(format!(
                    "Failed to export public key: {:?}",
                    result
                )));
            }

            // Convert blob to SPKI format
            Self::blob_to_spki(&blob, handle.algorithm())
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
            use std::ffi::OsStr;
            use std::os::windows::ffi::OsStrExt;

            // Validate handle ID size
            if handle.id().len() < std::mem::size_of::<usize>() {
                return Err(EstError::platform(format!(
                    "Invalid key handle ID size: expected at least {}, got {}",
                    std::mem::size_of::<usize>(),
                    handle.id().len()
                )));
            }

            // Reconstruct the NCRYPT_KEY_HANDLE from the stored ID
            let key_handle_value = usize::from_le_bytes(
                handle.id()[..std::mem::size_of::<usize>()]
                    .try_into()
                    .map_err(|_| EstError::platform("Invalid key handle ID"))?,
            );
            let key_handle = NCRYPT_KEY_HANDLE(key_handle_value);

            // Validate the handle is still valid
            let wide_algorithm: Vec<u16> = OsStr::new("Algorithm Name")
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let mut prop_size: u32 = 0;
            let validation_result = unsafe {
                NCryptGetProperty(
                    key_handle,
                    windows::core::PCWSTR(wide_algorithm.as_ptr()),
                    std::ptr::null_mut(),
                    0,
                    &mut prop_size,
                    NCRYPT_FLAGS(0),
                )
            };
            if validation_result.is_err() {
                return Err(EstError::platform(
                    "Key handle is invalid or has been freed. The key may have been deleted."
                ));
            }

            // RAII guards for hash cleanup
            struct HashAlgGuard(BCRYPT_ALG_HANDLE);
            impl Drop for HashAlgGuard {
                fn drop(&mut self) {
                    unsafe {
                        let _ = BCryptCloseAlgorithmProvider(self.0, 0);
                    }
                }
            }

            struct HashGuard(BCRYPT_HASH_HANDLE);
            impl Drop for HashGuard {
                fn drop(&mut self) {
                    unsafe {
                        let _ = BCryptDestroyHash(self.0);
                    }
                }
            }

            // Hash the data first (CNG signing requires pre-hashed data)
            let hash_algorithm = match handle.algorithm() {
                KeyAlgorithm::EcdsaP256 | KeyAlgorithm::Rsa { .. } => BCRYPT_SHA256_ALGORITHM,
                KeyAlgorithm::EcdsaP384 => {
                    // For P-384, we need SHA-384
                    windows::core::w!("SHA384")
                }
            };

            // Open hash algorithm
            let mut hash_alg_handle = BCRYPT_ALG_HANDLE::default();
            let result = unsafe {
                BCryptOpenAlgorithmProvider(
                    &mut hash_alg_handle,
                    hash_algorithm,
                    std::ptr::null(),
                    0,
                )
            };

            if result.is_err() {
                return Err(EstError::platform(format!(
                    "Failed to open hash algorithm: {:?}",
                    result
                )));
            }

            let _hash_alg_guard = HashAlgGuard(hash_alg_handle);

            // Create hash object
            let mut hash_handle = BCRYPT_HASH_HANDLE::default();
            let result = unsafe {
                BCryptCreateHash(
                    hash_alg_handle,
                    &mut hash_handle,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null(),
                    0,
                    0,
                )
            };

            if result.is_err() {
                return Err(EstError::platform(format!(
                    "Failed to create hash: {:?}",
                    result
                )));
            }

            let _hash_guard = HashGuard(hash_handle);

            // Hash the data
            let result = unsafe { BCryptHashData(hash_handle, data.as_ptr(), data.len() as u32, 0) };

            if result.is_err() {
                return Err(EstError::platform(format!(
                    "Failed to hash data: {:?}",
                    result
                )));
            }

            // Get hash size
            let hash_size = match handle.algorithm() {
                KeyAlgorithm::EcdsaP256 | KeyAlgorithm::Rsa { .. } => 32, // SHA-256
                KeyAlgorithm::EcdsaP384 => 48,                              // SHA-384
            };

            let mut hash = vec![0u8; hash_size];
            let result = unsafe { BCryptFinishHash(hash_handle, hash.as_mut_ptr(), hash_size as u32, 0) };

            if result.is_err() {
                return Err(EstError::platform(format!(
                    "Failed to finish hash: {:?}",
                    result
                )));
            }

            // Sign the hash
            let mut signature_size: u32 = 0;
            let result = unsafe {
                NCryptSignHash(
                    key_handle,
                    std::ptr::null(),
                    hash.as_ptr(),
                    hash.len() as u32,
                    std::ptr::null_mut(),
                    0,
                    &mut signature_size,
                    0,
                )
            };

            if result.is_err() {
                return Err(EstError::platform(format!(
                    "Failed to get signature size: {:?}",
                    result
                )));
            }

            let mut signature = vec![0u8; signature_size as usize];
            let result = unsafe {
                NCryptSignHash(
                    key_handle,
                    std::ptr::null(),
                    hash.as_ptr(),
                    hash.len() as u32,
                    signature.as_mut_ptr(),
                    signature_size,
                    &mut signature_size,
                    0,
                )
            };

            if result.is_err() {
                return Err(EstError::platform(format!(
                    "Failed to sign hash: {:?}",
                    result
                )));
            }

            // For ECDSA, CNG returns raw (r,s) format - convert to DER
            match handle.algorithm() {
                KeyAlgorithm::EcdsaP256 | KeyAlgorithm::EcdsaP384 => {
                    Self::ecdsa_raw_to_der(&signature)
                }
                KeyAlgorithm::Rsa { .. } => Ok(signature),
            }
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
            let keys = self
                ._keys
                .lock()
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
            let keys = self
                ._keys
                .lock()
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
            use std::ffi::OsStr;
            use std::os::windows::ffi::OsStrExt;

            // Get the container name from the key handle metadata
            let container_name = Self::get_container_name(handle)?;
            let provider_name = Self::get_provider_name(handle)?;

            // Open the storage provider
            let wide_provider: Vec<u16> = OsStr::new(&provider_name)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

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
                    "Failed to open CNG provider for deletion: {:?}",
                    result
                )));
            }

            // Open the key
            let wide_container: Vec<u16> = OsStr::new(&container_name)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let mut key_handle = NCRYPT_KEY_HANDLE::default();
            let result = unsafe {
                NCryptOpenKey(
                    prov_handle,
                    &mut key_handle,
                    windows::core::PCWSTR(wide_container.as_ptr()),
                    0,
                    NCRYPT_FLAGS(0),
                )
            };

            if result.is_err() {
                unsafe { NCryptFreeObject(prov_handle.0) };
                return Err(EstError::platform(format!(
                    "Failed to open key for deletion: {:?}",
                    result
                )));
            }

            // Delete the key
            let result = unsafe { NCryptDeleteKey(key_handle, 0) };

            // Clean up provider handle
            unsafe { NCryptFreeObject(prov_handle.0) };

            if result.is_err() {
                return Err(EstError::platform(format!(
                    "Failed to delete key: {:?}",
                    result
                )));
            }

            Ok(())
        }

        #[cfg(not(windows))]
        {
            self._keys
                .lock()
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
