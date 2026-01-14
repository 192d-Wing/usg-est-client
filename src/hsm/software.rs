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

//! Software-based (in-memory) key provider implementation.
//!
//! This module provides a software-based implementation of the [`KeyProvider`] trait
//! that stores cryptographic keys in memory. It is primarily intended for:
//!
//! - **Development and testing**: Quick setup without HSM hardware
//! - **Backward compatibility**: Drop-in replacement for existing rcgen-based CSR generation
//! - **Non-production environments**: Where hardware security is not required
//!
//! # Security Considerations
//!
//! **WARNING**: This implementation stores private keys in process memory and should
//! **NOT** be used in production environments where security is critical. Private keys:
//!
//! - Are not protected by hardware security boundaries
//! - May be swapped to disk by the operating system
//! - Can be extracted via memory dumps or debugging tools
//! - Are lost when the process terminates
//!
//! For production use, consider using a hardware-backed key provider (HSM, TPM, or cloud KMS).
//!
//! # Example
//!
//! ```no_run
//! use usg_est_client::hsm::{KeyProvider, KeyAlgorithm, SoftwareKeyProvider};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a new software key provider
//! let provider = SoftwareKeyProvider::new();
//!
//! // Generate an ECDSA P-256 key pair
//! let handle = provider
//!     .generate_key_pair(KeyAlgorithm::EcdsaP256, Some("my-key"))
//!     .await?;
//!
//! // Use the key for signing
//! let signature = provider.sign(&handle, b"data to sign").await?;
//!
//! // List all keys
//! let keys = provider.list_keys().await?;
//! println!("Found {} keys", keys.len());
//!
//! // Find a key by label
//! if let Some(key) = provider.find_key("my-key").await? {
//!     println!("Found key: {:?}", key);
//! }
//!
//! // Delete the key
//! provider.delete_key(&handle).await?;
//! # Ok(())
//! # }
//! ```

use super::{KeyAlgorithm, KeyHandle, KeyMetadata, KeyProvider, ProviderInfo};
use crate::error::{EstError, Result};
use async_trait::async_trait;
use const_oid::db::rfc5912::{ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, SHA_256_WITH_RSA_ENCRYPTION};
use der::Decode;
use rcgen::{KeyPair, PublicKeyData, SignatureAlgorithm};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Type alias for the key storage map: key_id -> (KeyPair, KeyMetadata)
type KeyStorage = Arc<RwLock<HashMap<Vec<u8>, (KeyPair, KeyMetadata)>>>;

/// Software-based key provider that stores keys in memory.
///
/// This implementation uses [`rcgen`] for key generation and signing operations.
/// Keys are stored in a thread-safe HashMap protected by an `Arc<RwLock<>>`.
///
/// # Thread Safety
///
/// All operations are thread-safe and can be called concurrently from multiple tasks.
#[derive(Clone)]
pub struct SoftwareKeyProvider {
    /// Internal key storage: key_id -> (KeyPair, KeyMetadata)
    keys: KeyStorage,

    /// Counter for generating unique key IDs
    next_id: Arc<RwLock<u64>>,
}

impl SoftwareKeyProvider {
    /// Create a new software key provider.
    ///
    /// The provider starts with no keys. Use [`generate_key_pair`](KeyProvider::generate_key_pair)
    /// to create new keys.
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
            next_id: Arc::new(RwLock::new(0)),
        }
    }

    /// Get the rcgen KeyPair for a given handle.
    ///
    /// This method provides access to the underlying rcgen KeyPair, which can be used
    /// directly with rcgen's `CertificateParams` for CSR generation.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use usg_est_client::hsm::{KeyProvider, KeyAlgorithm, SoftwareKeyProvider};
    /// use rcgen::CertificateParams;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let provider = SoftwareKeyProvider::new();
    /// let handle = provider.generate_key_pair(KeyAlgorithm::EcdsaP256, Some("key")).await?;
    ///
    /// // Get the rcgen KeyPair for CSR generation
    /// let key_pair = provider.get_rcgen_key_pair(&handle)?;
    /// let params = CertificateParams::default();
    /// let csr = params.serialize_request(&key_pair)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_rcgen_key_pair(&self, handle: &KeyHandle) -> Result<KeyPair> {
        let (kp, _) = self.get_key_pair(handle)?;
        Ok(kp)
    }

    /// Get the next unique key ID.
    fn next_key_id(&self) -> Vec<u8> {
        let mut id = self.next_id.write().unwrap();
        let current = *id;
        *id += 1;
        current.to_be_bytes().to_vec()
    }

    /// Convert KeyAlgorithm to rcgen SignatureAlgorithm.
    fn to_rcgen_algorithm(algorithm: KeyAlgorithm) -> Result<&'static SignatureAlgorithm> {
        match algorithm {
            KeyAlgorithm::EcdsaP256 => Ok(&rcgen::PKCS_ECDSA_P256_SHA256),
            KeyAlgorithm::EcdsaP384 => Ok(&rcgen::PKCS_ECDSA_P384_SHA384),
            KeyAlgorithm::Rsa { bits } => match bits {
                2048 => Ok(&rcgen::PKCS_RSA_SHA256),
                3072 => Ok(&rcgen::PKCS_RSA_SHA256),
                4096 => Ok(&rcgen::PKCS_RSA_SHA256),
                _ => Err(EstError::csr(format!(
                    "Unsupported RSA key size: {} bits (supported: 2048, 3072, 4096)",
                    bits
                ))),
            },
        }
    }

    /// Get a cloned key pair for a handle.
    fn get_key_pair(&self, handle: &KeyHandle) -> Result<(KeyPair, KeyMetadata)> {
        let keys = self.keys.read().unwrap();
        let (kp, metadata) = keys
            .get(&handle.id)
            .ok_or_else(|| EstError::csr(format!("Key not found: {:?}", handle.id)))?;

        // Clone by serializing and deserializing the key
        let der = kp.serialize_der();
        let alg = Self::to_rcgen_algorithm(handle.algorithm)?;

        // Convert Vec<u8> to PrivatePkcs8KeyDer
        use rustls_pki_types::PrivatePkcs8KeyDer;
        let key_der = PrivatePkcs8KeyDer::from(der);

        let cloned_kp = KeyPair::from_pkcs8_der_and_sign_algo(&key_der, alg)
            .map_err(|e| EstError::csr(format!("Failed to clone key pair: {}", e)))?;

        Ok((cloned_kp, metadata.clone()))
    }
}

impl Default for SoftwareKeyProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl KeyProvider for SoftwareKeyProvider {
    async fn generate_key_pair(
        &self,
        algorithm: KeyAlgorithm,
        label: Option<&str>,
    ) -> Result<KeyHandle> {
        // Check for duplicate labels
        if let Some(label_str) = label {
            let keys = self.keys.read().unwrap();
            for (_, metadata) in keys.values() {
                if metadata.label.as_deref() == Some(label_str) {
                    return Err(EstError::csr(format!(
                        "Key with label '{}' already exists",
                        label_str
                    )));
                }
            }
        }

        // Convert algorithm to rcgen format
        let rcgen_alg = Self::to_rcgen_algorithm(algorithm)?;

        // Generate the key pair using rcgen
        let key_pair = KeyPair::generate_for(rcgen_alg)
            .map_err(|e| EstError::csr(format!("Failed to generate key pair: {}", e)))?;

        // Create unique key ID
        let key_id = self.next_key_id();

        // Create metadata
        let metadata = KeyMetadata {
            label: label.map(String::from),
            can_sign: true,
            extractable: true, // Software keys are always extractable
            attributes: HashMap::new(),
        };

        // Store the key pair
        {
            let mut keys = self.keys.write().unwrap();
            keys.insert(key_id.clone(), (key_pair, metadata.clone()));
        }

        // Return the handle
        Ok(KeyHandle::new(key_id, algorithm, metadata))
    }

    async fn public_key(&self, handle: &KeyHandle) -> Result<SubjectPublicKeyInfoOwned> {
        let (key_pair, _) = self.get_key_pair(handle)?;

        // Get the public key SPKI from rcgen (DER encoded)
        let public_key_der = key_pair.subject_public_key_info();

        // Parse it into SubjectPublicKeyInfo
        SubjectPublicKeyInfoOwned::from_der(&public_key_der)
            .map_err(|e| EstError::csr(format!("Failed to parse public key: {}", e)))
    }

    async fn sign(&self, handle: &KeyHandle, data: &[u8]) -> Result<Vec<u8>> {
        let (key_pair, _) = self.get_key_pair(handle)?;

        // Get the private key in PKCS#8 DER format
        let pkcs8_der = key_pair.serialize_der();

        // Sign based on algorithm
        match handle.algorithm() {
            KeyAlgorithm::EcdsaP256 => {
                use p256::ecdsa::{Signature, SigningKey, signature::Signer};
                use p256::pkcs8::DecodePrivateKey;

                // Parse PKCS#8 DER into P-256 signing key
                let signing_key = SigningKey::from_pkcs8_der(&pkcs8_der).map_err(|e| {
                    EstError::csr(format!("Failed to parse P-256 private key: {}", e))
                })?;

                // Sign the digest (data is already hashed by encode_and_hash)
                let signature: Signature = signing_key.sign(data);

                // Return DER-encoded signature
                Ok(signature.to_der().as_bytes().to_vec())
            }
            KeyAlgorithm::EcdsaP384 => {
                use p384::ecdsa::{Signature, SigningKey, signature::Signer};
                use p384::pkcs8::DecodePrivateKey;

                // Parse PKCS#8 DER into P-384 signing key
                let signing_key = SigningKey::from_pkcs8_der(&pkcs8_der).map_err(|e| {
                    EstError::csr(format!("Failed to parse P-384 private key: {}", e))
                })?;

                // Sign the digest
                let signature: Signature = signing_key.sign(data);

                // Return DER-encoded signature
                Ok(signature.to_der().as_bytes().to_vec())
            }
            KeyAlgorithm::Rsa { .. } => {
                use rsa::RsaPrivateKey;
                use rsa::pkcs1v15::SigningKey;
                use rsa::pkcs8::DecodePrivateKey;
                use rsa::signature::{SignatureEncoding, Signer};
                use sha2::Sha256;

                // Parse PKCS#8 DER into RSA private key
                let private_key = RsaPrivateKey::from_pkcs8_der(&pkcs8_der).map_err(|e| {
                    EstError::csr(format!("Failed to parse RSA private key: {}", e))
                })?;

                // Create signing key with SHA-256
                let signing_key = SigningKey::<Sha256>::new(private_key);

                // Sign the digest
                let signature = signing_key.sign(data);

                // Return signature bytes
                Ok(signature.to_vec())
            }
        }
    }

    async fn algorithm_identifier(&self, handle: &KeyHandle) -> Result<AlgorithmIdentifierOwned> {
        // Return the appropriate algorithm identifier based on the key type
        let oid = match handle.algorithm {
            KeyAlgorithm::EcdsaP256 => ECDSA_WITH_SHA_256,
            KeyAlgorithm::EcdsaP384 => ECDSA_WITH_SHA_384,
            KeyAlgorithm::Rsa { .. } => SHA_256_WITH_RSA_ENCRYPTION,
        };

        Ok(AlgorithmIdentifierOwned {
            oid,
            parameters: None,
        })
    }

    async fn list_keys(&self) -> Result<Vec<KeyHandle>> {
        let keys = self.keys.read().unwrap();

        let mut handles = Vec::new();
        for (key_id, (key_pair, metadata)) in keys.iter() {
            // Determine the algorithm from the key pair
            let alg_ref = key_pair.algorithm();
            let algorithm = if std::ptr::eq(alg_ref, &rcgen::PKCS_ECDSA_P256_SHA256) {
                KeyAlgorithm::EcdsaP256
            } else if std::ptr::eq(alg_ref, &rcgen::PKCS_ECDSA_P384_SHA384) {
                KeyAlgorithm::EcdsaP384
            } else if std::ptr::eq(alg_ref, &rcgen::PKCS_RSA_SHA256) {
                // For RSA, we need to parse the public key to determine bit size
                // Default to 2048 for software keys (most common)
                KeyAlgorithm::Rsa { bits: 2048 }
            } else {
                // Unknown algorithm, skip this key
                continue;
            };

            handles.push(KeyHandle::new(key_id.clone(), algorithm, metadata.clone()));
        }

        Ok(handles)
    }

    async fn find_key(&self, label: &str) -> Result<Option<KeyHandle>> {
        let keys = self.keys.read().unwrap();

        for (key_id, (key_pair, metadata)) in keys.iter() {
            if metadata.label.as_deref() == Some(label) {
                // Determine the algorithm
                let alg_ref = key_pair.algorithm();
                let algorithm = if std::ptr::eq(alg_ref, &rcgen::PKCS_ECDSA_P256_SHA256) {
                    KeyAlgorithm::EcdsaP256
                } else if std::ptr::eq(alg_ref, &rcgen::PKCS_ECDSA_P384_SHA384) {
                    KeyAlgorithm::EcdsaP384
                } else if std::ptr::eq(alg_ref, &rcgen::PKCS_RSA_SHA256) {
                    KeyAlgorithm::Rsa { bits: 2048 }
                } else {
                    continue;
                };

                return Ok(Some(KeyHandle::new(
                    key_id.clone(),
                    algorithm,
                    metadata.clone(),
                )));
            }
        }

        Ok(None)
    }

    async fn delete_key(&self, handle: &KeyHandle) -> Result<()> {
        let mut keys = self.keys.write().unwrap();

        if keys.remove(&handle.id).is_some() {
            Ok(())
        } else {
            Err(EstError::csr(format!(
                "Key not found for deletion: {:?}",
                handle.id
            )))
        }
    }

    fn provider_info(&self) -> ProviderInfo {
        ProviderInfo {
            name: "Software Key Provider".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            manufacturer: "usg-est-client".to_string(),
            supports_key_generation: true,
            supports_key_deletion: true,
        }
    }
}

#[cfg(all(test, feature = "csr-gen"))]
mod tests {
    use super::*;
    use der::Encode;

    #[tokio::test]
    async fn test_new_provider() {
        let provider = SoftwareKeyProvider::new();
        let keys = provider.list_keys().await.unwrap();
        assert_eq!(keys.len(), 0);
    }

    #[tokio::test]
    async fn test_generate_ecdsa_p256_key() {
        let provider = SoftwareKeyProvider::new();

        let handle = provider
            .generate_key_pair(KeyAlgorithm::EcdsaP256, Some("test-p256"))
            .await
            .unwrap();

        assert_eq!(handle.algorithm(), KeyAlgorithm::EcdsaP256);
        assert_eq!(handle.metadata().label, Some("test-p256".to_string()));
        assert!(handle.metadata().can_sign);
        assert!(handle.metadata().extractable);
    }

    #[tokio::test]
    async fn test_generate_ecdsa_p384_key() {
        let provider = SoftwareKeyProvider::new();

        let handle = provider
            .generate_key_pair(KeyAlgorithm::EcdsaP384, Some("test-p384"))
            .await
            .unwrap();

        assert_eq!(handle.algorithm(), KeyAlgorithm::EcdsaP384);
    }

    #[tokio::test]
    async fn test_generate_rsa_key() {
        let provider = SoftwareKeyProvider::new();

        // RSA key generation may not be supported depending on rcgen backend
        let result = provider
            .generate_key_pair(KeyAlgorithm::Rsa { bits: 2048 }, Some("test-rsa"))
            .await;

        // Either it succeeds or fails with appropriate error
        match result {
            Ok(handle) => {
                assert_eq!(handle.algorithm(), KeyAlgorithm::Rsa { bits: 2048 });
            }
            Err(e) => {
                // RSA key generation may not be available
                assert!(
                    e.to_string().contains("no support") || e.to_string().contains("not supported")
                );
            }
        }
    }

    #[tokio::test]
    async fn test_generate_key_without_label() {
        let provider = SoftwareKeyProvider::new();

        let handle = provider
            .generate_key_pair(KeyAlgorithm::EcdsaP256, None)
            .await
            .unwrap();

        assert_eq!(handle.metadata().label, None);
    }

    #[tokio::test]
    async fn test_duplicate_label_error() {
        let provider = SoftwareKeyProvider::new();

        // First key with label "duplicate"
        provider
            .generate_key_pair(KeyAlgorithm::EcdsaP256, Some("duplicate"))
            .await
            .unwrap();

        // Second key with same label should fail
        let result = provider
            .generate_key_pair(KeyAlgorithm::EcdsaP256, Some("duplicate"))
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));
    }

    #[tokio::test]
    async fn test_unsupported_rsa_bits() {
        let provider = SoftwareKeyProvider::new();

        let result = provider
            .generate_key_pair(KeyAlgorithm::Rsa { bits: 1024 }, Some("weak-rsa"))
            .await;

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Unsupported RSA key size")
        );
    }

    #[tokio::test]
    async fn test_public_key_extraction() {
        let provider = SoftwareKeyProvider::new();

        let handle = provider
            .generate_key_pair(KeyAlgorithm::EcdsaP256, Some("test-pubkey"))
            .await
            .unwrap();

        let public_key = provider.public_key(&handle).await.unwrap();

        // Verify it's a valid SPKI structure
        assert!(!public_key.to_der().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_public_key_missing_key() {
        let provider = SoftwareKeyProvider::new();

        // Create a handle for a non-existent key
        let fake_handle = KeyHandle::new(
            vec![99, 99, 99],
            KeyAlgorithm::EcdsaP256,
            KeyMetadata::default(),
        );

        let result = provider.public_key(&fake_handle).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Key not found"));
    }

    #[tokio::test]
    async fn test_sign_p256() {
        use sha2::{Digest, Sha256};

        let provider = SoftwareKeyProvider::new();

        let handle = provider
            .generate_key_pair(KeyAlgorithm::EcdsaP256, Some("test-sign-p256"))
            .await
            .unwrap();

        // Hash some test data (sign() expects pre-hashed data)
        let data = b"test data to sign";
        let mut hasher = Sha256::new();
        hasher.update(data);
        let digest = hasher.finalize();

        // Sign the digest
        let signature = provider.sign(&handle, &digest).await.unwrap();

        // Verify we got a signature
        assert!(!signature.is_empty());

        // P-256 signatures should be around 70-72 bytes in DER format
        assert!(signature.len() >= 64 && signature.len() <= 72);
    }

    #[tokio::test]
    async fn test_sign_p384() {
        use sha2::{Digest, Sha384};

        let provider = SoftwareKeyProvider::new();

        let handle = provider
            .generate_key_pair(KeyAlgorithm::EcdsaP384, Some("test-sign-p384"))
            .await
            .unwrap();

        // Hash some test data
        let data = b"test data to sign";
        let mut hasher = Sha384::new();
        hasher.update(data);
        let digest = hasher.finalize();

        // Sign the digest
        let signature = provider.sign(&handle, &digest).await.unwrap();

        // Verify we got a signature
        assert!(!signature.is_empty());

        // P-384 signatures should be around 102-104 bytes in DER format
        assert!(signature.len() >= 96 && signature.len() <= 104);
    }

    #[tokio::test]
    #[ignore] // rcgen doesn't support RSA key generation without additional features
    async fn test_sign_rsa() {
        use sha2::{Digest, Sha256};

        let provider = SoftwareKeyProvider::new();

        let handle = provider
            .generate_key_pair(KeyAlgorithm::Rsa { bits: 2048 }, Some("test-sign-rsa"))
            .await
            .unwrap();

        // Hash some test data
        let data = b"test data to sign";
        let mut hasher = Sha256::new();
        hasher.update(data);
        let digest = hasher.finalize();

        // Sign the digest
        let signature = provider.sign(&handle, &digest).await.unwrap();

        // Verify we got a signature
        assert!(!signature.is_empty());

        // RSA-2048 signatures should be 256 bytes
        assert_eq!(signature.len(), 256);
    }

    #[tokio::test]
    async fn test_get_rcgen_key_pair() {
        let provider = SoftwareKeyProvider::new();

        let handle = provider
            .generate_key_pair(KeyAlgorithm::EcdsaP256, Some("test-rcgen"))
            .await
            .unwrap();

        // Get the rcgen KeyPair
        let key_pair = provider.get_rcgen_key_pair(&handle).unwrap();

        // Verify we can use it
        assert_eq!(key_pair.algorithm(), &rcgen::PKCS_ECDSA_P256_SHA256);
    }

    #[tokio::test]
    async fn test_algorithm_identifier() {
        let provider = SoftwareKeyProvider::new();

        // Test ECDSA P-256
        let handle_p256 = provider
            .generate_key_pair(KeyAlgorithm::EcdsaP256, Some("p256"))
            .await
            .unwrap();
        let alg_id_p256 = provider.algorithm_identifier(&handle_p256).await.unwrap();
        assert_eq!(alg_id_p256.oid, ECDSA_WITH_SHA_256);

        // Test ECDSA P-384
        let handle_p384 = provider
            .generate_key_pair(KeyAlgorithm::EcdsaP384, Some("p384"))
            .await
            .unwrap();
        let alg_id_p384 = provider.algorithm_identifier(&handle_p384).await.unwrap();
        assert_eq!(alg_id_p384.oid, ECDSA_WITH_SHA_384);

        // Test RSA (if supported)
        if let Ok(handle_rsa) = provider
            .generate_key_pair(KeyAlgorithm::Rsa { bits: 2048 }, Some("rsa"))
            .await
        {
            let alg_id_rsa = provider.algorithm_identifier(&handle_rsa).await.unwrap();
            assert_eq!(alg_id_rsa.oid, SHA_256_WITH_RSA_ENCRYPTION);
        }
    }

    #[tokio::test]
    async fn test_list_keys() {
        let provider = SoftwareKeyProvider::new();

        // Initially empty
        assert_eq!(provider.list_keys().await.unwrap().len(), 0);

        // Generate some keys
        provider
            .generate_key_pair(KeyAlgorithm::EcdsaP256, Some("key1"))
            .await
            .unwrap();
        provider
            .generate_key_pair(KeyAlgorithm::EcdsaP384, Some("key2"))
            .await
            .unwrap();

        // Try to add RSA key if supported
        let _ = provider
            .generate_key_pair(KeyAlgorithm::Rsa { bits: 2048 }, None)
            .await;

        // Should have at least 2 keys (ECDSA keys)
        let keys = provider.list_keys().await.unwrap();
        assert!(keys.len() >= 2);

        // Verify labels
        let labels: Vec<_> = keys
            .iter()
            .filter_map(|k| k.metadata().label.as_ref())
            .collect();
        assert!(labels.contains(&&"key1".to_string()));
        assert!(labels.contains(&&"key2".to_string()));
    }

    #[tokio::test]
    async fn test_find_key() {
        let provider = SoftwareKeyProvider::new();

        // Generate a key
        provider
            .generate_key_pair(KeyAlgorithm::EcdsaP256, Some("findme"))
            .await
            .unwrap();

        // Find it
        let found = provider.find_key("findme").await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().metadata().label, Some("findme".to_string()));

        // Try to find non-existent key
        let not_found = provider.find_key("nothere").await.unwrap();
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn test_delete_key() {
        let provider = SoftwareKeyProvider::new();

        // Generate a key
        let handle = provider
            .generate_key_pair(KeyAlgorithm::EcdsaP256, Some("deleteme"))
            .await
            .unwrap();

        // Verify it exists
        assert_eq!(provider.list_keys().await.unwrap().len(), 1);

        // Delete it
        provider.delete_key(&handle).await.unwrap();

        // Verify it's gone
        assert_eq!(provider.list_keys().await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_delete_missing_key() {
        let provider = SoftwareKeyProvider::new();

        let fake_handle = KeyHandle::new(
            vec![99, 99, 99],
            KeyAlgorithm::EcdsaP256,
            KeyMetadata::default(),
        );

        let result = provider.delete_key(&fake_handle).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[tokio::test]
    async fn test_provider_info() {
        let provider = SoftwareKeyProvider::new();
        let info = provider.provider_info();

        assert_eq!(info.name, "Software Key Provider");
        assert_eq!(info.manufacturer, "usg-est-client");
        assert!(info.supports_key_generation);
        assert!(info.supports_key_deletion);
        assert!(!info.version.is_empty());
    }

    #[tokio::test]
    async fn test_concurrent_operations() {
        let provider = Arc::new(SoftwareKeyProvider::new());

        // Spawn multiple tasks that generate keys concurrently
        let mut handles = vec![];
        for i in 0..10 {
            let provider_clone = Arc::clone(&provider);
            let handle = tokio::spawn(async move {
                provider_clone
                    .generate_key_pair(
                        KeyAlgorithm::EcdsaP256,
                        Some(&format!("concurrent-key-{}", i)),
                    )
                    .await
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete
        for handle in handles {
            handle.await.unwrap().unwrap();
        }

        // Verify all keys were created
        let keys = provider.list_keys().await.unwrap();
        assert_eq!(keys.len(), 10);
    }

    #[tokio::test]
    async fn test_key_id_uniqueness() {
        let provider = SoftwareKeyProvider::new();

        let handle1 = provider
            .generate_key_pair(KeyAlgorithm::EcdsaP256, Some("key1"))
            .await
            .unwrap();

        let handle2 = provider
            .generate_key_pair(KeyAlgorithm::EcdsaP256, Some("key2"))
            .await
            .unwrap();

        // Key IDs should be different
        assert_ne!(handle1.id(), handle2.id());
    }

    #[tokio::test]
    async fn test_clone_provider() {
        let provider1 = SoftwareKeyProvider::new();

        // Generate a key in the first provider
        provider1
            .generate_key_pair(KeyAlgorithm::EcdsaP256, Some("shared-key"))
            .await
            .unwrap();

        // Clone the provider
        let provider2 = provider1.clone();

        // Both providers should see the same key
        assert_eq!(provider1.list_keys().await.unwrap().len(), 1);
        assert_eq!(provider2.list_keys().await.unwrap().len(), 1);

        // Find the key through the cloned provider
        let found = provider2.find_key("shared-key").await.unwrap();
        assert!(found.is_some());
    }
}
