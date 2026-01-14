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

//! Hardware Security Module (HSM) integration for secure key storage.
//!
//! This module provides a trait-based abstraction for cryptographic key providers,
//! allowing EST client operations to use keys stored in Hardware Security Modules,
//! TPMs, cloud key management services, or software-based storage.
//!
//! # NIST 800-53 Controls
//!
//! - **SC-12**: Cryptographic Key Establishment and Management
//!   - Provider-agnostic key generation abstraction
//!   - Support for hardware-backed key storage (HSM, TPM, smart card)
//!   - Key lifecycle management (generation, usage, deletion)
//!   - Zero key material exposure design pattern
//! - **SC-13**: Cryptographic Protection
//!   - Cryptographic operations delegated to secure providers
//!   - Support for FIPS-validated HSM modules
//!   - Signature generation without private key exposure
//! - **SI-7**: Software, Firmware, and Information Integrity
//!   - Key attestation support for verifying hardware protection
//!   - Provider verification capabilities
//!
//! # Key Features
//!
//! - **Zero key material exposure**: Private keys never leave the secure boundary
//! - **Async-first design**: All operations are async-compatible
//! - **Provider-agnostic**: Works with any `KeyProvider` implementation
//! - **Extensible**: Easy to add new provider types
//!
//! # Example
//!
//! ```no_run
//! use usg_est_client::hsm::{KeyProvider, KeyAlgorithm, SoftwareKeyProvider};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a software key provider
//! let provider = SoftwareKeyProvider::new();
//!
//! // Generate a key pair
//! let key_handle = provider
//!     .generate_key_pair(KeyAlgorithm::EcdsaP256, Some("my-device-key"))
//!     .await?;
//!
//! // Get the public key
//! let public_key = provider.public_key(&key_handle).await?;
//!
//! // Sign data
//! let signature = provider.sign(&key_handle, b"data to sign").await?;
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "csr-gen")]
mod software;

#[cfg(feature = "csr-gen")]
pub use software::SoftwareKeyProvider;

#[cfg(feature = "pkcs11")]
pub mod pkcs11;

#[cfg(feature = "pkcs11")]
pub use pkcs11::Pkcs11KeyProvider;

use crate::error::Result;
use async_trait::async_trait;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use std::collections::HashMap;

/// Handle to a key stored in a key provider.
///
/// This is an opaque reference to a cryptographic key. The actual key material
/// is kept secure within the provider and never exposed.
#[derive(Debug, Clone)]
pub struct KeyHandle {
    /// Opaque identifier for the key (provider-specific).
    pub(crate) id: Vec<u8>,

    /// Key algorithm and parameters.
    pub(crate) algorithm: KeyAlgorithm,

    /// Provider-specific metadata.
    pub(crate) metadata: KeyMetadata,
}

impl KeyHandle {
    /// Create a new key handle.
    pub fn new(id: Vec<u8>, algorithm: KeyAlgorithm, metadata: KeyMetadata) -> Self {
        Self {
            id,
            algorithm,
            metadata,
        }
    }

    /// Get the key algorithm.
    pub fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    /// Get the key metadata.
    pub fn metadata(&self) -> &KeyMetadata {
        &self.metadata
    }

    /// Get the key ID (opaque, provider-specific).
    pub fn id(&self) -> &[u8] {
        &self.id
    }
}

/// Supported key algorithms for HSM operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyAlgorithm {
    /// ECDSA with P-256 curve (secp256r1 / prime256v1).
    EcdsaP256,

    /// ECDSA with P-384 curve (secp384r1).
    EcdsaP384,

    /// RSA with specified key size.
    Rsa {
        /// RSA modulus size in bits (typically 2048, 3072, or 4096).
        bits: u32,
    },
}

impl KeyAlgorithm {
    /// Get a string representation of the algorithm.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EcdsaP256 => "ECDSA-P256",
            Self::EcdsaP384 => "ECDSA-P384",
            Self::Rsa { .. } => "RSA",
        }
    }
}

/// Metadata about a cryptographic key.
#[derive(Debug, Clone, Default)]
pub struct KeyMetadata {
    /// Human-readable label for the key.
    pub label: Option<String>,

    /// Whether the key can be used for signing operations.
    pub can_sign: bool,

    /// Whether the key material is extractable from the provider.
    pub extractable: bool,

    /// Provider-specific attributes (e.g., "slot_id", "object_id").
    pub attributes: HashMap<String, String>,
}

/// Information about a key provider.
#[derive(Debug, Clone)]
pub struct ProviderInfo {
    /// Provider name (e.g., "SoftHSM", "YubiHSM", "AWS KMS").
    pub name: String,

    /// Provider version.
    pub version: String,

    /// Manufacturer or vendor name.
    pub manufacturer: String,

    /// Whether the provider supports key generation.
    pub supports_key_generation: bool,

    /// Whether the provider supports key deletion.
    pub supports_key_deletion: bool,
}

/// Trait for cryptographic key providers (software, HSM, TPM, cloud KMS, etc.).
///
/// Implementors of this trait provide secure key storage and signing operations
/// without exposing private key material. All operations are asynchronous to
/// support both local HSMs and remote key management services.
#[async_trait]
pub trait KeyProvider: Send + Sync {
    /// Generate a new key pair in the provider's secure storage.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The key algorithm and parameters
    /// * `label` - Optional human-readable label for the key
    ///
    /// # Returns
    ///
    /// A `KeyHandle` that can be used for subsequent operations.
    async fn generate_key_pair(
        &self,
        algorithm: KeyAlgorithm,
        label: Option<&str>,
    ) -> Result<KeyHandle>;

    /// Get the public key for a given key handle.
    ///
    /// # Arguments
    ///
    /// * `handle` - The key handle from `generate_key_pair`
    ///
    /// # Returns
    ///
    /// The public key in SubjectPublicKeyInfo (SPKI) format.
    async fn public_key(&self, handle: &KeyHandle) -> Result<SubjectPublicKeyInfoOwned>;

    /// Sign data using the private key identified by handle.
    ///
    /// The signature format depends on the key algorithm:
    /// - ECDSA: DER-encoded ECDSA-Sig-Value (SEQUENCE of two INTEGERs)
    /// - RSA: PKCS#1 v1.5 signature
    ///
    /// # Arguments
    ///
    /// * `handle` - The key handle
    /// * `data` - The data to sign (typically a hash digest)
    ///
    /// # Returns
    ///
    /// The signature bytes.
    async fn sign(&self, handle: &KeyHandle, data: &[u8]) -> Result<Vec<u8>>;

    /// Get the signature algorithm identifier for this key.
    ///
    /// Returns the AlgorithmIdentifier that should be used in certificates
    /// and CSRs when this key is used for signing.
    async fn algorithm_identifier(&self, handle: &KeyHandle) -> Result<AlgorithmIdentifierOwned>;

    /// List all keys available in this provider.
    ///
    /// # Returns
    ///
    /// A vector of key handles for all discoverable keys.
    async fn list_keys(&self) -> Result<Vec<KeyHandle>>;

    /// Find a key by label.
    ///
    /// # Arguments
    ///
    /// * `label` - The key label to search for
    ///
    /// # Returns
    ///
    /// The key handle if found, or None.
    async fn find_key(&self, label: &str) -> Result<Option<KeyHandle>>;

    /// Delete a key (if supported by the provider).
    ///
    /// # Arguments
    ///
    /// * `handle` - The key handle to delete
    ///
    /// # Returns
    ///
    /// An error if deletion is not supported or fails.
    async fn delete_key(&self, handle: &KeyHandle) -> Result<()>;

    /// Get information about this provider.
    fn provider_info(&self) -> ProviderInfo;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_algorithm_as_str() {
        assert_eq!(KeyAlgorithm::EcdsaP256.as_str(), "ECDSA-P256");
        assert_eq!(KeyAlgorithm::EcdsaP384.as_str(), "ECDSA-P384");
        assert_eq!(KeyAlgorithm::Rsa { bits: 2048 }.as_str(), "RSA");
    }

    #[test]
    fn test_key_handle_creation() {
        let metadata = KeyMetadata {
            label: Some("test-key".to_string()),
            can_sign: true,
            extractable: false,
            attributes: HashMap::new(),
        };

        let handle = KeyHandle::new(vec![1, 2, 3, 4], KeyAlgorithm::EcdsaP256, metadata);

        assert_eq!(handle.id(), &[1, 2, 3, 4]);
        assert_eq!(handle.algorithm(), KeyAlgorithm::EcdsaP256);
        assert_eq!(handle.metadata().label, Some("test-key".to_string()));
        assert!(handle.metadata().can_sign);
        assert!(!handle.metadata().extractable);
    }

    #[test]
    fn test_provider_info_creation() {
        let info = ProviderInfo {
            name: "TestProvider".to_string(),
            version: "1.0.0".to_string(),
            manufacturer: "Test Corp".to_string(),
            supports_key_generation: true,
            supports_key_deletion: false,
        };

        assert_eq!(info.name, "TestProvider");
        assert!(info.supports_key_generation);
        assert!(!info.supports_key_deletion);
    }
}
