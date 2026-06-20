// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! FIPS-validated key provider backed by the aws-lc-rs FIPS cryptographic module.
//!
//! This is Phase 2 of the FIPS migration: key generation and signing for EST
//! enrollment run inside the aws-lc-rs FIPS boundary instead of RustCrypto/ring.
//! It implements the [`KeyProvider`] trait, so it is a drop-in replacement for
//! [`SoftwareKeyProvider`](super::SoftwareKeyProvider) on the CSR path
//! (via `HsmCsrBuilder::build_with_provider`).
//!
//! ASN.1 encoding (SPKI, CSR structure) still uses the `spki`/`der`/`x509-cert`
//! crates — aws-lc-rs provides the cryptographic primitives only. The actual
//! key generation and signature operations are performed by the FIPS module.
//!
//! Available only with the `fips-tls` feature (Linux; Windows uses CNG FIPS).

use super::{KeyAlgorithm, KeyHandle, KeyMetadata, KeyProvider, ProviderInfo};
use crate::error::{EstError, Result};
use async_trait::async_trait;
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING, EcdsaKeyPair,
    KeyPair as _AwsLcKeyPair, RSA_PKCS1_SHA256,
};
use const_oid::db::rfc5912::{
    ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ID_EC_PUBLIC_KEY, SECP_256_R_1, SECP_384_R_1,
    SHA_256_WITH_RSA_ENCRYPTION,
};
use der::{Decode, Encode, asn1::BitString};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// A private key held inside the aws-lc-rs FIPS module.
///
/// Both variants implement `aws_lc_rs::signature::KeyPair`, which is `Send + Sync`,
/// so the provider is safe to share across threads.
enum FipsKey {
    Ecdsa(EcdsaKeyPair),
    Rsa(RsaKeyPair),
}

type KeyStore = Arc<RwLock<HashMap<Vec<u8>, (FipsKey, KeyAlgorithm, KeyMetadata)>>>;

/// FIPS-validated key provider using the aws-lc-rs FIPS module.
#[derive(Clone)]
pub struct AwsLcKeyProvider {
    keys: KeyStore,
    next_id: Arc<RwLock<u64>>,
}

impl AwsLcKeyProvider {
    /// Create a new, empty FIPS key provider.
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
            next_id: Arc::new(RwLock::new(0)),
        }
    }

    fn next_key_id(&self) -> Vec<u8> {
        let mut id = self
            .next_id
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let current = *id;
        *id += 1;
        current.to_be_bytes().to_vec()
    }

    /// Build the SPKI for an ECDSA public key from its SEC1 uncompressed point.
    fn ecdsa_spki(point: &[u8], algorithm: KeyAlgorithm) -> Result<SubjectPublicKeyInfoOwned> {
        let curve_oid = match algorithm {
            KeyAlgorithm::EcdsaP256 => SECP_256_R_1,
            KeyAlgorithm::EcdsaP384 => SECP_384_R_1,
            KeyAlgorithm::Rsa { .. } => {
                return Err(EstError::hsm("ecdsa_spki called for an RSA key"));
            }
        };
        let curve_der = curve_oid
            .to_der()
            .map_err(|e| EstError::hsm(format!("Failed to encode curve OID: {}", e)))?;
        let algorithm_id = AlgorithmIdentifierOwned {
            oid: ID_EC_PUBLIC_KEY,
            parameters: Some(
                der::Any::from_der(&curve_der)
                    .map_err(|e| EstError::hsm(format!("Failed to build EC parameters: {}", e)))?,
            ),
        };
        let subject_public_key = BitString::from_bytes(point)
            .map_err(|e| EstError::hsm(format!("Failed to encode EC public key: {}", e)))?;
        Ok(SubjectPublicKeyInfoOwned {
            algorithm: algorithm_id,
            subject_public_key,
        })
    }
}

impl Default for AwsLcKeyProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl KeyProvider for AwsLcKeyProvider {
    async fn generate_key_pair(
        &self,
        algorithm: KeyAlgorithm,
        label: Option<&str>,
    ) -> Result<KeyHandle> {
        // Reject duplicate labels (matches SoftwareKeyProvider semantics).
        if let Some(label_str) = label {
            let keys = self
                .keys
                .read()
                .map_err(|e| EstError::hsm(format!("Key storage lock poisoned: {}", e)))?;
            if keys
                .values()
                .any(|(_, _, m)| m.label.as_deref() == Some(label_str))
            {
                return Err(EstError::hsm(format!(
                    "Key with label '{}' already exists",
                    label_str
                )));
            }
        }

        let key = match algorithm {
            KeyAlgorithm::EcdsaP256 => FipsKey::Ecdsa(
                EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING)
                    .map_err(|_| EstError::hsm("FIPS ECDSA P-256 key generation failed"))?,
            ),
            KeyAlgorithm::EcdsaP384 => FipsKey::Ecdsa(
                EcdsaKeyPair::generate(&ECDSA_P384_SHA384_ASN1_SIGNING)
                    .map_err(|_| EstError::hsm("FIPS ECDSA P-384 key generation failed"))?,
            ),
            KeyAlgorithm::Rsa { bits } => {
                let size = match bits {
                    2048 => KeySize::Rsa2048,
                    3072 => KeySize::Rsa3072,
                    4096 => KeySize::Rsa4096,
                    other => {
                        return Err(EstError::hsm(format!(
                            "Unsupported RSA key size: {} bits (FIPS supports 2048, 3072, 4096)",
                            other
                        )));
                    }
                };
                FipsKey::Rsa(
                    RsaKeyPair::generate_fips(size)
                        .map_err(|_| EstError::hsm("FIPS RSA key generation failed"))?,
                )
            }
        };

        let key_id = self.next_key_id();
        let metadata = KeyMetadata {
            label: label.map(String::from),
            can_sign: true,
            extractable: false, // FIPS keys are not exported from the module.
            attributes: HashMap::new(),
        };

        self.keys
            .write()
            .map_err(|e| EstError::hsm(format!("Key storage lock poisoned: {}", e)))?
            .insert(key_id.clone(), (key, algorithm, metadata.clone()));

        Ok(KeyHandle::new(key_id, algorithm, metadata))
    }

    async fn public_key(&self, handle: &KeyHandle) -> Result<SubjectPublicKeyInfoOwned> {
        let keys = self
            .keys
            .read()
            .map_err(|e| EstError::hsm(format!("Key storage lock poisoned: {}", e)))?;
        let (key, algorithm, _) = keys
            .get(&handle.id)
            .ok_or_else(|| EstError::hsm(format!("Key not found: {:?}", handle.id)))?;

        match key {
            FipsKey::Ecdsa(kp) => Self::ecdsa_spki(kp.public_key().as_ref(), *algorithm),
            FipsKey::Rsa(kp) => {
                // aws-lc-rs gives the RSA public key as X.509 SPKI DER directly.
                let der = kp
                    .public_key()
                    .as_der()
                    .map_err(|_| EstError::hsm("Failed to encode RSA public key"))?;
                SubjectPublicKeyInfoOwned::from_der(der.as_ref())
                    .map_err(|e| EstError::hsm(format!("Failed to parse RSA SPKI: {}", e)))
            }
        }
    }

    async fn sign(&self, handle: &KeyHandle, data: &[u8]) -> Result<Vec<u8>> {
        let keys = self
            .keys
            .read()
            .map_err(|e| EstError::hsm(format!("Key storage lock poisoned: {}", e)))?;
        let (key, _, _) = keys
            .get(&handle.id)
            .ok_or_else(|| EstError::hsm(format!("Key not found: {:?}", handle.id)))?;

        // `data` is the raw to-be-signed bytes; the FIPS module applies the
        // algorithm's hash internally (matches SoftwareKeyProvider's contract).
        let rng = SystemRandom::new();
        match key {
            FipsKey::Ecdsa(kp) => {
                let sig = kp
                    .sign(&rng, data)
                    .map_err(|_| EstError::hsm("FIPS ECDSA signing failed"))?;
                Ok(sig.as_ref().to_vec()) // ASN.1 DER (ECDSA-Sig-Value)
            }
            FipsKey::Rsa(kp) => {
                let mut signature = vec![0u8; kp.public_modulus_len()];
                kp.sign(&RSA_PKCS1_SHA256, &rng, data, &mut signature)
                    .map_err(|_| EstError::hsm("FIPS RSA signing failed"))?;
                Ok(signature)
            }
        }
    }

    async fn algorithm_identifier(&self, handle: &KeyHandle) -> Result<AlgorithmIdentifierOwned> {
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
        let keys = self
            .keys
            .read()
            .map_err(|e| EstError::hsm(format!("Key storage lock poisoned: {}", e)))?;
        Ok(keys
            .iter()
            .map(|(id, (_, alg, meta))| KeyHandle::new(id.clone(), *alg, meta.clone()))
            .collect())
    }

    async fn find_key(&self, label: &str) -> Result<Option<KeyHandle>> {
        let keys = self
            .keys
            .read()
            .map_err(|e| EstError::hsm(format!("Key storage lock poisoned: {}", e)))?;
        Ok(keys.iter().find_map(|(id, (_, alg, meta))| {
            if meta.label.as_deref() == Some(label) {
                Some(KeyHandle::new(id.clone(), *alg, meta.clone()))
            } else {
                None
            }
        }))
    }

    async fn delete_key(&self, handle: &KeyHandle) -> Result<()> {
        let removed = self
            .keys
            .write()
            .map_err(|e| EstError::hsm(format!("Key storage lock poisoned: {}", e)))?
            .remove(&handle.id)
            .is_some();
        if removed {
            Ok(())
        } else {
            Err(EstError::hsm(format!(
                "Key not found for deletion: {:?}",
                handle.id
            )))
        }
    }

    fn provider_info(&self) -> ProviderInfo {
        ProviderInfo {
            name: "aws-lc-rs FIPS Key Provider".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            manufacturer: "usg-est-client".to_string(),
            supports_key_generation: true,
            supports_key_deletion: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Encode;

    #[tokio::test]
    async fn generate_and_sign_ecdsa_p256() {
        let provider = AwsLcKeyProvider::new();
        let handle = provider
            .generate_key_pair(KeyAlgorithm::EcdsaP256, Some("p256"))
            .await
            .expect("keygen");
        assert_eq!(handle.algorithm(), KeyAlgorithm::EcdsaP256);

        let spki = provider.public_key(&handle).await.expect("spki");
        assert!(!spki.to_der().unwrap().is_empty());

        let sig = provider.sign(&handle, b"to-be-signed").await.expect("sign");
        assert!(!sig.is_empty());
    }

    #[tokio::test]
    async fn generate_and_sign_ecdsa_p384() {
        let provider = AwsLcKeyProvider::new();
        let handle = provider
            .generate_key_pair(KeyAlgorithm::EcdsaP384, None)
            .await
            .expect("keygen");
        let sig = provider.sign(&handle, b"to-be-signed").await.expect("sign");
        assert!(!sig.is_empty());
    }

    #[tokio::test]
    async fn generate_and_sign_rsa_2048() {
        let provider = AwsLcKeyProvider::new();
        let handle = provider
            .generate_key_pair(KeyAlgorithm::Rsa { bits: 2048 }, Some("rsa"))
            .await
            .expect("keygen");
        let spki = provider.public_key(&handle).await.expect("spki");
        assert!(!spki.to_der().unwrap().is_empty());
        let sig = provider.sign(&handle, b"to-be-signed").await.expect("sign");
        assert_eq!(sig.len(), 256); // RSA-2048 signature size
    }

    #[tokio::test]
    async fn rejects_weak_rsa() {
        let provider = AwsLcKeyProvider::new();
        let err = provider
            .generate_key_pair(KeyAlgorithm::Rsa { bits: 1024 }, None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Unsupported RSA key size"));
    }

    #[tokio::test]
    async fn duplicate_label_rejected() {
        let provider = AwsLcKeyProvider::new();
        provider
            .generate_key_pair(KeyAlgorithm::EcdsaP256, Some("dup"))
            .await
            .unwrap();
        let err = provider
            .generate_key_pair(KeyAlgorithm::EcdsaP256, Some("dup"))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }
}
