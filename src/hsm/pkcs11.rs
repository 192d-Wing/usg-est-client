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

//! PKCS#11 Hardware Security Module integration.
//!
//! This module provides a PKCS#11-based implementation of the [`KeyProvider`] trait,
//! allowing EST client operations to use keys stored in hardware security modules,
//! smart cards, and other PKCS#11-compatible devices.
//!
//! # Key Features
//!
//! - **Hardware security boundary**: Private keys never leave the HSM/token
//! - **Multi-slot support**: Discover and use any available PKCS#11 token
//! - **Persistent keys**: Keys persist across application restarts
//! - **Standards-based**: Uses industry-standard PKCS#11 (Cryptoki) interface
//!
//! # Security Considerations
//!
//! - Private keys are generated and stored within the PKCS#11 token
//! - Keys can be marked as non-extractable for maximum security
//! - PIN/password authentication required for token access
//! - Audit logs may be available depending on HSM capabilities
//!
//! # Example
//!
//! ```no_run
//! use usg_est_client::hsm::{KeyProvider, KeyAlgorithm};
//! # #[cfg(feature = "pkcs11")]
//! use usg_est_client::hsm::pkcs11::Pkcs11KeyProvider;
//!
//! # #[cfg(feature = "pkcs11")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Initialize PKCS#11 provider with SoftHSM library
//! let provider = Pkcs11KeyProvider::new(
//!     "/usr/lib/softhsm/libsofthsm2.so",
//!     None, // Use first available slot
//!     "1234", // PIN
//! )?;
//!
//! // Generate a key pair in the HSM
//! let key_handle = provider
//!     .generate_key_pair(KeyAlgorithm::EcdsaP256, Some("device-key"))
//!     .await?;
//!
//! // Get the public key (safe to export)
//! let public_key = provider.public_key(&key_handle).await?;
//!
//! // Sign data (private key never leaves the HSM)
//! let signature = provider.sign(&key_handle, b"data to sign").await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Supported PKCS#11 Implementations
//!
//! This module has been tested with:
//! - **SoftHSM 2.x**: Software HSM for testing
//! - **YubiHSM 2**: Hardware HSM
//! - **AWS CloudHSM**: Cloud-based HSM
//!
//! Other PKCS#11-compliant implementations should work but may require testing.

use super::{KeyAlgorithm, KeyHandle, KeyMetadata, KeyProvider, ProviderInfo};
use crate::error::{EstError, Result};
use async_trait::async_trait;
use const_oid::db::rfc5912::{
    ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ID_EC_PUBLIC_KEY, SECP_256_R_1, SECP_384_R_1,
    SHA_256_WITH_RSA_ENCRYPTION,
};
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use der::{Decode, Encode, asn1::BitString};
use spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// PKCS#11-based key provider for hardware security modules.
///
/// This implementation uses the PKCS#11 (Cryptoki) standard to interact with
/// HSMs, smart cards, and other cryptographic tokens. Keys are generated and
/// stored within the secure boundary of the hardware device.
///
/// # Thread Safety
///
/// The PKCS#11 session is protected by a mutex and can be used safely from
/// multiple async tasks. However, note that PKCS#11 operations are inherently
/// blocking and may impact async performance.
pub struct Pkcs11KeyProvider {
    /// PKCS#11 context (library interface)
    /// Kept alive for the lifetime of the provider to maintain the library connection.
    #[allow(dead_code)]
    pkcs11: Arc<Pkcs11>,

    /// Active session with the token
    session: Arc<Mutex<Session>>,

    /// Slot being used
    slot: Slot,

    /// Provider metadata
    info: ProviderInfo,
}

// SAFETY: Pkcs11KeyProvider is thread-safe because:
// 1. All access to the Session is protected by a Mutex
// 2. PKCS#11 operations are inherently thread-safe when serialized
// 3. The pkcs11 context (Arc<Pkcs11>) is already Send+Sync
unsafe impl Send for Pkcs11KeyProvider {}
unsafe impl Sync for Pkcs11KeyProvider {}

impl Pkcs11KeyProvider {
    /// Create a new PKCS#11 key provider.
    ///
    /// # Arguments
    ///
    /// * `library_path` - Path to the PKCS#11 library (e.g., "/usr/lib/softhsm/libsofthsm2.so")
    /// * `slot_id` - Optional slot ID to use. If None, uses the first slot with a token.
    /// * `pin` - PIN/password for token authentication
    ///
    /// # Returns
    ///
    /// A configured PKCS#11 provider ready for key operations.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The PKCS#11 library cannot be loaded
    /// - No token is found in the specified slot
    /// - PIN authentication fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// # #[cfg(feature = "pkcs11")]
    /// # use usg_est_client::hsm::pkcs11::Pkcs11KeyProvider;
    /// # #[cfg(feature = "pkcs11")]
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Use SoftHSM for testing
    /// let provider = Pkcs11KeyProvider::new(
    ///     "/usr/lib/softhsm/libsofthsm2.so",
    ///     Some(0), // Specific slot
    ///     "1234",
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new<P: AsRef<Path>>(library_path: P, slot_id: Option<usize>, pin: &str) -> Result<Self> {
        // Initialize PKCS#11 library
        let pkcs11 = Pkcs11::new(library_path.as_ref()).map_err(|e| {
            EstError::hsm(format!(
                "Failed to load PKCS#11 library at {}: {}",
                library_path.as_ref().display(),
                e
            ))
        })?;

        pkcs11
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|e| EstError::hsm(format!("Failed to initialize PKCS#11 library: {}", e)))?;

        // Get library info for provider metadata
        let lib_info = pkcs11
            .get_library_info()
            .map_err(|e| EstError::hsm(format!("Failed to get library info: {}", e)))?;

        // Find the appropriate slot
        let slot = if let Some(id) = slot_id {
            // Use specified slot
            let slots = pkcs11
                .get_slots_with_token()
                .map_err(|e| EstError::hsm(format!("Failed to get slots: {}", e)))?;

            slots
                .into_iter()
                .find(|s| s.id() == id as u64)
                .ok_or_else(|| EstError::hsm(format!("Slot {} not found or has no token", id)))?
        } else {
            // Use first available slot with a token
            let slots = pkcs11
                .get_slots_with_token()
                .map_err(|e| EstError::hsm(format!("Failed to get slots: {}", e)))?;

            slots
                .into_iter()
                .next()
                .ok_or_else(|| EstError::hsm("No PKCS#11 slots with tokens found".to_string()))?
        };

        // Get token info for provider metadata
        let token_info = pkcs11
            .get_token_info(slot)
            .map_err(|e| EstError::hsm(format!("Failed to get token info: {}", e)))?;

        // Open a session
        let session = pkcs11
            .open_rw_session(slot)
            .map_err(|e| EstError::hsm(format!("Failed to open session: {}", e)))?;

        // Login with PIN
        let auth_pin = AuthPin::new(pin.to_string().into_boxed_str());
        session
            .login(UserType::User, Some(&auth_pin))
            .map_err(|e| EstError::hsm(format!("Failed to login to token: {}", e)))?;

        // Build provider info
        let info = ProviderInfo {
            name: format!(
                "{} ({})",
                token_info.label().trim(),
                lib_info.library_description().trim()
            ),
            version: format!(
                "{}.{}",
                lib_info.cryptoki_version().major(),
                lib_info.cryptoki_version().minor()
            ),
            manufacturer: token_info.manufacturer_id().trim().to_string(),
            supports_key_generation: true,
            supports_key_deletion: true,
        };

        Ok(Self {
            pkcs11: Arc::new(pkcs11),
            #[allow(clippy::arc_with_non_send_sync)]
            session: Arc::new(Mutex::new(session)),
            slot,
            info,
        })
    }

    /// Find a key object by its CKA_LABEL attribute.
    fn find_object_by_label(&self, label: &str) -> Result<Option<ObjectHandle>> {
        let session = self.session.lock()
            .map_err(|e| EstError::hsm(format!("PKCS#11 session lock poisoned: {}", e)))?;

        let template = vec![
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Class(ObjectClass::PRIVATE_KEY),
        ];

        session
            .find_objects(&template)
            .map_err(|e| EstError::hsm(format!("Failed to find object: {}", e)))
            .map(|handles| handles.into_iter().next())
    }

    /// Get the public key handle for a private key.
    fn get_public_key_handle(&self, private_handle: ObjectHandle) -> Result<ObjectHandle> {
        let session = self.session.lock()
            .map_err(|e| EstError::hsm(format!("PKCS#11 session lock poisoned: {}", e)))?;

        // Get the CKA_ID from the private key
        let id_attr = session
            .get_attributes(private_handle, &[AttributeType::Id])
            .map_err(|e| EstError::hsm(format!("Failed to get key ID: {}", e)))?;

        let key_id = match &id_attr[0] {
            Attribute::Id(id) => id.clone(),
            _ => return Err(EstError::hsm("Invalid CKA_ID attribute".to_string())),
        };

        // Find the corresponding public key
        let template = vec![
            Attribute::Id(key_id),
            Attribute::Class(ObjectClass::PUBLIC_KEY),
        ];

        let handles = session
            .find_objects(&template)
            .map_err(|e| EstError::hsm(format!("Failed to find public key: {}", e)))?;

        handles
            .into_iter()
            .next()
            .ok_or_else(|| EstError::hsm("Public key not found".to_string()))
    }

    /// Extract EC public key bytes from a PKCS#11 public key object.
    fn extract_ec_public_key(
        &self,
        pub_handle: ObjectHandle,
        curve_oid: ObjectIdentifier,
    ) -> Result<SubjectPublicKeyInfoOwned> {
        let session = self.session.lock()
            .map_err(|e| EstError::hsm(format!("PKCS#11 session lock poisoned: {}", e)))?;

        // Get EC_POINT attribute (contains the public key)
        let attrs = session
            .get_attributes(pub_handle, &[AttributeType::EcPoint])
            .map_err(|e| EstError::hsm(format!("Failed to get EC_POINT: {}", e)))?;

        let ec_point = match &attrs[0] {
            Attribute::EcPoint(point) => point.clone(),
            _ => return Err(EstError::hsm("Invalid EC_POINT attribute".to_string())),
        };

        // Build the AlgorithmIdentifier for EC public key
        let curve_oid_der = curve_oid.to_der()
            .expect("well-known curve OID from RFC 5912 is always valid");
        let alg_params = der::asn1::OctetStringRef::new(&curve_oid_der)
            .expect("DER-encoded OID is valid OctetString")
            .to_der()
            .expect("OctetString DER encoding cannot fail");

        // The algorithm identifier needs the curve OID as parameters
        let algorithm = AlgorithmIdentifierOwned {
            oid: ID_EC_PUBLIC_KEY,
            parameters: Some(der::asn1::AnyRef::from_der(&alg_params)
                .expect("well-formed DER from OctetString")
                .into()),
        };

        // EC_POINT is an OCTET STRING containing the point
        // We need to extract the actual point data
        let point_data = if ec_point.len() > 2 && ec_point[0] == 0x04 {
            // It's already a DER OCTET STRING, extract the contents
            &ec_point[2..]
        } else {
            &ec_point
        };

        // Convert to BitString for SubjectPublicKeyInfo
        let subject_public_key = BitString::from_bytes(point_data)
            .map_err(|e| EstError::hsm(format!("Failed to create bit string: {}", e)))?;

        Ok(SubjectPublicKeyInfoOwned {
            algorithm,
            subject_public_key,
        })
    }

    /// Extract RSA public key from a PKCS#11 public key object.
    fn extract_rsa_public_key(
        &self,
        pub_handle: ObjectHandle,
    ) -> Result<SubjectPublicKeyInfoOwned> {
        let session = self.session.lock()
            .map_err(|e| EstError::hsm(format!("PKCS#11 session lock poisoned: {}", e)))?;

        // Get RSA modulus and public exponent
        let attrs = session
            .get_attributes(
                pub_handle,
                &[AttributeType::Modulus, AttributeType::PublicExponent],
            )
            .map_err(|e| EstError::hsm(format!("Failed to get RSA attributes: {}", e)))?;

        let modulus = match &attrs[0] {
            Attribute::Modulus(m) => m.clone(),
            _ => return Err(EstError::hsm("Invalid modulus attribute".to_string())),
        };

        let public_exponent = match &attrs[1] {
            Attribute::PublicExponent(e) => e.clone(),
            _ => {
                return Err(EstError::hsm(
                    "Invalid public exponent attribute".to_string(),
                ));
            }
        };

        // Build RSA public key structure

        // RSA public key is SEQUENCE { modulus INTEGER, publicExponent INTEGER }
        let mut rsa_pubkey = Vec::new();
        rsa_pubkey.push(0x30); // SEQUENCE tag

        // Encode modulus as INTEGER
        let mut mod_int = vec![0x02]; // INTEGER tag
        let mut mod_len = modulus.len();
        // Add zero byte if high bit is set (to make it positive)
        let mod_bytes = if modulus[0] & 0x80 != 0 {
            mod_len += 1;
            let mut m = vec![0x00];
            m.extend_from_slice(&modulus);
            m
        } else {
            modulus.clone()
        };

        // Encode length
        if mod_len < 128 {
            mod_int.push(mod_len as u8);
        } else {
            let len_bytes = mod_len.to_be_bytes();
            let num_len_bytes = len_bytes.iter().position(|&b| b != 0).unwrap_or(7);
            mod_int.push(0x80 | (8 - num_len_bytes) as u8);
            mod_int.extend_from_slice(&len_bytes[num_len_bytes..]);
        }
        mod_int.extend_from_slice(&mod_bytes);

        // Encode public exponent as INTEGER
        let mut exp_int = vec![0x02]; // INTEGER tag
        let mut exp_len = public_exponent.len();
        let exp_bytes = if public_exponent[0] & 0x80 != 0 {
            exp_len += 1;
            let mut e = vec![0x00];
            e.extend_from_slice(&public_exponent);
            e
        } else {
            public_exponent.clone()
        };

        if exp_len < 128 {
            exp_int.push(exp_len as u8);
        } else {
            let len_bytes = exp_len.to_be_bytes();
            let num_len_bytes = len_bytes.iter().position(|&b| b != 0).unwrap_or(7);
            exp_int.push(0x80 | (8 - num_len_bytes) as u8);
            exp_int.extend_from_slice(&len_bytes[num_len_bytes..]);
        }
        exp_int.extend_from_slice(&exp_bytes);

        // Calculate total sequence length
        let seq_len = mod_int.len() + exp_int.len();
        if seq_len < 128 {
            rsa_pubkey.push(seq_len as u8);
        } else {
            let len_bytes = seq_len.to_be_bytes();
            let num_len_bytes = len_bytes.iter().position(|&b| b != 0).unwrap_or(7);
            rsa_pubkey.push(0x80 | (8 - num_len_bytes) as u8);
            rsa_pubkey.extend_from_slice(&len_bytes[num_len_bytes..]);
        }
        rsa_pubkey.extend_from_slice(&mod_int);
        rsa_pubkey.extend_from_slice(&exp_int);

        // Build the AlgorithmIdentifier for RSA (NULL parameters)
        let algorithm = AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::RSA_ENCRYPTION,
            parameters: Some(der::asn1::AnyRef::from_der(&[0x05, 0x00])
                .expect("DER NULL tag (0x05 0x00) is always valid")
                .into()),
        };

        let subject_public_key = BitString::from_bytes(&rsa_pubkey)
            .map_err(|e| EstError::hsm(format!("Failed to create bit string: {}", e)))?;

        Ok(SubjectPublicKeyInfoOwned {
            algorithm,
            subject_public_key,
        })
    }

    /// Convert a KeyHandle back to a PKCS#11 ObjectHandle.
    fn handle_to_object(&self, handle: &KeyHandle) -> Result<ObjectHandle> {
        // The KeyHandle.id contains the CKA_ID attribute value
        let session = self.session.lock()
            .map_err(|e| EstError::hsm(format!("PKCS#11 session lock poisoned: {}", e)))?;

        let template = vec![
            Attribute::Id(handle.id.clone()),
            Attribute::Class(ObjectClass::PRIVATE_KEY),
        ];

        let handles = session
            .find_objects(&template)
            .map_err(|e| EstError::hsm(format!("Failed to find key object: {}", e)))?;

        handles
            .into_iter()
            .next()
            .ok_or_else(|| EstError::hsm("Key object not found in token".to_string()))
    }

    /// Get key metadata from a PKCS#11 object.
    fn get_key_metadata(&self, handle: ObjectHandle) -> Result<KeyMetadata> {
        let session = self.session.lock()
            .map_err(|e| EstError::hsm(format!("PKCS#11 session lock poisoned: {}", e)))?;

        let attrs = session
            .get_attributes(
                handle,
                &[
                    AttributeType::Label,
                    AttributeType::Sign,
                    AttributeType::Extractable,
                    AttributeType::Id,
                ],
            )
            .map_err(|e| EstError::hsm(format!("Failed to get key attributes: {}", e)))?;

        let label = match &attrs[0] {
            Attribute::Label(l) => String::from_utf8_lossy(l).to_string(),
            _ => String::new(),
        };

        let can_sign = match &attrs[1] {
            Attribute::Sign(s) => *s,
            _ => false,
        };

        let extractable = match &attrs[2] {
            Attribute::Extractable(e) => *e,
            _ => false,
        };

        let key_id = match &attrs[3] {
            Attribute::Id(id) => hex::encode(id),
            _ => String::new(),
        };

        let mut attributes = HashMap::new();
        attributes.insert("slot_id".to_string(), self.slot.id().to_string());
        attributes.insert("key_id".to_string(), key_id);

        Ok(KeyMetadata {
            label: if label.is_empty() { None } else { Some(label) },
            can_sign,
            extractable,
            attributes,
        })
    }
}

#[async_trait]
impl KeyProvider for Pkcs11KeyProvider {
    async fn generate_key_pair(
        &self,
        algorithm: KeyAlgorithm,
        label: Option<&str>,
    ) -> Result<KeyHandle> {
        // Check for duplicate labels
        if let Some(label_str) = label
            && self.find_object_by_label(label_str)?.is_some()
        {
            return Err(EstError::hsm(format!(
                "Key with label '{}' already exists",
                label_str
            )));
        }

        let session = self.session.lock()
            .map_err(|e| EstError::hsm(format!("PKCS#11 session lock poisoned: {}", e)))?;

        // Generate a unique CKA_ID for this key pair
        let key_id = uuid::Uuid::new_v4().as_bytes().to_vec();

        let label_bytes = label.unwrap_or("").as_bytes().to_vec();

        // Build key generation template based on algorithm
        let (mechanism, pub_template, priv_template) = match algorithm {
            KeyAlgorithm::EcdsaP256 => {
                let ec_params = SECP_256_R_1.to_der()
                    .expect("SECP256R1 OID from RFC 5912 is always valid");
                (
                    Mechanism::EccKeyPairGen,
                    vec![
                        Attribute::EcParams(ec_params),
                        Attribute::Label(label_bytes.clone()),
                        Attribute::Id(key_id.clone()),
                        Attribute::Token(true),
                        Attribute::Verify(true),
                    ],
                    vec![
                        Attribute::Label(label_bytes),
                        Attribute::Id(key_id.clone()),
                        Attribute::Token(true),
                        Attribute::Private(true),
                        Attribute::Sensitive(true),
                        Attribute::Sign(true),
                        Attribute::Extractable(false),
                    ],
                )
            }
            KeyAlgorithm::EcdsaP384 => {
                let ec_params = SECP_384_R_1.to_der()
                    .expect("SECP384R1 OID from RFC 5912 is always valid");
                (
                    Mechanism::EccKeyPairGen,
                    vec![
                        Attribute::EcParams(ec_params),
                        Attribute::Label(label_bytes.clone()),
                        Attribute::Id(key_id.clone()),
                        Attribute::Token(true),
                        Attribute::Verify(true),
                    ],
                    vec![
                        Attribute::Label(label_bytes),
                        Attribute::Id(key_id.clone()),
                        Attribute::Token(true),
                        Attribute::Private(true),
                        Attribute::Sensitive(true),
                        Attribute::Sign(true),
                        Attribute::Extractable(false),
                    ],
                )
            }
            KeyAlgorithm::Rsa { bits } => {
                let modulus_bits = cryptoki::types::Ulong::from(bits as u64);

                (
                    Mechanism::RsaPkcsKeyPairGen,
                    vec![
                        Attribute::ModulusBits(modulus_bits),
                        Attribute::PublicExponent(vec![0x01, 0x00, 0x01]), // 65537
                        Attribute::Label(label_bytes.clone()),
                        Attribute::Id(key_id.clone()),
                        Attribute::Token(true),
                        Attribute::Verify(true),
                    ],
                    vec![
                        Attribute::Label(label_bytes),
                        Attribute::Id(key_id.clone()),
                        Attribute::Token(true),
                        Attribute::Private(true),
                        Attribute::Sensitive(true),
                        Attribute::Sign(true),
                        Attribute::Extractable(false),
                    ],
                )
            }
        };

        // Generate the key pair
        let (_pub_handle, priv_handle) = session
            .generate_key_pair(&mechanism, &pub_template, &priv_template)
            .map_err(|e| EstError::hsm(format!("Failed to generate key pair: {}", e)))?;

        // Get metadata
        let metadata = self.get_key_metadata(priv_handle)?;

        Ok(KeyHandle::new(key_id, algorithm, metadata))
    }

    async fn public_key(&self, handle: &KeyHandle) -> Result<SubjectPublicKeyInfoOwned> {
        let priv_handle = self.handle_to_object(handle)?;
        let pub_handle = self.get_public_key_handle(priv_handle)?;

        match handle.algorithm {
            KeyAlgorithm::EcdsaP256 => self.extract_ec_public_key(pub_handle, SECP_256_R_1),
            KeyAlgorithm::EcdsaP384 => self.extract_ec_public_key(pub_handle, SECP_384_R_1),
            KeyAlgorithm::Rsa { .. } => self.extract_rsa_public_key(pub_handle),
        }
    }

    async fn sign(&self, handle: &KeyHandle, data: &[u8]) -> Result<Vec<u8>> {
        let priv_handle = self.handle_to_object(handle)?;
        let session = self.session.lock()
            .map_err(|e| EstError::hsm(format!("PKCS#11 session lock poisoned: {}", e)))?;

        // Select mechanism based on algorithm
        let mechanism = match handle.algorithm {
            KeyAlgorithm::EcdsaP256 => Mechanism::Ecdsa,
            KeyAlgorithm::EcdsaP384 => Mechanism::Ecdsa,
            KeyAlgorithm::Rsa { .. } => Mechanism::RsaPkcs,
        };

        // For ECDSA, data should be a SHA-256 or SHA-384 hash
        // For RSA, data should be a DigestInfo structure (or just hash for PKCS#1)

        // Sign the data
        let signature = session
            .sign(&mechanism, priv_handle, data)
            .map_err(|e| EstError::hsm(format!("Failed to sign data: {}", e)))?;

        Ok(signature)
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
        let session = self.session.lock()
            .map_err(|e| EstError::hsm(format!("PKCS#11 session lock poisoned: {}", e)))?;

        let template = vec![Attribute::Class(ObjectClass::PRIVATE_KEY)];

        let handles = session
            .find_objects(&template)
            .map_err(|e| EstError::hsm(format!("Failed to list keys: {}", e)))?;

        let mut key_handles = Vec::new();

        for handle in handles {
            // Get key attributes to determine algorithm
            let attrs = session
                .get_attributes(
                    handle,
                    &[
                        AttributeType::KeyType,
                        AttributeType::Id,
                        AttributeType::EcParams,
                    ],
                )
                .map_err(|e| EstError::hsm(format!("Failed to get key attributes: {}", e)))?;

            let key_type = match &attrs[0] {
                Attribute::KeyType(kt) => kt,
                _ => continue,
            };

            let key_id = match &attrs[1] {
                Attribute::Id(id) => id.clone(),
                _ => continue,
            };

            let algorithm = match *key_type {
                cryptoki::object::KeyType::EC => {
                    // Determine curve from EC_PARAMS
                    if let Attribute::EcParams(params) = &attrs[2] {
                        // Parse OID from params
                        if let Ok(oid) = ObjectIdentifier::from_bytes(params) {
                            if oid == SECP_256_R_1 {
                                KeyAlgorithm::EcdsaP256
                            } else if oid == SECP_384_R_1 {
                                KeyAlgorithm::EcdsaP384
                            } else {
                                continue; // Unsupported curve
                            }
                        } else {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }
                cryptoki::object::KeyType::RSA => {
                    // Default to 2048 bits (we could query CKA_MODULUS_BITS if needed)
                    KeyAlgorithm::Rsa { bits: 2048 }
                }
                _ => continue, // Unsupported key type
            };

            let metadata = self.get_key_metadata(handle)?;
            key_handles.push(KeyHandle::new(key_id, algorithm, metadata));
        }

        Ok(key_handles)
    }

    async fn find_key(&self, label: &str) -> Result<Option<KeyHandle>> {
        if let Some(handle) = self.find_object_by_label(label)? {
            let session = self.session.lock()
            .map_err(|e| EstError::hsm(format!("PKCS#11 session lock poisoned: {}", e)))?;

            // Get key attributes
            let attrs = session
                .get_attributes(
                    handle,
                    &[
                        AttributeType::KeyType,
                        AttributeType::Id,
                        AttributeType::EcParams,
                    ],
                )
                .map_err(|e| EstError::hsm(format!("Failed to get key attributes: {}", e)))?;

            let key_type = match &attrs[0] {
                Attribute::KeyType(kt) => kt,
                _ => return Ok(None),
            };

            let key_id = match &attrs[1] {
                Attribute::Id(id) => id.clone(),
                _ => return Ok(None),
            };

            let algorithm = match *key_type {
                cryptoki::object::KeyType::EC => {
                    if let Attribute::EcParams(params) = &attrs[2] {
                        if let Ok(oid) = ObjectIdentifier::from_bytes(params) {
                            if oid == SECP_256_R_1 {
                                KeyAlgorithm::EcdsaP256
                            } else if oid == SECP_384_R_1 {
                                KeyAlgorithm::EcdsaP384
                            } else {
                                return Ok(None);
                            }
                        } else {
                            return Ok(None);
                        }
                    } else {
                        return Ok(None);
                    }
                }
                cryptoki::object::KeyType::RSA => KeyAlgorithm::Rsa { bits: 2048 },
                _ => return Ok(None),
            };

            let metadata = self.get_key_metadata(handle)?;
            Ok(Some(KeyHandle::new(key_id, algorithm, metadata)))
        } else {
            Ok(None)
        }
    }

    async fn delete_key(&self, handle: &KeyHandle) -> Result<()> {
        let priv_handle = self.handle_to_object(handle)?;
        let pub_handle = self.get_public_key_handle(priv_handle)?;

        let session = self.session.lock()
            .map_err(|e| EstError::hsm(format!("PKCS#11 session lock poisoned: {}", e)))?;

        // Delete both private and public keys
        session
            .destroy_object(priv_handle)
            .map_err(|e| EstError::hsm(format!("Failed to delete private key: {}", e)))?;

        session
            .destroy_object(pub_handle)
            .map_err(|e| EstError::hsm(format!("Failed to delete public key: {}", e)))?;

        Ok(())
    }

    fn provider_info(&self) -> ProviderInfo {
        self.info.clone()
    }
}

impl Drop for Pkcs11KeyProvider {
    fn drop(&mut self) {
        // Logout and close session
        if let Ok(session) = self.session.lock() {
            let _ = session.logout();
        }
    }
}
