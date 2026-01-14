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

//! CMS EnvelopedData support for encrypted private key decryption.
//!
//! This module provides support for decrypting private keys that are
//! encrypted using CMS EnvelopedData format, as returned by EST
//! server-side key generation.
//!
//! # Example
//!
//! ```no_run
//! use usg_est_client::enveloped::{decrypt_enveloped_data, DecryptionKey};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Your encrypted key data from server keygen
//! let encrypted_data = vec![]; // EnvelopedData bytes
//!
//! // Your decryption key (could be from certificate or transport key)
//! let decryption_key = todo!(); // DecryptionKey
//!
//! // Decrypt the private key
//! let private_key = decrypt_enveloped_data(&encrypted_data, &decryption_key)?;
//! # Ok(())
//! # }
//! ```

use crate::error::{EstError, Result};
use tracing::debug;

// CMS OIDs
const OID_ENVELOPED_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x03]; // 1.2.840.113549.1.7.3
#[allow(dead_code)]
const OID_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01]; // 1.2.840.113549.1.7.1

// Algorithm OIDs
const OID_AES_128_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02]; // 2.16.840.1.101.3.4.1.2
const OID_AES_192_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x16]; // 2.16.840.1.101.3.4.1.22
const OID_AES_256_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A]; // 2.16.840.1.101.3.4.1.42
const OID_3DES_CBC: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x07]; // 1.2.840.113549.3.7

/// Supported encryption algorithms for EnvelopedData.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    /// AES-128-CBC
    Aes128Cbc,
    /// AES-192-CBC
    Aes192Cbc,
    /// AES-256-CBC
    Aes256Cbc,
    /// Triple DES (3DES) CBC
    TripleDesCbc,
}

impl EncryptionAlgorithm {
    /// Get the key size in bytes for this algorithm.
    pub fn key_size(&self) -> usize {
        match self {
            Self::Aes128Cbc => 16,
            Self::Aes192Cbc => 24,
            Self::Aes256Cbc => 32,
            Self::TripleDesCbc => 24,
        }
    }

    /// Get the block size in bytes for this algorithm.
    pub fn block_size(&self) -> usize {
        match self {
            Self::Aes128Cbc | Self::Aes192Cbc | Self::Aes256Cbc => 16,
            Self::TripleDesCbc => 8,
        }
    }

    /// Get the algorithm name as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Aes128Cbc => "AES-128-CBC",
            Self::Aes192Cbc => "AES-192-CBC",
            Self::Aes256Cbc => "AES-256-CBC",
            Self::TripleDesCbc => "3DES-CBC",
        }
    }

    /// Parse algorithm from OID bytes.
    fn from_oid(oid: &[u8]) -> Option<Self> {
        if oid == OID_AES_128_CBC {
            Some(Self::Aes128Cbc)
        } else if oid == OID_AES_192_CBC {
            Some(Self::Aes192Cbc)
        } else if oid == OID_AES_256_CBC {
            Some(Self::Aes256Cbc)
        } else if oid == OID_3DES_CBC {
            Some(Self::TripleDesCbc)
        } else {
            None
        }
    }
}

/// Key material for decrypting EnvelopedData.
#[derive(Clone)]
pub struct DecryptionKey {
    /// The raw key bytes.
    key_bytes: Vec<u8>,

    /// Algorithm to use for decryption.
    algorithm: EncryptionAlgorithm,
}

impl DecryptionKey {
    /// Create a new decryption key.
    ///
    /// # Arguments
    ///
    /// * `key_bytes` - The raw key material
    /// * `algorithm` - The encryption algorithm
    pub fn new(key_bytes: Vec<u8>, algorithm: EncryptionAlgorithm) -> Result<Self> {
        // Validate key size
        if key_bytes.len() != algorithm.key_size() {
            return Err(EstError::operational(format!(
                "Invalid key size for {}: expected {}, got {}",
                algorithm.as_str(),
                algorithm.key_size(),
                key_bytes.len()
            )));
        }

        Ok(Self {
            key_bytes,
            algorithm,
        })
    }

    /// Get the key bytes.
    pub fn key_bytes(&self) -> &[u8] {
        &self.key_bytes
    }

    /// Get the encryption algorithm.
    pub fn algorithm(&self) -> EncryptionAlgorithm {
        self.algorithm
    }
}

/// Recipient information from EnvelopedData.
#[derive(Debug, Clone)]
pub struct RecipientInfo {
    /// Recipient identifier (serial number, subject key identifier, etc.).
    pub identifier: Vec<u8>,

    /// Encrypted content encryption key.
    pub encrypted_key: Vec<u8>,

    /// Key encryption algorithm used.
    pub key_encryption_algorithm: String,
}

/// Parsed EnvelopedData structure.
#[derive(Debug, Clone)]
pub struct EnvelopedData {
    /// Version of the EnvelopedData structure.
    pub version: u8,

    /// Recipient information (one or more recipients).
    pub recipients: Vec<RecipientInfo>,

    /// Content encryption algorithm.
    pub content_encryption_algorithm: EncryptionAlgorithm,

    /// Encrypted content (the actual encrypted private key).
    pub encrypted_content: Vec<u8>,

    /// Initialization vector (if applicable).
    pub iv: Option<Vec<u8>>,
}

/// Parse CMS ContentInfo structure to extract EnvelopedData.
///
/// # Arguments
///
/// * `data` - The DER-encoded ContentInfo
///
/// # Returns
///
/// A parsed `EnvelopedData` structure.
pub fn parse_enveloped_data(data: &[u8]) -> Result<EnvelopedData> {
    debug!("Parsing CMS EnvelopedData ({} bytes)", data.len());

    // Parse the outer ContentInfo structure using raw TLV parsing
    // ContentInfo ::= SEQUENCE {
    //   contentType ContentType,
    //   content [0] EXPLICIT ANY DEFINED BY contentType
    // }

    // Skip outer SEQUENCE
    let (_, content_info_content) = skip_tlv_header(data)?;

    // First element should be OID (tag 0x06)
    if content_info_content.is_empty() || content_info_content[0] != 0x06 {
        return Err(EstError::protocol("Expected OID in ContentInfo"));
    }

    let (oid_data, rest) = read_tlv(content_info_content)?;
    let (_, oid_bytes) = skip_tlv_header(oid_data)?;

    // Verify this is EnvelopedData
    if oid_bytes != OID_ENVELOPED_DATA {
        return Err(EstError::protocol(format!(
            "Expected EnvelopedData OID, got {:02X?}",
            oid_bytes
        )));
    }

    debug!("Found EnvelopedData content type");

    // The actual EnvelopedData is in [0] EXPLICIT context tag (tag 0xA0)
    if rest.is_empty() || (rest[0] & 0xC0) != 0x80 {
        return Err(EstError::protocol("ContentInfo missing content field"));
    }

    let (_, enveloped_content) = skip_tlv_header(rest)?;

    // Parse EnvelopedData structure
    parse_enveloped_data_inner(enveloped_content)
}

/// Parse the inner EnvelopedData structure.
fn parse_enveloped_data_inner(data: &[u8]) -> Result<EnvelopedData> {
    // EnvelopedData ::= SEQUENCE {
    //   version CMSVersion,
    //   originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
    //   recipientInfos RecipientInfos,
    //   encryptedContentInfo EncryptedContentInfo,
    //   unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL
    // }

    // Verify it starts with SEQUENCE
    if data.is_empty() || data[0] != 0x30 {
        return Err(EstError::protocol("Expected SEQUENCE for EnvelopedData"));
    }

    // Find version (first INTEGER)
    let version = extract_version(data)?;
    debug!("EnvelopedData version: {}", version);

    // Extract recipients and encrypted content info
    let (recipients, algorithm, encrypted_content, iv) = extract_enveloped_components(data)?;

    Ok(EnvelopedData {
        version,
        recipients,
        content_encryption_algorithm: algorithm,
        encrypted_content,
        iv,
    })
}

/// Extract version from EnvelopedData.
fn extract_version(data: &[u8]) -> Result<u8> {
    // Skip outer SEQUENCE tag and length
    if data.len() < 4 || data[0] != 0x30 {
        return Err(EstError::protocol("Invalid EnvelopedData structure"));
    }

    let (_, rest) = skip_tlv_header(data)?;

    // First element should be INTEGER (version)
    // Fixed: Check rest.len() >= 2 before accessing rest[1]
    if rest.len() >= 2 && rest[0] == 0x02 {
        let len = rest[1] as usize;
        if rest.len() >= 2 + len && len > 0 {
            return Ok(rest[2]);
        }
    }

    Err(EstError::protocol("Could not extract version"))
}

/// Extracted components from an EnvelopedData structure.
type EnvelopedComponents = (
    Vec<RecipientInfo>,
    EncryptionAlgorithm,
    Vec<u8>,
    Option<Vec<u8>>,
);

/// Extract components from EnvelopedData.
fn extract_enveloped_components(data: &[u8]) -> Result<EnvelopedComponents> {
    // This is a simplified parser for common EnvelopedData structures
    // A full implementation would use the cms crate's types

    let mut algorithm = EncryptionAlgorithm::Aes256Cbc; // Default
    let mut encrypted_content = Vec::new();
    let mut iv = None;

    // Skip outer SEQUENCE
    let (_, rest) = skip_tlv_header(data)?;

    // Skip version INTEGER
    let (_, rest) = skip_tlv(rest)?;

    // Look for RecipientInfos SET
    let (recipients, rest) = if !rest.is_empty() && rest[0] == 0x31 {
        // SET tag
        let (recipient_data, remaining) = read_tlv(rest)?;
        // Parse recipients from the SET
        let parsed_recipients = parse_recipient_infos(recipient_data)?;
        (parsed_recipients, remaining)
    } else {
        (Vec::new(), rest)
    };

    // EncryptedContentInfo SEQUENCE
    if !rest.is_empty() && rest[0] == 0x30 {
        let (enc_content_info, _) = read_tlv(rest)?;
        let (alg, content, extracted_iv) = parse_encrypted_content_info(enc_content_info)?;
        algorithm = alg;
        encrypted_content = content;
        iv = extracted_iv;
    }

    Ok((recipients, algorithm, encrypted_content, iv))
}

/// Parse RecipientInfos SET.
fn parse_recipient_infos(data: &[u8]) -> Result<Vec<RecipientInfo>> {
    let mut recipients = Vec::new();

    // Skip SET header
    let (_, content) = skip_tlv_header(data)?;
    let mut pos = 0;

    while pos < content.len() {
        // Each RecipientInfo is a SEQUENCE or context-tagged choice
        if content[pos] == 0x30 {
            // KeyTransRecipientInfo SEQUENCE
            let (ri_data, consumed) = read_tlv_at(&content[pos..])?;
            if let Ok(ri) = parse_key_trans_recipient_info(ri_data) {
                recipients.push(ri);
            }
            pos += consumed;
        } else {
            // Skip unknown recipient types
            let (_, consumed) = read_tlv_at(&content[pos..])?;
            pos += consumed;
        }
    }

    Ok(recipients)
}

/// Parse KeyTransRecipientInfo.
fn parse_key_trans_recipient_info(data: &[u8]) -> Result<RecipientInfo> {
    // KeyTransRecipientInfo ::= SEQUENCE {
    //   version CMSVersion,
    //   rid RecipientIdentifier,
    //   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
    //   encryptedKey EncryptedKey
    // }

    let (_, content) = skip_tlv_header(data)?;

    // Skip version
    let (_, rest) = skip_tlv(content)?;

    // RecipientIdentifier (IssuerAndSerialNumber or SubjectKeyIdentifier)
    let (rid_data, rest) = read_tlv(rest)?;
    let identifier = rid_data.to_vec();

    // KeyEncryptionAlgorithm
    let (kea_data, rest) = read_tlv(rest)?;
    let key_encryption_algorithm = extract_algorithm_name(kea_data);

    // EncryptedKey OCTET STRING
    let (ek_data, _) = read_tlv(rest)?;
    let (_, encrypted_key_content) = skip_tlv_header(ek_data)?;
    let encrypted_key = encrypted_key_content.to_vec();

    Ok(RecipientInfo {
        identifier,
        encrypted_key,
        key_encryption_algorithm,
    })
}

/// Parse EncryptedContentInfo.
fn parse_encrypted_content_info(
    data: &[u8],
) -> Result<(EncryptionAlgorithm, Vec<u8>, Option<Vec<u8>>)> {
    // EncryptedContentInfo ::= SEQUENCE {
    //   contentType ContentType,
    //   contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
    //   encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL
    // }

    let (_, content) = skip_tlv_header(data)?;

    // Skip contentType OID
    let (_, rest) = skip_tlv(content)?;

    // ContentEncryptionAlgorithm SEQUENCE
    let (alg_data, rest) = read_tlv(rest)?;
    let (algorithm, iv) = parse_content_encryption_algorithm(alg_data)?;

    // EncryptedContent [0] IMPLICIT OCTET STRING
    let encrypted_content = if !rest.is_empty() && (rest[0] & 0xC0) == 0x80 {
        // Context tag [0]
        let (_, content_data) = skip_tlv_header(rest)?;
        content_data.to_vec()
    } else {
        Vec::new()
    };

    Ok((algorithm, encrypted_content, iv))
}

/// Parse ContentEncryptionAlgorithm and extract IV.
fn parse_content_encryption_algorithm(
    data: &[u8],
) -> Result<(EncryptionAlgorithm, Option<Vec<u8>>)> {
    let (_, content) = skip_tlv_header(data)?;

    // OID
    let (oid_data, rest) = read_tlv(content)?;
    let (_, oid_bytes) = skip_tlv_header(oid_data)?;

    let algorithm =
        EncryptionAlgorithm::from_oid(oid_bytes).unwrap_or(EncryptionAlgorithm::Aes256Cbc);

    // IV is in parameters (OCTET STRING)
    let iv = if !rest.is_empty() && rest[0] == 0x04 {
        let (iv_data, _) = read_tlv(rest)?;
        let (_, iv_bytes) = skip_tlv_header(iv_data)?;
        Some(iv_bytes.to_vec())
    } else {
        None
    };

    Ok((algorithm, iv))
}

/// Extract algorithm name from AlgorithmIdentifier.
fn extract_algorithm_name(data: &[u8]) -> String {
    // Simplified: just return a placeholder
    let (_, content) = match skip_tlv_header(data) {
        Ok(x) => x,
        Err(_) => return "Unknown".to_string(),
    };

    if content.is_empty() {
        return "Unknown".to_string();
    }

    // Check for common RSA key encryption OID
    // Fixed: Need length >= 11 to safely access content[2..11]
    if content.len() >= 11
        && content[2..11] == [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
    {
        return "RSA".to_string();
    }

    "Unknown".to_string()
}

/// Skip TLV header and return remaining content.
fn skip_tlv_header(data: &[u8]) -> Result<(usize, &[u8])> {
    if data.is_empty() {
        return Err(EstError::protocol("Empty TLV"));
    }

    let mut pos = 1; // Skip tag

    if data.len() < 2 {
        return Err(EstError::protocol("TLV too short"));
    }

    let length = if data[pos] & 0x80 == 0 {
        // Short form
        let len = data[pos] as usize;
        pos += 1;
        len
    } else {
        // Long form
        let num_octets = (data[pos] & 0x7F) as usize;
        pos += 1;

        if data.len() < pos + num_octets {
            return Err(EstError::protocol("TLV length octets truncated"));
        }

        let mut len = 0usize;
        for &b in &data[pos..pos + num_octets] {
            len = (len << 8) | (b as usize);
        }
        pos += num_octets;
        len
    };

    if data.len() < pos + length {
        return Err(EstError::protocol("TLV content truncated"));
    }

    Ok((pos, &data[pos..pos + length]))
}

/// Skip an entire TLV and return remaining data.
fn skip_tlv(data: &[u8]) -> Result<(&[u8], &[u8])> {
    let (header_len, content) = skip_tlv_header(data)?;
    let total_len = header_len + content.len();
    Ok((&data[..total_len], &data[total_len..]))
}

/// Read TLV and return its content and remaining data.
fn read_tlv(data: &[u8]) -> Result<(&[u8], &[u8])> {
    let (_, _) = skip_tlv_header(data)?;
    skip_tlv(data)
}

/// Read TLV at position and return content plus bytes consumed.
fn read_tlv_at(data: &[u8]) -> Result<(&[u8], usize)> {
    let (header_len, content) = skip_tlv_header(data)?;
    let total_len = header_len + content.len();
    Ok((&data[..total_len], total_len))
}

/// Decrypt CMS EnvelopedData to recover the private key.
///
/// # Arguments
///
/// * `enveloped_data` - The DER-encoded EnvelopedData
/// * `decryption_key` - The key to use for decryption
///
/// # Returns
///
/// The decrypted private key bytes (typically PKCS#8 DER format).
pub fn decrypt_enveloped_data(
    enveloped_data: &[u8],
    decryption_key: &DecryptionKey,
) -> Result<Vec<u8>> {
    debug!("Decrypting EnvelopedData");

    // Step 1: Parse the EnvelopedData structure
    let envelope = parse_enveloped_data(enveloped_data)?;

    debug!(
        "EnvelopedData version: {}, recipients: {}, algorithm: {:?}",
        envelope.version,
        envelope.recipients.len(),
        envelope.content_encryption_algorithm
    );

    // Step 2: Verify algorithm matches
    if envelope.content_encryption_algorithm != decryption_key.algorithm() {
        return Err(EstError::operational(format!(
            "Algorithm mismatch: envelope uses {:?}, key is for {:?}",
            envelope.content_encryption_algorithm,
            decryption_key.algorithm()
        )));
    }

    // Step 3: Get IV
    let iv = envelope
        .iv
        .as_ref()
        .ok_or_else(|| EstError::operational("EnvelopedData missing IV"))?;

    // Step 4: Decrypt the content
    let decrypted = decrypt_content(
        &envelope.encrypted_content,
        decryption_key.key_bytes(),
        iv,
        envelope.content_encryption_algorithm,
    )?;

    debug!(
        "Successfully decrypted EnvelopedData ({} bytes)",
        decrypted.len()
    );

    Ok(decrypted)
}

/// Decrypt content using symmetric encryption.
#[cfg(feature = "enveloped")]
fn decrypt_content(
    encrypted: &[u8],
    key: &[u8],
    iv: &[u8],
    algorithm: EncryptionAlgorithm,
) -> Result<Vec<u8>> {
    use cbc::cipher::{BlockDecryptMut, KeyIvInit};

    // Verify IV size
    let expected_iv_size = algorithm.block_size();
    if iv.len() != expected_iv_size {
        return Err(EstError::operational(format!(
            "Invalid IV size: expected {}, got {}",
            expected_iv_size,
            iv.len()
        )));
    }

    let decrypted = match algorithm {
        EncryptionAlgorithm::Aes128Cbc => {
            type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
            let cipher = Aes128CbcDec::new_from_slices(key, iv)
                .map_err(|e| EstError::operational(format!("Failed to create cipher: {}", e)))?;
            let mut buffer = encrypted.to_vec();
            cipher
                .decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buffer)
                .map_err(|e| EstError::operational(format!("Decryption failed: {}", e)))?
                .to_vec()
        }
        EncryptionAlgorithm::Aes192Cbc => {
            type Aes192CbcDec = cbc::Decryptor<aes::Aes192>;
            let cipher = Aes192CbcDec::new_from_slices(key, iv)
                .map_err(|e| EstError::operational(format!("Failed to create cipher: {}", e)))?;
            let mut buffer = encrypted.to_vec();
            cipher
                .decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buffer)
                .map_err(|e| EstError::operational(format!("Decryption failed: {}", e)))?
                .to_vec()
        }
        EncryptionAlgorithm::Aes256Cbc => {
            type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
            let cipher = Aes256CbcDec::new_from_slices(key, iv)
                .map_err(|e| EstError::operational(format!("Failed to create cipher: {}", e)))?;
            let mut buffer = encrypted.to_vec();
            cipher
                .decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buffer)
                .map_err(|e| EstError::operational(format!("Decryption failed: {}", e)))?
                .to_vec()
        }
        EncryptionAlgorithm::TripleDesCbc => {
            type TdesEde3CbcDec = cbc::Decryptor<des::TdesEde3>;
            let cipher = TdesEde3CbcDec::new_from_slices(key, iv)
                .map_err(|e| EstError::operational(format!("Failed to create cipher: {}", e)))?;
            let mut buffer = encrypted.to_vec();
            cipher
                .decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buffer)
                .map_err(|e| EstError::operational(format!("Decryption failed: {}", e)))?
                .to_vec()
        }
    };

    Ok(decrypted)
}

#[cfg(not(feature = "enveloped"))]
fn decrypt_content(
    _encrypted: &[u8],
    _key: &[u8],
    _iv: &[u8],
    _algorithm: EncryptionAlgorithm,
) -> Result<Vec<u8>> {
    Err(EstError::not_supported(
        "EnvelopedData decryption requires the 'enveloped' feature",
    ))
}

/// Check if private key data is encrypted (EnvelopedData).
///
/// This function performs a heuristic check to determine if
/// the given data appears to be CMS EnvelopedData.
pub fn is_encrypted_key(data: &[u8]) -> bool {
    if data.len() < 15 {
        return false;
    }

    // Check for SEQUENCE tag at start
    if data[0] != 0x30 {
        return false;
    }

    // Try to find EnvelopedData OID
    // Look for the OID 1.2.840.113549.1.7.3 in the data
    for i in 0..data.len().saturating_sub(OID_ENVELOPED_DATA.len()) {
        if &data[i..i + OID_ENVELOPED_DATA.len()] == OID_ENVELOPED_DATA {
            return true;
        }
    }

    false
}

/// Extract encryption algorithm from AlgorithmIdentifier DER.
pub fn extract_encryption_algorithm(algorithm_der: &[u8]) -> Result<EncryptionAlgorithm> {
    let (_, content) = skip_tlv_header(algorithm_der)?;

    // First element is OID
    if content.is_empty() || content[0] != 0x06 {
        return Err(EstError::protocol("Expected OID in AlgorithmIdentifier"));
    }

    let (_, oid_bytes) = skip_tlv_header(content)?;

    EncryptionAlgorithm::from_oid(oid_bytes)
        .ok_or_else(|| EstError::protocol("Unknown encryption algorithm OID"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_algorithm_key_sizes() {
        assert_eq!(EncryptionAlgorithm::Aes128Cbc.key_size(), 16);
        assert_eq!(EncryptionAlgorithm::Aes192Cbc.key_size(), 24);
        assert_eq!(EncryptionAlgorithm::Aes256Cbc.key_size(), 32);
        assert_eq!(EncryptionAlgorithm::TripleDesCbc.key_size(), 24);
    }

    #[test]
    fn test_encryption_algorithm_block_sizes() {
        assert_eq!(EncryptionAlgorithm::Aes128Cbc.block_size(), 16);
        assert_eq!(EncryptionAlgorithm::Aes256Cbc.block_size(), 16);
        assert_eq!(EncryptionAlgorithm::TripleDesCbc.block_size(), 8);
    }

    #[test]
    fn test_decryption_key_creation() {
        // Valid key size
        let key = DecryptionKey::new(vec![0u8; 32], EncryptionAlgorithm::Aes256Cbc);
        assert!(key.is_ok());

        // Invalid key size
        let key = DecryptionKey::new(vec![0u8; 16], EncryptionAlgorithm::Aes256Cbc);
        assert!(key.is_err());
    }

    #[test]
    fn test_is_encrypted_key() {
        // Build a minimal EnvelopedData-like structure
        let mut data = vec![0x30, 0x82, 0x01, 0x00]; // SEQUENCE header
        data.push(0x06); // OID tag
        data.push(OID_ENVELOPED_DATA.len() as u8);
        data.extend_from_slice(OID_ENVELOPED_DATA);
        data.extend(vec![0x00; 10]); // Padding

        assert!(is_encrypted_key(&data));

        // Not a SEQUENCE
        let data = vec![0x04, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(!is_encrypted_key(&data));

        // Too short
        let data = vec![0x30];
        assert!(!is_encrypted_key(&data));
    }

    #[test]
    fn test_algorithm_names() {
        assert_eq!(EncryptionAlgorithm::Aes128Cbc.as_str(), "AES-128-CBC");
        assert_eq!(EncryptionAlgorithm::Aes256Cbc.as_str(), "AES-256-CBC");
        assert_eq!(EncryptionAlgorithm::TripleDesCbc.as_str(), "3DES-CBC");
    }

    #[test]
    fn test_algorithm_from_oid() {
        assert_eq!(
            EncryptionAlgorithm::from_oid(OID_AES_128_CBC),
            Some(EncryptionAlgorithm::Aes128Cbc)
        );
        assert_eq!(
            EncryptionAlgorithm::from_oid(OID_AES_256_CBC),
            Some(EncryptionAlgorithm::Aes256Cbc)
        );
        assert_eq!(
            EncryptionAlgorithm::from_oid(OID_3DES_CBC),
            Some(EncryptionAlgorithm::TripleDesCbc)
        );
        assert_eq!(EncryptionAlgorithm::from_oid(&[0x01, 0x02, 0x03]), None);
    }

    #[cfg(feature = "enveloped")]
    #[test]
    fn test_aes_decryption() {
        // Test data encrypted with AES-256-CBC
        // This is a simple test with known key, IV, and plaintext
        use cbc::cipher::{BlockEncryptMut, KeyIvInit};

        let key = [0x42u8; 32]; // Test key
        let iv = [0x24u8; 16]; // Test IV
        let plaintext = b"Hello, World!"; // 13 bytes (needs padding)

        // Encrypt with proper PKCS#7 padding
        type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
        let cipher = Aes256CbcEnc::new_from_slices(&key, &iv).unwrap();
        let mut buffer = plaintext.to_vec();
        buffer.resize(32, 0); // Space for padding (at least one block)
        let ciphertext = cipher
            .encrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buffer, plaintext.len())
            .unwrap()
            .to_vec();

        // Decrypt using our function
        let decryption_key =
            DecryptionKey::new(key.to_vec(), EncryptionAlgorithm::Aes256Cbc).unwrap();
        let decrypted = decrypt_content(
            &ciphertext,
            decryption_key.key_bytes(),
            &iv,
            EncryptionAlgorithm::Aes256Cbc,
        )
        .unwrap();

        assert_eq!(&decrypted, plaintext);
    }
}
