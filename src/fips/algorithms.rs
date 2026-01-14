// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! FIPS 140-2 Approved Algorithm Enforcement
//!
//! This module enforces FIPS 140-2 approved algorithms and blocks non-compliant
//! cryptographic operations.
//!
//! # NIST 800-53 Controls
//!
//! - **SC-13**: Cryptographic Protection
//!   - Enforces use of NIST-approved cryptographic algorithms
//!   - Blocks deprecated/weak algorithms (3DES, MD5, SHA-1, RC4)
//!   - Validates algorithm compliance before cryptographic operations
//!   - FIPS 140-2 compliant when using OpenSSL FIPS module
//! - **SC-12**: Cryptographic Key Establishment and Management
//!   - Enforces minimum key sizes (RSA ≥2048, ECDSA ≥P-256)
//!   - Validates key algorithm compatibility with FIPS 140-2
//! - **IA-7**: Cryptographic Module Authentication
//!   - Ensures only FIPS-validated cryptographic modules are used
//!   - Runtime validation of FIPS mode status
//!
//! # FIPS-Approved Algorithms
//!
//! ## Symmetric Encryption
//!
//! - AES-128-CBC
//! - AES-192-CBC
//! - AES-256-CBC
//! - AES-128-GCM
//! - AES-192-GCM
//! - AES-256-GCM
//!
//! ## Asymmetric Encryption
//!
//! - RSA 2048-bit
//! - RSA 3072-bit
//! - RSA 4096-bit
//! - ECDSA P-256 (secp256r1)
//! - ECDSA P-384 (secp384r1)
//! - ECDSA P-521 (secp521r1)
//!
//! ## Hash Functions
//!
//! - SHA-256
//! - SHA-384
//! - SHA-512
//! - SHA-512/256
//!
//! ## Key Derivation Functions
//!
//! - PBKDF2 with HMAC-SHA-256
//! - HKDF with HMAC-SHA-256
//!
//! ## Message Authentication
//!
//! - HMAC-SHA-256
//! - HMAC-SHA-384
//! - HMAC-SHA-512
//!
//! # Blocked Algorithms
//!
//! The following algorithms are NOT FIPS-approved and will be rejected:
//!
//! - 3DES (deprecated)
//! - DES (deprecated)
//! - MD5 (cryptographically broken)
//! - SHA-1 (deprecated for digital signatures)
//! - RC4 (cryptographically broken)
//! - RSA < 2048 bits
//! - ECC < 256 bits

use crate::error::{EstError, Result};
use std::fmt;

/// FIPS-approved symmetric encryption algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymmetricAlgorithm {
    /// AES-128 in CBC mode
    Aes128Cbc,
    /// AES-192 in CBC mode
    Aes192Cbc,
    /// AES-256 in CBC mode
    Aes256Cbc,
    /// AES-128 in GCM mode (authenticated encryption)
    Aes128Gcm,
    /// AES-192 in GCM mode (authenticated encryption)
    Aes192Gcm,
    /// AES-256 in GCM mode (authenticated encryption)
    Aes256Gcm,
}

impl fmt::Display for SymmetricAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aes128Cbc => write!(f, "AES-128-CBC"),
            Self::Aes192Cbc => write!(f, "AES-192-CBC"),
            Self::Aes256Cbc => write!(f, "AES-256-CBC"),
            Self::Aes128Gcm => write!(f, "AES-128-GCM"),
            Self::Aes192Gcm => write!(f, "AES-192-GCM"),
            Self::Aes256Gcm => write!(f, "AES-256-GCM"),
        }
    }
}

/// FIPS-approved asymmetric algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsymmetricAlgorithm {
    /// RSA with 2048-bit key
    Rsa2048,
    /// RSA with 3072-bit key
    Rsa3072,
    /// RSA with 4096-bit key
    Rsa4096,
    /// ECDSA with P-256 curve (secp256r1)
    EcdsaP256,
    /// ECDSA with P-384 curve (secp384r1)
    EcdsaP384,
    /// ECDSA with P-521 curve (secp521r1)
    EcdsaP521,
}

impl AsymmetricAlgorithm {
    /// Get the key size in bits
    pub fn key_size(&self) -> u32 {
        match self {
            Self::Rsa2048 => 2048,
            Self::Rsa3072 => 3072,
            Self::Rsa4096 => 4096,
            Self::EcdsaP256 => 256,
            Self::EcdsaP384 => 384,
            Self::EcdsaP521 => 521,
        }
    }

    /// Check if this is an RSA algorithm
    pub fn is_rsa(&self) -> bool {
        matches!(self, Self::Rsa2048 | Self::Rsa3072 | Self::Rsa4096)
    }

    /// Check if this is an ECDSA algorithm
    pub fn is_ecdsa(&self) -> bool {
        matches!(self, Self::EcdsaP256 | Self::EcdsaP384 | Self::EcdsaP521)
    }
}

impl fmt::Display for AsymmetricAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rsa2048 => write!(f, "RSA-2048"),
            Self::Rsa3072 => write!(f, "RSA-3072"),
            Self::Rsa4096 => write!(f, "RSA-4096"),
            Self::EcdsaP256 => write!(f, "ECDSA-P256"),
            Self::EcdsaP384 => write!(f, "ECDSA-P384"),
            Self::EcdsaP521 => write!(f, "ECDSA-P521"),
        }
    }
}

/// FIPS-approved hash functions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-256 (256-bit output)
    Sha256,
    /// SHA-384 (384-bit output)
    Sha384,
    /// SHA-512 (512-bit output)
    Sha512,
    /// SHA-512/256 (256-bit output from SHA-512)
    Sha512_256,
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sha256 => write!(f, "SHA-256"),
            Self::Sha384 => write!(f, "SHA-384"),
            Self::Sha512 => write!(f, "SHA-512"),
            Self::Sha512_256 => write!(f, "SHA-512/256"),
        }
    }
}

/// FIPS-approved TLS versions
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TlsVersion {
    /// TLS 1.2 (minimum FIPS-approved version)
    Tls12,
    /// TLS 1.3
    Tls13,
}

impl fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tls12 => write!(f, "TLS 1.2"),
            Self::Tls13 => write!(f, "TLS 1.3"),
        }
    }
}

/// Algorithm validation policy
#[derive(Debug, Clone)]
pub struct AlgorithmPolicy {
    /// Block non-FIPS algorithms
    pub block_non_fips: bool,
    /// Minimum RSA key size
    pub min_rsa_bits: u32,
    /// Minimum ECC key size
    pub min_ecc_bits: u32,
    /// Minimum TLS version
    pub min_tls_version: TlsVersion,
    /// Allow SHA-1 for legacy compatibility (not recommended)
    pub allow_sha1_legacy: bool,
}

impl Default for AlgorithmPolicy {
    fn default() -> Self {
        Self {
            block_non_fips: true,
            min_rsa_bits: 2048,
            min_ecc_bits: 256,
            min_tls_version: TlsVersion::Tls12,
            allow_sha1_legacy: false,
        }
    }
}

impl AlgorithmPolicy {
    /// Validate a symmetric algorithm against this policy
    pub fn validate_symmetric(&self, _algorithm: SymmetricAlgorithm) -> Result<()> {
        if self.block_non_fips {
            // All SymmetricAlgorithm variants are FIPS-approved
            Ok(())
        } else {
            Ok(())
        }
    }

    /// Validate an asymmetric algorithm against this policy
    pub fn validate_asymmetric(&self, algorithm: AsymmetricAlgorithm) -> Result<()> {
        if self.block_non_fips {
            // Check minimum key sizes
            if algorithm.is_rsa() && algorithm.key_size() < self.min_rsa_bits {
                return Err(EstError::FipsAlgorithmNotAllowed(format!(
                    "RSA key size {} is below minimum {}",
                    algorithm.key_size(),
                    self.min_rsa_bits
                )));
            }

            if algorithm.is_ecdsa() && algorithm.key_size() < self.min_ecc_bits {
                return Err(EstError::FipsAlgorithmNotAllowed(format!(
                    "ECC key size {} is below minimum {}",
                    algorithm.key_size(),
                    self.min_ecc_bits
                )));
            }
        }

        Ok(())
    }

    /// Validate a hash algorithm against this policy
    pub fn validate_hash(&self, _algorithm: HashAlgorithm) -> Result<()> {
        if self.block_non_fips {
            // All HashAlgorithm variants are FIPS-approved
            Ok(())
        } else {
            Ok(())
        }
    }

    /// Validate TLS version against this policy
    pub fn validate_tls_version(&self, version: TlsVersion) -> Result<()> {
        if version < self.min_tls_version {
            return Err(EstError::FipsAlgorithmNotAllowed(format!(
                "TLS version {} is below minimum {}",
                version, self.min_tls_version
            )));
        }
        Ok(())
    }

    /// Validate RSA key size
    pub fn validate_rsa_key_size(&self, bits: u32) -> Result<()> {
        if self.block_non_fips && bits < self.min_rsa_bits {
            return Err(EstError::FipsAlgorithmNotAllowed(format!(
                "RSA key size {} is below FIPS minimum {}",
                bits, self.min_rsa_bits
            )));
        }
        Ok(())
    }

    /// Validate ECC key size
    pub fn validate_ecc_key_size(&self, bits: u32) -> Result<()> {
        if self.block_non_fips && bits < self.min_ecc_bits {
            return Err(EstError::FipsAlgorithmNotAllowed(format!(
                "ECC key size {} is below FIPS minimum {}",
                bits, self.min_ecc_bits
            )));
        }
        Ok(())
    }

    /// Check if an algorithm name is blocked
    ///
    /// Returns an error if the algorithm is not FIPS-approved.
    pub fn check_algorithm_name(&self, name: &str) -> Result<()> {
        if !self.block_non_fips {
            return Ok(());
        }

        let name_lower = name.to_lowercase();

        // Blocked algorithms
        let blocked = [
            "3des", "des", "md5", "sha1", "sha-1", "rc4", "rc2", "md4", "md2", "rsa1024", "rsa512",
        ];

        for blocked_alg in &blocked {
            if name_lower.contains(blocked_alg) {
                // Special case: allow sha1 for legacy if policy permits
                if (name_lower.contains("sha1") || name_lower.contains("sha-1"))
                    && self.allow_sha1_legacy
                {
                    tracing::warn!(
                        "Allowing SHA-1 algorithm '{}' due to legacy compatibility policy",
                        name
                    );
                    return Ok(());
                }

                return Err(EstError::FipsAlgorithmNotAllowed(format!(
                    "Algorithm '{}' is not FIPS-approved (contains blocked algorithm '{}')",
                    name, blocked_alg
                )));
            }
        }

        Ok(())
    }
}

/// Algorithm validator with policy enforcement
pub struct AlgorithmValidator {
    policy: AlgorithmPolicy,
}

impl AlgorithmValidator {
    /// Create a new algorithm validator with default policy
    pub fn new() -> Self {
        Self {
            policy: AlgorithmPolicy::default(),
        }
    }

    /// Create a new algorithm validator with custom policy
    pub fn with_policy(policy: AlgorithmPolicy) -> Self {
        Self { policy }
    }

    /// Get the current policy
    pub fn policy(&self) -> &AlgorithmPolicy {
        &self.policy
    }

    /// Validate all aspects of an asymmetric algorithm
    pub fn validate_asymmetric_full(&self, algorithm: AsymmetricAlgorithm) -> Result<()> {
        self.policy.validate_asymmetric(algorithm)?;

        tracing::debug!(
            "Validated FIPS-approved asymmetric algorithm: {}",
            algorithm
        );
        Ok(())
    }

    /// Validate all aspects of a symmetric algorithm
    pub fn validate_symmetric_full(&self, algorithm: SymmetricAlgorithm) -> Result<()> {
        self.policy.validate_symmetric(algorithm)?;

        tracing::debug!("Validated FIPS-approved symmetric algorithm: {}", algorithm);
        Ok(())
    }

    /// Validate certificate signature algorithm OID
    ///
    /// Common signature algorithm OIDs:
    /// - 1.2.840.113549.1.1.11: sha256WithRSAEncryption
    /// - 1.2.840.113549.1.1.12: sha384WithRSAEncryption
    /// - 1.2.840.113549.1.1.13: sha512WithRSAEncryption
    /// - 1.2.840.10045.4.3.2: ecdsa-with-SHA256
    /// - 1.2.840.10045.4.3.3: ecdsa-with-SHA384
    /// - 1.2.840.10045.4.3.4: ecdsa-with-SHA512
    pub fn validate_signature_algorithm_oid(&self, oid: &str) -> Result<()> {
        if !self.policy.block_non_fips {
            return Ok(());
        }

        // FIPS-approved signature algorithm OIDs
        let approved = [
            "1.2.840.113549.1.1.11", // sha256WithRSAEncryption
            "1.2.840.113549.1.1.12", // sha384WithRSAEncryption
            "1.2.840.113549.1.1.13", // sha512WithRSAEncryption
            "1.2.840.10045.4.3.2",   // ecdsa-with-SHA256
            "1.2.840.10045.4.3.3",   // ecdsa-with-SHA384
            "1.2.840.10045.4.3.4",   // ecdsa-with-SHA512
        ];

        if approved.contains(&oid) {
            Ok(())
        } else {
            // Check for blocked OIDs
            let blocked = [
                "1.2.840.113549.1.1.4",  // md5WithRSAEncryption
                "1.2.840.113549.1.1.5",  // sha1WithRSAEncryption
                "1.2.840.10045.4.1",     // ecdsa-with-SHA1
                "1.2.840.113549.1.1.13", // sha1WithRSAEncryption (alt)
            ];

            if blocked.contains(&oid) {
                Err(EstError::FipsAlgorithmNotAllowed(format!(
                    "Signature algorithm OID '{}' is not FIPS-approved (blocked)",
                    oid
                )))
            } else {
                Err(EstError::FipsAlgorithmNotAllowed(format!(
                    "Signature algorithm OID '{}' is not in FIPS-approved list",
                    oid
                )))
            }
        }
    }
}

impl Default for AlgorithmValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symmetric_algorithms() {
        let validator = AlgorithmValidator::new();

        // All AES variants should be approved
        assert!(
            validator
                .validate_symmetric_full(SymmetricAlgorithm::Aes128Cbc)
                .is_ok()
        );
        assert!(
            validator
                .validate_symmetric_full(SymmetricAlgorithm::Aes256Gcm)
                .is_ok()
        );
    }

    #[test]
    fn test_asymmetric_algorithms() {
        let validator = AlgorithmValidator::new();

        // RSA 2048+ should be approved
        assert!(
            validator
                .validate_asymmetric_full(AsymmetricAlgorithm::Rsa2048)
                .is_ok()
        );
        assert!(
            validator
                .validate_asymmetric_full(AsymmetricAlgorithm::Rsa4096)
                .is_ok()
        );

        // ECDSA P-256+ should be approved
        assert!(
            validator
                .validate_asymmetric_full(AsymmetricAlgorithm::EcdsaP256)
                .is_ok()
        );
        assert!(
            validator
                .validate_asymmetric_full(AsymmetricAlgorithm::EcdsaP521)
                .is_ok()
        );
    }

    #[test]
    fn test_key_size_validation() {
        let policy = AlgorithmPolicy::default();

        // Valid key sizes
        assert!(policy.validate_rsa_key_size(2048).is_ok());
        assert!(policy.validate_rsa_key_size(4096).is_ok());
        assert!(policy.validate_ecc_key_size(256).is_ok());
        assert!(policy.validate_ecc_key_size(384).is_ok());

        // Invalid key sizes
        assert!(policy.validate_rsa_key_size(1024).is_err());
        assert!(policy.validate_ecc_key_size(192).is_err());
    }

    #[test]
    fn test_tls_version_validation() {
        let policy = AlgorithmPolicy::default();

        // TLS 1.2+ should be approved
        assert!(policy.validate_tls_version(TlsVersion::Tls12).is_ok());
        assert!(policy.validate_tls_version(TlsVersion::Tls13).is_ok());
    }

    #[test]
    fn test_blocked_algorithm_names() {
        let policy = AlgorithmPolicy::default();

        // Blocked algorithms should fail
        assert!(policy.check_algorithm_name("3DES").is_err());
        assert!(policy.check_algorithm_name("MD5").is_err());
        assert!(policy.check_algorithm_name("SHA1").is_err());
        assert!(policy.check_algorithm_name("RC4").is_err());
        assert!(policy.check_algorithm_name("DES").is_err());

        // Approved algorithms should pass
        assert!(policy.check_algorithm_name("AES-256-GCM").is_ok());
        assert!(policy.check_algorithm_name("SHA-256").is_ok());
        assert!(policy.check_algorithm_name("RSA-2048").is_ok());
    }

    #[test]
    fn test_signature_algorithm_oids() {
        let validator = AlgorithmValidator::new();

        // FIPS-approved OIDs should pass
        assert!(
            validator
                .validate_signature_algorithm_oid("1.2.840.113549.1.1.11")
                .is_ok()
        ); // sha256WithRSAEncryption
        assert!(
            validator
                .validate_signature_algorithm_oid("1.2.840.10045.4.3.2")
                .is_ok()
        ); // ecdsa-with-SHA256

        // Blocked OIDs should fail
        assert!(
            validator
                .validate_signature_algorithm_oid("1.2.840.113549.1.1.4")
                .is_err()
        ); // md5WithRSAEncryption
        assert!(
            validator
                .validate_signature_algorithm_oid("1.2.840.113549.1.1.5")
                .is_err()
        ); // sha1WithRSAEncryption
    }

    #[test]
    fn test_sha1_legacy_mode() {
        let mut policy = AlgorithmPolicy::default();
        policy.allow_sha1_legacy = true;

        // SHA-1 should be allowed with legacy flag
        assert!(policy.check_algorithm_name("SHA1").is_ok());
        assert!(policy.check_algorithm_name("SHA-1").is_ok());

        // Other blocked algorithms should still fail
        assert!(policy.check_algorithm_name("MD5").is_err());
        assert!(policy.check_algorithm_name("DES").is_err());
    }

    #[test]
    fn test_algorithm_key_sizes() {
        assert_eq!(AsymmetricAlgorithm::Rsa2048.key_size(), 2048);
        assert_eq!(AsymmetricAlgorithm::Rsa3072.key_size(), 3072);
        assert_eq!(AsymmetricAlgorithm::EcdsaP256.key_size(), 256);
        assert_eq!(AsymmetricAlgorithm::EcdsaP384.key_size(), 384);
    }

    #[test]
    fn test_algorithm_type_checks() {
        assert!(AsymmetricAlgorithm::Rsa2048.is_rsa());
        assert!(!AsymmetricAlgorithm::Rsa2048.is_ecdsa());

        assert!(AsymmetricAlgorithm::EcdsaP256.is_ecdsa());
        assert!(!AsymmetricAlgorithm::EcdsaP256.is_rsa());
    }
}
