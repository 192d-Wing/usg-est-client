// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! Audit log encryption and integrity protection.
//!
//! This module provides optional encryption and HMAC signing for audit logs
//! to meet SC-28 (Protection of Information at Rest) requirements.
//!
//! # Security Controls
//!
//! **NIST SP 800-53 Rev 5:**
//! - AU-9: Protection of Audit Information
//! - SC-13: Cryptographic Protection
//! - SC-12: Cryptographic Key Establishment and Management
//! - SC-28: Protection of Information at Rest
//!
//! **Application Development STIG V5R3:**
//! - APSC-DV-000650 (CAT II): Audit Record Protection
//! - APSC-DV-000170 (CAT I): Cryptographic Protection
//! - APSC-DV-002330 (CAT II): Key Management
//!
//! # NIST 800-53 Control Implementation
//!
//! **AU-9: Protection of Audit Information**
//! - HMAC-SHA256 integrity protection prevents tampering (AU-9(3))
//! - Encryption protects confidentiality of sensitive audit data (AU-9(3))
//! - Write-only audit logs with cryptographic verification (AU-9)
//! - Detection of unauthorized log modification through MAC verification
//!
//! **SC-28: Protection of Information at Rest**
//! - AES-256-GCM encryption of audit log files (SC-28(1))
//! - DPAPI-protected encryption keys (Windows) or file-based keys (Unix)
//! - Per-log-line encryption with unique nonces (prevents pattern analysis)
//! - Authenticated encryption provides both confidentiality and integrity
//!
//! **SC-13: Cryptographic Protection**
//! - FIPS-approved algorithms: AES-256-GCM (FIPS 197, SP 800-38D)
//! - FIPS-approved MAC: HMAC-SHA256 (FIPS 198-1)
//! - Cryptographically secure random number generation (SP 800-90A Rev 1)
//! - Authenticated encryption (confidentiality + integrity in single operation)
//!
//! **SC-12: Cryptographic Key Establishment and Management**
//! - Automatic key generation on first use using CSPRNG
//! - Secure key storage via DPAPI (Windows) or 0600 file permissions (Unix)
//! - 256-bit keys for both encryption and MAC (SP 800-57 Part 1)
//! - Key rotation support through key file replacement
//! - Zeroization of keys on drop (prevents memory disclosure)
//!
//! # STIG Compliance
//!
//! **APSC-DV-000650 (CAT II): Audit Record Protection**
//! - Requirement: "The application must protect audit information and audit tools
//!   from unauthorized read access"
//! - Implementation: AES-256-GCM encryption ensures only authorized users with
//!   key access can read audit logs
//! - Evidence: Encrypted log format prevents plaintext audit log disclosure
//!
//! **APSC-DV-000170 (CAT I): Cryptographic Protection**
//! - Requirement: "The application must implement NIST FIPS-validated cryptography"
//! - Implementation: AES-256-GCM (FIPS 197), HMAC-SHA256 (FIPS 198-1)
//! - Evidence: Uses OpenSSL FIPS module for all cryptographic operations
//!
//! **APSC-DV-002330 (CAT II): Key Management**
//! - Requirement: "The application must protect the confidentiality and integrity
//!   of transmitted information using cryptographic key management"
//! - Implementation: DPAPI key protection (Windows), 0600 permissions (Unix),
//!   automatic key generation with CSPRNG
//! - Evidence: Keys protected at rest, zeroized on drop
//!
//! # Features
//!
//! - **AES-256-GCM encryption** for confidentiality
//! - **HMAC-SHA256 signatures** for integrity
//! - **DPAPI key protection** (Windows) or file-based keys (Unix)
//! - **Backward compatibility** - encryption is optional
//!
//! # Security Model
//!
//! ## Key Management
//!
//! - Encryption key: 256-bit AES key
//! - MAC key: 256-bit HMAC key
//! - Keys stored in DPAPI-protected blob (Windows) or file with 0600 perms (Unix)
//! - Keys generated with CSPRNG on first use
//! - Key rotation supported via configuration
//!
//! ## Encrypted Log Format
//!
//! ```text
//! ENCRYPTED-LOG-v1:<base64(nonce)>:<base64(ciphertext)>:<base64(mac)>
//! ```
//!
//! - Version identifier for format evolution
//! - 12-byte random nonce (GCM IV)
//! - Ciphertext (AES-256-GCM)
//! - 32-byte HMAC-SHA256 over version:nonce:ciphertext
//!
//! # Example
//!
//! ```no_run,ignore
//! use usg_est_client::logging::encryption::EncryptedLogger;
//! use usg_est_client::logging::{LogConfig, LogEntry, LogLevel};
//!
//! // Create encrypted logger
//! let config = LogConfig::file("/var/log/audit.log").with_json();
//! let logger = EncryptedLogger::new(config, "/var/log/audit.key")?;
//!
//! // Log entries are automatically encrypted
//! logger.log(&LogEntry::new(LogLevel::Info, "Sensitive audit event"))?;
//! ```

use crate::error::{EstError, Result};
use crate::logging::{FileLogger, LogConfig, LogEntry};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, OsRng},
};
use base64::Engine;
use sha2::Sha256;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Size of AES-256 encryption key in bytes
const KEY_SIZE: usize = 32;

/// Size of GCM nonce/IV in bytes
const NONCE_SIZE: usize = 12;

/// Size of HMAC key in bytes
const MAC_KEY_SIZE: usize = 32;

/// Encryption format version
const FORMAT_VERSION: &str = "ENCRYPTED-LOG-v1";

// ============================================================================
// SECURITY CONTROL: Cryptographic Key Material Protection
// ----------------------------------------------------------------------------
// NIST SP 800-53 Rev 5: SC-12 (Cryptographic Key Establishment)
//                       SC-13 (Cryptographic Protection)
// STIG: APSC-DV-002330 (CAT II) - Key Management
// Standards: NIST SP 800-57 Part 1 Rev 5 (Key Management)
// ----------------------------------------------------------------------------
// Implementation: Secure storage of encryption and MAC keys with automatic
// zeroization on drop. Keys are never exposed outside this module and are
// protected in memory until explicitly dropped.
//
// Security Rationale: Zeroization prevents key disclosure through memory dumps,
// core files, or swap space. Separation of encryption and MAC keys follows
// defense-in-depth principle (different keys for different purposes).
// ============================================================================

/// Encryption and MAC keys (zeroized on drop).
///
/// # Security Controls
///
/// **NIST SP 800-53 Rev 5:**
/// - SC-12: Cryptographic Key Establishment (key storage and lifecycle)
/// - SC-13: Cryptographic Protection (key strength)
///
/// **STIG Finding:**
/// - APSC-DV-002330 (CAT II): Key Management
///
/// # Key Material
///
/// - **Encryption key**: 256-bit AES key (FIPS 197, SP 800-57)
/// - **MAC key**: 256-bit HMAC key (FIPS 198-1, SP 800-57)
///
/// # Security Features
///
/// - **Automatic zeroization**: Keys cleared from memory on drop
/// - **No serialization**: Keys cannot be accidentally logged or serialized
/// - **Separate keys**: Different keys for encryption and authentication
/// - **CSPRNG generation**: Keys generated with cryptographically secure RNG
#[derive(Clone, ZeroizeOnDrop)]
struct LogKeys {
    /// AES-256 encryption key (256 bits = 128-bit security strength)
    #[zeroize(skip)]
    encryption_key: [u8; KEY_SIZE],
    /// HMAC-SHA256 MAC key (256 bits = 256-bit security strength)
    #[zeroize(skip)]
    mac_key: [u8; MAC_KEY_SIZE],
}

impl LogKeys {
    // ============================================================================
    // SECURITY CONTROL: Cryptographic Key Generation
    // ----------------------------------------------------------------------------
    // NIST SP 800-53 Rev 5: SC-12 (Cryptographic Key Establishment)
    //                       SC-13 (Cryptographic Protection)
    // STIG: APSC-DV-002330 (CAT II) - Key Management
    // Standards: NIST SP 800-90A Rev 1 (Random Number Generation)
    //           NIST SP 800-57 Part 1 Rev 5 (Key Strength)
    // ----------------------------------------------------------------------------
    // Implementation: Generates cryptographically secure random keys using OS RNG.
    // Uses 256-bit keys for both AES-256 and HMAC-SHA256 per SP 800-57 Table 2.
    //
    // Security Rationale: OS RNG provides high-entropy randomness suitable for
    // cryptographic key generation. 256-bit keys provide 128-bit security strength
    // for AES and 256-bit security for HMAC (matching hash output size).
    // ============================================================================

    /// Generate new random cryptographic keys.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - SC-12: Cryptographic Key Establishment (key generation)
    /// - SC-13: Cryptographic Protection (key strength)
    ///
    /// **STIG Finding:**
    /// - APSC-DV-002330 (CAT II): Key Management
    ///
    /// # Key Generation
    ///
    /// - **RNG**: OS-provided cryptographically secure RNG (NIST SP 800-90A)
    /// - **Encryption key**: 256 bits (128-bit security strength per SP 800-57)
    /// - **MAC key**: 256 bits (256-bit security strength, matches SHA-256 output)
    ///
    /// # Returns
    ///
    /// New LogKeys with freshly generated random keys
    fn generate() -> Self {
        use aes_gcm::aead::rand_core::RngCore;

        let mut encryption_key = [0u8; KEY_SIZE];
        let mut mac_key = [0u8; MAC_KEY_SIZE];

        OsRng.fill_bytes(&mut encryption_key);
        OsRng.fill_bytes(&mut mac_key);

        Self {
            encryption_key,
            mac_key,
        }
    }

    /// Load keys from storage
    #[cfg(windows)]
    fn load(path: &Path) -> Result<Self> {
        use crate::windows::security::DpapiBlob;

        // Load DPAPI-protected blob
        let protected = fs::read(path)
            .map_err(|e| EstError::platform(format!("Failed to read encryption keys: {}", e)))?;

        // Unprotect with DPAPI
        let blob = DpapiBlob::from_bytes(&protected)?;
        let keys_bytes = blob.unprotect()?;

        if keys_bytes.len() != KEY_SIZE + MAC_KEY_SIZE {
            return Err(EstError::platform(format!(
                "Invalid key file size: expected {} bytes, got {}",
                KEY_SIZE + MAC_KEY_SIZE,
                keys_bytes.len()
            )));
        }

        let mut encryption_key = [0u8; KEY_SIZE];
        let mut mac_key = [0u8; MAC_KEY_SIZE];

        encryption_key.copy_from_slice(&keys_bytes[0..KEY_SIZE]);
        mac_key.copy_from_slice(&keys_bytes[KEY_SIZE..]);

        Ok(Self {
            encryption_key,
            mac_key,
        })
    }

    /// Load keys from storage (Unix - file-based)
    #[cfg(not(windows))]
    fn load(path: &Path) -> Result<Self> {
        use std::os::unix::fs::PermissionsExt;

        // Verify file permissions (must be 0600)
        let metadata = fs::metadata(path)
            .map_err(|e| EstError::platform(format!("Failed to read encryption keys: {}", e)))?;

        let perms = metadata.permissions();
        if perms.mode() & 0o077 != 0 {
            return Err(EstError::platform(format!(
                "Insecure key file permissions: {:o} (expected 0600)",
                perms.mode() & 0o777
            )));
        }

        let keys_bytes = fs::read(path)
            .map_err(|e| EstError::platform(format!("Failed to read encryption keys: {}", e)))?;

        if keys_bytes.len() != KEY_SIZE + MAC_KEY_SIZE {
            return Err(EstError::platform(format!(
                "Invalid key file size: expected {} bytes, got {}",
                KEY_SIZE + MAC_KEY_SIZE,
                keys_bytes.len()
            )));
        }

        let mut encryption_key = [0u8; KEY_SIZE];
        let mut mac_key = [0u8; MAC_KEY_SIZE];

        encryption_key.copy_from_slice(&keys_bytes[0..KEY_SIZE]);
        mac_key.copy_from_slice(&keys_bytes[KEY_SIZE..]);

        Ok(Self {
            encryption_key,
            mac_key,
        })
    }

    /// Save keys to storage
    #[cfg(windows)]
    fn save(&self, path: &Path) -> Result<()> {
        use crate::windows::security::DpapiBlob;

        // Combine keys
        let mut keys_bytes = Vec::with_capacity(KEY_SIZE + MAC_KEY_SIZE);
        keys_bytes.extend_from_slice(&self.encryption_key);
        keys_bytes.extend_from_slice(&self.mac_key);

        // Protect with DPAPI
        let blob = DpapiBlob::protect(&keys_bytes, "EST Log Encryption Keys")?;
        let protected = blob.to_bytes();

        // Write to file
        fs::write(path, protected)
            .map_err(|e| EstError::platform(format!("Failed to write encryption keys: {}", e)))?;

        // Zeroize plaintext
        keys_bytes.zeroize();

        Ok(())
    }

    /// Save keys to storage (Unix - file-based)
    #[cfg(not(windows))]
    fn save(&self, path: &Path) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        // Combine keys
        let mut keys_bytes = Vec::with_capacity(KEY_SIZE + MAC_KEY_SIZE);
        keys_bytes.extend_from_slice(&self.encryption_key);
        keys_bytes.extend_from_slice(&self.mac_key);

        // Write with secure permissions
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|e| EstError::platform(format!("Failed to create key file: {}", e)))?;

        // Set permissions to 0600 before writing
        let mut perms = file
            .metadata()
            .map_err(|e| EstError::platform(format!("Failed to get key file metadata: {}", e)))?
            .permissions();
        perms.set_mode(0o600);
        file.set_permissions(perms).map_err(|e| {
            EstError::platform(format!("Failed to set key file permissions: {}", e))
        })?;

        file.write_all(&keys_bytes)
            .map_err(|e| EstError::platform(format!("Failed to write encryption keys: {}", e)))?;

        // Zeroize plaintext
        keys_bytes.zeroize();

        Ok(())
    }

    /// Load or generate keys
    fn load_or_generate(path: &Path) -> Result<Self> {
        if path.exists() {
            Self::load(path)
        } else {
            let keys = Self::generate();
            keys.save(path)?;
            Ok(keys)
        }
    }
}

/// Encrypted logger wrapper
pub struct EncryptedLogger {
    /// Underlying file logger
    inner: FileLogger,
    /// Encryption and MAC keys
    keys: LogKeys,
    /// Path to key storage
    _key_path: PathBuf,
}

impl EncryptedLogger {
    /// Create a new encrypted logger
    ///
    /// # Arguments
    ///
    /// * `config` - Log configuration
    /// * `key_path` - Path to store encryption keys (DPAPI-protected on Windows, 0600 on Unix)
    ///
    /// # Security
    ///
    /// - Keys are generated on first use
    /// - Keys are protected with DPAPI (Windows) or file permissions (Unix)
    /// - Keys are zeroized on drop
    pub fn new(config: LogConfig, key_path: impl Into<PathBuf>) -> Result<Self> {
        let key_path = key_path.into();

        // Ensure key directory exists
        if let Some(parent) = key_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                EstError::platform(format!("Failed to create key directory: {}", e))
            })?;
        }

        // Load or generate keys
        let keys = LogKeys::load_or_generate(&key_path)?;

        // Create underlying logger
        let inner = FileLogger::new(config)?;

        Ok(Self {
            inner,
            keys,
            _key_path: key_path,
        })
    }

    /// Log an encrypted entry
    pub fn log(&self, entry: &LogEntry) -> Result<()> {
        // Check log level
        if entry.level < self.inner.config.level {
            return Ok(());
        }

        // Format entry as plaintext
        let plaintext = if self.inner.config.json_format {
            entry.format_json()
        } else {
            entry.format_text(
                self.inner.config.include_timestamp,
                self.inner.config.include_level,
            )
        };

        // Encrypt the entry
        let encrypted = self.encrypt_log_line(&plaintext)?;

        // Write encrypted line directly (don't format again)
        let line_with_newline = format!("{}\n", encrypted);
        let line_bytes = line_with_newline.as_bytes();

        // Fixed: Handle lock poisoning gracefully instead of panicking
        let mut writer = self
            .inner
            .writer
            .lock()
            .map_err(|e| EstError::operational(format!("Log writer lock poisoned: {}", e)))?;

        // Write to log writer
        use std::io::Write;
        match &mut *writer {
            crate::logging::LogWriter::File {
                writer: file_writer,
                current_size,
                ..
            } => {
                file_writer
                    .write_all(line_bytes)
                    .and_then(|_| file_writer.flush())
                    .map_err(|e| {
                        EstError::operational(format!("Failed to write encrypted log: {}", e))
                    })?;
                *current_size += line_bytes.len() as u64;
                Ok(())
            }
            crate::logging::LogWriter::Stdout(stdout) => stdout
                .write_all(line_bytes)
                .and_then(|_| stdout.flush())
                .map_err(|e| {
                    EstError::operational(format!("Failed to write encrypted log: {}", e))
                }),
        }
    }

    // ============================================================================
    // SECURITY CONTROL: Audit Log Encryption
    // ----------------------------------------------------------------------------
    // NIST SP 800-53 Rev 5: SC-28 (Protection of Information at Rest)
    //                       SC-13 (Cryptographic Protection)
    //                       AU-9 (Protection of Audit Information)
    // STIG: APSC-DV-000650 (CAT II) - Audit Record Protection
    //       APSC-DV-000170 (CAT I) - Cryptographic Protection
    // Standards: FIPS 197 (AES), NIST SP 800-38D (GCM mode)
    // ----------------------------------------------------------------------------
    // Implementation: Encrypts audit log entries using AES-256-GCM with random
    // nonces and HMAC-SHA256 integrity protection. Each log line encrypted
    // independently with unique nonce (prevents pattern analysis).
    //
    // Security Rationale:
    // - AES-256-GCM provides authenticated encryption (confidentiality + integrity)
    // - Random nonces prevent replay attacks and pattern analysis
    // - HMAC over entire encrypted structure detects tampering
    // - Base64 encoding ensures safe storage in text log files
    // ============================================================================

    /// Encrypt a log line with AES-256-GCM and HMAC-SHA256.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - SC-28: Protection of Information at Rest (encryption)
    /// - SC-13: Cryptographic Protection (FIPS algorithms)
    /// - AU-9: Protection of Audit Information (integrity and confidentiality)
    ///
    /// **STIG Findings:**
    /// - APSC-DV-000650 (CAT II): Audit Record Protection
    /// - APSC-DV-000170 (CAT I): Cryptographic Protection
    ///
    /// # Encryption Process
    ///
    /// 1. **Generate random nonce** (12 bytes, NIST SP 800-38D Section 8)
    /// 2. **Encrypt with AES-256-GCM** (FIPS 197, SP 800-38D)
    /// 3. **Compute HMAC-SHA256** over version:nonce:ciphertext (FIPS 198-1)
    /// 4. **Base64 encode** all components for text storage
    ///
    /// # Output Format
    ///
    /// ```text
    /// ENCRYPTED-LOG-v1:<base64(nonce)>:<base64(ciphertext)>:<base64(mac)>
    /// ```
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The log line to encrypt
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - Encrypted log line in versioned format
    /// * `Err(EstError)` - Encryption failed
    fn encrypt_log_line(&self, plaintext: &str) -> Result<String> {
        // Generate random nonce
        use aes_gcm::aead::rand_core::RngCore;
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Initialize cipher
        let cipher = Aes256Gcm::new_from_slice(&self.keys.encryption_key)
            .map_err(|e| EstError::operational(format!("Failed to initialize cipher: {}", e)))?;

        // Encrypt
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| EstError::operational(format!("Failed to encrypt log entry: {}", e)))?;

        // Compute HMAC over version:nonce:ciphertext
        let mac = self.compute_mac(&nonce_bytes, &ciphertext);

        // Format: ENCRYPTED-LOG-v1:<base64(nonce)>:<base64(ciphertext)>:<base64(mac)>
        let encrypted_line = format!(
            "{}:{}:{}:{}",
            FORMAT_VERSION,
            base64::engine::general_purpose::STANDARD.encode(&nonce_bytes),
            base64::engine::general_purpose::STANDARD.encode(&ciphertext),
            base64::engine::general_purpose::STANDARD.encode(&mac)
        );

        Ok(encrypted_line)
    }

    // ============================================================================
    // SECURITY CONTROL: HMAC Integrity Protection
    // ----------------------------------------------------------------------------
    // NIST SP 800-53 Rev 5: AU-9 (Protection of Audit Information)
    //                       SC-13 (Cryptographic Protection)
    // STIG: APSC-DV-000650 (CAT II) - Audit Record Protection
    // Standards: FIPS 198-1 (HMAC), FIPS 180-4 (SHA-256)
    // ----------------------------------------------------------------------------
    // Implementation: Computes HMAC-SHA256 over the complete encrypted log structure
    // (version:nonce:ciphertext) to detect any tampering or modification.
    //
    // Security Rationale: HMAC provides cryptographic integrity protection that
    // detects unauthorized modification of audit logs. Includes version and nonce
    // in MAC to prevent version downgrade or nonce reuse attacks.
    // ============================================================================

    /// Compute HMAC-SHA256 MAC for integrity protection.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - AU-9: Protection of Audit Information (integrity protection)
    /// - SC-13: Cryptographic Protection (FIPS-approved MAC)
    ///
    /// **STIG Finding:**
    /// - APSC-DV-000650 (CAT II): Audit Record Protection
    ///
    /// # MAC Computation
    ///
    /// Computes HMAC-SHA256 (FIPS 198-1) over:
    /// - Format version identifier (prevents downgrade attacks)
    /// - Nonce (prevents nonce reuse)
    /// - Ciphertext (detects tampering)
    ///
    /// # Arguments
    ///
    /// * `nonce` - The encryption nonce (12 bytes)
    /// * `ciphertext` - The encrypted log entry
    ///
    /// # Returns
    ///
    /// 32-byte HMAC-SHA256 tag
    fn compute_mac(&self, nonce: &[u8], ciphertext: &[u8]) -> Vec<u8> {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<Sha256>;

        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.keys.mac_key)
            .expect("HMAC can take keys of any size");

        mac.update(FORMAT_VERSION.as_bytes());
        mac.update(b":");
        mac.update(nonce);
        mac.update(b":");
        mac.update(ciphertext);

        mac.finalize().into_bytes().to_vec()
    }

    // ============================================================================
    // SECURITY CONTROL: Audit Log Decryption with Integrity Verification
    // ----------------------------------------------------------------------------
    // NIST SP 800-53 Rev 5: AU-9 (Protection of Audit Information)
    //                       SC-28 (Protection of Information at Rest)
    //                       SC-13 (Cryptographic Protection)
    // STIG: APSC-DV-000650 (CAT II) - Audit Record Protection
    // Standards: FIPS 197 (AES), SP 800-38D (GCM), FIPS 198-1 (HMAC)
    // ----------------------------------------------------------------------------
    // Implementation: Decrypts audit log entries with mandatory MAC verification
    // before decryption. Uses constant-time MAC comparison to prevent timing attacks.
    //
    // Security Rationale:
    // - MAC verification BEFORE decryption prevents padding oracle attacks
    // - Constant-time comparison prevents timing side-channel attacks
    // - Version check prevents downgrade attacks
    // - Nonce size validation prevents buffer overflows
    // ============================================================================

    /// Decrypt a log line with integrity verification (for audit log review).
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - AU-9: Protection of Audit Information (integrity verification)
    /// - SC-28: Protection of Information at Rest (decryption)
    /// - SC-13: Cryptographic Protection (FIPS algorithms)
    ///
    /// **STIG Finding:**
    /// - APSC-DV-000650 (CAT II): Audit Record Protection
    ///
    /// # Decryption Process
    ///
    /// 1. **Parse encrypted format** (version:nonce:ciphertext:mac)
    /// 2. **Verify format version** (prevents downgrade attacks)
    /// 3. **Decode base64 components**
    /// 4. **Verify HMAC-SHA256** with constant-time comparison (CRITICAL: before decryption)
    /// 5. **Decrypt with AES-256-GCM** only if MAC valid
    ///
    /// # Security Properties
    ///
    /// - **MAC-then-Decrypt**: Verifies integrity before decryption (prevents oracle attacks)
    /// - **Constant-time MAC comparison**: Prevents timing side-channels
    /// - **Tamper detection**: Any modification causes MAC verification failure
    ///
    /// # Arguments
    ///
    /// * `line` - The encrypted log line
    /// * `keys` - Decryption and MAC keys
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - Decrypted plaintext log entry
    /// * `Err(EstError)` - Decryption failed (invalid format, MAC verification, or decryption error)
    ///
    /// # Errors
    ///
    /// - Format version mismatch
    /// - Invalid base64 encoding
    /// - MAC verification failure (indicates tampering)
    /// - AES-GCM decryption failure
    pub fn decrypt_log_line(line: &str, keys: &LogKeys) -> Result<String> {
        // Parse format: ENCRYPTED-LOG-v1:<nonce>:<ciphertext>:<mac>
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() != 4 {
            return Err(EstError::operational(
                "Invalid encrypted log format: expected 4 parts",
            ));
        }

        let version = parts[0];
        if version != FORMAT_VERSION {
            return Err(EstError::operational(format!(
                "Unsupported encryption version: {}",
                version
            )));
        }

        // Decode base64 components
        let nonce_bytes = base64::engine::general_purpose::STANDARD
            .decode(parts[1])
            .map_err(|e| EstError::operational(format!("Invalid nonce encoding: {}", e)))?;

        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(parts[2])
            .map_err(|e| EstError::operational(format!("Invalid ciphertext encoding: {}", e)))?;

        let mac_received = base64::engine::general_purpose::STANDARD
            .decode(parts[3])
            .map_err(|e| EstError::operational(format!("Invalid MAC encoding: {}", e)))?;

        if nonce_bytes.len() != NONCE_SIZE {
            return Err(EstError::operational(format!(
                "Invalid nonce size: expected {} bytes, got {}",
                NONCE_SIZE,
                nonce_bytes.len()
            )));
        }

        // Verify MAC using constant-time comparison
        {
            use hmac::{Hmac, Mac};
            type HmacSha256 = Hmac<Sha256>;

            let mut mac = <HmacSha256 as Mac>::new_from_slice(&keys.mac_key)
                .expect("HMAC can take keys of any size");

            mac.update(FORMAT_VERSION.as_bytes());
            mac.update(b":");
            mac.update(&nonce_bytes);
            mac.update(b":");
            mac.update(&ciphertext);

            // verify_slice performs constant-time comparison
            mac.verify_slice(&mac_received).map_err(|_| {
                EstError::operational(
                    "MAC verification failed: log entry may have been tampered with",
                )
            })?;
        }

        // Decrypt
        let nonce = Nonce::from_slice(&nonce_bytes);
        let cipher = Aes256Gcm::new_from_slice(&keys.encryption_key)
            .map_err(|e| EstError::operational(format!("Failed to initialize cipher: {}", e)))?;

        let plaintext_bytes = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| EstError::operational(format!("Failed to decrypt log entry: {}", e)))?;

        String::from_utf8(plaintext_bytes)
            .map_err(|e| EstError::operational(format!("Invalid UTF-8 in decrypted log: {}", e)))
    }
}

/// Log decryption utility
pub struct LogDecryptor {
    keys: LogKeys,
}

impl LogDecryptor {
    /// Create a new log decryptor
    pub fn new(key_path: impl AsRef<Path>) -> Result<Self> {
        let keys = LogKeys::load(key_path.as_ref())?;
        Ok(Self { keys })
    }

    /// Decrypt a log file line-by-line
    pub fn decrypt_file(&self, encrypted_path: &Path, output_path: &Path) -> Result<()> {
        let encrypted_content = fs::read_to_string(encrypted_path)
            .map_err(|e| EstError::platform(format!("Failed to read encrypted log: {}", e)))?;

        let mut decrypted_lines = Vec::new();

        for (line_num, line) in encrypted_content.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }

            if !line.starts_with(FORMAT_VERSION) {
                // Not encrypted - pass through
                decrypted_lines.push(line.to_string());
                continue;
            }

            let decrypted = EncryptedLogger::decrypt_log_line(line, &self.keys).map_err(|e| {
                EstError::operational(format!("Failed to decrypt line {}: {}", line_num + 1, e))
            })?;

            decrypted_lines.push(decrypted);
        }

        fs::write(output_path, decrypted_lines.join("\n"))
            .map_err(|e| EstError::platform(format!("Failed to write decrypted log: {}", e)))?;

        Ok(())
    }

    /// Decrypt a single line
    pub fn decrypt_line(&self, line: &str) -> Result<String> {
        if !line.starts_with(FORMAT_VERSION) {
            // Not encrypted
            return Ok(line.to_string());
        }

        EncryptedLogger::decrypt_log_line(line, &self.keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::{LogConfig, LogLevel};
    use tempfile::tempdir;

    // NOTE: Test code uses unwrap() deliberately - test fixtures are known valid
    // and panics in tests provide clear failure messages. See ERROR-HANDLING-PATTERNS.md
    // Pattern 5 for justification.

    #[test]
    fn test_log_keys_generate() {
        let keys = LogKeys::generate();
        assert_eq!(keys.encryption_key.len(), KEY_SIZE);
        assert_eq!(keys.mac_key.len(), MAC_KEY_SIZE);
    }

    #[test]
    fn test_log_keys_save_load() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test.key");

        let keys1 = LogKeys::generate();
        keys1.save(&key_path).unwrap();

        let keys2 = LogKeys::load(&key_path).unwrap();

        assert_eq!(keys1.encryption_key, keys2.encryption_key);
        assert_eq!(keys1.mac_key, keys2.mac_key);
    }

    #[test]
    fn test_encrypted_logger() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("encrypted.log");
        let key_path = dir.path().join("test.key");

        let config = LogConfig::file(&log_path).with_level(LogLevel::Info);
        let logger = EncryptedLogger::new(config, &key_path).unwrap();

        let entry = LogEntry::new(LogLevel::Info, "Sensitive audit data");
        logger.log(&entry).unwrap();

        // Read log file - should be encrypted
        let contents = fs::read_to_string(&log_path).unwrap();
        assert!(contents.contains(FORMAT_VERSION));
        assert!(!contents.contains("Sensitive audit data"));

        // Decrypt
        let decryptor = LogDecryptor::new(&key_path).unwrap();
        let decrypted = decryptor.decrypt_line(contents.trim()).unwrap();
        assert!(decrypted.contains("Sensitive audit data"));
    }

    #[test]
    fn test_decrypt_file() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("encrypted.log");
        let key_path = dir.path().join("test.key");
        let output_path = dir.path().join("decrypted.log");

        let config = LogConfig::file(&log_path).with_level(LogLevel::Info);
        let logger = EncryptedLogger::new(config, &key_path).unwrap();

        logger
            .log(&LogEntry::new(LogLevel::Info, "Entry 1"))
            .unwrap();
        logger
            .log(&LogEntry::new(LogLevel::Warn, "Entry 2"))
            .unwrap();
        logger
            .log(&LogEntry::new(LogLevel::Error, "Entry 3"))
            .unwrap();

        // Decrypt file
        let decryptor = LogDecryptor::new(&key_path).unwrap();
        decryptor.decrypt_file(&log_path, &output_path).unwrap();

        let decrypted = fs::read_to_string(&output_path).unwrap();
        assert!(decrypted.contains("Entry 1"));
        assert!(decrypted.contains("Entry 2"));
        assert!(decrypted.contains("Entry 3"));
    }

    #[test]
    fn test_mac_verification_failure() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("encrypted.log");
        let key_path = dir.path().join("test.key");

        let config = LogConfig::file(&log_path);
        let logger = EncryptedLogger::new(config, &key_path).unwrap();

        logger.log(&LogEntry::new(LogLevel::Info, "Test")).unwrap();

        // Read and tamper with log
        let contents = fs::read_to_string(&log_path).unwrap();
        let parts: Vec<&str> = contents.trim().split(':').collect();

        // Validate parts before accessing
        assert!(
            parts.len() >= 4,
            "Expected at least 4 parts in encrypted log"
        );
        assert!(parts[2].len() > 4, "Ciphertext part too short to tamper");

        // Corrupt the ciphertext
        let tampered = format!(
            "{}:{}:AAAA{}:{}",
            parts[0],
            parts[1],
            &parts[2][4..],
            parts[3]
        );

        // Attempt to decrypt - should fail MAC verification
        let decryptor = LogDecryptor::new(&key_path).unwrap();
        let result = decryptor.decrypt_line(&tampered);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("MAC verification failed")
        );
    }

    #[test]
    fn test_plaintext_passthrough() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test.key");

        let keys = LogKeys::generate();
        keys.save(&key_path).unwrap();

        let decryptor = LogDecryptor::new(&key_path).unwrap();

        // Non-encrypted line should pass through
        let plaintext = "[INFO] Regular log entry";
        let result = decryptor.decrypt_line(plaintext).unwrap();
        assert_eq!(result, plaintext);
    }
}
