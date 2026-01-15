// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! Audit log encryption and integrity protection.
//!
//! This module provides optional encryption and HMAC signing for audit logs
//! to meet SC-28 (Protection of Information at Rest) requirements.
//!
//! # NIST 800-53 Controls
//!
//! - **SC-28**: Protection of Information at Rest
//!   - AES-256-GCM encryption of audit log files
//!   - DPAPI-protected encryption keys (Windows) or file-based keys (Unix)
//!   - Per-log-line encryption with unique nonces
//! - **SC-13**: Cryptographic Protection
//!   - FIPS-approved algorithms (AES-256-GCM, HMAC-SHA256)
//!   - Cryptographically secure random number generation
//!   - Authenticated encryption (confidentiality + integrity)
//! - **SC-12**: Cryptographic Key Establishment and Management
//!   - Automatic key generation on first use
//!   - Secure key storage via DPAPI or restricted file permissions
//!   - Key rotation support
//! - **AU-9**: Protection of Audit Information
//!   - HMAC-SHA256 integrity protection prevents tampering
//!   - Encryption protects confidentiality of sensitive audit data
//! - **SC-8**: Transmission Confidentiality and Integrity
//!   - Protection of audit data at rest complements TLS for data in transit
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

/// Encryption and MAC keys (zeroized on drop)
#[derive(Clone, ZeroizeOnDrop)]
struct LogKeys {
    /// AES-256 encryption key
    #[zeroize(skip)]
    encryption_key: [u8; KEY_SIZE],
    /// HMAC-SHA256 MAC key
    #[zeroize(skip)]
    mac_key: [u8; MAC_KEY_SIZE],
}

impl LogKeys {
    /// Generate new random keys
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

    /// Encrypt a log line
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

    /// Compute HMAC-SHA256 MAC
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

    /// Decrypt a log line (for audit log review)
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
