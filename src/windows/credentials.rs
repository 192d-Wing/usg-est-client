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

//! Secure credential storage for Windows.
//!
//! This module provides secure credential management using:
//!
//! - **Windows Credential Manager**: Store and retrieve credentials securely
//! - **DPAPI**: Encrypt sensitive data using Windows Data Protection API
//! - **Environment Variables**: Support for container/CI environments
//!
//! # NIST 800-53 Controls
//!
//! - **IA-5**: Authenticator Management
//!   - Secure storage of authentication credentials (passwords, tokens)
//!   - DPAPI encryption of credential material
//!   - Credential lifecycle management (store, retrieve, delete)
//! - **IA-7**: Cryptographic Module Authentication
//!   - Integration with Windows Credential Manager for secure storage
//!   - DPAPI-based encryption of sensitive authentication data
//! - **AC-2**: Account Management
//!   - Per-target credential storage and retrieval
//!   - Isolation of credentials by target name
//! - **SC-28**: Protection of Information at Rest
//!   - DPAPI encryption of stored credentials
//!   - Windows Credential Manager secure storage backend
//!
//! # Security Features
//!
//! - Credentials are never logged or written to disk in plaintext
//! - DPAPI encryption is tied to the current user or machine
//! - Credential Manager provides system-level credential isolation
//!
//! # Example
//!
//! ```no_run,ignore
//! use usg_est_client::windows::credentials::{CredentialManager, CredentialType};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let manager = CredentialManager::new();
//!
//! // Store a credential
//! manager.store("EST-Server", "username", "password", CredentialType::Generic)?;
//!
//! // Retrieve a credential
//! if let Some(cred) = manager.get("EST-Server")? {
//!     println!("Username: {}", cred.username);
//!     // Password is available but should not be logged
//! }
//!
//! // Delete a credential
//! manager.delete("EST-Server")?;
//! # Ok(())
//! # }
//! ```

use crate::error::{EstError, Result};

/// Credential type for Windows Credential Manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialType {
    /// Generic credential (CRED_TYPE_GENERIC).
    Generic,
    /// Domain password credential (CRED_TYPE_DOMAIN_PASSWORD).
    DomainPassword,
    /// Certificate credential (CRED_TYPE_CERTIFICATE).
    Certificate,
}

impl CredentialType {
    /// Get the Windows CRED_TYPE value.
    #[cfg(windows)]
    fn to_cred_type(&self) -> u32 {
        match self {
            Self::Generic => 1,        // CRED_TYPE_GENERIC
            Self::DomainPassword => 2, // CRED_TYPE_DOMAIN_PASSWORD
            Self::Certificate => 3,    // CRED_TYPE_CERTIFICATE
        }
    }
}

/// A stored credential.
#[derive(Debug, Clone)]
pub struct StoredCredential {
    /// Target name (identifier).
    pub target: String,
    /// Username.
    pub username: String,
    /// Password or secret (sensitive - avoid logging).
    password: String,
    /// Credential type.
    pub credential_type: CredentialType,
    /// Comment/description.
    pub comment: Option<String>,
}

impl StoredCredential {
    /// Get the password. Use with care - avoid logging.
    pub fn password(&self) -> &str {
        &self.password
    }

    /// Create a new credential.
    pub fn new(
        target: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
        credential_type: CredentialType,
    ) -> Self {
        Self {
            target: target.into(),
            username: username.into(),
            password: password.into(),
            credential_type,
            comment: None,
        }
    }

    /// Set a comment.
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }
}

/// Windows Credential Manager interface.
pub struct CredentialManager {
    /// Prefix for credential target names.
    prefix: String,
}

impl Default for CredentialManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialManager {
    /// Create a new credential manager with default prefix.
    pub fn new() -> Self {
        Self {
            prefix: "EST-AutoEnroll".to_string(),
        }
    }

    /// Create a credential manager with a custom prefix.
    pub fn with_prefix(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
        }
    }

    /// Get the full target name with prefix.
    fn full_target(&self, target: &str) -> String {
        format!("{}:{}", self.prefix, target)
    }

    /// Store a credential in Windows Credential Manager.
    #[cfg(windows)]
    pub fn store(
        &self,
        target: &str,
        username: &str,
        password: &str,
        credential_type: CredentialType,
    ) -> Result<()> {
        use std::ptr;
        use windows::Win32::Security::Credentials::{
            CRED_PERSIST_LOCAL_MACHINE, CREDENTIALW, CredWriteW,
        };
        use windows::core::PCWSTR;

        let full_target = self.full_target(target);
        let target_wide: Vec<u16> = full_target
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let username_wide: Vec<u16> = username.encode_utf16().chain(std::iter::once(0)).collect();
        let password_bytes = password.as_bytes();

        let mut credential = CREDENTIALW {
            Flags: 0,
            Type: credential_type.to_cred_type(),
            TargetName: PCWSTR(target_wide.as_ptr()),
            Comment: PCWSTR(ptr::null()),
            LastWritten: Default::default(),
            CredentialBlobSize: password_bytes.len() as u32,
            CredentialBlob: password_bytes.as_ptr() as *mut u8,
            Persist: CRED_PERSIST_LOCAL_MACHINE.0,
            AttributeCount: 0,
            Attributes: ptr::null_mut(),
            TargetAlias: PCWSTR(ptr::null()),
            UserName: PCWSTR(username_wide.as_ptr()),
        };

        unsafe {
            CredWriteW(&mut credential, 0)
                .map_err(|e| EstError::platform(format!("Failed to store credential: {}", e)))?;
        }

        tracing::debug!("Stored credential for target: {}", target);
        Ok(())
    }

    /// Store a credential (non-Windows stub).
    #[cfg(not(windows))]
    pub fn store(
        &self,
        _target: &str,
        _username: &str,
        _password: &str,
        _credential_type: CredentialType,
    ) -> Result<()> {
        Err(EstError::platform("Credential Manager requires Windows"))
    }

    /// Retrieve a credential from Windows Credential Manager.
    #[cfg(windows)]
    pub fn get(&self, target: &str) -> Result<Option<StoredCredential>> {
        use std::slice;
        use windows::Win32::Security::Credentials::{CREDENTIALW, CredFree, CredReadW};
        use windows::core::PCWSTR;

        let full_target = self.full_target(target);
        let target_wide: Vec<u16> = full_target
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut cred_ptr: *mut CREDENTIALW = std::ptr::null_mut();

        unsafe {
            // Try generic credential first
            let result = CredReadW(
                PCWSTR(target_wide.as_ptr()),
                1, // CRED_TYPE_GENERIC
                0,
                &mut cred_ptr,
            );

            if result.is_err() {
                // Credential not found is not an error
                return Ok(None);
            }

            if cred_ptr.is_null() {
                // CredReadW should set cred_ptr on success,
                // but if it does not, treat as if no credential was found.
                return Ok(None);
            }

            let cred = &*cred_ptr;

            // Extract username
            let username = if cred.UserName.is_null() {
                String::new()
            } else {
                let mut len = 0;
                let mut ptr = cred.UserName.0;
                while *ptr != 0 {
                    len += 1;
                    ptr = ptr.add(1);
                }
                String::from_utf16_lossy(slice::from_raw_parts(cred.UserName.0, len))
            };

            // Extract password
            let password = if cred.CredentialBlob.is_null() || cred.CredentialBlobSize == 0 {
                String::new()
            } else {
                let blob =
                    slice::from_raw_parts(cred.CredentialBlob, cred.CredentialBlobSize as usize);
                String::from_utf8_lossy(blob).to_string()
            };

            // Extract comment
            let comment = if cred.Comment.is_null() {
                None
            } else {
                let mut len = 0;
                let mut ptr = cred.Comment.0;
                while *ptr != 0 {
                    len += 1;
                    ptr = ptr.add(1);
                }
                Some(String::from_utf16_lossy(slice::from_raw_parts(
                    cred.Comment.0,
                    len,
                )))
            };

            CredFree(cred_ptr as *mut _);

            Ok(Some(StoredCredential {
                target: target.to_string(),
                username,
                password,
                credential_type: CredentialType::Generic,
                comment,
            }))
        }
    }

    /// Retrieve a credential (non-Windows stub).
    #[cfg(not(windows))]
    pub fn get(&self, _target: &str) -> Result<Option<StoredCredential>> {
        Err(EstError::platform("Credential Manager requires Windows"))
    }

    /// Delete a credential from Windows Credential Manager.
    #[cfg(windows)]
    pub fn delete(&self, target: &str) -> Result<()> {
        use windows::Win32::Security::Credentials::CredDeleteW;
        use windows::core::PCWSTR;

        let full_target = self.full_target(target);
        let target_wide: Vec<u16> = full_target
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            CredDeleteW(
                PCWSTR(target_wide.as_ptr()),
                1, // CRED_TYPE_GENERIC
                0,
            )
            .map_err(|e| EstError::platform(format!("Failed to delete credential: {}", e)))?;
        }

        tracing::debug!("Deleted credential for target: {}", target);
        Ok(())
    }

    /// Delete a credential (non-Windows stub).
    #[cfg(not(windows))]
    pub fn delete(&self, _target: &str) -> Result<()> {
        Err(EstError::platform("Credential Manager requires Windows"))
    }

    /// Check if a credential exists.
    pub fn exists(&self, target: &str) -> Result<bool> {
        Ok(self.get(target)?.is_some())
    }
}

/// DPAPI (Data Protection API) encryption for Windows.
///
/// DPAPI provides encryption tied to the current user or machine,
/// making it suitable for protecting secrets in configuration files.
pub struct Dpapi {
    /// Use machine-level protection instead of user-level.
    machine_scope: bool,
}

impl Default for Dpapi {
    fn default() -> Self {
        Self::new()
    }
}

impl Dpapi {
    /// Create a new DPAPI instance with user-level protection.
    pub fn new() -> Self {
        Self {
            machine_scope: false,
        }
    }

    /// Create a DPAPI instance with machine-level protection.
    ///
    /// Machine-level protection allows any user on the machine to decrypt.
    /// Use with caution in multi-user environments.
    pub fn machine_scope() -> Self {
        Self {
            machine_scope: true,
        }
    }

    /// Encrypt data using DPAPI.
    #[cfg(windows)]
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        use std::ptr;
        use windows::Win32::Security::Cryptography::{
            CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CryptProtectData,
        };

        let mut input_blob = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };

        let mut output_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };

        let flags = if self.machine_scope {
            CRYPTPROTECT_LOCAL_MACHINE
        } else {
            Default::default()
        };

        unsafe {
            CryptProtectData(
                &mut input_blob,
                None,
                None,
                None,
                None,
                flags,
                &mut output_blob,
            )
            .map_err(|e| EstError::platform(format!("DPAPI encrypt failed: {}", e)))?;

            let result =
                std::slice::from_raw_parts(output_blob.pbData, output_blob.cbData as usize)
                    .to_vec();

            // Free the output buffer
            windows::Win32::System::Memory::LocalFree(windows::Win32::Foundation::HLOCAL(
                output_blob.pbData as *mut _,
            ));

            Ok(result)
        }
    }

    /// Encrypt data (non-Windows stub).
    #[cfg(not(windows))]
    pub fn encrypt(&self, _data: &[u8]) -> Result<Vec<u8>> {
        Err(EstError::platform("DPAPI requires Windows"))
    }

    /// Decrypt data using DPAPI.
    #[cfg(windows)]
    pub fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        use std::ptr;
        use windows::Win32::Security::Cryptography::{CRYPT_INTEGER_BLOB, CryptUnprotectData};

        let mut input_blob = CRYPT_INTEGER_BLOB {
            cbData: encrypted.len() as u32,
            pbData: encrypted.as_ptr() as *mut u8,
        };

        let mut output_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };

        unsafe {
            CryptUnprotectData(
                &mut input_blob,
                None,
                None,
                None,
                None,
                Default::default(),
                &mut output_blob,
            )
            .map_err(|e| EstError::platform(format!("DPAPI decrypt failed: {}", e)))?;

            let result =
                std::slice::from_raw_parts(output_blob.pbData, output_blob.cbData as usize)
                    .to_vec();

            // Free the output buffer
            windows::Win32::System::Memory::LocalFree(windows::Win32::Foundation::HLOCAL(
                output_blob.pbData as *mut _,
            ));

            Ok(result)
        }
    }

    /// Decrypt data (non-Windows stub).
    #[cfg(not(windows))]
    pub fn decrypt(&self, _encrypted: &[u8]) -> Result<Vec<u8>> {
        Err(EstError::platform("DPAPI requires Windows"))
    }

    /// Encrypt a string and return base64-encoded result.
    pub fn encrypt_string(&self, data: &str) -> Result<String> {
        let encrypted = self.encrypt(data.as_bytes())?;
        Ok(base64::prelude::BASE64_STANDARD.encode(&encrypted))
    }

    /// Decrypt a base64-encoded string.
    pub fn decrypt_string(&self, encrypted_base64: &str) -> Result<String> {
        let encrypted = base64::prelude::BASE64_STANDARD
            .decode(encrypted_base64)
            .map_err(|e| EstError::platform(format!("Invalid base64: {}", e)))?;
        let decrypted = self.decrypt(&encrypted)?;
        String::from_utf8(decrypted)
            .map_err(|e| EstError::platform(format!("Invalid UTF-8: {}", e)))
    }
}

/// Credential source for configuration.
#[derive(Debug, Clone)]
pub enum CredentialSource {
    /// Direct value (not recommended for production).
    Direct(String),
    /// Environment variable.
    Environment(String),
    /// File containing the secret.
    File(std::path::PathBuf),
    /// Windows Credential Manager.
    CredentialManager(String),
    /// DPAPI-encrypted base64 string.
    DpapiEncrypted(String),
}

impl CredentialSource {
    /// Parse a credential source string.
    ///
    /// Formats:
    /// - `env:VAR_NAME` - Environment variable
    /// - `file:/path/to/secret` - File containing secret
    /// - `credential_manager:target` - Windows Credential Manager
    /// - `dpapi:base64data` - DPAPI-encrypted base64
    /// - `raw_value` - Direct value (not recommended)
    pub fn parse(s: &str) -> Self {
        if let Some(var) = s.strip_prefix("env:") {
            Self::Environment(var.to_string())
        } else if let Some(path) = s.strip_prefix("file:") {
            Self::File(std::path::PathBuf::from(path))
        } else if let Some(target) = s.strip_prefix("credential_manager:") {
            Self::CredentialManager(target.to_string())
        } else if let Some(data) = s.strip_prefix("dpapi:") {
            Self::DpapiEncrypted(data.to_string())
        } else {
            Self::Direct(s.to_string())
        }
    }

    /// Resolve the credential to its actual value.
    pub fn resolve(&self) -> Result<String> {
        match self {
            Self::Direct(value) => Ok(value.clone()),
            Self::Environment(var) => std::env::var(var)
                .map_err(|_| EstError::platform(format!("Environment variable {} not set", var))),
            Self::File(path) => std::fs::read_to_string(path)
                .map(|s| s.trim().to_string())
                .map_err(EstError::Io),
            Self::CredentialManager(target) => {
                let manager = CredentialManager::new();
                manager
                    .get(target)?
                    .map(|c| c.password().to_string())
                    .ok_or_else(|| EstError::platform(format!("Credential {} not found", target)))
            }
            Self::DpapiEncrypted(data) => {
                let dpapi = Dpapi::new();
                dpapi.decrypt_string(data)
            }
        }
    }

    /// Check if this is a secure storage method.
    pub fn is_secure(&self) -> bool {
        !matches!(self, Self::Direct(_))
    }
}

/// Secure string wrapper that prevents accidental logging.
///
/// This type intentionally does not implement Display or Debug
/// to prevent credentials from being accidentally logged.
pub struct SecureString {
    value: String,
}

impl SecureString {
    /// Create a new secure string.
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
        }
    }

    /// Get the value. Use with care.
    pub fn expose(&self) -> &str {
        &self.value
    }

    /// Get the length without exposing the value.
    pub fn len(&self) -> usize {
        self.value.len()
    }

    /// Check if empty without exposing the value.
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        // Zero out the memory (best effort)
        // Note: This may not be fully effective due to compiler optimizations
        // and the String's internal buffer management
        unsafe {
            let bytes = self.value.as_bytes_mut();
            std::ptr::write_bytes(bytes.as_mut_ptr(), 0, bytes.len());
        }
    }
}

impl From<String> for SecureString {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for SecureString {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

// Intentionally no Debug or Display implementation

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_type() {
        assert_eq!(CredentialType::Generic, CredentialType::Generic);
        assert_ne!(CredentialType::Generic, CredentialType::Certificate);
    }

    #[test]
    fn test_stored_credential() {
        let cred = StoredCredential::new("target", "user", "pass", CredentialType::Generic)
            .with_comment("Test credential");

        assert_eq!(cred.target, "target");
        assert_eq!(cred.username, "user");
        assert_eq!(cred.password(), "pass");
        assert_eq!(cred.comment, Some("Test credential".to_string()));
    }

    #[test]
    fn test_credential_manager_prefix() {
        let manager = CredentialManager::new();
        assert_eq!(manager.full_target("test"), "EST-AutoEnroll:test");

        let custom = CredentialManager::with_prefix("Custom");
        assert_eq!(custom.full_target("test"), "Custom:test");
    }

    #[test]
    fn test_credential_source_parse() {
        match CredentialSource::parse("env:MY_VAR") {
            CredentialSource::Environment(var) => assert_eq!(var, "MY_VAR"),
            _ => panic!("Expected Environment"),
        }

        match CredentialSource::parse("file:/path/to/secret") {
            CredentialSource::File(path) => assert_eq!(path.to_str().unwrap(), "/path/to/secret"),
            _ => panic!("Expected File"),
        }

        match CredentialSource::parse("credential_manager:myapp") {
            CredentialSource::CredentialManager(target) => assert_eq!(target, "myapp"),
            _ => panic!("Expected CredentialManager"),
        }

        match CredentialSource::parse("dpapi:SGVsbG8=") {
            CredentialSource::DpapiEncrypted(data) => assert_eq!(data, "SGVsbG8="),
            _ => panic!("Expected DpapiEncrypted"),
        }

        match CredentialSource::parse("plaintext") {
            CredentialSource::Direct(value) => assert_eq!(value, "plaintext"),
            _ => panic!("Expected Direct"),
        }
    }

    #[test]
    fn test_credential_source_is_secure() {
        assert!(!CredentialSource::Direct("test".into()).is_secure());
        assert!(CredentialSource::Environment("VAR".into()).is_secure());
        assert!(CredentialSource::CredentialManager("target".into()).is_secure());
    }

    #[test]
    fn test_credential_source_resolve_env() {
        std::env::set_var("TEST_CRED_VAR", "secret_value");
        let source = CredentialSource::Environment("TEST_CRED_VAR".into());
        assert_eq!(source.resolve().unwrap(), "secret_value");
        std::env::remove_var("TEST_CRED_VAR");
    }

    #[test]
    fn test_secure_string() {
        let secret = SecureString::new("my_secret");
        assert_eq!(secret.expose(), "my_secret");
        assert_eq!(secret.len(), 9);
        assert!(!secret.is_empty());

        let empty = SecureString::new("");
        assert!(empty.is_empty());
    }

    #[test]
    fn test_secure_string_from() {
        let s1: SecureString = "test".into();
        assert_eq!(s1.expose(), "test");

        let s2: SecureString = String::from("test2").into();
        assert_eq!(s2.expose(), "test2");
    }
}
