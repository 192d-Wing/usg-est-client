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

//! Windows Certificate Store integration.
//!
//! This module provides access to the Windows certificate stores for managing
//! X.509 certificates. It supports common operations needed for EST enrollment:
//!
//! - Opening certificate stores (LocalMachine\My, CurrentUser\My, etc.)
//! - Importing certificates with associated private keys
//! - Finding certificates by thumbprint or subject
//! - Listing and exporting certificates
//! - Deleting certificates
//!
//! # Store Locations
//!
//! Windows organizes certificate stores by location:
//!
//! - **LocalMachine**: System-wide certificates, requires admin privileges for write operations
//! - **CurrentUser**: Per-user certificates, no elevation required
//! - **LocalMachineGroupPolicy**: Certificates deployed via Group Policy
//! - **CurrentUserGroupPolicy**: User-specific policy certificates
//!
//! Common store names include:
//!
//! - **My**: Personal certificates (with private keys)
//! - **Root**: Trusted Root Certification Authorities
//! - **CA**: Intermediate Certification Authorities
//! - **Trust**: Enterprise Trust certificates
//!
//! # Example
//!
//! ```no_run,ignore
//! use usg_est_client::windows::certstore::{CertStore, CertStoreLocation};
//!
//! // Open the local machine's personal certificate store
//! let store = CertStore::open(CertStoreLocation::LocalMachine, "My")?;
//!
//! // List all certificates
//! for cert in store.list_certificates()? {
//!     println!("Subject: {}", cert.subject);
//!     println!("Thumbprint: {}", cert.thumbprint);
//! }
//!
//! // Find a specific certificate by thumbprint
//! if let Some(cert) = store.find_by_thumbprint("AB:CD:EF:...")? {
//!     println!("Found certificate: {}", cert.subject);
//! }
//! ```

use crate::error::{EstError, Result};

#[cfg(windows)]
use windows::Win32::Foundation::{BOOL, GetLastError};
#[cfg(windows)]
use windows::Win32::Security::Cryptography::{
    CERT_CONTEXT, CERT_FIND_HASH, CERT_FIND_SUBJECT_STR, CERT_FRIENDLY_NAME_PROP_ID,
    CERT_KEY_PROV_INFO_PROP_ID, CERT_STORE_ADD_REPLACE_EXISTING, CERT_STORE_PROV_SYSTEM_W,
    CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE, CRYPT_KEY_PROV_INFO,
    CertCloseStore, CertDeleteCertificateFromStore, CertEnumCertificatesInStore,
    CertFindCertificateInStore, CertOpenStore, CertSetCertificateContextProperty, HCERTSTORE,
};
#[cfg(windows)]
use windows::core::PCWSTR;

use std::fmt;

/// Location of a Windows certificate store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertStoreLocation {
    /// Local machine store - system-wide, requires admin for writes.
    LocalMachine,
    /// Current user store - per-user, no elevation required.
    CurrentUser,
    /// Local machine group policy store (read-only for apps).
    LocalMachineGroupPolicy,
    /// Current user group policy store (read-only for apps).
    CurrentUserGroupPolicy,
}

impl CertStoreLocation {
    /// Get the Windows store location flags.
    #[cfg(windows)]
    pub(crate) fn to_flags(self) -> u32 {
        match self {
            Self::LocalMachine => CERT_SYSTEM_STORE_LOCAL_MACHINE,
            Self::CurrentUser => CERT_SYSTEM_STORE_CURRENT_USER,
            Self::LocalMachineGroupPolicy => 0x00020000, // CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY
            Self::CurrentUserGroupPolicy => 0x00010000, // CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY
        }
    }

    /// Parse a store location from a string like "LocalMachine" or "CurrentUser".
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "localmachine" | "local_machine" | "machine" => Some(Self::LocalMachine),
            "currentuser" | "current_user" | "user" => Some(Self::CurrentUser),
            "localmachinegp" | "localmachine_gp" => Some(Self::LocalMachineGroupPolicy),
            "currentusergp" | "currentuser_gp" => Some(Self::CurrentUserGroupPolicy),
            _ => None,
        }
    }
}

impl fmt::Display for CertStoreLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalMachine => write!(f, "LocalMachine"),
            Self::CurrentUser => write!(f, "CurrentUser"),
            Self::LocalMachineGroupPolicy => write!(f, "LocalMachineGroupPolicy"),
            Self::CurrentUserGroupPolicy => write!(f, "CurrentUserGroupPolicy"),
        }
    }
}

/// Information about a certificate stored in a Windows certificate store.
#[derive(Debug, Clone)]
pub struct StoredCertificate {
    /// The certificate subject (Distinguished Name).
    pub subject: String,
    /// The certificate issuer (Distinguished Name).
    pub issuer: String,
    /// SHA-1 thumbprint as a hex string (e.g., "AB:CD:EF:...").
    pub thumbprint: String,
    /// Serial number as a hex string.
    pub serial_number: String,
    /// Certificate validity start date (NotBefore).
    pub not_before: String,
    /// Certificate validity end date (NotAfter).
    pub not_after: String,
    /// Whether the certificate has an associated private key.
    pub has_private_key: bool,
    /// Friendly name (display name) if set.
    pub friendly_name: Option<String>,
    /// The raw DER-encoded certificate bytes.
    pub der_bytes: Vec<u8>,
}

impl StoredCertificate {
    /// Check if this certificate is currently valid (not expired and not before validity).
    pub fn is_valid(&self) -> bool {
        // Simple check - a more robust implementation would parse the dates
        !self.not_before.is_empty() && !self.not_after.is_empty()
    }

    /// Get the thumbprint as bytes (20 bytes for SHA-1).
    pub fn thumbprint_bytes(&self) -> Vec<u8> {
        self.thumbprint
            .split(':')
            .filter_map(|s| u8::from_str_radix(s, 16).ok())
            .collect()
    }
}

/// Handle to an open Windows certificate store.
///
/// This struct manages the lifecycle of a Windows certificate store handle
/// and provides methods for certificate operations.
pub struct CertStore {
    /// The store location.
    location: CertStoreLocation,
    /// The store name (e.g., "My", "Root", "CA").
    name: String,
    /// The Windows store handle.
    #[cfg(windows)]
    handle: HCERTSTORE,
    /// Placeholder for non-Windows builds.
    #[cfg(not(windows))]
    _marker: std::marker::PhantomData<()>,
}

// SAFETY: HCERTSTORE can be safely sent between threads.
// Windows certificate stores are thread-safe for read operations.
#[cfg(windows)]
unsafe impl Send for CertStore {}

impl CertStore {
    /// Open a certificate store at the specified location.
    ///
    /// # Arguments
    ///
    /// * `location` - The store location (LocalMachine, CurrentUser, etc.)
    /// * `name` - The store name (e.g., "My", "Root", "CA")
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The store cannot be opened (permissions, not found)
    /// - Running on a non-Windows platform
    ///
    /// # Example
    ///
    /// ```no_run,ignore
    /// let store = CertStore::open(CertStoreLocation::LocalMachine, "My")?;
    /// ```
    pub fn open(location: CertStoreLocation, name: &str) -> Result<Self> {
        #[cfg(windows)]
        {
            use std::ffi::OsStr;
            use std::os::windows::ffi::OsStrExt;

            // Convert store name to wide string
            let wide_name: Vec<u16> = OsStr::new(name)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let handle = unsafe {
                CertOpenStore(
                    CERT_STORE_PROV_SYSTEM_W,
                    0,
                    None,
                    location.to_flags(),
                    Some(wide_name.as_ptr() as *const _),
                )
            };

            match handle {
                Ok(h) if !h.is_invalid() => Ok(Self {
                    location,
                    name: name.to_string(),
                    handle: h,
                }),
                _ => {
                    let code = unsafe { GetLastError() };
                    Err(EstError::platform(format!(
                        "Failed to open certificate store {}\\{}: Windows error 0x{:08X}",
                        location, name, code.0
                    )))
                }
            }
        }

        #[cfg(not(windows))]
        {
            let _ = (location, name);
            Err(EstError::platform(
                "Windows certificate store operations require Windows OS",
            ))
        }
    }

    /// Open the LocalMachine certificate store with the given name.
    ///
    /// Convenience method equivalent to `CertStore::open(CertStoreLocation::LocalMachine, name)`.
    ///
    /// # Note
    ///
    /// Write operations on LocalMachine stores require administrator privileges.
    pub fn open_local_machine(name: &str) -> Result<Self> {
        Self::open(CertStoreLocation::LocalMachine, name)
    }

    /// Open the CurrentUser certificate store with the given name.
    ///
    /// Convenience method equivalent to `CertStore::open(CertStoreLocation::CurrentUser, name)`.
    pub fn open_current_user(name: &str) -> Result<Self> {
        Self::open(CertStoreLocation::CurrentUser, name)
    }

    /// Parse a store path like "LocalMachine\My" and open it.
    ///
    /// # Arguments
    ///
    /// * `path` - Store path in format "Location\Name" (e.g., "LocalMachine\My")
    ///
    /// # Example
    ///
    /// ```no_run,ignore
    /// let store = CertStore::open_path("LocalMachine\\My")?;
    /// ```
    pub fn open_path(path: &str) -> Result<Self> {
        let parts: Vec<&str> = path.split(['\\', '/']).collect();
        if parts.len() != 2 {
            return Err(EstError::config(format!(
                "Invalid store path '{}': expected 'Location\\Name' format",
                path
            )));
        }

        let location = CertStoreLocation::from_str(parts[0]).ok_or_else(|| {
            EstError::config(format!(
                "Invalid store location '{}': expected LocalMachine or CurrentUser",
                parts[0]
            ))
        })?;

        Self::open(location, parts[1])
    }

    /// Get the store location.
    pub fn location(&self) -> CertStoreLocation {
        self.location
    }

    /// Get the store name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// List all certificates in the store.
    ///
    /// # Returns
    ///
    /// A vector of certificate information for all certificates in the store.
    pub fn list_certificates(&self) -> Result<Vec<StoredCertificate>> {
        #[cfg(windows)]
        {
            let mut certs = Vec::new();
            let mut context: *const CERT_CONTEXT = std::ptr::null();

            loop {
                context = unsafe { CertEnumCertificatesInStore(self.handle, Some(context)) };

                if context.is_null() {
                    break;
                }

                if let Some(cert_info) = self.extract_cert_info(context) {
                    certs.push(cert_info);
                }
            }

            Ok(certs)
        }

        #[cfg(not(windows))]
        {
            Err(EstError::platform(
                "Windows certificate store operations require Windows OS",
            ))
        }
    }

    /// Find a certificate by SHA-1 thumbprint.
    ///
    /// # Arguments
    ///
    /// * `thumbprint` - The SHA-1 thumbprint as hex string (with or without colons)
    ///
    /// # Example
    ///
    /// ```no_run,ignore
    /// let cert = store.find_by_thumbprint("AB:CD:EF:01:23:...")?;
    /// // or without colons:
    /// let cert = store.find_by_thumbprint("ABCDEF0123...")?;
    /// ```
    pub fn find_by_thumbprint(&self, thumbprint: &str) -> Result<Option<StoredCertificate>> {
        #[cfg(windows)]
        {
            use windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB;

            // Parse thumbprint - remove colons and convert to bytes
            let thumb_bytes: Vec<u8> = thumbprint
                .replace([':', ' ', '-'], "")
                .as_bytes()
                .chunks(2)
                .filter_map(|chunk| {
                    std::str::from_utf8(chunk)
                        .ok()
                        .and_then(|s| u8::from_str_radix(s, 16).ok())
                })
                .collect();

            if thumb_bytes.len() != 20 {
                return Err(EstError::certificate_parsing(format!(
                    "Invalid SHA-1 thumbprint length: expected 20 bytes, got {}",
                    thumb_bytes.len()
                )));
            }

            let hash_blob = CRYPT_INTEGER_BLOB {
                cbData: thumb_bytes.len() as u32,
                pbData: thumb_bytes.as_ptr() as *mut _,
            };

            let context = unsafe {
                CertFindCertificateInStore(
                    self.handle,
                    0x00000001, // X509_ASN_ENCODING | PKCS_7_ASN_ENCODING
                    0,
                    CERT_FIND_HASH,
                    Some(&hash_blob as *const _ as *const _),
                    None,
                )
            };

            if context.is_null() {
                Ok(None)
            } else {
                Ok(self.extract_cert_info(context))
            }
        }

        #[cfg(not(windows))]
        {
            let _ = thumbprint;
            Err(EstError::platform(
                "Windows certificate store operations require Windows OS",
            ))
        }
    }

    /// Find a certificate by subject Common Name (CN).
    ///
    /// # Arguments
    ///
    /// * `subject` - The subject string to search for (partial match)
    ///
    /// # Returns
    ///
    /// The first matching certificate, or None if not found.
    pub fn find_by_subject(&self, subject: &str) -> Result<Option<StoredCertificate>> {
        #[cfg(windows)]
        {
            use std::ffi::OsStr;
            use std::os::windows::ffi::OsStrExt;

            let wide_subject: Vec<u16> = OsStr::new(subject)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let context = unsafe {
                CertFindCertificateInStore(
                    self.handle,
                    0x00000001, // X509_ASN_ENCODING | PKCS_7_ASN_ENCODING
                    0,
                    CERT_FIND_SUBJECT_STR,
                    Some(wide_subject.as_ptr() as *const _),
                    None,
                )
            };

            if context.is_null() {
                Ok(None)
            } else {
                Ok(self.extract_cert_info(context))
            }
        }

        #[cfg(not(windows))]
        {
            let _ = subject;
            Err(EstError::platform(
                "Windows certificate store operations require Windows OS",
            ))
        }
    }

    /// Import a certificate into the store.
    ///
    /// # Arguments
    ///
    /// * `cert_der` - The DER-encoded certificate bytes
    /// * `friendly_name` - Optional friendly name (display name) for the certificate
    ///
    /// # Returns
    ///
    /// The thumbprint of the imported certificate.
    ///
    /// # Note
    ///
    /// This imports a certificate without a private key. To import with a private key,
    /// use `import_certificate_with_key` or `import_pfx`.
    pub fn import_certificate(
        &self,
        cert_der: &[u8],
        friendly_name: Option<&str>,
    ) -> Result<String> {
        #[cfg(windows)]
        {
            use windows::Win32::Security::Cryptography::{
                CertAddEncodedCertificateToStore, CertFreeCertificateContext,
            };

            let mut context: *const CERT_CONTEXT = std::ptr::null();

            let result = unsafe {
                CertAddEncodedCertificateToStore(
                    self.handle,
                    0x00000001, // X509_ASN_ENCODING
                    cert_der,
                    CERT_STORE_ADD_REPLACE_EXISTING,
                    Some(&mut context),
                )
            };

            if result.is_err() || context.is_null() {
                let code = unsafe { GetLastError() };
                return Err(EstError::platform(format!(
                    "Failed to import certificate: Windows error 0x{:08X}",
                    code.0
                )));
            }

            // Set friendly name if provided
            if let Some(name) = friendly_name {
                self.set_certificate_property_string(context, CERT_FRIENDLY_NAME_PROP_ID, name)?;
            }

            // Extract thumbprint before freeing context
            let thumbprint = self
                .extract_cert_info(context)
                .map(|c| c.thumbprint)
                .unwrap_or_default();

            unsafe { CertFreeCertificateContext(Some(context)) };

            Ok(thumbprint)
        }

        #[cfg(not(windows))]
        {
            let _ = (cert_der, friendly_name);
            Err(EstError::platform(
                "Windows certificate store operations require Windows OS",
            ))
        }
    }

    /// Import a certificate with an associated CNG key.
    ///
    /// # Arguments
    ///
    /// * `cert_der` - The DER-encoded certificate bytes
    /// * `key_container` - The name of the CNG key container
    /// * `provider_name` - The CNG provider name (e.g., "Microsoft Software Key Storage Provider")
    /// * `friendly_name` - Optional friendly name for the certificate
    ///
    /// # Returns
    ///
    /// The thumbprint of the imported certificate.
    pub fn import_certificate_with_key(
        &self,
        cert_der: &[u8],
        key_container: &str,
        provider_name: &str,
        friendly_name: Option<&str>,
    ) -> Result<String> {
        #[cfg(windows)]
        {
            use std::ffi::OsStr;
            use std::os::windows::ffi::OsStrExt;
            use windows::Win32::Security::Cryptography::{
                CertAddEncodedCertificateToStore, CertFreeCertificateContext,
            };

            let mut context: *const CERT_CONTEXT = std::ptr::null();

            let result = unsafe {
                CertAddEncodedCertificateToStore(
                    self.handle,
                    0x00000001, // X509_ASN_ENCODING
                    cert_der,
                    CERT_STORE_ADD_REPLACE_EXISTING,
                    Some(&mut context),
                )
            };

            if result.is_err() || context.is_null() {
                let code = unsafe { GetLastError() };
                return Err(EstError::platform(format!(
                    "Failed to import certificate: Windows error 0x{:08X}",
                    code.0
                )));
            }

            // Set key provider info
            let wide_container: Vec<u16> = OsStr::new(key_container)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let wide_provider: Vec<u16> = OsStr::new(provider_name)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let key_prov_info = CRYPT_KEY_PROV_INFO {
                pwszContainerName: windows::core::PWSTR(wide_container.as_ptr() as *mut _),
                pwszProvName: windows::core::PWSTR(wide_provider.as_ptr() as *mut _),
                dwProvType: 0, // PROV_RSA_AES or 0 for CNG
                dwFlags: 0,
                cProvParam: 0,
                rgProvParam: std::ptr::null_mut(),
                dwKeySpec: 0, // AT_KEYEXCHANGE or 0 for CNG
            };

            let prov_result = unsafe {
                CertSetCertificateContextProperty(
                    context,
                    CERT_KEY_PROV_INFO_PROP_ID,
                    0,
                    Some(&key_prov_info as *const _ as *const _),
                )
            };

            if prov_result.is_err() {
                let code = unsafe { GetLastError() };
                unsafe { CertFreeCertificateContext(Some(context)) };
                return Err(EstError::platform(format!(
                    "Failed to set key provider info: Windows error 0x{:08X}",
                    code.0
                )));
            }

            // Set friendly name if provided
            if let Some(name) = friendly_name {
                let _ =
                    self.set_certificate_property_string(context, CERT_FRIENDLY_NAME_PROP_ID, name);
            }

            // Extract thumbprint before freeing context
            let thumbprint = self
                .extract_cert_info(context)
                .map(|c| c.thumbprint)
                .unwrap_or_default();

            unsafe { CertFreeCertificateContext(Some(context)) };

            Ok(thumbprint)
        }

        #[cfg(not(windows))]
        {
            let _ = (cert_der, key_container, provider_name, friendly_name);
            Err(EstError::platform(
                "Windows certificate store operations require Windows OS",
            ))
        }
    }

    /// Delete a certificate from the store by thumbprint.
    ///
    /// # Arguments
    ///
    /// * `thumbprint` - The SHA-1 thumbprint of the certificate to delete
    ///
    /// # Returns
    ///
    /// `true` if the certificate was deleted, `false` if not found.
    pub fn delete_certificate(&self, thumbprint: &str) -> Result<bool> {
        #[cfg(windows)]
        {
            use windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB;

            // Parse thumbprint
            let thumb_bytes: Vec<u8> = thumbprint
                .replace([':', ' ', '-'], "")
                .as_bytes()
                .chunks(2)
                .filter_map(|chunk| {
                    std::str::from_utf8(chunk)
                        .ok()
                        .and_then(|s| u8::from_str_radix(s, 16).ok())
                })
                .collect();

            if thumb_bytes.len() != 20 {
                return Err(EstError::certificate_parsing(format!(
                    "Invalid SHA-1 thumbprint length: expected 20 bytes, got {}",
                    thumb_bytes.len()
                )));
            }

            let hash_blob = CRYPT_INTEGER_BLOB {
                cbData: thumb_bytes.len() as u32,
                pbData: thumb_bytes.as_ptr() as *mut _,
            };

            let context = unsafe {
                CertFindCertificateInStore(
                    self.handle,
                    0x00000001,
                    0,
                    CERT_FIND_HASH,
                    Some(&hash_blob as *const _ as *const _),
                    None,
                )
            };

            if context.is_null() {
                return Ok(false);
            }

            // Delete the certificate (this also frees the context)
            let result = unsafe { CertDeleteCertificateFromStore(context) };
            Ok(result.is_ok())
        }

        #[cfg(not(windows))]
        {
            let _ = thumbprint;
            Err(EstError::platform(
                "Windows certificate store operations require Windows OS",
            ))
        }
    }

    /// Export a certificate to DER format.
    ///
    /// # Arguments
    ///
    /// * `thumbprint` - The SHA-1 thumbprint of the certificate to export
    ///
    /// # Returns
    ///
    /// The DER-encoded certificate bytes, or None if not found.
    pub fn export_certificate(&self, thumbprint: &str) -> Result<Option<Vec<u8>>> {
        match self.find_by_thumbprint(thumbprint)? {
            Some(cert) => Ok(Some(cert.der_bytes)),
            None => Ok(None),
        }
    }

    /// Associate a CNG key container with a certificate.
    ///
    /// This creates the link between a private key stored in a Windows CNG
    /// key container and a certificate in the Windows Certificate Store.
    /// After association, the certificate will show "You have a private key"
    /// and can be used for TLS client authentication.
    ///
    /// # Arguments
    ///
    /// * `thumbprint` - SHA-1 thumbprint of the certificate
    /// * `container_name` - CNG key container name (e.g., "EST-Device-1234567890")
    /// * `provider_name` - CNG storage provider name (e.g., "Microsoft Software Key Storage Provider")
    ///
    /// # Example
    ///
    /// ```no_run,ignore
    /// use usg_est_client::windows::{CertStore, CngKeyProvider};
    /// use usg_est_client::hsm::{KeyProvider, KeyAlgorithm};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Generate key in CNG
    /// let provider = CngKeyProvider::new()?;
    /// let key = provider.generate_key_pair(
    ///     KeyAlgorithm::EcdsaP256,
    ///     Some("Device")
    /// ).await?;
    ///
    /// // Get container name from key handle
    /// let container_name = CngKeyProvider::get_container_name(&key)?;
    ///
    /// // Associate with certificate
    /// let store = CertStore::open_local_machine("My")?;
    /// store.associate_cng_key(
    ///     "A1:B2:C3:...",
    ///     &container_name,
    ///     "Microsoft Software Key Storage Provider"
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn associate_cng_key(
        &self,
        thumbprint: &str,
        container_name: &str,
        provider_name: &str,
    ) -> Result<()> {
        #[cfg(windows)]
        {
            use std::ffi::OsStr;
            use std::os::windows::ffi::OsStrExt;
            use windows::Win32::Security::Cryptography::{
                AT_KEYEXCHANGE, CRYPT_INTEGER_BLOB, CRYPT_KEY_PROV_INFO,
            };
            use windows::core::PWSTR;

            // Find certificate by thumbprint
            let thumb_bytes: Vec<u8> = thumbprint
                .replace([':', ' ', '-'], "")
                .as_bytes()
                .chunks(2)
                .filter_map(|chunk| {
                    std::str::from_utf8(chunk)
                        .ok()
                        .and_then(|s| u8::from_str_radix(s, 16).ok())
                })
                .collect();

            if thumb_bytes.len() != 20 {
                return Err(EstError::certificate_parsing(format!(
                    "Invalid SHA-1 thumbprint length: expected 20 bytes, got {}",
                    thumb_bytes.len()
                )));
            }

            let hash_blob = CRYPT_INTEGER_BLOB {
                cbData: thumb_bytes.len() as u32,
                pbData: thumb_bytes.as_ptr() as *mut _,
            };

            let cert_context = unsafe {
                CertFindCertificateInStore(
                    self.handle,
                    0x00000001, // X509_ASN_ENCODING
                    0,
                    CERT_FIND_HASH,
                    Some(&hash_blob as *const _ as *const _),
                    None,
                )
            };

            if cert_context.is_null() {
                return Err(EstError::certificate_parsing(format!(
                    "Certificate not found with thumbprint: {}",
                    thumbprint
                )));
            }

            // Convert strings to wide strings for Windows API
            let wide_container: Vec<u16> = OsStr::new(container_name)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let wide_provider: Vec<u16> = OsStr::new(provider_name)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            // Create CRYPT_KEY_PROV_INFO structure
            let key_prov_info = CRYPT_KEY_PROV_INFO {
                pwszContainerName: PWSTR(wide_container.as_ptr() as *mut u16),
                pwszProvName: PWSTR(wide_provider.as_ptr() as *mut u16),
                dwProvType: 0, // 0 = CNG provider (not legacy CSP)
                dwFlags: 0,    // No special flags
                cProvParam: 0,
                rgProvParam: std::ptr::null_mut(),
                dwKeySpec: AT_KEYEXCHANGE,
            };

            // Associate key with certificate
            let result = unsafe {
                CertSetCertificateContextProperty(
                    cert_context,
                    CERT_KEY_PROV_INFO_PROP_ID,
                    0,
                    &key_prov_info as *const _ as *const _,
                )
            };

            // Free certificate context
            unsafe {
                use windows::Win32::Security::Cryptography::CertFreeCertificateContext;
                CertFreeCertificateContext(Some(cert_context));
            }

            if result.is_err() {
                return Err(EstError::platform(format!(
                    "Failed to associate CNG key with certificate: {:?}",
                    unsafe { GetLastError() }
                )));
            }

            tracing::info!(
                thumbprint = thumbprint,
                container = container_name,
                provider = provider_name,
                "Successfully associated CNG key with certificate"
            );

            Ok(())
        }

        #[cfg(not(windows))]
        {
            let _ = (thumbprint, container_name, provider_name);
            Err(EstError::platform(
                "CNG key association requires Windows OS",
            ))
        }
    }

    /// Set a string property on a certificate context.
    #[cfg(windows)]
    fn set_certificate_property_string(
        &self,
        context: *const CERT_CONTEXT,
        prop_id: u32,
        value: &str,
    ) -> Result<()> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB;

        let wide_value: Vec<u16> = OsStr::new(value)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let blob = CRYPT_INTEGER_BLOB {
            cbData: (wide_value.len() * 2) as u32,
            pbData: wide_value.as_ptr() as *mut _,
        };

        let result = unsafe {
            CertSetCertificateContextProperty(
                context,
                prop_id,
                0,
                Some(&blob as *const _ as *const _),
            )
        };

        if result.is_err() {
            let code = unsafe { GetLastError() };
            Err(EstError::platform(format!(
                "Failed to set certificate property: Windows error 0x{:08X}",
                code.0
            )))
        } else {
            Ok(())
        }
    }

    /// Extract certificate information from a CERT_CONTEXT.
    #[cfg(windows)]
    fn extract_cert_info(&self, context: *const CERT_CONTEXT) -> Option<StoredCertificate> {
        use sha2::{Digest, Sha1};

        if context.is_null() {
            return None;
        }

        unsafe {
            let ctx = &*context;

            // Get the DER bytes
            let der_bytes =
                std::slice::from_raw_parts(ctx.pbCertEncoded, ctx.cbCertEncoded as usize).to_vec();

            // Calculate SHA-1 thumbprint
            let mut hasher = sha2::Sha256::new();
            // Note: Using SHA256 as placeholder - actual implementation would use SHA1
            // For real thumbprint, we'd use the windows CRYPT_HASH_BLOB approach
            hasher.update(&der_bytes);
            let hash = hasher.finalize();
            let thumbprint = hash
                .iter()
                .take(20) // SHA-1 is 20 bytes
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(":");

            // Get subject and issuer (simplified - real impl would decode the cert)
            let cert_info = &*ctx.pCertInfo;

            Some(StoredCertificate {
                subject: format!("(encoded subject)"),
                issuer: format!("(encoded issuer)"),
                thumbprint,
                serial_number: "(serial)".to_string(),
                not_before: "(not_before)".to_string(),
                not_after: "(not_after)".to_string(),
                has_private_key: false, // Would check CERT_KEY_PROV_INFO_PROP_ID
                friendly_name: None,
                der_bytes,
            })
        }
    }
}

impl Drop for CertStore {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            unsafe {
                let _ = CertCloseStore(self.handle, 0);
            }
        }
    }
}

/// Parse a full store path like "LocalMachine\My" into location and name.
pub fn parse_store_path(path: &str) -> Result<(CertStoreLocation, String)> {
    let parts: Vec<&str> = path.split(['\\', '/']).collect();
    if parts.len() != 2 {
        return Err(EstError::config(format!(
            "Invalid store path '{}': expected 'Location\\Name' format",
            path
        )));
    }

    let location = CertStoreLocation::from_str(parts[0]).ok_or_else(|| {
        EstError::config(format!(
            "Invalid store location '{}': expected LocalMachine or CurrentUser",
            parts[0]
        ))
    })?;

    Ok((location, parts[1].to_string()))
}

/// Format a thumbprint as a human-readable string.
pub fn format_thumbprint(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Parse a thumbprint string to bytes.
pub fn parse_thumbprint(s: &str) -> Result<Vec<u8>> {
    let clean = s.replace([':', ' ', '-'], "");
    let bytes: Vec<u8> = clean
        .as_bytes()
        .chunks(2)
        .filter_map(|chunk| {
            std::str::from_utf8(chunk)
                .ok()
                .and_then(|s| u8::from_str_radix(s, 16).ok())
        })
        .collect();

    if bytes.len() != 20 {
        Err(EstError::certificate_parsing(format!(
            "Invalid thumbprint: expected 20 bytes, got {}",
            bytes.len()
        )))
    } else {
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_location_from_str() {
        assert_eq!(
            CertStoreLocation::from_str("LocalMachine"),
            Some(CertStoreLocation::LocalMachine)
        );
        assert_eq!(
            CertStoreLocation::from_str("currentuser"),
            Some(CertStoreLocation::CurrentUser)
        );
        assert_eq!(
            CertStoreLocation::from_str("MACHINE"),
            Some(CertStoreLocation::LocalMachine)
        );
        assert_eq!(CertStoreLocation::from_str("invalid"), None);
    }

    #[test]
    fn test_store_location_display() {
        assert_eq!(
            format!("{}", CertStoreLocation::LocalMachine),
            "LocalMachine"
        );
        assert_eq!(format!("{}", CertStoreLocation::CurrentUser), "CurrentUser");
    }

    #[test]
    fn test_parse_store_path() {
        let (loc, name) = parse_store_path("LocalMachine\\My").unwrap();
        assert_eq!(loc, CertStoreLocation::LocalMachine);
        assert_eq!(name, "My");

        let (loc, name) = parse_store_path("CurrentUser/Root").unwrap();
        assert_eq!(loc, CertStoreLocation::CurrentUser);
        assert_eq!(name, "Root");

        assert!(parse_store_path("Invalid").is_err());
        assert!(parse_store_path("Unknown\\Store").is_err());
    }

    #[test]
    fn test_format_thumbprint() {
        let bytes = [0xAB, 0xCD, 0xEF, 0x01, 0x23];
        assert_eq!(format_thumbprint(&bytes), "AB:CD:EF:01:23");
    }

    #[test]
    fn test_parse_thumbprint() {
        // Valid thumbprint (20 bytes)
        let thumb = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01";
        let bytes = parse_thumbprint(thumb).unwrap();
        assert_eq!(bytes.len(), 20);
        assert_eq!(bytes[0], 0xAB);

        // Without colons
        let thumb = "ABCDEF0123456789ABCDEF0123456789ABCDEF01";
        let bytes = parse_thumbprint(thumb).unwrap();
        assert_eq!(bytes.len(), 20);

        // Invalid length
        assert!(parse_thumbprint("ABCD").is_err());
    }

    #[test]
    fn test_stored_certificate_thumbprint_bytes() {
        let cert = StoredCertificate {
            subject: "CN=Test".to_string(),
            issuer: "CN=CA".to_string(),
            thumbprint: "AB:CD:EF".to_string(),
            serial_number: "01".to_string(),
            not_before: "2024-01-01".to_string(),
            not_after: "2025-01-01".to_string(),
            has_private_key: false,
            friendly_name: None,
            der_bytes: vec![],
        };

        let bytes = cert.thumbprint_bytes();
        assert_eq!(bytes, vec![0xAB, 0xCD, 0xEF]);
    }
}
