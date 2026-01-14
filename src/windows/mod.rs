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

//! Windows platform integration for EST auto-enrollment.
//!
//! This module provides Windows-specific functionality for certificate enrollment,
//! including integration with the Windows Certificate Store, Cryptography Next Generation
//! (CNG) key providers, TPM 2.0 support, and machine identity retrieval.
//!
//! # Overview
//!
//! The Windows integration module enables automatic certificate enrollment on Windows
//! systems as a replacement for Microsoft Active Directory Certificate Services (ADCS)
//! auto-enrollment. It provides:
//!
//! - **Certificate Store Integration**: Read, write, and manage certificates in the
//!   Windows certificate stores (LocalMachine\My, CurrentUser\My, etc.)
//!
//! - **CNG Key Provider**: Generate and use cryptographic keys through Windows CNG,
//!   supporting various key storage providers including software, smart card, and TPM.
//!
//! - **TPM 2.0 Integration**: Generate TPM-protected keys using the Microsoft Platform
//!   Crypto Provider for enhanced security.
//!
//! - **Machine Identity**: Retrieve machine-specific information such as computer name,
//!   domain membership, and machine SID for enrollment credentials.
//!
//! # Feature Gate
//!
//! This module is only available when:
//! - The `windows` feature is enabled
//! - Compiling for a Windows target (`cfg(windows)`)
//!
//! # Security Considerations
//!
//! - Certificate store operations on LocalMachine require elevated (administrator) privileges
//! - TPM-backed keys provide hardware-level protection against key extraction
//! - Non-exportable keys prevent key material from being exported from CNG
//! - Event Log integration provides audit trails for security-sensitive operations
//!
//! # Example
//!
//! ```no_run,ignore
//! use usg_est_client::windows::{CertStore, CngKeyProvider, MachineIdentity};
//! use usg_est_client::hsm::{KeyProvider, KeyAlgorithm};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Open the LocalMachine\My certificate store
//! let store = CertStore::open_local_machine("My")?;
//!
//! // List existing certificates
//! let certs = store.list_certificates()?;
//! println!("Found {} certificates", certs.len());
//!
//! // Generate a key using CNG (non-exportable by default)
//! let provider = CngKeyProvider::new()?;
//! let key = provider.generate_key_pair(KeyAlgorithm::EcdsaP256, Some("EST-Device")).await?;
//!
//! // Get machine identity for enrollment
//! let identity = MachineIdentity::current()?;
//! println!("Machine: {}", identity.computer_name);
//! println!("Domain: {:?}", identity.domain);
//! # Ok(())
//! # }
//! ```

pub mod certstore;
pub mod cng;
pub mod identity;
pub mod tpm;

#[cfg(feature = "windows-service")]
pub mod eventlog;

#[cfg(feature = "windows-service")]
pub mod eventlog_layer;

#[cfg(feature = "windows-service")]
pub mod perfcounter;

#[cfg(feature = "windows-service")]
pub mod service;

#[cfg(feature = "windows-service")]
pub mod enrollment;

#[cfg(feature = "windows-service")]
pub mod credentials;

#[cfg(feature = "windows-service")]
pub mod security;

// DPAPI wrapper for data protection
pub mod dpapi;

pub use certstore::{CertStore, CertStoreLocation, StoredCertificate};
pub use cng::CngKeyProvider;
pub use identity::MachineIdentity;
pub use tpm::{TpmAvailability, TpmKeyProvider};

#[cfg(feature = "windows-service")]
pub use eventlog::{EventLog, EventType};

#[cfg(feature = "windows-service")]
pub use eventlog_layer::EventLogLayer;

#[cfg(feature = "windows-service")]
pub use perfcounter::{CounterType, PerformanceCounters, ServiceStateCounter};

#[cfg(feature = "windows-service")]
pub use service::{EnrollmentService, ServiceConfig, ServiceState, ServiceStateValue};

#[cfg(feature = "windows-service")]
pub use enrollment::{
    CertificateInfo, EnrollmentManager, EnrollmentOptions, EnrollmentResult, EnrollmentStatus,
    RecoveryHelper, RecoveryOptions,
};

#[cfg(feature = "windows-service")]
pub use credentials::{
    CredentialManager, CredentialSource, CredentialType, Dpapi, SecureString, StoredCredential,
};

#[cfg(feature = "windows-service")]
pub use security::{
    CertificatePinning, KeyAlgorithmPolicy, KeyProtection, NetworkSecurityConfig, ProxyConfig,
    SecurityAudit, SecurityAuditEvent, TlsSecurityConfig, TlsVersion,
};

use crate::error::{EstError, Result};

/// Check if this code is running on a Windows system.
///
/// This is always `true` when the module is compiled, but the function
/// is provided for runtime verification patterns.
#[inline]
pub fn is_windows() -> bool {
    cfg!(windows)
}

/// Check if the current process has administrator privileges.
///
/// This is required for operations on the LocalMachine certificate store.
///
/// # Returns
///
/// `true` if the process is running with elevated privileges.
#[cfg(windows)]
pub fn is_elevated() -> bool {
    use std::mem::MaybeUninit;
    use windows::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = windows::Win32::Foundation::HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }

        let mut elevation = MaybeUninit::<TOKEN_ELEVATION>::uninit();
        let mut size = 0u32;

        let result = GetTokenInformation(
            token,
            TokenElevation,
            Some(elevation.as_mut_ptr() as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        );

        if result.is_ok() {
            elevation.assume_init().TokenIsElevated != 0
        } else {
            false
        }
    }
}

/// Error codes specific to Windows operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsErrorCode {
    /// Access denied - operation requires elevated privileges.
    AccessDenied = 5,
    /// The certificate store was not found.
    StoreNotFound = 2,
    /// The certificate was not found in the store.
    CertificateNotFound = 3,
    /// The key provider is not available.
    ProviderNotAvailable = 4,
    /// TPM is not present or not enabled.
    TpmNotAvailable = 6,
    /// Generic Windows API error.
    ApiError = 1,
}

impl WindowsErrorCode {
    /// Convert from a Windows error code.
    pub fn from_win32(code: u32) -> Self {
        match code {
            5 => Self::AccessDenied,
            2 => Self::StoreNotFound,
            _ => Self::ApiError,
        }
    }
}

/// Create an EstError from a Windows HRESULT or Win32 error code.
pub(crate) fn windows_error(context: &str, code: i32) -> EstError {
    EstError::platform(format!("{}: Windows error 0x{:08X}", context, code))
}

/// Create an EstError from a Windows API operation.
pub(crate) fn windows_api_error(operation: &str) -> EstError {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::GetLastError;
        let code = unsafe { GetLastError() };
        EstError::platform(format!("{}: Windows error 0x{:08X}", operation, code.0))
    }
    #[cfg(not(windows))]
    {
        EstError::platform(format!("{}: Not running on Windows", operation))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_windows() {
        // This test will pass on all platforms since it just tests the function exists
        let _ = is_windows();
    }

    #[test]
    fn test_windows_error_code_from_win32() {
        assert_eq!(
            WindowsErrorCode::from_win32(5),
            WindowsErrorCode::AccessDenied
        );
        assert_eq!(
            WindowsErrorCode::from_win32(2),
            WindowsErrorCode::StoreNotFound
        );
        assert_eq!(
            WindowsErrorCode::from_win32(999),
            WindowsErrorCode::ApiError
        );
    }
}
