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

//! Windows Event Log integration for EST auto-enrollment.
//!
//! This module provides Windows Event Log support for logging enrollment
//! events, warnings, errors, and audit information. Events are logged to
//! the Application log under the "EST Auto-Enrollment" source.
//!
//! # NIST 800-53 Controls
//!
//! - **AU-2**: Audit Events
//!   - Defines auditable events: enrollment lifecycle, authentication, errors
//!   - Categorized event types (Info, Warning, Error, Audit)
//!   - Event ID ranges for different event categories (1000-4099)
//! - **AU-3**: Content of Audit Records
//!   - Structured event data: timestamps, certificate details, error information
//!   - Event source identification ("EST Auto-Enrollment")
//!   - Contextual data: thumbprints, subject names, URLs, error codes
//! - **AU-4**: Audit Storage Capacity
//!   - Integration with Windows Event Log retention policies
//!   - Automatic log rotation managed by Windows
//! - **AU-6**: Audit Review, Analysis, and Reporting
//!   - Events accessible via Windows Event Viewer
//!   - Machine-readable format for automated analysis
//!   - Integration with Windows event forwarding
//! - **AU-9**: Protection of Audit Information
//!   - Events protected by Windows Event Log ACLs
//!   - Tamper-evident audit trail
//! - **AU-12**: Audit Generation
//!   - Automatic audit event generation for all enrollment operations
//!   - Real-time event logging at point of occurrence
//!
//! # Event Categories
//!
//! Events are organized into categories by ID range:
//!
//! - **1000-1099**: Informational events (enrollment started, completed, service status)
//! - **2000-2099**: Warning events (renewal approaching, retry needed, config issues)
//! - **3000-3099**: Error events (enrollment failed, connection error, auth failure)
//! - **4000-4099**: Audit events (certificate installed, removed, key generated)
//!
//! # Event Data
//!
//! Each event includes structured data such as:
//!
//! - Certificate thumbprint
//! - Subject Common Name (CN)
//! - Expiration date
//! - EST server URL
//! - Error details (for error events)
//!
//! # Example
//!
//! ```no_run,ignore
//! use usg_est_client::windows::eventlog::{EventLog, EventId, EventType};
//!
//! let log = EventLog::open()?;
//!
//! // Log successful enrollment
//! log.log_event(
//!     EventId::ENROLLMENT_COMPLETED,
//!     EventType::Information,
//!     "Certificate enrolled successfully",
//!     Some(&EventData {
//!         thumbprint: Some("AB:CD:EF:...".to_string()),
//!         subject: Some("CN=device.example.com".to_string()),
//!         ..Default::default()
//!     }),
//! )?;
//!
//! // Log an error
//! log.log_error(
//!     EventId::ENROLLMENT_FAILED,
//!     "Enrollment failed: connection timeout",
//!     Some("https://est.example.com"),
//! )?;
//! ```

use crate::error::{EstError, Result};
use std::fmt;

/// Event source name for the Windows Event Log.
pub const EVENT_SOURCE: &str = "EST Auto-Enrollment";

/// Event log name (Application log).
pub const EVENT_LOG_NAME: &str = "Application";

/// Event ID constants.
///
/// Event IDs are organized by category:
/// - 1000-1099: Informational
/// - 2000-2099: Warnings
/// - 3000-3099: Errors
/// - 4000-4099: Audit
pub mod EventId {
    // Informational events (1000-1099)
    /// Service started.
    pub const SERVICE_STARTED: u32 = 1000;
    /// Service stopped.
    pub const SERVICE_STOPPED: u32 = 1001;
    /// Enrollment started.
    pub const ENROLLMENT_STARTED: u32 = 1010;
    /// Enrollment completed successfully.
    pub const ENROLLMENT_COMPLETED: u32 = 1011;
    /// Renewal started.
    pub const RENEWAL_STARTED: u32 = 1020;
    /// Renewal completed successfully.
    pub const RENEWAL_COMPLETED: u32 = 1021;
    /// Certificate check completed.
    pub const CHECK_COMPLETED: u32 = 1030;
    /// Configuration loaded.
    pub const CONFIG_LOADED: u32 = 1040;

    // Warning events (2000-2099)
    /// Certificate expiring soon.
    pub const CERT_EXPIRING_SOON: u32 = 2000;
    /// Renewal retry scheduled.
    pub const RENEWAL_RETRY: u32 = 2010;
    /// Enrollment pending approval.
    pub const ENROLLMENT_PENDING: u32 = 2020;
    /// Configuration warning.
    pub const CONFIG_WARNING: u32 = 2030;
    /// TPM not available, using software keys.
    pub const TPM_FALLBACK: u32 = 2040;

    // Error events (3000-3099)
    /// Enrollment failed.
    pub const ENROLLMENT_FAILED: u32 = 3000;
    /// Renewal failed.
    pub const RENEWAL_FAILED: u32 = 3001;
    /// Connection error.
    pub const CONNECTION_ERROR: u32 = 3010;
    /// Authentication failed.
    pub const AUTH_FAILED: u32 = 3020;
    /// Certificate store error.
    pub const CERT_STORE_ERROR: u32 = 3030;
    /// Key generation error.
    pub const KEY_GEN_ERROR: u32 = 3040;
    /// Configuration error.
    pub const CONFIG_ERROR: u32 = 3050;
    /// TLS error.
    pub const TLS_ERROR: u32 = 3060;

    // Audit events (4000-4099)
    /// Certificate installed.
    pub const CERT_INSTALLED: u32 = 4000;
    /// Certificate removed.
    pub const CERT_REMOVED: u32 = 4001;
    /// Certificate archived.
    pub const CERT_ARCHIVED: u32 = 4002;
    /// Key pair generated.
    pub const KEY_GENERATED: u32 = 4010;
    /// Key pair deleted.
    pub const KEY_DELETED: u32 = 4011;
    /// CSR created.
    pub const CSR_CREATED: u32 = 4020;
}

/// Event type/severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    /// Informational event.
    Information,
    /// Warning event.
    Warning,
    /// Error event.
    Error,
    /// Audit success.
    AuditSuccess,
    /// Audit failure.
    AuditFailure,
}

impl EventType {
    /// Get the Windows event type value.
    #[cfg(windows)]
    pub fn to_windows_type(self) -> u16 {
        match self {
            Self::Information => 4,   // EVENTLOG_INFORMATION_TYPE
            Self::Warning => 2,       // EVENTLOG_WARNING_TYPE
            Self::Error => 1,         // EVENTLOG_ERROR_TYPE
            Self::AuditSuccess => 8,  // EVENTLOG_AUDIT_SUCCESS
            Self::AuditFailure => 16, // EVENTLOG_AUDIT_FAILURE
        }
    }
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Information => write!(f, "Information"),
            Self::Warning => write!(f, "Warning"),
            Self::Error => write!(f, "Error"),
            Self::AuditSuccess => write!(f, "Audit Success"),
            Self::AuditFailure => write!(f, "Audit Failure"),
        }
    }
}

/// Structured event data for logging.
#[derive(Debug, Clone, Default)]
pub struct EventData {
    /// Certificate thumbprint (SHA-1 hex).
    pub thumbprint: Option<String>,
    /// Certificate subject (Distinguished Name).
    pub subject: Option<String>,
    /// Certificate expiration date.
    pub expiration: Option<String>,
    /// EST server URL.
    pub server_url: Option<String>,
    /// Error message or details.
    pub error_details: Option<String>,
    /// Additional context.
    pub context: Option<String>,
}

impl EventData {
    /// Create new event data with a thumbprint.
    pub fn with_thumbprint(thumbprint: &str) -> Self {
        Self {
            thumbprint: Some(thumbprint.to_string()),
            ..Default::default()
        }
    }

    /// Create new event data with certificate info.
    pub fn with_certificate(thumbprint: &str, subject: &str, expiration: &str) -> Self {
        Self {
            thumbprint: Some(thumbprint.to_string()),
            subject: Some(subject.to_string()),
            expiration: Some(expiration.to_string()),
            ..Default::default()
        }
    }

    /// Create new event data for an error.
    pub fn with_error(error: &str, server_url: Option<&str>) -> Self {
        Self {
            error_details: Some(error.to_string()),
            server_url: server_url.map(|s| s.to_string()),
            ..Default::default()
        }
    }

    /// Format as a multi-line string for event description.
    pub fn format_description(&self) -> String {
        let mut parts = Vec::new();

        if let Some(ref thumb) = self.thumbprint {
            parts.push(format!("Thumbprint: {}", thumb));
        }
        if let Some(ref subj) = self.subject {
            parts.push(format!("Subject: {}", subj));
        }
        if let Some(ref exp) = self.expiration {
            parts.push(format!("Expiration: {}", exp));
        }
        if let Some(ref url) = self.server_url {
            parts.push(format!("Server: {}", url));
        }
        if let Some(ref err) = self.error_details {
            parts.push(format!("Details: {}", err));
        }
        if let Some(ref ctx) = self.context {
            parts.push(format!("Context: {}", ctx));
        }

        parts.join("\n")
    }
}

/// Windows Event Log handle.
pub struct EventLog {
    /// Event source name.
    source: String,
    #[cfg(windows)]
    handle: windows::Win32::System::EventLog::HANDLE,
}

impl EventLog {
    /// Open the event log with the default source.
    pub fn open() -> Result<Self> {
        Self::open_source(EVENT_SOURCE)
    }

    /// Open the event log with a custom source.
    pub fn open_source(source: &str) -> Result<Self> {
        #[cfg(windows)]
        {
            use std::ffi::OsStr;
            use std::os::windows::ffi::OsStrExt;
            use windows::Win32::System::EventLog::RegisterEventSourceW;

            let wide_source: Vec<u16> = OsStr::new(source)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let handle = unsafe {
                RegisterEventSourceW(
                    windows::core::PCWSTR::null(),
                    windows::core::PCWSTR(wide_source.as_ptr()),
                )
            };

            match handle {
                Ok(h) if !h.is_invalid() => Ok(Self {
                    source: source.to_string(),
                    handle: h,
                }),
                _ => Err(EstError::platform(format!(
                    "Failed to register event source: {}",
                    source
                ))),
            }
        }

        #[cfg(not(windows))]
        {
            Ok(Self {
                source: source.to_string(),
            })
        }
    }

    /// Log an event to the Windows Event Log.
    pub fn log_event(
        &self,
        event_id: u32,
        event_type: EventType,
        message: &str,
        data: Option<&EventData>,
    ) -> Result<()> {
        #[cfg(windows)]
        {
            use std::ffi::OsStr;
            use std::os::windows::ffi::OsStrExt;
            use windows::Win32::System::EventLog::ReportEventW;

            // Build the full message
            let full_message = if let Some(d) = data {
                format!("{}\n\n{}", message, d.format_description())
            } else {
                message.to_string()
            };

            let wide_message: Vec<u16> = OsStr::new(&full_message)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let strings = [windows::core::PCWSTR(wide_message.as_ptr())];

            let result = unsafe {
                ReportEventW(
                    self.handle,
                    event_type.to_windows_type(),
                    0, // Category
                    event_id,
                    None, // User SID
                    Some(&strings),
                    None, // Raw data
                )
            };

            if result.is_err() {
                Err(EstError::platform(format!(
                    "Failed to report event {}: {:?}",
                    event_id, result
                )))
            } else {
                Ok(())
            }
        }

        #[cfg(not(windows))]
        {
            // On non-Windows, log to tracing
            let level = match event_type {
                EventType::Error | EventType::AuditFailure => tracing::Level::ERROR,
                EventType::Warning => tracing::Level::WARN,
                _ => tracing::Level::INFO,
            };

            let data_str = data.map(|d| d.format_description()).unwrap_or_default();

            match level {
                tracing::Level::ERROR => tracing::error!(
                    source = %self.source,
                    event_id = event_id,
                    event_type = %event_type,
                    data = %data_str,
                    "{}", message
                ),
                tracing::Level::WARN => tracing::warn!(
                    source = %self.source,
                    event_id = event_id,
                    event_type = %event_type,
                    data = %data_str,
                    "{}", message
                ),
                _ => tracing::info!(
                    source = %self.source,
                    event_id = event_id,
                    event_type = %event_type,
                    data = %data_str,
                    "{}", message
                ),
            }

            Ok(())
        }
    }

    /// Log an informational event.
    pub fn log_info(&self, event_id: u32, message: &str, data: Option<&EventData>) -> Result<()> {
        self.log_event(event_id, EventType::Information, message, data)
    }

    /// Log a warning event.
    pub fn log_warning(
        &self,
        event_id: u32,
        message: &str,
        data: Option<&EventData>,
    ) -> Result<()> {
        self.log_event(event_id, EventType::Warning, message, data)
    }

    /// Log an error event.
    pub fn log_error(&self, event_id: u32, message: &str, server_url: Option<&str>) -> Result<()> {
        let data = server_url.map(|url| EventData {
            server_url: Some(url.to_string()),
            ..Default::default()
        });
        self.log_event(event_id, EventType::Error, message, data.as_ref())
    }

    /// Log an audit event.
    pub fn log_audit(
        &self,
        event_id: u32,
        success: bool,
        message: &str,
        data: Option<&EventData>,
    ) -> Result<()> {
        let event_type = if success {
            EventType::AuditSuccess
        } else {
            EventType::AuditFailure
        };
        self.log_event(event_id, event_type, message, data)
    }

    // Convenience methods for common events

    /// Log service started event.
    pub fn log_service_started(&self) -> Result<()> {
        self.log_info(
            EventId::SERVICE_STARTED,
            "EST Auto-Enrollment service started",
            None,
        )
    }

    /// Log service stopped event.
    pub fn log_service_stopped(&self) -> Result<()> {
        self.log_info(
            EventId::SERVICE_STOPPED,
            "EST Auto-Enrollment service stopped",
            None,
        )
    }

    /// Log enrollment started.
    pub fn log_enrollment_started(&self, server_url: &str) -> Result<()> {
        let data = EventData {
            server_url: Some(server_url.to_string()),
            ..Default::default()
        };
        self.log_info(
            EventId::ENROLLMENT_STARTED,
            "Certificate enrollment started",
            Some(&data),
        )
    }

    /// Log enrollment completed.
    pub fn log_enrollment_completed(
        &self,
        thumbprint: &str,
        subject: &str,
        expiration: &str,
    ) -> Result<()> {
        let data = EventData::with_certificate(thumbprint, subject, expiration);
        self.log_info(
            EventId::ENROLLMENT_COMPLETED,
            "Certificate enrollment completed successfully",
            Some(&data),
        )
    }

    /// Log enrollment failed.
    pub fn log_enrollment_failed(&self, error: &str, server_url: Option<&str>) -> Result<()> {
        let data = EventData::with_error(error, server_url);
        self.log_event(
            EventId::ENROLLMENT_FAILED,
            EventType::Error,
            "Certificate enrollment failed",
            Some(&data),
        )
    }

    /// Log certificate expiring soon.
    pub fn log_cert_expiring(&self, thumbprint: &str, days_until_expiry: u32) -> Result<()> {
        let data = EventData {
            thumbprint: Some(thumbprint.to_string()),
            context: Some(format!("Days until expiry: {}", days_until_expiry)),
            ..Default::default()
        };
        self.log_warning(
            EventId::CERT_EXPIRING_SOON,
            &format!("Certificate expiring in {} days", days_until_expiry),
            Some(&data),
        )
    }

    /// Log certificate installed.
    pub fn log_cert_installed(&self, thumbprint: &str, subject: &str) -> Result<()> {
        let data = EventData {
            thumbprint: Some(thumbprint.to_string()),
            subject: Some(subject.to_string()),
            ..Default::default()
        };
        self.log_audit(
            EventId::CERT_INSTALLED,
            true,
            "Certificate installed to store",
            Some(&data),
        )
    }

    /// Log certificate removed.
    pub fn log_cert_removed(&self, thumbprint: &str) -> Result<()> {
        let data = EventData::with_thumbprint(thumbprint);
        self.log_audit(
            EventId::CERT_REMOVED,
            true,
            "Certificate removed from store",
            Some(&data),
        )
    }
}

impl Drop for EventLog {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            use windows::Win32::System::EventLog::DeregisterEventSource;
            unsafe {
                let _ = DeregisterEventSource(self.handle);
            }
        }
    }
}

/// Register the event source in the Windows registry.
///
/// This should be called during installation to properly register
/// the event source with the Windows Event Log.
#[cfg(windows)]
pub fn register_event_source() -> Result<()> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::System::Registry::{
        HKEY_LOCAL_MACHINE, KEY_WRITE, REG_DWORD, REG_EXPAND_SZ, REG_OPTION_NON_VOLATILE,
        RegCreateKeyExW, RegSetValueExW,
    };

    let key_path = format!(
        "SYSTEM\\CurrentControlSet\\Services\\EventLog\\{}\\{}",
        EVENT_LOG_NAME, EVENT_SOURCE
    );

    let wide_path: Vec<u16> = OsStr::new(&key_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut key = windows::Win32::System::Registry::HKEY::default();
    let mut disposition = 0u32;

    let result = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            windows::core::PCWSTR(wide_path.as_ptr()),
            0,
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut key,
            Some(&mut disposition),
        )
    };

    if result.is_err() {
        return Err(EstError::platform(format!(
            "Failed to create registry key: {:?}",
            result
        )));
    }

    // Set EventMessageFile (path to the executable with message resources)
    let exe_path = std::env::current_exe()
        .map_err(|e| EstError::platform(format!("Failed to get executable path: {}", e)))?;
    let exe_str = exe_path.to_string_lossy();
    let wide_exe: Vec<u16> = OsStr::new(exe_str.as_ref())
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let value_name: Vec<u16> = OsStr::new("EventMessageFile")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let _ = unsafe {
        RegSetValueExW(
            key,
            windows::core::PCWSTR(value_name.as_ptr()),
            0,
            REG_EXPAND_SZ,
            Some(std::slice::from_raw_parts(
                wide_exe.as_ptr() as *const u8,
                wide_exe.len() * 2,
            )),
        )
    };

    // Set TypesSupported
    let types_value: u32 = 7; // EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE
    let types_name: Vec<u16> = OsStr::new("TypesSupported")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let _ = unsafe {
        RegSetValueExW(
            key,
            windows::core::PCWSTR(types_name.as_ptr()),
            0,
            REG_DWORD,
            Some(std::slice::from_raw_parts(
                &types_value as *const u32 as *const u8,
                4,
            )),
        )
    };

    Ok(())
}

/// Unregister the event source from the Windows registry.
#[cfg(windows)]
pub fn unregister_event_source() -> Result<()> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RegDeleteKeyW};

    let key_path = format!(
        "SYSTEM\\CurrentControlSet\\Services\\EventLog\\{}\\{}",
        EVENT_LOG_NAME, EVENT_SOURCE
    );

    let wide_path: Vec<u16> = OsStr::new(&key_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let result = unsafe {
        RegDeleteKeyW(
            HKEY_LOCAL_MACHINE,
            windows::core::PCWSTR(wide_path.as_ptr()),
        )
    };

    if result.is_err() {
        Err(EstError::platform(format!(
            "Failed to delete registry key: {:?}",
            result
        )))
    } else {
        Ok(())
    }
}

/// Non-Windows stubs.
#[cfg(not(windows))]
pub fn register_event_source() -> Result<()> {
    Ok(())
}

#[cfg(not(windows))]
pub fn unregister_event_source() -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: Test code uses unwrap() deliberately - test fixtures are known valid
    // and panics in tests provide clear failure messages. See ERROR-HANDLING-PATTERNS.md
    // Pattern 5 for justification.

    #[test]
    fn test_event_type_display() {
        assert_eq!(format!("{}", EventType::Information), "Information");
        assert_eq!(format!("{}", EventType::Warning), "Warning");
        assert_eq!(format!("{}", EventType::Error), "Error");
    }

    #[test]
    fn test_event_data_with_thumbprint() {
        let data = EventData::with_thumbprint("AB:CD:EF");
        assert_eq!(data.thumbprint, Some("AB:CD:EF".to_string()));
        assert!(data.subject.is_none());
    }

    #[test]
    fn test_event_data_with_certificate() {
        let data = EventData::with_certificate("AB:CD:EF", "CN=test", "2025-12-31");
        assert_eq!(data.thumbprint, Some("AB:CD:EF".to_string()));
        assert_eq!(data.subject, Some("CN=test".to_string()));
        assert_eq!(data.expiration, Some("2025-12-31".to_string()));
    }

    #[test]
    fn test_event_data_with_error() {
        let data = EventData::with_error("Connection timeout", Some("https://est.example.com"));
        assert_eq!(data.error_details, Some("Connection timeout".to_string()));
        assert_eq!(data.server_url, Some("https://est.example.com".to_string()));
    }

    #[test]
    fn test_event_data_format_description() {
        let data = EventData {
            thumbprint: Some("AB:CD".to_string()),
            subject: Some("CN=test".to_string()),
            expiration: None,
            server_url: Some("https://est.example.com".to_string()),
            error_details: None,
            context: None,
        };

        let desc = data.format_description();
        assert!(desc.contains("Thumbprint: AB:CD"));
        assert!(desc.contains("Subject: CN=test"));
        assert!(desc.contains("Server: https://est.example.com"));
    }

    #[test]
    fn test_event_ids() {
        // Verify event ID ranges
        assert!(EventId::SERVICE_STARTED >= 1000 && EventId::SERVICE_STARTED < 1100);
        assert!(EventId::CERT_EXPIRING_SOON >= 2000 && EventId::CERT_EXPIRING_SOON < 2100);
        assert!(EventId::ENROLLMENT_FAILED >= 3000 && EventId::ENROLLMENT_FAILED < 3100);
        assert!(EventId::CERT_INSTALLED >= 4000 && EventId::CERT_INSTALLED < 4100);
    }

    #[cfg(not(windows))]
    #[test]
    fn test_event_log_non_windows() {
        // On non-Windows, should successfully create an EventLog
        let log = EventLog::open().unwrap();
        assert_eq!(log.source, EVENT_SOURCE);

        // Logging should not fail (logs to tracing)
        log.log_service_started().unwrap();
        log.log_info(EventId::CHECK_COMPLETED, "Test message", None)
            .unwrap();
    }
}
