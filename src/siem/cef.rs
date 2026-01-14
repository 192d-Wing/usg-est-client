// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! Common Event Format (CEF) for ArcSight integration
//!
//! CEF is a standard log format developed by ArcSight (now Micro Focus)
//! for security event logging. It's widely used in enterprise SIEM platforms.
//!
//! CEF Format:
//! ```text
//! CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
//! ```

use std::collections::HashMap;

/// CEF severity levels (0-10 scale)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum CefSeverity {
    /// Low severity (0-3)
    Low = 3,
    /// Medium severity (4-6)
    Medium = 6,
    /// High severity (7-8)
    High = 8,
    /// Very High/Critical severity (9-10)
    Critical = 10,
}

impl CefSeverity {
    /// Convert from event category
    pub fn from_category(category: &str) -> Self {
        match category {
            "security_violation" | "authentication_failure" => Self::Critical,
            "certificate_expired" | "key_operation_failure" => Self::High,
            "certificate_expiring" | "renewal_required" => Self::Medium,
            _ => Self::Low,
        }
    }
}

/// CEF event builder
pub struct CefEvent {
    /// Device vendor (e.g., "U.S. Government")
    pub device_vendor: String,
    /// Device product (e.g., "EST Client")
    pub device_product: String,
    /// Device version
    pub device_version: String,
    /// Signature ID (event type identifier)
    pub signature_id: String,
    /// Event name (human-readable)
    pub name: String,
    /// Severity (0-10)
    pub severity: CefSeverity,
    /// Extension fields (key-value pairs)
    pub extensions: HashMap<String, String>,
}

impl CefEvent {
    /// Create a new CEF event
    pub fn new(signature_id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            device_vendor: "U.S. Government".to_string(),
            device_product: "EST Client".to_string(),
            device_version: env!("CARGO_PKG_VERSION").to_string(),
            signature_id: signature_id.into(),
            name: name.into(),
            severity: CefSeverity::Low,
            extensions: HashMap::new(),
        }
    }

    /// Set severity
    pub fn with_severity(mut self, severity: CefSeverity) -> Self {
        self.severity = severity;
        self
    }

    /// Add extension field
    pub fn with_extension(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extensions.insert(key.into(), value.into());
        self
    }

    /// Format as CEF string
    pub fn to_cef(&self) -> String {
        let header = format!(
            "CEF:0|{}|{}|{}|{}|{}|{}",
            escape_cef_field(&self.device_vendor),
            escape_cef_field(&self.device_product),
            escape_cef_field(&self.device_version),
            escape_cef_field(&self.signature_id),
            escape_cef_field(&self.name),
            self.severity as u8
        );

        if self.extensions.is_empty() {
            header
        } else {
            let extensions = self
                .extensions
                .iter()
                .map(|(k, v)| format!("{}={}", escape_cef_key(k), escape_cef_value(v)))
                .collect::<Vec<_>>()
                .join(" ");

            format!("{}|{}", header, extensions)
        }
    }
}

/// Escape CEF header field (pipes and backslashes)
fn escape_cef_field(s: &str) -> String {
    s.replace('\\', "\\\\").replace('|', "\\|")
}

/// Escape CEF extension key (equals signs)
fn escape_cef_key(s: &str) -> String {
    s.replace('=', "\\=")
}

/// Escape CEF extension value (newlines and carriage returns)
fn escape_cef_value(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

/// Standard CEF extension fields for EST events
pub mod extensions {
    /// Source fields
    pub const SRC: &str = "src"; // Source IP
    pub const SHOST: &str = "shost"; // Source hostname
    pub const SUSER: &str = "suser"; // Source user
    pub const SPROC: &str = "sproc"; // Source process

    /// Destination fields
    pub const DST: &str = "dst"; // Destination IP
    pub const DHOST: &str = "dhost"; // Destination hostname
    pub const DPORT: &str = "dport"; // Destination port

    /// Event classification
    pub const CAT: &str = "cat"; // Category
    pub const ACT: &str = "act"; // Action
    pub const OUTCOME: &str = "outcome"; // Outcome

    /// Certificate fields (custom)
    pub const CERT_SUBJECT: &str = "cs1"; // Custom string 1
    pub const CERT_SUBJECT_LABEL: &str = "cs1Label";
    pub const CERT_ISSUER: &str = "cs2"; // Custom string 2
    pub const CERT_ISSUER_LABEL: &str = "cs2Label";
    pub const CERT_SERIAL: &str = "cs3"; // Custom string 3
    pub const CERT_SERIAL_LABEL: &str = "cs3Label";
    pub const CERT_THUMBPRINT: &str = "cs4"; // Custom string 4
    pub const CERT_THUMBPRINT_LABEL: &str = "cs4Label";

    /// Key operation fields (custom)
    pub const KEY_ALGORITHM: &str = "cs5"; // Custom string 5
    pub const KEY_ALGORITHM_LABEL: &str = "cs5Label";
    pub const KEY_SIZE: &str = "cn1"; // Custom number 1
    pub const KEY_SIZE_LABEL: &str = "cn1Label";

    /// Timing fields
    pub const START: &str = "start"; // Start time
    pub const END: &str = "end"; // End time
    pub const RT: &str = "rt"; // Receipt time

    /// Additional context
    pub const MSG: &str = "msg"; // Message
    pub const REQUEST: &str = "request"; // Request details
    pub const REASON: &str = "reason"; // Reason for failure/action
}

/// Helper to create CEF event from EST audit event
pub fn from_est_event(
    event_id: &str,
    event_name: &str,
    category: &str,
    details: HashMap<String, String>,
) -> CefEvent {
    let severity = CefSeverity::from_category(category);

    let mut event = CefEvent::new(event_id, event_name).with_severity(severity);

    // Add standard fields
    event = event.with_extension(extensions::CAT, category);

    // Add all details as extensions
    for (k, v) in details {
        event = event.with_extension(k, v);
    }

    event
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cef_basic_format() {
        let event = CefEvent::new("CERT-2002", "Certificate Enrolled")
            .with_severity(CefSeverity::Low);

        let cef = event.to_cef();

        assert!(cef.starts_with("CEF:0|"));
        assert!(cef.contains("U.S. Government"));
        assert!(cef.contains("EST Client"));
        assert!(cef.contains("CERT-2002"));
        assert!(cef.contains("Certificate Enrolled"));
        assert!(cef.contains("|3|")); // Low severity
    }

    #[test]
    fn test_cef_with_extensions() {
        let event = CefEvent::new("AUTH-1002", "Authentication Failed")
            .with_severity(CefSeverity::High)
            .with_extension("src", "10.0.1.100")
            .with_extension("shost", "workstation01.example.mil")
            .with_extension("dst", "10.0.2.50")
            .with_extension("outcome", "failure");

        let cef = event.to_cef();

        assert!(cef.contains("src=10.0.1.100"));
        assert!(cef.contains("shost=workstation01.example.mil"));
        assert!(cef.contains("dst=10.0.2.50"));
        assert!(cef.contains("outcome=failure"));
        assert!(cef.contains("|8|")); // High severity
    }

    #[test]
    fn test_cef_escape_pipes() {
        let event = CefEvent::new("TEST-001", "Test|With|Pipes");
        let cef = event.to_cef();

        assert!(cef.contains("Test\\|With\\|Pipes"));
    }

    #[test]
    fn test_cef_escape_newlines() {
        let event = CefEvent::new("TEST-002", "Test Event")
            .with_extension("msg", "Line 1\nLine 2\rLine 3");

        let cef = event.to_cef();

        assert!(cef.contains("msg=Line 1\\nLine 2\\rLine 3"));
    }

    #[test]
    fn test_severity_from_category() {
        assert_eq!(
            CefSeverity::from_category("security_violation"),
            CefSeverity::Critical
        );
        assert_eq!(
            CefSeverity::from_category("certificate_expired"),
            CefSeverity::High
        );
        assert_eq!(
            CefSeverity::from_category("certificate_expiring"),
            CefSeverity::Medium
        );
        assert_eq!(
            CefSeverity::from_category("certificate_lifecycle"),
            CefSeverity::Low
        );
    }
}
