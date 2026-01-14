// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! Log Event Extended Format (LEEF) for IBM QRadar integration
//!
//! LEEF is IBM's standard log format for security event logging,
//! used primarily with QRadar SIEM.
//!
//! LEEF Format (Version 2.0):
//! ```text
//! LEEF:2.0|Vendor|Product|Version|EventID|Field1=Value1<tab>Field2=Value2...
//! ```

use std::collections::HashMap;

/// LEEF severity levels (mapped to QRadar severity)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum LeefSeverity {
    /// Info level (1-3)
    Info = 2,
    /// Warning level (4-6)
    Warning = 5,
    /// Error level (7-8)
    Error = 7,
    /// Critical level (9-10)
    Critical = 10,
}

impl LeefSeverity {
    /// Convert from event category
    pub fn from_category(category: &str) -> Self {
        match category {
            "security_violation" | "authentication_failure" => Self::Critical,
            "certificate_expired" | "key_operation_failure" => Self::Error,
            "certificate_expiring" | "renewal_required" => Self::Warning,
            _ => Self::Info,
        }
    }
}

/// LEEF event builder
pub struct LeefEvent {
    /// Vendor (e.g., "USGov")
    pub vendor: String,
    /// Product (e.g., "EST-Client")
    pub product: String,
    /// Version
    pub version: String,
    /// Event ID
    pub event_id: String,
    /// Attributes (key-value pairs)
    pub attributes: HashMap<String, String>,
}

impl LeefEvent {
    /// Create a new LEEF event
    pub fn new(event_id: impl Into<String>) -> Self {
        Self {
            vendor: "USGov".to_string(),
            product: "EST-Client".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            event_id: event_id.into(),
            attributes: HashMap::new(),
        }
    }

    /// Add attribute
    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// Format as LEEF 2.0 string
    pub fn to_leef(&self) -> String {
        let header = format!(
            "LEEF:2.0|{}|{}|{}|{}",
            escape_leef_field(&self.vendor),
            escape_leef_field(&self.product),
            escape_leef_field(&self.version),
            escape_leef_field(&self.event_id)
        );

        if self.attributes.is_empty() {
            header
        } else {
            let attributes = self
                .attributes
                .iter()
                .map(|(k, v)| format!("{}={}", escape_leef_key(k), escape_leef_value(v)))
                .collect::<Vec<_>>()
                .join("\t"); // Tab-delimited

            format!("{}|{}", header, attributes)
        }
    }
}

/// Escape LEEF header field (pipes and backslashes)
fn escape_leef_field(s: &str) -> String {
    s.replace('\\', "\\\\").replace('|', "\\|")
}

/// Escape LEEF key (equals signs and tabs)
fn escape_leef_key(s: &str) -> String {
    s.replace('=', "\\=").replace('\t', "\\t")
}

/// Escape LEEF value (newlines, carriage returns, tabs)
fn escape_leef_value(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

/// Standard LEEF attribute names for EST events
pub mod attributes {
    /// Event classification
    pub const CAT: &str = "cat"; // Category
    pub const SEV: &str = "sev"; // Severity
    pub const DEV_TIME: &str = "devTime"; // Device time
    pub const DEV_TIME_FORMAT: &str = "devTimeFormat"; // Time format

    /// Source fields
    pub const SRC: &str = "src"; // Source IP
    pub const SRC_PORT: &str = "srcPort"; // Source port
    pub const SRC_HOST: &str = "srcHost"; // Source hostname
    pub const USRNAME: &str = "usrName"; // Username
    pub const IDENTHOST_NAME: &str = "identHostName"; // Identity hostname

    /// Destination fields
    pub const DST: &str = "dst"; // Destination IP
    pub const DST_PORT: &str = "dstPort"; // Destination port
    pub const DST_HOST: &str = "dstHost"; // Destination hostname
    pub const PROTO: &str = "proto"; // Protocol

    /// Event details
    pub const EVENT_ID: &str = "eventId"; // Event identifier
    pub const EVENT_NAME: &str = "eventName"; // Event name
    pub const EVENT_DESC: &str = "eventDesc"; // Event description

    /// Certificate fields (custom)
    pub const CERT_SUBJECT: &str = "certSubject";
    pub const CERT_ISSUER: &str = "certIssuer";
    pub const CERT_SERIAL: &str = "certSerial";
    pub const CERT_THUMBPRINT: &str = "certThumbprint";
    pub const CERT_NOT_BEFORE: &str = "certNotBefore";
    pub const CERT_NOT_AFTER: &str = "certNotAfter";

    /// Key operation fields (custom)
    pub const KEY_ALGORITHM: &str = "keyAlgorithm";
    pub const KEY_SIZE: &str = "keySize";
    pub const KEY_CONTAINER: &str = "keyContainer";

    /// Authentication fields
    pub const AUTH_METHOD: &str = "authMethod";
    pub const TLS_VERSION: &str = "tlsVersion";
    pub const CIPHER_SUITE: &str = "cipherSuite";

    /// Outcome
    pub const RESULT: &str = "result"; // Success/Failure
    pub const REASON: &str = "reason"; // Reason for outcome
}

/// Helper to create LEEF event from EST audit event
pub fn from_est_event(
    event_id: &str,
    event_name: &str,
    category: &str,
    details: HashMap<String, String>,
) -> LeefEvent {
    let severity = LeefSeverity::from_category(category);

    let mut event = LeefEvent::new(event_id);

    // Add standard fields
    event = event
        .with_attribute(attributes::EVENT_ID, event_id)
        .with_attribute(attributes::EVENT_NAME, event_name)
        .with_attribute(attributes::CAT, category)
        .with_attribute(attributes::SEV, (severity as u8).to_string());

    // Add timestamp
    let timestamp = chrono::Utc::now()
        .format("%Y-%m-%d %H:%M:%S%.3f")
        .to_string();
    event = event
        .with_attribute(attributes::DEV_TIME, timestamp)
        .with_attribute(attributes::DEV_TIME_FORMAT, "yyyy-MM-dd HH:mm:ss.SSS");

    // Add all details as attributes
    for (k, v) in details {
        event = event.with_attribute(k, v);
    }

    event
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leef_basic_format() {
        let event = LeefEvent::new("CERT-2002");

        let leef = event.to_leef();

        assert!(leef.starts_with("LEEF:2.0|"));
        assert!(leef.contains("USGov"));
        assert!(leef.contains("EST-Client"));
        assert!(leef.contains("CERT-2002"));
    }

    #[test]
    fn test_leef_with_attributes() {
        let event = LeefEvent::new("AUTH-1002")
            .with_attribute("src", "10.0.1.100")
            .with_attribute("srcHost", "workstation01.example.mil")
            .with_attribute("dst", "10.0.2.50")
            .with_attribute("result", "failure");

        let leef = event.to_leef();

        // Attributes are tab-delimited
        assert!(leef.contains("src=10.0.1.100"));
        assert!(leef.contains("srcHost=workstation01.example.mil"));
        assert!(leef.contains("dst=10.0.2.50"));
        assert!(leef.contains("result=failure"));
    }

    #[test]
    fn test_leef_escape_pipes() {
        let event = LeefEvent::new("TEST|WITH|PIPES");
        let leef = event.to_leef();

        assert!(leef.contains("TEST\\|WITH\\|PIPES"));
    }

    #[test]
    fn test_leef_escape_tabs() {
        let event = LeefEvent::new("TEST-001").with_attribute("msg", "Tab\there");

        let leef = event.to_leef();

        assert!(leef.contains("msg=Tab\\there"));
    }

    #[test]
    fn test_leef_escape_newlines() {
        let event = LeefEvent::new("TEST-002").with_attribute("msg", "Line 1\nLine 2\rLine 3");

        let leef = event.to_leef();

        assert!(leef.contains("msg=Line 1\\nLine 2\\rLine 3"));
    }

    #[test]
    fn test_severity_from_category() {
        assert_eq!(
            LeefSeverity::from_category("security_violation"),
            LeefSeverity::Critical
        );
        assert_eq!(
            LeefSeverity::from_category("certificate_expired"),
            LeefSeverity::Error
        );
        assert_eq!(
            LeefSeverity::from_category("certificate_expiring"),
            LeefSeverity::Warning
        );
        assert_eq!(
            LeefSeverity::from_category("certificate_lifecycle"),
            LeefSeverity::Info
        );
    }
}
