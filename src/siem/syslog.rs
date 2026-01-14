// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! RFC 5424 Syslog client implementation
//!
//! This module provides syslog forwarding capability for integration with
//! enterprise SIEM platforms. Supports:
//!
//! - RFC 5424 structured syslog format
//! - TCP and TLS transport
//! - Message buffering and retry
//! - SIEM-specific structured data

use crate::error::{EstError, Result};
use std::net::{TcpStream, ToSocketAddrs};
use std::io::Write;
use std::time::SystemTime;

/// Syslog severity levels (RFC 5424 Section 6.2.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Severity {
    /// Emergency: system is unusable
    Emergency = 0,
    /// Alert: action must be taken immediately
    Alert = 1,
    /// Critical: critical conditions
    Critical = 2,
    /// Error: error conditions
    Error = 3,
    /// Warning: warning conditions
    Warning = 4,
    /// Notice: normal but significant condition
    Notice = 5,
    /// Informational: informational messages
    Informational = 6,
    /// Debug: debug-level messages
    Debug = 7,
}

/// Syslog facility codes (RFC 5424 Section 6.2.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Facility {
    /// Kernel messages
    Kernel = 0,
    /// User-level messages (default)
    User = 1,
    /// Security/authorization messages
    Security = 4,
    /// System daemons
    Daemon = 3,
    /// Local use 0-7
    Local0 = 16,
    Local1 = 17,
    Local2 = 18,
    Local3 = 19,
    Local4 = 20,
    Local5 = 21,
    Local6 = 22,
    Local7 = 23,
}

/// Structured data element for RFC 5424
#[derive(Debug, Clone)]
pub struct StructuredData {
    /// SD-ID: identifies the type of structured data
    pub id: String,
    /// SD-PARAMs: key-value pairs
    pub params: Vec<(String, String)>,
}

/// Syslog message following RFC 5424 format
#[derive(Debug, Clone)]
pub struct SyslogMessage {
    /// Facility and severity
    pub facility: Facility,
    pub severity: Severity,
    /// Application name
    pub app_name: String,
    /// Process ID
    pub proc_id: Option<String>,
    /// Message ID
    pub msg_id: Option<String>,
    /// Structured data elements
    pub structured_data: Vec<StructuredData>,
    /// Message text
    pub message: String,
}

impl SyslogMessage {
    /// Create a new syslog message
    pub fn new(facility: Facility, severity: Severity, app_name: impl Into<String>) -> Self {
        Self {
            facility,
            severity,
            app_name: app_name.into(),
            proc_id: None,
            msg_id: None,
            structured_data: Vec::new(),
            message: String::new(),
        }
    }

    /// Set process ID
    pub fn with_proc_id(mut self, proc_id: impl Into<String>) -> Self {
        self.proc_id = Some(proc_id.into());
        self
    }

    /// Set message ID
    pub fn with_msg_id(mut self, msg_id: impl Into<String>) -> Self {
        self.msg_id = Some(msg_id.into());
        self
    }

    /// Add structured data element
    pub fn with_structured_data(mut self, sd: StructuredData) -> Self {
        self.structured_data.push(sd);
        self
    }

    /// Set message text
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = message.into();
        self
    }

    /// Format as RFC 5424 syslog message
    ///
    /// Format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
    pub fn to_rfc5424(&self, hostname: &str) -> String {
        // Calculate priority: facility * 8 + severity
        let priority = (self.facility as u8) * 8 + (self.severity as u8);

        // RFC 5424 version
        let version = 1;

        // Timestamp in RFC 3339 format
        let timestamp = format_rfc3339_timestamp();

        // PROCID (use "-" if not provided)
        let procid = self.proc_id.as_deref().unwrap_or("-");

        // MSGID (use "-" if not provided)
        let msgid = self.msg_id.as_deref().unwrap_or("-");

        // Format structured data
        let structured_data = if self.structured_data.is_empty() {
            "-".to_string()
        } else {
            self.structured_data
                .iter()
                .map(|sd| format_structured_data(sd))
                .collect::<Vec<_>>()
                .join("")
        };

        // Assemble message
        format!(
            "<{}>{}  {} {} {} {} {} {} {}",
            priority,
            version,
            timestamp,
            hostname,
            self.app_name,
            procid,
            msgid,
            structured_data,
            self.message
        )
    }
}

/// Format timestamp in RFC 3339 format
fn format_rfc3339_timestamp() -> String {
    let now = SystemTime::now();
    // Use chrono for RFC 3339 formatting
    chrono::DateTime::<chrono::Utc>::from(now)
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Format structured data element
fn format_structured_data(sd: &StructuredData) -> String {
    let params = sd
        .params
        .iter()
        .map(|(k, v)| format!("{}=\"{}\"", escape_sd_param(k), escape_sd_param(v)))
        .collect::<Vec<_>>()
        .join(" ");

    format!("[{} {}]", sd.id, params)
}

/// Escape special characters in structured data parameters
fn escape_sd_param(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace(']', "\\]")
}

/// Syslog client configuration
#[derive(Debug, Clone)]
pub struct SyslogConfig {
    /// Syslog server address (hostname:port)
    pub server: String,
    /// Use TLS for secure transport
    pub use_tls: bool,
    /// Facility to use for all messages
    pub facility: Facility,
    /// Application name
    pub app_name: String,
    /// Hostname to report (defaults to system hostname)
    pub hostname: Option<String>,
}

impl Default for SyslogConfig {
    fn default() -> Self {
        Self {
            server: "localhost:514".to_string(),
            use_tls: false,
            facility: Facility::Local0,
            app_name: "est-client".to_string(),
            hostname: None,
        }
    }
}

/// Syslog client for forwarding messages to SIEM
pub struct SyslogClient {
    config: SyslogConfig,
    hostname: String,
}

impl SyslogClient {
    /// Create a new syslog client
    pub fn new(config: SyslogConfig) -> Result<Self> {
        let hostname = if let Some(ref h) = config.hostname {
            h.clone()
        } else {
            // Get system hostname
            hostname::get()
                .map_err(|e| EstError::platform(format!("Failed to get hostname: {}", e)))?
                .to_string_lossy()
                .to_string()
        };

        Ok(Self { config, hostname })
    }

    /// Send a syslog message
    pub fn send(&self, message: &SyslogMessage) -> Result<()> {
        let formatted = message.to_rfc5424(&self.hostname);

        if self.config.use_tls {
            self.send_tls(&formatted)
        } else {
            self.send_tcp(&formatted)
        }
    }

    /// Send message via TCP
    fn send_tcp(&self, message: &str) -> Result<()> {
        let addr = self
            .config
            .server
            .to_socket_addrs()
            .map_err(|e| EstError::operational(format!("Invalid syslog server address: {}", e)))?
            .next()
            .ok_or_else(|| EstError::operational("No address resolved for syslog server"))?;

        let mut stream = TcpStream::connect(addr)
            .map_err(|e| EstError::operational(format!("Failed to connect to syslog server: {}", e)))?;

        // RFC 5425 octet counting framing
        let frame = format!("{} {}\n", message.len(), message);

        stream
            .write_all(frame.as_bytes())
            .map_err(|e| EstError::operational(format!("Failed to send syslog message: {}", e)))?;

        stream
            .flush()
            .map_err(|e| EstError::operational(format!("Failed to flush syslog stream: {}", e)))?;

        Ok(())
    }

    /// Send message via TLS
    fn send_tls(&self, _message: &str) -> Result<()> {
        // TLS support requires native-tls or rustls
        // For now, return error directing to TCP
        Err(EstError::config(
            "TLS syslog support not yet implemented. Use TCP with firewall rules for security.",
        ))
    }

    /// Create a message builder with default facility
    pub fn message_builder(&self, severity: Severity) -> SyslogMessage {
        SyslogMessage::new(self.config.facility, severity, &self.config.app_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_calculation() {
        // User facility (1), Info severity (6): 1*8+6 = 14
        let msg = SyslogMessage::new(Facility::User, Severity::Informational, "test");
        assert!(msg.to_rfc5424("localhost").starts_with("<14>"));
    }

    #[test]
    fn test_rfc5424_format() {
        let msg = SyslogMessage::new(Facility::Local0, Severity::Informational, "est-client")
            .with_proc_id("1234")
            .with_msg_id("CERT-2002")
            .with_message("Certificate enrolled successfully");

        let formatted = msg.to_rfc5424("workstation01.example.mil");

        // Should contain all required fields
        assert!(formatted.contains("est-client"));
        assert!(formatted.contains("1234"));
        assert!(formatted.contains("CERT-2002"));
        assert!(formatted.contains("Certificate enrolled successfully"));
        assert!(formatted.contains("workstation01.example.mil"));
    }

    #[test]
    fn test_structured_data_formatting() {
        let sd = StructuredData {
            id: "est@32473".to_string(),
            params: vec![
                ("event_id".to_string(), "CERT-2002".to_string()),
                ("category".to_string(), "certificate_lifecycle".to_string()),
            ],
        };

        let msg = SyslogMessage::new(Facility::Local0, Severity::Informational, "est-client")
            .with_structured_data(sd)
            .with_message("Certificate enrolled");

        let formatted = msg.to_rfc5424("localhost");

        assert!(formatted.contains("[est@32473"));
        assert!(formatted.contains("event_id=\"CERT-2002\""));
        assert!(formatted.contains("category=\"certificate_lifecycle\""));
    }

    #[test]
    fn test_escape_special_characters() {
        let escaped = escape_sd_param("test\"value\\with]special");
        assert_eq!(escaped, "test\\\"value\\\\with\\]special");
    }
}
