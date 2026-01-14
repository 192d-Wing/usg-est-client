// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! SIEM Integration Module
//!
//! This module provides enterprise SIEM integration capabilities including:
//!
//! - **Syslog Forwarding**: RFC 5424 compliant syslog client
//! - **CEF Format**: Common Event Format for ArcSight
//! - **LEEF Format**: Log Event Extended Format for IBM QRadar
//! - **Structured Logging**: SIEM-optimized event formats
//!
//! # Features
//!
//! Enable SIEM support in your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! usg-est-client = { version = "1.0", features = ["siem"] }
//! ```
//!
//! # Example Usage
//!
//! ## Syslog Forwarding
//!
//! ```no_run,ignore
//! use usg_est_client::siem::syslog::{SyslogClient, SyslogConfig, Severity, Facility};
//!
//! let config = SyslogConfig {
//!     server: "syslog.example.mil:514".to_string(),
//!     use_tls: false,
//!     facility: Facility::Local0,
//!     app_name: "est-client".to_string(),
//!     hostname: None,
//! };
//!
//! let client = SyslogClient::new(config)?;
//!
//! let message = client.message_builder(Severity::Informational)
//!     .with_msg_id("CERT-2002")
//!     .with_message("Certificate enrolled successfully");
//!
//! client.send(&message)?;
//! ```
//!
//! ## CEF Format (ArcSight)
//!
//! ```no_run,ignore
//! use usg_est_client::siem::cef::{CefEvent, CefSeverity, extensions};
//!
//! let event = CefEvent::new("CERT-2002", "Certificate Enrolled")
//!     .with_severity(CefSeverity::Low)
//!     .with_extension(extensions::SHOST, "workstation01.example.mil")
//!     .with_extension(extensions::CERT_SUBJECT, "CN=WORKSTATION01");
//!
//! println!("{}", event.to_cef());
//! ```
//!
//! ## LEEF Format (QRadar)
//!
//! ```no_run,ignore
//! use usg_est_client::siem::leef::{LeefEvent, attributes};
//!
//! let event = LeefEvent::new("CERT-2002")
//!     .with_attribute(attributes::EVENT_NAME, "Certificate Enrolled")
//!     .with_attribute(attributes::SRC_HOST, "workstation01.example.mil")
//!     .with_attribute(attributes::CERT_SUBJECT, "CN=WORKSTATION01");
//!
//! println!("{}", event.to_leef());
//! ```
//!
//! # SIEM Platform Integration
//!
//! ## Splunk
//!
//! Configure Splunk to ingest EST Client logs:
//!
//! ```ini
//! [source::/var/log/est-client/*.log]
//! sourcetype = est:client:json
//! index = security
//! ```
//!
//! ## ELK Stack (Elasticsearch, Logstash, Kibana)
//!
//! Logstash configuration:
//!
//! ```text
//! input {
//!   file {
//!     path => "/var/log/est-client/*.log"
//!     codec => "json"
//!     type => "est-client"
//!   }
//! }
//!
//! filter {
//!   if [type] == "est-client" {
//!     mutate {
//!       add_field => { "[@metadata][index]" => "est-client-%{+YYYY.MM.dd}" }
//!     }
//!   }
//! }
//!
//! output {
//!   elasticsearch {
//!     hosts => ["localhost:9200"]
//!     index => "%{[@metadata][index]}"
//!   }
//! }
//! ```
//!
//! ## ArcSight ESM
//!
//! Use CEF format with syslog forwarding:
//!
//! ```toml
//! [siem]
//! enabled = true
//! format = "cef"
//! syslog_server = "arcsight.example.mil:514"
//! ```
//!
//! ## IBM QRadar
//!
//! Use LEEF format with syslog forwarding:
//!
//! ```toml
//! [siem]
//! enabled = true
//! format = "leef"
//! syslog_server = "qradar.example.mil:514"
//! ```
//!
//! # Security Considerations
//!
//! - **TLS Transport**: Use TLS for syslog when transmitting over untrusted networks
//! - **Authentication**: Configure SIEM to authenticate log sources
//! - **Rate Limiting**: Implement rate limiting to prevent log flooding
//! - **Log Integrity**: Consider signing or encrypting logs for non-repudiation
//!
//! # Compliance
//!
//! This module helps meet the following compliance requirements:
//!
//! - **NIST SP 800-53 AU-6**: Audit Review, Analysis, and Reporting
//! - **NIST SP 800-53 AU-9**: Protection of Audit Information
//! - **STIG APSC-DV-000050**: Application must produce audit records
//! - **STIG APSC-DV-002520**: Application must protect audit information from modification

pub mod cef;
pub mod leef;
pub mod syslog;

// Re-export commonly used types
pub use cef::{CefEvent, CefSeverity};
pub use leef::{LeefEvent, LeefSeverity};
pub use syslog::{Facility, Severity, SyslogClient, SyslogConfig, SyslogMessage};
