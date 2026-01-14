// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! Windows Event Log tracing layer.
//!
//! This module provides a `tracing` subscriber layer that writes log events
//! to the Windows Event Log. This enables integration with enterprise logging
//! infrastructure and SIEM systems.
//!
//! # NIST 800-53 Controls
//!
//! - **AU-2**: Audit Events
//!   - Automatic conversion of application events to audit records
//!   - Severity-based event categorization (Info, Warning, Error)
//! - **AU-3**: Content of Audit Records
//!   - Structured field extraction from tracing events
//!   - Automatic inclusion of timestamps and event metadata
//! - **AU-6**: Audit Review, Analysis, and Reporting
//!   - Real-time event forwarding to Windows Event Log
//!   - Integration with Windows Event Forwarding (WEF)
//! - **AU-9**: Protection of Audit Information
//!   - Events protected by Windows Event Log security model
//!   - Leverages Windows ACL-based access control

use crate::windows::eventlog::{EventData, EventLog, EventType};
use std::sync::Arc;
use tracing::{field::Visit, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

/// Tracing layer that writes to Windows Event Log.
///
/// This layer converts tracing events to Windows Event Log entries,
/// mapping severity levels and extracting structured data from event fields.
pub struct EventLogLayer {
    event_log: Arc<EventLog>,
}

impl EventLogLayer {
    /// Create a new Windows Event Log layer.
    ///
    /// # Errors
    ///
    /// Returns an error if the event source cannot be registered.
    pub fn new() -> crate::error::Result<Self> {
        let event_log = EventLog::open()?;
        Ok(Self {
            event_log: Arc::new(event_log),
        })
    }

    /// Create a new Windows Event Log layer with a custom source.
    pub fn with_source(source: &str) -> crate::error::Result<Self> {
        let event_log = EventLog::open_source(source)?;
        Ok(Self {
            event_log: Arc::new(event_log),
        })
    }
}

impl<S> Layer<S> for EventLogLayer
where
    S: Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: Context<'_, S>,
    ) {
        // Extract event metadata
        let metadata = event.metadata();
        let level = metadata.level();
        let target = metadata.target();

        // Convert tracing level to Event Log type
        let event_type = match *level {
            tracing::Level::ERROR => EventType::Error,
            tracing::Level::WARN => EventType::Warning,
            _ => EventType::Information,
        };

        // Extract structured fields from the event
        let mut visitor = EventDataVisitor::default();
        event.record(&mut visitor);

        // Determine event ID based on target and message content
        let event_id = determine_event_id(target, &visitor.message, level);

        // Build event data from fields
        let event_data = EventData {
            thumbprint: visitor.thumbprint,
            subject: visitor.subject,
            expiration: visitor.expiration,
            server_url: visitor.server_url,
            error_details: visitor.error,
            context: visitor.context,
        };

        // Log to Windows Event Log
        let message = if visitor.message.is_empty() {
            format!("[{}] {}", target, visitor.message)
        } else {
            visitor.message.clone()
        };

        let _ = self.event_log.log_event(
            event_id,
            event_type,
            &message,
            Some(&event_data),
        );
    }
}

/// Visitor to extract structured data from tracing event fields.
#[derive(Default)]
struct EventDataVisitor {
    message: String,
    thumbprint: Option<String>,
    subject: Option<String>,
    expiration: Option<String>,
    server_url: Option<String>,
    error: Option<String>,
    context: Option<String>,
}

impl Visit for EventDataVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let name = field.name();
        let value_str = format!("{:?}", value);

        match name {
            "message" => self.message = value_str.trim_matches('"').to_string(),
            "thumbprint" => self.thumbprint = Some(value_str.trim_matches('"').to_string()),
            "subject" => self.subject = Some(value_str.trim_matches('"').to_string()),
            "expiration" => self.expiration = Some(value_str.trim_matches('"').to_string()),
            "server_url" => self.server_url = Some(value_str.trim_matches('"').to_string()),
            "error" => self.error = Some(value_str.trim_matches('"').to_string()),
            "context" => self.context = Some(value_str.trim_matches('"').to_string()),
            _ => {
                // Append other fields to context
                let field_info = format!("{}: {}", name, value_str);
                match &mut self.context {
                    Some(ctx) => {
                        ctx.push_str(", ");
                        ctx.push_str(&field_info);
                    }
                    None => self.context = Some(field_info),
                }
            }
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        let name = field.name();

        match name {
            "message" => self.message = value.to_string(),
            "thumbprint" => self.thumbprint = Some(value.to_string()),
            "subject" => self.subject = Some(value.to_string()),
            "expiration" => self.expiration = Some(value.to_string()),
            "server_url" => self.server_url = Some(value.to_string()),
            "error" => self.error = Some(value.to_string()),
            "context" => self.context = Some(value.to_string()),
            _ => {
                // Append other fields to context
                let field_info = format!("{}: {}", name, value);
                match &mut self.context {
                    Some(ctx) => {
                        ctx.push_str(", ");
                        ctx.push_str(&field_info);
                    }
                    None => self.context = Some(field_info),
                }
            }
        }
    }
}

/// Determine appropriate event ID based on log target and message content.
fn determine_event_id(target: &str, message: &str, level: &tracing::Level) -> u32 {
    use crate::windows::eventlog::EventId;

    // Service lifecycle events
    if target.contains("service") {
        if message.contains("started") || message.contains("Starting") {
            return EventId::SERVICE_STARTED;
        }
        if message.contains("stopped") || message.contains("Stopping") {
            return EventId::SERVICE_STOPPED;
        }
    }

    // Enrollment events
    if target.contains("enrollment") || message.contains("enrollment") {
        return match *level {
            tracing::Level::ERROR => {
                if message.contains("failed") || message.contains("error") {
                    EventId::ENROLLMENT_FAILED
                } else {
                    EventId::ENROLLMENT_FAILED
                }
            }
            tracing::Level::WARN => EventId::ENROLLMENT_PENDING,
            _ => {
                if message.contains("Starting") || message.contains("started") {
                    EventId::ENROLLMENT_STARTED
                } else if message.contains("complet") || message.contains("success") {
                    EventId::ENROLLMENT_COMPLETED
                } else {
                    EventId::ENROLLMENT_STARTED
                }
            }
        };
    }

    // Renewal events
    if target.contains("renewal") || message.contains("renewal") || message.contains("renew") {
        return match *level {
            tracing::Level::ERROR => EventId::RENEWAL_FAILED,
            tracing::Level::WARN => EventId::RENEWAL_RETRY,
            _ => {
                if message.contains("Starting") || message.contains("started") {
                    EventId::RENEWAL_STARTED
                } else if message.contains("complet") || message.contains("success") {
                    EventId::RENEWAL_COMPLETED
                } else {
                    EventId::RENEWAL_STARTED
                }
            }
        };
    }

    // Certificate events
    if message.contains("expiring") || message.contains("expir") {
        return EventId::CERT_EXPIRING_SOON;
    }

    if message.contains("installed") && message.contains("certificate") {
        return EventId::CERT_INSTALLED;
    }

    if message.contains("removed") && message.contains("certificate") {
        return EventId::CERT_REMOVED;
    }

    // Connection and authentication errors
    if target.contains("client") || target.contains("tls") || target.contains("http") {
        if message.contains("connect") || message.contains("connection") {
            return EventId::CONNECTION_ERROR;
        }
        if message.contains("auth") || message.contains("unauthorized") {
            return EventId::AUTH_FAILED;
        }
        if message.contains("tls") || message.contains("ssl") || message.contains("handshake") {
            return EventId::TLS_ERROR;
        }
    }

    // Configuration events
    if target.contains("config") || message.contains("config") {
        return match *level {
            tracing::Level::ERROR => EventId::CONFIG_ERROR,
            tracing::Level::WARN => EventId::CONFIG_WARNING,
            _ => EventId::CONFIG_LOADED,
        };
    }

    // Certificate store events
    if target.contains("cert_store") || target.contains("certstore") {
        return EventId::CERT_STORE_ERROR;
    }

    // Key generation events
    if message.contains("key") && (message.contains("generat") || message.contains("creat")) {
        return match *level {
            tracing::Level::ERROR => EventId::KEY_GEN_ERROR,
            _ => EventId::KEY_GENERATED,
        };
    }

    // TPM fallback
    if message.contains("TPM") && message.contains("fallback") {
        return EventId::TPM_FALLBACK;
    }

    // CSR events
    if message.contains("CSR") {
        return EventId::CSR_CREATED;
    }

    // Default event IDs by level
    match *level {
        tracing::Level::ERROR => 3099,  // Generic error
        tracing::Level::WARN => 2099,   // Generic warning
        tracing::Level::INFO => 1099,   // Generic info
        _ => 1099,                       // Debug/trace as info
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_determine_event_id_service() {
        use crate::windows::eventlog::EventId;

        assert_eq!(
            determine_event_id("service", "Service started", &tracing::Level::INFO),
            EventId::SERVICE_STARTED
        );

        assert_eq!(
            determine_event_id("service", "Service stopped", &tracing::Level::INFO),
            EventId::SERVICE_STOPPED
        );
    }

    #[test]
    fn test_determine_event_id_enrollment() {
        use crate::windows::eventlog::EventId;

        assert_eq!(
            determine_event_id("enrollment", "Starting enrollment", &tracing::Level::INFO),
            EventId::ENROLLMENT_STARTED
        );

        assert_eq!(
            determine_event_id("enrollment", "Enrollment completed", &tracing::Level::INFO),
            EventId::ENROLLMENT_COMPLETED
        );

        assert_eq!(
            determine_event_id("enrollment", "Enrollment failed", &tracing::Level::ERROR),
            EventId::ENROLLMENT_FAILED
        );
    }

    #[test]
    fn test_determine_event_id_renewal() {
        use crate::windows::eventlog::EventId;

        assert_eq!(
            determine_event_id("renewal", "Starting renewal", &tracing::Level::INFO),
            EventId::RENEWAL_STARTED
        );

        assert_eq!(
            determine_event_id("renewal", "Renewal failed", &tracing::Level::ERROR),
            EventId::RENEWAL_FAILED
        );
    }

    #[test]
    fn test_determine_event_id_config() {
        use crate::windows::eventlog::EventId;

        assert_eq!(
            determine_event_id("config", "Configuration loaded", &tracing::Level::INFO),
            EventId::CONFIG_LOADED
        );

        assert_eq!(
            determine_event_id("config", "Config error", &tracing::Level::ERROR),
            EventId::CONFIG_ERROR
        );
    }

    #[test]
    fn test_determine_event_id_generic() {
        assert_eq!(
            determine_event_id("unknown", "Something happened", &tracing::Level::ERROR),
            3099  // Generic error
        );

        assert_eq!(
            determine_event_id("unknown", "Warning message", &tracing::Level::WARN),
            2099  // Generic warning
        );

        assert_eq!(
            determine_event_id("unknown", "Info message", &tracing::Level::INFO),
            1099  // Generic info
        );
    }
}
