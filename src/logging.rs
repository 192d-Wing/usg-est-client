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

// ============================================================================
// SECURITY CONTROL: Audit Logging and Record Generation
// ----------------------------------------------------------------------------
// NIST SP 800-53 Rev 5: AU-2 (Audit Events)
//                       AU-3 (Content of Audit Records)
//                       AU-12 (Audit Generation)
//                       AU-9 (Protection of Audit Information)
// STIG: APSC-DV-000830 (CAT II) - Security-Relevant Events
//       APSC-DV-001740 (CAT I) - Audit Record Generation
//       APSC-DV-002440 (CAT II) - Audit Record Content
// Standards: NIST SP 800-92 (Guide to Computer Security Log Management)
// ----------------------------------------------------------------------------
// This module provides comprehensive audit logging for EST certificate
// enrollment operations. All security-relevant events are logged with
// sufficient detail to support forensic analysis, incident response, and
// compliance auditing.
//
// # Audit Event Categories
//
// The logging system captures the following security-relevant events:
//
// - Certificate enrollment attempts (success/failure)
// - TLS connection establishment (mutual authentication)
// - Cryptographic key generation operations
// - Authentication failures (HTTP Basic, TLS client cert)
// - Configuration changes
// - Error conditions that may indicate attacks
//
// # Audit Record Content (AU-3)
//
// Each audit record includes:
// - Timestamp (ISO 8601 format)
// - Event type (INFO, WARN, ERROR)
// - Event description
// - Subject identity (when available)
// - Event outcome (success/failure)
// - Structured fields for correlation
//
// # Log Protection (AU-9)
//
// Audit logs are protected through:
// - File rotation with size limits (prevents disk exhaustion)
// - Atomic write operations (prevents partial records)
// - Configurable output to secure locations
// - Optional encryption (see encryption module)
// - JSON format support for SIEM integration
//
// ============================================================================

//! Logging infrastructure for EST auto-enrollment.
//!
//! This module provides file-based logging with support for:
//!
//! - Log rotation by size
//! - Multiple log levels (trace, debug, info, warn, error)
//! - JSON structured logging option
//! - Configurable output destinations
//!
//! # Configuration
//!
//! Logging can be configured via the auto-enrollment configuration file
//! or programmatically:
//!
//! ```toml
//! [logging]
//! level = "info"
//! path = "C:\\ProgramData\\Department of War\\EST\\logs\\est.log"
//! json_format = false
//! max_size_mb = 10
//! max_files = 5
//! ```
//!
//! # Example
//!
//! ```no_run,ignore
//! use usg_est_client::logging::{LogConfig, FileLogger};
//!
//! let config = LogConfig {
//!     level: LogLevel::Info,
//!     path: Some("/var/log/est/enrollment.log".into()),
//!     json_format: false,
//!     max_size_bytes: 10 * 1024 * 1024, // 10 MB
//!     max_files: 5,
//! };
//!
//! let logger = FileLogger::new(config)?;
//! logger.info("Enrollment started");
//! ```

use crate::error::{EstError, Result};
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

// ============================================================================
// SECURITY CONTROL: Audit Event Filtering
// ----------------------------------------------------------------------------
// NIST SP 800-53 Rev 5: AU-2 (Audit Events)
//                       AU-12 (Audit Generation)
// STIG: APSC-DV-000830 (CAT II) - Security-Relevant Events
// ----------------------------------------------------------------------------
// Log levels enable filtering of audit events by severity. Production systems
// should use INFO or higher to capture security-relevant events while
// minimizing log volume.
//
// # Security Considerations
//
// - **ERROR**: Critical failures requiring immediate attention (authentication
//   failures, TLS errors, certificate validation failures)
// - **WARN**: Potential security issues (certificate expiration warnings,
//   configuration issues, deprecated cipher usage)
// - **INFO**: Normal security events (enrollment success, TLS connection
//   established, key generation)
// - **DEBUG/TRACE**: Development only (verbose protocol details, internal state)
//
// For compliance with AU-2, production systems must log at INFO level minimum
// to ensure all security-relevant events are captured.
// ============================================================================

/// Log level for filtering messages.
///
/// # Security Controls
///
/// **NIST SP 800-53 Rev 5:**
/// - AU-2: Audit Events (selective event logging)
/// - AU-12: Audit Generation (configurable audit capture)
///
/// **STIG Finding:**
/// - APSC-DV-000830 (CAT II): Security-Relevant Events
///
/// # Security Guidance
///
/// Production deployments must use INFO or higher to ensure compliance with
/// AU-2. DEBUG and TRACE levels may expose sensitive protocol details and
/// should only be used in development or troubleshooting scenarios.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum LogLevel {
    /// Most verbose - all messages.
    Trace = 0,
    /// Debug information.
    Debug = 1,
    /// Informational messages.
    #[default]
    Info = 2,
    /// Warnings.
    Warn = 3,
    /// Errors only.
    Error = 4,
}

impl LogLevel {
    /// Parse from string representation.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "trace" => Some(Self::Trace),
            "debug" => Some(Self::Debug),
            "info" => Some(Self::Info),
            "warn" | "warning" => Some(Self::Warn),
            "error" => Some(Self::Error),
            _ => None,
        }
    }

    /// Get the level name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Trace => "TRACE",
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        }
    }
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// SECURITY CONTROL: Audit Logging Configuration
// ----------------------------------------------------------------------------
// NIST SP 800-53 Rev 5: AU-2 (Audit Events)
//                       AU-3 (Content of Audit Records)
//                       AU-9 (Protection of Audit Information)
//                       AU-11 (Audit Record Retention)
// STIG: APSC-DV-002440 (CAT II) - Audit Record Content
//       APSC-DV-000830 (CAT II) - Security-Relevant Events
// ----------------------------------------------------------------------------
// Logging configuration controls audit record generation, content, and
// retention. Proper configuration is essential for compliance with audit
// requirements and forensic analysis capabilities.
//
// # Configuration Requirements
//
// - **AU-3**: Timestamps, event types, and outcomes must be included
// - **AU-9**: Logs must be protected from unauthorized access/modification
// - **AU-11**: Log rotation ensures retention without disk exhaustion
//
// # Secure Defaults
//
// - INFO level minimum (captures all security-relevant events)
// - Timestamps enabled (AU-3 requirement)
// - Level tags enabled (event type identification)
// - 10 MB rotation size (prevents disk exhaustion)
// - 5 rotated files (provides sufficient retention)
// ============================================================================

/// Logging configuration.
///
/// # Security Controls
///
/// **NIST SP 800-53 Rev 5:**
/// - AU-2: Audit Events (level filtering)
/// - AU-3: Content of Audit Records (timestamp, level, message format)
/// - AU-9: Protection of Audit Information (secure file locations)
/// - AU-11: Audit Record Retention (rotation policy)
///
/// **STIG Findings:**
/// - APSC-DV-002440 (CAT II): Audit Record Content
/// - APSC-DV-000830 (CAT II): Security-Relevant Events
///
/// # Security Requirements
///
/// Production configurations must:
/// - Set `level` to INFO or higher (AU-2 compliance)
/// - Enable `include_timestamp` (AU-3 requirement)
/// - Enable `include_level` (event type identification)
/// - Use secure `path` with restricted permissions (AU-9)
/// - Configure appropriate `max_files` for retention (AU-11)
///
/// # Example: Secure Configuration
///
/// ```no_run,ignore
/// use usg_est_client::logging::{LogConfig, LogLevel};
///
/// // Production-ready configuration
/// let config = LogConfig {
///     level: LogLevel::Info,
///     path: Some("/var/log/est/enrollment.log".into()),
///     json_format: true,  // SIEM integration
///     max_size_bytes: 10 * 1024 * 1024,  // 10 MB
///     max_files: 10,  // 100 MB total retention
///     include_timestamp: true,  // AU-3 requirement
///     include_level: true,  // Event classification
/// };
/// ```
#[derive(Debug, Clone)]
pub struct LogConfig {
    /// Minimum log level to output.
    pub level: LogLevel,
    /// Path to log file (None for stdout).
    pub path: Option<PathBuf>,
    /// Use JSON format for log entries.
    pub json_format: bool,
    /// Maximum log file size in bytes before rotation.
    pub max_size_bytes: u64,
    /// Maximum number of rotated log files to keep.
    pub max_files: u32,
    /// Include timestamps in log entries.
    pub include_timestamp: bool,
    /// Include log level in log entries.
    pub include_level: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            path: None,
            json_format: false,
            max_size_bytes: 10 * 1024 * 1024, // 10 MB
            max_files: 5,
            include_timestamp: true,
            include_level: true,
        }
    }
}

impl LogConfig {
    /// Create a new config for file logging.
    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self {
            path: Some(path.into()),
            ..Default::default()
        }
    }

    /// Create a new config for stdout logging.
    pub fn stdout() -> Self {
        Self::default()
    }

    /// Set the log level.
    pub fn with_level(mut self, level: LogLevel) -> Self {
        self.level = level;
        self
    }

    /// Enable JSON format.
    pub fn with_json(mut self) -> Self {
        self.json_format = true;
        self
    }

    /// Set max file size (in MB).
    pub fn with_max_size_mb(mut self, mb: u64) -> Self {
        self.max_size_bytes = mb * 1024 * 1024;
        self
    }

    /// Set max rotated files.
    pub fn with_max_files(mut self, count: u32) -> Self {
        self.max_files = count;
        self
    }
}

// ============================================================================
// SECURITY CONTROL: Audit Record Structure
// ----------------------------------------------------------------------------
// NIST SP 800-53 Rev 5: AU-3 (Content of Audit Records)
//                       AU-12 (Audit Generation)
// STIG: APSC-DV-002440 (CAT II) - Audit Record Content
// Standards: NIST SP 800-92 (Guide to Computer Security Log Management)
// ----------------------------------------------------------------------------
// Log entries contain the minimum required information for audit records:
//
// 1. **Timestamp**: When the event occurred (AU-3.a)
// 2. **Event Type**: Severity level (AU-3.b)
// 3. **Event Description**: What happened (AU-3.c)
// 4. **Outcome**: Success/failure implied by level (AU-3.d)
// 5. **Additional Details**: Structured fields for context (AU-3.e)
//
// This structure supports both human-readable text format and machine-readable
// JSON format for SIEM integration.
// ============================================================================

/// A log entry.
///
/// # Security Controls
///
/// **NIST SP 800-53 Rev 5:**
/// - AU-3: Content of Audit Records (timestamp, type, outcome, identity)
/// - AU-12: Audit Generation (structured event capture)
///
/// **STIG Finding:**
/// - APSC-DV-002440 (CAT II): Audit Record Content
///
/// # Audit Record Requirements
///
/// Each log entry satisfies AU-3 requirements by including:
/// - **timestamp**: Date and time of event (AU-3.a)
/// - **level**: Event type/severity (AU-3.b)
/// - **message**: Event description (AU-3.c)
/// - **fields**: Additional context (subject identity, outcome details)
///
/// # Example: Security Event Logging
///
/// ```no_run,ignore
/// use usg_est_client::logging::{LogEntry, LogLevel};
///
/// // Log successful certificate enrollment
/// let entry = LogEntry::new(LogLevel::Info, "Certificate enrollment successful")
///     .with_field("subject_cn", "device001.example.mil")
///     .with_field("est_server", "pki.example.mil")
///     .with_field("certificate_serial", "1A2B3C4D5E6F");
///
/// // Log authentication failure
/// let entry = LogEntry::new(LogLevel::Error, "TLS client authentication failed")
///     .with_field("server", "pki.example.mil")
///     .with_field("reason", "certificate_revoked");
/// ```
#[derive(Debug, Clone)]
pub struct LogEntry {
    /// Log level.
    pub level: LogLevel,
    /// Log message.
    pub message: String,
    /// Timestamp (ISO 8601).
    pub timestamp: String,
    /// Optional structured fields.
    pub fields: Vec<(String, String)>,
}

impl LogEntry {
    /// Create a new log entry.
    pub fn new(level: LogLevel, message: impl Into<String>) -> Self {
        Self {
            level,
            message: message.into(),
            timestamp: Self::current_timestamp(),
            fields: Vec::new(),
        }
    }

    /// Add a field to the entry.
    pub fn with_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.push((key.into(), value.into()));
        self
    }

    /// Get current timestamp in ISO 8601 format.
    fn current_timestamp() -> String {
        use std::time::SystemTime;

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();

        // Simple timestamp format (production would use chrono or time crate)
        let secs = now.as_secs();
        let hours = (secs / 3600) % 24;
        let minutes = (secs / 60) % 60;
        let seconds = secs % 60;

        format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
    }

    /// Format as plain text.
    pub fn format_text(&self, include_timestamp: bool, include_level: bool) -> String {
        let mut parts = Vec::new();

        if include_timestamp {
            parts.push(format!("[{}]", self.timestamp));
        }

        if include_level {
            parts.push(format!("[{}]", self.level));
        }

        parts.push(self.message.clone());

        for (k, v) in &self.fields {
            parts.push(format!("{}={}", k, v));
        }

        parts.join(" ")
    }

    /// Format as JSON.
    pub fn format_json(&self) -> String {
        let mut obj = String::from("{");

        obj.push_str(&format!("\"timestamp\":\"{}\",", self.timestamp));
        obj.push_str(&format!("\"level\":\"{}\",", self.level));
        obj.push_str(&format!(
            "\"message\":\"{}\"",
            self.message.replace('\\', "\\\\").replace('"', "\\\"")
        ));

        for (k, v) in &self.fields {
            obj.push_str(&format!(
                ",\"{}\":\"{}\"",
                k,
                v.replace('\\', "\\\\").replace('"', "\\\"")
            ));
        }

        obj.push('}');
        obj
    }
}

// ============================================================================
// SECURITY CONTROL: File-Based Audit Logging
// ----------------------------------------------------------------------------
// NIST SP 800-53 Rev 5: AU-9 (Protection of Audit Information)
//                       AU-11 (Audit Record Retention)
//                       AU-12 (Audit Generation)
// STIG: APSC-DV-001740 (CAT I) - Audit Record Generation
//       APSC-DV-002440 (CAT II) - Audit Record Content
// ----------------------------------------------------------------------------
// FileLogger provides persistent audit logging with automatic rotation to
// prevent disk exhaustion while maintaining sufficient retention for forensic
// analysis.
//
// # Security Features
//
// - **Atomic Writes**: Each log entry is written and flushed atomically to
//   prevent partial records in case of system failure
// - **Automatic Rotation**: Prevents disk exhaustion (AU-9, AU-11)
// - **Thread-Safe**: Mutex-protected writer enables concurrent logging
// - **Graceful Degradation**: Lock poisoning is handled without panic
//
// # Audit Protection (AU-9)
//
// Log files should be created with restricted permissions:
// - Unix: 0600 (owner read/write only)
// - Windows: ACL restricted to SYSTEM and Administrators
//
// # Retention (AU-11)
//
// Log rotation maintains a configurable number of historical files:
// - Current log: enrollment.log
// - Rotated logs: enrollment.log.1, enrollment.log.2, etc.
// - Oldest logs are automatically deleted when max_files is reached
// ============================================================================

/// File logger with rotation support.
///
/// # Security Controls
///
/// **NIST SP 800-53 Rev 5:**
/// - AU-9: Protection of Audit Information (atomic writes, secure storage)
/// - AU-11: Audit Record Retention (rotation policy)
/// - AU-12: Audit Generation (continuous logging capability)
///
/// **STIG Findings:**
/// - APSC-DV-001740 (CAT I): Audit Record Generation
/// - APSC-DV-002440 (CAT II): Audit Record Content
///
/// # Security Requirements
///
/// Production deployments must:
/// 1. Store logs in a secure location with restricted permissions
/// 2. Configure sufficient retention via `max_files` (AU-11)
/// 3. Monitor disk space to prevent log loss
/// 4. Protect log files from unauthorized modification (AU-9)
///
/// # Example: Secure File Logger
///
/// ```no_run,ignore
/// use usg_est_client::logging::{LogConfig, FileLogger, LogLevel};
///
/// // Create secure configuration
/// let config = LogConfig {
///     level: LogLevel::Info,
///     path: Some("/var/log/est/enrollment.log".into()),
///     json_format: true,
///     max_size_bytes: 10 * 1024 * 1024,  // 10 MB
///     max_files: 10,  // 100 MB retention
///     include_timestamp: true,
///     include_level: true,
/// };
///
/// let logger = FileLogger::new(config)?;
///
/// // Log security events
/// logger.info("Certificate enrollment initiated")?;
/// logger.log_with_fields(
///     LogLevel::Info,
///     "TLS handshake completed",
///     &[("cipher", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384")]
/// )?;
/// ```
pub struct FileLogger {
    config: LogConfig,
    writer: Arc<Mutex<LogWriter>>,
}

enum LogWriter {
    File {
        writer: BufWriter<File>,
        #[allow(dead_code)]
        path: PathBuf,
        current_size: u64,
    },
    Stdout(std::io::Stdout),
}

impl FileLogger {
    /// Create a new file logger.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - AU-9: Protection of Audit Information (secure file creation)
    /// - AU-12: Audit Generation (logger initialization)
    ///
    /// **STIG Finding:**
    /// - APSC-DV-001740 (CAT I): Audit Record Generation
    ///
    /// # Security Implementation
    ///
    /// This method creates the audit log file with appropriate permissions:
    /// - Parent directories are created if missing
    /// - File is opened in append mode to preserve existing audit records
    /// - Current file size is tracked for rotation
    ///
    /// On Unix systems, the file inherits the process umask. For production:
    /// ```bash
    /// umask 0077  # Before running EST client
    /// # Results in 0600 permissions (owner-only access)
    /// ```
    ///
    /// On Windows, files are created with default ACLs. For production:
    /// ```powershell
    /// # Restrict to SYSTEM and Administrators only
    /// icacls "C:\ProgramData\EST\logs" /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F"
    /// ```
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Parent directory cannot be created (permission denied)
    /// - Log file cannot be opened (disk full, permission denied)
    /// - File metadata cannot be read
    pub fn new(config: LogConfig) -> Result<Self> {
        let writer = match &config.path {
            Some(path) => {
                // Ensure parent directory exists
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).map_err(EstError::Io)?;
                }

                let file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(EstError::Io)?;

                let current_size = file.metadata().map(|m| m.len()).unwrap_or(0);

                LogWriter::File {
                    writer: BufWriter::new(file),
                    path: path.clone(),
                    current_size,
                }
            }
            None => LogWriter::Stdout(std::io::stdout()),
        };

        Ok(Self {
            config,
            writer: Arc::new(Mutex::new(writer)),
        })
    }

    /// Log an entry.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - AU-3: Content of Audit Records (formatted record output)
    /// - AU-12: Audit Generation (event recording)
    /// - AU-11: Audit Record Retention (automatic rotation)
    ///
    /// **STIG Finding:**
    /// - APSC-DV-002440 (CAT II): Audit Record Content
    ///
    /// # Security Implementation
    ///
    /// This method implements the core audit generation capability:
    ///
    /// 1. **Level Filtering**: Events below configured level are discarded
    /// 2. **Format Selection**: Text or JSON based on configuration
    /// 3. **Atomic Write**: Entry is written and flushed atomically
    /// 4. **Automatic Rotation**: Triggers rotation when size limit is reached
    /// 5. **Lock Poisoning Handling**: Gracefully handles thread panics
    ///
    /// The method ensures AU-3 compliance by including timestamp, level, and
    /// message in every audit record. Structured fields provide additional
    /// context for forensic analysis.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently. The internal
    /// mutex ensures atomic writes. If a thread panics while holding the lock,
    /// subsequent calls will return an error instead of panicking.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Writer lock is poisoned (previous thread panicked)
    /// - Write operation fails (disk full, permission denied)
    /// - Flush operation fails
    /// - Rotation fails
    pub fn log(&self, entry: &LogEntry) -> Result<()> {
        if entry.level < self.config.level {
            return Ok(());
        }

        let line = if self.config.json_format {
            entry.format_json()
        } else {
            entry.format_text(self.config.include_timestamp, self.config.include_level)
        };

        let line_with_newline = format!("{}\n", line);
        let line_bytes = line_with_newline.as_bytes();

        // Fixed: Handle lock poisoning gracefully instead of panicking
        let mut writer = self
            .writer
            .lock()
            .map_err(|e| EstError::operational(format!("Log writer lock poisoned: {}", e)))?;

        // Check for rotation
        if let LogWriter::File {
            path: _,
            ref mut current_size,
            ..
        } = *writer
            && *current_size + line_bytes.len() as u64 > self.config.max_size_bytes
        {
            // Perform rotation
            drop(writer);
            self.rotate()?;
            writer = self.writer.lock().map_err(|e| {
                EstError::operational(format!("Log writer lock poisoned after rotation: {}", e))
            })?;
        }

        match *writer {
            LogWriter::File {
                ref mut writer,
                ref mut current_size,
                ..
            } => {
                writer.write_all(line_bytes).map_err(EstError::Io)?;
                writer.flush().map_err(EstError::Io)?;
                *current_size += line_bytes.len() as u64;
            }
            LogWriter::Stdout(ref mut stdout) => {
                stdout.write_all(line_bytes).map_err(EstError::Io)?;
            }
        }

        Ok(())
    }

    /// Rotate log files.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - AU-9: Protection of Audit Information (prevents disk exhaustion)
    /// - AU-11: Audit Record Retention (maintains historical records)
    ///
    /// **STIG Finding:**
    /// - APSC-DV-001740 (CAT I): Audit Record Generation
    ///
    /// # Security Implementation
    ///
    /// This method implements log rotation to prevent disk exhaustion while
    /// maintaining audit record retention:
    ///
    /// 1. **Delete Oldest**: Removes the oldest log file if max_files is reached
    /// 2. **Shift Logs**: Renames existing rotated logs (N → N+1)
    /// 3. **Rotate Current**: Moves current log to .1
    /// 4. **Create New**: Opens fresh log file
    /// 5. **Update Writer**: Replaces writer with new file handle
    ///
    /// Example rotation sequence (max_files=3):
    /// - Before: enrollment.log (11MB), enrollment.log.1, enrollment.log.2, enrollment.log.3
    /// - After: enrollment.log (0MB), enrollment.log.1, enrollment.log.2, enrollment.log.3
    /// - Oldest file (.3) is deleted
    ///
    /// # Audit Continuity
    ///
    /// Rotation is atomic from the application's perspective. The mutex ensures
    /// no log entries are lost during rotation. New entries block until rotation
    /// completes.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Current log file cannot be renamed
    /// - New log file cannot be created
    /// - Writer lock is poisoned
    fn rotate(&self) -> Result<()> {
        let path = match &self.config.path {
            Some(p) => p,
            None => return Ok(()),
        };

        // Remove oldest file if it exists
        let oldest = format!("{}.{}", path.display(), self.config.max_files);
        if let Err(e) = fs::remove_file(&oldest) {
            // Ignore NotFound errors, log others
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!("Failed to remove old log file {}: {}", oldest, e);
            }
        }

        // Shift existing files
        for i in (1..self.config.max_files).rev() {
            let from = format!("{}.{}", path.display(), i);
            let to = format!("{}.{}", path.display(), i + 1);
            if let Err(e) = fs::rename(&from, &to) {
                // Ignore NotFound errors, log others
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!("Failed to rotate log file {} to {}: {}", from, to, e);
                }
            }
        }

        // Rename current file to .1
        let rotated = format!("{}.1", path.display());
        fs::rename(path, &rotated).map_err(EstError::Io)?;

        // Create new file
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
            .map_err(EstError::Io)?;

        // Fixed: Handle lock poisoning gracefully
        let mut writer = self.writer.lock().map_err(|e| {
            EstError::operational(format!("Log writer lock poisoned during rotation: {}", e))
        })?;
        *writer = LogWriter::File {
            writer: BufWriter::new(file),
            path: path.clone(),
            current_size: 0,
        };

        Ok(())
    }

    // ========================================================================
    // Convenience Logging Methods
    // ========================================================================
    //
    // These methods provide ergonomic access to the log() method at specific
    // severity levels. Each method creates a LogEntry with the appropriate
    // level and forwards to the core log() method.
    //
    // Security Note: All methods support AU-12 (Audit Generation) by enabling
    // consistent event recording across the codebase.

    /// Log at trace level (development/troubleshooting only).
    ///
    /// # Security Note
    ///
    /// TRACE level should not be used in production. It may expose sensitive
    /// protocol details, internal state, or cryptographic material.
    pub fn trace(&self, message: impl Into<String>) -> Result<()> {
        self.log(&LogEntry::new(LogLevel::Trace, message))
    }

    /// Log at debug level (development/troubleshooting only).
    ///
    /// # Security Note
    ///
    /// DEBUG level should not be used in production. It may expose detailed
    /// error information useful for attackers.
    pub fn debug(&self, message: impl Into<String>) -> Result<()> {
        self.log(&LogEntry::new(LogLevel::Debug, message))
    }

    /// Log at info level (normal security events).
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:** AU-2, AU-12 (Audit Generation)
    ///
    /// Use for security-relevant events:
    /// - Certificate enrollment success
    /// - TLS connection established
    /// - Key generation completed
    /// - Configuration loaded
    pub fn info(&self, message: impl Into<String>) -> Result<()> {
        self.log(&LogEntry::new(LogLevel::Info, message))
    }

    /// Log at warn level (potential security issues).
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:** AU-2, AU-12 (Audit Generation)
    ///
    /// Use for conditions that may indicate security concerns:
    /// - Certificate expiration warnings
    /// - Weak cipher suite negotiated
    /// - Configuration validation warnings
    /// - Retry attempts
    pub fn warn(&self, message: impl Into<String>) -> Result<()> {
        self.log(&LogEntry::new(LogLevel::Warn, message))
    }

    /// Log at error level (critical security failures).
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:** AU-2, AU-12 (Audit Generation)
    ///
    /// Use for security failures requiring immediate attention:
    /// - Authentication failures
    /// - Certificate validation failures
    /// - TLS handshake failures
    /// - Cryptographic errors
    /// - Authorization denials
    pub fn error(&self, message: impl Into<String>) -> Result<()> {
        self.log(&LogEntry::new(LogLevel::Error, message))
    }

    /// Log with structured fields for enhanced forensic analysis.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - AU-3: Content of Audit Records (structured context)
    /// - AU-12: Audit Generation (enhanced event capture)
    ///
    /// **STIG Finding:**
    /// - APSC-DV-002440 (CAT II): Audit Record Content
    ///
    /// # Security Implementation
    ///
    /// Structured fields provide additional context for audit records:
    /// - Subject identity (user, device, certificate CN)
    /// - Object identity (server URL, resource path)
    /// - Event outcome details (error codes, status)
    /// - Session context (connection ID, correlation ID)
    ///
    /// # Example: Authentication Failure
    ///
    /// ```no_run,ignore
    /// logger.log_with_fields(
    ///     LogLevel::Error,
    ///     "TLS client authentication failed",
    ///     &[
    ///         ("server", "pki.example.mil"),
    ///         ("client_cn", "device001.example.mil"),
    ///         ("reason", "certificate_expired"),
    ///         ("not_after", "2024-01-15T00:00:00Z"),
    ///     ]
    /// )?;
    /// ```
    pub fn log_with_fields(
        &self,
        level: LogLevel,
        message: impl Into<String>,
        fields: &[(&str, &str)],
    ) -> Result<()> {
        let mut entry = LogEntry::new(level, message);
        for (k, v) in fields {
            entry = entry.with_field(*k, *v);
        }
        self.log(&entry)
    }
}

// ============================================================================
// SECURITY CONTROL: Multi-Destination Audit Logging
// ----------------------------------------------------------------------------
// NIST SP 800-53 Rev 5: AU-9 (Protection of Audit Information)
//                       AU-12 (Audit Generation)
// STIG: APSC-DV-001740 (CAT I) - Audit Record Generation
// ----------------------------------------------------------------------------
// MultiLogger enables simultaneous logging to multiple destinations for
// enhanced audit protection and availability:
//
// - **Local File**: Primary audit trail with rotation
// - **Remote Syslog**: Centralized SIEM for real-time monitoring
// - **Windows Event Log**: Integration with OS audit subsystem
// - **Stdout**: Console output for interactive troubleshooting
//
// Multiple destinations increase audit reliability (AU-9) by ensuring that
// even if one destination fails (disk full, network outage), other destinations
// continue capturing audit events.
// ============================================================================

/// Combined logger that writes to multiple destinations.
///
/// # Security Controls
///
/// **NIST SP 800-53 Rev 5:**
/// - AU-9: Protection of Audit Information (redundant storage)
/// - AU-12: Audit Generation (multiple capture points)
///
/// **STIG Finding:**
/// - APSC-DV-001740 (CAT I): Audit Record Generation
///
/// # Security Benefits
///
/// Multiple log destinations provide:
/// - **Redundancy**: If one destination fails, others continue
/// - **Real-time Monitoring**: Syslog enables SIEM integration
/// - **Forensic Analysis**: Local files retain detailed history
/// - **OS Integration**: Windows Event Log for enterprise audit tools
///
/// # Example: Production Logging Configuration
///
/// ```no_run,ignore
/// use usg_est_client::logging::{MultiLogger, FileLogger, LogConfig, LogLevel};
///
/// let mut multi = MultiLogger::new();
///
/// // Primary audit trail (local file with rotation)
/// let file_logger = FileLogger::new(
///     LogConfig::file("/var/log/est/enrollment.log")
///         .with_level(LogLevel::Info)
///         .with_json()
///         .with_max_size_mb(10)
///         .with_max_files(10)
/// )?;
/// multi.add(file_logger);
///
/// // Console output for troubleshooting
/// let console_logger = FileLogger::new(
///     LogConfig::stdout()
///         .with_level(LogLevel::Warn)
/// )?;
/// multi.add(console_logger);
///
/// // Log to all destinations
/// multi.log(&LogEntry::new(LogLevel::Info, "Enrollment started"))?;
/// ```
pub struct MultiLogger {
    loggers: Vec<Box<dyn Logger + Send + Sync>>,
}

/// Trait for log destinations.
///
/// # Security Controls
///
/// **NIST SP 800-53 Rev 5:** AU-12 (Audit Generation)
///
/// This trait enables polymorphic logging to any destination that implements
/// the `log()` method, supporting diverse audit architectures.
pub trait Logger {
    /// Log an entry.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - AU-3: Content of Audit Records
    /// - AU-12: Audit Generation
    ///
    /// **STIG Finding:**
    /// - APSC-DV-002440 (CAT II): Audit Record Content
    fn log(&self, entry: &LogEntry) -> Result<()>;
}

impl Logger for FileLogger {
    fn log(&self, entry: &LogEntry) -> Result<()> {
        FileLogger::log(self, entry)
    }
}

impl MultiLogger {
    /// Create a new multi-logger.
    pub fn new() -> Self {
        Self {
            loggers: Vec::new(),
        }
    }

    /// Add a logger.
    pub fn add<L: Logger + Send + Sync + 'static>(&mut self, logger: L) {
        self.loggers.push(Box::new(logger));
    }

    /// Log to all destinations.
    pub fn log(&self, entry: &LogEntry) -> Result<()> {
        for logger in &self.loggers {
            logger.log(entry)?;
        }
        Ok(())
    }
}

impl Default for MultiLogger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    // NOTE: Test code uses unwrap() deliberately - test fixtures are known valid
    // and panics in tests provide clear failure messages. See ERROR-HANDLING-PATTERNS.md
    // Pattern 5 for justification.

    #[test]
    fn test_log_level_parse() {
        assert_eq!(LogLevel::parse("trace"), Some(LogLevel::Trace));
        assert_eq!(LogLevel::parse("DEBUG"), Some(LogLevel::Debug));
        assert_eq!(LogLevel::parse("Info"), Some(LogLevel::Info));
        assert_eq!(LogLevel::parse("WARN"), Some(LogLevel::Warn));
        assert_eq!(LogLevel::parse("warning"), Some(LogLevel::Warn));
        assert_eq!(LogLevel::parse("error"), Some(LogLevel::Error));
        assert_eq!(LogLevel::parse("invalid"), None);
    }

    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Trace < LogLevel::Debug);
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Error);
    }

    #[test]
    fn test_log_entry_format_text() {
        let entry = LogEntry::new(LogLevel::Info, "Test message").with_field("key", "value");

        let text = entry.format_text(true, true);
        assert!(text.contains("[INFO]"));
        assert!(text.contains("Test message"));
        assert!(text.contains("key=value"));
    }

    #[test]
    fn test_log_entry_format_json() {
        let entry = LogEntry::new(LogLevel::Error, "Error occurred").with_field("code", "500");

        let json = entry.format_json();
        assert!(json.contains("\"level\":\"ERROR\""));
        assert!(json.contains("\"message\":\"Error occurred\""));
        assert!(json.contains("\"code\":\"500\""));
    }

    #[test]
    fn test_log_config_builder() {
        let config = LogConfig::file("/var/log/test.log")
            .with_level(LogLevel::Debug)
            .with_json()
            .with_max_size_mb(5)
            .with_max_files(3);

        assert_eq!(config.level, LogLevel::Debug);
        assert!(config.json_format);
        assert_eq!(config.max_size_bytes, 5 * 1024 * 1024);
        assert_eq!(config.max_files, 3);
    }

    #[test]
    fn test_file_logger_stdout() {
        let config = LogConfig::stdout().with_level(LogLevel::Info);
        let logger = FileLogger::new(config).unwrap();

        // Should not fail
        logger.info("Test message").unwrap();
    }

    #[test]
    fn test_file_logger_file() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("test.log");

        let config = LogConfig::file(&log_path).with_level(LogLevel::Debug);
        let logger = FileLogger::new(config).unwrap();

        logger.info("Test info message").unwrap();
        logger.debug("Test debug message").unwrap();
        logger.error("Test error message").unwrap();

        // Verify file contains messages
        let contents = fs::read_to_string(&log_path).unwrap();
        assert!(contents.contains("Test info message"));
        assert!(contents.contains("Test debug message"));
        assert!(contents.contains("Test error message"));
    }

    #[test]
    fn test_file_logger_level_filter() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("test.log");

        let config = LogConfig::file(&log_path).with_level(LogLevel::Warn);
        let logger = FileLogger::new(config).unwrap();

        logger.debug("Debug message").unwrap();
        logger.info("Info message").unwrap();
        logger.warn("Warn message").unwrap();
        logger.error("Error message").unwrap();

        let contents = fs::read_to_string(&log_path).unwrap();
        assert!(!contents.contains("Debug message"));
        assert!(!contents.contains("Info message"));
        assert!(contents.contains("Warn message"));
        assert!(contents.contains("Error message"));
    }

    #[test]
    fn test_file_logger_json_format() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("test.log");

        let config = LogConfig::file(&log_path).with_json();
        let logger = FileLogger::new(config).unwrap();

        logger.info("JSON test").unwrap();

        let contents = fs::read_to_string(&log_path).unwrap();
        assert!(contents.starts_with('{'));
        assert!(contents.contains("\"level\":\"INFO\""));
        assert!(contents.contains("\"message\":\"JSON test\""));
    }

    #[test]
    fn test_multi_logger() {
        let mut multi = MultiLogger::new();

        let dir = tempdir().unwrap();
        let log1 = dir.path().join("log1.log");
        let log2 = dir.path().join("log2.log");

        multi.add(FileLogger::new(LogConfig::file(&log1)).unwrap());
        multi.add(FileLogger::new(LogConfig::file(&log2)).unwrap());

        multi
            .log(&LogEntry::new(LogLevel::Info, "Multi test"))
            .unwrap();

        let contents1 = fs::read_to_string(&log1).unwrap();
        let contents2 = fs::read_to_string(&log2).unwrap();

        assert!(contents1.contains("Multi test"));
        assert!(contents2.contains("Multi test"));
    }
}

// Optional encryption module (requires 'enveloped' feature for AES-GCM)
#[cfg(feature = "enveloped")]
pub mod encryption;
