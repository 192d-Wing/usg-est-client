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

/// Log level for filtering messages.
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

/// Logging configuration.
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

/// A log entry.
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

/// File logger with rotation support.
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

    // Convenience logging methods

    /// Log at trace level.
    pub fn trace(&self, message: impl Into<String>) -> Result<()> {
        self.log(&LogEntry::new(LogLevel::Trace, message))
    }

    /// Log at debug level.
    pub fn debug(&self, message: impl Into<String>) -> Result<()> {
        self.log(&LogEntry::new(LogLevel::Debug, message))
    }

    /// Log at info level.
    pub fn info(&self, message: impl Into<String>) -> Result<()> {
        self.log(&LogEntry::new(LogLevel::Info, message))
    }

    /// Log at warn level.
    pub fn warn(&self, message: impl Into<String>) -> Result<()> {
        self.log(&LogEntry::new(LogLevel::Warn, message))
    }

    /// Log at error level.
    pub fn error(&self, message: impl Into<String>) -> Result<()> {
        self.log(&LogEntry::new(LogLevel::Error, message))
    }

    /// Log with structured fields.
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

/// Combined logger that writes to multiple destinations.
pub struct MultiLogger {
    loggers: Vec<Box<dyn Logger + Send + Sync>>,
}

/// Trait for log destinations.
pub trait Logger {
    /// Log an entry.
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
