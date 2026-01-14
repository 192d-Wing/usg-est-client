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

//! OpenTelemetry metrics exporter for EST operations.
//!
//! This module provides OpenTelemetry-compatible metrics export using the
//! Prometheus exporter as a backend. OpenTelemetry service metadata is added
//! to the exported metrics.
//!
//! # Example
//!
//! ```no_run
//! use usg_est_client::metrics::{MetricsCollector, OperationType};
//! use usg_est_client::metrics::opentelemetry::OpenTelemetryExporter;
//! use std::time::Instant;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create OpenTelemetry exporter
//! let exporter = OpenTelemetryExporter::new("est-client", "0.1.0")?;
//!
//! // Create metrics collector
//! let metrics = MetricsCollector::new();
//!
//! // Record operations
//! let start = Instant::now();
//! // ... perform EST operation ...
//! metrics.record_operation(OperationType::SimpleEnroll, start.elapsed(), true).await;
//!
//! // Export metrics
//! let prometheus_text = exporter.export(&metrics).await?;
//! println!("{}", prometheus_text);
//!
//! // Shutdown
//! exporter.shutdown()?;
//! # Ok(())
//! # }
//! ```

use crate::metrics::MetricsCollector;
use crate::metrics::prometheus::PrometheusExporter;
use std::error::Error as StdError;

/// OpenTelemetry metrics exporter for EST client operations.
///
/// This exporter wraps the Prometheus exporter and adds OpenTelemetry
/// semantic conventions and service metadata.
pub struct OpenTelemetryExporter {
    service_name: String,
    service_version: String,
    prometheus_exporter: PrometheusExporter,
}

impl OpenTelemetryExporter {
    /// Create a new OpenTelemetry exporter with Prometheus backend.
    ///
    /// # Arguments
    ///
    /// * `service_name` - Name of the service (e.g., "est-client")
    /// * `service_version` - Version of the service (e.g., "0.1.0")
    ///
    /// # Errors
    ///
    /// Returns an error if the Prometheus exporter cannot be initialized.
    pub fn new(service_name: &str, service_version: &str) -> Result<Self, Box<dyn StdError>> {
        // Create Prometheus exporter with OpenTelemetry-compatible namespace
        let prometheus_exporter = PrometheusExporter::new("est")?;

        Ok(Self {
            service_name: service_name.to_string(),
            service_version: service_version.to_string(),
            prometheus_exporter,
        })
    }

    /// Export metrics in Prometheus format with OpenTelemetry metadata.
    ///
    /// # Arguments
    ///
    /// * `collector` - The metrics collector to export from
    ///
    /// # Returns
    ///
    /// A string containing the metrics in Prometheus text format with
    /// OpenTelemetry service metadata as comments.
    pub async fn export(&self, collector: &MetricsCollector) -> Result<String, Box<dyn StdError>> {
        let output = self.prometheus_exporter.export(collector).await?;

        // Add OpenTelemetry service metadata as Prometheus comments
        let mut result = String::new();
        result.push_str("# OpenTelemetry Semantic Conventions\n");
        result.push_str(&format!("# service.name=\"{}\"\n", self.service_name));
        result.push_str(&format!("# service.version=\"{}\"\n", self.service_version));
        result.push('\n');
        result.push_str(&output);

        Ok(result)
    }

    /// Get a reference to the underlying Prometheus exporter.
    pub fn prometheus_exporter(&self) -> &PrometheusExporter {
        &self.prometheus_exporter
    }

    /// Shutdown the OpenTelemetry pipeline.
    ///
    /// This should be called before the application exits to ensure all
    /// metrics are flushed.
    pub fn shutdown(self) -> Result<(), Box<dyn StdError>> {
        // No cleanup needed for Prometheus exporter
        Ok(())
    }

    /// Get service name.
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    /// Get service version.
    pub fn service_version(&self) -> &str {
        &self.service_version
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::OperationType;
    use std::time::Duration;

    // NOTE: Test code uses unwrap() deliberately - test fixtures are known valid
    // and panics in tests provide clear failure messages. See ERROR-HANDLING-PATTERNS.md
    // Pattern 5 for justification.

    #[tokio::test]
    async fn test_opentelemetry_exporter_creation() {
        let exporter = OpenTelemetryExporter::new("test-est-client", "0.1.0");
        assert!(exporter.is_ok());
        if let Ok(exp) = exporter {
            assert_eq!(exp.service_name(), "test-est-client");
            assert_eq!(exp.service_version(), "0.1.0");
            exp.shutdown().unwrap();
        }
    }

    #[tokio::test]
    async fn test_opentelemetry_export() {
        let collector = MetricsCollector::new();
        let exporter = OpenTelemetryExporter::new("test-est", "0.1.0").unwrap();

        // Record operations
        collector
            .record_operation(
                OperationType::SimpleEnroll,
                Duration::from_millis(100),
                true,
            )
            .await;
        collector
            .record_tls_handshake(Duration::from_millis(25), true)
            .await;

        // Export
        let output = exporter.export(&collector).await.unwrap();

        // Should contain metric data and service metadata
        assert!(!output.is_empty());
        assert!(output.contains("OpenTelemetry"));
        assert!(output.contains("service.name"));
        assert!(output.contains("test-est"));

        exporter.shutdown().unwrap();
    }

    #[tokio::test]
    async fn test_opentelemetry_shutdown() {
        let exporter = OpenTelemetryExporter::new("test-est", "0.1.0").unwrap();
        // Should not panic
        exporter.shutdown().unwrap();
    }

    #[tokio::test]
    async fn test_opentelemetry_service_metadata() {
        let exporter = OpenTelemetryExporter::new("my-service", "1.2.3").unwrap();
        assert_eq!(exporter.service_name(), "my-service");
        assert_eq!(exporter.service_version(), "1.2.3");
        exporter.shutdown().unwrap();
    }

    #[tokio::test]
    async fn test_opentelemetry_metric_format() {
        let collector = MetricsCollector::new();
        let exporter = OpenTelemetryExporter::new("est-service", "2.0.0").unwrap();

        collector
            .record_operation(OperationType::FullCmc, Duration::from_millis(200), true)
            .await;

        let output = exporter.export(&collector).await.unwrap();

        // Verify OpenTelemetry metadata is present
        assert!(output.contains("service.version=\"2.0.0\""));
        assert!(output.contains("service.name=\"est-service\""));

        // Verify Prometheus metrics are still present
        assert!(output.contains("est_operation_success_rate"));

        exporter.shutdown().unwrap();
    }
}
