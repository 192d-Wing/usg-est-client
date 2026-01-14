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

//! Prometheus metrics exporter for EST operations.
//!
//! This module provides Prometheus-compatible metrics export using the
//! `prometheus` crate. Metrics are exposed in the standard Prometheus text
//! format for scraping by Prometheus servers.
//!
//! # Example
//!
//! ```no_run
//! use usg_est_client::metrics::{MetricsCollector, OperationType};
//! use usg_est_client::metrics::prometheus::PrometheusExporter;
//! use std::time::Instant;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create metrics collector
//! let metrics = MetricsCollector::new();
//!
//! // Create Prometheus exporter
//! let exporter = PrometheusExporter::new("est_client")?;
//!
//! // Record some operations
//! let start = Instant::now();
//! // ... perform EST operation ...
//! metrics.record_operation(OperationType::SimpleEnroll, start.elapsed(), true).await;
//!
//! // Export metrics to Prometheus format
//! let prometheus_text = exporter.export(&metrics).await?;
//! println!("{}", prometheus_text);
//! # Ok(())
//! # }
//! ```

use crate::metrics::{MetricsCollector, MetricsSummary};
use prometheus::{
    Counter, CounterVec, Encoder, Gauge, GaugeVec, Histogram, HistogramOpts, HistogramVec, Opts,
    Registry, TextEncoder,
};
use std::error::Error as StdError;

/// Prometheus metrics exporter for EST client operations.
///
/// Fields are stored to keep the metrics registered with the registry.
/// They are accessed through the registry for export, not directly.
#[allow(dead_code)]
pub struct PrometheusExporter {
    registry: Registry,

    // Operation counters
    operations_total: CounterVec,
    operations_success: CounterVec,
    operations_failed: CounterVec,

    // Operation duration histograms
    operation_duration_seconds: HistogramVec,

    // Operation gauges (for current metrics snapshot)
    operation_duration_min_seconds: GaugeVec,
    operation_duration_max_seconds: GaugeVec,
    operation_duration_avg_seconds: GaugeVec,
    operation_success_rate: GaugeVec,

    // TLS metrics
    tls_handshakes_total: Counter,
    tls_handshakes_success: Counter,
    tls_handshakes_failed: Counter,
    tls_handshake_duration_seconds: Histogram,
    tls_handshake_success_rate: Gauge,
}

impl PrometheusExporter {
    /// Create a new Prometheus exporter with the specified namespace.
    ///
    /// # Arguments
    ///
    /// * `namespace` - Prefix for all metric names (e.g., "est_client")
    ///
    /// # Errors
    ///
    /// Returns an error if metrics cannot be registered with Prometheus.
    pub fn new(namespace: &str) -> Result<Self, Box<dyn StdError>> {
        let registry = Registry::new();

        // Operation counters
        let operations_total = CounterVec::new(
            Opts::new(
                format!("{}_operations_total", namespace),
                "Total number of EST operations by type",
            ),
            &["operation"],
        )?;

        let operations_success = CounterVec::new(
            Opts::new(
                format!("{}_operations_success_total", namespace),
                "Total number of successful EST operations by type",
            ),
            &["operation"],
        )?;

        let operations_failed = CounterVec::new(
            Opts::new(
                format!("{}_operations_failed_total", namespace),
                "Total number of failed EST operations by type",
            ),
            &["operation"],
        )?;

        // Operation duration histogram
        let operation_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                format!("{}_operation_duration_seconds", namespace),
                "EST operation duration in seconds",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
            &["operation"],
        )?;

        // Operation duration gauges
        let operation_duration_min_seconds = GaugeVec::new(
            Opts::new(
                format!("{}_operation_duration_min_seconds", namespace),
                "Minimum EST operation duration in seconds by type",
            ),
            &["operation"],
        )?;

        let operation_duration_max_seconds = GaugeVec::new(
            Opts::new(
                format!("{}_operation_duration_max_seconds", namespace),
                "Maximum EST operation duration in seconds by type",
            ),
            &["operation"],
        )?;

        let operation_duration_avg_seconds = GaugeVec::new(
            Opts::new(
                format!("{}_operation_duration_avg_seconds", namespace),
                "Average EST operation duration in seconds by type",
            ),
            &["operation"],
        )?;

        let operation_success_rate = GaugeVec::new(
            Opts::new(
                format!("{}_operation_success_rate", namespace),
                "EST operation success rate (0-100) by type",
            ),
            &["operation"],
        )?;

        // TLS metrics
        let tls_handshakes_total = Counter::with_opts(Opts::new(
            format!("{}_tls_handshakes_total", namespace),
            "Total number of TLS handshakes",
        ))?;

        let tls_handshakes_success = Counter::with_opts(Opts::new(
            format!("{}_tls_handshakes_success_total", namespace),
            "Total number of successful TLS handshakes",
        ))?;

        let tls_handshakes_failed = Counter::with_opts(Opts::new(
            format!("{}_tls_handshakes_failed_total", namespace),
            "Total number of failed TLS handshakes",
        ))?;

        let tls_handshake_duration_seconds = Histogram::with_opts(
            HistogramOpts::new(
                format!("{}_tls_handshake_duration_seconds", namespace),
                "TLS handshake duration in seconds",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]),
        )?;

        let tls_handshake_success_rate = Gauge::with_opts(Opts::new(
            format!("{}_tls_handshake_success_rate", namespace),
            "TLS handshake success rate (0-100)",
        ))?;

        // Register all metrics
        registry.register(Box::new(operations_total.clone()))?;
        registry.register(Box::new(operations_success.clone()))?;
        registry.register(Box::new(operations_failed.clone()))?;
        registry.register(Box::new(operation_duration_seconds.clone()))?;
        registry.register(Box::new(operation_duration_min_seconds.clone()))?;
        registry.register(Box::new(operation_duration_max_seconds.clone()))?;
        registry.register(Box::new(operation_duration_avg_seconds.clone()))?;
        registry.register(Box::new(operation_success_rate.clone()))?;
        registry.register(Box::new(tls_handshakes_total.clone()))?;
        registry.register(Box::new(tls_handshakes_success.clone()))?;
        registry.register(Box::new(tls_handshakes_failed.clone()))?;
        registry.register(Box::new(tls_handshake_duration_seconds.clone()))?;
        registry.register(Box::new(tls_handshake_success_rate.clone()))?;

        Ok(Self {
            registry,
            operations_total,
            operations_success,
            operations_failed,
            operation_duration_seconds,
            operation_duration_min_seconds,
            operation_duration_max_seconds,
            operation_duration_avg_seconds,
            operation_success_rate,
            tls_handshakes_total,
            tls_handshakes_success,
            tls_handshakes_failed,
            tls_handshake_duration_seconds,
            tls_handshake_success_rate,
        })
    }

    /// Export metrics to Prometheus text format.
    ///
    /// # Arguments
    ///
    /// * `collector` - The metrics collector to export from
    ///
    /// # Returns
    ///
    /// A string containing the metrics in Prometheus text format.
    pub async fn export(&self, collector: &MetricsCollector) -> Result<String, Box<dyn StdError>> {
        let summary = collector.get_summary().await;
        self.update_metrics(&summary)?;

        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer)?;

        Ok(String::from_utf8(buffer)?)
    }

    /// Update Prometheus metrics from a metrics summary.
    fn update_metrics(&self, summary: &MetricsSummary) -> Result<(), Box<dyn StdError>> {
        // Update operation metrics for each type
        self.update_operation_metrics("get_ca_certs", &summary.ca_certs)?;
        self.update_operation_metrics("simple_enroll", &summary.enrollments)?;
        self.update_operation_metrics("simple_reenroll", &summary.reenrollments)?;
        self.update_operation_metrics("get_csr_attributes", &summary.csr_attrs)?;
        self.update_operation_metrics("server_keygen", &summary.server_keygen)?;
        self.update_operation_metrics("full_cmc", &summary.full_cmc)?;

        // Update TLS metrics
        // Reset counters to current values (Prometheus doesn't support setting counters directly)
        // In practice, these would be incremented as operations occur
        self.tls_handshake_success_rate
            .set(summary.tls.success_rate());

        Ok(())
    }

    /// Update metrics for a specific operation type.
    fn update_operation_metrics(
        &self,
        operation: &str,
        metrics: &crate::metrics::OperationMetrics,
    ) -> Result<(), Box<dyn StdError>> {
        if metrics.total == 0 {
            return Ok(());
        }

        // Note: Prometheus counters should only be incremented, not set
        // In a real implementation, these would be updated as operations occur
        // For now, we'll use gauges to show the current state

        self.operation_duration_min_seconds
            .with_label_values(&[operation])
            .set(metrics.min_duration().as_secs_f64());

        self.operation_duration_max_seconds
            .with_label_values(&[operation])
            .set(metrics.max_duration().as_secs_f64());

        self.operation_duration_avg_seconds
            .with_label_values(&[operation])
            .set(metrics.average_duration().as_secs_f64());

        self.operation_success_rate
            .with_label_values(&[operation])
            .set(metrics.success_rate());

        Ok(())
    }

    /// Get a reference to the Prometheus registry.
    ///
    /// This can be used to integrate with Prometheus HTTP servers or
    /// other exporters.
    pub fn registry(&self) -> &Registry {
        &self.registry
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
    async fn test_prometheus_exporter_creation() {
        let exporter = PrometheusExporter::new("test_est").unwrap();
        assert!(!exporter.registry().gather().is_empty());
    }

    #[tokio::test]
    async fn test_prometheus_export() {
        let collector = MetricsCollector::new();
        let exporter = PrometheusExporter::new("test_est").unwrap();

        // Record some metrics
        collector
            .record_operation(
                OperationType::SimpleEnroll,
                Duration::from_millis(100),
                true,
            )
            .await;

        collector
            .record_tls_handshake(Duration::from_millis(50), true)
            .await;

        // Export to Prometheus format
        let output = exporter.export(&collector).await.unwrap();

        // Verify output contains expected metric names
        assert!(output.contains("test_est_operation_success_rate"));
        assert!(output.contains("test_est_tls_handshake_success_rate"));
    }

    #[tokio::test]
    async fn test_prometheus_metric_values() {
        let collector = MetricsCollector::new();
        let exporter = PrometheusExporter::new("test_est").unwrap();

        // Record multiple operations
        for _ in 0..5 {
            collector
                .record_operation(
                    OperationType::SimpleEnroll,
                    Duration::from_millis(100),
                    true,
                )
                .await;
        }

        let output = exporter.export(&collector).await.unwrap();

        // Verify metrics are present
        assert!(output.contains("simple_enroll"));
    }
}
