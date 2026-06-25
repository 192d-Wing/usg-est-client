# Metrics and Monitoring

This document describes the metrics collection and export capabilities of the USG EST Client, including integration with Prometheus and OpenTelemetry.

## Table of Contents

- [Overview](#overview)
- [Basic Metrics Collection](#basic-metrics-collection)
- [Prometheus Integration](#prometheus-integration)
- [OpenTelemetry Integration](#opentelemetry-integration)
- [Metric Types](#metric-types)
- [HTTP Server Integration](#http-server-integration)
- [Grafana Dashboards](#grafana-dashboards)

## Overview

The USG EST Client provides comprehensive metrics collection for monitoring EST operations in production environments. Metrics can be collected in-memory and exported to monitoring systems like Prometheus and OpenTelemetry.

### Features

- **Operation Metrics**: Track counts, durations, and success rates for all EST operations
- **TLS Metrics**: Monitor TLS handshake performance and success rates
- **Prometheus Export**: Native Prometheus text format export
- **OpenTelemetry**: Integration with OpenTelemetry observability platform
- **Thread-Safe**: Metrics can be collected from multiple concurrent operations
- **Zero-Overhead**: Metrics feature is optional and has no runtime cost when disabled

### Feature Flags

```toml
[dependencies]
usg-est-client = { version = "2.1", features = ["metrics"] }

# For Prometheus/OpenTelemetry export
usg-est-client = { version = "2.1", features = ["metrics", "metrics-prometheus"] }
```

## Basic Metrics Collection

### Creating a Metrics Collector

```rust
use usg_est_client::metrics::MetricsCollector;

let metrics = MetricsCollector::new();
```

### Recording Operations

```rust
use std::time::Instant;
use usg_est_client::metrics::OperationType;

let start = Instant::now();

// Perform EST operation
let result = client.simple_enroll(&csr).await;

// Record the operation
let success = result.is_ok();
metrics.record_operation(
    OperationType::SimpleEnroll,
    start.elapsed(),
    success
).await;
```

### Recording TLS Handshakes

```rust
let start = Instant::now();

// Perform TLS handshake
let handshake_result = perform_handshake().await;

metrics.record_tls_handshake(
    start.elapsed(),
    handshake_result.is_ok()
).await;
```

### Getting Metrics Summary

```rust
use usg_est_client::metrics::format_metrics_summary;

let summary = metrics.get_summary().await;

println!("Total operations: {}", summary.total_operations());
println!("Success rate: {:.2}%", summary.overall_success_rate());

// Format for human-readable output
let formatted = format_metrics_summary(&summary);
println!("{}", formatted);
```

### Resetting Metrics

```rust
// Reset all metrics to zero
metrics.reset().await;
```

## Prometheus Integration

The `metrics-prometheus` feature provides native Prometheus format export.

### Setup

```rust
use usg_est_client::metrics::MetricsCollector;
use usg_est_client::metrics::prometheus::PrometheusExporter;

// Create metrics collector
let metrics = MetricsCollector::new();

// Create Prometheus exporter with namespace prefix
let exporter = PrometheusExporter::new("est_client")?;
```

### Exporting Metrics

```rust
// Export current metrics in Prometheus text format
let prometheus_text = exporter.export(&metrics).await?;

println!("{}", prometheus_text);
```

### Example Output

```
# HELP est_client_operations_total Total number of EST operations by type
# TYPE est_client_operations_total gauge
est_client_operations_total{operation="simple_enroll"} 150
est_client_operations_total{operation="simple_reenroll"} 25

# HELP est_client_operation_success_rate EST operation success rate (0-100) by type
# TYPE est_client_operation_success_rate gauge
est_client_operation_success_rate{operation="simple_enroll"} 98.67
est_client_operation_success_rate{operation="simple_reenroll"} 100.00

# HELP est_client_operation_duration_avg_seconds Average EST operation duration in seconds by type
# TYPE est_client_operation_duration_avg_seconds gauge
est_client_operation_duration_avg_seconds{operation="simple_enroll"} 0.142
est_client_operation_duration_avg_seconds{operation="simple_reenroll"} 0.135

# HELP est_client_tls_handshake_success_rate TLS handshake success rate (0-100)
# TYPE est_client_tls_handshake_success_rate gauge
est_client_tls_handshake_success_rate 99.5
```

## OpenTelemetry Integration

The OpenTelemetry exporter provides integration with the OpenTelemetry observability platform.

### Setup

```rust
use usg_est_client::metrics::MetricsCollector;
use usg_est_client::metrics::opentelemetry::OpenTelemetryExporter;

// Create metrics collector
let metrics = MetricsCollector::new();

// Create OpenTelemetry exporter
let exporter = OpenTelemetryExporter::new(
    "est-client",  // service name
    "2.1.2"        // service version
)?;
```

### Exporting Metrics

```rust
// Export metrics via OpenTelemetry (Prometheus format backend)
let metrics_output = exporter.export(&metrics).await?;

println!("{}", metrics_output);
```

### Cleanup

```rust
// Shutdown the OpenTelemetry pipeline
exporter.shutdown()?;
```

### Service Metadata

OpenTelemetry automatically adds service metadata:

- `service.name`: Application name
- `service.version`: Application version

## Metric Types

### Operation Types

All EST operations are tracked separately:

- `get_ca_certs` - CA certificate retrieval
- `simple_enroll` - Simple enrollment
- `simple_reenroll` - Re-enrollment
- `get_csr_attributes` - CSR attributes retrieval
- `server_keygen` - Server-side key generation
- `full_cmc` - Full CMC operations

### Tracked Metrics

For each operation type:

- **Total Count**: Number of operations attempted
- **Success Count**: Number of successful operations
- **Failed Count**: Number of failed operations
- **Success Rate**: Percentage of successful operations (0-100)
- **Min Duration**: Minimum operation duration
- **Max Duration**: Maximum operation duration
- **Avg Duration**: Average operation duration

### TLS Metrics

- **Total Handshakes**: Number of TLS handshakes attempted
- **Successful Handshakes**: Number of successful handshakes
- **Failed Handshakes**: Number of failed handshakes
- **Success Rate**: TLS handshake success rate (0-100)
- **Avg Duration**: Average handshake duration

## HTTP Server Integration

### Using with Axum

```rust
use axum::{routing::get, Router};
use usg_est_client::metrics::MetricsCollector;
use usg_est_client::metrics::prometheus::PrometheusExporter;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let metrics = Arc::new(MetricsCollector::new());
    let exporter = Arc::new(PrometheusExporter::new("est_client").unwrap());

    let app = Router::new()
        .route("/metrics", get({
            let metrics = Arc::clone(&metrics);
            let exporter = Arc::clone(&exporter);
            move || async move {
                exporter.export(&metrics).await.unwrap_or_else(|e| {
                    format!("Error exporting metrics: {}", e)
                })
            }
        }));

    axum::Server::bind(&"0.0.0.0:9090".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
```

### Using with Warp

```rust
use warp::Filter;
use usg_est_client::metrics::MetricsCollector;
use usg_est_client::metrics::prometheus::PrometheusExporter;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let metrics = Arc::new(MetricsCollector::new());
    let exporter = Arc::new(PrometheusExporter::new("est_client").unwrap());

    let metrics_route = warp::path!("metrics").and_then({
        let metrics = Arc::clone(&metrics);
        let exporter = Arc::clone(&exporter);
        move || {
            let metrics = Arc::clone(&metrics);
            let exporter = Arc::clone(&exporter);
            async move {
                match exporter.export(&metrics).await {
                    Ok(text) => Ok::<_, warp::Rejection>(
                        warp::reply::with_header(
                            text,
                            "content-type",
                            "text/plain; version=0.0.4"
                        )
                    ),
                    Err(e) => Err(warp::reject::reject()),
                }
            }
        }
    });

    warp::serve(metrics_route)
        .run(([127, 0, 0, 1], 9090))
        .await;
}
```

### Prometheus Scraping Configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'est-client'
    scrape_interval: 15s
    static_configs:
      - targets: ['localhost:9090']
```

## Grafana Dashboards

### Example Dashboard Queries

**Total Operations Over Time**
```promql
sum(rate(est_client_operations_total[5m])) by (operation)
```

**Success Rate by Operation**
```promql
est_client_operation_success_rate
```

**Average Operation Duration**
```promql
est_client_operation_duration_avg_seconds
```

**TLS Handshake Performance**
```promql
rate(est_client_tls_handshakes_total[5m])
```

**Error Rate**
```promql
sum(rate(est_client_operations_failed_total[5m])) by (operation)
```

### Sample Dashboard Layout

1. **Overview Panel**
   - Total operations (counter)
   - Overall success rate (gauge)
   - TLS handshake success rate (gauge)

2. **Operations Graph**
   - Line graph of operation rates by type
   - 5-minute rate window

3. **Duration Heatmap**
   - Histogram of operation durations
   - Color-coded by operation type

4. **Error Panel**
   - Failed operations by type
   - Recent error rate trend

## Best Practices

### 1. Namespace Your Metrics

Always use a unique namespace prefix:

```rust
let exporter = PrometheusExporter::new("my_app_est")?;
```

### 2. Record All Operations

Wrap all EST operations with metrics recording:

```rust
async fn enroll_with_metrics(
    client: &EstClient,
    csr: &[u8],
    metrics: &MetricsCollector,
) -> Result<Certificate, EstError> {
    let start = Instant::now();
    let result = client.simple_enroll(csr).await;

    metrics.record_operation(
        OperationType::SimpleEnroll,
        start.elapsed(),
        result.is_ok()
    ).await;

    result
}
```

### 3. Expose Metrics on Separate Port

Keep metrics endpoint on a separate port from your main application:

```rust
// Main app on :8080
// Metrics on :9090
```

### 4. Set Appropriate Scrape Intervals

For EST operations (typically infrequent):

```yaml
scrape_interval: 30s  # or 60s for low-frequency operations
```

### 5. Monitor Both Success and Failure

Track both to understand overall system health:

```rust
// Always record, regardless of success/failure
metrics.record_operation(op_type, duration, success).await;
```

### 6. Use Alerts for Critical Metrics

```yaml
# Example Prometheus alert
- alert: HighEstFailureRate
  expr: est_client_operation_success_rate < 95
  for: 5m
  annotations:
    summary: "EST operation failure rate is high"
```

## Example: Complete Integration

See [examples/metrics.rs](../examples/metrics.rs) for a complete working example demonstrating:

- Basic metrics collection
- Prometheus export
- OpenTelemetry integration
- Simulated EST operations
- Formatted output

Run with:

```bash
cargo run --example metrics --features metrics,metrics-prometheus
```

## Troubleshooting

### Metrics Not Appearing

1. Verify feature flags are enabled:
   ```toml
   features = ["metrics", "metrics-prometheus"]
   ```

2. Check that operations are being recorded:
   ```rust
   let summary = metrics.get_summary().await;
   println!("Total ops: {}", summary.total_operations());
   ```

### Prometheus Scraping Fails

1. Verify HTTP endpoint is accessible:
   ```bash
   curl http://localhost:9090/metrics
   ```

2. Check Content-Type header:
   ```
   Content-Type: text/plain; version=0.0.4
   ```

3. Ensure firewall allows connections on metrics port

### High Memory Usage

Metrics are stored in memory. For long-running applications:

1. Periodically reset metrics:
   ```rust
   // Reset daily
   metrics.reset().await;
   ```

2. Or export to external storage and reset

## References

- [Prometheus Documentation](https://prometheus.io/docs/)
- [OpenTelemetry Documentation](https://opentelemetry.io/docs/)
- [Prometheus Best Practices](https://prometheus.io/docs/practices/naming/)
- [OpenTelemetry Metrics API](https://opentelemetry.io/docs/specs/otel/metrics/)
