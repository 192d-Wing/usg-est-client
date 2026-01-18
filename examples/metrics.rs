// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! Comprehensive example demonstrating EST client metrics collection and export.
//!
//! # Security Controls Demonstrated
//!
//! **NIST SP 800-53 Rev 5:**
//! - AU-2: Audit Events (operational metrics collection)
//! - AU-6: Audit Review (metrics analysis for security monitoring)
//! - SI-4: System Monitoring (performance and security metrics)
//!
//! **Application Development STIG V5R3:**
//! - APSC-DV-000830 (CAT II): Audit generation (operational event tracking)
//!
//! # Features
//!
//! - Basic metrics collection during EST operations
//! - Exporting metrics in Prometheus format
//! - Using OpenTelemetry for metrics
//! - Integrating with monitoring systems
//! - Tracking enrollment success/failure rates
//! - Performance monitoring (latency, throughput)
//!
//! # Usage
//!
//! ```bash
//! cargo run --example metrics --features metrics,metrics-prometheus
//! ```

use std::time::{Duration, Instant};
use usg_est_client::metrics::{MetricsCollector, OperationType, format_metrics_summary};

#[cfg(feature = "metrics-prometheus")]
use usg_est_client::metrics::prometheus::PrometheusExporter;

#[cfg(feature = "metrics-prometheus")]
use usg_est_client::metrics::opentelemetry::OpenTelemetryExporter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    println!("=== EST Client Metrics Example ===\n");

    // Create metrics collector
    let metrics = MetricsCollector::new();
    println!("✓ Created metrics collector\n");

    // Simulate various EST operations
    println!("Simulating EST operations...\n");

    // Simulate successful CA certificate retrievals
    for i in 1..=5 {
        let start = Instant::now();
        simulate_operation("CA Cert Retrieval", i, true).await;
        metrics
            .record_operation(OperationType::GetCaCerts, start.elapsed(), true)
            .await;
    }

    // Simulate enrollments (mix of success and failure)
    for i in 1..=10 {
        let start = Instant::now();
        let success = i % 3 != 0; // Fail every 3rd operation
        simulate_operation("Enrollment", i, success).await;
        metrics
            .record_operation(OperationType::SimpleEnroll, start.elapsed(), success)
            .await;
    }

    // Simulate re-enrollments
    for i in 1..=3 {
        let start = Instant::now();
        simulate_operation("Re-enrollment", i, true).await;
        metrics
            .record_operation(OperationType::SimpleReenroll, start.elapsed(), true)
            .await;
    }

    // Simulate CSR attributes retrieval
    for i in 1..=2 {
        let start = Instant::now();
        simulate_operation("CSR Attributes", i, true).await;
        metrics
            .record_operation(OperationType::GetCsrAttributes, start.elapsed(), true)
            .await;
    }

    // Simulate server key generation
    let start = Instant::now();
    simulate_operation("Server Keygen", 1, true).await;
    metrics
        .record_operation(OperationType::ServerKeygen, start.elapsed(), true)
        .await;

    // Simulate full CMC operations
    for i in 1..=4 {
        let start = Instant::now();
        let success = i != 2; // Fail the 2nd operation
        simulate_operation("Full CMC", i, success).await;
        metrics
            .record_operation(OperationType::FullCmc, start.elapsed(), success)
            .await;
    }

    // Simulate TLS handshakes
    for i in 1..=8 {
        let start = Instant::now();
        tokio::time::sleep(Duration::from_millis(10 + i * 5)).await;
        let success = i % 5 != 0; // Fail every 5th handshake
        metrics.record_tls_handshake(start.elapsed(), success).await;
    }

    println!("\n✓ Completed simulated operations\n");

    // Display metrics summary
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    let summary = metrics.get_summary().await;
    let formatted = format_metrics_summary(&summary);
    print!("{}", formatted);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    // Export to Prometheus format (if feature is enabled)
    #[cfg(feature = "metrics-prometheus")]
    {
        println!("=== Prometheus Export ===\n");
        let prometheus_exporter = PrometheusExporter::new("est_client")?;
        let prometheus_output = prometheus_exporter.export(&metrics).await?;

        println!("Prometheus metrics (first 20 lines):");
        println!("────────────────────────────────────────");
        for (i, line) in prometheus_output.lines().take(20).enumerate() {
            println!("{:3} | {}", i + 1, line);
        }
        println!("────────────────────────────────────────");
        println!("(Total {} lines)", prometheus_output.lines().count());
        println!("\n✓ Prometheus export successful\n");

        // Export via OpenTelemetry
        println!("=== OpenTelemetry Export ===\n");
        let otel_exporter = OpenTelemetryExporter::new("est-client", "0.1.0")?;
        let otel_output = otel_exporter.export(&metrics).await?;

        println!("OpenTelemetry metrics (first 20 lines):");
        println!("────────────────────────────────────────");
        for (i, line) in otel_output.lines().take(20).enumerate() {
            println!("{:3} | {}", i + 1, line);
        }
        println!("────────────────────────────────────────");
        println!("(Total {} lines)", otel_output.lines().count());
        println!("\n✓ OpenTelemetry export successful\n");

        // Cleanup
        otel_exporter.shutdown()?;
    }

    #[cfg(not(feature = "metrics-prometheus"))]
    {
        println!("ℹ️  Enable 'metrics-prometheus' feature to see Prometheus/OpenTelemetry export");
        println!("   Run: cargo run --example metrics --features metrics,metrics-prometheus\n");
    }

    // Show how to integrate with HTTP server (conceptual)
    println!("=== Integration Example ===\n");
    println!("To expose metrics via HTTP (add to your application):");
    println!();
    println!("```rust");
    println!("use warp::Filter;");
    println!();
    println!("let metrics_route = warp::path!(\"metrics\")");
    println!("    .map(move || {{");
    println!("        let prometheus_text = prometheus_exporter.export(&metrics).await.unwrap();");
    println!("        warp::reply::with_header(");
    println!("            prometheus_text,");
    println!("            \"content-type\",");
    println!("            \"text/plain; version=0.0.4\"");
    println!("        )");
    println!("    }});");
    println!();
    println!("warp::serve(metrics_route).run(([127, 0, 0, 1], 9090)).await;");
    println!("```");
    println!();
    println!("Then configure Prometheus scraping:");
    println!();
    println!("```yaml");
    println!("scrape_configs:");
    println!("  - job_name: 'est-client'");
    println!("    static_configs:");
    println!("      - targets: ['localhost:9090']");
    println!("```");

    println!("\n✅ Metrics example completed successfully!");

    Ok(())
}

/// Simulate an EST operation with variable duration
async fn simulate_operation(name: &str, iteration: u64, success: bool) {
    let duration_ms = 50 + (iteration * 10) % 150;
    tokio::time::sleep(Duration::from_millis(duration_ms)).await;

    let status = if success { "✓" } else { "✗" };
    println!("{} {} #{}: {}ms", status, name, iteration, duration_ms);
}
