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

//! Automatic Certificate Renewal Example
//!
//! This example demonstrates the automatic certificate renewal scheduler
//! that monitors certificate expiration and automatically renews certificates
//! before they expire.
//!
//! # Features
//!
//! - Background monitoring of certificate expiration
//! - Configurable renewal threshold (e.g., renew 30 days before expiry)
//! - Automatic re-enrollment with retry logic
//! - Event callbacks for renewal status
//!
//! # Usage
//!
//! ```bash
//! cargo run --example auto_renewal --features renewal,csr-gen -- --server https://est.example.com
//! ```

#[cfg(feature = "renewal")]
use std::env;
#[cfg(feature = "renewal")]
use std::time::Duration;

#[cfg(feature = "renewal")]
use usg_est_client::renewal::{RenewalConfig, RenewalScheduler};
#[cfg(feature = "renewal")]
use usg_est_client::{EstClient, EstClientConfig};

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("Automatic Certificate Renewal Example");
    println!("=====================================");
    println!();

    #[cfg(not(feature = "renewal"))]
    {
        eprintln!("Error: This example requires the 'renewal' feature");
        eprintln!("Run with: cargo run --example auto_renewal --features renewal,csr-gen");
        std::process::exit(1);
    }

    #[cfg(feature = "renewal")]
    {
        // Parse command line arguments
        let args: Vec<String> = env::args().collect();
        let server_url = args
            .iter()
            .position(|a| a == "--server")
            .and_then(|i| args.get(i + 1))
            .map(|s| s.as_str())
            .or_else(|| env::var("EST_SERVER_URL").ok().as_deref())
            .unwrap_or("https://testrfc7030.com:8443");

        println!("Server: {}", server_url);
        println!();

        // Create EST client configuration
        let config = match EstClientConfig::builder().server_url(server_url) {
            Ok(builder) => match builder.trust_any_insecure().build() {
                Ok(cfg) => cfg,
                Err(e) => {
                    eprintln!("Failed to build config: {}", e);
                    return;
                }
            },
            Err(e) => {
                eprintln!("Failed to parse server URL: {}", e);
                return;
            }
        };

        // Create EST client
        let client = match EstClient::new(config).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Failed to create EST client: {}", e);
                return;
            }
        };

        println!("✓ EST client created successfully");
        println!();

        // Configure renewal settings
        println!("Renewal Configuration:");
        println!("  - Check interval: Every 24 hours");
        println!("  - Renewal threshold: 30 days before expiration");
        println!("  - Max retries: 3 attempts");
        println!("  - Retry backoff: Exponential (2^n seconds)");
        println!();

        let renewal_config = RenewalConfig::builder()
            .renewal_threshold(Duration::from_secs(30 * 24 * 60 * 60)) // 30 days
            .check_interval(Duration::from_secs(24 * 60 * 60)) // Check daily
            .max_retries(3)
            .build();

        // Create renewal scheduler
        let _scheduler = RenewalScheduler::new(client, renewal_config);

        // Note: Event handling is configured via RenewalConfig::event_callback
        // which requires implementing the RenewalEventHandler trait

        println!("Renewal Scheduler Demonstration");
        println!("================================");
        println!();
        println!("In a production deployment, the scheduler would:");
        println!("  1. Load your existing certificate");
        println!("  2. Monitor expiration continuously");
        println!("  3. Automatically trigger renewal when threshold is reached");
        println!("  4. Retry failed renewals with exponential backoff");
        println!("  5. Notify you of renewal events via callbacks");
        println!();

        // Example: Setting a certificate to monitor
        // In a real application, you would load this from disk
        println!("Usage Pattern:");
        println!();
        println!("  // Load existing certificate");
        println!("  let cert_pem = std::fs::read_to_string(\"device.crt\")?;");
        println!("  let cert = Certificate::from_pem(&cert_pem)?;");
        println!();
        println!("  // Set certificate to monitor");
        println!("  scheduler.set_certificate(cert).await;");
        println!();
        println!("  // Start background monitoring");
        println!("  scheduler.start().await?;");
        println!();
        println!("  // Keep application running");
        println!("  tokio::signal::ctrl_c().await?;");
        println!();

        // Demonstrate the renewal configuration
        println!("Configuration Details:");
        println!("  - The scheduler checks expiration every 24 hours");
        println!("  - Renewal is triggered 30 days before certificate expires");
        println!("  - Failed renewals are retried up to 3 times");
        println!("  - Retry delays: 1s, 2s, 4s (exponential backoff)");
        println!();

        println!("Event Handling:");
        println!("  Implement the RenewalEventHandler trait and pass to config:");
        println!("  ");
        println!("  struct MyEventHandler;");
        println!("  ");
        println!("  impl RenewalEventHandler for MyEventHandler {{");
        println!("      fn on_event(&self, event: &RenewalEvent) {{");
        println!("          match event {{");
        println!("              RenewalEvent::CheckStarted => {{ /* ... */ }}");
        println!(
            "              RenewalEvent::RenewalSucceeded {{ certificate }} => {{ /* ... */ }}"
        );
        println!("              // ... handle other events");
        println!("          }}");
        println!("      }}");
        println!("  }}");
        println!("  ");
        println!("  Available events:");
        println!("  • CheckStarted - Expiration check initiated");
        println!("  • RenewalNeeded - Certificate is nearing expiration");
        println!("  • RenewalStarted - Renewal attempt beginning");
        println!("  • RenewalSucceeded - New certificate obtained");
        println!("  • RenewalFailed - Renewal attempt failed");
        println!("  • RenewalExhausted - All retry attempts exhausted");
        println!();

        println!("Integration with Your Application:");
        println!("  1. Create EST client with your production config");
        println!("  2. Configure renewal thresholds appropriate for your certificates");
        println!("  3. Set up event handlers to log/alert on renewal events");
        println!("  4. Load your certificate and start the scheduler");
        println!("  5. The scheduler runs in the background on its own task");
        println!();

        println!("Security Considerations:");
        println!("  • Store renewed certificates securely");
        println!("  • Update application TLS config after renewal");
        println!("  • Monitor renewal failures and alert administrators");
        println!("  • Consider certificate rotation for high-security environments");
        println!();

        println!("Done! For live renewal, enable with --features renewal,csr-gen");
    }
}
