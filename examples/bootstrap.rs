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

//! Bootstrap mode example.
//!
//! This example demonstrates how to use bootstrap/TOFU mode to discover
//! CA certificates from an EST server without pre-existing trust.
//!
//! # Security Controls Demonstrated
//!
//! **NIST SP 800-53 Rev 5:**
//! - IA-2: Identification and Authentication (Trust On First Use)
//! - SI-10: Information Input Validation (certificate fingerprint verification)
//!
//! **Application Development STIG V5R3:**
//! - APSC-DV-000160 (CAT I): Authentication (TOFU with out-of-band verification)
//! - APSC-DV-003235 (CAT I): Certificate Validation (fingerprint verification)
//!
//! # RFC 7030 Compliance
//!
//! - Section 4.1.1: Bootstrap mode (explicit trust anchor management)
//! - Section 2.4: Certificate fingerprint verification for TOFU
//!
//! # Security Warning
//!
//! ⚠️ Bootstrap mode performs NO TLS verification on first use. The certificate
//! fingerprint MUST be verified out-of-band (phone call, secure message, physical
//! verification) before trusting. Without verification, bootstrap is vulnerable to MITM.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example bootstrap -- --server https://est.example.com
//! ```

use std::env;
use std::io::{self, Write};
use std::process::exit;

use usg_est_client::bootstrap::BootstrapClient;

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    let env_url = env::var("EST_SERVER_URL").ok();
    let server_url = args
        .iter()
        .position(|a| a == "--server")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .or_else(|| env_url.as_deref())
        .unwrap_or("https://testrfc7030.com:8443");

    println!("EST Bootstrap Example");
    println!("=====================");
    println!("Server: {}", server_url);
    println!();
    println!("WARNING: This mode disables TLS certificate verification!");
    println!("You MUST verify the certificate fingerprints out-of-band.");
    println!();

    // Create bootstrap client
    let bootstrap = match BootstrapClient::new(server_url) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Failed to create bootstrap client: {}", e);
            exit(1);
        }
    };

    // Fetch CA certificates
    println!("Fetching CA certificates...");
    let (ca_certs, fingerprints) = match bootstrap.fetch_ca_certs().await {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Failed to fetch CA certificates: {}", e);
            exit(1);
        }
    };

    println!("Retrieved {} certificate(s):", ca_certs.len());
    println!();

    // Display certificate information and fingerprints
    for (i, (cert, fp)) in ca_certs.iter().zip(fingerprints.iter()).enumerate() {
        let cn = BootstrapClient::get_subject_cn(cert).unwrap_or_else(|| "Unknown".to_string());
        println!("Certificate {}:", i + 1);
        println!("  Subject CN: {}", cn);
        println!("  Fingerprint (SHA-256):");
        println!("    {}", BootstrapClient::format_fingerprint(fp));
        println!();
    }

    // Interactive verification
    print!("Do you want to trust these certificates? [y/N]: ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();

    if input.trim().to_lowercase() == "y" {
        println!();
        println!("Certificates verified and accepted.");
        println!();
        println!("To use these CA certificates with the EST client, save the");
        println!("fingerprints and use them to configure TrustAnchors::Explicit.");
        println!();

        // Show example code
        println!("Example configuration:");
        println!("```rust");
        println!("let config = EstClientConfig::builder()");
        println!("    .server_url(\"{}\")?", server_url);
        println!("    .trust_explicit(ca_cert_pems)");
        println!("    .build()?;");
        println!("```");
    } else {
        println!();
        println!("Certificates NOT trusted. Exiting.");
        exit(1);
    }
}
