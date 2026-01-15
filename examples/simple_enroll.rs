//! This example requires the `csr-gen` feature to be enabled.
//! Run with: cargo run --example simple_enroll --features csr-gen

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

//! Simple EST enrollment example.
//!
//! This example demonstrates basic EST client usage for certificate enrollment.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example simple_enroll -- --server https://est.example.com
//! ```
#[cfg(not(feature = "csr-gen"))]
compile_error!("This example requires the 'csr-gen' feature. Run with --features csr-gen");

use std::env;
use std::process::exit;

use usg_est_client::{EnrollmentResponse, EstClient, EstClientConfig};
#[cfg(feature = "csr-gen")]
use usg_est_client::csr::CsrBuilder;

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    let server_url = args
        .iter()
        .position(|a| a == "--server")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("https://testrfc7030.com:8443");

    let common_name = args
        .iter()
        .position(|a| a == "--cn")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("test-device.example.com");

    println!("EST Client Example");
    println!("==================");
    println!("Server: {}", server_url);
    println!("Common Name: {}", common_name);
    println!();

    // Build client configuration
    let builder = match EstClientConfig::builder().server_url(server_url) {
        Ok(b) => b.trust_any_insecure(), // For testing only!
        Err(e) => {
            eprintln!("Failed to parse server URL: {}", e);
            exit(1);
        }
    };

    let config = match builder.build() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to build config: {}", e);
            exit(1);
        }
    };

    // Create EST client
    let client = match EstClient::new(config).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to create EST client: {}", e);
            exit(1);
        }
    };

    // Step 1: Get CA certificates
    println!("Step 1: Fetching CA certificates...");
    match client.get_ca_certs().await {
        Ok(ca_certs) => {
            println!("  Retrieved {} CA certificate(s)", ca_certs.len());
            for cert in ca_certs.iter() {
                if let Some(cn) = get_cn(cert) {
                    println!("    - {}", cn);
                }
            }
        }
        Err(e) => {
            eprintln!("  Failed to get CA certs: {}", e);
            // Continue anyway for demonstration
        }
    }
    println!();

    // Step 2: Check CSR attributes (optional)
    println!("Step 2: Checking CSR attributes...");
    match client.get_csr_attributes().await {
        Ok(attrs) => {
            if attrs.is_empty() {
                println!("  No specific CSR attributes required");
            } else {
                println!("  Server requires {} attributes:", attrs.len());
                for attr in &attrs.attributes {
                    println!("    - OID: {}", attr.oid);
                }
            }
        }
        Err(e) => {
            println!("  CSR attributes not available: {}", e);
        }
    }
    println!();

    // Step 3: Generate CSR
    println!("Step 3: Generating CSR...");
    let (csr_der, _key_pair) = match CsrBuilder::new()
        .common_name(common_name)
        .organization("EST Client Example")
        .san_dns(common_name)
        .key_usage_digital_signature()
        .key_usage_key_encipherment()
        .extended_key_usage_client_auth()
        .build()
    {
        Ok(result) => {
            println!("  CSR generated successfully");
            result
        }
        Err(e) => {
            eprintln!("  Failed to generate CSR: {}", e);
            exit(1);
        }
    };
    println!("  CSR size: {} bytes", csr_der.len());
    println!();

    // Step 4: Enroll for certificate
    println!("Step 4: Enrolling for certificate...");
    match client.simple_enroll(&csr_der).await {
        Ok(EnrollmentResponse::Issued { certificate }) => {
            println!("  Certificate issued successfully!");
            if let Some(cn) = get_cn(&certificate) {
                println!("  Subject CN: {}", cn);
            }
            println!("  Serial: {:?}", certificate.tbs_certificate.serial_number);
        }
        Ok(EnrollmentResponse::Pending { retry_after }) => {
            println!("  Enrollment pending manual approval");
            println!("  Retry after: {} seconds", retry_after);
        }
        Err(e) => {
            eprintln!("  Enrollment failed: {}", e);
            exit(1);
        }
    }

    println!();
    println!("Done!");
}

fn get_cn(cert: &usg_est_client::Certificate) -> Option<String> {
    use const_oid::db::rfc4519::CN;

    for rdn in cert.tbs_certificate.subject.0.iter() {
        for atv in rdn.0.iter() {
            if atv.oid == CN
                && let Ok(s) = std::str::from_utf8(atv.value.value())
            {
                return Some(s.to_string());
            }
        }
    }
    None
}
