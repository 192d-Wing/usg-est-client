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

//! Certificate re-enrollment (renewal) example.
//!
//! This example demonstrates how to renew an existing certificate
//! using the EST simplereenroll operation.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example reenroll -- \
//!     --server https://est.example.com \
//!     --cert /path/to/client.pem \
//!     --key /path/to/client-key.pem
//! ```

#[cfg(not(feature = "csr-gen"))]
compile_error!("This example requires the 'csr-gen' feature. Run with --features csr-gen");

use std::env;
use std::fs;
use std::process::exit;

#[cfg(feature = "csr-gen")]
use usg_est_client::csr::CsrBuilder;
use usg_est_client::{ClientIdentity, EnrollmentResponse, EstClient, EstClientConfig};

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Parse command line arguments
    let args: Vec<String> = env::args().collect();

    let server_url = get_arg(&args, "--server").unwrap_or("https://testrfc7030.com:8443");
    let cert_path = get_arg(&args, "--cert");
    let key_path = get_arg(&args, "--key");

    println!("EST Re-enrollment Example");
    println!("=========================");
    println!("Server: {}", server_url);
    println!();

    // Check for required arguments
    let (cert_path, key_path) = match (cert_path, key_path) {
        (Some(c), Some(k)) => (c, k),
        _ => {
            eprintln!("Usage: reenroll --server URL --cert CERT_PEM --key KEY_PEM");
            eprintln!();
            eprintln!("This example requires an existing client certificate and key");
            eprintln!("for TLS client authentication.");
            exit(1);
        }
    };

    // Load client certificate and key
    println!("Loading client identity...");
    let cert_pem = match fs::read(cert_path) {
        Ok(data) => {
            println!("  Loaded certificate from: {}", cert_path);
            data
        }
        Err(e) => {
            eprintln!("  Failed to read certificate: {}", e);
            exit(1);
        }
    };

    let key_pem = match fs::read(key_path) {
        Ok(data) => {
            println!("  Loaded private key from: {}", key_path);
            data
        }
        Err(e) => {
            eprintln!("  Failed to read private key: {}", e);
            exit(1);
        }
    };

    // Build client configuration with client certificate authentication
    let builder = match EstClientConfig::builder().server_url(server_url) {
        Ok(b) => b
            .client_identity(ClientIdentity::new(cert_pem.clone(), key_pem))
            .trust_any_insecure(), // For testing only!
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
        Ok(c) => {
            println!("  EST client created successfully");
            c
        }
        Err(e) => {
            eprintln!("Failed to create EST client: {}", e);
            exit(1);
        }
    };
    println!();

    // Parse current certificate to get subject information
    println!("Parsing current certificate...");
    let current_cert = match parse_pem_certificate(&cert_pem) {
        Ok(cert) => {
            if let Some(cn) = get_cn(&cert) {
                println!("  Subject CN: {}", cn);
            }
            cert
        }
        Err(e) => {
            eprintln!("  Failed to parse certificate: {}", e);
            exit(1);
        }
    };
    println!();

    // Generate new CSR with same subject
    println!("Generating new CSR for re-enrollment...");
    let cn = get_cn(&current_cert).unwrap_or_else(|| "device.example.com".to_string());

    let (csr_der, _new_key) = match CsrBuilder::new()
        .common_name(&cn)
        .san_dns(&cn)
        .key_usage_digital_signature()
        .key_usage_key_encipherment()
        .extended_key_usage_client_auth()
        .build()
    {
        Ok(result) => {
            println!("  CSR generated with new key pair");
            result
        }
        Err(e) => {
            eprintln!("  Failed to generate CSR: {}", e);
            exit(1);
        }
    };
    println!();

    // Perform re-enrollment
    println!("Submitting re-enrollment request...");
    match client.simple_reenroll(&csr_der).await {
        Ok(EnrollmentResponse::Issued { certificate }) => {
            println!("  Certificate renewed successfully!");
            if let Some(cn) = get_cn(&certificate) {
                println!("  Subject CN: {}", cn);
            }
            println!("  Serial: {:?}", certificate.tbs_certificate.serial_number);
            println!();
            println!("Save the new certificate and update your configuration.");
        }
        Ok(EnrollmentResponse::Pending { retry_after }) => {
            println!("  Re-enrollment pending manual approval");
            println!("  Retry after: {} seconds", retry_after);
        }
        Err(e) => {
            eprintln!("  Re-enrollment failed: {}", e);
            exit(1);
        }
    }

    println!();
    println!("Done!");
}

fn get_arg<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
}

fn parse_pem_certificate(
    pem: &[u8],
) -> Result<usg_est_client::Certificate, Box<dyn std::error::Error>> {
    use der::Decode;

    // Simple PEM parsing
    let pem_str = std::str::from_utf8(pem)?;
    let begin = pem_str
        .find("-----BEGIN CERTIFICATE-----")
        .ok_or("No BEGIN marker")?;
    let end = pem_str
        .find("-----END CERTIFICATE-----")
        .ok_or("No END marker")?;

    let b64 = &pem_str[begin + 27..end];
    let b64_clean: String = b64.chars().filter(|c| !c.is_whitespace()).collect();

    use base64::prelude::*;
    let der = BASE64_STANDARD.decode(b64_clean)?;

    let cert = usg_est_client::Certificate::from_der(&der)?;
    Ok(cert)
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
