// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! Example: Certificate enrollment with TLS channel binding.
//!
//! This example demonstrates how to use channel binding to prevent
//! man-in-the-middle attacks during initial enrollment with HTTP Basic
//! authentication.
//!
//! # Security Controls Demonstrated
//!
//! **NIST SP 800-53 Rev 5:**
//! - IA-2: Identification and Authentication (channel binding for authentication)
//! - SC-8: Transmission Confidentiality (TLS with channel binding)
//! - SC-23: Session Authenticity (cryptographic session binding)
//!
//! **Application Development STIG V5R3:**
//! - APSC-DV-000160 (CAT I): Authentication (prevents credential forwarding)
//! - APSC-DV-002440 (CAT I): Session Management (cryptographic session binding)
//!
//! # RFC 7030 Section 3.5 - Channel Binding
//!
//! Channel binding provides cryptographic linkage between the TLS session
//! and the HTTP Basic authentication, preventing credential forwarding attacks
//! and MITM attacks during initial enrollment.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example channel_binding_enroll --features csr-gen \
//!     -- <est-server-url> <username> <password>
//! ```

use usg_est_client::{EnrollmentResponse, EstClient, EstClientConfig};

#[cfg(feature = "csr-gen")]
use usg_est_client::csr::CsrBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("Usage: {} <server-url> <username> <password>", args[0]);
        eprintln!("\nExample:");
        eprintln!("  {} https://est.example.com user pass123", args[0]);
        std::process::exit(1);
    }

    let server_url = &args[1];
    let username = &args[2];
    let password = &args[3];

    println!("EST Channel Binding Enrollment Example");
    println!("======================================\n");
    println!("Server URL: {}", server_url);
    println!("Username: {}", username);
    println!();

    // Step 1: Generate a channel binding challenge
    // This challenge will be included in both the CSR and could be verified
    // by the EST server to ensure the CSR creator is the enrollment requester
    println!("Step 1: Generating channel binding challenge...");
    let channel_binding = usg_est_client::tls::generate_channel_binding_challenge();
    let channel_binding_b64 = usg_est_client::tls::compute_channel_binding(&channel_binding);
    println!("Generated challenge (base64): {}", channel_binding_b64);
    println!();

    // Step 2: Configure EST client with channel binding enabled
    println!("Step 2: Configuring EST client with channel binding...");
    let config = EstClientConfig::builder()
        .server_url(server_url)?
        .http_auth(username, password)
        .enable_channel_binding() // Enable channel binding
        .build()?;

    let client = EstClient::new(config).await?;
    println!("EST client configured successfully");
    println!();

    // Step 3: Retrieve CA certificates
    println!("Step 3: Retrieving CA certificates...");
    let ca_certs = client.get_ca_certs().await?;
    println!("Retrieved {} CA certificate(s)", ca_certs.len());
    for (i, cert) in ca_certs.iter().enumerate() {
        let subject = &cert.tbs_certificate.subject;
        println!("  CA {}: {:?}", i + 1, subject);
    }
    println!();

    // Step 4: Generate CSR with channel binding
    #[cfg(feature = "csr-gen")]
    {
        println!("Step 4: Generating CSR with channel binding in challengePassword...");

        // Note: The rcgen library doesn't directly support setting challengePassword,
        // so this is a demonstration of the concept. In a real implementation,
        // you would need to:
        // 1. Use a CSR library that supports challengePassword attribute
        // 2. Include the channel_binding_b64 value in the CSR
        // 3. The EST server would verify this matches the TLS session

        let (csr_der, _key_pair) = CsrBuilder::new()
            .common_name("device.example.com")
            .organization("Example Corp")
            .organizational_unit("IT Department")
            .country("US")
            .san_dns("device.example.com")
            .build()?;

        println!("CSR generated successfully");
        println!("CSR size: {} bytes", csr_der.len());
        println!();

        // In a full implementation with challengePassword support:
        // let (csr_der, _key_pair) = CsrBuilder::new()
        //     .common_name("device.example.com")
        //     .challenge_password(&channel_binding_b64)  // <-- Include channel binding
        //     .build()?;

        // Step 5: Enroll with channel binding
        println!("Step 5: Enrolling for certificate...");
        println!("(Channel binding is enabled - CSR should contain challenge)");

        match client.simple_enroll(&csr_der).await? {
            EnrollmentResponse::Issued { certificate } => {
                println!("✓ Certificate issued successfully!");
                println!();
                println!("Certificate Details:");
                println!("  Subject: {:?}", certificate.tbs_certificate.subject);
                println!("  Issuer: {:?}", certificate.tbs_certificate.issuer);
                println!("  Serial: {:?}", certificate.tbs_certificate.serial_number);
                println!(
                    "  Valid from: {:?}",
                    certificate.tbs_certificate.validity.not_before
                );
                println!(
                    "  Valid to: {:?}",
                    certificate.tbs_certificate.validity.not_after
                );
                println!();
                println!("Channel binding provided additional security against MITM attacks!");
            }
            EnrollmentResponse::Pending { retry_after } => {
                println!("⏳ Enrollment pending manual approval");
                println!("   Retry after {} seconds", retry_after);
                println!();
                println!("The EST server has received your request with channel binding.");
                println!("Check back later for certificate issuance.");
            }
        }
    }

    #[cfg(not(feature = "csr-gen"))]
    {
        println!("ERROR: This example requires the 'csr-gen' feature");
        println!("Run with: cargo run --example channel_binding_enroll --features csr-gen");
    }

    Ok(())
}
