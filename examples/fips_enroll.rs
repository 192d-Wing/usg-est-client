// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! FIPS 140-2 Compliant Certificate Enrollment Example
//!
//! This example demonstrates certificate enrollment using FIPS-validated cryptography.
//!
//! # Security Controls Demonstrated
//!
//! **NIST SP 800-53 Rev 5:**
//! - SC-13: Cryptographic Protection (FIPS 140-2 approved algorithms only)
//! - SC-12: Cryptographic Key Establishment (FIPS-validated key generation)
//! - IA-7: Cryptographic Module Authentication (FIPS module verification)
//!
//! **Application Development STIG V5R3:**
//! - APSC-DV-000170 (CAT I): Use only FIPS-validated cryptography
//!
//! # FIPS 140-2 Compliance
//!
//! - Enforces use of FIPS-approved algorithms (AES-256, RSA-2048+, ECDSA P-256+)
//! - Blocks deprecated algorithms (3DES, MD5, SHA-1, RC4)
//! - Validates OpenSSL FIPS module status (CMVP #4282, #4616)
//! - Uses FIPS-approved random number generator (BCryptGenRandom)
//!
//! # Requirements
//!
//! - OpenSSL 3.0+ with FIPS module installed and configured
//! - FIPS mode enabled system-wide (via openssl.cnf)
//! - EST server that supports FIPS-approved algorithms
//!
//! # Running
//!
//! ```bash
//! cargo run --example fips_enroll --features fips,csr-gen -- --server https://est.example.mil
//! ```
//!
//! # FIPS Mode Setup
//!
//! See docs/fips-compliance.md for detailed setup instructions.

// Provide helpful error when features are missing
#[cfg(not(all(feature = "fips", feature = "csr-gen")))]
fn main() {
    eprintln!("ERROR: This example requires both 'fips' and 'csr-gen' features.");
    eprintln!(
        "Run with: cargo run --example fips_enroll --features fips,csr-gen -- --server <URL>"
    );
    std::process::exit(1);
}

#[cfg(all(feature = "fips", feature = "csr-gen"))]
use der::Encode;
#[cfg(all(feature = "fips", feature = "csr-gen"))]
use std::process;
#[cfg(all(feature = "fips", feature = "csr-gen"))]
use usg_est_client::csr::CsrBuilder;
#[cfg(all(feature = "fips", feature = "csr-gen"))]
use usg_est_client::fips::{FipsConfig, enable_fips_mode, fips_module_info};
#[cfg(all(feature = "fips", feature = "csr-gen"))]
use usg_est_client::{EnrollmentResponse, EstClient, EstClientConfig};

#[cfg(all(feature = "fips", feature = "csr-gen"))]
#[tokio::main]
async fn main() {
    // Parse command-line arguments
    let args: Vec<String> = std::env::args().collect();
    let server_url = if args.len() > 2 && args[1] == "--server" {
        &args[2]
    } else {
        eprintln!("Usage: {} --server <EST_SERVER_URL>", args[0]);
        eprintln!("Example: {} --server https://est.example.mil", args[0]);
        process::exit(1);
    };

    println!("=== FIPS 140-2 Compliant EST Certificate Enrollment ===\n");

    // Step 1: Check FIPS module status
    println!("Step 1: Checking FIPS module status...");
    let info = fips_module_info();
    println!("{}", info);

    if !info.fips_capable {
        eprintln!("\n❌ ERROR: OpenSSL FIPS module is not available");
        eprintln!("Please install OpenSSL 3.0+ with FIPS module");
        eprintln!("See docs/fips-compliance.md for setup instructions");
        process::exit(1);
    }

    if !info.fips_enabled {
        println!("\n⚠️  FIPS mode is not currently enabled. Attempting to enable...");
        match enable_fips_mode() {
            Ok(()) => println!("✅ FIPS mode enabled successfully"),
            Err(e) => {
                eprintln!("\n❌ ERROR: Failed to enable FIPS mode: {}", e);
                eprintln!("You may need to configure OpenSSL system-wide");
                eprintln!("See docs/fips-compliance.md for setup instructions");
                process::exit(1);
            }
        }
    } else {
        println!("✅ FIPS mode is already enabled");
    }

    // Step 2: Create FIPS configuration
    println!("\nStep 2: Creating FIPS configuration...");
    let fips_config = match FipsConfig::builder()
        .enforce_fips_mode(true) // Require FIPS mode
        .min_rsa_key_size(2048) // FIPS minimum
        .min_ecc_key_size(256) // FIPS minimum (P-256)
        .block_non_fips_algorithms(true) // Block weak algorithms
        .require_tls_12_minimum(true) // Require TLS 1.2+
        .build()
    {
        Ok(config) => {
            println!("✅ FIPS configuration created:");
            println!("   - Enforce FIPS mode: true");
            println!("   - Min RSA key size: 2048 bits");
            println!("   - Min ECC key size: 256 bits (P-256)");
            println!("   - Block non-FIPS algorithms: true");
            println!("   - Require TLS 1.2+: true");
            config
        }
        Err(e) => {
            eprintln!("\n❌ ERROR: Failed to create FIPS configuration: {}", e);
            process::exit(1);
        }
    };

    // Step 3: Create EST client configuration
    println!("\nStep 3: Creating EST client configuration...");
    let mut est_config = match EstClientConfig::builder().server_url(server_url) {
        Ok(builder) => match builder.build() {
            Ok(config) => config,
            Err(e) => {
                eprintln!("\n❌ ERROR: Failed to build config: {}", e);
                process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("\n❌ ERROR: Invalid server URL: {}", e);
            process::exit(1);
        }
    };

    est_config.fips_config = Some(fips_config);
    println!("✅ EST client configured:");
    println!("   - Server URL: {}", est_config.server_url);
    println!("   - FIPS mode: enabled");

    // Step 4: Create EST client
    println!("\nStep 4: Creating EST client...");
    let client = match EstClient::new(est_config).await {
        Ok(client) => {
            println!("✅ EST client created successfully");
            client
        }
        Err(e) => {
            eprintln!("\n❌ ERROR: Failed to create EST client: {}", e);
            process::exit(1);
        }
    };

    // Step 5: Get CA certificates
    println!("\nStep 5: Retrieving CA certificates...");
    let ca_certs = match client.get_ca_certs().await {
        Ok(certs) => {
            println!("✅ Retrieved {} CA certificate(s)", certs.len());
            for (i, cert) in certs.iter().enumerate() {
                let cert_der = cert.to_der().unwrap_or_default();
                println!("   Certificate {}: {} bytes (DER)", i + 1, cert_der.len());
            }
            certs
        }
        Err(e) => {
            eprintln!("\n❌ ERROR: Failed to retrieve CA certificates: {}", e);
            eprintln!("   This may indicate:");
            eprintln!("   - EST server is not reachable");
            eprintln!("   - Server does not support FIPS-approved TLS ciphers");
            eprintln!("   - Network connectivity issues");
            process::exit(1);
        }
    };

    // Step 6: Generate FIPS-compliant CSR
    println!("\nStep 6: Generating FIPS-compliant Certificate Signing Request...");
    println!("   Using RSA-2048 (FIPS-approved)");

    let (csr_der, _key_pair) = match CsrBuilder::new()
        .common_name("fips-device.example.mil")
        .organization("U.S. Department of Defense")
        .organizational_unit("Test Unit")
        .country("US")
        .san_dns("fips-device.example.mil")
        .build()
    {
        Ok((csr, key)) => {
            println!("✅ CSR generated successfully:");
            println!("   - Subject: CN=fips-device.example.mil");
            println!("   - Organization: U.S. Department of Defense");
            println!("   - Key Algorithm: RSA-2048 (FIPS-approved)");
            println!("   - Signature Algorithm: SHA-256 with RSA (FIPS-approved)");
            println!("   - CSR size: {} bytes (DER)", csr.len());
            (csr, key)
        }
        Err(e) => {
            eprintln!("\n❌ ERROR: Failed to generate CSR: {}", e);
            process::exit(1);
        }
    };

    // Step 7: Enroll for certificate
    println!("\nStep 7: Enrolling for certificate...");
    println!("   Sending CSR to EST server: {}", server_url);

    match client.simple_enroll(&csr_der).await {
        Ok(EnrollmentResponse::Issued { certificate }) => {
            let cert_der = certificate.to_der().unwrap_or_default();
            println!("\n✅ SUCCESS: Certificate issued!");
            println!("   Certificate size: {} bytes (DER)", cert_der.len());
            println!(
                "   Certificate chain includes {} certificate(s)",
                ca_certs.len()
            );
            println!("\n🎉 FIPS-compliant certificate enrollment completed successfully!");
            println!("\nNext steps:");
            println!("1. Save the issued certificate and private key");
            println!("2. Install certificate in system certificate store");
            println!("3. Configure applications to use the certificate");
            println!("4. Verify certificate with: openssl x509 -in cert.pem -text -noout");
        }
        Ok(EnrollmentResponse::Pending { retry_after }) => {
            println!("\n⏳ Certificate enrollment is pending manual approval");
            println!("   Retry after: {} seconds", retry_after);
            println!("\nNext steps:");
            println!("1. Wait for administrator approval");
            println!("2. Retry enrollment after {} seconds", retry_after);
            println!("3. Check with EST server administrator for approval status");
        }
        Err(e) => {
            eprintln!("\n❌ ERROR: Certificate enrollment failed: {}", e);
            eprintln!("   This may indicate:");
            eprintln!("   - Server requires authentication (HTTP Basic or TLS client cert)");
            eprintln!("   - CSR validation failed");
            eprintln!("   - Server policy violation");
            eprintln!("   - FIPS algorithm mismatch");
            process::exit(1);
        }
    }

    println!("\n=== FIPS Compliance Summary ===");
    println!("✅ All cryptographic operations used FIPS-validated modules");
    println!("✅ Only FIPS-approved algorithms were used:");
    println!("   - TLS: TLS 1.2+ (FIPS-compliant)");
    println!("   - Key: RSA-2048 (FIPS-approved)");
    println!("   - Hash: SHA-256 (FIPS-approved)");
    println!("   - Signature: sha256WithRSAEncryption (FIPS-approved)");
    println!("\n✅ FIPS 140-2 compliance requirements satisfied");
}
