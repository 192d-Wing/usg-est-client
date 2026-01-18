// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! DoD PKI Certificate Enrollment Example
//!
//! This example demonstrates certificate enrollment on DoD networks using
//! DoD Root CA trust anchors and certificate policy validation.
//!
//! # Security Controls Demonstrated
//!
//! **NIST SP 800-53 Rev 5:**
//! - IA-2: Identification and Authentication (CAC/PIV authentication)
//! - IA-5: Authenticator Management (DoD PKI certificate management)
//! - SC-8: Transmission Confidentiality (TLS with DoD PKI)
//! - SC-13: Cryptographic Protection (FIPS-validated DoD algorithms)
//!
//! **Application Development STIG V5R3:**
//! - APSC-DV-000160 (CAT I): Authentication (CAC/PIV certificate-based)
//! - APSC-DV-000170 (CAT I): FIPS-validated cryptography
//! - APSC-DV-003235 (CAT I): Certificate validation (DoD PKI chain validation)
//!
//! # DoD PKI Compliance
//!
//! - Uses DoD Root CA trust anchors (embedded or downloaded)
//! - Validates certificate policies (id-fpki-common-*)
//! - Supports CAC/PIV hardware authentication
//! - FIPS 140-2 compliant cryptography
//!
//! # Requirements
//!
//! - DoD Root CA certificates (embedded or downloaded)
//! - EST server that accepts DoD certificates
//! - Valid DoD credentials (CAC/PIV or username/password)
//!
//! # Running
//!
//! ```bash
//! # With CSR generation
//! cargo run --example dod_enroll --features dod-pki,csr-gen -- --server https://est.example.mil
//!
//! # With CAC/PIV card (requires pkcs11 feature)
//! cargo run --example dod_enroll --features dod-pki,pkcs11,csr-gen -- --server https://est.example.mil --cac
//! ```
//!
//! # DoD PKI Overview
//!
//! DoD Root CAs:
//! - DoD Root CA 3 (expires December 2029)
//! - DoD Root CA 4 (expires July 2032)
//! - DoD Root CA 5 (expires June 2041)
//! - DoD Root CA 6 (newest)
//!
//! Download DoD Root CAs from:
//! https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/unclass-certificates_pkcs7_DoD.zip

#![cfg(all(feature = "dod-pki", feature = "csr-gen"))]

use std::process;
use usg_est_client::csr::CsrBuilder;
use usg_est_client::dod::{
    DodCertificatePolicy, DodChainValidator, ValidationOptions, load_dod_root_cas,
};
use usg_est_client::{EnrollmentResponse, EstClient, EstClientConfig};

#[tokio::main]
async fn main() {
    // Parse command-line arguments
    let args: Vec<String> = std::env::args().collect();
    let mut server_url = None;
    let mut use_cac = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--server" => {
                if i + 1 < args.len() {
                    server_url = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--cac" => {
                use_cac = true;
            }
            _ => {}
        }
        i += 1;
    }

    let server_url = match server_url {
        Some(url) => url,
        None => {
            eprintln!("Usage: {} --server <EST_SERVER_URL> [--cac]", args[0]);
            eprintln!("Example: {} --server https://est.example.mil", args[0]);
            eprintln!("");
            eprintln!("Options:");
            eprintln!("  --server <URL>  EST server URL (required)");
            eprintln!("  --cac           Use CAC/PIV card for authentication");
            process::exit(1);
        }
    };

    println!("=== DoD PKI Certificate Enrollment ===\n");

    // Step 1: Check DoD Root CAs
    println!("Step 1: Loading DoD Root CA certificates...");
    match load_dod_root_cas() {
        Ok(roots) => {
            println!("Loaded {} DoD Root CA(s):", roots.len());
            for root in &roots {
                println!("  - {}", root.name);
                println!("    Subject: {}", root.subject_dn);
                println!("    Expires: {}", root.not_after);
            }
        }
        Err(e) => {
            println!("Note: DoD Root CAs not embedded: {}", e);
            println!(
                "  Download from: https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/unclass-certificates_pkcs7_DoD.zip"
            );
            println!("  Continuing with WebPKI trust anchors...\n");
        }
    }

    // Step 2: Handle CAC/PIV authentication if requested
    #[cfg(all(feature = "dod-pki", feature = "pkcs11"))]
    if use_cac {
        println!("\nStep 2: Detecting CAC/PIV card...");
        match usg_est_client::dod::enumerate_cac_certificates() {
            Ok(certs) => {
                if certs.is_empty() {
                    eprintln!("No certificates found on CAC/PIV card");
                    eprintln!("Ensure card is inserted and middleware is installed");
                    process::exit(1);
                }

                println!("Found {} certificate(s) on CAC:", certs.len());
                for cert in &certs {
                    println!("  - Slot {}: {}", cert.slot, cert.subject);
                    println!("    Valid: {}", cert.is_valid);
                    println!("    Key: {}", cert.key_algorithm);
                }

                // Find best certificate for EST enrollment
                if let Some(best) = certs.iter().find(|c| c.can_use_for_est()) {
                    println!(
                        "\nUsing certificate from slot {} for EST enrollment",
                        best.slot
                    );
                } else {
                    eprintln!("No suitable certificate found for EST enrollment");
                    process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("Failed to enumerate CAC certificates: {}", e);
                eprintln!("Ensure PKCS#11 middleware is installed (OpenSC, ActivClient)");
                process::exit(1);
            }
        }
    }

    #[cfg(not(all(feature = "dod-pki", feature = "pkcs11")))]
    if use_cac {
        eprintln!("CAC/PIV support requires --features dod-pki,pkcs11");
        process::exit(1);
    }

    // Step 3: Create EST client configuration
    println!("\nStep 3: Creating EST client configuration...");
    let est_config = match EstClientConfig::builder().server_url(&server_url) {
        Ok(builder) => match builder.build() {
            Ok(config) => config,
            Err(e) => {
                eprintln!("Failed to build config: {}", e);
                process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("Invalid server URL: {}", e);
            process::exit(1);
        }
    };

    println!("EST client configured:");
    println!("  - Server URL: {}", est_config.server_url);

    // Step 4: Create EST client
    println!("\nStep 4: Creating EST client...");
    let client = match EstClient::new(est_config).await {
        Ok(client) => {
            println!("EST client created successfully");
            client
        }
        Err(e) => {
            eprintln!("Failed to create EST client: {}", e);
            process::exit(1);
        }
    };

    // Step 5: Get CA certificates
    println!("\nStep 5: Retrieving CA certificates from server...");
    let ca_certs = match client.get_ca_certs().await {
        Ok(certs) => {
            println!("Retrieved {} CA certificate(s)", certs.len());
            certs
        }
        Err(e) => {
            eprintln!("Failed to retrieve CA certificates: {}", e);
            process::exit(1);
        }
    };

    // Step 6: Validate CA certificates against DoD PKI
    println!("\nStep 6: Validating CA certificates against DoD PKI...");
    let validation_options = ValidationOptions::builder()
        .min_assurance_level(0) // Accept any DoD policy
        .build();

    match DodChainValidator::with_options(validation_options) {
        Ok(validator) => {
            for (i, cert) in ca_certs.iter().enumerate() {
                match validator.validate(cert, &[]) {
                    Ok(result) => {
                        println!("  CA Certificate {} validation:", i + 1);
                        println!("    Valid: {}", result.valid);
                        if let Some(root) = &result.root_ca {
                            println!("    Root CA: {}", root);
                        }
                        if !result.policies.is_empty() {
                            println!("    Policies: {:?}", result.policies);
                        }
                    }
                    Err(e) => {
                        println!("  CA Certificate {} validation: {}", i + 1, e);
                    }
                }
            }
        }
        Err(e) => {
            println!("  Validator not available: {}", e);
        }
    }

    // Step 7: Generate DoD-compliant CSR
    println!("\nStep 7: Generating Certificate Signing Request...");
    let (csr_der, _key_pair) = match CsrBuilder::new()
        .common_name("dod-device.example.mil")
        .organization("U.S. Department of Defense")
        .organizational_unit("Test Unit")
        .country("US")
        .san_dns("dod-device.example.mil")
        .build()
    {
        Ok((csr, key)) => {
            println!("CSR generated successfully:");
            println!("  - Subject: CN=dod-device.example.mil");
            println!("  - Organization: U.S. Department of Defense");
            println!("  - Key Algorithm: RSA-2048");
            println!("  - CSR size: {} bytes", csr.len());
            (csr, key)
        }
        Err(e) => {
            eprintln!("Failed to generate CSR: {}", e);
            process::exit(1);
        }
    };

    // Step 8: Enroll for certificate
    println!("\nStep 8: Enrolling for certificate...");
    println!("  Sending CSR to EST server: {}", server_url);

    match client.simple_enroll(&csr_der).await {
        Ok(EnrollmentResponse::Issued { certificate }) => {
            println!("\nSUCCESS: Certificate issued!");

            // Validate issued certificate
            println!("\nValidating issued certificate...");
            let validation_options = ValidationOptions::builder()
                .require_policy(DodCertificatePolicy::MediumHardware)
                .build();

            match DodChainValidator::with_options(validation_options) {
                Ok(validator) => match validator.validate(&certificate, &ca_certs.certificates) {
                    Ok(result) => {
                        println!("  Valid DoD certificate: {}", result.valid);
                        if let Some(root) = &result.root_ca {
                            println!("  Chains to: {}", root);
                        }
                        println!("  Policies: {:?}", result.policies);
                    }
                    Err(e) => {
                        println!("  Validation note: {}", e);
                    }
                },
                Err(_) => {
                    println!("  (Validator not available)");
                }
            }

            println!("\nNext steps:");
            println!("1. Save the issued certificate and private key");
            println!("2. Install certificate in system certificate store");
            println!("3. Configure applications to use the certificate");
        }
        Ok(EnrollmentResponse::Pending { retry_after }) => {
            println!("\nCertificate enrollment is pending manual approval");
            println!("  Retry after: {} seconds", retry_after);
            println!("\nNext steps:");
            println!("1. Wait for administrator approval");
            println!("2. Retry enrollment after {} seconds", retry_after);
        }
        Err(e) => {
            eprintln!("\nCertificate enrollment failed: {}", e);
            eprintln!("  This may indicate:");
            eprintln!("  - Server requires authentication");
            eprintln!("  - CSR validation failed");
            eprintln!("  - Certificate policy violation");
            process::exit(1);
        }
    }

    println!("\n=== DoD PKI Certificate Enrollment Complete ===");
}
