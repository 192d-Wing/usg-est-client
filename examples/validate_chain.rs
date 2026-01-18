// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)
//
//! Certificate chain validation using RFC 5280 path validation.
//!
//! # Security Controls Demonstrated
//!
//! **NIST SP 800-53 Rev 5:**
//! - IA-2: Identification and Authentication (certificate-based authentication)
//! - SC-23: Session Authenticity (certificate chain validation)
//! - SI-10: Information Input Validation (certificate data validation)
//!
//! **Application Development STIG V5R3:**
//! - APSC-DV-003235 (CAT I): Certificate Validation (RFC 5280 compliant path validation)
//! - APSC-DV-000500 (CAT I): Input Validation (certificate structure validation)
//!
//! # RFC 5280 Validation Features
//!
//! - Signature verification with FIPS-approved algorithms
//! - Validity period checking (notBefore/notAfter)
//! - Basic constraints validation (CA flag, path length)
//! - Name constraints processing (DNS, email, URI)
//! - Policy constraints validation
//!
//! # Usage
//!
//! ```bash
//! cargo run --example validate_chain --features validation
//! ```

use base64::Engine;
use der::Decode;
use std::fs;
use std::path::PathBuf;
use x509_cert::Certificate;

// Import validation types
use usg_est_client::validation::{
    CertificateValidator, ValidationConfig, ValidationResult, get_subject_cn, is_ca_certificate,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("=== Certificate Chain Validation Example ===\n");

    // Example 1: Basic validation with default settings
    println!("1. Basic validation demo (using generated test certificates)");
    demo_basic_validation()?;

    // Example 2: Custom validation configuration
    println!("\n2. Custom validation configuration demo");
    demo_custom_validation()?;

    // Example 3: Name constraints checking
    println!("\n3. Name constraints checking demo");
    demo_name_constraints()?;

    // Example 4: Using validation with EST client
    println!("\n4. Using validation with EST client");
    demo_est_client_validation()?;

    println!("\n=== Validation Example Complete ===");
    Ok(())
}

/// Demonstrates basic certificate validation.
fn demo_basic_validation() -> Result<(), Box<dyn std::error::Error>> {
    // In a real scenario, you would load certificates from files
    // For this example, we show the API usage with placeholder comments

    println!("   Loading trust anchors (root CA certificates)...");
    println!("   Loading end-entity certificate to validate...");

    // Create a validator with empty trust anchors (for demonstration)
    let trust_anchors: Vec<Certificate> = Vec::new();
    let _validator = CertificateValidator::new(trust_anchors);

    println!("   Created validator with default configuration:");
    let config = ValidationConfig::default();
    println!("      - Max chain length: {}", config.max_chain_length);
    println!(
        "      - Enforce name constraints: {}",
        config.enforce_name_constraints
    );
    println!(
        "      - Enforce policy constraints: {}",
        config.enforce_policy_constraints
    );
    println!("      - Check revocation: {}", config.check_revocation);

    // Note: Actual validation requires real certificates
    println!("   (Actual validation requires real certificates to be loaded)");

    Ok(())
}

/// Demonstrates custom validation configuration.
fn demo_custom_validation() -> Result<(), Box<dyn std::error::Error>> {
    // Create custom validation configuration
    let config = ValidationConfig {
        max_chain_length: 5,              // Stricter than default of 10
        check_revocation: false,          // Disable revocation checking
        enforce_name_constraints: true,   // Enforce RFC 5280 name constraints
        enforce_policy_constraints: true, // Enforce RFC 5280 policy constraints
        allow_expired: false,             // Don't allow expired certificates
    };

    println!("   Custom validation configuration:");
    println!("      - Max chain length: {}", config.max_chain_length);
    println!(
        "      - Enforce name constraints: {}",
        config.enforce_name_constraints
    );
    println!(
        "      - Enforce policy constraints: {}",
        config.enforce_policy_constraints
    );

    // For testing, you might want to allow expired certificates
    let test_config = ValidationConfig {
        allow_expired: true,
        ..config
    };
    println!("   Test configuration allows expired certificates");

    // Create validator with custom config
    let trust_anchors: Vec<Certificate> = Vec::new();
    let _validator = CertificateValidator::with_config(trust_anchors, test_config);

    Ok(())
}

/// Demonstrates name constraints validation.
fn demo_name_constraints() -> Result<(), Box<dyn std::error::Error>> {
    println!("   Name constraints (RFC 5280 Section 4.2.1.10) checking:");
    println!("      - Validates DNS name constraints (permitted/excluded subtrees)");
    println!("      - Validates email (RFC822) name constraints");
    println!("      - Validates URI name constraints");
    println!("      - Validates directory name constraints");
    println!();
    println!("   Example: A CA with nameConstraints permitting only '.example.com'");
    println!("   would reject certificates for hosts in other domains.");
    println!();
    println!("   The validator accumulates constraints from CA certificates");
    println!("   and applies them to subordinate certificates per RFC 5280.");

    Ok(())
}

/// Demonstrates using validation with the EST client.
fn demo_est_client_validation() -> Result<(), Box<dyn std::error::Error>> {
    println!("   Configuring EST client with certificate validation:");
    println!();
    println!("   ```rust");
    println!("   use usg_est_client::{{EstClientConfig, CertificateValidationConfig}};");
    println!("   use x509_cert::Certificate;");
    println!();
    println!("   // Load your trust anchors");
    println!("   let trust_anchors: Vec<Certificate> = load_trust_anchors()?;");
    println!();
    println!("   // Create validation config");
    println!("   let validation_config = CertificateValidationConfig::new(trust_anchors)");
    println!("       .max_chain_length(5)");
    println!("       .disable_name_constraints();  // Optional");
    println!();
    println!("   // Configure EST client with validation");
    println!("   let config = EstClientConfig::builder()");
    println!("       .server_url(\"https://est.example.com\")?");
    println!("       .validation_config(validation_config)  // Enable validation");
    println!("       .build()?;");
    println!();
    println!("   // When you call simple_enroll(), the issued certificate");
    println!("   // will be automatically validated before being returned.");
    println!("   ```");
    println!();
    println!("   Benefits of validation:");
    println!("   - Ensures issued certificates chain to trusted roots");
    println!("   - Catches misconfigurations early");
    println!("   - Validates name constraints for security");
    println!("   - Checks certificate validity periods");

    Ok(())
}

/// Helper function to load a PEM certificate file.
#[allow(dead_code)]
fn load_certificate_from_pem(path: &PathBuf) -> Result<Certificate, Box<dyn std::error::Error>> {
    let pem_data = fs::read_to_string(path)?;

    // Find the certificate PEM block
    let begin = pem_data
        .find("-----BEGIN CERTIFICATE-----")
        .ok_or("No certificate found in PEM file")?;
    let end = pem_data
        .find("-----END CERTIFICATE-----")
        .ok_or("No certificate end marker found")?
        + "-----END CERTIFICATE-----".len();

    let pem_block = &pem_data[begin..end];

    // Decode base64 content
    let base64_content: String = pem_block
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();

    let der_bytes = base64::prelude::BASE64_STANDARD.decode(&base64_content)?;
    let cert = Certificate::from_der(&der_bytes)?;

    Ok(cert)
}

/// Helper function to display validation results.
#[allow(dead_code)]
fn display_validation_result(result: &ValidationResult) {
    println!("Validation Result:");
    println!("  Valid: {}", result.is_valid);
    println!("  Chain length: {}", result.chain.len());

    if !result.errors.is_empty() {
        println!("  Errors:");
        for error in &result.errors {
            println!("    - {}", error);
        }
    }

    if !result.warnings.is_empty() {
        println!("  Warnings:");
        for warning in &result.warnings {
            println!("    - {}", warning);
        }
    }

    // Display chain details
    if !result.chain.is_empty() {
        println!("  Certificate chain:");
        for (i, cert) in result.chain.iter().enumerate() {
            let cn = get_subject_cn(cert).unwrap_or_else(|| "<unknown>".to_string());
            let is_ca = is_ca_certificate(cert);
            println!("    {}. {} (CA: {})", i + 1, cn, is_ca);
        }
    }
}
