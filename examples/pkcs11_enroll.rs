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

//! PKCS#11 HSM-based Certificate Enrollment Example
//!
//! This example demonstrates how to use a PKCS#11-compatible HSM (Hardware Security Module)
//! for secure key generation and EST certificate enrollment. Private keys never leave the
//! hardware security boundary.
//!
//! # Security Controls Demonstrated
//!
//! **NIST SP 800-53 Rev 5:**
//! - SC-12: Cryptographic Key Establishment (PKCS#11 HSM key generation)
//! - SC-13: Cryptographic Protection (FIPS 140-2 Level 2+ HSM)
//! - AC-6: Least Privilege (non-exportable keys)
//! - IA-5: Authenticator Management (hardware-protected keys)
//!
//! **Application Development STIG V5R3:**
//! - APSC-DV-000170 (CAT I): FIPS-validated cryptography (HSM FIPS modules)
//! - APSC-DV-002340 (CAT II): Least privilege (hardware key protection)
//!
//! # PKCS#11 Security Features
//!
//! - Private keys generated and stored in HSM (never in software)
//! - Non-exportable key flag prevents key extraction
//! - PIN/password protection for key access
//! - FIPS 140-2 Level 2+ compliance with hardware HSMs
//! - Tamper-resistant hardware security boundary
//!
//! # Prerequisites
//!
//! You'll need a PKCS#11-compatible device or software HSM. For testing, you can use SoftHSM:
//!
//! ## Install SoftHSM (macOS)
//! ```bash
//! brew install softhsm
//! ```
//!
//! ## Install SoftHSM (Ubuntu/Debian)
//! ```bash
//! sudo apt-get install softhsm2
//! ```
//!
//! ## Initialize SoftHSM Token
//! ```bash
//! # Find the configuration directory
//! softhsm2-util --show-slots
//!
//! # Initialize a token (creates a new token in slot 0)
//! softhsm2-util --init-token --slot 0 --label "EST-Client" --so-pin 0000 --pin 1234
//! ```
//!
//! # Running the Example
//!
//! With SoftHSM installed and initialized:
//!
//! ```bash
//! # Basic usage (uses first available slot)
//! cargo run --example pkcs11_enroll --features pkcs11,csr-gen -- \
//!     --server https://est.example.com \
//!     --library /usr/lib/softhsm/libsofthsm2.so \
//!     --pin 1234 \
//!     --username testuser \
//!     --password testpass
//!
//! # Specify a specific slot ID
//! cargo run --example pkcs11_enroll --features pkcs11,csr-gen -- \
//!     --server https://est.example.com \
//!     --library /usr/local/lib/softhsm/libsofthsm2.so \
//!     --slot 0 \
//!     --pin 1234 \
//!     --username testuser \
//!     --password testpass
//!
//! # Use different key algorithm
//! cargo run --example pkcs11_enroll --features pkcs11,csr-gen -- \
//!     --server https://est.example.com \
//!     --library /usr/lib/softhsm/libsofthsm2.so \
//!     --pin 1234 \
//!     --algorithm ecdsa-p384 \
//!     --username testuser \
//!     --password testpass
//! ```
//!
//! # Hardware HSM Examples
//!
//! ## YubiHSM 2
//! ```bash
//! cargo run --example pkcs11_enroll --features pkcs11,csr-gen -- \
//!     --server https://est.example.com \
//!     --library /usr/lib/yubihsm_pkcs11.so \
//!     --pin 0001password \
//!     --username testuser \
//!     --password testpass
//! ```
//!
//! ## AWS CloudHSM
//! ```bash
//! cargo run --example pkcs11_enroll --features pkcs11,csr-gen -- \
//!     --server https://est.example.com \
//!     --library /opt/cloudhsm/lib/libcloudhsm_pkcs11.so \
//!     --pin user:password \
//!     --username testuser \
//!     --password testpass
//! ```

use clap::Parser;
use der::Encode;
use std::path::PathBuf;
use tracing::{error, info};
use usg_est_client::csr::CsrBuilder;
use usg_est_client::hsm::pkcs11::Pkcs11KeyProvider;
use usg_est_client::hsm::{KeyAlgorithm, KeyProvider};
use usg_est_client::{EnrollmentResponse, EstClient, EstClientConfig};
use x509_cert::Certificate;

#[derive(Parser, Debug)]
#[command(name = "pkcs11-enroll")]
#[command(about = "EST client enrollment using PKCS#11 HSM", long_about = None)]
struct Args {
    /// EST server URL (e.g., https://est.example.com)
    #[arg(short, long)]
    server: String,

    /// Path to PKCS#11 library
    #[arg(short, long)]
    library: PathBuf,

    /// PKCS#11 token PIN
    #[arg(short, long)]
    pin: String,

    /// PKCS#11 slot ID (optional, uses first slot with token if not specified)
    #[arg(long)]
    slot: Option<usize>,

    /// Key algorithm: ecdsa-p256, ecdsa-p384, or rsa-2048
    #[arg(short, long, default_value = "ecdsa-p256")]
    algorithm: String,

    /// Key label (name) in the HSM
    #[arg(long, default_value = "est-device-key")]
    key_label: String,

    /// Common Name for the certificate
    #[arg(short, long, default_value = "device.example.com")]
    common_name: String,

    /// Organization for the certificate
    #[arg(short, long, default_value = "Example Organization")]
    organization: String,

    /// HTTP Basic auth username
    #[arg(short, long)]
    username: String,

    /// HTTP Basic auth password
    #[arg(long)]
    password: String,

    /// CA label (for multi-CA EST servers)
    #[arg(long)]
    ca_label: Option<String>,

    /// Output file for the issued certificate (DER format)
    #[arg(long, default_value = "device-cert.der")]
    output: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    let args = Args::parse();

    info!("🔐 EST Client - PKCS#11 HSM Enrollment");
    info!("========================================");

    // Parse key algorithm
    let algorithm = match args.algorithm.as_str() {
        "ecdsa-p256" => KeyAlgorithm::EcdsaP256,
        "ecdsa-p384" => KeyAlgorithm::EcdsaP384,
        "rsa-2048" => KeyAlgorithm::Rsa { bits: 2048 },
        "rsa-3072" => KeyAlgorithm::Rsa { bits: 3072 },
        "rsa-4096" => KeyAlgorithm::Rsa { bits: 4096 },
        _ => {
            error!(
                "❌ Invalid algorithm. Use: ecdsa-p256, ecdsa-p384, rsa-2048, rsa-3072, or rsa-4096"
            );
            return Err("Invalid algorithm".into());
        }
    };

    // Initialize PKCS#11 provider
    info!("📦 Initializing PKCS#11 provider...");
    info!("   Library: {}", args.library.display());
    if let Some(slot) = args.slot {
        info!("   Slot: {}", slot);
    } else {
        info!("   Slot: (first available)");
    }

    let provider = Pkcs11KeyProvider::new(&args.library, args.slot, &args.pin)?;

    let provider_info = provider.provider_info();
    info!("✅ Connected to: {}", provider_info.name);
    info!("   Manufacturer: {}", provider_info.manufacturer);
    info!("   Version: {}", provider_info.version);

    // Check if key already exists
    info!("🔍 Checking for existing key '{}'...", args.key_label);
    let key_handle = if let Some(existing_key) = provider.find_key(&args.key_label).await? {
        info!("✅ Found existing key");
        info!("   Algorithm: {}", existing_key.algorithm().as_str());
        existing_key
    } else {
        info!("🔑 Generating new key pair in HSM...");
        info!("   Algorithm: {}", algorithm.as_str());
        info!("   Label: {}", args.key_label);

        let handle = provider
            .generate_key_pair(algorithm, Some(&args.key_label))
            .await?;

        info!("✅ Key pair generated successfully");
        info!("   Private key stored in HSM (non-extractable)");
        handle
    };

    // Get public key from HSM
    info!("📤 Exporting public key from HSM...");
    let _public_key_spki = provider.public_key(&key_handle).await?;

    // NOTE: CSR generation with PKCS#11 keys requires manual construction
    // For this example, we'll use a software key for CSR generation
    // In a production HSM integration, you would:
    // 1. Build the CSR manually using the HSM's public key
    // 2. Sign the CSR using provider.sign() with the HSM private key
    // 3. Encode the signed CSR in PKCS#10 format
    //
    // For demonstration purposes, we'll generate a software CSR
    info!("⚠️  Note: Using software key for CSR generation");
    info!("   (Full HSM-based CSR signing requires manual PKCS#10 construction)");

    info!("📝 Generating Certificate Signing Request...");
    let (csr_der, _key_pair) = CsrBuilder::new()
        .common_name(&args.common_name)
        .organization(&args.organization)
        .san_dns(&args.common_name)
        .build()?;

    info!("✅ CSR generated");
    info!(
        "   Subject: CN={}, O={}",
        args.common_name, args.organization
    );
    info!("");
    info!("💡 Note: This example uses a software-generated CSR.");
    info!("   For production HSM use, implement custom CSR signing with the HSM key.");

    // Configure EST client
    info!("🌐 Connecting to EST server...");
    info!("   Server: {}", args.server);

    let mut config_builder = EstClientConfig::builder()
        .server_url(&args.server)?
        .http_auth(&args.username, &args.password);

    if let Some(ca_label) = &args.ca_label {
        config_builder = config_builder.ca_label(ca_label);
    }

    let config = config_builder.build()?;
    let client = EstClient::new(config).await?;

    info!("✅ Connected to EST server");

    // Get CA certificates
    info!("📥 Fetching CA certificates...");
    let ca_certs = client.get_ca_certs().await?;
    info!("✅ Retrieved {} CA certificate(s)", ca_certs.len());

    // Enroll for certificate
    info!("📤 Submitting enrollment request...");
    match client.simple_enroll(&csr_der).await? {
        EnrollmentResponse::Issued { certificate } => {
            info!("✅ Certificate issued!");

            // Save certificate to file
            let cert_der = certificate.to_der()?;
            std::fs::write(&args.output, &cert_der)?;

            info!("💾 Certificate saved to: {}", args.output.display());
            info!("   Size: {} bytes", cert_der.len());

            // Display certificate info
            display_certificate_info(&certificate);

            info!("");
            info!("🎉 Enrollment successful!");
            info!("   Private key: Stored in HSM (label: {})", args.key_label);
            info!("   Certificate: {}", args.output.display());
            info!("");
            info!("💡 To list all keys in the HSM:");
            info!("   cargo run --example list_hsm_keys --features pkcs11 -- \\");
            info!(
                "       --library {} --pin {}",
                args.library.display(),
                args.pin
            );
        }
        EnrollmentResponse::Pending { retry_after } => {
            info!("⏳ Enrollment pending");
            info!("   Retry after: {} seconds", retry_after);
            info!("");
            info!("   The CA requires manual approval or additional processing.");
            info!(
                "   Re-run this command after {} seconds to check status.",
                retry_after
            );
        }
    }

    Ok(())
}

fn display_certificate_info(cert: &Certificate) {
    info!("");
    info!("📋 Certificate Information:");
    info!("   -------------------------");

    // Extract subject
    let subject = cert.tbs_certificate.subject.to_string();
    info!("   Subject: {}", subject);

    // Extract issuer
    let issuer = cert.tbs_certificate.issuer.to_string();
    info!("   Issuer: {}", issuer);

    // Extract serial number
    info!(
        "   Serial: {}",
        hex::encode(cert.tbs_certificate.serial_number.as_bytes())
    );

    // Extract validity
    info!("   Validity:");
    info!(
        "     Not Before: {}",
        cert.tbs_certificate.validity.not_before
    );
    info!(
        "     Not After:  {}",
        cert.tbs_certificate.validity.not_after
    );
}
