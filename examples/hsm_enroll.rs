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

//! HSM (Hardware Security Module) Enrollment Example
//!
//! This example demonstrates certificate enrollment using keys stored in
//! a Hardware Security Module (HSM) or other secure key provider.
//!
//! # Features
//!
//! - Key generation in HSM
//! - CSR creation with HSM-backed keys
//! - Private keys never leave the HSM
//! - Support for multiple key algorithms
//!
//! # Key Providers
//!
//! - **SoftwareKeyProvider**: In-memory keys (dev/test only)
//! - **PKCS#11 Provider**: Hardware HSMs via PKCS#11 interface
//! - **Custom Providers**: Implement KeyProvider trait
//!
//! # Usage
//!
//! ```bash
//! cargo run --example hsm_enroll --features hsm,csr-gen -- --server https://est.example.com
//! ```

#[cfg(all(feature = "hsm", feature = "csr-gen"))]
use std::env;

#[cfg(all(feature = "hsm", feature = "csr-gen"))]
use usg_est_client::hsm::{KeyAlgorithm, KeyProvider, SoftwareKeyProvider};
#[cfg(all(feature = "hsm", feature = "csr-gen"))]
use usg_est_client::{EnrollmentResponse, EstClient, EstClientConfig, csr::HsmCsrBuilder};

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("HSM Certificate Enrollment Example");
    println!("===================================");
    println!();

    #[cfg(not(all(feature = "hsm", feature = "csr-gen")))]
    {
        eprintln!("Error: This example requires both 'hsm' and 'csr-gen' features");
        eprintln!("Run with: cargo run --example hsm_enroll --features hsm,csr-gen");
        std::process::exit(1);
    }

    #[cfg(all(feature = "hsm", feature = "csr-gen"))]
    {
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

        println!("Server: {}", server_url);
        println!();

        // Demonstrate HSM key provider usage
        demonstrate_key_provider().await;
        println!();

        // Demonstrate enrollment with HSM
        if args.iter().any(|a| a == "--live") {
            perform_live_enrollment(server_url).await;
        } else {
            println!("Add --live flag to perform actual enrollment");
            demonstrate_enrollment_pattern();
        }

        println!();
        println!("Done!");
    }
}

#[cfg(all(feature = "hsm", feature = "csr-gen"))]
async fn demonstrate_key_provider() {
    println!("HSM Key Provider");
    println!("================");
    println!();
    println!("The KeyProvider trait abstracts key storage and operations:");
    println!();

    // Create a software key provider (for demonstration)
    // In production, you would use a hardware HSM provider
    let provider = SoftwareKeyProvider::new();
    println!("✓ Created SoftwareKeyProvider (in-memory keys)");
    println!("  Note: In production, use PKCS#11 or hardware HSM provider");
    println!();

    // List supported algorithms
    println!("Supported Key Algorithms:");
    println!("  • ECDSA P-256 (recommended for most use cases)");
    println!("  • ECDSA P-384 (higher security)");
    println!("  • RSA 2048 (legacy compatibility)");
    println!("  • RSA 3072");
    println!("  • RSA 4096 (maximum security)");
    println!();

    // Generate a key pair in the HSM
    println!("Generating key pair in HSM...");
    let key_handle = provider
        .generate_key_pair(KeyAlgorithm::EcdsaP256, Some("device-key"))
        .await
        .expect("Failed to generate key pair");

    println!("✓ Key pair generated successfully");
    println!("  Handle: {:?}", key_handle);
    println!("  Algorithm: ECDSA P-256");
    println!("  Label: device-key");
    println!();

    // Get public key
    let _public_key = provider
        .public_key(&key_handle)
        .await
        .expect("Failed to get public key");

    println!("✓ Public key retrieved (SubjectPublicKeyInfo)");
    println!();

    // List all keys in the provider
    let keys = provider.list_keys().await.expect("Failed to list keys");

    println!("Keys in HSM: {}", keys.len());
    for (i, key) in keys.iter().enumerate() {
        let label = key.metadata().label.as_deref().unwrap_or("unlabeled");
        println!("  {}. {} ({})", i + 1, key.algorithm().as_str(), label);
    }
    println!();

    // Find a key by label
    if let Ok(Some(key)) = provider.find_key("device-key").await {
        let label = key.metadata().label.as_deref().unwrap_or("unlabeled");
        println!("✓ Found key by label: {}", label);
    }
    println!();

    println!("Key Provider Security:");
    println!("  • Private keys never leave the HSM");
    println!("  • Signing operations performed inside HSM");
    println!("  • Keys can be marked as non-extractable");
    println!("  • Access control via HSM policies");
    println!();
}

#[cfg(all(feature = "hsm", feature = "csr-gen"))]
fn demonstrate_enrollment_pattern() {
    println!("Enrollment with HSM Keys");
    println!("========================");
    println!();
    println!("Standard enrollment pattern with HSM-backed keys:");
    println!();
    println!("  // 1. Create HSM key provider");
    println!("  let hsm = SoftwareKeyProvider::new(); // or PKCS11Provider");
    println!();
    println!("  // 2. Generate key pair in HSM");
    println!("  let key_handle = hsm.generate_key_pair(");
    println!("      KeyAlgorithm::EcdsaP256,");
    println!("      Some(\"device-key\")");
    println!("  ).await?;");
    println!();
    println!("  // 3. Create CSR with HSM-backed key");
    println!("  let csr_der = HsmCsrBuilder::new()");
    println!("      .common_name(\"device.example.com\")");
    println!("      .organization(\"Example Corp\")");
    println!("      .san_dns(\"device.example.com\")");
    println!("      .key_usage_digital_signature()");
    println!("      .key_usage_key_agreement()");
    println!("      .build_with_provider(&hsm, &key_handle)");
    println!("      .await?;");
    println!();
    println!("  // 4. Enroll with EST server");
    println!("  let response = client.simple_enroll(&csr_der).await?;");
    println!();
    println!("  // 5. Store certificate (private key stays in HSM)");
    println!("  match response {{");
    println!("      EnrollmentResponse::Issued {{ certificate }} => {{");
    println!("          // Certificate is issued, associate with HSM key");
    println!("          save_certificate(&certificate)?;");
    println!("      }}");
    println!("      _ => {{ /* handle pending */ }}");
    println!("  }}");
    println!();
    println!("Benefits:");
    println!("  • Private key never leaves the HSM");
    println!("  • CSR signed using HSM sign() operation");
    println!("  • Supports P-256, P-384, and RSA keys");
    println!("  • Works with any KeyProvider implementation");
    println!();
}

#[cfg(all(feature = "hsm", feature = "csr-gen"))]
async fn perform_live_enrollment(server_url: &str) {
    println!("Live Enrollment with HSM");
    println!("========================");
    println!();

    // Create EST client
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

    let client = match EstClient::new(config).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to create EST client: {}", e);
            return;
        }
    };

    println!("✓ EST client created");

    // Create HSM provider
    let hsm = SoftwareKeyProvider::new();
    println!("✓ HSM provider created");

    // Generate key pair
    println!("Generating ECDSA P-256 key pair in HSM...");
    let key_handle = match hsm
        .generate_key_pair(KeyAlgorithm::EcdsaP256, Some("est-device"))
        .await
    {
        Ok(handle) => handle,
        Err(e) => {
            eprintln!("Failed to generate key: {}", e);
            return;
        }
    };

    println!("✓ Key generated: {:?}", key_handle);

    // Get public key
    let _public_key = match hsm.public_key(&key_handle).await {
        Ok(pk) => pk,
        Err(e) => {
            eprintln!("Failed to get public key: {}", e);
            return;
        }
    };

    println!("✓ Public key retrieved");
    println!();

    // Generate CSR using HSM-backed key
    println!("Generating CSR with HSM-backed key...");

    let csr_der = match HsmCsrBuilder::new()
        .common_name("hsm-device.example.com")
        .organization("Example Corp")
        .organizational_unit("HSM Test")
        .san_dns("hsm-device.example.com")
        .key_usage_digital_signature()
        .key_usage_key_agreement()
        .extended_key_usage_client_auth()
        .build_with_provider(&hsm, &key_handle)
        .await
    {
        Ok(csr) => csr,
        Err(e) => {
            eprintln!("Failed to generate CSR: {}", e);
            return;
        }
    };

    println!("✓ CSR generated: {} bytes", csr_der.len());
    println!("  ✓ Signed using HSM key (private key never left HSM)");
    println!();

    // Perform enrollment
    println!("Enrolling with EST server...");
    match client.simple_enroll(&csr_der).await {
        Ok(EnrollmentResponse::Issued { certificate }) => {
            println!("✓ Certificate issued successfully!");
            println!();
            println!("Certificate Details:");
            println!("  Subject: {:?}", certificate.tbs_certificate.subject);
            println!("  Issuer: {:?}", certificate.tbs_certificate.issuer);
            println!();
            println!("In production:");
            println!("  • Save certificate to disk");
            println!("  • Associate with HSM key handle");
            println!("  • Configure TLS with certificate + HSM key");
            println!("  • Keep private key in HSM (never export)");
        }
        Ok(EnrollmentResponse::Pending { retry_after }) => {
            println!("Certificate enrollment pending");
            println!("Retry after: {} seconds", retry_after);
        }
        Err(e) => {
            eprintln!("Enrollment failed: {}", e);
            eprintln!();
            eprintln!("Note: Many EST servers don't support anonymous enrollment");
            eprintln!("      Configure HTTP Basic auth or TLS client cert");
        }
    }
    println!();
}
