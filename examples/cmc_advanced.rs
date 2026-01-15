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

//! Advanced CMC (Certificate Management over CMS) example.
//!
//! This example demonstrates the full CMC protocol features including:
//! - Building PKIData requests with multiple certificate requests
//! - Adding CMC control attributes (transaction ID, nonces, identification)
//! - Batch operations for multiple requests
//! - Parsing PKIResponse with status handling
//!
//! # CMC Protocol Overview
//!
//! CMC (RFC 5272, 5273, 5274) provides advanced certificate management features:
//! - Multiple certificate requests in a single message
//! - Transaction tracking with IDs and nonces
//! - Rich status reporting with detailed failure codes
//! - Support for PKCS#10 and CRMF request formats
//!
//! # Usage
//!
//! ```bash
//! cargo run --example cmc_advanced -- --server https://est.example.com
//! ```

#[cfg(not(feature = "csr-gen"))]
compile_error!("This example requires the 'csr-gen' feature. Run with --features csr-gen");

use std::env;

use usg_est_client::{
    EstClient, EstClientConfig,
    types::{
        CmcRequest,
        cmc_full::{
            BatchRequest, BodyPartId, CmcFailInfo, CmcStatusInfo, CmcStatusValue, PkiDataBuilder,
            PkiResponse, TaggedAttribute,
        },
    },
};
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

    println!("Advanced CMC Example");
    println!("====================");
    println!("Server: {}", server_url);
    println!();

    // Demonstrate CMC message construction (even without a live server)
    demonstrate_pki_data_construction();
    demonstrate_batch_operations();
    demonstrate_status_handling();
    demonstrate_control_attributes();

    // Optional: Connect to actual EST server for Full CMC
    if args.iter().any(|a| a == "--live") {
        run_live_cmc_request(server_url).await;
    } else {
        println!();
        println!("Note: Add --live flag to attempt actual CMC request to server");
    }

    println!();
    println!("Done!");
}

/// Demonstrates building a PKIData request with the fluent builder API.
fn demonstrate_pki_data_construction() {
    println!("1. Building PKIData Request");
    println!("   -------------------------");

    // Generate a test CSR
    let (csr_der, _key_pair) = CsrBuilder::new()
        .common_name("device1.example.com")
        .organization("Example Corp")
        .key_usage_digital_signature()
        .build()
        .expect("CSR generation failed");

    println!("   Generated CSR: {} bytes", csr_der.len());

    // Build PKIData with the fluent API
    let pki_data = PkiDataBuilder::new()
        .transaction_id(12345) // Unique transaction identifier
        .random_sender_nonce() // Random nonce for replay protection
        .identification("device-enrollment-001".to_string()) // Human-readable ID
        .add_certification_request(csr_der)
        .build()
        .expect("PKIData build failed");

    println!("   PKIData created:");
    println!(
        "     - Control attributes: {}",
        pki_data.control_sequence.len()
    );
    println!(
        "     - Certificate requests: {}",
        pki_data.req_sequence.len()
    );
    println!("     - CMS content: {}", pki_data.cms_sequence.len());

    // Encode to DER for transmission
    let der_bytes = pki_data.to_der().expect("DER encoding failed");
    println!("   DER encoded size: {} bytes", der_bytes.len());
    println!();
}

/// Demonstrates batch operations for multiple certificate requests.
fn demonstrate_batch_operations() {
    println!("2. Batch Operations");
    println!("   -----------------");

    // Create multiple PKIData requests for batch processing
    let mut batch = BatchRequest::new();

    // First request: Web server certificate
    let (csr1, _) = CsrBuilder::new()
        .common_name("webserver.example.com")
        .san_dns("www.example.com")
        .san_dns("webserver.example.com")
        .key_usage_digital_signature()
        .key_usage_key_encipherment()
        .extended_key_usage_server_auth()
        .build()
        .expect("CSR1 generation failed");

    let pki_data1 = PkiDataBuilder::new()
        .transaction_id(1001)
        .add_certification_request(csr1)
        .build()
        .expect("PKIData1 build failed");

    batch.add_request(pki_data1);

    // Second request: Client certificate
    let (csr2, _) = CsrBuilder::new()
        .common_name("client.example.com")
        .key_usage_digital_signature()
        .extended_key_usage_client_auth()
        .build()
        .expect("CSR2 generation failed");

    let pki_data2 = PkiDataBuilder::new()
        .transaction_id(1002)
        .add_certification_request(csr2)
        .build()
        .expect("PKIData2 build failed");

    batch.add_request(pki_data2);

    // Third request: Email signing certificate
    let (csr3, _) = CsrBuilder::new()
        .common_name("user@example.com")
        .key_usage_digital_signature()
        .build()
        .expect("CSR3 generation failed");

    let pki_data3 = PkiDataBuilder::new()
        .transaction_id(1003)
        .add_certification_request(csr3)
        .build()
        .expect("PKIData3 build failed");

    batch.add_request(pki_data3);

    println!("   Created batch with {} requests:", batch.len());
    println!("     1. Web server certificate (TLS server auth)");
    println!("     2. Client certificate (TLS client auth)");
    println!("     3. Email certificate (S/MIME signing)");

    // Encode the entire batch
    let batch_der = batch.to_der().expect("Batch DER encoding failed");
    println!("   Batch DER size: {} bytes", batch_der.len());
    println!();
}

/// Demonstrates CMC status handling and failure codes.
fn demonstrate_status_handling() {
    println!("3. CMC Status Handling");
    println!("   --------------------");

    // Demonstrate different status scenarios
    println!("   Status Values:");
    for (value, desc) in [
        (CmcStatusValue::Success, "Request granted"),
        (CmcStatusValue::Failed, "Request failed - see failInfo"),
        (
            CmcStatusValue::Pending,
            "Request pending - check back later",
        ),
        (CmcStatusValue::NoSupport, "Operation not supported"),
        (
            CmcStatusValue::ConfirmRequired,
            "Certificate acceptance confirmation required",
        ),
        (CmcStatusValue::PopRequired, "Proof of possession required"),
        (
            CmcStatusValue::Partial,
            "Some requests succeeded, others failed",
        ),
    ] {
        let marker = if value.is_success() {
            "+"
        } else if value.is_failure() {
            "-"
        } else {
            "?"
        };
        println!(
            "     [{}] {:?} ({}): {}",
            marker,
            value,
            value.to_u32(),
            desc
        );
    }
    println!();

    // Demonstrate failure codes
    println!("   Failure Codes:");
    for fail_info in [
        CmcFailInfo::BadAlgorithm,
        CmcFailInfo::BadMessageCheck,
        CmcFailInfo::BadRequest,
        CmcFailInfo::BadTime,
        CmcFailInfo::BadIdentity,
        CmcFailInfo::PopRequired,
        CmcFailInfo::PopFailed,
        CmcFailInfo::InternalCaError,
        CmcFailInfo::TryLater,
        CmcFailInfo::AuthDataFail,
    ] {
        println!(
            "     {:?} ({}): {}",
            fail_info,
            fail_info.to_u32(),
            fail_info.description()
        );
    }
    println!();

    // Create example status info structures
    let success_status = CmcStatusInfo::success(vec![BodyPartId::new(1)]);
    println!(
        "   Example success status: is_success={}",
        success_status.status.is_success()
    );

    let failed_status = CmcStatusInfo::failed(vec![BodyPartId::new(2)], CmcFailInfo::BadRequest);
    println!(
        "   Example failure status: is_failure={}, reason={}",
        failed_status.status.is_failure(),
        failed_status.fail_info.unwrap().description()
    );
    println!();
}

/// Demonstrates CMC control attributes.
fn demonstrate_control_attributes() {
    println!("4. CMC Control Attributes");
    println!("   -----------------------");

    // Transaction ID - unique identifier for tracking requests
    let tx_id = TaggedAttribute::transaction_id(BodyPartId::new(1), 987654321);
    println!("   Transaction ID: OID={}", tx_id.attr_type);

    // Sender Nonce - random value for replay protection
    let sender_nonce =
        TaggedAttribute::sender_nonce(BodyPartId::new(2), vec![0x01, 0x02, 0x03, 0x04]);
    println!("   Sender Nonce: OID={}", sender_nonce.attr_type);

    // Recipient Nonce - echoes server's nonce for correlation
    let recipient_nonce =
        TaggedAttribute::recipient_nonce(BodyPartId::new(3), vec![0xAA, 0xBB, 0xCC, 0xDD]);
    println!("   Recipient Nonce: OID={}", recipient_nonce.attr_type);

    // Identification - human-readable client identifier
    let identification =
        TaggedAttribute::identification(BodyPartId::new(4), "client-12345".to_string());
    println!("   Identification: OID={}", identification.attr_type);

    println!();
    println!("   Available CMC OIDs (from oid module):");
    println!(
        "     - statusInfo: {}",
        usg_est_client::types::cmc_full::oid::STATUS_INFO
    );
    println!(
        "     - transactionId: {}",
        usg_est_client::types::cmc_full::oid::TRANSACTION_ID
    );
    println!(
        "     - senderNonce: {}",
        usg_est_client::types::cmc_full::oid::SENDER_NONCE
    );
    println!(
        "     - recipientNonce: {}",
        usg_est_client::types::cmc_full::oid::RECIPIENT_NONCE
    );
    println!(
        "     - identification: {}",
        usg_est_client::types::cmc_full::oid::IDENTIFICATION
    );
    println!(
        "     - queryPending: {}",
        usg_est_client::types::cmc_full::oid::QUERY_PENDING
    );
    println!(
        "     - revokeRequest: {}",
        usg_est_client::types::cmc_full::oid::REVOKE_REQUEST
    );
    println!();
}

/// Attempts a live CMC request to an EST server.
async fn run_live_cmc_request(server_url: &str) {
    println!("5. Live CMC Request");
    println!("   -----------------");

    // Build client configuration
    let builder = match EstClientConfig::builder().server_url(server_url) {
        Ok(b) => b.trust_any_insecure(), // For testing only!
        Err(e) => {
            eprintln!("   Failed to parse server URL: {}", e);
            return;
        }
    };

    let config = match builder.build() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("   Failed to build config: {}", e);
            return;
        }
    };

    // Create EST client
    let client = match EstClient::new(config).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("   Failed to create EST client: {}", e);
            return;
        }
    };

    // Generate CSR for CMC request
    let (csr_der, _key_pair) = match CsrBuilder::new()
        .common_name("cmc-test.example.com")
        .organization("CMC Example")
        .key_usage_digital_signature()
        .build()
    {
        Ok(result) => result,
        Err(e) => {
            eprintln!("   Failed to generate CSR: {}", e);
            return;
        }
    };

    // Build CMC PKIData
    let pki_data = match PkiDataBuilder::new()
        .transaction_id(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        )
        .random_sender_nonce()
        .identification("cmc-example-client".to_string())
        .add_certification_request(csr_der)
        .build()
    {
        Ok(data) => data,
        Err(e) => {
            eprintln!("   Failed to build PKIData: {}", e);
            return;
        }
    };

    // Encode to DER
    let pki_data_der = match pki_data.to_der() {
        Ok(der) => der,
        Err(e) => {
            eprintln!("   Failed to encode PKIData: {}", e);
            return;
        }
    };

    println!("   PKIData size: {} bytes", pki_data_der.len());
    println!("   Sending Full CMC request...");

    // Wrap in CmcRequest for the EST client API
    let cmc_request = CmcRequest::new(pki_data_der);

    // Send Full CMC request
    match client.full_cmc(&cmc_request).await {
        Ok(cmc_response) => {
            println!(
                "   Received CMC response: {} bytes",
                cmc_response.data.len()
            );

            // Check the response status
            if cmc_response.is_success() {
                println!("   Status: SUCCESS");
                println!(
                    "   Certificates received: {}",
                    cmc_response.certificates.len()
                );
            } else {
                println!("   Status: {:?}", cmc_response.status);
            }

            // Also try to parse with the full PKIResponse for additional details
            match PkiResponse::from_der(&cmc_response.data) {
                Ok(pki_response) => {
                    if pki_response.is_pending() {
                        println!("   Request is awaiting manual approval");
                    }
                    if let Some(fail_info) = pki_response.fail_info() {
                        println!("   Failure reason: {}", fail_info.description());
                    }
                }
                Err(_) => {
                    // PKIResponse parsing is still a placeholder
                }
            }
        }
        Err(e) => {
            // Many EST servers don't support Full CMC
            println!("   CMC request failed: {}", e);
            println!(
                "   Note: Full CMC is optional in EST; many servers only support simple enrollment"
            );
        }
    }
}
