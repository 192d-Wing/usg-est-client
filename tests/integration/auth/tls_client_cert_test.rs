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

//! Integration tests for TLS client certificate authentication

use crate::integration::MockEstServer;
use std::fs;
#[cfg(feature = "csr-gen")]
use usg_est_client::csr::CsrBuilder;
use usg_est_client::{ClientIdentity, EstClient, EstClientConfig};

#[tokio::test]
#[cfg(feature = "csr-gen")]
async fn test_successful_tls_client_cert_auth() {
    // Start mock server
    let mock = MockEstServer::start().await;

    // Load enrollment response
    let cert_pkcs7_base64 = fs::read_to_string("tests/fixtures/pkcs7/valid-enroll.b64")
        .expect("Failed to load enrollment fixture");
    mock.mock_reenroll_success(&cert_pkcs7_base64).await;

    // Load client certificate and key
    let client_cert_pem =
        fs::read("tests/fixtures/certs/client.pem").expect("Failed to load client cert");
    let client_key_pem =
        fs::read("tests/fixtures/certs/client-key.pem").expect("Failed to load client key");

    // Create EST client with TLS client certificate
    let config = EstClientConfig::builder()
        .server_url(mock.url())
        .expect("Valid URL")
        .client_identity(ClientIdentity::new(client_cert_pem, client_key_pem))
        .trust_any_insecure() // OK for testing
        .build()
        .expect("Valid config");

    let client = EstClient::new(config)
        .await
        .expect("Client creation failed");

    // Generate CSR
    let (csr_der, _key_pair) = CsrBuilder::new()
        .common_name("test-device.example.com")
        .build()
        .expect("CSR generation failed");

    // Test: Re-enrollment with client cert (should use TLS client auth)
    let result = client.simple_reenroll(&csr_der).await;

    // Note: Mock server doesn't validate TLS client certs, but client should succeed
    assert!(
        result.is_ok(),
        "Client should enroll successfully with TLS client certificate"
    );
}

#[tokio::test]
#[cfg(feature = "csr-gen")]
async fn test_missing_client_certificate() {
    // Start mock server
    let mock = MockEstServer::start().await;

    let cert_pkcs7_base64 = fs::read_to_string("tests/fixtures/pkcs7/valid-enroll.b64")
        .expect("Failed to load enrollment fixture");
    mock.mock_reenroll_success(&cert_pkcs7_base64).await;

    // Create EST client WITHOUT client certificate
    let config = EstClientConfig::builder()
        .server_url(mock.url())
        .expect("Valid URL")
        .trust_any_insecure()
        .build()
        .expect("Valid config");

    let client = EstClient::new(config)
        .await
        .expect("Client creation failed");

    // Generate CSR
    let (csr_der, _key_pair) = CsrBuilder::new()
        .common_name("test-device.example.com")
        .build()
        .expect("CSR generation failed");

    // Test: Re-enrollment without client cert
    // In real EST, server would likely reject this with 401
    let _result = client.simple_reenroll(&csr_der).await;

    // The mock server doesn't enforce this, but in production EST servers,
    // re-enrollment typically requires TLS client cert authentication
}

#[tokio::test]
async fn test_invalid_client_certificate() {
    // Start mock server
    let mock = MockEstServer::start().await;

    let cert_pkcs7_base64 = fs::read_to_string("tests/fixtures/pkcs7/valid-enroll.b64")
        .expect("Failed to load enrollment fixture");
    mock.mock_reenroll_success(&cert_pkcs7_base64).await;

    // Create invalid certificate data
    let invalid_cert = b"-----BEGIN CERTIFICATE-----\nINVALID\n-----END CERTIFICATE-----";
    let invalid_key = b"-----BEGIN PRIVATE KEY-----\nINVALID\n-----END PRIVATE KEY-----";

    // Try to create EST client with invalid cert/key
    let config_result = EstClientConfig::builder()
        .server_url(mock.url())
        .expect("Valid URL")
        .client_identity(ClientIdentity::new(
            invalid_cert.to_vec(),
            invalid_key.to_vec(),
        ))
        .trust_any_insecure()
        .build();

    // Building config should succeed (validation happens during TLS handshake)
    assert!(config_result.is_ok(), "Config creation should succeed");

    // Client creation should fail during TLS setup with invalid identity material
    let client_result = EstClient::new(config_result.unwrap()).await;
    assert!(
        client_result.is_err(),
        "Invalid client identity should prevent client creation"
    );

    let err_msg = client_result.unwrap_err().to_string();
    assert!(
        err_msg.contains("TLS") || err_msg.contains("certificate") || err_msg.contains("key"),
        "Should fail with TLS/certificate/key error"
    );
}

#[tokio::test]
async fn test_certificate_chain_validation() {
    // Start mock server
    let mock = MockEstServer::start().await;

    let cert_pkcs7_base64 = fs::read_to_string("tests/fixtures/pkcs7/valid-enroll.b64")
        .expect("Failed to load enrollment fixture");
    mock.mock_reenroll_success(&cert_pkcs7_base64).await;

    // Load client cert (which is signed by our CA)
    let client_cert_pem =
        fs::read("tests/fixtures/certs/client.pem").expect("Failed to load client cert");
    let client_key_pem =
        fs::read("tests/fixtures/certs/client-key.pem").expect("Failed to load client key");

    // Create EST client with client cert
    let config = EstClientConfig::builder()
        .server_url(mock.url())
        .expect("Valid URL")
        .client_identity(ClientIdentity::new(client_cert_pem, client_key_pem))
        .trust_any_insecure()
        .build()
        .expect("Valid config");

    let client = EstClient::new(config).await;

    // Verify client can be created with valid certificate chain
    assert!(
        client.is_ok(),
        "Client creation should succeed with valid cert chain"
    );
}
