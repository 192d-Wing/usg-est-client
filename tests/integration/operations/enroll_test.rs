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

//! Integration tests for POST /simpleenroll operation

use crate::integration::MockEstServer;
use std::fs;
use usg_est_client::{EnrollmentResponse, EstClient, EstClientConfig};
#[cfg(feature = "csr-gen")]
use usg_est_client::csr::CsrBuilder;

#[tokio::test]
#[cfg(feature = "csr-gen")]
async fn test_successful_enrollment() {
    // Start mock server
    let mock = MockEstServer::start().await;

    // Load valid enrollment response fixture
    let cert_pkcs7_base64 = fs::read_to_string("tests/fixtures/pkcs7/valid-enroll.b64")
        .expect("Failed to load enrollment fixture");

    // Mock successful enrollment
    mock.mock_enroll_success(&cert_pkcs7_base64).await;

    // Create EST client
    let config = EstClientConfig::builder()
        .server_url(mock.url())
        .expect("Valid URL")
        .trust_any_insecure()
        .build()
        .expect("Valid config");

    let client = EstClient::new(config)
        .await
        .expect("Client creation failed");

    // Generate a CSR
    let (csr_der, _key_pair) = CsrBuilder::new()
        .common_name("test-device.example.com")
        .build()
        .expect("CSR generation failed");

    // Test: Simple enroll
    let result = client.simple_enroll(&csr_der).await;

    // Assert: Should succeed with issued certificate
    assert!(result.is_ok(), "simple_enroll failed: {:?}", result.err());

    match result.unwrap() {
        EnrollmentResponse::Issued { certificate } => {
            // Verify we got a certificate
            assert!(
                !certificate
                    .tbs_certificate
                    .serial_number
                    .as_bytes()
                    .is_empty()
            );
        }
        EnrollmentResponse::Pending { .. } => {
            panic!("Expected Issued, got Pending");
        }
    }
}

#[tokio::test]
#[cfg(feature = "csr-gen")]
async fn test_pending_enrollment() {
    // Start mock server
    let mock = MockEstServer::start().await;

    // Mock pending enrollment with retry-after
    mock.mock_enroll_pending(300).await;

    // Create EST client
    let config = EstClientConfig::builder()
        .server_url(mock.url())
        .expect("Valid URL")
        .trust_any_insecure()
        .build()
        .expect("Valid config");

    let client = EstClient::new(config)
        .await
        .expect("Client creation failed");

    // Generate a CSR
    let (csr_der, _key_pair) = CsrBuilder::new()
        .common_name("test-device.example.com")
        .build()
        .expect("CSR generation failed");

    // Test: Simple enroll returns pending
    let result = client.simple_enroll(&csr_der).await;

    // Assert: Should succeed with pending status
    assert!(result.is_ok(), "simple_enroll failed: {:?}", result.err());

    match result.unwrap() {
        EnrollmentResponse::Pending { retry_after } => {
            assert_eq!(retry_after, 300, "Retry-After should be 300 seconds");
        }
        EnrollmentResponse::Issued { .. } => {
            panic!("Expected Pending, got Issued");
        }
    }
}

#[tokio::test]
#[cfg(feature = "csr-gen")]
async fn test_authentication_required() {
    // Start mock server
    let mock = MockEstServer::start().await;

    // Mock authentication required
    mock.mock_enroll_auth_required().await;

    // Create EST client (without credentials)
    let config = EstClientConfig::builder()
        .server_url(mock.url())
        .expect("Valid URL")
        .trust_any_insecure()
        .build()
        .expect("Valid config");

    let client = EstClient::new(config)
        .await
        .expect("Client creation failed");

    // Generate a CSR
    let (csr_der, _key_pair) = CsrBuilder::new()
        .common_name("test-device.example.com")
        .build()
        .expect("CSR generation failed");

    // Test: Simple enroll without auth
    let result = client.simple_enroll(&csr_der).await;

    // Assert: Should fail with authentication required
    assert!(result.is_err(), "Should require authentication");
    let err = result.unwrap_err();
    assert!(
        matches!(err, usg_est_client::EstError::AuthenticationRequired { .. }),
        "Wrong error type: {:?}",
        err
    );
}

#[tokio::test]
#[cfg(feature = "csr-gen")]
async fn test_server_error() {
    // Start mock server
    let mock = MockEstServer::start().await;

    // Mock server error
    mock.mock_server_error(500, "Internal Server Error").await;

    // Create EST client
    let config = EstClientConfig::builder()
        .server_url(mock.url())
        .expect("Valid URL")
        .trust_any_insecure()
        .build()
        .expect("Valid config");

    let client = EstClient::new(config)
        .await
        .expect("Client creation failed");

    // Generate a CSR
    let (csr_der, _key_pair) = CsrBuilder::new()
        .common_name("test-device.example.com")
        .build()
        .expect("CSR generation failed");

    // Test: Simple enroll with server error
    let result = client.simple_enroll(&csr_der).await;

    // Assert: Should fail with server error
    assert!(result.is_err(), "Should fail with server error");
    let err = result.unwrap_err();
    assert!(
        matches!(err, usg_est_client::EstError::ServerError { .. }),
        "Wrong error type: {:?}",
        err
    );
}

#[tokio::test]
#[cfg(feature = "csr-gen")]
async fn test_csr_validation() {
    // Start mock server
    let mock = MockEstServer::start().await;

    let cert_pkcs7_base64 = fs::read_to_string("tests/fixtures/pkcs7/valid-enroll.b64")
        .expect("Failed to load enrollment fixture");
    mock.mock_enroll_success(&cert_pkcs7_base64).await;

    // Create EST client
    let config = EstClientConfig::builder()
        .server_url(mock.url())
        .expect("Valid URL")
        .trust_any_insecure()
        .build()
        .expect("Valid config");

    let client = EstClient::new(config)
        .await
        .expect("Client creation failed");

    // Generate a CSR with multiple attributes
    let (csr_der, _key_pair) = CsrBuilder::new()
        .common_name("test-device.example.com")
        .organization("Test Organization")
        .country("US")
        .san_dns("test-device.example.com")
        .key_usage_digital_signature()
        .key_usage_key_encipherment()
        .extended_key_usage_client_auth()
        .build()
        .expect("CSR generation failed");

    // Verify CSR is valid DER before sending
    assert!(!csr_der.is_empty(), "CSR should not be empty");

    // Test: Simple enroll with valid CSR
    let result = client.simple_enroll(&csr_der).await;

    // Assert: Should succeed
    assert!(result.is_ok(), "simple_enroll failed: {:?}", result.err());
}
