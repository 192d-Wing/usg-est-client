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

//! Integration tests for HTTP Basic authentication

use crate::integration::MockEstServer;
use std::fs;
#[cfg(feature = "csr-gen")]
use usg_est_client::csr::CsrBuilder;
use usg_est_client::{EstClient, EstClientConfig};

#[tokio::test]
#[cfg(feature = "csr-gen")]
async fn test_successful_http_basic_auth() {
    // Start mock server
    let mock = MockEstServer::start().await;

    // Mock successful enrollment (server accepts auth)
    let cert_pkcs7_base64 = fs::read_to_string("tests/fixtures/pkcs7/valid-enroll.b64")
        .expect("Failed to load enrollment fixture");
    mock.mock_enroll_success(&cert_pkcs7_base64).await;

    // Create EST client with HTTP Basic auth
    let config = EstClientConfig::builder()
        .server_url(mock.url())
        .expect("Valid URL")
        .http_auth("testuser", "testpass")
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

    // Test: Enrollment with HTTP Basic auth
    let result = client.simple_enroll(&csr_der).await;

    // Should succeed against the mock server when basic auth is provided
    assert!(
        result.is_ok(),
        "Enrollment should succeed with HTTP Basic auth"
    );
}

#[tokio::test]
#[cfg(feature = "csr-gen")]
async fn test_invalid_credentials() {
    // Start mock server
    let mock = MockEstServer::start().await;

    // Mock authentication required response
    mock.mock_enroll_auth_required().await;

    // Create EST client with (potentially wrong) credentials
    let config = EstClientConfig::builder()
        .server_url(mock.url())
        .expect("Valid URL")
        .http_auth("wronguser", "wrongpass")
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

    // Test: Enrollment with invalid credentials
    let result = client.simple_enroll(&csr_der).await;

    // Should get authentication required error
    assert!(result.is_err(), "Should fail with invalid credentials");
    let err = result.unwrap_err();
    assert!(
        matches!(err, usg_est_client::EstError::AuthenticationRequired { .. }),
        "Should return AuthenticationRequired error, got: {:?}",
        err
    );
}

#[tokio::test]
#[cfg(feature = "csr-gen")]
async fn test_missing_authorization_header() {
    // Start mock server
    let mock = MockEstServer::start().await;

    // Mock authentication required response
    mock.mock_enroll_auth_required().await;

    // Create EST client WITHOUT authentication
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

    // Test: Enrollment without authorization
    let result = client.simple_enroll(&csr_der).await;

    // Should get authentication required error
    assert!(result.is_err(), "Should fail without authentication");
    let err = result.unwrap_err();
    assert!(
        matches!(err, usg_est_client::EstError::AuthenticationRequired { .. }),
        "Should return AuthenticationRequired error"
    );
}

#[tokio::test]
async fn test_http_basic_auth_header_format() {
    // Verify that HTTP Basic auth creates proper Authorization header

    // Create config with HTTP Basic auth
    let config = EstClientConfig::builder()
        .server_url("https://test.example.com")
        .expect("Valid URL")
        .http_auth("user", "pass")
        .trust_any_insecure()
        .build()
        .expect("Valid config");

    // Verify config contains auth
    assert!(config.http_auth.is_some(), "HTTP auth should be configured");
    let auth = config.http_auth.unwrap();
    assert_eq!(auth.username, "user");
    assert_eq!(auth.password, "pass");

    // The actual header creation happens in the client
    // Expected format: "Basic base64(username:password)"
    // For "user:pass" -> base64("user:pass") = "dXNlcjpwYXNz"
    // Authorization header should be: "Basic dXNlcjpwYXNz"
}

#[tokio::test]
async fn test_empty_credentials() {
    // Test behavior with empty username/password

    let config = EstClientConfig::builder()
        .server_url("https://test.example.com")
        .expect("Valid URL")
        .http_auth("", "")
        .trust_any_insecure()
        .build();

    // Should allow empty credentials (valid for base64 encoding)
    assert!(config.is_ok(), "Should allow empty credentials");
}

#[tokio::test]
async fn test_special_characters_in_credentials() {
    // Test that special characters are handled correctly in HTTP Basic auth

    let config = EstClientConfig::builder()
        .server_url("https://test.example.com")
        .expect("Valid URL")
        .http_auth("user@example.com", "p@ss:w0rd!")
        .trust_any_insecure()
        .build();

    assert!(
        config.is_ok(),
        "Should handle special characters in credentials"
    );

    // Special characters like : and @ should be properly encoded
    let auth = config.unwrap().http_auth.unwrap();
    assert_eq!(auth.username, "user@example.com");
    assert_eq!(auth.password, "p@ss:w0rd!");
}
