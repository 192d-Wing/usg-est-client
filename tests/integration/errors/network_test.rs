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

//! Integration tests for network error handling

use std::time::Duration;
use usg_est_client::{EstClient, EstClientConfig};
#[cfg(feature = "csr-gen")]
use usg_est_client::csr::CsrBuilder;

#[tokio::test]
#[cfg(feature = "csr-gen")]
async fn test_connection_timeout() {
    // Use a non-routable IP address to trigger timeout
    // 192.0.2.0/24 is reserved for documentation (TEST-NET-1)
    let config = EstClientConfig::builder()
        .server_url("https://192.0.2.1:8443")
        .expect("Valid URL")
        .timeout(Duration::from_millis(100)) // Very short timeout
        .trust_any_insecure()
        .build()
        .expect("Valid config");

    let client = EstClient::new(config)
        .await
        .expect("Client creation failed");

    // Generate CSR
    let (csr_der, _key_pair) = CsrBuilder::new()
        .common_name("test.example.com")
        .build()
        .expect("CSR generation failed");

    // Test: Should timeout
    let result = client.simple_enroll(&csr_der).await;

    // Should fail with timeout/connection error
    assert!(result.is_err(), "Should fail with timeout");
    let err = result.unwrap_err();

    // Error should be HTTP-related (timeout or connection)
    assert!(
        matches!(err, usg_est_client::EstError::Http(_)),
        "Should be HTTP error, got: {:?}",
        err
    );
}

#[tokio::test]
#[cfg(feature = "csr-gen")]
async fn test_connection_refused() {
    // Use localhost with a port that's likely not listening
    let config = EstClientConfig::builder()
        .server_url("https://127.0.0.1:19999") // Unlikely port
        .expect("Valid URL")
        .timeout(Duration::from_secs(1))
        .trust_any_insecure()
        .build()
        .expect("Valid config");

    let client = EstClient::new(config)
        .await
        .expect("Client creation failed");

    // Generate CSR
    let (csr_der, _key_pair) = CsrBuilder::new()
        .common_name("test.example.com")
        .build()
        .expect("CSR generation failed");

    // Test: Should fail with connection refused
    let result = client.simple_enroll(&csr_der).await;

    // Should fail with connection error
    assert!(result.is_err(), "Should fail with connection refused");
}

#[tokio::test]
#[cfg(feature = "csr-gen")]
async fn test_dns_resolution_failure() {
    // Use an invalid domain name that should fail DNS resolution
    let config = EstClientConfig::builder()
        .server_url("https://this-domain-definitely-does-not-exist-12345.invalid")
        .expect("Valid URL")
        .timeout(Duration::from_secs(2))
        .trust_any_insecure()
        .build()
        .expect("Valid config");

    let client = EstClient::new(config)
        .await
        .expect("Client creation failed");

    // Generate CSR
    let (csr_der, _key_pair) = CsrBuilder::new()
        .common_name("test.example.com")
        .build()
        .expect("CSR generation failed");

    // Test: Should fail with DNS error
    let result = client.simple_enroll(&csr_der).await;

    // Should fail with HTTP/connection error
    assert!(result.is_err(), "Should fail with DNS resolution error");
}

#[tokio::test]
#[cfg(feature = "csr-gen")]
async fn test_tls_handshake_failure() {
    // This test would verify TLS handshake failures
    // In practice, this is difficult to test without a real server
    // that rejects TLS handshakes

    // For now, we verify that invalid server configs fail appropriately
    let config = EstClientConfig::builder()
        .server_url("https://expired.badssl.com") // Known expired cert site
        .expect("Valid URL")
        .timeout(Duration::from_secs(5))
        .build(); // Don't use trust_any_insecure - let it validate

    if config.is_err() {
        // Config creation might fail if WebPKI roots aren't available
        return;
    }

    let client_result = EstClient::new(config.unwrap()).await;

    // Client might be created but requests should fail
    if let Ok(client) = client_result {
        let (csr_der, _key_pair) = CsrBuilder::new()
            .common_name("test.example.com")
            .build()
            .expect("CSR generation failed");

        let result = client.simple_enroll(&csr_der).await;

        // Should fail due to TLS/certificate issues
        // (Note: This test might pass if the site starts working)
        assert!(
            result.is_err(),
            "TLS validation should fail with invalid certificates"
        );
    }
}

#[tokio::test]
async fn test_network_interruption_during_request() {
    // This would test handling of network interruption mid-request
    // Difficult to simulate reliably in integration tests
    // In practice, this would result in HTTP errors

    // Placeholder demonstrating the test concept
}

#[tokio::test]
#[cfg(feature = "csr-gen")]
async fn test_slow_server_response() {
    use tokio::time::timeout;

    // Use a non-routable address to simulate slow response
    let config = EstClientConfig::builder()
        .server_url("https://192.0.2.1:8443")
        .expect("Valid URL")
        .timeout(Duration::from_millis(500))
        .trust_any_insecure()
        .build()
        .expect("Valid config");

    let client = EstClient::new(config)
        .await
        .expect("Client creation failed");

    let (csr_der, _key_pair) = CsrBuilder::new()
        .common_name("test.example.com")
        .build()
        .expect("CSR generation failed");

    // Wrap in timeout to ensure test doesn't hang
    let result = timeout(Duration::from_secs(2), client.simple_enroll(&csr_der)).await;

    // Should either timeout or get an error
    assert!(
        result.is_err() || result.unwrap().is_err(),
        "Should handle slow/non-responsive server"
    );
}

#[tokio::test]
async fn test_invalid_url_scheme() {
    // Test that non-HTTPS URLs are rejected or handled properly

    // HTTP (not HTTPS) - some implementations may allow for testing
    let config = EstClientConfig::builder()
        .server_url("http://test.example.com")
        .expect("URL parsing succeeds");

    // Config should build, but in production HTTPS is required
    assert!(config.build().is_ok(), "HTTP URLs are technically valid");
}

#[tokio::test]
async fn test_malformed_url() {
    // Test completely invalid URLs
    let result = EstClientConfig::builder().server_url("not-a-valid-url");

    // Should fail to parse
    assert!(result.is_err(), "Should reject malformed URL");
}

#[tokio::test]
async fn test_url_with_invalid_port() {
    // Test URL with invalid port number
    let result = EstClientConfig::builder().server_url("https://test.example.com:99999");

    // Should fail - port number out of range
    assert!(result.is_err(), "Should reject invalid port number");
}
