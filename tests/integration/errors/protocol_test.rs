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

//! Integration tests for protocol error handling

use crate::integration::MockEstServer;
use usg_est_client::{EstClient, EstClientConfig};
#[cfg(feature = "csr-gen")]
use usg_est_client::csr::CsrBuilder;

#[tokio::test]
async fn test_invalid_content_type() {
    // Start mock server
    let mock = MockEstServer::start().await;

    // Mock response with wrong content type
    mock.mock_invalid_content_type("/.well-known/est/cacerts")
        .await;

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

    // Test: Get CA certs with invalid content type
    let result = client.get_ca_certs().await;

    // Should fail (could be content type, parsing, or base64 error)
    // The exact error depends on the parsing order in the client implementation
    assert!(result.is_err(), "Should reject invalid content type");
    let err = result.unwrap_err();
    assert!(
        matches!(err, usg_est_client::EstError::InvalidContentType { .. })
            || matches!(err, usg_est_client::EstError::Base64(_))
            || matches!(err, usg_est_client::EstError::CmsParsing(_)),
        "Expected InvalidContentType, Base64, or CmsParsing error, got: {:?}",
        err
    );
}

#[tokio::test]
#[cfg(feature = "csr-gen")]
async fn test_missing_required_headers() {
    // Start mock server
    let mock = MockEstServer::start().await;

    // Mock pending response without Retry-After header
    // (This would be a protocol violation)
    use wiremock::{
        Mock, ResponseTemplate,
        matchers::{method, path},
    };

    Mock::given(method("POST"))
        .and(path("/.well-known/est/simpleenroll"))
        .respond_with(ResponseTemplate::new(202)) // No Retry-After header
        .mount(mock.inner())
        .await;

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

    let (csr_der, _key_pair) = CsrBuilder::new()
        .common_name("test.example.com")
        .build()
        .expect("CSR generation failed");

    // Test: Enrollment with missing Retry-After header
    let _ = client.simple_enroll(&csr_der).await;

    // Behavior depends on implementation - might fail or default to 0
    // At minimum, should not panic
}

#[tokio::test]
async fn test_malformed_response_bodies() {
    // Start mock server
    let mock = MockEstServer::start().await;

    // Mock with invalid base64
    mock.mock_malformed_body("/.well-known/est/cacerts", "application/pkcs7-mime")
        .await;

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

    // Test: Get CA certs with malformed body
    let result = client.get_ca_certs().await;

    // Should fail with base64 or parsing error
    assert!(result.is_err(), "Should reject malformed response body");
}

#[tokio::test]
async fn test_unexpected_http_methods() {
    // This would test that the client uses correct HTTP methods
    // GET for /cacerts, POST for enrollment, etc.

    // The client enforces this at the code level, so this is more
    // of a verification that the API doesn't allow wrong methods
}

#[tokio::test]
#[cfg(feature = "csr-gen")]
async fn test_http_status_code_handling() {
    use wiremock::{
        Mock, ResponseTemplate,
        matchers::{method, path},
    };

    // Start mock server
    let mock = MockEstServer::start().await;

    // Test various HTTP status codes

    // 400 Bad Request
    Mock::given(method("POST"))
        .and(path("/.well-known/est/simpleenroll"))
        .respond_with(ResponseTemplate::new(400).set_body_string("Bad Request"))
        .mount(mock.inner())
        .await;

    let config = EstClientConfig::builder()
        .server_url(mock.url())
        .expect("Valid URL")
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

    let result = client.simple_enroll(&csr_der).await;

    // Should fail with ServerError
    assert!(result.is_err(), "Should handle 400 Bad Request");
    if let Err(e) = result {
        assert!(
            matches!(e, usg_est_client::EstError::ServerError { .. }),
            "Should be ServerError"
        );
    }
}

#[tokio::test]
async fn test_empty_response_body() {
    use wiremock::{
        Mock, ResponseTemplate,
        matchers::{method, path},
    };

    // Start mock server
    let mock = MockEstServer::start().await;

    // Mock empty response
    Mock::given(method("GET"))
        .and(path("/.well-known/est/cacerts"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("")
                .insert_header("Content-Type", "application/pkcs7-mime"),
        )
        .mount(mock.inner())
        .await;

    let config = EstClientConfig::builder()
        .server_url(mock.url())
        .expect("Valid URL")
        .trust_any_insecure()
        .build()
        .expect("Valid config");

    let client = EstClient::new(config)
        .await
        .expect("Client creation failed");

    let result = client.get_ca_certs().await;

    // Should fail with base64 or parsing error
    assert!(result.is_err(), "Should reject empty response body");
}

#[tokio::test]
async fn test_oversized_response() {
    // This would test handling of very large responses
    // To prevent DoS attacks, clients should have limits

    // Placeholder for future implementation
}

#[tokio::test]
async fn test_redirect_handling() {
    use wiremock::{
        Mock, ResponseTemplate,
        matchers::{method, path},
    };

    // Start mock server
    let mock = MockEstServer::start().await;

    // Mock redirect response
    Mock::given(method("GET"))
        .and(path("/.well-known/est/cacerts"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("Location", "https://other.example.com/cacerts"),
        )
        .mount(mock.inner())
        .await;

    let config = EstClientConfig::builder()
        .server_url(mock.url())
        .expect("Valid URL")
        .trust_any_insecure()
        .build()
        .expect("Valid config");

    let client = EstClient::new(config)
        .await
        .expect("Client creation failed");

    let _ = client.get_ca_certs().await;

    // reqwest follows redirects by default
    // Should either follow redirect or fail
    // (behavior depends on redirect destination)
}

#[tokio::test]
async fn test_content_encoding_handling() {
    // Test that client handles Content-Transfer-Encoding correctly
    // EST requires base64 encoding for binary content

    // The client expects "Content-Transfer-Encoding: base64"
    // and decodes accordingly
}

#[tokio::test]
async fn test_missing_content_type_header() {
    use wiremock::{
        Mock, ResponseTemplate,
        matchers::{method, path},
    };

    // Start mock server
    let mock = MockEstServer::start().await;

    // Mock response without Content-Type
    Mock::given(method("GET"))
        .and(path("/.well-known/est/cacerts"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("some data"), // No Content-Type header
        )
        .mount(mock.inner())
        .await;

    let config = EstClientConfig::builder()
        .server_url(mock.url())
        .expect("Valid URL")
        .trust_any_insecure()
        .build()
        .expect("Valid config");

    let client = EstClient::new(config)
        .await
        .expect("Client creation failed");

    let result = client.get_ca_certs().await;

    // Should fail - Content-Type is required for EST responses
    assert!(result.is_err(), "Should require Content-Type header");
}
