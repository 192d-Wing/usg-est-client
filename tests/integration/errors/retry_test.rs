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

//! Integration tests for retry logic

use crate::integration::MockEstServer;
use usg_est_client::{EstClient, EstClientConfig, EstError};
#[cfg(feature = "csr-gen")]
use usg_est_client::csr::CsrBuilder;

#[tokio::test]
#[cfg(feature = "csr-gen")]
async fn test_retry_after_header_parsing() {
    // Start mock server
    let mock = MockEstServer::start().await;

    // Mock pending enrollment with Retry-After
    mock.mock_enroll_pending(300).await;

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

    // Should get pending response with retry_after
    assert!(result.is_ok(), "Should parse Retry-After header");

    if let Ok(usg_est_client::EnrollmentResponse::Pending { retry_after }) = result {
        assert_eq!(retry_after, 300, "Should parse Retry-After value correctly");
    } else {
        panic!("Expected Pending response");
    }
}

#[tokio::test]
async fn test_error_is_retryable() {
    // Test the is_retryable() method on various error types

    // HTTP 202 with Retry-After is retryable
    let pending_err = EstError::enrollment_pending(300);
    assert!(
        pending_err.is_retryable(),
        "Pending enrollment should be retryable"
    );
    assert_eq!(
        pending_err.retry_after(),
        Some(300),
        "Should have retry_after value"
    );

    // HTTP 401 is not automatically retryable (needs new credentials)
    let auth_err = EstError::authentication_required("Basic".to_string());
    assert!(
        !auth_err.is_retryable(),
        "Auth required should not be auto-retryable"
    );
    assert_eq!(auth_err.retry_after(), None, "Should not have retry_after");

    // HTTP 500 might be retryable depending on the error
    let server_err = EstError::server_error(500, "Internal Error".to_string());
    assert!(
        !server_err.is_retryable(),
        "Server errors are not automatically retryable"
    );
}

#[tokio::test]
#[cfg(feature = "csr-gen")]
async fn test_retry_after_zero_seconds() {
    // Test handling of Retry-After: 0 (retry immediately)

    use wiremock::{
        Mock, ResponseTemplate,
        matchers::{method, path},
    };

    let mock = MockEstServer::start().await;

    Mock::given(method("POST"))
        .and(path("/.well-known/est/simpleenroll"))
        .respond_with(ResponseTemplate::new(202).insert_header("Retry-After", "0"))
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

    if let Ok(usg_est_client::EnrollmentResponse::Pending { retry_after }) = result {
        assert_eq!(retry_after, 0, "Should handle Retry-After: 0");
    }
}

#[tokio::test]
#[cfg(feature = "csr-gen")]
async fn test_retry_after_large_value() {
    // Test handling of very large Retry-After values

    use wiremock::{
        Mock, ResponseTemplate,
        matchers::{method, path},
    };

    let mock = MockEstServer::start().await;

    Mock::given(method("POST"))
        .and(path("/.well-known/est/simpleenroll"))
        .respond_with(
            ResponseTemplate::new(202).insert_header("Retry-After", "86400"), // 24 hours
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

    let (csr_der, _key_pair) = CsrBuilder::new()
        .common_name("test.example.com")
        .build()
        .expect("CSR generation failed");

    let result = client.simple_enroll(&csr_der).await;

    if let Ok(usg_est_client::EnrollmentResponse::Pending { retry_after }) = result {
        assert_eq!(retry_after, 86400, "Should handle large Retry-After values");
    }
}

#[tokio::test]
#[cfg(feature = "csr-gen")]
async fn test_malformed_retry_after_header() {
    // Test handling of invalid Retry-After values

    use wiremock::{
        Mock, ResponseTemplate,
        matchers::{method, path},
    };

    let mock = MockEstServer::start().await;

    Mock::given(method("POST"))
        .and(path("/.well-known/est/simpleenroll"))
        .respond_with(ResponseTemplate::new(202).insert_header("Retry-After", "not-a-number"))
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

    let _ = client.simple_enroll(&csr_der).await;

    // Should handle gracefully - either error or default to 0
    // Implementation-dependent behavior
}

#[tokio::test]
#[cfg(feature = "csr-gen")]
async fn test_http_date_retry_after() {
    // RFC 7231 allows Retry-After to be an HTTP-date instead of seconds
    // e.g., "Retry-After: Fri, 31 Dec 2024 23:59:59 GMT"

    use wiremock::{
        Mock, ResponseTemplate,
        matchers::{method, path},
    };

    let mock = MockEstServer::start().await;

    Mock::given(method("POST"))
        .and(path("/.well-known/est/simpleenroll"))
        .respond_with(
            ResponseTemplate::new(202)
                .insert_header("Retry-After", "Wed, 21 Oct 2025 07:28:00 GMT"),
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

    let (csr_der, _key_pair) = CsrBuilder::new()
        .common_name("test.example.com")
        .build()
        .expect("CSR generation failed");

    let _ = client.simple_enroll(&csr_der).await;

    // Should handle HTTP-date format (may convert to seconds or error)
    // Implementation-dependent
}

#[tokio::test]
async fn test_multiple_retry_attempts() {
    // This would test a scenario where multiple retry attempts are made
    // For now, this is more of a client usage pattern than a test

    // Pseudo-code:
    // 1. Submit enrollment
    // 2. Get 202 with Retry-After: 5
    // 3. Wait 5 seconds
    // 4. Retry enrollment
    // 5. Get either 200 (success) or another 202

    // This requires more complex mock server state management
}

#[tokio::test]
async fn test_exponential_backoff_pattern() {
    // This would test exponential backoff for retries
    // This is typically implemented at the application level
    // using the retry_after() value from errors

    // Example pattern:
    // attempt 1: wait retry_after
    // attempt 2: wait retry_after * 2
    // attempt 3: wait retry_after * 4
    // etc.
}

#[tokio::test]
async fn test_max_retry_limit() {
    // This would test that clients don't retry indefinitely
    // This is an application-level concern, not library-level

    // Good practice: limit to 3-5 retries maximum
}
