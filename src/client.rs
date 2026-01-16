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

//! EST client implementation.
//!
//! This module provides the main `EstClient` struct for interacting with
//! EST servers according to RFC 7030.

use base64::prelude::*;
use reqwest::StatusCode;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};

use crate::config::EstClientConfig;
use crate::error::{EstError, Result};
use crate::operations::enroll::encode_csr;
use crate::tls::build_http_client;
use crate::types::{
    CaCertificates, CmcRequest, CmcResponse, CsrAttributes, EnrollmentResponse,
    ServerKeygenResponse, content_types, operations, parse_certs_only,
};

#[cfg(feature = "validation")]
use crate::validation::{CertificateValidator, ValidationConfig};

/// EST client for certificate enrollment operations.
///
/// The `EstClient` provides methods for all EST operations defined in RFC 7030:
/// - CA certificate retrieval
/// - Simple enrollment
/// - Simple re-enrollment
/// - CSR attributes query
/// - Server-side key generation
/// - Full CMC
///
/// # Example
///
/// ```no_run
/// use usg_est_client::{EstClient, EstClientConfig};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = EstClientConfig::builder()
///     .server_url("https://est.example.com")?
///     .build()?;
///
/// let client = EstClient::new(config).await?;
///
/// // Get CA certificates
/// let ca_certs = client.get_ca_certs().await?;
/// println!("Got {} CA certificates", ca_certs.len());
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct EstClient {
    config: EstClientConfig,
    http: reqwest::Client,
}

impl EstClient {
    /// Create a new EST client with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if TLS configuration fails.
    pub async fn new(config: EstClientConfig) -> Result<Self> {
        let http = build_http_client(&config)?;

        Ok(Self { config, http })
    }

    /// Get the client configuration.
    pub fn config(&self) -> &EstClientConfig {
        &self.config
    }

    // =========================================================================
    // Mandatory Operations (RFC 7030 §4.1-4.2)
    // =========================================================================

    /// Retrieve CA certificates from the EST server.
    ///
    /// This operation fetches the current CA certificates from the
    /// `/.well-known/est/cacerts` endpoint.
    ///
    /// # RFC Reference
    ///
    /// RFC 7030 Section 4.1: Distribution of CA Certificates
    pub async fn get_ca_certs(&self) -> Result<CaCertificates> {
        let url = self.config.build_url(operations::CACERTS);
        tracing::debug!("GET {}", url);

        let response = self.http.get(url).send().await?;

        let response = self.handle_error_response(response).await?;

        let body = response.bytes().await?;
        let certs = parse_certs_only(&body)?;

        Ok(CaCertificates::new(certs))
    }

    /// Enroll for a new certificate.
    ///
    /// This operation submits a Certificate Signing Request (CSR) to the
    /// `/.well-known/est/simpleenroll` endpoint.
    ///
    /// # Arguments
    ///
    /// * `csr_der` - DER-encoded PKCS#10 Certificate Signing Request
    ///
    /// # Returns
    ///
    /// Returns `EnrollmentResponse::Issued` with the certificate if enrollment
    /// succeeds immediately, or `EnrollmentResponse::Pending` if manual approval
    /// is required.
    ///
    /// # Channel Binding
    ///
    /// If channel binding is enabled in the client configuration, the CSR should
    /// include the channel binding value in its challengePassword attribute.
    /// Use [`crate::tls::generate_channel_binding_challenge`] to create a challenge
    /// and include it in the CSR during generation.
    ///
    /// # RFC Reference
    ///
    /// RFC 7030 Section 4.2: Client Certificate Request Functions
    /// RFC 7030 Section 3.5: Channel Binding
    pub async fn simple_enroll(&self, csr_der: &[u8]) -> Result<EnrollmentResponse> {
        self.enroll_request(operations::SIMPLE_ENROLL, csr_der)
            .await
    }

    /// Re-enroll (renew/rekey) an existing certificate.
    ///
    /// This operation submits a Certificate Signing Request (CSR) to the
    /// `/.well-known/est/simplereenroll` endpoint.
    ///
    /// The client MUST be authenticated using the existing client certificate.
    ///
    /// # Arguments
    ///
    /// * `csr_der` - DER-encoded PKCS#10 Certificate Signing Request
    ///
    /// # RFC Reference
    ///
    /// RFC 7030 Section 4.2.2: Simple Re-enrollment
    pub async fn simple_reenroll(&self, csr_der: &[u8]) -> Result<EnrollmentResponse> {
        self.enroll_request(operations::SIMPLE_REENROLL, csr_der)
            .await
    }

    // =========================================================================
    // Optional Operations (RFC 7030 §4.3-4.5)
    // =========================================================================

    /// Query the server for required CSR attributes.
    ///
    /// This optional operation fetches the attributes the server expects
    /// to see in CSRs from the `/.well-known/est/csrattrs` endpoint.
    ///
    /// # RFC Reference
    ///
    /// RFC 7030 Section 4.5: CSR Attributes
    pub async fn get_csr_attributes(&self) -> Result<CsrAttributes> {
        let url = self.config.build_url(operations::CSR_ATTRS);
        tracing::debug!("GET {}", url);

        let response = self.http.get(url).send().await?;

        // Handle 404/501 as "not supported"
        if response.status() == StatusCode::NOT_FOUND
            || response.status() == StatusCode::NOT_IMPLEMENTED
        {
            return Err(EstError::not_supported("csrattrs"));
        }

        let response = self.handle_error_response(response).await?;

        let body = response.bytes().await?;
        CsrAttributes::parse(&body)
    }

    /// Request server-side key generation.
    ///
    /// This optional operation requests the server to generate a key pair
    /// and issue a certificate via the `/.well-known/est/serverkeygen` endpoint.
    ///
    /// # Arguments
    ///
    /// * `csr_der` - DER-encoded PKCS#10 CSR (with subject information but
    ///   placeholder public key)
    ///
    /// # Returns
    ///
    /// Returns the server-generated private key and issued certificate.
    ///
    /// # RFC Reference
    ///
    /// RFC 7030 Section 4.4: Server-Side Key Generation
    pub async fn server_keygen(&self, csr_der: &[u8]) -> Result<ServerKeygenResponse> {
        let url = self.config.build_url(operations::SERVER_KEYGEN);
        tracing::debug!("POST {}", url);

        // Base64 encode the CSR with size validation
        let body = encode_csr(csr_der)?;

        let mut request = self
            .http
            .post(url)
            .header(CONTENT_TYPE, content_types::PKCS10)
            .body(body);

        request = self.add_auth_header(request);

        let response = request.send().await?;

        // Handle 404/501 as "not supported"
        if response.status() == StatusCode::NOT_FOUND
            || response.status() == StatusCode::NOT_IMPLEMENTED
        {
            return Err(EstError::not_supported("serverkeygen"));
        }

        let response = self.handle_error_response(response).await?;

        // Parse multipart response
        self.parse_serverkeygen_response(response).await
    }

    /// Submit a Full CMC request.
    ///
    /// This optional operation allows for complex PKI operations via
    /// the `/.well-known/est/fullcmc` endpoint.
    ///
    /// # RFC Reference
    ///
    /// RFC 7030 Section 4.3: Full CMC
    pub async fn full_cmc(&self, request: &CmcRequest) -> Result<CmcResponse> {
        let url = self.config.build_url(operations::FULL_CMC);
        tracing::debug!("POST {}", url);

        let body = request.encode_base64();

        let mut http_request = self
            .http
            .post(url)
            .header(CONTENT_TYPE, content_types::CMC_REQUEST)
            .body(body);

        http_request = self.add_auth_header(http_request);

        let response = http_request.send().await?;

        // Handle 404/501 as "not supported"
        if response.status() == StatusCode::NOT_FOUND
            || response.status() == StatusCode::NOT_IMPLEMENTED
        {
            return Err(EstError::not_supported("fullcmc"));
        }

        let response = self.handle_error_response(response).await?;

        let body = response.bytes().await?;
        CmcResponse::parse(&body)
    }

    // =========================================================================
    // Helper Methods
    // =========================================================================

    /// Common enrollment request logic.
    async fn enroll_request(&self, operation: &str, csr_der: &[u8]) -> Result<EnrollmentResponse> {
        let url = self.config.build_url(operation);
        tracing::debug!("POST {}", url);

        // Log channel binding status
        if self.config.channel_binding {
            tracing::debug!(
                "Channel binding enabled - CSR should include challengePassword with channel binding value"
            );
        }

        // Base64 encode the CSR with size validation
        let body = encode_csr(csr_der)?;

        let mut request = self
            .http
            .post(url)
            .header(CONTENT_TYPE, content_types::PKCS10)
            .body(body);

        // Add authentication if configured
        request = self.add_auth_header(request);

        let response = request.send().await?;

        // Handle HTTP 202 (Pending)
        if response.status() == StatusCode::ACCEPTED {
            let retry_after = self.extract_retry_after(&response);
            return Ok(EnrollmentResponse::pending(retry_after));
        }

        // Handle other errors
        let response = self.handle_error_response(response).await?;

        // Parse the certificate from the response
        let body = response.bytes().await?;
        let certs = parse_certs_only(&body)?;

        // Fixed: Replace unwrap() with proper error handling to prevent panic
        let cert = certs
            .into_iter()
            .next()
            .ok_or_else(|| EstError::cms_parsing("No certificate in enrollment response"))?;

        // Validate the certificate if validation is configured
        #[cfg(feature = "validation")]
        if let Some(ref validation_config) = self.config.validation_config {
            self.validate_issued_certificate(&cert, validation_config)?;
        }

        // Return the first certificate (the issued one)
        Ok(EnrollmentResponse::issued(cert))
    }

    /// Add HTTP Basic auth header if configured.
    fn add_auth_header(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(ref auth) = self.config.http_auth {
            let credentials =
                BASE64_STANDARD.encode(format!("{}:{}", auth.username, auth.password));
            let header_value = format!("Basic {}", credentials);
            request.header(AUTHORIZATION, header_value)
        } else {
            request
        }
    }

    /// Handle error responses from the server.
    async fn handle_error_response(
        &self,
        response: reqwest::Response,
    ) -> Result<reqwest::Response> {
        let status = response.status();

        if status.is_success() {
            return Ok(response);
        }

        // Handle 401 Unauthorized
        if status == StatusCode::UNAUTHORIZED {
            let challenge = response
                .headers()
                .get("www-authenticate")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("unknown")
                .to_string();
            return Err(EstError::authentication_required(challenge));
        }

        // Handle other errors
        // For security, limit error message length to prevent information disclosure
        let message = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());

        // Sanitize error message: truncate to 256 chars and strip sensitive patterns
        let sanitized_message = Self::sanitize_error_message(&message);

        Err(EstError::server_error(status.as_u16(), sanitized_message))
    }

    /// Sanitize error messages to prevent information disclosure.
    ///
    /// # Security
    ///
    /// Server error messages may contain sensitive information such as:
    /// - Internal paths and file names
    /// - Software versions and stack traces
    /// - Database connection strings
    /// - Implementation details
    ///
    /// This function truncates long messages and removes common sensitive substrings.
    fn sanitize_error_message(message: &str) -> String {
        const MAX_ERROR_LENGTH: usize = 256;

        // Truncate to prevent excessively long error messages
        let mut sanitized = if message.len() > MAX_ERROR_LENGTH {
            let truncated = message.chars().take(MAX_ERROR_LENGTH).collect::<String>();
            format!("{}... (truncated)", truncated)
        } else {
            message.to_string()
        };

        // Redact common sensitive keywords (simple substring matching)
        // This is a defense-in-depth measure; not all patterns can be caught
        let sensitive_keywords = [
            ("password=", "[credential redacted]"),
            ("Password=", "[credential redacted]"),
            ("token=", "[credential redacted]"),
            ("Token=", "[credential redacted]"),
            ("secret=", "[credential redacted]"),
            ("Secret=", "[credential redacted]"),
            ("key=", "[credential redacted]"),
            ("Key=", "[credential redacted]"),
        ];

        for (keyword, replacement) in sensitive_keywords {
            if let Some(pos) = sanitized.find(keyword) {
                // Redact from keyword to next whitespace or end of string
                let redact_start = pos;
                let redact_end = sanitized[pos..]
                    .find(|c: char| c.is_whitespace())
                    .map(|i| pos + i)
                    .unwrap_or(sanitized.len());

                sanitized.replace_range(redact_start..redact_end, replacement);
            }
        }

        sanitized
    }

    /// Extract Retry-After header value.
    fn extract_retry_after(&self, response: &reqwest::Response) -> u64 {
        response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(60) // Default to 60 seconds
    }

    /// Parse server keygen multipart response.
    async fn parse_serverkeygen_response(
        &self,
        response: reqwest::Response,
    ) -> Result<ServerKeygenResponse> {
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        // Check if it's multipart
        if !content_type.starts_with(content_types::MULTIPART_MIXED) {
            return Err(EstError::invalid_content_type(
                content_types::MULTIPART_MIXED,
                &content_type,
            ));
        }

        // Extract boundary
        let boundary = content_type
            .split("boundary=")
            .nth(1)
            .ok_or_else(|| EstError::invalid_multipart("Missing boundary parameter"))?
            .trim_matches('"')
            .to_string();

        let body = response.bytes().await?;
        self.parse_multipart(&body, &boundary)
    }

    /// Parse multipart response body.
    fn parse_multipart(&self, body: &[u8], boundary: &str) -> Result<ServerKeygenResponse> {
        let body_str = std::str::from_utf8(body)
            .map_err(|_| EstError::invalid_multipart("Invalid UTF-8 in multipart body"))?;

        let delimiter = format!("--{}", boundary);
        let parts: Vec<&str> = body_str
            .split(&delimiter)
            .filter(|p| !p.is_empty() && *p != "--" && *p != "--\r\n")
            .collect();

        if parts.len() < 2 {
            return Err(EstError::invalid_multipart(
                "Expected at least 2 parts (key and certificate)",
            ));
        }

        let mut private_key: Option<Vec<u8>> = None;
        let mut certificate: Option<x509_cert::Certificate> = None;
        let mut key_encrypted = false;

        for part in parts {
            // Skip the final boundary marker
            if part.starts_with("--") {
                continue;
            }

            // Split headers from body
            let header_body: Vec<&str> = part.splitn(2, "\r\n\r\n").collect();
            if header_body.len() < 2 {
                continue;
            }

            let headers = header_body[0];
            let part_body = header_body[1].trim();

            // Determine content type from headers
            let part_content_type = headers
                .lines()
                .find(|l| l.to_lowercase().starts_with("content-type:"))
                .map(|l| l.split(':').nth(1).unwrap_or("").trim())
                .unwrap_or("");

            if part_content_type.contains("pkcs8") || part_content_type.contains("octet-stream") {
                // Private key part
                let key_data: Vec<u8> = part_body
                    .chars()
                    .filter(|c| !c.is_whitespace())
                    .collect::<String>()
                    .into_bytes();

                private_key = Some(
                    BASE64_STANDARD
                        .decode(&key_data)
                        .map_err(EstError::Base64)?,
                );

                // Check if encrypted (CMS EnvelopedData)
                if part_content_type.contains("enveloped") {
                    key_encrypted = true;
                }
            } else if part_content_type.contains("pkcs7") {
                // Certificate part
                let certs = parse_certs_only(part_body.as_bytes())?;
                if let Some(cert) = certs.into_iter().next() {
                    certificate = Some(cert);
                }
            }
        }

        match (private_key, certificate) {
            (Some(key), Some(cert)) => Ok(ServerKeygenResponse::new(cert, key, key_encrypted)),
            (None, _) => Err(EstError::invalid_multipart(
                "Missing private key in response",
            )),
            (_, None) => Err(EstError::invalid_multipart(
                "Missing certificate in response",
            )),
        }
    }

    /// Validate an issued certificate against the configured trust anchors.
    ///
    /// This method performs RFC 5280 path validation including:
    /// - Chain building from the certificate to a trust anchor
    /// - Validity period checking
    /// - Name constraints validation
    /// - Policy constraints validation
    /// - Basic constraints checking for CA certificates
    #[cfg(feature = "validation")]
    fn validate_issued_certificate(
        &self,
        cert: &x509_cert::Certificate,
        config: &crate::config::CertificateValidationConfig,
    ) -> Result<()> {
        tracing::debug!("Validating issued certificate against trust anchors");

        // Create validation config
        let validation_config = ValidationConfig {
            max_chain_length: config.max_chain_length,
            check_revocation: false, // Revocation checking is separate
            enforce_name_constraints: config.enforce_name_constraints,
            enforce_policy_constraints: config.enforce_policy_constraints,
            allow_expired: config.allow_expired,
        };

        // Create validator with trust anchors
        let validator =
            CertificateValidator::with_config(config.trust_anchors.clone(), validation_config);

        // Validate the certificate (no intermediates - they should be in trust anchors)
        let result = validator.validate(cert, &[])?;

        if result.is_valid {
            tracing::debug!("Certificate validation successful");
            Ok(())
        } else {
            let error_msg = result.errors.join("; ");
            tracing::warn!("Certificate validation failed: {}", error_msg);
            Err(EstError::operational(format!(
                "Issued certificate validation failed: {}",
                error_msg
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::EstClientConfig;

    // NOTE: Test code uses unwrap() deliberately - test fixtures are known valid
    // and panics in tests provide clear failure messages. See ERROR-HANDLING-PATTERNS.md
    // Pattern 5 for justification.

    #[test]
    fn test_url_building() {
        let config = EstClientConfig::builder()
            .server_url("https://est.example.com")
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(
            config.build_url("cacerts").as_str(),
            "https://est.example.com/.well-known/est/cacerts"
        );

        let config_with_label = EstClientConfig::builder()
            .server_url("https://est.example.com")
            .unwrap()
            .ca_label("myca")
            .build()
            .unwrap();

        assert_eq!(
            config_with_label.build_url("simpleenroll").as_str(),
            "https://est.example.com/.well-known/est/myca/simpleenroll"
        );
    }
}
