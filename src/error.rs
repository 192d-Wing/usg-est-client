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

// ============================================================================
// SECURITY CONTROL: Error Handling and Information Disclosure Prevention
// ----------------------------------------------------------------------------
// NIST SP 800-53 Rev 5: SI-11 (Error Handling)
//                       AU-2 (Audit Events)
//                       AU-3 (Content of Audit Records)
// STIG: APSC-DV-002440 (CAT II) - Error Message Content
//       APSC-DV-002330 (CAT II) - Error Logging
//       APSC-DV-000650 (CAT II) - Information Disclosure
// ----------------------------------------------------------------------------
// Error handling is a critical security control that must balance two concerns:
//
// 1. **Detailed Internal Logging**: Errors must include sufficient detail for
//    debugging, forensic analysis, and security monitoring (AU-3)
// 2. **Sanitized External Messages**: User-facing error messages must not
//    disclose sensitive details that could aid attackers (SI-11)
//
// # Security Requirements
//
// **SI-11 (Error Handling):**
// - Error messages must not reveal sensitive system information
// - Stack traces and internal details must not be exposed to users
// - Error codes should be generic yet actionable
//
// **AU-2/AU-3 (Audit Generation):**
// - Errors must be logged with full context for security monitoring
// - Authentication failures must be audited
// - Authorization failures must be audited
// - Cryptographic failures must be audited
//
// **APSC-DV-000650 (Information Disclosure):**
// - Error messages must not reveal:
//   - Internal file paths or system architecture
//   - Database schema or query details
//   - Cryptographic key material or algorithm internals
//   - User enumeration information (e.g., "user exists" vs "invalid password")
//
// # Implementation Strategy
//
// This module uses Rust's type-safe error handling (Result<T, EstError>) to
// ensure all errors are handled explicitly. Error messages are designed to:
//
// - Provide sufficient detail for internal audit logs
// - Use generic descriptions for user-facing messages
// - Preserve error chains for debugging (via thiserror)
// - Support retry logic for transient failures
//
// # Error Categories
//
// - **Protocol Errors**: TLS, HTTP, EST-specific (log details, show generic message)
// - **Authentication Errors**: Credential failures (audit, show generic message)
// - **Cryptographic Errors**: FIPS, algorithm, key errors (audit, show generic message)
// - **Validation Errors**: Certificate, input validation (audit, show safe message)
// - **Operational Errors**: Config, I/O, platform (log details, show generic message)
//
// ============================================================================

//! Error types for the EST client.
//!
//! This module defines all error types that can occur during EST operations,
//! including TLS errors, HTTP errors, parsing errors, and EST-specific errors.
//!
//! # Security Controls
//!
//! **NIST SP 800-53 Rev 5:**
//! - SI-11: Error Handling (secure error messages)
//! - AU-2: Audit Events (error logging)
//! - AU-3: Content of Audit Records (detailed error context)
//!
//! **STIG Findings:**
//! - APSC-DV-002440 (CAT II): Error Message Content
//! - APSC-DV-002330 (CAT II): Error Logging
//! - APSC-DV-000650 (CAT II): Information Disclosure Prevention

use thiserror::Error;

/// Result type alias using [`EstError`].
///
/// # Security Controls
///
/// **NIST SP 800-53 Rev 5:** SI-11 (Error Handling)
///
/// This type alias ensures consistent error handling across the EST client.
/// All fallible operations return Result<T, EstError> to enforce explicit
/// error handling at compile time.
pub type Result<T> = std::result::Result<T, EstError>;

// ============================================================================
// SECURITY CONTROL: Structured Error Types
// ----------------------------------------------------------------------------
// NIST SP 800-53 Rev 5: SI-11 (Error Handling)
//                       AU-2 (Audit Events)
// STIG: APSC-DV-002440 (CAT II) - Error Message Content
//       APSC-DV-000650 (CAT II) - Information Disclosure
// ----------------------------------------------------------------------------
// The EstError enum provides structured error types that balance security
// requirements:
//
// 1. **Type Safety**: Each error category has a dedicated variant
// 2. **Audit Support**: Error messages include sufficient context for logging
// 3. **Information Disclosure Prevention**: Messages avoid revealing sensitive
//    system internals, cryptographic details, or implementation-specific information
//
// # Error Message Design
//
// Error messages follow these security principles:
//
// - **Generic External Messages**: "TLS error", "Authentication required" (not
//   "Connection to 10.0.0.1:443 failed with OpenSSL error 0x1234")
// - **Detailed Internal Context**: Error contains specific details for audit logs
// - **No User Enumeration**: Don't distinguish between "user not found" and
//   "invalid password"
// - **No Path Disclosure**: Don't reveal internal file paths or directory structure
// - **No Algorithm Internals**: Don't expose cryptographic implementation details
//
// ============================================================================

/// Errors that can occur during EST client operations.
///
/// # Security Controls
///
/// **NIST SP 800-53 Rev 5:**
/// - SI-11: Error Handling (structured, safe error messages)
/// - AU-2: Audit Events (error classification for logging)
/// - AU-3: Content of Audit Records (detailed error context)
///
/// **STIG Findings:**
/// - APSC-DV-002440 (CAT II): Error Message Content
/// - APSC-DV-002330 (CAT II): Error Logging
/// - APSC-DV-000650 (CAT II): Information Disclosure Prevention
///
/// # Security Implementation
///
/// This enum uses the `thiserror` crate to generate Display implementations
/// that provide consistent error messages. Error messages are designed to:
///
/// - Be sufficiently detailed for internal audit logs
/// - Avoid exposing sensitive system information to users
/// - Support error correlation and debugging
/// - Enable proper retry logic for transient failures
///
/// # Usage in Security Contexts
///
/// When displaying errors to users (CLI, UI), consider using generic messages:
/// ```no_run,ignore
/// match result {
///     Err(EstError::AuthenticationRequired { .. }) => {
///         println!("Authentication failed. Please check credentials.");
///         // Log detailed error internally for audit
///     }
///     Err(EstError::CertificateValidation(msg)) => {
///         println!("Certificate validation failed.");
///         // Log msg internally for security monitoring
///     }
///     _ => println!("Operation failed. See logs for details."),
/// }
/// ```
#[derive(Debug, Error)]
pub enum EstError {
    /// TLS configuration or connection error.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:** SC-8 (Transmission Confidentiality)
    ///
    /// **STIG Finding:** APSC-DV-002330 (CAT II) - Error Logging
    ///
    /// TLS errors indicate failures in establishing secure communications.
    /// These must be logged as security events (AU-2) as they may indicate:
    /// - Certificate validation failures
    /// - Cipher suite mismatches
    /// - Protocol version incompatibilities
    /// - Man-in-the-middle attacks
    #[error("TLS error: {0}")]
    Tls(String),

    /// HTTP request or response error.
    ///
    /// # Security Note
    ///
    /// HTTP errors may contain sensitive details from reqwest. When displaying
    /// to users, use generic messages. Log full details internally for debugging.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// Response Content-Type header does not match expected value.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:** SI-10 (Information Input Validation)
    ///
    /// Content-Type validation prevents MIME confusion attacks where an attacker
    /// tricks the client into processing malicious content as a different type.
    #[error("Invalid content-type: expected '{expected}', got '{actual}'")]
    InvalidContentType {
        /// Expected content-type.
        expected: String,
        /// Actual content-type received.
        actual: String,
    },

    /// Failed to parse X.509 certificate.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:** SC-12 (Cryptographic Key Establishment)
    ///
    /// **STIG Finding:** APSC-DV-002330 (CAT II) - Error Logging
    ///
    /// Certificate parsing errors must be audited as they may indicate:
    /// - Malformed certificates (potential attack)
    /// - Invalid DER/PEM encoding
    /// - Unsupported certificate features
    #[error("Certificate parsing error: {0}")]
    CertificateParsing(String),

    /// Failed to parse CMS/PKCS#7 structure.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:** SC-13 (Cryptographic Protection)
    ///
    /// CMS parsing errors may indicate protocol attacks or malformed responses
    /// from the EST server. These should be logged and investigated.
    #[error("CMS/PKCS#7 parsing error: {0}")]
    CmsParsing(String),

    /// Failed to generate or parse CSR.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:** SC-12 (Cryptographic Key Establishment)
    ///
    /// CSR errors indicate failures in the certificate enrollment process,
    /// which must be audited for compliance and troubleshooting.
    #[error("CSR error: {0}")]
    Csr(String),

    /// EST server returned an error response.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:** AU-2 (Audit Events)
    ///
    /// **STIG Finding:** APSC-DV-002330 (CAT II) - Error Logging
    ///
    /// Server errors must be logged for security monitoring. Status codes
    /// indicate different failure modes:
    /// - 400: Malformed request (potential attack)
    /// - 401: Authentication failure (audit required)
    /// - 403: Authorization failure (audit required)
    /// - 500: Server-side error (operational issue)
    #[error("Server error {status}: {message}")]
    ServerError {
        /// HTTP status code.
        status: u16,
        /// Error message from server.
        message: String,
    },

    /// Enrollment request is pending manual approval (HTTP 202).
    ///
    /// The client should wait for `retry_after` seconds before retrying.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:** AU-2 (Audit Events)
    ///
    /// Pending enrollments should be logged to track the approval workflow
    /// and detect potential delays or approval issues.
    #[error("Enrollment pending, retry after {retry_after} seconds")]
    EnrollmentPending {
        /// Number of seconds to wait before retrying.
        retry_after: u64,
    },

    /// Server requires authentication (HTTP 401).
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - IA-2: Identification and Authentication
    /// - AU-2: Audit Events (authentication failures)
    ///
    /// **STIG Finding:** APSC-DV-002330 (CAT II) - Error Logging
    ///
    /// Authentication failures MUST be audited for security monitoring and
    /// incident detection. The WWW-Authenticate challenge helps the client
    /// determine the required authentication method (Basic, Digest, etc.).
    ///
    /// # Information Disclosure Note
    ///
    /// When displaying to users, use a generic message like "Authentication
    /// required" without revealing the specific challenge details, which
    /// could aid reconnaissance.
    #[error("Authentication required: {challenge}")]
    AuthenticationRequired {
        /// WWW-Authenticate challenge from server.
        challenge: String,
    },

    /// Base64 decoding error.
    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    /// DER encoding/decoding error.
    #[error("DER error: {0}")]
    Der(#[from] der::Error),

    /// URL parsing error.
    #[error("URL error: {0}")]
    Url(#[from] url::ParseError),

    /// Bootstrap fingerprint verification failed.
    #[error("Bootstrap verification failed: {0}")]
    BootstrapVerification(String),

    /// Required HTTP header is missing from response.
    #[error("Missing required header: {0}")]
    MissingHeader(String),

    /// Invalid multipart response format.
    #[error("Invalid multipart response: {0}")]
    InvalidMultipart(String),

    /// Invalid PEM data.
    #[error("Invalid PEM data: {0}")]
    InvalidPem(String),

    /// Operation not supported by server.
    #[error("Operation not supported: {0}")]
    NotSupported(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Platform-specific error (Windows, macOS, etc.).
    #[error("Platform error: {0}")]
    Platform(String),

    /// FIPS 140-2 module not available or not compiled in.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:** SC-13 (Cryptographic Protection)
    ///
    /// **STIG Finding:** APSC-DV-002330 (CAT II) - Error Logging
    ///
    /// FIPS mode is required for federal systems. This error indicates the
    /// cryptographic module is not available, which prevents the system from
    /// operating in a compliant manner. This MUST be treated as a critical
    /// error in production environments.
    #[error("FIPS 140-2 not available: {0}")]
    FipsNotAvailable(String),

    /// FIPS 140-2 mode not enabled when required.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:** SC-13 (Cryptographic Protection)
    ///
    /// **STIG Finding:** APSC-DV-002330 (CAT II) - Error Logging
    ///
    /// This error indicates FIPS mode is available but not enabled. For
    /// federal systems requiring FIPS compliance, this is a configuration
    /// error that must be corrected before operations can proceed.
    #[error("FIPS 140-2 mode not enabled: {0}")]
    FipsNotEnabled(String),

    /// FIPS 140-2 configuration invalid.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:** SC-13 (Cryptographic Protection)
    ///
    /// Invalid FIPS configuration indicates a misconfigured system that
    /// cannot meet cryptographic requirements. This must be audited and
    /// corrected before operations proceed.
    #[error("FIPS 140-2 configuration invalid: {0}")]
    FipsInvalidConfig(String),

    /// Algorithm not allowed in FIPS mode.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:** SC-13 (Cryptographic Protection)
    ///
    /// **STIG Finding:** APSC-DV-002330 (CAT II) - Error Logging
    ///
    /// This error indicates an attempt to use a non-FIPS-approved algorithm
    /// when FIPS mode is enabled. This is a critical security policy violation
    /// that must be logged and blocked. Examples:
    /// - MD5 hash algorithm
    /// - RC4 cipher
    /// - RSA keys < 2048 bits
    /// - Non-approved elliptic curves
    #[error("Algorithm not allowed in FIPS mode: {0}")]
    FipsAlgorithmNotAllowed(String),

    /// Certificate validation failed.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - SC-12: Cryptographic Key Establishment
    /// - IA-5: Authenticator Management
    ///
    /// **STIG Finding:** APSC-DV-002330 (CAT II) - Error Logging
    ///
    /// Certificate validation failures are critical security events that MUST
    /// be audited. They may indicate:
    /// - Expired or revoked certificates
    /// - Invalid certificate chains
    /// - Hostname mismatches
    /// - Untrusted certificate authorities
    /// - Certificate policy violations
    ///
    /// All validation failures should be logged with full details for security
    /// monitoring and incident response.
    #[error("Certificate validation failed: {0}")]
    CertificateValidation(String),

    /// PKCS#11 / smart card error.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:** SC-12 (Cryptographic Key Establishment)
    ///
    /// PKCS#11 errors indicate failures communicating with hardware security
    /// tokens (smart cards, HSMs, TPMs). These should be logged for operational
    /// monitoring and may indicate:
    /// - Token not inserted
    /// - PIN/password required
    /// - Token communication failure
    /// - Unsupported token operation
    #[error("PKCS#11 error: {0}")]
    Pkcs11(String),
}

impl EstError {
    /// Create a TLS error with the given message.
    pub fn tls(msg: impl Into<String>) -> Self {
        Self::Tls(msg.into())
    }

    /// Create a certificate parsing error with the given message.
    pub fn certificate_parsing(msg: impl Into<String>) -> Self {
        Self::CertificateParsing(msg.into())
    }

    /// Create a CMS parsing error with the given message.
    pub fn cms_parsing(msg: impl Into<String>) -> Self {
        Self::CmsParsing(msg.into())
    }

    /// Create a CSR error with the given message.
    pub fn csr(msg: impl Into<String>) -> Self {
        Self::Csr(msg.into())
    }

    /// Create an HSM error with the given message (reuses CSR error type).
    #[cfg(feature = "hsm")]
    pub fn hsm(msg: impl Into<String>) -> Self {
        Self::Csr(msg.into())
    }

    /// Create a server error with status and message.
    pub fn server_error(status: u16, message: impl Into<String>) -> Self {
        Self::ServerError {
            status,
            message: message.into(),
        }
    }

    /// Create an enrollment pending error.
    pub fn enrollment_pending(retry_after: u64) -> Self {
        Self::EnrollmentPending { retry_after }
    }

    /// Create an authentication required error.
    pub fn authentication_required(challenge: impl Into<String>) -> Self {
        Self::AuthenticationRequired {
            challenge: challenge.into(),
        }
    }

    /// Create an operational error with the given message.
    pub fn operational(msg: impl Into<String>) -> Self {
        Self::NotSupported(msg.into())
    }

    /// Create an invalid content-type error.
    pub fn invalid_content_type(expected: impl Into<String>, actual: impl Into<String>) -> Self {
        Self::InvalidContentType {
            expected: expected.into(),
            actual: actual.into(),
        }
    }

    /// Create a bootstrap verification error.
    pub fn bootstrap_verification(msg: impl Into<String>) -> Self {
        Self::BootstrapVerification(msg.into())
    }

    /// Create a missing header error.
    pub fn missing_header(header: impl Into<String>) -> Self {
        Self::MissingHeader(header.into())
    }

    /// Create an invalid multipart error.
    pub fn invalid_multipart(msg: impl Into<String>) -> Self {
        Self::InvalidMultipart(msg.into())
    }

    /// Create an invalid PEM error.
    pub fn invalid_pem(msg: impl Into<String>) -> Self {
        Self::InvalidPem(msg.into())
    }

    /// Create a not supported error.
    pub fn not_supported(operation: impl Into<String>) -> Self {
        Self::NotSupported(operation.into())
    }

    /// Create a protocol error (uses CertificateParsing for generic protocol errors).
    pub fn protocol(msg: impl Into<String>) -> Self {
        Self::CertificateParsing(msg.into())
    }

    /// Create a configuration error with the given message.
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    /// Create a platform-specific error with the given message.
    pub fn platform(msg: impl Into<String>) -> Self {
        Self::Platform(msg.into())
    }

    /// Returns true if this is a retryable error.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:** SC-5 (Denial of Service Protection)
    ///
    /// # Security Implementation
    ///
    /// This method identifies transient errors that can be safely retried
    /// without risk of account lockout or service disruption:
    ///
    /// - **EnrollmentPending**: Server explicitly requests retry with Retry-After
    /// - **Http**: Network errors (connection timeout, DNS failure)
    /// - **Tls**: Transient TLS handshake failures
    ///
    /// Non-retryable errors (e.g., authentication failures, validation errors)
    /// return false to prevent:
    /// - Account lockout from repeated authentication attempts
    /// - Server load from retrying failed operations
    /// - Denial of service through excessive retries
    ///
    /// Callers should implement exponential backoff for retryable errors to
    /// further mitigate DoS risk.
    ///
    /// # Example: Retry with Backoff
    ///
    /// ```no_run,ignore
    /// let mut attempts = 0;
    /// let max_attempts = 3;
    ///
    /// loop {
    ///     match perform_operation() {
    ///         Ok(result) => return Ok(result),
    ///         Err(e) if e.is_retryable() && attempts < max_attempts => {
    ///             attempts += 1;
    ///             let backoff = 2u64.pow(attempts) * 1000; // Exponential backoff
    ///             std::thread::sleep(Duration::from_millis(backoff));
    ///             continue;
    ///         }
    ///         Err(e) => return Err(e), // Don't retry
    ///     }
    /// }
    /// ```
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::EnrollmentPending { .. } | Self::Http(_) | Self::Tls(_)
        )
    }

    /// Returns the retry-after value if this is an EnrollmentPending error.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:** SC-5 (Denial of Service Protection)
    ///
    /// # Security Implementation
    ///
    /// The Retry-After value is provided by the EST server (HTTP 202 response)
    /// to indicate when the client should retry the enrollment request. Clients
    /// MUST honor this value to prevent overloading the server with repeated
    /// requests.
    ///
    /// Ignoring the Retry-After value could result in:
    /// - Server resource exhaustion
    /// - Client IP blocking
    /// - Denial of service for other clients
    ///
    /// # Example
    ///
    /// ```no_run,ignore
    /// match enroll_certificate() {
    ///     Err(e) if let Some(retry_after) = e.retry_after() => {
    ///         println!("Enrollment pending, waiting {} seconds", retry_after);
    ///         std::thread::sleep(Duration::from_secs(retry_after));
    ///         // Retry enrollment
    ///     }
    ///     Err(e) => return Err(e),
    ///     Ok(cert) => return Ok(cert),
    /// }
    /// ```
    pub fn retry_after(&self) -> Option<u64> {
        match self {
            Self::EnrollmentPending { retry_after } => Some(*retry_after),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = EstError::server_error(400, "Bad Request");
        assert_eq!(err.to_string(), "Server error 400: Bad Request");

        let err = EstError::enrollment_pending(30);
        assert_eq!(
            err.to_string(),
            "Enrollment pending, retry after 30 seconds"
        );
    }

    #[test]
    fn test_is_retryable() {
        assert!(EstError::enrollment_pending(30).is_retryable());
        assert!(!EstError::server_error(400, "Bad").is_retryable());
    }

    #[test]
    fn test_retry_after() {
        assert_eq!(EstError::enrollment_pending(60).retry_after(), Some(60));
        assert_eq!(EstError::server_error(400, "Bad").retry_after(), None);
    }
}
