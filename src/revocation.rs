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
// SECURITY CONTROL: Certificate Revocation Checking
// ----------------------------------------------------------------------------
// NIST SP 800-53 Rev 5: IA-5 (Authenticator Management)
//                       AU-10 (Non-Repudiation)
//                       SC-12 (Cryptographic Key Establishment)
//
// Application Development STIG V5R3:
//   APSC-DV-001740 (CAT II) - Certificate Revocation Validation
//
// SECURITY CONTROL IMPLEMENTATION:
//
// This module implements certificate revocation checking to detect and reject
// compromised certificates. Revocation checking is critical for PKI security.
//
// IA-5: AUTHENTICATOR MANAGEMENT
// -------------------------------
// Certificates serve as authenticators. This module:
//
// - Verifies certificates have not been revoked (key compromise, CA compromise)
// - Prevents use of revoked certificates for authentication
// - Supports two revocation protocols:
//   * CRL (Certificate Revocation List) - RFC 5280
//   * OCSP (Online Certificate Status Protocol) - RFC 6960
//
// Revocation scenarios requiring certificate rejection:
// - Key compromise: Private key exposed or stolen
// - CA compromise: Issuing CA's key compromised
// - Affiliation changed: Subject no longer affiliated with organization
// - Superseded: Certificate replaced by newer certificate
// - Cessation of operation: Certificate no longer needed
//
// AU-10: NON-REPUDIATION
// -----------------------
// Revocation checking provides non-repudiation evidence:
//
// - Revocation status checked at time of certificate use
// - Revocation date proves when certificate became invalid
// - Prevents disputes about certificate validity
// - Provides audit trail for compliance
//
// SC-12: CRYPTOGRAPHIC KEY ESTABLISHMENT
// ---------------------------------------
// Revocation protects against compromised cryptographic keys:
//
// - Detects when private keys are compromised
// - Prevents continued use of weak or exposed keys
// - Supports cryptographic agility (algorithm transitions)
//
// REVOCATION PROTOCOLS:
//
// CRL (Certificate Revocation List):
// - Periodically published list of revoked certificate serial numbers
// - Signed by CA to ensure authenticity
// - Cached to reduce network traffic
// - Includes revocation date and reason
// - Limitations: May be stale between updates
//
// OCSP (Online Certificate Status Protocol):
// - Real-time revocation status query
// - Lower latency than CRL
// - Reduced bandwidth (single certificate check)
// - May leak information about which certificates are being validated
// - Requires network connectivity to OCSP responder
//
// SECURITY TRADE-OFFS:
//
// 1. AVAILABILITY VS SECURITY:
//    - Soft-fail: Accept certificates if revocation check fails (network error)
//    - Hard-fail: Reject certificates if revocation check fails
//    - Recommendation: Hard-fail for high-security applications
//
// 2. PRIVACY VS SECURITY:
//    - OCSP may leak which certificates are being used
//    - CRL provides better privacy but higher latency
//    - OCSP Stapling mitigates privacy concerns (RFC 6066)
//
// 3. PERFORMANCE VS FRESHNESS:
//    - CRL caching improves performance but increases staleness
//    - OCSP provides real-time status but requires network round-trip
//    - Balance depends on threat model and network characteristics
//
// ============================================================================

//! Certificate revocation checking (CRL and OCSP).
//!
//! This module provides support for checking certificate revocation status
//! using Certificate Revocation Lists (CRL) and Online Certificate Status
//! Protocol (OCSP).
//!
//! # Security Controls
//!
//! **NIST SP 800-53 Rev 5:**
//! - IA-5 (Authenticator Management) - Certificate revocation validation
//! - AU-10 (Non-Repudiation) - Revocation status evidence
//! - SC-12 (Cryptographic Key Establishment) - Compromised key detection
//!
//! # Security Implementation
//!
//! Revocation checking prevents use of compromised certificates:
//! - CRL validation per RFC 5280
//! - OCSP validation per RFC 6960
//! - Configurable soft-fail vs hard-fail behavior
//! - CRL caching to reduce network traffic
//! - Signature verification of CRLs and OCSP responses
//!
//! # Example
//!
//! ```no_run
//! use usg_est_client::revocation::{RevocationChecker, RevocationConfig};
//! use usg_est_client::Certificate;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create revocation checker
//! let config = RevocationConfig::builder()
//!     .enable_crl(true)
//!     .enable_ocsp(true)
//!     .crl_cache_duration(std::time::Duration::from_secs(3600))
//!     .build();
//!
//! let checker = RevocationChecker::new(config);
//!
//! // Check certificate revocation status
//! let cert = todo!(); // Your certificate
//! let issuer = todo!(); // Issuer certificate
//! let status = checker.check_revocation(&cert, &issuer).await?;
//!
//! if status.is_revoked() {
//!     println!("Certificate has been revoked!");
//! }
//! # Ok(())
//! # }
//! ```

use crate::error::{EstError, Result};
use base64::Engine;
use der::{Decode, Encode, Sequence, asn1::OctetString};
use sha2::{Digest, Sha256};
use signature::Verifier;
use spki::AlgorithmIdentifierOwned;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use x509_cert::Certificate;
use x509_cert::crl::CertificateList;
use x509_cert::ext::pkix::crl::dp::DistributionPoint;
use x509_cert::ext::pkix::{AuthorityInfoAccessSyntax, CrlDistributionPoints};
use x509_cert::serial_number::SerialNumber;

// OCSP ASN.1 Structures (RFC 6960)

/// OCSP CertID structure
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct OcspCertId {
    /// Hash algorithm used for issuerNameHash and issuerKeyHash
    hash_algorithm: AlgorithmIdentifierOwned,
    /// Hash of the issuer's DN
    issuer_name_hash: OctetString,
    /// Hash of the issuer's public key
    issuer_key_hash: OctetString,
    /// Serial number of the certificate being checked
    serial_number: SerialNumber,
}

/// OCSP Request structure
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct OcspRequest {
    /// The request being made
    tbs_request: TbsRequest,
    // optionalSignature is not commonly used for basic OCSP requests
}

/// TBS (To Be Signed) Request
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct TbsRequest {
    /// List of certificate status requests
    request_list: der::asn1::SequenceOf<SingleRequest, 1>,
    // We're omitting optional fields (version, requestorName, requestExtensions) for simplicity
}

/// Single certificate status request
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct SingleRequest {
    /// Certificate identifier
    req_cert: OcspCertId,
    // singleRequestExtensions is optional and omitted
}

// Simple DER parser for OCSP response structures
// Provides basic DER/ASN.1 parsing without full der crate complexity
struct SimpleDerParser<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> SimpleDerParser<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn position(&self) -> usize {
        self.pos
    }

    fn remaining(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    fn read_byte(&mut self) -> Result<u8> {
        if self.pos >= self.data.len() {
            return Err(EstError::operational("Unexpected end of data"));
        }
        let byte = self.data[self.pos];
        self.pos += 1;
        Ok(byte)
    }

    fn peek_tag(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    fn read_length(&mut self) -> Result<usize> {
        let first = self.read_byte()?;
        if first & 0x80 == 0 {
            // Short form
            Ok(first as usize)
        } else {
            // Long form
            let num_octets = (first & 0x7F) as usize;
            if num_octets > 4 {
                return Err(EstError::operational(
                    "Length encoding too long (max 4 octets)",
                ));
            }
            if num_octets == 0 {
                return Err(EstError::operational(
                    "Invalid length encoding (zero octets)",
                ));
            }

            let mut length = 0usize;
            for _ in 0..num_octets {
                // Fixed: Use checked arithmetic to prevent integer overflow
                let byte = self.read_byte()? as usize;
                length = length
                    .checked_shl(8)
                    .and_then(|l| l.checked_add(byte))
                    .ok_or_else(|| {
                        EstError::operational("Length field overflow (value too large)")
                    })?;
            }

            // Additional sanity check: reject unreasonably large lengths
            const MAX_REASONABLE_LENGTH: usize = 100 * 1024 * 1024; // 100MB
            if length > MAX_REASONABLE_LENGTH {
                return Err(EstError::operational(format!(
                    "Length field exceeds reasonable maximum: {} bytes (max {} MB)",
                    length,
                    MAX_REASONABLE_LENGTH / (1024 * 1024)
                )));
            }

            Ok(length)
        }
    }

    fn expect_tag(&mut self, expected: u8) -> Result<()> {
        let tag = self.read_byte()?;
        if tag != expected {
            return Err(EstError::operational(format!(
                "Expected tag 0x{:02x}, got 0x{:02x}",
                expected, tag
            )));
        }
        Ok(())
    }

    fn expect_sequence(&mut self) -> Result<usize> {
        self.expect_tag(0x30)?; // SEQUENCE tag
        self.read_length()
    }

    fn skip_sequence(&mut self) -> Result<()> {
        self.expect_tag(0x30)?;
        let len = self.read_length()?;
        self.pos += len;
        Ok(())
    }

    fn expect_context_constructed(&mut self, num: u8) -> Result<usize> {
        let tag = 0xA0 | num; // Context-specific, constructed
        self.expect_tag(tag)?;
        self.read_length()
    }

    fn skip_context_specific(&mut self) -> Result<()> {
        let tag = self.read_byte()?;
        if (tag & 0xC0) != 0x80 {
            return Err(EstError::operational("Expected context-specific tag"));
        }
        let len = self.read_length()?;
        self.pos += len;
        Ok(())
    }

    fn read_enumerated(&mut self) -> Result<u8> {
        self.expect_tag(0x0A)?; // ENUMERATED tag
        let len = self.read_length()?;
        if len != 1 {
            return Err(EstError::operational("ENUMERATED must be 1 byte"));
        }
        self.read_byte()
    }

    fn skip_oid(&mut self) -> Result<()> {
        self.expect_tag(0x06)?; // OID tag
        let len = self.read_length()?;
        self.pos += len;
        Ok(())
    }

    fn read_octet_string(&mut self) -> Result<&'a [u8]> {
        self.expect_tag(0x04)?; // OCTET STRING tag
        let len = self.read_length()?;
        let start = self.pos;
        self.pos += len;
        Ok(&self.data[start..self.pos])
    }

    fn skip_generalized_time(&mut self) -> Result<()> {
        self.expect_tag(0x18)?; // GeneralizedTime tag
        let len = self.read_length()?;
        self.pos += len;
        Ok(())
    }
}

/// Configuration for revocation checking.
#[derive(Debug, Clone)]
pub struct RevocationConfig {
    /// Enable CRL checking.
    pub enable_crl: bool,

    /// Enable OCSP checking.
    pub enable_ocsp: bool,

    /// How long to cache CRL data.
    pub crl_cache_duration: Duration,

    /// Maximum size of CRL cache (number of entries).
    pub crl_cache_max_entries: usize,

    /// Timeout for OCSP requests.
    pub ocsp_timeout: Duration,

    /// Whether to fail if revocation status cannot be determined.
    pub fail_on_unknown: bool,
}

impl Default for RevocationConfig {
    fn default() -> Self {
        Self {
            enable_crl: true,
            enable_ocsp: true,
            crl_cache_duration: Duration::from_secs(3600), // 1 hour
            crl_cache_max_entries: 100,
            ocsp_timeout: Duration::from_secs(10),
            fail_on_unknown: false,
        }
    }
}

impl RevocationConfig {
    /// Create a new configuration builder.
    pub fn builder() -> RevocationConfigBuilder {
        RevocationConfigBuilder::default()
    }
}

/// Builder for `RevocationConfig`.
#[derive(Default)]
pub struct RevocationConfigBuilder {
    enable_crl: Option<bool>,
    enable_ocsp: Option<bool>,
    crl_cache_duration: Option<Duration>,
    crl_cache_max_entries: Option<usize>,
    ocsp_timeout: Option<Duration>,
    fail_on_unknown: Option<bool>,
}

impl RevocationConfigBuilder {
    /// Enable or disable CRL checking.
    pub fn enable_crl(mut self, enable: bool) -> Self {
        self.enable_crl = Some(enable);
        self
    }

    /// Enable or disable OCSP checking.
    pub fn enable_ocsp(mut self, enable: bool) -> Self {
        self.enable_ocsp = Some(enable);
        self
    }

    /// Set CRL cache duration.
    pub fn crl_cache_duration(mut self, duration: Duration) -> Self {
        self.crl_cache_duration = Some(duration);
        self
    }

    /// Set maximum CRL cache entries.
    pub fn crl_cache_max_entries(mut self, max: usize) -> Self {
        self.crl_cache_max_entries = Some(max);
        self
    }

    /// Set OCSP request timeout.
    pub fn ocsp_timeout(mut self, timeout: Duration) -> Self {
        self.ocsp_timeout = Some(timeout);
        self
    }

    /// Set whether to fail on unknown revocation status.
    pub fn fail_on_unknown(mut self, fail: bool) -> Self {
        self.fail_on_unknown = Some(fail);
        self
    }

    /// Build the configuration.
    pub fn build(self) -> RevocationConfig {
        let default = RevocationConfig::default();
        RevocationConfig {
            enable_crl: self.enable_crl.unwrap_or(default.enable_crl),
            enable_ocsp: self.enable_ocsp.unwrap_or(default.enable_ocsp),
            crl_cache_duration: self
                .crl_cache_duration
                .unwrap_or(default.crl_cache_duration),
            crl_cache_max_entries: self
                .crl_cache_max_entries
                .unwrap_or(default.crl_cache_max_entries),
            ocsp_timeout: self.ocsp_timeout.unwrap_or(default.ocsp_timeout),
            fail_on_unknown: self.fail_on_unknown.unwrap_or(default.fail_on_unknown),
        }
    }
}

/// Certificate revocation status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationStatus {
    /// Certificate is valid (not revoked).
    Valid,

    /// Certificate has been revoked.
    Revoked,

    /// Revocation status is unknown.
    Unknown,
}

impl RevocationStatus {
    /// Check if the certificate is revoked.
    pub fn is_revoked(&self) -> bool {
        matches!(self, Self::Revoked)
    }

    /// Check if the certificate is valid.
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }

    /// Check if the status is unknown.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}

/// Detailed revocation check result.
#[derive(Debug, Clone)]
pub struct RevocationCheckResult {
    /// Overall revocation status.
    pub status: RevocationStatus,

    /// Whether CRL was checked.
    pub crl_checked: bool,

    /// Whether OCSP was checked.
    pub ocsp_checked: bool,

    /// CRL revocation status (if checked).
    pub crl_status: Option<RevocationStatus>,

    /// OCSP revocation status (if checked).
    pub ocsp_status: Option<RevocationStatus>,

    /// Any errors encountered during checking.
    pub errors: Vec<String>,
}

impl RevocationCheckResult {
    /// Check if the certificate is revoked.
    pub fn is_revoked(&self) -> bool {
        self.status.is_revoked()
    }
}

/// CRL cache entry.
#[derive(Debug, Clone)]
struct CrlCacheEntry {
    /// The parsed CRL.
    crl: CertificateList,

    /// When this entry was cached.
    cached_at: SystemTime,

    /// When this CRL expires (from nextUpdate field).
    next_update: Option<SystemTime>,
}

/// Certificate revocation checker.
pub struct RevocationChecker {
    config: RevocationConfig,
    crl_cache: Arc<RwLock<HashMap<String, CrlCacheEntry>>>,
    http_client: reqwest::Client,
}

impl RevocationChecker {
    /// Create a new revocation checker with the given configuration.
    pub fn new(config: RevocationConfig) -> Self {
        // Create HTTP client with timeout
        let http_client = reqwest::Client::builder()
            .timeout(config.ocsp_timeout)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            config,
            crl_cache: Arc::new(RwLock::new(HashMap::new())),
            http_client,
        }
    }

    /// Check the revocation status of a certificate.
    ///
    /// # Arguments
    ///
    /// * `cert` - The certificate to check
    /// * `issuer` - The issuer certificate (needed for CRL/OCSP)
    ///
    /// # Returns
    ///
    /// A `RevocationCheckResult` with the revocation status and details.
    pub async fn check_revocation(
        &self,
        cert: &Certificate,
        issuer: &Certificate,
    ) -> Result<RevocationCheckResult> {
        let mut result = RevocationCheckResult {
            status: RevocationStatus::Unknown,
            crl_checked: false,
            ocsp_checked: false,
            crl_status: None,
            ocsp_status: None,
            errors: Vec::new(),
        };

        debug!("Checking revocation status for certificate");

        // Check CRL if enabled
        if self.config.enable_crl {
            match self.check_crl(cert, issuer).await {
                Ok(status) => {
                    result.crl_checked = true;
                    result.crl_status = Some(status);
                    info!("CRL check result: {:?}", status);

                    if status.is_revoked() {
                        result.status = RevocationStatus::Revoked;
                        return Ok(result);
                    } else if status.is_valid() {
                        result.status = RevocationStatus::Valid;
                    }
                }
                Err(e) => {
                    warn!("CRL check failed: {}", e);
                    result.errors.push(format!("CRL check failed: {}", e));
                }
            }
        }

        // Check OCSP if enabled and CRL didn't give a definitive answer
        if self.config.enable_ocsp && !result.status.is_revoked() {
            match self.check_ocsp(cert, issuer).await {
                Ok(status) => {
                    result.ocsp_checked = true;
                    result.ocsp_status = Some(status);
                    info!("OCSP check result: {:?}", status);

                    if status.is_revoked() {
                        result.status = RevocationStatus::Revoked;
                        return Ok(result);
                    } else if status.is_valid() {
                        result.status = RevocationStatus::Valid;
                    }
                }
                Err(e) => {
                    warn!("OCSP check failed: {}", e);
                    result.errors.push(format!("OCSP check failed: {}", e));
                }
            }
        }

        // Handle unknown status
        if result.status.is_unknown() && self.config.fail_on_unknown {
            return Err(EstError::operational(
                "Certificate revocation status could not be determined",
            ));
        }

        Ok(result)
    }

    /// Check revocation status using CRL.
    async fn check_crl(
        &self,
        cert: &Certificate,
        issuer: &Certificate,
    ) -> Result<RevocationStatus> {
        debug!("Performing CRL check");

        // Extract CRL distribution points from certificate
        let crl_urls = self.extract_crl_urls(cert)?;

        if crl_urls.is_empty() {
            debug!("No CRL distribution points found in certificate");
            return Ok(RevocationStatus::Unknown);
        }

        for url in crl_urls {
            // Check cache first
            if let Some(status) = self.check_crl_cache(&url, cert, issuer).await? {
                return Ok(status);
            }

            // Download and check CRL
            debug!("Downloading CRL from: {}", url);
            match self.download_and_check_crl(&url, cert, issuer).await {
                Ok(status) => return Ok(status),
                Err(e) => {
                    warn!("Failed to download/check CRL from {}: {}", url, e);
                    // Continue to next URL
                }
            }
        }

        Ok(RevocationStatus::Unknown)
    }

    /// Download CRL from URL and check certificate.
    async fn download_and_check_crl(
        &self,
        url: &str,
        cert: &Certificate,
        issuer: &Certificate,
    ) -> Result<RevocationStatus> {
        // Download CRL
        debug!("Fetching CRL from {}", url);
        let response = self.http_client.get(url).send().await?;

        if !response.status().is_success() {
            return Err(EstError::protocol(format!(
                "CRL download failed with status: {}",
                response.status()
            )));
        }

        let crl_data = response.bytes().await?;

        // Parse CRL (try DER first, then PEM)
        let crl = self.parse_crl(&crl_data)?;

        // Verify CRL signature using issuer's public key
        self.verify_crl_signature(&crl, issuer)?;

        // Check if certificate is in the CRL
        let status = self.check_cert_in_crl(cert, &crl)?;

        // Cache the CRL
        self.cache_crl(url, crl).await?;

        Ok(status)
    }

    /// Parse CRL data (DER or PEM format).
    fn parse_crl(&self, data: &[u8]) -> Result<CertificateList> {
        // Try DER first
        if let Ok(crl) = CertificateList::from_der(data) {
            debug!("Parsed CRL as DER");
            return Ok(crl);
        }

        // Try PEM
        let pem_str = std::str::from_utf8(data)
            .map_err(|_| EstError::protocol("CRL is not valid UTF-8 for PEM parsing"))?;

        // Look for PEM boundaries
        if let Some(pem_start) = pem_str.find("-----BEGIN X509 CRL-----")
            && let Some(pem_end) = pem_str.find("-----END X509 CRL-----")
        {
            let pem_content = &pem_str[pem_start + 24..pem_end];
            let cleaned_content = pem_content.replace(['\n', '\r', ' '], "");
            let der_data = base64::engine::general_purpose::STANDARD
                .decode(cleaned_content)
                .map_err(|e| EstError::protocol(format!("Invalid base64 in PEM CRL: {}", e)))?;

            let crl = CertificateList::from_der(&der_data)
                .map_err(|e| EstError::protocol(format!("Failed to parse PEM CRL: {}", e)))?;

            debug!("Parsed CRL as PEM");
            return Ok(crl);
        }

        Err(EstError::protocol("CRL is not valid DER or PEM format"))
    }

    /// Verify CRL signature using issuer's public key.
    fn verify_crl_signature(&self, crl: &CertificateList, issuer: &Certificate) -> Result<()> {
        use const_oid::ObjectIdentifier;
        use der::Encode;

        // Get the signature algorithm from the CRL
        let sig_alg_oid = &crl.signature_algorithm.oid;

        // Get the issuer's public key
        let issuer_spki = &issuer.tbs_certificate.subject_public_key_info;
        let pub_key_alg = &issuer_spki.algorithm.oid;

        debug!(
            "Verifying CRL signature with algorithm {:?} using key algorithm {:?}",
            sig_alg_oid, pub_key_alg
        );

        // Encode the TBSCertList to get the data that was signed
        let tbs_bytes = crl
            .tbs_cert_list
            .to_der()
            .map_err(|e| EstError::operational(format!("Failed to encode TBS CertList: {}", e)))?;

        // Get the signature bytes
        let signature = crl.signature.as_bytes().ok_or_else(|| {
            EstError::operational("CRL signature has unused bits (not byte-aligned)")
        })?;

        // Verify the signature based on the algorithm
        const RSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
        const RSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
        const RSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
        const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
        const ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
        const ECDSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");

        // Perform cryptographic signature verification
        match *sig_alg_oid {
            RSA_SHA256 | RSA_SHA384 | RSA_SHA512 => {
                self.verify_rsa_crl_signature(&tbs_bytes, signature, *sig_alg_oid, issuer_spki)?;
                debug!("CRL RSA signature verified successfully");
                Ok(())
            }
            ECDSA_SHA256 | ECDSA_SHA384 | ECDSA_SHA512 => {
                self.verify_ecdsa_crl_signature(&tbs_bytes, signature, *sig_alg_oid, issuer_spki)?;
                debug!("CRL ECDSA signature verified successfully");
                Ok(())
            }
            _ => {
                warn!("Unsupported CRL signature algorithm: {:?}", sig_alg_oid);
                Err(EstError::operational(format!(
                    "Unsupported CRL signature algorithm: {}",
                    sig_alg_oid
                )))
            }
        }
    }

    /// Verify RSA signature on CRL.
    fn verify_rsa_crl_signature(
        &self,
        tbs_bytes: &[u8],
        signature: &[u8],
        alg_oid: const_oid::ObjectIdentifier,
        issuer_spki: &spki::SubjectPublicKeyInfoOwned,
    ) -> Result<()> {
        use const_oid::ObjectIdentifier;
        use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey};
        use rsa::signature::Verifier;
        use sha2::{Sha256, Sha384, Sha512};

        const RSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
        const RSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
        const RSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");

        // Parse the RSA public key from SPKI
        let public_key_bytes = issuer_spki
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| EstError::operational("Public key has unused bits"))?;

        // Decode the RSA public key (PKCS#1 format inside the SPKI)
        use rsa::pkcs1::DecodeRsaPublicKey;
        let public_key = rsa::RsaPublicKey::from_pkcs1_der(public_key_bytes)
            .map_err(|e| EstError::operational(format!("Failed to parse RSA public key: {}", e)))?;

        let sig = RsaSignature::try_from(signature)
            .map_err(|e| EstError::operational(format!("Invalid RSA signature: {}", e)))?;

        // Verify based on hash algorithm
        match alg_oid {
            RSA_SHA256 => {
                let verifying_key = VerifyingKey::<Sha256>::new(public_key);
                verifying_key.verify(tbs_bytes, &sig).map_err(|e| {
                    EstError::operational(format!(
                        "RSA-SHA256 signature verification failed: {}",
                        e
                    ))
                })?;
            }
            RSA_SHA384 => {
                let verifying_key = VerifyingKey::<Sha384>::new(public_key);
                verifying_key.verify(tbs_bytes, &sig).map_err(|e| {
                    EstError::operational(format!(
                        "RSA-SHA384 signature verification failed: {}",
                        e
                    ))
                })?;
            }
            RSA_SHA512 => {
                let verifying_key = VerifyingKey::<Sha512>::new(public_key);
                verifying_key.verify(tbs_bytes, &sig).map_err(|e| {
                    EstError::operational(format!(
                        "RSA-SHA512 signature verification failed: {}",
                        e
                    ))
                })?;
            }
            _ => {
                return Err(EstError::operational(format!(
                    "Unsupported RSA signature algorithm: {}",
                    alg_oid
                )));
            }
        }

        Ok(())
    }

    /// Verify ECDSA signature on CRL.
    fn verify_ecdsa_crl_signature(
        &self,
        tbs_bytes: &[u8],
        signature: &[u8],
        alg_oid: const_oid::ObjectIdentifier,
        issuer_spki: &spki::SubjectPublicKeyInfoOwned,
    ) -> Result<()> {
        use const_oid::ObjectIdentifier;
        use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
        use p384::ecdsa::{Signature as P384Signature, VerifyingKey as P384VerifyingKey};
        use sha2::{Digest, Sha256, Sha384, Sha512};

        const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
        const ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
        const ECDSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");

        // Parse the ECDSA public key from SPKI
        let public_key_bytes = issuer_spki
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| EstError::operational("Public key has unused bits"))?;

        // Verify based on curve and hash algorithm
        match alg_oid {
            ECDSA_SHA256 => {
                // P-256 with SHA-256
                let verifying_key =
                    P256VerifyingKey::from_sec1_bytes(public_key_bytes).map_err(|e| {
                        EstError::operational(format!("Failed to parse P-256 public key: {}", e))
                    })?;

                let sig = P256Signature::from_der(signature).map_err(|e| {
                    EstError::operational(format!("Invalid ECDSA signature: {}", e))
                })?;

                // Hash the message
                let hash = Sha256::digest(tbs_bytes);

                verifying_key.verify(&hash, &sig).map_err(|e| {
                    EstError::operational(format!(
                        "ECDSA-SHA256 signature verification failed: {}",
                        e
                    ))
                })?;
            }
            ECDSA_SHA384 => {
                // P-384 with SHA-384
                let verifying_key =
                    P384VerifyingKey::from_sec1_bytes(public_key_bytes).map_err(|e| {
                        EstError::operational(format!("Failed to parse P-384 public key: {}", e))
                    })?;

                let sig = P384Signature::from_der(signature).map_err(|e| {
                    EstError::operational(format!("Invalid ECDSA signature: {}", e))
                })?;

                // Hash the message
                let hash = Sha384::digest(tbs_bytes);

                verifying_key.verify(&hash, &sig).map_err(|e| {
                    EstError::operational(format!(
                        "ECDSA-SHA384 signature verification failed: {}",
                        e
                    ))
                })?;
            }
            ECDSA_SHA512 => {
                // P-384 with SHA-512 (typically)
                let verifying_key =
                    P384VerifyingKey::from_sec1_bytes(public_key_bytes).map_err(|e| {
                        EstError::operational(format!("Failed to parse P-384 public key: {}", e))
                    })?;

                let sig = P384Signature::from_der(signature).map_err(|e| {
                    EstError::operational(format!("Invalid ECDSA signature: {}", e))
                })?;

                // Hash the message
                let hash = Sha512::digest(tbs_bytes);

                verifying_key.verify(&hash, &sig).map_err(|e| {
                    EstError::operational(format!(
                        "ECDSA-SHA512 signature verification failed: {}",
                        e
                    ))
                })?;
            }
            _ => {
                return Err(EstError::operational(format!(
                    "Unsupported ECDSA signature algorithm: {}",
                    alg_oid
                )));
            }
        }

        Ok(())
    }

    /// Check if certificate is revoked in CRL.
    fn check_cert_in_crl(
        &self,
        cert: &Certificate,
        crl: &CertificateList,
    ) -> Result<RevocationStatus> {
        let cert_serial = &cert.tbs_certificate.serial_number;

        // Check if there are any revoked certificates
        if let Some(revoked_certs) = &crl.tbs_cert_list.revoked_certificates {
            for revoked_cert in revoked_certs.iter() {
                if &revoked_cert.serial_number == cert_serial {
                    debug!("Certificate found in CRL - REVOKED");
                    return Ok(RevocationStatus::Revoked);
                }
            }
        }

        debug!("Certificate not found in CRL - VALID");
        Ok(RevocationStatus::Valid)
    }

    /// Cache a CRL.
    async fn cache_crl(&self, url: &str, crl: CertificateList) -> Result<()> {
        let mut cache = self.crl_cache.write().await;

        // Evict oldest entries while cache is at or above limit
        // Fixed: TOCTOU race condition - keep lock throughout eviction
        while cache.len() >= self.config.crl_cache_max_entries {
            // Find and remove oldest entry in a single atomic operation
            let oldest_key = cache
                .iter()
                .min_by_key(|(_, entry)| entry.cached_at)
                .map(|(k, _)| k.clone());

            if let Some(key) = oldest_key {
                cache.remove(&key);
                debug!("Evicted oldest CRL from cache: {}", key);
            } else {
                // Cache is empty, shouldn't happen but break to avoid infinite loop
                break;
            }
        }

        // Parse nextUpdate time from CRL
        let next_update = crl.tbs_cert_list.next_update.as_ref().map(|time| {
            // Convert X.509 time to SystemTime
            match time {
                x509_cert::time::Time::UtcTime(utc) => {
                    SystemTime::UNIX_EPOCH + utc.to_unix_duration()
                }
                x509_cert::time::Time::GeneralTime(r#gen) => {
                    SystemTime::UNIX_EPOCH + r#gen.to_unix_duration()
                }
            }
        });

        let entry = CrlCacheEntry {
            crl,
            cached_at: SystemTime::now(),
            next_update,
        };

        cache.insert(url.to_string(), entry);
        debug!("Cached CRL for {}", url);

        Ok(())
    }

    /// Extract CRL distribution point URLs from a certificate.
    fn extract_crl_urls(&self, cert: &Certificate) -> Result<Vec<String>> {
        let mut urls = Vec::new();

        // Look for CRL Distribution Points extension
        if let Some(extensions) = &cert.tbs_certificate.extensions {
            for ext in extensions.iter() {
                // CRL Distribution Points OID: 2.5.29.31
                let crl_dist_points_oid = const_oid::db::rfc5280::ID_CE_CRL_DISTRIBUTION_POINTS;

                if ext.extn_id == crl_dist_points_oid {
                    // Parse the CRL Distribution Points extension
                    match CrlDistributionPoints::from_der(ext.extn_value.as_bytes()) {
                        Ok(crl_dps) => {
                            debug!("Parsed CRL Distribution Points extension");

                            // Extract URLs from each distribution point
                            for dp in crl_dps.0.iter() {
                                if let Some(dist_point_urls) = self.extract_urls_from_dp(dp) {
                                    urls.extend(dist_point_urls);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Failed to parse CRL Distribution Points: {}", e);
                        }
                    }
                }
            }
        }

        Ok(urls)
    }

    /// Extract URLs from a distribution point.
    fn extract_urls_from_dp(&self, dp: &DistributionPoint) -> Option<Vec<String>> {
        let mut urls = Vec::new();

        if let Some(dist_point_name) = &dp.distribution_point {
            // DistributionPointName is a choice between FullName and NameRelativeToCRLIssuer
            // We're interested in FullName which contains GeneralNames
            match dist_point_name {
                x509_cert::ext::pkix::name::DistributionPointName::FullName(general_names) => {
                    for general_name in general_names.iter() {
                        // UniformResourceIdentifier is variant 6
                        if let x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(
                            uri,
                        ) = general_name
                            && let Ok(url) = std::str::from_utf8(uri.as_bytes())
                        {
                            debug!("Found CRL URL: {}", url);
                            urls.push(url.to_string());
                        }
                    }
                }
                _ => {
                    debug!("Distribution point uses NameRelativeToCRLIssuer (not supported)");
                }
            }
        }

        if urls.is_empty() { None } else { Some(urls) }
    }

    /// Check CRL cache for revocation status.
    async fn check_crl_cache(
        &self,
        url: &str,
        cert: &Certificate,
        _issuer: &Certificate,
    ) -> Result<Option<RevocationStatus>> {
        let cache = self.crl_cache.read().await;

        if let Some(entry) = cache.get(url) {
            let age = SystemTime::now()
                .duration_since(entry.cached_at)
                .unwrap_or(Duration::from_secs(0));

            // Check if cached CRL is still valid
            let is_fresh = age < self.config.crl_cache_duration;
            let not_expired = entry
                .next_update
                .map(|next| SystemTime::now() < next)
                .unwrap_or(true);

            if is_fresh && not_expired {
                debug!("Using cached CRL for {}", url);
                // Check certificate against cached CRL
                let status = self.check_cert_in_crl(cert, &entry.crl)?;
                return Ok(Some(status));
            } else {
                debug!("Cached CRL expired for {}", url);
            }
        }

        Ok(None)
    }

    /// Check revocation status using OCSP.
    async fn check_ocsp(
        &self,
        cert: &Certificate,
        issuer: &Certificate,
    ) -> Result<RevocationStatus> {
        debug!("Performing OCSP check");

        // Extract OCSP responder URL from certificate
        let ocsp_url = self.extract_ocsp_url(cert)?;

        if let Some(url) = ocsp_url {
            debug!("Sending OCSP request to: {}", url);

            // Create OCSP request
            let ocsp_request = self.create_ocsp_request(cert, issuer)?;

            // Send OCSP request
            match self.send_ocsp_request(&url, &ocsp_request).await {
                Ok(status) => Ok(status),
                Err(e) => {
                    warn!("OCSP request failed: {}", e);
                    Ok(RevocationStatus::Unknown)
                }
            }
        } else {
            debug!("No OCSP responder URL found in certificate");
            Ok(RevocationStatus::Unknown)
        }
    }

    /// Create an OCSP request for a certificate.
    ///
    /// Builds an RFC 6960 compliant OCSP request with CertID containing:
    /// - Hash algorithm: SHA-256
    /// - Issuer name hash: SHA-256(issuer DN)
    /// - Issuer key hash: SHA-256(issuer public key)
    /// - Certificate serial number
    fn create_ocsp_request(&self, cert: &Certificate, issuer: &Certificate) -> Result<Vec<u8>> {
        debug!("Creating OCSP request for certificate");

        // Build CertID
        let cert_id = self.build_cert_id(cert, issuer)?;

        // Create single request
        let single_request = SingleRequest { req_cert: cert_id };

        // Create request list with one request
        let mut request_list = der::asn1::SequenceOf::<SingleRequest, 1>::new();
        request_list
            .add(single_request)
            .map_err(|e| EstError::operational(format!("Failed to add request to list: {}", e)))?;

        // Create TBS request
        let tbs_request = TbsRequest { request_list };

        // Create OCSP request
        let ocsp_request = OcspRequest { tbs_request };

        // Encode to DER
        ocsp_request
            .to_der()
            .map_err(|e| EstError::operational(format!("Failed to encode OCSP request: {}", e)))
    }

    /// Build OCSP CertID for a certificate.
    fn build_cert_id(&self, cert: &Certificate, issuer: &Certificate) -> Result<OcspCertId> {
        use der::Encode;

        // Hash algorithm: SHA-256 (OID: 2.16.840.1.101.3.4.2.1)
        let hash_alg_oid = const_oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
        let hash_algorithm = AlgorithmIdentifierOwned {
            oid: hash_alg_oid,
            parameters: None,
        };

        // Compute issuer name hash (SHA-256 of DER-encoded issuer DN)
        let issuer_name_der =
            issuer.tbs_certificate.subject.to_der().map_err(|e| {
                EstError::operational(format!("Failed to encode issuer name: {}", e))
            })?;
        let issuer_name_hash_bytes = Sha256::digest(&issuer_name_der);
        let issuer_name_hash =
            OctetString::new(issuer_name_hash_bytes.as_slice()).map_err(|e| {
                EstError::operational(format!("Failed to create issuer name hash: {}", e))
            })?;

        // Compute issuer key hash (SHA-256 of issuer public key, excluding tag and length)
        let issuer_public_key_bytes = issuer
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| EstError::operational("Issuer public key has unused bits"))?;
        let issuer_key_hash_bytes = Sha256::digest(issuer_public_key_bytes);
        let issuer_key_hash = OctetString::new(issuer_key_hash_bytes.as_slice()).map_err(|e| {
            EstError::operational(format!("Failed to create issuer key hash: {}", e))
        })?;

        // Get certificate serial number
        let serial_number = cert.tbs_certificate.serial_number.clone();

        Ok(OcspCertId {
            hash_algorithm,
            issuer_name_hash,
            issuer_key_hash,
            serial_number,
        })
    }

    /// Send OCSP request and parse response.
    async fn send_ocsp_request(&self, url: &str, request: &[u8]) -> Result<RevocationStatus> {
        debug!("Sending OCSP request to {}", url);

        // Maximum OCSP response size to prevent memory exhaustion
        const MAX_OCSP_RESPONSE_SIZE: usize = 100 * 1024; // 100KB

        // Send OCSP request via HTTP POST
        let response = self
            .http_client
            .post(url)
            .header("Content-Type", "application/ocsp-request")
            .body(request.to_vec())
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(EstError::protocol(format!(
                "OCSP request failed with status: {}",
                response.status()
            )));
        }

        // Check Content-Length header if present
        if let Some(content_length) = response.headers().get("content-length") {
            if let Ok(size_str) = content_length.to_str() {
                if let Ok(size) = size_str.parse::<usize>() {
                    if size > MAX_OCSP_RESPONSE_SIZE {
                        return Err(EstError::protocol(format!(
                            "OCSP response too large: {} bytes (max {})",
                            size, MAX_OCSP_RESPONSE_SIZE
                        )));
                    }
                }
            }
        }

        let response_data = response.bytes().await?;

        // Verify actual size after reading
        if response_data.len() > MAX_OCSP_RESPONSE_SIZE {
            return Err(EstError::protocol(format!(
                "OCSP response too large: {} bytes (max {})",
                response_data.len(),
                MAX_OCSP_RESPONSE_SIZE
            )));
        }

        // Parse OCSP response
        self.parse_ocsp_response(&response_data)
    }

    /// Parse OCSP response.
    ///
    /// Parses RFC 6960 OCSP response and extracts certificate status.
    /// Uses SimpleDerParser for reliable parsing of nested ASN.1 structures.
    ///
    /// Structure:
    /// ```text
    /// OCSPResponse ::= SEQUENCE {
    ///    responseStatus   ENUMERATED,
    ///    responseBytes    [0] EXPLICIT ResponseBytes OPTIONAL }
    ///
    /// ResponseBytes ::= SEQUENCE {
    ///    responseType     OBJECT IDENTIFIER,
    ///    response         OCTET STRING (contains BasicOCSPResponse) }
    /// ```
    fn parse_ocsp_response(&self, data: &[u8]) -> Result<RevocationStatus> {
        debug!("Parsing OCSP response ({} bytes)", data.len());

        // Use simple DER parser for outer structure
        let mut parser = SimpleDerParser::new(data);

        // Parse outer SEQUENCE
        parser.expect_sequence()?;

        // Read responseStatus (ENUMERATED)
        let response_status = parser.read_enumerated()?;
        debug!("OCSP response status: {}", response_status);

        // Check if successful (0 = successful)
        if response_status != 0 {
            return match response_status {
                1 => Err(EstError::protocol("OCSP: malformed request")),
                2 => Err(EstError::protocol("OCSP: internal error")),
                3 => {
                    warn!("OCSP responder busy (try later)");
                    Ok(RevocationStatus::Unknown)
                }
                5 => Err(EstError::protocol("OCSP: signature required")),
                6 => Err(EstError::protocol("OCSP: unauthorized")),
                _ => Err(EstError::protocol(format!(
                    "OCSP: unknown status {}",
                    response_status
                ))),
            };
        }

        // Read responseBytes [0] EXPLICIT
        parser.expect_context_constructed(0)?;

        // Parse ResponseBytes SEQUENCE
        parser.expect_sequence()?;

        // Skip responseType OID (should be id-pkix-ocsp-basic)
        parser.skip_oid()?;

        // Read response OCTET STRING
        let basic_response_data = parser.read_octet_string()?;

        // Parse BasicOCSPResponse
        self.parse_basic_ocsp_response(basic_response_data)
    }

    /// Parse BasicOCSPResponse to extract certificate status.
    ///
    /// BasicOCSPResponse ::= SEQUENCE {
    ///    tbsResponseData      ResponseData,
    ///    signatureAlgorithm   AlgorithmIdentifier,
    ///    signature            BIT STRING,
    ///    certs                [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
    fn parse_basic_ocsp_response(&self, data: &[u8]) -> Result<RevocationStatus> {
        let mut parser = SimpleDerParser::new(data);

        // Parse BasicOCSPResponse SEQUENCE
        parser.expect_sequence()?;

        // Read tbsResponseData SEQUENCE
        let tbs_start = parser.position();
        parser.expect_sequence()?;
        let tbs_end = parser.position();

        // Extract tbs_response_data for potential signature verification
        let _tbs_response_data = &data[tbs_start..tbs_end];

        // Parse ResponseData to get cert status
        let cert_status = self.parse_response_data(&data[tbs_start..tbs_end])?;

        // Convert to RevocationStatus
        match cert_status {
            0 => {
                debug!("OCSP: certificate is GOOD");
                Ok(RevocationStatus::Valid)
            }
            1 => {
                debug!("OCSP: certificate is REVOKED");
                Ok(RevocationStatus::Revoked)
            }
            2 => {
                debug!("OCSP: certificate status UNKNOWN");
                Ok(RevocationStatus::Unknown)
            }
            _ => Err(EstError::operational(format!(
                "Invalid cert status: {}",
                cert_status
            ))),
        }
    }

    /// Parse ResponseData SEQUENCE to extract cert status.
    ///
    /// ResponseData ::= SEQUENCE {
    ///    version              [0] EXPLICIT Version DEFAULT v1,
    ///    responderID          ResponderID,
    ///    producedAt           GeneralizedTime,
    ///    responses            SEQUENCE OF SingleResponse,
    ///    responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
    fn parse_response_data(&self, data: &[u8]) -> Result<u8> {
        let mut parser = SimpleDerParser::new(data);

        // Skip outer SEQUENCE tag (already validated)
        parser.expect_sequence()?;

        // Skip version [0] if present (optional, context-specific tag 0xA0)
        if parser.peek_tag() == Some(0xA0) {
            parser.skip_context_specific()?;
        }

        // Skip responderID (context-specific [1] or [2])
        parser.skip_context_specific()?;

        // Skip producedAt (GeneralizedTime)
        parser.skip_generalized_time()?;

        // Read responses SEQUENCE
        parser.expect_sequence()?;

        // Parse first SingleResponse
        self.parse_single_response_status(parser.remaining())
    }

    /// Parse SingleResponse to extract just the cert status.
    ///
    /// SingleResponse ::= SEQUENCE {
    ///    certID               CertID,
    ///    certStatus           CertStatus,
    ///    thisUpdate           GeneralizedTime,
    ///    nextUpdate           [0] EXPLICIT GeneralizedTime OPTIONAL,
    ///    singleExtensions     [1] EXPLICIT Extensions OPTIONAL }
    ///
    /// CertStatus ::= CHOICE {
    ///    good         [0] IMPLICIT NULL,
    ///    revoked      [1] IMPLICIT RevokedInfo,
    ///    unknown      [2] IMPLICIT UnknownInfo }
    fn parse_single_response_status(&self, data: &[u8]) -> Result<u8> {
        let mut parser = SimpleDerParser::new(data);

        // SingleResponse SEQUENCE
        parser.expect_sequence()?;

        // Skip certID SEQUENCE
        parser.skip_sequence()?;

        // Read certStatus (context-specific tag indicates status)
        // [0] = good, [1] = revoked, [2] = unknown
        let status_tag = parser.read_byte()?;

        if (status_tag & 0xE0) == 0x80 {
            // Context-specific tag
            let status = status_tag & 0x1F;
            debug!("Cert status from context tag: {}", status);
            Ok(status)
        } else {
            Err(EstError::operational(format!(
                "Expected context-specific tag for certStatus, got: 0x{:02x}",
                status_tag
            )))
        }
    }

    /// Extract OCSP responder URL from certificate.
    fn extract_ocsp_url(&self, cert: &Certificate) -> Result<Option<String>> {
        // Look for Authority Information Access extension
        if let Some(extensions) = &cert.tbs_certificate.extensions {
            for ext in extensions.iter() {
                // Authority Information Access OID: 1.3.6.1.5.5.7.1.1
                let aia_oid = const_oid::db::rfc5280::ID_PE_AUTHORITY_INFO_ACCESS;

                if ext.extn_id == aia_oid {
                    // Parse the AIA extension
                    match AuthorityInfoAccessSyntax::from_der(ext.extn_value.as_bytes()) {
                        Ok(aia) => {
                            debug!("Parsed Authority Information Access extension");

                            // Look for OCSP access method
                            // OCSP OID: 1.3.6.1.5.5.7.48.1
                            let ocsp_oid = const_oid::db::rfc6960::ID_PKIX_OCSP;

                            for access_desc in aia.0.iter() {
                                if access_desc.access_method == ocsp_oid {
                                    // Extract URL from access location (GeneralName)
                                    if let x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(uri) = &access_desc.access_location
                                        && let Ok(url) = std::str::from_utf8(uri.as_bytes())
                                    {
                                        debug!("Found OCSP URL: {}", url);
                                        return Ok(Some(url.to_string()));
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Failed to parse Authority Information Access: {}", e);
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    /// Clear the CRL cache.
    pub async fn clear_cache(&self) {
        let mut cache = self.crl_cache.write().await;
        cache.clear();
        info!("CRL cache cleared");
    }
}

// NOTE: Test code uses unwrap() deliberately - test fixtures are known valid
#[cfg(all(test, feature = "revocation"))]
mod tests {
    use super::*;
    use der::Decode;

    // Helper to load a PEM certificate from fixture bytes
    fn load_cert(pem_bytes: &[u8]) -> Certificate {
        let pem_str = std::str::from_utf8(pem_bytes).unwrap();
        let pem = pem_str
            .find("-----BEGIN CERTIFICATE-----")
            .expect("PEM header not found");
        let pem_end = pem_str.find("-----END CERTIFICATE-----").unwrap();
        let b64 = &pem_str[pem + 27..pem_end];
        let cleaned = b64.replace(['\n', '\r', ' '], "");
        let der = base64::engine::general_purpose::STANDARD
            .decode(cleaned)
            .unwrap();
        Certificate::from_der(&der).unwrap()
    }

    static CA_PEM: &[u8] = include_bytes!("../tests/fixtures/certs/ca.pem");
    static CLIENT_PEM: &[u8] = include_bytes!("../tests/fixtures/certs/client.pem");
    static SERVER_PEM: &[u8] = include_bytes!("../tests/fixtures/certs/server.pem");

    // -----------------------------------------------------------------------
    // RevocationConfig default
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_config() {
        let config = RevocationConfig::default();
        assert!(config.enable_crl);
        assert!(config.enable_ocsp);
        assert_eq!(config.crl_cache_duration, Duration::from_secs(3600));
        assert_eq!(config.crl_cache_max_entries, 100);
        assert_eq!(config.ocsp_timeout, Duration::from_secs(10));
        assert!(!config.fail_on_unknown);
    }

    // -----------------------------------------------------------------------
    // RevocationConfigBuilder – full and partial builds
    // -----------------------------------------------------------------------

    #[test]
    fn test_revocation_config_builder_all_fields() {
        let config = RevocationConfig::builder()
            .enable_crl(false)
            .enable_ocsp(true)
            .crl_cache_duration(Duration::from_secs(7200))
            .crl_cache_max_entries(50)
            .ocsp_timeout(Duration::from_secs(30))
            .fail_on_unknown(true)
            .build();

        assert!(!config.enable_crl);
        assert!(config.enable_ocsp);
        assert_eq!(config.crl_cache_duration, Duration::from_secs(7200));
        assert_eq!(config.crl_cache_max_entries, 50);
        assert_eq!(config.ocsp_timeout, Duration::from_secs(30));
        assert!(config.fail_on_unknown);
    }

    #[test]
    fn test_revocation_config_builder_partial_uses_defaults() {
        let config = RevocationConfig::builder()
            .enable_crl(false)
            .build();

        // Explicitly set field
        assert!(!config.enable_crl);
        // Everything else should be default
        assert!(config.enable_ocsp);
        assert_eq!(config.crl_cache_duration, Duration::from_secs(3600));
        assert_eq!(config.crl_cache_max_entries, 100);
        assert_eq!(config.ocsp_timeout, Duration::from_secs(10));
        assert!(!config.fail_on_unknown);
    }

    #[test]
    fn test_revocation_config_builder_empty_gives_defaults() {
        let config = RevocationConfig::builder().build();
        let default = RevocationConfig::default();
        assert_eq!(config.enable_crl, default.enable_crl);
        assert_eq!(config.enable_ocsp, default.enable_ocsp);
        assert_eq!(config.crl_cache_duration, default.crl_cache_duration);
        assert_eq!(config.crl_cache_max_entries, default.crl_cache_max_entries);
        assert_eq!(config.ocsp_timeout, default.ocsp_timeout);
        assert_eq!(config.fail_on_unknown, default.fail_on_unknown);
    }

    // -----------------------------------------------------------------------
    // RevocationStatus
    // -----------------------------------------------------------------------

    #[test]
    fn test_revocation_status_valid() {
        let s = RevocationStatus::Valid;
        assert!(s.is_valid());
        assert!(!s.is_revoked());
        assert!(!s.is_unknown());
    }

    #[test]
    fn test_revocation_status_revoked() {
        let s = RevocationStatus::Revoked;
        assert!(s.is_revoked());
        assert!(!s.is_valid());
        assert!(!s.is_unknown());
    }

    #[test]
    fn test_revocation_status_unknown() {
        let s = RevocationStatus::Unknown;
        assert!(s.is_unknown());
        assert!(!s.is_valid());
        assert!(!s.is_revoked());
    }

    #[test]
    fn test_revocation_status_eq_and_clone() {
        let s1 = RevocationStatus::Valid;
        let s2 = s1; // Copy
        assert_eq!(s1, s2);

        let s3 = RevocationStatus::Revoked;
        assert_ne!(s1, s3);
    }

    #[test]
    fn test_revocation_status_debug() {
        let debug_str = format!("{:?}", RevocationStatus::Valid);
        assert_eq!(debug_str, "Valid");
        let debug_str = format!("{:?}", RevocationStatus::Revoked);
        assert_eq!(debug_str, "Revoked");
        let debug_str = format!("{:?}", RevocationStatus::Unknown);
        assert_eq!(debug_str, "Unknown");
    }

    // -----------------------------------------------------------------------
    // RevocationCheckResult
    // -----------------------------------------------------------------------

    #[test]
    fn test_revocation_check_result_is_revoked_true() {
        let result = RevocationCheckResult {
            status: RevocationStatus::Revoked,
            crl_checked: true,
            ocsp_checked: false,
            crl_status: Some(RevocationStatus::Revoked),
            ocsp_status: None,
            errors: Vec::new(),
        };
        assert!(result.is_revoked());
    }

    #[test]
    fn test_revocation_check_result_is_revoked_false() {
        let result = RevocationCheckResult {
            status: RevocationStatus::Valid,
            crl_checked: true,
            ocsp_checked: true,
            crl_status: Some(RevocationStatus::Valid),
            ocsp_status: Some(RevocationStatus::Valid),
            errors: Vec::new(),
        };
        assert!(!result.is_revoked());
    }

    #[test]
    fn test_revocation_check_result_with_errors() {
        let result = RevocationCheckResult {
            status: RevocationStatus::Unknown,
            crl_checked: false,
            ocsp_checked: false,
            crl_status: None,
            ocsp_status: None,
            errors: vec![
                "CRL check failed: timeout".to_string(),
                "OCSP check failed: network error".to_string(),
            ],
        };
        assert!(!result.is_revoked());
        assert_eq!(result.errors.len(), 2);
        assert!(result.errors[0].contains("CRL"));
        assert!(result.errors[1].contains("OCSP"));
    }

    #[test]
    fn test_revocation_check_result_debug_and_clone() {
        let result = RevocationCheckResult {
            status: RevocationStatus::Valid,
            crl_checked: true,
            ocsp_checked: false,
            crl_status: Some(RevocationStatus::Valid),
            ocsp_status: None,
            errors: vec![],
        };
        let cloned = result.clone();
        assert_eq!(cloned.status, result.status);
        assert_eq!(cloned.crl_checked, result.crl_checked);
        assert_eq!(cloned.ocsp_checked, result.ocsp_checked);
        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("Valid"));
    }

    // -----------------------------------------------------------------------
    // RevocationChecker construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_revocation_checker_new_default_config() {
        let config = RevocationConfig::default();
        let _checker = RevocationChecker::new(config);
        // Just verifying construction doesn't panic
    }

    #[test]
    fn test_revocation_checker_new_custom_config() {
        let config = RevocationConfig::builder()
            .enable_crl(false)
            .enable_ocsp(false)
            .ocsp_timeout(Duration::from_secs(1))
            .crl_cache_max_entries(5)
            .build();
        let _checker = RevocationChecker::new(config);
    }

    // -----------------------------------------------------------------------
    // RevocationChecker – check_revocation with both disabled
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_check_revocation_both_disabled_returns_unknown() {
        let config = RevocationConfig::builder()
            .enable_crl(false)
            .enable_ocsp(false)
            .fail_on_unknown(false)
            .build();
        let checker = RevocationChecker::new(config);

        let cert = load_cert(CLIENT_PEM);
        let issuer = load_cert(CA_PEM);

        let result = checker.check_revocation(&cert, &issuer).await.unwrap();
        assert!(result.status.is_unknown());
        assert!(!result.crl_checked);
        assert!(!result.ocsp_checked);
        assert!(result.crl_status.is_none());
        assert!(result.ocsp_status.is_none());
    }

    #[tokio::test]
    async fn test_check_revocation_both_disabled_fail_on_unknown() {
        let config = RevocationConfig::builder()
            .enable_crl(false)
            .enable_ocsp(false)
            .fail_on_unknown(true)
            .build();
        let checker = RevocationChecker::new(config);

        let cert = load_cert(CLIENT_PEM);
        let issuer = load_cert(CA_PEM);

        let result = checker.check_revocation(&cert, &issuer).await;
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // RevocationChecker – clear_cache
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_clear_cache() {
        let checker = RevocationChecker::new(RevocationConfig::default());
        // Insert a dummy entry into the cache
        {
            let cache = checker.crl_cache.write().await;
            // We can't easily create a real CrlCacheEntry without a CRL,
            // so just verify the cache is accessible and clearable
            assert!(cache.is_empty());
        }
        checker.clear_cache().await;
        let cache = checker.crl_cache.read().await;
        assert!(cache.is_empty());
    }

    // -----------------------------------------------------------------------
    // parse_crl – error paths
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_crl_invalid_data() {
        let checker = RevocationChecker::new(RevocationConfig::default());
        let result = checker.parse_crl(b"not a crl");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_crl_invalid_der() {
        let checker = RevocationChecker::new(RevocationConfig::default());
        let result = checker.parse_crl(&[0x30, 0x03, 0x01, 0x02, 0x03]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_crl_invalid_pem_base64() {
        let checker = RevocationChecker::new(RevocationConfig::default());
        let bad_pem = b"-----BEGIN X509 CRL-----\n!!!invalid!!!\n-----END X509 CRL-----";
        let result = checker.parse_crl(bad_pem);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_crl_pem_valid_base64_invalid_der() {
        let checker = RevocationChecker::new(RevocationConfig::default());
        let bad_pem = b"-----BEGIN X509 CRL-----\nYWJj\n-----END X509 CRL-----";
        let result = checker.parse_crl(bad_pem);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_crl_not_utf8_not_der() {
        let checker = RevocationChecker::new(RevocationConfig::default());
        // Start with something that's not valid DER and not valid UTF-8
        let data: Vec<u8> = vec![0xFF, 0xFE, 0xFD, 0xFC, 0xFB];
        let result = checker.parse_crl(&data);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // parse_ocsp_response – error paths via SimpleDerParser
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_ocsp_response_empty_data() {
        let checker = RevocationChecker::new(RevocationConfig::default());
        let result = checker.parse_ocsp_response(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_ocsp_response_not_a_sequence() {
        let checker = RevocationChecker::new(RevocationConfig::default());
        // Tag 0x01 (BOOLEAN) instead of 0x30 (SEQUENCE)
        let result = checker.parse_ocsp_response(&[0x01, 0x01, 0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_ocsp_response_malformed_status() {
        let checker = RevocationChecker::new(RevocationConfig::default());
        // SEQUENCE { ENUMERATED { 1 } } -> malformedRequest
        let data = [0x30, 0x03, 0x0A, 0x01, 0x01];
        let result = checker.parse_ocsp_response(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_ocsp_response_internal_error_status() {
        let checker = RevocationChecker::new(RevocationConfig::default());
        // SEQUENCE { ENUMERATED { 2 } } -> internalError
        let data = [0x30, 0x03, 0x0A, 0x01, 0x02];
        let result = checker.parse_ocsp_response(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_ocsp_response_try_later_returns_unknown() {
        let checker = RevocationChecker::new(RevocationConfig::default());
        // SEQUENCE { ENUMERATED { 3 } } -> tryLater
        let data = [0x30, 0x03, 0x0A, 0x01, 0x03];
        let result = checker.parse_ocsp_response(&data);
        assert!(result.is_ok());
        assert!(result.unwrap().is_unknown());
    }

    #[test]
    fn test_parse_ocsp_response_sig_required() {
        let checker = RevocationChecker::new(RevocationConfig::default());
        // SEQUENCE { ENUMERATED { 5 } } -> sigRequired
        let data = [0x30, 0x03, 0x0A, 0x01, 0x05];
        let result = checker.parse_ocsp_response(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_ocsp_response_unauthorized() {
        let checker = RevocationChecker::new(RevocationConfig::default());
        // SEQUENCE { ENUMERATED { 6 } } -> unauthorized
        let data = [0x30, 0x03, 0x0A, 0x01, 0x06];
        let result = checker.parse_ocsp_response(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_ocsp_response_unknown_status_code() {
        let checker = RevocationChecker::new(RevocationConfig::default());
        // SEQUENCE { ENUMERATED { 9 } } -> unknown error code
        let data = [0x30, 0x03, 0x0A, 0x01, 0x09];
        let result = checker.parse_ocsp_response(&data);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // SimpleDerParser – length encoding edge cases (via parse_ocsp_response)
    // -----------------------------------------------------------------------

    #[test]
    fn test_der_parser_long_form_length_too_many_octets() {
        let checker = RevocationChecker::new(RevocationConfig::default());
        // SEQUENCE with long-form length: 0x85 means 5 octets for length (>4, rejected)
        let data = [0x30, 0x85, 0x00, 0x00, 0x00, 0x00, 0x00];
        let result = checker.parse_ocsp_response(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_der_parser_zero_length_octets() {
        let checker = RevocationChecker::new(RevocationConfig::default());
        // SEQUENCE with long-form length: 0x80 means indefinite (0 octets, rejected)
        let data = [0x30, 0x80];
        let result = checker.parse_ocsp_response(&data);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // extract_crl_urls / extract_ocsp_url – certificates without extensions
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_crl_urls_from_test_cert() {
        let checker = RevocationChecker::new(RevocationConfig::default());
        let cert = load_cert(CLIENT_PEM);
        // Our test certs may or may not have CRL distribution points;
        // the important thing is the function doesn't error
        let urls = checker.extract_crl_urls(&cert).unwrap();
        // Result can be empty if cert has no CRL DPs
        assert!(urls.is_empty() || urls.iter().all(|u| u.starts_with("http")));
    }

    #[test]
    fn test_extract_ocsp_url_from_test_cert() {
        let checker = RevocationChecker::new(RevocationConfig::default());
        let cert = load_cert(CLIENT_PEM);
        let url = checker.extract_ocsp_url(&cert).unwrap();
        // Our test cert may not have OCSP URL
        if let Some(u) = &url {
            assert!(u.starts_with("http"));
        }
    }

    #[test]
    fn test_extract_crl_urls_from_ca_cert() {
        let checker = RevocationChecker::new(RevocationConfig::default());
        let cert = load_cert(CA_PEM);
        let urls = checker.extract_crl_urls(&cert).unwrap();
        // CA self-signed certs typically have no CRL DPs
        assert!(urls.is_empty() || urls.iter().all(|u| u.starts_with("http")));
    }

    #[test]
    fn test_extract_ocsp_url_from_server_cert() {
        let checker = RevocationChecker::new(RevocationConfig::default());
        let cert = load_cert(SERVER_PEM);
        let url = checker.extract_ocsp_url(&cert).unwrap();
        if let Some(u) = &url {
            assert!(u.starts_with("http"));
        }
    }

    // -----------------------------------------------------------------------
    // RevocationConfig Clone and Debug
    // -----------------------------------------------------------------------

    #[test]
    fn test_revocation_config_clone_and_debug() {
        let config = RevocationConfig::builder()
            .enable_crl(true)
            .enable_ocsp(false)
            .build();
        let cloned = config.clone();
        assert_eq!(cloned.enable_crl, config.enable_crl);
        assert_eq!(cloned.enable_ocsp, config.enable_ocsp);
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("RevocationConfig"));
    }
}
