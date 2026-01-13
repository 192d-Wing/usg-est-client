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

//! Certificate revocation checking (CRL and OCSP).
//!
//! This module provides support for checking certificate revocation status
//! using Certificate Revocation Lists (CRL) and Online Certificate Status
//! Protocol (OCSP).
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
use der::Decode;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use x509_cert::Certificate;
use x509_cert::crl::CertificateList;
use x509_cert::ext::pkix::crl::dp::DistributionPoint;
use x509_cert::ext::pkix::{AuthorityInfoAccessSyntax, CrlDistributionPoints};

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
        let tbs_bytes = crl.tbs_cert_list.to_der().map_err(|e| {
            EstError::operational(format!("Failed to encode TBS CertList: {}", e))
        })?;

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
        let public_key_bytes = issuer_spki.subject_public_key.as_bytes().ok_or_else(|| {
            EstError::operational("Public key has unused bits")
        })?;

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
                verifying_key
                    .verify(tbs_bytes, &sig)
                    .map_err(|e| EstError::operational(format!("RSA-SHA256 signature verification failed: {}", e)))?;
            }
            RSA_SHA384 => {
                let verifying_key = VerifyingKey::<Sha384>::new(public_key);
                verifying_key
                    .verify(tbs_bytes, &sig)
                    .map_err(|e| EstError::operational(format!("RSA-SHA384 signature verification failed: {}", e)))?;
            }
            RSA_SHA512 => {
                let verifying_key = VerifyingKey::<Sha512>::new(public_key);
                verifying_key
                    .verify(tbs_bytes, &sig)
                    .map_err(|e| EstError::operational(format!("RSA-SHA512 signature verification failed: {}", e)))?;
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
        use p256::ecdsa::{
            signature::Verifier as P256Verifier, Signature as P256Signature,
            VerifyingKey as P256VerifyingKey,
        };
        use p384::ecdsa::{
            signature::Verifier as P384Verifier, Signature as P384Signature,
            VerifyingKey as P384VerifyingKey,
        };
        use sha2::{Digest, Sha256, Sha384, Sha512};

        const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
        const ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
        const ECDSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");

        // Parse the ECDSA public key from SPKI
        let public_key_bytes = issuer_spki.subject_public_key.as_bytes().ok_or_else(|| {
            EstError::operational("Public key has unused bits")
        })?;

        // Verify based on curve and hash algorithm
        match alg_oid {
            ECDSA_SHA256 => {
                // P-256 with SHA-256
                let verifying_key = P256VerifyingKey::from_sec1_bytes(public_key_bytes)
                    .map_err(|e| EstError::operational(format!("Failed to parse P-256 public key: {}", e)))?;

                let sig = P256Signature::from_der(signature)
                    .map_err(|e| EstError::operational(format!("Invalid ECDSA signature: {}", e)))?;

                // Hash the message
                let hash = Sha256::digest(tbs_bytes);

                verifying_key
                    .verify(&hash, &sig)
                    .map_err(|e| EstError::operational(format!("ECDSA-SHA256 signature verification failed: {}", e)))?;
            }
            ECDSA_SHA384 => {
                // P-384 with SHA-384
                let verifying_key = P384VerifyingKey::from_sec1_bytes(public_key_bytes)
                    .map_err(|e| EstError::operational(format!("Failed to parse P-384 public key: {}", e)))?;

                let sig = P384Signature::from_der(signature)
                    .map_err(|e| EstError::operational(format!("Invalid ECDSA signature: {}", e)))?;

                // Hash the message
                let hash = Sha384::digest(tbs_bytes);

                verifying_key
                    .verify(&hash, &sig)
                    .map_err(|e| EstError::operational(format!("ECDSA-SHA384 signature verification failed: {}", e)))?;
            }
            ECDSA_SHA512 => {
                // P-384 with SHA-512 (typically)
                let verifying_key = P384VerifyingKey::from_sec1_bytes(public_key_bytes)
                    .map_err(|e| EstError::operational(format!("Failed to parse P-384 public key: {}", e)))?;

                let sig = P384Signature::from_der(signature)
                    .map_err(|e| EstError::operational(format!("Invalid ECDSA signature: {}", e)))?;

                // Hash the message
                let hash = Sha512::digest(tbs_bytes);

                verifying_key
                    .verify(&hash, &sig)
                    .map_err(|e| EstError::operational(format!("ECDSA-SHA512 signature verification failed: {}", e)))?;
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

        // Check cache size and evict oldest if needed
        if cache.len() >= self.config.crl_cache_max_entries {
            // Simple eviction: remove oldest entry
            if let Some(oldest_key) = cache
                .iter()
                .min_by_key(|(_, entry)| entry.cached_at)
                .map(|(k, _)| k.clone())
            {
                cache.remove(&oldest_key);
                debug!("Evicted oldest CRL from cache");
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
    fn create_ocsp_request(&self, _cert: &Certificate, _issuer: &Certificate) -> Result<Vec<u8>> {
        // TODO: Implement actual OCSP request creation
        // OCSP Request structure (ASN.1):
        // OCSPRequest ::= SEQUENCE {
        //    tbsRequest      TBSRequest,
        //    optionalSignature   [0] EXPLICIT Signature OPTIONAL }
        //
        // TBSRequest ::= SEQUENCE {
        //    version             [0] EXPLICIT Version DEFAULT v1,
        //    requestorName       [1] EXPLICIT GeneralName OPTIONAL,
        //    requestList         SEQUENCE OF Request,
        //    requestExtensions   [2] EXPLICIT Extensions OPTIONAL }
        //
        // Request ::= SEQUENCE {
        //    reqCert                  CertID,
        //    singleRequestExtensions  [0] EXPLICIT Extensions OPTIONAL }
        //
        // CertID ::= SEQUENCE {
        //    hashAlgorithm       AlgorithmIdentifier,
        //    issuerNameHash      OCTET STRING,
        //    issuerKeyHash       OCTET STRING,
        //    serialNumber        CertificateSerialNumber }
        //
        // For now, return a placeholder
        debug!("OCSP request creation (placeholder - not yet fully implemented)");
        Err(EstError::operational(
            "OCSP request creation not yet implemented",
        ))
    }

    /// Send OCSP request and parse response.
    async fn send_ocsp_request(&self, url: &str, request: &[u8]) -> Result<RevocationStatus> {
        debug!("Sending OCSP request to {}", url);

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

        let response_data = response.bytes().await?;

        // Parse OCSP response
        self.parse_ocsp_response(&response_data)
    }

    /// Parse OCSP response.
    fn parse_ocsp_response(&self, _data: &[u8]) -> Result<RevocationStatus> {
        // TODO: Implement actual OCSP response parsing
        // OCSPResponse ::= SEQUENCE {
        //    responseStatus      OCSPResponseStatus,
        //    responseBytes       [0] EXPLICIT ResponseBytes OPTIONAL }
        //
        // OCSPResponseStatus ::= ENUMERATED {
        //    successful          (0),
        //    malformedRequest    (1),
        //    internalError       (2),
        //    tryLater            (3),
        //    sigRequired         (5),
        //    unauthorized        (6) }
        //
        // ResponseBytes ::= SEQUENCE {
        //    responseType        OBJECT IDENTIFIER,
        //    response            OCTET STRING }
        //
        // For BasicOCSPResponse:
        // BasicOCSPResponse ::= SEQUENCE {
        //    tbsResponseData      ResponseData,
        //    signatureAlgorithm   AlgorithmIdentifier,
        //    signature            BIT STRING,
        //    certs                [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
        //
        // ResponseData ::= SEQUENCE {
        //    version              [0] EXPLICIT Version DEFAULT v1,
        //    responderID          ResponderID,
        //    producedAt           GeneralizedTime,
        //    responses            SEQUENCE OF SingleResponse,
        //    responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
        //
        // SingleResponse ::= SEQUENCE {
        //    certID               CertID,
        //    certStatus           CertStatus,
        //    thisUpdate           GeneralizedTime,
        //    nextUpdate           [0] EXPLICIT GeneralizedTime OPTIONAL,
        //    singleExtensions     [1] EXPLICIT Extensions OPTIONAL }
        //
        // CertStatus ::= CHOICE {
        //    good                 [0] IMPLICIT NULL,
        //    revoked              [1] IMPLICIT RevokedInfo,
        //    unknown              [2] IMPLICIT UnknownInfo }
        //
        // For now, return placeholder
        debug!("OCSP response parsing (placeholder - not yet fully implemented)");
        Ok(RevocationStatus::Unknown)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revocation_config_builder() {
        let config = RevocationConfig::builder()
            .enable_crl(true)
            .enable_ocsp(false)
            .crl_cache_duration(Duration::from_secs(7200))
            .fail_on_unknown(true)
            .build();

        assert!(config.enable_crl);
        assert!(!config.enable_ocsp);
        assert_eq!(config.crl_cache_duration, Duration::from_secs(7200));
        assert!(config.fail_on_unknown);
    }

    #[test]
    fn test_revocation_status() {
        assert!(RevocationStatus::Revoked.is_revoked());
        assert!(!RevocationStatus::Valid.is_revoked());
        assert!(RevocationStatus::Valid.is_valid());
        assert!(RevocationStatus::Unknown.is_unknown());
    }

    #[test]
    fn test_default_config() {
        let config = RevocationConfig::default();
        assert!(config.enable_crl);
        assert!(config.enable_ocsp);
        assert!(!config.fail_on_unknown);
    }
}
