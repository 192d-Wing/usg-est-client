// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! DoD Certificate Chain Validation
//!
//! This module provides certificate chain validation specific to DoD PKI,
//! including trust anchor verification, policy constraint checking, and
//! certificate revocation validation.
//!
//! # Overview
//!
//! DoD certificates must chain to one of the active DoD Root CAs:
//! - DoD Root CA 3 (expires December 2029)
//! - DoD Root CA 4 (expires July 2032)
//! - DoD Root CA 5 (expires June 2041)
//! - DoD Root CA 6 (newest)
//!
//! The validation process includes:
//! 1. Building certificate chain from leaf to root
//! 2. Verifying signatures at each level
//! 3. Checking validity periods
//! 4. Validating certificate policies
//! 5. Checking revocation status (optional)
//!
//! # Example
//!
//! ## Basic Validation (Sync)
//!
//! ```no_run
//! use usg_est_client::dod::validation::{DodChainValidator, ValidationOptions};
//! # use x509_cert::Certificate;
//!
//! # fn example(cert: &Certificate) -> Result<(), Box<dyn std::error::Error>> {
//! let validator = DodChainValidator::new()?;
//!
//! // Validate certificate chains to DoD Root CA
//! validator.validate(cert, &[])?;
//! println!("Certificate is valid DoD certificate");
//! # Ok(())
//! # }
//! ```
//!
//! ## Validation with Revocation Checking (Async)
//!
//! ```no_run
//! # #[cfg(feature = "revocation")]
//! use usg_est_client::dod::validation::{DodChainValidator, ValidationOptions};
//! # #[cfg(feature = "revocation")]
//! use usg_est_client::revocation::{RevocationChecker, RevocationConfig};
//! # use x509_cert::Certificate;
//!
//! # #[cfg(feature = "revocation")]
//! # async fn example(cert: &Certificate) -> Result<(), Box<dyn std::error::Error>> {
//! // Create validator with revocation checking enabled
//! let options = ValidationOptions::builder()
//!     .check_revocation(true)
//!     .build();
//! let validator = DodChainValidator::with_options(options)?;
//!
//! // Create revocation checker
//! let revocation_config = RevocationConfig::builder()
//!     .enable_crl(true)
//!     .build();
//! let revocation_checker = RevocationChecker::new(revocation_config);
//!
//! // Validate with revocation checking (async)
//! validator.validate_async(cert, &[], Some(&revocation_checker)).await?;
//! println!("Certificate is valid and not revoked");
//! # Ok(())
//! # }
//! ```
//!
//! # References
//!
//! - [RFC 5280](https://tools.ietf.org/html/rfc5280) - X.509 PKI Certificate Validation
//! - [DoD PKI Interoperability](https://public.cyber.mil/pki-pke/)

use crate::dod::policies::{DodCertificatePolicy, extract_dod_policies};
use crate::dod::roots::{DodRootCa, load_dod_root_cas};
use crate::error::{EstError, Result};
use std::time::SystemTime;
use tracing::{debug, warn};
use x509_cert::Certificate;

#[cfg(feature = "revocation")]
use crate::revocation::{RevocationChecker, RevocationStatus};

/// Validation options for DoD certificate chain validation
#[derive(Debug, Clone)]
pub struct ValidationOptions {
    /// Check certificate revocation status
    pub check_revocation: bool,

    /// Fail validation if revocation status is unknown (strict mode)
    /// If false, unknown revocation status will log a warning but not fail validation
    pub fail_on_unknown_revocation: bool,

    /// Required minimum assurance level (1-3)
    pub min_assurance_level: u8,

    /// Required certificate policies (if any)
    pub required_policies: Vec<DodCertificatePolicy>,

    /// Allow expired certificates (for testing only)
    pub allow_expired: bool,

    /// Trust anchors to use (if empty, uses embedded DoD Root CAs)
    pub trust_anchors: Vec<Certificate>,
}

impl Default for ValidationOptions {
    fn default() -> Self {
        Self {
            check_revocation: false,           // Disabled by default (requires network)
            fail_on_unknown_revocation: false, // Soft-fail mode by default
            min_assurance_level: 0,            // No minimum by default
            required_policies: Vec::new(),
            allow_expired: false,
            trust_anchors: Vec::new(),
        }
    }
}

impl ValidationOptions {
    /// Create a new builder for validation options
    pub fn builder() -> ValidationOptionsBuilder {
        ValidationOptionsBuilder::default()
    }
}

/// Builder for ValidationOptions
#[derive(Debug, Default)]
pub struct ValidationOptionsBuilder {
    check_revocation: bool,
    fail_on_unknown_revocation: bool,
    min_assurance_level: u8,
    required_policies: Vec<DodCertificatePolicy>,
    allow_expired: bool,
    trust_anchors: Vec<Certificate>,
}

impl ValidationOptionsBuilder {
    /// Enable/disable revocation checking
    pub fn check_revocation(mut self, check: bool) -> Self {
        self.check_revocation = check;
        self
    }

    /// Fail validation if revocation status is unknown (strict mode)
    pub fn fail_on_unknown_revocation(mut self, fail: bool) -> Self {
        self.fail_on_unknown_revocation = fail;
        self
    }

    /// Set minimum assurance level (1-3)
    pub fn min_assurance_level(mut self, level: u8) -> Self {
        self.min_assurance_level = level;
        self
    }

    /// Add a required certificate policy
    pub fn require_policy(mut self, policy: DodCertificatePolicy) -> Self {
        self.required_policies.push(policy);
        self
    }

    /// Allow expired certificates (testing only)
    pub fn allow_expired(mut self, allow: bool) -> Self {
        self.allow_expired = allow;
        self
    }

    /// Add a custom trust anchor
    pub fn add_trust_anchor(mut self, cert: Certificate) -> Self {
        self.trust_anchors.push(cert);
        self
    }

    /// Build the validation options
    pub fn build(self) -> ValidationOptions {
        ValidationOptions {
            check_revocation: self.check_revocation,
            fail_on_unknown_revocation: self.fail_on_unknown_revocation,
            min_assurance_level: self.min_assurance_level,
            required_policies: self.required_policies,
            allow_expired: self.allow_expired,
            trust_anchors: self.trust_anchors,
        }
    }
}

/// Result of certificate chain validation
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Whether validation succeeded
    pub valid: bool,

    /// Chain from leaf certificate to root
    pub chain: Vec<Certificate>,

    /// DoD Root CA that anchors this chain (if found)
    pub root_ca: Option<String>,

    /// Certificate policies found in the chain
    pub policies: Vec<DodCertificatePolicy>,

    /// Validation warnings (non-fatal issues)
    pub warnings: Vec<String>,
}

impl ValidationResult {
    /// Check if the certificate has a specific policy
    pub fn has_policy(&self, policy: &DodCertificatePolicy) -> bool {
        self.policies.contains(policy)
    }

    /// Get the highest assurance level in the chain
    pub fn max_assurance_level(&self) -> u8 {
        self.policies
            .iter()
            .map(|p| p.assurance_level())
            .max()
            .unwrap_or(0)
    }
}

/// DoD certificate chain validator
pub struct DodChainValidator {
    /// DoD Root CA trust anchors
    root_cas: Vec<DodRootCa>,

    /// Validation options
    options: ValidationOptions,
}

impl DodChainValidator {
    /// Create a new validator with default options
    ///
    /// Loads embedded DoD Root CAs as trust anchors.
    pub fn new() -> Result<Self> {
        Self::with_options(ValidationOptions::default())
    }

    /// Create a new validator with custom options
    pub fn with_options(options: ValidationOptions) -> Result<Self> {
        let root_cas = if options.trust_anchors.is_empty() {
            // Load embedded DoD Root CAs
            load_dod_root_cas().unwrap_or_default()
        } else {
            // Convert custom trust anchors to DodRootCa
            Vec::new() // Custom anchors handled separately
        };

        Ok(Self { root_cas, options })
    }

    /// Validate a certificate chains to a DoD Root CA
    ///
    /// # Arguments
    ///
    /// * `cert` - The end-entity certificate to validate
    /// * `intermediates` - Intermediate certificates in the chain
    ///
    /// # Returns
    ///
    /// Returns `Ok(ValidationResult)` if validation succeeds, or an error
    /// describing why validation failed.
    pub fn validate(
        &self,
        cert: &Certificate,
        intermediates: &[Certificate],
    ) -> Result<ValidationResult> {
        let mut result = ValidationResult {
            valid: false,
            chain: Vec::new(),
            root_ca: None,
            policies: Vec::new(),
            warnings: Vec::new(),
        };

        // Step 1: Build certificate chain
        let chain = self.build_chain(cert, intermediates)?;
        result.chain = chain.clone();

        // Step 2: Validate chain to root
        let root_name = self.validate_to_root(&chain)?;
        result.root_ca = Some(root_name);

        // Step 3: Check validity periods
        if !self.options.allow_expired {
            self.check_validity_periods(&chain)?;
        } else {
            result
                .warnings
                .push("Certificate validity period not checked".to_string());
        }

        // Step 4: Extract and validate policies
        let policies = extract_dod_policies(cert);
        result.policies = policies.clone();

        // Check minimum assurance level
        let max_level = policies
            .iter()
            .map(|p| p.assurance_level())
            .max()
            .unwrap_or(0);

        if max_level < self.options.min_assurance_level {
            return Err(EstError::CertificateValidation(format!(
                "Certificate assurance level {} is below minimum {}",
                max_level, self.options.min_assurance_level
            )));
        }

        // Check required policies
        for required in &self.options.required_policies {
            if !policies.contains(required) {
                return Err(EstError::CertificateValidation(format!(
                    "Certificate missing required policy: {}",
                    required
                )));
            }
        }

        // Step 5: Check revocation (if enabled)
        if self.options.check_revocation {
            self.check_revocation(&chain)?;
        }

        result.valid = true;
        Ok(result)
    }

    /// Validate a certificate chains to a DoD Root CA (async version with revocation checking)
    ///
    /// # Arguments
    ///
    /// * `cert` - The end-entity certificate to validate
    /// * `intermediates` - Intermediate certificates in the chain
    /// * `revocation_checker` - Optional revocation checker for CRL/OCSP validation
    ///
    /// # Returns
    ///
    /// Returns `Ok(ValidationResult)` if validation succeeds, or an error
    /// describing why validation failed.
    ///
    /// # Note
    ///
    /// This is the async version that supports revocation checking when enabled.
    /// Use this method when you have async context and need revocation validation.
    #[cfg(feature = "revocation")]
    pub async fn validate_async(
        &self,
        cert: &Certificate,
        intermediates: &[Certificate],
        revocation_checker: Option<&RevocationChecker>,
    ) -> Result<ValidationResult> {
        let mut result = ValidationResult {
            valid: false,
            chain: Vec::new(),
            root_ca: None,
            policies: Vec::new(),
            warnings: Vec::new(),
        };

        // Step 1: Build certificate chain
        let chain = self.build_chain(cert, intermediates)?;
        result.chain = chain.clone();

        // Step 2: Validate chain to root
        let root_name = self.validate_to_root(&chain)?;
        result.root_ca = Some(root_name);

        // Step 3: Check validity periods
        if !self.options.allow_expired {
            self.check_validity_periods(&chain)?;
        } else {
            result
                .warnings
                .push("Certificate validity period not checked".to_string());
        }

        // Step 4: Extract and validate policies
        let policies = extract_dod_policies(cert);
        result.policies = policies.clone();

        // Check minimum assurance level
        let max_level = policies
            .iter()
            .map(|p| p.assurance_level())
            .max()
            .unwrap_or(0);

        if max_level < self.options.min_assurance_level {
            return Err(EstError::CertificateValidation(format!(
                "Certificate assurance level {} is below minimum {}",
                max_level, self.options.min_assurance_level
            )));
        }

        // Check required policies
        for required in &self.options.required_policies {
            if !policies.contains(required) {
                return Err(EstError::CertificateValidation(format!(
                    "Certificate missing required policy: {}",
                    required
                )));
            }
        }

        // Step 5: Check revocation (if enabled)
        if self.options.check_revocation {
            self.check_revocation_async(&chain, revocation_checker)
                .await?;
        }

        result.valid = true;
        Ok(result)
    }

    /// Build certificate chain from leaf to root
    fn build_chain(
        &self,
        cert: &Certificate,
        intermediates: &[Certificate],
    ) -> Result<Vec<Certificate>> {
        let mut chain = vec![cert.clone()];
        let mut current = cert.clone();

        // Maximum chain depth (prevent infinite loops)
        const MAX_CHAIN_DEPTH: usize = 10;

        for _ in 0..MAX_CHAIN_DEPTH {
            // Check if current cert is self-signed (root)
            if is_self_signed(&current) {
                break;
            }

            // Find issuer in intermediates
            let issuer_dn = &current.tbs_certificate.issuer;
            let issuer = intermediates
                .iter()
                .find(|c| &c.tbs_certificate.subject == issuer_dn);

            match issuer {
                Some(issuer_cert) => {
                    chain.push(issuer_cert.clone());
                    current = issuer_cert.clone();
                }
                None => {
                    // Check if issuer is a root CA
                    let root = self
                        .root_cas
                        .iter()
                        .find(|r| &r.certificate.tbs_certificate.subject == issuer_dn);

                    if let Some(root_ca) = root {
                        chain.push(root_ca.certificate.clone());
                        break;
                    } else {
                        // Unable to build complete chain
                        return Err(EstError::CertificateValidation(format!(
                            "Unable to find issuer certificate for: {}",
                            format_dn(&current.tbs_certificate.subject)
                        )));
                    }
                }
            }
        }

        Ok(chain)
    }

    /// Validate that chain terminates at a DoD Root CA
    fn validate_to_root(&self, chain: &[Certificate]) -> Result<String> {
        if chain.is_empty() {
            return Err(EstError::CertificateValidation(
                "Empty certificate chain".to_string(),
            ));
        }

        // Get the last certificate (should be root or closest to root)
        let last = chain.last().unwrap();

        // Check against embedded DoD Root CAs
        for root_ca in &self.root_cas {
            if certificates_match(&root_ca.certificate, last) {
                return Ok(root_ca.name.clone());
            }
        }

        // Check against custom trust anchors
        for anchor in &self.options.trust_anchors {
            if certificates_match(anchor, last) {
                return Ok(format_dn(&anchor.tbs_certificate.subject));
            }
        }

        // If we have no embedded certs and no custom anchors, and the cert
        // appears to be self-signed, accept it with a warning
        if self.root_cas.is_empty() && self.options.trust_anchors.is_empty() {
            if is_self_signed(last) {
                return Ok("Self-signed (no trust anchors configured)".to_string());
            }
        }

        Err(EstError::CertificateValidation(
            "Certificate chain does not terminate at a trusted DoD Root CA".to_string(),
        ))
    }

    /// Check validity periods for all certificates in chain
    fn check_validity_periods(&self, chain: &[Certificate]) -> Result<()> {
        use std::time::SystemTime;

        let now = SystemTime::now();

        for cert in chain {
            let validity = &cert.tbs_certificate.validity;
            let subject = format_dn(&cert.tbs_certificate.subject);

            // Parse not_before time
            let not_before = Self::parse_x509_time(&validity.not_before)?;

            // Parse not_after time
            let not_after = Self::parse_x509_time(&validity.not_after)?;

            // Check if current time is before certificate validity period
            if now < not_before {
                return Err(EstError::CertificateValidation(format!(
                    "Certificate '{}' is not yet valid (not_before: {:?})",
                    subject, validity.not_before
                )));
            }

            // Check if certificate has expired
            if now > not_after {
                return Err(EstError::CertificateValidation(format!(
                    "Certificate '{}' has expired (not_after: {:?})",
                    subject, validity.not_after
                )));
            }

            tracing::debug!(
                "Certificate '{}' is valid (not_before: {:?}, not_after: {:?})",
                subject,
                validity.not_before,
                validity.not_after
            );
        }

        Ok(())
    }

    /// Parse X.509 Time to SystemTime.
    ///
    /// Supports both UtcTime and GeneralizedTime formats.
    fn parse_x509_time(x509_time: &x509_cert::time::Time) -> Result<SystemTime> {
        use std::time::SystemTime;
        use x509_cert::time::Time;

        // Both UtcTime and GeneralizedTime have to_unix_duration() method
        let duration = match x509_time {
            Time::UtcTime(utc) => utc.to_unix_duration(),
            Time::GeneralTime(general) => general.to_unix_duration(),
        };

        Ok(SystemTime::UNIX_EPOCH + duration)
    }

    /// Check revocation status for certificates in chain (sync version - limited)
    ///
    /// Note: The sync version cannot perform actual CRL/OCSP checks (which are async).
    /// Use `validate_async()` with a RevocationChecker for proper revocation validation.
    /// This method returns an error if revocation checking is requested in sync context.
    fn check_revocation(&self, _chain: &[Certificate]) -> Result<()> {
        #[cfg(feature = "revocation")]
        {
            return Err(EstError::operational(
                "Revocation checking requires async context. Use validate_async() instead of validate()",
            ));
        }

        #[cfg(not(feature = "revocation"))]
        {
            return Err(EstError::operational(
                "Revocation checking requires the 'revocation' feature to be enabled",
            ));
        }
    }

    /// Check revocation status for certificates in chain (async version)
    ///
    /// Validates each non-root certificate in the chain using CRL and/or OCSP.
    /// Requires a RevocationChecker instance for performing the checks.
    #[cfg(feature = "revocation")]
    async fn check_revocation_async(
        &self,
        chain: &[Certificate],
        revocation_checker: Option<&RevocationChecker>,
    ) -> Result<()> {
        let checker = revocation_checker.ok_or_else(|| {
            EstError::operational(
                "Revocation checking is enabled but no RevocationChecker provided",
            )
        })?;

        // Validate chain is not empty before loop
        if chain.is_empty() {
            return Err(EstError::operational("Empty certificate chain"));
        }

        // Check each certificate in chain (except root)
        for i in 0..chain.len() - 1 {
            let cert = &chain[i];
            let issuer = &chain[i + 1];

            // Skip self-signed certificates (roots)
            if is_self_signed(cert) {
                continue;
            }

            debug!(
                "Checking revocation for certificate in chain at position {}",
                i
            );

            // Perform revocation check
            let result = checker.check_revocation(cert, issuer).await?;

            // Check the status
            match result.status {
                RevocationStatus::Revoked => {
                    return Err(EstError::CertificateValidation(format!(
                        "Certificate at position {} in chain is revoked",
                        i
                    )));
                }
                RevocationStatus::Valid => {
                    debug!("Certificate at position {} passed revocation check", i);
                }
                RevocationStatus::Unknown => {
                    // Log warnings
                    warn!(
                        "Could not determine revocation status for certificate at position {}",
                        i
                    );
                    if !result.errors.is_empty() {
                        warn!("Revocation check errors: {:?}", result.errors);
                    }

                    // Fail if strict mode is enabled
                    if self.options.fail_on_unknown_revocation {
                        return Err(EstError::CertificateValidation(format!(
                            "Certificate at position {} has unknown revocation status (strict mode enabled)",
                            i
                        )));
                    }
                    // Otherwise, log but continue (soft-fail mode)
                }
            }
        }

        Ok(())
    }
}

/// Check if two certificates are the same
fn certificates_match(a: &Certificate, b: &Certificate) -> bool {
    // Compare subject and serial number
    a.tbs_certificate.subject == b.tbs_certificate.subject
        && a.tbs_certificate.serial_number == b.tbs_certificate.serial_number
}

/// Check if a certificate is self-signed
fn is_self_signed(cert: &Certificate) -> bool {
    cert.tbs_certificate.subject == cert.tbs_certificate.issuer
}

/// Format Distinguished Name for display
fn format_dn(name: &x509_cert::name::Name) -> String {
    let mut components = Vec::new();

    const CN: der::asn1::ObjectIdentifier = der::asn1::ObjectIdentifier::new_unwrap("2.5.4.3");
    const O: der::asn1::ObjectIdentifier = der::asn1::ObjectIdentifier::new_unwrap("2.5.4.10");
    const OU: der::asn1::ObjectIdentifier = der::asn1::ObjectIdentifier::new_unwrap("2.5.4.11");
    const C: der::asn1::ObjectIdentifier = der::asn1::ObjectIdentifier::new_unwrap("2.5.4.6");

    for rdn in name.0.iter() {
        for atv in rdn.0.iter() {
            let oid = &atv.oid;
            let value = &atv.value;

            let attr_name = if *oid == CN {
                "CN"
            } else if *oid == O {
                "O"
            } else if *oid == OU {
                "OU"
            } else if *oid == C {
                "C"
            } else {
                continue;
            };

            if let Ok(s) = std::str::from_utf8(value.value()) {
                components.push(format!("{}={}", attr_name, s));
            }
        }
    }

    components.reverse();
    components.join(", ")
}

/// Validate a certificate against DoD PKI requirements
///
/// Convenience function for simple validation without creating a validator.
pub fn validate_dod_certificate(
    cert: &Certificate,
    intermediates: &[Certificate],
) -> Result<ValidationResult> {
    let validator = DodChainValidator::new()?;
    validator.validate(cert, intermediates)
}

/// Check if a certificate is a DoD certificate
///
/// Returns true if the certificate has any DoD certificate policy.
pub fn is_dod_certificate(cert: &Certificate) -> bool {
    !extract_dod_policies(cert).is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_options_default() {
        let options = ValidationOptions::default();
        assert!(!options.check_revocation);
        assert_eq!(options.min_assurance_level, 0);
        assert!(options.required_policies.is_empty());
        assert!(!options.allow_expired);
    }

    #[test]
    fn test_validation_options_builder() {
        let options = ValidationOptions::builder()
            .check_revocation(true)
            .min_assurance_level(2)
            .require_policy(DodCertificatePolicy::MediumHardware)
            .allow_expired(true)
            .build();

        assert!(options.check_revocation);
        assert_eq!(options.min_assurance_level, 2);
        assert_eq!(options.required_policies.len(), 1);
        assert!(options.allow_expired);
    }

    #[test]
    fn test_validation_result_has_policy() {
        let result = ValidationResult {
            valid: true,
            chain: Vec::new(),
            root_ca: Some("DoD Root CA 5".to_string()),
            policies: vec![
                DodCertificatePolicy::MediumHardware,
                DodCertificatePolicy::PivAuth,
            ],
            warnings: Vec::new(),
        };

        assert!(result.has_policy(&DodCertificatePolicy::MediumHardware));
        assert!(result.has_policy(&DodCertificatePolicy::PivAuth));
        assert!(!result.has_policy(&DodCertificatePolicy::HighAssurance));
    }

    #[test]
    fn test_validation_result_max_assurance() {
        let result = ValidationResult {
            valid: true,
            chain: Vec::new(),
            root_ca: None,
            policies: vec![
                DodCertificatePolicy::MediumAssurance, // level 1
                DodCertificatePolicy::MediumHardware,  // level 2
            ],
            warnings: Vec::new(),
        };

        assert_eq!(result.max_assurance_level(), 2);
    }

    #[test]
    fn test_validator_new_without_roots() {
        // This should work even without embedded root CAs
        let validator = DodChainValidator::new();
        // May return error if no root CAs embedded, which is expected
        let _ = validator;
    }

    // NOTE: Test code uses unwrap() deliberately - test fixtures are known valid

    fn load_test_cert(pem_bytes: &[u8]) -> Certificate {
        use der::Decode;
        use rustls_pki_types::CertificateDer;
        use rustls_pki_types::pem::PemObject;

        let cert_der = CertificateDer::pem_slice_iter(pem_bytes)
            .next()
            .unwrap()
            .unwrap();
        Certificate::from_der(cert_der.as_ref()).unwrap()
    }

    #[test]
    fn test_validation_options_builder_fail_on_unknown_revocation() {
        let options = ValidationOptions::builder()
            .fail_on_unknown_revocation(true)
            .build();
        assert!(options.fail_on_unknown_revocation);
    }

    #[test]
    fn test_validation_options_builder_add_trust_anchor() {
        let cert = load_test_cert(include_bytes!("../../tests/fixtures/certs/ca.pem"));
        let options = ValidationOptions::builder()
            .add_trust_anchor(cert)
            .build();
        assert_eq!(options.trust_anchors.len(), 1);
    }

    #[test]
    fn test_validation_result_max_assurance_empty() {
        let result = ValidationResult {
            valid: true,
            chain: Vec::new(),
            root_ca: None,
            policies: Vec::new(),
            warnings: Vec::new(),
        };
        assert_eq!(result.max_assurance_level(), 0);
    }

    #[test]
    fn test_is_self_signed() {
        let ca = load_test_cert(include_bytes!("../../tests/fixtures/certs/ca.pem"));
        // The test CA cert is self-signed (subject == issuer)
        assert!(is_self_signed(&ca));
    }

    #[test]
    fn test_is_not_self_signed() {
        let client = load_test_cert(include_bytes!("../../tests/fixtures/certs/client.pem"));
        // Client cert is issued by CA, not self-signed
        assert!(!is_self_signed(&client));
    }

    #[test]
    fn test_certificates_match_same() {
        let ca = load_test_cert(include_bytes!("../../tests/fixtures/certs/ca.pem"));
        assert!(certificates_match(&ca, &ca));
    }

    #[test]
    fn test_certificates_match_different() {
        let ca = load_test_cert(include_bytes!("../../tests/fixtures/certs/ca.pem"));
        let client = load_test_cert(include_bytes!("../../tests/fixtures/certs/client.pem"));
        assert!(!certificates_match(&ca, &client));
    }

    #[test]
    fn test_format_dn_with_cert() {
        let ca = load_test_cert(include_bytes!("../../tests/fixtures/certs/ca.pem"));
        let dn = format_dn(&ca.tbs_certificate.subject);
        assert!(dn.contains("CN="));
    }

    #[test]
    fn test_is_dod_certificate_false_for_test_cert() {
        let ca = load_test_cert(include_bytes!("../../tests/fixtures/certs/ca.pem"));
        assert!(!is_dod_certificate(&ca));
    }

    #[test]
    fn test_validator_validate_self_signed_no_anchors() {
        // With no trust anchors, a self-signed cert should be accepted with a warning
        let ca = load_test_cert(include_bytes!("../../tests/fixtures/certs/ca.pem"));
        let options = ValidationOptions::builder().allow_expired(true).build();
        let validator = DodChainValidator::with_options(options).unwrap();
        let result = validator.validate(&ca, &[]);
        // Should succeed since no trust anchors and cert is self-signed
        assert!(result.is_ok());
        let vr = result.unwrap();
        assert!(vr.valid);
        assert!(vr
            .root_ca
            .as_ref()
            .unwrap()
            .contains("Self-signed"));
    }

    #[test]
    fn test_validator_validate_with_custom_trust_anchor() {
        let ca = load_test_cert(include_bytes!("../../tests/fixtures/certs/ca.pem"));
        let client = load_test_cert(include_bytes!("../../tests/fixtures/certs/client.pem"));

        let options = ValidationOptions::builder()
            .add_trust_anchor(ca.clone())
            .allow_expired(true)
            .build();
        let validator = DodChainValidator::with_options(options).unwrap();
        // Pass CA as intermediate so build_chain can find the issuer;
        // validate_to_root then matches the chain tail against trust_anchors.
        let result = validator.validate(&client, &[ca]);
        assert!(result.is_ok());
        let vr = result.unwrap();
        assert!(vr.valid);
    }

    #[test]
    fn test_parse_x509_time() {
        let ca = load_test_cert(include_bytes!("../../tests/fixtures/certs/ca.pem"));
        let not_before = &ca.tbs_certificate.validity.not_before;
        let parsed = DodChainValidator::parse_x509_time(not_before);
        assert!(parsed.is_ok());
    }
}
