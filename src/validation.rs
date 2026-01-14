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

//! Certificate chain validation and path building.
//!
//! This module implements RFC 5280 certificate path validation,
//! including chain building, trust anchor verification, and
//! constraint checking.
//!
//! # Example
//!
//! ```no_run
//! use usg_est_client::validation::{CertificateValidator, ValidationConfig};
//! use usg_est_client::Certificate;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Load certificates
//! let end_entity_cert = todo!(); // Your end-entity certificate
//! let intermediates = vec![]; // Intermediate CA certificates
//! let trust_anchors = vec![]; // Trusted root CA certificates
//!
//! // Create validator
//! let validator = CertificateValidator::new(trust_anchors);
//!
//! // Validate certificate chain
//! let result = validator.validate(&end_entity_cert, &intermediates)?;
//!
//! if result.is_valid {
//!     println!("Certificate chain is valid!");
//! }
//! # Ok(())
//! # }
//! ```

use crate::error::{EstError, Result};
use const_oid::ObjectIdentifier;
use der::Decode;
use std::time::SystemTime;
use tracing::{debug, warn};
use x509_cert::Certificate;
use x509_cert::ext::pkix::{
    NameConstraints,
    constraints::name::{GeneralSubtree, GeneralSubtrees},
    name::GeneralName,
};

/// OID for Name Constraints extension (2.5.29.30)
const NAME_CONSTRAINTS_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.30");

/// OID for Policy Constraints extension (2.5.29.36)
const POLICY_CONSTRAINTS_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.36");

/// OID for Certificate Policies extension (2.5.29.32)
const CERTIFICATE_POLICIES_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.32");

/// Accumulated name constraints during chain validation.
#[derive(Debug, Clone, Default)]
struct AccumulatedNameConstraints {
    /// Permitted DNS subtrees
    permitted_dns: Vec<String>,
    /// Excluded DNS subtrees
    excluded_dns: Vec<String>,
    /// Permitted email subtrees
    permitted_email: Vec<String>,
    /// Excluded email subtrees
    excluded_email: Vec<String>,
    /// Permitted URI subtrees
    permitted_uri: Vec<String>,
    /// Excluded URI subtrees
    excluded_uri: Vec<String>,
    /// Permitted directory name subtrees (as DER bytes)
    permitted_dir_names: Vec<Vec<u8>>,
    /// Excluded directory name subtrees (as DER bytes)
    excluded_dir_names: Vec<Vec<u8>>,
    /// Whether any constraints have been set
    has_constraints: bool,
}

/// Configuration for certificate validation.
#[derive(Debug, Clone)]
pub struct ValidationConfig {
    /// Maximum chain length (default: 10).
    pub max_chain_length: usize,

    /// Whether to check certificate revocation (CRL/OCSP).
    pub check_revocation: bool,

    /// Whether to enforce name constraints.
    pub enforce_name_constraints: bool,

    /// Whether to enforce policy constraints.
    pub enforce_policy_constraints: bool,

    /// Allow expired certificates (for testing only).
    pub allow_expired: bool,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            max_chain_length: 10,
            check_revocation: false,
            enforce_name_constraints: true,
            enforce_policy_constraints: true,
            allow_expired: false,
        }
    }
}

/// Result of certificate validation.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Whether the certificate is valid.
    pub is_valid: bool,

    /// The validated certificate chain (from end-entity to root).
    pub chain: Vec<Certificate>,

    /// Validation errors encountered.
    pub errors: Vec<String>,

    /// Validation warnings (non-fatal issues).
    pub warnings: Vec<String>,
}

/// Certificate path validator.
///
/// Implements RFC 5280 certificate path validation algorithm.
pub struct CertificateValidator {
    /// Trusted root CA certificates.
    trust_anchors: Vec<Certificate>,

    /// Validation configuration.
    config: ValidationConfig,
}

impl CertificateValidator {
    /// Create a new certificate validator with trusted root CAs.
    pub fn new(trust_anchors: Vec<Certificate>) -> Self {
        Self {
            trust_anchors,
            config: ValidationConfig::default(),
        }
    }

    /// Create a validator with custom configuration.
    pub fn with_config(trust_anchors: Vec<Certificate>, config: ValidationConfig) -> Self {
        Self {
            trust_anchors,
            config,
        }
    }

    /// Validate a certificate chain.
    ///
    /// # Arguments
    ///
    /// * `end_entity` - The end-entity certificate to validate
    /// * `intermediates` - Optional intermediate CA certificates
    ///
    /// # Returns
    ///
    /// A `ValidationResult` indicating whether the chain is valid.
    pub fn validate(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
    ) -> Result<ValidationResult> {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        debug!("Starting certificate path validation");

        // Step 1: Build the certificate chain
        let chain = match self.build_chain(end_entity, intermediates) {
            Ok(chain) => chain,
            Err(e) => {
                errors.push(format!("Failed to build certificate chain: {}", e));
                return Ok(ValidationResult {
                    is_valid: false,
                    chain: vec![],
                    errors,
                    warnings,
                });
            }
        };

        debug!("Built certificate chain with {} certificates", chain.len());

        // Step 2: Verify chain length
        if chain.is_empty() {
            return Err(EstError::operational("Empty certificate chain"));
        }

        if chain.len() > self.config.max_chain_length {
            errors.push(format!(
                "Certificate chain too long ({} > {})",
                chain.len(),
                self.config.max_chain_length
            ));
        }

        // Step 3: Verify each certificate in the chain
        // Accumulate name constraints from CA certificates (RFC 5280 Section 6.1)
        let mut accumulated_constraints = AccumulatedNameConstraints::default();
        // Policy state for policy constraints checking
        let mut require_explicit_policy: Option<usize> = None;
        let mut inhibit_policy_mapping: Option<usize> = None;

        for (i, cert) in chain.iter().enumerate() {
            debug!("Validating certificate {}/{}", i + 1, chain.len());

            // Check expiration
            if !self.config.allow_expired
                && let Err(e) = self.check_validity_period(cert)
            {
                errors.push(format!("Certificate {} invalid: {}", i, e));
            }

            // Check basic constraints
            if i > 0 {
                // Not the end-entity cert
                if let Err(e) = self.check_basic_constraints(cert) {
                    errors.push(format!("Certificate {} basic constraints: {}", i, e));
                }
            }

            // Check name constraints (if enabled)
            if self.config.enforce_name_constraints {
                // Apply accumulated name constraints to this certificate
                if i == 0 && accumulated_constraints.has_constraints {
                    // Check end-entity against accumulated constraints
                    if let Err(e) =
                        self.check_name_against_constraints(cert, &accumulated_constraints)
                    {
                        errors.push(format!(
                            "Certificate {} name constraints violation: {}",
                            i, e
                        ));
                    }
                }

                // Accumulate constraints from CA certificates for checking subordinate certs
                if i > 0
                    && let Err(e) =
                        self.accumulate_name_constraints(cert, &mut accumulated_constraints)
                {
                    errors.push(format!("Certificate {} invalid name constraints: {}", i, e));
                }
            }

            // Check policy constraints (if enabled)
            if self.config.enforce_policy_constraints {
                // Update policy constraint counters
                if let Some(ref mut counter) = require_explicit_policy
                    && *counter > 0
                {
                    *counter -= 1;
                }
                if let Some(ref mut counter) = inhibit_policy_mapping
                    && *counter > 0
                {
                    *counter -= 1;
                }

                // Parse and apply policy constraints from this certificate
                if let Err(e) = self.process_policy_constraints(
                    cert,
                    i,
                    &mut require_explicit_policy,
                    &mut inhibit_policy_mapping,
                    &mut errors,
                ) {
                    errors.push(format!("Certificate {} policy constraints error: {}", i, e));
                }
            }
        }

        // Step 4: Verify signatures along the chain
        for i in 0..chain.len() - 1 {
            if let Err(e) = self.verify_signature(&chain[i], &chain[i + 1]) {
                errors.push(format!(
                    "Signature verification failed for certificate {}: {}",
                    i, e
                ));
            }
        }

        // Step 5: Verify root certificate is trusted
        if let Some(root) = chain.last()
            && !self.is_trusted_root(root)
        {
            errors.push("Root certificate is not in trust store".to_string());
        }

        // Step 6: Check revocation status (if enabled)
        if self.config.check_revocation {
            warnings.push("Revocation checking not yet implemented".to_string());
        }

        let is_valid = errors.is_empty();

        Ok(ValidationResult {
            is_valid,
            chain,
            errors,
            warnings,
        })
    }

    /// Build a certificate chain from end-entity to root.
    fn build_chain(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
    ) -> Result<Vec<Certificate>> {
        let mut chain = vec![end_entity.clone()];
        let mut current = end_entity;

        // Build chain up to root
        for _ in 0..self.config.max_chain_length {
            if self.is_self_signed(current) {
                // Reached root
                break;
            }

            // Find issuer in intermediates or trust anchors
            let issuer = self
                .find_issuer(current, intermediates)
                .or_else(|| self.find_issuer_in_trust_anchors(current))
                .ok_or_else(|| EstError::operational("Could not find certificate issuer"))?;

            chain.push(issuer.clone());
            current = &chain[chain.len() - 1];
        }

        Ok(chain)
    }

    /// Find the issuer of a certificate in the provided set.
    fn find_issuer(&self, cert: &Certificate, candidates: &[Certificate]) -> Option<Certificate> {
        let issuer_dn = &cert.tbs_certificate.issuer;

        for candidate in candidates {
            let subject_dn = &candidate.tbs_certificate.subject;
            if subject_dn == issuer_dn {
                return Some(candidate.clone());
            }
        }

        None
    }

    /// Find the issuer in trust anchors.
    fn find_issuer_in_trust_anchors(&self, cert: &Certificate) -> Option<Certificate> {
        self.find_issuer(cert, &self.trust_anchors)
    }

    /// Check if a certificate is self-signed.
    fn is_self_signed(&self, cert: &Certificate) -> bool {
        let subject = &cert.tbs_certificate.subject;
        let issuer = &cert.tbs_certificate.issuer;
        subject == issuer
    }

    /// Check if a certificate is a trusted root.
    fn is_trusted_root(&self, cert: &Certificate) -> bool {
        self.trust_anchors.iter().any(|anchor| {
            // Compare by public key or serial number
            anchor.tbs_certificate.subject_public_key_info
                == cert.tbs_certificate.subject_public_key_info
        })
    }

    /// Check certificate validity period.
    fn check_validity_period(&self, cert: &Certificate) -> Result<()> {
        let now = SystemTime::now();
        let validity = &cert.tbs_certificate.validity;

        // Parse not_before time
        let not_before = Self::parse_time(&validity.not_before)?;
        if now < not_before {
            return Err(EstError::operational(format!(
                "Certificate not yet valid (not before: {:?})",
                not_before
            )));
        }

        // Parse not_after time
        let not_after = Self::parse_time(&validity.not_after)?;
        if now > not_after {
            return Err(EstError::operational(format!(
                "Certificate has expired (not after: {:?})",
                not_after
            )));
        }

        debug!("Certificate validity period check passed");
        Ok(())
    }

    /// Parse X.509 Time to SystemTime.
    fn parse_time(time: &x509_cert::time::Time) -> Result<SystemTime> {
        use der::DateTime;
        use std::time::Duration;
        use x509_cert::time::Time;

        let datetime: DateTime = match time {
            Time::UtcTime(utc) => (*utc).into(),
            Time::GeneralTime(general) => (*general).into(),
        };

        // Convert to SystemTime
        // DateTime is in format: YYYYMMDDhhmmssZ
        let year = datetime.year() as i64;
        let month = datetime.month() as u64;
        let day = datetime.day() as u64;
        let hour = datetime.hour() as u64;
        let minute = datetime.minutes() as u64;
        let second = datetime.seconds() as u64;

        // Calculate seconds since UNIX_EPOCH (1970-01-01)
        // This is a simplified calculation that doesn't account for leap years/seconds
        let mut days_since_epoch: i64 = 0;

        // Count years (accounting for leap years)
        for y in 1970..year {
            days_since_epoch += if Self::is_leap_year(y) { 366 } else { 365 };
        }

        // Count months in current year
        const DAYS_IN_MONTH: [u64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        for m in 1..month {
            days_since_epoch += DAYS_IN_MONTH[(m - 1) as usize] as i64;
            // Add leap day if February and leap year
            if m == 2 && Self::is_leap_year(year) {
                days_since_epoch += 1;
            }
        }

        // Add remaining days
        days_since_epoch += (day - 1) as i64;

        // Convert to seconds
        let seconds_since_epoch =
            days_since_epoch * 86400 + (hour * 3600 + minute * 60 + second) as i64;

        if seconds_since_epoch < 0 {
            return Err(EstError::operational(format!(
                "Invalid certificate time (before UNIX epoch): {}",
                seconds_since_epoch
            )));
        }

        Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(seconds_since_epoch as u64))
    }

    /// Check if a year is a leap year.
    fn is_leap_year(year: i64) -> bool {
        (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
    }

    /// Check basic constraints extension.
    fn check_basic_constraints(&self, cert: &Certificate) -> Result<()> {
        use der::Decode;
        use x509_cert::ext::pkix::BasicConstraints;

        // Look for basic constraints extension
        if let Some(extensions) = &cert.tbs_certificate.extensions {
            for ext in extensions.iter() {
                // Basic Constraints OID: 2.5.29.19
                let basic_constraints_oid = const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS;

                if ext.extn_id == basic_constraints_oid {
                    // Parse the Basic Constraints extension
                    match BasicConstraints::from_der(ext.extn_value.as_bytes()) {
                        Ok(bc) => {
                            // Verify cA flag is true for CA certificates
                            if !bc.ca {
                                return Err(EstError::operational(
                                    "CA certificate has cA flag set to FALSE in Basic Constraints",
                                ));
                            }

                            // Check pathLenConstraint if present
                            if let Some(path_len) = bc.path_len_constraint {
                                debug!("CA certificate has path length constraint: {}", path_len);
                                // Note: Path length validation should be enforced during
                                // chain building, not just at this check point
                            }

                            debug!("CA certificate has valid Basic Constraints (cA=TRUE)");
                            return Ok(());
                        }
                        Err(e) => {
                            return Err(EstError::operational(format!(
                                "Failed to parse Basic Constraints extension: {}",
                                e
                            )));
                        }
                    }
                }
            }
        }

        // RFC 5280 Section 4.2.1.9: Basic Constraints extension MUST appear
        // in all CA certificates
        warn!("CA certificate missing Basic Constraints extension");
        Err(EstError::operational(
            "CA certificate missing required Basic Constraints extension",
        ))
    }

    /// Verify certificate signature.
    fn verify_signature(&self, cert: &Certificate, issuer: &Certificate) -> Result<()> {
        use der::Encode;

        // Get the signature algorithm from the certificate
        let sig_alg = &cert.signature_algorithm;
        let sig_alg_oid = &sig_alg.oid;

        // Get the issuer's public key
        let issuer_spki = &issuer.tbs_certificate.subject_public_key_info;
        let pub_key_alg = &issuer_spki.algorithm.oid;

        debug!(
            "Verifying signature with algorithm {:?} using key algorithm {:?}",
            sig_alg_oid, pub_key_alg
        );

        // Encode the TBSCertificate to get the data that was signed
        let tbs_bytes = cert.tbs_certificate.to_der().map_err(|e| {
            EstError::operational(format!("Failed to encode TBS certificate: {}", e))
        })?;

        // Get the signature bytes
        let signature = cert.signature.as_bytes().ok_or_else(|| {
            EstError::operational("Certificate signature has unused bits (not byte-aligned)")
        })?;

        // Verify the signature based on the algorithm
        // RSA with SHA-256: 1.2.840.113549.1.1.11
        // RSA with SHA-384: 1.2.840.113549.1.1.12
        // RSA with SHA-512: 1.2.840.113549.1.1.13
        // ECDSA with SHA-256: 1.2.840.10045.4.3.2
        // ECDSA with SHA-384: 1.2.840.10045.4.3.3
        // ECDSA with SHA-512: 1.2.840.10045.4.3.4

        const RSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
        const RSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
        const RSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
        const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
        const ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
        const ECDSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");

        // Perform cryptographic signature verification
        match *sig_alg_oid {
            RSA_SHA256 | RSA_SHA384 | RSA_SHA512 => {
                self.verify_rsa_signature(&tbs_bytes, signature, *sig_alg_oid, issuer_spki)?;
                debug!("RSA signature verified successfully");
                Ok(())
            }
            ECDSA_SHA256 | ECDSA_SHA384 | ECDSA_SHA512 => {
                self.verify_ecdsa_signature(&tbs_bytes, signature, *sig_alg_oid, issuer_spki)?;
                debug!("ECDSA signature verified successfully");
                Ok(())
            }
            _ => {
                warn!("Unsupported signature algorithm: {:?}", sig_alg_oid);
                Err(EstError::operational(format!(
                    "Unsupported signature algorithm: {}",
                    sig_alg_oid
                )))
            }
        }
    }

    /// Verify RSA signature.
    fn verify_rsa_signature(
        &self,
        tbs_bytes: &[u8],
        signature: &[u8],
        alg_oid: ObjectIdentifier,
        issuer_spki: &spki::SubjectPublicKeyInfoOwned,
    ) -> Result<()> {
        use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey};
        use rsa::signature::Verifier;
        use sha2::{Sha256, Sha384, Sha512};

        const RSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
        const RSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
        const RSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");

        // Parse the RSA public key from SPKI
        // Extract the public key bytes
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
                    "Unexpected RSA algorithm OID: {}",
                    alg_oid
                )));
            }
        }

        Ok(())
    }

    /// Verify ECDSA signature.
    fn verify_ecdsa_signature(
        &self,
        tbs_bytes: &[u8],
        signature: &[u8],
        alg_oid: ObjectIdentifier,
        issuer_spki: &spki::SubjectPublicKeyInfoOwned,
    ) -> Result<()> {
        use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
        use p384::ecdsa::{Signature as P384Signature, VerifyingKey as P384VerifyingKey};
        use sha2::{Digest, Sha256, Sha384};
        use signature::Verifier;

        const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
        const ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
        const ECDSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");

        // Parse the EC public key
        let public_key_bytes = issuer_spki
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| EstError::operational("Public key has unused bits"))?;

        match alg_oid {
            ECDSA_SHA256 => {
                // P-256 curve
                let verifying_key =
                    P256VerifyingKey::from_sec1_bytes(public_key_bytes).map_err(|e| {
                        EstError::operational(format!("Failed to parse P-256 public key: {}", e))
                    })?;

                let sig = P256Signature::from_der(signature).map_err(|e| {
                    EstError::operational(format!("Invalid ECDSA signature: {}", e))
                })?;

                // Hash the TBS data
                let hash = Sha256::digest(tbs_bytes);

                verifying_key.verify(&hash, &sig).map_err(|e| {
                    EstError::operational(format!(
                        "ECDSA-SHA256 signature verification failed: {}",
                        e
                    ))
                })?;
            }
            ECDSA_SHA384 => {
                // P-384 curve
                let verifying_key =
                    P384VerifyingKey::from_sec1_bytes(public_key_bytes).map_err(|e| {
                        EstError::operational(format!("Failed to parse P-384 public key: {}", e))
                    })?;

                let sig = P384Signature::from_der(signature).map_err(|e| {
                    EstError::operational(format!("Invalid ECDSA signature: {}", e))
                })?;

                // Hash the TBS data
                let hash = Sha384::digest(tbs_bytes);

                verifying_key.verify(&hash, &sig).map_err(|e| {
                    EstError::operational(format!(
                        "ECDSA-SHA384 signature verification failed: {}",
                        e
                    ))
                })?;
            }
            ECDSA_SHA512 => {
                // P-521 would require p521 crate, not yet supported
                return Err(EstError::operational(
                    "ECDSA with SHA-512 (P-521) not yet supported",
                ));
            }
            _ => {
                return Err(EstError::operational(format!(
                    "Unexpected ECDSA algorithm OID: {}",
                    alg_oid
                )));
            }
        }

        Ok(())
    }

    /// Accumulate name constraints from a CA certificate.
    ///
    /// Per RFC 5280 Section 6.1.4, name constraints from CA certificates
    /// are accumulated and applied to all certificates issued by that CA.
    fn accumulate_name_constraints(
        &self,
        cert: &Certificate,
        accumulated: &mut AccumulatedNameConstraints,
    ) -> Result<()> {
        let Some(extensions) = &cert.tbs_certificate.extensions else {
            return Ok(());
        };

        for ext in extensions.iter() {
            if ext.extn_id == NAME_CONSTRAINTS_OID {
                debug!("Found name constraints extension");

                // Parse the NameConstraints extension
                let nc = NameConstraints::from_der(ext.extn_value.as_bytes()).map_err(|e| {
                    EstError::operational(format!("Failed to parse name constraints: {}", e))
                })?;

                // Process permitted subtrees
                if let Some(permitted) = &nc.permitted_subtrees {
                    self.add_subtrees_to_accumulated(permitted, accumulated, true);
                }

                // Process excluded subtrees
                if let Some(excluded) = &nc.excluded_subtrees {
                    self.add_subtrees_to_accumulated(excluded, accumulated, false);
                }

                accumulated.has_constraints = true;
            }
        }

        Ok(())
    }

    /// Add subtrees from a GeneralSubtrees to accumulated constraints.
    fn add_subtrees_to_accumulated(
        &self,
        subtrees: &GeneralSubtrees,
        accumulated: &mut AccumulatedNameConstraints,
        is_permitted: bool,
    ) {
        for subtree in subtrees.iter() {
            self.add_subtree_to_accumulated(subtree, accumulated, is_permitted);
        }
    }

    /// Add a single GeneralSubtree to accumulated constraints.
    fn add_subtree_to_accumulated(
        &self,
        subtree: &GeneralSubtree,
        accumulated: &mut AccumulatedNameConstraints,
        is_permitted: bool,
    ) {
        use der::Encode;

        match &subtree.base {
            GeneralName::DnsName(dns) => {
                let dns_str = dns.to_string();
                if is_permitted {
                    accumulated.permitted_dns.push(dns_str);
                } else {
                    accumulated.excluded_dns.push(dns_str);
                }
            }
            GeneralName::Rfc822Name(email) => {
                let email_str = email.to_string();
                if is_permitted {
                    accumulated.permitted_email.push(email_str);
                } else {
                    accumulated.excluded_email.push(email_str);
                }
            }
            GeneralName::UniformResourceIdentifier(uri) => {
                let uri_str = uri.to_string();
                if is_permitted {
                    accumulated.permitted_uri.push(uri_str);
                } else {
                    accumulated.excluded_uri.push(uri_str);
                }
            }
            GeneralName::DirectoryName(dn) => {
                // Store as DER for comparison
                if let Ok(der_bytes) = dn.to_der() {
                    if is_permitted {
                        accumulated.permitted_dir_names.push(der_bytes);
                    } else {
                        accumulated.excluded_dir_names.push(der_bytes);
                    }
                }
            }
            _ => {
                debug!("Ignoring unsupported GeneralName type in name constraints");
            }
        }
    }

    /// Check if a certificate's names comply with accumulated name constraints.
    fn check_name_against_constraints(
        &self,
        cert: &Certificate,
        constraints: &AccumulatedNameConstraints,
    ) -> Result<()> {
        use der::Encode;

        // Check subject DN against directory name constraints
        if !constraints.permitted_dir_names.is_empty() || !constraints.excluded_dir_names.is_empty()
        {
            let subject_der =
                cert.tbs_certificate.subject.to_der().map_err(|e| {
                    EstError::operational(format!("Failed to encode subject: {}", e))
                })?;

            // Check excluded first (exclusion takes precedence per RFC 5280)
            for excluded in &constraints.excluded_dir_names {
                if self.dn_is_within_subtree(&subject_der, excluded) {
                    return Err(EstError::operational(
                        "Subject DN matches excluded name constraint",
                    ));
                }
            }

            // Check permitted (if any permitted are specified, subject must match one)
            if !constraints.permitted_dir_names.is_empty() {
                let mut found_permitted = false;
                for permitted in &constraints.permitted_dir_names {
                    if self.dn_is_within_subtree(&subject_der, permitted) {
                        found_permitted = true;
                        break;
                    }
                }
                if !found_permitted {
                    return Err(EstError::operational(
                        "Subject DN does not match any permitted name constraint",
                    ));
                }
            }
        }

        // Check Subject Alternative Name extension for DNS, email, and URI constraints
        if let Some(extensions) = &cert.tbs_certificate.extensions {
            let san_oid = ObjectIdentifier::new_unwrap("2.5.29.17");

            for ext in extensions.iter() {
                if ext.extn_id == san_oid {
                    // Parse SAN and check each name
                    self.check_san_against_constraints(ext.extn_value.as_bytes(), constraints)?;
                }
            }
        }

        Ok(())
    }

    /// Check if a DN is within a subtree (simplified: checks for prefix match).
    fn dn_is_within_subtree(&self, subject_der: &[u8], subtree_der: &[u8]) -> bool {
        // Simplified check: for DN constraints, we check if the subject
        // has the subtree as a suffix (i.e., the subtree is a base DN)
        // A proper implementation would parse and compare RDN by RDN
        subject_der.ends_with(subtree_der) || subject_der == subtree_der || subtree_der.is_empty()
    }

    /// Check Subject Alternative Name against constraints.
    fn check_san_against_constraints(
        &self,
        san_bytes: &[u8],
        constraints: &AccumulatedNameConstraints,
    ) -> Result<()> {
        use x509_cert::ext::pkix::SubjectAltName;

        let san = SubjectAltName::from_der(san_bytes)
            .map_err(|e| EstError::operational(format!("Failed to parse SAN: {}", e)))?;

        for name in san.0.iter() {
            match name {
                GeneralName::DnsName(dns) => {
                    let dns_str = dns.to_string();
                    self.check_dns_constraint(&dns_str, constraints)?;
                }
                GeneralName::Rfc822Name(email) => {
                    let email_str = email.to_string();
                    self.check_email_constraint(&email_str, constraints)?;
                }
                GeneralName::UniformResourceIdentifier(uri) => {
                    let uri_str = uri.to_string();
                    self.check_uri_constraint(&uri_str, constraints)?;
                }
                _ => {
                    // Other name types not constrained by our current implementation
                }
            }
        }

        Ok(())
    }

    /// Check a DNS name against DNS constraints.
    fn check_dns_constraint(
        &self,
        dns: &str,
        constraints: &AccumulatedNameConstraints,
    ) -> Result<()> {
        // Check excluded first
        for excluded in &constraints.excluded_dns {
            if self.dns_matches_constraint(dns, excluded) {
                return Err(EstError::operational(format!(
                    "DNS name '{}' matches excluded constraint '{}'",
                    dns, excluded
                )));
            }
        }

        // Check permitted (if any specified)
        if !constraints.permitted_dns.is_empty() {
            let mut found = false;
            for permitted in &constraints.permitted_dns {
                if self.dns_matches_constraint(dns, permitted) {
                    found = true;
                    break;
                }
            }
            if !found {
                return Err(EstError::operational(format!(
                    "DNS name '{}' does not match any permitted constraint",
                    dns
                )));
            }
        }

        Ok(())
    }

    /// Check if a DNS name matches a constraint (supports wildcards).
    ///
    /// Per RFC 5280 Section 4.2.1.10:
    /// - A name matches if it is a subdomain (labels separated by dots)
    /// - Constraint ".example.com" matches "www.example.com" but NOT "evilexample.com"
    /// - Exact matches are also allowed
    fn dns_matches_constraint(&self, dns: &str, constraint: &str) -> bool {
        let dns_lower = dns.to_lowercase();
        let constraint_lower = constraint.to_lowercase();

        // If constraint starts with '.', it's a domain suffix constraint
        if let Some(suffix) = constraint_lower.strip_prefix('.') {
            // Must either be exact match to suffix, or end with the full constraint including the dot
            // This ensures label boundary: "www.example.com" matches ".example.com"
            // but "evilexample.com" does NOT match ".example.com"
            dns_lower == suffix || dns_lower.ends_with(&format!(".{}", suffix))
        } else {
            // No leading dot: constraint is for exact domain or its subdomains
            // "example.com" matches itself and "www.example.com" but not "evilexample.com"
            if dns_lower == constraint_lower {
                return true;
            }
            // Check if it's a subdomain: must end with ".<constraint>"
            // This ensures we have a label boundary (the dot)
            dns_lower.ends_with(&format!(".{}", constraint_lower))
        }
    }

    /// Check an email address against email constraints.
    fn check_email_constraint(
        &self,
        email: &str,
        constraints: &AccumulatedNameConstraints,
    ) -> Result<()> {
        // Check excluded first
        for excluded in &constraints.excluded_email {
            if self.email_matches_constraint(email, excluded) {
                return Err(EstError::operational(format!(
                    "Email '{}' matches excluded constraint '{}'",
                    email, excluded
                )));
            }
        }

        // Check permitted
        if !constraints.permitted_email.is_empty() {
            let mut found = false;
            for permitted in &constraints.permitted_email {
                if self.email_matches_constraint(email, permitted) {
                    found = true;
                    break;
                }
            }
            if !found {
                return Err(EstError::operational(format!(
                    "Email '{}' does not match any permitted constraint",
                    email
                )));
            }
        }

        Ok(())
    }

    /// Check if an email matches a constraint.
    fn email_matches_constraint(&self, email: &str, constraint: &str) -> bool {
        let email_lower = email.to_lowercase();
        let constraint_lower = constraint.to_lowercase();

        // Constraint can be:
        // 1. Full email address (exact match)
        // 2. Domain (matches @domain)
        // 3. .domain (matches @subdomain.domain)

        if constraint_lower.contains('@') {
            // Full email address - exact match
            email_lower == constraint_lower
        } else if let Some(suffix) = constraint_lower.strip_prefix('.') {
            // Domain suffix
            email_lower.ends_with(&constraint_lower)
                || email_lower.ends_with(&format!("@{}", suffix))
        } else {
            // Domain - matches @domain exactly
            email_lower.ends_with(&format!("@{}", constraint_lower))
        }
    }

    /// Check a URI against URI constraints.
    fn check_uri_constraint(
        &self,
        uri: &str,
        constraints: &AccumulatedNameConstraints,
    ) -> Result<()> {
        // Check excluded first
        for excluded in &constraints.excluded_uri {
            if self.uri_matches_constraint(uri, excluded) {
                return Err(EstError::operational(format!(
                    "URI '{}' matches excluded constraint '{}'",
                    uri, excluded
                )));
            }
        }

        // Check permitted
        if !constraints.permitted_uri.is_empty() {
            let mut found = false;
            for permitted in &constraints.permitted_uri {
                if self.uri_matches_constraint(uri, permitted) {
                    found = true;
                    break;
                }
            }
            if !found {
                return Err(EstError::operational(format!(
                    "URI '{}' does not match any permitted constraint",
                    uri
                )));
            }
        }

        Ok(())
    }

    /// Check if a URI matches a constraint (host-based matching).
    fn uri_matches_constraint(&self, uri: &str, constraint: &str) -> bool {
        // Extract host from URI
        let uri_host = uri
            .strip_prefix("http://")
            .or_else(|| uri.strip_prefix("https://"))
            .and_then(|s| s.split('/').next())
            .unwrap_or(uri);

        self.dns_matches_constraint(uri_host, constraint)
    }

    /// Process policy constraints from a certificate.
    fn process_policy_constraints(
        &self,
        cert: &Certificate,
        cert_index: usize,
        require_explicit_policy: &mut Option<usize>,
        inhibit_policy_mapping: &mut Option<usize>,
        errors: &mut Vec<String>,
    ) -> Result<()> {
        let Some(extensions) = &cert.tbs_certificate.extensions else {
            return Ok(());
        };

        // Check for Policy Constraints extension
        for ext in extensions.iter() {
            if ext.extn_id == POLICY_CONSTRAINTS_OID {
                debug!(
                    "Found policy constraints extension in certificate {}",
                    cert_index
                );

                // Parse policy constraints manually (TLV format)
                // PolicyConstraints ::= SEQUENCE {
                //   requireExplicitPolicy [0] SkipCerts OPTIONAL,
                //   inhibitPolicyMapping  [1] SkipCerts OPTIONAL
                // }
                let bytes = ext.extn_value.as_bytes();
                self.parse_policy_constraints(
                    bytes,
                    require_explicit_policy,
                    inhibit_policy_mapping,
                )?;
            }

            // Check for Certificate Policies extension when explicit policy is required
            if ext.extn_id == CERTIFICATE_POLICIES_OID
                && let Some(0) = require_explicit_policy
            {
                // We've reached a certificate where explicit policy is required
                // and it has certificate policies - this is valid
                debug!(
                    "Certificate {} has required certificate policies",
                    cert_index
                );
            }
        }

        // If require_explicit_policy counter reached 0, certificate must have policies
        if let Some(0) = require_explicit_policy {
            let has_policies = extensions
                .iter()
                .any(|ext| ext.extn_id == CERTIFICATE_POLICIES_OID);

            if !has_policies {
                errors.push(format!(
                    "Certificate {} is missing required certificate policies",
                    cert_index
                ));
            }
        }

        Ok(())
    }

    /// Parse Policy Constraints extension from DER bytes.
    fn parse_policy_constraints(
        &self,
        bytes: &[u8],
        require_explicit_policy: &mut Option<usize>,
        inhibit_policy_mapping: &mut Option<usize>,
    ) -> Result<()> {
        // PolicyConstraints is a SEQUENCE containing optional tagged integers
        if bytes.is_empty() || bytes[0] != 0x30 {
            return Err(EstError::operational(
                "Invalid policy constraints: not a SEQUENCE",
            ));
        }

        let (_, content) = self.parse_tlv(bytes)?;
        let mut pos = 0;

        while pos < content.len() {
            let tag = content[pos];
            let (len, value) = self.parse_tlv(&content[pos..])?;
            let total_len = if len < 128 { 2 + len } else { 3 + len };

            match tag {
                0x80 => {
                    // [0] requireExplicitPolicy
                    if !value.is_empty() {
                        let skip_certs = value[0] as usize;
                        *require_explicit_policy = Some(skip_certs);
                        debug!("requireExplicitPolicy: {}", skip_certs);
                    }
                }
                0x81 => {
                    // [1] inhibitPolicyMapping
                    if !value.is_empty() {
                        let skip_certs = value[0] as usize;
                        *inhibit_policy_mapping = Some(skip_certs);
                        debug!("inhibitPolicyMapping: {}", skip_certs);
                    }
                }
                _ => {
                    debug!("Unknown policy constraints tag: 0x{:02x}", tag);
                }
            }

            pos += total_len;
        }

        Ok(())
    }

    /// Parse a TLV (Tag-Length-Value) structure and return (length, value).
    fn parse_tlv<'a>(&self, bytes: &'a [u8]) -> Result<(usize, &'a [u8])> {
        if bytes.len() < 2 {
            return Err(EstError::operational("TLV too short"));
        }

        let _tag = bytes[0];
        let len_byte = bytes[1];

        let (len, header_len) = if len_byte < 128 {
            (len_byte as usize, 2)
        } else if len_byte == 0x81 {
            if bytes.len() < 3 {
                return Err(EstError::operational("TLV length field truncated"));
            }
            (bytes[2] as usize, 3)
        } else if len_byte == 0x82 {
            if bytes.len() < 4 {
                return Err(EstError::operational("TLV length field truncated"));
            }
            (((bytes[2] as usize) << 8) | (bytes[3] as usize), 4)
        } else {
            return Err(EstError::operational("Unsupported TLV length encoding"));
        };

        if bytes.len() < header_len + len {
            return Err(EstError::operational("TLV value truncated"));
        }

        Ok((len, &bytes[header_len..header_len + len]))
    }
}

/// Helper function to extract common name from certificate subject.
pub fn get_subject_cn(cert: &Certificate) -> Option<String> {
    use const_oid::db::rfc4519::CN;

    for rdn in cert.tbs_certificate.subject.0.iter() {
        for atv in rdn.0.iter() {
            if atv.oid == CN
                && let Ok(s) = std::str::from_utf8(atv.value.value())
            {
                return Some(s.to_string());
            }
        }
    }
    None
}

/// Helper function to check if a certificate is a CA certificate.
///
/// Parses the Basic Constraints extension and checks if the cA flag is TRUE.
pub fn is_ca_certificate(cert: &Certificate) -> bool {
    use der::Decode;
    use x509_cert::ext::pkix::BasicConstraints;

    if let Some(extensions) = &cert.tbs_certificate.extensions {
        for ext in extensions.iter() {
            let basic_constraints_oid = const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS;
            if ext.extn_id == basic_constraints_oid {
                // Parse Basic Constraints and check cA flag
                if let Ok(bc) = BasicConstraints::from_der(ext.extn_value.as_bytes()) {
                    return bc.ca;
                }
                // If parsing fails, assume not a CA
                return false;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_config_default() {
        let config = ValidationConfig::default();
        assert_eq!(config.max_chain_length, 10);
        assert!(!config.check_revocation);
        assert!(config.enforce_name_constraints);
        assert!(config.enforce_policy_constraints);
        assert!(!config.allow_expired);
    }

    #[test]
    fn test_validation_result_structure() {
        let result = ValidationResult {
            is_valid: true,
            chain: vec![],
            errors: vec![],
            warnings: vec![],
        };

        assert!(result.is_valid);
        assert!(result.errors.is_empty());
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn test_dns_constraint_matching() {
        let validator = CertificateValidator::new(vec![]);

        // Exact match
        assert!(validator.dns_matches_constraint("example.com", "example.com"));

        // Subdomain match
        assert!(validator.dns_matches_constraint("sub.example.com", "example.com"));
        assert!(validator.dns_matches_constraint("deep.sub.example.com", "example.com"));

        // Dot-prefixed constraint (domain suffix)
        assert!(validator.dns_matches_constraint("sub.example.com", ".example.com"));
        assert!(validator.dns_matches_constraint("example.com", ".example.com"));

        // Case insensitive
        assert!(validator.dns_matches_constraint("EXAMPLE.COM", "example.com"));
        assert!(validator.dns_matches_constraint("example.com", "EXAMPLE.COM"));

        // Non-matches
        assert!(!validator.dns_matches_constraint("example.org", "example.com"));
        assert!(!validator.dns_matches_constraint("notexample.com", "example.com"));
    }

    #[test]
    fn test_email_constraint_matching() {
        let validator = CertificateValidator::new(vec![]);

        // Exact email match
        assert!(validator.email_matches_constraint("user@example.com", "user@example.com"));

        // Domain match
        assert!(validator.email_matches_constraint("user@example.com", "example.com"));
        assert!(validator.email_matches_constraint("other@example.com", "example.com"));

        // Dot-prefixed domain suffix
        assert!(validator.email_matches_constraint("user@sub.example.com", ".example.com"));

        // Case insensitive
        assert!(validator.email_matches_constraint("USER@EXAMPLE.COM", "example.com"));

        // Non-matches
        assert!(!validator.email_matches_constraint("user@other.com", "example.com"));
        assert!(!validator.email_matches_constraint("user@notexample.com", "example.com"));
    }

    #[test]
    fn test_uri_constraint_matching() {
        let validator = CertificateValidator::new(vec![]);

        // HTTP URI matching
        assert!(validator.uri_matches_constraint("http://example.com/path", "example.com"));
        assert!(validator.uri_matches_constraint("https://example.com/path", "example.com"));

        // Subdomain matching
        assert!(validator.uri_matches_constraint("https://sub.example.com/path", "example.com"));

        // Dot-prefixed constraint
        assert!(validator.uri_matches_constraint("https://sub.example.com/", ".example.com"));

        // Non-matches
        assert!(!validator.uri_matches_constraint("https://other.com/", "example.com"));
    }

    #[test]
    fn test_accumulated_name_constraints() {
        let mut acc = AccumulatedNameConstraints::default();

        assert!(!acc.has_constraints);
        assert!(acc.permitted_dns.is_empty());
        assert!(acc.excluded_dns.is_empty());

        acc.permitted_dns.push("example.com".to_string());
        acc.excluded_dns.push("bad.example.com".to_string());
        acc.has_constraints = true;

        assert!(acc.has_constraints);
        assert_eq!(acc.permitted_dns.len(), 1);
        assert_eq!(acc.excluded_dns.len(), 1);
    }

    #[test]
    fn test_dns_constraint_checking() {
        let validator = CertificateValidator::new(vec![]);
        let mut constraints = AccumulatedNameConstraints::default();

        // With no constraints, everything should pass
        assert!(
            validator
                .check_dns_constraint("anything.com", &constraints)
                .is_ok()
        );

        // Add permitted constraint
        constraints.permitted_dns.push("example.com".to_string());

        // Matching DNS should pass
        assert!(
            validator
                .check_dns_constraint("example.com", &constraints)
                .is_ok()
        );
        assert!(
            validator
                .check_dns_constraint("sub.example.com", &constraints)
                .is_ok()
        );

        // Non-matching DNS should fail
        assert!(
            validator
                .check_dns_constraint("other.com", &constraints)
                .is_err()
        );

        // Add excluded constraint
        constraints.excluded_dns.push("bad.example.com".to_string());

        // Excluded should fail even if permitted matches
        assert!(
            validator
                .check_dns_constraint("bad.example.com", &constraints)
                .is_err()
        );
        assert!(
            validator
                .check_dns_constraint("sub.bad.example.com", &constraints)
                .is_err()
        );
    }

    #[test]
    fn test_email_constraint_checking() {
        let validator = CertificateValidator::new(vec![]);
        let mut constraints = AccumulatedNameConstraints::default();

        // Add permitted domain
        constraints.permitted_email.push("example.com".to_string());

        // Matching emails should pass
        assert!(
            validator
                .check_email_constraint("user@example.com", &constraints)
                .is_ok()
        );

        // Non-matching should fail
        assert!(
            validator
                .check_email_constraint("user@other.com", &constraints)
                .is_err()
        );

        // Add excluded email
        constraints
            .excluded_email
            .push("blocked@example.com".to_string());

        // Excluded email should fail
        assert!(
            validator
                .check_email_constraint("blocked@example.com", &constraints)
                .is_err()
        );
    }

    #[test]
    fn test_parse_tlv() {
        let validator = CertificateValidator::new(vec![]);

        // Simple TLV: tag=0x02 (INTEGER), length=0x01, value=0x05
        let simple = [0x02, 0x01, 0x05];
        let (len, value) = validator.parse_tlv(&simple).unwrap();
        assert_eq!(len, 1);
        assert_eq!(value, &[0x05]);

        // Long form length (1 byte): tag=0x04, length=0x81 0x80 (128 bytes)
        let mut long_form = vec![0x04, 0x81, 0x80];
        long_form.extend(vec![0x00; 128]);
        let (len, value) = validator.parse_tlv(&long_form).unwrap();
        assert_eq!(len, 128);
        assert_eq!(value.len(), 128);

        // Too short should error
        let too_short = [0x02];
        assert!(validator.parse_tlv(&too_short).is_err());
    }

    #[test]
    fn test_dn_is_within_subtree() {
        let validator = CertificateValidator::new(vec![]);

        // Exact match
        let subject = vec![0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
        let subtree = vec![0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
        assert!(validator.dn_is_within_subtree(&subject, &subtree));

        // Suffix match (subject ends with subtree)
        let subject = vec![
            0x30, 0x0A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
        ];
        let subtree = vec![0x06, 0x07, 0x08, 0x09, 0x0A];
        assert!(validator.dn_is_within_subtree(&subject, &subtree));

        // Empty subtree matches everything
        assert!(validator.dn_is_within_subtree(&subject, &[]));

        // Non-match
        let subtree = vec![0xFF, 0xFF];
        assert!(!validator.dn_is_within_subtree(&subject, &subtree));
    }
}
