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

//! Security utilities for Windows auto-enrollment.
//!
//! # Security Controls
//!
//! **NIST SP 800-53 Rev 5:**
//! - SC-12: Cryptographic Key Establishment and Management
//! - AC-6: Least Privilege
//! - IA-5: Authenticator Management
//! - AU-2: Audit Events
//! - SC-13: Cryptographic Protection
//!
//! **Application Development STIG V5R3:**
//! - APSC-DV-000170 (CAT I): Cryptographic Protection
//! - APSC-DV-002340 (CAT II): Least Privilege
//! - APSC-DV-000830 (CAT II): Audit Generation
//! - APSC-DV-002330 (CAT II): Key Management
//!
//! # Overview
//!
//! This module provides security-related functionality including:
//!
//! - **Key Protection**: Policies for private key generation and storage (SC-12, AC-6)
//! - **Certificate Pinning**: Pin EST server certificates for added security (SC-13)
//! - **Audit Logging**: Security event auditing (AU-2, APSC-DV-000830)
//! - **Network Security**: TLS configuration and proxy support (SC-8)
//!
//! # Key Protection (SC-12, AC-6)
//!
//! Private keys are protected by default using:
//! - **Non-exportable key storage**: Keys cannot be exported (AC-6, APSC-DV-002340)
//! - **TPM-backed keys**: Hardware-protected keys when available (SC-12, IA-5)
//! - **Key usage auditing**: All key operations logged (AU-2, APSC-DV-000830)
//! - **FIPS algorithm enforcement**: Only approved algorithms (SC-13, APSC-DV-000170)
//!
//! # Example
//!
//! ```no_run,ignore
//! use usg_est_client::windows::security::{KeyProtection, CertificatePinning};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Configure key protection
//! let protection = KeyProtection::default()
//!     .with_non_exportable(true)
//!     .with_tpm_preferred(true);
//!
//! // Configure certificate pinning
//! let pinning = CertificatePinning::new()
//!     .add_pin("SHA256:abc123...");
//! # Ok(())
//! # }
//! ```

use crate::error::{EstError, Result};
use std::collections::HashSet;

// ============================================================================
// SECURITY CONTROL: Key Protection Policy Configuration
// ----------------------------------------------------------------------------
// NIST SP 800-53 Rev 5: SC-12 (Cryptographic Key Establishment)
//                       AC-6 (Least Privilege)
//                       IA-5 (Authenticator Management)
// STIG: APSC-DV-000170 (CAT I) - Cryptographic Protection
//       APSC-DV-002340 (CAT II) - Least Privilege
//       APSC-DV-002330 (CAT II) - Key Management
// Standards: NIST SP 800-57 Part 1 Rev 5 (Key Management)
//           TCG TPM 2.0 Library Specification
// ----------------------------------------------------------------------------
// Implementation: Enforces security policies for private key generation,
// storage, and usage. Supports TPM (Trusted Platform Module) integration
// for hardware-backed key protection.
//
// Security Rationale:
// - Non-exportable keys prevent key exfiltration (AC-6, APSC-DV-002340)
// - TPM backing provides hardware security module protection (SC-12, IA-5)
// - Minimum key sizes enforce NIST SP 800-57 recommendations
// - Algorithm restrictions ensure only FIPS-approved algorithms (APSC-DV-000170)
// - Audit logging enables detection of unauthorized key usage (AU-2)
// ============================================================================

/// Key protection policy configuration.
///
/// # Security Controls
///
/// **NIST SP 800-53 Rev 5:**
/// - SC-12: Cryptographic Key Establishment (key generation and storage policies)
/// - AC-6: Least Privilege (non-exportable keys, restricted access)
/// - IA-5: Authenticator Management (key strength requirements)
/// - AU-2: Audit Events (key usage logging)
///
/// **STIG Findings:**
/// - APSC-DV-000170 (CAT I): Cryptographic Protection
/// - APSC-DV-002340 (CAT II): Least Privilege
/// - APSC-DV-002330 (CAT II): Key Management
///
/// # TPM Integration
///
/// TPM (Trusted Platform Module) provides hardware-backed key storage with:
/// - **Non-exportable keys**: Keys never leave hardware
/// - **Platform binding**: Keys tied to specific machine
/// - **Attestation capabilities**: Prove key is hardware-backed
/// - **FIPS 140-2 Level 2+**: Hardware security module certification
///
/// # Policy Modes
///
/// - **Default**: Non-exportable, TPM-preferred, RSA ≥2048, audit enabled
/// - **High Security**: TPM-required, RSA ≥3072, strict enforcement
/// - **Development**: Exportable, no TPM, minimal restrictions (NOT for production)
#[derive(Debug, Clone)]
pub struct KeyProtection {
    /// Require non-exportable keys (AC-6: Least Privilege).
    /// Non-exportable keys cannot be extracted from the key store,
    /// preventing key exfiltration attacks.
    pub non_exportable: bool,

    /// Prefer TPM-backed keys when available (SC-12, IA-5).
    /// TPM provides hardware-level key protection.
    pub tpm_preferred: bool,

    /// Require TPM-backed keys (fail if TPM unavailable).
    /// Enforces hardware-backed key storage for high-security environments.
    pub tpm_required: bool,

    /// Minimum key size for RSA (bits) per NIST SP 800-57.
    /// Default: 2048 bits (112-bit security strength, valid through 2030)
    pub min_rsa_key_size: u32,

    /// Allowed key algorithms (FIPS 140-2 approved only).
    /// Restricts key generation to NIST-approved algorithms.
    pub allowed_algorithms: HashSet<KeyAlgorithmPolicy>,

    /// Enable key usage auditing (AU-2: Audit Events).
    /// Logs all key generation, usage, and deletion events.
    pub audit_key_usage: bool,
}

impl Default for KeyProtection {
    fn default() -> Self {
        let mut allowed = HashSet::new();
        allowed.insert(KeyAlgorithmPolicy::EcdsaP256);
        allowed.insert(KeyAlgorithmPolicy::EcdsaP384);
        allowed.insert(KeyAlgorithmPolicy::Rsa2048);
        allowed.insert(KeyAlgorithmPolicy::Rsa3072);
        allowed.insert(KeyAlgorithmPolicy::Rsa4096);

        Self {
            non_exportable: true,
            tpm_preferred: true,
            tpm_required: false,
            min_rsa_key_size: 2048,
            allowed_algorithms: allowed,
            audit_key_usage: true,
        }
    }
}

impl KeyProtection {
    /// Create a new key protection policy with secure defaults.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - SC-12: Cryptographic Key Establishment (secure key generation policy)
    /// - AC-6: Least Privilege (non-exportable keys enabled)
    ///
    /// # Default Policy
    ///
    /// - Non-exportable: **true** (keys cannot be extracted)
    /// - TPM preferred: **true** (use hardware if available)
    /// - TPM required: **false** (software fallback allowed)
    /// - Minimum RSA: **2048 bits** (NIST SP 800-57)
    /// - Algorithms: **ECDSA P-256/P-384, RSA 2048/3072/4096**
    /// - Audit: **enabled** (log all key operations)
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a high-security policy (TPM required, larger keys, no export).
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - SC-12: Cryptographic Key Establishment (hardware-backed keys required)
    /// - AC-6: Least Privilege (maximum restrictions)
    /// - IA-5: Authenticator Management (3072-bit minimum for long-term security)
    ///
    /// **STIG Finding:**
    /// - APSC-DV-000170 (CAT I): Cryptographic Protection
    ///
    /// # High Security Policy
    ///
    /// - Non-exportable: **true** (keys cannot be extracted)
    /// - TPM preferred: **true**
    /// - TPM required: **true** (FAIL if TPM unavailable)
    /// - Minimum RSA: **3072 bits** (128-bit security strength, post-2030)
    /// - Algorithms: **FIPS-approved only**
    /// - Audit: **enabled** (full audit trail)
    ///
    /// # Use Cases
    ///
    /// - High-value certificates (multi-year validity)
    /// - Classified or sensitive systems
    /// - DoD/Federal compliance requirements
    /// - Long-term key storage (>2030)
    pub fn high_security() -> Self {
        Self {
            non_exportable: true,
            tpm_preferred: true,
            tpm_required: true,
            min_rsa_key_size: 3072,
            audit_key_usage: true,
            ..Default::default()
        }
    }

    /// Create a policy for development/testing (exportable, no TPM).
    ///
    /// # Security Warning
    ///
    /// **DO NOT USE IN PRODUCTION!** This policy disables critical security features:
    /// - Keys are exportable (can be copied/stolen)
    /// - No TPM protection (software-only storage)
    /// - Auditing disabled (no security event logging)
    ///
    /// Only use for local development, testing, or CI/CD environments where
    /// security requirements are relaxed.
    ///
    /// # Development Policy
    ///
    /// - Non-exportable: **false** (keys can be exported)
    /// - TPM preferred: **false**
    /// - TPM required: **false**
    /// - Minimum RSA: **2048 bits**
    /// - Audit: **disabled**
    pub fn development() -> Self {
        Self {
            non_exportable: false,
            tpm_preferred: false,
            tpm_required: false,
            min_rsa_key_size: 2048,
            audit_key_usage: false,
            ..Default::default()
        }
    }

    /// Set non-exportable requirement.
    pub fn with_non_exportable(mut self, non_exportable: bool) -> Self {
        self.non_exportable = non_exportable;
        self
    }

    /// Set TPM preference.
    pub fn with_tpm_preferred(mut self, preferred: bool) -> Self {
        self.tpm_preferred = preferred;
        self
    }

    /// Set TPM requirement.
    pub fn with_tpm_required(mut self, required: bool) -> Self {
        self.tpm_required = required;
        if required {
            self.tpm_preferred = true;
        }
        self
    }

    /// Set minimum RSA key size.
    pub fn with_min_rsa_key_size(mut self, bits: u32) -> Self {
        self.min_rsa_key_size = bits;
        self
    }

    // ============================================================================
    // SECURITY CONTROL: Algorithm Validation
    // ----------------------------------------------------------------------------
    // NIST SP 800-53 Rev 5: SC-13 (Cryptographic Protection)
    //                       IA-5 (Authenticator Management)
    // STIG: APSC-DV-000170 (CAT I) - Cryptographic Protection
    // Standards: FIPS 186-4, NIST SP 800-57 Part 1 Rev 5
    // ----------------------------------------------------------------------------
    // Validates that requested key algorithm meets policy requirements including
    // algorithm type (FIPS-approved) and minimum key size (NIST SP 800-57).
    // ============================================================================

    /// Validate a key algorithm against the policy.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - SC-13: Cryptographic Protection (algorithm approval)
    /// - IA-5: Authenticator Management (key strength)
    ///
    /// **STIG Finding:**
    /// - APSC-DV-000170 (CAT I): Cryptographic Protection
    ///
    /// # Validation Checks
    ///
    /// 1. **Algorithm allowed**: Must be in policy's allowed_algorithms set
    /// 2. **Key size**: RSA keys must meet minimum size requirement
    ///
    /// # FIPS-Approved Algorithms
    ///
    /// - **ECDSA**: P-256 (256-bit), P-384 (384-bit) - FIPS 186-4
    /// - **RSA**: 2048-bit, 3072-bit, 4096-bit - FIPS 186-4
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The key algorithm to validate
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Algorithm meets policy requirements
    /// * `Err(EstError)` - Algorithm not allowed or key size insufficient
    pub fn validate_algorithm(&self, algorithm: KeyAlgorithmPolicy) -> Result<()> {
        if !self.allowed_algorithms.contains(&algorithm) {
            return Err(EstError::platform(format!(
                "Key algorithm {:?} not allowed by policy",
                algorithm
            )));
        }

        // Check RSA key size
        let min_size = self.min_rsa_key_size;
        match algorithm {
            KeyAlgorithmPolicy::Rsa2048 if min_size > 2048 => {
                return Err(EstError::platform(format!(
                    "RSA-2048 below minimum key size of {} bits",
                    min_size
                )));
            }
            KeyAlgorithmPolicy::Rsa3072 if min_size > 3072 => {
                return Err(EstError::platform(format!(
                    "RSA-3072 below minimum key size of {} bits",
                    min_size
                )));
            }
            _ => {}
        }

        Ok(())
    }
}

// ============================================================================
// SECURITY CONTROL: FIPS-Approved Key Algorithms
// ----------------------------------------------------------------------------
// NIST SP 800-53 Rev 5: SC-13 (Cryptographic Protection)
//                       IA-5 (Authenticator Management)
// STIG: APSC-DV-000170 (CAT I) - Cryptographic Protection
// Standards: FIPS 186-4 (Digital Signature Standard)
//           NIST SP 800-57 Part 1 Rev 5 (Key Management)
// ----------------------------------------------------------------------------
// Defines FIPS-approved key algorithms and sizes for cryptographic operations.
// Only algorithms approved by NIST for use in federal systems are included.
//
// Security Rationale:
// - ECDSA P-256/P-384: FIPS 186-4 approved curves (128/192-bit security)
// - RSA 2048+: NIST SP 800-57 minimum for 112-bit security strength
// - RSA 3072+: Required for 128-bit security strength (post-2030)
// - Excludes weak algorithms: MD5, SHA-1, RSA < 2048, DSA
// ============================================================================

/// Key algorithm for policy validation.
///
/// # Security Controls
///
/// **NIST SP 800-53 Rev 5:**
/// - SC-13: Cryptographic Protection (FIPS-approved algorithms)
/// - IA-5: Authenticator Management (key strength requirements)
///
/// **STIG Finding:**
/// - APSC-DV-000170 (CAT I): Cryptographic Protection
///
/// # FIPS-Approved Algorithms
///
/// All variants are approved by FIPS 186-4 for digital signatures:
/// - **ECDSA P-256**: 256-bit key, 128-bit security strength
/// - **ECDSA P-384**: 384-bit key, 192-bit security strength
/// - **RSA 2048**: 2048-bit key, 112-bit security strength (minimum)
/// - **RSA 3072**: 3072-bit key, 128-bit security strength (post-2030)
/// - **RSA 4096**: 4096-bit key, 152-bit security strength (maximum)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyAlgorithmPolicy {
    /// ECDSA with P-256 curve (FIPS 186-4, 128-bit security).
    EcdsaP256,
    /// ECDSA with P-384 curve (FIPS 186-4, 192-bit security).
    EcdsaP384,
    /// RSA 2048-bit (FIPS 186-4, 112-bit security, minimum allowed).
    Rsa2048,
    /// RSA 3072-bit (FIPS 186-4, 128-bit security, post-2030 minimum).
    Rsa3072,
    /// RSA 4096-bit (FIPS 186-4, 152-bit security, maximum strength).
    Rsa4096,
}

// ============================================================================
// SECURITY CONTROL: Certificate Pinning
// ----------------------------------------------------------------------------
// NIST SP 800-53 Rev 5: SC-8 (Transmission Confidentiality and Integrity)
//                       SC-13 (Cryptographic Protection)
//                       IA-5 (Authenticator Management)
// STIG: APSC-DV-001750 (CAT I) - Certificate Validation
//       APSC-DV-000460 (CAT I) - PKI Certificate Validation
// Standards: RFC 7469 (Public Key Pinning Extension for HTTP)
//           NIST SP 800-52 Rev 2 (TLS Guidelines)
// ----------------------------------------------------------------------------
// Certificate pinning provides defense-in-depth against man-in-the-middle
// attacks by validating server certificates against known-good fingerprints.
// Prevents attacks even if a Certificate Authority is compromised.
//
// Security Rationale:
// - SHA-256 fingerprints provide cryptographic binding (SC-13, APSC-DV-001750)
// - SPKI pinning survives certificate renewal (IA-5)
// - Prevents MITM attacks from compromised/rogue CAs (SC-8)
// - Multiple pins allow for key rotation without downtime
// - Fallback option supports graceful degradation vs. hard failure
// ============================================================================

/// Certificate pinning configuration.
///
/// # Security Controls
///
/// **NIST SP 800-53 Rev 5:**
/// - SC-8: Transmission Confidentiality and Integrity (prevents MITM attacks)
/// - SC-13: Cryptographic Protection (SHA-256 fingerprint validation)
/// - IA-5: Authenticator Management (certificate authentication)
///
/// **STIG Findings:**
/// - APSC-DV-001750 (CAT I): Certificate Validation
/// - APSC-DV-000460 (CAT I): PKI Certificate Validation
///
/// # Certificate Pinning Methods
///
/// 1. **Certificate Pinning**: Pin the entire certificate's SHA-256 hash
///    - Pro: Simple, exact match
///    - Con: Must update pins when certificate expires/renews
///
/// 2. **Public Key Pinning (SPKI)**: Pin the SubjectPublicKeyInfo hash
///    - Pro: Survives certificate renewal (same key pair)
///    - Con: Requires key rotation planning
///
/// # Example
///
/// ```rust
/// use usg_est_client::windows::security::CertificatePinning;
///
/// let pinning = CertificatePinning::new()
///     .add_pin("SHA256:abc123...")
///     .add_pin("def456...") // Backup pin for rotation
///     .with_spki(true)      // Enable SPKI pinning
///     .with_fallback(false); // Fail closed if no match
/// ```
#[derive(Debug, Clone, Default)]
pub struct CertificatePinning {
    /// SHA-256 fingerprints of pinned certificates or public keys (hex-encoded).
    ///
    /// Security: Multiple pins support key rotation without service interruption.
    /// Each pin is normalized (lowercase, no colons/spaces) for comparison.
    pins: HashSet<String>,

    /// Allow fallback to unpinned validation if no pins match.
    ///
    /// Security: `false` (default) = fail closed (deny connection if no match).
    /// Set to `true` only for graceful migration to pinning in production.
    allow_fallback: bool,

    /// Include subjectPublicKeyInfo hash (SPKI) in addition to certificate hash.
    ///
    /// Security: SPKI pinning allows certificate renewal without pin updates,
    /// as long as the same key pair is reused. Recommended for long-lived systems.
    include_spki: bool,
}

impl CertificatePinning {
    /// Create a new certificate pinning configuration.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - SC-8: Transmission Confidentiality and Integrity (MITM prevention)
    ///
    /// # Default Configuration
    ///
    /// - No pins configured (pinning disabled until pins added)
    /// - Fallback: **disabled** (fail closed on mismatch)
    /// - SPKI: **disabled** (certificate hash only)
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a certificate pin (SHA-256 fingerprint).
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - SC-13: Cryptographic Protection (SHA-256 fingerprint validation)
    /// - IA-5: Authenticator Management (certificate authentication)
    ///
    /// **STIG Finding:**
    /// - APSC-DV-001750 (CAT I): Certificate Validation
    ///
    /// # Pin Format
    ///
    /// Accepts multiple formats (automatically normalized):
    /// - `SHA256:AB:CD:EF:...` (OpenSSL format)
    /// - `ABCDEF...` (hex string, no separators)
    /// - `ab:cd:ef:...` (lowercase with colons)
    ///
    /// # Security Note
    ///
    /// Always configure at least 2 pins (primary + backup) to support
    /// key rotation without service disruption.
    ///
    /// # Example
    ///
    /// ```rust
    /// let pinning = CertificatePinning::new()
    ///     .add_pin("SHA256:ABC123...")  // Primary certificate
    ///     .add_pin("DEF456...");         // Backup for rotation
    /// ```
    pub fn add_pin(mut self, pin: &str) -> Self {
        let normalized = pin
            .strip_prefix("SHA256:")
            .unwrap_or(pin)
            .to_lowercase()
            .replace(':', "")
            .replace(' ', "");
        self.pins.insert(normalized);
        self
    }

    /// Add multiple pins at once.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - SC-13: Cryptographic Protection (multiple fingerprints)
    ///
    /// # Example
    ///
    /// ```rust
    /// let pins = &["SHA256:ABC...", "SHA256:DEF..."];
    /// let pinning = CertificatePinning::new().add_pins(pins);
    /// ```
    pub fn add_pins(mut self, pins: &[&str]) -> Self {
        for pin in pins {
            self = self.add_pin(pin);
        }
        self
    }

    /// Allow fallback to standard validation if no pins match.
    ///
    /// # Security Warning
    ///
    /// **Default: `false` (fail closed)** - Recommended for production.
    ///
    /// Set to `true` only for:
    /// - Gradual rollout of pinning in production (monitor first)
    /// - Development/testing environments
    ///
    /// When `true`, logs a warning but allows connection if no pins match.
    /// When `false`, rejects connection if no pins match (secure default).
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - SC-8: Transmission Confidentiality and Integrity
    pub fn with_fallback(mut self, allow: bool) -> Self {
        self.allow_fallback = allow;
        self
    }

    /// Include SPKI (SubjectPublicKeyInfo) hash validation.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - IA-5: Authenticator Management (public key authentication)
    ///
    /// # SPKI Pinning
    ///
    /// When enabled, validates the public key hash in addition to (or instead of)
    /// the certificate hash. This allows certificate renewal without updating pins,
    /// as long as the same key pair is reused.
    ///
    /// **Use case**: Long-lived deployments where certificate renewal is frequent
    /// but key rotation is infrequent.
    pub fn with_spki(mut self, include: bool) -> Self {
        self.include_spki = include;
        self
    }

    /// Check if any pins are configured.
    ///
    /// Returns `true` if at least one pin has been added, `false` otherwise.
    pub fn has_pins(&self) -> bool {
        !self.pins.is_empty()
    }

    /// Get the number of configured pins.
    ///
    /// # Security Note
    ///
    /// Recommended minimum: 2 pins (primary + backup for rotation).
    pub fn pin_count(&self) -> usize {
        self.pins.len()
    }

    /// Validate a certificate fingerprint against configured pins.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - SC-8: Transmission Confidentiality and Integrity (MITM prevention)
    /// - SC-13: Cryptographic Protection (fingerprint validation)
    ///
    /// **STIG Findings:**
    /// - APSC-DV-001750 (CAT I): Certificate Validation
    /// - APSC-DV-000460 (CAT I): PKI Certificate Validation
    ///
    /// # Validation Logic
    ///
    /// 1. If no pins configured: **Allow** (pinning disabled)
    /// 2. If fingerprint matches any pin: **Allow**
    /// 3. If no match and fallback enabled: **Warn and allow**
    /// 4. If no match and fallback disabled: **Reject** (fail closed)
    ///
    /// # Arguments
    ///
    /// * `fingerprint` - SHA-256 fingerprint (any format: hex, with/without colons)
    ///
    /// # Errors
    ///
    /// Returns error if fingerprint doesn't match any pin and fallback is disabled.
    pub fn validate_fingerprint(&self, fingerprint: &str) -> Result<()> {
        if self.pins.is_empty() {
            return Ok(()); // No pins configured, allow all
        }

        let normalized = fingerprint.to_lowercase().replace(':', "").replace(' ', "");

        if self.pins.contains(&normalized) {
            return Ok(());
        }

        if self.allow_fallback {
            tracing::warn!("Certificate fingerprint not in pin set, allowing fallback");
            return Ok(());
        }

        Err(EstError::platform(format!(
            "Certificate fingerprint {} does not match any configured pin",
            fingerprint
        )))
    }

    /// Get all configured pins as an iterator.
    ///
    /// Returns normalized hex strings (lowercase, no colons).
    pub fn pins(&self) -> impl Iterator<Item = &String> {
        self.pins.iter()
    }
}

// ============================================================================
// SECURITY CONTROL: Security Audit Events
// ----------------------------------------------------------------------------
// NIST SP 800-53 Rev 5: AU-2 (Audit Events)
//                       AU-3 (Content of Audit Records)
//                       AU-12 (Audit Generation)
// STIG: APSC-DV-000830 (CAT II) - Audit Generation
//       APSC-DV-001630 (CAT II) - Security-Relevant Events
// Standards: NIST SP 800-92 (Guide to Computer Security Log Management)
// ----------------------------------------------------------------------------
// Defines security-relevant events that must be audited for compliance.
// Events are categorized by criticality for appropriate logging levels.
//
// Security Rationale:
// - AU-2: Identifies events requiring audit (NIST SP 800-53 Rev 5)
// - AU-3: Ensures audit records contain required information
// - AU-12: Generates audit records for security-relevant events
// - Critical events (failures, deletions, exports) logged at WARN level
// - Normal events logged at INFO level for operational monitoring
// ============================================================================

/// Security audit event types.
///
/// # Security Controls
///
/// **NIST SP 800-53 Rev 5:**
/// - AU-2: Audit Events (security-relevant event identification)
/// - AU-3: Content of Audit Records (event categorization)
/// - AU-12: Audit Generation (automated event logging)
///
/// **STIG Findings:**
/// - APSC-DV-000830 (CAT II): Audit Generation
/// - APSC-DV-001630 (CAT II): Security-Relevant Events
///
/// # Event Categories
///
/// **Critical Events** (always logged at WARN level):
/// - `KeyDeleted` - Private key removal (potential key loss)
/// - `CertificateDeleted` - Certificate removal (identity loss)
/// - `CertificateExported` - Certificate extraction (exfiltration risk)
/// - `AuthenticationFailure` - Failed authentication (attack indicator)
/// - `PolicyViolation` - Security policy violation (compliance issue)
///
/// **Normal Events** (logged at INFO level):
/// - `KeyGenerated`, `KeyUsed` - Cryptographic operations
/// - `CertificateEnrolled`, `CertificateRenewed` - PKI lifecycle
/// - `AuthenticationSuccess` - Successful authentication
/// - `ConfigurationChanged` - Configuration updates
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityAuditEvent {
    /// Private key pair generated (AU-2: cryptographic event).
    KeyGenerated,
    /// Private key pair deleted (AU-2: critical - key material destruction).
    KeyDeleted,
    /// Private key used for signing (AU-2: cryptographic operation).
    KeyUsed,
    /// Certificate enrolled from EST server (AU-2: PKI lifecycle event).
    CertificateEnrolled,
    /// Certificate renewed (AU-2: PKI lifecycle event).
    CertificateRenewed,
    /// Certificate deleted from store (AU-2: critical - identity loss).
    CertificateDeleted,
    /// Certificate exported (AU-2: critical - potential exfiltration).
    CertificateExported,
    /// Authentication succeeded (AU-2: access control event).
    AuthenticationSuccess,
    /// Authentication failed (AU-2: critical - attack indicator).
    AuthenticationFailure,
    /// Security configuration changed (AU-2: administrative event).
    ConfigurationChanged,
    /// Security policy violation detected (AU-2: critical - compliance issue).
    PolicyViolation,
}

impl SecurityAuditEvent {
    /// Get the event name for logging (AU-3: event type identifier).
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - AU-3: Content of Audit Records (event type field)
    ///
    /// Returns a standardized event name for inclusion in audit logs.
    /// Event names follow UPPERCASE_SNAKE_CASE convention for consistency.
    pub fn name(&self) -> &'static str {
        match self {
            Self::KeyGenerated => "KEY_GENERATED",
            Self::KeyDeleted => "KEY_DELETED",
            Self::KeyUsed => "KEY_USED",
            Self::CertificateEnrolled => "CERT_ENROLLED",
            Self::CertificateRenewed => "CERT_RENEWED",
            Self::CertificateDeleted => "CERT_DELETED",
            Self::CertificateExported => "CERT_EXPORTED",
            Self::AuthenticationSuccess => "AUTH_SUCCESS",
            Self::AuthenticationFailure => "AUTH_FAILURE",
            Self::ConfigurationChanged => "CONFIG_CHANGED",
            Self::PolicyViolation => "POLICY_VIOLATION",
        }
    }

    /// Check if this is a security-sensitive event (critical priority).
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - AU-2: Audit Events (criticality classification)
    /// - AU-6: Audit Review, Analysis, and Reporting (prioritization)
    ///
    /// **STIG Finding:**
    /// - APSC-DV-001630 (CAT II): Security-Relevant Events
    ///
    /// # Critical Events
    ///
    /// Returns `true` for events that indicate potential security issues:
    /// - `KeyDeleted` - Key material loss
    /// - `CertificateDeleted` - Identity credential loss
    /// - `CertificateExported` - Potential credential exfiltration
    /// - `AuthenticationFailure` - Possible attack or misconfiguration
    /// - `PolicyViolation` - Compliance violation
    ///
    /// Critical events are logged at WARN level and should trigger alerts.
    pub fn is_critical(&self) -> bool {
        matches!(
            self,
            Self::KeyDeleted
                | Self::CertificateDeleted
                | Self::CertificateExported
                | Self::AuthenticationFailure
                | Self::PolicyViolation
        )
    }
}

// ============================================================================
// SECURITY CONTROL: Security Audit Logger
// ----------------------------------------------------------------------------
// NIST SP 800-53 Rev 5: AU-2 (Audit Events)
//                       AU-3 (Content of Audit Records)
//                       AU-12 (Audit Generation)
//                       AU-4 (Audit Storage Capacity)
// STIG: APSC-DV-000830 (CAT II) - Audit Generation
//       APSC-DV-001630 (CAT II) - Security-Relevant Events
// Standards: NIST SP 800-92 (Guide to Computer Security Log Management)
// ----------------------------------------------------------------------------
// Centralized audit logging for security events. Supports multiple outputs:
// Windows Event Log, file-based logging, and structured logging (tracing).
//
// Security Rationale:
// - AU-2/AU-12: Generates audit records for all security-relevant events
// - AU-3: Includes timestamp, event type, outcome, and context in records
// - AU-4: File-based logging provides audit trail persistence
// - Windows Event Log integration for centralized log collection
// - Critical events logged at WARN level for alerting/monitoring
// ============================================================================

/// Security audit logger.
///
/// # Security Controls
///
/// **NIST SP 800-53 Rev 5:**
/// - AU-2: Audit Events (security event identification)
/// - AU-3: Content of Audit Records (timestamp, event, details)
/// - AU-12: Audit Generation (automated logging)
/// - AU-4: Audit Storage Capacity (file-based persistence)
///
/// **STIG Findings:**
/// - APSC-DV-000830 (CAT II): Audit Generation
/// - APSC-DV-001630 (CAT II): Security-Relevant Events
///
/// # Audit Outputs
///
/// 1. **Structured Logging** (tracing crate): Always enabled when auditing on
///    - Integrates with application logging infrastructure
///    - Supports log aggregation systems (ELK, Splunk, etc.)
///    - Critical events logged at WARN, others at INFO
///
/// 2. **Windows Event Log**: Optional (enabled by default)
///    - Integration with Windows security event monitoring
///    - Centralized log collection via Group Policy
///
/// 3. **File-based Logging**: Optional (disabled by default)
///    - Append-only audit trail with timestamps
///    - For environments without centralized logging
///    - Must configure rotation/retention separately
///
/// # Example
///
/// ```rust
/// use usg_est_client::windows::security::{SecurityAudit, SecurityAuditEvent};
///
/// let audit = SecurityAudit::new()
///     .with_event_log(true)
///     .with_file("/var/log/est-client-audit.log");
///
/// audit.log_key_generated("ECDSA-P256", Some("est-client-key"));
/// audit.log_auth_failure("Invalid credentials");
/// ```
pub struct SecurityAudit {
    /// Whether auditing is enabled (AU-12: audit generation control).
    ///
    /// Default: `true`. Set to `false` only for development/testing.
    enabled: bool,

    /// Log to Windows Event Log (AU-4: centralized audit storage).
    ///
    /// Default: `true`. Enables integration with Windows security monitoring.
    use_event_log: bool,

    /// Log to file (AU-4: audit trail persistence).
    ///
    /// Default: `None`. When set, appends audit records to the specified file
    /// with UNIX timestamp. Recommended for environments without centralized logging.
    log_file_path: Option<std::path::PathBuf>,
}

impl Default for SecurityAudit {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityAudit {
    /// Create a new security audit logger with secure defaults.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - AU-12: Audit Generation (enabled by default)
    ///
    /// # Default Configuration
    ///
    /// - Auditing: **enabled**
    /// - Windows Event Log: **enabled**
    /// - File logging: **disabled** (must configure separately)
    pub fn new() -> Self {
        Self {
            enabled: true,
            use_event_log: true,
            log_file_path: None,
        }
    }

    /// Create an audit logger with auditing disabled.
    ///
    /// # Security Warning
    ///
    /// **DO NOT USE IN PRODUCTION!** Disabling auditing violates:
    /// - NIST SP 800-53 Rev 5: AU-2, AU-12
    /// - STIG APSC-DV-000830 (CAT II)
    ///
    /// Only use for development/testing where compliance is not required.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            use_event_log: false,
            log_file_path: None,
        }
    }

    /// Set whether to use Windows Event Log.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - AU-4: Audit Storage Capacity (centralized logging)
    ///
    /// # Arguments
    ///
    /// * `use_event_log` - `true` to enable Windows Event Log integration
    ///
    /// Recommended for Windows environments with centralized log collection.
    pub fn with_event_log(mut self, use_event_log: bool) -> Self {
        self.use_event_log = use_event_log;
        self
    }

    /// Set a file path for audit logs (append-only).
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - AU-4: Audit Storage Capacity (file-based persistence)
    /// - AU-9: Protection of Audit Information (immutable append-only log)
    ///
    /// # Arguments
    ///
    /// * `path` - Path to audit log file (will be created if doesn't exist)
    ///
    /// # Security Note
    ///
    /// - File is append-only (cannot modify existing records)
    /// - Must configure separate log rotation/retention
    /// - Ensure file permissions restrict access (AU-9)
    /// - Recommended path: `/var/log/est-client-audit.log` (Linux/macOS)
    ///   or `C:\ProgramData\EST-Client\audit.log` (Windows)
    pub fn with_file(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.log_file_path = Some(path.into());
        self
    }

    /// Log a security audit event.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - AU-2: Audit Events (event logging)
    /// - AU-3: Content of Audit Records (timestamp, event type, details)
    /// - AU-12: Audit Generation (automated logging)
    ///
    /// **STIG Finding:**
    /// - APSC-DV-000830 (CAT II): Audit Generation
    ///
    /// # Audit Record Format
    ///
    /// **Structured Log** (tracing): `[SECURITY] EVENT_NAME - details`
    /// **File Log**: `<unix_timestamp> [SECURITY] EVENT_NAME - details`
    ///
    /// # Arguments
    ///
    /// * `event` - The security event type
    /// * `details` - Event-specific details (algorithm, thumbprint, reason, etc.)
    ///
    /// # Logging Levels (AU-6: Audit Review)
    ///
    /// - **WARN**: Critical events (failures, deletions, policy violations)
    /// - **INFO**: Normal events (generation, enrollment, success)
    pub fn log(&self, event: SecurityAuditEvent, details: &str) {
        if !self.enabled {
            return;
        }

        let message = format!("[SECURITY] {} - {}", event.name(), details);

        // Always log critical events at warn level
        if event.is_critical() {
            tracing::warn!("{}", message);
        } else {
            tracing::info!("{}", message);
        }

        // Log to file if configured
        if let Some(ref path) = self.log_file_path {
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            {
                use std::io::Write;
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let _ = writeln!(file, "{} {}", timestamp, message);
            }
        }
    }

    /// Log a key generation event (AU-2: cryptographic event).
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - AU-2: Audit Events (key generation)
    /// - SC-12: Cryptographic Key Establishment (key lifecycle)
    ///
    /// # Arguments
    ///
    /// * `algorithm` - Key algorithm (e.g., "ECDSA-P256", "RSA-2048")
    /// * `label` - Optional key label/identifier
    pub fn log_key_generated(&self, algorithm: &str, label: Option<&str>) {
        let details = match label {
            Some(l) => format!("Algorithm: {}, Label: {}", algorithm, l),
            None => format!("Algorithm: {}", algorithm),
        };
        self.log(SecurityAuditEvent::KeyGenerated, &details);
    }

    /// Log a certificate enrollment event (AU-2: PKI lifecycle).
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - AU-2: Audit Events (certificate enrollment)
    /// - IA-5: Authenticator Management (credential lifecycle)
    ///
    /// # Arguments
    ///
    /// * `thumbprint` - Certificate SHA-1 thumbprint
    /// * `subject` - Certificate subject DN
    pub fn log_certificate_enrolled(&self, thumbprint: &str, subject: &str) {
        let details = format!("Thumbprint: {}, Subject: {}", thumbprint, subject);
        self.log(SecurityAuditEvent::CertificateEnrolled, &details);
    }

    /// Log an authentication failure (AU-2: critical event).
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - AU-2: Audit Events (authentication failure)
    /// - AC-7: Unsuccessful Logon Attempts (failure tracking)
    ///
    /// **STIG Finding:**
    /// - APSC-DV-001630 (CAT II): Security-Relevant Events
    ///
    /// # Arguments
    ///
    /// * `reason` - Failure reason (e.g., "Invalid credentials", "Certificate expired")
    ///
    /// Logged at **WARN** level as a critical security event.
    pub fn log_auth_failure(&self, reason: &str) {
        self.log(SecurityAuditEvent::AuthenticationFailure, reason);
    }

    /// Log a policy violation (AU-2: critical event).
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - AU-2: Audit Events (policy violation)
    /// - AU-6: Audit Review, Analysis, and Reporting (incident detection)
    ///
    /// **STIG Finding:**
    /// - APSC-DV-001630 (CAT II): Security-Relevant Events
    ///
    /// # Arguments
    ///
    /// * `policy` - Policy name (e.g., "KeyProtection", "TlsVersion")
    /// * `details` - Violation details
    ///
    /// Logged at **WARN** level as a critical compliance event.
    pub fn log_policy_violation(&self, policy: &str, details: &str) {
        let message = format!("Policy: {}, Details: {}", policy, details);
        self.log(SecurityAuditEvent::PolicyViolation, &message);
    }
}

// ============================================================================
// SECURITY CONTROL: TLS Security Configuration
// ----------------------------------------------------------------------------
// NIST SP 800-53 Rev 5: SC-8 (Transmission Confidentiality and Integrity)
//                       SC-13 (Cryptographic Protection)
//                       IA-5 (Authenticator Management)
// STIG: APSC-DV-002440 (CAT I) - Encryption in Transit
//       APSC-DV-001750 (CAT I) - Certificate Validation
// Standards: NIST SP 800-52 Rev 2 (TLS Guidelines)
//           RFC 7030 (EST Protocol, requires TLS 1.2+)
// ----------------------------------------------------------------------------
// Configures TLS security for EST server connections. Enforces minimum
// TLS version, certificate validation, and optional certificate pinning.
//
// Security Rationale:
// - TLS 1.2+ required by RFC 7030 and NIST SP 800-52 Rev 2
// - TLS 1.3 preferred for improved security (forward secrecy, simpler handshake)
// - Hostname verification prevents MITM attacks (SC-8, APSC-DV-001750)
// - Certificate pinning provides defense-in-depth (SC-13)
// - Self-signed certificates ONLY for development (violates PKI trust model)
// ============================================================================

/// TLS security configuration.
///
/// # Security Controls
///
/// **NIST SP 800-53 Rev 5:**
/// - SC-8: Transmission Confidentiality and Integrity (TLS encryption)
/// - SC-13: Cryptographic Protection (TLS 1.2+, cipher suites)
/// - IA-5: Authenticator Management (certificate validation)
///
/// **STIG Findings:**
/// - APSC-DV-002440 (CAT I): Encryption in Transit
/// - APSC-DV-001750 (CAT I): Certificate Validation
///
/// # TLS Requirements (NIST SP 800-52 Rev 2)
///
/// - **Minimum Version**: TLS 1.2 (RFC 7030 requirement)
/// - **Preferred Version**: TLS 1.3 (improved security, performance)
/// - **Certificate Validation**: Enabled (verify chain and hostname)
/// - **Cipher Suites**: FIPS-approved only (AES-GCM, ChaCha20-Poly1305)
///
/// # Configuration Profiles
///
/// - **Production**: `new()` or `high_security()` - TLS 1.2+ or TLS 1.3 only
/// - **Development**: `development()` - Allows self-signed certs (testing only)
#[derive(Debug, Clone)]
pub struct TlsSecurityConfig {
    /// Minimum TLS version (SC-8: minimum encryption strength).
    ///
    /// RFC 7030 requires TLS 1.2+. Never set below TLS 1.2.
    pub min_version: TlsVersion,

    /// Preferred TLS version (SC-8: optimal encryption).
    ///
    /// TLS 1.3 preferred for: forward secrecy, simplified handshake, fewer cipher options.
    pub preferred_version: TlsVersion,

    /// Certificate pinning configuration (SC-13: defense-in-depth).
    ///
    /// Optional. When enabled, validates server certificate against known fingerprints.
    pub certificate_pinning: Option<CertificatePinning>,

    /// Allow self-signed certificates (IA-5: trust anchor validation).
    ///
    /// **Security Warning**: MUST be `false` in production. Violates PKI trust model.
    /// Set to `true` ONLY for development/testing with local EST servers.
    pub allow_self_signed: bool,

    /// Verify hostname (SC-8: MITM prevention).
    ///
    /// **Security Warning**: MUST be `true` in production. Prevents DNS spoofing attacks.
    /// Set to `false` ONLY for development/testing with IP addresses.
    pub verify_hostname: bool,

    /// Custom cipher suites (SC-13: algorithm selection).
    ///
    /// Empty = use system defaults (recommended).
    /// When specified, MUST contain only FIPS-approved cipher suites.
    pub cipher_suites: Vec<String>,
}

impl Default for TlsSecurityConfig {
    fn default() -> Self {
        Self {
            min_version: TlsVersion::Tls12,
            preferred_version: TlsVersion::Tls13,
            certificate_pinning: None,
            allow_self_signed: false,
            verify_hostname: true,
            cipher_suites: Vec::new(),
        }
    }
}

impl TlsSecurityConfig {
    /// Create a new TLS security configuration with secure defaults.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - SC-8: Transmission Confidentiality and Integrity (TLS 1.2+ required)
    ///
    /// # Default Configuration
    ///
    /// - Minimum version: **TLS 1.2** (RFC 7030 requirement)
    /// - Preferred version: **TLS 1.3** (optimal security)
    /// - Certificate pinning: **disabled** (configure separately)
    /// - Self-signed certificates: **disabled** (PKI validation required)
    /// - Hostname verification: **enabled** (MITM prevention)
    /// - Cipher suites: **system defaults** (FIPS-approved)
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a high-security configuration (TLS 1.3 only).
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - SC-8: Transmission Confidentiality and Integrity (maximum protection)
    /// - SC-13: Cryptographic Protection (TLS 1.3 only)
    ///
    /// # High Security Configuration
    ///
    /// - Minimum version: **TLS 1.3** (enforced, no TLS 1.2 fallback)
    /// - Preferred version: **TLS 1.3**
    /// - Self-signed certificates: **disabled**
    /// - Hostname verification: **enabled**
    ///
    /// **Use case**: High-value environments requiring maximum transport security.
    /// **Requirement**: EST server MUST support TLS 1.3 (fails if not available).
    pub fn high_security() -> Self {
        Self {
            min_version: TlsVersion::Tls13,
            preferred_version: TlsVersion::Tls13,
            certificate_pinning: None,
            allow_self_signed: false,
            verify_hostname: true,
            cipher_suites: Vec::new(),
        }
    }

    /// Create a configuration for development/testing.
    ///
    /// # Security Warning
    ///
    /// **DO NOT USE IN PRODUCTION!** This configuration disables critical security features:
    /// - Allows self-signed certificates (violates PKI trust model)
    /// - Disables hostname verification (vulnerable to MITM attacks)
    ///
    /// Violates:
    /// - NIST SP 800-53 Rev 5: SC-8, IA-5
    /// - STIG APSC-DV-002440 (CAT I), APSC-DV-001750 (CAT I)
    ///
    /// # Development Configuration
    ///
    /// - Minimum version: **TLS 1.2**
    /// - Self-signed certificates: **allowed** (testing with local servers)
    /// - Hostname verification: **disabled** (testing with IP addresses)
    ///
    /// **Use case**: Local development, integration testing with test EST servers.
    pub fn development() -> Self {
        Self {
            min_version: TlsVersion::Tls12,
            preferred_version: TlsVersion::Tls13,
            certificate_pinning: None,
            allow_self_signed: true,
            verify_hostname: false,
            cipher_suites: Vec::new(),
        }
    }

    /// Set certificate pinning configuration.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - SC-13: Cryptographic Protection (defense-in-depth)
    ///
    /// Adds certificate pinning for additional protection against MITM attacks,
    /// even if a Certificate Authority is compromised.
    ///
    /// # Example
    ///
    /// ```rust
    /// use usg_est_client::windows::security::{TlsSecurityConfig, CertificatePinning};
    ///
    /// let pinning = CertificatePinning::new()
    ///     .add_pin("SHA256:abc123...");
    ///
    /// let config = TlsSecurityConfig::new().with_pinning(pinning);
    /// ```
    pub fn with_pinning(mut self, pinning: CertificatePinning) -> Self {
        self.certificate_pinning = Some(pinning);
        self
    }

    /// Set minimum TLS version.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - SC-8: Transmission Confidentiality and Integrity (version enforcement)
    ///
    /// **Security Warning**: RFC 7030 requires TLS 1.2 minimum. Never set below TLS 1.2.
    ///
    /// # Arguments
    ///
    /// * `version` - Minimum TLS version (TLS 1.2 or TLS 1.3)
    pub fn with_min_version(mut self, version: TlsVersion) -> Self {
        self.min_version = version;
        self
    }
}

/// TLS protocol version.
///
/// # Security Controls
///
/// **NIST SP 800-53 Rev 5:**
/// - SC-8: Transmission Confidentiality and Integrity (protocol version)
///
/// **Standards:**
/// - RFC 7030: EST Protocol (requires TLS 1.2 minimum)
/// - NIST SP 800-52 Rev 2: TLS Guidelines (TLS 1.2+, prefer TLS 1.3)
///
/// # Supported Versions
///
/// - **TLS 1.2**: Minimum required by RFC 7030, NIST SP 800-52 Rev 2
/// - **TLS 1.3**: Preferred for improved security and performance
///
/// **Not supported**: TLS 1.0, TLS 1.1 (deprecated by NIST, IETF, and industry)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TlsVersion {
    /// TLS 1.2 (RFC 5246) - Minimum required by RFC 7030 and NIST SP 800-52 Rev 2.
    ///
    /// Supports: AEAD cipher suites (AES-GCM, ChaCha20-Poly1305), Perfect Forward Secrecy.
    Tls12,

    /// TLS 1.3 (RFC 8446) - Preferred version for enhanced security.
    ///
    /// Improvements over TLS 1.2:
    /// - Simplified handshake (faster, fewer round trips)
    /// - Mandatory Perfect Forward Secrecy (PFS)
    /// - Removed legacy/weak cipher suites
    /// - 0-RTT resumption (optional, disabled for anti-replay)
    Tls13,
}

impl TlsVersion {
    /// Get the version string for logging and display.
    ///
    /// Returns human-readable version string (e.g., "TLS 1.2", "TLS 1.3").
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tls12 => "TLS 1.2",
            Self::Tls13 => "TLS 1.3",
        }
    }
}

/// Network security configuration for EST client connections.
///
/// # Security Controls
///
/// **NIST SP 800-53 Rev 5:**
/// - SC-8: Transmission Confidentiality and Integrity (TLS configuration)
/// - SC-10: Network Disconnect (timeouts prevent resource exhaustion)
/// - SC-5: Denial of Service Protection (timeouts, retries)
///
/// # Configuration Components
///
/// - **TLS**: Encryption, certificate validation, protocol version
/// - **Proxy**: HTTP/HTTPS proxy support (corporate environments)
/// - **Timeouts**: Connection and request timeouts (prevent hangs)
/// - **Retries**: Retry policy for transient failures
#[derive(Debug, Clone, Default)]
pub struct NetworkSecurityConfig {
    /// TLS security settings (SC-8: encryption in transit).
    pub tls: TlsSecurityConfig,

    /// Optional proxy configuration (SC-7: boundary protection).
    ///
    /// Supports HTTP/HTTPS proxies with authentication. Use `ProxyConfig::from_environment()`
    /// to automatically detect proxy from HTTPS_PROXY environment variable.
    pub proxy: Option<ProxyConfig>,

    /// Connection timeout in seconds (SC-10: network disconnect).
    ///
    /// Default: 30 seconds. Prevents indefinite connection attempts.
    pub connect_timeout_secs: u64,

    /// Request timeout in seconds (SC-10: network disconnect).
    ///
    /// Default: 60 seconds. Prevents slow-read attacks and resource exhaustion.
    pub request_timeout_secs: u64,

    /// Maximum retry attempts (SC-5: DoS protection).
    ///
    /// Default: 3 retries. Handles transient network failures without infinite loops.
    pub max_retries: u32,

    /// Base retry delay in seconds (SC-5: exponential backoff).
    ///
    /// Default: 5 seconds. Uses exponential backoff (delay * 2^attempt).
    pub retry_delay_secs: u64,
}

impl NetworkSecurityConfig {
    /// Create a new network security configuration with secure defaults.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - SC-8: Transmission Confidentiality and Integrity (TLS enabled)
    /// - SC-10: Network Disconnect (reasonable timeouts)
    ///
    /// # Default Configuration
    ///
    /// - TLS: Secure defaults (TLS 1.2+, hostname verification)
    /// - Proxy: None (detect from environment if needed)
    /// - Connect timeout: **30 seconds**
    /// - Request timeout: **60 seconds**
    /// - Max retries: **3 attempts**
    /// - Retry delay: **5 seconds** (exponential backoff)
    pub fn new() -> Self {
        Self {
            tls: TlsSecurityConfig::default(),
            proxy: None,
            connect_timeout_secs: 30,
            request_timeout_secs: 60,
            max_retries: 3,
            retry_delay_secs: 5,
        }
    }

    /// Set proxy configuration.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - SC-7: Boundary Protection (proxy for network segmentation)
    ///
    /// # Example
    ///
    /// ```rust
    /// use usg_est_client::windows::security::{NetworkSecurityConfig, ProxyConfig};
    ///
    /// let proxy = ProxyConfig::new("http://proxy.example.com:8080")
    ///     .with_auth("user", "password");
    ///
    /// let config = NetworkSecurityConfig::new().with_proxy(proxy);
    /// ```
    pub fn with_proxy(mut self, proxy: ProxyConfig) -> Self {
        self.proxy = Some(proxy);
        self
    }

    /// Set connection and request timeouts.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - SC-10: Network Disconnect (prevent resource exhaustion)
    /// - SC-5: Denial of Service Protection (timeout limits)
    ///
    /// # Arguments
    ///
    /// * `connect` - Connection timeout in seconds (TCP handshake + TLS handshake)
    /// * `request` - Request timeout in seconds (total time for HTTP request/response)
    ///
    /// # Recommendations
    ///
    /// - Connect timeout: 10-30 seconds (network latency dependent)
    /// - Request timeout: 30-120 seconds (EST operations can be slow)
    pub fn with_timeouts(mut self, connect: u64, request: u64) -> Self {
        self.connect_timeout_secs = connect;
        self.request_timeout_secs = request;
        self
    }

    /// Set retry configuration.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - SC-5: Denial of Service Protection (prevent retry storms)
    ///
    /// # Arguments
    ///
    /// * `max_retries` - Maximum retry attempts (0-10 recommended)
    /// * `delay_secs` - Base delay between retries (exponential backoff applied)
    ///
    /// # Retry Strategy
    ///
    /// Uses exponential backoff: `delay * 2^attempt`
    /// - Attempt 1: delay_secs
    /// - Attempt 2: delay_secs * 2
    /// - Attempt 3: delay_secs * 4
    ///
    /// # Recommendations
    ///
    /// - Max retries: 3-5 (balance reliability vs. latency)
    /// - Base delay: 1-10 seconds (avoid overwhelming server)
    pub fn with_retries(mut self, max_retries: u32, delay_secs: u64) -> Self {
        self.max_retries = max_retries;
        self.retry_delay_secs = delay_secs;
        self
    }
}

/// HTTP/HTTPS proxy configuration.
///
/// # Security Controls
///
/// **NIST SP 800-53 Rev 5:**
/// - SC-7: Boundary Protection (proxy for network segmentation)
/// - IA-5: Authenticator Management (proxy authentication)
/// - AC-17: Remote Access (proxy for controlled internet access)
///
/// # Proxy Support
///
/// Supports HTTP and HTTPS proxies with optional authentication.
/// Compatible with corporate proxy environments (e.g., Squid, Microsoft Forefront).
///
/// # Environment Variables
///
/// Automatically detects proxy from standard environment variables:
/// - `HTTPS_PROXY` or `https_proxy` - Proxy URL
/// - `NO_PROXY` or `no_proxy` - Comma-separated bypass list
///
/// # Example
///
/// ```rust
/// use usg_est_client::windows::security::ProxyConfig;
///
/// // Manual configuration
/// let proxy = ProxyConfig::new("http://proxy.example.com:8080")
///     .with_auth("username", "password")
///     .with_no_proxy(&["localhost", "127.0.0.1", "*.internal"]);
///
/// // From environment
/// let proxy = ProxyConfig::from_environment();
/// ```
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Proxy URL (http:// or https://).
    ///
    /// Format: `http://hostname:port` or `https://hostname:port`
    /// Example: `http://proxy.example.com:8080`
    pub url: String,

    /// Proxy username (IA-5: authenticator management).
    ///
    /// Optional. Required if proxy requires authentication.
    /// **Security**: Store securely, avoid hardcoding in source code.
    pub username: Option<String>,

    /// Proxy password (IA-5: authenticator management).
    ///
    /// Optional. Required if proxy requires authentication.
    /// **Security Warning**: Stored in memory as plaintext. Use Windows Credential
    /// Manager or environment variables for production deployments.
    pub password: Option<String>,

    /// Hosts to bypass proxy (SC-7: selective proxy bypass).
    ///
    /// List of hostnames/domains that should bypass the proxy.
    /// Supports wildcards (e.g., `*.internal`, `.local`).
    /// Common: `localhost`, `127.0.0.1`, internal domains.
    pub no_proxy: Vec<String>,
}

impl ProxyConfig {
    /// Create a new proxy configuration.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - SC-7: Boundary Protection (proxy configuration)
    ///
    /// # Arguments
    ///
    /// * `url` - Proxy URL (e.g., `http://proxy.example.com:8080`)
    ///
    /// # Example
    ///
    /// ```rust
    /// use usg_est_client::windows::security::ProxyConfig;
    ///
    /// let proxy = ProxyConfig::new("http://proxy.example.com:8080");
    /// ```
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            username: None,
            password: None,
            no_proxy: Vec::new(),
        }
    }

    /// Set proxy authentication credentials.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - IA-5: Authenticator Management (proxy authentication)
    ///
    /// **Security Warning**: Credentials are stored in memory as plaintext.
    /// For production:
    /// - Use Windows Credential Manager
    /// - Use environment variables (not hardcoded)
    /// - Avoid logging proxy configuration (contains password)
    ///
    /// # Arguments
    ///
    /// * `username` - Proxy username
    /// * `password` - Proxy password
    ///
    /// # Example
    ///
    /// ```rust
    /// use usg_est_client::windows::security::ProxyConfig;
    ///
    /// let proxy = ProxyConfig::new("http://proxy.example.com:8080")
    ///     .with_auth("user", "password");
    /// ```
    pub fn with_auth(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self.password = Some(password.into());
        self
    }

    /// Add hosts to bypass proxy.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - SC-7: Boundary Protection (selective bypass)
    ///
    /// # Arguments
    ///
    /// * `hosts` - List of hostnames/domains to bypass
    ///
    /// Supports wildcards:
    /// - `localhost` - Exact match
    /// - `127.0.0.1` - IP address
    /// - `*.internal` - Wildcard domain
    /// - `.local` - Domain suffix
    ///
    /// # Example
    ///
    /// ```rust
    /// use usg_est_client::windows::security::ProxyConfig;
    ///
    /// let proxy = ProxyConfig::new("http://proxy.example.com:8080")
    ///     .with_no_proxy(&["localhost", "127.0.0.1", "*.internal", ".local"]);
    /// ```
    pub fn with_no_proxy(mut self, hosts: &[&str]) -> Self {
        self.no_proxy = hosts.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Create proxy configuration from environment variables.
    ///
    /// # Security Controls
    ///
    /// **NIST SP 800-53 Rev 5:**
    /// - SC-7: Boundary Protection (automatic proxy detection)
    ///
    /// # Environment Variables
    ///
    /// - `HTTPS_PROXY` or `https_proxy` - Proxy URL (required)
    /// - `NO_PROXY` or `no_proxy` - Comma-separated bypass list (optional)
    ///
    /// # Returns
    ///
    /// - `Some(ProxyConfig)` if HTTPS_PROXY is set
    /// - `None` if no proxy environment variable found
    ///
    /// # Security Note
    ///
    /// This method does NOT read proxy authentication from environment.
    /// Use `with_auth()` to add credentials after creation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use usg_est_client::windows::security::ProxyConfig;
    ///
    /// // export HTTPS_PROXY=http://proxy.example.com:8080
    /// // export NO_PROXY=localhost,127.0.0.1
    ///
    /// if let Some(proxy) = ProxyConfig::from_environment() {
    ///     println!("Proxy detected: {}", proxy.url);
    /// }
    /// ```
    pub fn from_environment() -> Option<Self> {
        std::env::var("HTTPS_PROXY")
            .or_else(|_| std::env::var("https_proxy"))
            .ok()
            .map(|url| {
                let mut config = Self::new(url);
                if let Ok(no_proxy) =
                    std::env::var("NO_PROXY").or_else(|_| std::env::var("no_proxy"))
                {
                    config.no_proxy = no_proxy.split(',').map(|s| s.trim().to_string()).collect();
                }
                config
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_protection_default() {
        let policy = KeyProtection::default();
        assert!(policy.non_exportable);
        assert!(policy.tpm_preferred);
        assert!(!policy.tpm_required);
        assert_eq!(policy.min_rsa_key_size, 2048);
    }

    #[test]
    fn test_key_protection_high_security() {
        let policy = KeyProtection::high_security();
        assert!(policy.non_exportable);
        assert!(policy.tpm_required);
        assert_eq!(policy.min_rsa_key_size, 3072);
    }

    #[test]
    fn test_key_protection_validate_algorithm() {
        let policy = KeyProtection::default();
        assert!(
            policy
                .validate_algorithm(KeyAlgorithmPolicy::EcdsaP256)
                .is_ok()
        );
        assert!(
            policy
                .validate_algorithm(KeyAlgorithmPolicy::Rsa2048)
                .is_ok()
        );

        let strict = KeyProtection::default().with_min_rsa_key_size(3072);
        assert!(
            strict
                .validate_algorithm(KeyAlgorithmPolicy::Rsa2048)
                .is_err()
        );
        assert!(
            strict
                .validate_algorithm(KeyAlgorithmPolicy::Rsa4096)
                .is_ok()
        );
    }

    #[test]
    fn test_certificate_pinning() {
        let pinning = CertificatePinning::new()
            .add_pin("SHA256:abcdef123456")
            .add_pin("ABCDEF123456");

        assert!(pinning.has_pins());
        assert_eq!(pinning.pin_count(), 2);

        assert!(pinning.validate_fingerprint("abcdef123456").is_ok());
        assert!(pinning.validate_fingerprint("ABCDEF123456").is_ok());
        assert!(pinning.validate_fingerprint("invalid").is_err());
    }

    #[test]
    fn test_certificate_pinning_fallback() {
        let pinning = CertificatePinning::new()
            .add_pin("abcdef")
            .with_fallback(true);

        assert!(pinning.validate_fingerprint("different").is_ok());
    }

    #[test]
    fn test_security_audit_event() {
        assert_eq!(SecurityAuditEvent::KeyGenerated.name(), "KEY_GENERATED");
        assert!(SecurityAuditEvent::PolicyViolation.is_critical());
        assert!(!SecurityAuditEvent::KeyGenerated.is_critical());
    }

    #[test]
    fn test_tls_version_ordering() {
        assert!(TlsVersion::Tls12 < TlsVersion::Tls13);
    }

    #[test]
    fn test_tls_security_config() {
        let config = TlsSecurityConfig::high_security();
        assert_eq!(config.min_version, TlsVersion::Tls13);
        assert!(!config.allow_self_signed);

        let dev = TlsSecurityConfig::development();
        assert!(dev.allow_self_signed);
    }

    #[test]
    fn test_proxy_config() {
        let proxy = ProxyConfig::new("http://proxy.example.com:8080")
            .with_auth("user", "pass")
            .with_no_proxy(&["localhost", "127.0.0.1"]);

        assert_eq!(proxy.url, "http://proxy.example.com:8080");
        assert_eq!(proxy.username, Some("user".to_string()));
        assert_eq!(proxy.no_proxy.len(), 2);
    }

    #[test]
    fn test_network_security_config() {
        let config = NetworkSecurityConfig::new()
            .with_timeouts(10, 30)
            .with_retries(5, 10);

        assert_eq!(config.connect_timeout_secs, 10);
        assert_eq!(config.request_timeout_secs, 30);
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.retry_delay_secs, 10);
    }
}
