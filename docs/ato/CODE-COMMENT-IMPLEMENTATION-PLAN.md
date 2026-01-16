# NIST/STIG Code Comment Implementation Plan

**Version**: 1.0.0
**Date**: 2026-01-16
**Status**: Implementation Guide

This document outlines the plan for adding NIST SP 800-53 Rev 5 and Application Development STIG comments throughout the codebase.

---

## Comment Format Standards

### NIST Control Comments
```rust
// NIST 800-53 Rev 5: SC-8 (Transmission Confidentiality and Integrity)
// Implementation: TLS 1.2+ with strong cipher suites
```

### STIG Finding Comments
```rust
// STIG: APSC-DV-000160 (CAT I) - Authentication
// Requirement: Cryptographically-based bidirectional authentication
```

### Combined Comments (for critical security functions)
```rust
// ============================================================================
// SECURITY CONTROL: TLS Configuration
// ----------------------------------------------------------------------------
// NIST 800-53 Rev 5: SC-8, IA-2, AC-17
// STIG: APSC-DV-000160 (CAT I), APSC-DV-000170 (CAT I)
// RFC 7030: Section 3.3.1 (TLS 1.1+), Section 3.5 (Channel Binding)
// ----------------------------------------------------------------------------
// This function builds TLS configuration with:
// - Minimum TLS 1.2 (RFC 7030 compliance, SC-8)
// - Mutual TLS authentication (IA-2, APSC-DV-000160)
// - Strong cipher suites (SC-8, APSC-DV-000170)
// - Certificate validation (IA-2, APSC-DV-003235)
// ============================================================================
```

---

## File-by-File Implementation Plan

### Priority 1: Critical Security Files (Immediate)

#### 1. `src/tls.rs` - TLS Configuration
**Controls**: SC-8, IA-2, AC-17
**STIG**: APSC-DV-000160, APSC-DV-000170, APSC-DV-002440

**Comments to Add**:

Lines 29-32 (existing RFC comment):
```rust
// ============================================================================
// SECURITY CONTROL: TLS Version Enforcement
// ----------------------------------------------------------------------------
// NIST 800-53 Rev 5: SC-8 (Transmission Confidentiality and Integrity)
// STIG: APSC-DV-000170 (CAT I) - Cryptographic Protection
// RFC 7030: Section 3.3.1 - TLS Requirements
// ----------------------------------------------------------------------------
// RFC 7030 Section 3.3.1 states: "TLS 1.1 [RFC4346] (or a later version) MUST be used"
// We use TLS 1.2 as the minimum since TLS 1.1 is deprecated (NIST guidance).
// This ensures confidentiality and integrity for all EST protocol communications.
// ============================================================================
```

Line 41 (`build_http_client` function):
```rust
/// Build a reqwest Client with the appropriate TLS configuration.
///
/// # Security Controls
///
/// **NIST 800-53 Rev 5:**
/// - SC-8: Transmission Confidentiality and Integrity (TLS 1.2+)
/// - IA-2: Identification and Authentication (Mutual TLS)
/// - AC-17: Remote Access (Secure protocol enforcement)
///
/// **STIG Requirements:**
/// - APSC-DV-000160 (CAT I): Cryptographically-based bidirectional authentication
/// - APSC-DV-000170 (CAT I): FIPS-validated cryptography for protection
/// - APSC-DV-002440 (CAT I): Session authenticity via TLS
///
/// # Channel Binding
///
/// When `channel_binding` is enabled in the config, this function prepares
/// the TLS configuration to support channel binding operations (RFC 7030 Section 3.5).
/// The actual channel binding value extraction must be done per-connection.
```

Line 77 (client certificate authentication):
```rust
// NIST 800-53: IA-2 (Identification and Authentication)
// STIG: APSC-DV-000160 (CAT I) - Bidirectional Authentication
// Configure mutual TLS with client certificate
if let Some(ref identity) = config.client_identity {
    let identity = build_reqwest_identity(identity)?;
    builder = builder.identity(identity);
}
```

Line 90 (TLS version enforcement):
```rust
// NIST 800-53: SC-8 (Transmission Confidentiality)
// STIG: APSC-DV-000170 (CAT I) - Cryptographic Protection
// RFC 7030: Section 3.3.1 compliance
// Enforce minimum TLS version 1.2 (TLS 1.1 is deprecated)
builder = builder.min_tls_version(reqwest::tls::Version::TLS_1_2);
```

---

#### 2. `src/validation.rs` - Certificate Path Validation
**Controls**: IA-2, SC-23, SI-10
**STIG**: APSC-DV-003235, APSC-DV-000500

**Comments to Add**:

Beginning of file (after module doc comment):
```rust
// ============================================================================
// SECURITY MODULE: RFC 5280 Certificate Path Validation
// ----------------------------------------------------------------------------
// NIST 800-53 Rev 5: IA-2, SC-23, SI-10
// STIG: APSC-DV-003235 (CAT I) - Certificate Validation
//       APSC-DV-000500 (CAT I) - Input Validation
// RFC 5280: Section 6 - Certification Path Validation
// ----------------------------------------------------------------------------
// This module implements RFC 5280-compliant certificate path validation
// including signature verification, expiration checking, constraints
// validation, and chain building. All certificate inputs are validated
// before use (SI-10, APSC-DV-000500).
// ============================================================================
```

`CertificateValidator::validate()` function:
```rust
    /// Validate a certificate against trusted root anchors.
    ///
    /// # Security Controls
    ///
    /// **NIST 800-53 Rev 5:**
    /// - IA-2: Authentication via certificate validation
    /// - SC-23: Session authenticity via certificate binding
    /// - SI-10: Input validation for certificate data
    ///
    /// **STIG Requirements:**
    /// - APSC-DV-003235 (CAT I): RFC 5280-compliant path validation
    /// - APSC-DV-000500 (CAT I): Certificate input validation
    ///
    /// # RFC 5280 Compliance
    ///
    /// This function implements RFC 5280 Section 6 certification path
    /// validation algorithm:
    /// 1. Build certification path from cert to trusted root
    /// 2. Verify signatures on all certificates in path
    /// 3. Check validity periods (not before/after)
    /// 4. Process basic constraints (CA flag, path length)
    /// 5. Process name constraints (DNS, email, URI)
    /// 6. Process policy constraints
    ///
    /// # Arguments
    ///
    /// * `cert` - The end-entity certificate to validate
    /// * `trusted_roots` - Collection of trusted root CA certificates
    ///
    /// # Returns
    ///
    /// * `Ok(ValidationResult)` - Certificate is valid with validated chain
    /// * `Err(ValidationError)` - Certificate failed validation with reason
```

`verify_signature()` function:
```rust
    /// Verify the digital signature on a certificate.
    ///
    /// # Security Controls
    ///
    /// **NIST 800-53 Rev 5:**
    /// - SC-13: Cryptographic protection (signature verification)
    /// - IA-2: Authentication via digital signature
    ///
    /// **STIG Requirements:**
    /// - APSC-DV-000170 (CAT I): FIPS-approved signature algorithms
    /// - APSC-DV-003235 (CAT I): Certificate signature validation
    ///
    /// # Supported Algorithms (FIPS 140-2 Approved)
    ///
    /// - RSA-PKCS#1 v1.5: SHA-256, SHA-384, SHA-512
    /// - RSA-PSS: SHA-256, SHA-384, SHA-512
    /// - ECDSA: P-256 with SHA-256, P-384 with SHA-384
```

`parse_tlv()` function:
```rust
    /// Parse ASN.1 Tag-Length-Value (TLV) structure with bounds checking.
    ///
    /// # Security Controls
    ///
    /// **NIST 800-53 Rev 5:**
    /// - SI-10: Information input validation
    /// - SI-3: Malicious code protection (bounds checking)
    ///
    /// **STIG Requirements:**
    /// - APSC-DV-000500 (CAT I): Input validation
    /// - APSC-DV-001620 (CAT I): Code injection prevention
    ///
    /// # Implementation Details
    ///
    /// This function performs rigorous bounds checking to prevent:
    /// - Buffer overruns (SI-3)
    /// - Integer overflows (SI-10)
    /// - Out-of-bounds memory access (APSC-DV-001620)
    ///
    /// Validation includes:
    /// - Tag existence check
    /// - Length field validation (including long-form encoding)
    /// - Value bounds verification
```

---

#### 3. `src/fips/algorithms.rs` - FIPS 140-2 Enforcement
**Controls**: SC-12, SC-13, IA-7
**STIG**: APSC-DV-000170

**Comments to Add** (these already exist, enhance them):

Line 1 (enhance existing comment):
```rust
// ============================================================================
// SECURITY MODULE: FIPS 140-2 Algorithm Enforcement
// ----------------------------------------------------------------------------
// NIST 800-53 Rev 5: SC-12, SC-13, IA-7
// STIG: APSC-DV-000170 (CAT I) - Cryptographic Protection
// FIPS 140-2: NIST-approved cryptographic algorithms
// CMVP Certificates: #4282 (OpenSSL 3.0.0), #4616 (OpenSSL 3.0.8)
// ----------------------------------------------------------------------------
// This module enforces use of FIPS 140-2 approved cryptographic algorithms
// and blocks deprecated/weak algorithms that pose security risks.
//
// SC-12: Cryptographic key sizes meet NIST requirements (RSA ≥2048, ECDSA ≥P-256)
// SC-13: Only FIPS-approved algorithms allowed in FIPS mode
// IA-7: Cryptographic module authentication via FIPS validation
// ============================================================================
```

Constants section:
```rust
// NIST 800-53: SC-13 (Cryptographic Protection)
// STIG: APSC-DV-000170 (CAT I)
// FIPS 140-2 Approved Symmetric Encryption Algorithms
pub const FIPS_APPROVED_SYMMETRIC: &[&str] = &[
    "AES-128-CBC", "AES-192-CBC", "AES-256-CBC",  // FIPS 197
    "AES-128-GCM", "AES-192-GCM", "AES-256-GCM",  // FIPS 197 + SP 800-38D
];

// NIST 800-53: SC-13 (Cryptographic Protection)
// STIG: APSC-DV-000170 (CAT I)
// FIPS 140-2 Approved Hash Functions
pub const FIPS_APPROVED_HASH: &[&str] = &[
    "SHA-256", "SHA-384", "SHA-512",     // FIPS 180-4
    "SHA-512/256",                        // FIPS 180-4
];

// NIST 800-53: SC-13 (Cryptographic Protection)
// STIG: APSC-DV-000170 (CAT I)
// Deprecated/Weak Algorithms (BLOCKED)
pub const DEPRECATED_ALGORITHMS: &[&str] = &[
    "3DES", "DES",        // Weak encryption (64-bit block size)
    "MD5",                // Collision attacks (RFC 6151)
    "SHA-1",              // Collision attacks (SHAttered)
    "RC4",                // Cryptanalysis vulnerabilities
];
```

---

#### 4. `src/logging/encryption.rs` - Audit Log Protection
**Controls**: AU-9, SC-13, SC-12, SC-28
**STIG**: APSC-DV-000170, APSC-DV-002440

**Comments to Add**:

Module documentation:
```rust
// ============================================================================
// SECURITY MODULE: Audit Log Encryption and Integrity Protection
// ----------------------------------------------------------------------------
// NIST 800-53 Rev 5: AU-9, SC-12, SC-13, SC-28
// STIG: APSC-DV-000170 (CAT I) - Cryptographic Protection
//       APSC-DV-002440 (CAT I) - Session Management (log integrity)
// ----------------------------------------------------------------------------
// This module provides encryption and integrity protection for audit logs.
//
// AU-9: Protection of audit information via encryption and MAC
// SC-12: Key management with DPAPI (Windows) or 0600 permissions (Unix)
// SC-13: FIPS-approved algorithms (AES-256-GCM, HMAC-SHA256)
// SC-28: Protection of information at rest
//
// Format: ENCRYPTED-LOG-v1:<nonce>:<ciphertext>:<mac>
// - 12-byte random nonce (GCM IV, unique per line)
// - AES-256-GCM authenticated encryption (FIPS 197 + SP 800-38D)
// - HMAC-SHA256 integrity protection (FIPS 198-1)
// ============================================================================
```

`LogKeys` struct:
```rust
/// Encryption keys for audit log protection.
///
/// # Security Controls
///
/// **NIST 800-53 Rev 5:**
/// - SC-12: Cryptographic key establishment and management
/// - SC-28: Protection of information at rest
///
/// **STIG Requirements:**
/// - APSC-DV-000170 (CAT I): FIPS-validated cryptography
///
/// # Key Protection
///
/// - **Windows**: DPAPI encryption (tied to user/machine credentials)
/// - **Unix**: File permissions 0600 (owner read/write only)
/// - **Memory**: Zeroized on drop (no key remnants in memory)
#[derive(ZeroizeOnDrop)]
pub struct LogKeys {
    encryption_key: [u8; 32],  // AES-256 key
    mac_key: [u8; 32],         // HMAC-SHA256 key
}
```

`encrypt_log_line()` function:
```rust
/// Encrypt a single log line with AES-256-GCM and HMAC-SHA256.
///
/// # Security Controls
///
/// **NIST 800-53 Rev 5:**
/// - SC-13: Cryptographic protection (AES-256-GCM)
/// - AU-9: Protection of audit information
/// - SC-28: Protection at rest
///
/// **STIG Requirements:**
/// - APSC-DV-000170 (CAT I): FIPS 140-2 approved algorithms
///
/// # Algorithm Details
///
/// - **Encryption**: AES-256-GCM (FIPS 197 + SP 800-38D)
/// - **MAC**: HMAC-SHA256 (FIPS 198-1)
/// - **Nonce**: 12 bytes from OsRng (cryptographically secure)
/// - **Format**: `ENCRYPTED-LOG-v1:<base64(nonce)>:<base64(ciphertext)>:<base64(mac)>`
///
/// # Protection Against
///
/// - Unauthorized read access (encryption)
/// - Tampering (MAC verification)
/// - Replay attacks (unique nonce per line)
```

`verify_mac()` function:
```rust
/// Verify HMAC-SHA256 with constant-time comparison.
///
/// # Security Controls
///
/// **NIST 800-53 Rev 5:**
/// - AU-9: Protection of audit information (integrity)
/// - SC-13: Cryptographic protection (MAC verification)
///
/// **STIG Requirements:**
/// - APSC-DV-000170 (CAT I): FIPS-approved MAC algorithm
///
/// # Timing Attack Prevention
///
/// This function uses constant-time comparison to prevent timing side-channel
/// attacks that could reveal information about the MAC value. This is critical
/// for maintaining the security of the integrity protection mechanism.
fn verify_mac(computed: &[u8], provided: &[u8]) -> bool {
    // Constant-time comparison (prevents timing attacks)
    use subtle::ConstantTimeEq;
    computed.ct_eq(provided).into()
}
```

---

#### 5. `src/windows/security.rs` - Windows Security Features
**Controls**: AC-3, AC-6, AU-2, AU-3, AU-12, SC-12
**STIG**: APSC-DV-000830, APSC-DV-000840, APSC-DV-002340

**Comments to Add**:

`SecurityAuditEvent` enum:
```rust
/// Security audit event types for compliance logging.
///
/// # Security Controls
///
/// **NIST 800-53 Rev 5:**
/// - AU-2: Audit events (defines auditable events)
/// - AU-3: Content of audit records (event metadata)
/// - AU-12: Audit generation (event triggers)
///
/// **STIG Requirements:**
/// - APSC-DV-000830 (CAT II): Audit generation
/// - APSC-DV-000840 (CAT II): Audit record content
///
/// # Event Categories
///
/// - **Key Operations**: Generation, deletion, usage (SC-12)
/// - **Certificate Lifecycle**: Enrollment, renewal, deletion (IA-2)
/// - **Authentication**: Success/failure events (IA-2, AC-7)
/// - **Security Violations**: Policy violations, unauthorized access (AC-3)
/// - **Configuration**: Changes to security settings (CM-6)
#[derive(Debug, Clone, Serialize)]
pub enum SecurityAuditEvent {
    // Key operations (SC-12, APSC-DV-000170)
    KeyGenerated { key_id: String, algorithm: String, key_size: u32 },
    KeyDeleted { key_id: String },
    KeyUsed { key_id: String, operation: String },

    // Certificate lifecycle (IA-2, APSC-DV-003235)
    CertificateEnrolled { subject: String, serial: String },
    CertificateRenewed { subject: String, serial: String },
    CertificateDeleted { subject: String, serial: String },

    // Authentication (IA-2, AC-7, APSC-DV-000160)
    AuthenticationSuccess { method: String, username: Option<String> },
    AuthenticationFailure { method: String, username: Option<String>, reason: String },

    // Security violations (AC-3, SI-10, APSC-DV-000500)
    PolicyViolation { policy: String, details: String },
    ConfigurationChanged { setting: String, old_value: String, new_value: String },
}
```

`KeyProtection` struct:
```rust
/// Key protection policy configuration.
///
/// # Security Controls
///
/// **NIST 800-53 Rev 5:**
/// - SC-12: Cryptographic key establishment and management
/// - AC-6: Least privilege (non-exportable keys)
/// - IA-5: Authenticator management (key strength)
///
/// **STIG Requirements:**
/// - APSC-DV-000170 (CAT I): Cryptographic protection
/// - APSC-DV-002340 (CAT II): Least privilege
///
/// # TPM Integration
///
/// TPM (Trusted Platform Module) provides hardware-backed key storage with:
/// - Non-exportable keys (keys never leave hardware)
/// - Platform binding (keys tied to specific machine)
/// - Attestation capabilities (prove key is hardware-backed)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyProtection {
    /// Require keys to be non-exportable (NIST 800-53: SC-12, AC-6)
    pub non_exportable: bool,

    /// TPM requirement level (NIST 800-53: SC-12, IA-5)
    pub tpm_requirement: TpmRequirement,

    /// Minimum key size enforcement (NIST 800-53: IA-5, SC-13)
    /// FIPS 140-2 requires RSA ≥2048, ECDSA ≥P-256
    pub min_rsa_key_size: u32,
}
```

---

### Priority 2: Supporting Files (Secondary)

#### 6. `src/config.rs` - Configuration Management
**Comments**: CM-2, CM-6, SI-10

```rust
/// EST client configuration.
///
/// # Security Controls
///
/// **NIST 800-53 Rev 5:**
/// - CM-2: Baseline configuration
/// - CM-6: Configuration settings
/// - SI-10: Information input validation
///
/// **STIG Requirements:**
/// - APSC-DV-000500 (CAT I): Input validation
///
/// # Configuration Validation
///
/// All configuration fields are validated before use:
/// - URLs: RFC 3986 compliance
/// - File paths: Path traversal prevention (SI-10)
/// - Timeouts: Range validation (0 < timeout ≤ 300)
/// - Enums: Whitelist validation
```

---

#### 7. `src/logging.rs` - Audit Logging
**Comments**: AU-2, AU-3, AU-6, AU-8, AU-12

```rust
/// File-based logger for audit trails.
///
/// # Security Controls
///
/// **NIST 800-53 Rev 5:**
/// - AU-2: Audit events
/// - AU-3: Content of audit records (timestamps, event type, outcome)
/// - AU-6: Audit review (file-based storage)
/// - AU-8: Time stamps (RFC 3339 format)
/// - AU-12: Audit generation
///
/// **STIG Requirements:**
/// - APSC-DV-000830 (CAT II): Audit generation
/// - APSC-DV-000840 (CAT II): Audit record content
///
/// # Audit Record Format
///
/// **Text Format**: `<timestamp> [<level>] <message> <fields>`
/// **JSON Format**: `{"timestamp":"...","level":"...","message":"...","fields":{...}}`
///
/// Timestamps use RFC 3339 (ISO 8601 with timezone) for consistency.
```

---

#### 8. `src/error.rs` - Error Handling
**Comments**: SI-10

```rust
/// EST client error types.
///
/// # Security Controls
///
/// **NIST 800-53 Rev 5:**
/// - SI-10: Information input validation (error context)
///
/// **STIG Requirements:**
/// - APSC-DV-000500 (CAT I): Input validation
///
/// # Error Handling Best Practices
///
/// - Preserve context for debugging
/// - Redact sensitive data (passwords, private keys)
/// - Provide actionable error messages
/// - Map HTTP status codes to error types
```

---

#### 9. `src/bootstrap.rs` - Bootstrap/TOFU
**Comments**: IA-2, SI-10

```rust
/// Bootstrap client for Trust On First Use (TOFU) mode.
///
/// # Security Controls
///
/// **NIST 800-53 Rev 5:**
/// - IA-2: Identification and authentication
/// - SI-10: Information input validation
///
/// **STIG Requirements:**
/// - APSC-DV-000160 (CAT I): Authentication
/// - APSC-DV-003235 (CAT I): Certificate validation
///
/// # Security Warning
///
/// Bootstrap mode accepts certificates without validation on first use.
/// The certificate fingerprint MUST be verified out-of-band before trusting.
/// This is typically done by:
/// - Phone call to CA administrator
/// - Secure messaging with verified fingerprint
/// - Physical verification of printed fingerprint
///
/// Without out-of-band verification, bootstrap mode is vulnerable to MITM attacks.
```

---

#### 10. `src/windows/cng.rs` - CNG Key Management
**Comments**: SC-12, IA-5

```rust
/// CNG (Cryptography Next Generation) key provider.
///
/// # Security Controls
///
/// **NIST 800-53 Rev 5:**
/// - SC-12: Cryptographic key establishment and management
/// - IA-5: Authenticator management
///
/// **STIG Requirements:**
/// - APSC-DV-000170 (CAT I): Cryptographic protection
///
/// # Key Generation
///
/// Keys are generated using BCryptGenRandom, the Windows FIPS 140-2
/// validated cryptographic random number generator (CMVP #4596).
///
/// Supported algorithms:
/// - RSA: 2048, 3072, 4096 bits (FIPS 186-4)
/// - ECDSA: P-256, P-384, P-521 (FIPS 186-4)
///
/// # Key Storage
///
/// Keys are stored in CNG key containers with:
/// - Non-exportable flag (keys cannot be extracted)
/// - DPAPI protection (encryption at rest)
/// - TPM binding (optional, hardware-backed)
```

---

#### 11. `src/windows/dpapi.rs` - DPAPI Wrapper
**Comments**: SC-12, SC-28

```rust
/// Windows Data Protection API (DPAPI) wrapper.
///
/// # Security Controls
///
/// **NIST 800-53 Rev 5:**
/// - SC-12: Cryptographic key establishment (key protection)
/// - SC-28: Protection of information at rest
///
/// **STIG Requirements:**
/// - APSC-DV-000170 (CAT I): Cryptographic protection
///
/// # DPAPI Security Model
///
/// DPAPI provides user-scoped encryption where:
/// - Encryption keys derived from user login credentials
/// - Data encrypted for current user only
/// - Decryption requires user to be logged in
/// - Master keys protected by LSA (Local Security Authority)
///
/// This ties data protection to Windows authentication (IA-2).
```

---

### Priority 3: Example and Test Files (Informational)

#### Examples
- `examples/*.rs`: Add brief security control comments to demonstrate proper usage
- Show how to enable FIPS mode, configure TLS, use encryption

#### Tests
- `tests/*.rs`: Add comments explaining what controls are being tested
- Reference NIST controls and STIG IDs in test names
- Example: `test_tls_min_version_sc_8_compliance()`

---

## Implementation Steps

### Phase 1: Critical Security Modules (Week 1)
1. `src/tls.rs` - TLS configuration
2. `src/validation.rs` - Certificate validation
3. `src/fips/algorithms.rs` - FIPS enforcement
4. `src/logging/encryption.rs` - Audit log protection

### Phase 2: Supporting Modules (Week 2)
5. `src/windows/security.rs` - Windows security features
6. `src/config.rs` - Configuration management
7. `src/logging.rs` - Audit logging
8. `src/error.rs` - Error handling

### Phase 3: Additional Modules (Week 3)
9. `src/bootstrap.rs` - Bootstrap/TOFU
10. `src/windows/cng.rs` - CNG key management
11. `src/windows/dpapi.rs` - DPAPI wrapper
12. Other supporting files

### Phase 4: Examples and Tests (Week 4)
13. `examples/*.rs` - Usage examples
14. `tests/*.rs` - Test files
15. Documentation updates

---

## Verification Checklist

After adding comments to each file:

- [ ] All critical security functions have NIST control comments
- [ ] All STIG CAT I findings have comments in relevant code
- [ ] Comments reference specific control IDs (e.g., "SC-8", "APSC-DV-000160")
- [ ] Comments explain WHY the code satisfies the control
- [ ] Comments include algorithm details for cryptographic functions
- [ ] Comments reference RFCs where applicable
- [ ] Doc comments (`///`) updated for public APIs
- [ ] Internal comments (`//`) added for implementation details
- [ ] No sensitive data (keys, passwords) in comments
- [ ] Comments are clear and concise

---

## Maintenance

### When to Update Comments

1. **New Security Feature**: Add NIST/STIG comments immediately
2. **Security Code Modification**: Update affected control comments
3. **Control Framework Update**: Review and update control IDs
4. **STIG Version Change**: Update STIG version and finding IDs
5. **Compliance Audit**: Add any missing comments identified

### Review Schedule

- **Quarterly**: Review comment accuracy and completeness
- **On Code Changes**: Update comments for modified security code
- **Annual**: Comprehensive review during ATO renewal
- **On Compliance Update**: Update when NIST/STIG guidance changes

---

## Example: Before and After

### Before (Minimal Comments)
```rust
// Build TLS configuration
pub fn build_http_client(config: &EstClientConfig) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(config.timeout)
        .tls_backend_rustls();

    // Enforce minimum TLS version
    builder = builder.min_tls_version(reqwest::tls::Version::TLS_1_2);

    builder.build().map_err(|e| EstError::tls(e.to_string()))
}
```

### After (Full Security Comments)
```rust
/// Build a reqwest Client with the appropriate TLS configuration.
///
/// # Security Controls
///
/// **NIST 800-53 Rev 5:**
/// - SC-8: Transmission Confidentiality and Integrity (TLS 1.2+)
/// - IA-2: Identification and Authentication (Mutual TLS)
/// - AC-17: Remote Access (Secure protocol enforcement)
///
/// **STIG Requirements:**
/// - APSC-DV-000160 (CAT I): Cryptographically-based bidirectional authentication
/// - APSC-DV-000170 (CAT I): FIPS-validated cryptography for protection
///
/// # RFC 7030 Compliance
///
/// RFC 7030 Section 3.3.1 requires TLS 1.1 or later. We enforce TLS 1.2
/// as the minimum since TLS 1.1 is deprecated per NIST guidance.
pub fn build_http_client(config: &EstClientConfig) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(config.timeout)
        .tls_backend_rustls();

    // NIST 800-53: SC-8 (Transmission Confidentiality)
    // STIG: APSC-DV-000170 (CAT I) - Cryptographic Protection
    // RFC 7030: Section 3.3.1 compliance
    // Enforce minimum TLS version 1.2 (TLS 1.1 is deprecated)
    builder = builder.min_tls_version(reqwest::tls::Version::TLS_1_2);

    builder.build().map_err(|e| EstError::tls(e.to_string()))
}
```

---

## Tools and Automation

### Comment Validation Script (Future)
```bash
#!/bin/bash
# check-security-comments.sh
# Validates that critical security functions have proper NIST/STIG comments

CRITICAL_FILES=(
    "src/tls.rs"
    "src/validation.rs"
    "src/fips/algorithms.rs"
    "src/logging/encryption.rs"
)

for file in "${CRITICAL_FILES[@]}"; do
    if ! grep -q "NIST 800-53" "$file"; then
        echo "WARNING: $file missing NIST control comments"
    fi
    if ! grep -q "STIG:" "$file"; then
        echo "WARNING: $file missing STIG requirement comments"
    fi
done
```

---

## References

- **NIST SP 800-53 Rev 5**: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
- **Application Development STIG V5R3**: https://public.cyber.mil/stigs/
- **Control Traceability Matrix**: `docs/ato/control-traceability-matrix.md`
- **Code-to-Control Mapping**: `docs/ato/CODE-TO-CONTROL-MAPPING.md`
- **STIG Checklist**: `docs/ato/stig-checklist.md`

---

**End of Implementation Plan**
