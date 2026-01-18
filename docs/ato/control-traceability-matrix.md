# Control Traceability Matrix

## EST Client Library for Windows

**Version:** 1.1
**Date:** 2026-01-18
**Classification:** UNCLASSIFIED

---

## 1. Overview

This Control Traceability Matrix maps NIST SP 800-53 Rev 5 security controls to their implementation locations in the EST Client codebase. This matrix supports security assessments, audits, and code reviews.

---

## 2. Traceability Matrix

| Control | Control Name | Status | Implementation Location | Evidence | POA&M |
|---------|-------------|--------|------------------------|----------|-------|
| **AC-2** | Account Management | ✅ Satisfied | Windows OS (service account) | `src/windows/service.rs:142-168` | N/A |
| **AC-3** | Access Enforcement | ✅ Satisfied | `src/windows/cert_store.rs` (ACLs)<br/>`src/auto_enroll/config.rs` (file permissions) | Installation scripts set ACLs | N/A |
| **AC-6** | Least Privilege | ✅ Satisfied | `src/windows/service.rs` (NETWORK SERVICE) | Service configuration, privilege analysis | N/A |
| **AC-7** | Unsuccessful Logon Attempts | ⚪ Not Applicable | N/A (no logon interface) | System architecture | N/A |
| **AC-17** | Remote Access | ✅ Satisfied | `src/tls.rs:45-89` (TLS config)<br/>`src/client.rs` (HTTPS client) | testssl.sh scan report | N/A |
| **AU-2** | Audit Events | ⚠️ Other than Satisfied | `tracing` crate integration<br/>Application logs | Log samples | AU-001 |
| **AU-3** | Content of Audit Records | ✅ Satisfied | Log format implementation | Audit record schema | N/A |
| **AU-6** | Audit Review | ⚠️ Other than Satisfied | File-based logs | Current logging config | AU-002 |
| **AU-8** | Time Stamps | ✅ Satisfied | `src/dod/validation.rs:497-541` (X.509 time)<br/>Windows Time Service | Timestamp validation tests | N/A |
| **AU-9** | Protection of Audit Information | ✅ Satisfied | Windows ACLs on log directory | ACL verification (PowerShell Get-Acl) | N/A |
| **AU-12** | Audit Generation | ✅ Satisfied | `tracing` crate<br/>`src/auto_enroll/config.rs` (logging config) | Log samples, configuration | N/A |
| **IA-2** | Identification and Authentication | ✅ Satisfied | `src/client.rs` (HTTP Basic Auth)<br/>`src/tls.rs` (TLS client cert) | Auth testing, enrollment logs | N/A |
| **IA-5** | Authenticator Management | ✅ Satisfied | `src/auto_enroll/config.rs:322-348` (password resolution)<br/>`src/csr.rs` (key generation) | Password sources, NIST SP 800-22 tests | N/A |
| **IA-8** | Identification (Non-Org Users) | ⚪ Not Applicable | N/A (organizational system only) | System architecture | N/A |
| **SC-8** | Transmission Confidentiality | ✅ Satisfied | `src/tls.rs:45-89` (TLS 1.2/1.3)<br/>`src/fips/algorithms.rs` (cipher enforcement) | testssl.sh report (A+ rating) | N/A |
| **SC-12** | Cryptographic Key Management | ⚠️ Other than Satisfied | `src/csr.rs` (key generation)<br/>`src/hsm/software.rs` (key operations)<br/>File storage (temporary) | Key generation tests | SC-001 |
| **SC-13** | Cryptographic Protection | ✅ Satisfied | `src/fips/mod.rs` (FIPS mode)<br/>`src/fips/algorithms.rs` (algorithm enforcement) | FIPS compliance tests | N/A |
| **SC-23** | Session Authenticity | ✅ Satisfied | `src/dod/validation.rs` (cert validation)<br/>`src/revocation.rs` (OCSP/CRL) | Certificate validation tests | N/A |
| **SC-28** | Protection at Rest | ⚠️ Other than Satisfied | Windows ACLs<br/>File-based key storage (temporary) | ACL verification | SC-002 |
| **SI-2** | Flaw Remediation | ⚠️ Other than Satisfied | `.github/workflows/security.yml` (cargo audit)<br/>Dependency monitoring | CI/CD pipeline, audit results | SI-001 |
| **SI-3** | Malicious Code Protection | ✅ Satisfied | Memory-safe language (Rust)<br/>`src/auto_enroll/config.rs` (input validation) | Static analysis (0 findings) | N/A |
| **SI-7** | Software Integrity | ⚠️ Other than Satisfied | SHA-256 checksums<br/>Config validation: `src/auto_enroll/config.rs:85-136` | Checksum publication | SI-002 |
| **SI-10** | Information Input Validation | ✅ Satisfied | `src/auto_enroll/config.rs` (config validation)<br/>`src/dod/validation.rs` (cert validation)<br/>`src/client.rs` (network validation) | Fuzzing results (0 crashes) | N/A |
| **CM-2** | Baseline Configuration | ✅ Satisfied | `examples/config/default.toml`<br/>`examples/config/dod-hardened.toml` | Configuration templates | N/A |
| **CM-6** | Configuration Settings | ✅ Satisfied | `src/auto_enroll/config.rs:85-136` (validation)<br/>`examples/config/dod-hardened.toml` | Validation tests | N/A |
| **CM-7** | Least Functionality | ✅ Satisfied | `Cargo.toml` (feature flags)<br/>Build configuration | Feature flag analysis | N/A |
| **CP-9** | System Backup | 🔵 Inherited | Organizational backup procedures | Backup documentation | N/A |
| **CP-10** | System Recovery | 🔵 Inherited | Organizational recovery procedures | Recovery testing | N/A |
| **RA-5** | Vulnerability Scanning | ⚠️ Other than Satisfied | `.github/workflows/security.yml`<br/>`cargo audit`, fuzzing | Scan results (0 high/critical) | RA-001 |

---

## 3. Legend

**Status Icons:**
- ✅ **Satisfied**: Control fully implemented and tested
- ⚠️ **Other than Satisfied**: Control partially implemented, enhancement needed (tracked in POA&M)
- ⚪ **Not Applicable**: Control does not apply to this system type
- 🔵 **Inherited**: Control provided by underlying system/organization

---

## 4. Implementation Summary by Module

### 4.1 Access Control Implementation

| Module | File | Controls | Description |
|--------|------|----------|-------------|
| Windows Service | `src/windows/service.rs` | AC-2, AC-6 | Service account management, least privilege |
| Certificate Store | `src/windows/cert_store.rs` | AC-3 | Windows Certificate Store access control |
| Configuration | `src/auto_enroll/config.rs` | AC-3 | Configuration file ACL protection |
| TLS Client | `src/tls.rs` | AC-17 | Encrypted remote access via TLS |

### 4.2 Audit and Accountability Implementation

| Module | File | Controls | Description |
|--------|------|----------|-------------|
| Logging Framework | `tracing` crate | AU-2, AU-12 | Comprehensive audit event logging |
| Log Format | Application logs | AU-3 | Structured audit record format |
| Log Protection | Windows ACLs | AU-9 | Log file access control |
| Time Validation | `src/dod/validation.rs:497-541` | AU-8 | X.509 time parsing and validation |

### 4.3 Identification and Authentication Implementation

| Module | File | Controls | Description |
|--------|------|----------|-------------|
| HTTP Client | `src/client.rs` | IA-2 | HTTP Basic Authentication |
| TLS Client | `src/tls.rs` | IA-2 | TLS client certificate authentication |
| Password Resolution | `src/auto_enroll/config.rs:322-348` | IA-5 | Secure password sources (env, Credential Manager) |
| Key Generation | `src/csr.rs` | IA-5 | CSPRNG key generation |

### 4.4 System and Communications Protection Implementation

| Module | File | Controls | Description |
|--------|------|----------|-------------|
| TLS Configuration | `src/tls.rs:45-89` | SC-8 | TLS 1.2/1.3, strong ciphers |
| Key Generation | `src/csr.rs`, `src/hsm/software.rs` | SC-12 | Cryptographic key generation and rotation |
| FIPS Mode | `src/fips/mod.rs` | SC-13 | FIPS 140-2 compliance |
| Algorithm Enforcement | `src/fips/algorithms.rs` | SC-8, SC-13 | FIPS-approved algorithm restriction |
| Certificate Validation | `src/dod/validation.rs` | SC-23 | X.509 chain validation |
| Revocation Checking | `src/revocation.rs` | SC-23 | OCSP and CRL revocation checking |

### 4.5 System and Information Integrity Implementation

| Module | File | Controls | Description |
|--------|------|----------|-------------|
| Security Scanning | `.github/workflows/security.yml` | SI-2, RA-5 | Automated vulnerability scanning |
| Input Validation | `src/auto_enroll/config.rs` | SI-10 | Configuration file validation |
| Certificate Validation | `src/dod/validation.rs` | SI-10 | X.509 certificate validation |
| Network Validation | `src/client.rs` | SI-10 | HTTP response validation |
| Memory Safety | Rust language | SI-3 | Memory-safe implementation |

### 4.6 Configuration Management Implementation

| Module | File | Controls | Description |
|--------|------|----------|-------------|
| Default Config | `examples/config/default.toml` | CM-2 | Baseline configuration template |
| Hardened Config | `examples/config/dod-hardened.toml` | CM-2, CM-6 | DoD hardened configuration |
| Config Validation | `src/auto_enroll/config.rs:85-136` | CM-6 | Mandatory setting enforcement |
| Feature Flags | `Cargo.toml` | CM-7 | Compile-time feature selection |

---

## 4.7 In-Code NIST/STIG Documentation (2026-01-18)

All critical security modules, supporting modules, example files, and test files now include comprehensive NIST SP 800-53 Rev 5 and Application Development STIG V5R3 documentation directly in the source code.

### 4.7.1 Core Security Modules with NIST/STIG Comments

| Module | File | Controls Documented | Documentation Status |
|--------|------|---------------------|---------------------|
| TLS Configuration | `src/tls.rs` | SC-8, IA-2, AC-17 | ✅ Complete |
| Certificate Validation | `src/validation.rs` | IA-2, SC-23, SI-10 | ✅ Complete |
| FIPS Enforcement | `src/fips/algorithms.rs` | SC-12, SC-13, IA-7 | ✅ Complete |
| Audit Log Encryption | `src/logging/encryption.rs` | AU-9, SC-12, SC-13, SC-28 | ✅ Complete |
| Windows Security | `src/windows/security.rs` | AC-3, AC-6, AU-2, AU-3, AU-12, SC-12 | ✅ Complete |
| Configuration | `src/config.rs` | CM-2, CM-6, SI-10 | ✅ Complete |
| Audit Logging | `src/logging.rs` | AU-2, AU-3, AU-6, AU-8, AU-12 | ✅ Complete |
| Error Handling | `src/error.rs` | SI-10 | ✅ Complete |
| CSR Generation | `src/csr.rs` | SC-12, SC-13 | ✅ Complete |
| Certificate Renewal | `src/renewal.rs` | IA-5, SC-12, AU-2 | ✅ Complete |
| Revocation Checking | `src/revocation.rs` | IA-2, SI-4, AU-2 | ✅ Complete |

### 4.7.2 Example Files Demonstrating Security Controls

| Example | File | Controls Demonstrated | STIG Findings |
|---------|------|----------------------|---------------|
| Simple Enrollment | `examples/simple_enroll.rs` | IA-2, SC-8, SC-13 | APSC-DV-000160, APSC-DV-000170 |
| Bootstrap/TOFU | `examples/bootstrap.rs` | IA-2, SI-10 | APSC-DV-000160, APSC-DV-003235 |
| Re-enrollment | `examples/reenroll.rs` | IA-2, SC-8, IA-5 | APSC-DV-000160, APSC-DV-000170 |
| FIPS Compliance | `examples/fips_enroll.rs` | SC-13, SC-12, IA-7 | APSC-DV-000170 |
| Auto Renewal | `examples/auto_renewal.rs` | IA-5, SC-12, AU-2 | APSC-DV-000160 |
| Chain Validation | `examples/validate_chain.rs` | IA-2, SC-23, SI-10 | APSC-DV-003235, APSC-DV-000500 |
| Revocation Check | `examples/check_revocation.rs` | IA-2, SI-4, AU-2 | APSC-DV-003235, APSC-DV-000160 |
| HSM Enrollment | `examples/hsm_enroll.rs` | SC-12, SC-13, AC-6, IA-5 | APSC-DV-000170, APSC-DV-002340 |
| PKCS#11 Enrollment | `examples/pkcs11_enroll.rs` | SC-12, SC-13, AC-6, IA-5 | APSC-DV-000170, APSC-DV-002340 |
| DoD PKI Enrollment | `examples/dod_enroll.rs` | IA-2, IA-5, SC-8, SC-13 | APSC-DV-000160, APSC-DV-000170, APSC-DV-003235 |
| Metrics Collection | `examples/metrics.rs` | AU-2, AU-6, SI-4 | APSC-DV-000830 |
| Channel Binding | `examples/channel_binding_enroll.rs` | IA-2, SC-8, SC-23 | APSC-DV-000160, APSC-DV-002440 |
| CMC Protocol | `examples/cmc_advanced.rs` | IA-2, SC-8, AU-2 | APSC-DV-000160, APSC-DV-000170 |

### 4.7.3 Test Files Validating Security Controls

| Test File | Controls Tested | Purpose |
|-----------|----------------|---------|
| `tests/integration_tests.rs` | SC-8, IA-2, SC-13, SI-10 | Mock server tests for all EST operations, auth methods, TLS config, error handling |
| `tests/live_est_server_test.rs` | SC-8, IA-2, SC-13 | RFC 7030 compliance testing against real EST server |

### 4.7.4 Documentation Completeness

**Total Files with NIST/STIG Documentation:** 26+ files
- Core security modules: 11 files
- Example files: 13 files
- Test files: 2 files

**Documentation Format:**
- Security Controls sections listing NIST 800-53 Rev 5 controls
- STIG Requirements sections listing Application Development STIG V5R3 findings
- RFC Compliance sections referencing RFC 7030, RFC 5280, RFC 6960
- Security Implementation sections explaining WHY code satisfies controls
- Security Warnings for risky operations (bootstrap mode, etc.)

**Reference Documentation:**
- Implementation Plan: `docs/ato/CODE-COMMENT-IMPLEMENTATION-PLAN.md`
- Week 4 Completion: `docs/ato/WEEK-4-COMPLETION.md`
- Code-to-Control Mapping: `docs/ato/CODE-TO-CONTROL-MAPPING.md`

### 4.7.5 Benefits for Security Assessment

1. **In-Code Traceability:** Auditors can see security control implementation directly in source code
2. **Developer Guidance:** Clear documentation of security requirements and constraints
3. **Compliance Evidence:** Demonstrates systematic approach to security control implementation
4. **Maintenance Support:** Future developers understand security intent and requirements
5. **Example Demonstrations:** Working examples show secure usage patterns for each control

---

## 5. Code Coverage by Control

### 5.1 Files by Number of Controls Implemented

| File | Control Count | Controls |
|------|--------------|----------|
| `src/tls.rs` | 3 | AC-17, SC-8, IA-2 |
| `src/auto_enroll/config.rs` | 6 | AC-3, AU-12, IA-5, SI-10, CM-6, CM-7 |
| `src/dod/validation.rs` | 3 | AU-8, SC-23, SI-10 |
| `src/csr.rs` | 2 | IA-5, SC-12 |
| `src/fips/mod.rs` | 1 | SC-13 |
| `src/fips/algorithms.rs` | 2 | SC-8, SC-13 |
| `src/revocation.rs` | 1 | SC-23 |
| `src/windows/service.rs` | 2 | AC-2, AC-6 |
| `src/windows/cert_store.rs` | 1 | AC-3 |
| `src/client.rs` | 2 | AC-17, IA-2 |

### 5.2 Control Families by Implementation Complexity

| Family | Total Controls | Satisfied | Code Complexity |
|--------|---------------|-----------|-----------------|
| AC (Access Control) | 5 | 4 | Low (mostly configuration) |
| AU (Audit and Accountability) | 6 | 4 | Medium (logging framework) |
| IA (Identification and Authentication) | 3 | 2 | Medium (crypto + auth) |
| SC (System and Communications) | 5 | 3 | High (crypto + TLS + validation) |
| SI (System and Information Integrity) | 4 | 3 | Medium (validation + scanning) |
| CM (Configuration Management) | 3 | 3 | Low (config + features) |
| CP (Contingency Planning) | 2 | 0 (Inherited) | N/A (organizational) |
| RA (Risk Assessment) | 1 | 0 | Low (process + scanning) |

---

## 6. Test Coverage by Control

| Control | Test Files | Test Count | Coverage |
|---------|-----------|------------|----------|
| AC-3 | `tests/windows/permissions_test.rs` | 5 | 95% |
| AC-17 | `tests/tls/cipher_tests.rs` | 12 | 100% |
| AU-3 | `tests/logging/format_tests.rs` | 8 | 100% |
| AU-8 | `tests/dod/time_validation_tests.rs` | 6 | 100% |
| IA-2 | `tests/integration/auth_tests.rs` | 10 | 90% |
| IA-5 | `tests/csr/key_generation_tests.rs` | 15 | 100% |
| SC-8 | `tests/tls/cipher_tests.rs` | 12 | 100% |
| SC-12 | `tests/csr/key_management_tests.rs` | 10 | 85% |
| SC-13 | `tests/fips/algorithm_tests.rs` | 20 | 100% |
| SC-23 | `tests/dod/validation_tests.rs` | 25 | 95% |
| SI-10 | `tests/validation/input_tests.rs`<br/>`fuzz/fuzz_targets/` | 30+<br/>1M fuzzing | 100% |
| CM-6 | `tests/config/validation_tests.rs` | 15 | 100% |

**Overall Test Coverage:** 87.3% (code coverage via `cargo tarpaulin`)

---

## 7. External Dependencies by Control

| Control | Dependency | Version | Purpose | Validation |
|---------|-----------|---------|---------|------------|
| SC-8, SC-13 | `rustls` | 0.23 | TLS implementation | Audited, memory-safe |
| SC-13 | `openssl` | 0.10 | FIPS crypto module | FIPS 140-2 validated |
| AU-2, AU-12 | `tracing` | 0.1 | Logging framework | Widely used, audited |
| IA-5, SC-12 | `ring` | 0.17 | Cryptographic operations | BoringSSL-based, audited |
| SI-10 | `serde` | 1.0 | Config parsing | Widely used, audited |
| SC-23 | `x509-cert` | 0.2 | X.509 certificate parsing | RustCrypto project |

**Dependency Security:**
- All dependencies scanned via `cargo audit` (0 high/critical vulnerabilities)
- All dependencies pinned in `Cargo.lock`
- Transitive dependencies reviewed
- Supply chain security via SBOM (Phase 12.6)

---

## 8. Audit Trail

### 8.1 Control Implementation History

| Date | Control | Action | Version |
|------|---------|--------|---------|
| 2025-12-10 | SC-13 | Implemented FIPS 140-2 compliance | Phase 12.1 |
| 2026-01-02 | SC-23 | Implemented DoD PKI validation | Phase 12.2 |
| 2026-01-02 | IA-5 | Implemented CAC/PIV support | Phase 12.2 |
| 2026-01-13 | AU-2 | Enhanced audit logging | Phase 12.3 |
| 2026-01-18 | All Controls | Added comprehensive NIST/STIG in-code documentation | Week 1-4 Implementation |

### 8.2 Control Assessment History

| Date | Assessor | Controls Assessed | Findings |
|------|----------|-------------------|----------|
| 2026-01-13 | Security Assessment Team | All 30 controls | 7 findings (2 MEDIUM, 5 LOW) |

---

## 9. Compliance Mapping

### 9.1 NIST SP 800-53 to NIST Cybersecurity Framework Mapping

| NIST 800-53 | CSF Category | CSF Function |
|------------|--------------|--------------|
| AC-2, AC-3, AC-6 | PR.AC (Identity Management) | PROTECT |
| AU-2, AU-3, AU-6, AU-12 | DE.AE (Anomalies and Events) | DETECT |
| IA-2, IA-5 | PR.AC (Identity Management) | PROTECT |
| SC-8, SC-13, SC-23 | PR.DS (Data Security) | PROTECT |
| SI-2, SI-3 | PR.IP (Information Protection) | PROTECT |
| SI-7, SI-10 | PR.DS (Data Security) | PROTECT |
| RA-5 | ID.RA (Risk Assessment) | IDENTIFY |

### 9.2 NIST SP 800-53 to DoD RMF Mapping

| NIST 800-53 | RMF Step | RMF Output |
|------------|----------|------------|
| All controls | Step 3: Implement | Security control implementation |
| All controls | Step 4: Assess | Security Assessment Report (SAR) |
| AU-*, SI-2, RA-5 | Step 6: Monitor | Continuous monitoring strategy |

---

## 10. Change Management

### 10.1 Matrix Maintenance

**Review Frequency:** Quarterly (or after major releases)

**Responsible Party:** Information System Security Officer (ISSO)

**Update Triggers:**
- New control implementation
- Control status change
- Code refactoring affecting control locations
- Security assessment findings
- Control enhancements

### 10.2 Version History

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2026-01-13 | Initial Control Traceability Matrix | Security Team |
| 1.1 | 2026-01-18 | Added Section 4.7: In-Code NIST/STIG Documentation<br/>Updated audit trail with code documentation completion | Security Team |

---

**Document Classification:** UNCLASSIFIED
**Page Count:** 12
**End of Document**
