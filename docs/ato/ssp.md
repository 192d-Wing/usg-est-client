# System Security Plan (SSP)

## EST Client Library for Windows

**Version:** 1.0
**Date:** 2026-01-13
**Classification:** UNCLASSIFIED
**Distribution:** Authorized to U.S. Government agencies and their contractors

---

## 1. System Identification

### 1.1 System Name and Identifier

**System Name:** EST (Enrollment over Secure Transport) Client Library
**System Abbreviation:** EST-CLIENT
**Unique Identifier:** TBD (Assigned by authorizing official)

### 1.2 System Categorization

Per FIPS 199 and NIST SP 800-60:

- **Confidentiality:** MODERATE
- **Integrity:** HIGH
- **Availability:** MODERATE

**Overall Impact Level:** HIGH

**Rationale:**
- Confidentiality (MODERATE): System handles private keys and certificates but not classified data
- Integrity (HIGH): Compromise could enable unauthorized network access or impersonation
- Availability (MODERATE): Service disruption affects certificate lifecycle but has workarounds

### 1.3 Responsible Organization

**Organization:** [Organization Name]
**Address:** [Organization Address]
**Point of Contact:** [Name, email, phone]

### 1.4 Information System Owner

**Name:** [System Owner Name]
**Title:** [Title]
**Organization:** [Organization]
**Email:** [Email]
**Phone:** [Phone]

### 1.5 Authorizing Official

**Name:** [AO Name]
**Title:** [Title]
**Organization:** [Organization]
**Email:** [Email]
**Phone:** [Phone]

### 1.6 Other Designated Contacts

**Information System Security Officer (ISSO):**
- Name: [ISSO Name]
- Email: [Email]
- Phone: [Phone]

**System Administrator:**
- Name: [Admin Name]
- Email: [Email]
- Phone: [Phone]

---

## 2. System Description

### 2.1 General System Description

The EST Client Library is a Rust-based software library and Windows service that implements RFC 7030 (Enrollment over Secure Transport) for automated certificate lifecycle management. It replaces Microsoft Active Directory Certificate Services (ADCS) auto-enrollment in DoD environments.

**Primary Functions:**
1. Automated certificate enrollment from EST servers
2. Automatic certificate renewal before expiration
3. Certificate revocation checking (CRL/OCSP)
4. CAC/PIV smart card integration
5. DoD PKI certificate chain validation
6. FIPS 140-2 compliant cryptographic operations

### 2.2 System Environment

**Operational Environment:**
- Windows Server 2019/2022 (Domain-joined systems)
- Windows 10/11 Enterprise (Workstations)
- .NET Framework not required (native Rust binary)

**Network Architecture:**
- Installed on Windows machines within DoD network
- HTTPS connections to EST server (port 443)
- OCSP/CRL connections for revocation checking (ports 80/443)
- No inbound connections required

**Deployment Model:**
- Library: Embedded in client applications
- Service: Windows background service for auto-enrollment
- Standalone: Command-line tool for manual operations

### 2.3 System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Windows Workstation                      │
│  ┌────────────────────────────────────────────────────────┐ │
│  │         EST Auto-Enrollment Service                    │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐ │ │
│  │  │   Machine    │  │     CSR      │  │   Windows   │ │ │
│  │  │   Identity   │──│  Generator   │──│  Cert Store │ │ │
│  │  └──────────────┘  └──────────────┘  └─────────────┘ │ │
│  │          │                 │                  │        │ │
│  │          └─────────────────┴──────────────────┘        │ │
│  │                            │                            │ │
│  │  ┌─────────────────────────┴───────────────────────┐  │ │
│  │  │          EST Client Library (Rust)              │  │ │
│  │  │  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │  │ │
│  │  │  │   TLS    │  │   HTTP   │  │  FIPS Crypto │  │  │ │
│  │  │  │  Client  │──│  Client  │──│   (OpenSSL)  │  │  │ │
│  │  │  └──────────┘  └──────────┘  └──────────────┘  │  │ │
│  │  └──────────────────────┬──────────────────────────┘  │ │
│  └─────────────────────────┼─────────────────────────────┘ │
│                            │                                │
│  ┌─────────────────────────┼─────────────────────────────┐ │
│  │       Optional: CAC/PIV Smart Card                    │ │
│  │  ┌──────────────┐      │      ┌──────────────┐       │ │
│  │  │    PKCS#11   │──────┼──────│  PIV Applet  │       │ │
│  │  │   Middleware │      │      │ (9A/9C/9D/9E)│       │ │
│  │  └──────────────┘      │      └──────────────┘       │ │
│  └────────────────────────┼──────────────────────────────┘ │
└────────────────────────────┼────────────────────────────────┘
                             │ HTTPS (TLS 1.2/1.3)
                             ▼
         ┌───────────────────────────────────────┐
         │          EST Server                   │
         │  ┌─────────────────────────────────┐  │
         │  │   RFC 7030 EST Endpoints        │  │
         │  │   • /cacerts                    │  │
         │  │   • /simpleenroll               │  │
         │  │   • /simplereenroll             │  │
         │  │   • /csrattrs (optional)        │  │
         │  └─────────────────────────────────┘  │
         └───────────────────────────────────────┘
                             │
                             ▼
         ┌───────────────────────────────────────┐
         │    DoD PKI Certificate Authority      │
         │  ┌─────────────────────────────────┐  │
         │  │   DoD Root CA 2-6               │  │
         │  │   Issuing CAs                   │  │
         │  │   CRL Distribution Points       │  │
         │  │   OCSP Responders               │  │
         │  └─────────────────────────────────┘  │
         └───────────────────────────────────────┘
```

### 2.4 System Boundaries

**Authorization Boundary Includes:**
- EST Client Library (Rust codebase)
- EST Auto-Enrollment Windows Service
- Command-line enrollment tool
- Configuration files
- Certificate store integration
- Local audit logs

**Authorization Boundary Excludes:**
- EST Server (separate system with separate ATO)
- Windows Operating System (covered by Windows STIG)
- Network infrastructure (routers, firewalls)
- DoD PKI infrastructure (separate accreditation)
- CAC/PIV cards and readers (covered by PIV standards)

### 2.5 Data Flow

**Certificate Enrollment Flow:**

1. **Initialization**
   - Service reads configuration file
   - Validates FIPS mode if required
   - Loads DoD Root CA trust anchors

2. **Identity Determination**
   - Retrieves Windows computer name
   - Determines DNS domain
   - Constructs subject DN (e.g., CN=HOSTNAME.domain.mil)

3. **Key Generation**
   - Generates RSA 2048/3072/4096 or ECDSA P-256/P-384 key pair
   - Uses FIPS 140-2 validated crypto module when FIPS mode enabled
   - Private key stored in Windows CNG or secure file location

4. **CSR Construction**
   - Builds PKCS#10 CSR with subject DN
   - Adds Subject Alternative Names (DNS, IP)
   - Includes key usage and extended key usage extensions
   - Signs CSR with private key

5. **EST Enrollment**
   - Establishes TLS 1.2/1.3 connection to EST server
   - Authenticates via HTTP Basic Auth or TLS client certificate
   - POSTs CSR to `/simpleenroll` or `/simplereenroll`
   - Validates server certificate against DoD Root CAs

6. **Certificate Receipt**
   - Receives issued certificate in PKCS#7 format
   - Validates certificate chain to DoD Root CA
   - Verifies certificate matches CSR public key
   - Checks revocation status via OCSP/CRL

7. **Certificate Installation**
   - Imports certificate to Windows Certificate Store
   - Associates private key with certificate (CNG)
   - Sets certificate friendly name
   - Logs successful enrollment

8. **Monitoring Loop**
   - Periodically checks certificate expiration
   - Triggers renewal when within threshold (default: 30 days)
   - Performs automatic re-enrollment
   - Archives old certificate

---

## 3. Security Controls

This section maps NIST SP 800-53 Rev 5 security controls to EST Client implementation.

### 3.1 Access Control (AC)

#### AC-2: Account Management

**Control:** The information system manages information system accounts.

**Implementation:**
- EST Client uses Windows integrated authentication for service account
- Service runs as NETWORK SERVICE or dedicated service account
- No additional user accounts created by EST Client
- EST server handles authorization (out of scope)

**Responsibility:** System (Windows OS account management)

#### AC-3: Access Enforcement

**Control:** The information system enforces approved authorizations for logical access.

**Implementation:**
- Windows file system ACLs protect configuration files (read-only for users)
- Private keys stored with restrictive permissions (SYSTEM only)
- Certificate store access controlled by Windows (CurrentUser vs LocalMachine)
- EST server enforces authorization via HTTP Basic Auth or TLS client cert

**Implementation Location:**
- File permissions set during installation
- CNG key containers created with KEY_READ restriction
- See: `src/windows/cert_store.rs`

**Responsibility:** Shared (EST Client + Windows OS)

#### AC-6: Least Privilege

**Control:** The organization employs the principle of least privilege.

**Implementation:**
- Service runs with minimum required privileges (NETWORK SERVICE)
- No administrator privileges required for normal operation
- Configuration file specifies exact permissions needed
- Code follows principle of least privilege (no unnecessary capabilities)

**Implementation Location:**
- Service configuration: `src/windows/service.rs`
- Privilege requirements documented in installation guide

**Responsibility:** System

#### AC-7: Unsuccessful Logon Attempts

**Control:** The information system enforces a limit on consecutive invalid logon attempts.

**Implementation:**
- Not applicable (EST Client does not provide logon interface)
- Authentication handled by EST server (out of scope)

**Responsibility:** Not Applicable

#### AC-17: Remote Access

**Control:** The organization establishes and documents usage restrictions for remote access.

**Implementation:**
- All EST communication encrypted via TLS 1.2/1.3
- No remote access TO the EST Client (outbound only)
- Remote management via Windows Remote Desktop (separate control)

**Responsibility:** Shared (EST Client enforces TLS, Windows OS provides remote access)

### 3.2 Audit and Accountability (AU)

#### AU-2: Audit Events

**Control:** The information system generates audit records for defined events.

**Implementation:**
- EST Client logs all security-relevant events:
  - Certificate enrollment requests (success/failure)
  - Certificate renewal operations
  - Authentication failures
  - Configuration changes
  - Revocation check results
  - FIPS mode violations
  - Key generation events
  - Certificate validation failures

**Logged Information:**
- Timestamp (UTC)
- Event type
- Outcome (success/failure/error)
- User/service account
- Source IP (where applicable)
- Certificate subject DN
- Error details

**Implementation Location:**
- Audit logging: `src/logging/audit.rs` (Phase 12.5)
- Log events defined in: `src/logging/events.rs`

**Responsibility:** System

#### AU-3: Content of Audit Records

**Control:** The information system generates audit records containing required information.

**Implementation:**
- All audit records include:
  - Event timestamp (RFC 3339 format, UTC)
  - Event type (enrollment, renewal, revocation_check, etc.)
  - Outcome (success, failure, error)
  - Subject identity (certificate CN or computer name)
  - Event source (service name, version)
  - Additional context (certificate serial, thumbprint, EST server URL)

**Audit Record Format:**
```json
{
  "timestamp": "2026-01-13T14:23:45.123Z",
  "event_type": "certificate_enrollment",
  "outcome": "success",
  "subject": "CN=WORKSTATION01.example.mil",
  "source": "est-autoenroll-service/1.0.0",
  "est_server": "https://est.example.mil",
  "certificate_serial": "1A2B3C4D5E6F",
  "certificate_thumbprint": "SHA1:1234567890ABCDEF...",
  "details": "Certificate issued with 1-year validity"
}
```

**Responsibility:** System

#### AU-6: Audit Review, Analysis, and Reporting

**Control:** The organization reviews and analyzes information system audit records.

**Implementation:**
- Audit logs written to:
  - Windows Event Log (Phase 12.5)
  - Local file (JSON or CEF format)
  - SIEM via syslog/TLS (Phase 12.5)
- Integration with enterprise SIEM (Splunk, ELK, ArcSight)
- Pre-built SIEM dashboards for monitoring
- Automated alerting for critical events

**Critical Events for Alerting:**
- Certificate enrollment failures (3+ consecutive)
- FIPS mode violations
- Revocation check failures
- Certificate expiration within 7 days
- Authentication failures to EST server

**Responsibility:** Shared (EST Client generates logs, organization reviews)

#### AU-8: Time Stamps

**Control:** The information system uses internal system clocks to generate time stamps.

**Implementation:**
- All audit events timestamped using Windows system clock
- Timestamps in UTC (ISO 8601 / RFC 3339 format)
- Synchronization with authoritative time source (Windows Time Service)
- Certificate validity checked against current time

**Implementation Location:**
- Time handling: `src/logging/timestamp.rs`
- X.509 time validation: `src/dod/validation.rs:497-541`

**Responsibility:** Shared (EST Client uses time, Windows OS synchronizes time)

#### AU-9: Protection of Audit Information

**Control:** The information system protects audit information from unauthorized access.

**Implementation:**
- Audit log files protected by Windows ACLs:
  - SYSTEM: Full Control
  - Administrators: Read
  - Users: No access
- Optional audit log encryption (Phase 12.5)
- Optional audit log signing for integrity (Phase 12.5)
- Log rotation with retention policy
- Archived logs moved to secure storage

**Implementation Location:**
- Log file permissions set during service installation
- Log rotation: `src/logging/rotation.rs` (Phase 12.5)

**Responsibility:** System

#### AU-12: Audit Generation

**Control:** The information system provides audit record generation capability.

**Implementation:**
- Comprehensive logging framework using `tracing` crate
- Structured logging (JSON/CEF formats)
- Configurable log levels (ERROR, WARN, INFO, DEBUG, TRACE)
- Log filtering by component
- Production deployments use INFO level (security events always logged)

**Configuration:**
```toml
[logging]
level = "INFO"
format = "json"
destination = "file"
file_path = "C:\\ProgramData\\EST\\logs\\audit.log"
rotation = "daily"
retention_days = 90
```

**Responsibility:** System

### 3.3 Identification and Authentication (IA)

#### IA-2: Identification and Authentication (Organizational Users)

**Control:** The information system uniquely identifies and authenticates organizational users.

**Implementation:**
- EST Client service authenticates to EST server via:
  - **HTTP Basic Authentication:** Username = machine account (COMPUTERNAME$)
  - **TLS Client Certificate:** Existing certificate for re-enrollment
- Service account identity managed by Windows
- No end-user authentication required (machine-level service)

**Implementation Location:**
- HTTP Basic Auth: `src/client.rs`
- TLS Client Cert: `src/tls.rs`
- Configuration: `src/auto_enroll/config.rs`

**Responsibility:** Shared (EST Client authenticates, EST server validates)

#### IA-5: Authenticator Management

**Control:** The organization manages information system authenticators.

**Implementation:**

**Password Management (HTTP Basic Auth):**
- Passwords never stored in configuration files
- Password sources:
  - Environment variables (set via Group Policy)
  - Windows Credential Manager (encrypted storage)
  - Secure file with restrictive ACLs
- Password complexity enforced by Active Directory policy

**Certificate Management (TLS Client Auth):**
- Private keys generated with cryptographically random entropy
- Private keys stored in Windows CNG (non-exportable)
- Key length requirements: RSA 2048+ bits, ECDSA P-256+ curve
- Automatic key rotation during renewal

**Implementation Location:**
- Password resolution: `src/auto_enroll/config.rs:322-348`
- Key generation: `src/csr.rs`, `src/hsm/software.rs`

**Responsibility:** Shared (EST Client manages, Windows OS provides key storage)

#### IA-8: Identification and Authentication (Non-Organizational Users)

**Control:** The information system uniquely identifies and authenticates non-organizational users.

**Implementation:**
- Not applicable (EST Client is an organizational system component)
- EST server identity verified via X.509 certificate chain validation
- Server certificate must chain to DoD Root CA

**Responsibility:** Not Applicable

### 3.4 System and Communications Protection (SC)

#### SC-8: Transmission Confidentiality and Integrity

**Control:** The information system protects the confidentiality and integrity of transmitted information.

**Implementation:**
- All EST communication encrypted via TLS 1.2 or TLS 1.3
- Minimum cipher suites (FIPS mode):
  - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
  - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
  - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
- No support for weak ciphers (3DES, RC4, NULL, EXPORT)
- Certificate validation enforced (no trust-on-first-use in production)

**Implementation Location:**
- TLS configuration: `src/tls.rs`
- FIPS cipher enforcement: `src/fips/algorithms.rs`
- DoD PKI validation: `src/dod/validation.rs`

**Responsibility:** System

#### SC-12: Cryptographic Key Establishment and Management

**Control:** The organization establishes and manages cryptographic keys.

**Implementation:**

**Key Generation:**
- RSA keys: 2048, 3072, or 4096 bits
- ECDSA keys: P-256, P-384, or P-521 curves
- Cryptographically secure random number generation (CSPRNG)
- FIPS 140-2 validated crypto module when FIPS mode enabled

**Key Storage:**
- Private keys stored in Windows CNG key containers (non-exportable)
- Key protection via DPAPI or TPM (when available)
- Temporary workaround: PEM file with ACL restrictions

**Key Usage:**
- Private keys used only for:
  - CSR signing during enrollment
  - TLS client authentication during re-enrollment
- Keys never transmitted over network
- Keys rotated automatically during certificate renewal

**Key Destruction:**
- Old private keys securely deleted after successful renewal
- CNG key deletion via CryptDestroyKey API
- File-based keys overwritten with random data before deletion

**Implementation Location:**
- Key generation: `src/csr.rs`, `src/hsm/software.rs`
- Key storage: Windows CNG API (Phase 11.2)
- Key rotation: `src/auto_enroll/enrollment.rs`

**Responsibility:** System

#### SC-13: Cryptographic Protection

**Control:** The information system implements FIPS-validated cryptography.

**Implementation:**
- FIPS 140-2 compliance via OpenSSL FIPS module (optional, feature-gated)
- Algorithm restrictions enforced when FIPS mode enabled:
  - Symmetric: AES-128-GCM, AES-256-GCM, AES-128-CBC, AES-256-CBC
  - Asymmetric: RSA 2048/3072/4096, ECDSA P-256/P-384/P-521
  - Hash: SHA-256, SHA-384, SHA-512
  - No weak algorithms: MD5, SHA-1 (except for certificate serial numbers), 3DES, RC4
- Runtime FIPS mode validation
- FIPS caveat certificate: [Certificate Number TBD]

**Implementation Location:**
- FIPS implementation: `src/fips/mod.rs`
- Algorithm enforcement: `src/fips/algorithms.rs`
- Configuration: `fips` feature flag in Cargo.toml

**Responsibility:** System

#### SC-23: Session Authenticity

**Control:** The information system protects the authenticity of communications sessions.

**Implementation:**
- TLS session authentication via server certificate validation
- Server certificate must chain to trusted DoD Root CA
- Certificate revocation checked via OCSP/CRL
- No session resumption with invalid/revoked certificates
- Session renegotiation follows secure renegotiation (RFC 5746)

**Implementation Location:**
- Certificate validation: `src/dod/validation.rs`
- Revocation checking: `src/revocation.rs`
- TLS configuration: `src/tls.rs`

**Responsibility:** System

#### SC-28: Protection of Information at Rest

**Control:** The information system protects the confidentiality and integrity of information at rest.

**Implementation:**

**Private Keys:**
- Stored in Windows CNG with DPAPI encryption (Windows OS provides)
- Optional TPM protection for private keys (Windows OS provides)
- File-based keys protected by Windows EFS (admin-configured)

**Configuration Files:**
- Passwords never stored in plaintext
- Sensitive fields use secure sources (env vars, Credential Manager)
- File ACLs restrict read access to SYSTEM and Administrators

**Certificates:**
- Public certificates (no encryption needed, integrity via signature)
- Windows Certificate Store protected by OS access controls

**Audit Logs:**
- Optional encryption of audit log files (Phase 12.5)
- ACLs prevent unauthorized modification
- Integrity protection via log signing (Phase 12.5)

**Responsibility:** Shared (EST Client manages keys/config, Windows OS encrypts)

### 3.5 System and Information Integrity (SI)

#### SI-2: Flaw Remediation

**Control:** The organization identifies, reports, and corrects information system flaws.

**Implementation:**
- Vulnerability scanning via `cargo audit` (Rust security advisories)
- Dependency scanning via `cargo deny`
- Continuous monitoring of dependencies for CVEs
- Security updates released within 30 days of disclosure
- Security advisories published on GitHub Security Advisories

**Process:**
1. Monitor Rust Security Advisory Database
2. Run `cargo audit` in CI/CD pipeline (daily)
3. Assess impact of identified vulnerabilities
4. Update dependencies or apply patches
5. Release security update with advisory
6. Notify users via GitHub, mailing list, NIEM

**Responsibility:** Organizational (development team)

#### SI-3: Malicious Code Protection

**Control:** The organization implements malicious code protection mechanisms.

**Implementation:**
- EST Client scanned by antivirus during installation
- Code signing of binaries (Authenticode for Windows)
- Builds performed in clean CI/CD environment
- Supply chain security via dependency verification
- SBOM (Software Bill of Materials) included in releases

**Preventive Measures:**
- Memory-safe language (Rust) prevents buffer overflows
- No dynamic code execution or eval()
- Input validation on all configuration file parsing
- No external script execution

**Implementation Location:**
- Input validation: `src/auto_enroll/config.rs`
- Build provenance: `.github/workflows/release.yml` (Phase 12.6)

**Responsibility:** Shared (EST Client code safety, Windows OS runs antivirus)

#### SI-7: Software, Firmware, and Information Integrity

**Control:** The organization employs integrity verification tools.

**Implementation:**

**Code Signing:**
- Windows executable signed with Authenticode certificate
- Signature verified by Windows during installation
- Signature includes timestamp (for validity after cert expiration)

**File Integrity:**
- SHA-256 checksums published for all release artifacts
- Checksums signed with GPG key
- Users verify checksums after download

**Configuration Integrity:**
- Configuration file parsed and validated on load
- Schema validation rejects unknown fields
- Syntax errors logged and service fails to start

**Runtime Integrity:**
- FIPS self-tests verify cryptographic module integrity
- Windows Code Integrity (CI) verifies executable signatures

**Implementation Location:**
- Config validation: `src/auto_enroll/config.rs`
- FIPS self-tests: `src/fips/self_test.rs`
- Build signing: Release process documentation

**Responsibility:** Shared (EST Client validates, Windows OS enforces)

#### SI-10: Information Input Validation

**Control:** The information system checks the validity of information inputs.

**Implementation:**

**Configuration File Validation:**
- TOML syntax validation (rejects malformed files)
- Schema validation with `serde` (deny_unknown_fields)
- Range checks (e.g., threshold_days > 0)
- URL validation (must be HTTPS, valid format)
- Path validation (prevent directory traversal)

**Certificate Validation:**
- X.509 structure parsing with error handling
- Signature verification
- Validity period checking
- Basic constraints validation
- Key usage validation
- Revocation checking

**Network Input Validation:**
- HTTP response validation (status codes, content-type)
- Base64 decoding with error handling
- DER/PEM parsing with bounds checking
- TLS certificate chain validation

**Implementation Location:**
- Config validation: `src/auto_enroll/config.rs:85-136`
- Certificate validation: `src/dod/validation.rs`
- Network validation: `src/client.rs`, `src/types/pkcs7.rs`

**Responsibility:** System

### 3.6 Configuration Management (CM)

#### CM-2: Baseline Configuration

**Control:** The organization develops and maintains a baseline configuration.

**Implementation:**
- Default configuration template provided: `examples/config/default.toml`
- Hardened configuration for DoD: `examples/config/dod-hardened.toml`
- Configuration documentation: `docs/windows-enrollment.md`
- Version control of configuration schemas
- Configuration Management Database (CMDB) entry recommended

**Baseline Components:**
- EST Client Library version
- Windows service configuration
- Certificate requirements (key algorithm, key usage)
- Renewal thresholds
- Logging configuration
- FIPS mode settings

**Responsibility:** Organizational (with EST Client providing templates)

#### CM-6: Configuration Settings

**Control:** The organization establishes mandatory configuration settings.

**Implementation:**

**Mandatory Settings (DoD Deployment):**
```toml
# FIPS mode required
[fips]
enabled = true
enforce = true

# TLS 1.2 minimum (1.3 preferred)
[security]
min_tls_version = "1.2"

# Certificate requirements
[certificate]
min_key_size = 2048  # RSA
min_ec_curve = "P-256"  # ECDSA

# Revocation checking required
[revocation]
enabled = true
require_valid = true

# Audit logging required
[logging]
level = "INFO"
audit_enabled = true
```

**Configuration Validation:**
- Service validates configuration on startup
- Fails to start if mandatory settings not met
- Logs configuration violations

**Responsibility:** Organizational (EST Client enforces)

#### CM-7: Least Functionality

**Control:** The organization configures the information system to provide only essential capabilities.

**Implementation:**
- Feature flags disable unused functionality at compile time
- Default build includes only core EST operations
- Optional features:
  - `fips`: FIPS 140-2 mode (DoD required)
  - `dod-pki`: DoD PKI integration (DoD required)
  - `hsm`: Hardware Security Module support (optional)
  - `revocation`: Revocation checking (DoD required)
  - `csr-gen`: CSR generation (required for enrollment)
- No unnecessary network services
- No remote management interface
- No scripting engine or plugin system

**Feature Flag Configuration:**
```toml
[dependencies]
usg-est-client = { version = "1.0", features = ["fips", "dod-pki", "revocation", "csr-gen"] }
```

**Responsibility:** System

### 3.7 Contingency Planning (CP)

#### CP-9: Information System Backup

**Control:** The organization conducts backups of information system data.

**Implementation:**

**Backed Up Data:**
- Configuration files (TOML)
- Installed certificates (Windows Certificate Store backup)
- Private keys (if file-based storage used)
- Audit logs

**Backup Procedures:**
- Configuration files: Standard file backup
- Certificates: Windows Certificate Store export (PFX)
- Private keys: Encrypted backup with strong passphrase
- Logs: Log archival and rotation

**Backup Frequency:**
- Configuration: After each change
- Certificates: Daily
- Logs: Continuous archival

**Recovery Testing:**
- Restore configuration and verify service starts
- Import certificate backup and verify TLS works
- Verify audit log integrity after restoration

**Responsibility:** Organizational (backup procedures)

#### CP-10: Information System Recovery and Reconstitution

**Control:** The organization provides for the recovery and reconstitution of the information system.

**Implementation:**

**Recovery Procedures:**

1. **Service Reinstallation:**
   - Install EST Client from trusted source
   - Verify code signature
   - Restore configuration file

2. **Certificate Recovery:**
   - If backup available: Import PFX to Certificate Store
   - If no backup: Perform re-enrollment using new key pair
   - EST server validates existing identity

3. **Service Restart:**
   - Start Windows service
   - Verify successful enrollment/renewal cycle
   - Check audit logs for errors

**Recovery Time Objective (RTO):** 1 hour
**Recovery Point Objective (RPO):** 24 hours

**Responsibility:** Organizational (with EST Client supporting re-enrollment)

### 3.8 Risk Assessment (RA)

#### RA-5: Vulnerability Scanning

**Control:** The organization scans for vulnerabilities in the information system.

**Implementation:**

**Static Analysis:**
- Rust Clippy linter (catches common bugs)
- Cargo audit (dependency vulnerabilities)
- Cargo deny (license/advisory enforcement)
- SAST tools (Semgrep, CodeQL)

**Dynamic Analysis:**
- Fuzzing with cargo-fuzz (libFuzzer)
- Integration testing with live EST server
- TLS scanner (testssl.sh, SSLyze)

**Dependency Scanning:**
- Automated via GitHub Dependabot
- Weekly vulnerability reports
- Critical vulnerabilities patched within 7 days

**Penetration Testing:**
- Annual penetration test by qualified team
- Findings tracked in POA&M
- Remediation within 30 days (High/Critical), 90 days (Medium)

**Responsibility:** Organizational (with EST Client supporting scanning)

---

## 4. Control Implementation Summary

### 4.1 Controls by Family

| Family | Total Controls | Implemented | Inherited | Not Applicable |
|--------|---------------|-------------|-----------|----------------|
| AC (Access Control) | 5 | 4 | 1 | 0 |
| AU (Audit and Accountability) | 6 | 6 | 0 | 0 |
| IA (Identification and Authentication) | 3 | 2 | 0 | 1 |
| SC (System and Communications Protection) | 5 | 5 | 0 | 0 |
| SI (System and Information Integrity) | 4 | 4 | 0 | 0 |
| CM (Configuration Management) | 3 | 3 | 0 | 0 |
| CP (Contingency Planning) | 2 | 0 | 2 | 0 |
| RA (Risk Assessment) | 1 | 0 | 1 | 0 |
| **Total** | **29** | **24** | **4** | **1** |

### 4.2 Control Status Legend

- **Implemented:** EST Client provides the control
- **Inherited:** Control provided by underlying system (Windows OS, network)
- **Not Applicable:** Control does not apply to this system type

---

## 5. Attachments

### 5.1 System Diagrams

- System Architecture Diagram (Section 2.3)
- Network Topology Diagram (TBD - organization specific)
- Data Flow Diagram (Section 2.5)

### 5.2 Configuration Files

- Default Configuration Template: `examples/config/default.toml`
- DoD Hardened Configuration: `examples/config/dod-hardened.toml`
- FIPS Configuration Example: `examples/config/fips.toml`

### 5.3 Related Documentation

- [Security Architecture](../../docs/security.md)
- [FIPS 140-2 Compliance Guide](fips-compliance.md)
- [Windows Enrollment Guide](../windows-enrollment.md)
- [STIG Compliance Checklist](stig-checklist.md) (Phase 12.4)

### 5.4 Acronyms

| Acronym | Definition |
|---------|-----------|
| AO | Authorizing Official |
| ATO | Authority to Operate |
| CAC | Common Access Card |
| CMDB | Configuration Management Database |
| CRL | Certificate Revocation List |
| CSR | Certificate Signing Request |
| DoD | Department of Defense |
| ECA | External Certificate Authority |
| EST | Enrollment over Secure Transport |
| FIPS | Federal Information Processing Standard |
| ISSO | Information System Security Officer |
| NIST | National Institute of Standards and Technology |
| OCSP | Online Certificate Status Protocol |
| PIV | Personal Identity Verification |
| PKI | Public Key Infrastructure |
| POA&M | Plan of Action and Milestones |
| RFC | Request for Comments |
| SIEM | Security Information and Event Management |
| SSP | System Security Plan |
| STIG | Security Technical Implementation Guide |
| TLS | Transport Layer Security |

---

## 6. Approval and Revision History

### 6.1 Approval

**Information System Owner:**
- Signature: _________________________ Date: __________
- Name:

**Information System Security Officer:**
- Signature: _________________________ Date: __________
- Name:

**Authorizing Official:**
- Signature: _________________________ Date: __________
- Name:

### 6.2 Revision History

| Version | Date | Description | Author |
|---------|------|-------------|--------|
| 1.0 | 2026-01-13 | Initial System Security Plan | EST Client Team |

---

**Document Classification:** UNCLASSIFIED
**Page Count:** 27
**End of Document**
