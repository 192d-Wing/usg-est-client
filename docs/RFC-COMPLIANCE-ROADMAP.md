# RFC 7030 Compliance Roadmap

**Document Version:** 1.0
**Date:** 2026-01-15
**Status:** Active Development
**Current RFC Compliance:** 95%

## Executive Summary

This roadmap outlines the path to achieving 100% RFC 7030 compliance for the usg-est-client implementation. The project is currently at **95% compliance** with all mandatory requirements met. This document details the remaining work needed to complete optional features and enhance the implementation.

### Current Status

- ✅ **Core Protocol:** 100% compliant (all mandatory operations)
- ✅ **Authentication:** 100% compliant (TLS + HTTP Basic)
- ⚠️ **Optional Features:** 85% compliant (channel binding partial, CMC framework only)

---

## Phase 1: High Priority - TLS Channel Binding (Weeks 1-2)

**Status:** 🟡 Framework Present
**Priority:** HIGH
**RFC Reference:** RFC 7030 Section 3.5
**Estimated Effort:** 2 weeks
**Compliance Impact:** +3%

### Objectives

Complete TLS channel binding implementation to prevent man-in-the-middle attacks during initial enrollment with HTTP Basic authentication.

### Technical Requirements

#### 1.1 TLS-Unique Value Extraction

**File:** `src/tls.rs`

- [ ] Add `get_tls_unique()` method to extract tls-unique channel binding data
  - Extract from TLS Finished messages per RFC 5929
  - Support both TLS 1.2 and TLS 1.3 (use `tls-exporter` for 1.3)
  - Return `Result<Vec<u8>>` with proper error handling

- [ ] Integrate with rustls to access TLS connection state
  - May require custom `ServerCertVerifier` to capture handshake data
  - Alternative: Use `rustls::ClientConnection::export_keying_material()` for TLS 1.3

**Code Location:** [src/tls.rs](../src/tls.rs)

#### 1.2 CSR Challenge-Password Integration

**File:** `src/operations/enroll.rs`

- [ ] Modify `encode_csr()` to accept optional channel binding value
  - Add parameter: `channel_binding: Option<&[u8]>`
  - When present, embed tls-unique in CSR challenge-password attribute

- [ ] Create CSR attribute injection helper
  - Parse existing CSR DER
  - Add/replace challenge-password attribute with base64(tls-unique)
  - Re-encode CSR with updated attributes

**Code Location:** [src/operations/enroll.rs](../src/operations/enroll.rs#L82-L85)

#### 1.3 Client API Enhancement

**File:** `src/client.rs`

- [ ] Add channel binding option to `EstClientConfig`
  - Boolean flag: `enable_channel_binding`
  - Default: `false` (opt-in for backward compatibility)

- [ ] Update `simple_enroll()` to use channel binding when enabled
  - Extract tls-unique from current TLS connection
  - Inject into CSR before transmission
  - Log channel binding usage for audit trail

**Code Location:** [src/client.rs:132-135](../src/client.rs#L132-L135)

#### 1.4 Testing

- [ ] Unit tests for tls-unique extraction
- [ ] Integration tests with mock EST server
- [ ] Test with both TLS 1.2 and TLS 1.3
- [ ] Verify challenge-password format matches RFC 7030

**Test Location:** `tests/integration/tls/channel_binding_test.rs`

### Deliverables

1. Working TLS channel binding implementation
2. API documentation with usage examples
3. Security advisory update (when to use channel binding)
4. Test coverage >80% for new code

### Dependencies

- `rustls` >= 0.23 (for TLS state access)
- May need `der` crate updates for CSR attribute manipulation

### Success Criteria

- [ ] Channel binding can be enabled via configuration
- [ ] tls-unique value correctly embedded in CSR
- [ ] EST server can verify channel binding
- [ ] All tests pass
- [ ] Documentation complete

---

## Phase 2: Medium Priority - CSR Signature Verification (Weeks 3-4)

**Status:** 🟡 Placeholder Implementation
**Priority:** MEDIUM
**RFC Reference:** RFC 2986 (PKCS#10)
**Estimated Effort:** 2 weeks
**Compliance Impact:** +1% (security enhancement)

### Objectives

Implement full PKCS#10 CSR signature verification to provide proof-of-possession validation for submitted CSRs.

### Technical Requirements

#### 2.1 PKCS#10 Parsing

**File:** `src/operations/enroll.rs`

- [ ] Replace placeholder `extract_public_key()` implementation
  - Parse CertificationRequest ASN.1 structure
  - Extract SubjectPublicKeyInfo from certificationRequestInfo
  - Support RSA, ECDSA P-256/P-384 public keys
  - Return parsed public key in SPKI format

**Code Location:** [src/operations/enroll.rs:88-107](../src/operations/enroll.rs#L88-L107)

#### 2.2 Signature Verification

**File:** `src/operations/enroll.rs`

- [ ] Implement `verify_csr_signature()` function
  - Parse signature algorithm from CSR
  - Extract signature BIT STRING
  - Hash certificationRequestInfo with appropriate algorithm
  - Verify signature using extracted public key

- [ ] Support signature algorithms:
  - RSA PKCS#1 v1.5 (SHA-256, SHA-384, SHA-512)
  - ECDSA (SHA-256, SHA-384)
  - RSA-PSS (if needed)

**Code Location:** [src/operations/enroll.rs:112-121](../src/operations/enroll.rs#L112-L121)

#### 2.3 Integration with Enrollment Flow

**File:** `src/client.rs`

- [ ] Add optional CSR verification step in `enroll_request()`
  - Configuration option: `verify_csr_signatures`
  - Default: `false` (client already knows CSR is valid)
  - Useful for server-side validation or auditing

- [ ] Add validation errors to `EstError` enum
  - `InvalidCsrSignature`
  - `UnsupportedSignatureAlgorithm`

**Code Location:** [src/client.rs:276-321](../src/client.rs#L276-L321)

#### 2.4 Testing

- [ ] Unit tests with pre-generated CSRs
  - Valid RSA CSRs (2048, 3072, 4096-bit)
  - Valid ECDSA CSRs (P-256, P-384)
  - Invalid signatures
  - Tampered CSRs

- [ ] Property-based testing
  - Generate random CSRs and verify signatures

**Test Location:** `tests/unit/csr_verification_test.rs`

### Deliverables

1. Complete CSR signature verification
2. Support for all common signature algorithms
3. Optional validation in enrollment flow
4. Comprehensive test suite

### Dependencies

- `rsa` crate (already included)
- `p256`, `p384` crates (already included)
- `signature` crate (already included)
- `der` crate for ASN.1 parsing

### Success Criteria

- [ ] Can parse public keys from CSRs
- [ ] Can verify signatures for RSA and ECDSA
- [ ] Invalid signatures detected correctly
- [ ] Performance impact <10ms per CSR
- [ ] Test coverage >90%

---

## Phase 3: Low Priority - Full CMC Implementation (Weeks 5-8)

**Status:** 🟡 Framework Only
**Priority:** LOW (Optional per RFC 7030)
**RFC Reference:** RFC 7030 Section 4.3, RFC 5272
**Estimated Effort:** 4 weeks
**Compliance Impact:** +1%

### Objectives

Complete the Full CMC implementation to support advanced PKI operations beyond simple enrollment.

### Technical Requirements

#### 3.1 CMC Request Building

**File:** `src/operations/fullcmc.rs`

- [ ] Implement `build_cmc_certification_request()`
  - Create TaggedRequest from PKCS#10 CSR
  - Wrap in PKIData with required control attributes
  - Add sender/recipient nonces
  - Generate transaction ID
  - Optionally sign with CMS SignedData

**Code Location:** [src/operations/fullcmc.rs:33-42](../src/operations/fullcmc.rs#L33-L42)

#### 3.2 CMC Request Types

**File:** `src/operations/fullcmc.rs`

- [ ] Implement `build_key_update_request()`
  - Create key update control attribute
  - Link old certificate to new CSR
  - Add proof-of-possession

- [ ] Implement `build_revocation_request()`
  - Create revocation request control
  - Include certificate serial number and issuer
  - Add revocation reason
  - Sign request

**Code Location:** [src/operations/fullcmc.rs:47-66](../src/operations/fullcmc.rs#L47-L66)

#### 3.3 CMC Response Parsing

**File:** `src/types/cmc.rs`

- [ ] Enhance `CmcResponse::parse()`
  - Parse PKIResponse structure
  - Extract CMC status info
  - Parse control attributes
  - Extract certificates from response
  - Handle pending responses with estimated time

**Code Location:** [src/types/cmc.rs:74-94](../src/types/cmc.rs#L74-L94)

#### 3.4 CMC Control Attributes

**File:** `src/types/cmc_full.rs`

- [ ] Implement missing control attributes:
  - Batch requests/responses
  - Get certificate
  - Query pending
  - Modify certification request
  - Pop link witness/random
  - Encrypted/decrypted POP

**Code Location:** [src/types/cmc_full.rs](../src/types/cmc_full.rs)

#### 3.5 Testing

- [ ] Unit tests for CMC message construction
- [ ] Integration tests with CMC-capable EST server
- [ ] Test all control attributes
- [ ] Test batch operations
- [ ] Test error handling for CMC failures

**Test Location:** `tests/integration/cmc_test.rs`

### Deliverables

1. Complete CMC request building
2. Full CMC response parsing
3. All CMC control attributes
4. Example code for common CMC operations
5. Documentation for CMC usage

### Dependencies

- `cms` crate (already included)
- `der` crate (already included)
- May need `cms` crate updates for newer control attributes

### Success Criteria

- [ ] Can build and send CMC certification requests
- [ ] Can build revocation requests
- [ ] Can build key update requests
- [ ] Can parse all CMC response types
- [ ] Can handle batch operations
- [ ] Test coverage >75%

### Optional Extensions

- [ ] Certificate status queries
- [ ] CRL retrieval via CMC
- [ ] Proof-of-possession variations
- [ ] Encrypted key transport

---

## Phase 4: Enhancement - Integration Testing (Weeks 9-10)

**Status:** 🟠 Needed
**Priority:** MEDIUM
**Estimated Effort:** 2 weeks
**Compliance Impact:** Quality/Reliability

### Objectives

Establish comprehensive integration testing with real EST servers to validate RFC compliance in production scenarios.

### Technical Requirements

#### 4.1 EST Test Server Setup

- [ ] Document setup of open-source EST servers
  - libest (Cisco)
  - StrongSwan EST
  - ejbca-est-proxy

- [ ] Create Docker Compose test environment
  - EST server with CA
  - Test certificates and keys
  - Network configuration

**Location:** `tests/integration/docker-compose.yml`

#### 4.2 Compliance Test Suite

**File:** `tests/integration/rfc_compliance_test.rs`

- [ ] Test all mandatory operations
  - `/cacerts` with various CA configurations
  - `/simpleenroll` with different authentication methods
  - `/simplereenroll` with certificate validation

- [ ] Test optional operations
  - `/csrattrs` with various attribute sets
  - `/serverkeygen` with key encryption
  - `/fullcmc` with various request types

- [ ] Test error conditions
  - HTTP 401 with various challenge types
  - HTTP 202 with Retry-After
  - HTTP 404 for unsupported operations
  - Malformed responses

- [ ] Test edge cases
  - Large certificate chains
  - Multiple CA labels
  - Certificate with unusual extensions
  - Very long validity periods

#### 4.3 Interoperability Testing

- [ ] Test against multiple EST server implementations
- [ ] Test with different TLS configurations
- [ ] Test with various CA configurations
- [ ] Document compatibility matrix

**Location:** `docs/interoperability.md`

#### 4.4 Performance Testing

- [ ] Measure operation latencies
- [ ] Test concurrent enrollment requests
- [ ] Memory usage profiling
- [ ] Identify optimization opportunities

**Location:** `tests/performance/`

### Deliverables

1. Working Docker-based test environment
2. Comprehensive RFC compliance test suite
3. Interoperability test results
4. Performance benchmark results
5. CI/CD integration

### Success Criteria

- [ ] All tests pass against libest
- [ ] All tests pass against StrongSwan
- [ ] Performance meets targets (<500ms for enrollment)
- [ ] CI runs integration tests automatically
- [ ] Documentation complete

---

## Phase 5: Enhancement - Advanced Features (Weeks 11-12)

**Status:** 🟢 Optional Enhancements
**Priority:** LOW
**Estimated Effort:** 2 weeks

### Objectives

Add advanced features that improve usability and production readiness beyond base RFC compliance.

### Features

#### 5.1 Retry Logic Enhancement

**File:** `src/client.rs`

- [ ] Implement exponential backoff for HTTP 202
- [ ] Add configurable retry limits
- [ ] Persist pending enrollment state
- [ ] Automatic retry on transient failures

#### 5.2 Certificate Lifecycle Management

**File:** `src/renewal.rs` (already has framework)

- [ ] Automatic certificate renewal scheduling
- [ ] Configurable renewal threshold (days before expiry)
- [ ] Notification system for expiring certificates
- [ ] Rollback on renewal failure

#### 5.3 Audit Logging

**File:** `src/logging.rs`

- [ ] Structured audit logs for all operations
- [ ] Tamper-evident log format
- [ ] Integration with syslog/journald
- [ ] Compliance with security logging standards

#### 5.4 Monitoring and Metrics

**Files:** `src/metrics/*.rs` (framework exists)

- [ ] Prometheus metrics export (already started)
- [ ] OpenTelemetry tracing
- [ ] Health check endpoints
- [ ] Alerting thresholds

### Deliverables

1. Production-ready retry logic
2. Automatic renewal capability
3. Comprehensive audit logging
4. Monitoring integration

---

## Implementation Timeline

```
Week 1-2:   Phase 1 - TLS Channel Binding
Week 3-4:   Phase 2 - CSR Signature Verification
Week 5-8:   Phase 3 - Full CMC Implementation
Week 9-10:  Phase 4 - Integration Testing
Week 11-12: Phase 5 - Advanced Features (optional)
```

### Milestone Schedule

| Milestone | Target Date | Compliance % |
|-----------|-------------|--------------|
| Phase 1 Complete | Week 2 | 98% |
| Phase 2 Complete | Week 4 | 99% |
| Phase 3 Complete | Week 8 | 100% |
| Phase 4 Complete | Week 10 | 100% + validated |
| Phase 5 Complete | Week 12 | 100% + production-ready |

---

## Resource Requirements

### Development Team

- **1 Senior Rust Developer** (Phases 1-3)
  - Strong cryptography background
  - Experience with TLS/PKI
  - Familiarity with RFC standards

- **1 QA Engineer** (Phase 4)
  - Integration testing experience
  - Docker/container expertise
  - Security testing background

### Infrastructure

- Development EST server environment
- CI/CD pipeline with integration tests
- Code review and approval process
- Documentation hosting

### Dependencies

| Dependency | Version | Purpose |
|-----------|---------|---------|
| rustls | >= 0.23 | TLS channel binding |
| rsa | >= 0.9 | CSR signature verification |
| p256/p384 | >= 0.13 | ECDSA verification |
| cms | >= 0.2 | CMC message handling |
| der | >= 0.7 | ASN.1 parsing |

---

## Risk Management

### Technical Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| rustls doesn't expose tls-unique | Medium | High | Use TLS 1.3 exporters or fork rustls |
| CMC complexity exceeds estimate | Medium | Medium | Phase 3 is optional; can defer |
| EST server compatibility issues | Low | Medium | Test early with multiple servers |
| Performance degradation | Low | Low | Profile and optimize critical paths |

### Mitigation Strategies

1. **Early prototyping** - Validate technical approach in week 1
2. **Incremental delivery** - Each phase delivers working features
3. **Continuous testing** - Run integration tests throughout
4. **Documentation first** - Write docs before code to clarify requirements

---

## Success Metrics

### Compliance Metrics

- [ ] 100% RFC 7030 mandatory requirements implemented
- [ ] 100% RFC 7030 optional requirements implemented
- [ ] Zero critical security vulnerabilities
- [ ] All integration tests passing

### Quality Metrics

- [ ] Code coverage >85% overall
- [ ] Zero clippy warnings
- [ ] Zero memory leaks (checked with valgrind)
- [ ] API documentation 100% complete

### Performance Metrics

- [ ] Certificate enrollment <500ms (p95)
- [ ] Memory usage <10MB per client
- [ ] Concurrent connections >1000
- [ ] Zero blocking operations in async code

---

## Post-Roadmap Activities

### Maintenance

- Security updates within 48 hours of disclosure
- Quarterly dependency updates
- Continuous integration test expansion
- Documentation updates with each release

### Future Enhancements (Out of Scope)

- SCEP protocol support (RFC 8894)
- ACME protocol support (RFC 8555)
- Certificate Transparency integration
- Hardware security module (HSM) enhancements (already has framework)
- FIPS 140-3 certification (already has FIPS 140-2)

---

## References

### RFCs

- **RFC 7030** - Enrollment over Secure Transport (EST)
- **RFC 2986** - PKCS #10: Certification Request Syntax
- **RFC 5272** - Certificate Management over CMS (CMC)
- **RFC 5273** - CMC: Transport Protocols
- **RFC 5274** - CMC: Compliance Requirements
- **RFC 5280** - X.509 Public Key Infrastructure Certificate
- **RFC 5929** - Channel Bindings for TLS

### Related Documents

- [CHANGELOG.md](../CHANGELOG.md) - Version history
- [README.md](../README.md) - Project overview
- [CONTRIBUTING.md](../CONTRIBUTING.md) - Contribution guidelines
- [docs/fips-compliance.md](fips-compliance.md) - FIPS 140-2 compliance

### External Resources

- [libest Documentation](https://github.com/cisco/libest)
- [StrongSwan EST](https://docs.strongswan.org/docs/5.9/plugins/est.html)
- [rustls Documentation](https://docs.rs/rustls)

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01-15 | Initial roadmap based on RFC compliance audit |

---

## Approval

This roadmap is subject to review and approval by the project maintainers.

**Document Owner:** EST Client Development Team
**Last Updated:** 2026-01-15
**Next Review:** 2026-02-15
