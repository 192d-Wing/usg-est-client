# TODO and FIXME Tracker

Comprehensive list of all TODO, FIXME, and action items found in the codebase.

**Last Scanned:** 2026-01-12
**Total Items:** 30 TODOs, 0 FIXMEs

---

## Critical Priority (Security/Functionality)

### 1. Revocation Module - Signature Verification

**Location:** [src/revocation.rs:451](src/revocation.rs#L451)
```rust
// TODO: Implement actual signature verification
```

**Issue:** CRL signature verification is a placeholder
**Impact:** Security - Cannot verify CRL authenticity
**Effort:** Medium
**Dependencies:** Requires RSA/ECDSA verification with issuer's public key
**Status:** ⚠️ Acknowledged in ROADMAP.md as needing production implementation

**Action Items:**
- [ ] Implement RSA signature verification for CRLs
- [ ] Implement ECDSA signature verification for CRLs
- [ ] Add issuer public key extraction
- [ ] Write comprehensive tests with real CRLs
- [ ] Update ROADMAP.md when complete

### 2. OCSP Implementation Stubs

**Locations:**
- [src/revocation.rs:657](src/revocation.rs#L657) - Request creation
- [src/revocation.rs:714](src/revocation.rs#L714) - Response parsing

```rust
// TODO: Implement actual OCSP request creation
// TODO: Implement actual OCSP response parsing
```

**Issue:** OCSP functionality is stubbed out
**Impact:** Functionality - Online revocation checking not working
**Effort:** High
**Dependencies:** OCSP protocol (RFC 6960), ASN.1 parsing
**Status:** ⚠️ Noted in docs/docs/security.md

**Action Items:**
- [ ] Implement OCSP request builder (RFC 6960 format)
- [ ] Implement OCSP response parser
- [ ] Add OCSP signature verification
- [ ] Test with live OCSP responders
- [ ] Update security.md documentation

### 3. DoD PKI - Revocation Checking

**Locations:**
- [src/dod/validation.rs:394](src/dod/validation.rs#L394)
- [src/dod/validation.rs:401](src/dod/validation.rs#L401)

```rust
// TODO: Implement CRL/OCSP checking when revocation feature is available
```

**Issue:** DoD validation doesn't check revocation status
**Impact:** Security - Cannot detect revoked DoD certificates
**Effort:** Medium
**Dependencies:** Revocation module fixes (items #1 and #2 above)
**Status:** ⚠️ Blocked by revocation module completion

**Action Items:**
- [ ] Wait for revocation module completion
- [ ] Integrate CRL checking into DoD validator
- [ ] Integrate OCSP checking into DoD validator
- [ ] Test with DoD PKI CRLs
- [ ] Update DoD documentation

### 4. Basic Constraints Validation

**Locations:**
- [src/validation.rs:481](src/validation.rs#L481)
- [src/validation.rs:1227](src/validation.rs#L1227)

```rust
// TODO: Parse and verify cA flag is true
// TODO: Parse basic constraints and check cA flag
```

**Issue:** Not validating CA certificates have cA flag set
**Impact:** Security - Could accept invalid certificate chains
**Effort:** Low
**Dependencies:** None
**Status:** ⚠️ Easy fix, should be prioritized

**Action Items:**
- [ ] Parse Basic Constraints extension
- [ ] Verify cA=TRUE for intermediate CAs
- [ ] Verify pathLenConstraint if present
- [ ] Add tests for invalid chains (cA=FALSE)
- [ ] Update validation documentation

---

## High Priority (Features/Functionality)

### 5. HSM-Backed CSR Generation

**Locations:**
- [examples/hsm_enroll.rs:186-187](examples/hsm_enroll.rs#L186-L187)
- [src/csr.rs:187](src/csr.rs#L187)

```rust
// TODO: Add HSM-backed CSR generation
// Note: rcgen doesn't directly support challenge-password
```

**Issue:** CSR builder generates its own keys, can't use HSM keys
**Impact:** Functionality - HSM integration incomplete
**Effort:** High
**Dependencies:** Manual PKCS#10 construction, HSM trait extension
**Status:** 📋 Planned feature, documented in examples

**Action Items:**
- [ ] Design API for CSR with external signing
- [ ] Implement manual PKCS#10 CSR construction
- [ ] Add HSM signing callback to CsrBuilder
- [ ] Update HSM trait to support CSR signing
- [ ] Write integration tests with SoftHSM
- [ ] Update examples/hsm_enroll.rs

### 6. Certificate Expiration Checking in Auto-Enroll

**Locations:**
- [src/bin/est-autoenroll-service.rs:228](src/bin/est-autoenroll-service.rs#L228)
- [src/bin/est-autoenroll-service.rs:256](src/bin/est-autoenroll-service.rs#L256)

```rust
// TODO: Check expiration and renewal threshold
// TODO: Check certificate expiration against renewal threshold
```

**Issue:** Auto-enrollment service doesn't check expiration properly
**Impact:** Functionality - May not renew certificates in time
**Effort:** Low
**Dependencies:** Time parsing utilities
**Status:** ⚠️ Service is example code but should work properly

**Action Items:**
- [ ] Implement certificate expiration parsing
- [ ] Add renewal threshold checking
- [ ] Add logging when certificate needs renewal
- [ ] Test with near-expiry certificates
- [ ] Update service documentation

### 7. Full Enrollment/Renewal Workflow in Auto-Enroll

**Locations:**
- [src/bin/est-autoenroll-service.rs:242](src/bin/est-autoenroll-service.rs#L242)
- [src/bin/est-autoenroll-service.rs:264](src/bin/est-autoenroll-service.rs#L264)

```rust
// TODO: Implement full enrollment workflow
// TODO: Implement renewal workflow
```

**Issue:** Service stubs don't implement actual EST operations
**Impact:** Functionality - Example service doesn't work
**Effort:** Medium
**Dependencies:** None (APIs exist)
**Status:** 📋 Example code - low priority

**Action Items:**
- [ ] Implement enrollment in check_and_renew()
- [ ] Implement reenrollment in check_and_renew()
- [ ] Add error handling and retry logic
- [ ] Add certificate storage/retrieval
- [ ] Test end-to-end workflow

### 8. DoD PKI Time Comparison

**Location:** [src/dod/validation.rs:386](src/dod/validation.rs#L386)

```rust
// TODO: Implement actual time comparison when time feature is available
```

**Issue:** Time comparison logic is simplified
**Impact:** Functionality - May not validate time correctly
**Effort:** Low
**Dependencies:** Time feature flag implementation
**Status:** ⚠️ Noted as simplified implementation

**Action Items:**
- [ ] Implement proper X.509 time parsing
- [ ] Handle UTCTime vs GeneralizedTime
- [ ] Add timezone handling
- [ ] Test with various time formats
- [ ] Update DoD validation docs

---

## Medium Priority (Enhancements/Configuration)

### 9. Windows Service Configuration Loading

**Location:** [src/windows/service.rs:418-421](src/windows/service.rs#L418-L421)

```rust
// TODO: Load configuration
// TODO: Check existing certificates
// TODO: Perform enrollment if needed
// TODO: Schedule renewals
```

**Issue:** Windows service has placeholder implementation
**Impact:** Functionality - Windows service doesn't work
**Effort:** Medium
**Dependencies:** Windows credential manager (#10)
**Status:** 🪟 Windows-specific, Phase 10.3 work

**Action Items:**
- [ ] Implement config file loading
- [ ] Add certificate enumeration from Windows store
- [ ] Implement enrollment logic
- [ ] Add renewal scheduling
- [ ] Test on Windows Server
- [ ] Update windows/service.rs documentation

### 10. Windows Credential Manager Integration

**Location:** [src/auto_enroll/config.rs:327](src/auto_enroll/config.rs#L327)

```rust
// TODO: Implement Windows Credential Manager lookup
```

**Issue:** Password lookup from Windows Credential Manager not implemented
**Impact:** Functionality - Can't retrieve stored credentials
**Effort:** Medium
**Dependencies:** Windows credential API
**Status:** 🪟 Windows-specific enhancement

**Action Items:**
- [ ] Add windows-sys or credentials crate dependency
- [ ] Implement CredRead API call
- [ ] Add proper error handling
- [ ] Add fallback to environment variables
- [ ] Test on Windows with stored credentials
- [ ] Document credential manager usage

### 11. Renewal Module - Actual Re-enrollment

**Location:** [src/renewal.rs:362](src/renewal.rs#L362)

```rust
// TODO: Implement actual re-enrollment logic
```

**Issue:** Renewal monitor has placeholder re-enrollment
**Impact:** Functionality - Automatic renewal doesn't work
**Effort:** Low
**Dependencies:** None (client APIs exist)
**Status:** ⚠️ Core feature should work

**Action Items:**
- [ ] Call client.reenroll() in renewal logic
- [ ] Add proper error handling
- [ ] Store renewed certificate
- [ ] Update monitoring state
- [ ] Add comprehensive tests
- [ ] Update renewal.rs documentation

---

## Low Priority (Documentation/Examples)

### 12. Example TODOs

Multiple examples have `todo!()` placeholders for demonstration purposes. These are intentional and don't need fixing as they're meant to show API usage.

**Locations:**
- [src/revocation.rs:39-40](src/revocation.rs#L39-L40) - Example code
- [src/enveloped.rs:32](src/enveloped.rs#L32) - Example code
- [src/validation.rs:30](src/validation.rs#L30) - Example code

**Status:** ✅ Intentional - examples show where user provides data

### 13. Notes and Reminders

Various "Note:" comments throughout codebase for documentation purposes. These are informational and don't require action.

**Examples:**
- Platform-specific limitations
- API usage notes
- Security considerations
- Performance characteristics

**Status:** ℹ️ Documentation - no action needed

---

## Deferred Items (Per ROADMAP.md)

These TODOs are acknowledged and intentionally deferred for future releases:

### Event Log Manifest
**Location:** ROADMAP Phase 10.4
**Status:** Deferred for future release

### Log File Compression
**Location:** ROADMAP Phase 10.4
**Status:** Deferred for future release

### Prometheus Endpoint
**Location:** ROADMAP Phase 10.5
**Status:** Deferred for future release

### SNMP Traps
**Location:** ROADMAP Phase 10.5
**Status:** Deferred for future release

### Interactive Mode
**Location:** ROADMAP Phase 10.6
**Status:** Deferred for future release

### PowerShell Completion
**Location:** ROADMAP Phase 10.6
**Status:** Deferred for future release

### SCEP Protocol Support
**Location:** ROADMAP Future Considerations
**Status:** Out of scope (different protocol from EST)

---

## Summary Statistics

| Priority | Count | Status |
|----------|-------|--------|
| Critical | 4 items | ⚠️ Security/core functionality |
| High | 4 items | 📋 Feature completeness |
| Medium | 3 items | 🔧 Enhancements |
| Low | 1 item | 📝 Examples/docs |
| Deferred | 7 items | 📅 Future releases |

**Total Actionable:** 12 items
**Total Deferred:** 7 items

## Action Plan

### Sprint 1 (Critical Security Fixes)

Focus on security-critical items:

1. ✅ Basic constraints validation (#4) - **1 day**
   - Low effort, high security impact
   - Already have validation infrastructure

2. ⚠️ CRL signature verification (#1) - **3 days**
   - Reuse RSA/ECDSA code from certificate validation
   - Critical for revocation checking

3. ⚠️ DoD PKI revocation integration (#3) - **2 days**
   - Depends on #1 completion
   - Required for DoD compliance

### Sprint 2 (OCSP and Revocation)

Complete revocation subsystem:

1. OCSP request creation (#2a) - **2 days**
2. OCSP response parsing (#2b) - **2 days**
3. OCSP signature verification (#2c) - **1 day**
4. Integration testing with live OCSP - **1 day**

### Sprint 3 (Feature Completeness)

High-priority functionality:

1. Renewal module re-enrollment (#11) - **1 day**
2. Auto-enroll expiration checking (#6) - **1 day**
3. DoD time comparison (#8) - **1 day**

### Sprint 4 (HSM Integration)

HSM-backed CSR generation (#5) - **5 days**
- API design: 1 day
- Implementation: 2 days
- Testing: 1 day
- Documentation: 1 day

### Future Sprints

- Windows service implementation (#9, #10)
- Auto-enroll workflows (#7)
- Deferred items per roadmap priority

## Tracking

Create GitHub/GitLab issues for each TODO:

```bash
# Example issue creation
gh issue create \
  --title "Implement CRL signature verification" \
  --label "security,critical" \
  --body "See TODO-TRACKER.md item #1"
```

## Notes

- All security-critical TODOs should be addressed before v1.0
- Feature TODOs can be addressed incrementally
- Example code TODOs are intentional and don't need fixing
- Deferred items are tracked in ROADMAP.md

## Contributing

When working on TODOs:

1. Check this document for context
2. Create issue/PR referencing TODO number
3. Update this document when TODO is resolved
4. Remove TODO comment from source code
5. Add tests and documentation
6. Update CHANGELOG.md

## References

- [ROADMAP.md](ROADMAP.md) - Feature roadmap and deferred items
- [SECURITY.md](SECURITY.md) - Security policy
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines

---

**Maintained by:** Development Team
**Review Frequency:** Monthly
**Last Updated:** 2026-01-12
