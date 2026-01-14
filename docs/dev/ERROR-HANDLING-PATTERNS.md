# Error Handling Patterns Guide

**Document Type:** Developer Reference
**Audience:** EST Client Library Contributors
**Last Updated:** 2026-01-14
**Status:** ACTIVE

---

## Purpose

This guide establishes standard error handling patterns for the EST Client Library to eliminate panic-inducing `unwrap()` calls and ensure robust, production-ready code. These patterns are part of the Q2 2026 Refactoring Sprint to reduce unwrap() usage by 80%.

**Related Documents:**
- [REFACTORING-SPRINT-PLAN.md](../ato/REFACTORING-SPRINT-PLAN.md) - Overall sprint plan
- [EXECUTIVE-SUMMARY.md](../ato/EXECUTIVE-SUMMARY.md) - Security audit results

---

## Core Principles

### 1. Never Panic on External Input

**Rule:** Any code path that processes external input (network, filesystem, user config, FFI) must never use `unwrap()`.

**Rationale:** Malicious or malformed input should never crash the service. This is a DoS vulnerability.

**NIST Control:** SI-11 (Error Handling)

### 2. Fail Gracefully

**Rule:** Errors should propagate up the call stack with context, allowing graceful degradation or recovery.

**Rationale:** Services should degrade functionality rather than crash completely.

**NIST Control:** SC-24 (Fail in Known State)

### 3. Provide Actionable Error Messages

**Rule:** Error messages must include enough context for operators to diagnose and fix issues.

**Rationale:** Reduces mean-time-to-resolution (MTTR) in production incidents.

**NIST Control:** SI-11 (Error Handling)

### 4. Don't Leak Sensitive Information

**Rule:** Error messages visible to users must not expose internal paths, memory addresses, or cryptographic material.

**Rationale:** Information disclosure aids attackers in reconnaissance.

**NIST Control:** SI-11 (Error Handling)

---

## Pattern 1: Option::unwrap() → ok_or_else()

**Use Case:** Optional values from collections, lookups, or network responses

### Anti-Pattern (Before)

```rust
// ❌ NEVER: Panics if collection is empty
let item = collection.get(0).unwrap();

// ❌ NEVER: Panics if key doesn't exist
let value = map.get("key").unwrap();

// ❌ NEVER: Panics if response missing certificate
let cert = response.cert.unwrap();
```

**Problem:** Any of these will panic if the value is `None`, causing service crash.

### Correct Pattern (After)

```rust
// ✅ GOOD: Propagates error with context
let item = collection.get(0)
    .ok_or_else(|| EstError::operational("Collection unexpectedly empty"))?;

// ✅ GOOD: Includes which key was missing
let value = map.get("key")
    .ok_or_else(|| EstError::config(format!("Missing required key: {}", "key")))?;

// ✅ GOOD: Protocol-level error
let cert = response.cert
    .ok_or_else(|| EstError::protocol("EST server did not return certificate"))?;
```

**Benefits:**
- Error propagates with `?` operator
- Context explains what went wrong
- Service logs error and continues with next request

### Applicable Locations

- `src/operations/enroll.rs` - EST protocol responses
- `src/auto_enroll/expand.rs` - Variable lookups
- `src/validation.rs` - Certificate chain access
- `src/hsm/pkcs11.rs` - Slot and session access

**Expected Impact:** ~150 instances

---

## Pattern 2: Result::unwrap() → map_err()

**Use Case:** FFI calls, external library results, system calls

### Anti-Pattern (Before)

```rust
// ❌ NEVER: Panics on Windows API failure
let handle = unsafe { OpenHandle(ptr) }.unwrap();

// ❌ NEVER: Panics on PKCS#11 error
let session = ctx.open_session(slot, flags).unwrap();

// ❌ NEVER: Panics on CNG error
let provider = BCryptOpenAlgorithmProvider(alg_id, flags).unwrap();
```

**Problem:** External APIs can fail for many reasons (permissions, hardware, resources). Panicking is not acceptable.

### Correct Pattern (After)

```rust
// ✅ GOOD: Converts Win32 error to EstError
let handle = unsafe { OpenHandle(ptr) }
    .map_err(|e| EstError::operational(format!("Failed to open handle: {:#x}", e)))?;

// ✅ GOOD: Includes PKCS#11 error details
let session = ctx.open_session(slot, flags)
    .map_err(|e| EstError::hsm(format!("Failed to open PKCS#11 session on slot {}: {}", slot, e)))?;

// ✅ GOOD: Maps CNG NTSTATUS to readable error
let provider = BCryptOpenAlgorithmProvider(alg_id, flags)
    .map_err(|e| EstError::operational(format!("Failed to open CNG provider '{}': {:#x}", alg_name, e)))?;
```

**Benefits:**
- Original error preserved in message
- Operator can diagnose (e.g., "slot locked", "insufficient permissions")
- Error code included for Windows Event Log correlation

### Error Message Template

```rust
format!(
    "Failed to {operation} {resource}: {error_details}",
    operation = "open",  // What we tried to do
    resource = "PKCS#11 session",  // What resource
    error_details = e  // Original error
)
```

### Applicable Locations

- `src/windows/cng.rs` - CNG cryptographic operations
- `src/windows/certstore.rs` - Certificate store operations
- `src/windows/tpm.rs` - TPM operations
- `src/hsm/pkcs11.rs` - PKCS#11 operations
- `src/windows/credentials.rs` - Credential manager operations

**Expected Impact:** ~100 instances

---

## Pattern 3: Lock::unwrap() → Strategy-Based Handling

**Use Case:** Mutex, RwLock operations on shared state

### Decision Matrix

| Lock Type | Data Criticality | Strategy | Rationale |
|-----------|------------------|----------|-----------|
| Configuration (read-only after init) | HIGH | Propagate Error | Poisoning indicates serious bug |
| Certificate cache | HIGH | Propagate Error | Corrupted cache unacceptable |
| Metrics counters | LOW | Recover | Can reset and continue |
| Log rotation state | MEDIUM | Recover | Degraded logging acceptable |

### Strategy A: Propagate Error (Critical Data)

**Use When:** Data corruption is unacceptable, poisoning indicates fatal bug

```rust
// ✅ GOOD: Propagate lock poisoning as error
let guard = CERT_CACHE.read()
    .map_err(|e| EstError::operational(format!("Certificate cache lock poisoned: {}", e)))?;
```

**Result:** Service returns error for this request, logs critical error, continues serving other requests.

### Strategy B: Recover (Non-Critical Data)

**Use When:** Data can be safely reset, degraded functionality acceptable

```rust
// ✅ GOOD: Recover from poisoned lock
let mut guard = METRICS.lock().unwrap_or_else(|poisoned| {
    tracing::warn!("Metrics lock poisoned, resetting counters");
    poisoned.into_inner()
});
```

**Result:** Service resets metrics to zero, logs warning, continues normal operation.

### Anti-Pattern (Before)

```rust
// ❌ NEVER: Panics entire service if any thread panics
let guard = SHARED_STATE.lock().unwrap();
```

**Problem:** Lock poisoning cascades - one panic in any thread crashes entire service.

### Applicable Locations

**Strategy A (Propagate):**
- `src/validation.rs` - Trust anchor cache
- `src/revocation.rs` - CRL/OCSP cache
- `src/config.rs` - Runtime configuration

**Strategy B (Recover):**
- `src/metrics/prometheus.rs` - Prometheus metrics
- `src/metrics/opentelemetry.rs` - OpenTelemetry metrics
- `src/logging.rs` - Log rotation state

**Expected Impact:** ~40 instances

---

## Pattern 4: Infallible Operations → expect() with Justification

**Use Case:** Operations guaranteed not to fail by API contract or input validation

### When This Pattern Applies

1. **Compile-time constants:** Hardcoded strings known to be valid
2. **Post-validation:** Values already validated earlier in the call
3. **Infallible conversions:** Type conversions that cannot fail
4. **Test fixtures:** Test data known to be valid

### Correct Pattern

```rust
// ✅ GOOD: Compile-time constant URL
let url = Url::parse("https://pki.example.mil/est")
    .expect("hardcoded URL is valid");

// ✅ GOOD: Already validated in config parsing
let port = self.server_url.port()
    .expect("port validated during config load");

// ✅ GOOD: UTF-8 string from ASCII constant
let header = String::from_utf8(b"EST-Client/1.0".to_vec())
    .expect("ASCII header is valid UTF-8");

// ✅ GOOD: DER encoding of well-known OID
let oid_bytes = ObjectIdentifier::new("2.5.29.19")
    .expect("X.509 basicConstraints OID is valid")
    .to_der();
```

**Key Requirements:**
1. Use `.expect()` with justification, not `.unwrap()`
2. Comment must explain WHY it cannot fail
3. Must be genuinely infallible (not "unlikely to fail")

### Anti-Pattern

```rust
// ❌ BAD: URL comes from user config - can fail
let url = Url::parse(&config.server_url).expect("URL should be valid");

// ❌ BAD: No justification for why this can't fail
let value = map.get("key").expect("required");
```

### Applicable Locations

- `src/config.rs` - Validated configuration access
- `src/tls.rs` - TLS configuration with validated certs
- `src/csr/pkcs10.rs` - DER encoding of known OIDs
- Test code throughout codebase

**Expected Impact:** ~30 instances promoted from unwrap() to expect()

---

## Pattern 5: Test Code → Document Safety

**Use Case:** Test assertions where panic is desired behavior

### Guideline

Keep `unwrap()` in test code if:
1. Test data is compile-time constant or fixture
2. Failure indicates test setup bug, not application bug
3. Panic provides clear test failure message

### Correct Pattern

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn test_certificate_parsing() {
        // ✅ GOOD: Test fixture is compile-time constant
        let cert_pem = include_str!("fixtures/test-cert.pem");
        let cert = parse_certificate(cert_pem).unwrap();  // Test fixture known valid

        assert_eq!(cert.subject_cn(), "Test Certificate");
    }

    #[test]
    fn test_invalid_certificate() {
        // ✅ GOOD: Test expects error, no unwrap()
        let result = parse_certificate("invalid");
        assert!(result.is_err());
    }
}
```

### When to Use Proper Error Handling in Tests

```rust
#[test]
fn test_error_handling() {
    // ✅ GOOD: Testing error path, need Result
    let result = risky_operation().unwrap_err();
    assert!(result.to_string().contains("expected error message"));
}

#[test]
fn test_integration() -> Result<(), EstError> {
    // ✅ GOOD: Integration test with proper error propagation
    let client = EstClient::new(test_config())?;
    let cert = client.enroll(&csr).await?;
    Ok(())
}
```

**Expected Impact:** ~58 instances remain as-is in test code (acceptable)

---

## Special Cases

### Case 1: Builder Patterns (CSR, TLS Config)

**Current Code:**
```rust
// src/csr.rs - Builder pattern with validation
pub fn san_dns(mut self, dns: impl Into<String>) -> Self {
    let dns_str = dns.into();
    let dns_name = dns_str.as_str().try_into()
        .unwrap_or_else(|_| panic!(
            "Invalid DNS name for SAN: '{}'. DNS names must conform to RFC 1035.",
            dns_str
        ));
    self.params.subject_alt_names.push(SanType::DnsName(dns_name));
    self
}
```

**Decision:** Keep this pattern (already fixed in commit `8392d31`)

**Rationale:**
- Builder pattern by convention panics on invalid builder input
- Enhanced panic message guides user to fix their code
- Failure happens at build time in user code, not from external input
- Alternative (returning Result) breaks builder pattern ergonomics

### Case 2: Windows FFI String Parsing

**Current Code:**
```rust
// src/windows/credentials.rs - UTF-16 string parsing with bounds
const MAX_USERNAME_LEN: usize = 1024;
let mut len = 0;
let mut ptr = cred.UserName.0;
unsafe {
    while len < MAX_USERNAME_LEN && *ptr != 0 {
        len += 1;
        ptr = ptr.add(1);
    }
}
if len >= MAX_USERNAME_LEN {
    tracing::warn!("Username truncated at maximum length {}", MAX_USERNAME_LEN);
}
let slice = unsafe { std::slice::from_raw_parts(cred.UserName.0, len) };
let username = String::from_utf16_lossy(slice);
```

**Decision:** Keep this pattern (already fixed in commit `d9b9ea9`)

**Rationale:**
- Maximum length prevents infinite loops
- `from_utf16_lossy()` cannot panic (replaces invalid sequences)
- Defensive programming for Windows API boundary

### Case 3: ASN.1 DER Parsing

**Current Code:**
```rust
// src/revocation.rs - Length parsing with overflow checks
length = length
    .checked_shl(8)
    .and_then(|l| l.checked_add(byte as usize))
    .ok_or_else(|| EstError::operational("Length field overflow"))?;

const MAX_REASONABLE_LENGTH: usize = 100 * 1024 * 1024; // 100MB
if length > MAX_REASONABLE_LENGTH {
    return Err(EstError::operational(format!("Length exceeds max: {}", length)));
}
```

**Decision:** Keep this pattern (already fixed in commit `022b9fb`)

**Rationale:**
- Checked arithmetic prevents integer overflow
- Sanity limit prevents memory exhaustion
- Proper error propagation

---

## Implementation Checklist

When refactoring a function:

- [ ] Identify all `unwrap()` calls
- [ ] Determine the pattern (Option, Result, Lock, Infallible, Test)
- [ ] Apply the appropriate remediation pattern
- [ ] Add error context (operation, resource, details)
- [ ] Consider NIST 800-53 control implications
- [ ] Add unit test for error path if not covered
- [ ] Update function documentation with `# Errors` section
- [ ] Verify no information leakage in error messages
- [ ] Run `cargo test` to ensure no regressions
- [ ] Run `cargo clippy` to verify warnings resolved

---

## Error Message Guidelines

### Good Error Messages

```rust
// ✅ GOOD: Actionable, includes context
EstError::config("Missing required configuration field 'server_url'")

// ✅ GOOD: Includes operation and resource
EstError::hsm(format!("Failed to generate key pair on slot {}: token locked", slot))

// ✅ GOOD: Protocol-level error with server context
EstError::protocol(format!("EST server returned invalid content-type: {}", content_type))
```

### Bad Error Messages

```rust
// ❌ BAD: Not actionable
EstError::operational("Error")

// ❌ BAD: Leaks internal paths
EstError::config(format!("Failed to read /var/lib/est-client/secrets/key.pem: {}", e))

// ❌ BAD: Too vague
EstError::hsm("Operation failed")
```

### Information Disclosure Rules

**Safe to include:**
- Operation being attempted ("failed to open session")
- Resource type ("PKCS#11 slot", "certificate")
- Protocol errors ("invalid content-type", "missing header")
- Configuration keys ("missing 'server_url'")

**Never include:**
- Full file paths (use basename only)
- Memory addresses
- Cryptographic key material
- Internal database queries
- Stack traces (log separately)

---

## Testing Error Handling

### Unit Test Template

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_on_empty_collection() {
        let empty_vec: Vec<String> = vec![];
        let result = process_items(&empty_vec);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), EstErrorKind::Operational);
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn test_error_on_invalid_input() {
        let result = parse_certificate("not a certificate");

        assert!(result.is_err());
        // Verify error message is actionable
        assert!(result.unwrap_err().to_string().contains("invalid"));
    }
}
```

### Integration Test Template

```rust
#[tokio::test]
async fn test_enrollment_with_invalid_server() {
    let mut config = EstConfig::default();
    config.server_url = "https://invalid.example.com/est".to_string();

    let client = EstClient::new(config).unwrap();
    let result = client.enroll(&test_csr()).await;

    // Should fail gracefully, not panic
    assert!(result.is_err());

    // Error should be informative
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("server") || err_msg.contains("network"));
}
```

---

## Code Review Checklist

When reviewing refactoring PRs:

**Error Handling:**
- [ ] No `unwrap()` on external input paths
- [ ] `expect()` has justification comment
- [ ] Error messages are actionable
- [ ] No information disclosure in errors
- [ ] Error type matches cause (Config, Operational, Protocol, etc.)

**Testing:**
- [ ] Error paths have unit tests
- [ ] Integration tests cover failure scenarios
- [ ] No test regressions

**Documentation:**
- [ ] Function has `# Errors` section
- [ ] Public API changes documented
- [ ] CHANGELOG.md updated if user-facing

**Performance:**
- [ ] No unnecessary allocations in error path
- [ ] Error construction is lazy (uses closures)

---

## NIST 800-53 Rev 5 Control Mapping

Proper error handling satisfies these security controls:

| Control | Requirement | Implementation |
|---------|-------------|----------------|
| **SI-11** | Error Handling | Don't expose sensitive information in errors |
| **SC-24** | Fail in Known State | Graceful degradation vs panic |
| **AU-9** | Protection of Audit Information | Lock error handling for log rotation |
| **SC-13** | Cryptographic Protection | Proper error handling in crypto operations |

---

## Common Mistakes to Avoid

### Mistake 1: Over-specific Error Messages

```rust
// ❌ BAD: Too specific, hard to maintain
EstError::operational("Failed to read certificate from /var/lib/est-client/certs/cert-12345.pem")

// ✅ GOOD: Generic but actionable
EstError::operational(format!("Failed to read certificate: {}", filename))
```

### Mistake 2: Ignoring Original Error

```rust
// ❌ BAD: Lost original error context
.map_err(|_| EstError::operational("Failed"))?;

// ✅ GOOD: Preserved original error
.map_err(|e| EstError::operational(format!("Failed to parse: {}", e)))?;
```

### Mistake 3: Wrong Error Type

```rust
// ❌ BAD: Protocol error for config issue
EstError::protocol("Missing server_url")

// ✅ GOOD: Correct error type
EstError::config("Missing required field 'server_url'")
```

### Mistake 4: Allocating in Error Path

```rust
// ❌ BAD: Allocates even if Ok
.ok_or(EstError::operational(format!("Error: {}", expensive_debug())))?;

// ✅ GOOD: Lazy allocation
.ok_or_else(|| EstError::operational(format!("Error: {}", expensive_debug())))?;
```

---

## Migration Statistics (as of 2026-01-14)

| Category | Before | After | Remaining | Target |
|----------|--------|-------|-----------|--------|
| **External Input** | 8 CRITICAL | 0 | 0 | 0 |
| **FFI/Libraries** | 100+ | 0 (in progress) | ~100 | 0 |
| **Lock Operations** | 40+ | 0 (in progress) | ~40 | 0 |
| **Infallible Ops** | 30+ | 0 (in progress) | ~30 | 30 (acceptable) |
| **Test Code** | 58 | 58 | 58 | 58 (acceptable) |
| **Total** | 339 | 8 fixed | 331 | 68 (goal) |

**Progress:** 2% complete → Target: 80% reduction by end of Q2 2026

---

## References

- [Rust Error Handling Best Practices](https://doc.rust-lang.org/book/ch09-00-error-handling.html)
- [NIST SP 800-53 Rev 5: SI-11 Error Handling](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf)
- [OWASP Error Handling](https://owasp.org/www-community/Improper_Error_Handling)
- [Refactoring Sprint Plan](../ato/REFACTORING-SPRINT-PLAN.md)

---

## Changelog

| Date | Author | Changes |
|------|--------|---------|
| 2026-01-14 | Security Team | Initial version for Q2 2026 refactoring sprint |

---

**Document End**

**Status:** ACTIVE
**Next Review:** Q3 2026 (Post-Sprint)
**Owner:** Development Team
