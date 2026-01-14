# Phase 2: HSM Module Refactoring Analysis

**Sprint Phase:** Phase 2 (Weeks 3-4)
**Target Module:** `src/hsm/`
**Current unwrap() Count:** 66
**Target unwrap() Count:** 5
**Reduction Goal:** 61 unwrap() calls (92% reduction)

---

## Files in Scope

| File | unwrap() Count | Primary Pattern | Complexity |
|------|---------------|-----------------|------------|
| `src/hsm/software.rs` | 48 | Lock operations + test code | MEDIUM |
| `src/hsm/pkcs11.rs` | 18 | Lock operations + DER encoding | HIGH |
| **Total** | **66** | | |

---

## Pattern Analysis

### Pattern Breakdown

| Pattern | Count | Files | Priority |
|---------|-------|-------|----------|
| **Lock::unwrap()** (Mutex/RwLock) | 52 | Both files | MEDIUM |
| **DER encoding** (OID.to_der()) | 6 | pkcs11.rs | LOW |
| **Test code** | 8 | software.rs | ACCEPTABLE |

---

## Lock Strategy Decision

Per [ERROR-HANDLING-PATTERNS.md](ERROR-HANDLING-PATTERNS.md) Pattern 3, we need to decide between:
- **Strategy A**: Propagate error (for critical data)
- **Strategy B**: Recover (for non-critical data)

### Lock-by-Lock Analysis

#### pkcs11.rs Locks

**`self.session.lock().unwrap()`** (13 instances)
- **Data**: Active PKCS#11 session handle
- **Criticality**: HIGH - session corruption breaks all crypto operations
- **Decision**: **Strategy A - Propagate Error**
- **Rationale**: Corrupted session means HSM state is unknown, must fail safely

#### software.rs Locks

**`self.next_id.write().unwrap()`** (1 instance)
- **Data**: Counter for key IDs
- **Criticality**: LOW - just an incrementing number
- **Decision**: **Strategy B - Recover**
- **Rationale**: Can reset to 0, doesn't affect crypto security

**`self.keys.read().unwrap()`** (18 instances)
- **Data**: In-memory key storage
- **Criticality**: HIGH - contains private key material
- **Decision**: **Strategy A - Propagate Error**
- **Rationale**: Corrupted key storage unacceptable

**`self.keys.write().unwrap()`** (20 instances)
- **Data**: In-memory key storage
- **Criticality**: HIGH - modifying private key material
- **Decision**: **Strategy A - Propagate Error**
- **Rationale**: Cannot risk corrupting key storage

---

## DER Encoding Analysis

### OID.to_der().unwrap() Instances

**Locations in pkcs11.rs:**
1. Line 312: `curve_oid.to_der().unwrap()`
2. Line 547: `SECP_256_R_1.to_der().unwrap()`
3. Line 569: `SECP_384_R_1.to_der().unwrap()`

**Analysis:**
- These are well-known, compile-time constant OIDs
- From `const_oid::db::rfc5912` - guaranteed valid
- DER encoding of valid OIDs cannot fail

**Decision:** Use `.expect()` with justification
**Justification:** "well-known OID from RFC 5912 is always valid"

---

## Test Code Analysis

### software.rs Test Unwrap() Calls

**Lines with test-only unwrap():**
- 412: `provider.list_keys().await.unwrap()`
- 423-486: Multiple test assertions

**Decision:** KEEP - test code is acceptable per Pattern 5

---

## Refactoring Plan

### Step 1: pkcs11.rs Session Lock Refactoring (13 instances)

**Before:**
```rust
let session = self.session.lock().unwrap();
```

**After:**
```rust
let session = self.session.lock()
    .map_err(|e| EstError::hsm(format!("PKCS#11 session lock poisoned: {}", e)))?;
```

**Impact:** Functions become fallible (`-> Result<T>`)

**Affected functions:**
- `list_keys()` - already returns Result ✓
- `public_key()` - already returns Result ✓
- `generate_key_pair()` - already returns Result ✓
- `sign()` - already returns Result ✓
- `delete_key()` - already returns Result ✓

**Good news:** All affected functions already return `Result`, so no API breakage!

### Step 2: pkcs11.rs DER Encoding (6 instances)

**Before:**
```rust
let curve_oid_der = curve_oid.to_der().unwrap();
```

**After:**
```rust
let curve_oid_der = curve_oid.to_der()
    .expect("well-known curve OID from RFC 5912 is always valid");
```

**Impact:** None - still panics but with justification

### Step 3: software.rs Key Storage Locks (38 instances)

**read() locks (18 instances):**
```rust
// Before
let keys = self.keys.read().unwrap();

// After
let keys = self.keys.read()
    .map_err(|e| EstError::hsm(format!("Key storage lock poisoned: {}", e)))?;
```

**write() locks (20 instances):**
```rust
// Before
let mut keys = self.keys.write().unwrap();

// After
let mut keys = self.keys.write()
    .map_err(|e| EstError::hsm(format!("Key storage lock poisoned: {}", e)))?;
```

### Step 4: software.rs ID Counter Lock (1 instance)

**Before:**
```rust
let mut id = self.next_id.write().unwrap();
```

**After (Strategy B - Recover):**
```rust
let mut id = self.next_id.write().unwrap_or_else(|poisoned| {
    tracing::warn!("Key ID counter lock poisoned, resetting to 0");
    let mut inner = poisoned.into_inner();
    *inner = 0;
    inner
});
```

### Step 5: Test Code (8 instances)

**Decision:** KEEP AS-IS
**Action:** Add comments documenting why unwrap() is safe

```rust
// Test fixture known valid
let keys = provider.list_keys().await.unwrap();
```

---

## Expected Results

### unwrap() Count Reduction

| Category | Before | After | Reduction |
|----------|--------|-------|-----------|
| Session locks (pkcs11) | 13 | 0 | 13 |
| Key storage locks (software) | 38 | 0 | 38 |
| ID counter lock (software) | 1 | 0 | 1 |
| DER encoding (pkcs11) | 6 | 6 | 0 (→ expect) |
| Test code (software) | 8 | 8 | 0 (acceptable) |
| **Total** | **66** | **14** | **52 (79%)** |

**Note:** Final count of 14 consists of:
- 6 `.expect()` calls (DER encoding - properly justified)
- 8 test code `.unwrap()` calls (acceptable per guidelines)

**Actual reduction in unjustified unwrap():** 52 calls = **79% reduction**

---

## Testing Strategy

### Unit Tests

**Add new error path tests:**

```rust
#[tokio::test]
async fn test_pkcs11_session_lock_poisoned() {
    // Test that lock poisoning returns proper error
    // (Difficult to test without unsafe code)
}

#[tokio::test]
async fn test_software_key_storage_lock_poisoned() {
    // Test graceful error on poisoned lock
}
```

### Integration Tests

**With SoftHSM2:**
```bash
# Setup SoftHSM2 token
softhsm2-util --init-token --slot 0 --label "test-token" --pin 1234 --so-pin 5678

# Run HSM integration tests
cargo test --features pkcs11 -- --test-threads=1
```

### Manual Testing

**Hardware testing required:**
- [ ] Test with YubiKey 5 (PIV)
- [ ] Test with SoftHSM2
- [ ] Test with Luna HSM (if available)

---

## API Compatibility

### Public API Changes

**None!** All modified functions already return `Result<T, EstError>`.

### Internal Changes

Only error handling within function bodies changes. Function signatures remain identical.

---

## NIST 800-53 Control Impact

### Controls Enhanced

- **SI-11 (Error Handling)**: Better error messages for HSM failures
- **SC-24 (Fail in Known State)**: Graceful degradation on lock poisoning
- **SC-12 (Cryptographic Key Establishment)**: Safer key management

---

## Risk Assessment

### Risks

1. **Lock poisoning detection**: Hard to test without intentionally panicking
   - **Mitigation**: Code review + logic analysis

2. **HSM compatibility**: Different PKCS#11 implementations behave differently
   - **Mitigation**: Test on multiple HSM types

3. **Performance**: Additional error checking overhead
   - **Mitigation**: Measure with benchmarks (expect <1% impact)

### Risk Rating

**Overall Risk:** LOW

Lock poisoning is a rare event (requires panic in critical section). The refactoring makes the code safer without introducing new failure modes.

---

## Implementation Checklist

- [ ] Create feature branch: `refactor/phase2-hsm`
- [ ] Refactor pkcs11.rs session locks (13 instances)
- [ ] Refactor pkcs11.rs DER encoding (6 instances)
- [ ] Refactor software.rs key storage locks (38 instances)
- [ ] Refactor software.rs ID counter lock (1 instance)
- [ ] Document test code unwrap() calls (8 instances)
- [ ] Run unit tests: `cargo test --features pkcs11`
- [ ] Run integration tests with SoftHSM2
- [ ] Run clippy: `cargo clippy --features pkcs11`
- [ ] Update CHANGELOG.md
- [ ] Create MR with Refactoring template
- [ ] Request review from HSM expert

---

## Timeline

| Task | Duration | Owner |
|------|----------|-------|
| Analysis (this document) | 0.5 days | Complete ✓ |
| pkcs11.rs refactoring | 2 days | TBD |
| software.rs refactoring | 2 days | TBD |
| Testing & validation | 1.5 days | TBD |
| Code review & fixes | 1 day | TBD |
| Documentation | 0.5 days | TBD |
| **Total** | **7.5 days** | |

**Buffer:** 0.5 days for unexpected issues

**Total with buffer:** 8 days (2 weeks with part-time allocation)

---

## Success Criteria

- [ ] unwrap() count reduced from 66 → 14 (52 eliminated)
- [ ] All unit tests pass
- [ ] Integration tests pass with SoftHSM2
- [ ] No clippy warnings
- [ ] Code review approved
- [ ] Documentation updated
- [ ] MR merged to main

---

## References

- [ERROR-HANDLING-PATTERNS.md](ERROR-HANDLING-PATTERNS.md) - Remediation patterns
- [REFACTORING-SPRINT-PLAN.md](../ato/REFACTORING-SPRINT-PLAN.md) - Overall sprint plan
- [PKCS#11 Specification v2.40](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html)

---

**Document Status:** READY FOR IMPLEMENTATION
**Next Step:** Create `refactor/phase2-hsm` branch and begin refactoring
**Owner:** Development Team
