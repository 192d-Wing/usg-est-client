# unwrap() Refactoring - [Module Name]

## Sprint Phase
<!-- Select one: Phase 2 (HSM), Phase 3 (Windows), Phase 4 (Auto-Enroll), Phase 5 (Core) -->
- [ ] Phase 2: HSM Module
- [ ] Phase 3: Windows Platform
- [ ] Phase 4: Auto-Enrollment Pipeline
- [ ] Phase 5: Core Libraries

## Changes Summary

### Files Modified
<!-- List files changed with unwrap() count reduction -->
- `src/[file].rs`: X unwrap() → Y unwrap() (Z reduction)

### Total Reduction
- **Before:** X unwrap() calls
- **After:** Y unwrap() calls
- **Reduction:** Z unwrap() calls (W% toward sprint goal)

## Remediation Patterns Applied

- [ ] Pattern 1: `Option::unwrap()` → `ok_or_else()`
- [ ] Pattern 2: `Result::unwrap()` → `map_err()`
- [ ] Pattern 3: `Lock::unwrap()` → Strategy-based handling
- [ ] Pattern 4: Infallible operations → `expect()` with justification
- [ ] Pattern 5: Test code → Document safety

## Testing

- [ ] All existing tests pass (`cargo test --lib`)
- [ ] New error path tests added
- [ ] Integration tests updated
- [ ] Manual testing completed on target platform

### Test Results
```
cargo test --lib
# Paste results here
```

## Documentation Updates

- [ ] Function documentation includes `# Errors` sections
- [ ] Error messages are actionable
- [ ] No information disclosure in error messages
- [ ] Error handling patterns guide followed

## NIST 800-53 Controls

<!-- Check applicable controls -->
- [ ] SI-11 (Error Handling) - No sensitive info in errors
- [ ] SC-24 (Fail in Known State) - Graceful degradation
- [ ] AU-9 (Protection of Audit Information) - Lock error handling

## Checklist

- [ ] Read ERROR-HANDLING-PATTERNS.md guide
- [ ] Applied appropriate pattern for each unwrap()
- [ ] Added error context (operation, resource, details)
- [ ] Verified no breaking API changes
- [ ] Ran `cargo clippy` - no new warnings
- [ ] unwrap() count decreased or remained same (pre-commit hook passed)
- [ ] Reviewed CI pipeline unwrap() dashboard
- [ ] Code review checklist completed

## Related Documentation

- [Error Handling Patterns Guide](/docs/dev/ERROR-HANDLING-PATTERNS.md)
- [Refactoring Sprint Plan](/docs/ato/REFACTORING-SPRINT-PLAN.md)
- [Executive Summary](/docs/ato/EXECUTIVE-SUMMARY.md)

## Reviewer Notes

<!-- Any specific areas to review or context for reviewers -->

/label ~refactoring ~Q2-2026-sprint
/assign @reviewer-username
