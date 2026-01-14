## unwrap() Tracking Dashboard

**Sprint Goal:** Reduce from 339 to 68 unwrap() calls (80% reduction)
**Timeline:** Q2 2026 (8 weeks)
**Test Run:** Local execution

### Overall Progress

| Metric | Value |
|--------|-------|
| **Current Count** | 339 |
| **Baseline (2026-01-14)** | 339 |
| **Sprint Goal** | 68 |
| **Reduction So Far** | 0 |
| **Progress** | 0% |

⚠️ No change in unwrap() count

### Top Files by unwrap() Count

| File | Count | Sprint Phase |
|------|-------|--------------|
| `hsm/software.rs` | 48 | Phase 2 (HSM) |
| `auto_enroll/config.rs` | 42 | Phase 4 (Auto-Enroll) |
| `auto_enroll/expand.rs` | 36 | Phase 4 (Auto-Enroll) |
| `auto_enroll/loader.rs` | 27 | Phase 4 (Auto-Enroll) |
| `logging/encryption.rs` | 26 | Phase 5 (Core) |
| `logging.rs` | 25 | Phase 5 (Core) |
| `bin/est-autoenroll-service.rs` | 22 | Phase 5 (Core) |
| `hsm/pkcs11.rs` | 18 | Phase 2 (HSM) |
| `csr/pkcs10.rs` | 12 | Phase 5 (Core) |
| `metrics/opentelemetry.rs` | 11 | Phase 5 (Core) |
| `windows/cng.rs` | 9 | Phase 3 (Windows) |
| `windows/perfcounter.rs` | 8 | Phase 3 (Windows) |
| `windows/dpapi.rs` | 6 | Phase 3 (Windows) |
| `metrics/prometheus.rs` | 5 | Phase 5 (Core) |
| `client.rs` | 5 | Phase 5 (Core) |

### Module Breakdown

| Module | Count | Target | Phase |
|--------|-------|--------|-------|
| `src/hsm/` | 66 | 5 | Phase 2 (Weeks 3-4) |
| `src/windows/` | 35 | 8 | Phase 3 (Weeks 5-6) |
| `src/auto_enroll/` + `src/operations/` | 108 | 5 | Phase 4 (Week 7) |
| Core (`validation`, `logging`, `config`) | 32 | 10 | Phase 5 (Week 8) |

### Resources

- 📘 [Error Handling Patterns Guide](docs/dev/ERROR-HANDLING-PATTERNS.md)
- 📋 [Refactoring Sprint Plan](docs/ato/REFACTORING-SPRINT-PLAN.md)
- 📊 [Executive Summary](docs/ato/EXECUTIVE-SUMMARY.md)

