# Security Tools and Testing

This document describes the security tools and testing infrastructure for the USG EST Client.

## Overview

The project uses multiple security tools for continuous security assurance:

1. **cargo-audit** - Vulnerability scanning
2. **cargo-deny** - Dependency policy enforcement
3. **cargo-fuzz** - Fuzzing critical parsers
4. **GitHub Actions** - Automated security scanning
5. **Clippy** - Security-focused linting

## cargo-audit

Scans dependencies for known security vulnerabilities using the RustSec advisory database.

### Installation

```bash
cargo install cargo-audit
```

### Usage

```bash
# Run vulnerability scan
cargo audit

# Generate JSON report
cargo audit --json > audit-report.json

# Fail on warnings
cargo audit --deny warnings
```

### Automated Scanning

The GitHub Actions workflow runs cargo-audit:
- On every push to main
- On every pull request
- Daily at 00:00 UTC
- Can be triggered manually

## cargo-deny

Enforces dependency policies for licenses, security advisories, and sources.

### Installation

```bash
# macOS
brew install cargo-deny

# Linux
wget https://github.com/EmbarkStudios/cargo-deny/releases/latest/download/cargo-deny-x86_64-unknown-linux-musl.tar.gz
tar -xzf cargo-deny-*.tar.gz
sudo mv cargo-deny /usr/local/bin/

# Windows
cargo install cargo-deny
```

### Usage

```bash
# Check all policies
cargo deny check

# Check specific policy
cargo deny check advisories
cargo deny check licenses
cargo deny check bans
cargo deny check sources
```

### Configuration

Policy configuration is in `deny.toml`:

- **Advisories**: Vulnerability scanning (denies vulnerabilities, warns on unmaintained)
- **Licenses**: Only allows Apache-2.0, MIT, BSD-2/3-Clause, ISC, and related
- **Bans**: Prevents use of insecure crates (md5, sha1, old OpenSSL)
- **Sources**: Only allows crates.io (no unknown registries or git repos)

### Known Exceptions

The following advisories are explicitly allowed in `deny.toml`:

- **RUSTSEC-2024-0436** (paste crate unmaintained)
  - Justification: Low risk compile-time proc-macro, transitive via cryptoki
  - Action: Monitoring for cryptoki updates

## Fuzzing

Fuzzing tests critical parsing code for crashes, panics, and undefined behavior.

### Prerequisites

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Requires nightly Rust
rustup toolchain install nightly
```

### Available Fuzz Targets

1. **fuzz_parse_pem_certificates** - PEM certificate parser
2. **fuzz_parse_pem_private_key** - PEM private key parser
3. **fuzz_validate_csr** - CSR validation
4. **fuzz_parse_pkcs7** - PKCS#7 parser

### Running Fuzz Tests

```bash
# Run a specific fuzz target
cargo +nightly fuzz run fuzz_parse_pem_certificates

# Run with specific timeout (in seconds)
cargo +nightly fuzz run fuzz_parse_pem_certificates -- -max_total_time=300

# Run with custom corpus
cargo +nightly fuzz run fuzz_parse_pem_certificates fuzz/corpus/fuzz_parse_pem_certificates

# List all fuzz targets
cargo +nightly fuzz list
```

### Interpreting Results

- **Success**: Fuzzer runs without crashes or panics
- **Failure**: Fuzzer finds input causing crash/panic/timeout
  - Failing input saved to `fuzz/artifacts/`
  - Review and fix the issue
  - Add to corpus for regression testing

### Continuous Fuzzing

For long-running fuzzing campaigns:

```bash
# Run for 24 hours with multiple workers
cargo +nightly fuzz run fuzz_parse_pem_certificates -- \
  -max_total_time=86400 \
  -workers=8 \
  -jobs=8
```

## GitHub Actions Security Workflow

Automated security checks run on every commit and PR.

### Workflow Jobs

1. **cargo-audit** - Daily vulnerability scanning
2. **cargo-deny** - Policy enforcement on all commits
3. **clippy-security** - Security-focused linting
4. **dependency-review** - PR dependency change review
5. **test-security-features** - Test all security features

### Viewing Results

- Go to **Actions** tab in GitHub
- Select **Security Audit** workflow
- View job results and logs
- Download artifacts (audit reports)

### Triggering Manual Scans

```bash
# Via GitHub CLI
gh workflow run security-audit.yml

# Or via GitHub UI: Actions → Security Audit → Run workflow
```

## Clippy Security Lints

Security-focused linting with Clippy.

### Running Locally

```bash
# Run security-focused lints
cargo clippy --all-targets --all-features -- \
  -D warnings \
  -W clippy::unwrap_used \
  -W clippy::expect_used \
  -W clippy::panic \
  -W clippy::todo \
  -W clippy::unimplemented
```

### Key Security Lints

- **unwrap_used** - Flags potential panics from unwrap()
- **expect_used** - Flags potential panics from expect()
- **panic** - Flags explicit panic!() calls
- **todo/unimplemented** - Flags incomplete code

## Testing Security Features

### Running Security Tests

```bash
# Run all tests
cargo test --all-features

# Test validation feature
cargo test --features validation

# Test FIPS configuration (compile check)
cargo check --features fips

# Test DoD configuration (compile check)
cargo check --features dod
```

### Coverage Analysis

```bash
# Install tarpaulin
cargo install cargo-tarpaulin

# Generate coverage report
cargo tarpaulin --all-features --out Html --output-dir coverage/
```

## Integration with CI/CD

### Pre-commit Hooks

Add to `.git/hooks/pre-commit`:

```bash
#!/bin/bash
set -e

echo "Running security checks..."

# Quick security scan
cargo audit

# License and dependency check
cargo deny check

# Lint check
cargo clippy -- -D warnings

echo "Security checks passed!"
```

### Pre-release Checklist

Before releasing a new version:

1. ✅ Run `cargo audit` - no vulnerabilities
2. ✅ Run `cargo deny check` - all policies pass
3. ✅ Run `cargo test --all-features` - all tests pass
4. ✅ Run `cargo clippy` - no warnings
5. ✅ Run fuzz tests for 1+ hour per target
6. ✅ Review dependency updates
7. ✅ Update SECURITY.md if needed

## Reporting Security Issues

If fuzzing or security tools discover vulnerabilities:

1. **Do not** create public issues
2. Follow responsible disclosure in SECURITY.md
3. Include:
   - Tool used (cargo-audit, fuzzing, etc.)
   - Reproduction steps
   - Impact assessment
   - Proposed fix (if available)

## Recommended Schedule

### Daily
- Automated cargo-audit scan (via GitHub Actions)
- Monitor GitHub security advisories

### Weekly
- Manual `cargo audit` review
- Review Dependabot PRs

### Monthly
- Run fuzzing campaign (8+ hours per target)
- Review and update `deny.toml` policies
- Dependency update review

### Quarterly
- Full security audit review
- Update SECURITY.md
- Review and rotate DoD PKI certificates
- Penetration testing (if applicable)

## Additional Resources

- [RustSec Advisory Database](https://rustsec.org/)
- [cargo-audit Documentation](https://docs.rs/cargo-audit/)
- [cargo-deny Documentation](https://embarkstudios.github.io/cargo-deny/)
- [cargo-fuzz Documentation](https://rust-fuzz.github.io/book/cargo-fuzz.html)
- [Clippy Lints](https://rust-lang.github.io/rust-clippy/)

## Support

For questions about security tooling:
- Open a discussion on GitHub
- Reference this document in issues
- Contact the security team (see SECURITY.md)

---

**Last Updated**: 2026-01-12
**Tools Version**: cargo-audit 0.18+, cargo-deny 0.14+, cargo-fuzz 0.11+
