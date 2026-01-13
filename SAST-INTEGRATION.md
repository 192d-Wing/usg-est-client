# SAST (Static Application Security Testing) Integration

This document explains the GitLab SAST integration for automated security scanning.

## Overview

GitLab SAST automatically scans source code for security vulnerabilities without executing the code. It runs on every pipeline and provides detailed reports.

## What is SAST?

**Static Application Security Testing (SAST)** analyzes source code to detect:
- Security vulnerabilities
- Insecure coding patterns
- Common security flaws (OWASP Top 10)
- Injection vulnerabilities
- Authentication issues
- Cryptographic problems
- Hard-coded secrets

## Configuration

SAST is enabled in [.gitlab-ci.yml](.gitlab-ci.yml):

```yaml
include:
  - template: Security/SAST.gitlab-ci.yml
```

That's it! GitLab automatically:
1. Detects Rust code
2. Runs appropriate analyzers
3. Generates security reports
4. Displays results in merge requests

## SAST Analyzers for Rust

GitLab SAST uses these analyzers for Rust:

### 1. Semgrep
- **Purpose**: Pattern-based code scanning
- **What it checks**:
  - Insecure function usage (unwrap, panic)
  - SQL injection patterns
  - Path traversal vulnerabilities
  - Cryptographic misuse
  - Hard-coded secrets
- **Language**: Multi-language (includes Rust rules)

### 2. Secret Detection
- **Purpose**: Find hard-coded credentials
- **What it checks**:
  - API keys
  - Passwords
  - Private keys
  - Access tokens
  - Database credentials

## Viewing SAST Results

### In Merge Requests

1. Create or open a merge request
2. Navigate to **Security** tab
3. View detected vulnerabilities with:
   - Severity (Critical, High, Medium, Low)
   - Description
   - File location
   - Code snippet
   - Remediation advice

### In Pipeline

1. Go to **CI/CD > Pipelines**
2. Click pipeline ID
3. Click **Security** tab
4. Download SAST report (JSON format)

### In Security Dashboard

GitLab Ultimate/Gold:
- **Security & Compliance > Vulnerability Report**
- Project-wide vulnerability tracking
- Trend analysis over time

## SAST Report Artifacts

Reports are saved as artifacts:
- Path: `gl-sast-report.json`
- Format: GitLab Security Report Schema
- Retention: 30 days (configurable)

Download via:
```bash
# Using GitLab API
curl --header "PRIVATE-TOKEN: <token>" \
  "https://gitlab.com/api/v4/projects/<id>/jobs/<job-id>/artifacts/gl-sast-report.json"
```

## Customizing SAST

### Adjusting Severity Threshold

Only fail pipeline on critical/high vulnerabilities:

```yaml
# Add to .gitlab-ci.yml
semgrep-sast:
  variables:
    SAST_EXCLUDED_ANALYZERS: ""
    SAST_EXCLUDED_PATHS: "spec,test,tests,tmp"
  rules:
    - if: $SAST_DISABLED
      when: never
    - if: $CI_COMMIT_BRANCH
  allow_failure: true  # Don't fail pipeline on findings
```

### Excluding Paths

Skip scanning for specific directories:

```yaml
variables:
  SAST_EXCLUDED_PATHS: "test,tests,vendor,fuzz"
```

### Disabling Specific Analyzers

```yaml
variables:
  SAST_EXCLUDED_ANALYZERS: "secret_detection"  # Disable secret detection
```

### Custom Rules

Create `.semgrep.yml` in repository root:

```yaml
rules:
  - id: custom-unwrap-check
    pattern: |
      .unwrap()
    message: Avoid using unwrap(), use ? or proper error handling
    severity: WARNING
    languages:
      - rust
```

## Integration with Merge Request Approvals

Require security review for vulnerabilities:

GitLab Premium/Ultimate:
1. **Settings > Merge requests > Merge request approvals**
2. Enable **Security approvals**
3. Set required approvals for security changes
4. MRs with vulnerabilities require security team approval

## False Positive Management

### Dismissing Vulnerabilities

If SAST reports false positive:

1. Open merge request
2. Navigate to **Security** tab
3. Click vulnerability
4. Select **Dismiss vulnerability**
5. Choose reason:
   - False positive
   - Used in tests only
   - Acceptable risk
   - Won't fix
6. Add comment explaining dismissal

### Suppressing in Code

For Semgrep, use inline comments:

```rust
// nosemgrep: rust.lang.security.unwrap-used
let value = some_option.unwrap();  // Justified: guaranteed to be Some here
```

## SAST vs Other Security Tools

| Tool | Type | When it Runs | What it Finds |
|------|------|--------------|---------------|
| **SAST** | Static analysis | Every commit | Code-level vulnerabilities |
| **cargo-audit** | Dependency scan | Every commit | Known CVEs in dependencies |
| **cargo-deny** | Policy check | Every commit | License/policy violations |
| **Clippy** | Linter | Every commit | Code quality & some security |
| **Fuzzing** | Dynamic test | Manual/scheduled | Runtime crashes & panics |
| **DAST** | Dynamic analysis | Deployed app | Runtime vulnerabilities |

**Use all together for defense in depth!**

## Common SAST Findings for Rust

### 1. Unsafe Unwrap Usage

**Finding:**
```rust
let value = result.unwrap();  // ❌ SAST warning
```

**Fix:**
```rust
let value = result?;  // ✅ Proper error propagation
// or
let value = result.expect("meaningful error message");  // ✅ With context
```

### 2. Hard-coded Secrets

**Finding:**
```rust
const API_KEY: &str = "sk_live_abc123";  // ❌ SAST alert
```

**Fix:**
```rust
let api_key = std::env::var("API_KEY")?;  // ✅ From environment
```

### 3. Path Traversal

**Finding:**
```rust
let path = format!("/data/{}", user_input);  // ❌ Potential traversal
std::fs::read(path)?;
```

**Fix:**
```rust
use std::path::PathBuf;

let mut path = PathBuf::from("/data");
path.push(user_input);
// Validate path doesn't escape /data directory
if !path.starts_with("/data") {
    return Err("Invalid path");
}
std::fs::read(path)?;  // ✅ Validated
```

### 4. Insecure Random

**Finding:**
```rust
use rand::random;
let token = random::<u64>();  // ❌ Not cryptographically secure
```

**Fix:**
```rust
use rand::rngs::OsRng;
use rand::RngCore;

let mut token = [0u8; 32];
OsRng.fill_bytes(&mut token);  // ✅ Cryptographically secure
```

### 5. SQL Injection (if using raw SQL)

**Finding:**
```rust
let query = format!("SELECT * FROM users WHERE id = {}", user_id);  // ❌ Injection risk
```

**Fix:**
```rust
// Use parameterized queries
sqlx::query!("SELECT * FROM users WHERE id = $1", user_id)
    .fetch_one(&pool)
    .await?;  // ✅ Safe
```

## Performance Impact

SAST jobs add minimal time to pipeline:
- **Semgrep**: ~30-60 seconds
- **Secret Detection**: ~10-20 seconds
- **Total overhead**: ~1 minute

**Runs in parallel with other jobs**, so total pipeline time increase is minimal.

## Best Practices

### 1. Fix High/Critical Issues Immediately

Don't merge code with critical or high severity findings.

### 2. Review All Findings

Even low severity issues can indicate poor coding patterns.

### 3. Document Dismissals

Always add clear justification when dismissing vulnerabilities.

### 4. Regular Reviews

Weekly review of security dashboard to track trends.

### 5. Security Training

Share SAST findings with team for learning opportunities.

### 6. Custom Rules

Add project-specific security rules in `.semgrep.yml`.

### 7. Integrate with Workflow

Make security reviews part of code review process.

## Troubleshooting

### Issue: SAST job not running

**Solution:**
```yaml
# Verify include statement in .gitlab-ci.yml
include:
  - template: Security/SAST.gitlab-ci.yml

# Check GitLab version (SAST requires GitLab 11.9+)
```

### Issue: False positives

**Solution:**
- Dismiss in UI with justification
- Use inline suppressions (nosemgrep comments)
- Adjust analyzer configuration

### Issue: Missing vulnerabilities

**Solution:**
- SAST is pattern-based, may miss context-specific issues
- Complement with cargo-audit, clippy, and manual review
- Consider custom Semgrep rules for project-specific patterns

### Issue: SAST job fails

**Solution:**
```bash
# Check job logs for errors
# Common issues:
# - Network timeout (increase timeout)
# - Large codebase (exclude unnecessary paths)
# - Analyzer crash (report to GitLab)
```

## Advanced Configuration

### Running SAST Locally

Install Semgrep:
```bash
# Using pip
pip install semgrep

# Run scan
semgrep --config=auto .
```

### CI/CD Variables

Control SAST behavior:

```yaml
variables:
  SAST_ANALYZER_IMAGE_TAG: "latest"
  SAST_EXCLUDED_PATHS: "test,vendor"
  SAST_EXCLUDED_ANALYZERS: ""
  SAST_DEFAULT_ANALYZERS: "semgrep"
  SECURE_ANALYZERS_PREFIX: "registry.gitlab.com/security-products"
```

### Custom Analyzer Image

Use specific version:

```yaml
semgrep-sast:
  variables:
    SAST_ANALYZER_IMAGE_TAG: "4.0.0"  # Pin version
```

## Compliance and Reporting

### DoD Compliance

SAST helps meet requirements for:
- **RMF (Risk Management Framework)**: Automated security testing
- **NIST 800-53**: SA-11 (Developer Security Testing)
- **FISMA**: Continuous monitoring requirements

### Audit Reports

Export findings for audits:
1. **Security & Compliance > Vulnerability Report**
2. Click **Export**
3. Select format (CSV, JSON)
4. Include in compliance documentation

## Resources

- [GitLab SAST Documentation](https://docs.gitlab.com/ee/user/application_security/sast/)
- [Semgrep Rules](https://semgrep.dev/explore)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Secure Coding Guidelines](https://www.securecoding.cert.org/)

## Integration with Other Tools

SAST complements but doesn't replace:
- **cargo-audit**: Use both for comprehensive security
- **cargo-deny**: Policy enforcement layer
- **Fuzzing**: Dynamic testing for edge cases
- **Manual review**: Human expertise for complex issues

## Support

For SAST-related issues:
- Check GitLab SAST documentation
- Review Semgrep rules at semgrep.dev
- Open issue with specific finding details
- Reference this document for configuration

---

**Last Updated**: 2026-01-12
**GitLab SAST Version**: Integrated via template (auto-updated)
**Primary Analyzer**: Semgrep for Rust
