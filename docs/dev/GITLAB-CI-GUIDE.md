# GitLab CI/CD Pipeline Guide

**Document Type:** Developer Reference
**Audience:** EST Client Library Contributors
**Last Updated:** 2026-01-14
**Status:** ACTIVE

---

## Overview

The EST Client Library uses GitLab CI/CD for continuous integration, security scanning, and unwrap() refactoring tracking. This guide explains how to use the pipeline effectively.

**Pipeline Configuration:** [.gitlab-ci.yml](../../.gitlab-ci.yml)

---

## Pipeline Stages

The pipeline consists of 6 stages that run sequentially:

### 1. Analysis Stage

**Purpose:** Track code quality metrics and unwrap() reduction progress

**Jobs:**
- `unwrap-tracking`: Generates dashboard tracking progress toward Q2 2026 goal

**Artifacts:**
- `report.md`: unwrap() tracking dashboard
- Available in GitLab UI under "Job Artifacts" → "unwrap() Dashboard"

**When it runs:**
- On merge requests
- On main branch pushes
- On feature/* branches
- On refactor/* branches

### 2. Test Stage

**Purpose:** Validate code correctness across platforms and Rust versions

**Jobs:**
- `test:stable:linux`: Run tests on Linux with stable Rust
- `test:stable:macos`: Run tests on macOS (if runner available)
- `test:stable:windows`: Run tests on Windows (if runner available)
- `test:beta`: Run tests with Rust beta version
- `test:msrv`: Run tests with Minimum Supported Rust Version (1.92.0)
- `test:features:*`: Test individual feature flags (csr-gen, hsm, renewal, etc.)

**Artifacts:** None

**When it runs:**
- On merge requests
- On main branch pushes

### 3. Lint Stage

**Purpose:** Enforce code style and documentation standards

**Jobs:**
- `clippy:default`: Run clippy with default features
- `clippy:all-features`: Run clippy with all features enabled
- `rustfmt`: Check code formatting
- `docs`: Build documentation and check for warnings

**Artifacts:** None

**When it runs:**
- On merge requests
- On main branch pushes

### 4. Security Stage

**Purpose:** Identify security vulnerabilities and compliance issues

**Jobs:**
- `security:cargo-audit`: Check for known CVEs in dependencies
- `security:cargo-deny:advisories`: Check security advisories
- `security:cargo-deny:licenses`: Verify license compliance
- `security:cargo-deny:bans`: Check for banned dependencies
- `security:cargo-deny:sources`: Verify dependency sources
- `security:clippy`: Run clippy with security-focused lints
- `security:test-features`: Test security-critical features

**Artifacts:**
- `audit-report.json`: Security audit results (30-day retention)

**When it runs:**
- On merge requests
- On main branch pushes
- On scheduled pipelines

### 5. Docs Stage

**Purpose:** Build and deploy documentation website

**Jobs:**
- `pages`: Build Zensical documentation site and deploy to GitLab Pages

**Artifacts:**
- `public/`: Built documentation site (7-day retention)

**When it runs:**
- On main branch when docs/ changes
- Manual trigger on main branch

**Output:** Available at `https://<namespace>.gitlab.io/<project>/`

### 6. Coverage Stage

**Purpose:** Generate code coverage reports

**Jobs:**
- `coverage:tarpaulin`: Generate coverage report with tarpaulin

**Artifacts:**
- `coverage/`: Coverage report in multiple formats
- Cobertura XML for GitLab UI integration

**When it runs:**
- On merge requests
- On main branch pushes

---

## Using the Pipeline

### Viewing Pipeline Status

**In GitLab UI:**
1. Navigate to **CI/CD → Pipelines**
2. Click on a pipeline to see all jobs
3. Click on a job to see logs and artifacts

**In Merge Requests:**
- Pipeline status shows at bottom of MR
- Click "View pipeline" to see details

### Accessing unwrap() Dashboard

**After pipeline runs:**
1. Go to the `unwrap-tracking` job
2. Click **"Browse"** next to artifacts
3. Open `report.md` to view dashboard
4. Or click **"unwrap() Dashboard"** shortcut if available

**What the dashboard shows:**
- Current unwrap() count vs baseline (339)
- Progress toward sprint goal (68)
- Top 15 files by unwrap() count
- Module breakdown by sprint phase
- Links to documentation

### Understanding Pipeline Failures

#### unwrap-tracking Job Failed

**Error:** "unwrap() count increased by X"

**Meaning:** Your changes added unwrap() calls

**Fix:**
1. Review the dashboard artifact to see which files
2. Apply error handling patterns from [ERROR-HANDLING-PATTERNS.md](ERROR-HANDLING-PATTERNS.md)
3. Replace `unwrap()` with proper error handling
4. Commit and push again

**Example:**
```bash
# View which files have new unwrap() calls
git diff main...HEAD | grep unwrap

# Fix them using patterns from the guide
# Then commit
git add src/
git commit -m "fix: replace unwrap() with proper error handling"
```

#### Test Job Failed

**Error:** Test assertion failure

**Meaning:** Your changes broke existing functionality

**Fix:**
1. Review test output in job logs
2. Fix the code or update tests
3. Run tests locally: `cargo test`
4. Commit and push fix

#### Clippy Job Failed

**Error:** Clippy lint warnings

**Meaning:** Code style or potential bugs detected

**Fix:**
1. Run locally: `cargo clippy --all-features -- -D warnings`
2. Fix warnings
3. Consider using `#[allow(clippy::lint_name)]` for false positives (with comment explaining why)
4. Commit and push

#### Security:cargo-audit Failed

**Error:** Known vulnerability in dependency

**Meaning:** A dependency has a published CVE

**Fix:**
1. Check `audit-report.json` artifact for details
2. Update vulnerable dependency: `cargo update -p <package>`
3. If no fix available, document in POA&M
4. Commit updated `Cargo.lock`

---

## Local Pipeline Testing

### Option 1: Simulate unwrap-tracking Job

We've created a test script that mimics the GitLab job:

```bash
# Run the local test script
./test-unwrap-tracking.sh

# View generated report
cat report.md
```

This generates the same dashboard that GitLab CI produces.

### Option 2: Install GitLab Runner

For full pipeline testing:

**Install gitlab-runner:**

**macOS:**
```bash
brew install gitlab-runner
```

**Linux:**
```bash
curl -L "https://packages.gitlab.com/install/repositories/runner/gitlab-runner/script.deb.sh" | sudo bash
sudo apt-get install gitlab-runner
```

**Windows:**
```powershell
# Download from https://docs.gitlab.com/runner/install/windows.html
```

**Run specific job:**
```bash
# Run unwrap-tracking job
gitlab-runner exec docker unwrap-tracking

# Run test job
gitlab-runner exec docker test:stable:linux

# Run clippy job
gitlab-runner exec docker clippy:default
```

**Note:** This requires Docker to be installed and running.

### Option 3: Run Pipeline Checks Manually

**Run tests:**
```bash
cargo test --lib
cargo test --all-features
cargo test --no-default-features
```

**Run clippy:**
```bash
cargo clippy --all-features -- -D warnings
cargo clippy -- -W clippy::unwrap_used -W clippy::expect_used
```

**Run rustfmt:**
```bash
cargo fmt --all -- --check
```

**Run cargo-audit:**
```bash
cargo install cargo-audit
cargo audit
```

**Build docs:**
```bash
cargo doc --all-features --no-deps
```

---

## Pipeline Variables

These variables are defined in `.gitlab-ci.yml` and can be customized:

| Variable | Default | Purpose |
|----------|---------|---------|
| `UNWRAP_BASELINE` | 339 | Starting unwrap() count (2026-01-14) |
| `UNWRAP_GOAL` | 68 | Target unwrap() count (Q2 2026) |
| `CARGO_TERM_COLOR` | always | Colorized cargo output |
| `RUST_BACKTRACE` | 1 | Enable backtraces in tests |
| `CARGO_HOME` | ${CI_PROJECT_DIR}/.cargo | Cargo cache location |

**To override in GitLab:**
1. Go to **Settings → CI/CD → Variables**
2. Add variable (e.g., `UNWRAP_BASELINE=350`)
3. Next pipeline will use new value

---

## Scheduled Pipelines

### Security Audit Schedule

**Purpose:** Daily security vulnerability scanning

**Job:** `security:scheduled`

**Setup in GitLab:**
1. Go to **CI/CD → Schedules**
2. Click **"New schedule"**
3. Set:
   - Description: "Daily Security Audit"
   - Interval: `0 0 * * *` (midnight UTC)
   - Target branch: `main`
   - Variables: `SCHEDULED_JOB=security`
4. Save

**Artifacts:**
- `audit-report-scheduled.json` (90-day retention)

---

## Merge Request Templates

Two templates are available for merge requests:

### Default Template

**File:** `.gitlab/merge_request_templates/Default.md`

**Use for:** General changes (features, bug fixes, docs)

**How to use:**
1. Create MR in GitLab
2. In description, click "Choose a template"
3. Select "Default"
4. Fill in sections

**Sections:**
- Description
- Type of change (checklist)
- Related issues
- Testing evidence
- Security considerations
- Checklist

### Refactoring Template

**File:** `.gitlab/merge_request_templates/Refactoring.md`

**Use for:** unwrap() refactoring sprint work

**How to use:**
1. Create MR in GitLab
2. Select "Refactoring" template
3. Select sprint phase
4. Document reduction metrics
5. Check remediation patterns used

**Sections:**
- Sprint phase selection
- unwrap() reduction metrics
- Remediation patterns applied
- Testing checklist
- NIST 800-53 controls
- Documentation updates

---

## Troubleshooting

### Pipeline is Stuck on "Pending"

**Cause:** No GitLab runners available

**Fix:**
1. Check **Settings → CI/CD → Runners**
2. Enable shared runners or register a specific runner
3. Or use GitLab.com shared runners (free tier available)

### Runner Out of Disk Space

**Cause:** Cargo cache is large

**Fix:**
1. Clear cargo cache in runner
2. Or reduce cache retention in `.gitlab-ci.yml`:
   ```yaml
   cache:
     policy: pull-push  # Change to 'pull' to not save cache
   ```

### Tests Pass Locally but Fail in CI

**Cause:** Environment differences (timezone, locale, temp directory)

**Fix:**
1. Check test dependencies on system state
2. Make tests more deterministic
3. Mock external dependencies
4. Check for race conditions in parallel tests

### unwrap() Count Mismatch

**Cause:** Different grep version or file encoding

**Fix:**
1. Run `./test-unwrap-tracking.sh` locally
2. Compare with pipeline output
3. Ensure using UTF-8 encoding
4. Check for files with CRLF line endings

---

## Best Practices

### Before Pushing

1. **Run tests locally**: `cargo test --all-features`
2. **Run clippy**: `cargo clippy --all-features -- -D warnings`
3. **Format code**: `cargo fmt --all`
4. **Check unwrap() count**: `./test-unwrap-tracking.sh`
5. **Review pre-commit hook output**

### During Development

1. **Check pipeline status frequently** - don't wait until MR review
2. **Fix failures immediately** - don't accumulate technical debt
3. **Review artifacts** - especially unwrap() dashboard
4. **Update tests** - add tests for new error paths
5. **Document errors** - add `# Errors` sections to functions

### In Merge Requests

1. **Use appropriate template** (Default or Refactoring)
2. **Link related issues** using `Closes #123` syntax
3. **Include test evidence** - paste test output
4. **Explain unwrap() changes** if count changed
5. **Request specific reviewers** using `/assign @username`

---

## Integration with Development Workflow

### Feature Development

```bash
# 1. Create feature branch
git checkout -b feature/my-feature

# 2. Make changes
vim src/my_feature.rs

# 3. Run local checks
cargo test
cargo clippy
./test-unwrap-tracking.sh

# 4. Commit (pre-commit hook runs)
git commit -m "feat: add my feature"

# 5. Push (pipeline runs)
git push origin feature/my-feature

# 6. Create MR in GitLab
# - Use Default template
# - Fill in sections
# - Review pipeline results
# - Address any failures

# 7. Request review
# /assign @reviewer-username in MR description
```

### Refactoring Sprint Work

```bash
# 1. Create refactor branch
git checkout -b refactor/phase2-hsm-module

# 2. Make changes following ERROR-HANDLING-PATTERNS.md
vim src/hsm/pkcs11.rs

# 3. Verify reduction
./test-unwrap-tracking.sh
# Should show decreased unwrap() count

# 4. Run tests
cargo test --features hsm

# 5. Commit
git commit -m "refactor(hsm): replace unwrap() in pkcs11 module

Applied Pattern 2 (Result::unwrap → map_err) to:
- slot enumeration (10 instances)
- session management (8 instances)

Reduction: 18 unwrap() calls → 0"

# 6. Push and create MR with Refactoring template
git push origin refactor/phase2-hsm-module
```

---

## Pipeline Performance

### Typical Run Times

| Stage | Duration | Notes |
|-------|----------|-------|
| Analysis | 10-30s | Very fast (grep only) |
| Test | 2-5 min | Depends on test count |
| Lint | 1-3 min | Clippy + rustfmt |
| Security | 3-5 min | Multiple cargo-deny checks |
| Docs | 2-4 min | If docs changed |
| Coverage | 5-10 min | Slowest stage |

**Total pipeline time:** 15-30 minutes

### Optimization Tips

1. **Use pipeline rules** to skip unnecessary jobs
2. **Cache effectively** - Cargo dependencies cached between runs
3. **Parallelize tests** - Use `cargo nextest` for faster test execution
4. **Skip coverage** - Only run on main branch or manually

---

## Additional Resources

- [GitLab CI/CD Documentation](https://docs.gitlab.com/ee/ci/)
- [GitLab Runner Documentation](https://docs.gitlab.com/runner/)
- [Error Handling Patterns Guide](ERROR-HANDLING-PATTERNS.md)
- [Refactoring Sprint Plan](../ato/REFACTORING-SPRINT-PLAN.md)
- [Executive Summary](../ato/EXECUTIVE-SUMMARY.md)

---

## Changelog

| Date | Author | Changes |
|------|--------|---------|
| 2026-01-14 | Development Team | Initial version for GitLab migration |

---

**Document End**

**Status:** ACTIVE
**Next Review:** Q2 2026
**Owner:** Development Team
