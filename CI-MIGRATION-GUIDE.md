# CI/CD Migration Quick Reference

Quick reference guide for migrating between GitHub Actions and GitLab CI/CD.

## Files Overview

| Platform | Configuration File | Documentation |
|----------|-------------------|---------------|
| GitHub Actions | [.github/workflows/*.yml](.github/workflows/) | GitHub Actions docs |
| GitLab CI/CD | [.gitlab-ci.yml](.gitlab-ci.yml) | [GITLAB-CI.md](GITLAB-CI.md) |

## Workflow Equivalents

### GitHub Actions → GitLab CI/CD

| GitHub Workflow | GitLab Pipeline | Status |
|----------------|-----------------|--------|
| [ci.yml](.github/workflows/ci.yml) | [.gitlab-ci.yml](.gitlab-ci.yml) (test, lint stages) | ✅ Migrated |
| [docs.yml](.github/workflows/docs.yml) | [.gitlab-ci.yml](.gitlab-ci.yml) (pages job) | ✅ Migrated |
| [security-audit.yml](.github/workflows/security-audit.yml) | [.gitlab-ci.yml](.gitlab-ci.yml) (security stage) | ✅ Migrated |

## Key Syntax Differences

### Triggers

```yaml
# GitHub Actions
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 0 * * *'
  workflow_dispatch:

# GitLab CI/CD
only:
  - main
  - merge_requests
  - schedules
# (Configure schedules via GitLab UI: CI/CD > Schedules)
```

### Jobs

```yaml
# GitHub Actions
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo test

# GitLab CI/CD
test:
  stage: test
  image: rust:latest
  script:
    - cargo test
  # Checkout is automatic
```

### Matrix Strategy

```yaml
# GitHub Actions
strategy:
  matrix:
    os: [ubuntu-latest, macos-latest]
    rust: [stable, beta]

# GitLab CI/CD (separate jobs)
test:stable:linux:
  image: rust:latest

test:stable:macos:
  tags: [macos]
```

### Caching

```yaml
# GitHub Actions
- uses: actions/cache@v5
  with:
    path: target
    key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}

# GitLab CI/CD
cache:
  key:
    files:
      - Cargo.lock
  paths:
    - target/
```

### Artifacts

```yaml
# GitHub Actions
- uses: actions/upload-artifact@v4
  with:
    name: audit-report
    path: audit-report.json
    retention-days: 30

# GitLab CI/CD
artifacts:
  name: "audit-report-$CI_COMMIT_REF_NAME"
  paths:
    - audit-report.json
  expire_in: 30 days
```

### Environment Variables

```yaml
# GitHub Actions
env:
  CARGO_TERM_COLOR: always
  RUST_BACKTRACE: 1

# GitLab CI/CD
variables:
  CARGO_TERM_COLOR: always
  RUST_BACKTRACE: "1"
```

### Conditions

```yaml
# GitHub Actions
if: github.event_name == 'pull_request'

# GitLab CI/CD
only:
  - merge_requests

# Or with rules:
rules:
  - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
```

## Feature Comparison

| Feature | GitHub Actions | GitLab CI/CD |
|---------|---------------|--------------|
| **Triggers** | | |
| Push to branch | ✅ `on: push` | ✅ `only: [main]` |
| Pull/Merge requests | ✅ `on: pull_request` | ✅ `only: [merge_requests]` |
| Scheduled | ✅ `on: schedule` | ✅ `only: [schedules]` + UI config |
| Manual | ✅ `workflow_dispatch` | ✅ Always available in UI |
| **Execution** | | |
| Parallel jobs | ✅ Automatic per workflow | ✅ Automatic per stage |
| Matrix builds | ✅ Native `strategy.matrix` | ⚠️ Multiple job definitions |
| Docker containers | ✅ `container:` | ✅ `image:` (default) |
| Self-hosted runners | ✅ Tags | ✅ Tags |
| **Caching** | | |
| Dependency caching | ✅ `actions/cache` | ✅ Built-in `cache:` |
| Cross-job caching | ✅ Yes | ✅ Yes |
| **Artifacts** | | |
| Job artifacts | ✅ `upload-artifact` | ✅ `artifacts:` |
| Retention | ✅ Up to 90 days | ✅ Configurable |
| Download between jobs | ✅ `download-artifact` | ✅ Automatic dependencies |
| **Reports** | | |
| Code coverage | ✅ Codecov integration | ✅ Native `coverage_report:` |
| Test results | ✅ Via actions | ✅ Native `reports:` |
| Security scanning | ⚠️ Third-party | ✅ Native SAST |
| **Deployment** | | |
| GitHub Pages | ✅ `deploy-pages` | ⚠️ Use artifacts |
| GitLab Pages | ⚠️ Not applicable | ✅ `pages` job |
| Environments | ✅ Yes | ✅ Yes |
| **Secrets** | | |
| Secret management | ✅ Org/repo secrets | ✅ Project/group variables |
| Masking | ✅ Automatic | ✅ Mark as "Masked" |
| Protected secrets | ✅ Environment secrets | ✅ Mark as "Protected" |

## Security Features Comparison

| Security Check | GitHub Actions | GitLab CI/CD |
|----------------|---------------|--------------|
| cargo-audit | ✅ Manual install | ✅ Manual install |
| cargo-deny | ✅ Manual install | ✅ Manual install |
| Clippy security lints | ✅ Yes | ✅ Yes |
| Dependency review | ✅ `dependency-review-action` | ⚠️ Use cargo-deny |
| SAST | ⚠️ Third-party (Semgrep, etc.) | ✅ Native template |
| Secret detection | ⚠️ Third-party | ✅ Native |
| License compliance | ⚠️ Third-party | ✅ Native |

## Migration Steps

### 1. Create GitLab CI/CD Configuration

```bash
# Copy the provided .gitlab-ci.yml to your repository root
cp .gitlab-ci.yml /path/to/your/repo/
```

### 2. Configure Runners (if needed)

For cross-platform testing, ensure runners are tagged:
- Linux: Default Docker runners
- macOS: Runners with `macos` tag
- Windows: Runners with `windows` tag

Or mark as `allow_failure: true` if not available.

### 3. Set Up Scheduled Pipelines

GitLab UI: **CI/CD > Schedules**
- Create schedule for daily security audit
- Cron: `0 0 * * *`
- Variable: `SCHEDULED_JOB=security`

### 4. Configure Project Settings

- **Settings > CI/CD > General pipelines**: Enable coverage reports
- **Settings > Repository > Protected branches**: Require pipeline success
- **Settings > Merge requests**: Enable pipeline checks

### 5. Test the Pipeline

```bash
# Push to a test branch
git checkout -b test-gitlab-ci
git push -u origin test-gitlab-ci

# Create merge request and verify:
# - All jobs pass
# - Coverage reports display
# - Artifacts are uploaded
```

### 6. Update Documentation

- [ ] Update README.md with GitLab badge
- [ ] Update CONTRIBUTING.md with GitLab CI references
- [ ] Add link to GITLAB-CI.md in main documentation

### 7. Optional: Remove GitHub Actions

Once GitLab CI/CD is verified:

```bash
# Backup workflows
mkdir -p .github/workflows-backup
mv .github/workflows/*.yml .github/workflows-backup/

# Or delete entirely
# rm -rf .github/workflows/
```

## Pipeline Badges

### GitHub Actions Badge

```markdown
[![CI](https://github.com/<user>/<repo>/workflows/CI/badge.svg)](https://github.com/<user>/<repo>/actions)
```

### GitLab CI/CD Badge

```markdown
[![Pipeline Status](https://gitlab.com/<namespace>/<project>/badges/main/pipeline.svg)](https://gitlab.com/<namespace>/<project>/-/pipelines)
[![Coverage](https://gitlab.com/<namespace>/<project>/badges/main/coverage.svg)](https://gitlab.com/<namespace>/<project>/-/pipelines)
```

## Common Issues and Solutions

### Issue: Jobs timeout

**Solution:** Increase timeout in job definition:

```yaml
test:
  timeout: 2h  # Default: 1h
```

### Issue: Cache not working

**Solution:** Clear runner cache or adjust cache policy:

```yaml
cache:
  policy: pull-push  # or just 'pull' for read-only
```

### Issue: macOS/Windows jobs failing

**Solution:** Mark as optional if runners not available:

```yaml
test:stable:macos:
  allow_failure: true
```

### Issue: cargo install too slow

**Solution:** Create custom Docker image with tools pre-installed:

```dockerfile
FROM rust:latest
RUN cargo install cargo-audit cargo-deny cargo-tarpaulin --locked
```

### Issue: Artifacts too large

**Solution:** Exclude unnecessary files:

```yaml
artifacts:
  paths:
    - audit-report.json
  exclude:
    - target/**/*
```

## Performance Tips

1. **Parallel execution**: Group independent jobs in same stage
2. **Caching**: Use `cache:` for dependencies, `artifacts:` for build outputs
3. **Docker images**: Use specific versions for reproducibility (`rust:1.92.0` not `rust:latest`)
4. **Conditional jobs**: Use `rules:` to skip unnecessary jobs
5. **Artifacts**: Only upload what's needed, use `expire_in:`

## Resources

- [GitLab CI/CD Documentation](https://docs.gitlab.com/ee/ci/)
- [Migrating from GitHub Actions](https://docs.gitlab.com/ee/ci/migration/github_actions.html)
- [GITLAB-CI.md](GITLAB-CI.md) - Full configuration guide
- [SECURITY-TOOLS.md](SECURITY-TOOLS.md) - Security automation

## Support

- Open an issue for CI/CD problems
- Check GitLab CI/CD logs for errors
- Reference this guide for syntax differences

---

**Last Updated**: 2026-01-12
**Status**: GitHub Actions ✅ Active | GitLab CI/CD ✅ Active
