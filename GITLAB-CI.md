# GitLab CI/CD Configuration

This document describes the GitLab CI/CD pipeline configuration for the USG EST Client, migrated from GitHub Actions.

## Overview

The GitLab CI/CD pipeline ([.gitlab-ci.yml](.gitlab-ci.yml)) provides comprehensive automated testing, linting, security scanning, and documentation deployment.

## Pipeline Stages

The pipeline consists of 5 stages that run sequentially:

1. **test** - Run test suite across platforms and Rust versions
2. **lint** - Code quality and formatting checks
3. **security** - Security vulnerability and policy scanning
4. **coverage** - Code coverage analysis
5. **docs** - Documentation site deployment (GitLab Pages)

## Jobs

### Test Stage

#### Cross-Platform Testing
- **test:stable:linux** - Test on latest stable Rust (Linux)
- **test:stable:macos** - Test on latest stable Rust (macOS) *
- **test:stable:windows** - Test on latest stable Rust (Windows) *
- **test:beta** - Test on beta Rust channel
- **test:msrv** - Test Minimum Supported Rust Version (1.92.0)

\* Requires GitLab runners with macOS/Windows tags. Marked as `allow_failure: true` if runners not available.

#### Feature Testing
Each feature is tested independently:
- **test:features:csr-gen** - Certificate Signing Request generation
- **test:features:hsm** - Hardware Security Module support
- **test:features:renewal** - Certificate renewal
- **test:features:validation** - Certificate validation
- **test:features:metrics** - Metrics and observability
- **test:features:revocation** - Certificate revocation
- **test:features:enveloped** - Enveloped data support
- **test:features:combined** - HSM + CSR generation combined

### Lint Stage

- **clippy:default** - Rust linting with default features
- **clippy:all-features** - Rust linting with all features enabled
- **rustfmt** - Code formatting verification
- **docs** - Documentation build verification

### Security Stage

#### Vulnerability Scanning
- **security:cargo-audit** - RustSec advisory database scan
  - Generates `audit-report.json` artifact
  - Expires after 30 days

#### Policy Enforcement
- **security:cargo-deny:advisories** - Security vulnerability policy
- **security:cargo-deny:licenses** - License compliance policy
- **security:cargo-deny:bans** - Banned dependency policy
- **security:cargo-deny:sources** - Source registry policy

#### Security Linting
- **security:clippy** - Security-focused Clippy lints
  - Warns on `unwrap_used`, `expect_used`, `panic`
  - Warns on `todo`, `unimplemented`, `unreachable`

#### Feature Security Testing
- **security:test-features** - Test security-sensitive features
  - Validation feature tests
  - FIPS configuration compile check
  - DoD PKI configuration compile check

#### Scheduled Security Audits
- **security:scheduled** - Daily automated security scan
  - Runs at 00:00 UTC (configure via GitLab Schedules)
  - Generates `audit-report-scheduled.json` artifact
  - Expires after 90 days

### Coverage Stage

- **coverage:tarpaulin** - Code coverage with cargo-tarpaulin
  - Generates Cobertura XML report
  - Integrates with GitLab merge request coverage display
  - Artifacts expire after 30 days

### Docs Stage

- **pages** - GitLab Pages documentation deployment
  - Builds Zensical documentation site
  - Deploys to `https://<namespace>.gitlab.io/<project>/`
  - Only runs on `main` branch when docs change

## Configuration

### Caching

The pipeline uses GitLab's caching mechanism to speed up builds:

```yaml
cache:
  key:
    files:
      - Cargo.lock
  paths:
    - .cargo/registry
    - .cargo/git
    - target/
```

Cache is keyed by `Cargo.lock` to ensure consistency across dependency updates.

### Variables

Global environment variables:

- `CARGO_TERM_COLOR: always` - Colored cargo output
- `RUST_BACKTRACE: "1"` - Enable backtraces for debugging
- `CARGO_HOME: "${CI_PROJECT_DIR}/.cargo"` - Cache Cargo home

### Triggers

Jobs run on:
- **Push to main branch** - Full pipeline
- **Merge requests** - Full pipeline (except pages)
- **Scheduled pipelines** - Security audits only
- **Manual trigger** - Via GitLab UI

### Platform-Specific Runners

For cross-platform testing, configure GitLab runners with appropriate tags:

- Linux: Uses standard Docker runners (`rust:latest` image)
- macOS: Requires runner tagged `macos`
- Windows: Requires runner tagged `windows`

If platform-specific runners are not available, jobs are marked `allow_failure: true`.

## Setting Up Scheduled Security Audits

To enable daily security audits:

1. Go to **CI/CD > Schedules** in your GitLab project
2. Click **New schedule**
3. Configure:
   - Description: "Daily Security Audit"
   - Interval Pattern: `0 0 * * *` (daily at midnight UTC)
   - Target Branch: `main`
   - Variables: `SCHEDULED_JOB = security`
4. Save schedule

The `security:scheduled` job will run automatically at the specified time.

## Artifacts

### Security Audit Reports

**On Push/MR:**
- Path: `audit-report.json`
- Retention: 30 days
- Download from: Pipeline > Jobs > security:cargo-audit > Browse

**Scheduled:**
- Path: `audit-report-scheduled.json`
- Retention: 90 days
- Download from: Pipeline > Jobs > security:scheduled > Browse

### Coverage Reports

- Path: `coverage/cobertura.xml`
- Retention: 30 days
- Displayed in merge request diff view
- Download from: Pipeline > Jobs > coverage:tarpaulin > Browse

### Documentation

- Path: `public/` (deployed to GitLab Pages)
- Access at: `https://<namespace>.gitlab.io/<project>/`

## Differences from GitHub Actions

### Syntax Changes

| GitHub Actions | GitLab CI/CD | Notes |
|---------------|--------------|-------|
| `jobs:` | `stages:` + job definitions | GitLab uses explicit stages |
| `runs-on: ubuntu-latest` | `image: rust:latest` | GitLab uses Docker by default |
| `uses: actions/checkout@v4` | Automatic checkout | GitLab checks out by default |
| `uses: actions/cache@v5` | `cache:` | Built-in caching mechanism |
| `if: github.event_name == 'pull_request'` | `only: merge_requests` | Different trigger syntax |
| `strategy.matrix` | Multiple job definitions | No native matrix, use multiple jobs |

### Feature Parity

✅ **Migrated:**
- Cross-platform testing (Linux, macOS, Windows)
- Multiple Rust versions (stable, beta, MSRV)
- Feature-specific testing
- Linting (Clippy, rustfmt)
- Security scanning (cargo-audit, cargo-deny)
- Code coverage (tarpaulin)
- Documentation deployment (Pages)
- Scheduled jobs

❌ **Not Available:**
- GitHub-specific actions (dependency-review-action)
  - Replaced with cargo-deny policy checks
- Codecov integration
  - Replaced with GitLab's native coverage reports

## Viewing Results

### Pipeline Status

View pipeline status on:
- Project homepage (pipeline badge)
- **CI/CD > Pipelines**
- Merge request page

### Job Logs

1. Navigate to **CI/CD > Pipelines**
2. Click pipeline ID
3. Click job name to view logs

### Coverage Reports

Coverage percentage displays in:
- Merge request overview
- Project badges (configure in Settings > CI/CD > General pipelines)

### Security Reports

Download security audit artifacts:
1. **CI/CD > Pipelines**
2. Select completed pipeline
3. Click **security:cargo-audit** job
4. Click **Browse** button (right side)
5. Download `audit-report.json`

## Troubleshooting

### Job Timeout

If jobs timeout (especially coverage):

```yaml
coverage:tarpaulin:
  timeout: 2h  # Add timeout (default: 1h)
```

### Cache Issues

If cache is stale or causing issues, clear it:
1. **CI/CD > Pipelines**
2. Click **Clear runner caches** button

Or disable cache for specific job:

```yaml
test:stable:linux:
  cache: []  # Disable cache
```

### Platform Runners Not Available

If macOS/Windows runners are not configured:

```yaml
test:stable:macos:
  allow_failure: true  # Mark as optional
```

### Cargo Install Slow

Pre-install tools in custom Docker image:

```dockerfile
FROM rust:latest
RUN cargo install cargo-audit cargo-tarpaulin --locked
```

Then reference in `.gitlab-ci.yml`:

```yaml
security:cargo-audit:
  image: registry.gitlab.com/<namespace>/<project>/rust-tools:latest
```

## Integration with GitLab Features

### Merge Request Checks

All test and security jobs must pass for merge requests (configure in **Settings > Merge requests**).

### Protected Branches

Configure branch protection rules to require pipeline success:
1. **Settings > Repository > Protected branches**
2. Select branch (e.g., `main`)
3. Check "Require pipeline to succeed"

### Pipeline Badges

Add pipeline status badge to README:

```markdown
[![Pipeline Status](https://gitlab.com/<namespace>/<project>/badges/main/pipeline.svg)](https://gitlab.com/<namespace>/<project>/-/pipelines)
[![Coverage](https://gitlab.com/<namespace>/<project>/badges/main/coverage.svg)](https://gitlab.com/<namespace>/<project>/-/pipelines)
```

## Security Considerations

### Secret Variables

Store sensitive data in **Settings > CI/CD > Variables**:
- Mark as "Protected" (only available on protected branches)
- Mark as "Masked" (hidden in logs)

Example:
- `CARGO_REGISTRY_TOKEN` - For publishing to crates.io
- `SSH_PRIVATE_KEY` - For deployment

### Container Registry

Use GitLab Container Registry for custom images:

```yaml
image: registry.gitlab.com/<namespace>/<project>/rust-builder:latest
```

### SAST (Static Application Security Testing)

Enable GitLab's built-in SAST:

```yaml
include:
  - template: Security/SAST.gitlab-ci.yml
```

## Performance Optimization

### Parallel Jobs

Jobs in the same stage run in parallel. Optimize stage organization:

- Move fast jobs (rustfmt, clippy) to early stage
- Group slow jobs (tarpaulin) in later stage

### Dependency Caching

Optimize cache paths for faster restoration:

```yaml
cache:
  paths:
    - .cargo/registry/index/
    - .cargo/registry/cache/
    - .cargo/git/db/
    - target/debug/deps/
    - target/debug/build/
```

### Artifact Size

Reduce artifact size to speed up uploads:

```yaml
artifacts:
  paths:
    - audit-report.json
  exclude:
    - target/**/*
```

## Migration Checklist

When migrating from GitHub Actions:

- [x] Create `.gitlab-ci.yml` configuration
- [ ] Configure GitLab runners (Linux, macOS, Windows)
- [ ] Set up scheduled pipelines for daily security audits
- [ ] Configure protected branches with pipeline requirements
- [ ] Add pipeline badges to README
- [ ] Update documentation references (CI links)
- [ ] Test pipeline on merge request
- [ ] Enable GitLab Pages (Settings > Pages)
- [ ] Configure merge request approval rules
- [ ] Archive or remove `.github/workflows/` files

## Additional Resources

- [GitLab CI/CD Documentation](https://docs.gitlab.com/ee/ci/)
- [GitLab CI/CD YAML Syntax Reference](https://docs.gitlab.com/ee/ci/yaml/)
- [GitLab Pages Documentation](https://docs.gitlab.com/ee/user/project/pages/)
- [GitLab Container Registry](https://docs.gitlab.com/ee/user/packages/container_registry/)

## Support

For questions about the GitLab CI/CD configuration:
- Open an issue in the project
- Reference this document
- Check GitLab CI/CD logs for errors

---

**Last Updated**: 2026-01-12
**Migrated From**: GitHub Actions workflows (ci.yml, docs.yml, security-audit.yml)
