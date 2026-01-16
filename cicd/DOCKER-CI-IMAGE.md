# Custom Docker Image for CI/CD

This document explains how to build, push, and use the custom Docker image for faster CI/CD builds.

## Overview

The custom Docker image ([Dockerfile.ci](Dockerfile.ci)) pre-installs expensive-to-build tools:
- **cargo-audit** (0.20.1) - Security vulnerability scanner
- **cargo-deny** (0.14.24) - Dependency policy enforcement
- **cargo-tarpaulin** (0.31.2) - Code coverage tool
- **rustfmt** - Code formatter
- **clippy** - Rust linter

## Performance Benefit

**Without custom image:**
- Installing tools on every job: ~3-4 minutes
- Total job time: ~5-7 minutes

**With custom image:**
- Tools pre-installed: 0 seconds
- Total job time: ~2-3 minutes

**Savings: ~3 minutes per job × 30 jobs = ~90 minutes per pipeline**

## Building the Image

### Prerequisites

1. Docker installed locally
2. Access to GitLab Container Registry
3. GitLab personal access token with `write_registry` scope

### Step 1: Build Locally

```bash
# Build the image
docker build -f Dockerfile.ci -t rust-ci:latest .

# Test the image
docker run --rm rust-ci:latest cargo audit --version
docker run --rm rust-ci:latest cargo deny --version
docker run --rm rust-ci:latest cargo tarpaulin --version
```

### Step 2: Tag for GitLab Registry

```bash
# Replace <namespace> and <project> with your GitLab namespace and project name
export GITLAB_NAMESPACE="yourusername"
export GITLAB_PROJECT="usg-est-client"

# Tag the image
docker tag rust-ci:latest registry.gitlab.com/${GITLAB_NAMESPACE}/${GITLAB_PROJECT}/rust-ci:latest
```

### Step 3: Login to GitLab Registry

```bash
# Login with personal access token
docker login registry.gitlab.com

# Or use GitLab CI token (in CI/CD pipeline)
echo $CI_REGISTRY_PASSWORD | docker login -u $CI_REGISTRY_USER --password-stdin $CI_REGISTRY
```

### Step 4: Push to Registry

```bash
# Push the image
docker push registry.gitlab.com/${GITLAB_NAMESPACE}/${GITLAB_PROJECT}/rust-ci:latest
```

## Using the Image in CI/CD

### Option A: Update All Security Jobs

Edit [.gitlab-ci.yml](.gitlab-ci.yml) to use the custom image:

```yaml
security:cargo-audit:
  stage: security
  image: registry.gitlab.com/<namespace>/<project>/rust-ci:latest  # Use custom image
  script:
    - cargo audit --json | tee audit-report.json  # No install needed!
  # ... rest of configuration
```

### Option B: Create Shared Template

Add this to `.gitlab-ci.yml`:

```yaml
# Template for jobs using custom CI image
.rust_ci_image: &rust_ci_image
  image: registry.gitlab.com/<namespace>/<project>/rust-ci:latest

# Use in jobs
security:cargo-audit:
  <<: *rust_ci_image
  stage: security
  script:
    - cargo audit --json | tee audit-report.json
```

### Option C: Global Default

Set as default image for all jobs:

```yaml
# At the top of .gitlab-ci.yml
default:
  image: registry.gitlab.com/<namespace>/<project>/rust-ci:latest
```

## Automatic Builds with CI/CD

### Create Image Build Pipeline

Add to `.gitlab-ci.yml`:

```yaml
stages:
  - build-image
  - test
  - lint
  - security
  - docs
  - coverage

# Build and push custom CI image
build:ci-image:
  stage: build-image
  image: docker:24-cli
  services:
    - docker:24-dind
  before_script:
    - echo $CI_REGISTRY_PASSWORD | docker login -u $CI_REGISTRY_USER --password-stdin $CI_REGISTRY
  script:
    - docker build -f Dockerfile.ci -t $CI_REGISTRY_IMAGE/rust-ci:latest .
    - docker push $CI_REGISTRY_IMAGE/rust-ci:latest
  only:
    - main
  rules:
    # Only rebuild image when Dockerfile.ci changes
    - changes:
        - Dockerfile.ci
      when: always
    # Or manually trigger
    - when: manual
      allow_failure: true
```

## Updating the Image

### When to Update

Rebuild the image when:
- cargo-audit, cargo-deny, or cargo-tarpaulin have new versions
- Security vulnerabilities in base image
- Need to add new pre-installed tools
- Rust version update

### Version Tags

Use semantic versioning for image tags:

```bash
# Build with version tag
docker build -f Dockerfile.ci -t registry.gitlab.com/${GITLAB_NAMESPACE}/${GITLAB_PROJECT}/rust-ci:1.0.0 .
docker build -f Dockerfile.ci -t registry.gitlab.com/${GITLAB_NAMESPACE}/${GITLAB_PROJECT}/rust-ci:latest .

# Push both tags
docker push registry.gitlab.com/${GITLAB_NAMESPACE}/${GITLAB_PROJECT}/rust-ci:1.0.0
docker push registry.gitlab.com/${GITLAB_NAMESPACE}/${GITLAB_PROJECT}/rust-ci:latest
```

## Image Verification

### Check Installed Versions

```bash
# Run shell in container
docker run -it --rm registry.gitlab.com/<namespace>/<project>/rust-ci:latest bash

# Inside container, verify tools
cargo --version
rustc --version
cargo audit --version
cargo deny --version
cargo tarpaulin --version
rustfmt --version
clippy-driver --version
```

### Security Scan

Use GitLab's Container Scanning:

```yaml
# Add to .gitlab-ci.yml
include:
  - template: Security/Container-Scanning.gitlab-ci.yml

container_scanning:
  variables:
    CI_APPLICATION_REPOSITORY: $CI_REGISTRY_IMAGE/rust-ci
    CI_APPLICATION_TAG: latest
```

## Troubleshooting

### Issue: Image not found

**Error:** `Error response from daemon: manifest for registry.gitlab.com/... not found`

**Solution:**
```bash
# Verify image exists in registry
# GitLab UI: Packages & Registries > Container Registry

# Check image name matches exactly
docker pull registry.gitlab.com/<namespace>/<project>/rust-ci:latest
```

### Issue: Permission denied

**Error:** `denied: access forbidden`

**Solution:**
```bash
# Ensure logged in
docker login registry.gitlab.com

# Verify token has write_registry scope
# GitLab UI: User Settings > Access Tokens
```

### Issue: Image too large

**Current size:** ~1.5 GB

**Optimization:**
```dockerfile
# Use rust:slim instead of rust:latest
FROM rust:1.92.0-slim

# Clear cargo cache after install
RUN cargo install ... && rm -rf /usr/local/cargo/registry

# Use multi-stage build (advanced)
FROM rust:1.92.0-slim as builder
# ... install tools
FROM rust:1.92.0-slim
COPY --from=builder /usr/local/cargo/bin/* /usr/local/cargo/bin/
```

### Issue: Outdated tools

**Update versions in Dockerfile.ci:**
```dockerfile
RUN cargo install --locked \
    cargo-audit@0.21.0 \      # Update version
    cargo-tarpaulin@0.32.0 \  # Update version
    && rm -rf /usr/local/cargo/registry
```

Then rebuild and push.

## Best Practices

### 1. Version Pinning

Always pin tool versions for reproducibility:
```dockerfile
cargo install --locked cargo-audit@0.20.1
```

### 2. Layer Optimization

Order Dockerfile commands from least to most frequently changed:
```dockerfile
# Rarely changes - base dependencies
RUN apt-get update && apt-get install ...

# Occasionally changes - tool versions
RUN cargo install ...

# Frequently changes - source code
COPY . /workspace
```

### 3. Cache Clearing

Clear caches to reduce image size:
```dockerfile
RUN cargo install ... \
    && rm -rf /usr/local/cargo/registry \
    && rm -rf /var/lib/apt/lists/*
```

### 4. Image Tags

Use multiple tags for flexibility:
- `latest` - Always current version
- `1.0.0` - Specific version (pinned in CI for stability)
- `rust-1.92` - Rust version indicator

### 5. Regular Updates

Schedule monthly image updates:
- Check for new tool versions
- Rebuild with latest security patches
- Update CI/CD to use new image

## Alternative: GitLab Auto DevOps

For simpler setup, use GitLab's Auto Build:

```yaml
# .gitlab-ci.yml
include:
  - template: Jobs/Build.gitlab-ci.yml

variables:
  AUTO_DEVOPS_BUILD_IMAGE_EXTRA_ARGS: "--build-arg INSTALL_TOOLS=true"
```

Then add to Dockerfile:
```dockerfile
ARG INSTALL_TOOLS=false
RUN if [ "$INSTALL_TOOLS" = "true" ]; then \
      cargo install cargo-audit cargo-deny cargo-tarpaulin; \
    fi
```

## Cost Considerations

**Storage:**
- GitLab.com free tier: 5 GB container registry storage
- Image size: ~1.5 GB
- Cleanup old images regularly: Settings > Packages & Registries > Cleanup policies

**CI/CD Minutes:**
- Building image: ~5-10 minutes
- But saves ~3 minutes per job
- Break-even: 2-3 pipeline runs

**Recommendation:** Build weekly or when Dockerfile.ci changes

## Resources

- [GitLab Container Registry Docs](https://docs.gitlab.com/ee/user/packages/container_registry/)
- [Docker Best Practices](https://docs.docker.com/develop/dev-best-practices/)
- [cargo-audit](https://github.com/RustSec/rustsec/tree/main/cargo-audit)
- [cargo-deny](https://github.com/EmbarkStudios/cargo-deny)
- [cargo-tarpaulin](https://github.com/xd009642/tarpaulin)

## Support

For issues with the Docker image:
- Open an issue referencing this document
- Check GitLab Container Registry logs
- Verify Dockerfile.ci syntax

---

**Last Updated**: 2026-01-12
**Image Version**: 1.0.0 (Rust 1.92.0, cargo-audit 0.20.1, cargo-deny 0.14.24, cargo-tarpaulin 0.31.2)
