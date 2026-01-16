# Building and Pushing the CI Docker Image

This guide shows how to build and push the custom CI Docker image to the GitLab Container Registry.

## Prerequisites

1. **Docker installed and running**
   ```bash
   docker --version  # Should be 20.10+
   ```

2. **GitLab account with registry access**
   - You need Developer or higher role on the project
   - Container Registry must be enabled (it is by default on GitLab.com)

3. **Project access**
   - Clone the repository
   - Navigate to project root: `cd usg-est-client`

## Method 1: Build and Push Locally (Recommended for Initial Setup)

### Step 1: Log in to GitLab Container Registry

```bash
# Option A: Using personal access token (recommended)
docker login registry.gitlab.com
# Username: your-gitlab-username
# Password: your-personal-access-token

# Option B: Using deploy token (for automation)
docker login registry.gitlab.com -u <deploy-token-username> -p <deploy-token>
```

**Creating a Personal Access Token:**
1. Go to GitLab → User Settings → Access Tokens
2. Create token with scopes: `read_registry`, `write_registry`
3. Save the token securely (you won't see it again)

### Step 2: Build the CI Image

```bash
# Build the image (takes ~5-10 minutes first time)
docker build -f Dockerfile.ci \
  -t registry.gitlab.com/192d-wing/usg-est-client/ci:latest \
  .

# Check the image was created
docker images | grep ci
```

**What happens during build:**
- Installs Rust 1.92 toolchain
- Installs system dependencies (pkg-config, libssl-dev, musl-tools)
- Installs cargo tools (cargo-audit, cargo-tarpaulin, cargo-deny)
- Adds x86_64-unknown-linux-gnu and x86_64-unknown-linux-musl targets

### Step 3: Push to GitLab Container Registry

```bash
# Push the image to registry
docker push registry.gitlab.com/192d-wing/usg-est-client/ci:latest

# Verify it's in the registry
# Go to GitLab UI: Project → Packages & Registries → Container Registry
```

**Expected output:**
```
The push refers to repository [registry.gitlab.com/192d-wing/usg-est-client/ci]
abc123def456: Pushed
...
latest: digest: sha256:123456... size: 1234
```

### Step 4: Test the Image Locally (Optional)

```bash
# Pull and run the image to verify
docker run --rm registry.gitlab.com/192d-wing/usg-est-client/ci:latest cargo --version
docker run --rm registry.gitlab.com/192d-wing/usg-est-client/ci:latest rustc --version
docker run --rm registry.gitlab.com/192d-wing/usg-est-client/ci:latest cargo audit --version
docker run --rm registry.gitlab.com/192d-wing/usg-est-client/ci:latest cargo tarpaulin --version
docker run --rm registry.gitlab.com/192d-wing/usg-est-client/ci:latest cargo deny --version
```

## Method 2: Build Using GitLab CI (Recommended for Updates)

### Option A: Trigger via Commit

If you modify `Dockerfile.ci`, the image is automatically rebuilt:

```bash
# Edit Dockerfile.ci
vim Dockerfile.ci

# Commit and push
git add Dockerfile.ci
git commit -m "update: CI image with new dependency"
git push origin main

# Check CI pipeline
# Go to GitLab UI: Project → CI/CD → Pipelines
# Look for "build-ci-image" job
```

### Option B: Manual Trigger with CI Variable

Build without changing Dockerfile.ci:

**Via GitLab UI:**
1. Go to CI/CD → Pipelines
2. Click "Run pipeline"
3. Select branch: `main`
4. Add variable:
   - Key: `CI_BUILD_IMAGE`
   - Value: `true`
5. Click "Run pipeline"

**Via GitLab CLI:**
```bash
# Using glab CLI tool
glab ci run --branch main --variable CI_BUILD_IMAGE=true

# Or using curl
curl --request POST \
  --header "PRIVATE-TOKEN: <your-token>" \
  "https://gitlab.com/api/v4/projects/192d-wing%2Fusg-est-client/pipeline?ref=main&variables[CI_BUILD_IMAGE]=true"
```

### Option C: Scheduled Weekly Builds

Set up automatic weekly rebuilds to pick up Rust updates:

1. Go to CI/CD → Schedules
2. Click "New schedule"
3. Configure:
   - Description: "Weekly CI image rebuild"
   - Interval pattern: `0 2 * * 0` (Every Sunday at 2 AM)
   - Target branch: `main`
   - Variables:
     - Key: `SCHEDULED_JOB`
     - Value: `build-ci-image`
4. Save schedule

## Verifying the Build

### Check Registry

**Via GitLab UI:**
1. Go to Project → Packages & Registries → Container Registry
2. You should see: `192d-wing/usg-est-client/ci`
3. Click it to see tags and details

**Via Docker CLI:**
```bash
# Pull the image
docker pull registry.gitlab.com/192d-wing/usg-est-client/ci:latest

# Inspect the image
docker inspect registry.gitlab.com/192d-wing/usg-est-client/ci:latest

# Check size
docker images | grep "192d-wing/usg-est-client/ci"
```

### Test CI Pipeline Uses New Image

After pushing the image, trigger any CI pipeline:

```bash
git commit --allow-empty -m "test: verify CI image works"
git push origin main
```

Check the job logs - you should see:
- Fast startup (no apt-get install or cargo install)
- Jobs using `${CI_IMAGE}` complete faster

## Troubleshooting

### Error: "authentication required"

```bash
# Log in again with correct credentials
docker logout registry.gitlab.com
docker login registry.gitlab.com

# Verify you have registry access
# GitLab UI: Project → Settings → General → Visibility
# Ensure Container Registry is enabled
```

### Error: "denied: access forbidden"

**Fix:** Check your GitLab role and permissions
1. Go to Project → Members
2. Ensure you have Developer role or higher
3. Or ask project maintainer to add you

### Error: "image not found" in CI

**Possible causes:**
1. Image not pushed yet → Push it first
2. Wrong image name → Check `.gitlab-ci.yml` matches registry path
3. Registry disabled → Enable in project settings

**Quick fix:** Pipeline falls back to `rust:latest` automatically

### Build Takes Too Long

**Optimize build time:**

```bash
# Use buildkit for parallel builds
DOCKER_BUILDKIT=1 docker build -f Dockerfile.ci \
  -t registry.gitlab.com/192d-wing/usg-est-client/ci:latest \
  .

# Or use docker buildx
docker buildx build -f Dockerfile.ci \
  -t registry.gitlab.com/192d-wing/usg-est-client/ci:latest \
  --push \
  .
```

### Image Too Large

Check image size:
```bash
docker images registry.gitlab.com/192d-wing/usg-est-client/ci:latest
# Should be ~1.5-2GB
```

If larger, optimize `Dockerfile.ci`:
```dockerfile
# Clean up cargo registry after installs
RUN cargo install tool --locked && \
    rm -rf /usr/local/cargo/registry
```

## Advanced: Multi-Architecture Builds

Build for multiple architectures (ARM64 + AMD64):

```bash
# Create and use buildx builder
docker buildx create --name multiarch --use
docker buildx inspect --bootstrap

# Build and push for multiple platforms
docker buildx build -f Dockerfile.ci \
  --platform linux/amd64,linux/arm64 \
  -t registry.gitlab.com/192d-wing/usg-est-client/ci:latest \
  --push \
  .
```

## Security Best Practices

1. **Use specific versions in Dockerfile.ci**
   ```dockerfile
   FROM rust:1.92.0-bookworm  # Pin exact version
   RUN cargo install cargo-audit --version 0.20.1 --locked
   ```

2. **Scan images for vulnerabilities**
   ```bash
   # Using Docker Scout
   docker scout quickview registry.gitlab.com/192d-wing/usg-est-client/ci:latest

   # Using Trivy
   trivy image registry.gitlab.com/192d-wing/usg-est-client/ci:latest
   ```

3. **Sign images (optional)**
   ```bash
   # Using Docker Content Trust
   export DOCKER_CONTENT_TRUST=1
   docker push registry.gitlab.com/192d-wing/usg-est-client/ci:latest
   ```

## Quick Reference

### One-liner: Build and Push

```bash
docker build -f Dockerfile.ci -t registry.gitlab.com/192d-wing/usg-est-client/ci:latest . && \
docker push registry.gitlab.com/192d-wing/usg-est-client/ci:latest
```

### Check What's Running in CI

```bash
# View CI job using the image
glab ci view --branch main

# Or check GitLab UI
# Project → CI/CD → Pipelines → Latest pipeline → View job logs
```

### Update Image Tag

To use a versioned tag instead of `latest`:

```bash
# Build with version tag
docker build -f Dockerfile.ci \
  -t registry.gitlab.com/192d-wing/usg-est-client/ci:v1.0.0 \
  -t registry.gitlab.com/192d-wing/usg-est-client/ci:latest \
  .

# Push both tags
docker push registry.gitlab.com/192d-wing/usg-est-client/ci:v1.0.0
docker push registry.gitlab.com/192d-wing/usg-est-client/ci:latest
```

## Next Steps

After successfully pushing the image:

1. ✅ Verify image appears in GitLab Container Registry
2. ✅ Run a test pipeline to confirm it's used
3. ✅ Set up weekly scheduled rebuild (optional)
4. ✅ Document team access instructions
5. ✅ Monitor pipeline performance improvements

## Getting Help

- **Registry issues**: Check [GitLab Container Registry docs](https://docs.gitlab.com/ee/user/packages/container_registry/)
- **Docker build issues**: Check [Docker documentation](https://docs.docker.com/engine/reference/commandline/build/)
- **CI/CD questions**: See [.gitlab-ci.yml](.gitlab-ci.yml) configuration
- **Performance questions**: See [docs/CI-DOCKER-IMAGE.md](CI-DOCKER-IMAGE.md)
