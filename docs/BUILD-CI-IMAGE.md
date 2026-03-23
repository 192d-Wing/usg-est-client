# Building and Pushing the CI Docker Image

This guide shows how to build and push the custom CI Docker image to the GitHub Container Registry (GHCR).

## Prerequisites

1. **Docker installed and running**
   ```bash
   docker --version  # Should be 20.10+
   ```

2. **GitHub account with registry access**
   - You need write access to the repository
   - GitHub Packages must be enabled (it is by default on GitHub.com)

3. **Project access**
   - Clone the repository
   - Navigate to project root: `cd usg-est-client`

## Method 1: Build and Push Locally (Recommended for Initial Setup)

### Step 1: Log in to GitHub Container Registry (GHCR)

```bash
# Option A: Using personal access token (recommended)
docker login ghcr.io
# Username: your-github-username
# Password: your-personal-access-token

# Option B: Using GITHUB_TOKEN (for automation)
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin
```

**Creating a Personal Access Token:**
1. Go to GitHub → Settings → Developer settings → Personal access tokens
2. Create token (classic) with scopes: `read:packages`, `write:packages`
3. Save the token securely (you won't see it again)

### Step 2: Build the CI Image

```bash
# Build the image (takes ~5-10 minutes first time)
docker build -f Dockerfile.ci \
  -t ghcr.io/192d-wing/usg-est-client/ci:latest \
  .

# Check the image was created
docker images | grep ci
```

**What happens during build:**
- Installs Rust 1.92 toolchain
- Installs system dependencies (pkg-config, libssl-dev, musl-tools)
- Installs cargo tools (cargo-audit, cargo-tarpaulin, cargo-deny)
- Adds x86_64-unknown-linux-gnu and x86_64-unknown-linux-musl targets

### Step 3: Push to GitHub Container Registry (GHCR)

```bash
# Push the image to registry
docker push ghcr.io/192d-wing/usg-est-client/ci:latest

# Verify it's in the registry
# Go to GitHub UI: Repository → Packages
```

**Expected output:**
```
The push refers to repository [ghcr.io/192d-wing/usg-est-client/ci]
abc123def456: Pushed
...
latest: digest: sha256:123456... size: 1234
```

### Step 4: Test the Image Locally (Optional)

```bash
# Pull and run the image to verify
docker run --rm ghcr.io/192d-wing/usg-est-client/ci:latest cargo --version
docker run --rm ghcr.io/192d-wing/usg-est-client/ci:latest rustc --version
docker run --rm ghcr.io/192d-wing/usg-est-client/ci:latest cargo audit --version
docker run --rm ghcr.io/192d-wing/usg-est-client/ci:latest cargo tarpaulin --version
docker run --rm ghcr.io/192d-wing/usg-est-client/ci:latest cargo deny --version
```

## Method 2: Build Using GitHub Actions (Recommended for Updates)

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
# Go to GitHub UI: Repository → Actions tab
# Look for "build-ci-image" workflow run
```

### Option B: Manual Trigger with Workflow Dispatch

Build without changing Dockerfile.ci:

**Via GitHub UI:**
1. Go to Actions tab
2. Select the CI image build workflow
3. Click "Run workflow"
4. Select branch: `main`
5. Click "Run workflow"

**Via GitHub CLI:**
```bash
# Using gh CLI tool
gh workflow run ci-image.yml --ref main

# Or using curl
curl -X POST \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github.v3+json" \
  "https://api.github.com/repos/192d-Wing/usg-est-client/actions/workflows/ci-image.yml/dispatches" \
  -d '{"ref":"main"}'
```

### Option C: Scheduled Weekly Builds

Set up automatic weekly rebuilds to pick up Rust updates by adding a schedule trigger to `.github/workflows/ci-image.yml`:

```yaml
on:
  schedule:
    - cron: '0 2 * * 0'  # Every Sunday at 2 AM
```

## Verifying the Build

### Check Registry

**Via GitHub UI:**
1. Go to Repository → Packages
2. You should see: `192d-wing/usg-est-client/ci`
3. Click it to see tags and details

**Via Docker CLI:**
```bash
# Pull the image
docker pull ghcr.io/192d-wing/usg-est-client/ci:latest

# Inspect the image
docker inspect ghcr.io/192d-wing/usg-est-client/ci:latest

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
docker logout ghcr.io
docker login ghcr.io

# Verify you have registry access
# GitHub UI: Repository → Settings → Packages
# Ensure GitHub Packages is enabled
```

### Error: "denied: access forbidden"

**Fix:** Check your GitHub role and permissions
1. Go to Repository → Settings → Collaborators
2. Ensure you have write access or higher
3. Or ask a repository admin to add you

### Error: "image not found" in CI

**Possible causes:**
1. Image not pushed yet → Push it first
2. Wrong image name → Check `.github/workflows/ci.yml` matches registry path
3. Packages disabled → Enable in repository settings

**Quick fix:** Pipeline falls back to `rust:latest` automatically

### Build Takes Too Long

**Optimize build time:**

```bash
# Use buildkit for parallel builds
DOCKER_BUILDKIT=1 docker build -f Dockerfile.ci \
  -t ghcr.io/192d-wing/usg-est-client/ci:latest \
  .

# Or use docker buildx
docker buildx build -f Dockerfile.ci \
  -t ghcr.io/192d-wing/usg-est-client/ci:latest \
  --push \
  .
```

### Image Too Large

Check image size:
```bash
docker images ghcr.io/192d-wing/usg-est-client/ci:latest
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
  -t ghcr.io/192d-wing/usg-est-client/ci:latest \
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
   docker scout quickview ghcr.io/192d-wing/usg-est-client/ci:latest

   # Using Trivy
   trivy image ghcr.io/192d-wing/usg-est-client/ci:latest
   ```

3. **Sign images (optional)**
   ```bash
   # Using Docker Content Trust
   export DOCKER_CONTENT_TRUST=1
   docker push ghcr.io/192d-wing/usg-est-client/ci:latest
   ```

## Quick Reference

### One-liner: Build and Push

```bash
docker build -f Dockerfile.ci -t ghcr.io/192d-wing/usg-est-client/ci:latest . && \
docker push ghcr.io/192d-wing/usg-est-client/ci:latest
```

### Check What's Running in CI

```bash
# View CI job using the image
gh run list --branch main

# Or check GitHub UI
# Repository → Actions → Latest workflow run → View job logs
```

### Update Image Tag

To use a versioned tag instead of `latest`:

```bash
# Build with version tag
docker build -f Dockerfile.ci \
  -t ghcr.io/192d-wing/usg-est-client/ci:v1.0.0 \
  -t ghcr.io/192d-wing/usg-est-client/ci:latest \
  .

# Push both tags
docker push ghcr.io/192d-wing/usg-est-client/ci:v1.0.0
docker push ghcr.io/192d-wing/usg-est-client/ci:latest
```

## Next Steps

After successfully pushing the image:

1. ✅ Verify image appears in GitHub Container Registry (GHCR)
2. ✅ Run a test pipeline to confirm it's used
3. ✅ Set up weekly scheduled rebuild (optional)
4. ✅ Document team access instructions
5. ✅ Monitor pipeline performance improvements

## Getting Help

- **Registry issues**: Check [GitHub Container Registry docs](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)
- **Docker build issues**: Check [Docker documentation](https://docs.docker.com/engine/reference/commandline/build/)
- **CI/CD questions**: See [.github/workflows/ci.yml](../.github/workflows/ci.yml) configuration
- **Performance questions**: See [docs/CI-DOCKER-IMAGE.md](CI-DOCKER-IMAGE.md)
