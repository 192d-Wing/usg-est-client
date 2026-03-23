# Quick Start: Building the CI Image

This project uses a custom Docker image for faster CI/CD pipelines. Here's how to build and push it.

## TL;DR

```bash
# 1. Log in to GitHub Container Registry (GHCR)
docker login ghcr.io

# 2. Run the build script
./scripts/build-ci-image.sh

# That's it! ✅
```

## What You Need

1. Docker installed and running
2. GitHub account with access to this project
3. Personal access token (classic) with `read:packages` + `write:packages` scopes

## Creating a Personal Access Token

1. Go to GitHub → **Settings** → **Developer settings** → **Personal access tokens**
2. Click **Generate new token (classic)**
3. Name: `Docker Registry Access`
4. Scopes: Check `read:packages` and `write:packages`
5. Click **Generate token**
6. **Save the token** (you won't see it again!)

## Build Methods

### Method 1: Automated Script (Recommended)

```bash
# Build and push to registry
./scripts/build-ci-image.sh

# Test build locally (don't push)
./scripts/build-ci-image.sh --test

# Build without cache
./scripts/build-ci-image.sh --no-cache

# Build with vulnerability scan
./scripts/build-ci-image.sh --scan

# Show all options
./scripts/build-ci-image.sh --help
```

### Method 2: Manual Docker Commands

```bash
# Log in
docker login ghcr.io

# Build
docker build -f Dockerfile.ci \
  -t ghcr.io/192d-wing/usg-est-client/ci:latest \
  .

# Push
docker push ghcr.io/192d-wing/usg-est-client/ci:latest
```

### Method 3: Use GitHub Actions

**Trigger via UI:**
1. Go to **Actions** tab
2. Select the CI image build workflow
3. Click **Run workflow**
4. Run

**Or push a change to Dockerfile.ci:**
```bash
vim Dockerfile.ci  # Make a change
git add Dockerfile.ci
git commit -m "update: CI image"
git push
# Image rebuilds automatically
```

## Verify It Worked

1. **Check GitHub Container Registry:**
   - Go to: **Packages** on the repository page
   - Look for: `192d-wing/usg-est-client/ci`

2. **Run a test pipeline:**
   ```bash
   git commit --allow-empty -m "test: CI image"
   git push
   ```

3. **Check job logs** - should show fast startup times

## Expected Performance

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| Test job duration | ~300s | ~125s | **58% faster** |
| Setup time | ~180s | ~5s | **97% faster** |
| Pipeline cost | $50/mo | $20/mo | **60% savings** |

## Troubleshooting

### "authentication required"
```bash
docker logout ghcr.io
docker login ghcr.io
# Enter username and personal access token
```

### "access forbidden"
- Check you have **Developer** role or higher
- Verify you have package access on the repository

### "image not found" in CI
- Wait ~1 minute for registry to propagate
- CI will fall back to `rust:latest` automatically

## More Information

- **Full guide**: [docs/BUILD-CI-IMAGE.md](docs/BUILD-CI-IMAGE.md)
- **Performance details**: [docs/CI-DOCKER-IMAGE.md](docs/CI-DOCKER-IMAGE.md)
- **Dockerfile**: [Dockerfile.ci](Dockerfile.ci)

## Quick Commands Reference

```bash
# Build and push
./scripts/build-ci-image.sh

# Test locally
./scripts/build-ci-image.sh --test

# Check image exists
docker pull ghcr.io/192d-wing/usg-est-client/ci:latest

# Test tools are installed
docker run --rm ghcr.io/192d-wing/usg-est-client/ci:latest cargo --version
docker run --rm ghcr.io/192d-wing/usg-est-client/ci:latest cargo audit --version

# View in GitHub
open https://github.com/192d-Wing/usg-est-client/pkgs/container/usg-est-client%2Fci
```

## Need Help?

- **Script help**: `./scripts/build-ci-image.sh --help`
- **Build issues**: See [docs/BUILD-CI-IMAGE.md](docs/BUILD-CI-IMAGE.md)
- **CI/CD questions**: Check `.github/workflows/ci.yml` comments
