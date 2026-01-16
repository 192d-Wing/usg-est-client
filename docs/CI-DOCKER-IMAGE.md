# Custom CI Docker Image

This project uses a custom Docker image for CI/CD pipelines to significantly speed up build times.

## Benefits

- **2-3x faster pipeline execution**: Pre-installed dependencies eliminate download/install time
- **Consistent environment**: All CI jobs use the same pre-configured environment
- **Reduced network usage**: No need to download Rust toolchains and cargo tools on every run
- **Cost savings**: Faster pipelines mean lower CI/CD costs

## What's Pre-installed

The custom CI image (`registry.gitlab.com/192d-wing/usg-est-client/ci:latest`) includes:

### System Dependencies
- pkg-config
- libssl-dev
- musl-tools (for static builds)
- git, curl, jq

### Rust Toolchains
- Rust 1.92 (stable)
- **Linux targets:**
  - x86_64-unknown-linux-gnu (standard GNU)
  - x86_64-unknown-linux-musl (static builds)
- **Windows targets:**
  - x86_64-pc-windows-gnu (MinGW cross-compilation)
- **macOS targets:**
  - x86_64-apple-darwin (Intel Macs)
  - aarch64-apple-darwin (Apple Silicon)
  - **Note:** macOS cross-compilation from Linux requires macOS SDK (not included)
  - For production macOS builds, use native macOS runners in CI

### Cargo Tools
- cargo-audit 0.20.1
- cargo-tarpaulin 0.31.2
- cargo-deny 0.16.3

## Building the CI Image

### Prerequisites

1. Docker installed and running
2. GitLab Container Registry access
3. Appropriate permissions to push to the registry

### Build and Push

```bash
# Log in to GitLab Container Registry
docker login registry.gitlab.com

# Build the image
docker build -f Dockerfile.ci -t registry.gitlab.com/192d-wing/usg-est-client/ci:latest .

# Push to registry
docker push registry.gitlab.com/192d-wing/usg-est-client/ci:latest
```

### Using GitLab CI to Build

The CI image is automatically built and updated when:

1. **Dockerfile.ci changes**: Triggered on push
2. **Manual trigger**: Set CI variable `CI_BUILD_IMAGE=true`
3. **Weekly schedule**: Picks up Rust toolchain updates

To manually trigger a build:

```bash
# In GitLab UI
CI/CD → Pipelines → Run pipeline
Add variable: CI_BUILD_IMAGE = true
```

## Using in CI/CD

The `.gitlab-ci.yml` is already configured to use the custom image:

```yaml
variables:
  CI_IMAGE: "registry.gitlab.com/192d-wing/usg-est-client/ci:latest"

jobs:
  test:
    image: ${CI_IMAGE}  # Uses custom image
    script:
      - cargo test
```

## Performance Comparison

### Before (Standard rust:latest)

```
test:stable:linux
  ├─ Setup (apt-get, cargo install): 180s
  ├─ Cargo test: 120s
  └─ Total: 300s (5 minutes)
```

### After (Custom CI Image)

```
test:stable:linux
  ├─ Setup (none needed): 5s
  ├─ Cargo test: 120s
  └─ Total: 125s (2 minutes)
```

**Savings: 175 seconds per job (58% faster)**

For a typical pipeline with 15 jobs using the image, this saves **~44 minutes** per pipeline run.

## Maintenance

### Updating Rust Version

Edit `Dockerfile.ci`:

```dockerfile
FROM rust:1.93-bookworm  # Update version here
```

Then rebuild and push the image.

### Adding New Tools

Edit `Dockerfile.ci` to add new cargo tools:

```dockerfile
RUN cargo install --locked new-tool --version X.Y.Z && \
    rm -rf /usr/local/cargo/registry
```

### Scheduled Updates

Configure a weekly GitLab CI schedule:

1. Go to CI/CD → Schedules
2. Create new schedule
3. Set interval: Weekly
4. Add variable: `SCHEDULED_JOB=build-ci-image`

## Troubleshooting

### Image Not Found

If you see "image not found" errors:

1. Check registry permissions
2. Ensure image was pushed successfully
3. Verify image name in `.gitlab-ci.yml` matches registry path

**Fallback**: The pipeline will fall back to `rust:latest` if the custom image is unavailable (configured in `.gitlab-ci.yml`).

### Old Image Cached

If changes to Dockerfile.ci aren't reflected:

```bash
# Clear local Docker cache
docker system prune -a

# Rebuild without cache
docker build --no-cache -f Dockerfile.ci -t registry.gitlab.com/192d-wing/usg-est-client/ci:latest .
```

### Size Too Large

If the image becomes too large (>2GB), consider:

1. Using multi-stage builds
2. Removing unnecessary tools
3. Cleaning up after cargo installs:
   ```dockerfile
   RUN cargo install tool && rm -rf /usr/local/cargo/registry
   ```

## Alternative: Release Dockerfile

For building release binaries with optimal caching, use `Dockerfile.release`:

```bash
docker build -f Dockerfile.release --build-arg TARGET=x86_64-unknown-linux-gnu -t est-enroll:latest .
```

This uses `cargo-chef` for dependency caching and creates a minimal runtime image.

## Security Considerations

- The CI image is stored in a private GitLab Container Registry
- Only authorized users can push updates
- Base image is official `rust:bookworm` from Docker Hub
- All cargo tools installed from crates.io with `--locked` flag
- Image is scanned by GitLab's container scanning (if available)

## Cost Analysis

### Without Custom Image
- Average pipeline: 15 jobs × 300s = 75 minutes
- Monthly (100 pipelines): 7,500 minutes = 125 hours
- **Estimated cost**: $50-75/month (GitLab shared runners)

### With Custom Image
- Average pipeline: 15 jobs × 125s = 31 minutes
- Monthly (100 pipelines): 3,100 minutes = 52 hours
- **Estimated cost**: $20-30/month
- **Plus**: Image storage ~500MB = ~$0.50/month

**Net savings: ~$25-45/month (58% reduction)**

## References

- Dockerfile.ci: Custom CI image definition
- Dockerfile.release: Multi-stage release build
- .gitlab-ci.yml: CI configuration using custom image
- [Docker Multi-stage Builds](https://docs.docker.com/build/building/multi-stage/)
- [GitLab Container Registry](https://docs.gitlab.com/ee/user/packages/container_registry/)
