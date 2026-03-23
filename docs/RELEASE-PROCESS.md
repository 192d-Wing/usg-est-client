# Release Process Documentation

This document describes how to create and publish releases for the USG EST Client.

## Overview

The project uses automated CI/CD pipelines to build releases for multiple platforms when a version tag is pushed. GitHub Actions is configured to handle releases.

## Supported Platforms

### Linux
- **x86_64-unknown-linux-gnu**: Standard Linux build (dynamically linked)
- **x86_64-unknown-linux-musl**: Static Linux build (no dependencies)

### macOS
- **x86_64-apple-darwin**: Intel Macs
- **aarch64-apple-darwin**: Apple Silicon Macs (M1/M2/M3)

### Windows
- **x86_64-pc-windows-msvc**: 64-bit Windows (MSVC toolchain)

## Release Process

### 1. Prepare for Release

Before creating a release, ensure:

1. **All tests pass**: Run the full test suite
   ```bash
   cargo test --all-features
   cargo clippy --all-features -- -D warnings
   cargo fmt --all -- --check
   ```

2. **Update version number**: Edit `Cargo.toml`
   ```toml
   [package]
   version = "1.0.0"  # Update this
   ```

3. **Update CHANGELOG.md**: Document changes in the release
   ```markdown
   ## [1.0.0] - 2026-01-16

   ### Added
   - Feature X
   - Feature Y

   ### Changed
   - Improved Z

   ### Fixed
   - Bug fix for A
   ```

4. **Update documentation**: Ensure all docs are current
   - README.md
   - CONFIGURATION.md
   - API documentation

5. **Commit changes**:
   ```bash
   git add Cargo.toml CHANGELOG.md
   git commit -m "chore: prepare release v1.0.0"
   ```

### 2. Create and Push Tag

#### Semantic Versioning

Use [Semantic Versioning](https://semver.org/):
- **Major version** (X.0.0): Breaking changes
- **Minor version** (0.X.0): New features, backward compatible
- **Patch version** (0.0.X): Bug fixes, backward compatible

#### Pre-release Tags

For pre-releases, use:
- `v1.0.0-alpha.1`: Alpha release
- `v1.0.0-beta.1`: Beta release
- `v1.0.0-rc.1`: Release candidate

#### Create Tag

```bash
# Create annotated tag
git tag -a v1.0.0 -m "Release version 1.0.0"

# Push tag to trigger release
git push origin v1.0.0
```

**Important**: The tag MUST match the pattern `v*.*.*` to trigger the release pipeline.

### 3. Automated Build Process

Once the tag is pushed, the CI/CD pipeline automatically:

1. **Builds binaries** for all platforms
2. **Generates SHA256 checksums** for verification
3. **Packages artifacts**:
   - Linux/macOS: `.tar.gz` archives
   - Windows: `.zip` archives
4. **Creates release** with all artifacts attached
5. **Generates release notes** from template

#### GitHub Actions

Workflow file: `.github/workflows/release.yml`

The workflow runs when tags matching `v*.*.*` are pushed:
- Builds on: `ubuntu-latest`, `macos-latest`, `windows-latest`
- Uploads artifacts to GitHub Releases
- Generates combined checksums file

#### Note on GitLab CI (Historical)

The project was previously hosted on GitLab. All CI/CD is now handled by GitHub Actions.

### 4. Verify Release

After the pipeline completes:

1. **Check build status**: Ensure all jobs succeeded
   - GitHub: Check Actions tab

2. **Download and test binaries**:
   ```bash
   # Download for your platform
   wget https://github.com/user/repo/releases/download/v1.0.0/est-enroll-1.0.0-x86_64-unknown-linux-gnu.tar.gz

   # Verify checksum
   sha256sum -c est-enroll-1.0.0-x86_64-unknown-linux-gnu.sha256

   # Extract and test
   tar -xzf est-enroll-1.0.0-x86_64-unknown-linux-gnu.tar.gz
   ./est-enroll-1.0.0-x86_64-unknown-linux-gnu --version
   ```

3. **Review release notes**: Ensure documentation links work

### 5. Announce Release

After verification:

1. **Update main branch**: Merge release preparation commits
   ```bash
   git checkout main
   git merge release-v1.0.0
   git push origin main
   ```

2. **Announce**: Post to relevant channels
   - Project mailing list
   - Slack/Discord channels
   - Social media (if applicable)

3. **Update documentation sites**: Publish updated docs

## Manual Release (Emergency)

If automated builds fail, you can create a manual release:

### Build Locally

```bash
# Linux
cargo build --release --target x86_64-unknown-linux-gnu --bin est-enroll --features cli

# macOS (Intel)
cargo build --release --target x86_64-apple-darwin --bin est-enroll --features cli

# macOS (Apple Silicon)
cargo build --release --target aarch64-apple-darwin --bin est-enroll --features cli

# Windows (requires Windows host or cross-compilation)
cargo build --release --target x86_64-pc-windows-msvc --bin est-enroll --features cli
```

### Package Artifacts

```bash
# Create archive
cd target/x86_64-unknown-linux-gnu/release
tar -czf est-enroll-1.0.0-x86_64-unknown-linux-gnu.tar.gz est-enroll

# Generate checksum
sha256sum est-enroll-1.0.0-x86_64-unknown-linux-gnu.tar.gz > est-enroll-1.0.0-x86_64-unknown-linux-gnu.sha256
```

### Upload to GitHub

```bash
# Using GitHub CLI
gh release create v1.0.0 \
  --title "Release v1.0.0" \
  --notes "See CHANGELOG.md for details" \
  est-enroll-1.0.0-*.tar.gz \
  est-enroll-1.0.0-*.sha256
```

## Troubleshooting

### Build Failures

**Problem**: Rust compilation errors

**Solution**:
1. Check Rust version compatibility (MSRV: 1.92.0)
2. Verify dependencies are up to date: `cargo update`
3. Check for platform-specific issues in error logs

**Problem**: Missing dependencies (Linux)

**Solution**:
```bash
sudo apt-get update
sudo apt-get install -y pkg-config libssl-dev
```

**Problem**: Cross-compilation fails

**Solution**: Use `cross` tool for cross-compilation:
```bash
cargo install cross
cross build --release --target x86_64-unknown-linux-musl --bin est-enroll --features cli
```

### CI/CD Issues

**Problem**: macOS or Windows runners unavailable

**Solution**: Jobs are marked with `allow_failure: true`. Linux builds will still succeed.

**Problem**: Artifacts not uploading

**Solution**:
1. Check job logs for permission errors
2. Verify artifact paths match expected patterns
3. Ensure release was created before artifact upload

### Tag Issues

**Problem**: Wrong tag format doesn't trigger release

**Solution**: Delete and recreate tag with correct format:
```bash
git tag -d v1.0.0           # Delete local tag
git push origin :v1.0.0     # Delete remote tag
git tag -a v1.0.0 -m "..."  # Recreate tag
git push origin v1.0.0      # Push correct tag
```

**Problem**: Need to update a release

**Solution**: Create a patch release:
```bash
# Fix the issue
git commit -m "fix: critical bug"

# Create new patch version
git tag -a v1.0.1 -m "Hotfix for v1.0.0"
git push origin v1.0.1
```

## Release Checklist

Use this checklist when creating a release:

- [ ] All tests pass locally
- [ ] Version number updated in `Cargo.toml`
- [ ] CHANGELOG.md updated with changes
- [ ] Documentation is current
- [ ] Commit changes: `git commit -m "chore: prepare release vX.Y.Z"`
- [ ] Create annotated tag: `git tag -a vX.Y.Z -m "Release vX.Y.Z"`
- [ ] Push tag: `git push origin vX.Y.Z`
- [ ] Monitor CI/CD pipeline
- [ ] Verify builds completed successfully
- [ ] Download and test binaries
- [ ] Verify checksums
- [ ] Check release notes accuracy
- [ ] Merge to main branch
- [ ] Announce release

## Security Considerations

### Binary Signatures

Consider implementing GPG signatures for releases:

```bash
# Sign release tag
git tag -s v1.0.0 -m "Release v1.0.0"

# Sign binaries
gpg --detach-sign --armor est-enroll-1.0.0-x86_64-unknown-linux-gnu.tar.gz
```

### Supply Chain Security

1. **Reproducible builds**: Document exact build environment
2. **Dependency audits**: Run `cargo audit` before releases
3. **SBOM generation**: Consider generating Software Bill of Materials

### Vulnerability Disclosure

If releasing a security fix:
1. Coordinate with security team
2. Create security advisory first
3. Reference CVE in release notes
4. Follow responsible disclosure timeline

## Automation Improvements

### Future Enhancements

1. **Automated changelog generation**: Use conventional commits
2. **Binary signing**: Add GPG signature verification
3. **Release candidates**: Automated RC builds on merge to release branch
4. **Version bumping**: Automate version number updates
5. **Docker images**: Build and publish container images

### CI/CD Optimizations

1. **Caching**: Improve build caches for faster releases
2. **Parallel builds**: Build all platforms simultaneously
3. **Artifact retention**: Configure appropriate retention policies
4. **Notifications**: Add Slack/email notifications for release status

## References

- [Semantic Versioning](https://semver.org/)
- [Keep a Changelog](https://keepachangelog.com/)
- [GitHub Releases](https://docs.github.com/en/repositories/releasing-projects-on-github)
- [GitHub Actions](https://docs.github.com/en/actions)
- [Rust Cross-Compilation](https://rust-lang.github.io/rustup/cross-compilation.html)
