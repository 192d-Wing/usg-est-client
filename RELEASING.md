# Quick Release Guide

This is a quick reference for creating releases. For detailed information, see [docs/RELEASE-PROCESS.md](docs/RELEASE-PROCESS.md).

## TL;DR - Create a Release

```bash
# 1. Update version and changelog
vim Cargo.toml CHANGELOG.md

# 2. Commit
git add Cargo.toml CHANGELOG.md
git commit -m "chore: prepare release v1.0.0"

# 3. Create and push tag
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0

# 4. Watch CI/CD build binaries automatically
# GitHub: https://github.com/192d-Wing/usg-est-client/actions
```

## What Happens Automatically

When you push a tag matching `v*.*.*`:

1. ✅ **CI/CD builds binaries** for:
   - Linux (x86_64-gnu and x86_64-musl)
   - macOS (Intel and Apple Silicon)
   - Windows (x86_64-msvc)

2. ✅ **Generates SHA256 checksums** for all binaries

3. ✅ **Creates GitHub Release** with:
   - All binary artifacts
   - Checksums file
   - Auto-generated release notes

4. ✅ **Publishes artifacts** to:
   - GitHub Releases

## Platforms Built

| Platform | Target | Binary Name |
|----------|--------|-------------|
| Linux (GNU) | x86_64-unknown-linux-gnu | est-enroll-VERSION-x86_64-unknown-linux-gnu.tar.gz |
| Linux (static) | x86_64-unknown-linux-musl | est-enroll-VERSION-x86_64-unknown-linux-musl.tar.gz |
| macOS Intel | x86_64-apple-darwin | est-enroll-VERSION-x86_64-apple-darwin.tar.gz |
| macOS ARM64 | aarch64-apple-darwin | est-enroll-VERSION-aarch64-apple-darwin.tar.gz |
| Windows | x86_64-pc-windows-msvc | est-enroll-VERSION-x86_64-pc-windows-msvc.exe.zip |

## Version Numbers

Follow [Semantic Versioning](https://semver.org/):

- **Major**: Breaking changes (v2.0.0)
- **Minor**: New features, backward compatible (v1.1.0)
- **Patch**: Bug fixes, backward compatible (v1.0.1)

### Pre-releases

- Alpha: `v1.0.0-alpha.1`
- Beta: `v1.0.0-beta.1`
- RC: `v1.0.0-rc.1`

## Quick Test

```bash
# Download your platform's binary from the release
# Example for Linux:
wget https://github.com/user/repo/releases/download/v1.0.0/est-enroll-1.0.0-x86_64-unknown-linux-gnu.tar.gz

# Verify checksum
sha256sum -c est-enroll-1.0.0-x86_64-unknown-linux-gnu.sha256

# Extract and test
tar -xzf est-enroll-1.0.0-x86_64-unknown-linux-gnu.tar.gz
./est-enroll-* --version
./est-enroll-* check --server https://testrfc7030.com --insecure
```

## If Something Goes Wrong

### Delete a tag

```bash
# Delete local tag
git tag -d v1.0.0

# Delete remote tag
git push origin :v1.0.0
```

### Create a hotfix

```bash
# Fix the issue, commit
git commit -m "fix: critical bug"

# Create patch release
git tag -a v1.0.1 -m "Hotfix for v1.0.0"
git push origin v1.0.1
```

## Release Checklist

- [ ] Tests pass: `cargo test --all-features`
- [ ] Lints pass: `cargo clippy --all-features -- -D warnings`
- [ ] Format check: `cargo fmt --all -- --check`
- [ ] Version updated in `Cargo.toml`
- [ ] Changelog updated in `CHANGELOG.md`
- [ ] Changes committed
- [ ] Tag created: `git tag -a vX.Y.Z -m "Release vX.Y.Z"`
- [ ] Tag pushed: `git push origin vX.Y.Z`
- [ ] CI/CD pipeline monitored
- [ ] Binaries downloaded and tested
- [ ] Release announced

## CI/CD Configuration Files

- **GitHub Actions**: `.github/workflows/release.yml`

## Need Help?

- Full documentation: [docs/RELEASE-PROCESS.md](docs/RELEASE-PROCESS.md)
- CI/CD troubleshooting: Check pipeline logs
- Build issues: See "Troubleshooting" section in RELEASE-PROCESS.md
