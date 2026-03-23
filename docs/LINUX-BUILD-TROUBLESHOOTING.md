# Linux Build Troubleshooting Guide

**Date:** 2026-01-26
**Classification:** UNCLASSIFIED

---

## Common Linux Linking Error: `cc` failed with exit status 1

This document provides solutions for the common linking error on Linux:

```
error: linking with `cc` failed: exit status: 1
```

---

## Root Causes

The linking error typically occurs due to missing system libraries required by the project's dependencies. The `usg-est-client` project has several optional dependencies that may require system libraries:

1. **OpenSSL** (when using `fips` or `native-tls-backend` features)
2. **pkg-config** (for finding system libraries)
3. **Build tools** (gcc, make, etc.)

---

## Quick Fix (Ubuntu/Debian)

For most users, installing the following packages will resolve the issue:

```bash
# Update package lists
sudo apt update

# Install essential build tools and OpenSSL development libraries
sudo apt install -y \
    build-essential \
    pkg-config \
    libssl-dev
```

Then rebuild:

```bash
cargo clean
cargo build --release
```

---

## Platform-Specific Solutions

### Ubuntu / Debian / Linux Mint

```bash
# Install build essentials
sudo apt install -y build-essential pkg-config

# Install OpenSSL development libraries
sudo apt install -y libssl-dev

# For older versions, you may need:
sudo apt install -y libssl1.1 libssl-dev
```

### RHEL / CentOS / Fedora / Rocky Linux

```bash
# Install development tools
sudo dnf groupinstall "Development Tools"
sudo dnf install -y pkg-config

# Install OpenSSL development libraries
sudo dnf install -y openssl-devel
```

For older RHEL/CentOS 7:
```bash
sudo yum groupinstall "Development Tools"
sudo yum install -y pkg-config openssl-devel
```

### Alpine Linux

```bash
# Install build tools
apk add --no-cache build-base pkgconfig

# Install OpenSSL development libraries
apk add --no-cache openssl-dev
```

### Arch Linux / Manjaro

```bash
# Install base development tools
sudo pacman -S base-devel

# Install OpenSSL
sudo pacman -S openssl pkg-config
```

### OpenSUSE / SUSE Linux

```bash
# Install development pattern
sudo zypper install -t pattern devel_basis

# Install OpenSSL development
sudo zypper install libopenssl-devel pkg-config
```

---

## Feature-Specific Requirements

### Default Build (no features)

**Requirements:** None - uses pure Rust cryptography (rustls)

```bash
cargo build --release --no-default-features
```

### FIPS Mode (`fips` feature)

**Requirements:** OpenSSL 3.0+ with FIPS module

```bash
# Ubuntu/Debian
sudo apt install -y libssl-dev

# RHEL/Fedora
sudo dnf install -y openssl-devel

# Build with FIPS
cargo build --release --features fips
```

**Note:** FIPS mode requires OpenSSL to be configured with the FIPS module. See [docs/ato/fips-configuration.md](ato/fips-configuration.md) for details.

### Native TLS Backend (`native-tls-backend` feature)

**Requirements:** System OpenSSL or TLS library

```bash
# Ubuntu/Debian
sudo apt install -y libssl-dev

# Build with native TLS
cargo build --release --features native-tls-backend
```

### Vendored OpenSSL (`native-tls-vendored` feature)

**Requirements:** Build tools only (OpenSSL is vendored)

This feature compiles OpenSSL from source, avoiding the need for system OpenSSL libraries:

```bash
# Ubuntu/Debian - only need build tools
sudo apt install -y build-essential pkg-config

# Build with vendored OpenSSL
cargo build --release --features native-tls-vendored
```

**Benefits:**
- No system OpenSSL dependency
- Portable binaries
- Useful for musl/Alpine/Lambda deployments

**Drawbacks:**
- Longer compilation time
- Larger binary size

---

## Troubleshooting Steps

### Step 1: Identify the Missing Library

Run the build with verbose output to see which library is failing:

```bash
cargo clean
cargo build --release --verbose 2>&1 | tee build.log
```

Look for errors like:
- `cannot find -lssl` → Missing libssl
- `cannot find -lcrypto` → Missing libcrypto (OpenSSL)
- `pkg-config not found` → Missing pkg-config

### Step 2: Check Installed Packages

**Ubuntu/Debian:**
```bash
# Check for OpenSSL development files
dpkg -l | grep libssl-dev

# Check for build tools
dpkg -l | grep build-essential
```

**RHEL/Fedora:**
```bash
# Check for OpenSSL development files
rpm -qa | grep openssl-devel

# Check for development tools
dnf grouplist installed | grep "Development Tools"
```

### Step 3: Verify pkg-config

```bash
# Check if pkg-config is installed
which pkg-config

# Check if OpenSSL is found by pkg-config
pkg-config --modversion openssl
```

### Step 4: Use Vendored Dependencies

If system libraries are problematic, use vendored dependencies:

```bash
# Build with vendored OpenSSL (if using FIPS or native-tls)
cargo build --release --features native-tls-vendored

# Or build with default features only (no OpenSSL)
cargo build --release
```

---

## Minimal Build (No System Dependencies)

If you don't need FIPS or native TLS, you can build with pure Rust cryptography:

```bash
# Clean previous build
cargo clean

# Build with only default features (rustls, no OpenSSL)
cargo build --release
```

This uses:
- **rustls** for TLS (pure Rust, no OpenSSL)
- **RustCrypto** ecosystem for cryptography

**No system dependencies required** except for basic build tools (gcc/clang).

---

## Docker / Container Builds

### Debian-based Container

```dockerfile
FROM rust:1.84-bookworm

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy project
WORKDIR /build
COPY . .

# Build
RUN cargo build --release
```

### Alpine-based Container (smaller image)

```dockerfile
FROM rust:1.84-alpine

# Install dependencies
RUN apk add --no-cache \
    build-base \
    pkgconfig \
    openssl-dev \
    musl-dev

# Copy project
WORKDIR /build
COPY . .

# Build with vendored OpenSSL for static linking
RUN cargo build --release --features native-tls-vendored
```

---

## Static Linking (musl)

For fully static binaries (no runtime dependencies):

```bash
# Install musl target
rustup target add x86_64-unknown-linux-musl

# Ubuntu/Debian: Install musl tools
sudo apt install -y musl-tools

# Build static binary with vendored OpenSSL
cargo build --release \
    --target x86_64-unknown-linux-musl \
    --features native-tls-vendored
```

The resulting binary has no dependencies and can run on any Linux system.

---

## CI/CD Configuration

### GitHub Actions (.github/workflows/build.yml)

```yaml
name: Build

on: [push, pull_request]

jobs:
  build-linux:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable

      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y build-essential pkg-config libssl-dev

      - name: Build
        run: cargo build --release --all-features
```

---

## Verification

After installing dependencies, verify the build:

```bash
# Clean previous build
cargo clean

# Build with all features
cargo build --release --all-features

# Run tests
cargo test --all-features

# Check binary
ls -lh target/release/est-enroll
file target/release/est-enroll
ldd target/release/est-enroll  # Check dynamic dependencies
```

---

## Common Error Messages

### Error: `cannot find -lssl`

**Cause:** Missing OpenSSL development libraries

**Solution:**
```bash
# Ubuntu/Debian
sudo apt install -y libssl-dev

# RHEL/Fedora
sudo dnf install -y openssl-devel
```

### Error: `pkg-config not found`

**Cause:** Missing pkg-config tool

**Solution:**
```bash
# Ubuntu/Debian
sudo apt install -y pkg-config

# RHEL/Fedora
sudo dnf install -y pkg-config
```

### Error: `error: linker 'cc' not found`

**Cause:** Missing C compiler

**Solution:**
```bash
# Ubuntu/Debian
sudo apt install -y build-essential

# RHEL/Fedora
sudo dnf groupinstall "Development Tools"
```

### Error: `could not find system library 'openssl'`

**Cause:** OpenSSL not found by pkg-config

**Solution:**
```bash
# Check if OpenSSL is installed
pkg-config --modversion openssl

# If not found, install:
# Ubuntu/Debian
sudo apt install -y libssl-dev

# Or use vendored OpenSSL
cargo build --release --features native-tls-vendored
```

---

## Need More Help?

1. **Check full error output**: Run `cargo build --verbose` and capture the full output
2. **Check OpenSSL version**: Run `openssl version` to verify OpenSSL is installed
3. **Check system info**: Run `uname -a` and `cat /etc/os-release` to identify your distribution
4. **Try minimal build**: Use `cargo build --release` without features to isolate the issue
5. **Try vendored build**: Use `--features native-tls-vendored` to avoid system libraries

---

## Summary

**Most Common Solution (Ubuntu/Debian):**
```bash
sudo apt install -y build-essential pkg-config libssl-dev
cargo clean
cargo build --release
```

**Most Common Solution (RHEL/Fedora):**
```bash
sudo dnf groupinstall "Development Tools"
sudo dnf install -y pkg-config openssl-devel
cargo clean
cargo build --release
```

**Alternative (No system dependencies):**
```bash
cargo build --release --no-default-features --features csr-gen
```

---

**Document Classification:** UNCLASSIFIED
**Maintained By:** Development Team
**Last Updated:** 2026-01-26

**End of Linux Build Troubleshooting Guide**
