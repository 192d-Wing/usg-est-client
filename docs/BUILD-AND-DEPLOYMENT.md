# Build and Deployment Guide

**Library:** usg-est-client
**Version:** 0.1.0
**Last Updated:** 2026-01-15

This guide covers building, testing, and deploying the usg-est-client library in production environments.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Building from Source](#building-from-source)
3. [Feature Flags](#feature-flags)
4. [Testing](#testing)
5. [Platform-Specific Considerations](#platform-specific-considerations)
6. [Deployment Scenarios](#deployment-scenarios)
7. [Performance Tuning](#performance-tuning)
8. [Security Hardening](#security-hardening)
9. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Minimum Requirements

| Component | Requirement |
|-----------|-------------|
| **Rust Version** | 1.70.0+ (MSRV) |
| **Operating System** | Linux, macOS, Windows |
| **Memory** | 512 MB RAM (build), 64 MB RAM (runtime) |
| **Network** | HTTPS access to EST server |
| **TLS** | TLS 1.2 or TLS 1.3 support |

### Development Tools

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Verify installation
rustc --version  # Should be 1.70.0 or newer
cargo --version

# Optional: Install development tools
cargo install cargo-audit  # Security auditing
cargo install cargo-deny   # License and dependency checking
cargo install cargo-tarpaulin  # Code coverage (Linux only)
```

### System Dependencies

#### Linux (Debian/Ubuntu)

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    ca-certificates
```

#### Linux (Red Hat/CentOS/Fedora)

```bash
sudo dnf install -y \
    gcc \
    pkg-config \
    openssl-devel \
    ca-certificates
```

#### macOS

```bash
# Install Xcode Command Line Tools
xcode-select --install

# Install OpenSSL (optional, for some features)
brew install openssl@3
```

#### Windows

```powershell
# No additional dependencies required
# Visual Studio Build Tools or MinGW-w64 recommended
```

---

## Building from Source

### Quick Build

```bash
# Clone the repository
git clone https://github.com/192d-Wing/usg-est-client.git
cd usg-est-client

# Build with default features
cargo build --release

# Run tests
cargo test --release
```

### Build Profiles

#### Development Build

```bash
# Fast compilation, includes debug symbols
cargo build

# With all features
cargo build --all-features
```

#### Release Build

```bash
# Optimized for performance
cargo build --release

# Strip debug symbols for smaller binary
cargo build --release --config profile.release.strip=true
```

#### Production Build

```bash
# Maximum optimization
RUSTFLAGS="-C target-cpu=native" cargo build --release

# With Link-Time Optimization (LTO)
cargo build --release --config profile.release.lto=true
```

### Cross-Compilation

#### Linux → Windows

```bash
# Install target
rustup target add x86_64-pc-windows-gnu

# Build
cargo build --release --target x86_64-pc-windows-gnu
```

#### macOS → Linux

```bash
# Install target
rustup target add x86_64-unknown-linux-musl

# Build
cargo build --release --target x86_64-unknown-linux-musl
```

---

## Feature Flags

### Available Features

| Feature | Description | Default | Dependencies |
|---------|-------------|---------|--------------|
| `csr-gen` | CSR generation utilities | No | rcgen |
| `hsm` | Hardware Security Module support | No | - |
| `pkcs11` | PKCS#11 provider | No | pkcs11, cryptoki |
| `renewal` | Automatic certificate renewal | No | - |
| `validation` | Certificate chain validation | No | - |
| `revocation` | CRL/OCSP support | No | - |
| `metrics` | Metrics collection | No | - |
| `metrics-prometheus` | Prometheus exporter | No | prometheus |
| `enveloped` | CMS EnvelopedData decryption | No | cms |
| `fips` | FIPS 140-2 mode | No | - |

### Building with Specific Features

```bash
# CSR generation only
cargo build --release --features csr-gen

# HSM + PKCS#11 support
cargo build --release --features "hsm,pkcs11"

# Full production features
cargo build --release --features "csr-gen,renewal,validation,revocation,metrics"

# All features (development)
cargo build --release --all-features

# No default features
cargo build --release --no-default-features
```

### Feature Dependencies

Some features require others:

```toml
# Example: metrics-prometheus requires metrics
features = ["metrics", "metrics-prometheus"]

# Example: pkcs11 requires hsm
features = ["hsm", "pkcs11"]
```

---

## Testing

### Unit Tests

```bash
# Run all tests
cargo test

# Run tests with specific features
cargo test --features csr-gen

# Run tests with all features
cargo test --all-features

# Run specific test
cargo test test_verify_csr_signature

# Run tests with output
cargo test -- --nocapture

# Run tests in parallel (default)
cargo test -- --test-threads=4
```

### Integration Tests

```bash
# Run integration tests
cargo test --test '*'

# Run specific integration test
cargo test --test enrollment_test

# With verbose output
cargo test --test '*' -- --nocapture
```

### Code Coverage

```bash
# Linux only (requires tarpaulin)
cargo install cargo-tarpaulin

# Generate coverage report
cargo tarpaulin --out Html --output-dir coverage

# View report
open coverage/index.html  # macOS
xdg-open coverage/index.html  # Linux
```

### Benchmarks

```bash
# Run benchmarks (requires nightly Rust)
cargo +nightly bench

# Specific benchmark
cargo +nightly bench --bench csr_verification
```

### Security Audit

```bash
# Install cargo-audit
cargo install cargo-audit

# Run security audit
cargo audit

# Fix known vulnerabilities
cargo audit fix
```

### License Compliance

```bash
# Install cargo-deny
cargo install cargo-deny

# Check licenses
cargo deny check licenses

# Check for banned dependencies
cargo deny check bans

# Full check
cargo deny check
```

---

## Platform-Specific Considerations

### Linux

#### Optimization Flags

```bash
# For x86-64
RUSTFLAGS="-C target-cpu=native -C opt-level=3" cargo build --release

# For ARM64
RUSTFLAGS="-C target-cpu=native" cargo build --release --target aarch64-unknown-linux-gnu
```

#### Static Linking (musl)

```bash
# Install musl target
rustup target add x86_64-unknown-linux-musl

# Build static binary
cargo build --release --target x86_64-unknown-linux-musl

# Verify static linking
ldd target/x86_64-unknown-linux-musl/release/libusgest_client.so
# Should output: "not a dynamic executable"
```

#### systemd Integration

```bash
# Install as systemd service (if building CLI tools)
sudo cp target/release/est-client /usr/local/bin/
sudo cp systemd/est-client.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable est-client
sudo systemctl start est-client
```

### macOS

#### Universal Binary (x86_64 + ARM64)

```bash
# Install both targets
rustup target add x86_64-apple-darwin
rustup target add aarch64-apple-darwin

# Build for both architectures
cargo build --release --target x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin

# Combine into universal binary
lipo -create \
    target/x86_64-apple-darwin/release/libusgest_client.dylib \
    target/aarch64-apple-darwin/release/libusgest_client.dylib \
    -output libusgest_client.dylib
```

#### Code Signing

```bash
# Sign the library (requires Developer ID)
codesign --sign "Developer ID Application: Your Name" libusgest_client.dylib

# Verify signature
codesign --verify --verbose libusgest_client.dylib
```

### Windows

#### MSVC Toolchain (Recommended)

```powershell
# Install Visual Studio Build Tools
# Download from: https://visualstudio.microsoft.com/downloads/

# Build with MSVC
cargo build --release --target x86_64-pc-windows-msvc
```

#### MinGW Toolchain

```powershell
# Install MinGW-w64
# Download from: https://www.mingw-w64.org/

# Build with MinGW
cargo build --release --target x86_64-pc-windows-gnu
```

#### Windows Service Integration

```powershell
# Register as Windows service (requires admin)
sc.exe create EstClient binPath= "C:\path\to\est-client.exe"
sc.exe start EstClient
```

---

## Deployment Scenarios

### Scenario 1: Embedded Library

**Use Case:** Integrate EST client into existing application

```toml
# Cargo.toml
[dependencies]
usg-est-client = { version = "0.1", features = ["csr-gen", "renewal"] }
tokio = { version = "1", features = ["rt-multi-thread"] }
```

```rust
// Your application code
use usg_est_client::{EstClient, EstClientConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = EstClientConfig::builder()
        .server_url("https://est.company.com")?
        .client_identity_from_files("cert.pem", "key.pem")?
        .build()?;

    let client = EstClient::new(config).await?;
    // Use client...
    Ok(())
}
```

### Scenario 2: Standalone Service

**Use Case:** Certificate management service

```bash
# Build standalone binary
cargo build --release --bin est-daemon --features "renewal,metrics-prometheus"

# Deploy
sudo cp target/release/est-daemon /usr/local/bin/
sudo cp config/est-daemon.toml /etc/est/daemon.toml
sudo systemctl enable est-daemon
sudo systemctl start est-daemon
```

### Scenario 3: Docker Container

**Use Case:** Containerized deployment

```dockerfile
# Dockerfile
FROM rust:1.75 as builder

WORKDIR /build
COPY . .

# Build with specific features
RUN cargo build --release --features "csr-gen,renewal,validation"

# Runtime image
FROM debian:bookworm-slim

# Install CA certificates
RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy binary
COPY --from=builder /build/target/release/libusgest_client.so /usr/local/lib/

# Set library path
ENV LD_LIBRARY_PATH=/usr/local/lib

# Run
CMD ["/usr/local/bin/your-app"]
```

**Build and Run:**

```bash
# Build image
docker build -t est-client:latest .

# Run container
docker run -d \
    -e EST_SERVER_URL=https://est.company.com \
    -e EST_USERNAME=device001 \
    -e EST_PASSWORD=secret \
    -v /etc/ssl/certs:/etc/ssl/certs:ro \
    est-client:latest
```

### Scenario 4: Kubernetes Deployment

**Use Case:** Cloud-native EST client

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: est-client
spec:
  replicas: 3
  selector:
    matchLabels:
      app: est-client
  template:
    metadata:
      labels:
        app: est-client
    spec:
      containers:
      - name: est-client
        image: your-registry/est-client:0.1.0
        env:
        - name: EST_SERVER_URL
          valueFrom:
            configMapKeyRef:
              name: est-config
              key: server-url
        - name: EST_USERNAME
          valueFrom:
            secretKeyRef:
              name: est-credentials
              key: username
        - name: EST_PASSWORD
          valueFrom:
            secretKeyRef:
              name: est-credentials
              key: password
        volumeMounts:
        - name: certs
          mountPath: /etc/ssl/certs
          readOnly: true
      volumes:
      - name: certs
        configMap:
          name: ca-certificates
```

**Deploy:**

```bash
# Create namespace
kubectl create namespace est-client

# Create config
kubectl create configmap est-config \
    --from-literal=server-url=https://est.company.com \
    -n est-client

# Create secrets
kubectl create secret generic est-credentials \
    --from-literal=username=device001 \
    --from-literal=password=secret \
    -n est-client

# Deploy
kubectl apply -f deployment.yaml -n est-client
```

### Scenario 5: IoT Device

**Use Case:** Embedded device with limited resources

```bash
# Build for ARM with size optimization
cargo build --release \
    --target armv7-unknown-linux-gnueabihf \
    --no-default-features \
    --features csr-gen \
    -Z build-std=std,panic_abort \
    -Z build-std-features=panic_immediate_abort

# Strip binary
arm-linux-gnueabihf-strip target/armv7-unknown-linux-gnueabihf/release/est-client

# Check size
ls -lh target/armv7-unknown-linux-gnueabihf/release/est-client
```

---

## Performance Tuning

### Compile-Time Optimizations

```toml
# Cargo.toml
[profile.release]
opt-level = 3              # Maximum optimization
lto = "fat"                # Link-time optimization
codegen-units = 1          # Better optimization, slower compile
panic = "abort"            # Smaller binary
strip = true               # Remove symbols
```

### Runtime Optimizations

#### Tokio Configuration

```rust
use tokio::runtime::Builder;

let runtime = Builder::new_multi_thread()
    .worker_threads(4)  // Adjust based on CPU cores
    .thread_name("est-worker")
    .enable_all()
    .build()?;
```

#### Connection Pooling

```rust
let config = EstClientConfig::builder()
    .server_url("https://est.company.com")?
    .timeout(Duration::from_secs(30))  // Adjust based on network
    .build()?;

// Reuse client for multiple operations
let client = EstClient::new(config).await?;
```

#### Memory Management

```bash
# Set thread stack size
export RUST_MIN_STACK=2097152  # 2MB

# Control allocator (Linux)
export MALLOC_ARENA_MAX=2
```

### Benchmarking

```rust
// benches/csr_verification.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use usg_est_client::operations::enroll::verify_csr_signature;

fn benchmark_csr_verification(c: &mut Criterion) {
    let csr_der = include_bytes!("../fixtures/test_csr.der");

    c.bench_function("verify_csr_signature", |b| {
        b.iter(|| verify_csr_signature(black_box(csr_der)))
    });
}

criterion_group!(benches, benchmark_csr_verification);
criterion_main!(benches);
```

---

## Security Hardening

### Build Security

```bash
# Enable security auditing in CI/CD
cargo audit

# Check for vulnerable dependencies
cargo deny check advisories

# Verify SBOM (Software Bill of Materials)
cargo deny check licenses
```

### Runtime Security

#### File Permissions

```bash
# Restrict access to private keys (Unix)
chmod 600 /etc/est/private-key.pem
chown est-service:est-service /etc/est/private-key.pem

# Restrict access to configuration
chmod 640 /etc/est/config.toml
chown root:est-service /etc/est/config.toml
```

#### Process Isolation (Linux)

```ini
# /etc/systemd/system/est-client.service
[Service]
Type=simple
User=est-service
Group=est-service
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/est
CapabilityBoundingSet=
```

#### SELinux/AppArmor

```bash
# SELinux context (Red Hat/CentOS)
sudo chcon -t bin_t /usr/local/bin/est-client
sudo semanage fcontext -a -t cert_t "/etc/est(/.*)?""
sudo restorecon -Rv /etc/est

# AppArmor profile (Ubuntu/Debian)
sudo cp apparmor/est-client /etc/apparmor.d/
sudo apparmor_parser -r /etc/apparmor.d/est-client
```

### FIPS 140-2 Compliance

```bash
# Build with FIPS feature (requires FIPS-certified OpenSSL)
cargo build --release --features fips

# Verify FIPS mode at runtime
OPENSSL_FIPS=1 ./target/release/est-client
```

---

## Troubleshooting

### Common Build Issues

#### Issue: OpenSSL not found

```
error: failed to run custom build command for `openssl-sys`
```

**Solution (Linux):**

```bash
sudo apt-get install libssl-dev pkg-config
```

**Solution (macOS):**

```bash
brew install openssl@3
export OPENSSL_DIR=$(brew --prefix openssl@3)
cargo build --release
```

#### Issue: Link errors on musl

```
error: linking with `cc` failed
```

**Solution:**

```bash
rustup target add x86_64-unknown-linux-musl
sudo apt-get install musl-tools
cargo build --release --target x86_64-unknown-linux-musl
```

#### Issue: MSRV (Minimum Supported Rust Version) error

```
error: package requires rustc 1.70.0 or newer
```

**Solution:**

```bash
rustup update
rustc --version  # Verify >= 1.70.0
```

### Runtime Issues

#### Issue: TLS connection failed

```
Error: Tls error: invalid peer certificate: UnknownIssuer
```

**Solution:**

```rust
// Add CA certificates to trust store
let config = EstClientConfig::builder()
    .server_url("https://est.company.com")?
    .trust_anchors_pem(include_bytes!("ca-bundle.pem"))?
    .build()?;
```

#### Issue: HTTP 401 Unauthorized

```
Error: Authentication required: Basic realm="EST"
```

**Solution:**

```rust
// Provide credentials
let config = EstClientConfig::builder()
    .server_url("https://est.company.com")?
    .http_auth("username", "password")
    .build()?;
```

#### Issue: CSR verification failed

```
Error: CSR signature invalid
```

**Solution:**

```rust
// Ensure CSR is properly signed
use usg_est_client::operations::enroll::verify_csr_signature;

let is_valid = verify_csr_signature(&csr_der)?;
if !is_valid {
    eprintln!("CSR signature is invalid - regenerate CSR");
}
```

### Debug Logging

```bash
# Enable trace logging
export RUST_LOG=usg_est_client=trace

# Enable logging for specific module
export RUST_LOG=usg_est_client::operations=debug

# Full debug output
export RUST_LOG=debug
```

```rust
// In code
use tracing::Level;

tracing_subscriber::fmt()
    .with_max_level(Level::DEBUG)
    .init();
```

### Performance Debugging

```bash
# Profile CPU usage (Linux)
cargo install flamegraph
cargo flamegraph --bin est-client

# Memory profiling
cargo install heaptrack
heaptrack target/release/est-client

# System calls trace (Linux)
strace -c target/release/est-client
```

---

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/ci.yml
name: CI

on: [push, pull_request]

jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        rust: [stable, beta, 1.70.0]  # MSRV

    steps:
    - uses: actions/checkout@v3

    - uses: actions-rs/toolchain@v1
      with:
        toolchain: ${{ matrix.rust }}
        override: true

    - name: Build
      run: cargo build --release --all-features

    - name: Test
      run: cargo test --release --all-features

    - name: Security Audit
      run: |
        cargo install cargo-audit
        cargo audit
```

### Additional GitHub Actions Examples

For more CI/CD configuration examples, see the workflow files in `.github/workflows/`.

---

## Version Management

### Semantic Versioning

The library follows [Semantic Versioning 2.0.0](https://semver.org/):

- **MAJOR**: Incompatible API changes
- **MINOR**: Backward-compatible functionality additions
- **PATCH**: Backward-compatible bug fixes

### Release Process

```bash
# Update version in Cargo.toml
sed -i 's/version = "0.1.0"/version = "0.2.0"/' Cargo.toml

# Update CHANGELOG.md
# Add release notes

# Commit and tag
git add Cargo.toml CHANGELOG.md
git commit -m "Release v0.2.0"
git tag -a v0.2.0 -m "Version 0.2.0"
git push origin main --tags

# Publish to crates.io
cargo publish
```

---

## Support and Resources

### Documentation

- API Docs: <https://docs.rs/usg-est-client>
- RFC 7030: <https://tools.ietf.org/html/rfc7030>
- Implementation Guide: [docs/dev/IMPLEMENTATION-GUIDE.md](dev/IMPLEMENTATION-GUIDE.md)

### Community

- GitHub Issues: <https://github.com/192d-Wing/usg-est-client/issues>
- Discussions: <https://github.com/192d-Wing/usg-est-client/discussions>

### Security

- Security Policy: [SECURITY.md](../SECURITY.md)
- Vulnerability Reporting: <security@your-org.com>

---

**Document Version:** 1.0
**Last Updated:** 2026-01-15
**Maintainer:** EST Client Development Team
