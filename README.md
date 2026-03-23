# usg-est-client

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Crates.io](https://img.shields.io/crates/v/usg-est-client.svg)](https://crates.io/crates/usg-est-client)
[![Documentation](https://docs.rs/usg-est-client/badge.svg)](https://docs.rs/usg-est-client)

## CI/CD & Security

[![GitHub Actions](https://img.shields.io/github/actions/workflow/status/192d-Wing/usg-est-client/ci.yml?branch=main)](https://github.com/192d-Wing/usg-est-client/actions)
[![Security Audit](https://img.shields.io/badge/security-cargo--audit-success.svg)](https://github.com/192d-Wing/usg-est-client/actions)
[![License Check](https://img.shields.io/badge/licenses-cargo--deny-success.svg)](deny.toml)

- 🔒 **Security**: Daily automated security audits with cargo-audit and cargo-deny
- ✅ **Testing**: Cross-platform CI/CD (Linux, macOS, Windows) with Rust stable, beta, and MSRV
- 📊 **Coverage**: Automated code coverage reporting with tarpaulin
- 🔍 **SAST**: Static Application Security Testing via GitHub Actions
- 📚 **Documentation**: [Security Tools Guide](SECURITY-TOOLS.md) | [GitHub Actions CI](.github/workflows/ci.yml)

A Rust implementation of an **RFC 7030 compliant EST (Enrollment over Secure Transport) client** for automated X.509 certificate enrollment and management.

## Features

### Core EST Protocol (RFC 7030)

- ✅ **All Mandatory Operations**
  - `/cacerts` - Distribution of CA certificates
  - `/simpleenroll` - Simple certificate enrollment
  - `/simplereenroll` - Certificate re-enrollment

- ✅ **All Optional Operations**
  - `/csrattrs` - CSR attributes retrieval
  - `/serverkeygen` - Server-side key generation
  - `/fullcmc` - Full CMC support

- ✅ **Authentication Methods**
  - TLS client certificate authentication
  - HTTP Basic authentication fallback
  - Bootstrap/TOFU mode for initial CA discovery

### Advanced Features

- 🔄 **Automatic Certificate Renewal** - Background monitoring with configurable thresholds
- 🔒 **Hardware Security Module (HSM) Integration** - Trait-based abstraction for secure key storage
- ✅ **Certificate Chain Validation** - RFC 5280 path validation
- 📊 **Metrics and Monitoring** - Operation tracking and performance metrics
- 🚫 **Certificate Revocation** - CRL and OCSP support frameworks
- 🔐 **Encrypted Private Keys** - CMS EnvelopedData decryption

### Design Philosophy

- **Async-first**: Built on Tokio for high-performance async I/O
- **Type-safe**: Leverages Rust's type system for correctness
- **Modular**: Feature-gated components for minimal dependencies
- **Zero-copy**: Efficient memory usage where possible
- **Production-ready**: Comprehensive error handling and logging

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
usg-est-client = "0.1"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

### Basic Enrollment Example

```rust
use usg_est_client::{EstClient, EstClientConfig, EnrollmentResponse};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure the EST client
    let config = EstClientConfig::builder()
        .server_url("https://est.example.com")?
        .http_auth("username", "password")
        .build()?;

    // Create the client
    let client = EstClient::new(config).await?;

    // Get CA certificates
    let ca_certs = client.get_ca_certs().await?;
    println!("Retrieved {} CA certificate(s)", ca_certs.len());

    // Generate a CSR (requires csr-gen feature)
    #[cfg(feature = "csr-gen")]
    {
        use usg_est_client::csr::CsrBuilder;

        let (csr_der, key_pair) = CsrBuilder::new()
            .common_name("device.example.com")
            .organization("Example Corp")
            .san_dns("device.example.com")
            .build()?;

        // Enroll for a certificate
        match client.simple_enroll(&csr_der).await? {
            EnrollmentResponse::Issued { certificate } => {
                println!("Certificate issued successfully!");
                // Save certificate and key_pair
            }
            EnrollmentResponse::Pending { retry_after } => {
                println!("Enrollment pending, retry in {} seconds", retry_after);
            }
        }
    }

    Ok(())
}
```

### Bootstrap Mode (TOFU)

For initial CA discovery without pre-existing trust:

```rust
use usg_est_client::bootstrap::BootstrapClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bootstrap = BootstrapClient::new("https://est.example.com")?;

    // Fetch CA certificates without TLS verification
    let (ca_certs, fingerprints) = bootstrap.fetch_ca_certs().await?;

    // Display fingerprints for out-of-band verification
    for (i, fp) in fingerprints.iter().enumerate() {
        println!("CA {} SHA-256: {}", i, BootstrapClient::format_fingerprint(fp));
    }

    // After manual verification, use ca_certs to configure the main client
    Ok(())
}
```

### Automatic Certificate Renewal

```rust
use usg_est_client::renewal::{RenewalScheduler, RenewalConfig};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = EstClientConfig::builder()
        .server_url("https://est.example.com")?
        .build()?;

    let client = EstClient::new(config).await?;

    // Configure renewal: check daily, renew 30 days before expiration
    let renewal_config = RenewalConfig::builder()
        .renewal_threshold(Duration::from_secs(30 * 24 * 60 * 60)) // 30 days
        .check_interval(Duration::from_secs(24 * 60 * 60))         // Daily
        .max_retries(3)
        .build();

    let scheduler = RenewalScheduler::new(client, renewal_config);

    // Set certificate to monitor
    // scheduler.set_certificate(cert).await;

    // Start background monitoring
    // scheduler.start().await?;

    Ok(())
}
```

### Hardware Security Module (HSM) Integration

```rust
use usg_est_client::hsm::{SoftwareKeyProvider, KeyAlgorithm};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a key provider (software or HSM)
    let provider = SoftwareKeyProvider::new();

    // Generate a key pair in the provider
    let key_handle = provider
        .generate_key_pair(KeyAlgorithm::EcdsaP256, Some("device-key"))
        .await?;

    // Get the public key
    let public_key = provider.public_key(&key_handle).await?;

    // Sign data (private key never leaves the provider)
    let signature = provider.sign(&key_handle, b"data to sign").await?;

    Ok(())
}
```

## Feature Flags

Control which features are compiled into your application:

```toml
[dependencies]
usg-est-client = { version = "0.1", default-features = false, features = ["csr-gen", "renewal"] }
```

### Available Features

| Feature | Default | Description |
|---------|---------|-------------|
| `csr-gen` | ✅ | CSR generation helpers using rcgen |
| `hsm` | ❌ | Hardware Security Module trait abstractions |
| `renewal` | ❌ | Automatic certificate renewal scheduler |
| `validation` | ❌ | RFC 5280 certificate chain validation |
| `metrics` | ❌ | Operation metrics collection |
| `revocation` | ❌ | CRL and OCSP revocation checking |
| `enveloped` | ❌ | CMS EnvelopedData decryption |

## API Documentation

Full API documentation is available at [docs.rs/usg-est-client](https://docs.rs/usg-est-client).

### Core Types

- [`EstClient`](https://docs.rs/usg-est-client/latest/usg_est_client/struct.EstClient.html) - Main EST client
- [`EstClientConfig`](https://docs.rs/usg-est-client/latest/usg_est_client/struct.EstClientConfig.html) - Client configuration
- [`EnrollmentResponse`](https://docs.rs/usg-est-client/latest/usg_est_client/enum.EnrollmentResponse.html) - Enrollment result
- [`EstError`](https://docs.rs/usg-est-client/latest/usg_est_client/enum.EstError.html) - Error types

### Modules

- [`bootstrap`](https://docs.rs/usg-est-client/latest/usg_est_client/bootstrap/) - Bootstrap/TOFU mode
- [`csr`](https://docs.rs/usg-est-client/latest/usg_est_client/csr/) - CSR generation (with `csr-gen` feature)
- [`hsm`](https://docs.rs/usg-est-client/latest/usg_est_client/hsm/) - HSM integration (with `hsm` feature)
- [`renewal`](https://docs.rs/usg-est-client/latest/usg_est_client/renewal/) - Automatic renewal (with `renewal` feature)
- [`validation`](https://docs.rs/usg-est-client/latest/usg_est_client/validation/) - Certificate validation (with `validation` feature)
- [`metrics`](https://docs.rs/usg-est-client/latest/usg_est_client/metrics/) - Metrics collection (with `metrics` feature)

## RFC 7030 Compliance

This library implements all requirements from RFC 7030 (EST Protocol):

| Requirement | Section | Status |
|------------|---------|--------|
| TLS 1.2+ required | 3.3.1 | ✅ |
| Base64 Content-Transfer-Encoding | 4 | ✅ |
| `application/pkcs10` Content-Type | 4.2 | ✅ |
| `application/pkcs7-mime` responses | 4.1, 4.2 | ✅ |
| HTTP 202 + Retry-After | 4.2.3 | ✅ |
| Well-known URI paths | 3.2.2 | ✅ |
| Optional CA label segment | 3.2.2 | ✅ |
| Client certificate TLS auth | 3.3.2 | ✅ |
| HTTP Basic auth fallback | 3.2.3 | ✅ |
| PKCS#7 certs-only parsing | 4.1.3 | ✅ |
| CSR attributes (optional) | 4.5 | ✅ |
| Server key generation (optional) | 4.4 | ✅ |
| Full CMC (optional) | 4.3 | ✅ |
| Bootstrap/TOFU mode | 4.1.1 | ✅ |

## Testing

Run the test suite:

```bash
# Unit tests
cargo test

# All tests with all features
cargo test --all-features

# Integration tests
cargo test --test '*'

# Code coverage (requires tarpaulin)
cargo tarpaulin --all-features --out Html
```

**Current Test Coverage**: 55.82% (79 unit tests, 80 integration tests)

## Examples

See the [`examples/`](examples/) directory for complete working examples:

- `simple_enroll.rs` - Basic certificate enrollment
- `bootstrap.rs` - Bootstrap mode CA discovery
- `reenroll.rs` - Certificate re-enrollment
- `server_keygen.rs` - Server-side key generation
- `auto_renewal.rs` - Automatic certificate renewal (requires `renewal` feature)
- `check_revocation.rs` - Certificate revocation checking with CRL and OCSP (requires `revocation` feature)
- `hsm_enroll.rs` - Hardware Security Module integration (requires `hsm` and `csr-gen` features)

Run an example:

```bash
cargo run --example simple_enroll --features csr-gen
```

## Security Considerations

### TLS Configuration

- **TLS 1.2 minimum**: Enforced by default
- **Certificate validation**: Uses Mozilla's root certificates via `webpki-roots`
- **Client authentication**: Supports mutual TLS with client certificates

### Key Management

- **Private keys**: Never transmitted over the network
- **HSM support**: Private keys can remain in hardware security modules
- **Secure defaults**: Non-extractable keys, sensitive data cleared from memory

### Bootstrap Mode

⚠️ **Warning**: Bootstrap mode (`BootstrapClient`) performs **no TLS verification**. It should only be used for initial CA discovery with out-of-band fingerprint verification.

### Best Practices

1. Always verify CA certificate fingerprints when using bootstrap mode
2. Use client certificate authentication when available
3. Store private keys in HSMs for production deployments
4. Enable automatic certificate renewal to prevent expiration
5. Monitor metrics for enrollment failures and retry patterns

## Architecture

```text
┌─────────────────────────────────────────┐
│          EstClient (main API)           │
│  - simple_enroll()                      │
│  - simple_reenroll()                    │
│  - get_ca_certs()                       │
│  - server_keygen()                      │
└─────────────┬───────────────────────────┘
              │
     ┌────────┴────────┐
     ▼                 ▼
┌──────────┐    ┌──────────────┐
│   TLS    │    │   HTTP/REST  │
│ rustls   │    │   reqwest    │
└──────────┘    └──────────────┘
     │                 │
     └────────┬────────┘
              ▼
     ┌────────────────┐
     │  EST Server    │
     │  (RFC 7030)    │
     └────────────────┘
```

## Dependencies

Core dependencies (always included):

- `tokio` - Async runtime
- `reqwest` - HTTP client with rustls
- `rustls` - TLS implementation
- `x509-cert` - X.509 certificate parsing
- `der` - DER encoding/decoding
- `thiserror` - Error handling

Optional dependencies (feature-gated):

- `rcgen` - CSR generation (`csr-gen` feature)
- `async-trait` - Async trait support (`hsm` feature)

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development

```bash
# Format code
cargo fmt

# Lint
cargo clippy --all-features

# Run all checks
cargo check --all-features
cargo test --all-features
cargo doc --all-features --no-deps
```

## License

Licensed under the Apache License, Version 2.0 ([LICENSE](LICENSE) or <http://www.apache.org/licenses/LICENSE-2.0>).

### Copyright

Copyright 2025 U.S. Federal Government (in countries where recognized)

## Acknowledgments

This implementation follows RFC 7030 and incorporates best practices from:

- [RFC 7030](https://tools.ietf.org/html/rfc7030) - Enrollment over Secure Transport (EST)
- [RFC 5280](https://tools.ietf.org/html/rfc5280) - X.509 Public Key Infrastructure
- [RFC 2986](https://tools.ietf.org/html/rfc2986) - PKCS #10 Certification Request Syntax

Built with the excellent Rust cryptography ecosystem:

- [RustCrypto](https://github.com/RustCrypto) - Cryptographic algorithm implementations
- [rustls](https://github.com/rustls/rustls) - Modern TLS library

## Status

This project is under active development. See [ROADMAP.md](ROADMAP.md) for planned features and [CHANGELOG.md](CHANGELOG.md) for version history.

**Current Version**: 0.1.0 (Development)

**Stability**: Core EST operations are stable and production-ready. Advanced features (HSM, renewal, metrics) have framework implementations ready for production completion.

## Support

- 📖 [Documentation](https://docs.rs/usg-est-client)
- 🐛 [Issue Tracker](https://github.com/192d-Wing/usg-est-client/issues)
- 💬 [Discussions](https://github.com/192d-Wing/usg-est-client/discussions)

---

### Made with Rust

Built with ❤️ and the Rust ecosystem.
