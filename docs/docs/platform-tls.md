# Platform-Specific TLS Configuration

This document describes the TLS backend options available in `usg-est-client` and when to use each.

## Default: rustls (Recommended)

By default, `usg-est-client` uses [rustls](https://github.com/rustls/rustls), a modern TLS library written entirely in Rust.

```toml
[dependencies]
usg-est-client = "0.1"
```

### Advantages

| Benefit | Description |
|---------|-------------|
| **Memory Safety** | Pure Rust implementation, no C code vulnerabilities |
| **Performance** | Often faster than OpenSSL, especially with aws-lc-rs backend |
| **Portability** | No system dependencies, works consistently across platforms |
| **Static Linking** | Easy to create fully static binaries |
| **Security by Default** | Modern TLS 1.2/1.3 only, no legacy protocols |

### Disadvantages

| Limitation | Description |
|------------|-------------|
| **Certificate Store** | Doesn't use OS certificate store by default |
| **FIPS Compliance** | Not FIPS 140-2 certified (use native-tls for FIPS) |

## Alternative: native-tls

The `native-tls-backend` feature uses the operating system's TLS implementation:

| Platform | TLS Library |
|----------|-------------|
| Windows | SChannel |
| macOS | Security.framework |
| Linux | OpenSSL |

```toml
[dependencies]
usg-est-client = { version = "0.1", features = ["native-tls-backend"] }
```

### When to Use native-tls

1. **FIPS Compliance Required**: OS-provided TLS may be FIPS certified
2. **Enterprise Certificate Management**: Need OS certificate store integration
3. **Regulatory Requirements**: Must use government-approved TLS implementation
4. **Legacy Compatibility**: Need to support older TLS configurations

### Platform-Specific Behavior

#### Windows (SChannel)

- Uses Windows Certificate Store automatically
- Integrates with Active Directory certificate management
- Supports smart card authentication
- FIPS mode available via Windows Group Policy

#### macOS (Security.framework)

- Uses macOS Keychain for certificates
- Integrates with Apple's security infrastructure
- Automatic certificate trust management

#### Linux (OpenSSL)

- Requires OpenSSL development headers at build time
- Uses system CA certificates from `/etc/ssl/certs/`
- Version depends on system OpenSSL installation

## Vendored OpenSSL (Linux Static Builds)

For Linux deployments where OpenSSL may not be available (Alpine, musl, AWS Lambda), use vendored OpenSSL:

```toml
[dependencies]
usg-est-client = { version = "0.1", features = ["native-tls-vendored"] }
```

This compiles OpenSSL from source and statically links it, eliminating runtime dependencies.

### Build Requirements

```bash
# Debian/Ubuntu
sudo apt-get install build-essential perl

# Alpine
apk add build-base perl

# RHEL/CentOS
sudo yum groupinstall "Development Tools"
sudo yum install perl
```

### Use Cases

- AWS Lambda deployments
- Alpine/musl-based containers
- Fully static binaries
- Air-gapped environments

## Feature Comparison

| Feature | rustls (default) | native-tls | native-tls-vendored |
|---------|------------------|------------|---------------------|
| TLS 1.2 | ✅ | ✅ | ✅ |
| TLS 1.3 | ✅ | Platform-dependent | Platform-dependent |
| Memory Safe | ✅ | ❌ | ❌ |
| OS Cert Store | ❌ (manual) | ✅ | ✅ |
| FIPS Available | ❌ | ✅ (platform) | ✅ |
| Static Linking | ✅ Easy | ⚠️ Complex | ✅ |
| Build Dependencies | None | OpenSSL headers | Build tools + Perl |
| Binary Size | Smaller | Larger | Larger |

## Certificate Trust Configuration

### With rustls (Default)

rustls uses Mozilla's root certificates by default via `webpki-roots`:

```rust
let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    // Uses Mozilla root CAs by default
    .build()?;
```

To use custom CA certificates:

```rust
let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .explicit_trust_anchor_pem(&ca_pem)?
    .build()?;
```

### With native-tls

native-tls automatically uses the OS certificate store. Additional CAs can still be added:

```rust
let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    // Also trusts OS certificates when native-tls-backend is enabled
    .explicit_trust_anchor_pem(&additional_ca_pem)?
    .build()?;
```

## Performance Considerations

### Benchmarks (Approximate)

| Operation | rustls | OpenSSL (native-tls) |
|-----------|--------|----------------------|
| Handshake | Faster | Baseline |
| Bulk Transfer | Similar | Similar |
| Memory Usage | Lower | Higher |
| Startup Time | Faster | Slower (library load) |

**Note**: Actual performance varies by platform, OpenSSL version, and workload.

### Recommendations

| Deployment | Recommended Backend |
|------------|---------------------|
| General use | rustls (default) |
| FIPS required | native-tls |
| Windows enterprise | native-tls |
| Container/serverless | rustls or native-tls-vendored |
| Embedded/IoT | rustls |

## Troubleshooting

### OpenSSL Not Found (Linux)

```
error: failed to run custom build command for `openssl-sys`
```

**Solution**: Install OpenSSL development headers:

```bash
# Debian/Ubuntu
sudo apt-get install libssl-dev

# RHEL/CentOS
sudo yum install openssl-devel

# Alpine
apk add openssl-dev
```

Or use `native-tls-vendored` to compile OpenSSL from source.

### Certificate Verification Failures

If certificates work with one backend but not another:

1. **rustls**: Check that CA is in the explicit trust anchors or Mozilla roots
2. **native-tls**: Verify certificate is in OS certificate store

### TLS Version Issues

If connecting to legacy servers requiring old TLS versions:

- rustls only supports TLS 1.2 and 1.3
- native-tls may support TLS 1.0/1.1 depending on OS configuration

**Note**: EST (RFC 7030) requires TLS 1.2 minimum, so this shouldn't affect EST operations.

## Security Considerations

1. **Prefer rustls** for new deployments unless specific requirements mandate native-tls
2. **Keep dependencies updated** - both rustls and OpenSSL receive security updates
3. **Use explicit trust anchors** for EST server connections when possible
4. **Avoid TLS 1.0/1.1** - EST requires TLS 1.2+ anyway

## References

- [rustls GitHub](https://github.com/rustls/rustls)
- [Rustls Performance (Prossimo)](https://www.memorysafety.org/blog/rustls-performance/)
- [reqwest TLS documentation](https://docs.rs/reqwest/latest/reqwest/tls/index.html)
- [native-tls crate](https://docs.rs/native-tls/)
