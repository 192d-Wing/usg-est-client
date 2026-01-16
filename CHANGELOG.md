# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Windows CNG Integration (2026-01-15)

- **Complete Windows CNG KeyProvider Implementation** (`windows-service` feature)
  - `CngKeyProvider::public_key()` - Export public keys from CNG to SPKI format
    - Supports BCRYPT_ECCPUBLIC_BLOB → SPKI conversion for ECDSA keys
    - Supports BCRYPT_RSAPUBLIC_BLOB → SPKI conversion for RSA keys
    - Proper ASN.1 DER encoding with algorithm identifiers
  - `CngKeyProvider::sign()` - Sign data using CNG keys
    - BCrypt hash APIs for SHA-256 and SHA-384
    - NCryptSignHash for signing operations
    - ECDSA raw (r,s) to DER format conversion
    - RSA PKCS#1 v1.5 signature support
  - `CngKeyProvider::delete_key()` - Clean up CNG key containers
    - Proper key container deletion using NCryptDeleteKey
    - Resource cleanup and error handling
  - Helper functions for blob conversion and signature formatting
  - See [src/windows/cng.rs](src/windows/cng.rs)
  - **Impact**: Enables full Windows enrollment workflow with CNG-backed keys
  - **Unblocks**: Auto-enrollment service, Windows Certificate Store integration

#### Auto-Enrollment Configuration System (Phase 11.1)

- **TOML Configuration File System** (`auto-enroll` feature)
  - `AutoEnrollConfig` struct with comprehensive schema for machine enrollment
  - Server, trust, authentication, certificate, renewal, storage, logging, service sections
  - Variable expansion support (`${COMPUTERNAME}`, `${USERDNSDOMAIN}`, etc.)
  - Cross-platform config file discovery with precedence rules
  - `ConfigLoader` with builder pattern for customization
  - See [src/auto_enroll/](src/auto_enroll/)

- **JSON Schema for IDE Support**
  - Full JSON Schema Draft-07 specification for configuration files
  - Enables IntelliSense and validation in VS Code, IntelliJ, etc.
  - See [schema/est-config.schema.json](schema/est-config.schema.json)

- **Example Configuration Files**
  - `examples/config/machine-cert.toml` - Basic machine certificate enrollment
  - `examples/config/workstation.toml` - Domain workstation with auto-renewal
  - `examples/config/server.toml` - Server certificate with multiple SANs
  - `examples/config/kiosk.toml` - Minimal config for embedded devices

- **Windows Enrollment Documentation**
  - Comprehensive configuration guide in [docs/windows-enrollment.md](docs/windows-enrollment.md)
  - Variable expansion reference, deployment scenarios, security considerations

#### HSM and PKCS#11 Support (Phase 10.2.3-10.2.4)

- **Hardware Security Module Integration** (`hsm` feature)
  - `KeyProvider` trait for abstracting key storage
  - `SoftwareKeyProvider` for in-memory keys (dev/test)
  - Key generation, signing, listing, and deletion operations
  - See [src/hsm/mod.rs](src/hsm/mod.rs)

- **PKCS#11 Support** (`pkcs11` feature)
  - `Pkcs11KeyProvider` for hardware HSM integration
  - Support for SoftHSM, YubiHSM 2, AWS CloudHSM
  - ECDSA P-256/P-384 and RSA 2048/3072/4096 key algorithms
  - Automatic slot discovery or explicit slot selection
  - See [src/hsm/pkcs11.rs](src/hsm/pkcs11.rs)

#### Full CMC Implementation (Phase 10.2.6)

- **Complete CMC Protocol Support**
  - RFC 5272/5273/5274 compliant implementation
  - `PkiDataBuilder` fluent API for constructing requests
  - All CMC control attributes (transactionId, nonces, identification)
  - Batch operations with `BatchRequest`/`BatchResponse`
  - All status codes and failure info types
  - See [src/types/cmc_full.rs](src/types/cmc_full.rs)

#### Metrics Export (Phase 10.2.8)

- **Prometheus/OpenTelemetry Integration** (`metrics-prometheus` feature)
  - `PrometheusExporter` for Prometheus format output
  - `OpenTelemetryExporter` for OpenTelemetry metrics
  - See [src/metrics/prometheus.rs](src/metrics/prometheus.rs)

#### Core EST Operations (Phase 1-9)

- RFC 7030 compliant EST client implementation
- All mandatory EST operations: `/cacerts`, `/simpleenroll`, `/simplereenroll`
- Optional EST operations: `/csrattrs`, `/serverkeygen`, `/fullcmc`
- TLS client certificate authentication
- HTTP Basic authentication fallback
- Bootstrap/TOFU mode for initial CA discovery
- Comprehensive error handling and retry logic
- CSR generation helpers (feature-gated with `csr-gen`)

#### Advanced Features (Phase 10.2)

- **Automatic Certificate Renewal** (`renewal` feature)
  - `RenewalScheduler` for background certificate expiration monitoring
  - Configurable renewal thresholds and check intervals
  - Exponential backoff retry logic for failed renewals
  - Event callback system for extensibility
  - See [src/renewal.rs](src/renewal.rs)

- **Certificate Chain Validation** (`validation` feature)
  - RFC 5280 certificate path validation
  - Chain building from end-entity to root CA
  - Trust anchor verification
  - Basic constraints and validity period checking
  - See [src/validation.rs](src/validation.rs)

- **Metrics and Monitoring** (`metrics` feature)
  - Thread-safe metrics collection for EST operations
  - Operation counters (total, success, failed)
  - Duration histograms (min, max, average)
  - TLS handshake metrics
  - Success rate calculations
  - Ready for Prometheus/OpenTelemetry integration
  - See [src/metrics.rs](src/metrics.rs)

- **Certificate Revocation Checking** (`revocation` feature)
  - RevocationChecker with CRL and OCSP support frameworks
  - CRL caching with configurable refresh duration
  - Revocation status checking API
  - Distribution point and OCSP responder URL extraction
  - See [src/revocation.rs](src/revocation.rs)

- **Encrypted Private Key Decryption** (`enveloped` feature)
  - CMS EnvelopedData parsing framework
  - Multi-algorithm support (AES-128/192/256, 3DES-CBC)
  - DecryptionKey validation
  - Support for server-side key generation with encryption
  - See [src/enveloped.rs](src/enveloped.rs)

#### Integration Testing (Phase 10.1)

- Integration tests with wiremock for all EST operations
- Mock EST server test fixtures
- Authentication testing (TLS client cert, HTTP Basic)
- Error handling and retry logic tests
- Code coverage: 55.82% (from initial 26.21%)

### Changed

- License changed from AGPL-3.0 to Apache-2.0
- ROADMAP reorganized: moved SCEP protocol support to "Possible Future Enhancements"
- All new modules are feature-gated for minimal default footprint

### Fixed

- Floating point precision in metrics tests
- Unused import warnings in validation and metrics modules
- Test data length validation in enveloped module
- Clippy warnings for `--all-targets` compilation
  - Added `required-features` for feature-gated examples in Cargo.toml
  - Fixed unused imports with proper `#[cfg]` guards
  - Converted nested `if` statements to Edition 2024 let-chain syntax
  - Added `clap` dev-dependency for pkcs11_enroll example

### Security

- All advanced feature modules include Apache 2.0 license headers
- CMS EnvelopedData decryption framework (implementation pending)
- Certificate revocation checking framework (CRL/OCSP parsing pending)

## [0.1.0] - Initial Development

### Project Setup

- Initial project structure
- Core EST client implementation
- Bootstrap mode support
- Basic documentation

---

## Compliance Status

### RFC 7030 (EST Protocol)

- ✅ All mandatory operations implemented
- ✅ All optional operations implemented
- ✅ TLS 1.2+ requirement met
- ✅ Client certificate authentication
- ✅ HTTP Basic authentication
- ✅ Bootstrap/TOFU mode

### Test Coverage

- 56 unit tests (all passing)
- Integration tests for all operations
- 55.82% code coverage

### Feature Flags

- `csr-gen` (default) - CSR generation with rcgen
- `hsm` - Hardware Security Module trait abstraction
- `pkcs11` - PKCS#11 HSM integration (includes `hsm`)
- `renewal` - Automatic certificate renewal
- `validation` - RFC 5280 certificate chain validation
- `metrics` - EST operation metrics collection
- `metrics-prometheus` - Prometheus/OpenTelemetry exporters (includes `metrics`)
- `revocation` - CRL and OCSP revocation checking
- `enveloped` - CMS EnvelopedData decryption
- `auto-enroll` - TOML configuration file system for auto-enrollment

---

[Unreleased]: https://github.com/johnwillman/usg-est-client/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/johnwillman/usg-est-client/releases/tag/v0.1.0
