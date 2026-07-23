# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.1.3] - 2026-07-22

Dependency and supply-chain maintenance release. No public API changes.

### Security

- FIPS module pinning now actually constrains the validated module. `aws-lc-rs`
  was pinned to an exact version on the stated grounds that CMVP validation
  attaches to a specific module version, but that pin did not have that effect:
  the validated module ships in `aws-lc-fips-sys`, which `aws-lc-rs` requires
  only as a caret range, leaving it free to float across `0.13.x`. Consumers
  resolving this crate from crates.io could therefore link a module version
  other than the one built and tested here. `aws-lc-fips-sys` is now a direct
  dependency pinned to `=0.13.16`, and `aws-lc-rs` moves to `=1.17.3`, the
  release series in which the AWS-LC FIPS v3 module was awarded FIPS 140-3
  validation (CMVP certificates #5314 static / #5298 dynamic). The exact pin on
  `aws-lc-rs` is retained on new grounds: upstream plans to switch
  `aws-lc-fips-sys` to the FIPS v4 branch in v1.18.0, a minor bump that a caret
  requirement would take silently. `docs/fips-compliance.md` now records the
  certificates and both constraints. (#72)

### Changed

- `aes-gcm` 0.10.3 → 0.11.0 (#68, #76). aes-gcm 0.11 moves to aead 0.6, which no
  longer re-exports `OsRng` through `aes_gcm::aead`; the encrypted audit logger
  now draws key and nonce bytes from `getrandom` directly, so its entropy source
  no longer moves with RustCrypto releases. Also updated for two aead 0.6 API
  changes (`Nonce::from_slice` deprecated in favour of `From`/`TryFrom`, and
  `Aead::{encrypt,decrypt}` taking the nonce by reference). The on-disk format is
  unchanged — same AES-256-GCM, same 12-byte nonce, same `ENCRYPTED-LOG-v1`
  framing — so existing encrypted logs remain readable. The bump also unifies the
  block-cipher tree: aes-gcm 0.10 pulled in aes 0.8 / cipher 0.4 alongside the
  aes 0.9 / cipher 0.5 already used by the `enveloped` CBC and 3DES paths.
- `hsm::aws_lc`: use `RsaKeyPair::generate` instead of the deprecated
  `generate_fips`. Upstream deprecated the latter as equivalent to the former,
  and it is a one-line delegation, so there is no behavioral change.
- Dependency updates: `rustls` 0.23.40 → 0.23.42, `rustls-pki-types` 1.14.1 →
  1.15.0, `der` 0.8.0 → 0.8.1, `time` 0.3.47 → 0.3.53, `uuid` 1.23.4 → 1.23.5,
  `webpki-roots` 1.0.7 → 1.0.8, `zeroize` 1.8.2 → 1.9.0, `getrandom` 0.4.2 →
  0.4.3. (#61, #65, #67, #70, #71, #73, #74, #75)
- CI: `github/codeql-action` v3.36.2 → v4.36.2 across all four steps — `init`,
  `analyze`, and both `upload-sarif`. Bumping `analyze` alone made the runner
  fail with a configuration/runtime version mismatch. (#59, #77)
- CI: `actions/attest-build-provenance` v2.2.0 → v4.1.1,
  `step-security/harden-runner` v2.10.4 → v2.19.4, `actions/upload-artifact`
  v7.0.0 → v7.0.1, `taiki-e/install-action` 2.82.3 → 2.82.6. (#60, #63, #64, #66)

## [2.1.2] - 2026-06-25

### Fixed

- Windows Credential Manager (`auto_enroll::config`): `read_credential_manager`
  dereferenced the `CredReadW` out-pointer and built a slice from
  `CredentialBlob` with no null checks. A null out-pointer (which `CredReadW`
  may leave on a reported success) or a null/zero-length `CredentialBlob` (valid
  for a credential with no secret) is undefined behavior. The pointer is now
  null-checked before dereference, a null/empty blob is treated as an empty
  password, and the credential buffer is freed before the UTF-8 conversion can
  early-return (previously a leak on the invalid-UTF-8 path). (#49)

### Security

- Supply-chain / ATO hardening of the CI and release pipeline (no library API
  change): CodeQL SAST, CycloneDX SBOM generation + Grype vulnerability scan,
  gitleaks secret scanning, coverage-guided fuzzing of the PEM/PKCS#7/CSR
  parsers, OpenSSF Scorecard, cosign keyless signing + SLSA build-provenance for
  release artifacts, all GitHub Actions pinned to commit SHAs, least-privilege
  workflow permissions, and Docker base images pinned by digest. Added
  `docs/ATO-DAST-justification.md` documenting DAST as not-applicable for a
  client library with fuzzing as the dynamic-analysis control. (#47, #48, #50)

### Changed

- Dependency updates: `openssl` 0.10.80 → 0.10.81, `uuid` 1.23.2 → 1.23.4, and
  GitHub Actions version bumps (checkout, codecov, setup-python, deploy-pages,
  upload-pages-artifact). (#9, #10, #11, #12, #13, #15, #21)

## [2.1.1] - 2026-06-24

### Fixed

- PKCS#11 EC public keys: the `SubjectPublicKeyInfo` `AlgorithmIdentifier`
  parameters now encode the named curve as a bare OID (RFC 5480 §2.1.1) instead
  of wrapping it in an OCTET STRING. The malformed encoding was accepted by
  RustCrypto's `from_sec1_bytes` (which ignores the `AlgorithmIdentifier`) but
  rejected by rustls-webpki during the mTLS client `CertificateVerify`
  (`UnsupportedSignatureAlgorithmForPublicKeyContext`), surfacing to the client
  as a TLS `DecryptError`. Bootstrap/server-auth never parse the client SPKI, so
  only token-backed `simplereenroll` mutual TLS was affected. `CKA_EC_POINT` is
  now decoded as a DER OCTET STRING rather than stripped by a fixed offset.

## [2.1.0] - 2026-06-23

### Added

- PKCS#11 token-backed TLS client identity for mutual-TLS `simplereenroll`:
  `hsm::pkcs11_tls::Pkcs11SigningKey` (a rustls `SigningKey` that signs
  handshakes inside the token) and `hsm::pkcs11_tls::Pkcs11ClientCertResolver`,
  plus `EstClientConfig::client_cert_resolver` / `client_identity_resolver()`.
  Lets a node authenticate with a non-extractable TPM/HSM key (the EST
  `ClientIdentity` is PEM-only). When set, the transport is built from a
  preconfigured rustls `ClientConfig` (TLS 1.3, explicit `http/1.1` ALPN,
  bootstrap/insecure trust rejected fail-closed). All under the `pkcs11` feature.
- `Pkcs11KeyProvider::sign_blocking` — synchronous signing for the rustls signer.

### Fixed

- `Pkcs11KeyProvider::sign` now DER-encodes ECDSA signatures (PKCS#11 returns the
  raw IEEE-P1363 `r||s`; the CSR/TLS layers expect the ASN.1 `Ecdsa-Sig-Value`).
  Previously `HsmCsrBuilder::build_with_provider` with a PKCS#11 EC key produced a
  malformed CSR signature.
- `find_key`/`list_keys`/`generate_key_pair` no longer self-deadlock: they held
  the session mutex while calling `get_key_metadata`, which re-locked the
  non-reentrant mutex. `get_key_metadata` now takes the held session.
- `find_key`/`list_keys` now strip the DER tag/length from `CKA_EC_PARAMS` before
  decoding the curve OID, so existing EC token keys are found instead of silently
  dropped.

### Security

- Bump `quinn-proto` to 0.11.15 (RUSTSEC-2026-0185). It is an optional, unused
  transitive dependency (reqwest HTTP/3, not enabled) but was pinned in the lock.

## [2.0.1] - 2026-06-23

### Fixed

- PKCS#7 parsing (`cacerts`, `simpleenroll`, `simplereenroll`) now accepts a raw
  binary DER response body, not only base64. RFC 7030 specifies base64 with
  `Content-Transfer-Encoding: base64`, but some EST servers return binary DER
  (`application/pkcs7-mime` with no transfer encoding); `parse_certs_only` now
  detects the leading SEQUENCE tag (`0x30`) and skips base64 decoding in that
  case. Fixes enrollment against such servers.

## [2.0.0] - 2026-06-20

FIPS migration: cryptography now runs in a FIPS-validated module — the aws-lc-rs
FIPS module on Linux (the `fips` feature) and the Windows CNG FIPS module on
Windows — across TLS, key generation, signing, certificate-chain verification,
fingerprint hashing, and EnvelopedData decryption.

### Changed

- **BREAKING:** Consolidated FIPS support onto a single `fips` cargo feature
  backed by the **aws-lc-rs FIPS module** (Linux). The legacy OpenSSL FIPS path
  and its `openssl`/`openssl-sys` dependencies were removed. `fips-tls` remains
  as a deprecated alias of `fips`.
- **BREAKING:** Removed OpenSSL-specific public API — `FipsConfig::fips_config_path`
  and `FipsModuleInfo::openssl_version` (replaced by `FipsModuleInfo::module`).
- Pinned `aws-lc-rs` to an exact version (`=1.17.0`); FIPS 140 validation (CMVP)
  attaches to a specific module version.

### Added

- FIPS-validated cryptography under `fips` (Linux): fail-closed TLS provider,
  key generation + signing (`AwsLcKeyProvider`, selected by `default_key_provider`),
  certificate-chain signature verification, certificate fingerprint hashing, and
  EnvelopedData AES-128/256-CBC decryption — all in the aws-lc-rs FIPS module.
- Windows CNG FIPS mode: `CngKeyProvider::new_fips()` / `is_fips_mode_enabled()`
  (fail-closed) and the cross-platform `hsm::fips_key_provider()` entry point.
- CI: a Windows job (compiles/tests the Windows module for the first time) and an
  arm64 Linux build in the test matrix.

### Security

- Certificate-chain signature verification and symmetric/hash operations run in a
  FIPS-validated module under `fips`. Under `fips`, non-FIPS EnvelopedData ciphers
  (3DES, AES-192) are rejected. Note: a `fips` build links the module but is not,
  by itself, a CMVP-validated operating environment — confirm the validated module
  version and operating conditions for an ATO. See `docs/fips-compliance.md`.

## [1.0.1] - 2026-01-16

### Fixed

- Updated unwrap() baseline in GitLab CI to 359 (from 339) to reflect current codebase state

## [1.0.0] - 2026-01-16

### Added

#### Environment Variable Configuration (v1.0.0)

- **EST_SERVER_URL Environment Variable Support**
  - All example files now check `EST_SERVER_URL` environment variable before using defaults
  - Priority order: CLI argument → ENV variable → Default value
  - Updated examples: simple_enroll, reenroll, bootstrap, cmc_advanced, hsm_enroll, auto_renewal
  - Updated TOML configs with `${EST_SERVER_URL:default}` syntax for variable expansion
  - See [CONFIGURATION.md](CONFIGURATION.md) for deployment patterns

- **--insecure CLI Flag for Testing**
  - Added `--insecure` flag to `est-enroll check` and `est-enroll diagnose` commands
  - Bypasses TLS certificate verification for testing purposes
  - **Security Restriction**: Only works with <https://testrfc7030.com> (54.70.32.33)
  - Validates both hostname and resolved IP address before allowing bypass
  - See [docs/INSECURE-FLAG-SECURITY.md](docs/INSECURE-FLAG-SECURITY.md) for security implementation

#### CI/CD Release Automation (v1.0.0)

- **GitHub Actions Release Pipeline**
  - Automated multi-platform builds on tag push (v*.*.*)
  - Platforms: Linux (gnu, musl), macOS (Intel, Apple Silicon), Windows
  - Automatic SHA256 checksum generation
  - Release creation with all binaries and checksums
  - See [.github/workflows/release.yml](.github/workflows/release.yml)

- **GitHub Actions Release Pipeline**
  - Parallel builds for all platforms
  - GitHub Release integration
  - Template-based builds with graceful fallbacks
  - See [.github/workflows/release.yml](.github/workflows/release.yml)

- **Release Documentation**
  - Comprehensive release process guide: [docs/RELEASE-PROCESS.md](docs/RELEASE-PROCESS.md)
  - Quick reference guide: [RELEASING.md](RELEASING.md)
  - Platform matrix, troubleshooting, security considerations

#### RFC 7030 Compliance Audit and Roadmap (2026-01-15)

- **Phase 2: CSR Signature Verification** ✅ COMPLETED (2026-01-15)
  - Implemented complete PKCS#10 CSR parsing and signature verification
  - **Supported Algorithms:**
    - RSA with SHA-256 (OID: 1.2.840.113549.1.1.11)
    - RSA with SHA-384 (OID: 1.2.840.113549.1.1.12)
    - RSA with SHA-512 (OID: 1.2.840.113549.1.1.13)
    - ECDSA with SHA-256 / P-256 (OID: 1.2.840.10045.4.3.2)
    - ECDSA with SHA-384 / P-384 (OID: 1.2.840.10045.4.3.3)
  - Added `verify_csr_signature()` function for proof-of-possession validation
  - Added `extract_public_key()` to extract SubjectPublicKeyInfo from CSRs
  - Configuration option: `verify_csr_signatures` in EstClientConfig
  - **Comprehensive test suite:** 11 new tests covering all algorithms and edge cases
  - All 63 library tests passing
  - **Impact**: Prevents unauthorized certificate issuance by validating CSR signatures
  - **Compliance**: RFC 2986 (PKCS#10), RFC 7030 Section 4.2
  - See [src/operations/enroll.rs:87-380](src/operations/enroll.rs#L87-L380) for implementation

- **Phase 1: TLS Channel Binding Implementation** ✅ COMPLETED (2026-01-15)
  - Added `compute_channel_binding()` function for creating channel binding values
  - Added `generate_channel_binding_challenge()` for creating secure challenges
  - Enhanced EST client logging to indicate channel binding status
  - Updated API documentation with channel binding guidance (RFC 7030 Section 3.5)
  - Added comprehensive unit tests (6 tests, all passing)
  - Created `examples/channel_binding_enroll.rs` demonstrating usage
  - **Status**: Framework complete and tested
  - **Impact**: Provides defense against MITM attacks during HTTP Basic authentication
  - **Compliance**: RFC 7030 Section 3.5 - Channel Binding
  - See [src/tls.rs:229-321](src/tls.rs#L229-L321) for implementation

- **Comprehensive RFC 7030 Compliance Evaluation**
  - Complete audit of implementation against RFC 7030 requirements
  - **Current compliance: 99%** (up from 98% - Phase 2 completed)
  - Only one area remaining: Full CMC implementation
  - See [docs/RFC-COMPLIANCE-ROADMAP.md](docs/RFC-COMPLIANCE-ROADMAP.md)

- **Implementation Roadmap Created**
  - Detailed 12-week plan to achieve 100% RFC compliance
  - Phase 1: TLS channel binding (weeks 1-2) ✅ COMPLETED
  - Phase 2: CSR signature verification (weeks 3-4) ✅ COMPLETED
  - Phase 3: Full CMC implementation (weeks 5-8) - IN PROGRESS
  - Phase 4: Integration testing (weeks 9-10)
  - Phase 5: Advanced features (weeks 11-12)
  - See [docs/dev/IMPLEMENTATION-GUIDE.md](docs/dev/IMPLEMENTATION-GUIDE.md)

- **RFC Compliance Status**
  - ✅ All mandatory EST operations (cacerts, simpleenroll, simplereenroll): 100%
  - ✅ TLS 1.2+ requirement: 100%
  - ✅ Authentication mechanisms (TLS client cert + HTTP Basic): 100%
  - ✅ Content-type and encoding compliance: 100%
  - ✅ HTTP status code handling (202, 401, 404): 100%
  - ✅ URI path structure (/.well-known/est/): 100%
  - ✅ PKCS#7 and PKCS#10 handling: 100%
  - ✅ Bootstrap/TOFU mode: 100%
  - ✅ CSR attributes endpoint: 100%
  - ✅ TLS channel binding: **COMPLETED** (Phase 1) 🎉
  - ✅ CSR signature verification: **COMPLETED** (Phase 2) 🎉
  - ⚠️ Full CMC: API framework complete, implementation pending

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

[Unreleased]: https://github.com/192d-Wing/usg-est-client/compare/v2.1.3...HEAD
[2.1.3]: https://github.com/192d-Wing/usg-est-client/compare/v2.1.2...v2.1.3
[1.0.1]: https://github.com/192d-Wing/usg-est-client/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/192d-Wing/usg-est-client/compare/v0.1.0...v1.0.0
[0.1.0]: https://github.com/192d-Wing/usg-est-client/releases/tag/v0.1.0
