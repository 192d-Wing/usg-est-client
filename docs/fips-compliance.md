# FIPS 140 Compliance Guide

This guide documents the FIPS 140 (Federal Information Processing Standard) compliance features of the usg-est-client for deployment on Department of Defense (DoD) networks.

> **Status / accuracy note.** The crate's FIPS cryptography is provided by the
> **aws-lc-rs FIPS module** on Linux (the `fips` feature) and the **Windows CNG
> FIPS module** on Windows (`CngKeyProvider::new_fips`). The earlier OpenSSL FIPS
> path has been removed. Building with `fips` links a FIPS module but is **not, by
> itself, a CMVP-validated operating environment**: FIPS 140 validation attaches
> to a specific module version operated per its Security Policy. The `aws-lc-rs`
> dependency is pinned to an exact version (`=1.17.0`) so the build cannot roll
> forward off a validated version; confirm the exact CMVP-validated version and
> operating conditions before relying on this for an ATO. Sections below that
> still describe OpenSSL `openssl.cnf` setup are retained for historical reference
> and are slated for rewrite.

## Table of Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [FIPS Module Setup](#fips-module-setup)
- [Configuration](#configuration)
- [Algorithm Enforcement](#algorithm-enforcement)
- [Testing and Validation](#testing-and-validation)
- [Troubleshooting](#troubleshooting)
- [References](#references)

## Overview

FIPS 140-2 is a U.S. government computer security standard that specifies security requirements for cryptographic modules. For DoD deployment, systems must use FIPS 140-2 validated cryptographic modules.

### What is FIPS Mode?

When FIPS mode is enabled, the EST client:

- Uses the aws-lc-rs FIPS module (Linux) or Windows CNG FIPS module as the
  crypto provider for TLS and PKI operations
- Enforces FIPS-approved algorithms only
- Blocks non-FIPS algorithms (3DES, DES, MD5, SHA-1, RC4, etc.)
- Validates minimum key sizes (RSA ≥2048 bits, ECC ≥256 bits)
- Installs the FIPS rustls provider fail-closed (errors if not in FIPS mode)
- Requires TLS 1.2 minimum (TLS 1.3 recommended)

### FIPS-Approved Algorithms

#### Symmetric Encryption
- AES-128-CBC, AES-192-CBC, AES-256-CBC
- AES-128-GCM, AES-192-GCM, AES-256-GCM (authenticated encryption)

#### Asymmetric Encryption
- RSA 2048-bit, 3072-bit, 4096-bit
- ECDSA P-256 (secp256r1)
- ECDSA P-384 (secp384r1)
- ECDSA P-521 (secp521r1)

#### Hash Functions
- SHA-256, SHA-384, SHA-512, SHA-512/256

#### Key Derivation
- PBKDF2 with HMAC-SHA-256
- HKDF with HMAC-SHA-256

#### Message Authentication
- HMAC-SHA-256, HMAC-SHA-384, HMAC-SHA-512

### Blocked Algorithms

The following algorithms are **NOT** FIPS-approved and will be rejected:

- 3DES (deprecated)
- DES (deprecated)
- MD5 (cryptographically broken)
- SHA-1 (deprecated for digital signatures)
- RC4, RC2 (cryptographically broken)
- RSA < 2048 bits
- ECC < 256 bits

## Requirements

### System Requirements

- **Linux** (x86_64/aarch64) to build the aws-lc-rs FIPS module via the `fips`
  feature; build deps Go and cmake. On **Windows**, FIPS comes from the CNG FIPS
  module under the system FIPS policy (no `fips` feature).
- Rust 1.92+ (Edition 2024)

### FIPS cryptographic module

- **Linux:** aws-lc-rs FIPS module (`aws-lc-fips-sys`), pinned to an exact version.
- **Windows:** Microsoft CNG FIPS module under the "System cryptography: Use FIPS
  compliant algorithms" policy.

FIPS 140 validation (CMVP) attaches to a specific module version. Confirm the
exact CMVP-validated version for your platform before an ATO.

See: https://csrc.nist.gov/projects/cryptographic-module-validation-program

### Cargo Features

Enable the `fips` feature in your `Cargo.toml`:

```toml
[dependencies]
usg-est-client = { version = "0.1", features = ["fips"] }
```

Or build with the feature flag:

```bash
cargo build --features fips
cargo test --features fips
```

## FIPS Module Setup

FIPS cryptography is provided by the crypto module the crate is built/run
against. There is **no separate OpenSSL FIPS provider to install** — the Linux
path statically links the aws-lc-rs FIPS module at build time, and the Windows
path uses the operating system's CNG FIPS module under the system security
policy.

### Linux (aws-lc-rs FIPS)

The `fips` feature links the aws-lc-rs FIPS module (`aws-lc-fips-sys`), which is
built from source at compile time and self-tests at startup. No system-wide FIPS
configuration is required.

1. **Install build dependencies** (the FIPS module builds via CMake + Go):

```bash
sudo apt-get update
sudo apt-get install -y cmake golang build-essential
```

2. **Build/test with the `fips` feature:**

```bash
cargo build --features fips
cargo test --features fips
```

Supported targets: Linux `x86_64` and `aarch64`.

3. **Activate at runtime.** The FIPS rustls provider is installed **fail-closed**
   when the EST client is constructed; you can also install it explicitly at
   startup:

```rust
usg_est_client::fips::enable_fips_mode()?; // errors if not linked against the FIPS module
```

   If the build is not actually linked against the FIPS module, installation
   returns an error rather than silently using non-FIPS cryptography.

### Windows (CNG FIPS)

On Windows, FIPS is provided by the operating system's CNG FIPS module, governed
by the system security policy — **not** by this crate's `fips` feature (which is
Linux-only). Do not enable `fips` on Windows; use the `windows` feature.

1. **Enable the Windows FIPS policy:** turn on "System cryptography: Use FIPS
   compliant algorithms for encryption, hashing, and signing" (Local Security
   Policy → Local Policies → Security Options, or via Group Policy). This makes
   CNG operate its FIPS-validated modules.

2. **Build with the `windows` feature** and obtain the CNG FIPS key provider:

```rust
use usg_est_client::hsm::fips_key_provider; // CngKeyProvider in FIPS mode

// Fail-closed: errors if the Windows FIPS policy is not enabled.
let provider = fips_key_provider()?;
```

   `usg_est_client::windows::CngKeyProvider::is_fips_mode_enabled()` reports
   whether the policy is currently active.

## Configuration

### Basic FIPS Configuration

```rust
use usg_est_client::{EstClient, EstClientConfig};
use usg_est_client::fips::FipsConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create FIPS configuration
    let fips_config = FipsConfig::builder()
        .enforce_fips_mode(true)           // Require FIPS mode to be enabled
        .min_rsa_key_size(2048)            // FIPS minimum
        .min_ecc_key_size(256)             // FIPS minimum (P-256)
        .block_non_fips_algorithms(true)   // Block non-FIPS algorithms
        .require_tls_12_minimum(true)      // Require TLS 1.2+
        .build()?;

    // Create EST client with FIPS
    let config = EstClientConfig::builder()
        .server_url("https://est.example.mil")?
        .fips_config(fips_config)
        .build()?;

    let client = EstClient::new(config).await?;

    // All operations now use FIPS-validated cryptography
    let ca_certs = client.get_ca_certs().await?;
    println!("Retrieved {} CA certificates (FIPS mode)", ca_certs.len());

    Ok(())
}
```

### Non-Enforcing Mode (Development)

For development/testing without FIPS module installed:

```rust
use usg_est_client::fips::FipsConfig;

// Create FIPS config without enforcement
let fips_config = FipsConfig::builder()
    .enforce_fips_mode(false)              // Don't require FIPS mode
    .min_rsa_key_size(2048)                // Still validate key sizes
    .min_ecc_key_size(256)
    .block_non_fips_algorithms(true)       // Still block weak algorithms
    .build()?;
```

### Custom Key Size Requirements

For higher security environments:

```rust
let fips_config = FipsConfig::builder()
    .enforce_fips_mode(true)
    .min_rsa_key_size(3072)                // Higher than FIPS minimum
    .min_ecc_key_size(384)                 // P-384 minimum
    .require_tls_12_minimum(false)         // Allow TLS 1.3 only (via TLS config)
    .build()?;
```

### SHA-1 Legacy Mode

**NOT RECOMMENDED** - Only for legacy compatibility:

```rust
use usg_est_client::fips::algorithms::AlgorithmPolicy;

let mut policy = AlgorithmPolicy::default();
policy.allow_sha1_legacy = true;  // ⚠️ Security risk
```

## Algorithm Enforcement

### Runtime Algorithm Validation

```rust
use usg_est_client::fips::algorithms::*;

// Create algorithm validator
let validator = AlgorithmValidator::new();

// Validate symmetric algorithm
validator.validate_symmetric_full(SymmetricAlgorithm::Aes256Gcm)?;

// Validate asymmetric algorithm
validator.validate_asymmetric_full(AsymmetricAlgorithm::Rsa2048)?;

// Validate signature algorithm OID
validator.validate_signature_algorithm_oid("1.2.840.113549.1.1.11")?; // sha256WithRSAEncryption
```

### Custom Algorithm Policy

```rust
use usg_est_client::fips::algorithms::*;

let policy = AlgorithmPolicy {
    block_non_fips: true,
    min_rsa_bits: 4096,              // Require RSA-4096
    min_ecc_bits: 384,               // Require P-384
    min_tls_version: TlsVersion::Tls13,  // Require TLS 1.3
    allow_sha1_legacy: false,
};

let validator = AlgorithmValidator::with_policy(policy);
```

### Certificate Validation

When validating certificates, the signature algorithm is checked:

```rust
// FIPS-approved signature algorithms (automatically validated):
// - sha256WithRSAEncryption (OID: 1.2.840.113549.1.1.11)
// - sha384WithRSAEncryption (OID: 1.2.840.113549.1.1.12)
// - sha512WithRSAEncryption (OID: 1.2.840.113549.1.1.13)
// - ecdsa-with-SHA256 (OID: 1.2.840.10045.4.3.2)
// - ecdsa-with-SHA384 (OID: 1.2.840.10045.4.3.3)
// - ecdsa-with-SHA512 (OID: 1.2.840.10045.4.3.4)

// Blocked signature algorithms:
// - md5WithRSAEncryption (OID: 1.2.840.113549.1.1.4)
// - sha1WithRSAEncryption (OID: 1.2.840.113549.1.1.5)
// - ecdsa-with-SHA1 (OID: 1.2.840.10045.4.1)
```

## Testing and Validation

### Check FIPS Status

```rust
use usg_est_client::fips::fips_module_info;

let info = fips_module_info();
println!("{}", info);
// Output:
// FIPS Module: aws-lc-rs FIPS module
// FIPS Capable: true
// FIPS Enabled: true
```

### Enable FIPS Mode Programmatically

```rust
use usg_est_client::fips::enable_fips_mode;

// Attempt to enable FIPS mode
match enable_fips_mode() {
    Ok(()) => println!("FIPS mode enabled successfully"),
    Err(e) => eprintln!("Failed to enable FIPS mode: {}", e),
}
```

### Run FIPS Tests

```bash
# Run all FIPS unit tests
cargo test --features fips --lib fips

# Run FIPS integration tests
cargo test --features fips --test '*' fips

# Run FIPS tests that require FIPS module (marked with #[ignore])
cargo test --features fips -- --ignored
```

### Test Coverage

The FIPS implementation is covered by unit tests in `src/fips/`, configuration
and algorithm-validation tests in `tests/fips/`, and — on the Linux `fips` CI
job — the cert-chain verification fixtures and EnvelopedData known-answer tests
that exercise the aws-lc-rs FIPS module directly.

## Troubleshooting

### FIPS Module Not Available

**Error**: `aws-lc-rs FIPS module is not available; the build is not linked against the FIPS module`

**Solution**:

1. Rebuild with the `fips` feature on Linux: `cargo build --features fips`
2. Ensure the build dependencies are installed (CMake, Go, a C toolchain)
3. Use a supported target (Linux `x86_64`/`aarch64`); the FIPS module does not
   build on Windows/macOS — use the Windows CNG path on Windows

### FIPS Mode Not Enabled

**Error**: `FIPS mode is required but the FIPS crypto provider is not active`

**Solution**:

1. Call `usg_est_client::fips::enable_fips_mode()` at startup (or construct the
   EST client, which installs the FIPS provider fail-closed)
2. On Windows, enable the system FIPS policy ("System cryptography: Use FIPS
   compliant algorithms ...") and check
   `CngKeyProvider::is_fips_mode_enabled()`

### Algorithm Not Allowed

**Error**: `Algorithm not allowed in FIPS mode: Algorithm '3DES' is not FIPS-approved`

**Solution**:
1. Check certificate signature algorithm
2. Ensure server uses FIPS-approved algorithms
3. Request certificate re-issuance with SHA-256 or better
4. Verify CSR uses approved algorithms

### Key Size Too Small

**Error**: `FIPS 140-2 configuration invalid: FIPS requires RSA key size >= 2048 bits`

**Solution**:
1. Generate new key pair with minimum 2048-bit RSA or 256-bit ECC
2. Update configuration to use larger key sizes
3. Request certificate re-issuance with compliant key size

## References

### Standards and Specifications

- [FIPS 140-3 Standard](https://csrc.nist.gov/pubs/fips/140-3/final)
- [NIST CMVP](https://csrc.nist.gov/projects/cryptographic-module-validation-program)
- [NIST SP 800-131A Rev 2](https://csrc.nist.gov/pubs/sp/800/131/a/r2/final) - Transitions: Algorithms and Key Lengths

### FIPS Module Documentation

- [aws-lc-rs](https://github.com/aws/aws-lc-rs) and its [FIPS documentation](https://aws.github.io/aws-lc-rs/index.html) (Linux)
- [AWS-LC FIPS / CMVP status](https://github.com/aws/aws-lc/blob/main/crypto/fipsmodule/FIPS.md) — confirm the validated module version for an ATO
- [Microsoft CNG FIPS mode](https://learn.microsoft.com/windows/security/security-foundations/certification/fips-140-validation) (Windows)

### DoD References

- [DoD Instruction 8500.01](https://www.esd.whs.mil/Portals/54/Documents/DD/issuances/dodi/850001p.pdf) - Cybersecurity
- [DISA STIG Library](https://public.cyber.mil/stigs/)
- [DoD PKI](https://public.cyber.mil/pki-pke/)

### CMVP module status

- [AWS-LC CMVP certificates](https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search?SearchMode=Basic&Vendor=Amazon) — verify the certificate that matches the linked aws-lc version
- [Microsoft CNG CMVP certificates](https://learn.microsoft.com/windows/security/security-foundations/certification/fips-140-validation)

## Support

For FIPS-related issues:

1. Check this documentation first
2. Review [GitHub Issues](https://github.com/johnwillman/usg-est-client/issues)
3. Consult the aws-lc-rs / Windows CNG FIPS documentation linked above
4. Contact your organization's security team

## Changelog

### FIPS migration (2026-06)

- Replaced the OpenSSL FIPS path with the **aws-lc-rs FIPS module** (Linux) for
  TLS, key generation, signing, certificate-chain verification, fingerprint
  hashing, and EnvelopedData (AES-128/256-CBC) — and **Windows CNG FIPS** mode
  via `CngKeyProvider::new_fips` / `hsm::fips_key_provider`.
- Consolidated to a single `fips` feature (`fips-tls` is a deprecated alias);
  dropped the OpenSSL dependencies; pinned `aws-lc-rs` to an exact version.

### Version 0.1.0 (2025-01-02)

- Initial FIPS 140-2 implementation (OpenSSL FIPS module integration — since
  removed; see the FIPS migration entry above)
- Algorithm policy enforcement
- Complete documentation

---

**Security Notice**: FIPS 140-2 compliance is a requirement for U.S. Federal Government deployments. Ensure you are using a FIPS-validated cryptographic module and have proper authorization before deploying in production.
