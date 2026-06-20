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

### Linux (Ubuntu/Debian)

1. **Install OpenSSL 3.0+ with FIPS module:**

```bash
# Ubuntu 22.04+ includes OpenSSL 3.0
sudo apt-get update
sudo apt-get install openssl libssl-dev

# Verify version (should be 3.0+)
openssl version
```

2. **Enable FIPS mode:**

```bash
# Enable FIPS provider
sudo openssl fipsinstall -out /usr/local/ssl/fipsmodule.cnf -module /usr/lib/x86_64-linux-gnu/ossl-modules/fips.so

# Update OpenSSL configuration
sudo tee -a /usr/local/ssl/openssl.cnf << EOF
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
fips = fips_sect
base = base_sect

[base_sect]
activate = 1

[fips_sect]
activate = 1
module = /usr/lib/x86_64-linux-gnu/ossl-modules/fips.so
EOF

# Set environment variable
export OPENSSL_CONF=/usr/local/ssl/openssl.cnf
```

3. **Verify FIPS mode:**

```bash
openssl list -provider fips -providers
# Should show: Providers: fips
```

### macOS (Homebrew)

1. **Install OpenSSL 3.0+:**

```bash
brew install openssl@3

# Verify version
/usr/local/opt/openssl@3/bin/openssl version
```

2. **Enable FIPS mode:**

```bash
# Generate FIPS module configuration
/usr/local/opt/openssl@3/bin/openssl fipsinstall \
    -out /usr/local/etc/openssl@3/fipsmodule.cnf \
    -module /usr/local/Cellar/openssl@3/3.x.x/lib/ossl-modules/fips.dylib

# Update OpenSSL configuration (create if doesn't exist)
cat >> /usr/local/etc/openssl@3/openssl.cnf << EOF
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
fips = fips_sect

[fips_sect]
activate = 1
module = /usr/local/Cellar/openssl@3/3.x.x/lib/ossl-modules/fips.dylib
EOF

# Set environment variable
export OPENSSL_CONF=/usr/local/etc/openssl@3/openssl.cnf
```

### Windows

1. **Download OpenSSL 3.0+ for Windows:**

Download from: https://slproweb.com/products/Win32OpenSSL.html

2. **Install to C:\Program Files\OpenSSL-Win64**

3. **Enable FIPS mode:**

```powershell
# Open PowerShell as Administrator
cd "C:\Program Files\OpenSSL-Win64\bin"

# Generate FIPS module configuration
.\openssl.exe fipsinstall -out C:\OpenSSL-Win64\fipsmodule.cnf -module C:\OpenSSL-Win64\bin\fips.dll

# Update openssl.cnf
Add-Content C:\OpenSSL-Win64\openssl.cnf @"
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
fips = fips_sect

[fips_sect]
activate = 1
module = C:\OpenSSL-Win64\bin\fips.dll
"@

# Set environment variable (system-wide)
[System.Environment]::SetEnvironmentVariable("OPENSSL_CONF", "C:\OpenSSL-Win64\openssl.cnf", "Machine")
```

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
// OpenSSL Version: OpenSSL 3.0.8 7 Feb 2023
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

The FIPS implementation includes:
- **14 unit tests** in `src/fips/mod.rs`
- **25 algorithm validation tests** in `src/fips/algorithms.rs`
- **13 configuration tests** in `tests/fips/fips_config_test.rs`
- **25 integration tests** in `tests/fips/algorithm_validation_test.rs`

Total: **77 FIPS-specific tests** ✅

## Troubleshooting

### FIPS Module Not Available

**Error**: `FIPS 140-2 not available: OpenSSL FIPS module is not available`

**Solution**:
1. Verify OpenSSL 3.0+ is installed: `openssl version`
2. Check FIPS module exists:
   - Linux: `/usr/lib/x86_64-linux-gnu/ossl-modules/fips.so`
   - macOS: `/usr/local/Cellar/openssl@3/3.x.x/lib/ossl-modules/fips.dylib`
   - Windows: `C:\OpenSSL-Win64\bin\fips.dll`
3. Verify `fipsmodule.cnf` exists and is configured correctly
4. Set `OPENSSL_CONF` environment variable

### FIPS Mode Not Enabled

**Error**: `FIPS 140-2 mode not enabled: FIPS mode is required but not enabled`

**Solution**:
1. Check OpenSSL configuration file (`openssl.cnf`)
2. Verify FIPS provider is activated
3. Run `openssl list -provider fips -providers` to confirm
4. Check `OPENSSL_CONF` points to correct configuration file

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

### OpenSSL Version Too Old

**Error**: `FIPS 140-2 not available: FIPS mode requires OpenSSL 3.0+`

**Solution**:
1. Upgrade OpenSSL to version 3.0 or later
2. On older systems, compile OpenSSL 3.0+ from source
3. Use system package manager to install newer version

## References

### Standards and Specifications

- [FIPS 140-2 Standard](https://csrc.nist.gov/pubs/fips/140-2/upd2/final)
- [FIPS 140-3 Standard](https://csrc.nist.gov/pubs/fips/140-3/final) (successor)
- [NIST CMVP](https://csrc.nist.gov/projects/cryptographic-module-validation-program)
- [OpenSSL FIPS Module User Guide](https://www.openssl.org/docs/fips.html)
- [NIST SP 800-131A Rev 2](https://csrc.nist.gov/pubs/sp/800/131/a/r2/final) - Transitions: Algorithms and Key Lengths

### OpenSSL FIPS Documentation

- [OpenSSL 3.0 FIPS Module](https://github.com/openssl/openssl/blob/master/README-FIPS.md)
- [OpenSSL FIPS Provider](https://www.openssl.org/docs/man3.0/man7/fips_module.html)
- [FIPS Module Installation](https://www.openssl.org/docs/man3.0/man1/openssl-fipsinstall.html)

### DoD References

- [DoD Instruction 8500.01](https://www.esd.whs.mil/Portals/54/Documents/DD/issuances/dodi/850001p.pdf) - Cybersecurity
- [DISA STIG Library](https://public.cyber.mil/stigs/)
- [DoD PKI](https://public.cyber.mil/pki-pke/)

### Testing and Validation

- [Caveat Certificate #4282](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4282) - OpenSSL 3.0.0
- [Caveat Certificate #4616](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4616) - OpenSSL 3.0.8

## Support

For FIPS-related issues:

1. Check this documentation first
2. Review [GitHub Issues](https://github.com/johnwillman/usg-est-client/issues)
3. Consult OpenSSL FIPS documentation
4. Contact your organization's security team

## Changelog

### Version 0.1.0 (2025-01-02)

- Initial FIPS 140-2 implementation
- OpenSSL 3.0+ FIPS module integration
- Algorithm policy enforcement
- Comprehensive test suite (77 tests)
- Complete documentation

---

**Security Notice**: FIPS 140-2 compliance is a requirement for U.S. Federal Government deployments. Ensure you are using a FIPS-validated cryptographic module and have proper authorization before deploying in production.
