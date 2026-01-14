# Security

This document describes the security features, best practices, and deployment recommendations for the USG EST Client.

## Security Features

### Cryptographic Validation

The EST client implements comprehensive cryptographic validation to ensure certificate authenticity:

- **RSA Signature Verification**: Supports RSA-SHA256, RSA-SHA384, and RSA-SHA512
- **ECDSA Signature Verification**: Supports ECDSA-SHA256 (P-256) and ECDSA-SHA384 (P-384)
- **Certificate Validity Checking**: Validates `notBefore` and `notAfter` dates with leap year support
- **Name Constraints**: RFC 5280 compliant DNS constraint matching with proper label boundaries

### Credential Security

Sensitive data is protected through automatic memory zeroing:

- **Password Protection**: HTTP Basic authentication passwords are automatically zeroed using `zeroize`
- **Private Key Protection**: TLS client certificate private keys are automatically zeroed on drop
- **Memory Safety**: Credentials are scrubbed from memory when no longer needed

### File Security

Private key files are validated for proper permissions:

- **Permission Validation** (Unix): Private keys must have mode `0600` or more restrictive
- **Secure Loading**: Use `ClientIdentity::from_files_with_validation()` for production deployments
- **Error Reporting**: Clear error messages indicate insecure permissions

### Defense in Depth

Additional protections against various attack vectors:

- **DoS Prevention**: CSR size limited to 256 KB (typical: 1-2 KB)
- **Error Sanitization**: Server error messages truncated and sanitized to prevent information disclosure
- **Certificate Parsing**: Invalid certificates logged with warnings to detect malformed chains
- **TLS Requirements**: Enforces TLS 1.2+ per RFC 7030

## Deployment Recommendations

### For DoD/Government Deployments

1. **Use Secure File Loading**

```rust
use usg_est_client::config::ClientIdentity;

// This validates that the private key file has 0600 permissions
let identity = ClientIdentity::from_files_with_validation(
    "certs/client-cert.pem",
    "certs/client-key.pem",
)?;
```

2. **Enable Certificate Validation**

```bash
# Build with validation feature for certificate chain validation
cargo build --release --features validation
```

3. **Enable FIPS Mode for DoD ATO**

```bash
# Full DoD compliance with FIPS 140-2 cryptography
cargo build --release --features fips,dod-pki
```

4. **Configure Trust Anchors Explicitly**

```rust
use usg_est_client::config::{EstClientConfig, TrustAnchors};

let config = EstClientConfig::builder("https://est.example.mil/.well-known/est")
    .trust_anchors(TrustAnchors::Explicit(vec![
        dod_root_ca_pem.to_vec(),
        // Add DoD intermediate CAs as needed
    ]))
    .client_identity(identity)
    .build()?;
```

### For Enterprise Deployments

1. **Use Strong Authentication**

```rust
use usg_est_client::config::HttpAuth;

// HTTP Basic auth with strong credentials
let auth = HttpAuth::new("est-client", env::var("EST_PASSWORD")?);

let config = EstClientConfig::builder(server_url)
    .http_auth(auth)
    .build()?;
```

2. **Enable Logging for Security Monitoring**

```rust
use tracing_subscriber;

// Configure structured logging for security events
tracing_subscriber::fmt()
    .with_max_level(tracing::Level::INFO)
    .init();
```

3. **Monitor Certificate Expiration**

```rust
// Use the renewal feature to check certificate expiration
#[cfg(feature = "renewal")]
{
    use usg_est_client::renewal::time_until_expiry;

    let days_until_expiry = time_until_expiry(&cert)?;
    if days_until_expiry < 30 {
        // Trigger certificate renewal
    }
}
```

## Security Audit Results

The codebase has undergone comprehensive security review and remediation:

### High Priority Issues (RESOLVED)

- ✅ **Certificate Signature Verification**: Implemented full cryptographic validation
- ✅ **Validity Period Checking**: Proper time parsing with leap year support
- ✅ **DNS Constraint Matching**: Fixed label boundary checking per RFC 5280
- ✅ **Unmaintained Dependencies**: Migrated from `rustls-pemfile` to `rustls-pki-types`

### Medium Priority Issues (RESOLVED)

- ✅ **Credential Zeroing**: Automatic memory scrubbing using `zeroize` crate
- ✅ **File Permission Validation**: Unix permission checking for private keys

### Low Priority Issues (RESOLVED)

- ✅ **Certificate Parsing Logging**: Warnings logged for invalid certificates
- ✅ **CSR Size Validation**: 256 KB limit to prevent DoS attacks
- ✅ **Error Message Sanitization**: Truncation and redaction of sensitive information

### Known Issues

#### Low Risk
- **`paste` crate warning**: Transitive dependency via `cryptoki 0.11.0`
  - Risk: Very low (compile-time proc-macro only)
  - Action: Monitoring for `cryptoki` updates

## Security Best Practices

### Key Management

1. **Private Key Permissions**: Always set private key files to mode `0600`
   ```bash
   chmod 600 client-key.pem
   ```

2. **Secure Storage**: Store private keys in secure locations with restricted access
   - Linux: `/etc/pki/private/` or `/root/.pki/`
   - Consider using HSM/TPM via the `pkcs11` feature

3. **Key Rotation**: Implement regular key rotation policies
   - Recommended: 1-2 year rotation for RSA-2048
   - Use shorter lifetimes for higher security requirements

### Network Security

1. **TLS Configuration**: Always use explicit trust anchors for production

```rust
// ❌ DON'T: Use WebPki for untrusted environments
.trust_anchors(TrustAnchors::WebPki)

// ✅ DO: Use explicit trust anchors
.trust_anchors(TrustAnchors::Explicit(ca_certs))
```

2. **Certificate Validation**: Never disable certificate validation in production

```rust
// ❌ DON'T: Use InsecureAcceptAny in production
.trust_anchors(TrustAnchors::InsecureAcceptAny)

// ✅ DO: Use Bootstrap with proper fingerprint verification
.trust_anchors(TrustAnchors::Bootstrap(BootstrapConfig {
    fingerprints: vec![expected_fingerprint],
    // Implement proper out-of-band verification
}))
```

3. **Authentication**: Use client certificates over HTTP Basic auth when possible
   - Client certificates provide mutual TLS authentication
   - HTTP Basic auth should use strong, unique passwords

### Operational Security

1. **Logging**: Enable security logging but avoid logging sensitive data
   ```rust
   // Logging is already configured to avoid sensitive data
   // Certificate parsing errors and validation failures are logged
   ```

2. **Monitoring**: Monitor for certificate-related warnings
   ```rust
   // Watch for these log messages:
   // - "Failed to parse certificate from PEM data"
   // - "Certificate has expired"
   // - "CSR too large"
   ```

3. **Incident Response**: Implement procedures for:
   - Certificate compromise
   - Private key exposure
   - EST server compromise

## Compliance

### DoD Requirements

The EST client supports DoD compliance requirements:

- **FIPS 140-2**: Enable with `--features fips`
  - Uses OpenSSL FIPS module for cryptographic operations
  - Validated algorithms only

- **DoD PKI**: Enable with `--features dod-pki`
  - DoD Root CA trust anchors
  - Certificate policy validation
  - CAC/PIV support via PKCS#11

- **Full Compliance**: Use `--features dod` for complete DoD ATO compliance
  - Combines FIPS + DoD PKI features
  - Meets DoD Cloud Computing SRG requirements

### RFC 7030 Compliance

The client implements RFC 7030 (EST) with security enhancements:

- ✅ TLS 1.2+ required (TLS 1.1 deprecated)
- ✅ HTTP Basic authentication supported
- ✅ TLS client certificate authentication
- ✅ Bootstrap mode with fingerprint verification
- ✅ All required EST operations

## Reporting Security Issues

**DO NOT** create public GitHub issues for security vulnerabilities.

### Responsible Disclosure

We follow a coordinated disclosure process. To report security vulnerabilities:

**Preferred Method:** [GitHub Security Advisories](https://github.com/johnwillman/usg-est-client/security/advisories) (Private)
1. Navigate to the Security tab
2. Click "Report a vulnerability"
3. Provide detailed information

**Alternative Methods:**
- **Email:** security@[organization].mil (for DoD deployments)
- **Encrypted Email:** PGP key available in repository
- **Phone:** [Security Hotline] (CRITICAL issues only)

### What to Include

When reporting vulnerabilities, please provide:
- Vulnerability description and potential impact
- Affected version(s)
- Steps to reproduce
- Proof of concept (if applicable)
- Suggested fix (if any)

### Response Timeline

We are committed to timely responses:
- **CRITICAL:** Acknowledgment within 2 hours, patch within 24 hours
- **HIGH:** Acknowledgment within 8 hours, patch within 7 days
- **MEDIUM:** Acknowledgment within 24 hours, patch within 30 days
- **LOW:** Acknowledgment within 72 hours, patch within 90 days

See our [Security Update SLA](docs/ato/security-update-sla.md) for complete details.

### Disclosure Policy

- Standard disclosure: 90 days after patch release
- Earlier disclosure if actively exploited
- Coordinated with reporter
- Security researchers credited (with permission)

## Security Updates

### Update Service Level Agreement

This library provides formal security update commitments. Our [Security Update SLA](docs/ato/security-update-sla.md) defines:

**Response Times by Severity:**

| Severity | Patch Release | Example Vulnerabilities |
|----------|---------------|------------------------|
| **CRITICAL** | 24 hours | Remote code execution, PKI compromise |
| **HIGH** | 7 days | Authentication bypass, key exposure |
| **MEDIUM** | 30 days | Information disclosure, DoS |
| **LOW** | 90 days | Minor information leaks |

**Stay Informed:**
- [GitHub Security Advisories](https://github.com/johnwillman/usg-est-client/security/advisories)
- [GitHub Releases](https://github.com/johnwillman/usg-est-client/releases) - Check release notes
- Dependabot alerts (if repository is watched)
- Security mailing list: security-announce@[organization]

**Supported Versions:**
- **Current version (1.x):** Full security support
- **Previous version (0.x):** Critical vulnerabilities only until 2026-12-31
- **Older versions:** No support - upgrade required

### Dependency Security

We monitor dependencies daily:
- ✅ Automated `cargo audit` scanning
- ✅ Dependabot security updates
- ✅ License compliance verification
- ✅ Supply chain security (SBOM provided)

Dependency vulnerabilities are patched according to the same SLA as direct vulnerabilities.

## License

Security-related contributions are welcome under the Apache 2.0 license.

---

**Last Updated**: 2026-01-13
**Security Audit Date**: 2026-01-12
**Security Update SLA**: 2026-01-13 (POA&M SI-001)
**Next Review**: 2026-04-13 (quarterly)
