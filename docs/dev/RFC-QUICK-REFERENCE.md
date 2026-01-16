# RFC 7030 Quick Reference Card

**Quick lookup for developers implementing EST features**

## EST Operations

| Operation | Endpoint | Method | Content-Type | Auth Required | Status |
|-----------|----------|--------|--------------|---------------|--------|
| **CA Certs** | `/cacerts` | GET | - | Optional | ✅ Complete |
| **Simple Enroll** | `/simpleenroll` | POST | `application/pkcs10` | Required | ✅ Complete |
| **Simple Re-enroll** | `/simplereenroll` | POST | `application/pkcs10` | Required | ✅ Complete |
| **CSR Attributes** | `/csrattrs` | GET | - | Optional | ✅ Complete |
| **Server Keygen** | `/serverkeygen` | POST | `application/pkcs10` | Required | ✅ Complete |
| **Full CMC** | `/fullcmc` | POST | `application/pkcs7-mime` | Required | ⚠️ Partial |

## HTTP Status Codes

| Code | Meaning | EST Usage | Client Action |
|------|---------|-----------|---------------|
| **200** | OK | Success | Parse response |
| **202** | Accepted | Pending approval | Check `Retry-After` header, wait and retry |
| **400** | Bad Request | Malformed request | Fix request, check CSR format |
| **401** | Unauthorized | Auth required | Check `WWW-Authenticate` header, provide credentials |
| **404** | Not Found | Operation not supported | Try different operation or check URL |
| **500** | Server Error | Internal server error | Log error, retry with backoff |
| **501** | Not Implemented | Feature not supported | Check server capabilities |

## Content Types

| Content-Type | Usage | Direction |
|--------------|-------|-----------|
| `application/pkcs10` | PKCS#10 CSR | Client → Server |
| `application/pkcs7-mime` | Certificate response | Server → Client |
| `application/pkcs7-mime; smime-type=certs-only` | CA certificates | Server → Client |
| `application/csrattrs` | CSR attributes | Server → Client |
| `application/pkcs7-mime; smime-type=CMC-request` | CMC request | Client → Server |
| `application/pkcs7-mime; smime-type=CMC-response` | CMC response | Server → Client |
| `multipart/mixed` | Server keygen response | Server → Client |

## Authentication Methods

### TLS Client Certificate

```rust
let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .client_identity_pem(cert_pem, key_pem)
    .build()?;
```

**When to use:** Most secure, preferred method
**RFC Section:** 3.3.2

### HTTP Basic Authentication

```rust
let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .http_auth("username", "password")
    .build()?;
```

**When to use:** Initial enrollment when no client cert available
**RFC Section:** 3.2.3
**Security:** Should be combined with channel binding

### Bootstrap (TOFU)

```rust
let bootstrap = BootstrapClient::new("https://est.example.com")?;
let (certs, fingerprints) = bootstrap.fetch_ca_certs().await?;
// Verify fingerprints out-of-band before trusting
```

**When to use:** First-time setup, no prior CA knowledge
**RFC Section:** 4.1.1
**Security:** MUST verify fingerprints out-of-band

## Common Code Patterns

### Basic Enrollment

```rust
use usg_est_client::{EstClient, EstClientConfig};

let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .http_auth("user", "pass")
    .build()?;

let client = EstClient::new(config).await?;

// Get CA certificates first
let ca_certs = client.get_ca_certs().await?;

// Generate CSR (requires csr-gen feature)
#[cfg(feature = "csr-gen")]
{
    let (csr_der, key_pair) = CsrBuilder::new()
        .common_name("device.example.com")
        .build()?;

    // Enroll
    match client.simple_enroll(&csr_der).await? {
        EnrollmentResponse::Issued { certificate } => {
            println!("Certificate issued!");
        }
        EnrollmentResponse::Pending { retry_after } => {
            println!("Pending, retry in {} seconds", retry_after);
        }
    }
}
```

### Re-enrollment

```rust
// Use existing client certificate for authentication
let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .client_identity_pem(existing_cert, existing_key)
    .build()?;

let client = EstClient::new(config).await?;

// Generate new CSR
let (new_csr, new_key) = CsrBuilder::new()
    .common_name("device.example.com")
    .build()?;

// Re-enroll
let response = client.simple_reenroll(&new_csr).await?;
```

### Query CSR Attributes

```rust
let attrs = client.get_csr_attributes().await?;

for attr in attrs.attributes {
    println!("Required attribute: {}", attr.oid);
}
```

## File Locations

| Feature | File | RFC Section |
|---------|------|-------------|
| Client API | `src/client.rs` | All |
| Configuration | `src/config.rs` | 3.2 |
| TLS setup | `src/tls.rs` | 3.3 |
| Enrollment | `src/operations/enroll.rs` | 4.2 |
| CA certs | `src/operations/cacerts.rs` | 4.1 |
| Server keygen | `src/operations/serverkeygen.rs` | 4.4 |
| CSR attrs | `src/types/csr_attrs.rs` | 4.5 |
| CMC | `src/operations/fullcmc.rs` | 4.3 |
| PKCS#7 parsing | `src/types/pkcs7.rs` | 4.1.3 |
| Bootstrap | `src/bootstrap.rs` | 4.1.1 |
| Types | `src/types/mod.rs` | All |
| Errors | `src/error.rs` | All |

## Error Handling

### Error Types

```rust
match client.simple_enroll(&csr).await {
    Ok(response) => { /* handle success */ }
    Err(EstError::AuthenticationRequired(challenge)) => {
        println!("Need auth: {}", challenge);
    }
    Err(EstError::ServerError(code, msg)) => {
        println!("Server error {}: {}", code, msg);
    }
    Err(EstError::Tls(msg)) => {
        println!("TLS error: {}", msg);
    }
    Err(EstError::CmsParsing(msg)) => {
        println!("Invalid response: {}", msg);
    }
    Err(e) => {
        println!("Other error: {}", e);
    }
}
```

## Security Checklist

- [ ] Use TLS 1.2 or higher (enforced by default)
- [ ] Validate server certificate (enabled by default)
- [ ] Use client certificate authentication when possible
- [ ] Verify CA fingerprints when using bootstrap mode
- [ ] Store private keys with restrictive permissions (0600 on Unix)
- [ ] Enable automatic certificate renewal
- [ ] Log all enrollment operations for audit
- [ ] Use CSR size limits (enforced by default)
- [ ] Consider HSM for private key storage
- [ ] Enable channel binding with HTTP Basic auth (requires Phase 1)

## Testing

### Unit Test

```rust
#[test]
fn test_enrollment_flow() {
    let config = EstClientConfig::builder()
        .server_url("https://test.example.com")
        .unwrap()
        .build()
        .unwrap();

    assert_eq!(
        config.build_url("simpleenroll").as_str(),
        "https://test.example.com/.well-known/est/simpleenroll"
    );
}
```

### Integration Test

```rust
#[tokio::test]
async fn test_ca_certs_retrieval() {
    let server = start_test_server();

    let config = EstClientConfig::builder()
        .server_url(server.url())
        .unwrap()
        .build()
        .unwrap();

    let client = EstClient::new(config).await.unwrap();
    let certs = client.get_ca_certs().await.unwrap();

    assert!(!certs.is_empty());
}
```

## RFC References

### Quick Lookup

- **3.2.2** - URI structure
- **3.2.3** - HTTP authentication
- **3.3.1** - TLS requirements
- **3.3.2** - Client authentication
- **3.5** - Channel binding
- **4.1** - CA certificates
- **4.1.1** - Bootstrap
- **4.2** - Enrollment/re-enrollment
- **4.2.3** - Pending responses
- **4.3** - Full CMC
- **4.4** - Server keygen
- **4.5** - CSR attributes

### OIDs

```rust
// Common OIDs used in EST
const SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
const CHALLENGE_PASSWORD: &str = "1.2.840.113549.1.9.7";
const EXTENSION_REQUEST: &str = "1.2.840.113549.1.9.14";
```

## Performance Tips

1. **Reuse EstClient** - Create once, use for multiple operations
2. **Connection pooling** - reqwest handles this automatically
3. **Concurrent requests** - Use tokio::spawn for parallel enrollments
4. **Timeout configuration** - Adjust based on network conditions
5. **CSR caching** - Pre-generate CSRs to reduce latency

## Common Pitfalls

### ❌ Don't

```rust
// Don't create client for every request
for device in devices {
    let client = EstClient::new(config).await?; // Wasteful!
    client.simple_enroll(&csr).await?;
}

// Don't ignore retry-after
if response.status() == 202 {
    // Immediately retry - BAD!
    client.simple_enroll(&csr).await?;
}

// Don't use unwrap in production
let cert = client.get_ca_certs().await.unwrap(); // Will panic!
```

### ✅ Do

```rust
// Create client once
let client = EstClient::new(config).await?;
for device in devices {
    client.simple_enroll(&device.csr).await?;
}

// Respect retry-after
if let EnrollmentResponse::Pending { retry_after } = response {
    tokio::time::sleep(Duration::from_secs(retry_after)).await;
    client.simple_enroll(&csr).await?;
}

// Handle errors properly
let cert = client.get_ca_certs().await
    .map_err(|e| format!("Failed to get CA certs: {}", e))?;
```

## Feature Flags

| Feature | Adds | When to use |
|---------|------|-------------|
| `csr-gen` | CSR generation helpers | Client-side CSR creation |
| `hsm` | HSM trait abstractions | Hardware key storage |
| `pkcs11` | PKCS#11 support | HSM integration |
| `renewal` | Auto-renewal scheduler | Long-running clients |
| `validation` | RFC 5280 validation | Chain validation |
| `metrics` | Metrics collection | Monitoring |
| `metrics-prometheus` | Prometheus export | Prometheus monitoring |
| `revocation` | CRL/OCSP support | Revocation checking |
| `enveloped` | CMS decryption | Encrypted key transport |
| `fips` | FIPS 140-2 mode | Federal compliance |

## Debugging

### Enable Logging

```bash
RUST_LOG=debug cargo run
RUST_LOG=usg_est_client=trace cargo test
```

### Common Debug Points

```rust
tracing::debug!("EST operation: {}", operation);
tracing::debug!("Request URL: {}", url);
tracing::debug!("Response status: {}", response.status());
```

### Verify TLS

```bash
# Check server certificate
openssl s_client -connect est.example.com:443 -servername est.example.com

# Check client certificate
openssl x509 -in cert.pem -text -noout

# Verify CSR
openssl req -in csr.pem -text -noout
```

## Getting Help

1. Check the [API docs](https://docs.rs/usg-est-client)
2. Read the [full roadmap](../RFC-COMPLIANCE-ROADMAP.md)
3. Review [implementation guide](IMPLEMENTATION-GUIDE.md)
4. See [examples](../../examples/)
5. Check [test code](../../tests/)

---

**Last Updated:** 2026-01-15
**RFC Version:** RFC 7030 (November 2013)
**Implementation Version:** usg-est-client 0.1.0
