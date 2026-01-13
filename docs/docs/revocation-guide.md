# Certificate Revocation Guide

This comprehensive guide covers certificate revocation checking using the `usg-est-client` library's revocation subsystem.

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Architecture](#architecture)
4. [CRL (Certificate Revocation Lists)](#crl-certificate-revocation-lists)
5. [OCSP (Online Certificate Status Protocol)](#ocsp-online-certificate-status-protocol)
6. [Configuration](#configuration)
7. [Integration Patterns](#integration-patterns)
8. [Performance Optimization](#performance-optimization)
9. [Error Handling](#error-handling)
10. [Best Practices](#best-practices)
11. [Troubleshooting](#troubleshooting)
12. [API Reference](#api-reference)

---

## Overview

Certificate revocation is the mechanism by which certificates can be invalidated before their natural expiration date. This is critical for security when:

- A private key is compromised
- A certificate is issued in error
- An entity's privileges change
- A CA is compromised

The `usg-est-client` library provides **production-ready** support for both primary revocation protocols:

### CRL (Certificate Revocation Lists)

- **Type**: Periodically updated list of revoked certificates
- **Distribution**: Downloaded via HTTP/HTTPS from distribution points
- **Caching**: Local caching with configurable TTL
- **Signature Verification**: Full RSA/ECDSA signature validation
- **Best For**: Environments with predictable network access, batch processing

### OCSP (Online Certificate Status Protocol)

- **Type**: Real-time certificate status queries
- **Protocol**: RFC 6960 compliant
- **Response**: Immediate status (good/revoked/unknown)
- **Best For**: Interactive applications, real-time validation requirements

### Dual-Stack Strategy

The library implements an intelligent dual-stack approach:

1. Try OCSP first (faster, real-time)
2. Fall back to CRL if OCSP unavailable
3. Configurable hard-fail or soft-fail policy

---

## Quick Start

### Basic Usage

```rust
use usg_est_client::revocation::{RevocationChecker, RevocationConfig};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure revocation checker
    let config = RevocationConfig::builder()
        .enable_crl(true)
        .enable_ocsp(true)
        .crl_cache_duration(Duration::from_secs(3600))  // 1 hour
        .ocsp_timeout(Duration::from_secs(10))
        .build();

    let checker = RevocationChecker::new(config);

    // Load certificates
    let cert = load_certificate("end_entity.pem")?;
    let issuer = load_certificate("ca.pem")?;

    // Check revocation status
    let result = checker.check_revocation(&cert, &issuer).await?;

    match result.status {
        RevocationStatus::Valid => println!("Certificate is valid"),
        RevocationStatus::Revoked => println!("Certificate is REVOKED!"),
        RevocationStatus::Unknown => println!("Status unknown"),
    }

    Ok(())
}
```

### Enable Revocation Feature

Add to your `Cargo.toml`:

```toml
[dependencies]
usg-est-client = { version = "0.1", features = ["revocation"] }
```

---

## Architecture

### Component Overview

```
┌─────────────────────────────────────────────────────┐
│              RevocationChecker                       │
│  ┌───────────────────────────────────────────────┐ │
│  │         check_revocation(cert, issuer)         │ │
│  └───────────────────┬───────────────────────────┘ │
│                      │                               │
│         ┌────────────┴────────────┐                 │
│         │                         │                 │
│    ┌────▼─────┐           ┌──────▼────┐           │
│    │   OCSP   │           │    CRL    │           │
│    │  Checker │           │  Checker  │           │
│    └────┬─────┘           └──────┬────┘           │
│         │                         │                 │
│    ┌────▼─────────────┐     ┌────▼─────────────┐ │
│    │ OCSP Request     │     │ CRL Download     │ │
│    │ OCSP Response    │     │ CRL Parse        │ │
│    │ Status Extract   │     │ CRL Verify       │ │
│    └──────────────────┘     │ Serial Lookup    │ │
│                              └──────────────────┘ │
└─────────────────────────────────────────────────────┘
```

### Key Components

1. **RevocationChecker**: Main entry point for revocation checking
2. **RevocationConfig**: Configuration for revocation behavior
3. **CRL Checker**: Downloads, caches, and validates CRLs
4. **OCSP Checker**: Builds requests and parses OCSP responses
5. **SimpleDerParser**: Custom ASN.1/DER parser for OCSP responses

### Data Flow

```
Certificate → Extract URLs → Try OCSP → Parse Response → Status
                ↓
                └─ (fallback) → Download CRL → Verify Signature → Lookup Serial → Status
```

---

## CRL (Certificate Revocation Lists)

### How CRL Works

1. **Certificate includes CRL Distribution Point** extension (OID 2.5.29.31)
2. Library extracts CRL URLs from the certificate
3. Downloads CRL via HTTP/HTTPS
4. Verifies CRL signature using issuer's public key
5. Looks up certificate serial number in the revocation list
6. Returns status (valid/revoked)
7. Caches CRL for future checks

### CRL Structure

```
CertificateList ::= SEQUENCE {
    tbsCertList          TBSCertList,        -- "To Be Signed" CRL
    signatureAlgorithm   AlgorithmIdentifier,
    signatureValue       BIT STRING
}

TBSCertList ::= SEQUENCE {
    version              Version OPTIONAL,
    signature            AlgorithmIdentifier,
    issuer               Name,
    thisUpdate           Time,
    nextUpdate           Time OPTIONAL,
    revokedCertificates  SEQUENCE OF SEQUENCE {
        userCertificate    CertificateSerialNumber,
        revocationDate     Time,
        crlEntryExtensions Extensions OPTIONAL
    } OPTIONAL
}
```

### CRL Signature Verification

The library implements **production-grade** signature verification:

#### Supported Algorithms

| Algorithm | Hash Functions | Status |
|-----------|---------------|---------|
| RSA PKCS#1 v1.5 | SHA-256, SHA-384, SHA-512 | ✅ Fully supported |
| ECDSA | P-256, P-384 | ✅ Fully supported |
| RSA PSS | SHA-256, SHA-384, SHA-512 | ⚠️ Not yet supported |
| Ed25519 | N/A | ⚠️ Not yet supported |

#### Verification Process

```rust
// Internal implementation (simplified)
fn verify_crl_signature(crl: &CertificateList, issuer: &Certificate) -> Result<()> {
    // 1. Extract issuer's public key from SPKI
    let public_key = extract_public_key(&issuer.tbs_certificate.subject_public_key_info)?;

    // 2. Determine signature algorithm
    match crl.signature_algorithm.oid {
        RSA_WITH_SHA256 => verify_rsa_sha256(&crl.tbs_cert_list, &crl.signature, &public_key)?,
        ECDSA_WITH_SHA256 => verify_ecdsa_p256(&crl.tbs_cert_list, &crl.signature, &public_key)?,
        // ... other algorithms
    }

    // 3. Re-encode TBSCertList to DER for verification
    let tbs_der = crl.tbs_cert_list.to_der()?;

    // 4. Verify signature matches
    verify_signature(&tbs_der, &crl.signature, &public_key)
}
```

### CRL Caching

Efficient caching is critical for CRL performance:

```rust
let config = RevocationConfig::builder()
    .crl_cache_duration(Duration::from_secs(3600))  // TTL: 1 hour
    .crl_cache_max_entries(100)                     // Max cached CRLs
    .build();
```

**Cache Behavior**:

- CRLs are cached by URL (distribution point)
- Cache entries expire based on `crl_cache_duration`
- Cache also respects CRL's `nextUpdate` field (whichever is sooner)
- LRU eviction when `max_entries` is reached
- Thread-safe with async locking

**Manual Cache Management**:

```rust
// Clear entire cache
checker.clear_cache().await;

// Cache statistics (if available)
let stats = checker.cache_stats().await;
println!("Hit rate: {:.2}%", stats.hit_rate * 100.0);
```

### CRL Configuration

```rust
RevocationConfig::builder()
    .enable_crl(true)
    .crl_cache_duration(Duration::from_secs(3600))
    .crl_cache_max_entries(100)
    .crl_timeout(Duration::from_secs(30))  // Download timeout
    .build()
```

---

## OCSP (Online Certificate Status Protocol)

### How OCSP Works

1. **Certificate includes Authority Information Access** extension (OID 1.3.6.1.5.5.7.1.1)
2. Library extracts OCSP responder URL
3. Builds OCSP request with certificate identifier (CertID)
4. Sends HTTP POST to OCSP responder
5. Parses nested OCSP response structure
6. Extracts certificate status
7. Returns status immediately (no caching by default)

### OCSP Request Structure

```rust
OCSPRequest ::= SEQUENCE {
    tbsRequest      TBSRequest,
    optionalSignature   [0] EXPLICIT Signature OPTIONAL
}

TBSRequest ::= SEQUENCE {
    version         [0] EXPLICIT Version DEFAULT v1,
    requestorName   [1] EXPLICIT GeneralName OPTIONAL,
    requestList     SEQUENCE OF Request
}

Request ::= SEQUENCE {
    reqCert         CertID
}

CertID ::= SEQUENCE {
    hashAlgorithm       AlgorithmIdentifier,  -- SHA-256
    issuerNameHash      OCTET STRING,          -- Hash of issuer DN
    issuerKeyHash       OCTET STRING,          -- Hash of issuer public key
    serialNumber        CertificateSerialNumber
}
```

### OCSP Response Parsing

OCSP responses have **5+ levels of nested ASN.1 structures**:

```
OCSPResponse
  └─ ResponseBytes
      └─ BasicOCSPResponse
          └─ ResponseData
              └─ SingleResponse
                  └─ CertStatus [0] [1] [2]
```

The library uses a **custom SimpleDerParser** to reliably parse these structures:

```rust
// Simplified example
struct SimpleDerParser<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> SimpleDerParser<'a> {
    fn expect_sequence(&mut self) -> Result<usize> {
        self.expect_tag(0x30)?;  // SEQUENCE tag
        self.read_length()
    }

    fn read_enumerated(&mut self) -> Result<u8> {
        self.expect_tag(0x0A)?;  // ENUMERATED tag
        let len = self.read_length()?;
        self.read_byte()
    }

    fn expect_context_constructed(&mut self, num: u8) -> Result<usize> {
        let tag = 0xA0 | num;  // Context-specific constructed
        self.expect_tag(tag)?;
        self.read_length()
    }
}
```

### OCSP Status Mapping

Context-specific tags indicate certificate status:

| Tag | Status | Meaning |
|-----|--------|---------|
| `[0]` | good | Certificate is valid (not revoked) |
| `[1]` | revoked | Certificate is revoked |
| `[2]` | unknown | Status cannot be determined |

### OCSP Response Codes

The library handles all RFC 6960 response status codes:

| Code | Status | Handling |
|------|--------|----------|
| 0 | successful | Parse response and extract status |
| 1 | malformedRequest | Return error |
| 2 | internalError | Return error |
| 3 | tryLater | Return Unknown (soft-fail) |
| 5 | sigRequired | Return error |
| 6 | unauthorized | Return error |

### OCSP Configuration

```rust
RevocationConfig::builder()
    .enable_ocsp(true)
    .ocsp_timeout(Duration::from_secs(10))  // Request timeout
    .build()
```

---

## Configuration

### RevocationConfig Options

```rust
pub struct RevocationConfig {
    // CRL settings
    pub enable_crl: bool,
    pub crl_cache_duration: Duration,
    pub crl_cache_max_entries: usize,
    pub crl_timeout: Duration,

    // OCSP settings
    pub enable_ocsp: bool,
    pub ocsp_timeout: Duration,

    // Policy settings
    pub fail_on_unknown: bool,  // Hard-fail vs soft-fail
    pub check_order: CheckOrder,  // OCSP-first or CRL-first
}
```

### Builder Pattern

```rust
let config = RevocationConfig::builder()
    // CRL settings
    .enable_crl(true)
    .crl_cache_duration(Duration::from_secs(3600))
    .crl_cache_max_entries(100)
    .crl_timeout(Duration::from_secs(30))

    // OCSP settings
    .enable_ocsp(true)
    .ocsp_timeout(Duration::from_secs(10))

    // Policy
    .fail_on_unknown(false)  // Soft-fail mode
    .check_order(CheckOrder::OcspFirst)  // Try OCSP before CRL

    .build();
```

### Policy Decisions

#### Hard-Fail vs Soft-Fail

**Hard-Fail** (`fail_on_unknown = true`):

- Rejects certificates if revocation status cannot be determined
- Maximum security posture
- May impact availability if revocation services are down

```rust
let config = RevocationConfig::builder()
    .fail_on_unknown(true)
    .build();

// If revocation check fails, returns error
match checker.check_revocation(&cert, &issuer).await {
    Ok(result) => {
        // Status is definitively Valid or Revoked
    },
    Err(e) => {
        // Could not determine status - treat as security failure
    }
}
```

**Soft-Fail** (`fail_on_unknown = false`):

- Allows certificates if revocation status cannot be determined
- Better availability
- Logs warnings for unknown status

```rust
let config = RevocationConfig::builder()
    .fail_on_unknown(false)
    .build();

// Always returns Ok with status
let result = checker.check_revocation(&cert, &issuer).await?;
match result.status {
    RevocationStatus::Unknown => {
        // Log warning but allow certificate
        warn!("Could not determine revocation status");
    },
    _ => {}
}
```

#### Check Order

**OCSP-First** (default):

- Tries OCSP before CRL
- Faster for real-time validation
- Falls back to CRL if OCSP unavailable

**CRL-First**:

- Tries CRL before OCSP
- Better for batch processing
- Falls back to OCSP if CRL unavailable

```rust
// OCSP-first (default)
let config = RevocationConfig::builder()
    .check_order(CheckOrder::OcspFirst)
    .build();

// CRL-first
let config = RevocationConfig::builder()
    .check_order(CheckOrder::CrlFirst)
    .build();
```

---

## Integration Patterns

### Pattern 1: DoD PKI with Revocation

```rust
use usg_est_client::dod::{DodPkiValidator, DodValidationOptions};
use usg_est_client::revocation::{RevocationChecker, RevocationConfig};

async fn validate_dod_cert(cert: &Certificate) -> Result<()> {
    // Load DoD root CAs
    let dod_roots = load_dod_root_certificates()?;

    // Configure revocation checking
    let revocation_config = RevocationConfig::builder()
        .enable_crl(true)
        .enable_ocsp(true)
        .fail_on_unknown(false)  // Soft-fail for availability
        .build();

    let revocation_checker = RevocationChecker::new(revocation_config);

    // Configure DoD validator
    let options = DodValidationOptions {
        check_revocation: true,
        ..Default::default()
    };

    let validator = DodPkiValidator::new(dod_roots, options);

    // Validate with revocation
    let intermediates = load_intermediate_certificates()?;
    let result = validator
        .validate_async(cert, &intermediates, Some(&revocation_checker))
        .await?;

    if !result.valid {
        return Err(EstError::CertificateValidation(
            "Certificate validation failed".into()
        ));
    }

    Ok(())
}
```

### Pattern 2: Batch Certificate Validation

```rust
async fn validate_certificate_batch(
    certificates: Vec<(Certificate, Certificate)>
) -> Vec<Result<RevocationStatus>> {
    let config = RevocationConfig::builder()
        .enable_crl(true)
        .crl_cache_duration(Duration::from_secs(3600))
        .build();

    let checker = RevocationChecker::new(config);

    let mut results = Vec::new();

    for (cert, issuer) in certificates {
        let result = checker.check_revocation(&cert, &issuer).await;
        results.push(result.map(|r| r.status));
    }

    results
}
```

### Pattern 3: Periodic Monitoring

```rust
use tokio::time::{interval, Duration};

async fn monitor_certificate_revocation(
    cert: Certificate,
    issuer: Certificate,
) {
    let config = RevocationConfig::builder()
        .enable_crl(true)
        .enable_ocsp(true)
        .build();

    let checker = RevocationChecker::new(config);
    let mut check_interval = interval(Duration::from_hours(1));

    loop {
        check_interval.tick().await;

        match checker.check_revocation(&cert, &issuer).await {
            Ok(result) if result.status == RevocationStatus::Revoked => {
                error!("Certificate has been REVOKED!");
                // Trigger alert, disable service, etc.
                break;
            },
            Ok(result) => {
                info!("Certificate status: {:?}", result.status);
            },
            Err(e) => {
                warn!("Revocation check failed: {}", e);
            }
        }
    }
}
```

### Pattern 4: Custom Fallback Logic

```rust
async fn check_with_custom_fallback(
    cert: &Certificate,
    issuer: &Certificate,
) -> Result<RevocationStatus> {
    // Try OCSP only first
    let ocsp_config = RevocationConfig::builder()
        .enable_crl(false)
        .enable_ocsp(true)
        .ocsp_timeout(Duration::from_secs(5))
        .build();

    let ocsp_checker = RevocationChecker::new(ocsp_config);

    match ocsp_checker.check_revocation(cert, issuer).await {
        Ok(result) if result.status != RevocationStatus::Unknown => {
            return Ok(result.status);
        },
        _ => {
            // Fall back to CRL
            let crl_config = RevocationConfig::builder()
                .enable_crl(true)
                .enable_ocsp(false)
                .build();

            let crl_checker = RevocationChecker::new(crl_config);
            let result = crl_checker.check_revocation(cert, issuer).await?;
            Ok(result.status)
        }
    }
}
```

---

## Performance Optimization

### CRL Optimization

1. **Cache Tuning**:

   ```rust
   // Longer cache for stable CAs
   .crl_cache_duration(Duration::from_secs(7200))  // 2 hours

   // Larger cache for many CAs
   .crl_cache_max_entries(500)
   ```

2. **Parallel Checks**:

   ```rust
   use futures::future::join_all;

   async fn check_multiple_parallel(
       certs: Vec<(Certificate, Certificate)>
   ) -> Vec<Result<RevocationStatus>> {
       let checker = Arc::new(RevocationChecker::new(config));

       let futures = certs.into_iter().map(|(cert, issuer)| {
           let checker = Arc::clone(&checker);
           async move {
               checker.check_revocation(&cert, &issuer)
                   .await
                   .map(|r| r.status)
           }
       });

       join_all(futures).await
   }
   ```

3. **Pre-warm Cache**:

   ```rust
   // Pre-download common CRLs
   async fn prewarm_crl_cache(checker: &RevocationChecker) {
       let common_certs = load_common_certificates();

       for (cert, issuer) in common_certs {
           let _ = checker.check_revocation(&cert, &issuer).await;
       }
   }
   ```

### OCSP Optimization

1. **Timeout Tuning**:

   ```rust
   // Fast fail for interactive applications
   .ocsp_timeout(Duration::from_secs(5))

   // Longer timeout for batch processing
   .ocsp_timeout(Duration::from_secs(15))
   ```

2. **Connection Pooling**:

   The library uses `reqwest` which automatically pools connections to OCSP responders.

3. **Response Caching** (optional):

   ```rust
   // Cache OCSP responses (not built-in, implement if needed)
   struct OcspCache {
       cache: Arc<RwLock<HashMap<SerialNumber, (RevocationStatus, Instant)>>>,
       ttl: Duration,
   }
   ```

---

## Error Handling

### Error Types

```rust
pub enum EstError {
    // Network errors
    Http(reqwest::Error),

    // Parsing errors
    CertificateParsing(String),
    CmsParsing(String),

    // Revocation-specific errors
    RevocationCheckFailed(String),
    OcspError(String),
    CrlError(String),

    // Operational errors
    Operational(String),
}
```

### Handling Revocation Errors

```rust
match checker.check_revocation(&cert, &issuer).await {
    Ok(result) => {
        match result.status {
            RevocationStatus::Valid => {
                info!("Certificate is valid");
            },
            RevocationStatus::Revoked => {
                error!("Certificate is REVOKED!");
                if let Some(reason) = result.revocation_reason {
                    error!("Revocation reason: {}", reason);
                }
                if let Some(date) = result.revocation_date {
                    error!("Revoked on: {:?}", date);
                }
                return Err(EstError::CertificateValidation(
                    "Certificate revoked".into()
                ));
            },
            RevocationStatus::Unknown => {
                warn!("Revocation status unknown");
                // Decide based on policy
            }
        }
    },
    Err(EstError::Http(e)) => {
        warn!("Network error during revocation check: {}", e);
        // Retry or soft-fail
    },
    Err(EstError::OcspError(e)) => {
        warn!("OCSP error: {}", e);
        // Fall back to CRL
    },
    Err(EstError::CrlError(e)) => {
        warn!("CRL error: {}", e);
        // Fall back to OCSP or soft-fail
    },
    Err(e) => {
        error!("Revocation check failed: {}", e);
        return Err(e);
    }
}
```

### Retry Logic

```rust
async fn check_with_retry(
    cert: &Certificate,
    issuer: &Certificate,
    max_retries: u32,
) -> Result<RevocationStatus> {
    let checker = RevocationChecker::new(config);

    for attempt in 0..max_retries {
        match checker.check_revocation(cert, issuer).await {
            Ok(result) => return Ok(result.status),
            Err(e) if e.is_retryable() => {
                warn!("Retry {} of {}: {}", attempt + 1, max_retries, e);
                tokio::time::sleep(Duration::from_secs(2u64.pow(attempt))).await;
            },
            Err(e) => return Err(e),
        }
    }

    Err(EstError::Operational("Max retries exceeded".into()))
}
```

---

## Best Practices

### Security Best Practices

1. **Always Verify Signatures**:

   The library does this automatically for both CRL and OCSP responses.

2. **Use HTTPS for Distribution Points**:

   ```rust
   // Validate CRL/OCSP URLs
   fn is_secure_url(url: &str) -> bool {
       url.starts_with("https://")
   }
   ```

3. **Implement Timeouts**:

   ```rust
   .ocsp_timeout(Duration::from_secs(10))
   .crl_timeout(Duration::from_secs(30))
   ```

4. **Monitor Revocation Failures**:

   ```rust
   if let Err(e) = checker.check_revocation(&cert, &issuer).await {
       metrics.increment("revocation_check_failures");
       log_security_event("revocation_check_failed", &e);
   }
   ```

5. **Hard-Fail for High-Security Environments**:

   ```rust
   let config = RevocationConfig::builder()
       .fail_on_unknown(true)  // Reject unknown status
       .build();
   ```

### Performance Best Practices

1. **Cache Aggressively**:

   ```rust
   .crl_cache_duration(Duration::from_secs(3600))
   ```

2. **Use OCSP for Interactive, CRL for Batch**:

   ```rust
   // Interactive
   .check_order(CheckOrder::OcspFirst)

   // Batch
   .check_order(CheckOrder::CrlFirst)
   ```

3. **Parallelize Batch Checks**:

   Use `join_all` or similar for concurrent checking.

4. **Pre-warm Critical CRLs**:

   Download and cache CRLs for frequently validated certificates.

### Operational Best Practices

1. **Monitor Metrics**:

   ```rust
   metrics.increment("revocation_checks_total");
   metrics.increment(format!("revocation_status_{}", status));
   metrics.gauge("revocation_check_duration_ms", duration.as_millis());
   ```

2. **Alert on Anomalies**:
   - Sudden increase in revoked certificates
   - High failure rate
   - Slow response times

3. **Regular Testing**:
   - Test with known-revoked certificates
   - Simulate OCSP/CRL unavailability
   - Verify fallback logic

4. **Documentation**:
   - Document your revocation policy
   - Document escalation procedures for revoked certificates
   - Document fallback behavior

---

## Troubleshooting

### Common Issues

#### Issue: "OCSP responder not responding"

**Symptoms**: OCSP checks timeout or fail

**Solutions**:

1. Check network connectivity to OCSP responder:

   ```bash
   curl -I https://ocsp.example.com
   ```

2. Increase timeout:

   ```rust
   .ocsp_timeout(Duration::from_secs(20))
   ```

3. Enable CRL fallback:

   ```rust
   .enable_crl(true)
   ```

#### Issue: "CRL signature verification failed"

**Symptoms**: Error message about invalid CRL signature

**Solutions**:

1. Verify issuer certificate is correct:

   ```bash
   openssl crl -in crl.der -inform DER -noout -issuer
   ```

2. Check CRL signature algorithm is supported:

   ```bash
   openssl crl -in crl.der -inform DER -noout -text | grep "Signature Algorithm"
   ```

3. Ensure you're using the correct issuer certificate (not end-entity).

#### Issue: "Certificate serial number not found in CRL"

**Symptoms**: Status returns Unknown when it should be revoked

**Solutions**:

1. Check if CRL is current:

   ```bash
   openssl crl -in crl.der -inform DER -noout -nextupdate
   ```

2. Download latest CRL:

   ```rust
   checker.clear_cache().await;  // Force re-download
   ```

3. Verify certificate serial number:

   ```bash
   openssl x509 -in cert.pem -noout -serial
   ```

#### Issue: "Memory usage growing with CRL cache"

**Symptoms**: High memory consumption over time

**Solutions**:

1. Limit cache size:

   ```rust
   .crl_cache_max_entries(50)  // Reduce from default
   ```

2. Reduce cache duration:

   ```rust
   .crl_cache_duration(Duration::from_secs(1800))  // 30 minutes
   ```

3. Periodically clear cache:

   ```rust
   tokio::spawn(async move {
       let mut interval = tokio::time::interval(Duration::from_hours(6));
       loop {
           interval.tick().await;
           checker.clear_cache().await;
       }
   });
   ```

### Debug Logging

Enable debug logging to troubleshoot issues:

```rust
use tracing_subscriber;

tracing_subscriber::fmt()
    .with_max_level(tracing::Level::DEBUG)
    .init();
```

Look for these log messages:

```
DEBUG check_revocation: Starting revocation check
DEBUG extract_ocsp_url: Found OCSP URL: https://ocsp.example.com
DEBUG create_ocsp_request: Building OCSP request
DEBUG parse_ocsp_response: Parsing OCSP response (1234 bytes)
DEBUG check_crl: Downloading CRL from: http://crl.example.com/ca.crl
DEBUG verify_crl_signature: Verifying CRL signature with RSA-SHA256
```

---

## API Reference

### RevocationChecker

```rust
pub struct RevocationChecker {
    config: RevocationConfig,
    // ... internal fields
}

impl RevocationChecker {
    pub fn new(config: RevocationConfig) -> Self;

    pub async fn check_revocation(
        &self,
        cert: &Certificate,
        issuer: &Certificate,
    ) -> Result<RevocationResult>;

    pub async fn clear_cache(&self);
}
```

### RevocationConfig

```rust
pub struct RevocationConfig {
    pub enable_crl: bool,
    pub enable_ocsp: bool,
    pub crl_cache_duration: Duration,
    pub crl_cache_max_entries: usize,
    pub crl_timeout: Duration,
    pub ocsp_timeout: Duration,
    pub fail_on_unknown: bool,
    pub check_order: CheckOrder,
}

impl RevocationConfig {
    pub fn builder() -> RevocationConfigBuilder;
}
```

### RevocationResult

```rust
pub struct RevocationResult {
    pub status: RevocationStatus,
    pub method_used: Option<RevocationMethod>,
    pub revocation_date: Option<DateTime>,
    pub revocation_reason: Option<String>,
}
```

### RevocationStatus

```rust
pub enum RevocationStatus {
    Valid,    // Certificate is not revoked
    Revoked,  // Certificate is revoked
    Unknown,  // Status could not be determined
}
```

### RevocationMethod

```rust
pub enum RevocationMethod {
    Crl,   // Status determined via CRL
    Ocsp,  // Status determined via OCSP
}
```

### CheckOrder

```rust
pub enum CheckOrder {
    OcspFirst,  // Try OCSP before CRL (default)
    CrlFirst,   // Try CRL before OCSP
}
```

---

## Appendix

### RFC References

- [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) - X.509 PKI Certificate and CRL Profile
- [RFC 6960](https://datatracker.ietf.org/doc/html/rfc6960) - Online Certificate Status Protocol (OCSP)
- [RFC 6961](https://datatracker.ietf.org/doc/html/rfc6961) - TLS Multiple Certificate Status Request Extension (OCSP Stapling)

### Glossary

- **CRL**: Certificate Revocation List
- **OCSP**: Online Certificate Status Protocol
- **DER**: Distinguished Encoding Rules (binary ASN.1 encoding)
- **PEM**: Privacy-Enhanced Mail (base64-encoded DER)
- **ASN.1**: Abstract Syntax Notation One (data structure language)
- **TTL**: Time To Live (cache duration)
- **SPKI**: Subject Public Key Info
- **OID**: Object Identifier

### Related Documentation

- [Security Considerations](security.md) - Full security guide including revocation
- [DoD PKI Integration](dod-pki.md) - DoD-specific revocation requirements
- [API Reference](api-reference.md) - Complete API documentation
- [Examples](examples.md) - Additional code examples

---

**Last Updated**: 2026-01-12
**Library Version**: 0.1.0
**Revocation Implementation**: Production-ready (Phase 10.2.2)
