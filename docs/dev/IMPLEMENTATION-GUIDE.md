# RFC Compliance Implementation Guide

**Quick Reference for Developers**
**Based on:** [RFC-COMPLIANCE-ROADMAP.md](../RFC-COMPLIANCE-ROADMAP.md)

This guide provides detailed implementation instructions for each phase of the RFC compliance roadmap.

---

## Phase 1: TLS Channel Binding Implementation

### Step 1.1: Add TLS-Unique Extraction to `src/tls.rs`

```rust
use rustls::ClientConnection;

/// Extract tls-unique channel binding value from a TLS connection.
///
/// For TLS 1.2: Uses the Finished message per RFC 5929 Section 3.1
/// For TLS 1.3: Uses exporter with label "EXPORTER-Channel-Binding"
///
/// # Security
///
/// The tls-unique value binds the TLS session to application-level
/// authentication, preventing credential forwarding attacks.
pub fn extract_tls_unique(conn: &ClientConnection) -> Result<Vec<u8>> {
    // TLS 1.3 approach - use key exporter
    let context = b"";
    let output_len = 32; // 32 bytes for SHA-256

    let mut output = vec![0u8; output_len];
    conn.export_keying_material(
        &mut output,
        b"EXPORTER-Channel-Binding",
        Some(context)
    ).map_err(|e| EstError::tls(format!("Failed to export keying material: {}", e)))?;

    Ok(output)
}
```

**Key Points:**
- TLS 1.3 uses `export_keying_material()` instead of Finished messages
- Label must be "EXPORTER-Channel-Binding" per RFC 9266
- Returns 32 bytes (SHA-256 hash size)
- Must be called after handshake completes

**Testing:**
```rust
#[test]
fn test_tls_unique_extraction() {
    // Create mock TLS connection
    let conn = create_test_connection();

    let unique = extract_tls_unique(&conn).unwrap();
    assert_eq!(unique.len(), 32);
    assert!(unique.iter().any(|&b| b != 0)); // Not all zeros
}
```

### Step 1.2: Modify CSR to Include Channel Binding

```rust
// In src/operations/enroll.rs

use der::{Decode, Encode};
use x509_cert::request::CertReq;

/// Add channel binding to a CSR by injecting it into the challengePassword attribute.
///
/// # Arguments
///
/// * `csr_der` - Original DER-encoded CSR
/// * `channel_binding` - tls-unique value to embed
///
/// # Returns
///
/// Modified CSR with channel binding in challengePassword attribute
pub fn add_channel_binding_to_csr(
    csr_der: &[u8],
    channel_binding: &[u8],
) -> Result<Vec<u8>> {
    // Parse the CSR
    let mut csr = CertReq::from_der(csr_der)
        .map_err(|e| EstError::csr(format!("Failed to parse CSR: {}", e)))?;

    // Encode channel binding as base64
    let cb_value = BASE64_STANDARD.encode(channel_binding);

    // Create challengePassword attribute
    let challenge_password_oid = const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.7");

    // Add or replace the attribute
    // (Implementation depends on x509_cert crate API)
    // For now, this is a simplified version

    // Re-encode the modified CSR
    csr.to_der()
        .map_err(|e| EstError::csr(format!("Failed to encode CSR: {}", e)))
}
```

**Alternative Approach (if CSR modification is complex):**
Generate a new CSR with channel binding already included during CSR creation:

```rust
// In src/csr/pkcs10.rs (if csr-gen feature is enabled)

pub struct CsrBuilder {
    // ... existing fields ...
    channel_binding: Option<Vec<u8>>,
}

impl CsrBuilder {
    pub fn channel_binding(mut self, value: Vec<u8>) -> Self {
        self.channel_binding = Some(value);
        self
    }

    pub fn build(&self) -> Result<(Vec<u8>, KeyPair)> {
        // ... existing code ...

        // Add challengePassword attribute if channel binding is set
        if let Some(ref cb) = self.channel_binding {
            let cb_b64 = BASE64_STANDARD.encode(cb);
            // Add to CSR attributes
        }

        // ... existing code ...
    }
}
```

### Step 1.3: Update Client API

```rust
// In src/config.rs

impl EstClientConfig {
    /// Enable TLS channel binding for enrollment requests.
    ///
    /// When enabled, the tls-unique value from the TLS handshake
    /// is included in the CSR challengePassword field. This binds
    /// the certificate request to the TLS session, preventing
    /// credential forwarding attacks.
    ///
    /// # Security
    ///
    /// Enable this when using HTTP Basic authentication during
    /// initial enrollment to prevent MITM attacks.
    pub fn enable_channel_binding(mut self) -> Self {
        self.channel_binding = true;
        self
    }
}
```

```rust
// In src/client.rs

async fn enroll_request(&self, operation: &str, csr_der: &[u8]) -> Result<EnrollmentResponse> {
    let url = self.config.build_url(operation);
    tracing::debug!("POST {}", url);

    // Apply channel binding if enabled
    let csr_to_send = if self.config.channel_binding {
        // Get TLS connection from reqwest (this is the tricky part)
        // May need to use a custom connector
        let tls_unique = self.get_tls_unique_from_connection()?;
        add_channel_binding_to_csr(csr_der, &tls_unique)?
    } else {
        csr_der.to_vec()
    };

    // Base64 encode the CSR
    let body = encode_csr(&csr_to_send)?;

    // ... rest of enrollment logic ...
}
```

**Challenge:** Accessing TLS connection state from reqwest is non-trivial. Options:

1. **Custom TLS Connector:** Create a custom `rustls::ClientConnection` and wrap it
2. **Connection Pooling Hook:** Use reqwest's connection pool to access the underlying stream
3. **Two-Phase Enrollment:** Establish TLS, get tls-unique, then create and send CSR

**Recommended Approach:**
```rust
// Use reqwest's connection callback (if available)
// or create a custom connector that captures tls-unique

pub struct ChannelBindingConnector {
    tls_unique: Arc<Mutex<Option<Vec<u8>>>>,
}

impl ChannelBindingConnector {
    pub fn get_tls_unique(&self) -> Option<Vec<u8>> {
        self.tls_unique.lock().unwrap().clone()
    }
}
```

---

## Phase 2: CSR Signature Verification

### Step 2.1: Parse Public Key from CSR

```rust
// In src/operations/enroll.rs

use der::Decode;
use spki::SubjectPublicKeyInfoOwned;

/// Extract the public key from a DER-encoded CSR.
///
/// # Returns
///
/// SPKI-encoded public key suitable for signature verification
pub fn extract_public_key(csr_der: &[u8]) -> Result<Vec<u8>> {
    // Parse CertificationRequest
    let csr = CertReq::from_der(csr_der)
        .map_err(|e| EstError::csr(format!("Failed to parse CSR: {}", e)))?;

    // Extract subject_pk_info from certificationRequestInfo
    let spki = csr.info.public_key.clone();

    // Encode to DER
    spki.to_der()
        .map_err(|e| EstError::csr(format!("Failed to encode public key: {}", e)))
}
```

### Step 2.2: Verify CSR Signature

```rust
use signature::Verifier;
use rsa::RsaPublicKey;
use rsa::pkcs1v15::VerifyingKey;
use p256::ecdsa::VerifyingKey as P256VerifyingKey;

/// Verify the signature on a PKCS#10 CSR.
///
/// This validates proof-of-possession of the private key.
pub fn verify_csr_signature(csr_der: &[u8]) -> Result<bool> {
    let csr = CertReq::from_der(csr_der)
        .map_err(|e| EstError::csr(format!("Failed to parse CSR: {}", e)))?;

    // Get the data that was signed (certificationRequestInfo)
    let signed_data = csr.info.to_der()
        .map_err(|e| EstError::csr(format!("Failed to encode info: {}", e)))?;

    // Get signature algorithm and value
    let sig_alg = &csr.algorithm;
    let signature = csr.signature.raw_bytes();

    // Get public key
    let spki = &csr.info.public_key;

    // Verify based on algorithm
    match sig_alg.oid {
        // RSA with SHA-256: 1.2.840.113549.1.1.11
        oid if oid.to_string() == "1.2.840.113549.1.1.11" => {
            verify_rsa_signature(spki, &signed_data, signature, RsaSignatureHash::Sha256)
        }
        // ECDSA with SHA-256: 1.2.840.10045.4.3.2
        oid if oid.to_string() == "1.2.840.10045.4.3.2" => {
            verify_ecdsa_signature(spki, &signed_data, signature, EcdsaCurve::P256)
        }
        _ => Err(EstError::csr(format!(
            "Unsupported signature algorithm: {}",
            sig_alg.oid
        ))),
    }
}

fn verify_rsa_signature(
    spki: &SubjectPublicKeyInfoOwned,
    data: &[u8],
    signature: &[u8],
    hash: RsaSignatureHash,
) -> Result<bool> {
    use sha2::{Sha256, Digest};

    // Parse RSA public key
    let public_key = RsaPublicKey::try_from(spki)
        .map_err(|e| EstError::csr(format!("Invalid RSA public key: {}", e)))?;

    // Create verifying key
    let verifying_key: VerifyingKey<Sha256> = VerifyingKey::new(public_key);

    // Hash the data
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();

    // Verify signature
    use rsa::signature::Verifier;
    use rsa::pkcs1v15::Signature;

    let sig = Signature::try_from(signature)
        .map_err(|e| EstError::csr(format!("Invalid signature format: {}", e)))?;

    verifying_key.verify(&digest, &sig)
        .map(|_| true)
        .map_err(|_| EstError::csr("Signature verification failed"))
}

fn verify_ecdsa_signature(
    spki: &SubjectPublicKeyInfoOwned,
    data: &[u8],
    signature: &[u8],
    curve: EcdsaCurve,
) -> Result<bool> {
    use p256::ecdsa::{Signature, VerifyingKey};
    use sha2::{Sha256, Digest};

    // Parse ECDSA public key
    let public_key = VerifyingKey::from_sec1_bytes(spki.subject_public_key.raw_bytes())
        .map_err(|e| EstError::csr(format!("Invalid ECDSA public key: {}", e)))?;

    // Hash the data
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();

    // Parse signature
    let sig = Signature::from_der(signature)
        .map_err(|e| EstError::csr(format!("Invalid ECDSA signature: {}", e)))?;

    // Verify
    public_key.verify(&digest, &sig)
        .map(|_| true)
        .map_err(|_| EstError::csr("ECDSA signature verification failed"))
}

enum RsaSignatureHash {
    Sha256,
    Sha384,
    Sha512,
}

enum EcdsaCurve {
    P256,
    P384,
}
```

### Step 2.3: Add Configuration Option

```rust
// In src/config.rs

pub struct EstClientConfig {
    // ... existing fields ...

    /// Verify CSR signatures before submission.
    ///
    /// When enabled, the client validates that CSR signatures are
    /// correct before sending to the EST server. This catches
    /// malformed CSRs early.
    pub verify_csr_signatures: bool,
}

impl EstClientConfigBuilder {
    pub fn verify_csr_signatures(mut self) -> Self {
        self.verify_csr_signatures = true;
        self
    }
}
```

---

## Phase 3: Full CMC Implementation

### Step 3.1: Build CMC Certification Request

```rust
// In src/operations/fullcmc.rs

use crate::types::cmc_full::{PkiDataBuilder, TaggedRequest};

/// Build a CMC certification request from a PKCS#10 CSR.
pub fn build_cmc_certification_request(csr_der: &[u8]) -> Result<CmcRequest> {
    // Generate unique transaction ID
    let transaction_id = generate_transaction_id();

    // Generate sender nonce
    let sender_nonce = generate_nonce();

    // Create tagged request
    let body_part_id = 1;
    let tagged_request = TaggedRequest::new(body_part_id, csr_der.to_vec());

    // Build PKI data
    let pki_data = PkiDataBuilder::new()
        .transaction_id(transaction_id)
        .sender_nonce(sender_nonce)
        .add_request(tagged_request)
        .build()?;

    // Encode to DER
    let data = pki_data.to_der()
        .map_err(|e| EstError::cmc(format!("Failed to encode PKIData: {}", e)))?;

    Ok(CmcRequest::from_der(data))
}

fn generate_transaction_id() -> Vec<u8> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..16).map(|_| rng.gen::<u8>()).collect()
}

fn generate_nonce() -> Vec<u8> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..16).map(|_| rng.gen::<u8>()).collect()
}
```

### Step 3.2: Parse CMC Response

```rust
// In src/types/cmc.rs

impl CmcResponse {
    pub fn parse(body: &[u8]) -> Result<Self> {
        // Decode base64
        let der_bytes = decode_base64(body)?;

        // Parse ContentInfo
        let content_info = ContentInfo::from_der(&der_bytes)
            .map_err(|e| EstError::cms_parsing(format!("Failed to parse ContentInfo: {}", e)))?;

        // Extract SignedData
        let signed_data = extract_signed_data(&content_info)?;

        // Parse PKIResponse from encapContentInfo
        let pki_response = PkiResponse::from_der(&signed_data.encap_content_info.content)
            .map_err(|e| EstError::cmc(format!("Failed to parse PKIResponse: {}", e)))?;

        // Extract status
        let status = parse_cmc_status_info(&pki_response)?;

        // Extract certificates
        let certificates = extract_certificates(&signed_data)?;

        Ok(Self {
            data: der_bytes,
            certificates,
            status,
        })
    }
}

fn parse_cmc_status_info(response: &PkiResponse) -> Result<CmcStatus> {
    // Look for CMCStatusInfoV2 control attribute
    for control in &response.control_sequence {
        if control.is_status_info() {
            let status_info = control.parse_as_status_info()?;
            return Ok(match status_info.status {
                0 => CmcStatus::Success,
                2 => CmcStatus::Failed,
                3 => CmcStatus::Pending,
                _ => CmcStatus::NoResponse,
            });
        }
    }
    Ok(CmcStatus::NoResponse)
}
```

---

## Testing Guidelines

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_binding_round_trip() {
        let tls_unique = b"test-tls-unique-value-32-bytes!!";
        let csr = generate_test_csr();

        let modified_csr = add_channel_binding_to_csr(&csr, tls_unique).unwrap();
        let extracted = extract_channel_binding_from_csr(&modified_csr).unwrap();

        assert_eq!(extracted, tls_unique);
    }

    #[test]
    fn test_csr_signature_verification_rsa() {
        let (csr_der, _key) = generate_rsa_csr_2048();
        assert!(verify_csr_signature(&csr_der).unwrap());
    }

    #[test]
    fn test_csr_signature_verification_ecdsa() {
        let (csr_der, _key) = generate_ecdsa_csr_p256();
        assert!(verify_csr_signature(&csr_der).unwrap());
    }

    #[test]
    fn test_invalid_signature_rejected() {
        let mut csr = generate_test_csr();
        // Corrupt the signature
        csr[csr.len() - 1] ^= 0xFF;

        assert!(verify_csr_signature(&csr).is_err());
    }
}
```

### Integration Tests

```rust
// tests/integration/rfc_compliance_test.rs

#[tokio::test]
async fn test_enrollment_with_channel_binding() {
    let server = start_test_est_server();

    let config = EstClientConfig::builder()
        .server_url(server.url())
        .unwrap()
        .enable_channel_binding()
        .http_auth("test", "password")
        .build()
        .unwrap();

    let client = EstClient::new(config).await.unwrap();

    let (csr, _key) = generate_test_csr();
    let response = client.simple_enroll(&csr).await.unwrap();

    assert!(response.certificate().is_some());
}

#[tokio::test]
async fn test_cmc_certification_request() {
    let server = start_cmc_enabled_server();

    let config = EstClientConfig::builder()
        .server_url(server.url())
        .unwrap()
        .build()
        .unwrap();

    let client = EstClient::new(config).await.unwrap();

    let (csr, _key) = generate_test_csr();
    let cmc_request = build_cmc_certification_request(&csr).unwrap();

    let response = client.full_cmc(&cmc_request).await.unwrap();
    assert!(response.is_success());
}
```

---

## Code Review Checklist

Before submitting PR, ensure:

- [ ] All new functions have documentation comments
- [ ] Security considerations documented in code
- [ ] Error handling uses Result<T> consistently
- [ ] No unwrap() or expect() in production code
- [ ] Unit tests for all new functions
- [ ] Integration tests for user-facing features
- [ ] Cargo clippy passes with no warnings
- [ ] Cargo test --all-features passes
- [ ] Documentation examples compile
- [ ] CHANGELOG.md updated
- [ ] Performance impact measured (if applicable)

---

## Common Pitfalls

### 1. TLS Connection State Access

**Problem:** reqwest abstracts away the underlying TLS connection.

**Solution:** Use custom connector or middleware to capture TLS state.

### 2. ASN.1 Encoding Errors

**Problem:** DER encoding is strict and easy to get wrong.

**Solution:** Use `der` crate's derive macros and validate with `openssl asn1parse`.

### 3. Signature Algorithm Mismatches

**Problem:** CSR may use algorithm not supported by verification code.

**Solution:** Match on algorithm OID and return clear error for unsupported algorithms.

### 4. Channel Binding Timing

**Problem:** tls-unique must be extracted after handshake completes.

**Solution:** Ensure connection is fully established before extracting.

---

## Useful Commands

```bash
# Run all tests
cargo test --all-features

# Run integration tests only
cargo test --test '*'

# Run with logging
RUST_LOG=debug cargo test test_name -- --nocapture

# Check code coverage
cargo tarpaulin --all-features --out Html

# Lint code
cargo clippy --all-features -- -D warnings

# Format code
cargo fmt --all

# Generate documentation
cargo doc --no-deps --all-features --open

# Benchmark performance
cargo bench

# Check for security vulnerabilities
cargo audit

# Verify RFC compliance
cargo test rfc_compliance
```

---

## Additional Resources

- [rustls documentation](https://docs.rs/rustls)
- [der crate documentation](https://docs.rs/der)
- [x509-cert documentation](https://docs.rs/x509-cert)
- [RFC 7030 full text](https://tools.ietf.org/html/rfc7030)
- [RFC 5929 Channel Bindings](https://tools.ietf.org/html/rfc5929)
- [libest example code](https://github.com/cisco/libest/tree/master/example)

---

**Next Steps:** Start with Phase 1 (TLS Channel Binding) and work through each phase sequentially.

For questions or clarifications, refer to [RFC-COMPLIANCE-ROADMAP.md](../RFC-COMPLIANCE-ROADMAP.md).
