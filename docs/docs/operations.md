# EST Operations

This guide provides detailed information about all EST operations supported by the library.

## Overview

EST (Enrollment over Secure Transport) defines several operations for certificate management. This library implements all mandatory and optional operations from RFC 7030.

## Operation Categories

### Mandatory Operations

These operations MUST be supported by all EST servers:

- **Distribution of CA Certificates** (`/cacerts`)
- **Simple Enrollment** (`/simpleenroll`)
- **Simple Re-enrollment** (`/simplereenroll`)

### Optional Operations

These operations MAY be supported by EST servers:

- **CSR Attributes** (`/csrattrs`)
- **Server-Side Key Generation** (`/serverkeygen`)
- **Full CMC** (`/fullcmc`)

---

## CA Certificates (`/cacerts`)

Retrieve the current CA certificates from the EST server.

### Usage

```rust
let ca_certs = client.get_ca_certs().await?;

println!("Retrieved {} CA certificate(s)", ca_certs.len());

for cert in ca_certs.iter() {
    println!("Issuer: {:?}", cert.tbs_certificate.issuer);
    println!("Subject: {:?}", cert.tbs_certificate.subject);
}
```

### Response

Returns a `CaCertificates` struct containing a collection of X.509 certificates.

```rust
pub struct CaCertificates {
    certificates: Vec<x509_cert::Certificate>,
}

impl CaCertificates {
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    pub fn iter(&self) -> impl Iterator<Item = &Certificate>;
}
```

### RFC Reference

- RFC 7030 Section 4.1: Distribution of CA Certificates
- Content-Type: `application/pkcs7-mime`
- Format: PKCS#7 certs-only structure

### Use Cases

- Initial trust establishment
- CA certificate rollover
- Verifying certificate chains

---

## Simple Enrollment (`/simpleenroll`)

Request a new certificate from the EST server.

### Usage

```rust
use usg_est_client::{csr::CsrBuilder, EnrollmentResponse};

// Generate CSR
let (csr_der, key_pair) = CsrBuilder::new()
    .common_name("device.example.com")
    .organization("Example Corp")
    .build()?;

// Submit enrollment request
match client.simple_enroll(&csr_der).await? {
    EnrollmentResponse::Issued { certificate } => {
        println!("Certificate issued!");
        // Save certificate and key_pair
    }
    EnrollmentResponse::Pending { retry_after } => {
        println!("Pending approval. Retry after {} seconds", retry_after);
        // Implement retry logic
    }
}
```

### Request

- **Method**: POST
- **Content-Type**: `application/pkcs10`
- **Body**: Base64-encoded PKCS#10 CSR
- **Authentication**: Optional (HTTP Basic or TLS client certificate)

### Response

The response can be one of two types:

#### Immediate Issuance (HTTP 200)

Certificate is issued immediately:

```rust
EnrollmentResponse::Issued {
    certificate: x509_cert::Certificate,
}
```

#### Pending Approval (HTTP 202)

Enrollment requires manual approval:

```rust
EnrollmentResponse::Pending {
    retry_after: u64, // Seconds to wait before retrying
}
```

### Handling Pending Enrollments

```rust
use tokio::time::{sleep, Duration};

loop {
    match client.simple_enroll(&csr_der).await? {
        EnrollmentResponse::Issued { certificate } => {
            println!("Certificate issued!");
            break;
        }
        EnrollmentResponse::Pending { retry_after } => {
            println!("Still pending... retrying in {} seconds", retry_after);
            sleep(Duration::from_secs(retry_after)).await;
        }
    }
}
```

### RFC Reference

- RFC 7030 Section 4.2.1: Simple Enrollment

---

## Simple Re-enrollment (`/simplereenroll`)

Renew or rekey an existing certificate.

### Usage

```rust
use usg_est_client::{ClientIdentity, EstClientConfig};

// Load existing certificate and key
let cert_pem = std::fs::read("current-cert.pem")?;
let key_pem = std::fs::read("current-key.pem")?;

// Configure with client certificate authentication
let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .client_identity(ClientIdentity::new(cert_pem, key_pem))
    .build()?;

let client = EstClient::new(config).await?;

// Generate new CSR (can use new key for rekeying)
let (csr_der, new_key) = CsrBuilder::new()
    .common_name("device.example.com")
    .build()?;

// Re-enroll
match client.simple_reenroll(&csr_der).await? {
    EnrollmentResponse::Issued { certificate } => {
        println!("Certificate renewed!");
        // Update stored certificate and key
    }
    EnrollmentResponse::Pending { retry_after } => {
        println!("Re-enrollment pending approval");
    }
}
```

### Requirements

- **MUST** use TLS client certificate authentication (the certificate being renewed)
- Subject field and SubjectAltName extension should match the current certificate

### Renewal vs. Rekeying

**Renewal**: Generate CSR with the same key pair
```rust
// Use existing key
let csr_der = CsrBuilder::new()
    .common_name("device.example.com")
    .with_key_pair(existing_key_pair)
    .build_with_key(&existing_key_pair)?;
```

**Rekeying**: Generate CSR with a new key pair
```rust
// Generate new key
let (csr_der, new_key_pair) = CsrBuilder::new()
    .common_name("device.example.com")
    .build()?;
```

### RFC Reference

- RFC 7030 Section 4.2.2: Simple Re-enrollment

---

## CSR Attributes (`/csrattrs`)

Query the server for CSR attribute requirements.

### Usage

```rust
match client.get_csr_attributes().await {
    Ok(attrs) => {
        if attrs.is_empty() {
            println!("No specific requirements");
        } else {
            println!("Server requires {} attributes:", attrs.len());
            for attr in &attrs.attributes {
                println!("  - OID: {}", attr.oid);
            }
        }
    }
    Err(EstError::NotSupported { operation }) => {
        println!("CSR attributes not supported by server");
    }
    Err(e) => return Err(e.into()),
}
```

### Response

```rust
pub struct CsrAttributes {
    pub attributes: Vec<CsrAttribute>,
}

pub struct CsrAttribute {
    pub oid: ObjectIdentifier,
    pub values: Vec<Vec<u8>>,
}
```

### Common Attributes

The library provides OID constants for common attributes:

```rust
use usg_est_client::types::csr_attrs::oids;

// Check for specific attributes
if attrs.contains_oid(&oids::CHALLENGE_PASSWORD) {
    println!("Challenge password required");
}

if attrs.contains_oid(&oids::EXTENSION_REQUEST) {
    println!("Extension request required");
}

// Available OID constants:
// - CHALLENGE_PASSWORD
// - EXTENSION_REQUEST
// - SUBJECT_ALT_NAME
// - KEY_USAGE
// - EXTENDED_KEY_USAGE
// - BASIC_CONSTRAINTS
```

### Applying Attributes to CSR

```rust
// Get attributes from server
let attrs = client.get_csr_attributes().await?;

// Build CSR with attributes
let (csr_der, key_pair) = CsrBuilder::new()
    .common_name("device.example.com")
    .with_attributes(&attrs) // Apply server requirements
    .build()?;
```

### RFC Reference

- RFC 7030 Section 4.5: CSR Attributes

---

## Server-Side Key Generation (`/serverkeygen`)

Request the server to generate a key pair and issue a certificate.

### Usage

```rust
use usg_est_client::ServerKeygenResponse;

// Create a CSR with subject information
// (The public key is just a placeholder)
let (csr_der, _) = CsrBuilder::new()
    .common_name("device.example.com")
    .organization("Example Corp")
    .build()?;

// Request server key generation
let response = client.server_keygen(&csr_der).await?;

println!("Certificate issued!");
println!("Private key encrypted: {}", response.key_encrypted);

// Save the server-generated private key securely
std::fs::write("server-generated-key.der", &response.private_key)?;

// Save the certificate
use der::Encode;
std::fs::write("certificate.der", response.certificate.to_der()?)?;
```

### Response

```rust
pub struct ServerKeygenResponse {
    pub certificate: Certificate,
    pub private_key: Vec<u8>,      // DER-encoded PKCS#8
    pub key_encrypted: bool,
}
```

### Encrypted Private Keys

If `key_encrypted` is true, the private key is wrapped in CMS EnvelopedData:

```rust
use usg_est_client::operations::serverkeygen;

if response.key_encrypted {
    // Check if encrypted
    assert!(serverkeygen::is_key_encrypted(&response.private_key));

    // Decrypt (requires additional implementation)
    // let decrypted_key = serverkeygen::decrypt_private_key(
    //     &response.private_key,
    //     &decryption_key
    // )?;
}
```

### Converting to PEM

```rust
use usg_est_client::operations::serverkeygen::{parse_pkcs8_key, PrivateKeyInfo};

let key_info = parse_pkcs8_key(&response.private_key)?;
let pem = key_info.to_pem();

std::fs::write("private-key.pem", pem)?;
```

### Decrypting Encrypted Private Keys

When the server returns an encrypted private key (`key_encrypted: true`), you can decrypt it using the `enveloped` module:

```rust
use usg_est_client::enveloped::{
    decrypt_enveloped_data, is_encrypted_key, parse_enveloped_data,
    DecryptionKey, EncryptionAlgorithm
};

// Check if the key is encrypted
if is_encrypted_key(&response.private_key) {
    // Parse the EnvelopedData structure
    let envelope = parse_enveloped_data(&response.private_key)?;

    println!("Encryption algorithm: {:?}", envelope.content_encryption_algorithm);
    println!("Recipients: {}", envelope.recipients.len());

    // Get the content encryption key (from key transport, key agreement, etc.)
    // This typically comes from:
    // - A pre-shared transport key
    // - Key derived from your private key (for KeyAgreeRecipientInfo)
    // - Key unwrapped using your RSA private key (for KeyTransRecipientInfo)
    let content_key = obtain_content_key(&envelope, &your_private_key)?;

    // Create decryption key
    let decryption_key = DecryptionKey::new(
        content_key,
        envelope.content_encryption_algorithm,
    )?;

    // Decrypt the private key
    let decrypted_key = decrypt_enveloped_data(
        &response.private_key,
        &decryption_key
    )?;

    println!("Decrypted PKCS#8 private key: {} bytes", decrypted_key.len());
}
```

### Supported Encryption Algorithms

The library supports the following content encryption algorithms:

| Algorithm | Key Size | Block Size | OID |
|-----------|----------|------------|-----|
| AES-128-CBC | 16 bytes | 16 bytes | 2.16.840.1.101.3.4.1.2 |
| AES-192-CBC | 24 bytes | 16 bytes | 2.16.840.1.101.3.4.1.22 |
| AES-256-CBC | 32 bytes | 16 bytes | 2.16.840.1.101.3.4.1.42 |
| 3DES-CBC | 24 bytes | 8 bytes | 1.2.840.113549.3.7 |

### EnvelopedData Structure

The encrypted private key uses CMS EnvelopedData format (RFC 5652):

```rust
use usg_est_client::enveloped::{EnvelopedData, RecipientInfo};

pub struct EnvelopedData {
    pub version: u8,
    pub recipients: Vec<RecipientInfo>,
    pub content_encryption_algorithm: EncryptionAlgorithm,
    pub encrypted_content: Vec<u8>,
    pub iv: Option<Vec<u8>>,
}

pub struct RecipientInfo {
    pub identifier: Vec<u8>,              // Recipient identifier
    pub encrypted_key: Vec<u8>,           // Encrypted content encryption key
    pub key_encryption_algorithm: String, // Key encryption algorithm
}
```

### Security Considerations

- Server-generated private keys are transmitted over the network
- Ensure TLS is properly configured with strong cipher suites
- Consider using client-generated keys when possible for better security
- Store private keys securely (encrypted at rest, proper permissions)
- When using encrypted keys, protect the decryption key appropriately

### RFC Reference

- RFC 7030 Section 4.4: Server-Side Key Generation
- RFC 5652: Cryptographic Message Syntax (CMS)

---

## Full CMC (`/fullcmc`)

Support for complex PKI operations using Certificate Management over CMS (CMC). Full CMC provides advanced features beyond simple enrollment, including batch operations, transaction tracking, and comprehensive status reporting.

### Overview

Full CMC (RFC 5272) is an optional EST operation that enables:

- **Multiple certificate requests** in a single transaction
- **Transaction tracking** with IDs and nonces
- **Detailed status reporting** with specific failure codes
- **Batch operations** for multiple enrollment requests
- **Advanced controls** for identity proof, POP, and revocation

⚠️ **Note**: Full CMC is optional in EST. Many servers only support simple enrollment. Always check server capabilities first.

### Basic Usage

```rust
use usg_est_client::{
    CmcRequest,
    types::cmc_full::{PkiDataBuilder, PkiResponse},
};

// Generate a CSR
let (csr_der, _key) = CsrBuilder::new()
    .common_name("device.example.com")
    .build()?;

// Build CMC PKIData request
let pki_data = PkiDataBuilder::new()
    .transaction_id(12345)              // Unique transaction ID
    .random_sender_nonce()               // Random nonce for replay protection
    .identification("client-001".to_string())  // Human-readable identifier
    .add_certification_request(csr_der)  // Add PKCS#10 CSR
    .build()?;

// Encode to DER
let pki_data_der = pki_data.to_der()?;

// Wrap in CmcRequest
let cmc_request = CmcRequest::new(pki_data_der);

// Submit to EST server
let cmc_response = client.full_cmc(&cmc_request).await?;

// Check response status
if cmc_response.is_success() {
    println!("CMC request successful!");
    println!("Certificates: {}", cmc_response.certificates.len());
} else {
    println!("Status: {:?}", cmc_response.status);
}
```

### PKIData Structure

The `PkiData` structure is the main CMC request message:

```rust
pub struct PkiData {
    pub control_sequence: Vec<TaggedAttribute>,    // Control attributes
    pub req_sequence: Vec<TaggedRequest>,          // Certificate requests
    pub cms_sequence: Vec<Vec<u8>>,                // CMS content
    pub other_msg_sequence: Vec<OtherMsg>,         // Extension messages
}
```

### Building CMC Requests with PkiDataBuilder

The fluent builder API simplifies CMC message construction:

```rust
use usg_est_client::types::cmc_full::PkiDataBuilder;

let pki_data = PkiDataBuilder::new()
    // Transaction tracking
    .transaction_id(98765)
    .sender_nonce(vec![0x01, 0x02, 0x03, 0x04])

    // Client identification
    .identification("device-enrollment-123".to_string())

    // Add certificate requests
    .add_certification_request(csr1_der)
    .add_certification_request(csr2_der)

    // Build the PKIData
    .build()?;

// Serialize to DER for transmission
let der_bytes = pki_data.to_der()?;
```

### Control Attributes

CMC control attributes provide metadata and transaction management:

#### Transaction ID

Unique identifier for tracking requests and responses:

```rust
use usg_est_client::types::cmc_full::{TaggedAttribute, BodyPartId};

let tx_id = TaggedAttribute::transaction_id(
    BodyPartId::new(1),
    12345
);
```

#### Sender Nonce

Random value for replay protection:

```rust
let nonce = TaggedAttribute::sender_nonce(
    BodyPartId::new(2),
    vec![0xAA, 0xBB, 0xCC, 0xDD]
);

// Or use random nonce generation
let pki_data = PkiDataBuilder::new()
    .random_sender_nonce()  // Generates cryptographically random nonce
    .build()?;
```

#### Identification

Human-readable client identifier:

```rust
let ident = TaggedAttribute::identification(
    BodyPartId::new(3),
    "engineering-device-001".to_string()
);
```

#### Available Control OIDs

```rust
use usg_est_client::types::cmc_full::oid;

// Core controls
oid::TRANSACTION_ID     // 1.3.6.1.5.5.7.7.5
oid::SENDER_NONCE       // 1.3.6.1.5.5.7.7.6
oid::RECIPIENT_NONCE    // 1.3.6.1.5.5.7.7.7
oid::IDENTIFICATION     // 1.3.6.1.5.5.7.7.2

// Status and response
oid::STATUS_INFO        // 1.3.6.1.5.5.7.7.1
oid::QUERY_PENDING      // 1.3.6.1.5.5.7.7.21

// Advanced operations
oid::REVOKE_REQUEST     // 1.3.6.1.5.5.7.7.17
oid::GET_CERT           // 1.3.6.1.5.5.7.7.15
oid::GET_CRL            // 1.3.6.1.5.5.7.7.16
```

### Batch Operations

Submit multiple certificate requests in a single transaction:

```rust
use usg_est_client::types::cmc_full::BatchRequest;

let mut batch = BatchRequest::new();

// Web server certificate
let pki_data1 = PkiDataBuilder::new()
    .transaction_id(1001)
    .add_certification_request(webserver_csr)
    .build()?;
batch.add_request(pki_data1);

// Client authentication certificate
let pki_data2 = PkiDataBuilder::new()
    .transaction_id(1002)
    .add_certification_request(client_csr)
    .build()?;
batch.add_request(pki_data2);

// Email signing certificate
let pki_data3 = PkiDataBuilder::new()
    .transaction_id(1003)
    .add_certification_request(email_csr)
    .build()?;
batch.add_request(pki_data3);

// Encode the entire batch
let batch_der = batch.to_der()?;

// Submit to server
let cmc_request = CmcRequest::new(batch_der);
let cmc_response = client.full_cmc(&cmc_request).await?;
```

### PKIResponse Parsing

Parse detailed response information:

```rust
use usg_est_client::types::cmc_full::PkiResponse;

let pki_response = PkiResponse::from_der(&cmc_response.data)?;

// Check status
if pki_response.is_success() {
    println!("All requests succeeded");
    println!("Certificates: {}", pki_response.certificates.len());
} else if pki_response.is_pending() {
    println!("Requests are pending manual approval");
} else if let Some(fail_info) = pki_response.fail_info() {
    println!("Request failed: {}", fail_info.description());
}
```

### CMC Status Values

Comprehensive status reporting:

```rust
use usg_est_client::types::cmc_full::{CmcStatusValue, CmcStatusInfo};

pub enum CmcStatusValue {
    Success = 0,           // Request granted
    Failed = 2,            // Request failed (see failInfo)
    Pending = 3,           // Awaiting approval
    NoSupport = 4,         // Operation not supported
    ConfirmRequired = 5,   // Confirmation needed
    PopRequired = 6,       // Proof of possession required
    Partial = 7,           // Some requests succeeded
}

// Check status
if status.is_success() {
    println!("Operation completed successfully");
} else if status.is_failure() {
    println!("Operation failed");
} else if status.is_pending() {
    println!("Operation is pending");
}
```

### CMC Failure Codes

Detailed failure information:

```rust
use usg_est_client::types::cmc_full::CmcFailInfo;

pub enum CmcFailInfo {
    BadAlgorithm = 0,       // Unsupported algorithm
    BadMessageCheck = 1,    // Signature verification failed
    BadRequest = 2,         // Malformed request
    BadTime = 3,            // Request time invalid/expired
    BadCertId = 4,          // Invalid certificate ID
    UnsupportedExt = 5,     // Unsupported extension
    MustArchiveKeys = 6,    // Key archival required
    BadIdentity = 7,        // Identity verification failed
    PopRequired = 8,        // Proof of possession required
    PopFailed = 9,          // POP verification failed
    NoKeyReuse = 10,        // Key reuse not allowed
    InternalCaError = 11,   // Internal CA error
    TryLater = 12,          // Server busy, retry
    AuthDataFail = 13,      // Authentication failed
}

// Get human-readable description
let description = fail_info.description();
println!("Failure reason: {}", description);
```

### Status Info Structure

```rust
use usg_est_client::types::cmc_full::{CmcStatusInfo, BodyPartId};

pub struct CmcStatusInfo {
    pub status: CmcStatusValue,
    pub body_list: Vec<BodyPartId>,      // Affected request parts
    pub status_string: Option<String>,   // Human-readable message
    pub fail_info: Option<CmcFailInfo>,  // Failure details
    pub pending_info: Option<PendingInfo>, // Pending operation info
}

// Create status info
let success = CmcStatusInfo::success(vec![BodyPartId::new(1)]);

let failed = CmcStatusInfo::failed(
    vec![BodyPartId::new(2)],
    CmcFailInfo::BadRequest
);

let pending = CmcStatusInfo::pending(
    vec![BodyPartId::new(3)],
    PendingInfo {
        pending_token: vec![0x01, 0x02],
        pending_time: Some(3600), // Retry after 1 hour
    }
);
```

### Body Part IDs

Reference specific parts of CMC messages:

```rust
use usg_est_client::types::cmc_full::BodyPartId;

// Create body part ID
let id = BodyPartId::new(42);

// Get numeric value
let value = id.value(); // Returns: 42

// Used to link controls to requests
let control = TaggedAttribute::transaction_id(
    BodyPartId::new(1),  // References this body part
    12345
);
```

### Complete Example

See the comprehensive example in `examples/cmc_advanced.rs`:

```bash
# Run the CMC example (demonstrates all features)
cargo run --example cmc_advanced --features csr-gen

# Attempt live CMC request to a server
cargo run --example cmc_advanced --features csr-gen -- \
    --server https://est.example.com \
    --live
```

The example demonstrates:

- Building PKIData with multiple controls
- Batch operations with 3 certificate requests
- Status value and failure code handling
- All available control attributes
- Live server communication (optional)

### Request Format

- **Method**: POST
- **Content-Type**: `application/pkcs7-mime; smime-type=CMC-Request`
- **Body**: Base64-encoded CMC PKIData
- **Authentication**: Optional (HTTP Basic or TLS client certificate)

### Response Format

- **HTTP 200**: Success
- **Content-Type**: `application/pkcs7-mime; smime-type=CMC-Response`
- **Body**: Base64-encoded CMC PKIResponse

### CMC Use Cases

#### Multiple Certificate Requests

```rust
// Request certificates for multiple purposes in one transaction
let batch = BatchRequest::new();
batch.add_request(build_tls_server_request()?);
batch.add_request(build_tls_client_request()?);
batch.add_request(build_email_signing_request()?);
```

#### Certificate Revocation

```rust
// Use revocation control (requires server support)
use usg_est_client::types::cmc_full::oid;

let revoke_control = TaggedAttribute::new(
    BodyPartId::new(1),
    oid::REVOKE_REQUEST,
    revocation_data
);
```

#### Transaction Tracking

```rust
// Use transaction ID and nonces for reliable tracking
let pki_data = PkiDataBuilder::new()
    .transaction_id(generate_unique_id())
    .random_sender_nonce()
    .build()?;

// Server will include recipient nonce in response
// for correlation and replay protection
```

### CMC Server Support

Full CMC is **optional** in EST. Check server support:

```rust
// Attempt CMC operation
match client.full_cmc(&cmc_request).await {
    Ok(response) => {
        // Server supports Full CMC
        println!("CMC supported: {:?}", response.status);
    }
    Err(EstError::ServerError { status: 501, .. }) => {
        println!("Server does not support Full CMC (501 Not Implemented)");
        println!("Fall back to simple enrollment");
    }
    Err(e) => return Err(e.into()),
}
```

### Security Considerations

- **Authentication**: Full CMC requests should use strong authentication (TLS client certificates preferred)
- **Replay Protection**: Always include sender nonce for replay attack prevention
- **Transaction IDs**: Use cryptographically random or sequentially unique transaction IDs
- **Signature Verification**: Servers SHOULD verify request signatures
- **Authorization**: Servers MUST verify client authorization for requested operations

### RFC References

- **RFC 7030 Section 4.3**: Full CMC in EST
- **RFC 5272**: Certificate Management over CMS (CMC)
- **RFC 5273**: CMC Transport Protocols
- **RFC 5274**: CMC Compliance Requirements

---

## Automatic Certificate Renewal

The library provides automatic certificate renewal capabilities through the `renewal` feature. This allows certificates to be monitored for expiration and automatically renewed before they expire.

### Overview

The automatic renewal system consists of:

- **RenewalScheduler**: Background task that monitors certificate expiration
- **RenewalConfig**: Configuration for renewal behavior
- **RenewalEventHandler**: Trait for handling renewal events

### Renewal Basic Usage

```rust
use usg_est_client::renewal::{RenewalScheduler, RenewalConfig};
use std::time::Duration;

// Create EST client
let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .build()?;

let client = EstClient::new(config).await?;

// Configure renewal behavior
let renewal_config = RenewalConfig::builder()
    .renewal_threshold(Duration::from_secs(30 * 24 * 60 * 60))  // 30 days
    .check_interval(Duration::from_secs(24 * 60 * 60))          // Check daily
    .max_retries(3)
    .build();

// Create and start the scheduler
let scheduler = RenewalScheduler::new(client, renewal_config);

// The scheduler will now:
// 1. Check certificate expiration daily
// 2. Trigger renewal 30 days before expiration
// 3. Retry up to 3 times on failure
```

### Configuration Options

The `RenewalConfig` provides fine-grained control over renewal behavior:

```rust
let config = RenewalConfig::builder()
    // When to renew: 30 days before expiration
    .renewal_threshold(Duration::from_secs(30 * 24 * 60 * 60))

    // How often to check: every 24 hours
    .check_interval(Duration::from_secs(24 * 60 * 60))

    // Retry behavior
    .max_retries(3)
    .initial_retry_delay(Duration::from_secs(1))

    // Event handling (optional)
    // .event_callback(handler)

    .build();
```

#### Configuration Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `renewal_threshold` | `Duration` | How far before expiration to trigger renewal | Required |
| `check_interval` | `Duration` | How often to check certificate expiration | Required |
| `max_retries` | `u32` | Maximum number of retry attempts | `3` |
| `initial_retry_delay` | `Duration` | Initial delay before first retry | `1s` |

### Retry Behavior

Failed renewal attempts are automatically retried with exponential backoff:

- **Attempt 1**: Immediate (on threshold)
- **Attempt 2**: After 1 second
- **Attempt 3**: After 2 seconds (2^1)
- **Attempt 4**: After 4 seconds (2^2)
- etc.

The retry delay doubles with each attempt, providing graceful degradation during temporary server unavailability.

### Event Handling

Implement the `RenewalEventHandler` trait to receive notifications about renewal events:

```rust
use usg_est_client::renewal::{RenewalEvent, RenewalEventHandler};

struct MyEventHandler;

impl RenewalEventHandler for MyEventHandler {
    fn on_event(&self, event: &RenewalEvent) {
        match event {
            RenewalEvent::CheckStarted => {
                println!("Starting expiration check");
            }
            RenewalEvent::RenewalNeeded { expires_at } => {
                println!("Certificate expires at {:?}, renewal needed", expires_at);
            }
            RenewalEvent::RenewalStarted => {
                println!("Beginning renewal attempt");
            }
            RenewalEvent::RenewalSucceeded { certificate } => {
                println!("Renewal succeeded!");
                // Save new certificate
            }
            RenewalEvent::RenewalFailed { error, attempt } => {
                eprintln!("Renewal attempt {} failed: {}", attempt, error);
            }
            RenewalEvent::RenewalExhausted { last_error } => {
                eprintln!("All renewal attempts exhausted: {}", last_error);
                // Alert operators
            }
        }
    }
}

// Configure with event handler
let config = RenewalConfig::builder()
    .renewal_threshold(Duration::from_secs(30 * 24 * 60 * 60))
    .check_interval(Duration::from_secs(24 * 60 * 60))
    .event_callback(Arc::new(MyEventHandler))
    .build();
```

### Renewal Events

The `RenewalEvent` enum provides detailed information about the renewal lifecycle:

- **CheckStarted**: Periodic expiration check initiated
- **RenewalNeeded**: Certificate is nearing expiration (within threshold)
- **RenewalStarted**: Renewal attempt beginning
- **RenewalSucceeded**: New certificate successfully obtained
- **RenewalFailed**: Renewal attempt failed (will retry if attempts remain)
- **RenewalExhausted**: All retry attempts exhausted

### Integration with Simple Re-enrollment

The renewal scheduler uses the `simple_reenroll` operation internally:

```rust
// The scheduler does this automatically:
let new_cert = client.simple_reenroll(&csr_der).await?;
```

You can also trigger manual renewal:

```rust
// Generate new CSR with existing or new key pair
let (csr_der, key_pair) = CsrBuilder::new()
    .common_name("device.example.com")
    .build()?;

// Submit re-enrollment request
match client.simple_reenroll(&csr_der).await? {
    EnrollmentResponse::Issued { certificate } => {
        // Replace old certificate with new one
    }
    EnrollmentResponse::Pending { retry_after } => {
        // Handle pending state
    }
}
```

### Best Practices

#### 1. Choose Appropriate Thresholds

```rust
// Production: Renew 30 days before expiration
.renewal_threshold(Duration::from_secs(30 * 24 * 60 * 60))

// Short-lived certificates: Renew at 50% of lifetime
// For a 7-day cert, renew after 3.5 days
.renewal_threshold(Duration::from_secs(3 * 24 * 60 * 60 + 12 * 60 * 60))
```

**Recommendations**:

- For 1-year certificates: 30-60 days before expiration
- For 90-day certificates: 15-30 days before expiration
- For short-lived certificates (7 days): 50% of lifetime

#### 2. Monitor Renewal Events

Always implement event handlers to track renewal success/failure:

```rust
impl RenewalEventHandler for ProductionHandler {
    fn on_event(&self, event: &RenewalEvent) {
        match event {
            RenewalEvent::RenewalSucceeded { .. } => {
                // Log success to monitoring system
                metrics.increment("cert_renewal_success");
            }
            RenewalEvent::RenewalExhausted { last_error } => {
                // Alert on-call team
                alert_ops("Certificate renewal failed", last_error);
            }
            _ => {}
        }
    }
}
```

#### 3. Handle Renewal Failures Gracefully

```rust
RenewalEvent::RenewalExhausted { last_error } => {
    // 1. Alert operators immediately
    send_alert("Critical: Certificate renewal failed");

    // 2. Log detailed error information
    error!("Renewal exhausted after all retries: {}", last_error);

    // 3. Consider fallback options:
    //    - Manual intervention
    //    - Secondary EST server
    //    - Certificate from backup CA
}
```

#### 4. Persist Certificate State

```rust
RenewalEvent::RenewalSucceeded { certificate } => {
    // Atomically replace certificate
    let cert_pem = pem::encode(&Pem::new("CERTIFICATE", certificate_der));

    // Write to temporary file first
    fs::write("/etc/pki/cert.pem.new", cert_pem)?;

    // Atomic rename
    fs::rename("/etc/pki/cert.pem.new", "/etc/pki/cert.pem")?;

    // Reload services using the certificate
    reload_tls_services()?;
}
```

#### 5. Test Renewal Process

```rust
// Test renewal workflow before deployment
#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn test_renewal_workflow() {
        let config = RenewalConfig::builder()
            .renewal_threshold(Duration::from_secs(60))  // 1 minute for testing
            .check_interval(Duration::from_secs(10))
            .build();

        // Verify scheduler triggers renewal correctly
    }
}
```

### Production Deployment

#### Systemd Service Example

```ini
[Unit]
Description=EST Certificate Renewal Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/my-est-client-daemon
Restart=always
RestartSec=10

# Security hardening
PrivateTmp=true
NoNewPrivileges=true
ReadOnlyPaths=/usr
ReadWritePaths=/var/lib/my-app/certs

[Install]
WantedBy=multi-user.target
```

#### Docker Container

```dockerfile
FROM rust:1.70 as builder
WORKDIR /app
COPY . .
RUN cargo build --release --features renewal

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates
COPY --from=builder /app/target/release/my-est-client /usr/local/bin/
CMD ["my-est-client"]
```

#### Kubernetes CronJob

For environments where persistent renewal daemons are not desired:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: cert-renewal-check
spec:
  schedule: "0 0 * * *"  # Daily at midnight
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: renewal
            image: my-est-client:latest
            args: ["--check-renewal"]
          restartPolicy: OnFailure
```

### Monitoring and Alerting

Key metrics to track:

```rust
// Example with custom metrics
impl RenewalEventHandler for MetricsHandler {
    fn on_event(&self, event: &RenewalEvent) {
        match event {
            RenewalEvent::CheckStarted => {
                metrics.increment("renewal_checks_total");
            }
            RenewalEvent::RenewalNeeded { expires_at } => {
                let days_until_expiry = (*expires_at - SystemTime::now())
                    .as_secs() / (24 * 60 * 60);
                metrics.gauge("cert_days_until_expiry", days_until_expiry as f64);
            }
            RenewalEvent::RenewalSucceeded { .. } => {
                metrics.increment("renewal_success_total");
                metrics.gauge("renewal_last_success_timestamp", unix_timestamp());
            }
            RenewalEvent::RenewalFailed { .. } => {
                metrics.increment("renewal_failures_total");
            }
            RenewalEvent::RenewalExhausted { .. } => {
                metrics.increment("renewal_exhausted_total");
                // Trigger PagerDuty/OpsGenie alert
                alert_critical("Certificate renewal failed completely");
            }
            _ => {}
        }
    }
}
```

**Recommended Alerts**:

1. Certificate expires in < 14 days (Warning)
2. Certificate expires in < 7 days (Critical)
3. Renewal failed (Warning)
4. Renewal exhausted after all retries (Critical)
5. No successful renewal in > 30 days (Warning)

### Renewal vs. Manual Re-enrollment

| Aspect | Automatic Renewal | Manual Re-enrollment |
|--------|-------------------|---------------------|
| Trigger | Time-based (threshold) | Explicit API call |
| Scheduling | Built-in scheduler | Your responsibility |
| Retries | Automatic exponential backoff | Manual implementation |
| Events | RenewalEventHandler trait | Return values only |
| Use Case | Production services | Testing, one-time renewal |

### Security Considerations

1. **Certificate Storage**: Protect renewed certificates with appropriate file permissions
2. **Private Key Protection**: Consider using HSM for private keys (see HSM documentation)
3. **Audit Logging**: Log all renewal events for security audit trails
4. **Time Synchronization**: Ensure system clock is accurate (NTP) for expiration checks
5. **Graceful Degradation**: Plan for renewal failures with sufficient threshold margins

### Troubleshooting

#### Renewal Not Triggering

```rust
// Check scheduler is actually running
let scheduler = RenewalScheduler::new(client, config);
// Don't drop the scheduler! It stops when dropped.
```

#### Repeated Failures

```rust
RenewalEvent::RenewalFailed { error, .. } => {
    // Common issues:
    match error {
        EstError::AuthenticationRequired { .. } => {
            // Client certificate expired or invalid
            error!("Authentication failed - check client certificate");
        }
        EstError::NetworkError { .. } => {
            // Network connectivity issues
            error!("Network error - check EST server reachability");
        }
        EstError::ServerError { status: 429, .. } => {
            // Rate limited
            error!("Rate limited by server");
        }
        _ => error!("Renewal failed: {}", error),
    }
}
```

#### Certificate Not Updated After Renewal

Ensure you're handling the `RenewalSucceeded` event and persisting the new certificate:

```rust
RenewalEvent::RenewalSucceeded { certificate } => {
    // Must save certificate AND reload TLS configuration
    save_certificate(certificate)?;
    reload_tls_config()?;  // Don't forget this!
}
```

### See Also

- [Simple Re-enrollment](#simple-re-enrollment-simplereenroll) - Manual re-enrollment
- [Configuration Guide](configuration.md) - EST client configuration
- [Security Considerations](security.md) - Security best practices
- [Examples](../examples/auto_renewal.rs) - Complete renewal example

---

## Error Handling

All operations can return errors. Common error patterns:

```rust
use usg_est_client::EstError;

match client.simple_enroll(&csr_der).await {
    Ok(response) => {
        // Handle success
    }
    Err(EstError::AuthenticationRequired { challenge }) => {
        println!("Auth required: {}", challenge);
    }
    Err(EstError::ServerError { status, message }) => {
        println!("Server error {}: {}", status, message);
    }
    Err(EstError::NotSupported { operation }) => {
        println!("Operation {} not supported", operation);
    }
    Err(EstError::TlsConfig(msg)) => {
        println!("TLS configuration error: {}", msg);
    }
    Err(e) => {
        println!("Error: {}", e);
    }
}
```

## Multi-CA Deployments

EST servers can support multiple CAs using labels:

```rust
let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .ca_label("engineering-ca")  // Use specific CA
    .build()?;

// This will use URLs like:
// https://est.example.com/.well-known/est/engineering-ca/cacerts
// https://est.example.com/.well-known/est/engineering-ca/simpleenroll
```

## Next Steps

- Review [Configuration](configuration.md) for advanced options
- Read [Security Considerations](security.md)
- Explore [Examples](examples.md) for complete workflows
