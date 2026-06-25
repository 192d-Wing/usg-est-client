# API Reference

Complete API reference for the `usg-est-client` library.

## Core Types

### EstClient

Main client for EST operations.

```rust
pub struct EstClient { /* ... */ }
```

#### Methods

##### `new`
```rust
pub async fn new(config: EstClientConfig) -> Result<Self>
```

Create a new EST client with the given configuration.

**Example:**
```rust
let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .build()?;
let client = EstClient::new(config).await?;
```

---

##### `get_ca_certs`
```rust
pub async fn get_ca_certs(&self) -> Result<CaCertificates>
```

Retrieve CA certificates from the EST server (`GET /cacerts`).

**Returns:** `CaCertificates` containing one or more CA certificates.

**Example:**
```rust
let ca_certs = client.get_ca_certs().await?;
```

---

##### `simple_enroll`
```rust
pub async fn simple_enroll(&self, csr_der: &[u8]) -> Result<EnrollmentResponse>
```

Enroll for a new certificate (`POST /simpleenroll`).

**Parameters:**
- `csr_der`: DER-encoded PKCS#10 Certificate Signing Request

**Returns:** `EnrollmentResponse` (Issued or Pending)

**Example:**
```rust
match client.simple_enroll(&csr_der).await? {
    EnrollmentResponse::Issued { certificate } => { /* ... */ }
    EnrollmentResponse::Pending { retry_after } => { /* ... */ }
}
```

---

##### `simple_reenroll`
```rust
pub async fn simple_reenroll(&self, csr_der: &[u8]) -> Result<EnrollmentResponse>
```

Re-enroll (renew/rekey) an existing certificate (`POST /simplereenroll`).

**Parameters:**
- `csr_der`: DER-encoded PKCS#10 Certificate Signing Request

**Returns:** `EnrollmentResponse` (Issued or Pending)

**Note:** Requires TLS client certificate authentication.

**Example:**
```rust
let response = client.simple_reenroll(&csr_der).await?;
```

---

##### `get_csr_attributes`
```rust
pub async fn get_csr_attributes(&self) -> Result<CsrAttributes>
```

Query the server for required CSR attributes (`GET /csrattrs`).

**Returns:** `CsrAttributes` containing required attribute OIDs

**Errors:** Returns `EstError::NotSupported` if the server doesn't support this operation.

**Example:**
```rust
match client.get_csr_attributes().await {
    Ok(attrs) => { /* Use attributes */ }
    Err(EstError::NotSupported { .. }) => { /* Optional operation */ }
    Err(e) => return Err(e),
}
```

---

##### `server_keygen`
```rust
pub async fn server_keygen(&self, csr_der: &[u8]) -> Result<ServerKeygenResponse>
```

Request server-side key generation (`POST /serverkeygen`).

**Parameters:**
- `csr_der`: DER-encoded PKCS#10 CSR (public key is placeholder)

**Returns:** `ServerKeygenResponse` with certificate and private key

**Example:**
```rust
let response = client.server_keygen(&csr_der).await?;
```

---

##### `full_cmc`
```rust
pub async fn full_cmc(&self, request: &CmcRequest) -> Result<CmcResponse>
```

Submit a Full CMC request (`POST /fullcmc`).

**Parameters:**
- `request`: CMC PKIData request

**Returns:** `CmcResponse` containing CMC PKIResponse

**Example:**
```rust
let cmc_request = CmcRequest::new(cmc_data);
let response = client.full_cmc(&cmc_request).await?;
```

---

##### `config`
```rust
pub fn config(&self) -> &EstClientConfig
```

Get a reference to the client configuration.

---

## Configuration

### EstClientConfig

Configuration for the EST client.

```rust
pub struct EstClientConfig {
    pub server_url: Url,
    pub ca_label: Option<String>,
    pub client_identity: Option<ClientIdentity>,
    pub http_auth: Option<HttpAuth>,
    pub trust_anchors: TrustAnchors,
    pub timeout: Duration,
    pub channel_binding: bool,
}
```

#### Methods

##### `builder`
```rust
pub fn builder() -> EstClientConfigBuilder
```

Create a new configuration builder.

**Example:**
```rust
let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .build()?;
```

---

##### `build_url`
```rust
pub fn build_url(&self, operation: &str) -> Url
```

Build a full URL for an EST operation.

---

### EstClientConfigBuilder

Builder for `EstClientConfig`.

#### Methods

##### `server_url`
```rust
pub fn server_url(self, url: &str) -> Result<Self, url::ParseError>
```

Set the EST server URL (required).

---

##### `ca_label`
```rust
pub fn ca_label(self, label: impl Into<String>) -> Self
```

Set the CA label for multi-CA deployments (optional).

---

##### `client_identity`
```rust
pub fn client_identity(self, identity: ClientIdentity) -> Self
```

Set client certificate identity for TLS authentication (optional).

---

##### `http_auth`
```rust
pub fn http_auth(self, auth: HttpAuth) -> Self
```

Set HTTP Basic authentication credentials (optional).

---

##### `trust_explicit`
```rust
pub fn trust_explicit(self, ca_certs: Vec<Vec<u8>>) -> Self
```

Use explicit CA certificates for trust anchors.

**Parameters:**
- `ca_certs`: Vector of PEM-encoded CA certificates

---

##### `trust_any_insecure`
```rust
pub fn trust_any_insecure(self) -> Self
```

Disable certificate validation (INSECURE - testing only).

---

##### `timeout`
```rust
pub fn timeout(self, timeout: Duration) -> Self
```

Set request timeout (default: 30 seconds).

---

##### `channel_binding`
```rust
pub fn channel_binding(self, enabled: bool) -> Self
```

Enable TLS channel binding for challenge-password.

---

##### `build`
```rust
pub fn build(self) -> Result<EstClientConfig, &'static str>
```

Build the configuration.

**Errors:** Returns error if server_url is not set.

---

## Response Types

### EnrollmentResponse

Response from enrollment or re-enrollment operations.

```rust
pub enum EnrollmentResponse {
    Issued {
        certificate: Certificate,
    },
    Pending {
        retry_after: u64,
    },
}
```

#### Methods

##### `certificate`
```rust
pub fn certificate(&self) -> Option<&Certificate>
```

Returns the certificate if issued.

---

##### `is_pending`
```rust
pub fn is_pending(&self) -> bool
```

Returns true if enrollment is pending.

---

##### `retry_after`
```rust
pub fn retry_after(&self) -> Option<u64>
```

Returns retry-after value if pending.

---

##### `issued` / `pending` (constructors)
```rust
pub fn issued(certificate: Certificate) -> Self
pub fn pending(retry_after: u64) -> Self
```

---

### CaCertificates

Collection of CA certificates.

```rust
pub struct CaCertificates {
    certificates: Vec<Certificate>,
}
```

#### Methods

##### `new`
```rust
pub fn new(certificates: Vec<Certificate>) -> Self
```

---

##### `len` / `is_empty`
```rust
pub fn len(&self) -> usize
pub fn is_empty(&self) -> bool
```

---

##### `iter`
```rust
pub fn iter(&self) -> impl Iterator<Item = &Certificate>
```

---

##### `to_pem_vec`
```rust
pub fn to_pem_vec(&self) -> Result<Vec<Vec<u8>>>
```

Convert certificates to PEM format.

---

### ServerKeygenResponse

Response from server key generation.

```rust
pub struct ServerKeygenResponse {
    pub certificate: Certificate,
    pub private_key: Vec<u8>,
    pub key_encrypted: bool,
}
```

#### Methods

##### `new`
```rust
pub fn new(certificate: Certificate, private_key: Vec<u8>, key_encrypted: bool) -> Self
```

---

### CsrAttributes

CSR attribute requirements from the server.

```rust
pub struct CsrAttributes {
    pub attributes: Vec<CsrAttribute>,
}
```

#### Methods

##### `parse`
```rust
pub fn parse(body: &[u8]) -> Result<Self>
```

Parse from base64-encoded response body.

---

##### `is_empty` / `len`
```rust
pub fn is_empty(&self) -> bool
pub fn len(&self) -> usize
```

---

##### `contains_oid`
```rust
pub fn contains_oid(&self, oid: &ObjectIdentifier) -> bool
```

Check if a specific OID is required.

---

##### `oids`
```rust
pub fn oids(&self) -> Vec<ObjectIdentifier>
```

Get all attribute OIDs.

---

### CsrAttribute

Individual CSR attribute.

```rust
pub struct CsrAttribute {
    pub oid: ObjectIdentifier,
    pub values: Vec<Vec<u8>>,
}
```

#### Methods

##### `new`
```rust
pub fn new(oid: ObjectIdentifier) -> Self
```

---

##### `with_values`
```rust
pub fn with_values(oid: ObjectIdentifier, values: Vec<Vec<u8>>) -> Self
```

---

##### `has_values`
```rust
pub fn has_values(&self) -> bool
```

---

## CMC Types

### CmcRequest

CMC PKIData request message.

```rust
pub struct CmcRequest {
    pub data: Vec<u8>,
}
```

#### Methods

##### `new` / `from_der`
```rust
pub fn new(data: impl Into<Vec<u8>>) -> Self
pub fn from_der(data: Vec<u8>) -> Self
```

---

##### `as_bytes`
```rust
pub fn as_bytes(&self) -> &[u8]
```

---

##### `encode_base64`
```rust
pub fn encode_base64(&self) -> String
```

---

### CmcResponse

CMC PKIResponse message.

```rust
pub struct CmcResponse {
    pub data: Vec<u8>,
    pub certificates: Vec<Certificate>,
    pub status: CmcStatus,
}
```

#### Methods

##### `parse`
```rust
pub fn parse(body: &[u8]) -> Result<Self>
```

---

##### `is_success`
```rust
pub fn is_success(&self) -> bool
```

---

### CmcStatus

CMC operation status.

```rust
pub enum CmcStatus {
    Success,
    Failed,
    Pending,
    NoSupport,
    ConfirmRequired,
    PopRequired,
    Partial,
}
```

#### Methods

##### `from_code` / `to_code`
```rust
pub fn from_code(code: u32) -> Self
pub fn to_code(self) -> u32
```

---

## CSR Generation (Feature: csr-gen)

### CsrBuilder

Builder for generating Certificate Signing Requests.

```rust
pub struct CsrBuilder { /* ... */ }
```

#### Methods

##### `new`
```rust
pub fn new() -> Self
```

---

##### Subject Methods

```rust
pub fn common_name(self, cn: impl Into<String>) -> Self
pub fn organization(self, org: impl Into<String>) -> Self
pub fn organizational_unit(self, ou: impl Into<String>) -> Self
pub fn country(self, country: impl Into<String>) -> Self
pub fn state(self, state: impl Into<String>) -> Self
pub fn locality(self, locality: impl Into<String>) -> Self
```

---

##### SAN Methods

```rust
pub fn san_dns(self, dns: impl Into<String>) -> Self
pub fn san_ip(self, ip: IpAddr) -> Self
pub fn san_email(self, email: impl Into<String>) -> Self
pub fn san_uri(self, uri: impl Into<String>) -> Self
```

---

##### Key Usage Methods

```rust
pub fn key_usage_digital_signature(self) -> Self
pub fn key_usage_key_encipherment(self) -> Self
pub fn key_usage_key_agreement(self) -> Self

pub fn extended_key_usage_client_auth(self) -> Self
pub fn extended_key_usage_server_auth(self) -> Self
```

---

##### Build Methods

```rust
pub fn build(self) -> Result<(Vec<u8>, KeyPair)>
```

Build CSR with a new ECDSA P-256 key pair.

**Returns:** (DER-encoded CSR, KeyPair)

---

```rust
pub fn build_with_key(self, key_pair: &KeyPair) -> Result<Vec<u8>>
```

Build CSR using the provided key pair.

**Returns:** DER-encoded CSR

---

```rust
pub fn with_key_pair(self, key_pair: KeyPair) -> Self
```

Use an existing key pair.

---

```rust
pub fn with_attributes(self, attrs: &CsrAttributes) -> Self
```

Apply server CSR attributes.

---

### Helper Functions

```rust
pub fn generate_device_csr(
    common_name: &str,
    organization: Option<&str>,
) -> Result<(Vec<u8>, KeyPair)>
```

Generate a simple CSR for a device.

---

```rust
pub fn generate_server_csr(
    common_name: &str,
    san_names: &[&str],
) -> Result<(Vec<u8>, KeyPair)>
```

Generate a CSR for a TLS server.

---

## Bootstrap

### BootstrapClient

Client for bootstrap/TOFU mode.

```rust
pub struct BootstrapClient { /* ... */ }
```

#### Methods

##### `new`
```rust
pub fn new(server_url: &str) -> Result<Self>
```

Create a new bootstrap client.

---

##### `fetch_ca_certs`
```rust
pub async fn fetch_ca_certs(&self)
    -> Result<(Vec<Certificate>, Vec<[u8; 32]>)>
```

Fetch CA certificates without verification (TOFU).

**Returns:** (Certificates, SHA-256 fingerprints)

---

##### `format_fingerprint`
```rust
pub fn format_fingerprint(fp: &[u8; 32]) -> String
```

Format fingerprint as hex string (AA:BB:CC:...).

---

##### `parse_fingerprint`
```rust
pub fn parse_fingerprint(s: &str) -> Result<[u8; 32]>
```

Parse fingerprint from hex string.

---

##### `get_subject_cn`
```rust
pub fn get_subject_cn(cert: &Certificate) -> Option<String>
```

Extract Common Name from certificate subject.

---

## Authentication

### ClientIdentity

TLS client certificate identity.

```rust
pub struct ClientIdentity {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
}
```

#### Methods

##### `new`
```rust
pub fn new(cert_pem: Vec<u8>, key_pem: Vec<u8>) -> Self
```

---

### HttpAuth

HTTP Basic authentication credentials.

```rust
pub struct HttpAuth {
    pub username: String,
    pub password: String,
}
```

---

## Error Types

### EstError

Main error type.

```rust
pub enum EstError {
    TlsConfig(String),
    Http(reqwest::Error),
    InvalidContentType { expected: String, actual: String },
    CertificateParsing(String),
    CmsParsing(String),
    CsrGeneration(String),
    ServerError { status: u16, message: String },
    EnrollmentPending { retry_after: u64 },
    AuthenticationRequired { challenge: String },
    Base64(base64::DecodeError),
    Der(der::Error),
    Url(url::ParseError),
    BootstrapVerification(String),
    MissingHeader(String),
    InvalidMultipart(String),
    NotSupported { operation: String },
}
```

#### Methods

##### Error Constructors

```rust
pub fn tls_config(msg: impl Into<String>) -> Self
pub fn invalid_content_type(expected: &str, actual: &str) -> Self
pub fn certificate_parsing(msg: impl Into<String>) -> Self
pub fn cms_parsing(msg: impl Into<String>) -> Self
pub fn csr(msg: impl Into<String>) -> Self
pub fn server_error(status: u16, msg: impl Into<String>) -> Self
pub fn authentication_required(challenge: impl Into<String>) -> Self
pub fn bootstrap_verification(msg: impl Into<String>) -> Self
pub fn invalid_multipart(msg: impl Into<String>) -> Self
pub fn not_supported(operation: impl Into<String>) -> Self
```

---

##### `is_retryable`
```rust
pub fn is_retryable(&self) -> bool
```

Returns true if the error is retryable.

---

##### `retry_after`
```rust
pub fn retry_after(&self) -> Option<u64>
```

Returns retry-after value for retryable errors.

---

## Re-exports

```rust
pub use x509_cert::Certificate;
```

X.509 certificate type from the `x509-cert` crate.

---

## Constants

### Content Types

```rust
pub mod content_types {
    pub const PKCS10: &str = "application/pkcs10";
    pub const PKCS7_MIME: &str = "application/pkcs7-mime";
    pub const PKCS7_CERTS_ONLY: &str = "application/pkcs7-mime; smime-type=certs-only";
    pub const PKCS8: &str = "application/pkcs8";
    pub const CSR_ATTRS: &str = "application/csrattrs";
    pub const CMC_REQUEST: &str = "application/pkcs7-mime; smime-type=CMC-request";
    pub const CMC_RESPONSE: &str = "application/pkcs7-mime; smime-type=CMC-response";
    pub const MULTIPART_MIXED: &str = "multipart/mixed";
}
```

---

### Operations

```rust
pub mod operations {
    pub const CACERTS: &str = "cacerts";
    pub const SIMPLE_ENROLL: &str = "simpleenroll";
    pub const SIMPLE_REENROLL: &str = "simplereenroll";
    pub const CSR_ATTRS: &str = "csrattrs";
    pub const SERVER_KEYGEN: &str = "serverkeygen";
    pub const FULL_CMC: &str = "fullcmc";
}
```

---

### CSR Attribute OIDs

```rust
pub mod csr_attrs::oids {
    pub const CHALLENGE_PASSWORD: ObjectIdentifier;     // 1.2.840.113549.1.9.7
    pub const EXTENSION_REQUEST: ObjectIdentifier;      // 1.2.840.113549.1.9.14
    pub const SUBJECT_ALT_NAME: ObjectIdentifier;       // 2.5.29.17
    pub const KEY_USAGE: ObjectIdentifier;              // 2.5.29.15
    pub const EXTENDED_KEY_USAGE: ObjectIdentifier;     // 2.5.29.37
    pub const BASIC_CONSTRAINTS: ObjectIdentifier;      // 2.5.29.19
}
```

---

## Version Information

```rust
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
```

Library version string.
