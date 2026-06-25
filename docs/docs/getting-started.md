# Getting Started

This guide will help you get started with `usg-est-client` for certificate enrollment and management.

## Installation

Add `usg-est-client` to your `Cargo.toml`:

```toml
[dependencies]
usg-est-client = "2.1"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

### Feature Flags

The library supports optional features:

```toml
[dependencies]
usg-est-client = { version = "2.1", features = ["csr-gen"] }
```

- `csr-gen` (default): Enables CSR generation helpers using the `rcgen` crate
- `default`: Includes `csr-gen`

To use the library without CSR generation:

```toml
[dependencies]
usg-est-client = { version = "2.1", default-features = false }
```

## Basic Usage

### 1. Create a Client

The first step is to create an `EstClient` with appropriate configuration:

```rust
use usg_est_client::{EstClient, EstClientConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Build configuration
    let config = EstClientConfig::builder()
        .server_url("https://est.example.com")?
        .build()?;

    // Create client
    let client = EstClient::new(config).await?;

    Ok(())
}
```

### 2. Retrieve CA Certificates

Before enrolling, you typically want to retrieve the CA certificates:

```rust
let ca_certs = client.get_ca_certs().await?;

for cert in ca_certs.iter() {
    println!("CA Certificate: {:?}", cert.tbs_certificate.subject);
}
```

### 3. Generate a CSR (with csr-gen feature)

```rust
use usg_est_client::csr::CsrBuilder;

let (csr_der, key_pair) = CsrBuilder::new()
    .common_name("device.example.com")
    .organization("Example Corp")
    .country("US")
    .san_dns("device.example.com")
    .key_usage_digital_signature()
    .key_usage_key_encipherment()
    .extended_key_usage_client_auth()
    .build()?;

// Save the key_pair securely - you'll need it later!
```

### 4. Enroll for a Certificate

```rust
use usg_est_client::EnrollmentResponse;

match client.simple_enroll(&csr_der).await? {
    EnrollmentResponse::Issued { certificate } => {
        println!("Certificate issued!");
        println!("Serial: {:?}", certificate.tbs_certificate.serial_number);
        // Save the certificate
    }
    EnrollmentResponse::Pending { retry_after } => {
        println!("Enrollment pending approval");
        println!("Retry after {} seconds", retry_after);
        // Implement retry logic
    }
}
```

## Complete Example

Here's a complete example that ties everything together:

```rust
use usg_est_client::{
    csr::CsrBuilder,
    EnrollmentResponse,
    EstClient,
    EstClientConfig,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Configure client
    let config = EstClientConfig::builder()
        .server_url("https://est.example.com")?
        .build()?;

    // 2. Create client
    let client = EstClient::new(config).await?;

    // 3. Get CA certificates (optional but recommended)
    let ca_certs = client.get_ca_certs().await?;
    println!("Retrieved {} CA certificate(s)", ca_certs.len());

    // 4. Check what the server requires (optional)
    match client.get_csr_attributes().await {
        Ok(attrs) => {
            if !attrs.is_empty() {
                println!("Server requires {} attributes", attrs.len());
            }
        }
        Err(_) => {
            println!("Server does not provide CSR attributes");
        }
    }

    // 5. Generate CSR
    let (csr_der, key_pair) = CsrBuilder::new()
        .common_name("mydevice.example.com")
        .organization("My Organization")
        .country("US")
        .san_dns("mydevice.example.com")
        .key_usage_digital_signature()
        .key_usage_key_encipherment()
        .extended_key_usage_client_auth()
        .build()?;

    // 6. Enroll
    match client.simple_enroll(&csr_der).await? {
        EnrollmentResponse::Issued { certificate } => {
            println!("✓ Certificate issued successfully!");

            // Save certificate (example - use proper file handling)
            use der::Encode;
            let cert_der = certificate.to_der()?;
            std::fs::write("certificate.der", cert_der)?;

            // Save private key (example - use proper secure storage)
            std::fs::write("private-key.pem", key_pair.serialize_pem())?;

            println!("Certificate and key saved.");
        }
        EnrollmentResponse::Pending { retry_after } => {
            println!("⏳ Enrollment pending manual approval");
            println!("Retry after {} seconds", retry_after);
        }
    }

    Ok(())
}
```

## Authentication

EST servers typically require authentication. There are two main methods:

### TLS Client Certificate Authentication

Use an existing client certificate to authenticate:

```rust
use usg_est_client::ClientIdentity;

let cert_pem = std::fs::read("client-cert.pem")?;
let key_pem = std::fs::read("client-key.pem")?;

let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .client_identity(ClientIdentity::new(cert_pem, key_pem))
    .build()?;
```

### Explicit Trust Anchors

Provide specific CA certificates:

```rust
let ca_cert_pem = std::fs::read("ca-cert.pem")?;

let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .trust_explicit(vec![ca_cert_pem])
    .build()?;
```

### Bootstrap Mode (TOFU)

For initial enrollment without pre-established trust:

```rust
use usg_est_client::bootstrap::BootstrapClient;

// Create bootstrap client
let bootstrap = BootstrapClient::new("https://est.example.com")?;

// Fetch CA certificates (unverified!)
let (ca_certs, fingerprints) = bootstrap.fetch_ca_certs().await?;

// Display fingerprints for out-of-band verification
for (i, fp) in fingerprints.iter().enumerate() {
    println!("Certificate {} fingerprint: {}",
        i + 1,
        BootstrapClient::format_fingerprint(fp)
    );
}

// After user verifies fingerprints, use the CA certificates
// to configure the regular EstClient
```

## Error Handling

The library provides comprehensive error types:

```rust
use usg_est_client::EstError;

match client.simple_enroll(&csr_der).await {
    Ok(response) => {
        // Handle successful enrollment
    }
    Err(EstError::AuthenticationRequired { challenge }) => {
        println!("Authentication required: {}", challenge);
    }
    Err(EstError::ServerError { status, message }) => {
        println!("Server error {}: {}", status, message);
    }
    Err(e) => {
        println!("Error: {}", e);
    }
}
```

## Next Steps

- Read about [EST Operations](operations.md) for detailed operation guides
- Learn about [Configuration](configuration.md) options
- Review [Security Considerations](security.md)
- Explore more [Examples](examples.md)
