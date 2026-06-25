# Usage Examples

This guide provides practical examples for common EST client scenarios.

## Table of Contents

1. [Basic Enrollment](#basic-enrollment)
2. [Certificate Renewal](#certificate-renewal)
3. [Bootstrap Mode](#bootstrap-mode)
4. [Server Key Generation](#server-key-generation)
5. [CSR Attributes](#csr-attributes)
6. [Multi-CA Deployment](#multi-ca-deployment)
7. [Retry Logic](#retry-logic)
8. [Production Patterns](#production-patterns)

---

## Basic Enrollment

Simple certificate enrollment with CSR generation.

```rust
use usg_est_client::{
    csr::CsrBuilder,
    EnrollmentResponse,
    EstClient,
    EstClientConfig,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure client
    let config = EstClientConfig::builder()
        .server_url("https://est.example.com")?
        .build()?;

    let client = EstClient::new(config).await?;

    // Generate CSR
    let (csr_der, key_pair) = CsrBuilder::new()
        .common_name("device.example.com")
        .organization("Example Corp")
        .country("US")
        .san_dns("device.example.com")
        .key_usage_digital_signature()
        .key_usage_key_encipherment()
        .extended_key_usage_client_auth()
        .build()?;

    // Enroll
    match client.simple_enroll(&csr_der).await? {
        EnrollmentResponse::Issued { certificate } => {
            println!("Certificate issued!");

            // Save certificate
            use der::Encode;
            std::fs::write("certificate.der", certificate.to_der()?)?;

            // Save private key
            std::fs::write("private-key.pem", key_pair.serialize_pem())?;
        }
        EnrollmentResponse::Pending { retry_after } => {
            println!("Pending approval. Retry after {} seconds", retry_after);
        }
    }

    Ok(())
}
```

---

## Certificate Renewal

Renewing an existing certificate with TLS client authentication.

```rust
use usg_est_client::{
    csr::CsrBuilder,
    ClientIdentity,
    EnrollmentResponse,
    EstClient,
    EstClientConfig,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load existing certificate and key
    let cert_pem = std::fs::read("current-cert.pem")?;
    let key_pem = std::fs::read("current-key.pem")?;

    // Configure with client certificate authentication
    let config = EstClientConfig::builder()
        .server_url("https://est.example.com")?
        .client_identity(ClientIdentity::new(cert_pem, key_pem))
        .build()?;

    let client = EstClient::new(config).await?;

    // Option 1: Renewal (same key)
    // Load existing key pair and generate CSR
    let existing_key = rcgen::KeyPair::from_pem(&std::fs::read_to_string("current-key.pem")?)?;
    let csr_der = CsrBuilder::new()
        .common_name("device.example.com")
        .build_with_key(&existing_key)?;

    // Option 2: Rekeying (new key)
    let (csr_der, new_key) = CsrBuilder::new()
        .common_name("device.example.com")
        .build()?;

    // Re-enroll
    match client.simple_reenroll(&csr_der).await? {
        EnrollmentResponse::Issued { certificate } => {
            println!("Certificate renewed!");

            // Save new certificate
            use der::Encode;
            std::fs::write("new-certificate.der", certificate.to_der()?)?;

            // If rekeying, save new key
            std::fs::write("new-private-key.pem", new_key.serialize_pem())?;
        }
        EnrollmentResponse::Pending { retry_after } => {
            println!("Renewal pending. Retry after {} seconds", retry_after);
        }
    }

    Ok(())
}
```

---

## Bootstrap Mode

Initial enrollment using Trust On First Use (TOFU).

```rust
use usg_est_client::{
    bootstrap::BootstrapClient,
    csr::CsrBuilder,
    EnrollmentResponse,
    EstClient,
    EstClientConfig,
    HttpAuth,
};
use std::io::{self, Write};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_url = "https://est.example.com";

    // Phase 1: Bootstrap - fetch CA certificates
    println!("=== Bootstrap Phase ===");
    let bootstrap = BootstrapClient::new(server_url)?;
    let (ca_certs, fingerprints) = bootstrap.fetch_ca_certs().await?;

    // Display fingerprints for out-of-band verification
    println!("\nCA Certificate Fingerprints (verify these!):");
    for (i, fp) in fingerprints.iter().enumerate() {
        println!("  Certificate {}: {}",
            i + 1,
            BootstrapClient::format_fingerprint(fp)
        );
    }

    // Interactive verification
    print!("\nDo you trust these certificates? [y/N]: ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    if input.trim().to_lowercase() != "y" {
        println!("Certificates not trusted. Exiting.");
        return Ok(());
    }

    // Phase 2: Regular enrollment with verified CA certificates
    println!("\n=== Enrollment Phase ===");
    let ca_pems = ca_certs.to_pem_vec()?;

    let config = EstClientConfig::builder()
        .server_url(server_url)?
        .trust_explicit(ca_pems)
        .http_auth(HttpAuth {
            username: "device001".to_string(),
            password: "secret".to_string(),
        })
        .build()?;

    let client = EstClient::new(config).await?;

    // Generate CSR and enroll
    let (csr_der, key_pair) = CsrBuilder::new()
        .common_name("device001.example.com")
        .build()?;

    match client.simple_enroll(&csr_der).await? {
        EnrollmentResponse::Issued { certificate } => {
            println!("Certificate issued!");

            // Save everything
            use der::Encode;
            std::fs::write("certificate.der", certificate.to_der()?)?;
            std::fs::write("private-key.pem", key_pair.serialize_pem())?;

            // Save CA certificates for future use
            for (i, ca_pem) in ca_pems.iter().enumerate() {
                std::fs::write(format!("ca-cert-{}.pem", i), ca_pem)?;
            }

            println!("Saved certificate, key, and CA certificates");
        }
        EnrollmentResponse::Pending { retry_after } => {
            println!("Enrollment pending");
        }
    }

    Ok(())
}
```

---

## Server Key Generation

Request the server to generate a key pair.

```rust
use usg_est_client::{
    csr::CsrBuilder,
    EstClient,
    EstClientConfig,
    HttpAuth,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = EstClientConfig::builder()
        .server_url("https://est.example.com")?
        .http_auth(HttpAuth {
            username: "user".to_string(),
            password: "pass".to_string(),
        })
        .build()?;

    let client = EstClient::new(config).await?;

    // Create CSR with subject info (public key is placeholder)
    let (csr_der, _) = CsrBuilder::new()
        .common_name("device.example.com")
        .organization("Example Corp")
        .build()?;

    // Request server key generation
    let response = client.server_keygen(&csr_der).await?;

    println!("Certificate and key received from server");
    println!("Private key encrypted: {}", response.key_encrypted);

    if response.key_encrypted {
        println!("WARNING: Private key is encrypted - decryption required");
        // Handle encrypted key
    }

    // Save certificate
    use der::Encode;
    std::fs::write("certificate.der", response.certificate.to_der()?)?;

    // Save private key (PKCS#8 DER format)
    std::fs::write("server-generated-key.der", &response.private_key)?;

    // Convert to PEM
    use usg_est_client::operations::serverkeygen::parse_pkcs8_key;
    let key_info = parse_pkcs8_key(&response.private_key)?;
    std::fs::write("server-generated-key.pem", key_info.to_pem())?;

    println!("Saved certificate and private key");

    Ok(())
}
```

---

## CSR Attributes

Query and apply server CSR requirements.

```rust
use usg_est_client::{
    csr::CsrBuilder,
    types::csr_attrs::oids,
    EstClient,
    EstClientConfig,
    EstError,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = EstClientConfig::builder()
        .server_url("https://est.example.com")?
        .build()?;

    let client = EstClient::new(config).await?;

    // Query CSR attributes
    let attrs = match client.get_csr_attributes().await {
        Ok(attrs) => attrs,
        Err(EstError::NotSupported { .. }) => {
            println!("Server doesn't provide CSR attributes");
            // Use default CSR builder
            let (csr_der, key_pair) = CsrBuilder::new()
                .common_name("device.example.com")
                .build()?;
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    if attrs.is_empty() {
        println!("No specific CSR requirements");
    } else {
        println!("Server requires {} attributes:", attrs.len());

        // Check for specific requirements
        if attrs.contains_oid(&oids::CHALLENGE_PASSWORD) {
            println!("  - Challenge password required");
        }
        if attrs.contains_oid(&oids::EXTENSION_REQUEST) {
            println!("  - Extension request required");
        }
        if attrs.contains_oid(&oids::KEY_USAGE) {
            println!("  - Key usage required");
        }
        if attrs.contains_oid(&oids::SUBJECT_ALT_NAME) {
            println!("  - Subject alternative name required");
        }
    }

    // Build CSR with server requirements
    let (csr_der, key_pair) = CsrBuilder::new()
        .common_name("device.example.com")
        .with_attributes(&attrs)  // Apply server requirements
        .build()?;

    // Proceed with enrollment
    let response = client.simple_enroll(&csr_der).await?;

    Ok(())
}
```

---

## Multi-CA Deployment

Working with multiple CAs.

```rust
use usg_est_client::{
    csr::CsrBuilder,
    EnrollmentResponse,
    EstClient,
    EstClientConfig,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Enroll with different CAs
    let cas = vec![
        ("engineering", "Engineering CA"),
        ("operations", "Operations CA"),
    ];

    for (ca_label, ca_name) in cas {
        println!("\n=== {} ===", ca_name);

        let config = EstClientConfig::builder()
            .server_url("https://est.example.com")?
            .ca_label(ca_label)
            .build()?;

        let client = EstClient::new(config).await?;

        // Get CA certs
        let ca_certs = client.get_ca_certs().await?;
        println!("Retrieved {} CA certificate(s)", ca_certs.len());

        // Generate CSR
        let (csr_der, key_pair) = CsrBuilder::new()
            .common_name(&format!("device.{}.example.com", ca_label))
            .organizational_unit(ca_name)
            .build()?;

        // Enroll
        match client.simple_enroll(&csr_der).await? {
            EnrollmentResponse::Issued { certificate } => {
                println!("Certificate issued by {}", ca_name);

                // Save with CA-specific filename
                use der::Encode;
                std::fs::write(
                    format!("certificate-{}.der", ca_label),
                    certificate.to_der()?
                )?;
                std::fs::write(
                    format!("key-{}.pem", ca_label),
                    key_pair.serialize_pem()
                )?;
            }
            EnrollmentResponse::Pending { .. } => {
                println!("Enrollment pending for {}", ca_name);
            }
        }
    }

    Ok(())
}
```

---

## Retry Logic

Handling pending enrollments with retry.

```rust
use usg_est_client::{
    csr::CsrBuilder,
    EnrollmentResponse,
    EstClient,
    EstClientConfig,
};
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = EstClientConfig::builder()
        .server_url("https://est.example.com")?
        .build()?;

    let client = EstClient::new(config).await?;

    let (csr_der, key_pair) = CsrBuilder::new()
        .common_name("device.example.com")
        .build()?;

    // Retry logic
    let max_retries = 10;
    let mut retries = 0;

    loop {
        match client.simple_enroll(&csr_der).await? {
            EnrollmentResponse::Issued { certificate } => {
                println!("Certificate issued after {} retries!", retries);

                use der::Encode;
                std::fs::write("certificate.der", certificate.to_der()?)?;
                std::fs::write("private-key.pem", key_pair.serialize_pem())?;

                break;
            }
            EnrollmentResponse::Pending { retry_after } => {
                retries += 1;

                if retries >= max_retries {
                    eprintln!("Max retries ({}) exceeded", max_retries);
                    return Err("Enrollment timed out".into());
                }

                println!("Attempt {}/{}: Pending, retrying in {} seconds",
                    retries, max_retries, retry_after);

                sleep(Duration::from_secs(retry_after)).await;
            }
        }
    }

    Ok(())
}
```

---

## Production Patterns

### Pattern 1: Automated Certificate Lifecycle

```rust
use usg_est_client::{
    csr::CsrBuilder,
    ClientIdentity,
    EnrollmentResponse,
    EstClient,
    EstClientConfig,
};
use tokio::time::{sleep, Duration};
use x509_cert::Certificate;

struct CertificateManager {
    server_url: String,
    device_name: String,
}

impl CertificateManager {
    pub fn new(server_url: String, device_name: String) -> Self {
        Self { server_url, device_name }
    }

    /// Check if certificate should be renewed
    fn should_renew(&self, cert: &Certificate) -> bool {
        // Renew if less than 30 days remaining
        let not_after = cert.tbs_certificate.validity.not_after.to_unix_duration();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let days_remaining = (not_after - now) / 86400;
        days_remaining < 30
    }

    /// Initial enrollment
    pub async fn enroll(&self) -> Result<(), Box<dyn std::error::Error>> {
        let config = EstClientConfig::builder()
            .server_url(&self.server_url)?
            .build()?;

        let client = EstClient::new(config).await?;

        let (csr_der, key_pair) = CsrBuilder::new()
            .common_name(&self.device_name)
            .build()?;

        match client.simple_enroll(&csr_der).await? {
            EnrollmentResponse::Issued { certificate } => {
                self.save_certificate(&certificate)?;
                self.save_key(&key_pair)?;
                Ok(())
            }
            EnrollmentResponse::Pending { .. } => {
                Err("Pending enrollment not handled in this example".into())
            }
        }
    }

    /// Renew certificate
    pub async fn renew(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Load current certificate and key
        let cert_pem = std::fs::read("certificate.pem")?;
        let key_pem = std::fs::read("private-key.pem")?;

        let config = EstClientConfig::builder()
            .server_url(&self.server_url)?
            .client_identity(ClientIdentity::new(cert_pem, key_pem))
            .build()?;

        let client = EstClient::new(config).await?;

        // Generate new key for rekeying
        let (csr_der, new_key) = CsrBuilder::new()
            .common_name(&self.device_name)
            .build()?;

        match client.simple_reenroll(&csr_der).await? {
            EnrollmentResponse::Issued { certificate } => {
                self.save_certificate(&certificate)?;
                self.save_key(&new_key)?;
                Ok(())
            }
            EnrollmentResponse::Pending { .. } => {
                Err("Pending renewal not handled in this example".into())
            }
        }
    }

    fn save_certificate(&self, cert: &Certificate) -> Result<(), Box<dyn std::error::Error>> {
        use der::Encode;
        std::fs::write("certificate.der", cert.to_der()?)?;
        // Also save PEM, update symlinks, etc.
        Ok(())
    }

    fn save_key(&self, key: &rcgen::KeyPair) -> Result<(), Box<dyn std::error::Error>> {
        std::fs::write("private-key.pem", key.serialize_pem())?;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manager = CertificateManager::new(
        "https://est.example.com".to_string(),
        "device001.example.com".to_string(),
    );

    // Initial enrollment
    manager.enroll().await?;

    // Periodic renewal check (in production, use a timer/scheduler)
    loop {
        sleep(Duration::from_secs(86400)).await; // Check daily

        // Load current certificate
        let cert_der = std::fs::read("certificate.der")?;
        let cert = Certificate::from_der(&cert_der)?;

        if manager.should_renew(&cert) {
            println!("Certificate needs renewal");
            manager.renew().await?;
        }
    }
}
```

### Pattern 2: Error Handling with Logging

```rust
use usg_est_client::{EstClient, EstClientConfig, EstError};
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let config = EstClientConfig::builder()
        .server_url("https://est.example.com")?
        .build()?;

    let client = match EstClient::new(config).await {
        Ok(c) => {
            info!("EST client created successfully");
            c
        }
        Err(e) => {
            error!("Failed to create EST client: {}", e);
            return Err(e.into());
        }
    };

    // Enrollment with comprehensive error handling
    match client.simple_enroll(&csr_der).await {
        Ok(response) => {
            info!("Enrollment request successful");
            // Handle response
        }
        Err(EstError::AuthenticationRequired { challenge }) => {
            warn!("Authentication required: {}", challenge);
            // Retry with authentication
        }
        Err(EstError::ServerError { status, message }) => {
            error!("Server error {}: {}", status, message);
            // Log and alert
        }
        Err(EstError::TlsConfig(msg)) => {
            error!("TLS configuration error: {}", msg);
            // Check TLS configuration
        }
        Err(e) if e.is_retryable() => {
            warn!("Retryable error: {}", e);
            if let Some(retry_after) = e.retry_after() {
                info!("Retrying after {} seconds", retry_after);
                // Implement retry
            }
        }
        Err(e) => {
            error!("Enrollment failed: {}", e);
            return Err(e.into());
        }
    }

    Ok(())
}
```

---

## Running the Examples

The library includes complete examples in the `examples/` directory:

### Simple Enrollment

```bash
cargo run --example simple_enroll -- \
    --server https://est.example.com \
    --cn device.example.com
```

### Re-enrollment

```bash
cargo run --example reenroll -- \
    --server https://est.example.com \
    --cert /path/to/cert.pem \
    --key /path/to/key.pem
```

### Bootstrap Mode

```bash
cargo run --example bootstrap -- \
    --server https://est.example.com
```

---

## Next Steps

- Review [Configuration](configuration.md) for advanced options
- Read [Security Considerations](security.md) before deploying
- Check [API Reference](api-reference.md) for complete API details
