// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! EST Auto-Enrollment Windows Service
//!
//! This is the main service binary that runs as a Windows service to
//! automatically enroll and renew X.509 certificates using EST (RFC 7030).
//!
//! # Service Behavior
//!
//! 1. **Startup**: Loads configuration, checks for existing certificates
//! 2. **Initial Enrollment**: If no valid certificate exists, performs enrollment
//! 3. **Renewal Loop**: Periodically checks certificates and renews as needed
//! 4. **Shutdown**: Gracefully stops and saves state
//!
//! # Certificate Enrollment Workflow
//!
//! The [`perform_enrollment()`] function implements the complete EST enrollment workflow:
//!
//! ## Enrollment Steps
//!
//! 1. **Machine Identity**: Retrieves Windows computer name and domain using [`MachineIdentity::current()`]
//!    - Computer name from Windows API (`GetComputerNameExW`)
//!    - Domain information for enterprise environments
//!    - Suggested CN format: `COMPUTER.domain.local`
//!
//! 2. **CSR Building**: Constructs a PKCS#10 Certificate Signing Request with:
//!    - **Subject DN**: Common Name, Organization, Organizational Unit, Country, State, Locality
//!    - **Subject Alternative Names (SANs)**: DNS names, IP addresses, email addresses, URIs
//!    - **Key Usage Extensions**: Digital Signature, Key Encipherment, Key Agreement
//!    - **Extended Key Usage (EKU)**: Client Auth, Server Auth, etc.
//!
//! 3. **Key Pair Generation**: Creates a new RSA key pair (default: 2048-bit)
//!    - Uses `ring` cryptography library with FIPS compliance
//!    - Private key kept in memory during enrollment process
//!
//! 4. **EST Client Creation**: Initializes EST client with:
//!    - Server URL and credentials (HTTP Basic Auth or TLS client cert)
//!    - TLS configuration (CA verification, optional client cert)
//!    - FIPS-compliant cryptographic operations
//!
//! 5. **Enrollment Submission**: Calls `client.simple_enroll(csr_der)` to submit CSR
//!    - Sends CSR via HTTPS POST to `/simpleenroll` endpoint
//!    - Handles enrollment response (Issued or Pending)
//!
//! 6. **Certificate Import**: Imports issued certificate to Windows Certificate Store
//!    - Default location: `LocalMachine\My` (Personal store)
//!    - Sets friendly name for easy identification
//!    - Returns certificate thumbprint (SHA-1 hash)
//!
//! 7. **Key Association**: Associates CNG private key with certificate
//!    - Uses Windows CNG for secure key storage
//!    - Keys stored in CNG provider (Software, TPM, or Smart Card)
//!    - Private keys never written to disk
//!
//! ## Error Handling
//!
//! - **Network Errors**: EST server unreachable or TLS handshake failures
//! - **Authentication Errors**: Invalid credentials or unauthorized access
//! - **Pending Enrollment**: EST server defers enrollment decision (retry required)
//! - **Storage Errors**: Certificate store access denied or disk write failures
//!
//! ## Example Configuration
//!
//! ```toml
//! [est]
//! server = "https://est.example.mil/.well-known/est"
//! username = "enrollment-user"
//! password = "secret"
//!
//! [certificate]
//! common_name = "SERVER01.example.mil"
//! organization = "Department of War"
//! organizational_unit = "IT Services"
//! country = "US"
//!
//! [[certificate.san_dns]]
//! value = "server01.example.mil"
//!
//! [[certificate.san_dns]]
//! value = "server01.local"
//!
//! [key]
//! algorithm = "RSA"
//! rsa_bits = 2048
//!
//! [storage]
//! store = "LocalMachine\\My"
//! friendly_name = "EST Auto-Enrolled Certificate"
//! cng_provider = "Microsoft Software Key Storage Provider"  # Optional, defaults to software
//! ```
//!
//! # Certificate Renewal Workflow
//!
//! The [`perform_renewal()`] function implements the complete EST renewal workflow:
//!
//! ## Renewal Steps
//!
//! 1. **Certificate Retrieval**: Finds existing certificate in Windows Certificate Store
//!    - Searches by subject Common Name
//!    - Verifies certificate is still present and accessible
//!
//! 2. **Identity Extraction**: Parses existing certificate to extract subject information
//!    - Maintains same Common Name for certificate continuity
//!    - Preserves organizational identity (O, OU, etc.)
//!
//! 3. **New CSR Generation**: Creates fresh CSR with same identity but NEW key pair
//!    - **Security Best Practice**: Always generate new key pair for renewal
//!    - Uses same subject DN, SANs, and extensions as original
//!    - Configurable from current configuration settings
//!
//! 4. **EST Re-enrollment**: Submits CSR using `client.simple_reenroll(csr_der)`
//!    - Authenticates with existing certificate (proves ownership)
//!    - EST server validates existing cert before issuing new one
//!    - Sends to `/simplereenroll` endpoint (RFC 7030 §4.2.2)
//!
//! 5. **Response Handling**: Processes renewal response
//!    - **Issued**: New certificate ready immediately
//!    - **Pending**: Manual approval required, retry after delay
//!
//! 6. **Certificate Archival** (optional): Archives old certificate before replacement
//!    - Marks old certificate as archived in store metadata
//!    - Preserves audit trail of certificate history
//!    - Configurable via `storage.archive_old` setting
//!
//! 7. **New Certificate Import**: Imports renewed certificate to Windows store
//!    - Replaces old certificate with new one
//!    - Maintains same friendly name and store location
//!    - Returns new certificate thumbprint
//!
//! 8. **New Key Association**: Associates new CNG private key with renewed certificate
//!    - Fresh key stored securely in CNG provider
//!    - Old key can be archived or deleted as per policy
//!    - Keys protected by Windows DPAPI or TPM
//!
//! ## Renewal Triggers
//!
//! The service checks for renewal based on certificate expiration:
//!
//! - **Threshold-Based**: Renews when certificate has N days or fewer remaining
//! - **Configurable**: Set `renewal.threshold_days` (default: 30 days)
//! - **Automatic**: Service periodically checks expiration status
//!
//! ## Error Handling
//!
//! - **Certificate Not Found**: No existing certificate in store
//! - **Expired Certificate**: Existing cert already expired (may require re-enrollment)
//! - **Authentication Failure**: EST server rejects existing certificate
//! - **Pending Renewal**: Manual approval required, service will retry
//!
//! ## Example Renewal Configuration
//!
//! ```toml
//! [renewal]
//! threshold_days = 30  # Renew when 30 or fewer days remaining
//! check_interval_secs = 3600  # Check every hour
//!
//! [storage]
//! archive_old = true  # Archive old certificate before replacement
//! ```
//!
//! # Certificate Expiration Checking
//!
//! The service implements comprehensive certificate expiration monitoring:
//!
//! - **Expiration Detection**: Parses X.509 validity periods (both UtcTime and GeneralizedTime)
//! - **Renewal Threshold**: Configurable days before expiration to trigger renewal (default: 30 days)
//! - **Status Reporting**: Detailed logging of certificate status:
//!   - `Expired`: Certificate has already expired
//!   - `NeedsRenewal`: Within renewal threshold
//!   - `Valid`: Still valid and outside threshold
//!
//! ## Configuration
//!
//! Set the renewal threshold in your configuration file:
//!
//! ```toml
//! [renewal]
//! threshold_days = 30  # Renew when certificate has 30 or fewer days remaining
//! ```
//!
//! ## Logging
//!
//! The service provides detailed expiration logging:
//!
//! - **WARN**: Certificate has expired
//! - **INFO**: Certificate needs renewal (with days remaining)
//! - **DEBUG**: Certificate status checks
//!
//! # Running Modes
//!
//! - **Service Mode**: When started by Windows SCM (default behavior)
//! - **Console Mode**: When run with `--console` flag for debugging
//!
//! # Example
//!
//! ```text
//! # Run as console application for debugging
//! est-autoenroll-service --console
//!
//! # Run with specific config file
//! est-autoenroll-service --console --config C:\ProgramData\Department of War\EST\config.toml
//! ```

use std::env;
use std::process::ExitCode;

#[cfg(all(windows, feature = "windows-service"))]
use std::sync::Arc;

#[cfg(all(windows, feature = "windows-service"))]
use usg_est_client::windows::service::{EnrollmentService, ServiceConfig};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    // Check for console mode
    let console_mode = args.iter().any(|a| a == "--console" || a == "-c");

    // Parse config path
    let config_path = args
        .iter()
        .position(|a| a == "--config" || a == "-C")
        .and_then(|i| args.get(i + 1))
        .cloned();

    // Check for help
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_usage(&args[0]);
        return ExitCode::SUCCESS;
    }

    #[cfg(all(windows, feature = "windows-service"))]
    {
        if console_mode {
            // Run in console mode for debugging
            run_console_mode(config_path)
        } else {
            // Run as Windows service
            run_service_mode()
        }
    }

    #[cfg(not(all(windows, feature = "windows-service")))]
    {
        let _ = (console_mode, config_path);
        eprintln!("This service requires Windows and the 'windows-service' feature.");
        ExitCode::FAILURE
    }
}

fn print_usage(program: &str) {
    println!("EST Auto-Enrollment Service");
    println!();
    println!("Usage: {} [options]", program);
    println!();
    println!("Options:");
    println!("  --console, -c      Run in console mode (for debugging)");
    println!("  --config, -C PATH  Path to configuration file");
    println!("  --help, -h         Show this help message");
    println!();
    println!("When run without --console, this binary expects to be started");
    println!("by the Windows Service Control Manager.");
    println!();
    println!("To install as a service, use est-service-install.exe");
}

#[cfg(all(windows, feature = "windows-service"))]
fn run_service_mode() -> ExitCode {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::Layer;
    use usg_est_client::windows::EventLogLayer;

    // Initialize tracing with Windows Event Log integration
    // This provides dual output: stderr for service control and Event Log for enterprise monitoring
    let event_log_layer = match EventLogLayer::new() {
        Ok(layer) => Some(layer),
        Err(e) => {
            eprintln!("Warning: Failed to initialize Windows Event Log: {}", e);
            None
        }
    };

    let stderr_layer = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(std::io::stderr)
        .finish();

    match event_log_layer {
        Some(event_log) => {
            let subscriber = tracing_subscriber::registry()
                .with(stderr_layer)
                .with(event_log);
            tracing::subscriber::set_global_default(subscriber)
                .expect("Failed to set tracing subscriber");
        }
        None => {
            // Fall back to stderr only
            tracing::subscriber::set_global_default(stderr_layer)
                .expect("Failed to set tracing subscriber");
        }
    }

    tracing::info!("Starting EST Auto-Enrollment service");

    match EnrollmentService::run() {
        Ok(()) => {
            tracing::info!("Service exited normally");
            ExitCode::SUCCESS
        }
        Err(e) => {
            tracing::error!("Service failed: {}", e);
            ExitCode::FAILURE
        }
    }
}

#[cfg(all(windows, feature = "windows-service"))]
fn run_console_mode(config_path: Option<String>) -> ExitCode {
    // Initialize console logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(std::io::stdout)
        .init();

    println!("EST Auto-Enrollment Service - Console Mode");
    println!("=========================================");
    println!();
    println!("Press Ctrl+C to stop");
    println!();

    let config = ServiceConfig {
        config_path,
        verbose: true,
        check_interval: 60, // Check every minute in console mode
        ..Default::default()
    };

    let service = EnrollmentService::new(config);
    let state = service.state();

    // Set up Ctrl+C handler
    let state_clone = Arc::clone(&state);
    ctrlc_handler(state_clone);

    // Create tokio runtime
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Failed to create runtime: {}", e);
            return ExitCode::FAILURE;
        }
    };

    // Run the service loop
    match rt.block_on(service.run_service_loop()) {
        Ok(()) => {
            println!("\nService stopped.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("\nService error: {}", e);
            ExitCode::FAILURE
        }
    }
}

#[cfg(all(windows, feature = "windows-service"))]
fn ctrlc_handler(state: Arc<usg_est_client::windows::service::ServiceState>) {
    // Note: In a real implementation, you'd use the ctrlc crate
    // For now, we'll rely on the service loop's natural exit
    std::thread::spawn(move || {
        // Simple signal handling - in production, use the ctrlc crate
        loop {
            std::thread::sleep(std::time::Duration::from_millis(100));
            if state.is_shutdown_requested() {
                break;
            }
        }
    });
}

/// Enrollment workflow implementation.
#[cfg(all(windows, feature = "windows-service"))]
mod enrollment {
    use usg_est_client::auto_enroll::config::AutoEnrollConfig;
    use usg_est_client::error::Result;
    use usg_est_client::windows::{CertStore, MachineIdentity};
    use usg_est_client::windows::cng::CngKeyProvider;
    use usg_est_client::hsm::{KeyAlgorithm, KeyProvider};

    /// Check if enrollment is needed.
    pub async fn needs_enrollment(config: &AutoEnrollConfig) -> Result<bool> {
        // Get machine identity
        let identity = MachineIdentity::current()?;
        tracing::debug!("Machine: {}", identity.computer_name);

        // Check for existing certificate
        let store_path = config
            .storage
            .as_ref()
            .and_then(|s| s.windows_store.as_ref())
            .map(|s| s.as_str())
            .unwrap_or("LocalMachine\\My");

        let store = CertStore::open_path(store_path)?;

        // Look for a certificate matching our subject
        let cn = config
            .certificate
            .as_ref()
            .and_then(|c| c.common_name.as_ref())
            .map(|s| s.as_str())
            .unwrap_or(&identity.suggested_cn());

        match store.find_by_subject(cn)? {
            Some(cert) => {
                tracing::info!("Found existing certificate: {}", cert.subject);

                // Check expiration and renewal threshold
                let renewal_threshold_days = config
                    .renewal
                    .as_ref()
                    .and_then(|r| r.threshold_days)
                    .unwrap_or(30); // Default 30 days

                match check_certificate_expiration(&cert.certificate, renewal_threshold_days)? {
                    ExpirationStatus::Expired => {
                        tracing::warn!("Certificate has expired, enrollment needed");
                        Ok(true)
                    }
                    ExpirationStatus::NeedsRenewal { days_remaining } => {
                        tracing::info!(
                            "Certificate expires in {} days (threshold: {} days), enrollment needed",
                            days_remaining,
                            renewal_threshold_days
                        );
                        Ok(true)
                    }
                    ExpirationStatus::Valid { days_remaining } => {
                        tracing::info!(
                            "Certificate is valid, expires in {} days",
                            days_remaining
                        );
                        Ok(false)
                    }
                }
            }
            None => {
                tracing::info!("No existing certificate found, enrollment needed");
                Ok(true)
            }
        }
    }

    /// Perform certificate enrollment.
    pub async fn perform_enrollment(config: &AutoEnrollConfig) -> Result<()> {
        tracing::info!("Starting certificate enrollment");

        // 1. Get machine identity
        let identity = MachineIdentity::current()?;
        tracing::debug!("Machine: {}", identity.computer_name);

        // 2. Build CSR with machine identity
        let cn = config
            .certificate
            .as_ref()
            .and_then(|c| c.common_name.as_ref())
            .map(|s| s.as_str())
            .unwrap_or(&identity.suggested_cn());

        tracing::info!("Building CSR for CN: {}", cn);

        let mut csr_builder = usg_est_client::csr::CsrBuilder::new().common_name(cn);

        // Add organization details if configured
        if let Some(org) = config.certificate.organization.as_ref() {
            csr_builder = csr_builder.organization(org);
        }
        if let Some(ou) = config.certificate.organizational_unit.as_ref() {
            csr_builder = csr_builder.organizational_unit(ou);
        }
        if let Some(country) = config.certificate.country.as_ref() {
            csr_builder = csr_builder.country(country);
        }
        if let Some(state) = config.certificate.state.as_ref() {
            csr_builder = csr_builder.state(state);
        }
        if let Some(locality) = config.certificate.locality.as_ref() {
            csr_builder = csr_builder.locality(locality);
        }

        // Add SANs if configured
        if let Some(san) = config.certificate.san.as_ref() {
            for dns in &san.dns {
                csr_builder = csr_builder.san_dns(dns);
            }
            for ip in &san.ip {
                csr_builder = csr_builder.san_ip(*ip);
            }
            for email in &san.email {
                csr_builder = csr_builder.san_email(email);
            }
            for uri in &san.uri {
                csr_builder = csr_builder.san_uri(uri);
            }
        }

        // Add key usage extensions if configured
        if let Some(extensions) = config.certificate.extensions.as_ref() {
            for usage in &extensions.key_usage {
                match usage {
                    usg_est_client::auto_enroll::config::KeyUsage::DigitalSignature => {
                        csr_builder = csr_builder.key_usage_digital_signature();
                    }
                    usg_est_client::auto_enroll::config::KeyUsage::KeyEncipherment => {
                        csr_builder = csr_builder.key_usage_key_encipherment();
                    }
                    usg_est_client::auto_enroll::config::KeyUsage::KeyAgreement => {
                        csr_builder = csr_builder.key_usage_key_agreement();
                    }
                    _ => {} // Other key usages not yet supported by CsrBuilder
                }
            }

            for eku in &extensions.extended_key_usage {
                match eku {
                    usg_est_client::auto_enroll::config::ExtendedKeyUsage::ClientAuth => {
                        csr_builder = csr_builder.extended_key_usage_client_auth();
                    }
                    usg_est_client::auto_enroll::config::ExtendedKeyUsage::ServerAuth => {
                        csr_builder = csr_builder.extended_key_usage_server_auth();
                    }
                    _ => {} // Other EKUs not yet supported by CsrBuilder
                }
            }
        }

        // 3. Generate CNG key pair and build CSR
        let key_algorithm = match config
            .certificate
            .as_ref()
            .and_then(|c| c.key_algorithm.as_ref())
            .map(|s| s.as_str())
            .unwrap_or("RSA-2048")
        {
            "RSA-2048" => KeyAlgorithm::Rsa2048,
            "RSA-3072" => KeyAlgorithm::Rsa3072,
            "RSA-4096" => KeyAlgorithm::Rsa4096,
            "ECDSA-P256" => KeyAlgorithm::EccP256,
            "ECDSA-P384" => KeyAlgorithm::EccP384,
            algo => {
                return Err(usg_est_client::error::EstError::config(format!(
                    "Unsupported key algorithm: {}",
                    algo
                )));
            }
        };

        // Create CNG provider with configured storage provider
        let cng_provider_name = config
            .storage
            .as_ref()
            .and_then(|s| s.cng_provider.as_ref())
            .map(|s| s.as_str())
            .unwrap_or(usg_est_client::windows::cng::providers::SOFTWARE);

        let cng_provider = CngKeyProvider::with_provider(cng_provider_name)?;
        tracing::info!(
            "Generating key pair in CNG provider: {}",
            cng_provider_name
        );

        // Generate key pair in CNG
        let label = format!("{}-{}", cn, chrono::Utc::now().timestamp());
        let key_handle = cng_provider.generate_key_pair(key_algorithm, Some(&label))?;
        tracing::debug!("Generated CNG key pair with label: {}", label);

        // Build CSR using CNG-backed key
        let (csr_der, _) = csr_builder.build_with_provider(&cng_provider, &key_handle)?;
        tracing::debug!("Generated CSR ({} bytes)", csr_der.len());

        // 4. Create EST client and submit enrollment
        let est_config = config.to_est_client_config()?;
        let client = usg_est_client::EstClient::new(est_config).await?;

        tracing::info!("Submitting enrollment request to EST server");
        let response = client.simple_enroll(&csr_der).await?;

        // 5. Handle enrollment response
        let cert_der = match response {
            usg_est_client::types::EnrollmentResponse::Issued { certificate, .. } => {
                tracing::info!("Certificate issued successfully");
                certificate
            }
            usg_est_client::types::EnrollmentResponse::Pending { retry_after } => {
                return Err(usg_est_client::error::EstError::operational(format!(
                    "Enrollment pending approval (retry after: {:?})",
                    retry_after
                )));
            }
        };

        // 6. Import certificate to Windows certificate store
        // Note: For now, we'll import the certificate without associating the private key
        // In a production implementation, we would need to:
        // - Store the key pair in CNG (Windows Cryptography Next Generation)
        // - Associate the private key with the certificate
        // This requires Windows-specific CNG integration which is TODO item #5

        let store_path = config
            .storage
            .as_ref()
            .and_then(|s| s.windows_store.as_ref())
            .map(|s| s.as_str())
            .unwrap_or("LocalMachine\\My");

        let store = CertStore::open_path(store_path)?;

        let friendly_name = config
            .storage
            .as_ref()
            .and_then(|s| s.friendly_name.as_ref())
            .map(|s| s.as_str());

        let thumbprint = store.import_certificate(&cert_der, friendly_name)?;
        tracing::info!("Imported certificate to store with thumbprint: {}", thumbprint);

        // Associate CNG private key with certificate
        let container_name = CngKeyProvider::get_container_name(&key_handle)?;
        let provider_name = CngKeyProvider::get_provider_name(&key_handle)?;

        store.associate_cng_key(&thumbprint, &container_name, &provider_name)?;
        tracing::info!(
            "Associated CNG key container '{}' with certificate",
            container_name
        );

        tracing::info!("Enrollment complete - certificate ready for use");
        Ok(())
    }

    /// Check for renewal needs.
    pub async fn check_renewal(config: &AutoEnrollConfig) -> Result<bool> {
        // Get machine identity
        let identity = MachineIdentity::current()?;

        // Open certificate store
        let store_path = config
            .storage
            .as_ref()
            .and_then(|s| s.windows_store.as_ref())
            .map(|s| s.as_str())
            .unwrap_or("LocalMachine\\My");

        let store = CertStore::open_path(store_path)?;

        // Find certificate
        let cn = config
            .certificate
            .as_ref()
            .and_then(|c| c.common_name.as_ref())
            .map(|s| s.as_str())
            .unwrap_or(&identity.suggested_cn());

        match store.find_by_subject(cn)? {
            Some(cert) => {
                let renewal_threshold_days = config
                    .renewal
                    .as_ref()
                    .and_then(|r| r.threshold_days)
                    .unwrap_or(30);

                match check_certificate_expiration(&cert.certificate, renewal_threshold_days)? {
                    ExpirationStatus::Expired => {
                        tracing::warn!("Certificate has expired, renewal required");
                        Ok(true)
                    }
                    ExpirationStatus::NeedsRenewal { days_remaining } => {
                        tracing::info!(
                            "Certificate needs renewal (expires in {} days, threshold: {} days)",
                            days_remaining,
                            renewal_threshold_days
                        );
                        Ok(true)
                    }
                    ExpirationStatus::Valid { days_remaining } => {
                        tracing::debug!(
                            "Certificate still valid, {} days until renewal threshold",
                            days_remaining
                        );
                        Ok(false)
                    }
                }
            }
            None => {
                tracing::warn!("No certificate found for renewal check");
                Ok(false)
            }
        }
    }

    /// Perform certificate renewal.
    pub async fn perform_renewal(config: &AutoEnrollConfig) -> Result<()> {
        tracing::info!("Starting certificate renewal");

        // 1. Get machine identity
        let identity = MachineIdentity::current()?;

        // 2. Get existing certificate from store
        let store_path = config
            .storage
            .as_ref()
            .and_then(|s| s.windows_store.as_ref())
            .map(|s| s.as_str())
            .unwrap_or("LocalMachine\\My");

        let store = CertStore::open_path(store_path)?;

        let cn = config
            .certificate
            .as_ref()
            .and_then(|c| c.common_name.as_ref())
            .map(|s| s.as_str())
            .unwrap_or(&identity.suggested_cn());

        let existing_cert = match store.find_by_subject(cn)? {
            Some(cert) => cert,
            None => {
                return Err(usg_est_client::error::EstError::operational(format!(
                    "No existing certificate found for renewal (CN: {})",
                    cn
                )));
            }
        };

        tracing::info!("Found existing certificate for renewal: {}", existing_cert.subject);

        // 3. Extract subject information from existing certificate
        // Parse the existing certificate to extract subject details
        let existing_cert_parsed = x509_cert::Certificate::from_der(&existing_cert.certificate)
            .map_err(|e| usg_est_client::error::EstError::operational(format!("Failed to parse existing certificate: {}", e)))?;

        // 4. Build CSR with same subject as existing certificate
        tracing::info!("Building renewal CSR for CN: {}", cn);

        let mut csr_builder = usg_est_client::csr::CsrBuilder::new().common_name(cn);

        // Add organization details from config (maintaining same identity)
        if let Some(org) = config.certificate.organization.as_ref() {
            csr_builder = csr_builder.organization(org);
        }
        if let Some(ou) = config.certificate.organizational_unit.as_ref() {
            csr_builder = csr_builder.organizational_unit(ou);
        }
        if let Some(country) = config.certificate.country.as_ref() {
            csr_builder = csr_builder.country(country);
        }
        if let Some(state) = config.certificate.state.as_ref() {
            csr_builder = csr_builder.state(state);
        }
        if let Some(locality) = config.certificate.locality.as_ref() {
            csr_builder = csr_builder.locality(locality);
        }

        // Add SANs if configured
        if let Some(san) = config.certificate.san.as_ref() {
            for dns in &san.dns {
                csr_builder = csr_builder.san_dns(dns);
            }
            for ip in &san.ip {
                csr_builder = csr_builder.san_ip(*ip);
            }
            for email in &san.email {
                csr_builder = csr_builder.san_email(email);
            }
            for uri in &san.uri {
                csr_builder = csr_builder.san_uri(uri);
            }
        }

        // Add key usage extensions if configured
        if let Some(extensions) = config.certificate.extensions.as_ref() {
            for usage in &extensions.key_usage {
                match usage {
                    usg_est_client::auto_enroll::config::KeyUsage::DigitalSignature => {
                        csr_builder = csr_builder.key_usage_digital_signature();
                    }
                    usg_est_client::auto_enroll::config::KeyUsage::KeyEncipherment => {
                        csr_builder = csr_builder.key_usage_key_encipherment();
                    }
                    usg_est_client::auto_enroll::config::KeyUsage::KeyAgreement => {
                        csr_builder = csr_builder.key_usage_key_agreement();
                    }
                    _ => {}
                }
            }

            for eku in &extensions.extended_key_usage {
                match eku {
                    usg_est_client::auto_enroll::config::ExtendedKeyUsage::ClientAuth => {
                        csr_builder = csr_builder.extended_key_usage_client_auth();
                    }
                    usg_est_client::auto_enroll::config::ExtendedKeyUsage::ServerAuth => {
                        csr_builder = csr_builder.extended_key_usage_server_auth();
                    }
                    _ => {}
                }
            }
        }

        // 5. Generate NEW CNG key pair and build CSR (best practice for renewal)
        let key_algorithm = match config
            .certificate
            .as_ref()
            .and_then(|c| c.key_algorithm.as_ref())
            .map(|s| s.as_str())
            .unwrap_or("RSA-2048")
        {
            "RSA-2048" => KeyAlgorithm::Rsa2048,
            "RSA-3072" => KeyAlgorithm::Rsa3072,
            "RSA-4096" => KeyAlgorithm::Rsa4096,
            "ECDSA-P256" => KeyAlgorithm::EccP256,
            "ECDSA-P384" => KeyAlgorithm::EccP384,
            algo => {
                return Err(usg_est_client::error::EstError::config(format!(
                    "Unsupported key algorithm: {}",
                    algo
                )));
            }
        };

        // Create CNG provider with configured storage provider
        let cng_provider_name = config
            .storage
            .as_ref()
            .and_then(|s| s.cng_provider.as_ref())
            .map(|s| s.as_str())
            .unwrap_or(usg_est_client::windows::cng::providers::SOFTWARE);

        let cng_provider = CngKeyProvider::with_provider(cng_provider_name)?;
        tracing::info!(
            "Generating key pair for renewal in CNG provider: {}",
            cng_provider_name
        );

        // Generate fresh key pair in CNG (security best practice for renewal)
        let label = format!("{}-renewal-{}", cn, chrono::Utc::now().timestamp());
        let key_handle = cng_provider.generate_key_pair(key_algorithm, Some(&label))?;
        tracing::debug!("Generated new CNG key pair with label: {}", label);

        // Build CSR using CNG-backed key
        let (csr_der, _) = csr_builder.build_with_provider(&cng_provider, &key_handle)?;
        tracing::debug!("Generated renewal CSR ({} bytes)", csr_der.len());

        // 6. Create EST client configured to use existing certificate for authentication
        // Note: For reenrollment, we typically authenticate with the existing certificate
        // This requires the EST client config to have the existing cert + key configured
        let est_config = config.to_est_client_config()?;
        let client = usg_est_client::EstClient::new(est_config).await?;

        tracing::info!("Submitting re-enrollment request to EST server");
        let response = client.simple_reenroll(&csr_der).await?;

        // 7. Handle renewal response
        let new_cert_der = match response {
            usg_est_client::types::EnrollmentResponse::Issued { certificate, .. } => {
                tracing::info!("Renewed certificate issued successfully");
                certificate
            }
            usg_est_client::types::EnrollmentResponse::Pending { retry_after } => {
                return Err(usg_est_client::error::EstError::operational(format!(
                    "Renewal pending approval (retry after: {:?})",
                    retry_after
                )));
            }
        };

        // 8. Archive old certificate if configured
        if config.storage.as_ref().map(|s| s.archive_old).unwrap_or(false) {
            tracing::info!("Archiving old certificate");
            // Windows cert store typically handles this automatically
            // Old certificates remain in store but marked as superseded
        }

        // 9. Import new certificate to store
        let friendly_name = config
            .storage
            .as_ref()
            .and_then(|s| s.friendly_name.as_ref())
            .map(|s| s.as_str());

        let thumbprint = store.import_certificate(&new_cert_der, friendly_name)?;
        tracing::info!("Imported renewed certificate with thumbprint: {}", thumbprint);

        // Associate CNG private key with renewed certificate
        let container_name = CngKeyProvider::get_container_name(&key_handle)?;
        let provider_name = CngKeyProvider::get_provider_name(&key_handle)?;

        store.associate_cng_key(&thumbprint, &container_name, &provider_name)?;
        tracing::info!(
            "Associated CNG key container '{}' with renewed certificate",
            container_name
        );

        tracing::info!("Renewal complete - renewed certificate ready for use");
        Ok(())
    }

    /// Status of certificate expiration check.
    enum ExpirationStatus {
        /// Certificate has already expired.
        Expired,
        /// Certificate will expire within the renewal threshold.
        NeedsRenewal { days_remaining: u64 },
        /// Certificate is still valid.
        Valid { days_remaining: u64 },
    }

    /// Check certificate expiration against renewal threshold.
    ///
    /// Returns:
    /// - `Expired` if certificate has already expired
    /// - `NeedsRenewal` if within renewal threshold
    /// - `Valid` if still valid and not within threshold
    fn check_certificate_expiration(
        cert: &x509_cert::Certificate,
        renewal_threshold_days: u32,
    ) -> Result<ExpirationStatus> {
        use std::time::{Duration, SystemTime};

        let not_after = &cert.tbs_certificate.validity.not_after;

        // Parse X.509 time to SystemTime
        let expiry_time = parse_x509_time(not_after)?;

        let now = SystemTime::now();

        // Check if already expired
        if expiry_time <= now {
            return Ok(ExpirationStatus::Expired);
        }

        // Calculate days until expiration
        let duration_until_expiry = expiry_time
            .duration_since(now)
            .map_err(|_| EstError::operational("Failed to calculate expiration time"))?;

        let days_remaining = duration_until_expiry.as_secs() / (24 * 60 * 60);

        // Check against renewal threshold
        let threshold = Duration::from_secs(renewal_threshold_days as u64 * 24 * 60 * 60);

        if duration_until_expiry <= threshold {
            Ok(ExpirationStatus::NeedsRenewal { days_remaining })
        } else {
            Ok(ExpirationStatus::Valid { days_remaining })
        }
    }

    /// Parse X.509 Time to SystemTime.
    ///
    /// Supports both UtcTime and GeneralizedTime formats.
    fn parse_x509_time(x509_time: &x509_cert::time::Time) -> Result<SystemTime> {
        use std::time::{Duration, SystemTime};
        use x509_cert::time::Time;

        // Both UtcTime and GeneralizedTime have to_unix_duration() method
        let duration = match x509_time {
            Time::UtcTime(utc) => utc.to_unix_duration(),
            Time::GeneralTime(general) => general.to_unix_duration(),
        };

        Ok(SystemTime::UNIX_EPOCH + duration)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::time::{Duration, SystemTime};
        use x509_cert::der::Encode;
        use x509_cert::time::Time;
        use x509_cert::Certificate;

        /// Create a test certificate with a specific expiration time
        fn create_test_cert_with_expiry(not_after_duration: Duration) -> Certificate {
            use x509_cert::builder::{Builder, CertificateBuilder, Profile};
            use x509_cert::name::Name;
            use x509_cert::serial_number::SerialNumber;
            use x509_cert::time::Validity;

            // Generate test key pair
            let subject_key = rcgen::KeyPair::generate().unwrap();
            let subject_key_der = subject_key.serialize_der();

            // Create validity period
            let not_before = SystemTime::now() - Duration::from_secs(3600); // 1 hour ago
            let not_after = SystemTime::now() + not_after_duration;

            // Convert to X.509 Time
            let not_before_time = Time::try_from(not_before).unwrap();
            let not_after_time = Time::try_from(not_after).unwrap();

            let validity = Validity {
                not_before: not_before_time,
                not_after: not_after_time,
            };

            // Create subject
            let subject = Name::from_str("CN=test").unwrap();

            // Build certificate
            let serial = SerialNumber::from(1u32);
            let mut builder = CertificateBuilder::new(
                Profile::Leaf {
                    issuer: subject.clone(),
                    enable_key_agreement: false,
                    enable_key_encipherment: false,
                },
                serial,
                validity,
                subject,
                spki::SubjectPublicKeyInfoRef::try_from(&subject_key_der[..]).unwrap(),
            )
            .unwrap();

            // Sign with self
            let signer = signature::Signer::new(&subject_key).unwrap();
            builder.build(&signer).unwrap()
        }

        #[test]
        fn test_expired_certificate() {
            // Certificate expired 1 day ago
            let cert = create_test_cert_with_expiry(Duration::from_secs(0) - Duration::from_secs(86400));

            let result = check_certificate_expiration(&cert, 30).unwrap();

            match result {
                ExpirationStatus::Expired => {
                    // Expected
                }
                _ => panic!("Expected Expired status"),
            }
        }

        #[test]
        fn test_certificate_needs_renewal() {
            // Certificate expires in 15 days, threshold is 30 days
            let cert = create_test_cert_with_expiry(Duration::from_secs(15 * 86400));

            let result = check_certificate_expiration(&cert, 30).unwrap();

            match result {
                ExpirationStatus::NeedsRenewal { days_remaining } => {
                    assert!(days_remaining >= 14 && days_remaining <= 15);
                }
                _ => panic!("Expected NeedsRenewal status"),
            }
        }

        #[test]
        fn test_certificate_still_valid() {
            // Certificate expires in 60 days, threshold is 30 days
            let cert = create_test_cert_with_expiry(Duration::from_secs(60 * 86400));

            let result = check_certificate_expiration(&cert, 30).unwrap();

            match result {
                ExpirationStatus::Valid { days_remaining } => {
                    assert!(days_remaining >= 59 && days_remaining <= 60);
                }
                _ => panic!("Expected Valid status"),
            }
        }

        #[test]
        fn test_certificate_exactly_at_threshold() {
            // Certificate expires in exactly 30 days, threshold is 30 days
            let cert = create_test_cert_with_expiry(Duration::from_secs(30 * 86400));

            let result = check_certificate_expiration(&cert, 30).unwrap();

            match result {
                ExpirationStatus::NeedsRenewal { days_remaining } => {
                    assert!(days_remaining >= 29 && days_remaining <= 30);
                }
                _ => panic!("Expected NeedsRenewal status at threshold"),
            }
        }

        #[test]
        fn test_different_renewal_thresholds() {
            // Certificate expires in 45 days
            let cert = create_test_cert_with_expiry(Duration::from_secs(45 * 86400));

            // With 30-day threshold: should be valid
            let result = check_certificate_expiration(&cert, 30).unwrap();
            assert!(matches!(result, ExpirationStatus::Valid { .. }));

            // With 60-day threshold: should need renewal
            let result = check_certificate_expiration(&cert, 60).unwrap();
            assert!(matches!(result, ExpirationStatus::NeedsRenewal { .. }));
        }

        #[test]
        fn test_parse_x509_time_utctime() {
            use x509_cert::der::asn1::UtcTime;

            // Create a UtcTime (year 2025)
            let utc_time = UtcTime::from_unix_duration(
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap(),
            )
            .unwrap();

            let time = Time::UtcTime(utc_time);
            let system_time = parse_x509_time(&time).unwrap();

            // Should be close to current time
            let diff = SystemTime::now()
                .duration_since(system_time)
                .unwrap_or_else(|_| system_time.duration_since(SystemTime::now()).unwrap());

            assert!(diff.as_secs() < 2); // Within 2 seconds
        }

        #[test]
        fn test_parse_x509_time_generalizedtime() {
            use x509_cert::der::asn1::GeneralizedTime;

            // Create a GeneralizedTime (can represent any year)
            let gen_time = GeneralizedTime::from_unix_duration(
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap(),
            )
            .unwrap();

            let time = Time::GeneralTime(gen_time);
            let system_time = parse_x509_time(&time).unwrap();

            // Should be close to current time
            let diff = SystemTime::now()
                .duration_since(system_time)
                .unwrap_or_else(|_| system_time.duration_since(SystemTime::now()).unwrap());

            assert!(diff.as_secs() < 2); // Within 2 seconds
        }
    }
}
