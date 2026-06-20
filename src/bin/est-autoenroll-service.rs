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
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::SubscriberExt;
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

    match event_log_layer {
        Some(event_log) => {
            // Compose a stderr fmt layer (INFO-filtered) with the Event Log layer.
            let stderr_layer = tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_filter(tracing_subscriber::filter::LevelFilter::INFO);
            let subscriber = tracing_subscriber::registry()
                .with(stderr_layer)
                .with(event_log);
            tracing::subscriber::set_global_default(subscriber)
                .expect("Failed to set tracing subscriber");
        }
        None => {
            // Fall back to stderr only.
            let stderr_subscriber = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::INFO)
                .with_writer(std::io::stderr)
                .finish();
            tracing::subscriber::set_global_default(stderr_subscriber)
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
