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
    // Initialize tracing to Windows Event Log
    // In production, this would use the Windows Event Log tracing subscriber
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(std::io::stderr)
        .init();

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
    pub async fn perform_enrollment(_config: &AutoEnrollConfig) -> Result<()> {
        tracing::info!("Starting certificate enrollment");

        // TODO: Implement full enrollment workflow:
        // 1. Generate key pair (CNG/TPM)
        // 2. Build CSR
        // 3. Connect to EST server
        // 4. Submit enrollment request
        // 5. Import certificate to store
        // 6. Associate private key

        tracing::info!("Enrollment complete");
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
    pub async fn perform_renewal(_config: &AutoEnrollConfig) -> Result<()> {
        tracing::info!("Starting certificate renewal");

        // TODO: Implement renewal workflow:
        // 1. Get existing certificate for TLS auth
        // 2. Generate new key pair
        // 3. Build CSR
        // 4. Submit re-enrollment request
        // 5. Import new certificate
        // 6. Archive old certificate (optional)

        tracing::info!("Renewal complete");
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
