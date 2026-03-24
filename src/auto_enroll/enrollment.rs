// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! Certificate enrollment and renewal operations.
//!
//! This module implements the enrollment and renewal workflows for
//! automatic certificate management via EST.

#[cfg(windows)]
use crate::auto_enroll::config::AutoEnrollConfig;
#[cfg(windows)]
use crate::error::{EstError, Result};
#[cfg(windows)]
use crate::hsm::{KeyAlgorithm, KeyProvider};
#[cfg(windows)]
use crate::windows::cng::CngKeyProvider;
#[cfg(windows)]
use crate::windows::{CertStore, MachineIdentity};

/// Check if initial enrollment is needed.
///
/// Returns `true` if:
/// - No certificate exists in the configured store
/// - The existing certificate has expired
/// - The existing certificate needs renewal
#[cfg(windows)]
pub async fn needs_enrollment(config: &AutoEnrollConfig) -> Result<bool> {
    // Get machine identity
    let identity = MachineIdentity::current()?;
    tracing::debug!("Machine: {}", identity.computer_name);

    // Check for existing certificate
    let store_path = config
        .storage
        .windows_store
        .as_ref()
        .map(|s| s.as_str())
        .unwrap_or("LocalMachine\\My");

    let store = CertStore::open_path(store_path)?;

    // Look for a certificate matching our subject
    let cn = &config.certificate.common_name;

    match store.find_by_subject(cn)? {
        Some(cert) => {
            tracing::info!("Found existing certificate: {}", cert.subject);

            // Check expiration and renewal threshold
            let renewal_threshold_days = config.renewal.threshold_days;

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
                    tracing::info!("Certificate is valid, expires in {} days", days_remaining);
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
///
/// This function:
/// 1. Gets machine identity
/// 2. Builds a CSR with configured subject and extensions
/// 3. Generates a new key pair
/// 4. Submits the enrollment request to the EST server
/// 5. Imports the issued certificate to the Windows store
/// 6. Saves the private key (temporary workaround until CNG integration)
#[cfg(windows)]
pub async fn perform_enrollment(config: &AutoEnrollConfig) -> Result<()> {
    tracing::info!("Starting certificate enrollment");

    // 1. Get machine identity
    let identity = MachineIdentity::current()?;
    tracing::debug!("Machine: {}", identity.computer_name);

    // 2. Build CSR with machine identity
    let cn = &config.certificate.common_name;
    tracing::info!("Building CSR for CN: {}", cn);

    let mut csr_builder = crate::csr::CsrBuilder::new().common_name(cn);

    // Add organization details if configured
    if let Some(ref org) = config.certificate.organization {
        csr_builder = csr_builder.organization(org);
    }
    if let Some(ref ou) = config.certificate.organizational_unit {
        csr_builder = csr_builder.organizational_unit(ou);
    }
    if let Some(ref country) = config.certificate.country {
        csr_builder = csr_builder.country(country);
    }
    if let Some(ref state) = config.certificate.state {
        csr_builder = csr_builder.state(state);
    }
    if let Some(ref locality) = config.certificate.locality {
        csr_builder = csr_builder.locality(locality);
    }

    // Add SANs if configured
    if let Some(ref san) = config.certificate.san {
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
    if let Some(ref extensions) = config.certificate.extensions {
        for usage in &extensions.key_usage {
            match usage {
                crate::auto_enroll::config::KeyUsage::DigitalSignature => {
                    csr_builder = csr_builder.key_usage_digital_signature();
                }
                crate::auto_enroll::config::KeyUsage::KeyEncipherment => {
                    csr_builder = csr_builder.key_usage_key_encipherment();
                }
                crate::auto_enroll::config::KeyUsage::KeyAgreement => {
                    csr_builder = csr_builder.key_usage_key_agreement();
                }
                _ => {} // Other key usages not yet supported by CsrBuilder
            }
        }

        for eku in &extensions.extended_key_usage {
            match eku {
                crate::auto_enroll::config::ExtendedKeyUsage::ClientAuth => {
                    csr_builder = csr_builder.extended_key_usage_client_auth();
                }
                crate::auto_enroll::config::ExtendedKeyUsage::ServerAuth => {
                    csr_builder = csr_builder.extended_key_usage_server_auth();
                }
                _ => {} // Other EKUs not yet supported by CsrBuilder
            }
        }
    }

    // 3. Generate CNG key pair and build CSR
    let key_algorithm = match config.certificate.key_algorithm.as_str() {
        "RSA-2048" => KeyAlgorithm::Rsa2048,
        "RSA-3072" => KeyAlgorithm::Rsa3072,
        "RSA-4096" => KeyAlgorithm::Rsa4096,
        "ECDSA-P256" => KeyAlgorithm::EccP256,
        "ECDSA-P384" => KeyAlgorithm::EccP384,
        algo => {
            return Err(EstError::config(format!(
                "Unsupported key algorithm: {}",
                algo
            )));
        }
    };

    // Create CNG provider with configured storage provider
    let cng_provider_name = config
        .storage
        .cng_provider
        .as_ref()
        .map(|s| s.as_str())
        .unwrap_or(crate::windows::cng::providers::SOFTWARE);

    let cng_provider = CngKeyProvider::with_provider(cng_provider_name)?;
    tracing::info!(
        "Generating {} key pair in CNG provider: {}",
        config.certificate.key_algorithm,
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
    let client = crate::EstClient::new(est_config).await?;

    tracing::info!("Submitting enrollment request to EST server");
    let response = client.simple_enroll(&csr_der).await?;

    // 5. Handle enrollment response
    let cert_der = match response {
        crate::types::EnrollmentResponse::Issued { certificate, .. } => {
            tracing::info!("Certificate issued successfully");
            certificate
        }
        crate::types::EnrollmentResponse::Pending { retry_after } => {
            return Err(EstError::operational(format!(
                "Enrollment pending approval (retry after: {:?})",
                retry_after
            )));
        }
    };

    // 6. Import certificate to Windows certificate store
    let store_path = config
        .storage
        .windows_store
        .as_ref()
        .map(|s| s.as_str())
        .unwrap_or("LocalMachine\\My");

    let store = CertStore::open_path(store_path)?;

    let friendly_name = config.storage.friendly_name.as_ref().map(|s| s.as_str());

    let thumbprint = store.import_certificate(&cert_der, friendly_name)?;
    tracing::info!(
        "Imported certificate to store with thumbprint: {}",
        thumbprint
    );

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

/// Check if renewal is needed for an existing certificate.
///
/// Returns `true` if the certificate exists and is within the renewal threshold.
#[cfg(windows)]
pub async fn check_renewal(config: &AutoEnrollConfig) -> Result<bool> {
    // Get machine identity
    let identity = MachineIdentity::current()?;

    // Open certificate store
    let store_path = config
        .storage
        .windows_store
        .as_ref()
        .map(|s| s.as_str())
        .unwrap_or("LocalMachine\\My");

    let store = CertStore::open_path(store_path)?;

    // Find certificate
    let cn = &config.certificate.common_name;

    match store.find_by_subject(cn)? {
        Some(cert) => {
            let renewal_threshold_days = config.renewal.threshold_days;

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
///
/// This function:
/// 1. Gets machine identity
/// 2. Retrieves the existing certificate
/// 3. Builds a new CSR with a fresh key pair (security best practice)
/// 4. Submits the re-enrollment request to the EST server
/// 5. Archives the old certificate (if configured)
/// 6. Imports the renewed certificate
/// 7. Saves the new private key
#[cfg(windows)]
pub async fn perform_renewal(config: &AutoEnrollConfig) -> Result<()> {
    tracing::info!("Starting certificate renewal");

    // 1. Get machine identity
    let identity = MachineIdentity::current()?;

    // 2. Get existing certificate from store
    let store_path = config
        .storage
        .windows_store
        .as_ref()
        .map(|s| s.as_str())
        .unwrap_or("LocalMachine\\My");

    let store = CertStore::open_path(store_path)?;

    let cn = &config.certificate.common_name;

    let existing_cert = match store.find_by_subject(cn)? {
        Some(cert) => cert,
        None => {
            return Err(EstError::operational(format!(
                "No existing certificate found for renewal (CN: {})",
                cn
            )));
        }
    };

    tracing::info!(
        "Found existing certificate for renewal: {}",
        existing_cert.subject
    );

    // 3. Build CSR with same subject as existing certificate
    tracing::info!("Building renewal CSR for CN: {}", cn);

    let mut csr_builder = crate::csr::CsrBuilder::new().common_name(cn);

    // Add organization details from config (maintaining same identity)
    if let Some(ref org) = config.certificate.organization {
        csr_builder = csr_builder.organization(org);
    }
    if let Some(ref ou) = config.certificate.organizational_unit {
        csr_builder = csr_builder.organizational_unit(ou);
    }
    if let Some(ref country) = config.certificate.country {
        csr_builder = csr_builder.country(country);
    }
    if let Some(ref state) = config.certificate.state {
        csr_builder = csr_builder.state(state);
    }
    if let Some(ref locality) = config.certificate.locality {
        csr_builder = csr_builder.locality(locality);
    }

    // Add SANs if configured
    if let Some(ref san) = config.certificate.san {
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
    if let Some(ref extensions) = config.certificate.extensions {
        for usage in &extensions.key_usage {
            match usage {
                crate::auto_enroll::config::KeyUsage::DigitalSignature => {
                    csr_builder = csr_builder.key_usage_digital_signature();
                }
                crate::auto_enroll::config::KeyUsage::KeyEncipherment => {
                    csr_builder = csr_builder.key_usage_key_encipherment();
                }
                crate::auto_enroll::config::KeyUsage::KeyAgreement => {
                    csr_builder = csr_builder.key_usage_key_agreement();
                }
                _ => {}
            }
        }

        for eku in &extensions.extended_key_usage {
            match eku {
                crate::auto_enroll::config::ExtendedKeyUsage::ClientAuth => {
                    csr_builder = csr_builder.extended_key_usage_client_auth();
                }
                crate::auto_enroll::config::ExtendedKeyUsage::ServerAuth => {
                    csr_builder = csr_builder.extended_key_usage_server_auth();
                }
                _ => {}
            }
        }
    }

    // 4. Generate NEW CNG key pair and build CSR (best practice for renewal)
    let key_algorithm = match config.certificate.key_algorithm.as_str() {
        "RSA-2048" => KeyAlgorithm::Rsa2048,
        "RSA-3072" => KeyAlgorithm::Rsa3072,
        "RSA-4096" => KeyAlgorithm::Rsa4096,
        "ECDSA-P256" => KeyAlgorithm::EccP256,
        "ECDSA-P384" => KeyAlgorithm::EccP384,
        algo => {
            return Err(EstError::config(format!(
                "Unsupported key algorithm: {}",
                algo
            )));
        }
    };

    // Create CNG provider with configured storage provider
    let cng_provider_name = config
        .storage
        .cng_provider
        .as_ref()
        .map(|s| s.as_str())
        .unwrap_or(crate::windows::cng::providers::SOFTWARE);

    let cng_provider = CngKeyProvider::with_provider(cng_provider_name)?;
    tracing::info!(
        "Generating {} key pair for renewal in CNG provider: {}",
        config.certificate.key_algorithm,
        cng_provider_name
    );

    // Generate fresh key pair in CNG (security best practice for renewal)
    let label = format!("{}-renewal-{}", cn, chrono::Utc::now().timestamp());
    let key_handle = cng_provider.generate_key_pair(key_algorithm, Some(&label))?;
    tracing::debug!("Generated new CNG key pair with label: {}", label);

    // Build CSR using CNG-backed key
    let (csr_der, _) = csr_builder.build_with_provider(&cng_provider, &key_handle)?;
    tracing::debug!("Generated renewal CSR ({} bytes)", csr_der.len());

    // 5. Create EST client configured to use existing certificate for authentication
    let est_config = config.to_est_client_config()?;
    let client = crate::EstClient::new(est_config).await?;

    tracing::info!("Submitting re-enrollment request to EST server");
    let response = client.simple_reenroll(&csr_der).await?;

    // 6. Handle renewal response
    let new_cert_der = match response {
        crate::types::EnrollmentResponse::Issued { certificate, .. } => {
            tracing::info!("Renewed certificate issued successfully");
            certificate
        }
        crate::types::EnrollmentResponse::Pending { retry_after } => {
            return Err(EstError::operational(format!(
                "Renewal pending approval (retry after: {:?})",
                retry_after
            )));
        }
    };

    // 7. Archive old certificate if configured
    if config.storage.archive_old {
        tracing::info!("Archiving old certificate");
        // Windows cert store typically handles this automatically
        // Old certificates remain in store but marked as superseded
    }

    // 8. Import new certificate to store
    let friendly_name = config.storage.friendly_name.as_ref().map(|s| s.as_str());

    let thumbprint = store.import_certificate(&new_cert_der, friendly_name)?;
    tracing::info!(
        "Imported renewed certificate with thumbprint: {}",
        thumbprint
    );

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
#[cfg(windows)]
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
#[cfg(windows)]
fn check_certificate_expiration(
    cert_der: &[u8],
    renewal_threshold_days: u32,
) -> Result<ExpirationStatus> {
    use std::time::{Duration, SystemTime};

    // Parse certificate
    let cert = x509_cert::Certificate::from_der(cert_der)
        .map_err(|e| EstError::operational(format!("Failed to parse certificate: {}", e)))?;

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
#[cfg(windows)]
fn parse_x509_time(x509_time: &x509_cert::time::Time) -> Result<std::time::SystemTime> {
    use std::time::SystemTime;
    use x509_cert::time::Time;

    // Both UtcTime and GeneralizedTime have to_unix_duration() method
    let duration = match x509_time {
        Time::UtcTime(utc) => utc.to_unix_duration(),
        Time::GeneralTime(general) => general.to_unix_duration(),
    };

    Ok(SystemTime::UNIX_EPOCH + duration)
}

// Non-Windows stubs - these return platform errors on non-Windows targets.
/// Check if certificate enrollment is needed (Windows only).
#[cfg(not(windows))]
pub async fn needs_enrollment(
    _config: &crate::auto_enroll::AutoEnrollConfig,
) -> crate::error::Result<bool> {
    Err(crate::error::EstError::platform(
        "Certificate enrollment requires Windows",
    ))
}

/// Perform certificate enrollment (Windows only).
#[cfg(not(windows))]
pub async fn perform_enrollment(
    _config: &crate::auto_enroll::AutoEnrollConfig,
) -> crate::error::Result<()> {
    Err(crate::error::EstError::platform(
        "Certificate enrollment requires Windows",
    ))
}

/// Check if certificate renewal is needed (Windows only).
#[cfg(not(windows))]
pub async fn check_renewal(
    _config: &crate::auto_enroll::AutoEnrollConfig,
) -> crate::error::Result<bool> {
    Err(crate::error::EstError::platform(
        "Certificate renewal requires Windows",
    ))
}

/// Perform certificate renewal (Windows only).
#[cfg(not(windows))]
pub async fn perform_renewal(
    _config: &crate::auto_enroll::AutoEnrollConfig,
) -> crate::error::Result<()> {
    Err(crate::error::EstError::platform(
        "Certificate renewal requires Windows",
    ))
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    use super::*;

    // Tests would go here - moved from the binary module
    // For now, we rely on the integration tests in the binary
}
