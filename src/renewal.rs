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

//! Automatic certificate renewal and expiration monitoring.
//!
//! This module provides utilities for monitoring certificate expiration
//! and automatically triggering re-enrollment before certificates expire.
//!
//! # Example
//!
//! ```no_run
//! use usg_est_client::{EstClient, EstClientConfig};
//! use usg_est_client::renewal::{RenewalScheduler, RenewalConfig};
//! use std::time::Duration;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Configure renewal scheduler
//! let renewal_config = RenewalConfig::builder()
//!     .renewal_threshold(Duration::from_secs(30 * 24 * 60 * 60)) // 30 days
//!     .check_interval(Duration::from_secs(24 * 60 * 60)) // Daily checks
//!     .max_retries(3)
//!     .build();
//!
//! // Create EST client
//! let config = EstClientConfig::builder()
//!     .server_url("https://est.example.com")?
//!     .build()?;
//! let client = EstClient::new(config).await?;
//!
//! // Start renewal scheduler
//! let mut scheduler = RenewalScheduler::new(client, renewal_config);
//! scheduler.start().await?;
//! # Ok(())
//! # }
//! ```

use crate::EstClient;
use crate::error::{EstError, Result};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tokio::time::{interval, sleep};
use tracing::{debug, error, info, warn};
use x509_cert::Certificate;

/// Configuration for automatic certificate renewal.
#[derive(Clone)]
pub struct RenewalConfig {
    /// Time before expiration to trigger renewal (e.g., 30 days).
    pub renewal_threshold: Duration,

    /// How often to check certificate expiration.
    pub check_interval: Duration,

    /// Maximum number of retry attempts for failed renewals.
    pub max_retries: usize,

    /// Delay between retry attempts (exponential backoff base).
    pub retry_delay: Duration,

    /// Optional callback for renewal events.
    pub event_callback: Option<Arc<dyn RenewalEventHandler>>,
}

impl RenewalConfig {
    /// Create a new renewal configuration builder.
    pub fn builder() -> RenewalConfigBuilder {
        RenewalConfigBuilder::default()
    }

    /// Create a default renewal configuration.
    ///
    /// Defaults:
    /// - Renewal threshold: 30 days before expiration
    /// - Check interval: Once per day
    /// - Max retries: 3
    /// - Retry delay: 1 hour (with exponential backoff)
    pub fn default_config() -> Self {
        Self {
            renewal_threshold: Duration::from_secs(30 * 24 * 60 * 60), // 30 days
            check_interval: Duration::from_secs(24 * 60 * 60),         // 1 day
            max_retries: 3,
            retry_delay: Duration::from_secs(60 * 60), // 1 hour
            event_callback: None,
        }
    }
}

/// Builder for `RenewalConfig`.
#[derive(Default)]
pub struct RenewalConfigBuilder {
    renewal_threshold: Option<Duration>,
    check_interval: Option<Duration>,
    max_retries: Option<usize>,
    retry_delay: Option<Duration>,
    event_callback: Option<Arc<dyn RenewalEventHandler>>,
}

impl RenewalConfigBuilder {
    /// Set the renewal threshold (time before expiration to renew).
    pub fn renewal_threshold(mut self, threshold: Duration) -> Self {
        self.renewal_threshold = Some(threshold);
        self
    }

    /// Set the check interval (how often to check for expiration).
    pub fn check_interval(mut self, interval: Duration) -> Self {
        self.check_interval = Some(interval);
        self
    }

    /// Set the maximum number of retries for failed renewals.
    pub fn max_retries(mut self, retries: usize) -> Self {
        self.max_retries = Some(retries);
        self
    }

    /// Set the base retry delay (used with exponential backoff).
    pub fn retry_delay(mut self, delay: Duration) -> Self {
        self.retry_delay = Some(delay);
        self
    }

    /// Set the event callback handler.
    pub fn event_callback(mut self, callback: Arc<dyn RenewalEventHandler>) -> Self {
        self.event_callback = Some(callback);
        self
    }

    /// Build the renewal configuration.
    pub fn build(self) -> RenewalConfig {
        let default = RenewalConfig::default_config();
        RenewalConfig {
            renewal_threshold: self.renewal_threshold.unwrap_or(default.renewal_threshold),
            check_interval: self.check_interval.unwrap_or(default.check_interval),
            max_retries: self.max_retries.unwrap_or(default.max_retries),
            retry_delay: self.retry_delay.unwrap_or(default.retry_delay),
            event_callback: self.event_callback.or(default.event_callback),
        }
    }
}

/// Events that occur during the renewal process.
#[derive(Clone)]
pub enum RenewalEvent {
    /// Certificate expiration check started.
    CheckStarted,

    /// Certificate will expire soon and needs renewal.
    RenewalNeeded {
        /// Time until expiration.
        time_until_expiry: Duration,
    },

    /// Renewal attempt started.
    RenewalStarted {
        /// Attempt number (1-based).
        attempt: usize,
    },

    /// Renewal succeeded.
    RenewalSucceeded {
        /// The newly issued certificate.
        certificate: Box<Certificate>,
    },

    /// Renewal failed.
    RenewalFailed {
        /// Attempt number (1-based).
        attempt: usize,
        /// Error that occurred.
        error: String,
    },

    /// All renewal attempts exhausted.
    RenewalExhausted {
        /// Total number of attempts made.
        attempts: usize,
    },

    /// Certificate is still valid (no renewal needed).
    CertificateValid {
        /// Time until expiration.
        time_until_expiry: Duration,
    },
}

/// Handler for renewal events.
///
/// Implement this trait to receive notifications about renewal events.
pub trait RenewalEventHandler: Send + Sync {
    /// Handle a renewal event.
    fn handle_event(&self, event: RenewalEvent);
}

/// Automatic certificate renewal scheduler.
///
/// Monitors certificate expiration and automatically triggers re-enrollment
/// when certificates approach expiration.
pub struct RenewalScheduler {
    client: Arc<EstClient>,
    config: RenewalConfig,
    current_cert: Arc<RwLock<Option<Certificate>>>,
    running: Arc<RwLock<bool>>,
}

impl RenewalScheduler {
    /// Create a new renewal scheduler.
    pub fn new(client: EstClient, config: RenewalConfig) -> Self {
        Self {
            client: Arc::new(client),
            config,
            current_cert: Arc::new(RwLock::new(None)),
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Set the certificate to monitor.
    pub async fn set_certificate(&self, cert: Certificate) {
        let mut current = self.current_cert.write().await;
        *current = Some(cert);
    }

    /// Get the current certificate being monitored.
    pub async fn get_certificate(&self) -> Option<Certificate> {
        self.current_cert.read().await.clone()
    }

    /// Check if the scheduler is currently running.
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    /// Start the renewal scheduler.
    ///
    /// This will run in the background, checking certificate expiration
    /// at the configured interval and triggering renewals as needed.
    pub async fn start(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if *running {
            return Err(EstError::operational("Renewal scheduler already running"));
        }
        *running = true;
        drop(running);

        info!("Starting certificate renewal scheduler");
        self.emit_event(RenewalEvent::CheckStarted).await;

        let client = Arc::clone(&self.client);
        let config = self.config.clone();
        let current_cert = Arc::clone(&self.current_cert);
        let running_flag = Arc::clone(&self.running);

        tokio::spawn(async move {
            let mut check_interval = interval(config.check_interval);

            loop {
                check_interval.tick().await;

                // Check if we should still be running
                if !*running_flag.read().await {
                    info!("Renewal scheduler stopped");
                    break;
                }

                // Get current certificate
                let cert = {
                    let guard = current_cert.read().await;
                    guard.clone()
                };

                if let Some(cert) = cert {
                    // Check expiration and renew if needed
                    Self::check_and_renew(&client, &config, &cert, &current_cert).await;
                } else {
                    debug!("No certificate set for renewal monitoring");
                }
            }
        });

        Ok(())
    }

    /// Stop the renewal scheduler.
    pub async fn stop(&self) {
        let mut running = self.running.write().await;
        *running = false;
        info!("Stopping certificate renewal scheduler");
    }

    /// Check certificate expiration and trigger renewal if needed.
    async fn check_and_renew(
        client: &Arc<EstClient>,
        config: &RenewalConfig,
        cert: &Certificate,
        current_cert: &Arc<RwLock<Option<Certificate>>>,
    ) {
        match Self::time_until_expiry(cert) {
            Ok(time_remaining) => {
                debug!(
                    "Certificate expires in {} seconds",
                    time_remaining.as_secs()
                );

                if time_remaining <= config.renewal_threshold {
                    info!(
                        "Certificate expiring in {} days, triggering renewal",
                        time_remaining.as_secs() / 86400
                    );

                    Self::emit_event_static(
                        config,
                        RenewalEvent::RenewalNeeded {
                            time_until_expiry: time_remaining,
                        },
                    )
                    .await;

                    // Attempt renewal with retries
                    Self::attempt_renewal_with_retries(client, config, cert, current_cert).await;
                } else {
                    debug!("Certificate still valid, no renewal needed");
                    Self::emit_event_static(
                        config,
                        RenewalEvent::CertificateValid {
                            time_until_expiry: time_remaining,
                        },
                    )
                    .await;
                }
            }
            Err(e) => {
                error!("Failed to check certificate expiration: {}", e);
            }
        }
    }

    /// Attempt certificate renewal with retry logic.
    async fn attempt_renewal_with_retries(
        client: &Arc<EstClient>,
        config: &RenewalConfig,
        cert: &Certificate,
        current_cert: &Arc<RwLock<Option<Certificate>>>,
    ) {
        for attempt in 1..=config.max_retries {
            info!("Renewal attempt {}/{}", attempt, config.max_retries);

            Self::emit_event_static(config, RenewalEvent::RenewalStarted { attempt }).await;

            // Perform re-enrollment
            match Self::perform_reenrollment(client, cert).await {
                Ok(new_cert) => {
                    info!("Certificate renewal successful");

                    // Update the current certificate
                    {
                        let mut current = current_cert.write().await;
                        *current = Some(new_cert.clone());
                    }

                    Self::emit_event_static(
                        config,
                        RenewalEvent::RenewalSucceeded {
                            certificate: Box::new(new_cert.clone()),
                        },
                    )
                    .await;

                    // Success - exit retry loop
                    return;
                }
                Err(e) => {
                    warn!("Renewal attempt {} failed: {}", attempt, e);

                    Self::emit_event_static(
                        config,
                        RenewalEvent::RenewalFailed {
                            attempt,
                            error: e.to_string(),
                        },
                    )
                    .await;

                    if attempt < config.max_retries {
                        // Exponential backoff
                        let delay = config.retry_delay * 2_u32.pow(attempt as u32 - 1);
                        info!("Retrying in {} seconds", delay.as_secs());
                        sleep(delay).await;
                    }
                }
            }
        }

        error!(
            "All renewal attempts exhausted ({} attempts)",
            config.max_retries
        );
        Self::emit_event_static(
            config,
            RenewalEvent::RenewalExhausted {
                attempts: config.max_retries,
            },
        )
        .await;

        // Note: In production, you might want to take additional action here,
        // such as sending alerts, shutting down services, etc.
    }

    /// Perform certificate re-enrollment.
    ///
    /// Generates a new key pair and CSR based on the existing certificate's subject,
    /// then requests a new certificate from the EST server using simple re-enrollment.
    async fn perform_reenrollment(client: &EstClient, cert: &Certificate) -> Result<Certificate> {
        use crate::bootstrap::BootstrapClient;
        use crate::csr::CsrBuilder;

        debug!("Starting certificate re-enrollment");

        // Extract subject information from existing certificate
        let subject_cn = BootstrapClient::get_subject_cn(cert).ok_or_else(|| {
            EstError::operational("Cannot extract Common Name from existing certificate")
        })?;

        debug!("Re-enrolling certificate for CN: {}", subject_cn);

        // Build a new CSR with the same subject as the existing certificate
        // Generate a new key pair for the renewed certificate
        let (csr_der, _new_key_pair) = CsrBuilder::new()
            .common_name(&subject_cn)
            .san_dns(&subject_cn)
            .key_usage_digital_signature()
            .key_usage_key_encipherment()
            .extended_key_usage_client_auth()
            .build()?;

        debug!("Generated new CSR for re-enrollment");

        // Submit re-enrollment request
        let response = client.simple_reenroll(&csr_der).await?;

        // Parse the new certificate
        let new_cert = response
            .certificate()
            .ok_or_else(|| EstError::protocol("No certificate in re-enrollment response"))?
            .clone();

        info!(
            "Successfully renewed certificate for CN: {}",
            BootstrapClient::get_subject_cn(&new_cert).unwrap_or_else(|| "<unknown>".to_string())
        );

        Ok(new_cert)
    }

    /// Calculate time until certificate expiration.
    fn time_until_expiry(cert: &Certificate) -> Result<Duration> {
        let not_after = &cert.tbs_certificate.validity.not_after;

        // Parse X.509 time to SystemTime
        let expiry_time = Self::parse_x509_time(not_after)?;

        let now = SystemTime::now();
        expiry_time
            .duration_since(now)
            .map_err(|_| EstError::operational("Certificate has already expired"))
    }

    /// Parse X.509 Time to SystemTime.
    #[cfg(feature = "time")]
    fn parse_x509_time(x509_time: &x509_cert::time::Time) -> Result<SystemTime> {
        use x509_cert::time::Time;

        // Both UtcTime and GeneralizedTime have to_unix_duration() method
        let duration = match x509_time {
            Time::UtcTime(utc) => utc.to_unix_duration(),
            Time::GeneralTime(r#gen) => r#gen.to_unix_duration(),
        };

        Ok(SystemTime::UNIX_EPOCH + duration)
    }

    /// Parse X.509 Time to SystemTime (fallback when time feature is disabled).
    #[cfg(not(feature = "time"))]
    fn parse_x509_time(x509_time: &x509_cert::time::Time) -> Result<SystemTime> {
        use x509_cert::time::Time;

        // Without the time crate, return a placeholder far future time
        // This allows compilation but renewal won't work correctly
        let _ = x509_time; // Suppress unused warning
        tracing::warn!(
            "Renewal feature enabled without time crate - certificate expiration checks disabled"
        );

        // Return a time far in the future to prevent false expiration
        Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(u64::MAX / 2))
    }

    /// Calculate days since Unix epoch for a given date.
    /// This is a simplified implementation for demonstration.
    #[allow(dead_code)]
    fn days_since_epoch(year: i32, month: u8, day: u8) -> i64 {
        // Simplified calculation - assumes Gregorian calendar
        let mut days = (year - 1970) as i64 * 365;

        // Add leap years
        days += ((year - 1969) / 4) as i64;
        days -= ((year - 1901) / 100) as i64;
        days += ((year - 1601) / 400) as i64;

        // Add days for months
        let days_in_month = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        for m in 1..month {
            days += days_in_month[(m - 1) as usize] as i64;
        }

        // Add leap day if February and leap year
        if month > 2 && Self::is_leap_year(year) {
            days += 1;
        }

        // Add day of month
        days += (day - 1) as i64;

        days
    }

    /// Check if a year is a leap year.
    #[allow(dead_code)]
    fn is_leap_year(year: i32) -> bool {
        (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
    }

    /// Emit a renewal event (instance method).
    async fn emit_event(&self, event: RenewalEvent) {
        if let Some(ref callback) = self.config.event_callback {
            callback.handle_event(event);
        }
    }

    /// Emit a renewal event (static method for use in spawned tasks).
    async fn emit_event_static(config: &RenewalConfig, event: RenewalEvent) {
        if let Some(ref callback) = config.event_callback {
            callback.handle_event(event);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_renewal_config_builder() {
        let config = RenewalConfig::builder()
            .renewal_threshold(Duration::from_secs(7 * 24 * 60 * 60))
            .check_interval(Duration::from_secs(60 * 60))
            .max_retries(5)
            .retry_delay(Duration::from_secs(30 * 60))
            .build();

        assert_eq!(
            config.renewal_threshold,
            Duration::from_secs(7 * 24 * 60 * 60)
        );
        assert_eq!(config.check_interval, Duration::from_secs(60 * 60));
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.retry_delay, Duration::from_secs(30 * 60));
    }

    #[test]
    fn test_default_config() {
        let config = RenewalConfig::default_config();
        assert_eq!(
            config.renewal_threshold,
            Duration::from_secs(30 * 24 * 60 * 60)
        );
        assert_eq!(config.check_interval, Duration::from_secs(24 * 60 * 60));
        assert_eq!(config.max_retries, 3);
    }

    #[test]
    fn test_is_leap_year() {
        assert!(RenewalScheduler::is_leap_year(2000));
        assert!(RenewalScheduler::is_leap_year(2004));
        assert!(!RenewalScheduler::is_leap_year(1900));
        assert!(!RenewalScheduler::is_leap_year(2001));
        assert!(RenewalScheduler::is_leap_year(2024));
    }

    #[test]
    fn test_days_since_epoch() {
        // Jan 1, 1970 should be 0
        let days = RenewalScheduler::days_since_epoch(1970, 1, 1);
        assert_eq!(days, 0);

        // Jan 2, 1970 should be 1
        let days = RenewalScheduler::days_since_epoch(1970, 1, 2);
        assert_eq!(days, 1);

        // Jan 1, 1971 should be 365
        let days = RenewalScheduler::days_since_epoch(1971, 1, 1);
        assert_eq!(days, 365);
    }
}
