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

//! Windows Performance Counters for EST Auto-Enrollment monitoring.
//!
//! This module provides Windows Performance Counter integration for monitoring
//! EST auto-enrollment operations. It allows administrators to track key metrics
//! using standard Windows tools like Performance Monitor (perfmon.exe).
//!
//! # Performance Counters
//!
//! The following counters are available:
//!
//! - **Certificates Enrolled**: Total successful enrollments
//! - **Certificates Renewed**: Total successful renewals
//! - **Enrollment Failures**: Total enrollment failures
//! - **Renewal Failures**: Total renewal failures
//! - **Days Until Expiration**: Days until certificate expires (current)
//! - **Last Check Time**: Unix timestamp of last certificate check
//! - **Operations Per Minute**: Rate of EST operations
//!
//! # Security
//!
//! Performance counters are readable by all authenticated users by default.
//! Counter registration requires administrator privileges.
//!
//! # Example
//!
//! ```no_run,ignore
//! use usg_est_client::windows::perfcounter::{PerformanceCounters, CounterType};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create and register counters
//! let counters = PerformanceCounters::new("EST Auto-Enrollment")?;
//! counters.register()?;
//!
//! // Update counters during operation
//! counters.increment(CounterType::CertificatesEnrolled)?;
//! counters.set_value(CounterType::DaysUntilExpiration, 30)?;
//!
//! // Clean up on service shutdown
//! counters.unregister()?;
//! # Ok(())
//! # }
//! ```

use crate::error::{EstError, Result};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Performance counter types tracked by the EST service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CounterType {
    /// Total number of successful certificate enrollments.
    CertificatesEnrolled,
    /// Total number of successful certificate renewals.
    CertificatesRenewed,
    /// Total number of enrollment failures.
    EnrollmentFailures,
    /// Total number of renewal failures.
    RenewalFailures,
    /// Days until the current certificate expires.
    DaysUntilExpiration,
    /// Unix timestamp of the last certificate check.
    LastCheckTime,
    /// Number of EST operations per minute (rolling average).
    OperationsPerMinute,
    /// Current service state (0=stopped, 1=running, 2=paused).
    ServiceState,
    /// Number of certificates managed by this service.
    CertificatesManaged,
    /// Average enrollment time in milliseconds.
    AverageEnrollmentTimeMs,
}

impl CounterType {
    /// Get the counter name for display in Performance Monitor.
    pub fn name(&self) -> &'static str {
        match self {
            Self::CertificatesEnrolled => "Certificates Enrolled",
            Self::CertificatesRenewed => "Certificates Renewed",
            Self::EnrollmentFailures => "Enrollment Failures",
            Self::RenewalFailures => "Renewal Failures",
            Self::DaysUntilExpiration => "Days Until Expiration",
            Self::LastCheckTime => "Last Check Time (Unix)",
            Self::OperationsPerMinute => "Operations Per Minute",
            Self::ServiceState => "Service State",
            Self::CertificatesManaged => "Certificates Managed",
            Self::AverageEnrollmentTimeMs => "Avg Enrollment Time (ms)",
        }
    }

    /// Get the counter description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::CertificatesEnrolled => "Total number of certificates successfully enrolled",
            Self::CertificatesRenewed => "Total number of certificates successfully renewed",
            Self::EnrollmentFailures => "Total number of enrollment failures",
            Self::RenewalFailures => "Total number of renewal failures",
            Self::DaysUntilExpiration => "Days until the current certificate expires",
            Self::LastCheckTime => "Unix timestamp of the last certificate check",
            Self::OperationsPerMinute => "Rate of EST operations per minute",
            Self::ServiceState => "Current service state (0=stopped, 1=running, 2=paused)",
            Self::CertificatesManaged => "Number of certificates managed by this service",
            Self::AverageEnrollmentTimeMs => "Average enrollment operation time in milliseconds",
        }
    }

    /// Get the counter type category.
    pub fn is_cumulative(&self) -> bool {
        matches!(
            self,
            Self::CertificatesEnrolled
                | Self::CertificatesRenewed
                | Self::EnrollmentFailures
                | Self::RenewalFailures
        )
    }

    /// Get all counter types.
    pub fn all() -> &'static [CounterType] {
        &[
            Self::CertificatesEnrolled,
            Self::CertificatesRenewed,
            Self::EnrollmentFailures,
            Self::RenewalFailures,
            Self::DaysUntilExpiration,
            Self::LastCheckTime,
            Self::OperationsPerMinute,
            Self::ServiceState,
            Self::CertificatesManaged,
            Self::AverageEnrollmentTimeMs,
        ]
    }
}

/// In-memory counter storage.
///
/// This provides a cross-platform implementation that can be exposed
/// via Windows Performance Counters, Prometheus metrics, or other
/// monitoring systems.
#[derive(Debug)]
pub struct CounterValues {
    certificates_enrolled: AtomicU64,
    certificates_renewed: AtomicU64,
    enrollment_failures: AtomicU64,
    renewal_failures: AtomicU64,
    days_until_expiration: AtomicI64,
    last_check_time: AtomicU64,
    operations_per_minute: AtomicU64,
    service_state: AtomicU64,
    certificates_managed: AtomicU64,
    average_enrollment_time_ms: AtomicU64,
}

impl Default for CounterValues {
    fn default() -> Self {
        Self::new()
    }
}

impl CounterValues {
    /// Create new counter storage with zero values.
    pub fn new() -> Self {
        Self {
            certificates_enrolled: AtomicU64::new(0),
            certificates_renewed: AtomicU64::new(0),
            enrollment_failures: AtomicU64::new(0),
            renewal_failures: AtomicU64::new(0),
            days_until_expiration: AtomicI64::new(-1), // -1 = unknown
            last_check_time: AtomicU64::new(0),
            operations_per_minute: AtomicU64::new(0),
            service_state: AtomicU64::new(0),
            certificates_managed: AtomicU64::new(0),
            average_enrollment_time_ms: AtomicU64::new(0),
        }
    }

    /// Get the value of a counter.
    pub fn get(&self, counter: CounterType) -> i64 {
        match counter {
            CounterType::CertificatesEnrolled => {
                self.certificates_enrolled.load(Ordering::Relaxed) as i64
            }
            CounterType::CertificatesRenewed => {
                self.certificates_renewed.load(Ordering::Relaxed) as i64
            }
            CounterType::EnrollmentFailures => {
                self.enrollment_failures.load(Ordering::Relaxed) as i64
            }
            CounterType::RenewalFailures => self.renewal_failures.load(Ordering::Relaxed) as i64,
            CounterType::DaysUntilExpiration => self.days_until_expiration.load(Ordering::Relaxed),
            CounterType::LastCheckTime => self.last_check_time.load(Ordering::Relaxed) as i64,
            CounterType::OperationsPerMinute => {
                self.operations_per_minute.load(Ordering::Relaxed) as i64
            }
            CounterType::ServiceState => self.service_state.load(Ordering::Relaxed) as i64,
            CounterType::CertificatesManaged => {
                self.certificates_managed.load(Ordering::Relaxed) as i64
            }
            CounterType::AverageEnrollmentTimeMs => {
                self.average_enrollment_time_ms.load(Ordering::Relaxed) as i64
            }
        }
    }

    /// Set the value of a counter.
    pub fn set(&self, counter: CounterType, value: i64) {
        match counter {
            CounterType::CertificatesEnrolled => {
                self.certificates_enrolled
                    .store(value as u64, Ordering::Relaxed);
            }
            CounterType::CertificatesRenewed => {
                self.certificates_renewed
                    .store(value as u64, Ordering::Relaxed);
            }
            CounterType::EnrollmentFailures => {
                self.enrollment_failures
                    .store(value as u64, Ordering::Relaxed);
            }
            CounterType::RenewalFailures => {
                self.renewal_failures.store(value as u64, Ordering::Relaxed);
            }
            CounterType::DaysUntilExpiration => {
                self.days_until_expiration.store(value, Ordering::Relaxed);
            }
            CounterType::LastCheckTime => {
                self.last_check_time.store(value as u64, Ordering::Relaxed);
            }
            CounterType::OperationsPerMinute => {
                self.operations_per_minute
                    .store(value as u64, Ordering::Relaxed);
            }
            CounterType::ServiceState => {
                self.service_state.store(value as u64, Ordering::Relaxed);
            }
            CounterType::CertificatesManaged => {
                self.certificates_managed
                    .store(value as u64, Ordering::Relaxed);
            }
            CounterType::AverageEnrollmentTimeMs => {
                self.average_enrollment_time_ms
                    .store(value as u64, Ordering::Relaxed);
            }
        }
    }

    /// Increment a cumulative counter by 1.
    pub fn increment(&self, counter: CounterType) {
        self.increment_by(counter, 1);
    }

    /// Increment a cumulative counter by a specified amount.
    pub fn increment_by(&self, counter: CounterType, amount: u64) {
        match counter {
            CounterType::CertificatesEnrolled => {
                self.certificates_enrolled
                    .fetch_add(amount, Ordering::Relaxed);
            }
            CounterType::CertificatesRenewed => {
                self.certificates_renewed
                    .fetch_add(amount, Ordering::Relaxed);
            }
            CounterType::EnrollmentFailures => {
                self.enrollment_failures
                    .fetch_add(amount, Ordering::Relaxed);
            }
            CounterType::RenewalFailures => {
                self.renewal_failures.fetch_add(amount, Ordering::Relaxed);
            }
            _ => {} // Non-cumulative counters don't support increment
        }
    }

    /// Update the last check time to now.
    pub fn update_last_check_time(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_check_time.store(now, Ordering::Relaxed);
    }

    /// Reset all counters to their initial values.
    pub fn reset(&self) {
        self.certificates_enrolled.store(0, Ordering::Relaxed);
        self.certificates_renewed.store(0, Ordering::Relaxed);
        self.enrollment_failures.store(0, Ordering::Relaxed);
        self.renewal_failures.store(0, Ordering::Relaxed);
        self.days_until_expiration.store(-1, Ordering::Relaxed);
        self.last_check_time.store(0, Ordering::Relaxed);
        self.operations_per_minute.store(0, Ordering::Relaxed);
        self.service_state.store(0, Ordering::Relaxed);
        self.certificates_managed.store(0, Ordering::Relaxed);
        self.average_enrollment_time_ms.store(0, Ordering::Relaxed);
    }

    /// Get all counter values as a snapshot.
    pub fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            certificates_enrolled: self.get(CounterType::CertificatesEnrolled) as u64,
            certificates_renewed: self.get(CounterType::CertificatesRenewed) as u64,
            enrollment_failures: self.get(CounterType::EnrollmentFailures) as u64,
            renewal_failures: self.get(CounterType::RenewalFailures) as u64,
            days_until_expiration: self.get(CounterType::DaysUntilExpiration),
            last_check_time: self.get(CounterType::LastCheckTime) as u64,
            operations_per_minute: self.get(CounterType::OperationsPerMinute) as u64,
            service_state: self.get(CounterType::ServiceState) as u64,
            certificates_managed: self.get(CounterType::CertificatesManaged) as u64,
            average_enrollment_time_ms: self.get(CounterType::AverageEnrollmentTimeMs) as u64,
        }
    }
}

/// A snapshot of all counter values at a point in time.
#[derive(Debug, Clone, Default)]
pub struct CounterSnapshot {
    /// Total certificates enrolled.
    pub certificates_enrolled: u64,
    /// Total certificates renewed.
    pub certificates_renewed: u64,
    /// Total enrollment failures.
    pub enrollment_failures: u64,
    /// Total renewal failures.
    pub renewal_failures: u64,
    /// Days until certificate expiration (-1 if unknown).
    pub days_until_expiration: i64,
    /// Last check time (Unix timestamp).
    pub last_check_time: u64,
    /// Operations per minute.
    pub operations_per_minute: u64,
    /// Service state (0=stopped, 1=running, 2=paused).
    pub service_state: u64,
    /// Number of certificates managed.
    pub certificates_managed: u64,
    /// Average enrollment time in milliseconds.
    pub average_enrollment_time_ms: u64,
}

/// Performance counters manager for EST Auto-Enrollment.
///
/// This wraps counter storage and provides Windows Performance Counter
/// integration when running on Windows.
#[derive(Clone)]
pub struct PerformanceCounters {
    /// Counter category name.
    category_name: String,
    /// In-memory counter values.
    values: Arc<CounterValues>,
    /// Whether counters are registered with Windows.
    #[allow(dead_code)]
    registered: Arc<std::sync::atomic::AtomicBool>,
}

impl PerformanceCounters {
    /// Create a new performance counters instance.
    ///
    /// # Arguments
    ///
    /// * `category_name` - The performance counter category name
    pub fn new(category_name: &str) -> Result<Self> {
        Ok(Self {
            category_name: category_name.to_string(),
            values: Arc::new(CounterValues::new()),
            registered: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// Get the category name.
    pub fn category_name(&self) -> &str {
        &self.category_name
    }

    /// Get access to the underlying counter values.
    pub fn values(&self) -> &CounterValues {
        &self.values
    }

    /// Register performance counters with Windows.
    ///
    /// This operation requires administrator privileges on Windows.
    /// On non-Windows platforms, this is a no-op.
    #[cfg(windows)]
    pub fn register(&self) -> Result<()> {
        // Windows Performance Counter registration requires:
        // 1. Creating a performance counter category
        // 2. Defining counter metadata
        // 3. Installing the counters via lodctr.exe or programmatically
        //
        // For now, we provide the in-memory implementation and log
        // that Windows counter registration is not yet implemented.
        tracing::warn!(
            "Windows Performance Counter registration not yet implemented for category '{}'",
            self.category_name
        );
        tracing::info!(
            "Counter values are available via PerformanceCounters::values() and snapshot()"
        );

        self.registered
            .store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// Register performance counters (no-op on non-Windows).
    #[cfg(not(windows))]
    pub fn register(&self) -> Result<()> {
        self.registered
            .store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// Unregister performance counters from Windows.
    #[cfg(windows)]
    pub fn unregister(&self) -> Result<()> {
        self.registered
            .store(false, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// Unregister performance counters (no-op on non-Windows).
    #[cfg(not(windows))]
    pub fn unregister(&self) -> Result<()> {
        self.registered
            .store(false, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// Check if counters are registered.
    pub fn is_registered(&self) -> bool {
        self.registered.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Increment a cumulative counter.
    pub fn increment(&self, counter: CounterType) -> Result<()> {
        if !counter.is_cumulative() {
            return Err(EstError::platform(format!(
                "Counter '{}' is not cumulative",
                counter.name()
            )));
        }
        self.values.increment(counter);
        Ok(())
    }

    /// Set a counter value.
    pub fn set_value(&self, counter: CounterType, value: i64) -> Result<()> {
        self.values.set(counter, value);
        Ok(())
    }

    /// Get a counter value.
    pub fn get_value(&self, counter: CounterType) -> i64 {
        self.values.get(counter)
    }

    /// Get a snapshot of all counter values.
    pub fn snapshot(&self) -> CounterSnapshot {
        self.values.snapshot()
    }

    /// Record a successful enrollment.
    pub fn record_enrollment_success(&self) {
        self.values.increment(CounterType::CertificatesEnrolled);
        self.values.update_last_check_time();
    }

    /// Record an enrollment failure.
    pub fn record_enrollment_failure(&self) {
        self.values.increment(CounterType::EnrollmentFailures);
        self.values.update_last_check_time();
    }

    /// Record a successful renewal.
    pub fn record_renewal_success(&self) {
        self.values.increment(CounterType::CertificatesRenewed);
        self.values.update_last_check_time();
    }

    /// Record a renewal failure.
    pub fn record_renewal_failure(&self) {
        self.values.increment(CounterType::RenewalFailures);
        self.values.update_last_check_time();
    }

    /// Update the days until expiration counter.
    pub fn update_expiration_days(&self, days: i64) {
        self.values.set(CounterType::DaysUntilExpiration, days);
    }

    /// Update the service state counter.
    pub fn update_service_state(&self, state: ServiceStateCounter) {
        self.values.set(CounterType::ServiceState, state as i64);
    }

    /// Update the number of managed certificates.
    pub fn update_certificates_managed(&self, count: u64) {
        self.values
            .set(CounterType::CertificatesManaged, count as i64);
    }

    /// Record enrollment time for averaging.
    pub fn record_enrollment_time(&self, duration_ms: u64) {
        // Simple implementation: just store the last value
        // A more sophisticated implementation would calculate a rolling average
        self.values
            .set(CounterType::AverageEnrollmentTimeMs, duration_ms as i64);
    }
}

/// Service state values for the performance counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum ServiceStateCounter {
    /// Service is stopped.
    Stopped = 0,
    /// Service is running.
    Running = 1,
    /// Service is paused.
    Paused = 2,
    /// Service is starting.
    Starting = 3,
    /// Service is stopping.
    Stopping = 4,
}

/// Timing helper for measuring operation duration.
pub struct OperationTimer {
    start: std::time::Instant,
    counters: PerformanceCounters,
}

impl OperationTimer {
    /// Start timing an operation.
    pub fn start(counters: PerformanceCounters) -> Self {
        Self {
            start: std::time::Instant::now(),
            counters,
        }
    }

    /// Complete the operation and record timing.
    pub fn complete_enrollment(self, success: bool) {
        let duration_ms = self.start.elapsed().as_millis() as u64;
        self.counters.record_enrollment_time(duration_ms);

        if success {
            self.counters.record_enrollment_success();
        } else {
            self.counters.record_enrollment_failure();
        }
    }

    /// Complete the operation and record timing for renewal.
    pub fn complete_renewal(self, success: bool) {
        let duration_ms = self.start.elapsed().as_millis() as u64;
        self.counters.record_enrollment_time(duration_ms);

        if success {
            self.counters.record_renewal_success();
        } else {
            self.counters.record_renewal_failure();
        }
    }

    /// Get elapsed time without completing.
    pub fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: Test code uses unwrap() deliberately - test fixtures are known valid
    // and panics in tests provide clear failure messages. See ERROR-HANDLING-PATTERNS.md
    // Pattern 5 for justification.

    #[test]
    fn test_counter_type_names() {
        assert_eq!(
            CounterType::CertificatesEnrolled.name(),
            "Certificates Enrolled"
        );
        assert_eq!(
            CounterType::DaysUntilExpiration.name(),
            "Days Until Expiration"
        );
    }

    #[test]
    fn test_counter_type_cumulative() {
        assert!(CounterType::CertificatesEnrolled.is_cumulative());
        assert!(CounterType::EnrollmentFailures.is_cumulative());
        assert!(!CounterType::DaysUntilExpiration.is_cumulative());
        assert!(!CounterType::ServiceState.is_cumulative());
    }

    #[test]
    fn test_counter_values_increment() {
        let values = CounterValues::new();

        assert_eq!(values.get(CounterType::CertificatesEnrolled), 0);
        values.increment(CounterType::CertificatesEnrolled);
        assert_eq!(values.get(CounterType::CertificatesEnrolled), 1);
        values.increment_by(CounterType::CertificatesEnrolled, 5);
        assert_eq!(values.get(CounterType::CertificatesEnrolled), 6);
    }

    #[test]
    fn test_counter_values_set() {
        let values = CounterValues::new();

        values.set(CounterType::DaysUntilExpiration, 30);
        assert_eq!(values.get(CounterType::DaysUntilExpiration), 30);

        values.set(CounterType::ServiceState, 1);
        assert_eq!(values.get(CounterType::ServiceState), 1);
    }

    #[test]
    fn test_counter_values_reset() {
        let values = CounterValues::new();

        values.increment(CounterType::CertificatesEnrolled);
        values.set(CounterType::DaysUntilExpiration, 30);

        values.reset();

        assert_eq!(values.get(CounterType::CertificatesEnrolled), 0);
        assert_eq!(values.get(CounterType::DaysUntilExpiration), -1);
    }

    #[test]
    fn test_counter_snapshot() {
        let values = CounterValues::new();
        values.increment_by(CounterType::CertificatesEnrolled, 10);
        values.set(CounterType::DaysUntilExpiration, 45);

        let snapshot = values.snapshot();
        assert_eq!(snapshot.certificates_enrolled, 10);
        assert_eq!(snapshot.days_until_expiration, 45);
    }

    #[test]
    fn test_performance_counters_new() {
        let counters = PerformanceCounters::new("Test Category").unwrap();
        assert_eq!(counters.category_name(), "Test Category");
        assert!(!counters.is_registered());
    }

    #[test]
    fn test_performance_counters_increment() {
        let counters = PerformanceCounters::new("Test").unwrap();

        counters
            .increment(CounterType::CertificatesEnrolled)
            .unwrap();
        assert_eq!(counters.get_value(CounterType::CertificatesEnrolled), 1);
    }

    #[test]
    fn test_performance_counters_increment_non_cumulative() {
        let counters = PerformanceCounters::new("Test").unwrap();

        let result = counters.increment(CounterType::DaysUntilExpiration);
        assert!(result.is_err());
    }

    #[test]
    fn test_performance_counters_record_success() {
        let counters = PerformanceCounters::new("Test").unwrap();

        counters.record_enrollment_success();
        counters.record_enrollment_success();
        counters.record_renewal_success();

        let snapshot = counters.snapshot();
        assert_eq!(snapshot.certificates_enrolled, 2);
        assert_eq!(snapshot.certificates_renewed, 1);
        assert!(snapshot.last_check_time > 0);
    }

    #[test]
    fn test_performance_counters_record_failure() {
        let counters = PerformanceCounters::new("Test").unwrap();

        counters.record_enrollment_failure();
        counters.record_renewal_failure();

        let snapshot = counters.snapshot();
        assert_eq!(snapshot.enrollment_failures, 1);
        assert_eq!(snapshot.renewal_failures, 1);
    }

    #[test]
    fn test_service_state_counter() {
        let counters = PerformanceCounters::new("Test").unwrap();

        counters.update_service_state(ServiceStateCounter::Running);
        assert_eq!(counters.get_value(CounterType::ServiceState), 1);

        counters.update_service_state(ServiceStateCounter::Paused);
        assert_eq!(counters.get_value(CounterType::ServiceState), 2);
    }

    #[test]
    fn test_operation_timer() {
        let counters = PerformanceCounters::new("Test").unwrap();
        let timer = OperationTimer::start(counters.clone());

        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(timer.elapsed_ms() >= 10);

        timer.complete_enrollment(true);

        assert_eq!(counters.get_value(CounterType::CertificatesEnrolled), 1);
        assert!(counters.get_value(CounterType::AverageEnrollmentTimeMs) >= 10);
    }
}
