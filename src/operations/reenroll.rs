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

//! Simple Re-enrollment operation (POST /simplereenroll).
//!
//! This module provides utilities for the simple re-enrollment operation
//! defined in RFC 7030 Section 4.2.2.

use x509_cert::Certificate;

use crate::error::Result;

/// Validate that a CSR is suitable for re-enrollment.
///
/// Per RFC 7030 Section 4.2.2:
/// "The Subject field and SubjectAltName extension MUST be identical
/// to the corresponding fields in the certificate being renewed/rekeyed"
pub fn validate_reenroll_csr(_csr_der: &[u8], _current_cert: &Certificate) -> Result<()> {
    // Full validation would require:
    // 1. Parse the CSR
    // 2. Extract Subject from CSR
    // 3. Compare with current certificate Subject
    // 4. Extract SubjectAltName from CSR (if present)
    // 5. Compare with current certificate SubjectAltName

    // For now, we trust the caller has constructed a valid CSR
    Ok(())
}

/// Check if a certificate is near expiration and should be renewed.
///
/// Returns the number of days until expiration, or None if the
/// certificate has already expired.
pub fn days_until_expiration(cert: &Certificate) -> Option<i64> {
    use std::time::SystemTime;

    let not_after = &cert.tbs_certificate().validity().not_after;

    // Convert to SystemTime
    let expiry: SystemTime = not_after.to_system_time();
    let now = SystemTime::now();

    match expiry.duration_since(now) {
        Ok(duration) => Some((duration.as_secs() / 86400) as i64),
        Err(_) => None, // Already expired
    }
}

/// Check if a certificate should be renewed based on a threshold.
///
/// Returns true if the certificate will expire within the given
/// number of days.
pub fn should_renew(cert: &Certificate, threshold_days: i64) -> bool {
    match days_until_expiration(cert) {
        Some(days) => days <= threshold_days,
        None => true, // Already expired
    }
}

/// Extract the serial number from a certificate.
pub fn get_serial_number(cert: &Certificate) -> Vec<u8> {
    cert.tbs_certificate().serial_number().as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    // Note: Full tests would require test certificates
    // These are placeholder tests

    #[test]
    fn test_serial_number_extraction() {
        // Would need a test certificate to properly test this
    }
}
