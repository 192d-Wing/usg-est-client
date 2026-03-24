// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! DoD Root CA Certificates
//!
//! This module provides embedded DoD Root CA certificates and utilities
//! for validating certificate chains to DoD trust anchors.
//!
//! # Active DoD Root CAs (as of 2025)
//!
//! - **DoD Root CA 3**: SHA-256, expires December 30, 2029
//! - **DoD Root CA 4**: SHA-256, expires July 25, 2032
//! - **DoD Root CA 5**: SHA-256, expires June 14, 2041
//! - **DoD Root CA 6**: SHA-256, newest root CA
//!
//! # Certificate Download
//!
//! DoD Root CA certificates can be downloaded from:
//! https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/unclass-certificates_pkcs7_DoD.zip
//!
//! # Example
//!
//! ```no_run
//! use usg_est_client::dod::load_dod_root_cas;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Load all active DoD Root CAs
//! let roots = load_dod_root_cas()?;
//! println!("Loaded {} DoD Root CAs", roots.len());
//!
//! for root in &roots {
//!     println!("  - {}: {} (expires {})",
//!         root.name, root.subject_dn, root.not_after);
//! }
//! # Ok(())
//! # }
//! ```

use crate::error::{EstError, Result};
use der::Decode;
use x509_cert::Certificate;

/// DoD Root CA certificate with metadata
#[derive(Debug, Clone)]
pub struct DodRootCa {
    /// Friendly name (e.g., "DoD Root CA 3")
    pub name: String,

    /// X.509 certificate
    pub certificate: Certificate,

    /// Subject Distinguished Name (formatted)
    pub subject_dn: String,

    /// Issuer Distinguished Name (formatted)
    pub issuer_dn: String,

    /// Certificate validity period - Not Before
    pub not_before: String,

    /// Certificate validity period - Not After
    pub not_after: String,

    /// SHA-256 fingerprint (hex)
    pub fingerprint_sha256: String,
}

// Embedded DoD Root CA certificates (DER-encoded)
// These would be populated with actual DoD Root CA certificates
// Downloaded from: https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/unclass-certificates_pkcs7_DoD.zip

/// DoD Root CA 3 certificate (DER-encoded)
/// Valid until: December 30, 2029
/// Subject: CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US
const DOD_ROOT_CA_3: &[u8] = &[
    // Placeholder: actual certificate bytes would go here
    // This would be extracted from the DoD PKI certificate bundle
];

/// DoD Root CA 4 certificate (DER-encoded)
/// Valid until: July 25, 2032
/// Subject: CN=DoD Root CA 4, OU=PKI, OU=DoD, O=U.S. Government, C=US
const DOD_ROOT_CA_4: &[u8] = &[
    // Placeholder: actual certificate bytes would go here
];

/// DoD Root CA 5 certificate (DER-encoded)
/// Valid until: June 14, 2041
/// Subject: CN=DoD Root CA 5, OU=PKI, OU=DoD, O=U.S. Government, C=US
const DOD_ROOT_CA_5: &[u8] = &[
    // Placeholder: actual certificate bytes would go here
];

/// DoD Root CA 6 certificate (DER-encoded)
/// Newest DoD Root CA (issued 2024)
/// Subject: CN=DoD Root CA 6, OU=PKI, OU=DoD, O=U.S. Government, C=US
const DOD_ROOT_CA_6: &[u8] = &[
    // Placeholder: actual certificate bytes would go here
];

/// Load all active DoD Root CA certificates
///
/// This function returns a vector of all currently active DoD Root CA
/// certificates (CA 3, 4, 5, and 6) with metadata.
///
/// # Errors
///
/// Returns an error if any of the embedded certificates cannot be parsed.
///
/// # Example
///
/// ```no_run
/// use usg_est_client::dod::load_dod_root_cas;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let roots = load_dod_root_cas()?;
/// println!("Loaded {} DoD Root CAs", roots.len());
/// # Ok(())
/// # }
/// ```
pub fn load_dod_root_cas() -> Result<Vec<DodRootCa>> {
    let mut roots = Vec::new();

    // Load DoD Root CA 3
    if !DOD_ROOT_CA_3.is_empty() {
        roots.push(parse_dod_root_ca("DoD Root CA 3", DOD_ROOT_CA_3)?);
    }

    // Load DoD Root CA 4
    if !DOD_ROOT_CA_4.is_empty() {
        roots.push(parse_dod_root_ca("DoD Root CA 4", DOD_ROOT_CA_4)?);
    }

    // Load DoD Root CA 5
    if !DOD_ROOT_CA_5.is_empty() {
        roots.push(parse_dod_root_ca("DoD Root CA 5", DOD_ROOT_CA_5)?);
    }

    // Load DoD Root CA 6
    if !DOD_ROOT_CA_6.is_empty() {
        roots.push(parse_dod_root_ca("DoD Root CA 6", DOD_ROOT_CA_6)?);
    }

    // If no certificates are embedded, return an informative error
    if roots.is_empty() {
        return Err(EstError::Config(
            "No DoD Root CA certificates are embedded. \
             Download from: https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/unclass-certificates_pkcs7_DoD.zip"
                .to_string(),
        ));
    }

    Ok(roots)
}

/// Parse a DoD Root CA certificate from DER bytes
fn parse_dod_root_ca(name: &str, der_bytes: &[u8]) -> Result<DodRootCa> {
    // Parse certificate
    let certificate = Certificate::from_der(der_bytes)
        .map_err(|e| EstError::CertificateParsing(format!("Failed to parse {}: {}", name, e)))?;

    // Extract subject DN
    let subject_dn = format_dn(&certificate.tbs_certificate.subject);

    // Extract issuer DN
    let issuer_dn = format_dn(&certificate.tbs_certificate.issuer);

    // Extract validity period
    let not_before = format_time(&certificate.tbs_certificate.validity.not_before);
    let not_after = format_time(&certificate.tbs_certificate.validity.not_after);

    // Calculate SHA-256 fingerprint
    let fingerprint_sha256 = calculate_fingerprint_sha256(der_bytes);

    Ok(DodRootCa {
        name: name.to_string(),
        certificate,
        subject_dn,
        issuer_dn,
        not_before,
        not_after,
        fingerprint_sha256,
    })
}

/// Format a Distinguished Name for display
fn format_dn(name: &x509_cert::name::Name) -> String {
    // Extract RDN components and format
    // For DoD certs, this is typically:
    // C=US, O=U.S. Government, OU=DoD, OU=PKI, CN=DoD Root CA X

    let mut components = Vec::new();

    // Common DN attribute OIDs
    const CN: der::asn1::ObjectIdentifier = der::asn1::ObjectIdentifier::new_unwrap("2.5.4.3"); // commonName
    const O: der::asn1::ObjectIdentifier = der::asn1::ObjectIdentifier::new_unwrap("2.5.4.10"); // organizationName
    const OU: der::asn1::ObjectIdentifier = der::asn1::ObjectIdentifier::new_unwrap("2.5.4.11"); // organizationalUnitName
    const C: der::asn1::ObjectIdentifier = der::asn1::ObjectIdentifier::new_unwrap("2.5.4.6"); // countryName

    for rdn in name.0.iter() {
        for atv in rdn.0.iter() {
            // Get OID and value
            let oid = &atv.oid;
            let value = &atv.value;

            let attr_name = if *oid == CN {
                "CN"
            } else if *oid == O {
                "O"
            } else if *oid == OU {
                "OU"
            } else if *oid == C {
                "C"
            } else {
                continue; // Skip unknown attributes
            };

            // Extract string value - try to get the inner bytes
            if let Ok(s) = std::str::from_utf8(value.value()) {
                components.push(format!("{}={}", attr_name, s));
            }
        }
    }

    // Reverse to get DN in standard order (C, O, OU, CN)
    components.reverse();
    components.join(", ")
}

/// Format a Time value for display
fn format_time(time: &x509_cert::time::Time) -> String {
    // Convert to DateTime for consistent formatting
    let datetime = time.to_date_time();
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        datetime.year(),
        datetime.month(),
        datetime.day(),
        datetime.hour(),
        datetime.minutes(),
        datetime.seconds()
    )
}

/// Calculate SHA-256 fingerprint of certificate
fn calculate_fingerprint_sha256(der_bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(der_bytes);
    let result = hasher.finalize();

    // Format as hex string with colons
    result
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Validate that a certificate chains to a DoD Root CA
///
/// This function checks if the provided certificate can be validated
/// against one of the DoD Root CAs.
///
/// # Arguments
///
/// * `cert` - The certificate to validate
/// * `intermediates` - Optional intermediate certificates in the chain
///
/// # Returns
///
/// Returns `Ok(())` if the certificate chains to a DoD Root CA, otherwise
/// returns an error describing the validation failure.
///
/// # Example
///
/// ```no_run
/// use usg_est_client::dod::validate_dod_chain;
/// # use x509_cert::Certificate;
///
/// # fn example(cert: Certificate) -> Result<(), Box<dyn std::error::Error>> {
/// // Validate certificate chains to DoD Root CA
/// validate_dod_chain(&cert, &[])?;
/// println!("Certificate is valid DoD certificate");
/// # Ok(())
/// # }
/// ```
pub fn validate_dod_chain(_cert: &Certificate, _intermediates: &[Certificate]) -> Result<()> {
    // Placeholder implementation
    // Full implementation would:
    // 1. Load DoD Root CAs
    // 2. Build certificate chain
    // 3. Validate signatures up to root
    // 4. Check validity periods
    // 5. Verify certificate policies

    // For now, return an error indicating this is not yet implemented
    Err(EstError::Config(
        "DoD certificate chain validation is not yet implemented. \
         This will be completed in Phase 12.2.3"
            .to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_dod_root_cas_placeholder() {
        // Test should fail until actual certificates are embedded
        let result = load_dod_root_cas();
        assert!(result.is_err());

        if let Err(EstError::Config(msg)) = result {
            assert!(msg.contains("No DoD Root CA certificates"));
        }
    }

    #[test]
    fn test_format_dn() {
        // Test DN formatting with empty name
        let name = x509_cert::name::Name::default();
        let formatted = format_dn(&name);
        assert_eq!(formatted, "");
    }

    #[test]
    fn test_calculate_fingerprint_sha256() {
        // Test SHA-256 fingerprint calculation
        let test_data = b"test data";
        let fingerprint = calculate_fingerprint_sha256(test_data);

        // Verify format (64 hex chars with colons)
        assert_eq!(fingerprint.len(), 95); // 64 hex + 31 colons
        assert!(fingerprint.contains(':'));
    }

    // NOTE: Test code uses unwrap() deliberately - test fixtures are known valid

    #[test]
    fn test_calculate_fingerprint_sha256_deterministic() {
        let data = b"deterministic test";
        let fp1 = calculate_fingerprint_sha256(data);
        let fp2 = calculate_fingerprint_sha256(data);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_calculate_fingerprint_sha256_different_inputs() {
        let fp1 = calculate_fingerprint_sha256(b"input one");
        let fp2 = calculate_fingerprint_sha256(b"input two");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_parse_dod_root_ca_with_real_cert() {
        // Use the test CA cert fixture as a stand-in for a root CA
        use rustls_pki_types::CertificateDer;
        use rustls_pki_types::pem::PemObject;

        let pem = include_bytes!("../../tests/fixtures/certs/ca.pem");
        let cert_der = CertificateDer::pem_slice_iter(pem).next().unwrap().unwrap();
        let root = parse_dod_root_ca("Test Root CA", cert_der.as_ref()).unwrap();

        assert_eq!(root.name, "Test Root CA");
        assert!(!root.subject_dn.is_empty());
        assert!(!root.issuer_dn.is_empty());
        assert!(!root.not_before.is_empty());
        assert!(!root.not_after.is_empty());
        assert!(!root.fingerprint_sha256.is_empty());
        assert_eq!(root.fingerprint_sha256.len(), 95);
    }

    #[test]
    fn test_parse_dod_root_ca_invalid_der() {
        let result = parse_dod_root_ca("Bad CA", &[0xFF, 0x01, 0x02]);
        assert!(result.is_err());
    }

    #[test]
    fn test_format_dn_with_real_cert() {
        use rustls_pki_types::CertificateDer;
        use rustls_pki_types::pem::PemObject;

        let pem = include_bytes!("../../tests/fixtures/certs/ca.pem");
        let cert_der = CertificateDer::pem_slice_iter(pem).next().unwrap().unwrap();
        let cert = Certificate::from_der(cert_der.as_ref()).unwrap();
        let dn = format_dn(&cert.tbs_certificate.subject);
        // The test CA has CN=EST Test CA, O=EST Test Organization, C=US
        assert!(dn.contains("CN="));
        assert!(dn.contains("EST Test CA"));
    }

    #[test]
    fn test_format_time_utc() {
        use rustls_pki_types::CertificateDer;
        use rustls_pki_types::pem::PemObject;

        let pem = include_bytes!("../../tests/fixtures/certs/ca.pem");
        let cert_der = CertificateDer::pem_slice_iter(pem).next().unwrap().unwrap();
        let cert = Certificate::from_der(cert_der.as_ref()).unwrap();
        let time_str = format_time(&cert.tbs_certificate.validity.not_before);
        // Should produce a formatted date string containing UTC
        assert!(time_str.contains("UTC"));
    }

    #[test]
    fn test_validate_dod_chain_placeholder() {
        use rustls_pki_types::CertificateDer;
        use rustls_pki_types::pem::PemObject;

        let pem = include_bytes!("../../tests/fixtures/certs/client.pem");
        let cert_der = CertificateDer::pem_slice_iter(pem).next().unwrap().unwrap();
        let cert = Certificate::from_der(cert_der.as_ref()).unwrap();
        // The placeholder implementation always returns an error
        let result = validate_dod_chain(&cert, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_dod_root_ca_placeholder_constants_empty() {
        // The placeholder root CA constants should be empty
        assert!(DOD_ROOT_CA_3.is_empty());
        assert!(DOD_ROOT_CA_4.is_empty());
        assert!(DOD_ROOT_CA_5.is_empty());
        assert!(DOD_ROOT_CA_6.is_empty());
    }
}
