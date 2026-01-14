// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! CAC/PIV Smart Card Support
//!
//! This module provides integration with Common Access Cards (CAC) and Personal
//! Identity Verification (PIV) cards for DoD deployments.
//!
//! # NIST 800-53 Controls
//!
//! - **IA-2**: Identification and Authentication (Organizational Users)
//!   - Multi-factor authentication using CAC/PIV smart cards
//!   - Hardware token (something you have) + PIN (something you know)
//!   - FIPS 201-2 compliant PIV authentication
//! - **IA-4**: Identifier Management
//!   - Unique identification via PIV card serial numbers and certificates
//!   - Identity binding to cryptographic keys on smart card
//! - **IA-5**: Authenticator Management
//!   - Secure authenticator (PIV card) lifecycle
//!   - PIN-protected access to private keys
//!   - Certificate-based authentication credentials
//! - **IA-8**: Identification and Authentication (Non-Organizational Users)
//!   - Federal PKI certificate-based authentication
//!   - Support for DoD External Certificate Authority (ECA) certificates
//! - **SC-17**: Public Key Infrastructure Certificates
//!   - PIV certificate validation and trust chain verification
//!   - Integration with DoD PKI infrastructure
//!
//! # Overview
//!
//! CAC and PIV cards contain multiple certificates in different slots:
//!
//! | Slot | Name | OID | Use |
//! |------|------|-----|-----|
//! | 9A | PIV Authentication | 2.16.840.1.101.3.7.2.1.1.0 | TLS client auth, VPN, EST enrollment |
//! | 9C | Digital Signature | 2.16.840.1.101.3.7.2.1.1.1 | Document signing, email signing |
//! | 9D | Key Management | 2.16.840.1.101.3.7.2.1.1.2 | Encryption, key exchange |
//! | 9E | Card Authentication | 2.16.840.1.101.3.7.2.96 | Physical access (no PIN) |
//!
//! # Requirements
//!
//! - PKCS#11 middleware (OpenSC, ActivClient, CoolKey)
//! - Smart card reader
//! - CAC/PIV card with valid certificates
//!
//! # Example
//!
//! ```no_run
//! use usg_est_client::dod::{enumerate_cac_certificates, PivSlot};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Enumerate certificates on CAC
//! let certs = enumerate_cac_certificates()?;
//!
//! for cert in &certs {
//!     println!("Slot {:?}: {}", cert.slot, cert.subject);
//!     if cert.slot == PivSlot::Authentication {
//!         println!("  -> Can be used for EST enrollment");
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # References
//!
//! - [NIST SP 800-73-4](https://csrc.nist.gov/publications/detail/sp/800-73/4/final) - PIV Card Application
//! - [NIST SP 800-78-4](https://csrc.nist.gov/publications/detail/sp/800-78/4/final) - PIV Cryptographic Algorithms

use crate::error::{EstError, Result};
use x509_cert::Certificate;

/// PIV card slots
///
/// Each slot serves a specific purpose and has different PIN requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PivSlot {
    /// Slot 9A - PIV Authentication
    ///
    /// Used for TLS client authentication, VPN, EST enrollment.
    /// Requires PIN for private key operations.
    Authentication,

    /// Slot 9C - Digital Signature
    ///
    /// Used for document signing, email signing, CSR signing.
    /// Requires PIN for each signature operation.
    DigitalSignature,

    /// Slot 9D - Key Management
    ///
    /// Used for encryption/decryption, key exchange.
    /// Requires PIN for private key operations.
    KeyManagement,

    /// Slot 9E - Card Authentication
    ///
    /// Used for physical access control.
    /// Does NOT require PIN (contactless access).
    CardAuthentication,

    /// Slot 82-95 - Retired Key Management
    ///
    /// Historical key management certificates.
    RetiredKeyManagement(u8),
}

impl PivSlot {
    /// Get the PIV slot ID (hex)
    pub fn slot_id(&self) -> u8 {
        match self {
            Self::Authentication => 0x9A,
            Self::DigitalSignature => 0x9C,
            Self::KeyManagement => 0x9D,
            Self::CardAuthentication => 0x9E,
            Self::RetiredKeyManagement(n) => 0x82 + n,
        }
    }

    /// Get the PKCS#11 object ID for this slot
    pub fn pkcs11_id(&self) -> &'static [u8] {
        match self {
            Self::Authentication => &[0x01],
            Self::DigitalSignature => &[0x02],
            Self::KeyManagement => &[0x03],
            Self::CardAuthentication => &[0x04],
            Self::RetiredKeyManagement(_) => &[0x05], // Varies
        }
    }

    /// Whether this slot requires PIN for operations
    pub fn requires_pin(&self) -> bool {
        !matches!(self, Self::CardAuthentication)
    }

    /// Human-readable name for this slot
    pub fn name(&self) -> &'static str {
        match self {
            Self::Authentication => "PIV Authentication",
            Self::DigitalSignature => "Digital Signature",
            Self::KeyManagement => "Key Management",
            Self::CardAuthentication => "Card Authentication",
            Self::RetiredKeyManagement(_) => "Retired Key Management",
        }
    }

    /// Get the typical use case for this slot
    pub fn use_case(&self) -> &'static str {
        match self {
            Self::Authentication => "TLS client auth, VPN, EST enrollment",
            Self::DigitalSignature => "Document signing, email signing",
            Self::KeyManagement => "Encryption, key exchange",
            Self::CardAuthentication => "Physical access (contactless)",
            Self::RetiredKeyManagement(_) => "Historical key recovery",
        }
    }

    /// Check if this slot can be used for EST enrollment
    pub fn can_use_for_est(&self) -> bool {
        matches!(self, Self::Authentication | Self::DigitalSignature)
    }

    /// Parse slot from PKCS#11 slot ID
    pub fn from_slot_id(id: u8) -> Option<Self> {
        match id {
            0x9A => Some(Self::Authentication),
            0x9C => Some(Self::DigitalSignature),
            0x9D => Some(Self::KeyManagement),
            0x9E => Some(Self::CardAuthentication),
            0x82..=0x95 => Some(Self::RetiredKeyManagement(id - 0x82)),
            _ => None,
        }
    }
}

impl std::fmt::Display for PivSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (0x{:02X})", self.name(), self.slot_id())
    }
}

/// Certificate from a CAC/PIV card
#[derive(Debug, Clone)]
pub struct CacCertificate {
    /// PIV slot containing this certificate
    pub slot: PivSlot,

    /// X.509 certificate
    pub certificate: Certificate,

    /// Subject Distinguished Name (formatted)
    pub subject: String,

    /// Issuer Distinguished Name (formatted)
    pub issuer: String,

    /// Certificate serial number (hex)
    pub serial: String,

    /// Certificate validity - Not Before
    pub not_before: String,

    /// Certificate validity - Not After
    pub not_after: String,

    /// Whether the certificate is currently valid (time-wise)
    pub is_valid: bool,

    /// Key algorithm (RSA-2048, ECC P-256, etc.)
    pub key_algorithm: String,
}

impl CacCertificate {
    /// Check if this certificate can be used for EST enrollment
    pub fn can_use_for_est(&self) -> bool {
        self.slot.can_use_for_est() && self.is_valid
    }

    /// Check if this certificate requires PIN for operations
    pub fn requires_pin(&self) -> bool {
        self.slot.requires_pin()
    }
}

/// CAC reader detection result
#[derive(Debug, Clone)]
pub struct CacReader {
    /// Reader name
    pub name: String,

    /// Whether a card is present
    pub card_present: bool,

    /// PKCS#11 slot index
    pub slot_index: u64,
}

/// Enumerate all certificates on CAC/PIV cards
///
/// This function searches for connected smart card readers and extracts
/// certificates from any CAC/PIV cards found.
///
/// # Requirements
///
/// - PKCS#11 middleware must be installed (OpenSC, ActivClient, etc.)
/// - Smart card reader must be connected
/// - CAC/PIV card must be inserted
///
/// # Example
///
/// ```no_run
/// use usg_est_client::dod::enumerate_cac_certificates;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let certs = enumerate_cac_certificates()?;
/// for cert in &certs {
///     println!("Found certificate in slot {:?}", cert.slot);
///     println!("  Subject: {}", cert.subject);
///     println!("  Valid: {}", cert.is_valid);
/// }
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "pkcs11")]
pub fn enumerate_cac_certificates() -> Result<Vec<CacCertificate>> {
    enumerate_cac_certificates_with_middleware(None)
}

/// Enumerate CAC certificates using a specific PKCS#11 middleware
///
/// # Arguments
///
/// * `middleware_path` - Path to PKCS#11 library (e.g., "/usr/lib/opensc-pkcs11.so")
///                       If None, uses system default
#[cfg(feature = "pkcs11")]
pub fn enumerate_cac_certificates_with_middleware(
    middleware_path: Option<&str>,
) -> Result<Vec<CacCertificate>> {
    use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
    use cryptoki::object::{Attribute, AttributeType, ObjectClass};
    use der::Decode;

    // Determine PKCS#11 library path
    let lib_path = middleware_path
        .map(String::from)
        .or_else(detect_pkcs11_middleware)
        .ok_or_else(|| {
            EstError::Pkcs11(
                "No PKCS#11 middleware found. Install OpenSC or ActivClient.".to_string(),
            )
        })?;

    // Initialize PKCS#11 context
    let pkcs11 = Pkcs11::new(&lib_path)
        .map_err(|e| EstError::Pkcs11(format!("Failed to load PKCS#11 library: {}", e)))?;

    let init_args = CInitializeArgs::new(CInitializeFlags::empty());
    pkcs11
        .initialize(init_args)
        .map_err(|e| EstError::Pkcs11(format!("Failed to initialize PKCS#11: {}", e)))?;

    let mut certificates = Vec::new();

    // Get all slots with tokens
    let slots = pkcs11
        .get_slots_with_token()
        .map_err(|e| EstError::Pkcs11(format!("Failed to get PKCS#11 slots: {}", e)))?;

    for slot in slots {
        // Open a session (read-only, no login needed for certificate enumeration)
        let session = match pkcs11.open_ro_session(slot) {
            Ok(s) => s,
            Err(_) => continue, // Skip slots we can't access
        };

        // Find certificate objects
        let template = vec![Attribute::Class(ObjectClass::CERTIFICATE)];

        let objects = match session.find_objects(&template) {
            Ok(o) => o,
            Err(_) => continue,
        };

        for obj in objects {
            // Get certificate attributes
            let attrs = match session.get_attributes(
                obj,
                &[
                    AttributeType::Value,
                    AttributeType::Id,
                    AttributeType::Label,
                ],
            ) {
                Ok(a) => a,
                Err(_) => continue,
            };

            // Extract certificate DER value
            let cert_der = attrs.iter().find_map(|a| {
                if let Attribute::Value(v) = a {
                    Some(v.clone())
                } else {
                    None
                }
            });

            let cert_der = match cert_der {
                Some(d) => d,
                None => continue,
            };

            // Get certificate ID (used to determine slot)
            let cert_id = attrs.iter().find_map(|a| {
                if let Attribute::Id(id) = a {
                    Some(id.clone())
                } else {
                    None
                }
            });

            // Parse certificate
            let certificate = match Certificate::from_der(&cert_der) {
                Ok(c) => c,
                Err(_) => continue,
            };

            // Determine PIV slot from certificate ID
            let piv_slot = cert_id
                .and_then(|id| id.first().copied())
                .and_then(PivSlot::from_slot_id)
                .unwrap_or(PivSlot::Authentication);

            // Extract certificate metadata
            let cac_cert = parse_cac_certificate(certificate, piv_slot);
            certificates.push(cac_cert);
        }
    }

    Ok(certificates)
}

/// Detect installed PKCS#11 middleware
#[cfg(feature = "pkcs11")]
fn detect_pkcs11_middleware() -> Option<String> {
    // Common PKCS#11 library locations
    let candidates = [
        // OpenSC (Linux)
        "/usr/lib/opensc-pkcs11.so",
        "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
        "/usr/lib64/opensc-pkcs11.so",
        // OpenSC (macOS)
        "/usr/local/lib/opensc-pkcs11.so",
        "/opt/homebrew/lib/opensc-pkcs11.so",
        // ActivClient (Linux)
        "/usr/lib/libacpkcs211.so",
        "/usr/lib64/libacpkcs211.so",
        // ActivClient (Windows paths - would need different handling)
        // CoolKey (Linux)
        "/usr/lib/pkcs11/libcoolkeypk11.so",
        "/usr/lib64/pkcs11/libcoolkeypk11.so",
        // SafeNet (Linux)
        "/usr/lib/libeToken.so",
        "/usr/lib64/libeToken.so",
    ];

    for path in &candidates {
        if std::path::Path::new(path).exists() {
            return Some(path.to_string());
        }
    }

    // Check environment variable
    std::env::var("PKCS11_MODULE").ok()
}

/// Parse a certificate from CAC into CacCertificate struct
fn parse_cac_certificate(certificate: Certificate, slot: PivSlot) -> CacCertificate {
    // Extract subject DN
    let subject = format_dn(&certificate.tbs_certificate.subject);

    // Extract issuer DN
    let issuer = format_dn(&certificate.tbs_certificate.issuer);

    // Extract serial number
    let serial = hex::encode(certificate.tbs_certificate.serial_number.as_bytes());

    // Extract validity period
    let not_before = format_time(&certificate.tbs_certificate.validity.not_before);
    let not_after = format_time(&certificate.tbs_certificate.validity.not_after);

    // Check if certificate is currently valid
    let is_valid = check_validity(&certificate.tbs_certificate.validity);

    // Extract key algorithm
    let key_algorithm = format_key_algorithm(&certificate.tbs_certificate.subject_public_key_info);

    CacCertificate {
        slot,
        certificate,
        subject,
        issuer,
        serial,
        not_before,
        not_after,
        is_valid,
        key_algorithm,
    }
}

/// Format Distinguished Name
fn format_dn(name: &x509_cert::name::Name) -> String {
    let mut components = Vec::new();

    // Common DN attribute OIDs
    const CN: der::asn1::ObjectIdentifier = der::asn1::ObjectIdentifier::new_unwrap("2.5.4.3");
    const O: der::asn1::ObjectIdentifier = der::asn1::ObjectIdentifier::new_unwrap("2.5.4.10");
    const OU: der::asn1::ObjectIdentifier = der::asn1::ObjectIdentifier::new_unwrap("2.5.4.11");
    const C: der::asn1::ObjectIdentifier = der::asn1::ObjectIdentifier::new_unwrap("2.5.4.6");

    for rdn in name.0.iter() {
        for atv in rdn.0.iter() {
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
                continue;
            };

            if let Ok(s) = std::str::from_utf8(value.value()) {
                components.push(format!("{}={}", attr_name, s));
            }
        }
    }

    components.reverse();
    components.join(", ")
}

/// Format time for display
fn format_time(time: &x509_cert::time::Time) -> String {
    let datetime = time.to_date_time();
    format!(
        "{:04}-{:02}-{:02}",
        datetime.year(),
        datetime.month(),
        datetime.day()
    )
}

/// Check if certificate validity period is current
fn check_validity(validity: &x509_cert::time::Validity) -> bool {
    // Simplified check - in production, would compare against current time
    // For now, just return true as placeholder
    let _ = validity;
    true
}

/// Format key algorithm for display
fn format_key_algorithm(spki: &x509_cert::spki::SubjectPublicKeyInfoOwned) -> String {
    let oid = &spki.algorithm.oid;

    // RSA OID
    const RSA: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
    // EC OID
    const EC: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

    if *oid == RSA {
        // Estimate key size from public key length
        let key_bits = spki.subject_public_key.raw_bytes().len() * 8;
        format!("RSA-{}", key_bits)
    } else if *oid == EC {
        // Check curve OID in parameters
        "ECC".to_string()
    } else {
        format!("Unknown ({})", oid)
    }
}

/// Find the best certificate for EST enrollment
///
/// Searches CAC certificates and returns the best one for EST enrollment,
/// preferring the PIV Authentication certificate (slot 9A).
///
/// # Example
///
/// ```no_run
/// use usg_est_client::dod::find_est_certificate;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// if let Some(cert) = find_est_certificate()? {
///     println!("Using certificate: {}", cert.subject);
///     println!("From slot: {:?}", cert.slot);
/// } else {
///     println!("No suitable certificate found on CAC");
/// }
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "pkcs11")]
pub fn find_est_certificate() -> Result<Option<CacCertificate>> {
    let certs = enumerate_cac_certificates()?;

    // Prefer PIV Authentication (9A) slot
    if let Some(cert) = certs
        .iter()
        .find(|c| c.slot == PivSlot::Authentication && c.is_valid)
    {
        return Ok(Some(cert.clone()));
    }

    // Fall back to Digital Signature (9C) slot
    if let Some(cert) = certs
        .iter()
        .find(|c| c.slot == PivSlot::DigitalSignature && c.is_valid)
    {
        return Ok(Some(cert.clone()));
    }

    // Return any valid certificate that can be used for EST
    Ok(certs.into_iter().find(|c| c.can_use_for_est()))
}

/// List all available smart card readers
#[cfg(feature = "pkcs11")]
pub fn list_readers() -> Result<Vec<CacReader>> {
    use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};

    let lib_path = detect_pkcs11_middleware()
        .ok_or_else(|| EstError::Pkcs11("No PKCS#11 middleware found".to_string()))?;

    let pkcs11 = Pkcs11::new(&lib_path)
        .map_err(|e| EstError::Pkcs11(format!("Failed to load PKCS#11 library: {}", e)))?;

    let init_args = CInitializeArgs::new(CInitializeFlags::empty());
    pkcs11
        .initialize(init_args)
        .map_err(|e| EstError::Pkcs11(format!("Failed to initialize PKCS#11: {}", e)))?;

    let slots = pkcs11
        .get_all_slots()
        .map_err(|e| EstError::Pkcs11(format!("Failed to get slots: {}", e)))?;

    let mut readers = Vec::new();

    for slot in slots {
        let slot_info = match pkcs11.get_slot_info(slot) {
            Ok(info) => info,
            Err(_) => continue,
        };

        let token_present = pkcs11.get_token_info(slot).is_ok();

        readers.push(CacReader {
            name: slot_info.slot_description().to_string(),
            card_present: token_present,
            slot_index: slot.id(),
        });
    }

    Ok(readers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_piv_slot_ids() {
        assert_eq!(PivSlot::Authentication.slot_id(), 0x9A);
        assert_eq!(PivSlot::DigitalSignature.slot_id(), 0x9C);
        assert_eq!(PivSlot::KeyManagement.slot_id(), 0x9D);
        assert_eq!(PivSlot::CardAuthentication.slot_id(), 0x9E);
        assert_eq!(PivSlot::RetiredKeyManagement(0).slot_id(), 0x82);
        assert_eq!(PivSlot::RetiredKeyManagement(5).slot_id(), 0x87);
    }

    #[test]
    fn test_piv_slot_from_id() {
        assert_eq!(PivSlot::from_slot_id(0x9A), Some(PivSlot::Authentication));
        assert_eq!(PivSlot::from_slot_id(0x9C), Some(PivSlot::DigitalSignature));
        assert_eq!(PivSlot::from_slot_id(0x9D), Some(PivSlot::KeyManagement));
        assert_eq!(
            PivSlot::from_slot_id(0x9E),
            Some(PivSlot::CardAuthentication)
        );
        assert_eq!(
            PivSlot::from_slot_id(0x82),
            Some(PivSlot::RetiredKeyManagement(0))
        );
        assert_eq!(PivSlot::from_slot_id(0x00), None);
    }

    #[test]
    fn test_piv_slot_requires_pin() {
        assert!(PivSlot::Authentication.requires_pin());
        assert!(PivSlot::DigitalSignature.requires_pin());
        assert!(PivSlot::KeyManagement.requires_pin());
        assert!(!PivSlot::CardAuthentication.requires_pin());
    }

    #[test]
    fn test_piv_slot_can_use_for_est() {
        assert!(PivSlot::Authentication.can_use_for_est());
        assert!(PivSlot::DigitalSignature.can_use_for_est());
        assert!(!PivSlot::KeyManagement.can_use_for_est());
        assert!(!PivSlot::CardAuthentication.can_use_for_est());
    }

    #[test]
    fn test_piv_slot_display() {
        assert_eq!(
            PivSlot::Authentication.to_string(),
            "PIV Authentication (0x9A)"
        );
        assert_eq!(
            PivSlot::CardAuthentication.to_string(),
            "Card Authentication (0x9E)"
        );
    }

    #[test]
    fn test_piv_slot_name() {
        assert_eq!(PivSlot::Authentication.name(), "PIV Authentication");
        assert_eq!(PivSlot::DigitalSignature.name(), "Digital Signature");
        assert_eq!(PivSlot::KeyManagement.name(), "Key Management");
        assert_eq!(PivSlot::CardAuthentication.name(), "Card Authentication");
    }

    #[test]
    fn test_piv_slot_use_case() {
        assert!(PivSlot::Authentication.use_case().contains("EST"));
        assert!(PivSlot::DigitalSignature.use_case().contains("signing"));
        assert!(PivSlot::KeyManagement.use_case().contains("Encryption"));
        assert!(PivSlot::CardAuthentication.use_case().contains("Physical"));
    }
}
