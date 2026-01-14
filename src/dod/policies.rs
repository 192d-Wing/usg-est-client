// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! DoD Certificate Policy Validation
//!
//! This module provides validation of DoD certificate policies per the
//! DoD X.509 Certificate Policy.
//!
//! # DoD Certificate Policy OIDs
//!
//! All DoD certificate policies are under the arc: **2.16.840.1.101.2.1.11**
//!
//! ## Common Policy OIDs
//!
//! | Policy | OID | Description |
//! |--------|-----|-------------|
//! | Medium Assurance | 2.16.840.1.101.2.1.11.36 | Software tokens |
//! | Medium Hardware | 2.16.840.1.101.2.1.11.18 | Hardware tokens (CAC) |
//! | High Assurance | 2.16.840.1.101.2.1.11.42 | High-security environments |
//! | PIV Auth | 2.16.840.1.101.2.1.11.10 | PIV authentication |
//! | PIV Auth Hardware | 2.16.840.1.101.2.1.11.20 | PIV hardware authentication |
//! | Common Auth | 2.16.840.1.101.2.1.11.39 | Common authentication |
//! | Card Auth | 2.16.840.1.101.2.1.11.17 | Card authentication |
//! | Content Signing | 2.16.840.1.101.2.1.11.38 | Content/code signing |
//!
//! # Example
//!
//! ```no_run
//! use usg_est_client::dod::{DodCertificatePolicy, validate_dod_policy};
//! # use x509_cert::Certificate;
//!
//! # fn example(cert: &Certificate) -> Result<(), Box<dyn std::error::Error>> {
//! // Validate certificate has required DoD policy
//! let policy = validate_dod_policy(cert)?;
//! println!("Certificate policy: {:?}", policy);
//!
//! // Check if certificate can be used for authentication
//! if policy.allows_authentication() {
//!     println!("Certificate can be used for authentication");
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # References
//!
//! - [DoD X.509 Certificate Policy](https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/pdf/Unclass-DoD_X.509_Certificate_Policy_v10.7_Jun_3_21.pdf)

use crate::error::{EstError, Result};
use const_oid::ObjectIdentifier;
use der::Reader;
use x509_cert::Certificate;

/// DoD Certificate Policy arc (2.16.840.1.101.2.1.11)
pub const DOD_POLICY_ARC: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.11");

/// DoD Medium Assurance policy (software tokens)
pub const DOD_MEDIUM_ASSURANCE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.11.36");

/// DoD Medium Hardware policy (CAC/hardware tokens)
pub const DOD_MEDIUM_HARDWARE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.11.18");

/// DoD High Assurance policy
pub const DOD_HIGH_ASSURANCE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.11.42");

/// DoD PIV Authentication policy
pub const DOD_PIV_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.11.10");

/// DoD PIV Authentication Hardware policy
pub const DOD_PIV_AUTH_HARDWARE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.11.20");

/// DoD Common Authentication policy
pub const DOD_COMMON_AUTH: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.11.39");

/// DoD Card Authentication policy
pub const DOD_CARD_AUTH: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.11.17");

/// DoD Content Signing policy
pub const DOD_CONTENT_SIGNING: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.11.38");

/// DoD Device Identification policy
pub const DOD_DEVICE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.11.44");

/// DoD certificate policy types
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DodCertificatePolicy {
    /// Medium Assurance - software tokens
    MediumAssurance,

    /// Medium Hardware - CAC and hardware tokens
    MediumHardware,

    /// High Assurance - high-security environments
    HighAssurance,

    /// PIV Authentication
    PivAuth,

    /// PIV Authentication Hardware
    PivAuthHardware,

    /// Common Authentication
    CommonAuth,

    /// Card Authentication (no PIN required)
    CardAuth,

    /// Content/Code Signing
    ContentSigning,

    /// Device Identification
    Device,

    /// Unknown DoD policy (OID under DoD arc but not recognized)
    Unknown(String),
}

impl DodCertificatePolicy {
    /// Get the OID for this policy
    pub fn oid(&self) -> Option<ObjectIdentifier> {
        match self {
            Self::MediumAssurance => Some(DOD_MEDIUM_ASSURANCE),
            Self::MediumHardware => Some(DOD_MEDIUM_HARDWARE),
            Self::HighAssurance => Some(DOD_HIGH_ASSURANCE),
            Self::PivAuth => Some(DOD_PIV_AUTH),
            Self::PivAuthHardware => Some(DOD_PIV_AUTH_HARDWARE),
            Self::CommonAuth => Some(DOD_COMMON_AUTH),
            Self::CardAuth => Some(DOD_CARD_AUTH),
            Self::ContentSigning => Some(DOD_CONTENT_SIGNING),
            Self::Device => Some(DOD_DEVICE),
            Self::Unknown(_) => None,
        }
    }

    /// Check if this policy allows authentication operations
    pub fn allows_authentication(&self) -> bool {
        matches!(
            self,
            Self::MediumAssurance
                | Self::MediumHardware
                | Self::HighAssurance
                | Self::PivAuth
                | Self::PivAuthHardware
                | Self::CommonAuth
                | Self::CardAuth
        )
    }

    /// Check if this policy allows digital signatures
    pub fn allows_signing(&self) -> bool {
        matches!(
            self,
            Self::MediumAssurance
                | Self::MediumHardware
                | Self::HighAssurance
                | Self::ContentSigning
        )
    }

    /// Check if this policy requires hardware token
    pub fn requires_hardware(&self) -> bool {
        matches!(
            self,
            Self::MediumHardware | Self::HighAssurance | Self::PivAuthHardware | Self::CardAuth
        )
    }

    /// Check if this policy requires PIN entry
    pub fn requires_pin(&self) -> bool {
        // Card Authentication is specifically designed for no-PIN scenarios
        !matches!(self, Self::CardAuth)
    }

    /// Get the assurance level (1-3, higher is more secure)
    pub fn assurance_level(&self) -> u8 {
        match self {
            Self::HighAssurance => 3,
            Self::MediumHardware | Self::PivAuthHardware => 2,
            Self::MediumAssurance
            | Self::PivAuth
            | Self::CommonAuth
            | Self::CardAuth
            | Self::ContentSigning
            | Self::Device => 1,
            Self::Unknown(_) => 0,
        }
    }

    /// Get a human-readable description of this policy
    pub fn description(&self) -> &'static str {
        match self {
            Self::MediumAssurance => "DoD Medium Assurance (software tokens)",
            Self::MediumHardware => "DoD Medium Hardware (CAC/hardware tokens)",
            Self::HighAssurance => "DoD High Assurance (high-security)",
            Self::PivAuth => "DoD PIV Authentication",
            Self::PivAuthHardware => "DoD PIV Authentication Hardware",
            Self::CommonAuth => "DoD Common Authentication",
            Self::CardAuth => "DoD Card Authentication (no PIN)",
            Self::ContentSigning => "DoD Content/Code Signing",
            Self::Device => "DoD Device Identification",
            Self::Unknown(_) => "Unknown DoD Policy",
        }
    }
}

impl std::fmt::Display for DodCertificatePolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}

/// Parse a DoD policy from an OID
pub fn parse_dod_policy(oid: &ObjectIdentifier) -> Option<DodCertificatePolicy> {
    // Check if the OID is under the DoD policy arc
    let oid_str = oid.to_string();
    if !oid_str.starts_with("2.16.840.1.101.2.1.11") {
        return None;
    }

    // Match known policies
    if *oid == DOD_MEDIUM_ASSURANCE {
        Some(DodCertificatePolicy::MediumAssurance)
    } else if *oid == DOD_MEDIUM_HARDWARE {
        Some(DodCertificatePolicy::MediumHardware)
    } else if *oid == DOD_HIGH_ASSURANCE {
        Some(DodCertificatePolicy::HighAssurance)
    } else if *oid == DOD_PIV_AUTH {
        Some(DodCertificatePolicy::PivAuth)
    } else if *oid == DOD_PIV_AUTH_HARDWARE {
        Some(DodCertificatePolicy::PivAuthHardware)
    } else if *oid == DOD_COMMON_AUTH {
        Some(DodCertificatePolicy::CommonAuth)
    } else if *oid == DOD_CARD_AUTH {
        Some(DodCertificatePolicy::CardAuth)
    } else if *oid == DOD_CONTENT_SIGNING {
        Some(DodCertificatePolicy::ContentSigning)
    } else if *oid == DOD_DEVICE {
        Some(DodCertificatePolicy::Device)
    } else {
        // Unknown DoD policy
        Some(DodCertificatePolicy::Unknown(oid_str))
    }
}

/// Certificate policies extension OID (2.5.29.32)
const CERTIFICATE_POLICIES_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.32");

/// Validate that a certificate contains a DoD policy
///
/// Extracts and validates certificate policies from the certificate's
/// Certificate Policies extension (OID 2.5.29.32).
///
/// # Arguments
///
/// * `cert` - The certificate to validate
///
/// # Returns
///
/// Returns the primary DoD policy found in the certificate, or an error
/// if no DoD policy is present.
///
/// # Example
///
/// ```no_run
/// use usg_est_client::dod::validate_dod_policy;
/// # use x509_cert::Certificate;
///
/// # fn example(cert: &Certificate) -> Result<(), Box<dyn std::error::Error>> {
/// let policy = validate_dod_policy(cert)?;
/// println!("Certificate has DoD policy: {}", policy);
/// # Ok(())
/// # }
/// ```
pub fn validate_dod_policy(cert: &Certificate) -> Result<DodCertificatePolicy> {
    // Get certificate extensions
    let extensions = cert.tbs_certificate.extensions.as_ref().ok_or_else(|| {
        EstError::CertificateValidation("No extensions in certificate".to_string())
    })?;

    // Find Certificate Policies extension
    for ext in extensions.iter() {
        if ext.extn_id == CERTIFICATE_POLICIES_OID {
            // Parse the extension value to extract policy OIDs
            return parse_certificate_policies_extension(&ext.extn_value);
        }
    }

    Err(EstError::CertificateValidation(
        "Certificate does not contain Certificate Policies extension".to_string(),
    ))
}

/// Extract all DoD policies from a certificate
///
/// Returns all DoD policies found in the certificate, not just the primary one.
pub fn extract_dod_policies(cert: &Certificate) -> Vec<DodCertificatePolicy> {
    let extensions = match cert.tbs_certificate.extensions.as_ref() {
        Some(exts) => exts,
        None => return Vec::new(),
    };

    for ext in extensions.iter() {
        if ext.extn_id == CERTIFICATE_POLICIES_OID {
            return parse_all_dod_policies(&ext.extn_value);
        }
    }

    Vec::new()
}

/// Parse Certificate Policies extension to extract DoD policy
fn parse_certificate_policies_extension(
    value: &der::asn1::OctetString,
) -> Result<DodCertificatePolicy> {
    use der::Decode;

    // Certificate Policies is a SEQUENCE OF PolicyInformation
    // PolicyInformation ::= SEQUENCE {
    //     policyIdentifier   CertPolicyId,
    //     policyQualifiers   SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo OPTIONAL
    // }
    // CertPolicyId ::= OBJECT IDENTIFIER

    let bytes = value.as_bytes();

    // Try to parse as a SEQUENCE
    let mut reader = der::SliceReader::new(bytes)
        .map_err(|e| EstError::CertificateParsing(format!("Invalid policies extension: {}", e)))?;

    // Read the outer SEQUENCE
    let policies: der::asn1::SequenceOf<PolicyInformation, 16> =
        der::asn1::SequenceOf::decode(&mut reader).map_err(|e| {
            EstError::CertificateParsing(format!("Failed to parse policies: {}", e))
        })?;

    // Find first DoD policy
    for policy_info in policies.iter() {
        if let Some(dod_policy) = parse_dod_policy(&policy_info.policy_identifier) {
            return Ok(dod_policy);
        }
    }

    Err(EstError::CertificateValidation(
        "No DoD certificate policy found in Certificate Policies extension".to_string(),
    ))
}

/// Parse all DoD policies from extension value
fn parse_all_dod_policies(value: &der::asn1::OctetString) -> Vec<DodCertificatePolicy> {
    use der::Decode;

    let bytes = value.as_bytes();

    let mut reader = match der::SliceReader::new(bytes) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let policies: der::asn1::SequenceOf<PolicyInformation, 16> =
        match der::asn1::SequenceOf::decode(&mut reader) {
            Ok(p) => p,
            Err(_) => return Vec::new(),
        };

    policies
        .iter()
        .filter_map(|policy_info| parse_dod_policy(&policy_info.policy_identifier))
        .collect()
}

/// PolicyInformation structure from RFC 5280
#[derive(Clone, Debug, Eq, PartialEq)]
struct PolicyInformation {
    policy_identifier: ObjectIdentifier,
    // policy_qualifiers omitted - we only need the OID
}

impl<'a> der::Decode<'a> for PolicyInformation {
    fn decode<R: der::Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        reader.sequence(|r| {
            let policy_identifier = ObjectIdentifier::decode(r)?;
            // Skip any remaining content (policy qualifiers)
            while r.peek_header().is_ok() {
                let _ = r.decode::<der::asn1::Any>()?;
            }
            Ok(Self { policy_identifier })
        })
    }
}

impl der::FixedTag for PolicyInformation {
    const TAG: der::Tag = der::Tag::Sequence;
}

/// Check if certificate has any DoD policy
pub fn has_dod_policy(cert: &Certificate) -> bool {
    !extract_dod_policies(cert).is_empty()
}

/// Check if certificate policy allows a specific use
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyUse {
    /// TLS client authentication
    Authentication,
    /// Digital signature (documents, email)
    Signing,
    /// Key encipherment
    Encryption,
    /// EST enrollment
    EstEnrollment,
}

/// Validate that certificate policy allows a specific use
pub fn validate_policy_for_use(cert: &Certificate, use_case: PolicyUse) -> Result<()> {
    let policy = validate_dod_policy(cert)?;

    let allowed = match use_case {
        PolicyUse::Authentication => policy.allows_authentication(),
        PolicyUse::Signing => policy.allows_signing(),
        PolicyUse::Encryption => {
            // Most policies allow encryption
            !matches!(policy, DodCertificatePolicy::CardAuth)
        }
        PolicyUse::EstEnrollment => {
            // EST enrollment requires authentication capability
            policy.allows_authentication()
        }
    };

    if allowed {
        Ok(())
    } else {
        Err(EstError::CertificateValidation(format!(
            "Certificate policy {} does not allow {:?}",
            policy, use_case
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_oids() {
        assert_eq!(DOD_MEDIUM_ASSURANCE.to_string(), "2.16.840.1.101.2.1.11.36");
        assert_eq!(DOD_MEDIUM_HARDWARE.to_string(), "2.16.840.1.101.2.1.11.18");
        assert_eq!(DOD_HIGH_ASSURANCE.to_string(), "2.16.840.1.101.2.1.11.42");
        assert_eq!(DOD_PIV_AUTH.to_string(), "2.16.840.1.101.2.1.11.10");
        assert_eq!(
            DOD_PIV_AUTH_HARDWARE.to_string(),
            "2.16.840.1.101.2.1.11.20"
        );
    }

    #[test]
    fn test_parse_dod_policy() {
        assert_eq!(
            parse_dod_policy(&DOD_MEDIUM_ASSURANCE),
            Some(DodCertificatePolicy::MediumAssurance)
        );
        assert_eq!(
            parse_dod_policy(&DOD_MEDIUM_HARDWARE),
            Some(DodCertificatePolicy::MediumHardware)
        );
        assert_eq!(
            parse_dod_policy(&DOD_HIGH_ASSURANCE),
            Some(DodCertificatePolicy::HighAssurance)
        );

        // Non-DoD policy should return None
        let non_dod_oid = ObjectIdentifier::new_unwrap("1.2.3.4.5");
        assert_eq!(parse_dod_policy(&non_dod_oid), None);
    }

    #[test]
    fn test_policy_allows_authentication() {
        assert!(DodCertificatePolicy::MediumAssurance.allows_authentication());
        assert!(DodCertificatePolicy::MediumHardware.allows_authentication());
        assert!(DodCertificatePolicy::HighAssurance.allows_authentication());
        assert!(DodCertificatePolicy::PivAuth.allows_authentication());
        assert!(DodCertificatePolicy::CardAuth.allows_authentication());
        assert!(!DodCertificatePolicy::ContentSigning.allows_authentication());
        assert!(!DodCertificatePolicy::Device.allows_authentication());
    }

    #[test]
    fn test_policy_allows_signing() {
        assert!(DodCertificatePolicy::MediumAssurance.allows_signing());
        assert!(DodCertificatePolicy::MediumHardware.allows_signing());
        assert!(DodCertificatePolicy::ContentSigning.allows_signing());
        assert!(!DodCertificatePolicy::PivAuth.allows_signing());
        assert!(!DodCertificatePolicy::CardAuth.allows_signing());
    }

    #[test]
    fn test_policy_requires_hardware() {
        assert!(!DodCertificatePolicy::MediumAssurance.requires_hardware());
        assert!(DodCertificatePolicy::MediumHardware.requires_hardware());
        assert!(DodCertificatePolicy::HighAssurance.requires_hardware());
        assert!(DodCertificatePolicy::PivAuthHardware.requires_hardware());
        assert!(DodCertificatePolicy::CardAuth.requires_hardware());
    }

    #[test]
    fn test_policy_requires_pin() {
        assert!(DodCertificatePolicy::MediumAssurance.requires_pin());
        assert!(DodCertificatePolicy::MediumHardware.requires_pin());
        assert!(!DodCertificatePolicy::CardAuth.requires_pin());
    }

    #[test]
    fn test_assurance_levels() {
        assert_eq!(DodCertificatePolicy::HighAssurance.assurance_level(), 3);
        assert_eq!(DodCertificatePolicy::MediumHardware.assurance_level(), 2);
        assert_eq!(DodCertificatePolicy::PivAuthHardware.assurance_level(), 2);
        assert_eq!(DodCertificatePolicy::MediumAssurance.assurance_level(), 1);
        assert_eq!(
            DodCertificatePolicy::Unknown("test".to_string()).assurance_level(),
            0
        );
    }

    #[test]
    fn test_policy_display() {
        assert_eq!(
            DodCertificatePolicy::MediumHardware.to_string(),
            "DoD Medium Hardware (CAC/hardware tokens)"
        );
        assert_eq!(
            DodCertificatePolicy::CardAuth.to_string(),
            "DoD Card Authentication (no PIN)"
        );
    }

    #[test]
    fn test_policy_oid_roundtrip() {
        let policy = DodCertificatePolicy::MediumHardware;
        let oid = policy.oid().unwrap();
        let parsed = parse_dod_policy(&oid).unwrap();
        assert_eq!(policy, parsed);
    }
}
