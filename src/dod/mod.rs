// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! Department of Defense (DoD) PKI Integration
//!
//! This module provides integration with the DoD Public Key Infrastructure (PKI),
//! including DoD Root CA trust anchors, certificate policy validation, and
//! CAC/PIV smart card support for DoD deployments.
//!
//! # Overview
//!
//! The DoD PKI is the primary PKI for U.S. Department of Defense organizations.
//! It provides identity certificates, encryption certificates, and digital
//! signature certificates to DoD personnel, systems, and services.
//!
//! ## DoD Root CAs
//!
//! As of 2025, the following DoD Root CAs are active:
//!
//! - **DoD Root CA 3**: Valid until December 30, 2029
//! - **DoD Root CA 4**: Valid until July 25, 2032
//! - **DoD Root CA 5**: Valid until June 14, 2041
//! - **DoD Root CA 6**: Newest root CA (issued 2024)
//!
//! ## Certificate Policies
//!
//! DoD certificates assert one or more certificate policy OIDs under the arc:
//! **2.16.840.1.101.2.1.11**
//!
//! Common policies include:
//! - Medium Assurance (2.16.840.1.101.2.1.11.36)
//! - Medium Hardware (2.16.840.1.101.2.1.11.18)
//! - High Assurance (2.16.840.1.101.2.1.11.42)
//! - PIV Authentication (2.16.840.1.101.2.1.11.10, 2.16.840.1.101.2.1.11.20)
//!
//! ## CAC/PIV Smart Cards
//!
//! Common Access Cards (CAC) and Personal Identity Verification (PIV) cards
//! contain multiple certificates in separate slots:
//!
//! - **Slot 9A (PIV Authentication)**: System login, VPN, EST client auth
//! - **Slot 9C (Digital Signature)**: Document/email signing, CSR signing
//! - **Slot 9D (Key Management)**: Encryption/decryption
//! - **Slot 9E (Card Authentication)**: Physical access (no PIN required)
//!
//! # Example
//!
//! ```no_run
//! use usg_est_client::{EstClient, EstClientConfig};
//! use usg_est_client::dod::load_dod_root_cas;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create EST client with DoD PKI preset
//! let config = EstClientConfig::builder()
//!     .server_url("https://est.example.mil")?
//!     .dod_pki_preset()? // Auto-loads DoD Root CAs
//!     .build()?;
//!
//! let client = EstClient::new(config).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # References
//!
//! - [DoD PKI Management](https://crl.gds.disa.mil/)
//! - [DoD Cyber Exchange PKI](https://public.cyber.mil/pki-pke/)
//! - [DoD Certificate Policy](https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/pdf/Unclass-DoD_X.509_Certificate_Policy_v10.7_Jun_3_21.pdf)

#[cfg(feature = "dod-pki")]
pub mod roots;

#[cfg(feature = "dod-pki")]
pub mod policies;

#[cfg(all(feature = "dod-pki", feature = "pkcs11"))]
pub mod cac;

#[cfg(feature = "dod-pki")]
pub mod validation;

// Re-export commonly used types
#[cfg(feature = "dod-pki")]
pub use roots::{DodRootCa, load_dod_root_cas, validate_dod_chain};

#[cfg(feature = "dod-pki")]
pub use policies::{
    DOD_CARD_AUTH, DOD_COMMON_AUTH, DOD_CONTENT_SIGNING, DOD_DEVICE, DOD_HIGH_ASSURANCE,
    DOD_MEDIUM_ASSURANCE, DOD_MEDIUM_HARDWARE, DOD_PIV_AUTH, DOD_PIV_AUTH_HARDWARE, DOD_POLICY_ARC,
    DodCertificatePolicy, PolicyUse, extract_dod_policies, has_dod_policy, parse_dod_policy,
    validate_dod_policy, validate_policy_for_use,
};

#[cfg(all(feature = "dod-pki", feature = "pkcs11"))]
pub use cac::{
    CacCertificate, CacReader, PivSlot, enumerate_cac_certificates,
    enumerate_cac_certificates_with_middleware, find_est_certificate, list_readers,
};

#[cfg(feature = "dod-pki")]
pub use validation::{
    DodChainValidator, ValidationOptions, ValidationOptionsBuilder, ValidationResult,
    is_dod_certificate, validate_dod_certificate,
};
