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

//! # usg-est-client
//!
//! A Rust implementation of an RFC 7030 compliant EST (Enrollment over Secure Transport) client.
//!
//! EST is a protocol for obtaining X.509 certificates over HTTPS. This library provides
//! a fully-featured EST client supporting all mandatory and optional operations defined
//! in RFC 7030.
//!
//! ## Features
//!
//! - **Async-first design** using Tokio
//! - **All EST operations**: cacerts, simpleenroll, simplereenroll, csrattrs, serverkeygen, fullcmc
//! - **TLS client authentication** with certificate-based auth
//! - **HTTP Basic auth** fallback
//! - **Bootstrap/TOFU mode** for initial CA discovery
//! - **CSR generation helpers** (feature-gated)
//!
//! ## Quick Start
//!
//! ```no_run
//! use usg_est_client::{EstClient, EstClientConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create client configuration
//!     let config = EstClientConfig::builder()
//!         .server_url("https://est.example.com")?
//!         .build()?;
//!
//!     // Create EST client
//!     let client = EstClient::new(config).await?;
//!
//!     // Get CA certificates
//!     let ca_certs = client.get_ca_certs().await?;
//!     println!("Retrieved {} CA certificates", ca_certs.len());
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Certificate Enrollment
//!
//! ```no_run
//! use usg_est_client::{EstClient, EstClientConfig, EnrollmentResponse};
//! # #[cfg(feature = "csr-gen")]
//! use usg_est_client::csr::CsrBuilder;
//!
//! # #[cfg(feature = "csr-gen")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = EstClientConfig::builder()
//!     .server_url("https://est.example.com")?
//!     .http_auth("username", "password")
//!     .build()?;
//!
//! let client = EstClient::new(config).await?;
//!
//! // Generate a CSR
//! let (csr_der, key_pair) = CsrBuilder::new()
//!     .common_name("device.example.com")
//!     .organization("Example Corp")
//!     .san_dns("device.example.com")
//!     .build()?;
//!
//! // Enroll for a certificate
//! match client.simple_enroll(&csr_der).await? {
//!     EnrollmentResponse::Issued { certificate } => {
//!         println!("Certificate issued!");
//!     }
//!     EnrollmentResponse::Pending { retry_after } => {
//!         println!("Enrollment pending, retry in {} seconds", retry_after);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Bootstrap Mode (TOFU)
//!
//! For initial CA certificate discovery without pre-existing trust:
//!
//! ```no_run
//! use usg_est_client::bootstrap::BootstrapClient;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let bootstrap = BootstrapClient::new("https://est.example.com")?;
//!
//! // Fetch CA certificates (without TLS verification)
//! let (ca_certs, fingerprints) = bootstrap.fetch_ca_certs().await?;
//!
//! // Display fingerprints for out-of-band verification
//! for (i, fp) in fingerprints.iter().enumerate() {
//!     println!("CA {} fingerprint: {}", i, BootstrapClient::format_fingerprint(fp));
//! }
//!
//! // After user verification, use the CA certs to configure the main client
//! # Ok(())
//! # }
//! ```
//!
//! ## Cargo Features
//!
//! - `csr-gen` (default): Enables CSR generation helpers using `rcgen`
//!
//! ## RFC 7030 Compliance
//!
//! This library implements:
//! - Section 4.1: Distribution of CA Certificates (`get_ca_certs`)
//! - Section 4.2: Simple Enrollment (`simple_enroll`, `simple_reenroll`)
//! - Section 4.3: Full CMC (`full_cmc`)
//! - Section 4.4: Server-Side Key Generation (`server_keygen`)
//! - Section 4.5: CSR Attributes (`get_csr_attributes`)
//! - Section 4.1.1: Bootstrap Distribution (via `bootstrap` module)
//!
//! TLS requirements per Section 3.3:
//! - TLS 1.2 or later required
//! - Client certificate authentication supported
//! - HTTP Basic auth supported as fallback

#![warn(missing_docs)]
#![warn(rustdoc::missing_crate_level_docs)]

pub mod bootstrap;
pub mod client;
pub mod config;
pub mod error;
pub mod operations;
pub mod tls;
pub mod types;

#[cfg(feature = "csr-gen")]
pub mod csr;

#[cfg(feature = "hsm")]
pub mod hsm;

#[cfg(feature = "fips")]
pub mod fips;

#[cfg(feature = "dod-pki")]
pub mod dod;

#[cfg(feature = "renewal")]
pub mod renewal;

#[cfg(feature = "validation")]
pub mod validation;

#[cfg(feature = "metrics")]
pub mod metrics;

#[cfg(feature = "revocation")]
pub mod revocation;

#[cfg(feature = "enveloped")]
pub mod enveloped;

#[cfg(feature = "auto-enroll")]
pub mod auto_enroll;

#[cfg(all(windows, feature = "windows"))]
pub mod windows;

#[cfg(feature = "windows-service")]
pub mod logging;

#[cfg(feature = "siem")]
pub mod siem;

// Re-export main types at crate root for convenience
pub use client::EstClient;
#[cfg(feature = "validation")]
pub use config::CertificateValidationConfig;
pub use config::{
    BootstrapConfig, ClientIdentity, EstClientConfig, EstClientConfigBuilder, HttpAuth,
    TrustAnchors,
};
pub use error::{EstError, Result};
pub use types::{
    CaCertificates, CmcRequest, CmcResponse, CsrAttributes, EnrollmentResponse,
    ServerKeygenResponse,
};

// Re-export x509_cert::Certificate for convenience
pub use x509_cert::Certificate;

/// Library version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// User-Agent string for HTTP requests.
pub const USER_AGENT: &str = concat!("usg-est-client/", env!("CARGO_PKG_VERSION"));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_user_agent() {
        assert!(USER_AGENT.starts_with("usg-est-client/"));
    }
}
