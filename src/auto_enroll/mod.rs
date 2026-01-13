// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! Auto-enrollment configuration and runtime for Windows machine certificate enrollment.
//!
//! This module provides a complete solution for replacing Microsoft Active Directory
//! Certificate Services (ADCS) auto-enrollment with EST-based certificate management.
//!
//! # Features
//!
//! - TOML-based configuration files
//! - Variable expansion (`${COMPUTERNAME}`, `${USERDNSDOMAIN}`, etc.)
//! - Windows certificate store integration (when on Windows)
//! - Automatic renewal scheduling
//!
//! # Example Configuration
//!
//! ```toml
//! [server]
//! url = "https://est.example.com"
//! timeout_seconds = 60
//!
//! [trust]
//! mode = "explicit"
//! ca_bundle_path = "C:\\ProgramData\\Department of War\\EST\\ca-bundle.pem"
//!
//! [authentication]
//! method = "http_basic"
//! username = "${COMPUTERNAME}"
//!
//! [certificate]
//! common_name = "${COMPUTERNAME}.${USERDNSDOMAIN}"
//! organization = "Example Corp"
//!
//! [renewal]
//! enabled = true
//! threshold_days = 30
//! ```
//!
//! # Usage
//!
//! ```no_run
//! use usg_est_client::auto_enroll::{AutoEnrollConfig, ConfigLoader};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Load configuration from default locations
//! let config = ConfigLoader::new().load()?;
//!
//! // Or load from a specific path
//! let config = ConfigLoader::new()
//!     .with_path("/path/to/config.toml")
//!     .load()?;
//!
//! // Convert to EST client config
//! let est_config = config.to_est_client_config()?;
//! # Ok(())
//! # }
//! ```

mod config;
mod enrollment;
mod expand;
mod loader;

pub use config::*;
pub use enrollment::{check_renewal, needs_enrollment, perform_enrollment, perform_renewal};
pub use expand::expand_variables;
pub use loader::{ConfigLoader, write_default_config};
