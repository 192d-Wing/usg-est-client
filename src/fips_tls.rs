// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! FIPS-validated TLS via the aws-lc-rs FIPS cryptographic module.
//!
//! This is Phase 1 of migrating the crate onto FIPS-validated cryptography.
//! It wires rustls to use the aws-lc-rs **FIPS** module (built via
//! `aws-lc-rs/fips` + `rustls/fips`) as the process-wide TLS crypto provider.
//!
//! # Scope
//!
//! This module covers **TLS transport only**. The EST PKI operations (key
//! generation, CSR signing, certificate-signature validation, EnvelopedData)
//! still run on non-validated implementations until the later FIPS phases
//! route them through aws-lc-rs (Linux/macOS) or Windows CNG.
//!
//! # Usage
//!
//! Call [`install_fips_provider`] once at process startup, before constructing
//! any EST client, then assert with [`is_fips_active`]:
//!
//! ```no_run,ignore
//! usg_est_client::fips_tls::install_fips_provider()?;
//! assert!(usg_est_client::fips_tls::is_fips_active());
//! ```
//!
//! # Platform support
//!
//! The aws-lc-rs FIPS module (`aws-lc-fips-sys`) builds on FIPS-supported
//! targets (Linux x86_64/aarch64). On Windows, use the CNG FIPS module instead;
//! this module is not available there.

use crate::error::{EstError, Result};

/// Install the aws-lc-rs FIPS [`CryptoProvider`](rustls::crypto::CryptoProvider)
/// as the process-wide rustls default.
///
/// Both `reqwest`'s bundled rustls and this crate's own rustls configuration
/// pick up the process default, so installing it here makes all EST TLS use the
/// FIPS module.
///
/// Call once, early, before any TLS client is built. If a default provider is
/// already installed (e.g. this was called twice), the second call is a no-op
/// success. Returns an error if the compiled-in provider is not actually in FIPS
/// mode — a hard fail-closed so a misconfigured build can't silently fall back to
/// non-validated crypto.
pub fn install_fips_provider() -> Result<()> {
    // Under the `rustls/fips` + `aws-lc-rs/fips` features, the aws-lc-rs default
    // provider is backed by the FIPS module.
    let provider = rustls::crypto::aws_lc_rs::default_provider();

    if !provider.fips() {
        return Err(EstError::platform(
            "aws-lc-rs crypto provider is not in FIPS mode; \
             the build is not linked against the FIPS module",
        ));
    }

    // `install_default` returns Err if a default is already set; that is fine for
    // an idempotent install, as long as the already-installed provider is FIPS.
    if provider.install_default().is_err() && !is_fips_active() {
        return Err(EstError::platform(
            "a non-FIPS rustls crypto provider was already installed as the default",
        ));
    }

    Ok(())
}

/// Returns `true` if the process-wide default rustls crypto provider is the
/// FIPS-validated module.
pub fn is_fips_active() -> bool {
    rustls::crypto::CryptoProvider::get_default()
        .map(|p| p.fips())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fips_provider_installs_and_is_active() {
        // The aws-lc-rs FIPS provider must report FIPS mode and install cleanly.
        install_fips_provider().expect("FIPS provider should install");
        assert!(
            is_fips_active(),
            "default provider must be FIPS after install"
        );
    }
}
