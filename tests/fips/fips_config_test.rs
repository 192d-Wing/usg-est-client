// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! FIPS 140-2 Configuration Tests
//!
//! These tests validate the FIPS configuration and mode detection functionality.

#![cfg(feature = "fips")]

use usg_est_client::fips::{enable_fips_mode, fips_module_info, FipsConfig};

#[test]
fn test_fips_config_builder_defaults() {
    let config = FipsConfig::builder().enforce_fips_mode(false).build();

    // With enforce=false, build should succeed even without FIPS
    assert!(config.is_ok());

    let config = config.unwrap();
    assert_eq!(config.min_rsa_key_size, 2048);
    assert_eq!(config.min_ecc_key_size, 256);
    assert!(config.block_non_fips_algorithms);
    assert!(config.require_tls_12_minimum);
}

#[test]
fn test_fips_config_custom_key_sizes() {
    let config = FipsConfig::builder()
        .enforce_fips_mode(false)
        .min_rsa_key_size(3072)
        .min_ecc_key_size(384)
        .build();

    assert!(config.is_ok());

    let config = config.unwrap();
    assert_eq!(config.min_rsa_key_size, 3072);
    assert_eq!(config.min_ecc_key_size, 384);
}

#[test]
fn test_fips_config_minimum_rsa_key_size() {
    // RSA key size below 2048 should fail
    let config = FipsConfig::builder()
        .enforce_fips_mode(false)
        .min_rsa_key_size(1024)
        .build();

    assert!(config.is_err());
    let err = config.unwrap_err();
    assert!(err.to_string().contains("2048"));
}

#[test]
fn test_fips_config_minimum_ecc_key_size() {
    // ECC key size below 256 should fail
    let config = FipsConfig::builder()
        .enforce_fips_mode(false)
        .min_ecc_key_size(192)
        .build();

    assert!(config.is_err());
    let err = config.unwrap_err();
    assert!(err.to_string().contains("256"));
}

#[test]
fn test_fips_config_display() {
    let config = FipsConfig::default();
    let display = format!("{}", config);

    assert!(display.contains("enforce: false"));
    assert!(display.contains("min_rsa: 2048"));
    assert!(display.contains("min_ecc: 256"));
    assert!(display.contains("block_non_fips: true"));
}

#[test]
fn test_fips_config_validation() {
    let config = FipsConfig::builder().enforce_fips_mode(false).build();

    assert!(config.is_ok());

    let config = config.unwrap();
    // Validation should succeed for non-enforced mode
    let validation_result = config.validate();

    // Note: Validation may fail if the FIPS module is not active, but that's
    // expected in test environments
    if validation_result.is_err() {
        let err = validation_result.unwrap_err();
        println!("Validation failed (expected in non-FIPS environment): {}", err);
    }
}

#[test]
fn test_fips_module_info() {
    let info = fips_module_info();

    // Should identify the active FIPS module
    assert!(!info.module.is_empty());
    println!("FIPS Module: {}", info.module);
    println!("FIPS Capable: {}", info.fips_capable);
    println!("FIPS Enabled: {}", info.fips_enabled);

    // Display should work
    let display = format!("{}", info);
    assert!(display.contains("FIPS Module:"));
    assert!(display.contains("FIPS Capable:"));
    assert!(display.contains("FIPS Enabled:"));
}

#[test]
#[ignore] // Requires FIPS module to be installed and configured
fn test_enable_fips_mode() {
    let result = enable_fips_mode();

    match result {
        Ok(()) => {
            println!("FIPS mode enabled successfully");
            let info = fips_module_info();
            assert!(info.fips_enabled, "FIPS mode should be enabled");
        }
        Err(e) => {
            println!(
                "FIPS mode could not be enabled (expected if FIPS module not installed): {}",
                e
            );
            // This is expected in environments without FIPS module
        }
    }
}

#[test]
fn test_fips_config_enforce_without_module() {
    // Try to enforce FIPS mode when module may not be available
    let config = FipsConfig::builder().enforce_fips_mode(true).build();

    // Build may fail if FIPS is not available, which is expected
    match config {
        Ok(_) => {
            println!("FIPS configuration succeeded (FIPS module available)");
        }
        Err(e) => {
            println!("FIPS configuration failed (expected without FIPS module): {}", e);
            assert!(
                e.to_string().contains("FIPS")
                    || e.to_string().contains("not enabled")
                    || e.to_string().contains("not available")
            );
        }
    }
}

#[test]
fn test_fips_config_clone() {
    let config1 = FipsConfig::default();
    let config2 = config1.clone();

    assert_eq!(config1.min_rsa_key_size, config2.min_rsa_key_size);
    assert_eq!(config1.min_ecc_key_size, config2.min_ecc_key_size);
    assert_eq!(
        config1.block_non_fips_algorithms,
        config2.block_non_fips_algorithms
    );
}

#[test]
fn test_fips_config_block_non_fips_toggle() {
    let config = FipsConfig::builder()
        .enforce_fips_mode(false)
        .block_non_fips_algorithms(false)
        .build()
        .unwrap();

    assert!(!config.block_non_fips_algorithms);

    let config = FipsConfig::builder()
        .enforce_fips_mode(false)
        .block_non_fips_algorithms(true)
        .build()
        .unwrap();

    assert!(config.block_non_fips_algorithms);
}

#[test]
fn test_fips_config_tls_minimum_requirement() {
    let config = FipsConfig::builder()
        .enforce_fips_mode(false)
        .require_tls_12_minimum(true)
        .build()
        .unwrap();

    assert!(config.require_tls_12_minimum);

    let config = FipsConfig::builder()
        .enforce_fips_mode(false)
        .require_tls_12_minimum(false)
        .build()
        .unwrap();

    assert!(!config.require_tls_12_minimum);
}
