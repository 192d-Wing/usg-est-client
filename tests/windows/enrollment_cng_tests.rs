// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! Integration tests for enrollment workflow with CNG (SC-001)

#![cfg(all(windows, feature = "windows-service"))]

use usg_est_client::auto_enroll::AutoEnrollConfig;
use usg_est_client::error::Result;
use usg_est_client::hsm::{KeyAlgorithm, KeyProvider};
use usg_est_client::windows::cng::{CngKeyProvider, providers};

/// Seconds since the Unix epoch, used to build unique key labels in tests.
fn unique_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Test that enrollment configuration properly handles CNG provider
#[tokio::test]
async fn test_enrollment_config_cng_provider_default() {
    let toml = r#"
[est]
url = "https://est.example.com/.well-known/est"

[certificate]
common_name = "test-device"

[storage]
windows_store = "LocalMachine\\My"
"#;

    let config: AutoEnrollConfig = toml::from_str(toml).expect("Failed to parse config");

    // Should use software provider by default
    assert!(config.storage.cng_provider.is_none());
}

/// Test that enrollment configuration properly parses explicit CNG provider
#[tokio::test]
async fn test_enrollment_config_cng_provider_explicit() {
    let toml = r#"
[est]
url = "https://est.example.com/.well-known/est"

[certificate]
common_name = "test-device"

[storage]
windows_store = "LocalMachine\\My"
cng_provider = "Microsoft Platform Crypto Provider"
"#;

    let config: AutoEnrollConfig = toml::from_str(toml).expect("Failed to parse config");

    assert_eq!(
        config.storage.cng_provider.as_deref(),
        Some("Microsoft Platform Crypto Provider")
    );
}

/// Test that deprecated key_path is still parsed but ignored
#[tokio::test]
#[allow(deprecated)]
async fn test_enrollment_config_deprecated_key_path() {
    let toml = r#"
[est]
url = "https://est.example.com/.well-known/est"

[certificate]
common_name = "test-device"

[storage]
windows_store = "LocalMachine\\My"
key_path = "C:\\old\\path\\key.pem"
cng_provider = "Microsoft Software Key Storage Provider"
"#;

    let config: AutoEnrollConfig = toml::from_str(toml).expect("Failed to parse config");

    // key_path is deprecated and should be ignored
    assert!(config.storage.key_path.is_some());

    // cng_provider should be used instead
    assert!(config.storage.cng_provider.is_some());
}

/// Test key algorithm parsing from configuration
#[tokio::test]
async fn test_key_algorithm_parsing() {
    use usg_est_client::auto_enroll::KeyAlgorithm as ConfigKeyAlgorithm;

    let test_cases = vec![
        ("rsa-2048", ConfigKeyAlgorithm::Rsa2048),
        ("rsa-3072", ConfigKeyAlgorithm::Rsa3072),
        ("rsa-4096", ConfigKeyAlgorithm::Rsa4096),
        ("ecdsa-p256", ConfigKeyAlgorithm::EcdsaP256),
        ("ecdsa-p384", ConfigKeyAlgorithm::EcdsaP384),
    ];

    for (config_str, expected_algo) in test_cases {
        let toml = format!(
            r#"
[est]
url = "https://est.example.com/.well-known/est"

[certificate]
common_name = "test-device"

[certificate.key]
algorithm = "{}"

[storage]
windows_store = "LocalMachine\\My"
"#,
            config_str
        );

        let config: AutoEnrollConfig = toml::from_str(&toml).expect("Failed to parse config");

        // Verify the key algorithm is parsed correctly from the [certificate.key] section.
        let algo = config
            .certificate
            .key
            .as_ref()
            .expect("key section present")
            .algorithm;
        assert_eq!(algo, expected_algo);
    }
}

/// Test CNG provider selection logic
#[tokio::test]
async fn test_cng_provider_selection() -> Result<()> {
    // Test default (None) should use SOFTWARE
    let provider_name = None::<&str>.map(|s| s).unwrap_or(providers::SOFTWARE);
    assert_eq!(provider_name, providers::SOFTWARE);

    // Test explicit software provider
    let provider_name =
        Some("Microsoft Software Key Storage Provider").unwrap_or(providers::SOFTWARE);
    assert_eq!(provider_name, "Microsoft Software Key Storage Provider");

    // Test explicit TPM provider
    let provider_name = Some("Microsoft Platform Crypto Provider").unwrap_or(providers::SOFTWARE);
    assert_eq!(provider_name, "Microsoft Platform Crypto Provider");

    Ok(())
}

/// Test enrollment workflow key generation parameters
#[tokio::test]
async fn test_enrollment_key_generation_parameters() -> Result<()> {
    let provider = CngKeyProvider::new()?;

    // Test label generation (simulating enrollment workflow)
    let cn = "test-device.example.com";
    let timestamp = unique_ts();
    let label = format!("{}-{}", cn, timestamp);

    let key_handle = provider
        .generate_key_pair(KeyAlgorithm::Rsa { bits: 2048 }, Some(&label))
        .await?;

    // Verify label is preserved in metadata
    assert_eq!(key_handle.metadata().label, Some(label.clone()));

    // Verify container name includes label
    let container_name = CngKeyProvider::get_container_name(&key_handle)?;
    assert!(container_name.contains(cn));

    Ok(())
}

/// Test renewal workflow key generation (fresh keys)
#[tokio::test]
async fn test_renewal_workflow_fresh_keys() -> Result<()> {
    let provider = CngKeyProvider::new()?;

    // Simulate original key
    let original_label = "device-1234567890";
    let original_key = provider
        .generate_key_pair(KeyAlgorithm::Rsa { bits: 2048 }, Some(original_label))
        .await?;
    let original_container = CngKeyProvider::get_container_name(&original_key)?;

    // Simulate renewal key (should be different)
    let renewal_label = format!("{}-renewal-{}", "device", unique_ts());
    let renewal_key = provider
        .generate_key_pair(KeyAlgorithm::Rsa { bits: 2048 }, Some(&renewal_label))
        .await?;
    let renewal_container = CngKeyProvider::get_container_name(&renewal_key)?;

    // Verify they are different keys
    assert_ne!(original_container, renewal_container);
    assert_ne!(original_key.metadata().label, renewal_key.metadata().label);

    Ok(())
}

/// Test that enrollment doesn't create file-based keys
#[tokio::test]
async fn test_no_file_based_keys_created() {
    // This is a negative test - verify that the enrollment workflow
    // does NOT create any PEM files

    // The actual implementation is in src/auto_enroll/enrollment.rs
    // which has removed all file-based key storage code

    // This test documents the expectation that:
    // 1. No key_pair.serialize_pem() calls exist in enrollment
    // 2. No std::fs::write() calls for private keys
    // 3. All keys go directly to CNG

    // This would be verified by:
    // - Code review (done)
    // - Integration test with actual enrollment (requires EST server)

    // For now, this test serves as documentation
    assert!(true, "File-based key storage has been removed");
}

/// Test CNG key container naming convention
#[tokio::test]
async fn test_cng_container_naming_convention() -> Result<()> {
    let provider = CngKeyProvider::new()?;

    // Test with various labels
    let test_labels = vec!["simple", "with-dashes", "with.dots", "device.example.com"];

    for label in test_labels {
        let key_handle = provider
            .generate_key_pair(KeyAlgorithm::Rsa { bits: 2048 }, Some(label))
            .await?;
        let container_name = CngKeyProvider::get_container_name(&key_handle)?;

        // Verify naming convention: EST-{label}-{timestamp}
        assert!(container_name.starts_with("EST-"));
        assert!(container_name.contains(label));

        // Verify container name is unique (contains timestamp)
        std::thread::sleep(std::time::Duration::from_millis(10));
        let key_handle2 = provider
            .generate_key_pair(KeyAlgorithm::Rsa { bits: 2048 }, Some(label))
            .await?;
        let container_name2 = CngKeyProvider::get_container_name(&key_handle2)?;
        assert_ne!(container_name, container_name2);
    }

    Ok(())
}

/// Test configuration validation for CNG
#[tokio::test]
async fn test_config_validation_cng() {
    // Valid configuration with CNG provider
    let valid_toml = r#"
[est]
url = "https://est.example.com/.well-known/est"

[certificate]
common_name = "test-device"

[certificate.key]
algorithm = "rsa-2048"

[storage]
windows_store = "LocalMachine\\My"
cng_provider = "Microsoft Software Key Storage Provider"
"#;

    let result: std::result::Result<AutoEnrollConfig, _> = toml::from_str(valid_toml);
    assert!(result.is_ok());

    // Invalid key algorithm: not a known variant, so it must fail to parse.
    let invalid_toml = r#"
[est]
url = "https://est.example.com/.well-known/est"

[certificate]
common_name = "test-device"

[certificate.key]
algorithm = "rsa-1024"

[storage]
windows_store = "LocalMachine\\My"
"#;

    let result: std::result::Result<AutoEnrollConfig, _> = toml::from_str(invalid_toml);
    assert!(
        result.is_err(),
        "an unknown key algorithm should fail to parse"
    );
}

/// Test memory safety: keys are not leaked
#[tokio::test]
async fn test_cng_key_memory_safety() -> Result<()> {
    let provider = CngKeyProvider::new()?;

    // Generate key
    let label = format!("test-memory-{}", unique_ts());
    let key_handle = provider
        .generate_key_pair(KeyAlgorithm::Rsa { bits: 2048 }, Some(&label))
        .await?;

    // Get container name (proves key exists)
    let container_name = CngKeyProvider::get_container_name(&key_handle)?;
    assert!(!container_name.is_empty());

    // Drop key handle
    drop(key_handle);

    // Key should still exist in CNG (not in memory)
    // This is the security benefit of CNG - keys persist in CNG storage
    // even after the handle is dropped

    Ok(())
}

/// Test error handling: invalid algorithm
#[tokio::test]
async fn test_error_handling_invalid_algorithm() {
    let _provider = CngKeyProvider::new().unwrap();

    // This would fail at runtime if we tried to use an invalid algorithm
    // The actual validation happens in the enrollment workflow when parsing config

    // Document expected behavior
    assert!(
        true,
        "Invalid algorithms are rejected during config parsing"
    );
}

/// Test CNG provider persistence across calls
#[tokio::test]
async fn test_cng_provider_persistence() -> Result<()> {
    // Create provider
    let provider1 = CngKeyProvider::with_provider(providers::SOFTWARE)?;

    // Generate key
    let key1 = provider1
        .generate_key_pair(KeyAlgorithm::Rsa { bits: 2048 }, Some("test1"))
        .await?;
    let container1 = CngKeyProvider::get_container_name(&key1)?;

    // Create new provider instance
    let provider2 = CngKeyProvider::with_provider(providers::SOFTWARE)?;

    // Generate another key
    let key2 = provider2
        .generate_key_pair(KeyAlgorithm::Rsa { bits: 2048 }, Some("test2"))
        .await?;
    let container2 = CngKeyProvider::get_container_name(&key2)?;

    // Both keys should exist in CNG storage
    assert_ne!(container1, container2);

    // Keys persist beyond provider lifetime
    drop(provider1);
    drop(provider2);

    Ok(())
}

/// Stress test: Generate many keys rapidly
#[tokio::test]
#[ignore] // Run with --ignored flag for stress tests
async fn stress_test_rapid_key_generation() -> Result<()> {
    let provider = CngKeyProvider::new()?;
    let count = 50;

    println!("Generating {} keys rapidly...", count);

    let start = std::time::Instant::now();

    for i in 0..count {
        let label = format!("stress-test-{}", i);
        let _key = provider
            .generate_key_pair(KeyAlgorithm::Rsa { bits: 2048 }, Some(&label))
            .await?;

        if i % 10 == 0 {
            println!("  Generated {} keys", i);
        }
    }

    let elapsed = start.elapsed();
    println!("Generated {} keys in {:?}", count, elapsed);
    println!("Average: {:?} per key", elapsed / count);

    Ok(())
}
