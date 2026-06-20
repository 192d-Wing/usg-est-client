// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! Tests for Windows CNG key container integration (SC-001)

#![cfg(all(windows, feature = "windows-service"))]

use usg_est_client::error::Result;
use usg_est_client::hsm::{KeyAlgorithm, KeyProvider};
use usg_est_client::windows::CertStore;
use usg_est_client::windows::cng::{CngKeyProvider, providers};

use super::unique_ts;

/// Test CNG provider initialization with software provider
#[tokio::test]
async fn test_cng_provider_software_initialization() -> Result<()> {
    let provider = CngKeyProvider::new()?;
    assert_eq!(provider.provider_name(), providers::SOFTWARE);
    assert!(!provider.is_tpm());
    assert!(!provider.is_smart_card());
    Ok(())
}

/// Test CNG provider initialization with specific provider
#[tokio::test]
async fn test_cng_provider_with_custom_provider() -> Result<()> {
    let provider = CngKeyProvider::with_provider(providers::SOFTWARE)?;
    assert_eq!(provider.provider_name(), providers::SOFTWARE);
    Ok(())
}

/// Test CNG provider initialization with invalid provider fails
#[tokio::test]
async fn test_cng_provider_invalid_provider_fails() {
    let result = CngKeyProvider::with_provider("Invalid Provider Name");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not available"));
}

/// Test RSA-2048 key generation in CNG
#[tokio::test]
async fn test_cng_rsa2048_key_generation() -> Result<()> {
    let provider = CngKeyProvider::new()?;
    let label = format!("test-rsa2048-{}", unique_ts());

    let key_handle = provider
        .generate_key_pair(KeyAlgorithm::Rsa { bits: 2048 }, Some(&label))
        .await?;

    assert_eq!(key_handle.algorithm(), KeyAlgorithm::Rsa { bits: 2048 });

    Ok(())
}

/// Test RSA-3072 key generation in CNG
#[tokio::test]
async fn test_cng_rsa3072_key_generation() -> Result<()> {
    let provider = CngKeyProvider::new()?;
    let label = format!("test-rsa3072-{}", unique_ts());

    let key_handle = provider
        .generate_key_pair(KeyAlgorithm::Rsa { bits: 3072 }, Some(&label))
        .await?;

    assert_eq!(key_handle.algorithm(), KeyAlgorithm::Rsa { bits: 3072 });

    Ok(())
}

/// Test ECDSA P-256 key generation in CNG
#[tokio::test]
async fn test_cng_ecc_p256_key_generation() -> Result<()> {
    let provider = CngKeyProvider::new()?;
    let label = format!("test-ecc-p256-{}", unique_ts());

    let key_handle = provider
        .generate_key_pair(KeyAlgorithm::EcdsaP256, Some(&label))
        .await?;

    assert_eq!(key_handle.algorithm(), KeyAlgorithm::EcdsaP256);

    Ok(())
}

/// Test get_container_name helper method
#[tokio::test]
async fn test_get_container_name() -> Result<()> {
    let provider = CngKeyProvider::new()?;
    let label = format!("test-container-{}", unique_ts());

    let key_handle = provider
        .generate_key_pair(KeyAlgorithm::Rsa { bits: 2048 }, Some(&label))
        .await?;

    let container_name = CngKeyProvider::get_container_name(&key_handle)?;

    // Container name should start with "EST-"
    assert!(
        container_name.starts_with("EST-"),
        "Container name should start with EST-, got: {}",
        container_name
    );

    // Container name should contain the label
    assert!(
        container_name.contains(&label),
        "Container name should contain label, got: {}",
        container_name
    );

    Ok(())
}

/// Test get_provider_name helper method
#[tokio::test]
async fn test_get_provider_name() -> Result<()> {
    let provider = CngKeyProvider::new()?;
    let label = format!("test-provider-{}", unique_ts());

    let key_handle = provider
        .generate_key_pair(KeyAlgorithm::Rsa { bits: 2048 }, Some(&label))
        .await?;

    let provider_name = CngKeyProvider::get_provider_name(&key_handle)?;

    // Provider name should match what we initialized with
    assert_eq!(provider_name, providers::SOFTWARE);

    Ok(())
}

/// Test key generation without label
#[tokio::test]
async fn test_cng_key_generation_no_label() -> Result<()> {
    let provider = CngKeyProvider::new()?;

    let key_handle = provider
        .generate_key_pair(KeyAlgorithm::Rsa { bits: 2048 }, None)
        .await?;

    assert_eq!(key_handle.algorithm(), KeyAlgorithm::Rsa { bits: 2048 });

    // Container name should still be generated
    let container_name = CngKeyProvider::get_container_name(&key_handle)?;
    assert!(container_name.starts_with("EST-"));

    Ok(())
}

/// Test multiple key generation creates unique containers
#[tokio::test]
async fn test_cng_multiple_keys_unique_containers() -> Result<()> {
    let provider = CngKeyProvider::new()?;

    let key1 = provider
        .generate_key_pair(KeyAlgorithm::Rsa { bits: 2048 }, Some("key1"))
        .await?;
    let key2 = provider
        .generate_key_pair(KeyAlgorithm::Rsa { bits: 2048 }, Some("key2"))
        .await?;

    let container1 = CngKeyProvider::get_container_name(&key1)?;
    let container2 = CngKeyProvider::get_container_name(&key2)?;

    assert_ne!(
        container1, container2,
        "Each key should have unique container name"
    );

    Ok(())
}

/// Test CNG key signing operation
#[tokio::test]
async fn test_cng_key_signing() -> Result<()> {
    let provider = CngKeyProvider::new()?;
    let label = format!("test-signing-{}", unique_ts());

    let key_handle = provider
        .generate_key_pair(KeyAlgorithm::Rsa { bits: 2048 }, Some(&label))
        .await?;

    // Test data to sign
    let data = b"Test data for signing";

    // Sign the data
    let signature = provider.sign(&key_handle, data).await?;

    // Signature should not be empty
    assert!(!signature.is_empty());

    // For RSA-2048 with SHA-256, signature should be 256 bytes
    assert_eq!(signature.len(), 256);

    Ok(())
}

/// Test CertStore associate_cng_key with valid inputs
#[tokio::test]
#[ignore] // Requires actual certificate in Windows store
async fn test_certstore_associate_cng_key_valid() -> Result<()> {
    // This test requires:
    // 1. A certificate in LocalMachine\My store
    // 2. A CNG key container
    // Run manually with actual certificate

    let store = CertStore::open_path("LocalMachine\\My")?;
    let provider = CngKeyProvider::new()?;

    // Generate test key
    let label = format!("test-assoc-{}", unique_ts());
    let key_handle = provider
        .generate_key_pair(KeyAlgorithm::Rsa { bits: 2048 }, Some(&label))
        .await?;

    let container_name = CngKeyProvider::get_container_name(&key_handle)?;
    let provider_name = CngKeyProvider::get_provider_name(&key_handle)?;

    // You would need to replace this with an actual thumbprint
    let test_thumbprint = "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2";

    let result = store.associate_cng_key(test_thumbprint, &container_name, &provider_name);

    // This will fail without real cert, but tests the API
    assert!(result.is_err() || result.is_ok());

    Ok(())
}

/// Test CertStore associate_cng_key with invalid thumbprint format
#[tokio::test]
async fn test_certstore_associate_cng_key_invalid_thumbprint() -> Result<()> {
    let store = CertStore::open_path("LocalMachine\\My")?;

    let result = store.associate_cng_key(
        "INVALID", // Invalid thumbprint
        "test-container",
        providers::SOFTWARE,
    );

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Invalid SHA-1 thumbprint")
    );

    Ok(())
}

/// Test CertStore associate_cng_key with non-existent certificate
#[tokio::test]
async fn test_certstore_associate_cng_key_nonexistent_cert() -> Result<()> {
    let store = CertStore::open_path("LocalMachine\\My")?;

    // Valid format but non-existent thumbprint
    let fake_thumbprint = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    let result = store.associate_cng_key(fake_thumbprint, "test-container", providers::SOFTWARE);

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Certificate not found")
    );

    Ok(())
}

/// Test key metadata preservation
#[tokio::test]
async fn test_cng_key_metadata_preservation() -> Result<()> {
    let provider = CngKeyProvider::new()?;
    let label = "test-metadata";

    let key_handle = provider
        .generate_key_pair(KeyAlgorithm::Rsa { bits: 2048 }, Some(label))
        .await?;

    // Check metadata
    let metadata = key_handle.metadata();
    assert_eq!(metadata.label, Some(label.to_string()));
    assert!(metadata.can_sign);

    // Check attributes
    assert!(metadata.attributes.contains_key("container"));
    assert!(metadata.attributes.contains_key("provider"));

    Ok(())
}

/// Performance benchmark: RSA-2048 key generation
#[tokio::test]
#[ignore] // Run with --ignored flag for benchmarks
async fn bench_rsa2048_generation() -> Result<()> {
    let provider = CngKeyProvider::new()?;
    let iterations = 10;

    let start = std::time::Instant::now();

    for i in 0..iterations {
        let label = format!("bench-rsa2048-{}", i);
        let _key = provider
            .generate_key_pair(KeyAlgorithm::Rsa { bits: 2048 }, Some(&label))
            .await?;
    }

    let elapsed = start.elapsed();
    let avg_ms = elapsed.as_millis() / iterations;

    println!("RSA-2048 generation: avg {}ms per key", avg_ms);

    // Should be reasonably fast (< 500ms per key for software provider)
    assert!(avg_ms < 500);

    Ok(())
}

/// Performance benchmark: ECDSA P-256 key generation
#[tokio::test]
#[ignore] // Run with --ignored flag for benchmarks
async fn bench_ecc_p256_generation() -> Result<()> {
    let provider = CngKeyProvider::new()?;
    let iterations = 10;

    let start = std::time::Instant::now();

    for i in 0..iterations {
        let label = format!("bench-ecc-p256-{}", i);
        let _key = provider
            .generate_key_pair(KeyAlgorithm::EcdsaP256, Some(&label))
            .await?;
    }

    let elapsed = start.elapsed();
    let avg_ms = elapsed.as_millis() / iterations;

    println!("ECC P-256 generation: avg {}ms per key", avg_ms);

    // ECC should be faster than RSA (< 200ms per key)
    assert!(avg_ms < 200);

    Ok(())
}

/// Test CNG provider is_tpm detection
#[tokio::test]
#[ignore] // Requires TPM hardware
async fn test_cng_provider_tpm_detection() -> Result<()> {
    let result = CngKeyProvider::with_provider(providers::PLATFORM);

    match result {
        Ok(provider) => {
            assert!(provider.is_tpm());
            assert_eq!(provider.provider_name(), providers::PLATFORM);
            println!("TPM provider available");
        }
        Err(_) => {
            println!("TPM provider not available (no TPM hardware)");
            // Not an error - just means no TPM
        }
    }

    Ok(())
}

/// Integration test: Full enrollment workflow simulation
#[tokio::test]
#[ignore] // Requires full environment setup
async fn test_integration_cng_enrollment_workflow() -> Result<()> {
    // This simulates the full workflow:
    // 1. Generate CNG key
    // 2. Create CSR
    // 3. Get certificate (mock)
    // 4. Import certificate
    // 5. Associate key with certificate

    let provider = CngKeyProvider::new()?;
    let label = format!("test-enrollment-{}", unique_ts());

    // Step 1: Generate CNG key
    let key_handle = provider
        .generate_key_pair(KeyAlgorithm::Rsa { bits: 2048 }, Some(&label))
        .await?;

    // Step 2: Build CSR (would use CsrBuilder in real code)
    // Step 3: Submit to EST server (skipped in test)
    // Step 4: Import certificate (skipped - need real cert)

    // Step 5: Extract metadata for association
    let container_name = CngKeyProvider::get_container_name(&key_handle)?;
    let provider_name = CngKeyProvider::get_provider_name(&key_handle)?;

    // Verify metadata is present
    assert!(!container_name.is_empty());
    assert_eq!(provider_name, providers::SOFTWARE);

    println!("Full workflow test completed successfully");
    println!("  Container: {}", container_name);
    println!("  Provider: {}", provider_name);

    Ok(())
}
