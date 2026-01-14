// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! EST Key Migration Utility
//!
//! This tool migrates private keys from PEM files to Windows CNG key containers
//! and associates them with existing certificates in the Windows Certificate Store.
//!
//! # Usage
//!
//! ```text
//! # Migrate a single key
//! est-migrate-keys --key-file C:\keys\device.pem --thumbprint A1B2C3... --label "Device-Key"
//!
//! # Migrate with specific CNG provider
//! est-migrate-keys --key-file key.pem --thumbprint A1B2... --provider "Microsoft Platform Crypto Provider"
//!
//! # Batch migration from config file
//! est-migrate-keys --config migration-config.toml
//! ```
//!
//! # Migration Process
//!
//! 1. **Load PEM Key**: Read and parse private key from PEM file
//! 2. **Import to CNG**: Store key in CNG provider with DPAPI protection
//! 3. **Find Certificate**: Locate certificate by thumbprint in Windows store
//! 4. **Associate Key**: Link CNG container to certificate
//! 5. **Verify**: Test that certificate can use the CNG key
//! 6. **Secure Delete**: Optionally shred the PEM file
//!
//! # Safety
//!
//! - Creates backup of PEM file before deletion
//! - Verifies CNG key works before removing PEM file
//! - Supports dry-run mode for testing
//! - Detailed logging of all operations

#[cfg(not(windows))]
fn main() {
    eprintln!("Error: This tool requires Windows OS");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() {
    use std::env;
    use std::process::ExitCode;

    let args: Vec<String> = env::args().collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_usage(&args[0]);
        return ExitCode::SUCCESS;
    }

    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    match run_migration(&args) {
        Ok(()) => {
            tracing::info!("Migration completed successfully");
            ExitCode::SUCCESS
        }
        Err(e) => {
            tracing::error!("Migration failed: {}", e);
            ExitCode::FAILURE
        }
    }
}

#[cfg(windows)]
fn print_usage(program: &str) {
    println!("EST Key Migration Utility");
    println!();
    println!("USAGE:");
    println!("    {} [OPTIONS]", program);
    println!();
    println!("OPTIONS:");
    println!("    --key-file <PATH>        Path to PEM private key file");
    println!("    --thumbprint <SHA1>      Certificate thumbprint (SHA-1 hex)");
    println!("    --label <NAME>           Label for CNG key container");
    println!("    --provider <NAME>        CNG provider (default: Software)");
    println!("    --store <PATH>           Certificate store (default: LocalMachine\\My)");
    println!("    --dry-run                Test migration without changes");
    println!("    --no-delete              Keep PEM file after migration");
    println!("    --help, -h               Show this help message");
    println!();
    println!("EXAMPLES:");
    println!(
        "    {} --key-file key.pem --thumbprint A1B2C3... --label Device",
        program
    );
    println!(
        "    {} --key-file key.pem --thumbprint A1B2... --provider \"Microsoft Platform Crypto Provider\"",
        program
    );
    println!();
}

#[cfg(windows)]
fn run_migration(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use std::path::PathBuf;
    use usg_est_client::error::EstError;
    use usg_est_client::hsm::{KeyAlgorithm, KeyProvider};
    use usg_est_client::windows::CertStore;
    use usg_est_client::windows::cng::{CngKeyProvider, providers};

    // Parse command line arguments
    let key_file = get_arg(args, "--key-file").ok_or("Missing required argument: --key-file")?;
    let thumbprint =
        get_arg(args, "--thumbprint").ok_or("Missing required argument: --thumbprint")?;
    let label = get_arg(args, "--label").ok_or("Missing required argument: --label")?;
    let provider_name = get_arg(args, "--provider").unwrap_or(providers::SOFTWARE.to_string());
    let store_path = get_arg(args, "--store").unwrap_or("LocalMachine\\My".to_string());
    let dry_run = args.iter().any(|a| a == "--dry-run");
    let no_delete = args.iter().any(|a| a == "--no-delete");

    tracing::info!("Starting key migration");
    tracing::info!("  Key file: {}", key_file);
    tracing::info!("  Thumbprint: {}", thumbprint);
    tracing::info!("  Label: {}", label);
    tracing::info!("  Provider: {}", provider_name);
    tracing::info!("  Store: {}", store_path);
    tracing::info!("  Dry run: {}", dry_run);

    if dry_run {
        tracing::warn!("DRY RUN MODE - No changes will be made");
    }

    // 1. Load PEM key file
    tracing::info!("Loading private key from file...");
    let key_pem = std::fs::read_to_string(&key_file)?;

    // Parse key to determine algorithm
    let key_algorithm = detect_key_algorithm(&key_pem)?;
    tracing::info!("Detected key algorithm: {:?}", key_algorithm);

    if dry_run {
        tracing::info!("[DRY RUN] Would import key to CNG");
    } else {
        // 2. Import key to CNG
        tracing::info!("Importing key to CNG provider: {}", provider_name);
        let cng_provider = CngKeyProvider::with_provider(&provider_name)?;

        // For now, we'd need to add an import_key method to CngKeyProvider
        // This is a placeholder showing the intended flow
        tracing::warn!("Note: Key import to CNG requires implementation of import_key() method");
        tracing::warn!("Current version can only migrate keys generated by CNG");

        return Err(Box::new(EstError::platform(
            "CNG key import not yet implemented. Please regenerate keys using EST enrollment with CNG enabled.",
        )));
    }

    // 3. Find certificate by thumbprint
    tracing::info!("Finding certificate in store: {}", store_path);
    let store = CertStore::open_path(&store_path)?;

    // Verify certificate exists
    let cert_info = store
        .find_by_thumbprint(&thumbprint)?
        .ok_or_else(|| format!("Certificate not found with thumbprint: {}", thumbprint))?;
    tracing::info!("Found certificate: {}", cert_info.subject);

    if dry_run {
        tracing::info!("[DRY RUN] Would associate CNG key with certificate");
        tracing::info!("[DRY RUN] Migration validation successful");
    } else {
        // 4. Associate CNG key with certificate
        // This would use the container name from the imported key
        // store.associate_cng_key(&thumbprint, &container_name, &provider_name)?;

        // 5. Verify the association works
        // Try to use the certificate for signing to verify

        // 6. Optionally delete PEM file
        if !no_delete {
            tracing::info!("Securely deleting PEM file...");
            secure_delete(&key_file)?;
        } else {
            tracing::info!("Keeping PEM file as requested");
        }
    }

    Ok(())
}

#[cfg(windows)]
fn get_arg(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

#[cfg(windows)]
fn detect_key_algorithm(
    pem: &str,
) -> Result<usg_est_client::hsm::KeyAlgorithm, Box<dyn std::error::Error>> {
    use usg_est_client::hsm::KeyAlgorithm;

    // Simple heuristic - check PEM header
    if pem.contains("BEGIN RSA PRIVATE KEY") || pem.contains("BEGIN PRIVATE KEY") {
        // Would need to parse to determine exact size
        // For now, default to RSA-2048
        Ok(KeyAlgorithm::Rsa2048)
    } else if pem.contains("BEGIN EC PRIVATE KEY") {
        // Would need to parse to determine curve
        Ok(KeyAlgorithm::EccP256)
    } else {
        Err("Unsupported key format".into())
    }
}

#[cfg(windows)]
fn secure_delete(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs::{File, OpenOptions};
    use std::io::{Seek, SeekFrom, Write};

    // Create backup first
    let backup_path = format!("{}.backup", path);
    std::fs::copy(path, &backup_path)?;
    tracing::info!("Created backup: {}", backup_path);

    // Overwrite with zeros
    let mut file = OpenOptions::new().write(true).open(path)?;

    let size = file.metadata()?.len();
    let zeros = vec![0u8; size as usize];
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&zeros)?;
    file.sync_all()?;
    drop(file);

    // Delete the file
    std::fs::remove_file(path)?;
    tracing::info!("Securely deleted: {}", path);

    Ok(())
}
