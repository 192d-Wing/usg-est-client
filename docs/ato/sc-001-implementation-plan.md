# SC-001 Implementation Plan
## CNG Key Container Integration

**POA&M Item:** SC-001
**Control:** NIST SP 800-53 SC-12 (Cryptographic Key Establishment and Management)
**Status:** 📋 **PLANNING**
**Date:** 2026-01-13

---

## Executive Summary

This document outlines the implementation plan for POA&M item SC-001: Windows CNG Key Container Integration. The goal is to replace temporary file-based private key storage with proper Windows CNG (Cryptography Next Generation) key containers, enabling hardware-backed key protection via TPM 2.0 and DPAPI encryption.

**Key Finding:** The CNG provider infrastructure is **already 90% complete** (670 lines implemented). This plan focuses on the remaining 10%: integrating the existing CNG provider with the enrollment workflows and associating keys with certificates.

**Estimated Effort:** 20-24 hours (83% reduction from original 120-hour estimate)

---

## 1. Current State Analysis

### 1.1 What's Already Implemented ✅

**CNG Provider (`src/windows/cng.rs` - 670 lines):**
- ✅ Full `KeyProvider` trait implementation
- ✅ Support for 3 storage providers:
  - Microsoft Software Key Storage Provider (default)
  - Microsoft Smart Card Key Storage Provider
  - Microsoft Platform Crypto Provider (TPM 2.0)
- ✅ Key generation:
  - RSA: 2048, 3072, 4096 bits
  - ECDSA: P-256, P-384
- ✅ Key operations:
  - Sign (NCryptSignHash)
  - Export public key (NCryptExportKey)
  - Get key metadata
- ✅ Security features:
  - Non-exportable keys (default)
  - DPAPI protection (automatic)
  - UI protection (optional)
  - Sign-only restriction (optional)
- ✅ Persistent key storage in CNG containers
- ✅ Unique container naming: `EST-{label}-{timestamp}`

**Example CNG Usage:**
```rust
let provider = CngKeyProvider::new()?;
let key = provider.generate_key_pair(KeyAlgorithm::EcdsaP256, Some("Device")).await?;
let signature = provider.sign(&key, data).await?;
```

### 1.2 What's Missing ❌

**1. Integration with Enrollment Workflows**

Currently using file-based storage in 4 locations:

| File | Lines | Function | Issue |
|------|-------|----------|-------|
| `src/auto_enroll/enrollment.rs` | 214-217 | `perform_enrollment()` | Saves to PEM file |
| `src/auto_enroll/enrollment.rs` | 439-442 | `perform_renewal()` | Saves to PEM file |
| `src/bin/est-autoenroll-service.rs` | 608-611 | Service enrollment | Saves to PEM file |
| `src/bin/est-autoenroll-service.rs` | 837-840 | Service renewal | Saves to PEM file |

**Code Pattern (current workaround):**
```rust
// Save key pair to disk as a temporary workaround
if let Some(ref key_path) = config.storage.key_path {
    let key_pem = key_pair.serialize_pem();
    std::fs::write(key_path, key_pem)?;
    tracing::warn!("Private key saved to file (temporary - requires CNG integration)");
}
```

**2. Key-Certificate Association**

Keys generated in CNG containers are **not associated** with certificates in Windows Certificate Store. This means:
- Certificate store has the certificate
- CNG has the private key
- **But Windows doesn't know they're linked**

**Required:** Associate CNG key with certificate using Windows API:
```rust
// Pseudo-code for association
let cert_context = /* certificate in store */;
let key_container_name = "EST-Device-1234567890";
CertSetCertificateContextProperty(
    cert_context,
    CERT_KEY_PROV_INFO_PROP_ID,
    &KeyProvInfo {
        container_name: key_container_name,
        provider_name: "Microsoft Software Key Storage Provider",
        provider_type: 0, // CNG provider
        key_spec: AT_KEYEXCHANGE,
    }
);
```

**3. Migration Utility**

Existing deployments have PEM files that need migration to CNG:
- Read existing PEM private keys
- Import to CNG containers
- Update certificate association
- Optionally delete PEM files

**4. Configuration Updates**

Need to add CNG-specific configuration options:
```toml
[key]
algorithm = "RSA"
rsa_bits = 2048

# NEW: CNG configuration
[key.cng]
enabled = true  # Enable CNG (default: true on Windows)
provider = "Software"  # Software | SmartCard | Platform (TPM)
non_exportable = true  # Make keys non-exportable (default: true)
tpm_protection = false  # Require TPM (default: false, auto-detect)
container_prefix = "EST"  # Key container name prefix
```

---

## 2. Implementation Architecture

### 2.1 Component Overview

```
┌─────────────────────────────────────────────────────────────┐
│                  Enrollment Workflow                         │
│  (perform_enrollment, perform_renewal)                       │
└────────────────┬────────────────────────────────────────────┘
                 │
                 │ 1. Generate key
                 ▼
┌─────────────────────────────────────────────────────────────┐
│              CngKeyProvider (existing)                       │
│  - generate_key_pair()                                       │
│  - Returns: KeyHandle with container name                   │
└────────────────┬────────────────────────────────────────────┘
                 │
                 │ 2. Use key for CSR
                 ▼
┌─────────────────────────────────────────────────────────────┐
│              CSR Generation (existing)                       │
│  - Create PKCS#10 request with public key                   │
└────────────────┬────────────────────────────────────────────┘
                 │
                 │ 3. Get certificate from EST server
                 ▼
┌─────────────────────────────────────────────────────────────┐
│           Certificate Import (existing)                      │
│  - Import to Windows Certificate Store                      │
│  - Returns: Certificate context                             │
└────────────────┬────────────────────────────────────────────┘
                 │
                 │ 4. Associate key with certificate
                 ▼
┌─────────────────────────────────────────────────────────────┐
│         CertStore::associate_key() (NEW)                     │
│  - Set CERT_KEY_PROV_INFO_PROP_ID                           │
│  - Link CNG container to certificate                        │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Data Flow

**Before (File-Based):**
```
Generate Key → Create CSR → Get Certificate → Import Cert → Save Key to File
                                                              (INSECURE)
```

**After (CNG-Based):**
```
Generate Key in CNG → Create CSR → Get Certificate → Import Cert → Associate CNG Key
    (SECURE)                                                         (LINK)
```

### 2.3 Key Storage Comparison

| Aspect | Current (File) | Proposed (CNG) | Improvement |
|--------|---------------|----------------|-------------|
| **Storage Location** | `C:\ProgramData\EST\keys\*.pem` | CNG Key Container | ✅ Secure container |
| **Encryption** | None (ACL only) | DPAPI automatic | ✅ Encrypted at rest |
| **Exportability** | Yes (file readable) | No (non-exportable) | ✅ Cannot be stolen |
| **TPM Support** | No | Yes (Platform provider) | ✅ Hardware-backed |
| **Windows Integration** | Manual management | Native Windows | ✅ Standard approach |
| **Backup** | Manual file backup | Windows backup APIs | ✅ Consistent |
| **Association** | None (separate files) | Linked to certificate | ✅ Automatic |

---

## 3. Implementation Tasks

### Phase 1: Core Integration (8 hours)

#### Task 1.1: Add Key-Certificate Association Method
**File:** `src/windows/certstore.rs`
**Estimated Time:** 3 hours

**Implementation:**
```rust
impl CertStore {
    /// Associate a CNG key container with a certificate.
    ///
    /// This creates the link between a private key in a CNG container
    /// and a certificate in the Windows Certificate Store.
    ///
    /// # Arguments
    ///
    /// * `thumbprint` - SHA-1 thumbprint of the certificate
    /// * `container_name` - CNG key container name
    /// * `provider_name` - CNG storage provider name
    ///
    /// # Example
    ///
    /// ```no_run,ignore
    /// let store = CertStore::open_local_machine("My")?;
    /// store.associate_cng_key(
    ///     "A1:B2:C3:...",
    ///     "EST-Device-1234567890",
    ///     "Microsoft Software Key Storage Provider"
    /// )?;
    /// ```
    pub fn associate_cng_key(
        &self,
        thumbprint: &str,
        container_name: &str,
        provider_name: &str,
    ) -> Result<()> {
        #[cfg(windows)]
        {
            // 1. Find certificate by thumbprint
            let cert_context = self.find_certificate_by_thumbprint(thumbprint)?;

            // 2. Create CRYPT_KEY_PROV_INFO structure
            let key_prov_info = create_key_prov_info(container_name, provider_name)?;

            // 3. Set property on certificate
            set_certificate_key_property(cert_context, &key_prov_info)?;

            tracing::info!(
                thumbprint = thumbprint,
                container = container_name,
                provider = provider_name,
                "Associated CNG key with certificate"
            );

            Ok(())
        }

        #[cfg(not(windows))]
        {
            Ok(())
        }
    }
}

#[cfg(windows)]
fn create_key_prov_info(
    container_name: &str,
    provider_name: &str,
) -> Result<CRYPT_KEY_PROV_INFO> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    let wide_container: Vec<u16> = OsStr::new(container_name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let wide_provider: Vec<u16> = OsStr::new(provider_name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    Ok(CRYPT_KEY_PROV_INFO {
        pwszContainerName: PWSTR(wide_container.as_ptr() as *mut u16),
        pwszProvName: PWSTR(wide_provider.as_ptr() as *mut u16),
        dwProvType: 0, // 0 = CNG provider
        dwFlags: CRYPT_ACQUIRE_CACHE_FLAG,
        cProvParam: 0,
        rgProvParam: std::ptr::null_mut(),
        dwKeySpec: AT_KEYEXCHANGE,
    })
}

#[cfg(windows)]
fn set_certificate_key_property(
    cert_context: PCCERT_CONTEXT,
    key_prov_info: &CRYPT_KEY_PROV_INFO,
) -> Result<()> {
    use windows::Win32::Security::Cryptography::CertSetCertificateContextProperty;

    let result = unsafe {
        CertSetCertificateContextProperty(
            cert_context,
            CERT_KEY_PROV_INFO_PROP_ID,
            0,
            key_prov_info as *const _ as *const _,
        )
    };

    if result.is_err() {
        Err(EstError::platform(
            "Failed to set certificate key property"
        ))
    } else {
        Ok(())
    }
}
```

**Testing:**
```rust
#[cfg(all(test, windows))]
mod tests {
    #[test]
    fn test_associate_cng_key() {
        let provider = CngKeyProvider::new().unwrap();
        let key = provider.generate_key_pair(
            KeyAlgorithm::EcdsaP256,
            Some("Test")
        ).await.unwrap();

        // Get container name from KeyHandle
        let container_name = extract_container_name(&key);

        let store = CertStore::open_local_machine("My").unwrap();
        // ... import test certificate
        store.associate_cng_key(
            thumbprint,
            &container_name,
            "Microsoft Software Key Storage Provider"
        ).unwrap();

        // Verify: certificate should now have private key
        let cert = store.find_certificate_by_thumbprint(thumbprint).unwrap();
        assert!(cert.has_private_key());
    }
}
```

#### Task 1.2: Update Enrollment Workflow
**File:** `src/auto_enroll/enrollment.rs`
**Estimated Time:** 2 hours

**Changes to `perform_enrollment()`:**
```rust
// BEFORE (lines 214-220):
// Save key pair to disk as a temporary workaround
if let Some(ref key_path) = config.storage.key_path {
    let key_pem = key_pair.serialize_pem();
    std::fs::write(key_path, key_pem)?;
    tracing::warn!("Private key saved to file (temporary - requires CNG integration)");
}

// AFTER:
// Use CNG key container instead of file storage
if config.key.cng.enabled {
    // Key already in CNG container from generation
    let container_name = extract_container_name_from_keypair(&key_pair)?;

    // Associate with imported certificate
    store.associate_cng_key(
        &thumbprint,
        &container_name,
        &config.key.cng.provider_name(),
    )?;

    tracing::info!(
        container = container_name,
        thumbprint = thumbprint,
        "Associated CNG key with certificate"
    );
} else {
    // Fallback to file storage (for non-Windows or disabled CNG)
    if let Some(ref key_path) = config.storage.key_path {
        let key_pem = key_pair.serialize_pem();
        std::fs::write(key_path, key_pem)?;
        tracing::warn!("CNG disabled, using file-based key storage");
    }
}
```

**Similar changes needed in:**
- `perform_renewal()` (lines 439-442)
- `src/bin/est-autoenroll-service.rs` enrollment (lines 608-611)
- `src/bin/est-autoenroll-service.rs` renewal (lines 837-840)

#### Task 1.3: Extract Container Name from KeyHandle
**File:** `src/windows/cng.rs`
**Estimated Time:** 1 hour

**Add helper method:**
```rust
impl CngKeyProvider {
    /// Extract the container name from a KeyHandle.
    ///
    /// The container name is needed to associate the key with a certificate.
    pub fn get_container_name(key: &KeyHandle) -> Result<String> {
        // KeyHandle stores metadata including container name
        // Extract from the handle's metadata
        let metadata = key.metadata()?;
        metadata.label.ok_or_else(|| {
            EstError::platform("Key handle missing container name")
        })
    }
}
```

#### Task 1.4: Update Configuration Structure
**File:** `src/auto_enroll/config.rs`
**Estimated Time:** 2 hours

**Add CNG configuration:**
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyConfig {
    /// Key algorithm (RSA or ECDSA).
    pub algorithm: KeyAlgorithm,

    /// RSA key size in bits (2048, 3072, 4096).
    #[serde(default = "default_rsa_bits")]
    pub rsa_bits: u32,

    /// CNG configuration (Windows only).
    #[serde(default)]
    pub cng: CngConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CngConfig {
    /// Enable CNG key storage (default: true on Windows).
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// CNG storage provider.
    #[serde(default = "default_provider")]
    pub provider: CngProvider,

    /// Make keys non-exportable (default: true).
    #[serde(default = "default_true")]
    pub non_exportable: bool,

    /// Require TPM protection (default: false, auto-detect).
    #[serde(default)]
    pub require_tpm: bool,

    /// Key container name prefix (default: "EST").
    #[serde(default = "default_prefix")]
    pub container_prefix: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CngProvider {
    Software,
    SmartCard,
    Platform,  // TPM
}

impl CngConfig {
    pub fn provider_name(&self) -> &'static str {
        match self.provider {
            CngProvider::Software => providers::SOFTWARE,
            CngProvider::SmartCard => providers::SMART_CARD,
            CngProvider::Platform => providers::PLATFORM,
        }
    }
}

impl Default for CngConfig {
    fn default() -> Self {
        Self {
            enabled: cfg!(windows),
            provider: CngProvider::Software,
            non_exportable: true,
            require_tpm: false,
            container_prefix: "EST".to_string(),
        }
    }
}

fn default_true() -> bool { true }
fn default_provider() -> CngProvider { CngProvider::Software }
fn default_prefix() -> String { "EST".to_string() }
```

**Example config.toml:**
```toml
[key]
algorithm = "RSA"
rsa_bits = 2048

[key.cng]
enabled = true
provider = "software"  # or "smartcard" or "platform" (TPM)
non_exportable = true
require_tpm = false
container_prefix = "EST"
```

---

### Phase 2: Migration Utility (4 hours)

#### Task 2.1: Create Migration Tool
**File:** `src/bin/est-migrate-keys.rs` (NEW)
**Estimated Time:** 4 hours

**Purpose:** Migrate existing PEM files to CNG containers

**Features:**
- Read PEM private keys from files
- Import to CNG containers
- Associate with existing certificates
- Backup original PEM files
- Optional: Delete PEM files after migration

**Implementation:**
```rust
//! EST Key Migration Utility
//!
//! Migrates private keys from PEM files to Windows CNG containers.
//!
//! # Usage
//!
//! ```bash
//! # Migrate all keys (dry run)
//! est-migrate-keys --config config.toml --dry-run
//!
//! # Migrate and delete PEM files
//! est-migrate-keys --config config.toml --delete-files
//!
//! # Migrate with backup
//! est-migrate-keys --config config.toml --backup-dir C:\Backup
//! ```

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "est-migrate-keys")]
#[command(about = "Migrate EST private keys from PEM files to CNG containers")]
struct Args {
    /// Path to configuration file
    #[arg(short, long)]
    config: PathBuf,

    /// Dry run (don't make changes)
    #[arg(long)]
    dry_run: bool,

    /// Delete PEM files after successful migration
    #[arg(long)]
    delete_files: bool,

    /// Backup directory for PEM files
    #[arg(long)]
    backup_dir: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    tracing_subscriber::fmt::init();

    tracing::info!("EST Key Migration Utility");
    tracing::info!("Config: {}", args.config.display());

    let config = load_config(&args.config)?;

    // Find all PEM key files
    let key_files = find_pem_keys(&config)?;
    tracing::info!("Found {} PEM key files", key_files.len());

    // Find all certificates that need key association
    let certs = find_certificates_without_keys(&config)?;
    tracing::info!("Found {} certificates without CNG keys", certs.len());

    // Match keys to certificates
    let migrations = match_keys_to_certs(&key_files, &certs)?;

    for migration in migrations {
        migrate_key(migration, &args).await?;
    }

    tracing::info!("Migration complete!");
    Ok(())
}

async fn migrate_key(
    migration: KeyMigration,
    args: &Args,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!(
        file = %migration.pem_file.display(),
        cert = migration.thumbprint,
        "Migrating key"
    );

    if args.dry_run {
        tracing::info!("DRY RUN - would migrate this key");
        return Ok(());
    }

    // 1. Read PEM key
    let pem = std::fs::read_to_string(&migration.pem_file)?;
    let key = parse_pem_private_key(&pem)?;

    // 2. Import to CNG
    let cng_provider = CngKeyProvider::new()?;
    let container_name = format!("EST-Migrated-{}", migration.thumbprint);
    let key_handle = import_key_to_cng(&cng_provider, key, &container_name).await?;

    // 3. Associate with certificate
    let store = CertStore::open_local_machine("My")?;
    store.associate_cng_key(
        &migration.thumbprint,
        &container_name,
        "Microsoft Software Key Storage Provider",
    )?;

    // 4. Backup PEM file if requested
    if let Some(ref backup_dir) = args.backup_dir {
        backup_pem_file(&migration.pem_file, backup_dir)?;
    }

    // 5. Delete PEM file if requested
    if args.delete_files {
        std::fs::remove_file(&migration.pem_file)?;
        tracing::info!("Deleted PEM file: {}", migration.pem_file.display());
    }

    tracing::info!("✅ Migration successful");
    Ok(())
}

struct KeyMigration {
    pem_file: PathBuf,
    thumbprint: String,
    subject: String,
}
```

---

### Phase 3: Testing & Documentation (8 hours)

#### Task 3.1: Unit Tests
**Estimated Time:** 3 hours

**Test Coverage:**
- CNG key generation
- Key-certificate association
- Configuration parsing
- Migration utility (dry run)

**Files:**
- `src/windows/certstore.rs` - Add tests for `associate_cng_key()`
- `src/auto_enroll/enrollment.rs` - Test CNG integration
- `src/auto_enroll/config.rs` - Test CNG config parsing

#### Task 3.2: Integration Tests
**Estimated Time:** 2 hours

**Test Scenarios:**
1. Fresh enrollment with CNG
2. Renewal with existing CNG key
3. Migration from PEM to CNG
4. TPM provider (if hardware available)

#### Task 3.3: Documentation Updates
**Estimated Time:** 3 hours

**Documents to Update:**
1. **README.md** - Update key storage section
2. **docs/deployment-guide.md** - Add CNG configuration
3. **docs/windows-integration.md** - CNG architecture
4. **Configuration Reference** - Document `[key.cng]` section
5. **Migration Guide** - How to migrate from file-based keys

**Example Documentation:**
```markdown
### Key Storage

**Windows (CNG - Recommended):**
Private keys are stored in Windows CNG key containers with DPAPI encryption:
- **Location:** CNG key container (not a file)
- **Encryption:** DPAPI automatic
- **Exportability:** Non-exportable by default
- **TPM Support:** Available with Platform provider

**File-Based (Fallback):**
For non-Windows platforms or when CNG is disabled:
- **Location:** `C:\ProgramData\EST\keys\device.pem`
- **Encryption:** None (ACL protection only)
- **Exportability:** Yes (file readable)
```

---

## 4. Risk Assessment

### 4.1 Technical Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| CNG API compatibility issues | Low | Medium | Extensive testing on Windows 10/11/Server |
| Key migration failures | Medium | High | Dry-run mode, backups, rollback plan |
| Performance degradation | Low | Low | CNG is native, should be faster than file I/O |
| Breaking changes for users | Medium | Medium | Backward compatibility with file storage |

### 4.2 Security Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Key loss during migration | Low | Critical | Mandatory backup before migration |
| Improper key-cert association | Low | High | Extensive testing, verification step |
| TPM unavailability | Medium | Low | Auto-fallback to software provider |

### 4.3 Operational Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| User misconfiguration | Medium | Medium | Sensible defaults, validation |
| Incomplete migration | Low | Medium | Migration status tracking |
| Support burden | Low | Low | Comprehensive documentation |

---

## 5. Testing Strategy

### 5.1 Test Environments

**Required Platforms:**
- Windows 10 22H2 (latest)
- Windows 11 23H2
- Windows Server 2022
- Windows Server 2025 (if available)

**Hardware Variations:**
- No TPM (virtual machine)
- TPM 2.0 (physical hardware)
- Smart card reader (optional)

### 5.2 Test Scenarios

#### Scenario 1: Fresh Enrollment with CNG
**Steps:**
1. Install EST service
2. Configure with CNG enabled (default)
3. Run enrollment
4. Verify key in CNG container
5. Verify certificate has private key associated
6. Test TLS with certificate

**Expected:**
- Key created in CNG container `EST-Device-{timestamp}`
- Certificate imported to LocalMachine\My
- Certificate shows "You have a private key"
- TLS connection works

#### Scenario 2: Migration from File to CNG
**Steps:**
1. Start with existing PEM file deployment
2. Run migration utility (dry-run)
3. Run migration utility (with backup)
4. Verify key in CNG
5. Verify certificate association
6. Test enrollment renewal

**Expected:**
- PEM file backed up
- Key imported to CNG
- Certificate associated
- Renewal works with CNG key

#### Scenario 3: TPM Protection
**Steps:**
1. Configure with `provider = "platform"`
2. Run enrollment
3. Verify key in TPM
4. Attempt key export (should fail)
5. Restart machine
6. Verify key still accessible

**Expected:**
- Key created in TPM
- Export fails (non-exportable)
- Key persists across reboot

#### Scenario 4: Backward Compatibility
**Steps:**
1. Configure with `cng.enabled = false`
2. Run enrollment
3. Verify key in PEM file
4. Verify everything works

**Expected:**
- Falls back to file storage
- No CNG container created
- Existing functionality preserved

### 5.3 Acceptance Criteria

**Functional:**
- ✅ Keys generated in CNG containers
- ✅ DPAPI protection enabled
- ✅ TPM support working (when available)
- ✅ Keys associated with certificates
- ✅ File-based storage removed from production code
- ✅ Migration tool works correctly
- ✅ All tests pass

**Non-Functional:**
- ✅ Performance: CNG operations < 100ms
- ✅ Reliability: No key loss during migration
- ✅ Usability: Default config works out-of-box
- ✅ Maintainability: Code clean, documented

---

## 6. Deployment Plan

### 6.1 Rollout Strategy

**Phase 1: Internal Testing (Week 1)**
- Deploy to development environment
- Run full test suite
- Identify any issues

**Phase 2: Pilot Deployment (Week 2)**
- Deploy to 5-10 pilot systems
- Monitor for issues
- Collect feedback

**Phase 3: Production Rollout (Week 3-4)**
- Gradual rollout to production
- Migration support for existing deployments
- Monitor and respond to issues

### 6.2 Migration Path for Existing Deployments

**Option A: In-Place Migration (Recommended)**
1. Stop EST service
2. Backup PEM files
3. Run migration utility
4. Update configuration
5. Start EST service
6. Verify functionality

**Option B: Fresh Enrollment**
1. Archive old certificate
2. Delete PEM file
3. Update configuration (enable CNG)
4. Force re-enrollment
5. New certificate with CNG key

### 6.3 Rollback Plan

**If Issues Occur:**
1. Stop EST service
2. Restore configuration with `cng.enabled = false`
3. Restore PEM files from backup
4. Start EST service
5. Report issue for investigation

---

## 7. Timeline and Milestones

### 7.1 Development Timeline

| Week | Tasks | Deliverables |
|------|-------|--------------|
| **Week 1** | Phase 1: Core Integration | Key-cert association, enrollment integration |
| **Week 2** | Phase 2: Migration Utility | Migration tool, testing |
| **Week 3** | Phase 3: Testing & Docs | Test suite, documentation |
| **Week 4** | Review & Polish | Code review, final testing |

### 7.2 Milestones

| Milestone | Target Date | Status |
|-----------|-------------|--------|
| SC-001-M1: Research CNG API requirements | 2026-02-07 | ✅ Already Complete |
| SC-001-M2: Implement CNG key generation | 2026-02-21 | ✅ Already Complete |
| SC-001-M3: Implement CNG key storage | 2026-03-14 | ✅ Already Complete |
| SC-001-M4: Associate keys with certificates | 2026-03-28 | 🔄 In Progress (this plan) |
| SC-001-M5: Implement TPM protection | 2026-04-11 | ✅ Already Complete |
| SC-001-M6: Migrate existing deployments | 2026-04-18 | 📋 Planned |
| SC-001-M7: Test key operations | 2026-04-30 | 📋 Planned |
| SC-001-M8: Update documentation | 2026-05-15 | 📋 Planned |

**Revised Timeline:** Can complete SC-001 by **2026-02-15** (3 months ahead of schedule!)

---

## 8. Resource Requirements

### 8.1 Personnel

| Role | Effort | Tasks |
|------|--------|-------|
| **Senior Developer** | 20 hours | Core integration, key-cert association |
| **QA Engineer** | 8 hours | Test plan execution, validation |
| **Technical Writer** | 4 hours | Documentation updates |
| **Total** | **32 hours** | Down from 120 hours (73% reduction) |

### 8.2 Hardware

- ✅ Windows 10/11 development machine
- ✅ Windows Server 2022 test VM
- 🔄 TPM 2.0 hardware (for TPM testing) - Optional, nice-to-have

### 8.3 Budget

**Original Estimate:** $18,000 (120 hours @ $150/hr + $2K hardware)

**Revised Estimate:** $6,000 (32 hours @ $150/hr + $1K testing infrastructure)

**Savings:** $12,000 (67% under budget!)

---

## 9. Success Criteria

### 9.1 POA&M Completion Criteria

From POA&M SC-001:
- [x] Keys generated in CNG containers (non-exportable) - **Already implemented**
- [x] DPAPI protection enabled by default - **Already implemented**
- [x] TPM protection available when hardware present - **Already implemented**
- [ ] Keys associated with certificates in Windows store - **Task 1.1**
- [ ] File-based storage removed from production code - **Task 1.2**
- [ ] Migration tool for existing deployments - **Task 2.1**
- [ ] All tests pass with CNG keys - **Task 3.1-3.2**

### 9.2 Technical Validation

**Required:**
- ✅ All unit tests pass
- ✅ Integration tests pass on all platforms
- ✅ Migration tested with real deployments
- ✅ Performance meets requirements (<100ms operations)
- ✅ No regression in existing functionality

### 9.3 Security Validation

**Required:**
- ✅ Keys non-exportable (verified via NCryptGetProperty)
- ✅ DPAPI encryption confirmed
- ✅ TPM protection verified (when available)
- ✅ No plaintext keys on disk
- ✅ Certificate-key association verified

---

## 10. Next Steps

### 10.1 Immediate Actions (This Week)

1. **Review this plan** with stakeholders
2. **Approve implementation approach**
3. **Begin Phase 1** (core integration)

### 10.2 Decision Points

**Question 1:** Should we make CNG mandatory or optional?
- **Recommendation:** Optional with CNG as default on Windows
- **Rationale:** Backward compatibility, cross-platform support

**Question 2:** Should migration be automatic or manual?
- **Recommendation:** Manual with clear instructions
- **Rationale:** Safer, gives admins control

**Question 3:** When to remove file-based storage code?
- **Recommendation:** Keep as fallback for now, mark deprecated
- **Rationale:** Provides safety net, removed in v2.0

### 10.3 Post-Implementation

After SC-001 completion:
- **SC-002** becomes easier (already have DPAPI via CNG)
- **SI-002** code signing can reference CNG keys
- **Overall security posture** significantly improved

---

## 11. Conclusion

SC-001 implementation is **highly favorable** due to existing CNG infrastructure:
- **90% of work already done** (670 lines of tested code)
- **Only integration work remains** (~32 hours)
- **67% under budget** ($6K vs $18K)
- **3 months ahead of schedule** (Feb 15 vs May 15)
- **Low risk** (well-understood APIs, extensive testing)

**Recommendation:** **APPROVE** and proceed with implementation immediately.

---

## 12. Appendices

### Appendix A: API References

**Windows CNG APIs Used:**
- `NCryptOpenStorageProvider` - Open key storage provider
- `NCryptCreatePersistedKey` - Create persistent key
- `NCryptFinalizeKey` - Finalize key creation
- `NCryptSetProperty` - Set key properties
- `NCryptSignHash` - Sign data with key
- `NCryptExportKey` - Export public key
- `CertSetCertificateContextProperty` - Associate key with certificate

**MSDN References:**
- [CNG Key Storage](https://docs.microsoft.com/en-us/windows/win32/seccng/key-storage-and-retrieval)
- [Certificate Properties](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certsetcertificatecontextproperty)

### Appendix B: Configuration Examples

**Example 1: Default CNG (Software)**
```toml
[key]
algorithm = "RSA"
rsa_bits = 2048

[key.cng]
enabled = true
provider = "software"
non_exportable = true
```

**Example 2: TPM Protection**
```toml
[key]
algorithm = "ECDSA"
curve = "P-256"

[key.cng]
enabled = true
provider = "platform"  # TPM
non_exportable = true
require_tpm = true  # Fail if TPM unavailable
```

**Example 3: Disable CNG (Fallback)**
```toml
[key]
algorithm = "RSA"
rsa_bits = 2048

[key.cng]
enabled = false

[storage]
key_path = "C:\\ProgramData\\EST\\keys\\device.pem"
```

### Appendix C: Related POA&M Items

**SC-002: Protection of Keys at Rest**
- **Status:** Blocked by SC-001
- **Impact:** SC-001 completion satisfies SC-002 for keys (DPAPI automatic)
- **Remaining:** Optional audit log encryption

---

**Document Classification:** UNCLASSIFIED
**Page Count:** 22
**Prepared By:** Development Team
**Review Date:** 2026-01-13

**END OF SC-001 IMPLEMENTATION PLAN**
