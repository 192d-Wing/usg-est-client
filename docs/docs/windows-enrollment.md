# Windows Auto-Enrollment Guide

This guide explains how to configure automated machine certificate enrollment using EST (RFC 7030) as a replacement for Microsoft Active Directory Certificate Services (ADCS) auto-enrollment.

## Table of Contents

1. [Overview](#overview)
2. [Configuration File Format](#configuration-file-format)
3. [Variable Expansion](#variable-expansion)
4. [Configuration Sections](#configuration-sections)
5. [Deployment Scenarios](#deployment-scenarios)
6. [Windows Integration](#windows-integration)
7. [Security Considerations](#security-considerations)
8. [Troubleshooting](#troubleshooting)

## Overview

The EST auto-enrollment system provides a modern, standards-based alternative to ADCS auto-enrollment:

- **Standards-Based**: Uses RFC 7030 (EST) instead of proprietary protocols
- **Cross-Platform**: Works on Windows, Linux, and macOS
- **Flexible Authentication**: Supports HTTP Basic, client certificates, and Windows Credential Manager
- **Automatic Renewal**: Background service monitors and renews certificates before expiration
- **Hardware Integration**: Supports Windows CNG, TPM, and PKCS#11 HSMs

### Comparison with ADCS Auto-Enrollment

| Feature | ADCS Auto-Enrollment | EST Auto-Enrollment |
|---------|---------------------|---------------------|
| Protocol | Proprietary (MS-WCCE) | RFC 7030 (EST) |
| Platform | Windows only | Cross-platform |
| Domain Required | Yes (Active Directory) | No |
| Certificate Stores | Windows Store only | Windows Store or PEM files |
| Key Storage | CNG, CSP | Software, CNG, TPM, PKCS#11 |
| Authentication | Kerberos, NTLM | HTTP Basic, Client Cert |
| Server Software | Windows Server + ADCS | Any EST server |

## Configuration File Format

Configuration files use TOML format with support for variable expansion. The file is typically located at:

- **Windows**: `C:\ProgramData\Department of War\EST\config.toml`
- **Linux**: `/etc/est/config.toml`
- **macOS**: `/etc/est/config.toml`

You can also override the location using the `EST_CONFIG_PATH` environment variable.

### Minimal Configuration

    ```toml
    [server]
    url = "https://est.example.com"
    
    [certificate]
    common_name = "${COMPUTERNAME}.${USERDNSDOMAIN}"
    ```

### IDE Support

All example configuration files include a JSON schema reference for IDE autocompletion:

    ```toml
    # yaml-language-server: $schema=../../schema/est-config.schema.json
    ```

This enables IntelliSense, validation, and inline documentation in VS Code, IntelliJ, and other modern editors.

## Variable Expansion

Configuration values support variable expansion using `${VARIABLE_NAME}` syntax. This allows machine-specific values to be computed at runtime.

### Supported Variables

| Variable | Description | Example (Windows) | Example (Unix) |
|----------|-------------|-------------------|----------------|
| `${COMPUTERNAME}` | Computer/hostname | `DESKTOP-ABC123` | `webserver` |
| `${USERDNSDOMAIN}` | DNS domain suffix | `corp.contoso.com` | `example.com` |
| `${USERDOMAIN}` | NetBIOS domain | `CORP` | N/A |
| `${USERNAME}` | Current username | `jsmith` | `jsmith` |
| `${HOME}` | Home directory | `C:\Users\jsmith` | `/home/jsmith` |
| `${USERPROFILE}` | User profile dir | `C:\Users\jsmith` | `/home/jsmith` |
| `${PROGRAMDATA}` | Program data dir | `C:\ProgramData` | `/var/lib` |
| `${LOCALAPPDATA}` | Local app data | `C:\Users\...\AppData\Local` | `~/.local/share` |
| `${TEMP}` | Temp directory | `C:\Users\...\AppData\Local\Temp` | `/tmp` |

### Custom Variables

Any environment variable can be referenced. If the variable is not found, it is left unchanged:

    ```toml
    [certificate]
    # Uses environment variable MY_CUSTOM_CN if set
    common_name = "${MY_CUSTOM_CN}"
    ```

### Examples

    ```toml
    # Machine certificate CN with domain
    common_name = "${COMPUTERNAME}.${USERDNSDOMAIN}"
    # Result: DESKTOP-ABC123.corp.contoso.com
    
    # Machine account username (Active Directory style)
    username = "${COMPUTERNAME}$"
    # Result: DESKTOP-ABC123$
    
    # Subject Alternative Names
    dns = ["${COMPUTERNAME}.${USERDNSDOMAIN}", "${COMPUTERNAME}"]
    # Result: ["DESKTOP-ABC123.corp.contoso.com", "DESKTOP-ABC123"]
    ```

## Configuration Sections

### [server]

EST server connection settings.

    ```toml
    [server]
    # EST server URL (required, must be HTTPS)
    url = "https://est.example.com"
    
    # Optional CA label for multi-CA deployments
    # When set, URLs become: /.well-known/est/{ca_label}/{operation}
    ca_label = "machines"
    
    # Request timeout in seconds (default: 60)
    timeout_seconds = 60
    
    # Enable TLS channel binding per RFC 7030 Section 3.5
    # Places tls-unique value in CSR challenge-password field
    channel_binding = true
    ```

### [trust]

Server certificate trust verification.

    ```toml
    [trust]
    # Trust mode: "webpki", "explicit", "bootstrap", or "insecure"
    mode = "explicit"
    
    # Path to CA certificate bundle (PEM format)
    # Required when mode is "explicit"
    ca_bundle_path = "C:\\ProgramData\\Department of War\\EST\\ca-bundle.pem"
    
    # Expected CA fingerprint for bootstrap mode
    # Format: SHA-256 hash with optional colons
    bootstrap_fingerprint = "sha256:AB:CD:EF:01:23:45:67:89:..."
    ```

**Trust Modes:**

- **`webpki`**: Use Mozilla's root CA store (default, suitable for public CAs)
- **`explicit`**: Use specific CA certificates from `ca_bundle_path` (recommended for enterprise)
- **`bootstrap`**: Trust-On-First-Use with fingerprint verification (initial setup only)
- **`insecure`**: Accept any certificate (TESTING ONLY, never use in production)

### [authentication]

Authentication credentials for EST server.

    ```toml
    [authentication]
    # Authentication method: "none", "http_basic", "client_cert", or "auto"
    method = "auto"
    
    # --- HTTP Basic Authentication ---
    username = "${COMPUTERNAME}$"
    password_source = "env:EST_PASSWORD"
    
    # --- Client Certificate Authentication ---
    # Option 1: Windows certificate store (Windows only)
    cert_store = "LocalMachine\\My"
    cert_thumbprint = "auto"  # or specific thumbprint
    
    # Option 2: PEM files
    cert_path = "C:\\ProgramData\\Department of War\\EST\\client.pem"
    key_path = "C:\\ProgramData\\Department of War\\EST\\client.key"
    ```

**Authentication Methods:**

- **`none`**: No authentication (rarely used, only for open enrollment)
- **`http_basic`**: Username/password in Authorization header
- **`client_cert`**: TLS client certificate (mutual TLS)
- **`auto`**: Try client_cert first, fallback to http_basic

**Password Sources:**

- **`env:VARIABLE_NAME`**: Read from environment variable
- **`file:/path/to/file`**: Read from file (first line, trimmed)
- **`credential_manager`**: Windows Credential Manager (Windows only, planned)

### [certificate]

Certificate request configuration (subject, SANs, extensions).

    ```toml
    [certificate]
    # Subject Distinguished Name fields
    common_name = "${COMPUTERNAME}.${USERDNSDOMAIN}"  # Required
    organization = "Example Corporation"
    organizational_unit = "IT Department"
    country = "US"  # ISO 3166-1 alpha-2 code
    state = "Virginia"
    locality = "Arlington"
    
    [certificate.san]
    # Subject Alternative Names
    dns = [
        "${COMPUTERNAME}.${USERDNSDOMAIN}",
        "${COMPUTERNAME}",
        "alias.example.com"
    ]
    ip = ["192.168.1.100", "10.0.1.100"]
    include_ip = true  # Auto-detect local IPs
    
    [certificate.key]
    # Key algorithm: "ecdsa-p256", "ecdsa-p384", "rsa-2048", "rsa-3072", "rsa-4096"
    algorithm = "ecdsa-p256"
    
    # Key provider: "software", "cng", "tpm", "pkcs11"
    provider = "software"
    
    # Mark private key as non-exportable (CNG/TPM only)
    non_exportable = true
    
    # Enable TPM key attestation (requires server support)
    attestation = false
    
    [certificate.extensions]
    # Key usage flags
    key_usage = ["digital_signature", "key_encipherment"]
    
    # Extended key usage OIDs
    extended_key_usage = ["client_auth", "server_auth"]
    ```

**Key Algorithms:**

- **`ecdsa-p256`**: ECDSA with P-256 curve (recommended, fast, small keys)
- **`ecdsa-p384`**: ECDSA with P-384 curve (higher security)
- **`rsa-2048`**: RSA 2048-bit (legacy compatibility)
- **`rsa-3072`**: RSA 3072-bit (balanced)
- **`rsa-4096`**: RSA 4096-bit (maximum security, slower)

**Key Providers:**

- **`software`**: In-memory or file-based keys (cross-platform)
- **`cng`**: Windows Cryptography Next Generation (Windows only, Phase 11.2)
- **`tpm`**: Trusted Platform Module (hardware-backed, Phase 11.2)
- **`pkcs11`**: PKCS#11 HSM (hardware security module, Phase 11.2)

**Extended Key Usage:**

- `server_auth`: TLS server authentication
- `client_auth`: TLS client authentication
- `code_signing`: Code signing
- `email_protection`: S/MIME email
- `time_stamping`: Timestamping
- `ocsp_signing`: OCSP response signing
- `smart_card_logon`: Smart card logon (Windows)

### [renewal]

Automatic certificate renewal settings.

    ```toml
    [renewal]
    # Enable automatic renewal
    enabled = true
    
    # Days before expiration to trigger renewal
    threshold_days = 30
    
    # Hours between certificate expiration checks
    check_interval_hours = 6
    
    # Maximum renewal retry attempts
    max_retries = 5
    
    # Minutes between retry attempts (base for exponential backoff)
    retry_delay_minutes = 30
    ```

**Renewal Logic:**

1. Background service checks certificate expiration every `check_interval_hours`
2. If certificate expires within `threshold_days`, renewal is triggered
3. If renewal fails, retry with exponential backoff (base = `retry_delay_minutes`)
4. After `max_retries` failures, log error and wait until next check interval

### [storage]

Certificate and key storage configuration.

    ```toml
    [storage]
    # --- Windows Certificate Store (Windows only) ---
    windows_store = "LocalMachine\\My"
    friendly_name = "EST Machine Certificate"
    
    # --- PEM Files (cross-platform) ---
    cert_path = "C:\\ProgramData\\Department of War\\EST\\machine.pem"
    key_path = "C:\\ProgramData\\Department of War\\EST\\machine.key"
    chain_path = "C:\\ProgramData\\Department of War\\EST\\chain.pem"
    
    # Archive old certificates instead of deleting
    archive_old = true
    ```

**Windows Certificate Stores:**

- `LocalMachine\My`: Computer certificate store (recommended for machine certs)
- `LocalMachine\Root`: Trusted root CAs
- `CurrentUser\My`: User certificate store
- `LocalMachine\TrustedPublisher`: Trusted publishers

### [logging]

Logging and monitoring configuration.

    ```toml
    [logging]
    # Log level: "debug", "info", "warn", "error"
    level = "info"
    
    # Log file path
    path = "C:\\ProgramData\\Department of War\\EST\\logs\\est-enroll.log"
    
    # Enable Windows Event Log integration (Windows only)
    windows_event_log = true
    
    # Enable JSON formatted logging (for log aggregation)
    json_format = false
    
    # Log rotation settings
    max_size_mb = 10
    max_files = 5
    ```

### [service]

Windows Service configuration (Windows only).

    ```toml
    [service]
    # Service start type: "automatic", "delayed", "manual", "disabled"
    start_type = "automatic"
    
    # Service account
    run_as = "LocalSystem"  # or "NetworkService", "DOMAIN\\ServiceAccount"
    
    # Service dependencies (must start before this service)
    dependencies = ["Tcpip", "Dnscache"]
    
    # Health check HTTP port (optional)
    health_check_port = 8080
    ```

## Deployment Scenarios

### Scenario 1: Domain Workstations

Replace ADCS auto-enrollment for Windows domain workstations.

**Requirements:**

- Machine certificates with domain FQDN
- Windows certificate store integration
- Automatic renewal
- Windows Event Log monitoring

**Configuration:** See [workstation.toml](../examples/config/workstation.toml)

**Key Features:**

- Uses `${COMPUTERNAME}$` as username (machine account style)
- Stores certificate in `LocalMachine\My` with friendly name
- Enables Windows Event Log for centralized monitoring
- Auto-renewal 45 days before expiration
- Client certificate re-enrollment after initial HTTP Basic enrollment

### Scenario 2: Web Servers

TLS certificates for web servers with multiple DNS names.

**Requirements:**

- Multiple Subject Alternative Names (SANs)
- RSA 2048 for broad compatibility
- TPM key protection (if available)
- Longer renewal threshold to avoid service disruption

**Configuration:** See [server.toml](../examples/config/server.toml)

**Key Features:**

- Multiple DNS SANs including wildcards
- Specific IP addresses for direct access
- TPM-backed keys with attestation
- 60-day renewal threshold (earlier than workstations)
- JSON logging for SIEM integration

### Scenario 3: Kiosks and Embedded Devices

Minimal configuration for resource-constrained devices.

**Requirements:**

- Simple certificate with hostname only
- No Windows-specific features
- Low log verbosity
- Extended check intervals to reduce overhead

**Configuration:** See [kiosk.toml](../examples/config/kiosk.toml)

**Key Features:**

- Uses webpki trust (simpler deployment)
- Software key provider (no HSM required)
- Warn-level logging only
- 24-hour check interval (vs 6 hours for workstations)

### Scenario 4: Initial Bootstrap

First-time enrollment when CA certificate is unknown.

    ```toml
    [server]
    url = "https://est.newdeployment.com"
    
    [trust]
    # Bootstrap mode - TOFU with fingerprint verification
    mode = "bootstrap"
    bootstrap_fingerprint = "sha256:AB:CD:EF:01:23:45:67:89:..."
    
    [authentication]
    method = "http_basic"
    username = "bootstrap-account"
    password_source = "env:BOOTSTRAP_PASSWORD"
    
    [certificate]
    common_name = "${COMPUTERNAME}.newdeployment.com"
    ```

**Important:** After successful bootstrap, switch to `explicit` trust mode with the retrieved CA certificate. Never use `bootstrap` mode in production long-term.

## Windows Integration

### Windows Certificate Store

When `storage.windows_store` is configured, certificates are stored in the Windows certificate store instead of PEM files.

**Benefits:**

- Native Windows integration (IIS, RDP, etc. can use the certificate)
- Private key protected by Windows DPAPI
- Certificate UI visible in MMC (certlm.msc)
- Support for friendly names and certificate properties

**Implementation Status:** Phase 11.2 (planned)

### Windows CNG (Cryptography Next Generation)

When `certificate.key.provider = "cng"`, private keys are stored using Windows CNG.

**Benefits:**

- Hardware-backed key storage (if TPM available)
- Non-exportable keys (cannot be copied)
- Integration with Windows security policies
- Audit logging of key operations

**Implementation Status:** Phase 11.2 (planned)

### Trusted Platform Module (TPM)

When `certificate.key.provider = "tpm"`, private keys are stored in the TPM.

**Benefits:**

- Hardware root of trust
- Keys never leave the TPM chip
- Attestation capabilities (prove key is TPM-backed)
- Resistance to software attacks

**Requirements:**

- TPM 2.0 chip
- Windows 10/11 or Linux with tpm2-tools

**Implementation Status:** Phase 11.2 (planned)

### Windows Service

The enrollment client runs as a Windows Service for automatic background operation.

**Service Name:** `EST-Enrollment` (planned)

**Service Features:**

- Automatic startup on boot
- Runs as LocalSystem (or configured account)
- Monitors certificate expiration in background
- Integrates with Windows Event Log
- Supports service dependencies (e.g., wait for network)

**Implementation Status:** Phase 11.3 (planned)

### Windows Event Log

When `logging.windows_event_log = true`, events are written to Windows Event Log.

**Event Sources:**

- **Information**: Successful enrollment, renewal
- **Warning**: Approaching expiration, retry attempts
- **Error**: Enrollment failures, configuration errors

**Event IDs** (planned):

- 1000: Enrollment started
- 1001: Enrollment successful
- 1002: Enrollment failed
- 2000: Renewal started
- 2001: Renewal successful
- 2002: Renewal failed
- 3000: Configuration loaded
- 3001: Configuration error

**Implementation Status:** Phase 11.4 (planned)

## Auto-Enrollment Service Implementation

The EST Auto-Enrollment Windows Service (`est-autoenroll-service`) provides automated certificate lifecycle management with full enrollment and renewal workflows. This section documents the implementation details completed in Phase 12.

### Service Architecture

The service runs as a Windows background service (or console application for debugging) and performs the following operations:

1. **Startup**: Loads configuration from TOML file
2. **Initial Check**: Verifies if a valid certificate exists
3. **Enrollment**: If no certificate or expired, performs initial enrollment
4. **Monitoring Loop**: Periodically checks certificate expiration
5. **Renewal**: Automatically renews certificates before expiration
6. **Graceful Shutdown**: Stops cleanly on service stop command

### Enrollment Workflow Implementation

The [`perform_enrollment()`](../../src/bin/est-autoenroll-service.rs#L266) function implements the complete EST enrollment workflow:

#### Step 1: Machine Identity Retrieval

```rust
let identity = MachineIdentity::current()?;
```

- Retrieves Windows computer name using `GetComputerNameExW` API
- Extracts DNS domain information from Windows domain membership
- Generates suggested CN format: `COMPUTERNAME.domain.local`

#### Step 2: CSR Construction

Builds a PKCS#10 Certificate Signing Request with full configuration support:

```rust
let mut csr_builder = usg_est_client::csr::CsrBuilder::new()
    .common_name(cn)
    .organization(org)
    .organizational_unit(ou)
    .country(country)
    .state(state)
    .locality(locality);
```

**Supported Fields:**
- **Subject DN**: CN, O, OU, C, ST, L (all optional except CN)
- **Subject Alternative Names**: DNS names, IP addresses, email addresses, URIs
- **Key Usage**: Digital Signature, Key Encipherment, Key Agreement
- **Extended Key Usage**: Client Auth, Server Auth, Code Signing, Email Protection

#### Step 3: Key Pair Generation

```rust
let (csr_der, key_pair) = csr_builder.build()?;
```

- Generates RSA key pair (default: 2048-bit) using FIPS-compliant `ring` library
- Private key kept in memory during enrollment process
- Returns both CSR (DER-encoded) and key pair for later storage

#### Step 4: EST Client Creation and Enrollment

```rust
let est_config = config.to_est_client_config()?;
let client = usg_est_client::EstClient::new(est_config).await?;
let response = client.simple_enroll(&csr_der).await?;
```

- Creates EST client with configured server URL and credentials
- Supports HTTP Basic Auth or TLS client certificate authentication
- Sends CSR via HTTPS POST to `/simpleenroll` endpoint (RFC 7030 §4.2.1)
- Handles both immediate issuance and pending responses

#### Step 5: Response Handling

```rust
let cert_der = match response {
    EnrollmentResponse::Issued { certificate, .. } => certificate,
    EnrollmentResponse::Pending { retry_after } => {
        tracing::warn!("Enrollment is pending, retry after: {:?}", retry_after);
        return Err(EstError::operational("Enrollment pending, manual approval required"));
    }
};
```

- **Issued**: Certificate is ready, proceed to import
- **Pending**: Server defers decision, requires manual approval or retry

#### Step 6: Certificate Import

```rust
let store = CertStore::open_path(store_path)?;
let thumbprint = store.import_certificate(&cert_der, friendly_name)?;
```

- Imports certificate to Windows Certificate Store (default: `LocalMachine\My`)
- Sets friendly name for easy identification in Certificate Manager
- Returns SHA-1 thumbprint for reference
- Certificate is now available to Windows applications (IIS, RDP, etc.)

#### Step 7: Private Key Storage (Temporary Workaround)

```rust
if let Some(key_path) = config.storage.as_ref().and_then(|s| s.key_path.as_ref()) {
    let key_pem = key_pair.serialize_pem();
    std::fs::write(key_path, key_pem)?;
    tracing::warn!("Private key saved to disk (CNG integration not yet implemented)");
}
```

**Current Limitation**: Windows CNG integration not yet implemented (blocked on TODO #5)

**Temporary Solution**: Saves PEM-encoded private key to disk if `storage.key_path` is configured

**Future Enhancement**: Will use Windows CNG to create key container and associate private key with certificate

### Renewal Workflow Implementation

The [`perform_renewal()`](../../src/bin/est-autoenroll-service.rs#L479) function implements the complete EST renewal workflow:

#### Step 1: Certificate Retrieval

```rust
let store = CertStore::open_path(store_path)?;
let existing_cert = match store.find_by_subject(cn)? {
    Some(cert) => cert,
    None => return Err(EstError::operational("No existing certificate found")),
};
```

- Searches Windows Certificate Store by subject Common Name
- Verifies certificate is present and accessible
- Returns error if certificate not found (may need re-enrollment)

#### Step 2: Identity Extraction

```rust
let existing_cert_parsed = x509_cert::Certificate::from_der(&existing_cert.certificate)?;
let subject_cn = BootstrapClient::get_subject_cn(&existing_cert_parsed)
    .ok_or_else(|| EstError::operational("Could not extract CN from existing certificate"))?;
```

- Parses existing certificate DER encoding
- Extracts Common Name from subject DN
- Maintains identity continuity (same CN in renewed certificate)

#### Step 3: New CSR Generation

```rust
let mut csr_builder = usg_est_client::csr::CsrBuilder::new()
    .common_name(&subject_cn);
// Add all configured SANs, key usage, EKU...
let (csr_der, key_pair) = csr_builder.build()?;
```

**Security Best Practice**: Always generate a NEW key pair for renewal

- Uses same subject DN as existing certificate
- Applies current configuration for SANs and extensions (may differ from original)
- Generates fresh RSA key pair (forward secrecy)

#### Step 4: EST Re-enrollment

```rust
let client = usg_est_client::EstClient::new(est_config).await?;
let response = client.simple_reenroll(&csr_der).await?;
```

- Uses `/simplereenroll` endpoint instead of `/simpleenroll` (RFC 7030 §4.2.2)
- Authenticates with existing certificate (proves ownership)
- EST server validates existing certificate before issuing new one
- Server may apply different validation rules for re-enrollment vs initial enrollment

#### Step 5: Response Processing

```rust
let new_cert_der = match response {
    EnrollmentResponse::Issued { certificate, .. } => certificate,
    EnrollmentResponse::Pending { retry_after } => {
        tracing::warn!("Renewal is pending, retry after: {:?}", retry_after);
        return Err(EstError::operational("Renewal pending, manual approval required"));
    }
};
```

Same response handling as enrollment (Issued or Pending)

#### Step 6: Certificate Archival (Optional)

```rust
if config.storage.as_ref().map(|s| s.archive_old).unwrap_or(false) {
    tracing::info!("Archiving old certificate: {}", existing_cert.thumbprint);
    // Future: Mark certificate as archived in Windows store metadata
}
```

- Configurable via `storage.archive_old` setting
- Preserves audit trail of certificate history
- **Current Status**: Logs intent, actual archival not yet implemented

#### Step 7: New Certificate Import

```rust
let thumbprint = store.import_certificate(&new_cert_der, friendly_name)?;
tracing::info!("Renewed certificate imported: {}", thumbprint);
```

- Imports renewed certificate to same store location
- Maintains same friendly name for consistency
- New certificate replaces old certificate as current identity

#### Step 8: New Key Storage

```rust
if let Some(key_path) = config.storage.as_ref().and_then(|s| s.key_path.as_ref()) {
    let key_pem = key_pair.serialize_pem();
    std::fs::write(key_path, key_pem)?;
}
```

- Overwrites old private key file with new key
- Same limitation as enrollment: CNG integration needed

### Renewal Triggers

The service uses threshold-based renewal:

```rust
let threshold_days = config.renewal
    .as_ref()
    .and_then(|r| r.threshold_days)
    .unwrap_or(30);

if days_until_expiration <= threshold_days {
    perform_renewal(config).await?;
}
```

**Configurable Settings:**
- `renewal.threshold_days`: Days before expiration to trigger renewal (default: 30)
- `renewal.check_interval_secs`: How often to check expiration (default: 3600 seconds = 1 hour)

**Example**: With `threshold_days = 30`, a certificate expiring on Feb 15 will be renewed starting on Jan 16.

### Error Handling and Retry Logic

The service implements comprehensive error handling:

**Network Errors:**
```rust
EstError::network("Failed to connect to EST server")
```
- TLS handshake failures
- DNS resolution failures
- Connection timeouts

**Authentication Errors:**
```rust
EstError::authentication("401 Unauthorized")
```
- Invalid HTTP Basic credentials
- Expired or invalid client certificate
- EST server authorization policy rejection

**Operational Errors:**
```rust
EstError::operational("Certificate store access denied")
```
- Windows Certificate Store access denied
- Disk write failures for key storage
- Certificate parsing errors

**Pending Enrollment:**
```rust
EstError::operational("Enrollment pending, manual approval required")
```
- EST server deferred enrollment decision
- Service will retry based on `Retry-After` header
- Manual approval may be required on server side

### Example Service Configuration

Complete example for auto-enrollment service:

```toml
[est]
server = "https://est.example.mil/.well-known/est"
username = "${COMPUTERNAME}$"
password = "env:EST_PASSWORD"

[certificate]
common_name = "${COMPUTERNAME}.${USERDNSDOMAIN}"
organization = "Department of War"
organizational_unit = "IT Services"
country = "US"

[[certificate.san_dns]]
value = "${COMPUTERNAME}.${USERDNSDOMAIN}"

[[certificate.san_dns]]
value = "${COMPUTERNAME}"

[certificate.key_usage]
digital_signature = true
key_encipherment = true

[certificate.extended_key_usage]
client_auth = true
server_auth = true

[key]
algorithm = "RSA"
rsa_bits = 2048

[storage]
store = "LocalMachine\\My"
friendly_name = "EST Auto-Enrolled Certificate"
key_path = "C:\\ProgramData\\Department of War\\EST\\keys\\machine.pem"
archive_old = true

[renewal]
threshold_days = 30
check_interval_secs = 3600
```

### Running the Service

**Console Mode (for debugging):**
```powershell
est-autoenroll-service --console --config C:\ProgramData\Department of War\EST\config.toml
```

**Service Mode (production):**
```powershell
# Install service
sc.exe create EST-AutoEnroll binPath= "C:\Program Files\EST\est-autoenroll-service.exe"

# Start service
sc.exe start EST-AutoEnroll
```

**Logging:**
- Console mode: Logs to stdout with colored output
- Service mode: Logs to Windows Event Log (when implemented)
- All modes: Optional file logging via configuration

### Current Limitations

1. **Private Key Association**: CNG integration not yet implemented (TODO #5)
   - **Impact**: Private keys saved to disk instead of Windows key containers
   - **Workaround**: Use `storage.key_path` to specify secure file location
   - **Future**: Will use Windows CNG to associate key with certificate

2. **Certificate Archival**: Archival marking not yet implemented
   - **Impact**: `storage.archive_old` logs intent but doesn't mark old cert
   - **Workaround**: Old certificate is replaced by new one (standard behavior)
   - **Future**: Will set certificate store metadata for archived certs

3. **Windows Event Log**: Integration not yet implemented (TODO #11.4)
   - **Impact**: Service events not visible in Windows Event Viewer
   - **Workaround**: Use file logging or console mode
   - **Future**: Will write structured events to Windows Event Log

### Implementation Status

✅ **Completed (Phase 12.0):**
- Full enrollment workflow with machine identity integration
- Full renewal workflow with re-enrollment support
- CSR building with all configuration options
- Certificate import to Windows Certificate Store
- Private key disk storage (temporary workaround)
- Error handling and retry logic
- Configuration file support

⏳ **Planned (Future Phases):**
- Windows CNG key container integration (Phase 11.2 / TODO #5)
- Certificate archival implementation (Phase 11.2)
- Windows Event Log integration (Phase 11.4)
- Windows Service installation/management (Phase 11.3)
- Retry with exponential backoff (Phase 11.3)

## Security Considerations

### Protecting Credentials

**HTTP Basic Authentication:**

1. **Never hardcode passwords** in configuration files
2. Use `password_source = "env:VARIABLE"` and set via Group Policy or deployment script
3. Or use `password_source = "credential_manager"` for Windows Credential Manager
4. Restrict file permissions on config file (administrators only)

**Client Certificate Authentication:**

1. Use Windows certificate store with private key marked non-exportable
2. Or use TPM-backed keys that cannot be extracted
3. Protect PEM key files with strict ACLs (SYSTEM and Administrators only)

### Trust Anchor Protection

**Explicit Trust:**

1. Distribute CA certificate bundle via Group Policy or deployment automation
2. Store in protected location (e.g., `C:\ProgramData\EST\ca-bundle.pem`)
3. Set ACL to read-only for SYSTEM and Administrators
4. Verify integrity with file hash or signature

**Bootstrap Mode:**

1. **Only use for initial setup**, never in production
2. Always verify fingerprint from trusted out-of-band source
3. After bootstrap, switch to explicit trust mode
4. Delete bootstrap configuration after migration

### Network Security

1. **Always use HTTPS** (RFC 7030 requirement)
2. Enable TLS channel binding if server supports it
3. Consider network segmentation (EST server on management VLAN)
4. Use firewall rules to restrict EST client network access

### Key Protection

**Minimum Requirements:**

- Use `non_exportable = true` for Windows CNG keys
- Use `provider = "tpm"` for highest security
- Never log or display private keys
- Rotate keys on renewal (default behavior)

**Defense in Depth:**

- Combine client cert auth + HTTP Basic for two-factor enrollment
- Use short certificate lifetimes (e.g., 90 days) for frequent rotation
- Enable audit logging for key operations
- Monitor for anomalous enrollment activity

## Troubleshooting

### Configuration Validation

Run the enrollment client with `--validate-config` to check for errors:

    ```powershell
    # Windows
    est-enroll.exe --validate-config
    
    # Linux
    est-enroll --validate-config
    ```

**Common Validation Errors:**

- `server.url is required`: Missing or empty server URL
- `server.url must be HTTPS`: URL uses http:// instead of https://
- `username is required when method is http_basic`: Missing HTTP Basic credentials
- `password_source is required`: Missing password source for HTTP Basic auth

### Variable Expansion Issues

Enable debug logging to see expanded values:

    ```toml
    [logging]
    level = "debug"
    ```

Look for log entries like:

    ```
    Expanded common_name: DESKTOP-ABC123.corp.contoso.com
    ```

**Common Issues:**

- `${USERDNSDOMAIN}` is empty: Machine not joined to domain, or domain suffix not set
- `${COMPUTERNAME}` contains unexpected value: Check `COMPUTERNAME` environment variable

### Connection Failures

**Symptoms:**

- Error: "Failed to connect to EST server"
- Error: "SSL/TLS handshake failed"

**Troubleshooting:**

1. Verify EST server URL is correct and accessible:

       ```powershell
       curl https://est.example.com/.well-known/est/cacerts
       ```

2. Check trust anchor configuration:

       ```powershell
       # Verify CA bundle file exists and is valid
       openssl x509 -in C:\ProgramData\EST\ca-bundle.pem -text -noout
       ```

3. Test TLS connection:

       ```powershell
       # Windows
       Test-NetConnection -ComputerName est.example.com -Port 443
       ```

4. Check firewall and proxy settings

### Authentication Failures

**Symptoms:**

- Error: "401 Unauthorized"
- Error: "Failed to authenticate with EST server"

**Troubleshooting:**

**For HTTP Basic:**

1. Verify credentials are correct:

       ```powershell
       # Check environment variable is set
       echo $env:EST_PASSWORD
       ```

2. Test credentials manually:

       ```powershell
       $cred = Get-Credential
       Invoke-WebRequest -Uri https://est.example.com/.well-known/est/cacerts -Credential $cred
       ```

**For Client Certificate:**

1. Verify certificate exists in store or file:

       ```powershell
       # Windows Store
       Get-ChildItem Cert:\LocalMachine\My
    
       # PEM file
       openssl x509 -in client.pem -text -noout
       ```

2. Check certificate is not expired:

       ```powershell
       openssl x509 -in client.pem -noout -dates
       ```

3. Verify private key matches certificate:

       ```powershell
       # Extract public key from cert and key, compare
       openssl x509 -in client.pem -pubkey -noout > cert-pub.pem
       openssl pkey -in client.key -pubout > key-pub.pem
       diff cert-pub.pem key-pub.pem
       ```

### Enrollment Errors

**Error: "CSR generation failed"**

- Check certificate configuration (common_name, organization, etc.)
- Verify key algorithm is supported
- If using HSM: ensure key provider is accessible

**Error: "Server returned 202 Accepted"**

- Enrollment is pending manual approval on server
- Check `Retry-After` header for when to retry
- Contact EST server administrator

**Error: "Certificate parsing failed"**

- Server returned invalid response
- Enable debug logging to see raw response
- Check EST server configuration

### Renewal Issues

**Certificate Not Renewing:**

1. Check renewal is enabled:

       ```toml
       [renewal]
       enabled = true
       ```

2. Verify certificate is within renewal threshold:

       ```powershell
       # Check expiration date
       openssl x509 -in machine.pem -noout -dates
    
       # Calculate days until expiration
       # (Compare with threshold_days in config)
       ```

3. Check renewal service is running:

       ```powershell
       # Windows
       Get-Service EST-Enrollment
    
       # Linux
       systemctl status est-enrollment
       ```

4. Review logs for renewal attempts and errors

**Renewal Fails with 401:**

- Re-enrollment requires client certificate authentication
- Ensure `authentication.method = "auto"` or `"client_cert"`
- Verify current certificate is in correct location for client auth

### Performance Issues

**High CPU/Memory Usage:**

- Increase `renewal.check_interval_hours` (reduce check frequency)
- Use `logging.level = "warn"` instead of "debug" or "info"
- Check for certificate store corruption (Windows)

**Slow Enrollment:**

- Increase `server.timeout_seconds`
- Check network latency to EST server
- If using HSM: hardware crypto operations may be slow (expected)

### Log Analysis

**Enable Debug Logging:**

    ```toml
    [logging]
    level = "debug"
    path = "C:\\ProgramData\\Department of War\\EST\\logs\\debug.log"
    ```

**Key Log Events:**

- `Loading configuration from: ...` - Config file location
- `Expanded variable: ...` - Variable expansion results
- `Connecting to EST server: ...` - Connection attempts
- `HTTP status: ...` - Server responses
- `Enrollment successful` - Successful enrollment
- `Renewal triggered` - Renewal started
- `Certificate expires in X days` - Expiration monitoring

**Log Rotation:**

- Default: 10 MB max size, 5 files
- Configure via `logging.max_size_mb` and `logging.max_files`
- Old logs are automatically rotated when size limit reached

## Additional Resources

- [RFC 7030 - Enrollment over Secure Transport (EST)](https://tools.ietf.org/html/rfc7030)
- [Example Configuration Files](../examples/config/)
- [JSON Schema](../schema/est-config.schema.json)
- [API Documentation](../README.md)
- [Development Roadmap](../ROADMAP.md)

## Getting Help

For issues and questions:

1. Check [Troubleshooting](#troubleshooting) section above
2. Review example configurations in `examples/config/`
3. Enable debug logging and review logs
4. Open an issue on GitHub with:
   - Configuration file (redact sensitive values)
   - Relevant log entries
   - Error messages
   - Platform and version information
