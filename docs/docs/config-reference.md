# Configuration File Reference

This document provides a complete reference for EST client configuration files in TOML format.

## Table of Contents

1. [Overview](#overview)
2. [File Locations](#file-locations)
3. [Complete Configuration Schema](#complete-configuration-schema)
4. [Section Reference](#section-reference)
5. [Variable Expansion](#variable-expansion)
6. [Validation Rules](#validation-rules)
7. [Examples by Use Case](#examples-by-use-case)

## Overview

EST client configuration uses TOML format with support for:

- Environment variable expansion (`${VARIABLE}`)
- Cross-platform path handling
- Schema validation with JSON Schema
- Hierarchical configuration with sensible defaults

### Minimal Required Configuration

```toml
[server]
url = "https://est.example.com"

[certificate]
common_name = "device.example.com"
```

### IDE Support

Add this line at the top of configuration files for IDE autocompletion:

```toml
# yaml-language-server: $schema=../../schema/est-config.schema.json
```

## File Locations

### Default Search Paths

| Platform | Path |
|----------|------|
| Windows | `C:\ProgramData\Department of War\EST\config.toml` |
| Linux | `/etc/est/config.toml` |
| macOS | `/etc/est/config.toml` |

### Override with Environment Variable

```bash
# Windows
set EST_CONFIG_PATH=C:\custom\path\config.toml

# Linux/macOS
export EST_CONFIG_PATH=/custom/path/config.toml
```

### Command Line Override

```bash
est-enroll --config /path/to/config.toml
```

## Complete Configuration Schema

```toml
# =============================================================================
# EST Client Configuration Reference
# =============================================================================

# -----------------------------------------------------------------------------
# Server Configuration
# -----------------------------------------------------------------------------
[server]
# EST server URL (required, must be HTTPS for production)
url = "https://est.example.com"

# Optional CA label for multi-CA deployments
# Changes endpoints from /.well-known/est/{operation} to
# /.well-known/est/{ca_label}/{operation}
ca_label = ""

# Request timeout in seconds (default: 60)
timeout_seconds = 60

# Enable TLS channel binding (RFC 7030 Section 3.5)
# Places tls-unique value in CSR challenge-password field
channel_binding = false

# -----------------------------------------------------------------------------
# Trust Anchor Configuration
# -----------------------------------------------------------------------------
[trust]
# Trust mode: "webpki", "explicit", "bootstrap", "insecure"
# - webpki: Mozilla root CA store (default)
# - explicit: Use specific CA certificates
# - bootstrap: Trust-On-First-Use with fingerprint verification
# - insecure: Accept any certificate (TESTING ONLY)
mode = "webpki"

# Path to CA certificate bundle (PEM format)
# Required when mode = "explicit"
ca_bundle_path = ""

# Expected CA fingerprint for bootstrap mode
# Format: "sha256:XX:XX:XX..." (colon-separated hex)
bootstrap_fingerprint = ""

# -----------------------------------------------------------------------------
# Authentication Configuration
# -----------------------------------------------------------------------------
[authentication]
# Authentication method: "none", "http_basic", "client_cert", "auto"
# - none: No authentication (rarely used)
# - http_basic: Username/password
# - client_cert: TLS client certificate (mutual TLS)
# - auto: Try client_cert, fallback to http_basic
method = "auto"

# HTTP Basic Authentication
username = ""
# Password source: "env:VARIABLE", "file:/path", "credential_manager"
password_source = ""

# Client Certificate Authentication (Windows)
cert_store = ""        # e.g., "LocalMachine\\My"
cert_thumbprint = ""   # "auto" or specific thumbprint

# Client Certificate Authentication (PEM files)
cert_path = ""         # Path to certificate PEM
key_path = ""          # Path to private key PEM

# -----------------------------------------------------------------------------
# Certificate Request Configuration
# -----------------------------------------------------------------------------
[certificate]
# Subject Distinguished Name (common_name is required)
common_name = ""
organization = ""
organizational_unit = ""
country = ""           # ISO 3166-1 alpha-2 code
state = ""
locality = ""

# Subject Alternative Names
[certificate.san]
dns = []               # DNS names: ["host.example.com", "alias.example.com"]
ip = []                # IP addresses: ["192.168.1.100"]
email = []             # Email addresses: ["admin@example.com"]
uri = []               # URIs: ["https://example.com/"]
include_ip = false     # Auto-detect local IPs

# Key Configuration
[certificate.key]
# Algorithm: "ecdsa-p256", "ecdsa-p384", "rsa-2048", "rsa-3072", "rsa-4096"
algorithm = "ecdsa-p256"

# Provider: "software", "cng", "tpm", "pkcs11"
provider = "software"

# Mark private key as non-exportable (CNG/TPM only)
non_exportable = false

# Enable TPM key attestation
attestation = false

# PKCS#11 configuration (when provider = "pkcs11")
pkcs11_library = ""    # Path to PKCS#11 library
pkcs11_slot = 0        # Slot ID (or -1 for auto-select)
pkcs11_pin_source = "" # "env:PIN_VAR" or "file:/path"

# Certificate Extensions
[certificate.extensions]
# Key usage flags
key_usage = ["digital_signature"]

# Extended key usage OIDs or short names
extended_key_usage = ["client_auth"]

# Custom extensions (OID = value pairs)
# custom = { "2.5.29.99" = "custom value" }

# -----------------------------------------------------------------------------
# Renewal Configuration
# -----------------------------------------------------------------------------
[renewal]
# Enable automatic renewal
enabled = false

# Days before expiration to trigger renewal
threshold_days = 30

# Hours between expiration checks
check_interval_hours = 6

# Maximum retry attempts before giving up
max_retries = 5

# Base delay between retries (minutes)
# Actual delay uses exponential backoff
retry_delay_minutes = 30

# Jitter percentage (0-100) to randomize retry timing
jitter_percent = 20

# -----------------------------------------------------------------------------
# Storage Configuration
# -----------------------------------------------------------------------------
[storage]
# Windows Certificate Store (Windows only)
windows_store = ""     # e.g., "LocalMachine\\My"
friendly_name = ""     # Certificate friendly name

# PEM File Storage (cross-platform)
cert_path = ""         # Output certificate path
key_path = ""          # Output private key path
chain_path = ""        # Output certificate chain path

# Archive old certificates before replacement
archive_old = false
archive_path = ""      # Archive directory

# File permissions (Unix only, octal)
cert_mode = "0644"
key_mode = "0600"

# -----------------------------------------------------------------------------
# Logging Configuration
# -----------------------------------------------------------------------------
[logging]
# Log level: "trace", "debug", "info", "warn", "error"
level = "info"

# Log file path (leave empty for no file logging)
path = ""

# Enable Windows Event Log (Windows only)
windows_event_log = false

# Enable JSON formatted logging (for log aggregation)
json_format = false

# Log rotation
max_size_mb = 10       # Max size before rotation
max_files = 5          # Number of rotated files to keep

# Include timestamps in logs
timestamps = true

# Include source location in debug logs
source_location = false

# -----------------------------------------------------------------------------
# Windows Service Configuration (Windows only)
# -----------------------------------------------------------------------------
[service]
# Service start type: "automatic", "delayed", "manual", "disabled"
start_type = "automatic"

# Service account
# Options: "LocalSystem", "NetworkService", "LocalService", "DOMAIN\\User"
run_as = "LocalSystem"

# Service dependencies (services that must start first)
dependencies = []      # e.g., ["Tcpip", "Dnscache"]

# Health check HTTP port (0 = disabled)
health_check_port = 0

# Recovery actions: "restart", "none"
recovery_action = "restart"
recovery_delay_seconds = 60

# -----------------------------------------------------------------------------
# Metrics Configuration (optional)
# -----------------------------------------------------------------------------
[metrics]
# Enable metrics collection
enabled = false

# Prometheus metrics endpoint port (0 = disabled)
prometheus_port = 0

# StatsD server address
statsd_address = ""

# Metrics prefix
prefix = "est_client"

# -----------------------------------------------------------------------------
# Proxy Configuration (optional)
# -----------------------------------------------------------------------------
[proxy]
# HTTP proxy URL
http_proxy = ""

# HTTPS proxy URL
https_proxy = ""

# No proxy list (comma-separated)
no_proxy = ""

# Proxy authentication
proxy_username = ""
proxy_password_source = ""  # "env:VAR" or "file:/path"
```

## Section Reference

### [server]

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `url` | string | Yes | - | EST server URL (must be HTTPS) |
| `ca_label` | string | No | "" | CA label for multi-CA servers |
| `timeout_seconds` | integer | No | 60 | HTTP request timeout |
| `channel_binding` | boolean | No | false | Enable TLS channel binding |

### [trust]

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `mode` | string | No | "webpki" | Trust mode |
| `ca_bundle_path` | string | Conditional | - | Required if mode="explicit" |
| `bootstrap_fingerprint` | string | Conditional | - | Required if mode="bootstrap" |

**Trust Modes:**

| Mode | Security | Use Case |
|------|----------|----------|
| `webpki` | High | Public EST servers with public CA |
| `explicit` | High | Enterprise CAs, private PKI |
| `bootstrap` | Medium | Initial setup only, requires fingerprint |
| `insecure` | None | Testing only, never production |

### [authentication]

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `method` | string | No | "auto" | Authentication method |
| `username` | string | Conditional | - | HTTP Basic username |
| `password_source` | string | Conditional | - | Password location |
| `cert_store` | string | No | - | Windows cert store |
| `cert_thumbprint` | string | No | - | Certificate thumbprint |
| `cert_path` | string | No | - | PEM certificate file |
| `key_path` | string | No | - | PEM private key file |

**Password Sources:**

| Format | Example | Description |
|--------|---------|-------------|
| `env:VAR` | `env:EST_PASSWORD` | Read from environment variable |
| `file:/path` | `file:/etc/est/password` | Read first line of file |
| `credential_manager` | `credential_manager` | Windows Credential Manager |

### [certificate]

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `common_name` | string | Yes | - | Certificate CN |
| `organization` | string | No | - | O field |
| `organizational_unit` | string | No | - | OU field |
| `country` | string | No | - | C field (2-letter ISO code) |
| `state` | string | No | - | ST field |
| `locality` | string | No | - | L field |

### [certificate.san]

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `dns` | string[] | No | [] | DNS Subject Alternative Names |
| `ip` | string[] | No | [] | IP Subject Alternative Names |
| `email` | string[] | No | [] | Email Subject Alternative Names |
| `uri` | string[] | No | [] | URI Subject Alternative Names |
| `include_ip` | boolean | No | false | Auto-detect local IPs |

### [certificate.key]

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `algorithm` | string | No | "ecdsa-p256" | Key algorithm |
| `provider` | string | No | "software" | Key storage provider |
| `non_exportable` | boolean | No | false | Prevent key export |
| `attestation` | boolean | No | false | TPM attestation |

**Key Algorithms:**

| Algorithm | Key Size | Performance | Security |
|-----------|----------|-------------|----------|
| `ecdsa-p256` | 256-bit | Fast | High |
| `ecdsa-p384` | 384-bit | Medium | Very High |
| `rsa-2048` | 2048-bit | Slow | Medium |
| `rsa-3072` | 3072-bit | Slower | High |
| `rsa-4096` | 4096-bit | Slowest | Very High |

**Key Providers:**

| Provider | Platform | Security | Notes |
|----------|----------|----------|-------|
| `software` | All | Medium | In-memory keys |
| `cng` | Windows | High | Windows CNG |
| `tpm` | All* | Very High | Hardware TPM |
| `pkcs11` | All | Very High | HSM |

### [certificate.extensions]

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `key_usage` | string[] | No | ["digital_signature"] | Key usage flags |
| `extended_key_usage` | string[] | No | ["client_auth"] | EKU OIDs |

**Key Usage Values:**

- `digital_signature`
- `non_repudiation`
- `key_encipherment`
- `data_encipherment`
- `key_agreement`
- `key_cert_sign`
- `crl_sign`
- `encipher_only`
- `decipher_only`

**Extended Key Usage Values:**

| Short Name | OID |
|------------|-----|
| `server_auth` | 1.3.6.1.5.5.7.3.1 |
| `client_auth` | 1.3.6.1.5.5.7.3.2 |
| `code_signing` | 1.3.6.1.5.5.7.3.3 |
| `email_protection` | 1.3.6.1.5.5.7.3.4 |
| `time_stamping` | 1.3.6.1.5.5.7.3.8 |
| `ocsp_signing` | 1.3.6.1.5.5.7.3.9 |
| `smart_card_logon` | 1.3.6.1.4.1.311.20.2.2 |

### [renewal]

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `enabled` | boolean | No | false | Enable auto-renewal |
| `threshold_days` | integer | No | 30 | Days before expiry to renew |
| `check_interval_hours` | integer | No | 6 | Hours between checks |
| `max_retries` | integer | No | 5 | Max retry attempts |
| `retry_delay_minutes` | integer | No | 30 | Base retry delay |
| `jitter_percent` | integer | No | 20 | Retry timing jitter |

### [storage]

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `windows_store` | string | No | - | Windows cert store path |
| `friendly_name` | string | No | - | Certificate friendly name |
| `cert_path` | string | No | - | PEM certificate output |
| `key_path` | string | No | - | PEM key output |
| `chain_path` | string | No | - | PEM chain output |
| `archive_old` | boolean | No | false | Archive before replace |

### [logging]

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `level` | string | No | "info" | Log level |
| `path` | string | No | - | Log file path |
| `windows_event_log` | boolean | No | false | Windows Event Log |
| `json_format` | boolean | No | false | JSON output |
| `max_size_mb` | integer | No | 10 | Max log file size |
| `max_files` | integer | No | 5 | Rotated files to keep |

### [service]

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `start_type` | string | No | "automatic" | Service start type |
| `run_as` | string | No | "LocalSystem" | Service account |
| `dependencies` | string[] | No | [] | Service dependencies |
| `health_check_port` | integer | No | 0 | Health check port |

## Variable Expansion

### Supported Variables

| Variable | Windows | Linux/macOS |
|----------|---------|-------------|
| `${COMPUTERNAME}` | Computer name | hostname |
| `${USERDNSDOMAIN}` | DNS domain | /etc/resolv.conf |
| `${USERDOMAIN}` | NetBIOS domain | - |
| `${USERNAME}` | Current user | Current user |
| `${HOME}` | `USERPROFILE` | `$HOME` |
| `${PROGRAMDATA}` | `ProgramData` | `/var/lib` |
| `${TEMP}` | Temp directory | `/tmp` |

### Expansion Examples

```toml
[certificate]
# Expands to: DESKTOP-ABC123.corp.contoso.com
common_name = "${COMPUTERNAME}.${USERDNSDOMAIN}"

[certificate.san]
# Expands to: ["DESKTOP-ABC123.corp.contoso.com", "DESKTOP-ABC123"]
dns = ["${COMPUTERNAME}.${USERDNSDOMAIN}", "${COMPUTERNAME}"]

[authentication]
# Machine account style username
username = "${COMPUTERNAME}$"
```

### Custom Environment Variables

Any environment variable can be referenced:

```toml
[certificate]
organization = "${MY_ORG_NAME}"

[authentication]
username = "${DEVICE_ID}"
```

## Validation Rules

### URL Validation

- Must be a valid URL format
- Must use HTTPS for production (HTTP only allowed in insecure mode)
- Port is optional (defaults to 443)

### Path Validation

- Must be absolute paths
- Parent directory must exist (for output paths)
- Must have appropriate permissions

### Certificate Validation

- `common_name` is required
- `country` must be 2-letter ISO 3166-1 alpha-2 code
- Key algorithm must be supported
- Extensions must use valid OIDs or short names

### Renewal Validation

- `threshold_days` must be positive
- `check_interval_hours` must be at least 1
- `jitter_percent` must be 0-100

## Examples by Use Case

### Domain Workstation

```toml
[server]
url = "https://est.corp.contoso.com"

[trust]
mode = "explicit"
ca_bundle_path = "C:\\ProgramData\\EST\\ca-bundle.pem"

[authentication]
method = "http_basic"
username = "${COMPUTERNAME}$"
password_source = "env:EST_PASSWORD"

[certificate]
common_name = "${COMPUTERNAME}.${USERDNSDOMAIN}"
organization = "Contoso Corporation"
organizational_unit = "Workstations"

[certificate.san]
dns = ["${COMPUTERNAME}.${USERDNSDOMAIN}", "${COMPUTERNAME}"]

[certificate.key]
algorithm = "ecdsa-p256"
provider = "cng"
non_exportable = true

[certificate.extensions]
key_usage = ["digital_signature", "key_encipherment"]
extended_key_usage = ["client_auth"]

[renewal]
enabled = true
threshold_days = 45
check_interval_hours = 6

[storage]
windows_store = "LocalMachine\\My"
friendly_name = "Domain Workstation Certificate"

[logging]
level = "info"
windows_event_log = true
```

### Web Server

```toml
[server]
url = "https://est.example.com"
ca_label = "servers"

[trust]
mode = "explicit"
ca_bundle_path = "/etc/est/ca-bundle.pem"

[authentication]
method = "client_cert"
cert_path = "/etc/est/client.pem"
key_path = "/etc/est/client.key"

[certificate]
common_name = "www.example.com"
organization = "Example Corp"
country = "US"

[certificate.san]
dns = ["www.example.com", "example.com", "*.example.com"]
ip = ["203.0.113.50"]

[certificate.key]
algorithm = "rsa-2048"
provider = "software"

[certificate.extensions]
key_usage = ["digital_signature", "key_encipherment"]
extended_key_usage = ["server_auth"]

[renewal]
enabled = true
threshold_days = 60
check_interval_hours = 12

[storage]
cert_path = "/etc/ssl/certs/server.pem"
key_path = "/etc/ssl/private/server.key"
chain_path = "/etc/ssl/certs/chain.pem"
```

### IoT Device

```toml
[server]
url = "https://est.iot.example.com"
timeout_seconds = 30

[trust]
mode = "explicit"
ca_bundle_path = "/opt/device/ca.pem"

[authentication]
method = "http_basic"
username = "${DEVICE_ID}"
password_source = "file:/opt/device/credentials"

[certificate]
common_name = "${DEVICE_ID}.iot.example.com"

[certificate.key]
algorithm = "ecdsa-p256"
provider = "tpm"
attestation = true

[renewal]
enabled = true
threshold_days = 14
check_interval_hours = 24

[storage]
cert_path = "/opt/device/cert.pem"
key_path = "/opt/device/key.pem"

[logging]
level = "warn"
path = "/var/log/est-client.log"
max_size_mb = 5
max_files = 2
```

### HSM-Protected Key

```toml
[server]
url = "https://est.secure.example.com"

[trust]
mode = "explicit"
ca_bundle_path = "/etc/pki/ca-bundle.pem"

[authentication]
method = "client_cert"
cert_path = "/etc/pki/client.pem"
key_path = "/etc/pki/client.key"

[certificate]
common_name = "secure-server.example.com"
organization = "Example Corp"
organizational_unit = "Security"

[certificate.key]
algorithm = "ecdsa-p256"
provider = "pkcs11"
pkcs11_library = "/usr/lib/softhsm/libsofthsm2.so"
pkcs11_slot = 0
pkcs11_pin_source = "env:HSM_PIN"

[storage]
cert_path = "/etc/pki/server.pem"
# Key stays in HSM, no key_path needed
```

## Related Documentation

- [Windows Enrollment Guide](windows-enrollment.md) - Complete Windows setup
- [Configuration Guide](configuration.md) - API configuration options
- [Security Considerations](security.md) - Security best practices
- [Troubleshooting](troubleshooting.md) - Common issues and solutions
