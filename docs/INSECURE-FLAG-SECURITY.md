# Security Implementation: `--insecure` Flag Restriction

## Overview

The `--insecure` flag in the `est-enroll` CLI tool is designed for testing connectivity with servers that have invalid or self-signed TLS certificates. However, to prevent accidental misuse in production environments, the flag is **strictly restricted** to only work with the official RFC 7030 test server.

## Restriction Details

### Allowed Server

The `--insecure` flag will **only** work with:

- **Hostname**: `testrfc7030.com`
- **IP Address**: `54.70.32.33`
- **Protocol**: HTTPS only

### Validation Process

When the `--insecure` flag is used, the tool performs the following security checks:

1. **Hostname Verification**: Checks if the server hostname is `testrfc7030.com`
2. **DNS Resolution**: Resolves the hostname to verify it points to the expected IP (54.70.32.33)
3. **IP Matching**: If using the IP directly, validates it matches the allowed IP

### Security Error Messages

If the `--insecure` flag is used with any other server, users receive a detailed error message:

```
Security Error: --insecure flag is restricted to the official RFC 7030 test server only.

Allowed server: https://testrfc7030.com
Your server:    https://example.com

The --insecure flag bypasses critical TLS security checks and is restricted
to prevent accidental use in production environments.

For testing with 'example.com', use one of these secure alternatives:
1. Configure explicit trust with your CA certificate:
   [trust]
   mode = "explicit"
   ca_bundle_path = "/path/to/ca-bundle.pem"

2. Use bootstrap/TOFU mode for initial CA discovery:
   cargo run --example bootstrap -- --server https://example.com

3. Add your CA to the system trust store

For more information, see CONFIGURATION.md
```

## Design Rationale

### Why This Restriction?

1. **Prevents Production Misuse**: Developers cannot accidentally use `--insecure` with production servers
2. **Enforces Best Practices**: Forces users to properly configure trust for their own servers
3. **Clear Error Guidance**: When blocked, users receive helpful alternatives for their use case
4. **No Backdoors**: There's no way to bypass the restriction without modifying the source code

### Why Allow testrfc7030.com?

- It's the official RFC 7030 test server
- It has known certificate issues (non-standards-compliant)
- It's specifically designed for EST protocol testing
- It's a publicly known test server, not a production service

## Secure Alternatives

For testing with your own EST servers, use these methods instead of `--insecure`:

### 1. Bootstrap/TOFU Mode (Recommended)

```bash
cargo run --example bootstrap -- --server https://your-server.example.com
```

This mode:
- Disables TLS verification (like `--insecure`)
- Displays certificate fingerprints for manual verification
- Requires explicit user confirmation before trusting certificates
- Is designed for initial trust establishment

### 2. Explicit Trust Configuration

Configure your CA certificate in the config file:

```toml
[trust]
mode = "explicit"
ca_bundle_path = "/path/to/your-ca-bundle.pem"
```

Or provide it via CLI:
```bash
est-enroll check --server https://your-server.com --config your-config.toml
```

### 3. System Trust Store

Add your CA certificate to the system trust store:

**Linux:**
```bash
sudo cp your-ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

**macOS:**
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain your-ca.crt
```

**Windows:**
```powershell
Import-Certificate -FilePath your-ca.crt -CertStoreLocation Cert:\LocalMachine\Root
```

## Implementation Details

### Code Location

The validation function is implemented in `src/bin/est-enroll.rs`:

```rust
async fn validate_insecure_usage(server_url: &str) -> Result<(), Box<dyn std::error::Error>>
```

### Integration Points

The validation is called in two places:

1. **`cmd_check`**: Before performing connectivity checks
2. **`cmd_diagnose`**: Before running diagnostics

### Error Handling

- **Valid server**: Proceeds with TLS verification disabled
- **Invalid server**: Returns detailed error and exits with non-zero code
- **DNS resolution failure**: Treated as security error, rejects the request

## Testing

### Valid Usage (Should Succeed)

```bash
# Using hostname
./est-enroll check --server https://testrfc7030.com --insecure

# Using IP address
./est-enroll check --server https://54.70.32.33 --insecure

# Diagnose command
./est-enroll diagnose --server https://testrfc7030.com --insecure
```

### Invalid Usage (Should Fail)

```bash
# Production server (blocked)
./est-enroll check --server https://example.com --insecure
# Error: Security Error: --insecure flag is restricted...

# Internal server (blocked)
./est-enroll check --server https://est.internal.corp --insecure
# Error: Security Error: --insecure flag is restricted...

# Different test server (blocked)
./est-enroll check --server https://test.example.com --insecure
# Error: Security Error: --insecure flag is restricted...
```

## Maintenance Considerations

### When to Update

The allowed server list should only be updated if:

1. The RFC 7030 test server changes IP address or hostname
2. An official alternative test server is established by IETF/IANA
3. A critical security issue requires temporary exception (document in commit message)

### How to Update

Modify the constants in `validate_insecure_usage()`:

```rust
const ALLOWED_TEST_SERVER: &str = "testrfc7030.com";
const ALLOWED_TEST_IP: &str = "54.70.32.33";
```

**Note**: Any changes to these constants should be reviewed carefully and require strong justification.

## Security Audit Notes

### Threat Model

**Mitigated Threats:**
- ✅ Accidental production deployment with `--insecure`
- ✅ Copy-paste errors from documentation/scripts
- ✅ Lazy configuration (using `--insecure` instead of proper trust setup)
- ✅ Social engineering (tricking users to add `--insecure` flag)

**Remaining Considerations:**
- ⚠️ Users can still modify source code to bypass (acceptable - requires intentional action)
- ⚠️ DNS hijacking could redirect testrfc7030.com (mitigated by IP verification)
- ✅ IP spoofing not possible due to TLS handshake requirements

### Compliance

This implementation aligns with:
- **Principle of Least Privilege**: Flag only works where absolutely necessary
- **Fail-Safe Defaults**: Denies by default, allows only specific exception
- **Defense in Depth**: Multiple checks (hostname + IP verification)
- **Secure by Design**: Forces users toward secure alternatives

## Related Documentation

- [CONFIGURATION.md](../CONFIGURATION.md) - General configuration and environment variables
- [bootstrap.rs](../examples/bootstrap.rs) - Bootstrap/TOFU mode example
- [RFC 7030](https://www.rfc-editor.org/rfc/rfc7030.html) - EST protocol specification

## Version History

- **2026-01-16**: Initial implementation with testrfc7030.com restriction
  - Restricts `--insecure` to official RFC 7030 test server only
  - Validates both hostname and resolved IP address
  - Provides helpful error messages with secure alternatives
