# EST Client Configuration Guide

This document describes how to configure the EST client using environment variables and configuration files.

## Environment Variables

The EST client supports configuration through environment variables, allowing for flexible deployment across different environments without modifying code or configuration files.

### Primary Environment Variables

#### `EST_SERVER_URL`

The URL of the EST server endpoint.

**Format:** `https://hostname[:port][/path]`

**Examples:**
```bash
# Basic HTTPS endpoint
export EST_SERVER_URL="https://est.example.com"

# With custom port
export EST_SERVER_URL="https://est.example.mil:8443"

# With custom path (RFC 7030 well-known path)
export EST_SERVER_URL="https://est.example.com/.well-known/est"
```

**Usage in Examples:**

All example programs check for `EST_SERVER_URL` before falling back to defaults:

```bash
# Using environment variable
export EST_SERVER_URL="https://your-est-server.com:8443"
cargo run --example simple_enroll --features csr-gen

# Using command line argument (takes precedence)
cargo run --example simple_enroll --features csr-gen -- --server https://est.example.com

# Using default (https://testrfc7030.com:8443)
cargo run --example simple_enroll --features csr-gen
```

**Priority Order:**
1. Command-line argument (`--server`)
2. Environment variable (`EST_SERVER_URL`)
3. Default value (varies by example, typically `https://testrfc7030.com:8443`)

## Configuration Files (TOML)

Configuration files support environment variable expansion using the syntax:

```toml
# Use environment variable with fallback
url = "${EST_SERVER_URL:https://est.example.com}"

# Required environment variable (fails if not set)
url = "${EST_SERVER_URL}"
```

### Example Configuration Files

All TOML configuration files in `examples/config/` now support `EST_SERVER_URL`:

#### Server Configuration
```toml
[server]
# Configure via environment variable EST_SERVER_URL or set directly below
url = "${EST_SERVER_URL:https://est.example.com}"
ca_label = "servers"
timeout_seconds = 180
```

#### DoD Hardened Configuration
```toml
[server]
# EST server URL (HTTPS required per STIG APSC-DV-002440)
# Must be DoD-approved EST server
# Configure via environment variable EST_SERVER_URL or set directly below
url = "${EST_SERVER_URL:https://est.example.mil/.well-known/est}"
```

## Deployment Patterns

### Pattern 1: Environment-Based Configuration

Use environment variables for different deployment stages:

```bash
# Development
export EST_SERVER_URL="https://est-dev.example.com"

# Staging
export EST_SERVER_URL="https://est-staging.example.com"

# Production
export EST_SERVER_URL="https://est.example.com"
```

### Pattern 2: Docker/Container Deployment

Pass environment variables to containers:

```dockerfile
FROM rust:latest
ENV EST_SERVER_URL="https://est.example.com"
COPY . .
RUN cargo build --release
CMD ["./target/release/your-app"]
```

Or via docker-compose:

```yaml
services:
  est-client:
    image: est-client
    environment:
      - EST_SERVER_URL=https://est.example.com
```

### Pattern 3: Kubernetes Deployment

Use ConfigMaps or Secrets:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: est-config
data:
  EST_SERVER_URL: "https://est.example.com"
---
apiVersion: v1
kind: Pod
metadata:
  name: est-client
spec:
  containers:
  - name: client
    image: est-client
    envFrom:
    - configMapRef:
        name: est-config
```

### Pattern 4: Systemd Service (Linux)

```ini
[Unit]
Description=EST Auto-Enrollment Service
After=network.target

[Service]
Type=simple
Environment="EST_SERVER_URL=https://est.example.com"
ExecStart=/usr/local/bin/est-client
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

### Pattern 5: Windows Service

Set environment variables at the system level:

```powershell
# PowerShell (run as Administrator)
[System.Environment]::SetEnvironmentVariable('EST_SERVER_URL', 'https://est.example.mil', 'Machine')
```

Or in the service configuration via registry.

## Additional Environment Variables

Other environment variables may be used depending on your configuration:

### `EST_PASSWORD`

Password for HTTP Basic authentication (when using `password_source = "env:EST_PASSWORD"` in TOML):

```bash
export EST_PASSWORD="your-secure-password"
```

### Windows-Specific Variables

- `COMPUTERNAME` - Automatically expanded in TOML configs
- `USERDNSDOMAIN` - Automatically expanded in TOML configs

Example in configuration:
```toml
[certificate]
common_name = "${COMPUTERNAME}.${USERDNSDOMAIN}"
```

## Security Best Practices

1. **Never commit secrets to version control**
   - Use `.env` files locally (add to `.gitignore`)
   - Use secret management systems in production

2. **Use HTTPS only**
   - EST protocol requires TLS
   - Never use `http://` URLs in production

3. **Validate server certificates**
   - Use explicit CA trust anchors in production
   - Only use `trust_any_insecure()` for development/testing

4. **Protect configuration files**
   - Set appropriate file permissions (e.g., `chmod 600`)
   - Store in secure locations with restricted access

5. **Use least privilege**
   - Run services with minimal required permissions
   - Use dedicated service accounts

## Examples

### Running Examples with Environment Variables

```bash
# Bootstrap example
export EST_SERVER_URL="https://est.example.com"
cargo run --example bootstrap

# Simple enrollment
export EST_SERVER_URL="https://est.example.mil:8443"
cargo run --example simple_enroll --features csr-gen

# Re-enrollment with client certificate
export EST_SERVER_URL="https://est.example.com"
cargo run --example reenroll --features csr-gen -- \
  --cert /path/to/cert.pem \
  --key /path/to/key.pem
```

### Using Configuration Files

```bash
# With environment variable expansion
export EST_SERVER_URL="https://est.production.com"
est-client --config /etc/est/config.toml

# Direct configuration (no environment variable)
est-client --config /etc/est/config.toml
# (uses the default URL in the TOML file)
```

## Testing with Self-Signed or Invalid Certificates

For development and testing purposes, you can bypass TLS certificate verification using the `--insecure` flag with the `est-enroll` CLI tool.

**IMPORTANT SECURITY RESTRICTION:** The `--insecure` flag is restricted to the official RFC 7030 test server only:
- Allowed server: `https://testrfc7030.com` (IP: 54.70.32.33)
- This restriction prevents accidental use in production environments

```bash
# Check connectivity to the RFC 7030 test server (allowed)
./est-enroll check --server https://testrfc7030.com --insecure

# Using IP address directly (also allowed)
./est-enroll check --server https://54.70.32.33 --insecure

# Run full diagnostics with the test server
./est-enroll diagnose --server https://testrfc7030.com --insecure

# Attempting to use with other servers will be rejected
./est-enroll check --server https://example.com --insecure
# Error: Security Error: --insecure flag is restricted to the official RFC 7030 test server only.
```

**⚠️ WARNING:** The `--insecure` flag disables TLS certificate verification and is restricted to prevent misuse.

### For Testing with YOUR Server

If you need to test with your own EST server that has self-signed or untrusted certificates, use one of these **secure alternatives**:

1. **Bootstrap/TOFU Mode** (Recommended for initial setup):
   ```bash
   cargo run --example bootstrap -- --server https://your-server.example.com
   ```
   This allows you to manually verify and accept certificate fingerprints.

2. **Explicit Trust Configuration**:
   ```toml
   [trust]
   mode = "explicit"
   ca_bundle_path = "/path/to/your-ca-bundle.pem"
   ```

3. **Add CA to System Trust Store**:
   - Linux: Copy CA cert to `/etc/ssl/certs/` or `/usr/local/share/ca-certificates/`
   - macOS: Use Keychain Access to add CA to System keychain
   - Windows: Use Certificate Manager (certmgr.msc) to add to Trusted Root CAs

## Troubleshooting

### Environment variable not being used

Check that:
1. The variable is exported: `echo $EST_SERVER_URL`
2. The variable is available in the process environment
3. Command-line arguments aren't overriding it

### TOML parsing errors

Ensure:
1. Environment variable syntax is correct: `${VAR}` or `${VAR:default}`
2. No circular references in expansion
3. Required variables are set if no default provided

### Connection errors

Verify:
1. URL format is correct (must start with `https://`)
2. Server is reachable: `curl -v $EST_SERVER_URL/cacerts`
3. Firewall/network allows HTTPS traffic
4. TLS certificates are valid

### TLS certificate verification failures

If you see errors like "invalid peer certificate" or "certificate is not standards compliant":

1. **For production:** Ensure your EST server has a valid certificate from a trusted CA
2. **For testing:** Use the `--insecure` flag (see above) to bypass verification temporarily
3. **For internal CAs:** Configure explicit trust using CA bundle path in your config file:
   ```toml
   [trust]
   mode = "explicit"
   ca_bundle_path = "/path/to/your/ca-bundle.pem"
   ```

## Reference

For more information, see:

- [RFC 7030 - Enrollment over Secure Transport](https://www.rfc-editor.org/rfc/rfc7030.html)
- Example configurations in `examples/config/`
- Individual example source code in `examples/`
- Main README.md for general documentation
