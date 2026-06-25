# Troubleshooting Guide

This guide covers common issues and solutions when using the EST client.

## Table of Contents

1. [Quick Diagnostics](#quick-diagnostics)
2. [Configuration Issues](#configuration-issues)
3. [Connection Issues](#connection-issues)
4. [Authentication Issues](#authentication-issues)
5. [Certificate Issues](#certificate-issues)
6. [Renewal Issues](#renewal-issues)
7. [Platform-Specific Issues](#platform-specific-issues)
8. [Error Reference](#error-reference)
9. [Diagnostic Commands](#diagnostic-commands)
10. [Getting Help](#getting-help)

## Quick Diagnostics

### First Steps

Run these commands to quickly diagnose issues:

```bash
# Validate configuration
est-enroll --validate-config

# Test connectivity
est-enroll --test-connection

# Verbose enrollment attempt
est-enroll --enroll --verbose
```

### Common Quick Fixes

| Symptom | Quick Fix |
|---------|-----------|
| "Configuration file not found" | Set `EST_CONFIG_PATH` environment variable |
| "Failed to connect" | Check network, proxy, firewall |
| "401 Unauthorized" | Verify username/password |
| "Certificate verification failed" | Check `ca_bundle_path` |
| "Certificate expired" | Trigger manual renewal |

## Configuration Issues

### Config File Not Found

**Symptom:**

```text
Error: Configuration file not found at default locations
```

**Solution:**

1. Check file exists at expected location:
   - Windows: `C:\ProgramData\Department of War\EST\config.toml`
   - Linux: `/etc/est/config.toml`

2. Set explicit path:

   ```bash
   export EST_CONFIG_PATH=/path/to/config.toml
   est-enroll --enroll
   ```

3. Verify file permissions:

   ```bash
   # Linux
   ls -la /etc/est/config.toml
   # Should be readable by the user running est-enroll
   ```

### Invalid TOML Syntax

**Symptom:**

```text
Error: Failed to parse configuration: TOML syntax error at line 15
```

**Solution:**

1. Validate TOML syntax:

   ```bash
   # Install toml-cli if needed
   cargo install toml-cli
   toml check /etc/est/config.toml
   ```

2. Common TOML mistakes:

   ```toml
   # Wrong: Missing quotes
   url = https://est.example.com

   # Correct:
   url = "https://est.example.com"

   # Wrong: Backslashes in strings (Windows paths)
   ca_bundle_path = "C:\ProgramData\EST\ca.pem"

   # Correct: Escape backslashes or use forward slashes
   ca_bundle_path = "C:\\ProgramData\\EST\\ca.pem"
   ca_bundle_path = "C:/ProgramData/EST/ca.pem"
   ```

### Variable Expansion Failures

**Symptom:**

```text
common_name expanded to: ${USERDNSDOMAIN}  (literal text, not expanded)
```

**Solution:**

1. Verify environment variables exist:

   ```powershell
   # Windows
   $env:USERDNSDOMAIN
   $env:COMPUTERNAME

   # Linux
   echo $HOSTNAME
   ```

2. For domain suffix on Linux:

   ```bash
   # Check resolv.conf
   cat /etc/resolv.conf

   # Set manually if needed
   export USERDNSDOMAIN=$(hostname -d)
   ```

3. Use fallback values:

   ```toml
   # If domain unknown, use explicit value
   common_name = "${COMPUTERNAME}.example.com"
   ```

### Missing Required Fields

**Symptom:**

```text
Error: Missing required field: server.url
```

**Solution:**

Ensure all required fields are present:

```toml
# Minimum required configuration
[server]
url = "https://est.example.com"  # Required

[certificate]
common_name = "device.example.com"  # Required
```

## Connection Issues

### Cannot Connect to Server

**Symptom:**

```text
Error: Failed to connect to EST server: Connection refused
```

**Solutions:**

1. **Verify server URL:**

   ```bash
   curl -v https://est.example.com/.well-known/est/cacerts
   ```

2. **Check DNS resolution:**

   ```bash
   nslookup est.example.com
   dig est.example.com
   ```

3. **Test port connectivity:**

   ```bash
   # Linux
   nc -zv est.example.com 443

   # Windows
   Test-NetConnection -ComputerName est.example.com -Port 443
   ```

4. **Check firewall rules:**

   ```bash
   # Linux (iptables)
   iptables -L -n | grep 443

   # Windows
   Get-NetFirewallRule | Where-Object {$_.Action -eq "Block"}
   ```

### Timeout Errors

**Symptom:**

```text
Error: Request timed out after 60 seconds
```

**Solutions:**

1. **Increase timeout:**

   ```toml
   [server]
   timeout_seconds = 120
   ```

2. **Check network latency:**

   ```bash
   ping est.example.com
   traceroute est.example.com
   ```

3. **Verify proxy settings:**

   ```toml
   [proxy]
   https_proxy = "http://proxy.example.com:8080"
   ```

### TLS/SSL Errors

**Symptom:**

```text
Error: SSL certificate problem: unable to get local issuer certificate
```

**Solutions:**

1. **Provide CA certificate:**

   ```toml
   [trust]
   mode = "explicit"
   ca_bundle_path = "/etc/est/ca-bundle.pem"
   ```

2. **Verify CA certificate is valid:**

   ```bash
   openssl x509 -in /etc/est/ca-bundle.pem -text -noout

   # Check expiration
   openssl x509 -in /etc/est/ca-bundle.pem -noout -dates
   ```

3. **Test TLS connection:**

   ```bash
   openssl s_client -connect est.example.com:443 -CAfile /etc/est/ca-bundle.pem
   ```

4. **Check certificate chain:**

   ```bash
   openssl s_client -connect est.example.com:443 -showcerts < /dev/null
   ```

### Proxy Issues

**Symptom:**

```text
Error: Failed to connect through proxy
```

**Solutions:**

1. **Configure proxy:**

   ```toml
   [proxy]
   https_proxy = "http://proxy.example.com:8080"
   no_proxy = "localhost,127.0.0.1,.internal.example.com"
   ```

2. **With authentication:**

   ```toml
   [proxy]
   https_proxy = "http://proxy.example.com:8080"
   proxy_username = "user"
   proxy_password_source = "env:PROXY_PASSWORD"
   ```

3. **Test proxy connection:**

   ```bash
   curl -v --proxy http://proxy.example.com:8080 https://est.example.com/
   ```

## Authentication Issues

### 401 Unauthorized

**Symptom:**

```text
Error: 401 Unauthorized - Authentication required
```

**Solutions:**

1. **Verify credentials:**

   ```toml
   [authentication]
   method = "http_basic"
   username = "estuser"
   password_source = "env:EST_PASSWORD"
   ```

   ```bash
   # Check password is set
   echo $EST_PASSWORD
   ```

2. **Test credentials manually:**

   ```bash
   curl -u estuser:password https://est.example.com/.well-known/est/cacerts
   ```

3. **Check password source:**

   ```bash
   # If using file:
   cat /etc/est/password.txt

   # Ensure no trailing newline or whitespace
   cat -A /etc/est/password.txt
   ```

### Client Certificate Authentication Failures

**Symptom:**

```text
Error: SSL client certificate error
```

**Solutions:**

1. **Verify certificate and key match:**

   ```bash
   # Get certificate public key hash
   openssl x509 -in client.pem -pubkey -noout | openssl md5

   # Get key public key hash
   openssl pkey -in client.key -pubout | openssl md5

   # Hashes should match
   ```

2. **Check certificate validity:**

   ```bash
   openssl x509 -in client.pem -noout -dates
   openssl x509 -in client.pem -noout -checkend 0
   ```

3. **Verify key is not encrypted (or provide password):**

   ```bash
   # Check if key is encrypted
   head -1 client.key
   # If it contains "ENCRYPTED", you need to decrypt or provide password
   ```

4. **Windows certificate store:**

   ```powershell
   # List certificates
   Get-ChildItem Cert:\LocalMachine\My

   # Check private key association
   $cert = Get-ChildItem Cert:\LocalMachine\My\<thumbprint>
   $cert.HasPrivateKey
   ```

### Windows Credential Manager Issues

**Symptom:**

```text
Error: Failed to retrieve credentials from Windows Credential Manager
```

**Solutions:**

1. **Add credential manually:**

   ```powershell
   # Using cmdkey
   cmdkey /generic:EST-Enrollment /user:estuser /pass:password

   # Verify
   cmdkey /list:EST-Enrollment
   ```

2. **Check service account permissions:**
   - Credentials are user-specific
   - Service account may need its own credentials

## Certificate Issues

### CSR Generation Failures

**Symptom:**

```text
Error: Failed to generate CSR
```

**Solutions:**

1. **Check key algorithm support:**

   ```toml
   [certificate.key]
   # Try software provider first
   provider = "software"
   algorithm = "ecdsa-p256"
   ```

2. **Verify subject fields:**

   ```toml
   [certificate]
   # Country must be 2-letter code
   country = "US"  # Not "United States"
   ```

3. **Check TPM availability:**

   ```powershell
   # Windows
   Get-TPM

   # Linux
   ls /dev/tpm*
   ```

### Certificate Parsing Errors

**Symptom:**

```text
Error: Failed to parse certificate from server response
```

**Solutions:**

1. **Enable verbose logging:**

   ```toml
   [logging]
   level = "debug"
   ```

2. **Check server response:**

   ```bash
   curl -v -u user:pass https://est.example.com/.well-known/est/cacerts | base64 -d | openssl pkcs7 -inform DER -print_certs
   ```

3. **Contact EST server administrator** if response is malformed

### Certificate Storage Failures

**Symptom:**

```text
Error: Failed to store certificate in Windows certificate store
```

**Solutions:**

1. **Check permissions:**

   ```powershell
   # Run as Administrator for LocalMachine store
   Start-Process est-enroll -Verb RunAs
   ```

2. **Verify store exists:**

   ```powershell
   Get-ChildItem Cert:\LocalMachine\My
   ```

3. **Check Windows crypto service:**

   ```powershell
   Get-Service CryptSvc
   ```

### Duplicate Certificates

**Symptom:**
Multiple certificates with same subject in store

**Solutions:**

1. **Enable archiving:**

   ```toml
   [storage]
   archive_old = true
   archive_path = "C:\\ProgramData\\EST\\archive"
   ```

2. **Manual cleanup:**

   ```powershell
   # View duplicates
   Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -like "*EST*"}

   # Remove old certificates (keep most recent)
   $certs = Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -like "*EST*"} | Sort-Object NotAfter -Descending
   $certs | Select-Object -Skip 1 | Remove-Item
   ```

## Renewal Issues

### Renewal Not Triggering

**Symptom:**
Certificate approaching expiration but not renewing

**Solutions:**

1. **Verify renewal is enabled:**

   ```toml
   [renewal]
   enabled = true
   threshold_days = 30
   check_interval_hours = 6
   ```

2. **Check current certificate expiration:**

   ```powershell
   $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.FriendlyName -like "*EST*"}
   $daysRemaining = ($cert.NotAfter - (Get-Date)).Days
   Write-Host "Days until expiration: $daysRemaining"
   ```

3. **Verify service is running:**

   ```powershell
   Get-Service EST-Enrollment
   ```

4. **Force renewal check:**

   ```bash
   est-enroll --check-renewal --verbose
   ```

### Renewal Authentication Failures

**Symptom:**

```text
Error: Re-enrollment failed: 401 Unauthorized
```

**Solutions:**

1. **Use auto authentication method:**

   ```toml
   [authentication]
   method = "auto"  # Uses current cert for re-enrollment
   ```

2. **Verify current certificate is valid:**

   ```bash
   openssl x509 -in /etc/est/machine.pem -noout -checkend 0
   ```

3. **Check certificate can be used for client auth:**

   ```bash
   openssl x509 -in /etc/est/machine.pem -noout -purpose
   # Should show "SSL client : Yes"
   ```

### Renewal Loop / Constant Renewal

**Symptom:**
Certificate renews repeatedly or immediately after renewal

**Solutions:**

1. **Check renewal threshold:**

   ```toml
   [renewal]
   # Ensure threshold is less than certificate validity period
   threshold_days = 30  # If cert is valid for 90 days, this is fine
   ```

2. **Check server certificate validity period:**

   ```bash
   # The issued certificate should have longer validity than threshold
   openssl x509 -in /etc/est/machine.pem -noout -dates
   ```

3. **Review logs for errors:**

   ```bash
   tail -f /var/log/est-client.log
   ```

## Platform-Specific Issues

### Windows

**Service Won't Start:**

```powershell
# Check event log
Get-EventLog -LogName Application -Source EST-Enrollment -Newest 10

# Check service dependencies
sc qc EST-Enrollment

# Verify executable path
(Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\EST-Enrollment").ImagePath
```

**Access Denied to Certificate Store:**

```powershell
# Check if running with sufficient privileges
whoami /priv

# For LocalMachine store, need SYSTEM or elevated Administrator
```

**TPM Errors:**

```powershell
# Check TPM status
Get-TPM

# Clear TPM (warning: destructive!)
# Clear-TPM

# Initialize TPM
Initialize-TPM
```

### Linux

**Permission Denied:**

```bash
# Check file permissions
ls -la /etc/est/
ls -la /var/lib/est/

# Fix ownership
sudo chown -R est-enroll:est-enroll /etc/est/
sudo chmod 600 /etc/est/config.toml
```

**SELinux Issues:**

```bash
# Check for SELinux denials
sudo ausearch -m avc -ts recent

# Create policy if needed
sudo audit2allow -a -M est-enroll
sudo semodule -i est-enroll.pp
```

**systemd Service Issues:**

```bash
# Check service status
systemctl status est-enroll

# View logs
journalctl -u est-enroll -f

# Check unit file
systemctl cat est-enroll
```

### macOS

**Keychain Access:**

```bash
# Check keychain access
security list-keychains

# Verify certificate in keychain
security find-certificate -c "EST" -a

# Trust issues
security verify-cert -c /etc/est/machine.pem
```

**Network Extension Permissions:**

```bash
# Check System Preferences → Security & Privacy → Privacy → Network
# EST client may need explicit network access
```

## Error Reference

### Error Codes

| Code | Message | Cause | Solution |
|------|---------|-------|----------|
| E001 | Configuration not found | Config file missing | Set EST_CONFIG_PATH |
| E002 | Invalid configuration | TOML syntax error | Validate config syntax |
| E003 | Connection refused | Server unreachable | Check network/firewall |
| E004 | Connection timeout | Slow network | Increase timeout |
| E005 | TLS handshake failed | Certificate mismatch | Check CA bundle |
| E006 | 401 Unauthorized | Bad credentials | Verify username/password |
| E007 | 403 Forbidden | No permission | Check server ACLs |
| E008 | 404 Not Found | Wrong endpoint | Check server URL |
| E009 | 500 Server Error | Server issue | Contact server admin |
| E010 | CSR generation failed | Key error | Check key config |
| E011 | Certificate parse error | Invalid response | Check server response |
| E012 | Storage failed | Permission denied | Check store permissions |

### Common EstError Variants

```rust
EstError::TlsConfig       // TLS configuration issue
EstError::Http            // HTTP transport error
EstError::ServerError     // Server returned error status
EstError::AuthenticationRequired  // 401 response
EstError::EnrollmentPending  // 202 response (retry later)
EstError::NotSupported    // 501 response
EstError::CmsParsing      // Failed to parse PKCS#7
EstError::Base64          // Base64 decode error
EstError::Config          // Configuration error
```

## Diagnostic Commands

### Full Diagnostic Script

```bash
#!/bin/bash
# EST Client Diagnostic Script

echo "=== EST Client Diagnostics ==="
echo

echo "--- Configuration ---"
est-enroll --validate-config 2>&1
echo

echo "--- Connection Test ---"
est-enroll --test-connection 2>&1
echo

echo "--- Certificate Status ---"
est-enroll --check-cert 2>&1
echo

echo "--- Renewal Status ---"
est-enroll --check-renewal 2>&1
echo

echo "--- Environment ---"
echo "COMPUTERNAME: $COMPUTERNAME"
echo "USERDNSDOMAIN: $USERDNSDOMAIN"
echo "EST_CONFIG_PATH: $EST_CONFIG_PATH"
echo

echo "--- Network ---"
ping -c 3 $(grep 'url' /etc/est/config.toml | cut -d'"' -f2 | sed 's|https://||' | cut -d'/' -f1) 2>&1
echo

echo "--- Certificate Store ---"
openssl x509 -in /etc/est/machine.pem -noout -subject -dates 2>&1 || echo "No certificate found"
echo

echo "--- Logs (last 20 lines) ---"
tail -20 /var/log/est-client.log 2>/dev/null || echo "No log file found"
```

### Windows Diagnostic Script

```powershell
# EST Client Diagnostic Script for Windows

Write-Host "=== EST Client Diagnostics ===" -ForegroundColor Cyan

Write-Host "`n--- Configuration ---" -ForegroundColor Yellow
& est-enroll.exe --validate-config

Write-Host "`n--- Connection Test ---" -ForegroundColor Yellow
& est-enroll.exe --test-connection

Write-Host "`n--- Certificate Status ---" -ForegroundColor Yellow
Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.FriendlyName -like "*EST*"} |
    Select-Object Subject, Thumbprint, NotAfter, @{N='DaysRemaining';E={($_.NotAfter - (Get-Date)).Days}}

Write-Host "`n--- Service Status ---" -ForegroundColor Yellow
Get-Service EST-Enrollment -ErrorAction SilentlyContinue | Select-Object Status, StartType

Write-Host "`n--- Environment ---" -ForegroundColor Yellow
Write-Host "COMPUTERNAME: $env:COMPUTERNAME"
Write-Host "USERDNSDOMAIN: $env:USERDNSDOMAIN"
Write-Host "EST_CONFIG_PATH: $env:EST_CONFIG_PATH"

Write-Host "`n--- Event Log (last 10) ---" -ForegroundColor Yellow
Get-EventLog -LogName Application -Source EST-Enrollment -Newest 10 -ErrorAction SilentlyContinue |
    Select-Object TimeGenerated, EntryType, Message
```

## Getting Help

### Before Asking for Help

1. Run diagnostic scripts above
2. Enable debug logging:

   ```toml
   [logging]
   level = "debug"
   ```

3. Reproduce the issue
4. Collect logs and configuration (redact sensitive data)

### Information to Include

When reporting issues, include:

1. **Platform**: OS version, architecture
2. **EST Client Version**: `est-enroll --version`
3. **Configuration**: config.toml (redact passwords)
4. **Error Message**: Full error text
5. **Logs**: Relevant log entries (debug level)
6. **Steps to Reproduce**: What you did
7. **Expected vs Actual**: What should happen vs what happened

### Support Channels

- **GitHub Issues**: [Project Issues Page]
- **Documentation**: See [docs/](.) directory
- **RFC 7030**: [EST Specification](https://tools.ietf.org/html/rfc7030)

### Log Redaction Checklist

Before sharing logs or configuration:

- [ ] Remove/mask passwords
- [ ] Remove/mask API keys
- [ ] Remove/mask private keys
- [ ] Anonymize hostnames if needed
- [ ] Anonymize usernames if needed
- [ ] Remove certificate serial numbers if sensitive
