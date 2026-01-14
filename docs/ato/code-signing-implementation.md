# Code Signing Implementation Guide with Smartcard Support

**POA&M Item**: SI-002
**Control**: SI-7 (Software, Firmware, and Information Integrity)
**Implementation Date**: 2026-01-14
**Version**: 1.0

---

## Executive Summary

This document provides comprehensive implementation guidance for code signing the EST Client using smartcard-based certificates (CAC/PIV cards). Smartcard-based signing provides enhanced security compared to file-based certificates by storing private keys in tamper-resistant hardware.

**Implementation Overview**:
- **Authenticode Signing**: Windows executables signed using smartcard certificates
- **GPG Signing**: Release checksums signed with GPG keys on smartcard
- **SLSA Provenance**: Build attestations for supply chain security
- **Hardware Security**: Private keys never leave the smartcard
- **DoD Compatibility**: Works with CAC cards and PIV-compliant smartcards

**Security Benefits**:
- Private keys stored in tamper-resistant hardware (FIPS 140-2 certified)
- Keys cannot be copied or exported
- PIN protection prevents unauthorized use
- Audit trail of all signing operations
- Meets DoD PKI requirements

---

## Table of Contents

1. [Overview](#1-overview)
2. [Smartcard Requirements](#2-smartcard-requirements)
3. [Authenticode Signing with Smartcard](#3-authenticode-signing-with-smartcard)
4. [GPG Signing with Smartcard](#4-gpg-signing-with-smartcard)
5. [SLSA Build Provenance](#5-slsa-build-provenance)
6. [Build Pipeline Integration](#6-build-pipeline-integration)
7. [Signature Verification](#7-signature-verification)
8. [Security Considerations](#8-security-considerations)
9. [Troubleshooting](#9-troubleshooting)
10. [Compliance Mapping](#10-compliance-mapping)

---

## 1. Overview

### 1.1 Code Signing Purpose

**Authenticode** (Windows):
- Verifies publisher identity
- Ensures binary hasn't been modified
- Prevents SmartScreen warnings
- Required for Windows driver signing

**GPG Signatures** (Cross-platform):
- Signs release checksums (SHA-256)
- Enables end-to-end verification
- Compatible with Linux/Unix tooling
- Can sign source tarballs

**SLSA Provenance** (Supply Chain):
- Attests to build process integrity
- Documents build inputs and outputs
- Prevents tampering in CI/CD pipeline
- Supports reproducible builds

### 1.2 Smartcard Advantages

**vs. File-Based Certificates**:
| Feature | File Cert | Smartcard |
|---------|-----------|-----------|
| Key exportable | ✅ Yes (risk) | ❌ No (secure) |
| Tamper resistance | ❌ Low | ✅ High (FIPS 140-2) |
| PIN protection | Optional | ✅ Required |
| Audit trail | No | ✅ Yes |
| CAC compatible | No | ✅ Yes |
| Cost | Lower | Higher (hardware) |

**DoD Requirements**:
- DoD requires PKI certificates for code signing
- CAC cards contain code signing certificates (if requested)
- Smartcard usage aligns with DoD Cybersecurity requirements
- FIPS 140-2 Level 2 or higher for key storage

---

## 2. Smartcard Requirements

### 2.1 Supported Smartcards

**CAC (Common Access Card)** - DoD standard:
- Issued by DoD to military and contractors
- Contains PKI certificates for various purposes
- Code signing certificate requires special request
- FIPS 140-2 Level 3 certified

**PIV (Personal Identity Verification)** - Federal civilian:
- Issued by federal agencies
- Similar to CAC for civilian employees
- Contains digital signature certificate
- FIPS 140-2 Level 2 certified

**YubiKey** - Commercial PIV-compatible:
- YubiKey 5 series (FIPS or non-FIPS)
- Supports PIV applet (code signing)
- FIPS 140-2 Level 2 (FIPS models)
- Widely available commercial option

### 2.2 Certificate Requirements

**Authenticode Certificate** (Windows):
- **Purpose**: Code Signing
- **Algorithm**: RSA 2048-bit minimum (4096-bit recommended)
- **Hash**: SHA-256 or SHA-384
- **Validity**: 1-3 years
- **Issuer**: DoD Root CA or commercial CA (DigiCert, etc.)

**GPG Key** (Checksums):
- **Algorithm**: RSA 4096-bit or Ed25519
- **Usage**: Sign
- **Validity**: 2-5 years with expiration
- **Storage**: Smartcard via OpenPGP applet

### 2.3 Hardware and Software

**Smartcard Reader**:
- USB smartcard reader (PC/SC compatible)
- Examples: Identiv SCR3500, Gemalto IDBridge CT30
- Built-in reader (many DoD-compliant laptops)

**Windows Software**:
- Windows SDK (signtool.exe)
- smartcard middleware (DoD PKI or manufacturer's)
- Visual Studio Build Tools (optional)

**GPG Software**:
- GnuPG 2.3+ (smartcard support)
- scdaemon (smartcard daemon)
- pinentry (PIN entry dialog)

---

## 3. Authenticode Signing with Smartcard

### 3.1 Certificate Enrollment

**Option 1: CAC Card (DoD)**:
```bash
# Request code signing certificate from DoD PKI
# Submit request via https://crl.gds.eis.mil or DoD RA

# Certificate automatically loaded onto CAC card
# No manual installation required
```

**Option 2: Commercial Certificate on PIV Card**:
```powershell
# Generate key pair on smartcard
certutil -csp "Microsoft Base Smart Card Crypto Provider" `
         -generate-key -importpfx

# Submit CSR to commercial CA (DigiCert, etc.)
# Import certificate to smartcard
certutil -csp "Microsoft Base Smart Card Crypto Provider" `
         -importcert certificate.cer
```

### 3.2 Signing with signtool.exe

**Locate Certificate on Smartcard**:
```powershell
# List certificates on smartcard
certutil -scinfo

# Example output:
# SmartCard Reader: Gemalto IDBridge CT30
# Card: PIV
# Cert Serial: 1A2B3C4D5E6F7890
# Subject: CN=John Doe, OU=Development, O=U.S. Government
# Issuer: CN=DoD Root CA 3
```

**Sign Executable**:
```powershell
# Sign using subject name (prompts for PIN)
signtool sign /v /debug /sm /a /n "John Doe" `
  /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 `
  est-client.exe

# Parameters:
#   /sm = Use smartcard (machine store)
#   /a = Auto-select certificate
#   /n = Certificate subject name
#   /fd SHA256 = File digest algorithm
#   /tr = Timestamp server URL (RFC 3161)
#   /td SHA256 = Timestamp digest algorithm
```

**Sign with Specific Certificate**:
```powershell
# Sign using certificate SHA1 thumbprint
signtool sign /v /sha1 1A2B3C4D5E6F7890ABCDEF1234567890ABCDEF12 `
  /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 `
  est-client.exe

# User will be prompted for smartcard PIN
```

**Batch Signing Script**:
```powershell
# sign-release.ps1
param(
    [Parameter(Mandatory=$true)]
    [string]$CertSubject,

    [Parameter(Mandatory=$true)]
    [string[]]$Files
)

$timestampServer = "http://timestamp.digicert.com"

foreach ($file in $Files) {
    Write-Host "Signing: $file"

    signtool sign /v /sm /a /n $CertSubject `
        /fd SHA256 /tr $timestampServer /td SHA256 `
        /d "EST Client for U.S. Government" `
        /du "https://github.com/usgov/est-client" `
        $file

    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to sign $file"
        exit 1
    }

    # Verify signature
    signtool verify /v /pa $file

    if ($LASTEXITCODE -ne 0) {
        Write-Error "Signature verification failed for $file"
        exit 1
    }
}

Write-Host "All files signed successfully"
```

**Usage**:
```powershell
# Sign all release binaries
.\sign-release.ps1 -CertSubject "John Doe" -Files @(
    "dist\est-client.exe",
    "dist\est-service.exe",
    "dist\est-client-gui.exe"
)
```

### 3.3 Dual Signing (SHA-1 + SHA-256)

For Windows 7 compatibility (legacy systems):

```powershell
# First signature: SHA-256 (primary)
signtool sign /sm /a /n "John Doe" `
  /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 `
  est-client.exe

# Second signature: SHA-1 (legacy compatibility)
signtool sign /sm /a /n "John Doe" `
  /as `
  /fd SHA1 /tr http://timestamp.digicert.com /td SHA1 `
  est-client.exe

# /as = Append signature (dual signing)
```

---

## 4. GPG Signing with Smartcard

### 4.1 GPG Key Generation on Smartcard

**YubiKey Example** (OpenPGP applet):

```bash
# Initialize YubiKey for OpenPGP
gpg --card-edit

> admin
> factory-reset  # WARNING: Erases all keys
> generate

# Follow prompts:
#   - Key type: RSA 4096
#   - Expiration: 2 years
#   - Name: EST Client Release Signing
#   - Email: est-releases@agency.gov
#   - Comment: Smartcard-backed release signing key

> quit

# Export public key
gpg --armor --export est-releases@agency.gov > release-signing-key.asc

# Publish public key to keyserver
gpg --send-keys <KEY-ID>
```

**CAC Card** (if OpenPGP applet available):
```bash
# Some CAC cards support OpenPGP applet
# Check with: gpg --card-status

# If not supported, use PIV certificate for S/MIME instead
# Or use YubiKey as dedicated GPG signing token
```

### 4.2 Signing Release Checksums

**Generate Checksums**:
```bash
# Generate SHA-256 checksums for all release files
cd dist/
sha256sum *.exe *.zip *.tar.gz > SHA256SUMS

# Example SHA256SUMS:
# 1a2b3c4d... est-client-v1.0.0-windows-x64.exe
# 5e6f7g8h... est-client-v1.0.0-windows-x86.exe
# 9i0j1k2l... est-client-v1.0.0-linux-x64.tar.gz
```

**Sign with GPG Smartcard**:
```bash
# Sign checksums file (prompts for smartcard PIN)
gpg --armor --detach-sign --output SHA256SUMS.asc SHA256SUMS

# Verify signature
gpg --verify SHA256SUMS.asc SHA256SUMS

# Output:
# gpg: Signature made 2026-01-14 using RSA key ABC123...
# gpg: Good signature from "EST Client Release Signing"
# Primary key fingerprint: 1234 5678 9ABC DEF0 1234 5678 9ABC DEF0 1234 5678
```

**Automated Signing Script**:
```bash
#!/bin/bash
# sign-checksums.sh

set -euo pipefail

DIST_DIR="dist"
GPG_KEY="est-releases@agency.gov"

cd "$DIST_DIR"

# Generate checksums
echo "Generating SHA-256 checksums..."
sha256sum *.exe *.zip *.tar.gz > SHA256SUMS

# Sign with smartcard (will prompt for PIN)
echo "Signing checksums with GPG smartcard..."
gpg --armor --detach-sign --local-user "$GPG_KEY" \
    --output SHA256SUMS.asc SHA256SUMS

# Verify signature
echo "Verifying signature..."
gpg --verify SHA256SUMS.asc SHA256SUMS

echo "Checksums signed successfully"
echo "Files:"
echo "  - SHA256SUMS"
echo "  - SHA256SUMS.asc"
```

### 4.3 GPG Key Management

**Backup Master Key** (offline storage):
```bash
# Export master key (store offline in safe)
gpg --armor --export-secret-keys est-releases@agency.gov > master-key.asc

# Export subkeys only (for smartcard)
gpg --armor --export-secret-subkeys est-releases@agency.gov > subkeys.asc

# Revocation certificate (in case of compromise)
gpg --gen-revoke est-releases@agency.gov > revoke.asc
```

**Key Rotation** (every 2 years):
```bash
# Extend key expiration
gpg --edit-key est-releases@agency.gov
> expire
> 2y  # Extend for 2 more years
> save

# Generate new subkey on new smartcard
gpg --edit-key est-releases@agency.gov
> addkey
> (select RSA sign only, 4096 bits)
> quit

# Update published public key
gpg --send-keys <KEY-ID>
```

---

## 5. SLSA Build Provenance

### 5.1 SLSA Overview

**SLSA** (Supply-chain Levels for Software Artifacts):
- Framework for supply chain security
- Documents build process integrity
- Prevents unauthorized modifications
- Supports reproducible builds

**SLSA Levels**:
- **Level 1**: Documentation (build process documented)
- **Level 2**: Provenance (build attested, signed)
- **Level 3**: Hardened builds (ephemeral, isolated)
- **Level 4**: Hermetic builds (reproducible)

**Target for EST Client**: SLSA Level 2

### 5.2 Provenance Generation

**Using GitHub Actions** (slsa-github-generator):

```yaml
# .github/workflows/release.yml
name: Release with SLSA Provenance

on:
  push:
    tags:
      - 'v*'

permissions:
  contents: write
  id-token: write  # For provenance signing

jobs:
  build:
    runs-on: windows-latest
    outputs:
      hashes: ${{ steps.hash.outputs.hashes }}
    steps:
      - uses: actions/checkout@v4

      - name: Build Release
        run: cargo build --release

      - name: Generate Hashes
        id: hash
        run: |
          cd target/release
          sha256sum est-client.exe > hashes.txt
          echo "hashes=$(cat hashes.txt | base64)" >> $GITHUB_OUTPUT

      - name: Upload Artifacts
        uses: actions/upload-artifact@v4
        with:
          name: binaries
          path: target/release/est-client.exe

  provenance:
    needs: [build]
    permissions:
      actions: read
      id-token: write
      contents: write
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v1.9.0
    with:
      base64-subjects: "${{ needs.build.outputs.hashes }}"
      upload-assets: true

  sign-and-release:
    needs: [build, provenance]
    runs-on: windows-latest
    steps:
      - uses: actions/download-artifact@v4

      # Authenticode signing would require smartcard access
      # In CI/CD, use Azure Key Vault or GitHub Codespaces with smartcard

      - name: Create Release
        uses: softprops/action-gh-release@v1
        with:
          files: |
            binaries/est-client.exe
            **/attestation.intoto.jsonl
```

**Manual Provenance** (for smartcard-signed builds):

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "subject": [
    {
      "name": "est-client.exe",
      "digest": {
        "sha256": "1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890"
      }
    }
  ],
  "predicate": {
    "builder": {
      "id": "https://github.com/usgov/est-client/actions/workflows/release.yml"
    },
    "buildType": "https://github.com/Attestations/GitHubActionsWorkflow@v1",
    "invocation": {
      "configSource": {
        "uri": "git+https://github.com/usgov/est-client@refs/tags/v1.0.0",
        "digest": {
          "sha1": "abc123def456..."
        },
        "entryPoint": ".github/workflows/release.yml"
      }
    },
    "metadata": {
      "buildStartedOn": "2026-01-14T10:00:00Z",
      "buildFinishedOn": "2026-01-14T10:15:00Z",
      "completeness": {
        "parameters": true,
        "environment": false,
        "materials": true
      },
      "reproducible": false
    },
    "materials": [
      {
        "uri": "git+https://github.com/usgov/est-client@v1.0.0",
        "digest": {
          "sha1": "abc123..."
        }
      }
    ]
  }
}
```

**Sign Provenance with GPG**:
```bash
# Sign provenance file
gpg --armor --sign --local-user est-releases@agency.gov \
    attestation.intoto.jsonl

# Output: attestation.intoto.jsonl.asc
```

### 5.3 Provenance Verification

**Verify SLSA Provenance**:
```bash
# Install slsa-verifier
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest

# Verify provenance
slsa-verifier verify-artifact est-client.exe \
  --provenance-path attestation.intoto.jsonl \
  --source-uri github.com/usgov/est-client \
  --source-tag v1.0.0

# Output:
# PASSED: Verified SLSA provenance
```

---

## 6. Build Pipeline Integration

### 6.1 Local Build with Smartcard Signing

**Build Script** (`scripts/build-and-sign.ps1`):
```powershell
#Requires -Version 7.0

param(
    [Parameter(Mandatory=$true)]
    [string]$Version,

    [Parameter(Mandatory=$true)]
    [string]$SigningCertSubject,

    [string]$Configuration = "Release",
    [string]$OutputDir = "dist"
)

$ErrorActionPreference = "Stop"

# Step 1: Build
Write-Host "Building EST Client v$Version..."
cargo build --release --features "windows-service,siem,enveloped"

if ($LASTEXITCODE -ne 0) {
    throw "Build failed"
}

# Step 2: Prepare distribution
Write-Host "Preparing distribution..."
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$binaries = @(
    "target\release\est-client.exe",
    "target\release\est-service.exe"
)

foreach ($binary in $binaries) {
    Copy-Item $binary -Destination $OutputDir
}

# Step 3: Authenticode signing (smartcard)
Write-Host "Signing binaries with Authenticode (smartcard PIN required)..."

foreach ($binary in Get-ChildItem "$OutputDir\*.exe") {
    Write-Host "  Signing: $($binary.Name)"

    signtool sign /v /sm /a /n $SigningCertSubject `
        /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 `
        /d "EST Client for U.S. Government" `
        /du "https://github.com/usgov/est-client" `
        $binary.FullName

    if ($LASTEXITCODE -ne 0) {
        throw "Authenticode signing failed for $($binary.Name)"
    }

    # Verify
    signtool verify /v /pa $binary.FullName
}

# Step 4: Generate checksums
Write-Host "Generating checksums..."
Push-Location $OutputDir

Get-ChildItem *.exe | ForEach-Object {
    $hash = (Get-FileHash $_.Name -Algorithm SHA256).Hash.ToLower()
    "$hash  $($_.Name)" | Out-File -Append -Encoding utf8 SHA256SUMS
}

Pop-Location

# Step 5: GPG signing (smartcard)
Write-Host "Signing checksums with GPG (smartcard PIN required)..."
gpg --armor --detach-sign --output "$OutputDir\SHA256SUMS.asc" "$OutputDir\SHA256SUMS"

if ($LASTEXITCODE -ne 0) {
    throw "GPG signing failed"
}

# Step 6: Verify signatures
Write-Host "Verifying signatures..."
gpg --verify "$OutputDir\SHA256SUMS.asc" "$OutputDir\SHA256SUMS"

# Step 7: Create release archive
Write-Host "Creating release archive..."
$archiveName = "est-client-v$Version-windows-x64.zip"
Compress-Archive -Path "$OutputDir\*" -DestinationPath "$OutputDir\$archiveName" -Force

Write-Host ""
Write-Host "Build and signing complete!" -ForegroundColor Green
Write-Host "Release files in: $OutputDir\"
Write-Host "  - Signed executables"
Write-Host "  - SHA256SUMS (checksums)"
Write-Host "  - SHA256SUMS.asc (GPG signature)"
Write-Host "  - $archiveName (release archive)"
```

**Usage**:
```powershell
# Build and sign v1.0.0 using smartcard
.\scripts\build-and-sign.ps1 `
    -Version "1.0.0" `
    -SigningCertSubject "John Doe"

# Will prompt for:
#   1. Smartcard PIN (Authenticode signing)
#   2. Smartcard PIN (GPG signing)
```

### 6.2 CI/CD with Remote Smartcard

**GitHub Actions with Smartcard** (using GitHub Codespaces):

The challenge with smartcards in CI/CD is physical access. Solutions:

**Option 1: Azure Key Vault** (Cloud HSM):
```yaml
# Use Azure Key Vault for signing (FIPS 140-2 Level 2)
- name: Sign with Azure Key Vault
  uses: Azure/code-signing@v1
  with:
    azure-key-vault-name: ${{ secrets.KEY_VAULT_NAME }}
    azure-key-vault-certificate-name: "code-signing-cert"
    files: "dist/*.exe"
```

**Option 2: Self-Hosted Runner with Smartcard**:
```yaml
# Use self-hosted runner with smartcard reader attached
jobs:
  sign:
    runs-on: [self-hosted, windows, smartcard]
    steps:
      - name: Sign with Local Smartcard
        run: |
          # Smartcard connected to self-hosted runner
          signtool sign /sm /a /n "${{ secrets.CERT_SUBJECT }}" `
            /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 `
            dist\est-client.exe
        env:
          # PIN stored as secret, passed to automated PIN entry
          SMARTCARD_PIN: ${{ secrets.SMARTCARD_PIN }}
```

**Option 3: Manual Signing Step**:
```yaml
# Build in CI, sign manually, upload signed binaries
jobs:
  build:
    runs-on: windows-latest
    steps:
      - name: Build
        run: cargo build --release

      - name: Upload Unsigned Binaries
        uses: actions/upload-artifact@v4
        with:
          name: unsigned-binaries
          path: target/release/*.exe

# Manual step:
# 1. Download unsigned binaries
# 2. Sign with smartcard locally
# 3. Upload signed binaries to release
```

---

## 7. Signature Verification

### 7.1 Authenticode Verification (Windows)

**Command Line Verification**:
```powershell
# Verify Authenticode signature
signtool verify /v /pa est-client.exe

# Output:
# Verifying: est-client.exe
# Signature verified successfully
# Signing Certificate Chain:
#   Issued to: John Doe
#   Issued by: DoD Root CA 3
#   Expires:   12/31/2027
#   SHA256 hash: 1A2B3C4D...
```

**PowerShell Verification**:
```powershell
# Get signature details
$sig = Get-AuthenticodeSignature est-client.exe

# Check status
if ($sig.Status -eq 'Valid') {
    Write-Host "Signature valid" -ForegroundColor Green
    Write-Host "Signer: $($sig.SignerCertificate.Subject)"
    Write-Host "Timestamp: $($sig.TimeStamperCertificate.NotBefore)"
} else {
    Write-Host "Signature invalid: $($sig.StatusMessage)" -ForegroundColor Red
}
```

**Automated Verification Script**:
```powershell
# verify-signatures.ps1
param([string]$Path)

Get-ChildItem $Path -Filter *.exe | ForEach-Object {
    $sig = Get-AuthenticodeSignature $_.FullName

    [PSCustomObject]@{
        File = $_.Name
        Status = $sig.Status
        Signer = $sig.SignerCertificate.Subject
        Algorithm = $sig.SignatureType
        Timestamp = $sig.TimeStamperCertificate.NotBefore
    }
} | Format-Table -AutoSize
```

### 7.2 GPG Verification

**Verify Checksums**:
```bash
# Import public key (first time only)
gpg --import release-signing-key.asc

# Or from keyserver
gpg --recv-keys <KEY-ID>

# Verify checksums signature
gpg --verify SHA256SUMS.asc SHA256SUMS

# Output:
# gpg: Signature made 2026-01-14 using RSA key ABC123
# gpg: Good signature from "EST Client Release Signing"
```

**Verify File Integrity**:
```bash
# Verify file matches checksum
sha256sum --check SHA256SUMS

# Output:
# est-client.exe: OK
# est-service.exe: OK
```

**Complete Verification Script**:
```bash
#!/bin/bash
# verify-release.sh

set -euo pipefail

RELEASE_DIR="${1:-.}"

cd "$RELEASE_DIR"

echo "Verifying EST Client release..."
echo ""

# Step 1: Verify GPG signature on checksums
echo "[1/3] Verifying GPG signature..."
if gpg --verify SHA256SUMS.asc SHA256SUMS 2>&1 | grep -q "Good signature"; then
    echo "✓ GPG signature valid"
else
    echo "✗ GPG signature invalid" >&2
    exit 1
fi

echo ""

# Step 2: Verify file integrity
echo "[2/3] Verifying file integrity..."
if sha256sum --check SHA256SUMS; then
    echo "✓ All checksums match"
else
    echo "✗ Checksum mismatch" >&2
    exit 1
fi

echo ""

# Step 3: Verify Authenticode (Windows only)
if command -v osslsigncode &> /dev/null; then
    echo "[3/3] Verifying Authenticode signatures..."
    for exe in *.exe; do
        if osslsigncode verify -in "$exe" | grep -q "Signature verification: ok"; then
            echo "✓ $exe: Authenticode signature valid"
        else
            echo "✗ $exe: Authenticode signature invalid" >&2
            exit 1
        fi
    done
else
    echo "[3/3] Skipping Authenticode verification (osslsigncode not installed)"
fi

echo ""
echo "All verifications passed!" >&2
```

### 7.3 SLSA Provenance Verification

**Verify Build Provenance**:
```bash
# Install slsa-verifier
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest

# Verify artifact provenance
slsa-verifier verify-artifact est-client.exe \
  --provenance-path attestation.intoto.jsonl \
  --source-uri github.com/usgov/est-client \
  --source-tag v1.0.0

# Verify builder
slsa-verifier verify-artifact est-client.exe \
  --provenance-path attestation.intoto.jsonl \
  --builder-id https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v1.9.0
```

---

## 8. Security Considerations

### 8.1 Smartcard Security

**PIN Protection**:
- Minimum 6-8 character PIN
- PIN retry limit (3-10 attempts before lockout)
- Admin PIN for card reset (PUK code)
- Never hardcode PINs in scripts or CI/CD

**Physical Security**:
- Store smartcard in secure location when not in use
- Use tamper-evident seals for backup cards
- Log all signing operations
- Revoke certificates if card is lost or compromised

**Key Backup**:
- Master keys backed up offline (safe deposit box)
- Backup cards in secure storage
- Document recovery procedures
- Test recovery process annually

### 8.2 Timestamping

**Why Timestamp**:
- Signatures remain valid after certificate expires
- Proves when code was signed
- Required for long-term validity

**Timestamp Servers**:
- **DigiCert**: `http://timestamp.digicert.com`
- **Sectigo**: `http://timestamp.sectigo.com`
- **GlobalSign**: `http://timestamp.globalsign.com`

**Timestamp Verification**:
```powershell
# Check timestamp
$sig = Get-AuthenticodeSignature est-client.exe
$sig.TimeStamperCertificate

# Output shows timestamp CA and time
```

### 8.3 Certificate Revocation

**If Smartcard Compromised**:
1. **Immediately revoke certificate**:
   ```bash
   # Contact CA to revoke certificate
   # Publish revocation on CRL/OCSP
   ```

2. **Notify users**:
   - Post security advisory
   - Provide new signing key fingerprint
   - Instructions to verify new signatures

3. **Re-sign all releases**:
   - Sign with new certificate
   - Update SHA256SUMS files
   - Re-publish with new signatures

4. **Update trust**:
   - Publish new public key
   - Update keyservers
   - Document in release notes

---

## 9. Troubleshooting

### 9.1 Authenticode Issues

**Problem**: "No certificates were found that met all the given criteria"

**Solution**:
```powershell
# Check certificates on smartcard
certutil -scinfo

# Ensure correct CSP
signtool sign /csp "Microsoft Base Smart Card Crypto Provider" ...

# Or specify exact certificate by thumbprint
signtool sign /sha1 <THUMBPRINT> ...
```

**Problem**: "SignTool Error: The specified timestamp server could not be reached"

**Solution**:
```powershell
# Try alternate timestamp server
signtool sign /tr http://timestamp.sectigo.com /td SHA256 ...

# Or retry with timeout
for ($i=0; $i -lt 3; $i++) {
    signtool sign /tr http://timestamp.digicert.com /td SHA256 est-client.exe
    if ($LASTEXITCODE -eq 0) { break }
    Start-Sleep -Seconds 5
}
```

### 9.2 GPG/Smartcard Issues

**Problem**: "gpg: card error: Card not present"

**Solution**:
```bash
# Restart scdaemon
gpg-connect-agent "SCD KILLSCD" /bye
gpg-connect-agent "SCD LEARN --force" /bye

# Check card status
gpg --card-status
```

**Problem**: "gpg: signing failed: Invalid value"

**Solution**:
```bash
# Reset GPG agent
gpgconf --kill gpg-agent
gpgconf --launch gpg-agent

# Ensure PIN entry works
echo "test" | gpg --armor --sign --local-user <KEY-ID>
```

### 9.3 Build Issues

**Problem**: Smartcard not detected in CI/CD

**Solution**:
- Use Azure Key Vault or AWS KMS for cloud signing
- Use self-hosted runner with smartcard reader
- Sign manually outside CI/CD pipeline

---

## 10. Compliance Mapping

### 10.1 NIST 800-53 Rev 5

**SI-7: Software, Firmware, and Information Integrity**:
- ✅ (1) Integrity Checks - Authenticode signatures
- ✅ (7) Integration of Detection and Response - Signature verification before execution
- ✅ (10) Protection of Boot Firmware - Not applicable (application software)
- ✅ (15) Code Authentication - Authenticode + GPG signatures

**AU-10: Non-Repudiation**:
- ✅ (1) Association of Identity with Witness - Smartcard private key
- ✅ (2) Validate Binding of Information Producer - Certificate chain validation
- ✅ (4) Validate Binding of Information Reviewer - Timestamp

**IA-5: Authenticator Management**:
- ✅ (2) PKI-Based Authentication - Smartcard certificates
- ✅ (11) Hardware Token-Based Authentication - Smartcard = hardware token

### 10.2 DoD Requirements

**DoD Instruction 8500.01**:
- ✅ Code signing required for DoD systems
- ✅ PKI certificates from DoD Root CA or approved commercial CA
- ✅ FIPS 140-2 validated cryptography (smartcard)

**DoD Software Assurance**:
- ✅ Provenance tracking (SLSA)
- ✅ Integrity verification (signatures)
- ✅ Supply chain security (signed builds)

### 10.3 FedRAMP

**SA-10: Developer Configuration Management**:
- ✅ (1) Software Integrity Verification - Code signatures

**SR-4: Provenance**:
- ✅ (1) Chain of Custody - SLSA provenance
- ✅ (2) Validation of Screening - Build attestation

---

## 11. Appendices

### Appendix A: Certificate Procurement Guide

**DoD PKI Certificate Request**:
1. Visit https://crl.gds.eis.mil
2. Login with CAC card
3. Request "Code Signing Certificate"
4. Justify business need
5. Await approval (1-2 weeks)
6. Certificate loaded to CAC automatically

**Commercial Certificate** (DigiCert EV Code Signing):
1. Purchase EV Code Signing Certificate ($300-500/year)
2. Identity verification process (1-2 weeks)
3. Receive USB token with certificate pre-loaded
4. Or generate CSR on YubiKey, import certificate

### Appendix B: Smartcard Readers

**Recommended Readers**:
- Identiv SCR3500: $25, PC/SC, CAC compatible
- Gemalto IDBridge CT30: $30, CCID, PIV compatible
- Built-in readers: Many Dell, HP, Lenovo laptops

**Driver Installation** (Windows):
- Most readers work with built-in Windows drivers
- Install manufacturer drivers if needed
- Verify with: `certutil -scinfo`

### Appendix C: Example Certificates

**Subject Names**:
```
DoD:       CN=Doe.John.1234567890, OU=PKI, OU=DoD, O=U.S. Government, C=US
Commercial: CN=Acme Corporation, O=Acme Corporation, L=Reston, ST=Virginia, C=US
```

**Extended Key Usage (EKU)**:
- Code Signing: `1.3.6.1.5.5.7.3.3`
- Timestamping: `1.3.6.1.5.5.7.3.8`

---

**Document Owner**: Development Team / Security Team
**Next Review**: Before SI-002 implementation (Q2 2026)
**Version**: 1.0
**Last Updated**: 2026-01-14

---

**Classification**: UNCLASSIFIED // FOR OFFICIAL USE ONLY (FOUO)
**Distribution**: Authorized to U.S. Government agencies and contractors
