#Requires -Version 7.0

<#
.SYNOPSIS
    Verify EST Client release signatures and integrity.

.DESCRIPTION
    This script verifies a signed release:
    1. Authenticode signatures on executables
    2. GPG signature on checksums file
    3. File integrity via SHA-256 checksums
    4. Certificate chain validity
    5. Timestamp verification

.PARAMETER Path
    Path to release directory containing signed files

.PARAMETER Verbose
    Show detailed verification output

.EXAMPLE
    .\verify-release.ps1 -Path dist

    Verify all signatures in the dist directory.

.EXAMPLE
    .\verify-release.ps1 -Path releases\v1.0.0 -Verbose

    Verify with detailed output.

.NOTES
    Author: EST Client Development Team
    Requires: signtool.exe, GnuPG
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, HelpMessage="Path to release directory")]
    [ValidateScript({ Test-Path $_ })]
    [string]$Path,

    [Parameter(HelpMessage="Show detailed output")]
    [switch]$Detail
)

$ErrorActionPreference = "Stop"
$script:VerificationsPassed = 0
$script:VerificationsFailed = 0

# Color output helpers
function Write-Pass {
    param([string]$Message)
    Write-Host "✓ $Message" -ForegroundColor Green
    $script:VerificationsPassed++
}

function Write-Fail {
    param([string]$Message)
    Write-Host "✗ $Message" -ForegroundColor Red
    $script:VerificationsFailed++
}

function Write-Section {
    param([string]$Title)
    Write-Host "`n$Title" -ForegroundColor Cyan
    Write-Host ("─" * $Title.Length) -ForegroundColor Cyan
}

function Write-Detail {
    param([string]$Message)
    if ($Detail) {
        Write-Host "  $Message" -ForegroundColor Gray
    }
}

# Verify prerequisites
function Test-Prerequisites {
    $missing = @()

    if (-not (Get-Command signtool -ErrorAction SilentlyContinue)) {
        $missing += "signtool.exe (Windows SDK)"
    }

    if (-not (Get-Command gpg -ErrorAction SilentlyContinue)) {
        $missing += "GPG (GnuPG)"
    }

    if ($missing.Count -gt 0) {
        throw "Missing required tools: $($missing -join ', ')"
    }
}

# Verify Authenticode signatures
function Test-AuthenticodeSignatures {
    Write-Section "[1/4] Authenticode Signature Verification"

    $exeFiles = Get-ChildItem "$Path\*.exe" -ErrorAction SilentlyContinue

    if ($exeFiles.Count -eq 0) {
        Write-Host "No .exe files found" -ForegroundColor Yellow
        return
    }

    foreach ($exe in $exeFiles) {
        Write-Host "`nVerifying: " -NoNewline
        Write-Host $exe.Name -ForegroundColor Yellow

        # Get signature details
        $sig = Get-AuthenticodeSignature $exe.FullName

        if ($sig.Status -eq 'Valid') {
            Write-Pass "Signature valid"

            # Certificate details
            Write-Detail "Signer: $($sig.SignerCertificate.Subject)"
            Write-Detail "Issuer: $($sig.SignerCertificate.Issuer)"
            Write-Detail "Algorithm: $($sig.SignatureType)"
            Write-Detail "Valid from: $($sig.SignerCertificate.NotBefore.ToString('yyyy-MM-dd'))"
            Write-Detail "Valid until: $($sig.SignerCertificate.NotAfter.ToString('yyyy-MM-dd'))"

            # Timestamp
            if ($sig.TimeStamperCertificate) {
                Write-Pass "Timestamp present"
                Write-Detail "Timestamp: $($sig.TimeStamperCertificate.NotBefore.ToString('yyyy-MM-dd HH:mm:ss'))"
            }
            else {
                Write-Fail "No timestamp found"
            }

            # Certificate chain
            $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
            $chain.Build($sig.SignerCertificate) | Out-Null

            if ($chain.ChainStatus.Length -eq 0) {
                Write-Pass "Certificate chain valid"

                if ($Detail) {
                    Write-Detail "Chain:"
                    $chain.ChainElements | ForEach-Object {
                        Write-Detail "  - $($_.Certificate.Subject)"
                    }
                }
            }
            else {
                Write-Fail "Certificate chain has issues"
                $chain.ChainStatus | ForEach-Object {
                    Write-Detail "Error: $($_.StatusInformation)"
                }
            }

            # signtool verification
            Write-Detail "Running signtool verify..."
            $output = & signtool verify /v /pa $exe.FullName 2>&1

            if ($LASTEXITCODE -eq 0) {
                Write-Pass "signtool verification passed"
            }
            else {
                Write-Fail "signtool verification failed"
                if ($Detail) {
                    Write-Detail ($output | Out-String)
                }
            }
        }
        else {
            Write-Fail "Signature invalid: $($sig.StatusMessage)"
        }
    }
}

# Verify GPG signature
function Test-GPGSignature {
    Write-Section "[2/4] GPG Signature Verification"

    if (-not (Test-Path "$Path\SHA256SUMS")) {
        Write-Fail "SHA256SUMS file not found"
        return
    }

    if (-not (Test-Path "$Path\SHA256SUMS.asc")) {
        Write-Fail "SHA256SUMS.asc signature not found"
        return
    }

    Write-Host "`nVerifying GPG signature on checksums..."

    $output = & gpg --verify "$Path\SHA256SUMS.asc" "$Path\SHA256SUMS" 2>&1

    if ($output -match "Good signature") {
        Write-Pass "GPG signature valid"

        # Extract signer info
        if ($output -match 'from "(.*?)"') {
            Write-Detail "Signer: $($matches[1])"
        }

        # Extract key fingerprint
        if ($output -match "Primary key fingerprint: (.*?)$") {
            Write-Detail "Fingerprint: $($matches[1].Trim())"
        }

        # Check key trust
        if ($output -match "WARNING: This key is not certified") {
            Write-Host "  Note: GPG key not in your trust web" -ForegroundColor Yellow
            Write-Host "  Import the public key: gpg --import release-key.asc" -ForegroundColor Yellow
        }
    }
    elseif ($output -match "Can't check signature: No public key") {
        Write-Fail "Public key not in keyring"
        Write-Host "  Import the public key and try again" -ForegroundColor Yellow
    }
    else {
        Write-Fail "GPG signature invalid"
        if ($Detail) {
            Write-Detail ($output | Out-String)
        }
    }
}

# Verify file integrity
function Test-FileIntegrity {
    Write-Section "[3/4] File Integrity Verification"

    if (-not (Test-Path "$Path\SHA256SUMS")) {
        Write-Fail "SHA256SUMS file not found"
        return
    }

    Push-Location $Path

    try {
        $checksums = Get-Content "SHA256SUMS"

        foreach ($line in $checksums) {
            if ($line -match '^([a-f0-9]{64})\s+(.+)$') {
                $expectedHash = $matches[1]
                $fileName = $matches[2].Trim()

                if (Test-Path $fileName) {
                    Write-Host "`nVerifying: " -NoNewline
                    Write-Host $fileName -ForegroundColor Yellow

                    $actualHash = (Get-FileHash $fileName -Algorithm SHA256).Hash.ToLower()

                    if ($actualHash -eq $expectedHash) {
                        Write-Pass "Checksum matches"
                        Write-Detail "SHA-256: $actualHash"
                    }
                    else {
                        Write-Fail "Checksum mismatch!"
                        Write-Detail "Expected: $expectedHash"
                        Write-Detail "Actual:   $actualHash"
                    }
                }
                else {
                    Write-Fail "File not found: $fileName"
                }
            }
        }
    }
    finally {
        Pop-Location
    }
}

# Verify release completeness
function Test-ReleaseCompleteness {
    Write-Section "[4/4] Release Completeness Check"

    $requiredFiles = @(
        "SHA256SUMS",
        "SHA256SUMS.asc"
    )

    $foundExe = $false

    foreach ($file in $requiredFiles) {
        if (Test-Path "$Path\$file") {
            Write-Pass "$file present"
        }
        else {
            Write-Fail "$file missing"
        }
    }

    # Check for at least one executable
    $exeFiles = Get-ChildItem "$Path\*.exe" -ErrorAction SilentlyContinue
    if ($exeFiles.Count -gt 0) {
        Write-Pass "$($exeFiles.Count) executable(s) present"
        $foundExe = $true
    }
    else {
        Write-Fail "No executables found"
    }

    # Check for release archive
    $zipFiles = Get-ChildItem "$Path\*.zip" -ErrorAction SilentlyContinue
    if ($zipFiles.Count -gt 0) {
        Write-Pass "Release archive present"
    }

    # Check for release notes
    if (Test-Path "$Path\RELEASE-NOTES.md") {
        Write-Pass "Release notes present"
    }
}

# Generate verification report
function New-VerificationReport {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $report = @"

═══════════════════════════════════════════════════════════════════
                    VERIFICATION SUMMARY
═══════════════════════════════════════════════════════════════════

Verification Date: $timestamp
Release Path: $Path

Results:
  ✓ Passed: $script:VerificationsPassed
  ✗ Failed: $script:VerificationsFailed

Status: $(if ($script:VerificationsFailed -eq 0) { "ALL CHECKS PASSED" } else { "SOME CHECKS FAILED" })

"@

    if ($script:VerificationsFailed -eq 0) {
        Write-Host $report -ForegroundColor Green
        Write-Host "This release is verified and safe to install.`n" -ForegroundColor Green
        return $true
    }
    else {
        Write-Host $report -ForegroundColor Red
        Write-Host "DO NOT INSTALL - Verification failures detected!`n" -ForegroundColor Red
        return $false
    }
}

# Main execution
function Main {
    Write-Host @"

╔═══════════════════════════════════════════════════════════════╗
║           EST Client Release Verification                     ║
╚═══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

    try {
        Write-Host "Release Path: " -NoNewline
        Write-Host (Resolve-Path $Path) -ForegroundColor Yellow

        Test-Prerequisites
        Test-AuthenticodeSignatures
        Test-GPGSignature
        Test-FileIntegrity
        Test-ReleaseCompleteness

        $success = New-VerificationReport

        if ($success) {
            exit 0
        }
        else {
            exit 1
        }
    }
    catch {
        Write-Host "`n✗ Verification failed: $($_.Exception.Message)" -ForegroundColor Red
        if ($Detail) {
            Write-Host "`nStack trace:" -ForegroundColor Gray
            Write-Host $_.ScriptStackTrace -ForegroundColor Gray
        }
        exit 1
    }
}

# Run
Main
