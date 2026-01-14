#Requires -Version 7.0

<#
.SYNOPSIS
    Build and sign EST Client release with smartcard-based code signing.

.DESCRIPTION
    This script automates the complete release build process:
    1. Build binaries with Cargo
    2. Sign executables with Authenticode (smartcard certificate)
    3. Generate SHA-256 checksums
    4. Sign checksums with GPG (smartcard)
    5. Create release archive

    Requires:
    - Smartcard with code signing certificate (CAC/PIV/YubiKey)
    - signtool.exe (Windows SDK)
    - GnuPG 2.3+ with smartcard support

.PARAMETER Version
    Version number for the release (e.g., "1.0.0")

.PARAMETER SigningCertSubject
    Subject name of the Authenticode certificate on smartcard
    Example: "John Doe" or "CN=Doe.John.1234567890"

.PARAMETER GPGKeyID
    GPG key ID for checksum signing (email or key fingerprint)
    Example: "est-releases@agency.gov"

.PARAMETER Configuration
    Build configuration (default: "Release")

.PARAMETER OutputDir
    Output directory for signed binaries (default: "dist")

.PARAMETER Features
    Cargo features to enable (default: "windows-service,siem,enveloped")

.EXAMPLE
    .\build-and-sign.ps1 -Version "1.0.0" -SigningCertSubject "John Doe" -GPGKeyID "est-releases@agency.gov"

    Build and sign version 1.0.0 using smartcard certificates.

.NOTES
    Author: EST Client Development Team
    Requires smartcard with certificates loaded
    Will prompt for smartcard PIN twice (Authenticode + GPG)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, HelpMessage="Release version (e.g., 1.0.0)")]
    [ValidatePattern('^\d+\.\d+\.\d+(-[a-zA-Z0-9]+)?$')]
    [string]$Version,

    [Parameter(Mandatory=$true, HelpMessage="Authenticode certificate subject name")]
    [string]$SigningCertSubject,

    [Parameter(Mandatory=$true, HelpMessage="GPG key ID for checksum signing")]
    [string]$GPGKeyID,

    [Parameter(HelpMessage="Build configuration")]
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [Parameter(HelpMessage="Output directory")]
    [string]$OutputDir = "dist",

    [Parameter(HelpMessage="Cargo features to enable")]
    [string]$Features = "windows-service,siem,enveloped",

    [Parameter(HelpMessage="Timestamp server URL")]
    [string]$TimestampServer = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Color output helpers
function Write-Success {
    param([string]$Message)
    Write-Host "✓ $Message" -ForegroundColor Green
}

function Write-Step {
    param([string]$Message)
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function Write-Info {
    param([string]$Message)
    Write-Host "  $Message" -ForegroundColor Gray
}

# Verify prerequisites
function Test-Prerequisites {
    Write-Step "Checking prerequisites"

    # Check cargo
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        throw "Cargo not found. Install Rust from https://rustup.rs"
    }
    Write-Info "Cargo: $(cargo --version)"

    # Check signtool
    if (-not (Get-Command signtool -ErrorAction SilentlyContinue)) {
        throw "signtool.exe not found. Install Windows SDK"
    }
    Write-Info "signtool: Found"

    # Check GPG
    if (-not (Get-Command gpg -ErrorAction SilentlyContinue)) {
        throw "GPG not found. Install GnuPG from https://gnupg.org"
    }
    Write-Info "GPG: $(gpg --version | Select-Object -First 1)"

    # Check smartcard certificate
    Write-Info "Checking for smartcard certificate..."
    $certs = certutil -scinfo 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "No smartcard detected. Insert smartcard and try again."
    }

    if ($certs -notmatch $SigningCertSubject) {
        Write-Warning "Certificate subject '$SigningCertSubject' not found on smartcard"
        Write-Info "Available certificates:"
        certutil -scinfo | Select-String "Subject:"
        throw "Certificate not found"
    }

    Write-Success "All prerequisites met"
}

# Clean previous build
function Invoke-Clean {
    Write-Step "Cleaning previous build"

    if (Test-Path "target/$Configuration") {
        Remove-Item -Path "target/$Configuration" -Recurse -Force
        Write-Info "Removed target/$Configuration"
    }

    if (Test-Path $OutputDir) {
        Remove-Item -Path $OutputDir -Recurse -Force
        Write-Info "Removed $OutputDir"
    }

    Write-Success "Clean complete"
}

# Build binaries
function Invoke-Build {
    Write-Step "Building EST Client v$Version"

    $buildArgs = @(
        "build"
        "--release"
        "--features"
        $Features
    )

    Write-Info "Running: cargo $($buildArgs -join ' ')"

    & cargo @buildArgs

    if ($LASTEXITCODE -ne 0) {
        throw "Build failed with exit code $LASTEXITCODE"
    }

    Write-Success "Build complete"
}

# Prepare distribution
function New-Distribution {
    Write-Step "Preparing distribution"

    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

    $binaries = @(
        "target\release\est-client.exe"
    )

    # Check for optional binaries
    if (Test-Path "target\release\est-service.exe") {
        $binaries += "target\release\est-service.exe"
    }

    foreach ($binary in $binaries) {
        if (-not (Test-Path $binary)) {
            throw "Binary not found: $binary"
        }

        $fileName = Split-Path $binary -Leaf
        Copy-Item $binary -Destination "$OutputDir\$fileName"
        Write-Info "Copied: $fileName"
    }

    Write-Success "Distribution prepared"
}

# Sign with Authenticode
function Invoke-AuthenticodeSigning {
    Write-Step "Signing binaries with Authenticode"

    Write-Host "`nYou will be prompted for your smartcard PIN." -ForegroundColor Yellow

    $exeFiles = Get-ChildItem "$OutputDir\*.exe"

    foreach ($exe in $exeFiles) {
        Write-Info "Signing: $($exe.Name)"

        $signArgs = @(
            "sign"
            "/v"                    # Verbose
            "/sm"                   # Use smartcard (machine store)
            "/a"                    # Auto-select certificate
            "/n"
            $SigningCertSubject
            "/fd"
            "SHA256"                # File digest algorithm
            "/tr"
            $TimestampServer        # Timestamp server
            "/td"
            "SHA256"                # Timestamp digest
            "/d"
            "EST Client for U.S. Government"
            "/du"
            "https://github.com/usgov/est-client"
            $exe.FullName
        )

        & signtool @signArgs

        if ($LASTEXITCODE -ne 0) {
            throw "Authenticode signing failed for $($exe.Name)"
        }

        # Verify signature
        Write-Info "Verifying: $($exe.Name)"
        $verifyArgs = @("verify", "/v", "/pa", $exe.FullName)
        & signtool @verifyArgs | Out-Null

        if ($LASTEXITCODE -ne 0) {
            throw "Signature verification failed for $($exe.Name)"
        }
    }

    Write-Success "All binaries signed and verified"
}

# Generate checksums
function New-Checksums {
    Write-Step "Generating SHA-256 checksums"

    Push-Location $OutputDir

    try {
        # Remove old checksums if exist
        if (Test-Path "SHA256SUMS") {
            Remove-Item "SHA256SUMS"
        }

        Get-ChildItem *.exe | ForEach-Object {
            $hash = (Get-FileHash $_.Name -Algorithm SHA256).Hash.ToLower()
            $line = "$hash  $($_.Name)"
            $line | Out-File -Append -Encoding utf8 -NoNewline SHA256SUMS
            "`n" | Out-File -Append -Encoding utf8 -NoNewline SHA256SUMS
            Write-Info "$($_.Name): $hash"
        }

        Write-Success "Checksums generated"
    }
    finally {
        Pop-Location
    }
}

# Sign checksums with GPG
function Invoke-GPGSigning {
    Write-Step "Signing checksums with GPG"

    Write-Host "`nYou will be prompted for your GPG smartcard PIN." -ForegroundColor Yellow

    $gpgArgs = @(
        "--armor"
        "--detach-sign"
        "--local-user"
        $GPGKeyID
        "--output"
        "$OutputDir\SHA256SUMS.asc"
        "$OutputDir\SHA256SUMS"
    )

    & gpg @gpgArgs

    if ($LASTEXITCODE -ne 0) {
        throw "GPG signing failed"
    }

    # Verify GPG signature
    Write-Info "Verifying GPG signature..."
    $verifyArgs = @("--verify", "$OutputDir\SHA256SUMS.asc", "$OutputDir\SHA256SUMS")
    $output = & gpg @verifyArgs 2>&1

    if ($output -match "Good signature") {
        Write-Success "GPG signature verified"
    }
    else {
        throw "GPG signature verification failed"
    }
}

# Create release archive
function New-ReleaseArchive {
    Write-Step "Creating release archive"

    $archiveName = "est-client-v$Version-windows-x64.zip"
    $archivePath = "$OutputDir\$archiveName"

    Compress-Archive -Path "$OutputDir\*" -DestinationPath $archivePath -Force

    $archiveSize = (Get-Item $archivePath).Length / 1MB
    Write-Info "Archive: $archiveName ($([math]::Round($archiveSize, 2)) MB)"

    Write-Success "Release archive created"
}

# Generate release notes
function New-ReleaseNotes {
    Write-Step "Generating release notes"

    $notesPath = "$OutputDir\RELEASE-NOTES.md"

    $notes = @"
# EST Client v$Version

**Release Date**: $(Get-Date -Format "yyyy-MM-DD")

## Signatures

This release is signed with:

1. **Authenticode**: All `.exe` files are signed with a smartcard-based code signing certificate
   - Subject: $SigningCertSubject
   - Algorithm: SHA-256
   - Timestamped: Yes

2. **GPG**: Checksums file is signed with GPG key
   - Key ID: $GPGKeyID
   - Algorithm: RSA 4096 or Ed25519

## Verification

### Verify Authenticode Signatures (Windows)

``````powershell
signtool verify /v /pa est-client.exe
``````

### Verify Checksums (All Platforms)

``````bash
# Verify GPG signature
gpg --verify SHA256SUMS.asc SHA256SUMS

# Verify file integrity
sha256sum --check SHA256SUMS
``````

## Files

$(Get-ChildItem "$OutputDir\*.exe" | ForEach-Object { "- $($_.Name)" })
- SHA256SUMS (checksums)
- SHA256SUMS.asc (GPG signature)

## Installation

See [Installation Guide](../../README.md#installation) for details.

## Security

Report security vulnerabilities to: [security contact]

---

**This release was built and signed with smartcard-based certificates for enhanced security.**
"@

    $notes | Out-File -FilePath $notesPath -Encoding utf8

    Write-Info "Release notes: RELEASE-NOTES.md"
    Write-Success "Release notes generated"
}

# Main execution
function Main {
    $startTime = Get-Date

    Write-Host @"

╔════════════════════════════════════════════════════════════════╗
║         EST Client Build and Sign (Smartcard Edition)         ║
║                                                                ║
║  Version: $Version                                     ║
║  Cert: $SigningCertSubject                                   ║
║  GPG: $GPGKeyID                          ║
╚════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

    try {
        Test-Prerequisites
        Invoke-Clean
        Invoke-Build
        New-Distribution
        Invoke-AuthenticodeSigning
        New-Checksums
        Invoke-GPGSigning
        New-ReleaseArchive
        New-ReleaseNotes

        $duration = (Get-Date) - $startTime

        Write-Host "`n" -NoNewline
        Write-Host "═" * 70 -ForegroundColor Green
        Write-Host "Build and signing complete!" -ForegroundColor Green
        Write-Host "═" * 70 -ForegroundColor Green

        Write-Host "`nRelease files in: " -NoNewline
        Write-Host $OutputDir -ForegroundColor Yellow
        Write-Host "`nContents:" -ForegroundColor Cyan
        Get-ChildItem $OutputDir | ForEach-Object {
            $size = if ($_.PSIsContainer) { "<DIR>" } else { "{0:N0} bytes" -f $_.Length }
            Write-Host ("  {0,-40} {1,15}" -f $_.Name, $size)
        }

        Write-Host "`nDuration: " -NoNewline
        Write-Host ("{0:mm}m {0:ss}s" -f $duration) -ForegroundColor Yellow

        Write-Host "`nNext steps:" -ForegroundColor Cyan
        Write-Host "  1. Verify signatures: .\scripts\verify-release.ps1 -Path $OutputDir"
        Write-Host "  2. Test installation"
        Write-Host "  3. Create GitHub release"
        Write-Host "  4. Publish to distribution channels"

    }
    catch {
        Write-Host "`n✗ Build failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "`nStack trace:" -ForegroundColor Gray
        Write-Host $_.ScriptStackTrace -ForegroundColor Gray
        exit 1
    }
}

# Run
Main
