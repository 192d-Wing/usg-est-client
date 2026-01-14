#!/bin/bash

#
# EST Client Release Verification Script (Unix/Linux)
#
# Verifies:
#   1. GPG signature on checksums
#   2. File integrity via SHA-256 checksums
#   3. Release completeness
#
# Usage:
#   ./verify-release.sh [release-directory]
#
# Example:
#   ./verify-release.sh dist/
#

set -euo pipefail

# Color output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# Counters
PASSED=0
FAILED=0

# Functions
print_header() {
    echo -e "${CYAN}"
    echo "═══════════════════════════════════════════════════════════════════"
    echo "           EST Client Release Verification (Unix/Linux)           "
    echo "═══════════════════════════════════════════════════════════════════"
    echo -e "${NC}"
}

print_section() {
    echo ""
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}$(echo "$1" | sed 's/./─/g')${NC}"
}

print_pass() {
    echo -e "${GREEN}✓${NC} $1"
    ((PASSED++))
}

print_fail() {
    echo -e "${RED}✗${NC} $1"
    ((FAILED++))
}

print_info() {
    echo -e "  ${NC}$1"
}

check_prerequisites() {
    print_section "[1/3] Checking Prerequisites"

    local missing=()

    if ! command -v gpg &> /dev/null; then
        missing+=("gpg (GnuPG)")
    fi

    if ! command -v sha256sum &> /dev/null; then
        missing+=("sha256sum")
    fi

    if [ ${#missing[@]} -gt 0 ]; then
        print_fail "Missing required tools: ${missing[*]}"
        echo ""
        echo "Install with:"
        echo "  Debian/Ubuntu: sudo apt-get install gnupg coreutils"
        echo "  RHEL/CentOS:   sudo yum install gnupg2 coreutils"
        echo "  macOS:         brew install gnupg coreutils"
        exit 1
    fi

    print_pass "All prerequisites met"
    print_info "GPG: $(gpg --version | head -n1)"
    print_info "sha256sum: found"
}

verify_gpg_signature() {
    print_section "[2/3] GPG Signature Verification"

    local checksums_file="$RELEASE_DIR/SHA256SUMS"
    local signature_file="$RELEASE_DIR/SHA256SUMS.asc"

    if [ ! -f "$checksums_file" ]; then
        print_fail "SHA256SUMS file not found"
        return
    fi

    if [ ! -f "$signature_file" ]; then
        print_fail "SHA256SUMS.asc signature not found"
        return
    fi

    echo ""
    echo "Verifying GPG signature on checksums..."

    # Verify signature
    if gpg --verify "$signature_file" "$checksums_file" 2>&1 | grep -q "Good signature"; then
        print_pass "GPG signature valid"

        # Extract signer info
        local signer=$(gpg --verify "$signature_file" "$checksums_file" 2>&1 | grep -oP 'from "\K[^"]+')
        if [ -n "$signer" ]; then
            print_info "Signer: $signer"
        fi

        # Extract fingerprint
        local fingerprint=$(gpg --verify "$signature_file" "$checksums_file" 2>&1 | grep -oP 'Primary key fingerprint: \K.+$')
        if [ -n "$fingerprint" ]; then
            print_info "Fingerprint: $fingerprint"
        fi

        # Check if key is trusted
        if gpg --verify "$signature_file" "$checksums_file" 2>&1 | grep -q "WARNING: This key is not certified"; then
            echo -e "${YELLOW}  Note: GPG key not in your trust web${NC}"
            echo -e "${YELLOW}  Import the public key: gpg --import release-key.asc${NC}"
        fi
    elif gpg --verify "$signature_file" "$checksums_file" 2>&1 | grep -q "Can't check signature: No public key"; then
        print_fail "Public key not in keyring"
        echo -e "${YELLOW}  Import the public key and try again${NC}"
        echo -e "${YELLOW}  gpg --import release-key.asc${NC}"
    else
        print_fail "GPG signature invalid"
        if [ "${VERBOSE:-false}" = "true" ]; then
            gpg --verify "$signature_file" "$checksums_file" 2>&1 | sed 's/^/  /'
        fi
    fi
}

verify_file_integrity() {
    print_section "[3/3] File Integrity Verification"

    local checksums_file="$RELEASE_DIR/SHA256SUMS"

    if [ ! -f "$checksums_file" ]; then
        print_fail "SHA256SUMS file not found"
        return
    fi

    pushd "$RELEASE_DIR" > /dev/null

    while IFS= read -r line; do
        if [[ $line =~ ^([a-f0-9]{64})[[:space:]]+(.+)$ ]]; then
            local expected_hash="${BASH_REMATCH[1]}"
            local filename="${BASH_REMATCH[2]}"

            if [ -f "$filename" ]; then
                echo ""
                echo -e "Verifying: ${YELLOW}$filename${NC}"

                local actual_hash=$(sha256sum "$filename" | awk '{print $1}')

                if [ "$actual_hash" = "$expected_hash" ]; then
                    print_pass "Checksum matches"
                    if [ "${VERBOSE:-false}" = "true" ]; then
                        print_info "SHA-256: $actual_hash"
                    fi
                else
                    print_fail "Checksum mismatch!"
                    print_info "Expected: $expected_hash"
                    print_info "Actual:   $actual_hash"
                fi
            else
                print_fail "File not found: $filename"
            fi
        fi
    done < "$checksums_file"

    popd > /dev/null
}

verify_completeness() {
    print_section "[4/4] Release Completeness Check"

    local required_files=("SHA256SUMS" "SHA256SUMS.asc")

    for file in "${required_files[@]}"; do
        if [ -f "$RELEASE_DIR/$file" ]; then
            print_pass "$file present"
        else
            print_fail "$file missing"
        fi
    done

    # Check for executables or archives
    local exe_count=$(find "$RELEASE_DIR" -maxdepth 1 \( -name "*.exe" -o -name "*.tar.gz" -o -name "*.zip" \) | wc -l)
    if [ "$exe_count" -gt 0 ]; then
        print_pass "$exe_count binary/archive file(s) present"
    else
        print_fail "No binary or archive files found"
    fi

    # Check for release notes
    if [ -f "$RELEASE_DIR/RELEASE-NOTES.md" ]; then
        print_pass "Release notes present"
    fi
}

print_summary() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")

    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                    VERIFICATION SUMMARY                           ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Verification Date: $timestamp"
    echo "Release Path: $RELEASE_DIR"
    echo ""
    echo "Results:"
    echo -e "  ${GREEN}✓${NC} Passed: $PASSED"
    echo -e "  ${RED}✗${NC} Failed: $FAILED"
    echo ""

    if [ "$FAILED" -eq 0 ]; then
        echo -e "${GREEN}Status: ALL CHECKS PASSED${NC}"
        echo ""
        echo -e "${GREEN}This release is verified and safe to install.${NC}"
        echo ""
        return 0
    else
        echo -e "${RED}Status: SOME CHECKS FAILED${NC}"
        echo ""
        echo -e "${RED}DO NOT INSTALL - Verification failures detected!${NC}"
        echo ""
        return 1
    fi
}

main() {
    local release_dir="${1:-.}"

    # Resolve absolute path
    RELEASE_DIR=$(cd "$release_dir" && pwd)

    print_header

    echo "Release Path: $RELEASE_DIR"
    echo ""

    check_prerequisites
    verify_gpg_signature
    verify_file_integrity
    verify_completeness

    if print_summary; then
        exit 0
    else
        exit 1
    fi
}

# Show usage if -h or --help
if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    echo "Usage: $0 [release-directory]"
    echo ""
    echo "Verify EST Client release signatures and integrity."
    echo ""
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  -v, --verbose  Show detailed output"
    echo ""
    echo "Example:"
    echo "  $0 dist/"
    echo ""
    exit 0
fi

# Enable verbose mode
if [ "${1:-}" = "-v" ] || [ "${1:-}" = "--verbose" ]; then
    VERBOSE=true
    shift
fi

# Run main
main "$@"
