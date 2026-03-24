#!/bin/bash
#
# Build and push the custom CI Docker image
#
# Usage:
#   ./scripts/build-ci-image.sh           # Build and push to registry
#   ./scripts/build-ci-image.sh --test    # Build and test locally only
#   ./scripts/build-ci-image.sh --help    # Show help
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REGISTRY="ghcr.io"
PROJECT="192d-wing/usg-est-client"
IMAGE_NAME="ci"
TAG="latest"
FULL_IMAGE="${REGISTRY}/${PROJECT}/${IMAGE_NAME}:${TAG}"

# Functions
print_header() {
    echo -e "${BLUE}=== $1 ===${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

show_help() {
    cat << EOF
Build and Push Custom CI Docker Image

Usage:
  $0 [OPTIONS]

Options:
  --test          Build and test locally only (don't push)
  --no-cache      Build without using Docker cache
  --scan          Scan image for vulnerabilities after building
  --version TAG   Use custom tag instead of 'latest'
  --help          Show this help message

Examples:
  $0                           # Build and push
  $0 --test                    # Test build locally
  $0 --version v1.2.3          # Build with custom tag
  $0 --no-cache --scan         # Full rebuild with security scan

Multi-Platform Support:
  If Docker buildx is available, the image will be built for linux/amd64
  and pushed as a multi-platform manifest. This ensures compatibility
  across different architectures.

Environment Variables:
  DOCKER_BUILDKIT=1            Enable BuildKit for faster builds
  CR_PAT                       GitHub Container Registry token

Prerequisites:
  - Docker installed and running
  - Docker buildx installed (for multi-platform support)
  - Logged in to GitHub Container Registry
  - Execute from project root directory

For detailed documentation, see: docs/BUILD-CI-IMAGE.md
EOF
    exit 0
}

check_prerequisites() {
    print_header "Checking Prerequisites"

    # Check Docker is installed
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed"
        echo "Install Docker from: https://docs.docker.com/get-docker/"
        exit 1
    fi
    print_success "Docker is installed: $(docker --version)"

    # Check Docker is running
    if ! docker info &> /dev/null; then
        print_error "Docker daemon is not running"
        echo "Start Docker and try again"
        exit 1
    fi
    print_success "Docker daemon is running"

    # Check we're in project root
    if [ ! -f "cicd/Dockerfile.ci" ]; then
        print_error "cicd/Dockerfile.ci not found"
        echo "Run this script from the project root directory"
        exit 1
    fi
    print_success "Found cicd/Dockerfile.ci"

    echo ""
}

check_registry_login() {
    print_header "Checking Registry Authentication"

    # Check if already logged in
    if docker system info 2>&1 | grep -q "${REGISTRY}"; then
        print_success "Already logged in to ${REGISTRY}"
        return 0
    fi

    # Try to log in
    print_warning "Not logged in to ${REGISTRY}"
    echo "Attempting to log in..."

    if [ -n "$CR_PAT" ]; then
        echo "$CR_PAT" | docker login "$REGISTRY" -u USERNAME --password-stdin
    else
        docker login "$REGISTRY"
    fi

    if [ $? -eq 0 ]; then
        print_success "Successfully logged in to ${REGISTRY}"
    else
        print_error "Failed to log in to ${REGISTRY}"
        echo ""
        echo "To log in manually:"
        echo "  docker login ${REGISTRY}"
        echo ""
        echo "Or set environment variables:"
        echo "  export CR_PAT=your-github-token"
        exit 1
    fi

    echo ""
}

build_image() {
    print_header "Building CI Docker Image"

    BUILD_ARGS=""
    if [ "$NO_CACHE" = true ]; then
        BUILD_ARGS="$BUILD_ARGS --no-cache"
        print_warning "Building without cache (will take longer)"
    fi

    # Check if buildx is available for multi-platform builds
    USE_BUILDX=false
    if docker buildx version &> /dev/null; then
        USE_BUILDX=true
        print_success "Docker buildx detected - will build multi-platform image (linux/amd64)"
    else
        print_warning "Docker buildx not available - building for current platform only"
    fi

    echo "Image: ${FULL_IMAGE}"
    echo "Dockerfile: cicd/Dockerfile.ci"
    if [ "$USE_BUILDX" = true ]; then
        echo "Platforms: linux/amd64"
    fi
    echo ""

    # Build the image
    if [ "$USE_BUILDX" = true ]; then
        # Multi-platform build with buildx
        set -x
        docker buildx build $BUILD_ARGS \
            --platform linux/amd64 \
            -f cicd/Dockerfile.ci \
            -t "${FULL_IMAGE}" \
            --load \
            .
        set +x
    else
        # Standard build for current platform
        set -x
        docker build $BUILD_ARGS \
            -f cicd/Dockerfile.ci \
            -t "${FULL_IMAGE}" \
            .
        set +x
    fi

    if [ $? -eq 0 ]; then
        print_success "Image built successfully"

        # Show image info
        echo ""
        echo "Image details:"
        docker images "${FULL_IMAGE}" --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}"
    else
        print_error "Image build failed"
        exit 1
    fi

    echo ""
}

test_image() {
    print_header "Testing CI Image"

    echo "Running verification tests..."
    echo ""

    # Test Rust installation
    echo -n "Testing Rust... "
    if docker run --rm "${FULL_IMAGE}" rustc --version > /dev/null 2>&1; then
        RUST_VERSION=$(docker run --rm "${FULL_IMAGE}" rustc --version)
        print_success "$RUST_VERSION"
    else
        print_error "Rust not found"
        exit 1
    fi

    # Test Cargo
    echo -n "Testing Cargo... "
    if docker run --rm "${FULL_IMAGE}" cargo --version > /dev/null 2>&1; then
        CARGO_VERSION=$(docker run --rm "${FULL_IMAGE}" cargo --version)
        print_success "$CARGO_VERSION"
    else
        print_error "Cargo not found"
        exit 1
    fi

    # Test cargo-audit
    echo -n "Testing cargo-audit... "
    if docker run --rm "${FULL_IMAGE}" cargo audit --version > /dev/null 2>&1; then
        AUDIT_VERSION=$(docker run --rm "${FULL_IMAGE}" cargo audit --version)
        print_success "$AUDIT_VERSION"
    else
        print_error "cargo-audit not found"
        exit 1
    fi

    # Test cargo-tarpaulin
    echo -n "Testing cargo-tarpaulin... "
    if docker run --rm "${FULL_IMAGE}" cargo tarpaulin --version > /dev/null 2>&1; then
        TARPAULIN_VERSION=$(docker run --rm "${FULL_IMAGE}" cargo tarpaulin --version)
        print_success "$TARPAULIN_VERSION"
    else
        print_error "cargo-tarpaulin not found"
        exit 1
    fi

    # Test cargo-deny
    echo -n "Testing cargo-deny... "
    if docker run --rm "${FULL_IMAGE}" cargo deny --version > /dev/null 2>&1; then
        DENY_VERSION=$(docker run --rm "${FULL_IMAGE}" cargo deny --version)
        print_success "$DENY_VERSION"
    else
        print_error "cargo-deny not found"
        exit 1
    fi

    # Test targets
    echo -n "Testing x86_64-unknown-linux-gnu target... "
    if docker run --rm "${FULL_IMAGE}" rustup target list --installed | grep -q "x86_64-unknown-linux-gnu"; then
        print_success "Installed"
    else
        print_error "Not installed"
        exit 1
    fi

    echo -n "Testing x86_64-unknown-linux-musl target... "
    if docker run --rm "${FULL_IMAGE}" rustup target list --installed | grep -q "x86_64-unknown-linux-musl"; then
        print_success "Installed"
    else
        print_error "Not installed"
        exit 1
    fi

    echo -n "Testing x86_64-pc-windows-gnu target... "
    if docker run --rm "${FULL_IMAGE}" rustup target list --installed | grep -q "x86_64-pc-windows-gnu"; then
        print_success "Installed"
    else
        print_error "Not installed"
        exit 1
    fi

    echo -n "Testing x86_64-apple-darwin target... "
    if docker run --rm "${FULL_IMAGE}" rustup target list --installed | grep -q "x86_64-apple-darwin"; then
        print_success "Installed"
    else
        print_error "Not installed"
        exit 1
    fi

    echo -n "Testing aarch64-apple-darwin target... "
    if docker run --rm "${FULL_IMAGE}" rustup target list --installed | grep -q "aarch64-apple-darwin"; then
        print_success "Installed"
    else
        print_error "Not installed"
        exit 1
    fi

    print_success "All tests passed!"
    echo ""
}

scan_image() {
    print_header "Scanning Image for Vulnerabilities"

    # Try different scanning tools
    if command -v trivy &> /dev/null; then
        echo "Using Trivy..."
        trivy image "${FULL_IMAGE}"
    elif command -v docker-scout &> /dev/null; then
        echo "Using Docker Scout..."
        docker scout quickview "${FULL_IMAGE}"
    else
        print_warning "No vulnerability scanner found"
        echo "Install Trivy or Docker Scout for vulnerability scanning"
        echo "  Trivy: https://github.com/aquasecurity/trivy"
        echo "  Docker Scout: https://docs.docker.com/scout/"
    fi

    echo ""
}

push_image() {
    print_header "Pushing Image to Registry"

    echo "Pushing: ${FULL_IMAGE}"
    echo ""

    # Check if we should use buildx for multi-platform push
    if docker buildx version &> /dev/null; then
        print_success "Using buildx to push multi-platform image"

        # Build and push multi-platform image directly
        docker buildx build \
            --platform linux/amd64 \
            -f cicd/Dockerfile.ci \
            -t "${FULL_IMAGE}" \
            --push \
            .
    else
        # Standard push
        docker push "${FULL_IMAGE}"
    fi

    if [ $? -eq 0 ]; then
        print_success "Image pushed successfully"
        echo ""
        echo "Image available at:"
        echo "  ${FULL_IMAGE}"
        echo ""
        echo "View in GitHub:"
        echo "  https://github.com/orgs/192d-Wing/packages"
    else
        print_error "Failed to push image"
        exit 1
    fi

    echo ""
}

# Parse command line arguments
TEST_ONLY=false
NO_CACHE=false
SCAN=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --test)
            TEST_ONLY=true
            shift
            ;;
        --no-cache)
            NO_CACHE=true
            shift
            ;;
        --scan)
            SCAN=true
            shift
            ;;
        --version)
            TAG="$2"
            FULL_IMAGE="${REGISTRY}/${PROJECT}/${IMAGE_NAME}:${TAG}"
            shift 2
            ;;
        --help|-h)
            show_help
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Main execution
echo ""
print_header "CI Docker Image Build Script"
echo "Image: ${FULL_IMAGE}"
echo "Mode: $([ "$TEST_ONLY" = true ] && echo "Test Only" || echo "Build and Push")"
echo ""

check_prerequisites
build_image
test_image

if [ "$SCAN" = true ]; then
    scan_image
fi

if [ "$TEST_ONLY" = false ]; then
    check_registry_login
    push_image

    print_success "Build and push completed successfully!"
    echo ""
    echo "Next steps:"
    echo "  1. Verify image in GitHub Container Registry"
    echo "  2. Run a test CI pipeline to confirm it's used"
    echo "  3. Monitor pipeline performance improvements"
else
    print_success "Local build and test completed successfully!"
    echo ""
    echo "To push to registry, run without --test flag:"
    echo "  $0"
fi

echo ""
