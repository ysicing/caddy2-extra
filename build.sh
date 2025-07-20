#!/bin/bash

# Build script for Caddy with GFWReport plugin
# This script provides multiple build methods for the plugin

set -e

# Configuration
PLUGIN_NAME="gfwreport"
BINARY_NAME="caddy"
BUILD_DIR="build"
VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check Go installation
    if ! command -v go &> /dev/null; then
        log_error "Go is not installed. Please install Go 1.19 or later."
        exit 1
    fi
    
    # Check Go version
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    log_info "Go version: $GO_VERSION"
    
    # Check if xcaddy is available for method 1
    if command -v xcaddy &> /dev/null; then
        XCADDY_VERSION=$(xcaddy version 2>/dev/null || echo "unknown")
        log_info "xcaddy version: $XCADDY_VERSION"
    else
        log_warning "xcaddy not found. Method 1 (xcaddy build) will not be available."
    fi
}

# Show external build command
show_external_build_command() {
    log_info "External build command:"
    echo ""
    echo "To build from an external directory, use:"
    echo ""
    echo "  xcaddy build --with github.com/ysicing/caddy2-extra/gfwreport=../caddy2-extra/gfwreport"
    echo ""
    echo "Or if you're in a different relative path:"
    echo ""
    echo "  xcaddy build --with github.com/ysicing/caddy2-extra/gfwreport=/path/to/caddy2-extra/gfwreport"
    echo ""
    log_info "This will create a 'caddy' binary in your current directory with the gfwreport plugin included."
    echo ""
    log_info "Example usage:"
    echo "  mkdir ~/my-caddy-build"
    echo "  cd ~/my-caddy-build"
    echo "  xcaddy build --with github.com/ysicing/caddy2-extra/gfwreport=~/path/to/caddy2-extra/gfwreport"
    echo "  ./caddy list-modules | grep gfwreport"
}

# Method 1: Build using xcaddy (recommended)
build_with_xcaddy() {
    log_info "Building with xcaddy..."
    
    if ! command -v xcaddy &> /dev/null; then
        log_error "xcaddy is not installed. Installing..."
        go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
        
        if ! command -v xcaddy &> /dev/null; then
            log_error "Failed to install xcaddy"
            return 1
        fi
    fi
    
    # Create build directory
    mkdir -p "$BUILD_DIR"
    
    # Build with xcaddy
    log_info "Running xcaddy build..."
    xcaddy build \
        --output "$BUILD_DIR/$BINARY_NAME" \
        --with "github.com/ysicing/caddy2-extra/gfwreport=./gfwreport"
    
    if [ $? -eq 0 ]; then
        log_success "Build completed successfully with xcaddy"
        return 0
    else
        log_error "Build failed with xcaddy"
        return 1
    fi
}

# Method 2: Manual build using go build
build_manual() {
    log_info "Building manually with go build..."
    
    # Create build directory
    mkdir -p "$BUILD_DIR"
    
    # Build the binary
    log_info "Running go build..."
    CGO_ENABLED=0 go build \
        -ldflags "-X main.version=$VERSION -s -w" \
        -o "$BUILD_DIR/$BINARY_NAME" \
        main.go
    
    if [ $? -eq 0 ]; then
        log_success "Build completed successfully with go build"
        return 0
    else
        log_error "Build failed with go build"
        return 1
    fi
}

# Method 3: Build Docker image
build_docker() {
    log_info "Building Docker image..."
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        return 1
    fi
    
    # Build Docker image
    docker build -t "caddy-$PLUGIN_NAME:$VERSION" -f examples/Dockerfile .
    
    if [ $? -eq 0 ]; then
        log_success "Docker image built successfully"
        docker tag "caddy-$PLUGIN_NAME:$VERSION" "caddy-$PLUGIN_NAME:latest"
        log_info "Tagged as caddy-$PLUGIN_NAME:latest"
        return 0
    else
        log_error "Docker build failed"
        return 1
    fi
}

# Test the built binary
test_binary() {
    local binary_path="$BUILD_DIR/$BINARY_NAME"
    
    if [ ! -f "$binary_path" ]; then
        log_error "Binary not found at $binary_path"
        return 1
    fi
    
    log_info "Testing built binary..."
    
    # Test version
    log_info "Checking version..."
    "$binary_path" version
    
    # Test plugin loading
    log_info "Checking if plugin is loaded..."
    if "$binary_path" list-modules | grep -q "http.handlers.$PLUGIN_NAME"; then
        log_success "Plugin is properly loaded"
    else
        log_error "Plugin is not loaded"
        return 1
    fi
    
    # Test configuration validation
    log_info "Testing configuration validation..."
    if [ -f "examples/basic-config.Caddyfile" ]; then
        "$binary_path" validate --config examples/basic-config.Caddyfile --adapter caddyfile
        if [ $? -eq 0 ]; then
            log_success "Configuration validation passed"
        else
            log_error "Configuration validation failed"
            return 1
        fi
    fi
    
    return 0
}

# Clean build artifacts
clean() {
    log_info "Cleaning build artifacts..."
    rm -rf "$BUILD_DIR"
    log_success "Clean completed"
}

# Install the binary
install() {
    local binary_path="$BUILD_DIR/$BINARY_NAME"
    local install_path="/usr/local/bin/$BINARY_NAME"
    
    if [ ! -f "$binary_path" ]; then
        log_error "Binary not found. Please build first."
        return 1
    fi
    
    log_info "Installing binary to $install_path..."
    
    if [ "$EUID" -ne 0 ]; then
        log_info "Installing with sudo..."
        sudo cp "$binary_path" "$install_path"
        sudo chmod +x "$install_path"
    else
        cp "$binary_path" "$install_path"
        chmod +x "$install_path"
    fi
    
    log_success "Installation completed"
}

# Show usage information
usage() {
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  xcaddy      Build using xcaddy (recommended)"
    echo "  external    Build from external directory (xcaddy build --with github.com/ysicing/caddy2-extra/gfwreport=../caddy2-extra/gfwreport)"
    echo "  manual      Build manually with go build"
    echo "  docker      Build Docker image"
    echo "  test        Test the built binary"
    echo "  clean       Clean build artifacts"
    echo "  install     Install binary to /usr/local/bin"
    echo "  all         Build with xcaddy, test, and show info"
    echo "  help        Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 xcaddy           # Build with xcaddy"
    echo "  $0 external         # Show external build command"
    echo "  $0 manual           # Build manually"
    echo "  $0 docker           # Build Docker image"
    echo "  $0 all              # Build, test, and show info"
}

# Main execution
main() {
    local command="${1:-all}"
    
    case "$command" in
        "xcaddy")
            check_prerequisites
            build_with_xcaddy
            ;;
        "external")
            show_external_build_command
            ;;
        "manual")
            check_prerequisites
            build_manual
            ;;
        "docker")
            check_prerequisites
            build_docker
            ;;
        "test")
            test_binary
            ;;
        "clean")
            clean
            ;;
        "install")
            install
            ;;
        "all")
            check_prerequisites
            
            # Try xcaddy first, fallback to manual
            if build_with_xcaddy || build_manual; then
                test_binary
                
                # Show build info
                log_info "Build information:"
                echo "  Plugin: $PLUGIN_NAME"
                echo "  Version: $VERSION"
                echo "  Binary: $BUILD_DIR/$BINARY_NAME"
                
                if [ -f "$BUILD_DIR/$BINARY_NAME" ]; then
                    echo "  Size: $(du -h "$BUILD_DIR/$BINARY_NAME" | cut -f1)"
                fi
                
                log_info "To install: $0 install"
                log_info "To test: $BUILD_DIR/$BINARY_NAME run --config examples/basic-config.Caddyfile"
            else
                log_error "All build methods failed"
                exit 1
            fi
            ;;
        "help"|"-h"|"--help")
            usage
            ;;
        *)
            log_error "Unknown command: $command"
            usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
