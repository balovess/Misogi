#!/bin/bash
# =============================================================================
# Misogi (禊) — Quick Start Script
# =============================================================================
# One-command setup and launch for Misogi secure file transfer system.
#
# Usage:
#   ./scripts/quickstart.sh [OPTIONS]
#
# Options:
#   --preset <name>    Use a preset configuration (minimal, lgwan, medical, enterprise)
#   --no-docker        Build from source instead of Docker
#   --check-only       Only run dependency checks, don't start services
#   --help             Show this help message
#
# Examples:
#   ./scripts/quickstart.sh                    # Default setup with Docker
#   ./scripts/quickstart.sh --preset lgwan     # LGWAN government preset
#   ./scripts/quickstart.sh --no-docker        # Build from source
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PRESET="default"
USE_DOCKER=true
CHECK_ONLY=false
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------

print_header() {
    echo -e "${BLUE}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                    Misogi (禊) Quick Start                     ║"
    echo "║         Secure File Transfer with CDR Sanitization            ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_step() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

show_help() {
    print_header
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --preset <name>    Use preset configuration (minimal, lgwan, medical, enterprise)"
    echo "  --no-docker        Build from source instead of Docker"
    echo "  --check-only       Only run dependency checks"
    echo "  --help             Show this help message"
    echo ""
    echo "Available Presets:"
    echo "  minimal    - Minimum configuration for testing"
    echo "  lgwan      - Japanese local government (LGWAN) compliance"
    echo "  medical    - Medical institution (HIPAA-Japan) compliance"
    echo "  enterprise - General enterprise configuration"
    echo ""
    echo "Examples:"
    echo "  $0                      # Default setup with Docker"
    echo "  $0 --preset lgwan       # LGWAN government preset"
    echo "  $0 --no-docker          # Build from source"
    exit 0
}

# -----------------------------------------------------------------------------
# Dependency Checking
# -----------------------------------------------------------------------------

check_docker() {
    if command -v docker &> /dev/null; then
        DOCKER_VERSION=$(docker --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        print_step "Docker: $DOCKER_VERSION"
        return 0
    else
        print_error "Docker: not found"
        print_info "Install: https://docs.docker.com/get-docker/"
        return 1
    fi
}

check_docker_compose() {
    if docker compose version &> /dev/null; then
        COMPOSE_VERSION=$(docker compose version --short 2>/dev/null)
        print_step "Docker Compose: $COMPOSE_VERSION"
        return 0
    elif command -v docker-compose &> /dev/null; then
        COMPOSE_VERSION=$(docker-compose --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
        print_step "Docker Compose: $COMPOSE_VERSION (legacy)"
        return 0
    else
        print_error "Docker Compose: not found"
        return 1
    fi
}

check_git() {
    if command -v git &> /dev/null; then
        GIT_VERSION=$(git --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
        print_step "Git: $GIT_VERSION"
        return 0
    else
        print_warning "Git: not found (optional)"
        return 0
    fi
}

check_curl() {
    if command -v curl &> /dev/null; then
        print_step "curl: available"
        return 0
    else
        print_warning "curl: not found (needed for health checks)"
        return 0
    fi
}

check_openssl() {
    if command -v openssl &> /dev/null; then
        OPENSSL_VERSION=$(openssl version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
        print_step "OpenSSL: $OPENSSL_VERSION"
        return 0
    else
        print_warning "OpenSSL: not found (needed for key generation)"
        return 0
    fi
}

check_rust() {
    if command -v rustc &> /dev/null; then
        RUST_VERSION=$(rustc --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
        print_step "Rust: $RUST_VERSION"
        return 0
    else
        print_warning "Rust: not found (only needed for --no-docker)"
        return 0
    fi
}

check_protoc() {
    if command -v protoc &> /dev/null; then
        PROTOC_VERSION=$(protoc --version 2>/dev/null | grep -oE '[0-9]+')
        print_step "protoc: $PROTOC_VERSION"
        return 0
    else
        print_warning "protoc: not found (only needed for --no-docker)"
        return 0
    fi
}

run_dependency_checks() {
    echo ""
    echo "Checking dependencies..."
    echo "========================"
    
    local all_required=true
    
    if [ "$USE_DOCKER" = true ]; then
        check_docker || all_required=false
        check_docker_compose || all_required=false
    else
        check_rust
        check_protoc
    fi
    
    check_git
    check_curl
    check_openssl
    
    echo ""
    
    if [ "$all_required" = true ]; then
        print_step "All required dependencies satisfied"
        return 0
    else
        print_error "Missing required dependencies"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Configuration Setup
# -----------------------------------------------------------------------------

setup_config() {
    echo ""
    echo "Setting up configuration..."
    echo "==========================="
    
    cd "$PROJECT_ROOT"
    
    # Create config file if not exists
    if [ ! -f "misogi.toml" ]; then
        case "$PRESET" in
            minimal)
                cp config/examples/minimal.toml misogi.toml
                print_step "Created misogi.toml (minimal preset)"
                ;;
            lgwan)
                cp config/examples/lgwan.toml misogi.toml
                print_step "Created misogi.toml (LGWAN government preset)"
                ;;
            medical)
                cp config/examples/medical.toml misogi.toml
                print_step "Created misogi.toml (medical institution preset)"
                ;;
            enterprise)
                cp config/examples/enterprise.toml misogi.toml
                print_step "Created misogi.toml (enterprise preset)"
                ;;
            *)
                cp config/misogi.toml.default misogi.toml
                print_step "Created misogi.toml (default configuration)"
                ;;
        esac
    else
        print_info "misogi.toml already exists, skipping"
    fi
    
    # Create .env file if not exists
    if [ ! -f ".env" ]; then
        if [ -f "docker/env.example" ]; then
            cp docker/env.example .env
            print_step "Created .env from template"
        fi
    else
        print_info ".env already exists, skipping"
    fi
    
    # Create data directories
    mkdir -p data/uploads data/staging data/chunks data/downloads
    print_step "Created data directories"
}

# -----------------------------------------------------------------------------
# Key Generation
# -----------------------------------------------------------------------------

generate_keys() {
    echo ""
    echo "Generating RSA keypair..."
    echo "========================="
    
    cd "$PROJECT_ROOT"
    
    mkdir -p keys
    
    if [ -f "keys/private.pem" ] && [ -f "keys/public.pem" ]; then
        print_info "RSA keypair already exists, skipping"
        return 0
    fi
    
    if command -v openssl &> /dev/null; then
        openssl genrsa -out keys/private.pem 2048 2>/dev/null
        openssl rsa -in keys/private.pem -pubout -out keys/public.pem 2>/dev/null
        chmod 600 keys/private.pem
        chmod 644 keys/public.pem
        print_step "Generated RSA keypair in keys/"
    else
        print_warning "OpenSSL not found, skipping key generation"
        print_info "Generate keys manually: cargo run --package misogi-auth --example generate-keys -- ./keys"
    fi
}

# -----------------------------------------------------------------------------
# Docker Deployment
# -----------------------------------------------------------------------------

start_docker() {
    echo ""
    echo "Starting Docker services..."
    echo "==========================="
    
    cd "$PROJECT_ROOT"
    
    # Build and start services
    docker compose up -d --build
    
    echo ""
    echo "Waiting for services to start..."
    sleep 5
    
    # Health check
    check_health
}

check_health() {
    echo ""
    echo "Checking service health..."
    echo "========================="
    
    local sender_healthy=false
    local receiver_healthy=false
    local max_attempts=30
    local attempt=0
    
    while [ $attempt -lt $max_attempts ]; do
        if curl -sf http://localhost:3001/api/v1/health > /dev/null 2>&1; then
            sender_healthy=true
        fi
        
        if curl -sf http://localhost:3002/api/v1/health > /dev/null 2>&1; then
            receiver_healthy=true
        fi
        
        if [ "$sender_healthy" = true ] && [ "$receiver_healthy" = true ]; then
            break
        fi
        
        attempt=$((attempt + 1))
        echo -n "."
        sleep 1
    done
    
    echo ""
    
    if [ "$sender_healthy" = true ]; then
        print_step "Sender: healthy (http://localhost:3001)"
    else
        print_warning "Sender: not responding"
    fi
    
    if [ "$receiver_healthy" = true ]; then
        print_step "Receiver: healthy (http://localhost:3002)"
    else
        print_warning "Receiver: not responding"
    fi
}

# -----------------------------------------------------------------------------
# Source Build
# -----------------------------------------------------------------------------

build_from_source() {
    echo ""
    echo "Building from source..."
    echo "======================="
    
    cd "$PROJECT_ROOT"
    
    cargo build --release --bins
    print_step "Build complete"
    
    echo ""
    echo "Binaries available at:"
    echo "  ./target/release/misogi-sender"
    echo "  ./target/release/misogi-receiver"
}

# -----------------------------------------------------------------------------
# Print Next Steps
# -----------------------------------------------------------------------------

print_next_steps() {
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                    Setup Complete!                             ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Services:"
    echo "  • Sender API:   http://localhost:3001"
    echo "  • Receiver API: http://localhost:3002"
    echo "  • Tunnel Port:  localhost:9000"
    echo ""
    echo "Quick Test:"
    echo "  curl http://localhost:3001/api/v1/health"
    echo "  curl -F 'file=@test.pdf' http://localhost:3001/api/v1/upload"
    echo ""
    echo "Useful Commands:"
    echo "  docker compose logs -f        # View logs"
    echo "  docker compose down           # Stop services"
    echo "  docker compose ps             # Check status"
    echo ""
    echo "Documentation:"
    echo "  README.md                     # Overview"
    echo "  docker/README.md              # Docker guide"
    echo "  config/misogi.toml.default    # Configuration reference"
    echo ""
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --preset)
                PRESET="$2"
                shift 2
                ;;
            --no-docker)
                USE_DOCKER=false
                shift
                ;;
            --check-only)
                CHECK_ONLY=true
                shift
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
    
    print_header
    
    # Run dependency checks
    if ! run_dependency_checks; then
        exit 1
    fi
    
    if [ "$CHECK_ONLY" = true ]; then
        exit 0
    fi
    
    # Setup configuration
    setup_config
    
    # Generate keys
    generate_keys
    
    # Start services
    if [ "$USE_DOCKER" = true ]; then
        start_docker
    else
        build_from_source
    fi
    
    # Print next steps
    print_next_steps
}

main "$@"
