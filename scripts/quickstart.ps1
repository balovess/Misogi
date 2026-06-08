# =============================================================================
# Misogi (禊) — Quick Start Script for Windows
# =============================================================================
# One-command setup and launch for Misogi secure file transfer system.
#
# Usage:
#   .\scripts\quickstart.ps1 [OPTIONS]
#
# Options:
#   -Preset <name>     Use a preset configuration (minimal, lgwan, medical, enterprise)
#   -NoDocker          Build from source instead of Docker
#   -CheckOnly         Only run dependency checks, don't start services
#   -Help              Show this help message
#
# Examples:
#   .\scripts\quickstart.ps1                    # Default setup with Docker
#   .\scripts\quickstart.ps1 -Preset lgwan      # LGWAN government preset
#   .\scripts\quickstart.ps1 -NoDocker          # Build from source
# =============================================================================

param(
    [string]$Preset = "default",
    [switch]$NoDocker,
    [switch]$CheckOnly,
    [switch]$Help
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot

# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------

function Print-Header {
    Write-Host ""
    Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Blue
    Write-Host "║                    Misogi (禊) Quick Start                     ║" -ForegroundColor Blue
    Write-Host "║         Secure File Transfer with CDR Sanitization            ║" -ForegroundColor Blue
    Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Blue
    Write-Host ""
}

function Print-Success {
    param([string]$Message)
    Write-Host "[✓] $Message" -ForegroundColor Green
}

function Print-Warning {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Print-Error {
    param([string]$Message)
    Write-Host "[✗] $Message" -ForegroundColor Red
}

function Print-Info {
    param([string]$Message)
    Write-Host "[i] $Message" -ForegroundColor Cyan
}

function Show-Help {
    Print-Header
    Write-Host "Usage: .\scripts\quickstart.ps1 [OPTIONS]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -Preset <name>     Use preset configuration (minimal, lgwan, medical, enterprise)"
    Write-Host "  -NoDocker          Build from source instead of Docker"
    Write-Host "  -CheckOnly         Only run dependency checks"
    Write-Host "  -Help              Show this help message"
    Write-Host ""
    Write-Host "Available Presets:"
    Write-Host "  minimal    - Minimum configuration for testing"
    Write-Host "  lgwan      - Japanese local government (LGWAN) compliance"
    Write-Host "  medical    - Medical institution (HIPAA-Japan) compliance"
    Write-Host "  enterprise - General enterprise configuration"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\scripts\quickstart.ps1                      # Default setup with Docker"
    Write-Host "  .\scripts\quickstart.ps1 -Preset lgwan       # LGWAN government preset"
    Write-Host "  .\scripts\quickstart.ps1 -NoDocker           # Build from source"
    exit 0
}

# -----------------------------------------------------------------------------
# Dependency Checking
# -----------------------------------------------------------------------------

function Check-Docker {
    if (Get-Command docker -ErrorAction SilentlyContinue) {
        $version = (docker --version 2>$null) -replace '.*(\d+\.\d+\.\d+).*', '$1'
        Print-Success "Docker: $version"
        return $true
    } else {
        Print-Error "Docker: not found"
        Print-Info "Install: https://docs.docker.com/desktop/install/windows-install/"
        return $false
    }
}

function Check-DockerCompose {
    if (docker compose version 2>$null) {
        $version = (docker compose version --short 2>$null)
        Print-Success "Docker Compose: $version"
        return $true
    } elseif (Get-Command docker-compose -ErrorAction SilentlyContinue) {
        $version = (docker-compose --version 2>$null) -replace '.*(\d+\.\d+\.\d+).*', '$1'
        Print-Success "Docker Compose: $version (legacy)"
        return $true
    } else {
        Print-Error "Docker Compose: not found"
        return $false
    }
}

function Check-Git {
    if (Get-Command git -ErrorAction SilentlyContinue) {
        $version = (git --version 2>$null) -replace '.*(\d+\.\d+\.\d+).*', '$1'
        Print-Success "Git: $version"
        return $true
    } else {
        Print-Warning "Git: not found (optional)"
        return $true
    }
}

function Check-Curl {
    if (Get-Command curl -ErrorAction SilentlyContinue) {
        Print-Success "curl: available"
        return $true
    } else {
        Print-Warning "curl: not found (needed for health checks)"
        return $true
    }
}

function Check-OpenSSL {
    if (Get-Command openssl -ErrorAction SilentlyContinue) {
        $version = (openssl version 2>$null) -replace '.*(\d+\.\d+\.\d+).*', '$1'
        Print-Success "OpenSSL: $version"
        return $true
    } else {
        Print-Warning "OpenSSL: not found (needed for key generation)"
        return $true
    }
}

function Check-Rust {
    if (Get-Command rustc -ErrorAction SilentlyContinue) {
        $version = (rustc --version 2>$null) -replace '.*(\d+\.\d+\.\d+).*', '$1'
        Print-Success "Rust: $version"
        return $true
    } else {
        Print-Warning "Rust: not found (only needed for -NoDocker)"
        return $true
    }
}

function Run-DependencyChecks {
    Write-Host ""
    Write-Host "Checking dependencies..."
    Write-Host "========================"
    
    $allRequired = $true
    
    if (-not $NoDocker) {
        if (-not (Check-Docker)) { $allRequired = $false }
        if (-not (Check-DockerCompose)) { $allRequired = $false }
    } else {
        Check-Rust | Out-Null
    }
    
    Check-Git | Out-Null
    Check-Curl | Out-Null
    Check-OpenSSL | Out-Null
    
    Write-Host ""
    
    if ($allRequired) {
        Print-Success "All required dependencies satisfied"
        return $true
    } else {
        Print-Error "Missing required dependencies"
        return $false
    }
}

# -----------------------------------------------------------------------------
# Configuration Setup
# -----------------------------------------------------------------------------

function Setup-Config {
    Write-Host ""
    Write-Host "Setting up configuration..."
    Write-Host "==========================="
    
    Set-Location $ProjectRoot
    
    # Create config file if not exists
    if (-not (Test-Path "misogi.toml")) {
        $configSource = switch ($Preset) {
            "minimal" { "config\examples\minimal.toml" }
            "lgwan" { "config\examples\lgwan.toml" }
            "medical" { "config\examples\medical.toml" }
            "enterprise" { "config\examples\enterprise.toml" }
            default { "config\misogi.toml.default" }
        }
        
        if (Test-Path $configSource) {
            Copy-Item $configSource "misogi.toml"
            Print-Success "Created misogi.toml ($Preset preset)"
        } else {
            Print-Warning "Config template not found: $configSource"
        }
    } else {
        Print-Info "misogi.toml already exists, skipping"
    }
    
    # Create .env file if not exists
    if (-not (Test-Path ".env")) {
        if (Test-Path "docker\env.example") {
            Copy-Item "docker\env.example" ".env"
            Print-Success "Created .env from template"
        }
    } else {
        Print-Info ".env already exists, skipping"
    }
    
    # Create data directories
    $dirs = @("data\uploads", "data\staging", "data\chunks", "data\downloads")
    foreach ($dir in $dirs) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }
    Print-Success "Created data directories"
}

# -----------------------------------------------------------------------------
# Key Generation
# -----------------------------------------------------------------------------

function Generate-Keys {
    Write-Host ""
    Write-Host "Generating RSA keypair..."
    Write-Host "========================="
    
    Set-Location $ProjectRoot
    
    $keysDir = "keys"
    if (-not (Test-Path $keysDir)) {
        New-Item -ItemType Directory -Path $keysDir -Force | Out-Null
    }
    
    if ((Test-Path "keys\private.pem") -and (Test-Path "keys\public.pem")) {
        Print-Info "RSA keypair already exists, skipping"
        return
    }
    
    if (Get-Command openssl -ErrorAction SilentlyContinue) {
        openssl genrsa -out "keys\private.pem" 2048 2>$null
        openssl rsa -in "keys\private.pem" -pubout -out "keys\public.pem" 2>$null
        Print-Success "Generated RSA keypair in keys\"
    } else {
        Print-Warning "OpenSSL not found, skipping key generation"
        Print-Info "Generate keys manually: cargo run --package misogi-auth --example generate-keys -- .\keys"
    }
}

# -----------------------------------------------------------------------------
# Docker Deployment
# -----------------------------------------------------------------------------

function Start-DockerServices {
    Write-Host ""
    Write-Host "Starting Docker services..."
    Write-Host "==========================="
    
    Set-Location $ProjectRoot
    
    # Build and start services
    docker compose up -d --build
    
    Write-Host ""
    Write-Host "Waiting for services to start..."
    Start-Sleep -Seconds 5
    
    # Health check
    Check-Health
}

function Check-Health {
    Write-Host ""
    Write-Host "Checking service health..."
    Write-Host "========================="
    
    $senderHealthy = $false
    $receiverHealthy = $false
    $maxAttempts = 30
    
    for ($i = 0; $i -lt $maxAttempts; $i++) {
        try {
            $response = Invoke-WebRequest -Uri "http://localhost:3001/api/v1/health" -TimeoutSec 2 -ErrorAction SilentlyContinue
            if ($response.StatusCode -eq 200) { $senderHealthy = $true }
        } catch {}
        
        try {
            $response = Invoke-WebRequest -Uri "http://localhost:3002/api/v1/health" -TimeoutSec 2 -ErrorAction SilentlyContinue
            if ($response.StatusCode -eq 200) { $receiverHealthy = $true }
        } catch {}
        
        if ($senderHealthy -and $receiverHealthy) { break }
        
        Write-Host -NoNewline "."
        Start-Sleep -Seconds 1
    }
    
    Write-Host ""
    
    if ($senderHealthy) {
        Print-Success "Sender: healthy (http://localhost:3001)"
    } else {
        Print-Warning "Sender: not responding"
    }
    
    if ($receiverHealthy) {
        Print-Success "Receiver: healthy (http://localhost:3002)"
    } else {
        Print-Warning "Receiver: not responding"
    }
}

# -----------------------------------------------------------------------------
# Source Build
# -----------------------------------------------------------------------------

function Build-FromSource {
    Write-Host ""
    Write-Host "Building from source..."
    Write-Host "======================="
    
    Set-Location $ProjectRoot
    
    cargo build --release --bins
    Print-Success "Build complete"
    
    Write-Host ""
    Write-Host "Binaries available at:"
    Write-Host "  .\target\release\misogi-sender.exe"
    Write-Host "  .\target\release\misogi-receiver.exe"
}

# -----------------------------------------------------------------------------
# Print Next Steps
# -----------------------------------------------------------------------------

function Print-NextSteps {
    Write-Host ""
    Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║                    Setup Complete!                             ║" -ForegroundColor Green
    Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    Write-Host "Services:"
    Write-Host "  • Sender API:   http://localhost:3001"
    Write-Host "  • Receiver API: http://localhost:3002"
    Write-Host "  • Tunnel Port:  localhost:9000"
    Write-Host ""
    Write-Host "Quick Test:"
    Write-Host "  curl http://localhost:3001/api/v1/health"
    Write-Host "  curl -F 'file=@test.pdf' http://localhost:3001/api/v1/upload"
    Write-Host ""
    Write-Host "Useful Commands:"
    Write-Host "  docker compose logs -f        # View logs"
    Write-Host "  docker compose down           # Stop services"
    Write-Host "  docker compose ps             # Check status"
    Write-Host ""
    Write-Host "Documentation:"
    Write-Host "  README.md                     # Overview"
    Write-Host "  docker\README.md              # Docker guide"
    Write-Host "  config\misogi.toml.default    # Configuration reference"
    Write-Host ""
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

if ($Help) {
    Show-Help
}

Print-Header

# Run dependency checks
if (-not (Run-DependencyChecks)) {
    exit 1
}

if ($CheckOnly) {
    exit 0
}

# Setup configuration
Setup-Config

# Generate keys
Generate-Keys

# Start services
if (-not $NoDocker) {
    Start-DockerServices
} else {
    Build-FromSource
}

# Print next steps
Print-NextSteps
