# =============================================================================
# Misogi (禊) — Windows One-Click Installation Script
# =============================================================================
# This script automates the complete installation of Misogi on Windows.
# It handles WSL2, Docker Desktop, and Misogi setup.
#
# Usage:
#   .\scripts\install-windows.ps1 [OPTIONS]
#
# Options:
#   -InstallDocker     Install Docker Desktop if not present
#   -InstallWSL2       Install WSL2 if not present
#   -Preset <name>     Use a preset configuration
#   -Help              Show this help message
#
# Requirements:
#   - Windows 10 version 2004+ or Windows 11
#   - Administrator privileges (for WSL2/Docker installation)
# =============================================================================

param(
    [switch]$InstallDocker,
    [switch]$InstallWSL2,
    [string]$Preset = "default",
    [switch]$Help
)

$ErrorActionPreference = "Stop"

# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------

function Print-Header {
    Write-Host ""
    Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Blue
    Write-Host "║              Misogi (禊) Windows Installation                 ║" -ForegroundColor Blue
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
    Write-Host "Usage: .\scripts\install-windows.ps1 [OPTIONS]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -InstallDocker     Install Docker Desktop if not present"
    Write-Host "  -InstallWSL2       Install WSL2 if not present"
    Write-Host "  -Preset <name>     Use a preset configuration"
    Write-Host "  -Help              Show this help message"
    Write-Host ""
    Write-Host "This script will:"
    Write-Host "  1. Check and optionally install WSL2"
    Write-Host "  2. Check and optionally install Docker Desktop"
    Write-Host "  3. Clone or update the Misogi repository"
    Write-Host "  4. Run the quickstart setup"
    Write-Host ""
    exit 0
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# -----------------------------------------------------------------------------
# WSL2 Installation
# -----------------------------------------------------------------------------

function Check-WSL2 {
    Write-Host "Checking WSL2..." -ForegroundColor Cyan
    
    $wslStatus = wsl --status 2>$null
    if ($LASTEXITCODE -eq 0) {
        Print-Success "WSL2 is installed and configured"
        return $true
    } else {
        Print-Warning "WSL2 is not installed"
        return $false
    }
}

function Install-WSL2 {
    Write-Host ""
    Write-Host "Installing WSL2..." -ForegroundColor Cyan
    Write-Host "This requires administrator privileges."
    Write-Host ""
    
    if (-not (Test-Administrator)) {
        Print-Error "Administrator privileges required for WSL2 installation"
        Print-Info "Please run PowerShell as Administrator and try again."
        Print-Info "Or run: wsl --install"
        return $false
    }
    
    # Enable WSL
    dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart | Out-Null
    Print-Success "Enabled Windows Subsystem for Linux"
    
    # Enable Virtual Machine Platform
    dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart | Out-Null
    Print-Success "Enabled Virtual Machine Platform"
    
    # Set WSL2 as default
    wsl --set-default-version 2 2>$null
    Print-Success "Set WSL2 as default version"
    
    # Install Ubuntu
    Write-Host "Installing Ubuntu (this may take a few minutes)..."
    wsl --install -d Ubuntu 2>$null
    
    Print-Success "WSL2 installation complete"
    Print-Warning "A system restart may be required"
    return $true
}

# -----------------------------------------------------------------------------
# Docker Installation
# -----------------------------------------------------------------------------

function Check-DockerDesktop {
    Write-Host "Checking Docker Desktop..." -ForegroundColor Cyan
    
    if (Get-Command docker -ErrorAction SilentlyContinue) {
        $version = docker --version 2>$null
        Print-Success "Docker Desktop: $version"
        return $true
    } else {
        Print-Warning "Docker Desktop is not installed"
        return $false
    }
}

function Install-DockerDesktop {
    Write-Host ""
    Write-Host "Installing Docker Desktop..." -ForegroundColor Cyan
    
    $dockerUrl = "https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe"
    $installerPath = "$env:TEMP\DockerDesktopInstaller.exe"
    
    Write-Host "Downloading Docker Desktop installer..."
    try {
        Invoke-WebRequest -Uri $dockerUrl -OutFile $installerPath -UseBasicParsing
        Print-Success "Downloaded Docker Desktop installer"
    } catch {
        Print-Error "Failed to download Docker Desktop installer"
        Print-Info "Please download manually from: https://www.docker.com/products/docker-desktop"
        return $false
    }
    
    Write-Host "Running Docker Desktop installer..."
    Write-Host "This will open a new window. Please complete the installation."
    
    Start-Process -FilePath $installerPath -Wait
    
    Print-Success "Docker Desktop installation initiated"
    Print-Info "Please restart PowerShell after Docker Desktop installation completes"
    return $true
}

# -----------------------------------------------------------------------------
# Git and Repository
# -----------------------------------------------------------------------------

function Check-Git {
    if (Get-Command git -ErrorAction SilentlyContinue) {
        return $true
    }
    return $false
}

function Install-Git {
    Write-Host "Installing Git for Windows..." -ForegroundColor Cyan
    
    $gitUrl = "https://github.com/git-for-windows/git/releases/download/v2.43.0.windows.1/Git-2.43.0-64-bit.exe"
    $installerPath = "$env:TEMP\GitInstaller.exe"
    
    try {
        Invoke-WebRequest -Uri $gitUrl -OutFile $installerPath -UseBasicParsing
        Start-Process -FilePath $installerPath -ArgumentList "/VERYSILENT", "/NORESTART" -Wait
        Print-Success "Git installed successfully"
        return $true
    } catch {
        Print-Error "Failed to install Git"
        Print-Info "Please install manually from: https://git-scm.com/download/win"
        return $false
    }
}

function Clone-Repository {
    param([string]$TargetPath)
    
    Write-Host ""
    Write-Host "Setting up Misogi repository..." -ForegroundColor Cyan
    
    $repoUrl = "https://github.com/balovess/Misogi.git"
    
    if (Test-Path "$TargetPath\.git") {
        Print-Info "Repository already exists at $TargetPath"
        Set-Location $TargetPath
        git pull 2>$null
        Print-Success "Repository updated"
    } else {
        if (Test-Path $TargetPath) {
            Print-Warning "Directory exists but is not a git repository"
        } else {
            git clone $repoUrl $TargetPath
            Print-Success "Repository cloned to $TargetPath"
        }
    }
    
    return $TargetPath
}

# -----------------------------------------------------------------------------
# Main Installation Flow
# -----------------------------------------------------------------------------

function Main {
    if ($Help) {
        Show-Help
    }
    
    Print-Header
    
    # Check Windows version
    $windowsVersion = [System.Environment]::OSVersion.Version
    if ($windowsVersion.Major -lt 10) {
        Print-Error "Windows 10 or later is required"
        exit 1
    }
    
    # Step 1: WSL2
    $wslInstalled = Check-WSL2
    if (-not $wslInstalled) {
        if ($InstallWSL2) {
            if (-not (Install-WSL2)) {
                Print-Warning "WSL2 installation incomplete. Continuing anyway..."
            }
        } else {
            Print-Info "To install WSL2, run: wsl --install"
            Print-Info "Or re-run this script with -InstallWSL2 flag"
            
            $response = Read-Host "Install WSL2 now? (Y/n)"
            if ($response -ne "n") {
                Install-WSL2
            }
        }
    }
    
    # Step 2: Docker Desktop
    $dockerInstalled = Check-DockerDesktop
    if (-not $dockerInstalled) {
        if ($InstallDocker) {
            if (-not (Install-DockerDesktop)) {
                Print-Warning "Docker Desktop installation incomplete. Continuing anyway..."
            }
        } else {
            Print-Info "To install Docker Desktop, visit: https://www.docker.com/products/docker-desktop"
            Print-Info "Or re-run this script with -InstallDocker flag"
            
            $response = Read-Host "Install Docker Desktop now? (Y/n)"
            if ($response -ne "n") {
                Install-DockerDesktop
            }
        }
    }
    
    # Step 3: Git
    if (-not (Check-Git)) {
        Print-Warning "Git is not installed"
        $response = Read-Host "Install Git now? (Y/n)"
        if ($response -ne "n") {
            Install-Git
        }
    }
    
    # Step 4: Repository
    $projectRoot = Split-Path -Parent $PSScriptRoot
    
    Write-Host ""
    Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║              Prerequisites Complete                            ║" -ForegroundColor Green
    Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    
    # Step 5: Run quickstart
    Write-Host "Running Misogi quickstart setup..." -ForegroundColor Cyan
    Write-Host ""
    
    $quickstartScript = Join-Path $PSScriptRoot "quickstart.ps1"
    if (Test-Path $quickstartScript) {
        & $quickstartScript -Preset $Preset
    } else {
        Print-Error "quickstart.ps1 not found at $quickstartScript"
        Print-Info "Please run quickstart.ps1 manually after ensuring prerequisites are installed"
    }
}

Main
