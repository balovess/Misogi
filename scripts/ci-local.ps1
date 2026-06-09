# =============================================================================
# Local CI Validation Script for Misogi
# =============================================================================
# Simulates GitHub Actions CI pipeline locally without Docker.
# Usage: ./scripts/ci-local.ps1 [-Job lint|check|test|doc|security|wasm|all]
#
# Requirements:
#   - Rust toolchain (stable)
#   - cargo-audit (for security job)
#   - wasm32-unknown-unknown target (for wasm job)

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("lint", "check", "test", "doc", "security", "wasm", "all")]
    [string]$Job = "all"
)

$ErrorActionPreference = "Stop"
$WorkspaceRoot = $PSScriptRoot | Split-Path -Parent

# =============================================================================
# Color Output Helpers
# =============================================================================

function Write-Step {
    param([string]$Message)
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "    OK: $Message" -ForegroundColor Green
}

function Write-Fail {
    param([string]$Message)
    Write-Host "    FAIL: $Message" -ForegroundColor Red
}

function Write-Info {
    param([string]$Message)
    Write-Host "    $Message" -ForegroundColor Gray
}

# =============================================================================
# Job: Lint
# =============================================================================

function Invoke-Lint {
    Write-Step "Running Lint Job"
    
    # Format check
    Write-Info "Checking code formatting..."
    $fmtResult = cargo fmt --all -- --check 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Format check passed"
    } else {
        Write-Fail "Format check failed"
        Write-Host $fmtResult
        return $false
    }
    
    # Clippy
    Write-Info "Running Clippy lints..."
    $clippyResult = cargo clippy --workspace --all-targets -- -D warnings -D clippy::all 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Clippy passed"
    } else {
        Write-Fail "Clippy failed"
        Write-Host $clippyResult
        return $false
    }
    
    return $true
}

# =============================================================================
# Job: Check
# =============================================================================

function Invoke-Check {
    Write-Step "Running Check Job"
    
    Write-Info "Compiling workspace (all targets)..."
    $checkResult = cargo check --workspace --all-targets 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Compilation check passed"
    } else {
        Write-Fail "Compilation check failed"
        Write-Host $checkResult
        return $false
    }
    
    return $true
}

# =============================================================================
# Job: Test
# =============================================================================

function Invoke-Test {
    Write-Step "Running Test Job"
    
    Write-Info "Running all tests..."
    $testResult = cargo test --workspace -- --nocapture 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Success "All tests passed"
    } else {
        Write-Fail "Tests failed"
        Write-Host $testResult
        return $false
    }
    
    return $true
}

# =============================================================================
# Job: Doc
# =============================================================================

function Invoke-Doc {
    Write-Step "Running Doc Job"
    
    Write-Info "Generating documentation..."
    $docResult = cargo doc --workspace --no-deps 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Documentation generated"
        Write-Info "Output: target/doc/"
    } else {
        Write-Fail "Documentation generation failed"
        Write-Host $docResult
        return $false
    }
    
    return $true
}

# =============================================================================
# Job: Security
# =============================================================================

function Invoke-Security {
    Write-Step "Running Security Audit"
    
    # Check if cargo-audit is installed
    $auditInstalled = Get-Command cargo-audit -ErrorAction SilentlyContinue
    if (-not $auditInstalled) {
        Write-Info "Installing cargo-audit..."
        cargo install cargo-audit
    }
    
    Write-Info "Running security audit..."
    $auditResult = cargo audit 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Security audit passed"
    } else {
        Write-Fail "Security vulnerabilities found"
        Write-Host $auditResult
        return $false
    }
    
    return $true
}

# =============================================================================
# Job: WASM
# =============================================================================

function Invoke-Wasm {
    Write-Step "Running WASM Compile Gate"
    
    # Check if wasm32 target is installed
    Write-Info "Checking wasm32-unknown-unknown target..."
    $targets = rustup target list --installed 2>&1
    if ($targets -notcontains "wasm32-unknown-unknown") {
        Write-Info "Installing wasm32-unknown-unknown target..."
        rustup target add wasm32-unknown-unknown
    }
    
    Write-Info "Compiling WASM module..."
    $wasmResult = cargo check -p misogi-wasm --target wasm32-unknown-unknown --no-default-features --features browser 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Success "WASM compilation passed"
    } else {
        Write-Fail "WASM compilation failed"
        Write-Host $wasmResult
        return $false
    }
    
    return $true
}

# =============================================================================
# Main
# =============================================================================

Write-Host @"
================================================================================
Misogi Local CI Validation
================================================================================
Job: $Job
Workspace: $WorkspaceRoot
"@ -ForegroundColor Yellow

Push-Location $WorkspaceRoot

$results = @{}

switch ($Job) {
    "lint" {
        $results["lint"] = Invoke-Lint
    }
    "check" {
        $results["check"] = Invoke-Check
    }
    "test" {
        $results["test"] = Invoke-Test
    }
    "doc" {
        $results["doc"] = Invoke-Doc
    }
    "security" {
        $results["security"] = Invoke-Security
    }
    "wasm" {
        $results["wasm"] = Invoke-Wasm
    }
    "all" {
        $results["lint"] = Invoke-Lint
        $results["check"] = Invoke-Check
        $results["test"] = Invoke-Test
        $results["doc"] = Invoke-Doc
        $results["security"] = Invoke-Security
        $results["wasm"] = Invoke-Wasm
    }
}

Pop-Location

# =============================================================================
# Summary
# =============================================================================

Write-Host "`n================================================================================"
Write-Host "CI Summary"
Write-Host "================================================================================"

$allPassed = $true
foreach ($key in $results.Keys) {
    $status = if ($results[$key]) { "PASS" } else { "FAIL"; $allPassed = $false }
    $color = if ($results[$key]) { "Green" } else { "Red" }
    Write-Host "  $key : $status" -ForegroundColor $color
}

Write-Host "================================================================================`n"

if ($allPassed) {
    Write-Host "All CI checks passed!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "Some CI checks failed!" -ForegroundColor Red
    exit 1
}
