# =============================================================================
# Version Synchronization Script
# =============================================================================
#
# Usage:
#   ./scripts/version-sync.ps1 -Action [check|sync|bump] -Version [x.y.z]
#
# Actions:
#   check - Verify all crate versions are valid semver
#   sync  - Sync all crates to a specific version
#   bump  - Bump specific crate version
#

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("check", "sync", "bump")]
    [string]$Action,

    [Parameter(Mandatory=$false)]
    [string]$Version,

    [Parameter(Mandatory=$false)]
    [string]$Crate
)

$ErrorActionPreference = "Stop"

function Test-SemVer {
    param([string]$Version)
    return $Version -match '^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?$'
}

function Get-CrateVersions {
    $crates = Get-ChildItem -Path "crates" -Directory
    $versions = @{}

    foreach ($crate in $crates) {
        $cargoToml = Join-Path $crate.FullName "Cargo.toml"
        if (Test-Path $cargoToml) {
            $content = Get-Content $cargoToml -Raw
            if ($content -match 'version\s*=\s*"([^"]+)"') {
                $versions[$crate.Name] = $matches[1]
            }
        }
    }
    return $versions
}

switch ($Action) {
    "check" {
        Write-Host "Checking all crate versions..."
        $versions = Get-CrateVersions

        $allValid = $true
        foreach ($crate in $versions.Keys) {
            $ver = $versions[$crate]
            if (Test-SemVer $ver) {
                Write-Host "  [OK] $crate : $ver" -ForegroundColor Green
            } else {
                Write-Host "  [FAIL] $crate : $ver (invalid semver)" -ForegroundColor Red
                $allValid = $false
            }
        }

        if ($allValid) {
            Write-Host "`nAll versions are valid semver!" -ForegroundColor Green
            exit 0
        } else {
            Write-Host "`nSome versions are invalid!" -ForegroundColor Red
            exit 1
        }
    }

    "sync" {
        if (-not $Version) {
            Write-Error "Version parameter is required for sync action"
            exit 1
        }

        if (-not (Test-SemVer $Version)) {
            Write-Error "Invalid semver format: $Version"
            exit 1
        }

        Write-Host "Syncing all crates to version $Version..."
        $crates = Get-ChildItem -Path "crates" -Directory

        foreach ($crate in $crates) {
            $cargoToml = Join-Path $crate.FullName "Cargo.toml"
            if (Test-Path $cargoToml) {
                $content = Get-Content $cargoToml -Raw
                $newContent = $content -replace '(version\s*=\s*)"([^"]+)"', "`$1`"$Version`""
                Set-Content -Path $cargoToml -Value $newContent -NoNewline
                Write-Host "  Updated $crate to $Version"
            }
        }

        Write-Host "`nAll crates synced to $Version!" -ForegroundColor Green
    }

    "bump" {
        if (-not $Crate) {
            Write-Error "Crate parameter is required for bump action"
            exit 1
        }
        if (-not $Version) {
            Write-Error "Version parameter is required for bump action"
            exit 1
        }

        $cargoToml = Join-Path "crates" $Crate "Cargo.toml"
        if (-not (Test-Path $cargoToml)) {
            Write-Error "Crate not found: $Crate"
            exit 1
        }

        $content = Get-Content $cargoToml -Raw
        $newContent = $content -replace '(version\s*=\s*)"([^"]+)"', "`$1`"$Version`""
        Set-Content -Path $cargoToml -Value $newContent -NoNewline
        Write-Host "Updated $Crate to $Version" -ForegroundColor Green
    }
}
