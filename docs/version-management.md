# Version Management Guide

## Overview

Misogi uses [cargo-release](https://github.com/crate-ci/cargo-release) for automated version management.
Each crate maintains its own version number following [Semantic Versioning](https://semver.org/).

## Prerequisites

Install cargo-release:

```bash
cargo install cargo-release
```

## Versioning Strategy

### Independent Versioning

Each crate has its own version number, allowing for:
- Independent release cycles
- Granular changelog entries
- Flexible dependency management

### Version Format

All versions follow [SemVer 2.0.0](https://semver.org/spec/v2.0.0.html):

```
MAJOR.MINOR.PATCH[-PRERELEASE]

Examples:
  0.1.0
  1.0.0
  2.1.3-alpha.1
  3.0.0-rc.2
```

## Common Operations

### Bump a Single Crate

```bash
# Patch version (0.1.0 -> 0.1.1)
cargo release patch misogi-core

# Minor version (0.1.0 -> 0.2.0)
cargo release minor misogi-core

# Major version (0.1.0 -> 1.0.0)
cargo release major misogi-core
```

### Bump All Crates

```bash
# Bump all crates by patch version
cargo release patch --workspace

# Bump all crates by minor version
cargo release minor --workspace
```

### Pre-release Versions

```bash
# Alpha release
cargo release 0.2.0-alpha.1 misogi-core

# Beta release
cargo release 0.2.0-beta.1 misogi-core

# Release candidate
cargo release 0.2.0-rc.1 misogi-core
```

## Workflow

1. **Development**: Make changes to the crate
2. **Update CHANGELOG**: Add entries to CHANGELOG.md under `[Unreleased]`
3. **Release**: Run `cargo release [level] [crate-name]`
4. **Verify**: Check GitHub Actions CI/CD pipeline

## CHANGELOG Management

The CHANGELOG.md file follows [Keep a Changelog](https://keepachangelog.com/).

### Structure

```markdown
## [Unreleased]

### Added
- New feature description

### Changed
- Change description

### Fixed
- Bug fix description

## [0.1.0] - 2026-04-11

### Added
- Initial release features
```

### Categories

- **Added**: New features
- **Changed**: Changes to existing features
- **Deprecated**: Features to be removed
- **Removed**: Removed features
- **Fixed**: Bug fixes
- **Security**: Security-related changes

## CI/CD Integration

The CI pipeline validates:
- All versions are valid semver
- CHANGELOG entries exist for released versions
- Version tags match Cargo.toml versions

## Manual Version Sync

Use the version-sync script for manual operations:

```powershell
# Check all versions
./scripts/version-sync.ps1 -Action check

# Sync all crates to a specific version
./scripts/version-sync.ps1 -Action sync -Version 0.2.0

# Bump a specific crate
./scripts/version-sync.ps1 -Action bump -Crate misogi-core -Version 0.2.0
```

## Crate List

| Crate | Description |
|-------|-------------|
| misogi-core | Core library for Misogi file transfer system |
| misogi-cdr | Content Disarm and Reconstruction engine |
| misogi-auth | Authentication and authorization framework |
| misogi-sender | Sender node - handles file upload |
| misogi-receiver | Receiver node - handles file reception |
| misogi-smtp | SMTP server for email processing |
| misogi-wasm | WASM plugin runtime |
| misogi-rest-api | RESTful admin API |
| misogi-nocode | No-code integration layer |
| misogi-bootstrap | Application bootstrap |
| misogi-config | Configuration loader |
| misogi-health | Health probes |
| misogi-macros | Procedural macros |
| korea-fss-plugin | Korea FSS compliance plugin |

## Tag Format

Git tags follow the format: `{crate-name}-v{version}`

Examples:
- `misogi-core-v0.2.0`
- `misogi-cdr-v1.0.0`
- `misogi-auth-v0.1.1`

## Troubleshooting

### Version Mismatch

If CI reports version mismatch:

1. Check the crate's Cargo.toml version
2. Verify CHANGELOG.md has an entry for that version
3. Ensure the git tag matches the expected format

### Invalid SemVer

If a version fails semver validation:

1. Ensure format is `MAJOR.MINOR.PATCH`
2. Pre-release versions must use `-alpha.N`, `-beta.N`, or `-rc.N`
3. No spaces or special characters allowed

### cargo-release Errors

Common issues:

```bash
# Dry-run to preview changes
cargo release --dry-run patch misogi-core

# Skip confirmation prompts
cargo release --execute patch misogi-core
```
