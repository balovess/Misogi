# misogi-nocode

**No-Code Integration Layer — YAML-based declarative configuration for non-developers**

![Rust 2024](https://img.shields.io/badge/Rust-2024-orange) ![License](https://img.shields.io/badge/License-Apache--2.0-blue)

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    No-Code Layer                            │
├─────────────────────────────────────────────────────────────┤
│  Layer 1: schema.rs   — YAML Schema Definition              │
│    ↓ Defines the complete YAML structure with validation     │
│  Layer 2: compiler.rs — YAML → MisogiConfig Compiler        │
│    ↓ Transforms YAML to internal config structs             │
│  Layer 3: runtime.rs  — Hot-Reload Runtime Engine           │
│    ↓ Manages config lifecycle and graceful reloads          │
│  Layer 4: api.rs      — Admin REST API Control Plane         │
│    ↓ HTTP endpoints for config management                   │
│  Layer 5: cli.rs      — misogi-admin CLI Tool               │
│    ↓ Command-line interface for operations                  │
└─────────────────────────────────────────────────────────────┘
```

## Design Principles

| Principle | Implementation |
|-----------|----------------|
| **Accessibility** | YAML format chosen over TOML for better readability by non-developers |
| **Safety** | All configurations validated before application; rollback on error |
| **Transparency** | Detailed compilation reports with warnings and errors |
| **Zero-Trust** | Secrets masked in all API responses and logs |

## Key Public API

- **`YamlConfig`** — Parsed YAML configuration structure
- **`compile()`** — Transform YAML to internal `MisogiConfig`
- **`NoCodeRuntime`** — Hot-reload runtime with file watching
- **`create_admin_router()`** — Axum router for admin API

## Key Dependencies

- `serde_yaml`: YAML parsing
- `tokio`: Async runtime + file watching
- `axum`: Admin API web framework
- `clap`: CLI argument parsing

## Quick Example

### YAML Configuration (`config.yaml`)

```yaml
system:
  name: "Production Gateway"
  log_level: "info"

auth:
  jwt:
    issuer: "misogi-gateway"
    audience: "internal"
    expiry_seconds: 3600

storage:
  type: "s3"
  bucket: "misogi-files"
  region: "ap-northeast-1"

cdr:
  policy: "StripActiveContent"
  formats: ["pdf", "docx", "xlsx", "pptx"]
```

### Rust Usage

```rust
use misogi_nocode::{YamlConfig, NoCodeRuntime, compile};

// Parse and validate YAML
let yaml_config = YamlConfig::from_yaml_str(include_str!("config.yaml"))?;

// Compile to internal config
let report = compile(&yaml_config)?;
assert!(report.errors.is_empty(), "Configuration has errors");

// Initialize runtime with hot-reload
let runtime = NoCodeRuntime::new(yaml_config);
runtime.watch_file("config.yaml").await?;
```

## CLI Tool (`misogi-admin`)

```bash
# Validate configuration
misogi-admin validate config.yaml

# Apply configuration with hot-reload
misogi-admin apply config.yaml --watch

# Export current config to YAML
misogi-admin export > current-config.yaml
```

## Hot-Reload

The runtime watches the configuration file for changes:

1. Detect file modification via `notify` crate
2. Parse and validate new configuration
3. If valid: graceful reload with zero downtime
4. If invalid: log error, keep previous configuration

## Full Documentation

For complete YAML schema reference, CLI commands, and integration patterns, see the [root README](../../README.md).
