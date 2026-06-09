# misogi-bootstrap

**Application Assembly and Component Wiring — Builder Pattern for dependency injection**

![Rust 2024](https://img.shields.io/badge/Rust-2024-orange) ![License](https://img.shields.io/badge/License-Apache--2.0-blue)

## Architecture Overview

```
MisogiConfig (TOML/JSON)
      │
      ▼
MisogiApplicationBuilder ──build_all()──▶ MisogiApp
 │                              │
 ├── build_jwt_validator()      │ Holds:
 ├── build_jwt_issuer()        │  • JwtValidator (Arc)
 ├── build_identity_registry()  │  • JwtIssuer (Arc)
 ├── build_auth_engine()        │  • IdentityRegistry
 ├── build_parser_registry()    │  • AuthEngine
 ├── build_storage()            │  • ParserRegistry
 └── build_transport()          │  • StorageBackend (dyn)
                                │  • TransportLayer (stub)
                                │
                                ▼
                        app.start().await
                        app.shutdown().await
```

## Feature Flags

| Feature | Description | Default |
|---------|-------------|---------|
| `jwt` | Enable JWT authentication components | yes |
| `ldap` | Enable LDAP/AD identity provider support | no |
| `oidc` | Enable OIDC/OAuth2 identity provider support | no |
| `saml` | Enable SAML 2.0 identity provider support | no |
| `storage` | Enable S3/MinIO cloud storage backend | no |

## Build Order

Components are built in strict dependency order. The builder enforces this at runtime:

| Step | Component | Dependencies |
|------|-----------|--------------|
| 1 | **JwtValidator** | `config.jwt` |
| 2 | **JwtIssuer** | `config.jwt` |
| 3 | **IdentityRegistry** | none |
| 4 | **AuthEngine** | JwtValidator, optionally IdentityRegistry |
| 5 | **ParserRegistry** | none |
| 6 | **StorageBackend** | `config.storage` |
| 7 | **TransportLayer** | `config.transport` |

## Key Public API

- **`MisogiApplicationBuilder`** — Fluent builder for component assembly
- **`MisogiApp`** — Fully-wired application instance
- **`MisogiConfig`** — Complete configuration structure
- **`BootstrapError`** — Comprehensive error type for bootstrap operations

## Key Dependencies

- `tokio`: Async runtime
- `misogi-auth`: Authentication components
- `misogi-core`: Core types and traits
- `misogi-cdr`: CDR engine

## Quick Example

```rust
use misogi_bootstrap::{MisogiApplicationBuilder, MisogiConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration from file
    let config = MisogiConfig::from_toml_file("misogi.toml")?;

    // Build all components and create application instance
    let app = MisogiApplicationBuilder::new()
        .with_config(config)
        .build_all()?      // Build everything in dependency order
        .build()?;         // Produce the final MisogiApp

    // Start serving requests (blocks until shutdown signal)
    app.start().await?;

    Ok(())
}
```

## Error Handling

All bootstrap operations return `BootstrapError` with detailed context:

| Error Type | Cause | Resolution |
|------------|-------|------------|
| `Configuration` | Invalid TOML/YAML | Fix config file and retry |
| `MissingDependency` | Build order violation | Adjust build method call order |
| `Component` | Component init failure | Check keys, permissions, network |

## Thread Safety

- `MisogiApplicationBuilder` is **not** thread-safe (single-threaded startup only)
- `MisogiApp` is fully thread-safe when wrapped in `Arc<>`
- All internal components use `Arc<>` for zero-cost sharing across async tasks

## Full Documentation

For complete configuration options, component details, and deployment patterns, see the [root README](../../README.md).
