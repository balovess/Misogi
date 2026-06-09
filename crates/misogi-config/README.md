# misogi-config

**Centralized TOML Configuration Loader — Unified configuration for all Misogi subsystems**

![Rust 2024](https://img.shields.io/badge/Rust-2024-orange) ![License](https://img.shields.io/badge/License-Apache--2.0-blue)

## Architecture Overview

```
Configuration Flow:
1. Load from TOML file or string
2. Apply MISOGI_* environment variable overrides (optional)
3. Validate all sections
4. Distribute to subsystems via accessor methods
```

## Feature Flags

| Feature | Description |
|---------|-------------|
| `auth` | Enable JWT configuration section |
| `cdr` | Enable CDR configuration section (future) |
| `storage` | Enable storage backend configuration |
| `transport` | Enable transport layer configuration |
| `full` | Enable all subsystem configurations |

## Key Public API

- **`MisogiConfig`** — Root configuration structure
- **`GeneralConfig`** — General application settings
- **`JwtConfigSection`** — JWT authentication configuration
- **`IdentityProviderConfig`** — IdP configuration (LDAP/OIDC/SAML)
- **`StorageConfigSection`** — Storage backend configuration
- **`TransportConfigSection`** — Transport layer configuration
- **`ConfigError`** — Configuration error type

## Key Dependencies

- `toml`: TOML parsing
- `serde`: Serialization framework
- `thiserror`: Error handling

## Quick Example

### TOML Configuration (`misogi.toml`)

```toml
[general]
app_name = "Misogi Gateway"
log_level = "info"
environment = "production"

[jwt]
issuer = "misogi-gateway"
audience = "internal"
expiry_seconds = 3600
public_key_path = "./keys/public.pem"
private_key_path = "./keys/private.pem"

[[identity_providers]]
id = "corporate-ad"
provider_type = "ldap"
endpoint = "ldap://ad.corporate.local:389"
base_dn = "dc=corporate,dc=local"

[storage]
type = "s3"
bucket = "misogi-files"
region = "ap-northeast-1"

[transport]
type = "grpc"
bind = "0.0.0.0:50051"
```

### Rust Usage

```rust
use misogi_config::MisogiConfig;
use std::path::Path;

// Load from file (with env overrides + validation)
let config = MisogiConfig::from_file(Path::new("misogi.toml"))?;

// Extract subsystem configs
let jwt = config.jwt_config();
let storage = config.storage_config();
let transport = config.transport_config();

// Iterate identity providers
for provider in config.identity_provider_configs() {
    println!("Provider: {} ({})", provider.id, provider.provider_type);
}
```

## Environment Variable Overrides

Configuration values can be overridden via `MISOGI_*` environment variables:

```bash
export MISOGI_GENERAL_LOG_LEVEL=debug
export MISOGI_JWT_EXPIRY_SECONDS=7200
export MISOGI_STORAGE_BUCKET=production-files
```

## Validation

All configuration sections are validated on load:

| Section | Validation |
|---------|------------|
| `jwt` | Key paths exist, expiry > 0 |
| `identity_providers` | Valid LDAP/OIDC/SAML endpoints |
| `storage` | Valid S3/Azure/GCS configuration |
| `transport` | Valid bind address |

## Full Documentation

For complete configuration schema, validation rules, and environment variable reference, see the [root README](../../README.md).
