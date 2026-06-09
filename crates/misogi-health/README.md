# misogi-health

**Kubernetes-Compatible System Health Probes — Deep component-level status reporting**

![Rust 2024](https://img.shields.io/badge/Rust-2024-orange) ![License](https://img.shields.io/badge/License-Apache--2.0-blue)

## Architecture Overview

```
misogi-health
├── types.rs           — Health status data models (serde-compatible)
├── checker.rs         — Health check engine with component registry
├── built_in_checks.rs — Built-in implementations (feature-gated)
├── handlers.rs        — HTTP endpoint handlers (feature-gated: `http`)
└── *_tests.rs        — Comprehensive test suites
```

## Feature Flags

| Feature | Description | Default |
|---------|-------------|---------|
| (none) | Core types + checker engine only | Yes |
| `http` | Axum HTTP handlers for K8s probes | No |
| `full` | All features including HTTP | No |

## Key Public API

- **`HealthChecker`** — Health check engine with pluggable component registry
- **`HealthCheckable`** — Trait for custom health check implementations
- **`HealthStatus`** — Complete health status structure
- **`ComponentHealth`** — Per-component health details
- **`OverallHealth`** — Overall system health enum (`Healthy`/`Degraded`/`Unhealthy`)

## Built-in Health Checks

| Check | Feature Gate | Description |
|-------|--------------|-------------|
| `JwtValidatorHealthCheck` | `misogi-auth` | JWT token validation health |
| `IdentityRegistryHealthCheck` | `misogi-auth` | Identity provider connectivity |
| `StorageBackendHealthCheck` | `misogi-core` | Storage backend availability |
| `ParserRegistryHealthCheck` | `misogi-cdr` | CDR parser registry status |

## Key Dependencies

- `tokio`: Async runtime
- `serde`: Serialization for JSON responses
- `axum`: HTTP handlers (optional, `http` feature)

## Quick Example (Library Usage)

```rust
use misogi_health::checker::{HealthChecker, HealthCheckable};
use misogi_health::types::{ComponentHealth, ComponentStatus, OverallHealth};

// Create checker and register components
let checker = HealthChecker::new();
checker.register(Box::new(MyDatabaseCheck::new(pool)));
checker.register(Box::new(MyCacheCheck::new(redis)));

// Execute health checks
let status = checker.check_all().await;
assert_eq!(status.overall, OverallHealth::Healthy);

// Get individual component status
let db_health = status.components.get("database");
println!("Database: {:?}", db_health);
```

## Quick Example (HTTP Integration)

```rust
use misogi_health::handlers::{HealthState, build_health_router};
use std::sync::Arc;

let state = HealthState::new(Arc::new(checker));
let health_routes = build_health_router(state);

// Merge into main Axum app
let app = axum::Router::new()
    .route("/api", api_routes)
    .merge(health_routes);

// Endpoints available:
// GET /healthz       — Liveness probe (always 200)
// GET /readyz        — Readiness probe (checks components)
// GET /healthz/deep  — Full JSON with all details
```

## Kubernetes Integration

Configure your deployment with standard probes:

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 8080
  initialDelaySeconds: 15
  periodSeconds: 20

readinessProbe:
  httpGet:
    path: /readyz
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10
```

## Response Format

### `/healthz` (Liveness)

```json
{
  "status": "ok",
  "timestamp": "2026-06-09T10:30:00Z"
}
```

### `/readyz` (Readiness)

```json
{
  "status": "ready",
  "components": {
    "database": "healthy",
    "cache": "healthy",
    "storage": "healthy"
  }
}
```

### `/healthz/deep` (Deep Health)

```json
{
  "overall": "healthy",
  "timestamp": "2026-06-09T10:30:00Z",
  "components": {
    "database": {
      "status": "healthy",
      "latency_ms": 5,
      "details": {"pool_size": 10, "active": 3}
    },
    "storage": {
      "status": "healthy",
      "latency_ms": 12,
      "details": {"bucket": "misogi-files", "region": "ap-northeast-1"}
    }
  }
}
```

## Full Documentation

For complete API reference, custom check implementation guide, and Kubernetes deployment patterns, see the [root README](../../README.md).
