# misogi-rest-api

**Comprehensive RESTful Admin API for Misogi Secure File Transfer System**

![Rust 2024](https://img.shields.io/badge/Rust-2024-orange) ![Axum](https://img.shields.io/badge/Axum-0.8-blue) ![License](https://img.shields.io/badge/License-Apache--2.0-blue)

## Architecture Overview

```
  HTTP Client (Browser / CLI)
           |
          HTTPS
           |
  +--------v---------+
  |  Middleware Stack  |  (outermost -> innermost)
  |  [TraceLayer]     |
  |  -> [CorsLayer]   |
  |  -> [RateLimit]   |
  |  -> [AuthLayer]   |
  |                   |
  |  Router (/api/v1) |
  |  /files /scan     |
  |  /policies /audit |
  |  /health /metrics|
  +-------------------+
```

## Feature Flags

| Flag | Description | Default |
|------|-------------|---------|
| `full` | Enable all standard features | yes |
| `openapi` | Enable OpenAPI 3.0 spec generation + Swagger UI | no |

## Key Capabilities

| Capability | Endpoint | Description |
|------------|----------|-------------|
| **File Management** | `/api/v1/files` | Upload, list, retrieve, delete files with sanitization reports |
| **Scan Orchestration** | `/api/v1/scan` | Submit async scan jobs, poll status, download sanitized results |
| **Policy CRUD** | `/api/v1/policies` | Full lifecycle management for sanitization policies |
| **Audit Logging** | `/api/v1/audit` | Queryable audit trail with time-range and action-type filtering |
| **Health Probes** | `/health/liveness`, `/health/readiness` | Kubernetes liveness and readiness probes |
| **Prometheus Metrics** | `/metrics` | Prometheus text exposition format |

## Key Public API

- **`create_app()`** — Build the complete Axum router with all endpoints
- **`RestApiConfig`** — Configuration for API behavior (rate limits, auth, etc.)
- **`ApiError`** — Unified error type with HTTP status mapping
- **`VersionRouter`** — Multi-version API routing support

## Key Dependencies

- `axum`: Web framework
- `tokio`: Async runtime
- `serde`/`serde_json`: Serialization
- `utoipa`: OpenAPI 3.0 spec generation (optional)
- `dashmap`: Concurrent rate limiting

## Quick Example

```rust
use misogi_rest_api::router::create_app;
use misogi_rest_api::models::RestApiConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = RestApiConfig::default();
    let app = create_app(config).await?;

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

## Rate Limiting

Per-API-key sliding-window rate limiter using `DashMap`:

```toml
[api]
rate_limit_requests_per_minute = 60
rate_limit_burst = 10
```

## Authentication

JWT authentication via `misogi-auth` middleware:

- Bearer token extraction from `Authorization` header
- RS256 signature validation
- Role-based endpoint authorization

## Full Documentation

For complete endpoint reference, OpenAPI spec, and integration patterns, see the [root README](../../README.md).
