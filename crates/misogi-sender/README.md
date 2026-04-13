# misogi-sender

**Misogi Sender Node — File Upload and Transfer Initiation**

Sender component providing HTTP API for file uploads, gRPC streaming for efficient chunked transfer to receiver, file monitoring with automatic detection, and dual mode operation (server or daemon).

## Key Public API

- **HTTP Server** (Axum-based) — RESTful endpoints for file uploads
- **gRPC Client** — Streaming client for receiver communication
- **File Monitoring** — Automatic detection of new files using `notify`
- **CLI Interface** — Command-line interface with `clap` (`server`, `daemon` modes)
- **Configuration** — TOML-based configuration files

## Key Dependencies

- `tokio`: Async runtime
- `axum`: Web framework
- `tonic`: gRPC client
- `tower-http`: HTTP middleware
- `notify`: File system monitoring
- `clap`: CLI parsing
- `serde`: Serialization

## Quick Start

```bash
# Build
cargo build --release --bin misogi-sender

# Run as server
misogi-sender server --config config.toml

# Run as daemon
misogi-sender daemon --config config.toml
```

## API Endpoints

- `POST /api/v1/upload` — Upload file
- `GET /api/v1/transfers/{transfer_id}` — Get transfer status
- `GET /api/v1/transfers` — List transfers

## Full Documentation

For complete configuration options, architecture overview, project structure, logging format, and error handling details, see the [root README](../../README.md).
