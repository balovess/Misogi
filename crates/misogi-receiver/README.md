# misogi-receiver

**Misogi Receiver Node — File Reception and Storage**

Receiver component providing gRPC server for receiving chunked file streams, HTTP API for downloads, file reassembly, storage management, and dual mode operation (server/daemon with tunnel support).

## Key Public API

- **gRPC Server** (Tonic) — Receive chunked file streams over TLS
- **HTTP Server** (Axum) — RESTful download endpoints
- **File Reassembly** — Reconstruct files from received chunks
- **Tunnel Support** — Direct tunnel mode for point-to-point transfer
- **CLI Interface** (`clap`) — `server`, `daemon`, `tunnel` modes

## Key Dependencies

`tokio`, `axum`, `tonic`, `tower-http`, `notify`, `clap`, `serde`, `futures`

## Quick Start

```bash
cargo build --release --bin misogi-receiver
misogi-receiver server --config config.toml        # Server mode
misogi-receiver daemon --config config.toml         # Daemon mode
misogi-receiver server --config config.toml --tunnel-port 50051  # Tunnel
```

## Full Documentation

See the [root README](../../README.md) for architecture, configuration, security, and logging details.
