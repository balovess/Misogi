[日本語](README_ja.md) | [English](README.md)

# Misogi

**A high-performance, secure file transfer system built with Rust 2024 Edition**

Misogi (禊ぎ) is a modern file transfer solution designed for reliability, security, and performance. It implements a sender-receiver architecture with support for chunked file transfers, real-time monitoring, and gRPC-based communication.

## Features

- 🚀 **High Performance**: Built with async Rust using Tokio for maximum throughput
- 🔒 **Security First**: Implements secure communication channels with TLS support
- 📦 **Chunked Transfers**: Efficient file transfer with configurable chunk sizes
- 🔄 **Real-time Monitoring**: Track file transfers with detailed progress information
- 🛠️ **Dual Mode Operation**: Run as server or daemon based on your needs
- 📡 **gRPC Integration**: Modern RPC framework for reliable communication
- 🔍 **Comprehensive Logging**: JSON-formatted logs with configurable log levels
- 🎯 **Type Safe**: Leverages Rust 2024 edition for maximum type safety and performance

## Architecture

Misogi consists of three main components:

### misogi-core
Core library containing:
- Protocol definitions (Protobuf)
- Hash utilities for file integrity
- Error handling
- Type definitions

### misogi-sender
Sender node responsible for:
- File upload and transfer initiation
- HTTP API for file submission
- gRPC streaming to receiver
- File system monitoring with `notify`

### misogi-receiver
Receiver node responsible for:
- File reception and storage
- HTTP download endpoints
- gRPC service for receiving streams
- File reassembly from chunks

## Requirements

- **Rust**: 1.75+ (Edition 2024)
- **Protocol Buffers**: For gRPC service definitions
- **Tokio**: Async runtime

## Installation

### Clone the repository

```bash
git clone https://github.com/balovess/Misogi.git
cd Misogi
```

### Build the project

```bash
cargo build --release
```

### Build binaries separately

```bash
# Build sender
cargo build --release --bin misogi-sender

# Build receiver
cargo build --release --bin misogi-receiver
```

## Usage

### Sender Node

#### Server Mode

```bash
misogi-sender server --config config.toml
```

#### Daemon Mode

```bash
misogi-sender daemon --config config.toml
```

#### Command Line Options

```bash
misogi-sender --help
```

### Receiver Node

#### Server Mode

```bash
misogi-receiver server --config config.toml
```

#### Daemon Mode

```bash
misogi-receiver daemon --config config.toml
```

#### Command Line Options

```bash
misogi-receiver --help
```

## Configuration

Create a `config.toml` file with the following structure:

### Sender Configuration

```toml
[server]
addr = "127.0.0.1:3000"
storage_dir = "./storage"
chunk_size = 1048576  # 1MB
log_level = "info"

[receiver]
addr = "127.0.0.1:50051"  # Optional: gRPC receiver address
```

### Receiver Configuration

```toml
[server]
addr = "127.0.0.1:3001"
download_dir = "./downloads"
storage_dir = "./storage"
tunnel_port = 50051
log_level = "info"
```

## Project Structure

```
Misogi/
├── Cargo.toml              # Workspace configuration
├── Cargo.lock              # Dependency lock file
├── crates/
│   ├── misogi-core/        # Core library
│   │   ├── Cargo.toml
│   │   ├── build.rs
│   │   ├── proto/          # Protobuf definitions
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── protocol.rs
│   │       ├── hash.rs
│   │       ├── error.rs
│   │       └── types.rs
│   ├── misogi-sender/      # Sender application
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs
│   │       ├── cli.rs
│   │       ├── config.rs
│   │       ├── state.rs
│   │       ├── upload_engine.rs
│   │       ├── http_routes.rs
│   │       ├── grpc_service.rs
│   │       └── tunnel_task.rs
│   └── misogi-receiver/    # Receiver application
│       ├── Cargo.toml
│       └── src/
│           ├── main.rs
│           ├── cli.rs
│           ├── config.rs
│           ├── state.rs
│           ├── storage.rs
│           ├── http_routes.rs
│           ├── grpc_service.rs
│           └── tunnel_handler.rs
```

## Development

### Running Tests

```bash
cargo test
```

### Building Documentation

```bash
cargo doc --open
```

### Code Formatting

```bash
cargo fmt
```

### Linting

```bash
cargo clippy
```

## Technical Details

### Protocol

Misogi uses Protocol Buffers (Protobuf) for defining gRPC services:

- **FileTransfer**: Core service for file transfer operations
- **ChunkStream**: Streaming service for chunked file data
- **Status Reporting**: Real-time transfer status updates

### Error Handling

The project implements comprehensive error handling using `thiserror` for:
- Network errors
- File I/O errors
- Protocol errors
- Configuration errors

### Logging

Structured JSON logging with `tracing` and `tracing-subscriber`:
- Configurable log levels (trace, debug, info, warn, error)
- Environment variable based filtering
- JSON output for easy parsing

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Style

- All code must compile with Rust 2024 Edition
- Follow Rust community guidelines
- Add comprehensive documentation comments
- Ensure all tests pass before submitting

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.

Copyright 2026 Misogi Contributors

## Acknowledgments

- Built with [Tokio](https://tokio.rs/) - Async runtime
- Uses [Axum](https://github.com/tokio-rs/axum) - Web framework
- Implements [Tonic](https://github.com/hyperium/tonic) - gRPC library
- Powered by [Prost](https://github.com/tokio-rs/prost) - Protocol buffers

---

**Misogi** - Purifying your file transfers with Rust's safety and performance.
