# misogi-core

**Core Library for the Misogi File Transfer System**

Foundational components including Protocol Buffer definitions for gRPC, MD5 hash utilities for file integrity verification, comprehensive error types, and core data structures used across the entire system.

## Key Public API

- **`protocol` module** — Auto-generated Rust code from `.proto` definitions (FileTransferRequest, ChunkData, etc.)
- **`hash` module** — MD5 hash calculation (`calculate_file_hash`)
- **`error` module** — `MisogiError` type with comprehensive error handling
- **`types` module** — Core data structures and type definitions

## Key Dependencies

- `tokio`: Async runtime
- `prost`: Protocol Buffer implementation
- `tonic`: gRPC framework
- `serde`: Serialization framework
- `thiserror`: Error handling
- `md-5`: Hash algorithm
- `uuid`: Unique identifiers
- `chrono`: Date and time handling

## Build Note

Includes `build.rs` script that automatically generates Rust code from Protocol Buffer definitions in `proto/` directory.

## Quick Example

```rust
use misogi_core::protocol::{FileTransferRequest, ChunkData};
use misogi_core::hash::calculate_file_hash;

let request = FileTransferRequest {
    file_id: uuid::Uuid::new_v4(),
    file_name: "example.txt".to_string(),
    file_size: 1024,
    chunk_count: 10,
};

let hash = calculate_file_hash(&file_data)?;
```

## Full Documentation

For complete API documentation, protocol details, project structure, and usage patterns, see the [root README](../../README.md).
