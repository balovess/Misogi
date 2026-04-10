# misogi-core

Core library for the Misogi file transfer system.

## Overview

`misogi-core` provides the foundational components for the Misogi file transfer system, including:

- **Protocol Definitions**: Protocol Buffer definitions for gRPC communication
- **Hash Utilities**: MD5 hash calculation for file integrity verification
- **Error Handling**: Comprehensive error types using `thiserror`
- **Type Definitions**: Core data structures used across the system

## Features

- 📡 **Protocol Buffer Integration**: Auto-generated Rust code from `.proto` definitions
- 🔐 **Hash Verification**: File integrity checking with MD5 hashing
- 🎯 **Type Safety**: Strongly typed data structures
- ⚡ **Async Support**: Built for async/await patterns with Tokio
- 📦 **Serialization**: Serde-based serialization for data structures

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
misogi-core = { path = "../misogi-core" }
```

## Usage

### Protocol Types

```rust
use misogi_core::protocol::{FileTransferRequest, ChunkData};

// Create a file transfer request
let request = FileTransferRequest {
    file_id: uuid::Uuid::new_v4(),
    file_name: "example.txt".to_string(),
    file_size: 1024,
    chunk_count: 10,
};
```

### Hash Utilities

```rust
use misogi_core::hash::calculate_file_hash;

// Calculate MD5 hash of file content
let hash = calculate_file_hash(&file_data)?;
println!("File hash: {}", hash);
```

### Error Handling

```rust
use misogi_core::error::MisogiError;

fn transfer_file() -> Result<(), MisogiError> {
    // Implementation
    Ok(())
}
```

## API Documentation

Generate API documentation with:

```bash
cargo doc --open -p misogi-core
```

## Dependencies

- `tokio`: Async runtime
- `prost`: Protocol Buffer implementation
- `tonic`: gRPC framework
- `serde`: Serialization framework
- `thiserror`: Error handling
- `md-5`: Hash algorithm
- `uuid`: Unique identifiers
- `chrono`: Date and time handling

## Building

The crate includes a `build.rs` script that automatically generates Rust code from Protocol Buffer definitions:

```rust
// build.rs
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_proto("proto/file_transfer.proto")?;
    Ok(())
}
```

## Project Structure

```
misogi-core/
├── proto/
│   └── file_transfer.proto    # Protocol Buffer definitions
├── src/
│   ├── lib.rs                 # Library root
│   ├── protocol.rs            # Protocol implementations
│   ├── hash.rs                # Hash utilities
│   ├── error.rs               # Error types
│   └── types.rs               # Core type definitions
├── build.rs                   # Build script for proto compilation
└── Cargo.toml
```

## License

Licensed under the Apache 2.0 License. See [LICENSE](../../LICENSE) for details.

---

# misogi-core

Misogi ファイル転送システムのコアライブラリ。

## 概要

`misogi-core` は、Misogi ファイル転送システムの基盤コンポーネントを提供します：

- **プロトコル定義**: gRPC 通信用の Protocol Buffer 定義
- **ハッシュユーティリティ**: ファイル整合性検証のための MD5 ハッシュ計算
- **エラーハンドリング**: `thiserror` を使用した包括的なエラー型
- **型定義**: システム全体で使用されるコアデータ構造

## 機能

- 📡 **Protocol Buffer 統合**: `.proto` 定義から自動生成された Rust コード
- 🔐 **ハッシュ検証**: MD5 ハッシングによるファイル整合性チェック
- 🎯 **型安全性**: 強く型付けされたデータ構造
- ⚡ **非同期サポート**: Tokio を使用した async/await パターン向けに構築
- 📦 **シリアライゼーション**: データ構造のための Serde ベースのシリアライゼーション

## インストール

`Cargo.toml` に追加：

```toml
[dependencies]
misogi-core = { path = "../misogi-core" }
```

## 使用方法

### プロトコル型

```rust
use misogi_core::protocol::{FileTransferRequest, ChunkData};

// ファイル転送リクエストの作成
let request = FileTransferRequest {
    file_id: uuid::Uuid::new_v4(),
    file_name: "example.txt".to_string(),
    file_size: 1024,
    chunk_count: 10,
};
```

### ハッシュユーティリティ

```rust
use misogi_core::hash::calculate_file_hash;

// ファイル内容の MD5 ハッシュを計算
let hash = calculate_file_hash(&file_data)?;
println!("ファイルハッシュ：{}", hash);
```

### エラーハンドリング

```rust
use misogi_core::error::MisogiError;

fn transfer_file() -> Result<(), MisogiError> {
    // 実装
    Ok(())
}
```

## API ドキュメント

API ドキュメントの生成：

```bash
cargo doc --open -p misogi-core
```

## 依存関係

- `tokio`: 非同期ランタイム
- `prost`: Protocol Buffer 実装
- `tonic`: gRPC フレームワーク
- `serde`: シリアライゼーションフレームワーク
- `thiserror`: エラーハンドリング
- `md-5`: ハッシュアルゴリズム
- `uuid`: 一意の識別子
- `chrono`: 日付と時刻の処理

## ビルド

このクレートは Protocol Buffer 定義から Rust コードを自動生成する `build.rs` スクリプトを含みます：

```rust
// build.rs
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_proto("proto/file_transfer.proto")?;
    Ok(())
}
```

## プロジェクト構造

```
misogi-core/
├── proto/
│   └── file_transfer.proto    # Protocol Buffer 定義
├── src/
│   ├── lib.rs                 # ライブラリルート
│   ├── protocol.rs            # プロトコル実装
│   ├── hash.rs                # ハッシュユーティリティ
│   ├── error.rs               # エラー型
│   └── types.rs               # コア型定義
├── build.rs                   # proto コンパイル用ビルドスクリプト
└── Cargo.toml
```

## ライセンス

Apache 2.0 ライセンスの下でライセンスされています。詳細は [LICENSE](../../LICENSE) を参照してください。
