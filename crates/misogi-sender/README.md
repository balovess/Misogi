# misogi-sender

Misogi sender node - handles file upload and transfer initiation.

## Overview

`misogi-sender` is the sender component of the Misogi file transfer system. It provides:

- **HTTP API**: RESTful endpoints for file upload
- **gRPC Streaming**: Efficient chunked transfer to receiver
- **File Monitoring**: Watch directories for new files
- **Dual Mode**: Run as server or daemon

## Features

- 🌐 **HTTP Server**: Axum-based web server for file uploads
- 📡 **gRPC Client**: Streaming client for receiver communication
- 📂 **File Monitoring**: Automatic detection of new files using `notify`
- 🔄 **Chunked Transfer**: Configurable chunk sizes for efficient transfer
- 📊 **Progress Tracking**: Real-time transfer status monitoring
- 🔧 **CLI Interface**: Command-line interface with `clap`
- ⚙️ **Configuration**: TOML-based configuration files

## Installation

Build the sender binary:

```bash
cargo build --release --bin misogi-sender
```

## Usage

### Server Mode

Run as an HTTP server:

```bash
misogi-sender server --config config.toml
```

### Daemon Mode

Run as a background daemon with file monitoring:

```bash
misogi-sender daemon --config config.toml
```

### Command Line Options

```bash
misogi-sender --help
```

## Configuration

Create a `config.toml` file:

```toml
[server]
addr = "127.0.0.1:3000"
storage_dir = "./storage"
chunk_size = 1048576  # 1MB
log_level = "info"

[receiver]
addr = "127.0.0.1:50051"  # gRPC receiver address
```

## API Endpoints

### Upload File

```http
POST /api/v1/upload
Content-Type: multipart/form-data

{
  "file": <file_data>
}
```

### Get Transfer Status

```http
GET /api/v1/transfers/{transfer_id}
```

### List Transfers

```http
GET /api/v1/transfers
```

## Architecture

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │ HTTP
       ▼
┌─────────────────┐
│  misogi-sender  │
│  ┌───────────┐  │
│  │ HTTP API  │  │
│  └─────┬─────┘  │
│        │        │
│  ┌─────▼─────┐  │
│  │   gRPC    │  │
│  │  Client   │  │
│  └─────┬─────┘  │
└────────┼────────┘
         │ gRPC Stream
         ▼
┌─────────────────┐
│ misogi-receiver │
└─────────────────┘
```

## Project Structure

```
misogi-sender/
├── src/
│   ├── main.rs           # Application entry point
│   ├── cli.rs            # Command-line interface
│   ├── config.rs         # Configuration management
│   ├── state.rs          # Application state
│   ├── upload_engine.rs  # File upload logic
│   ├── http_routes.rs    # HTTP route handlers
│   ├── grpc_service.rs   # gRPC client service
│   ├── router.rs         # HTTP router setup
│   └── tunnel_task.rs    # Transfer tunnel management
└── Cargo.toml
```

## Development

### Build

```bash
cargo build -p misogi-sender
```

### Test

```bash
cargo test -p misogi-sender
```

### Run

```bash
cargo run -p misogi-sender -- server --config config.toml
```

## Dependencies

- `tokio`: Async runtime
- `axum`: Web framework
- `tonic`: gRPC client
- `tower-http`: HTTP middleware
- `notify`: File system monitoring
- `clap`: CLI parsing
- `serde`: Serialization
- `uuid`: Unique identifiers
- `chrono`: Timestamps

## Logging

The sender uses structured JSON logging:

```json
{
  "timestamp": "2026-04-10T12:00:00Z",
  "level": "INFO",
  "fields": {
    "message": "Transfer started",
    "file_id": "550e8400-e29b-41d4-a716-446655440000",
    "file_name": "example.txt"
  }
}
```

## Error Handling

Errors are handled gracefully with detailed error messages:

- Network errors
- File I/O errors
- Protocol errors
- Configuration errors

## License

Licensed under the Apache 2.0 License. See [LICENSE](../../LICENSE) for details.

---

# misogi-sender

Misogi 送信ノード - ファイルアップロードと転送開始を処理します。

## 概要

`misogi-sender` は、Misogi ファイル転送システムの送信コンポーネントです。以下を提供します：

- **HTTP API**: ファイルアップロードのための RESTful エンドポイント
- **gRPC ストリーミング**: 受信者への効率的なチャンク転送
- **ファイルモニタリング**: 新しいファイルのディレクトリ監視
- **デュアルモード**: サーバーまたはデーモンとして実行

## 機能

- 🌐 **HTTP サーバー**: ファイルアップロードのための Axum ベースのウェブサーバー
- 📡 **gRPC クライアント**: 受信者通信用のストリーミングクライアント
- 📂 **ファイルモニタリング**: `notify` を使用した新しいファイルの自動検出
- 🔄 **チャンク転送**: 効率的な転送のための設定可能なチャンクサイズ
- 📊 **進捗追跡**: リアルタイムの転送ステータスモニタリング
- 🔧 **CLI インターフェース**: `clap` を使用したコマンドラインインターフェース
- ⚙️ **設定**: TOML ベースの設定ファイル

## インストール

送信者バイナリのビルド：

```bash
cargo build --release --bin misogi-sender
```

## 使用方法

### サーバーモード

HTTP サーバーとして実行：

```bash
misogi-sender server --config config.toml
```

### デーモンモード

ファイルモニタリング付きのバックグラウンドデーモンとして実行：

```bash
misogi-sender daemon --config config.toml
```

### コマンドラインオプション

```bash
misogi-sender --help
```

## 設定

`config.toml` ファイルを作成：

```toml
[server]
addr = "127.0.0.1:3000"
storage_dir = "./storage"
chunk_size = 1048576  # 1MB
log_level = "info"

[receiver]
addr = "127.0.0.1:50051"  # gRPC 受信者アドレス
```

## API エンドポイント

### ファイルのアップロード

```http
POST /api/v1/upload
Content-Type: multipart/form-data

{
  "file": <file_data>
}
```

### 転送ステータスの取得

```http
GET /api/v1/transfers/{transfer_id}
```

### 転送の一覧

```http
GET /api/v1/transfers
```

## アーキテクチャ

```
┌─────────────┐
│   クライアント  │
└──────┬──────┘
       │ HTTP
       ▼
┌─────────────────┐
│  misogi-sender  │
│  ┌───────────┐  │
│  │ HTTP API  │  │
│  └─────┬─────┘  │
│        │        │
│  ┌─────▼─────┐  │
│  │   gRPC    │  │
│  │  クライアント  │  │
│  └─────┬─────┘  │
└────────┼────────┘
         │ gRPC ストリーム
         ▼
┌─────────────────┐
│ misogi-receiver │
└─────────────────┘
```

## プロジェクト構造

```
misogi-sender/
├── src/
│   ├── main.rs           # アプリケーションエントリーポイント
│   ├── cli.rs            # コマンドラインインターフェース
│   ├── config.rs         # 設定管理
│   ├── state.rs          # アプリケーションステート
│   ├── upload_engine.rs  # ファイルアップロードロジック
│   ├── http_routes.rs    # HTTP ルートハンドラー
│   ├── grpc_service.rs   # gRPC クライアントサービス
│   ├── router.rs         # HTTP ルーターセットアップ
│   └── tunnel_task.rs    # 転送トンネル管理
└── Cargo.toml
```

## 開発

### ビルド

```bash
cargo build -p misogi-sender
```

### テスト

```bash
cargo test -p misogi-sender
```

### 実行

```bash
cargo run -p misogi-sender -- server --config config.toml
```

## 依存関係

- `tokio`: 非同期ランタイム
- `axum`: ウェブフレームワーク
- `tonic`: gRPC クライアント
- `tower-http`: HTTP ミドルウェア
- `notify`: ファイルシステムモニタリング
- `clap`: CLI パーシング
- `serde`: シリアライゼーション
- `uuid`: 一意の識別子
- `chrono`: タイムスタンプ

## ロギング

送信者は構造化 JSON ロギングを使用します：

```json
{
  "timestamp": "2026-04-10T12:00:00Z",
  "level": "INFO",
  "fields": {
    "message": "転送開始",
    "file_id": "550e8400-e29b-41d4-a716-446655440000",
    "file_name": "example.txt"
  }
}
```

## エラーハンドリング

エラーは詳細なエラーメッセージで適切に処理されます：

- ネットワークエラー
- ファイル I/O エラー
- プロトコルエラー
- 設定エラー

## ライセンス

Apache 2.0 ライセンスの下でライセンスされています。詳細は [LICENSE](../../LICENSE) を参照してください。
