# misogi-receiver

Misogi receiver node - handles file reception and storage.

## Overview

`misogi-receiver` is the receiver component of the Misogi file transfer system. It provides:

- **gRPC Server**: Receive chunked file streams
- **HTTP Download**: RESTful endpoints for file download
- **File Storage**: Efficient file reassembly and storage
- **Dual Mode**: Run as server or daemon

## Features

- 📡 **gRPC Server**: Tonic-based server for receiving file chunks
- 🌐 **HTTP Server**: Axum-based web server for downloads
- 💾 **File Reassembly**: Reconstruct files from received chunks
- 📂 **Storage Management**: Organized file storage with metadata
- 🔄 **Tunnel Support**: Direct tunnel mode for point-to-point transfer
- 📊 **Progress Tracking**: Real-time receive status monitoring
- 🔧 **CLI Interface**: Command-line interface with `clap`
- ⚙️ **Configuration**: TOML-based configuration files

## Installation

Build the receiver binary:

```bash
cargo build --release --bin misogi-receiver
```

## Usage

### Server Mode

Run as a gRPC/HTTP server:

```bash
misogi-receiver server --config config.toml
```

### Daemon Mode

Run as a background daemon:

```bash
misogi-receiver daemon --config config.toml
```

### Tunnel Mode

Enable tunnel mode for direct sender-receiver communication:

```bash
misogi-receiver server --config config.toml --tunnel-port 50051
```

### Command Line Options

```bash
misogi-receiver --help
```

## Configuration

Create a `config.toml` file:

```toml
[server]
addr = "127.0.0.1:3001"
download_dir = "./downloads"
storage_dir = "./storage"
tunnel_port = 50051
log_level = "info"
```

## API Endpoints

### Download File

```http
GET /api/v1/download/{file_id}
```

### List Received Files

```http
GET /api/v1/files
```

### Get File Info

```http
GET /api/v1/files/{file_id}
```

### Get Transfer Status

```http
GET /api/v1/transfers/{transfer_id}
```

## Architecture

```
┌─────────────────┐
│  misogi-sender  │
│  ┌───────────┐  │
│  │   gRPC    │  │
│  │  Client   │  │
│  └─────┬─────┘  │
└────────┼────────┘
         │ gRPC Stream
         ▼
┌─────────────────┐
│ misogi-receiver │
│  ┌───────────┐  │
│  │   gRPC    │  │
│  │  Server   │  │
│  └─────┬─────┘  │
│        │        │
│  ┌─────▼─────┐  │
│  │  Storage  │  │
│  │  Manager  │  │
│  └─────┬─────┘  │
│        │        │
│  ┌─────▼─────┐  │
│  │ HTTP API  │  │
│  └─────┬─────┘  │
└────────┼────────┘
         │ HTTP
         ▼
┌─────────────┐
│   Client    │
└─────────────┘
```

## Project Structure

```
misogi-receiver/
├── src/
│   ├── main.rs            # Application entry point
│   ├── cli.rs             # Command-line interface
│   ├── config.rs          # Configuration management
│   ├── state.rs           # Application state
│   ├── storage.rs         # File storage management
│   ├── http_routes.rs     # HTTP route handlers
│   ├── grpc_service.rs    # gRPC server service
│   ├── router.rs          # HTTP router setup
│   ├── daemon.rs          # Daemon mode logic
│   └── tunnel_handler.rs  # Tunnel mode handler
└── Cargo.toml
```

## Development

### Build

```bash
cargo build -p misogi-receiver
```

### Test

```bash
cargo test -p misogi-receiver
```

### Run

```bash
cargo run -p misogi-receiver -- server --config config.toml
```

## Dependencies

- `tokio`: Async runtime
- `axum`: Web framework
- `tonic`: gRPC server with TLS support
- `tower-http`: HTTP middleware
- `notify`: File system monitoring
- `clap`: CLI parsing
- `serde`: Serialization
- `uuid`: Unique identifiers
- `futures`: Async utilities

## Storage Structure

Files are stored in an organized structure:

```
storage/
├── incoming/          # Files being received
│   └── {file_id}/
│       └── chunk_0001
├── completed/         # Fully received files
│   └── {file_name}
└── metadata/          # Transfer metadata
    └── {file_id}.json
```

## Logging

The receiver uses structured JSON logging:

```json
{
  "timestamp": "2026-04-10T12:00:00Z",
  "level": "INFO",
  "fields": {
    "message": "File received successfully",
    "file_id": "550e8400-e29b-41d4-a716-446655440000",
    "file_name": "example.txt",
    "total_size": 1048576,
    "chunks_received": 10
  }
}
```

## Error Handling

Comprehensive error handling for:

- Network errors
- File I/O errors
- Storage errors
- Protocol errors
- Configuration errors

## Security

- TLS support for gRPC connections
- File integrity verification
- Secure storage permissions
- Input validation

## License

Licensed under the Apache 2.0 License. See [LICENSE](../../LICENSE) for details.

---

# misogi-receiver

Misogi 受信ノード - ファイル受信と保存を処理します。

## 概要

`misogi-receiver` は、Misogi ファイル転送システムの受信コンポーネントです。以下を提供します：

- **gRPC サーバー**: チャンクファイルストリームを受信
- **HTTP ダウンロード**: ファイルダウンロードのための RESTful エンドポイント
- **ファイル保存**: 効率的なファイルの再構築と保存
- **デュアルモード**: サーバーまたはデーモンとして実行

## 機能

- 📡 **gRPC サーバー**: ファイルチャンク受信のための Tonic ベースのサーバー
- 🌐 **HTTP サーバー**: ダウンロードのための Axum ベースのウェブサーバー
- 💾 **ファイル再構築**: 受信したチャンクからファイルを再構築
- 📂 **ストレージ管理**: メタデータ付きの整理されたファイル保存
- 🔄 **トンネルサポート**: ポイントツーポイント転送のためのダイレクトトンネルモード
- 📊 **進捗追跡**: リアルタイムの受信ステータスモニタリング
- 🔧 **CLI インターフェース**: `clap` を使用したコマンドラインインターフェース
- ⚙️ **設定**: TOML ベースの設定ファイル

## インストール

受信者バイナリのビルド：

```bash
cargo build --release --bin misogi-receiver
```

## 使用方法

### サーバーモード

gRPC/HTTP サーバーとして実行：

```bash
misogi-receiver server --config config.toml
```

### デーモンモード

バックグラウンドデーモンとして実行：

```bash
misogi-receiver daemon --config config.toml
```

### トンネルモード

送信者 - 受信者の直接通信用にトンネルモードを有効化：

```bash
misogi-receiver server --config config.toml --tunnel-port 50051
```

### コマンドラインオプション

```bash
misogi-receiver --help
```

## 設定

`config.toml` ファイルを作成：

```toml
[server]
addr = "127.0.0.1:3001"
download_dir = "./downloads"
storage_dir = "./storage"
tunnel_port = 50051
log_level = "info"
```

## API エンドポイント

### ファイルのダウンロード

```http
GET /api/v1/download/{file_id}
```

### 受信ファイルの一覧

```http
GET /api/v1/files
```

### ファイル情報の取得

```http
GET /api/v1/files/{file_id}
```

### 転送ステータスの取得

```http
GET /api/v1/transfers/{transfer_id}
```

## アーキテクチャ

```
┌─────────────────┐
│  misogi-sender  │
│  ┌───────────┐  │
│  │   gRPC    │  │
│  │  クライアント  │  │
│  └─────┬─────┘  │
└────────┼────────┘
         │ gRPC ストリーム
         ▼
┌─────────────────┐
│ misogi-receiver │
│  ┌───────────┐  │
│  │   gRPC    │  │
│  │  サーバー   │  │
│  └─────┬─────┘  │
│        │        │
│  ┌─────▼─────┐  │
│  │  ストレージ  │  │
│  │  マネージャー │  │
│  └─────┬─────┘  │
│        │        │
│  ┌─────▼─────┐  │
│  │ HTTP API  │  │
│  └─────┬─────┘  │
└────────┼────────┘
         │ HTTP
         ▼
┌─────────────┐
│   クライアント  │
└─────────────┘
```

## プロジェクト構造

```
misogi-receiver/
├── src/
│   ├── main.rs            # アプリケーションエントリーポイント
│   ├── cli.rs             # コマンドラインインターフェース
│   ├── config.rs          # 設定管理
│   ├── state.rs           # アプリケーションステート
│   ├── storage.rs         # ファイル保存管理
│   ├── http_routes.rs     # HTTP ルートハンドラー
│   ├── grpc_service.rs    # gRPC サーバーサービス
│   ├── router.rs          # HTTP ルーターセットアップ
│   ├── daemon.rs          # デーモンモードロジック
│   └── tunnel_handler.rs  # トンネルモードハンドラー
└── Cargo.toml
```

## 開発

### ビルド

```bash
cargo build -p misogi-receiver
```

### テスト

```bash
cargo test -p misogi-receiver
```

### 実行

```bash
cargo run -p misogi-receiver -- server --config config.toml
```

## 依存関係

- `tokio`: 非同期ランタイム
- `axum`: ウェブフレームワーク
- `tonic`: TLS サポート付き gRPC サーバー
- `tower-http`: HTTP ミドルウェア
- `notify`: ファイルシステムモニタリング
- `clap`: CLI パーシング
- `serde`: シリアライゼーション
- `uuid`: 一意の識別子
- `futures`: 非同期ユーティリティ

## 保存構造

ファイルは整理された構造で保存されます：

```
storage/
├── incoming/          # 受信中のファイル
│   └── {file_id}/
│       └── chunk_0001
├── completed/         # 完全に受信されたファイル
│   └── {file_name}
└── metadata/          # 転送メタデータ
    └── {file_id}.json
```

## ロギング

受信者は構造化 JSON ロギングを使用します：

```json
{
  "timestamp": "2026-04-10T12:00:00Z",
  "level": "INFO",
  "fields": {
    "message": "ファイルが正常に受信されました",
    "file_id": "550e8400-e29b-41d4-a716-446655440000",
    "file_name": "example.txt",
    "total_size": 1048576,
    "chunks_received": 10
  }
}
```

## エラーハンドリング

包括的なエラーハンドリング：

- ネットワークエラー
- ファイル I/O エラー
- ストレージエラー
- プロトコルエラー
- 設定エラー

## セキュリティ

- gRPC 接続のための TLS サポート
- ファイル整合性検証
- 安全なストレージ権限
- 入力検証

## ライセンス

Apache 2.0 ライセンスの下でライセンスされています。詳細は [LICENSE](../../LICENSE) を参照してください。
