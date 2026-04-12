[English](README.md) | [日本語](README_ja.md)

# Misogi (禊ぎ)

**Rust 2024 Edition で構築された、高性能・セキュアなファイル転送システム**

Misogi（禊ぎ）は、信頼性、セキュリティ、パフォーマンスを重視して設計されたモダンなファイル転送ソリューションです。チャンク転送、リアルタイムモニタリング、gRPC ベースの通信をサポートする送信者 - 受信者アーキテクチャを実装しています。

## 主な特徴

- 🚀 **高性能**: Tokio を使用した非同期 Rust により最大スループットを実現
- 🔒 **セキュリティ優先**: TLS サポートを備えた安全な通信チャネルを実装
- 📦 **チャンク転送**: 設定可能なチャンクサイズによる効率的なファイル転送
- 🔄 **リアルタイムモニタリング**: 詳細な進捗情報でファイル転送を追跡
- 🛠️ **デュアルモード操作**: サーバーまたはデーモンとして実行可能
- 📡 **gRPC 統合**: 信頼性の高い通信のためのモダンな RPC フレームワーク
- 🔍 **包括的なロギング**: 設定可能なログレベルの JSON 形式ログ
- 🎯 **型安全**: 最大の型安全性とパフォーマンスのために Rust 2024 edition を活用

## アーキテクチャ

> **🧪 クリーンルーム設計**: すべての CDR アルゴリズムは公開仕様書のみに基づいて開発されています —
> ISO 32000 (PDF)、APPNOTE (.ZIP)、ECMA-376 (OOXML)、W3C (SVG)、および Rust/nom ドキュメント。
> サードパーティ製品の逆エンジニアリングは一切行っていません。

Misogi は 3 つの主要コンポーネントで構成されています：

### misogi-core
コアライブラリ：
- プロトコル定義（Protobuf）
- ファイル整合性のためのハッシュユーティリティ
- エラーハンドリング
- 型定義

### misogi-sender
送信ノード：
- ファイルアップロードと転送開始
- ファイル送信のための HTTP API
- 受信者への gRPC ストリーミング
- `notify` によるファイルシステムモニタリング

### misogi-receiver
受信ノード：
- ファイル受信と保存
- HTTP ダウンロードエンドポイント
- ストリーム受信のための gRPC サービス
- チャンクからのファイル再構築

## 要件

- **Rust**: 1.75+（Edition 2024）
- **Protocol Buffers**: gRPC サービス定義用
- **Tokio**: 非同期ランタイム

## インストール

### リポジトリのクローン

```bash
git clone https://github.com/balovess/Misogi.git
cd Misogi
```

### プロジェクトのビルド

```bash
cargo build --release
```

### バイナリの個別ビルド

```bash
# 送信者のビルド
cargo build --release --bin misogi-sender

# 受信者のビルド
cargo build --release --bin misogi-receiver
```

## 使用方法

### 送信ノード

#### サーバーモード

```bash
misogi-sender server --config config.toml
```

#### デーモンモード

```bash
misogi-sender daemon --config config.toml
```

#### コマンドラインオプション

```bash
misogi-sender --help
```

### 受信ノード

#### サーバーモード

```bash
misogi-receiver server --config config.toml
```

#### デーモンモード

```bash
misogi-receiver daemon --config config.toml
```

#### コマンドラインオプション

```bash
misogi-receiver --help
```

## 設定

以下の構造で `config.toml` ファイルを作成します：

### 送信者設定

```toml
[server]
addr = "127.0.0.1:3000"
storage_dir = "./storage"
chunk_size = 1048576  # 1MB
log_level = "info"

[receiver]
addr = "127.0.0.1:50051"  # オプション：gRPC 受信者アドレス
```

### 受信者設定

```toml
[server]
addr = "127.0.0.1:3001"
download_dir = "./downloads"
storage_dir = "./storage"
tunnel_port = 50051
log_level = "info"
```

## プロジェクト構造

```
Misogi/
├── Cargo.toml              # ワークスペース設定
├── Cargo.lock              # 依存関係ロックファイル
├── crates/
│   ├── misogi-core/        # コアライブラリ
│   │   ├── Cargo.toml
│   │   ├── build.rs
│   │   ├── proto/          # Protobuf 定義
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── protocol.rs
│   │       ├── hash.rs
│   │       ├── error.rs
│   │       └── types.rs
│   ├── misogi-sender/      # 送信者アプリケーション
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
│   └── misogi-receiver/    # 受信者アプリケーション
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

## 開発

### テストの実行

```bash
cargo test
```

### ドキュメントのビルド

```bash
cargo doc --open
```

### コードのフォーマット

```bash
cargo fmt
```

### リンティング

```bash
cargo clippy
```

## 技術的詳細

### プロトコル

Misogi は Protocol Buffers（Protobuf）を使用して gRPC サービスを定義しています：

- **FileTransfer**: ファイル転送操作のコアサービス
- **ChunkStream**: チャンクファイルデータのためのストリーミングサービス
- **Status Reporting**: リアルタイム転送ステータス更新

### エラーハンドリング

`thiserror` を使用して包括的なエラーハンドリングを実装：
- ネットワークエラー
- ファイル I/O エラー
- プロトコルエラー
- 設定エラー

### ロギング

`tracing` と `tracing-subscriber` による構造化 JSON ロギング：
- 設定可能なログレベル（trace, debug, info, warn, error）
- 環境変数ベースのフィルタリング
- パース容易な JSON 出力

## コントリビュート

コントリビューションを歓迎します！以下の手順に従ってください：

1. リポジトリをフォーク
2. 機能ブランチを作成（`git checkout -b feature/amazing-feature`）
3. 変更をコミット（`git commit -m 'Add some amazing feature'`）
4. ブランチにプッシュ（`git push origin feature/amazing-feature`）
5. プルリクエストをオープン

### コードスタイル

- すべてのコードは Rust 2024 Edition でコンパイル可能であること
- Rust コミュニティガイドラインに従うこと
- 包括的なドキュメントコメントを追加すること
- 送信前にすべてのテストに合格すること

## ライセンス

このプロジェクトは Apache 2.0 ライセンスの下でライセンスされています - 詳細は [LICENSE](LICENSE) ファイルを参照してください。
特許許諾については [PATENTS](PATENTS) も併せてご確認ください。

## ⚠️ 免責事項 / Disclaimer

**JP**: 本ソフトウェアは**「現状のまま（As Is）」**提供され、明示・黙示を問わず
いかなる保証も伴いません。作者は、データ漏洩、情報流出、業務中断、金銭的損失、
設定ミスまたは未知の脆弱性（ゼロデイ攻撃を含む）によるセキュリティインシデント等、
本ソフトウェアの使用によって生じたいかなる損害について**一切の責任を負いません。**
**本ソフトウェアが全ての悪意あるコンテンツを100%検出することを保証するものではありません。**
政府機関、金融機関、重要インフラ等での本番稼働前に、
**各自の責任において十分な内部セキュリティ審査とコンプライアンスレビューを実施してください。**

**EN**: This software is provided **"AS IS"** without warranty of any kind.
The authors assume **NO LIABILITY** for damages including data breaches,
business interruption, or security incidents from unknown vulnerabilities.
This software does NOT guarantee 100% threat detection.
Conduct internal security review before production deployment.

Copyright 2026 Misogi Contributors

## 謝辞

- [Tokio](https://tokio.rs/) - 非同期ランタイム
- [Axum](https://github.com/tokio-rs/axum) - ウェブフレームワーク
- [Tonic](https://github.com/hyperium/tonic) - gRPC ライブラリ
- [Prost](https://github.com/tokio-rs/prost) - プロトコルバッファ

---

**Misogi** - Rust の安全性とパフォーマンスでファイル転送を浄化します。
