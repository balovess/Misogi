# 🌍 圧倒的な統合性（Polyglot Integration）

## Polyglot Integration Examples

Misogi は Rust 製のヘッドレス CDR（Content Disarm & Reconstruction）エンジンですが、
gRPC / REST インターフェースを介して**あらゆる言語・プラットフォーム**から利用可能です。

本ディレクトリは、各種プログラミング言語およびランタイム環境における
Misogi クライアント実装例（SDK サンプル）を集積するポリグロット統合エコシステムです。

---

## 📐 Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Misogi Headless Engine                       │
│                   (Rust / Tonic gRPC Server)                        │
│                                                                     │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐   │
│  │ Sender Node  │◄──►│  CDR Engine  │◄──►│   Receiver Node      │   │
│  │  (:50051)    │    │  (Core)      │    │   (:50052)           │   │
│  └──────┬───────┘    └──────┬───────┘    └──────────┬───────────┘   │
│         │ gRPC              │ gRPC / HTTP/2           │             │
│         │                   │                         │             │
│  ┌──────▼───────────────────▼─────────────────────────▼───────────┐  │
│  │                    Protocol Layer                               │  │
│  │     SenderService V1/V2  │  ReceiverService V1/V2               │  │
│  │     (misogi.file_transfer.v*)                                  │  │
│  └────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┬──────────────────┐
          │                   │                   │                  │
   ┌──────▼──────┐   ┌───────▼──────┐   ┌────────▼────────┐  ┌──────▼──────┐
   │ Java/Spring │   │   Python     │   │  React (Web)    │  │ WASM/Browser │
   │    Boot     │   │  (asyncio)   │   │  (gRPC-Web)     │  │  (client)    │
   │             │   │              │   │                 │  │              │
   │ gRPC-Java   │   │ grpcio       │   │ grpc-web + TS   │  │ wasm-bindgen │
   │ + Spring    │   │ + asyncio    │   │ protoc-gen-ts   │  │ + protobuf-js│
   └─────────────┘   └──────────────┘   └─────────────────┘  └──────────────┘

   examples/          examples/           examples/            examples/
   java-spring-boot/  python-client/      web-react/            wasm-browser/
```

---

## 📦 Example Projects Index

| # | Directory | Language / Runtime | Protocol | Description |
|---|-----------|--------------------|----------|-------------|
| 1 | `java-spring-boot/` | Java 21+ / Spring Boot 3.x | gRPC-Java | Spring Boot 3 ベースの gRPC クライアント。SIer 環境でのエンタープライズ統合向け。 |
| 2 | `python-client/` | Python 3.11+ / asyncio | grpcio | 非同期 Python クライアント。スクリプト自動化・データパイプライン用途。 |
| 3 | `web-react/` | TypeScript / React 18+ | gRPC-Web | React フロントエンド。ブラウザからの直接操作 UI 向け。 |
| 4 | `wasm-browser/` | Rust → WASM / Browser | protobuf-js | ブラウザ内 WASM ランタイムでプロトコル処理を行う軽量クライアント。 |

---

## ⚡ Quick Start

### Prerequisites

| Component | Minimum Version |
|-----------|----------------|
| Rust toolchain | 1.85+ (edition 2024) |
| Misogi server | Running on `:50051` (sender) / `:50052` (receiver) |
| Buf CLI (for SDK generation) | v1.40+ _(optional, see `../proto-dist/`)_ |

### Start Misogi Server

```bash
# Build and run sender node
cargo run --bin misogi-sender -- --config sender.toml

# In another terminal, build and run receiver node
cargo run --bin misogi-receiver -- --config receiver.toml
```

### Generate Client SDKs (Optional)

See [`../proto-dist/`](../proto-dist/) for detailed instructions:

```bash
cd ../proto-dist
buf generate
# Generated clients appear in: gen/java/, gen/python/, gen/go/, gen/ts/
```

### Run Each Example

```bash
# 1. Java Spring Boot
cd java-spring-boot && ./mvnw spring-boot:run

# 2. Python Client
cd python-client && pip install -r requirements.txt && python main.py

# 3. React Web
cd web-react && npm install && npm start

# 4. WASM Browser
cd wasm-browser && npm install && npm start
```

---

## 🔧 Proto Service Reference

Misogi の gRPC API は 2 つのバージョンを提供します：

### V1 — Stable Production API (`misogi.file_transfer.v1`)

| Service | RPC Method | Streaming | Description |
|---------|------------|-----------|-------------|
| `SenderService` | `Upload` | client→server | チャンク単位のファイルアップロード |
| `SenderService` | `GetFileStatus` | unary | ファイル状態取得 |
| `SenderService` | `ListFiles` | unary | ファイル一覧（ページネーション対応） |
| `SenderService` | `TriggerTransfer` | unary | レシーバーへの転送開始指示 |
| `ReceiverService` | `ReceiveChunk` | bidi | チャnk受信と ACK 応答 |
| `ReceiverService` | `DownloadFile` | server→client | ファイルダウンロードストリーム |
| `ReceiverService` | `ListFiles` | unary | レシーバー側ファイル一覧 |

### V2 — Future Extension (`misogi.file_transfer.v2`)

V2 は V1 に**後方互換**な形で以下を追加予定：

- `UploadV2`: 拡張メタデータ付きアップロード（MIME ヒント、カスタム注釈）
- `PreScan`: AI による事前コンテンツ分析（PII 検出、リスク評価）
- `ScanDepth` / `RiskLevel` 列挙型によるきめ細かい制御

> **Note**: V2 は現時点ではスケルトン定義のみ。実装は 2025-Q3 以降に予定されています。

---

## 📁 Directory Structure

```
examples/
├── README.md                  ← 本ファイル（インデックス）
├── java-spring-boot/
│   ├── README.md              ← Java 実装ガイド（準備中）
│   ├── src/main/java/         ← (将来)
│   ├── pom.xml                ← (将来)
│   └── ...
├── python-client/
│   ├── README.md              ← Python 実装ガイド（準備中）
│   ├── misogi_client.py       ← (将来)
│   ├── requirements.txt       ← (将来)
│   └── ...
├── web-react/
│   ├── README.md              ← React 実装ガイド（準備中）
│   ├── src/                   ← (将来)
│   ├── package.json           ← (将来)
│   └── ...
└── wasm-browser/
    ├── README.md              ← WASM 実装ガイド（準備中）
    ├── src/                   ← (将来)
    ├── package.json           ← (将来)
    └── ...
```

---

## 🤝 Contributing New Language Examples

新たな言語バインディングを追加する場合、以下の手順に従ってください：

1. `examples/<language-name>/` ディレクトリを作成
2. バイリンガル（日本語 / 英語）の `README.md` を作成
3. [`../proto-dist/buf.gen.yaml`](../proto-dist/buf.gen.yaml) に該当言語のプラグイン設定を追加
4. 本ファイル（`README.md`）の Index Table を更新
5. Architecture 図にノードを追加

---

## 📄 License

各サンプルコードのライセンスは親プロジェクト（[LICENSE](../LICENSE)）に準拠します。
生成された SDK コード（`proto-dist/gen/` 内）は各言語の Apache 2.0 ライセンスに従います。
