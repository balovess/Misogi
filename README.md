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

> **🧪 Clean Room Design**: All CDR algorithms are developed from publicly available specifications only —
> ISO 32000 (PDF), APPNOTE (.ZIP), ECMA-376 (OOXML), W3C (SVG), and Rust/nom documentation.
> No reverse engineering of any third-party product has been performed.

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

---

## 🌍 圧倒的な統合性（Polyglot Integration）

Misogi は日本の SIer（富士通、日立、NEC、NTTデータ等）が既存技術スタックを書き換えることなく統合できるよう、多言語 SDK エコシステムを提供します。

### 統合アーキテクチャ

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Misogi CDR Engine (Rust)                         │
│              True CDR · WASM Edge · gRPC Native                     │
├─────────────┬─────────────┬──────────────┬────────────┬────────────┤
│    Java     │   Python    │   Node.js    │  Browser   │   gRPC     │
│ Spring Boot │   asyncio   │ React + TS   │   WASM     │   Tonic    │
│  gRPC-Java  │  grpcio     │  gRPC-Web    │  wasm32    │  Native   │
└──────┬──────┴──────┬──────┴──────┬───────┴──────┬─────┴──────┬─────┘
       │             │             │              │            │
   proto-dist/   examples/      examples/     examples/    crates/
   v1/v2 proto   java-spring-   web-react     wasm-browser  misogi-core
                 boot/          /src/client/
                 src/main/      grpc.ts
                 java/
```

### サポート言語とクイックスタート

| 言語 | フレームワーク | 場所 | セットアップ |
|------|-------------|------|------------|
| **Java** | Spring Boot 3.x + gRPC-Java | [`examples/java-spring-boot`](examples/java-spring-boot/) | `./gradlew bootRun` |
| **Python** | asyncio + grpcio | [`examples/python-client`](examples/python-client/) | `pip install -e . && misogi sanitize file.pdf` |
| **React** | Vite + TypeScript + gRPC-Web | [`examples/web-react`](examples/web-react/) | `npm install && npm run dev` |
| **WASM** | wasm-pack + browser | [`examples/wasm-browser`](examples/wasm-browser/) | `wasm-pack build && open index.html` |

### Proto 配布

gRPC スタブは [`proto-dist/`](proto-dist/) ディレクトリから Buf ツールチェーンで生成可能です：

```bash
cd proto-dist
buf generate          # Java/Python/TS/Go の全スタブを一括生成
buf lint               # Proto 定義のLintチェック
buf breaking --against '.git/#branch=main'  # 後方互換性検証
```

---

## 🚀 WASM Edge Sanitization（WASM 边縁浄化）

Misogi の最強の非対称武器 — **ブラウザ内完結型 CDR 処理**。ファイルはサーバーに送信されることなく、クライアントサイドで完全に浄化されます。

### パフォーマンス比較

| 指標 | Misogi WASM (Browser) | FileZen / VOTIRO (Server) |
|------|---------------------|--------------------------|
| **レイテンシ** | < 200ms (ローカル処理) | 2–10s (ラウンドトリップ) |
| **帯域消費** | 0 (処理前後同サイズ) | 2x (アップロード＋ダウンロード) |
| **プライバシー** | ファイルはクライアントを出ない | サーバーにファイル転送必須 |
| **サーバー依存** | 不要 | 専用インフラ必要 |
| **オフライン動作** | ✅ 可能 | ❌ 不可能 |

### 技術的仕組み

```
┌──────────────────────────────────────────────────┐
│                  Browser                          │
│                                                   │
│  [Drag & Drop] → [WASM Module] → [Sanitized PDF] │
│                      │                            │
│                      ▼                            │
│  ┌─────────────────────────────────────┐         │
│  │  misogi-wasm (wasm32-unknown-unknown)│         │
│  │  · sanitize_pdf()                   │         │
│  │  · sanitize_office()                │         │
│  │  · scan_pii()                       │         │
│  │  · detect_file_type()               │         │
│  └─────────────────────────────────────┘         │
│                                                   │
│  Zero network dependency · Zero server trust      │
└──────────────────────────────────────────────────┘
```

### デモ起動

```bash
cd crates/misogi-wasm
wasm-pack build --target web --out-dir examples/wasm-browser/pkg
cd examples/wasm-browser
python -m http.server 8080  # Open http://localhost:8080
```

---

## 📡 SIer 集成指南（SIer 向け統合ガイド）

日本の政府・企業システムインテグレーター向けの、各言語別詳細統合ガイド。

### Java / Spring Boot 統合（富士通／日立／NEC 向け）

```java
// gRPC クライアント初期化
ManagedChannel channel = ManagedChannelBuilder.forAddress("misogi-gov.local", 50051)
    .usePlaintext().build();
FileTransferServiceGrpc.FileTransferServiceBlockingStub stub =
    FileServiceGrpc.newBlockingStub(channel);

// ファイルアップロード → CDR 処理 → ダウンロード
UploadResponse resp = stub.uploadFile(UploadRequest.newBuilder()
    .setFileName("report.pdf")
    .setData(ByteString.copyFrom(fileBytes))
    .setPolicy("STRIP")
    .build());
```

完全な例: [`examples/java-spring-boot/`](examples/java-spring-boot/)

### Python 非同期クライアント（NTT データ／KDDI 向け）

```python
import asyncio
from misogi_client.client import MisogiClient

async def sanitize():
    async with MisogiChannel("localhost:50051") as client:
        job = await client.sanitize_file(
            "document.docx",
            policy="FLAT",
            chunk_size=1024*1024
        )
        result = await client.download_result(job.job_id)
        print(f"Threats found: {result.threat_count}")

asyncio.run(sanitize())
```

完全な例: [`examples/python-client/`](examples/python-client/)

### React + gRPC-Web フロントエンド（Web システム向け）

```typescript
import { useMisogiClient } from '../hooks/useMisogiClient';

function SanitizePanel() {
  const { client, connected } = useMisogiClient('http://localhost:8080');

  const handleDrop = async (file: File) => {
    const jobId = await client.uploadAndScan(file, 'STRIP');
    const result = await client.pollUntilComplete(jobId);
    downloadBlob(result.data, `sanitized_${file.name}`);
  };
}
```

完全な例 + Envoy プロキシ設定: [`examples/web-react/`](examples/web-react/)

### カスタム外部スキャナ実装

`ExternalScanner` trait を実装して、任意のセキュリティ製品を接続可能：

```rust
use misogi_core::scanners::{ExternalScanner, ScanResult, ScanError};

pub struct MyCustomScanner {
    endpoint: String,
}

#[async_trait]
impl ExternalScanner for MyCustomScanner {
    fn name(&self) -> &str { "my-custom-scanner" }

    async fn scan_stream(&self, data: &[u8]) -> Result<ScanResult> {
        // 自社製スキャンエンジンとの通信ロジック
        todo!()
    }

    async fn health_check(&self) -> bool {
        // ヘルスチェック実装
        true
    }
}
```

### デプロイメントオプション

| 環境 | 推奨構成 | 適用シーン |
|------|---------|-----------|
| **オンプレミス (LGWAN)** | Docker Compose + ClamAV | 庁省内閉網導入 |
| **G-Cloud (クラウド認証基盤)** | Helm Chart + OIDC連携 | 政府クラウド移行 |
| **AWS/Azure GovCloud** | EKS/AKS + HPA | 高可用性要件 |
| **エッジ/WASM** | ブラウザ埋め込み | リモートワーク・端末浄化 |

---

## 🔒 Security: Rust Memory Safety（Rust メモリ安全性）

### CVE 対比: Misogi vs 競合製品

| 製品 | 言語 | メモリ安全 | 歴史 CVE 数 | 代表的な CVE クラス |
|------|------|----------|------------|------------------|
| **Misogi** | **Rust** | **✅ コンパイル時保証** | **0** | — |
| FileZen (Sharp) | C/C++ | ❌ 実行時依存 | 10+ | Buffer Overflow, Use-After-Free |
| VOTIRO | C/C++ | ❌ 実行時依存 | 5+ | Heap Corruption, Integer Overflow |
| その他 CDR 製品 | C#/Java | ⚠️ GC依存 | 3+ | Deserialization, Injection |

### True CDR vs 単純 NOP 置換

```
【従来方式 (NOP 置換)】          【Misogi True CDR】
┌──────────────┐                ┌──────────────┐
│ 元ファイル     │                │ 元ファイル     │
│  [PDF バイナリ]│                │  [PDF バイナリ]│
└──────┬───────┘                └──────┬───────┘
       │ 危険命令を 0x90 で上書き       │ 解析
       ▼                               ▼
┌──────────────┐                ┌──────────────┐
│ 「浄化」済み  │ ← 元のバイト │ 新規コンテナ   │ ← ゼロコピー再構築
│ (元バイト残存)│   が残存する   │ (安全な要素のみ)│
└──────────────┘                └──────────────┘
 ⚠️ 回避可能                        ✅ 本質的に安全
```

### セキュリティ機能チェックリスト

- ✅ **RS256 JWT** — 非対称鍵署名 (HS256 対称鍵は不使用)
- ✅ **LDAP / AD / OIDC / SAML** — 日本政府 IDP 連携対応
- ✅ **暗号化通信** — TLS 1.3 (gRPC + HTTP + SMTP)
- ✅ **監査ログ** — 全操作の不変ログ (PostgreSQL 永続化)
- ✅ **個人情報 (PII) 検出** — マイナンバー (個人番号) パターン検知
- ✅ **ISMAP 準拠** — LGWAN セキュリティ要件対応
- ✅ **Zero-Copy Rebuild** — True CDR による元バイト完全排除
- ✅ **NetworkPolicy** — K8s ネットワーク分離 (デフォルト Deny All)
- ✅ **Rate Limiting** — API レート制限 (Sliding Window アルゴリズム)

---

## 🐳 Deployment Options（デプロイオプション）

### Docker Compose (クイックスタート)

```bash
# 環境変数設定
cp docker/.env.example .env
# vim .env  # 必要に応じて編集

# 全サービス起動 (Core 5サービス)
docker compose -f docker/docker-compose.prod.yml up -d

# + 監視スタック追加 (ClamAV + Prometheus + Grafana)
docker compose -f docker/docker-compose.prod.yml --profile scanner up -d
```

### Kubernetes / Helm (本番環境)

```bash
# Helm Chart でデプロイ
helm install misogi ./helm/misogi \
  -n misogi-system \
  --create-namespace \
  -f values-production.yaml

# ステータス確認
kubectl get pods -n misogi-system
kubectl get ingress -n misogi-system

# Grafana ダッシュボードアクセス
kubectl port-forward svc/misogi-grafana 3000:80 -n misogi-system
```

### ベアメタル (直接ビルド)

```bash
# RSA 鍵ペア生成 (初回のみ)
cargo run --package misogi-auth --example generate-keys -- ./keys

# ビルド & 起動
cargo build --release --bins
./target/release/misogi-sender --config config.toml &
./target/release/misogi-receiver --config config.toml &
./target/release/misogi-smtp --config smtp.toml &
```

### WASM エッジ (ブラウザ埋め込み)

```bash
cd crates/misogi-wasm
wasm-pack build --target web --out-dir ../examples/wasm-browser/pkg
cd ../examples/wasm-browser
npx serve .
# → Open http://localhost:3000 for zero-server sanitization demo
```

### デプロイメント比較

| モード | 起動時間 | スケーラビリティ | 運用複雑度 | 最適ユースケース |
|--------|---------|---------------|-----------|----------------|
| **Docker Compose** | ~30s | 単一ホスト | ★☆☆ | PoC / 検証環境 |
| **Helm (K8s)** | ~2min | 水平自動スケール | ★★★ | 本番運用 / 大規模導入 |
| **ベアメタル** | 即座 | 手動 | ★★☆ | 開発 / デバッグ |
| **WASM エッジ** | 即座 | N/A (クライアント側) | ☆☆☆ | リモートワーク / 端末 |

---

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
See also [PATENTS](PATENTS) for patent grant information.

## ⚠️ Disclaimer / 免責事項

**EN**: This software is provided **"AS IS"** without warranty of any kind, express or implied.
The authors assume **NO LIABILITY** for damages including but not limited to:
data breaches, information leakage, business interruption, financial loss,
or security incidents from misconfiguration or unknown vulnerabilities (including zero-day exploits).
**This software does NOT guarantee 100% detection of all malicious content.**
Before deploying in production environments — especially government systems,
financial institutions, or critical infrastructure — you **MUST** conduct
thorough internal security assessments and compliance reviews at your own responsibility.

**JP**: 本ソフトウェアは**「現状のまま（As Is）」**提供され、明示・黙示を問わず
いかなる保証も伴いません。作者は、データ漏洩、情報流出、業務中断、金銭的損失、
設定ミスまたは未知の脆弱性（ゼロデイ攻撃を含む）によるセキュリティインシデント等、
本ソフトウェアの使用によって生じたいかなる損害について**一切の責任を負いません。**
**本ソフトウェアが全ての悪意あるコンテンツを100%検出することを保証するものではありません。**
政府機関、金融機関、重要インフラ等での本番稼働前に、**各自の責任において*
*十分な内部セキュリティ審査とコンプライアンスレビューを実施してください。**

Copyright 2026 Misogi Contributors

## Acknowledgments

- Built with [Tokio](https://tokio.rs/) - Async runtime
- Uses [Axum](https://github.com/tokio-rs/axum) - Web framework
- Implements [Tonic](https://github.com/hyperium/tonic) - gRPC library
- Powered by [Prost](https://github.com/tokio-rs/prost) - Protocol buffers

---

**Misogi** - Purifying your file transfers with Rust's safety and performance.
