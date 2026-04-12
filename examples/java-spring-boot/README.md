# ☕ Java Spring Boot gRPC Client

## Spring Boot 3 ベースの Misogi gRPC クライアント実装例

本プロジェクトは、Java エコシステム（特に SIer 環境）でのエンタープライズ統合を想定した
Spring Boot 3.2.x アプリケーションから Misogi CDR エンジンを操作するための**完全な参照実装**です。

gRPC-Java を直接使用し、型安全なクライアントスタブと REST→gRPC ブリッジ機能を提供します。

---

## 📋 Overview / 概要

| Item | Detail |
|------|--------|
| **Language** | Java 21+ (LTS) |
| **Framework** | Spring Boot 3.2.x |
| **gRPC Library** | gRPC-Java 1.62.x |
| **Build Tool** | Gradle 8.x (with protobuf-gradle-plugin) |
| **Protocol** | `misogi.file_transfer.v1` SenderService / ReceiverService |

### Target Use Cases / 対象ユースケース

- 既存 Java エンタープライズシステムからのファイル送受信
- Spring Batch との連携による一括ファイル処理
- Spring Security による認証統合
- Web フロントエンドからの HTTP 経由アクセス（REST→gRPC ブリッジ）
- SIer 現場での既存レガシーシステム接続

---

## 📁 Project Structure / プロジェクト構成

```
examples/java-spring-boot/
├── build.gradle                  ← Gradle build config (proto plugin included)
├── settings.gradle               ← Project name: misogi-java-example
├── README.md                     ← 本ファイル
├── src/main/java/com/example/misogi/
│   ├── MisogiJavaExampleApplication.java   ← Spring Boot entry point
│   ├── client/
│   │   ├── MisogiGrpcClient.java           ← Core gRPC client wrapper
│   │   └── MisogiException.java            ← Domain exception
│   ├── service/
│   │   └── FileUploadService.java          ← @Service with lifecycle hooks
│   └── controller/
│       └── DemoController.java             ← REST → gRPC bridge
├── src/main/resources/
│   └── application.yml                     ← Configuration
└── src/test/java/com/example/misogi/client/
    └── MisogiGrpcClientTest.java            ← In-process unit tests
```

---

## 🔧 Prerequisites / 前提条件

| Component / コンポーネント | Minimum Version / 最低バージョン |
|----------------------------|----------------------------------|
| JDK                        | 21+ (LTS) |
| Gradle                     | 8.x |
| Misogi Server              | Running on configured port (default 50051) |

### Verification / 動作確認

```bash
java --version    # openjdk 21.0.x or later
gradle --version  # Gradle 8.x
```

---

## 🚀 Quick Start / クイックスタート

### Step 1: Generate Proto Code / Proto コード生成

Gradle の protobuf プラグインを使用して、`proto-dist/v1/misogi.proto` から
Java クラスを生成します。

```bash
cd examples/java-spring-boot

# Generate gRPC stubs from V1 proto definition
./gradlew generateProto
```

生成されるクラス:
- `misogi.file_transfer.v1.SenderServiceGrpc` — SenderService の blocking/async stub
- `misogi.file_transfer.v1.ReceiverServiceGrpc` — ReceiverService の blocking/async stub
- 全メッセージタイプ (`Chunk`, `FileStatusResponse`, etc.)

> **Note:** 初回実行時は Protobuf コンパイラと gRPC プラグインが自動的にダウンロードされます。

### Step 2: Run Application / アプリケーション起動

```bash
# Start Spring Boot application (port 8080)
./gradlew bootRun
```

起動ログに以下が表示されれば成功:

```
Initialising Misogi gRPC client → localhost:50051
Misogi gRPC client initialised successfully
Started MisogiJavaExampleApplication in X.XXX seconds
```

### Step 3: Test with curl / curl でテスト

#### Upload a file / ファイルアップロード

```bash
# Create a test file
echo "Hello Misogi CDR Engine!" > /tmp/testfile.txt

# Upload via REST endpoint (bridges to gRPC)
curl -X POST http://localhost:8080/api/demo/upload \
  -F "file=@/tmp/testfile.txt"
```

Response:

```json
{
  "fileId": "generated-file-1234567890",
  "status": "received",
  "originalFilename": "testfile.txt"
}
```

#### Check file status / ステータス確認

```bash
# Replace <FILE_ID> with the fileId from upload response
curl http://localhost:8080/api/demo/status/<FILE_ID>
```

#### List all files / ファイル一覧取得

```bash
curl http://localhost:8080/api/demo/files
```

#### Download a file / ファイルダウンロード

```bash
curl -O -J http://localhost:8080/api/demo/download/<FILE_ID>
```

#### Trigger transfer / 転送トリガー

```bash
curl -X POST http://localhost:8080/api/demo/transfer/<FILE_ID>
```

---

## ⚙️ Configuration / 設定

### application.yml / 設定ファイル

```yaml
misogi:
  grpc:
    host: localhost       # Misogi gRPC server hostname
    port: 50051           # Misogi gRPC server port
    tls:
      enabled: false      # Set true for TLS (mTLS)
  upload:
    chunk-size: 65536     # Streaming chunk size in bytes (64 KiB)

server:
  port: 8080              # REST API port
```

### Environment Variables / 環境変数

設定値は環境変数でも上書き可能:

```bash
export MISOGI_GRPC_HOST=192.168.1.100
export MISOGI_GRPC_PORT=50051
```

---

## 🔒 TLS Configuration / TLS 設定

本クライアントはデフォルトで平文 (plaintext) 接続を使用します。
本番環境では TLS を有効化することを強く推奨します。

### Enabling TLS / TLS 有効化手順

1. `application.yml` で `misogi.grpc.tls.enabled: true` を設定
2. `MisogiGrpcClient` のコンストラクタ引数に `ManagedChannelBuilder` を渡し、TLS 設定を行う:

```java
// Example: TLS-enabled channel creation
ManagedChannel channel = ManagedChannelBuilder.forAddress(host, port)
    .useTransportSecurity()
    .build();
var client = new MisogiGrpcClient(channel);
```

3. サーバー証明書の検証が必要な場合は `SslContext` をカスタマイズしてください

---

## 🏗 Architecture / アーキテクチャ

```
┌─────────────────────────────────────────────────────────────┐
│                    Web Frontend / Browser                   │
│                         (HTTP/REST)                          │
└─────────────────────────────┬───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              DemoController (:8080)                          │
│         ┌──────────┬──────────┬──────────┬──────────┐        │
│         │ /upload  │ /status  │/download │ /files   │        │
│         └────┬─────┴────┬─────┴────┬─────┴────┬─────┘        │
└──────────────┼──────────┼──────────┼──────────┘                │
               ▼          ▼          ▼                           │
┌─────────────────────────────────────────────────────────────┐
│            FileUploadService (@Service)                      │
│         ┌──────────────────────────────────┐                 │
│         │  @PostConstruct → init channel    │                 │
│         │  @PreDestroy  → shutdown channel  │                 │
│         └──────────────┬───────────────────┘                 │
└────────────────────────┼────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              MisogiGrpcClient                                │
│                                                              │
│  ┌──────────────────┐  ┌──────────────────┐                 │
│  │ SenderServiceStub │  │ReceiverServiceStub│                │
│  │  • upload()       │  │  • downloadFile() │                │
│  │  • getFileStatus()│  │  • listFiles()    │                │
│  │  • listFiles()    │  └──────────────────┘                 │
│  │  • triggerTransfer│                                       │
│  └────────┬──────────┘                                        │
└───────────┼──────────────────────────────────────────────────┘
            │ gRPC (protobuf over HTTP/2)
            ▼
┌─────────────────────────────────────────────────────────────┐
│              Misogi Rust Server (:50051)                     │
│         ┌────────────────────┬──────────────────┐            │
│         │   SenderService    │  ReceiverService  │            │
│         │   (Tonic/Rust)     │  (Tonic/Rust)     │            │
│         └────────────────────┴──────────────────┘            │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow / データフロー (Upload)

```
[HTTP MultipartFile] → [DemoController] → [temp file]
                                                │
                                     [FileUploadService]
                                                │
                                   [MisogiGrpcClient.uploadFile()]
                                                │
                                    ┌───────────┴───────────┐
                                    │ Read 64KB chunks      │
                                    │ MD5 each chunk        │
                                    │ Stream via gRPC       │
                                    └───────────┬───────────┘
                                                │
                              [SenderService.Upload (stream Chunk)]
                                                │
                                  [UploadResponse {file_id, status}]
```

---

## 🧪 Testing / テスト

### Unit Tests / 単体テスト

In-process gRPC サーバーを使用し、外部依存なしで動作します:

```bash
./gradlew test
```

テスト対象:
- アップロードフロー（ファイル存在確認、チャンク送信、レスポンス受信）
- ファイルステータス取得
- ファイル一覧取得
- ダウンロードフロー
- シャットダウンの冪等性
- エラーハンドリング（ファイル不存在など）

### Integration Tests / 統合テスト

統合テストには稼働中の Misogi サーバーが必要です:

```bash
# 1. Start Misogi server (from project root)
cargo run --release --bin misogi-server

# 2. Run this example
cd examples/java-spring-boot
./gradlew generateProto bootRun

# 3. Test with curl commands (see Quick Start section)
```

---

## 🔗 Related Links / 関連リンク

- [V1 Proto Definition](../../proto-dist/v1/misogi.proto) — gRPC サービス定義 (V1)
- [V2 Proto Definition](../../proto-dist/v2/misogi.proto) — gRPC サービス定義 (V2, 拡張)
- [Misogi Core](../../crates/misogi-core/) — Rust コアエンジン
- [Parent Index](../README.md) — 全サンプル一覧

---

## 📝 Key Classes / 主要クラス一覧

| Class | Role / 役割 |
|-------|-------------|
| [`MisogiJavaExampleApplication`](src/main/java/com/example/misogi/MisogiJavaExampleApplication.java) | Spring Boot エントリポイント |
| [`MisogiGrpcClient`](src/main/java/com/example/misogi/client/MisogiGrpcClient.java) | gRPC クライアントの核 (全 RPC 操作をカバー) |
| [`MisogiException`](src/main/java/com/example/misogi/client/MisogiException.java) | ドメイン例外 (record 型) |
| [`FileUploadService`](src/main/java/com/example/misogi/service/FileUploadService.java) | Spring @Service ラッパー (lifecycle 管理) |
| [`DemoController`](src/main/java/com/example/misogi/controller/DemoController.java) | REST→gRPC ブリッジコントローラー |
