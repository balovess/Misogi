# 📦 Proto Distribution / SDK Generator

## Protocol Buffer 配布用ディレクトリ

本ディレクトリは、Misogi gRPC サービスの **Protocol Buffer 定義ファイル (.proto)**
および**マルチ言語 SDK 自動生成**のための Buf 設定を集約します。

外部のクライアント実装（Java、Python、Go、TypeScript 等）は、
本ディレクトリから proto ファイルを参照し、各言語の gRPC スタブコードを生成します。

---

## 📁 Directory Structure

```
proto-dist/
├── README.md              ← 本ファイル
├── buf.yaml               ← Buf モジュール定義（breaking/lint ルール）
├── buf.gen.yaml           ← Buf コード生成設定（4 言語対応）
├── v1/
│   └── misogi.proto       ← V1 安定版 API 定義（現行 production）
└── v2/
    └── misogi.proto       ← V2 拡張 API 定義（将来向け、V1 を import）
```

生成結果は以下に出力されます：

```
gen/
├── java/                  ← gRPC-Java stubs (Maven 座標で利用可能)
├── python/                ← grpcio Python packages
├── go/                    ├── protoc-gen-go stubs (source_relative)
└── ts/                    ← TypeScript declarations + runtime
```

---

## 🔧 Prerequisites / 前提条件

### Option A: Buf CLI（推奨）

```bash
# Install Buf CLI (macOS/Linux)
brew install bufbuild/buf/buf

# Install Buf CLI (Windows via scoop)
scoop install buf

# Or download directly from https://buf.build/docs/installation
buf --version   # >= 1.40.0
```

### Option B: protoc 直接使用

```bash
protoc --version   # libprotoc 27+

# Additional language-specific plugins:
# Java:   built into protoc
# Python: pip install grpcio-tools
# Go:     go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
# TS:     npm install -g protoc-gen-ts
```

---

## 🚀 Generate SDK Stubs / SDK スタブ生成方法

### Using Buf CLI（推奨）

```bash
cd proto-dist

# Generate all language stubs at once
buf generate

# Verify generated output
ls gen/java/ gen/python/ gen/go/ gen/ts/
```

### Using protoc Directly（Buf 未導入の場合）

```bash
# Java
protoc \
  --proto_path=. \
  --java_out=gen/java \
  --grpc-java_out=gen/java \
  v1/misogi.proto

# Python
python -m grpc_tools.protoc \
  --proto_path=. \
  --python_out=gen/python \
  --grpc_python_out=gen/python \
  v1/misogi.proto

# Go
protoc \
  --proto_path=. \
  --go_out=gen/go --go_opt=paths=source_relative \
  --go-grpc_out=gen/go --go-grpc_opt=paths=source_relative \
  v1/misogi.proto

# TypeScript
protoc \
  --proto_path=. \
  --ts_out=gen/ts \
  v1/misogi.proto
```

---

## 📋 Generated SDK Usage / 生成 SDK の使い方

### Java (Spring Boot)

`gen/java/` の出力を Maven プロジェクトに配置し、gRPC-Java スタブとして参照。

```xml
<!-- In your pom.xml, reference generated sources -->
<sourceDirectory>../proto-dist/gen/java</sourceDirectory>
```

### Python

```bash
cp -r gen/python/* your_project/proto/
# Then in Python code:
from misogi.file_transfer.v1 import misogi_pb2, misogi_pb2_grpc
```

### Go

```bash
cp -r gen/go/* your_project/proto/
// In Go code:
import "your_module/proto/v1"
```

### TypeScript / JavaScript

```bash
cp -r gen/ts/* your_frontend/src/proto/
// Import in TSX/TS files:
import { SenderServiceClient } from "./proto/MisogiServiceClientPb";
```

---

## ⚠️ Important Notes / 重要事項

### V1 vs V2 Compatibility

| Version | Status | When to Use |
|---------|--------|-------------|
| **v1/** | ✅ Stable (Production) | All current client implementations |
| **v2/** | 🚧 Skeleton (Future) | AI-enhanced features (2025-Q3+) |

- V2 proto は V1 を `import` しているため、**必ず両方とも配布に含める**必要があります。
- クライアント実装では原則として **V1 のみ**を使用してください。

### Breaking Change Policy

`buf.yaml` にて `breaking.use: FILE` を指定済みです。
Buf CLI の `buf breaking` コマンドにより、後方互換性違反を自動検出できます：

```bash
# Check compatibility against the last pushed version
buf breaking --against '.git#branch=main'
```

---

## 🔗 Related Links / 関連リンク

- [Buf Docs](https://buf.build/docs/) — Buf CLI 公式ドキュメント
- [Protocol Buffers Docs](https://protobuf.dev/) — Google Protobuf 公式
- [Misogi Core](../crates/misogi-core/) — Rust コアエンジン（proto 定義元）
- [Examples Index](../examples/) — 各言語サンプル一覧
