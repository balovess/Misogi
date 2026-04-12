# 🐍 Python Async gRPC Client

## Python asyncio ベースの非同期 Misogi gRPC クライアント

本プロジェクトは、Python エコシステムから Misogi CDR エンジンを操作するための
**本格的な非同期（asyncio）gRPC クライアント**実装です。

`grpc.aio` ネイティブ非同期チャネルを使用し、高スループットなストリーミング転送、
進捗表示、および型安全な API を提供します。

---

## 📋 Overview / 概要

| Item | Detail |
|------|--------|
| **Language** | Python 3.11+ |
| **Async Runtime** | asyncio (native `grpc.aio`) |
| **gRPC Library** | grpcio ≥ 1.60.0 / grpcio-tools |
| **Terminal UI** | Rich 13+ (progress bars, tables, panels) |
| **Protocol** | `misogi.file_transfer.v1` SenderService / ReceiverService |
| **Package** | `misogi-client` v0.1.0 |

### Target Use Cases / 対象ユースケース

- データパイプライン自動化（**Airflow** / **Dagster** 連携）
- バッチ処理スクリプトからのファイルサニタイズ
- Jupyter Notebook / IPython での対話的操作
- CI/CD パイプラインへの組み込み
- 監視・運用自動化ツール

---

## 🔧 Prerequisites / 前提条件

```bash
# Required — Python version check
python --version          # >= 3.11

# Optional: generate proto stubs from source (if not pre-generated)
protoc --version          # libprotoc 27+
```

---

## 🚀 Quick Start / クイックスタート

### Step 1 — Install Dependencies / 依存関係のインストール

```bash
cd examples/python-client
pip install -r requirements.txt
```

Or with **uv** (recommended for speed):

```bash
uv pip install -r requirements.txt
```

### Step 2 — Generate gRPC Stubs / スタブの生成

> ⚠️ Proto ファイルから Python スタブを生成する必要があります。
> 一度生成すれば以降は不要です。

**Linux / macOS:**

```bash
bash generate_stubs.sh
```

**Windows (PowerShell):**

```powershell
.\generate_stubs.bat
```

Expected output:

```
==> Misogi Python gRPC Stub Generator
    Proto source : ../../proto-dist/v1/misogi.proto
    Output target: src/misogi_client/pb2/

[OK] Stubs generated successfully in src/misogi_client/pb2/
     - misogi_pb2.py          (message types)
     - misogi_pb2_grpc.py     (service stubs)
```

### Step 3 — Run CLI / CLI 実行

```bash
# Basic usage — sanitize a single file
python -m misogi_client.cli document.pdf

# With options
python -m misogi_client.cli report.docx \
    --policy TEXT \
    --output ./sanitized_report.txt \
    --host 192.168.1.100 \
    --port 50051 \
    --verbose
```

Or after installing as a package:

```bash
pip install -e .
misogi-sanitize document.pdf --policy STRIP
```

---

## 📁 Directory Structure / ディレクトリ構成

```
python-client/
├── README.md                          ← 本ファイル
├── requirements.txt                   ← pip 依存関係
├── pyproject.toml                     ← プロジェクト設定 + メタデータ
├── generate_stubs.sh                  ← スタブ生成スクリプト (Unix)
├── generate_stubs.bat                 ← スタブ生成スクリプト (Windows)
└── src/
    └── misogi_client/
        ├── __init__.py                ← パッケージ公開 API
        ├── client.py                  ← コア非同期 gRPC クライアント
        ├── models.py                  ← データモデル・例外クラス
        ├── cli.py                     ← コマンドラインインターフェース
        └── pb2/                       ← 生成された gRPC スタブ (git 管理外推奨)
            ├── __init__.py
            ├── misogi_pb2.py          ← (generate_stubs.sh で生成)
            └── misogi_pb2_grpc.py     ← (generate_stubs.sh で生成)
└── tests/
    ├── __init__.py
    └── test_client.py                 ← 単体テスト
```

---

## 📡 Library Usage / ライブラリとしての使用方法

### Basic One-Shot Sanitization / 基本的な一括サニタイズ

```python
"""Sanitize a file in one line using the convenience method."""

import asyncio
from pathlib import Path
from misogi_client import MisogiAsyncClient, SanitizationPolicy


async def main() -> None:
    async with MisogiAsyncClient("localhost", 50051) as client:
        result = await client.sanitize_file(
            input_path="suspicious.pdf",
            output_path="clean.pdf",
            policy=SanitizationPolicy.STRIP_ACTIVE_CONTENT,
        )
        if result.success:
            print(f"✓ Sanitized: {result.download_metadata.bytes_written} bytes")
        else:
            print(f"✗ Failed: {result.upload_status.status}")


asyncio.run(main())
```

### Granular Control / 詳細制御（アップロード→ポーリング→ダウンロード）

```python
"""Full manual control over each phase of the sanitization workflow."""

import asyncio
from misogi_client import MisogiAsyncClient, SanitizationPolicy


async def granular_workflow(file_path: str) -> None:
    async with MisogiAsyncClient("localhost", 50051) as client:
        # Phase 1: Upload with progress callback
        def on_progress(sent: int, total: int) -> None:
            pct = sent / total * 100
            print(f"  Upload: {pct:.1f}% ({sent:,}/{total:,} bytes)")

        status = await client.upload_file(
            file_path=file_path,
            policy=SanitizationPolicy.CONVERT_TO_FLAT,
            chunk_size=128 * 1024,
            progress_callback=on_progress,
        )
        print(f"Uploaded → transfer_id={status.transfer_id}")

        # Phase 2: Poll until sanitized
        while True:
            current = await client.get_file_status(status.transfer_id)
            print(f"  Status: {current.status} ({current.progress_pct:.0f}%)")
            if current.is_complete:
                break
            await asyncio.sleep(1)

        # Phase 3: Download result
        meta = await client.download_file(
            transfer_id=status.transfer_id,
            output_path="output_sanitized.pdf",
        )
        print(f"Downloaded → {meta.output_path} ({meta.bytes_written} bytes)")


asyncio.run(granular_workflow("document.pdf"))
```

### List Files / ファイル一覧取得

```python
import asyncio
from misogi_client import MisogiAsyncClient


async def list_all_files() -> None:
    async with MisogiAsyncClient() as client:
        files = await client.list_files(page=1, per_page=20)
        for f in files:
            print(f"{f.file_id}: {f.filename} ({f.size_bytes:,} bytes) [{f.status}]")


asyncio.run(list_all_files())
```

---

## 🔗 Airflow / Dagster Integration / ワークフロー統合

### Apache Airflow Operator / オペレーター

```python
"""MisogiSanitizeOperator — Airflow custom operator for file sanitization."""

from airflow.models.baseoperator import BaseOperator
from misogi_client import MisogiAsyncClient, SanitizationPolicy


class MisogiSanitizeOperator(BaseOperator):
    """Sanitizes a file through Misogi CDR engine via gRPC."""

    template_fields = ["input_path", "output_path"]

    def __init__(
        self,
        input_path: str,
        output_path: str,
        host: str = "localhost",
        port: int = 50051,
        policy: str = "STRIP_ACTIVE_CONTENT",
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.input_path = input_path
        self.output_path = output_path
        self.host = host
        self.port = port
        self.policy = SanitizationPolicy(policy)

    def execute(self, context) -> str:
        import asyncio

        async def _run() -> str:
            async with MisogiAsyncClient(self.host, self.port) as client:
                result = await client.sanitize_file(
                    self.input_path,
                    self.output_path,
                    self.policy,
                )
                if not result.success:
                    raise RuntimeError(f"Sanitization failed: {result}")
                return result.download_metadata.transfer_id

        return asyncio.run(_run())


# Usage in DAG:
# sanitize = MisogiSanitizeOperator(
#     task_id="sanitize_document",
#     input_path="{{ ti.xcom_pull(task_ids='extract') }}",
#     output_path="/data/sanitized/{{ ds }}/report.pdf",
#     dag=dag,
# )
```

### Dagster Asset / アセット

```python
"""Misogi sanitization as a Dagster solid/op asset."""

import dagster as dg
from misogi_client import MisogiAsyncClient, SanitizationPolicy


@dg.asset
def sanitized_document(context: dg.AssetExecutionContext) -> str:
    """Sanitize an uploaded document via Misogi CDR."""
    import asyncio

    async def _sanitize() -> str:
        async with MisogiAsyncClient() as client:
            result = await client.sanitize_file(
                "/data/uploads/raw/document.pdf",
                "/data/clean/sanitized_document.pdf",
                SanitizationPolicy.TEXT_ONLY,
            )
            return str(result.download_metadata.output_path)

    return asyncio.run(_sanitize())
```

---

## 🛠️ CLI Reference / CLI リファレンス

```
Usage: python -m misogi_client.cli <file_path> [OPTIONS]

Arguments:
  file_path                    Path to the file to sanitize

Options:
  --policy STRIP|FLAT|TEXT     Sanitization policy (default: STRIP)
  --output PATH                Output file path (default: sanitized_<original>)
  --host HOST                  Misogi sender gRPC host (default: localhost)
  --port PORT                  Misogi sender gRPC port (default: 50051)
  --receiver-port PORT         Misogi receiver gRPC port (default: sender_port+1)
  --chunk-size SIZE            Upload chunk size in bytes (default: 65536)
  --verbose                    Show detailed progress and debug info
  --no-color                   Disable colored terminal output
  --version                    Show version and exit
  -h, --help                   Show help message and exit
```

### Exit Codes / 終了コード

| Code | Meaning |
|------|---------|
| `0` | Success — file sanitized cleanly |
| `1` | Sanitization error — server-side failure or threats found |
| `2` | Connection error — cannot reach Misogi services |
| `130` | Interrupted by user (Ctrl+C) |

### Policy Options / ポリシー選択肢

| Flag | Enum Value | Description |
|------|-----------|-------------|
| `STRIP` | `STRIP_ACTIVE_CONTENT` | マクロ・スクリプト・埋め込みオブジェクトを除去（デフォルト） |
| `FLAT` | `CONVERT_TO_FLAT` | 入れ構造をフラット化（隠しデータ排除） |
| `TEXT` | `TEXT_ONLY` | テキストのみ抽出（最も攻撃的なサニタイズ） |

---

## ⚠️ Error Handling / エラーハンドリング

### Exception Hierarchy / 例外階層

```
MisogiError (base)
├── MisogiConnectionError   — gRPC チャネル接続失敗
│   .host, .port
├── MisogiSanitizationError — サーバー側処理エラー
│   .transfer_id, .code
└── MisogiDownloadError     — ダウンロード中断
      .transfer_id, .bytes_received
```

### Recommended Pattern / 推奨パターン

```python
import asyncio
from misogi_client import (
    MisogiAsyncClient,
    MisogiConnectionError,
    MisogiSanitizationError,
    MisogiDownloadError,
)


async def safe_sanitize(path: str) -> None:
    try:
        async with MisogiAsyncClient("misogi.internal", 50051) as client:
            result = await client.sanitize_file(path)
            print(f"OK: {result.download_metadata.output_path}")

    except MisogiConnectionError as e:
        print(f"Cannot reach server at {e.host}:{e.port}: {e}")
        # Retry logic, fallback, or alert here

    except MisogiSanitizationError as e:
        print(f"Server rejected file [id={e.transfer_id}, code={e.code}]: {e}")
        # Log for audit, notify security team

    except MisogiDownloadError as e:
        print(f"Download failed after {e.bytes_received} bytes: {e}")
        # Partial download cleanup, retry from offset


asyncio.run(safe_sanitize("upload.xlsx"))
```

---

## 🧪 Testing / テスト

```bash
# Install test dependencies
pip install pytest pytest-asyncio mypy ruff

# Run unit tests (no server required)
pytest tests/test_client.py -v

# Type checking
mypy src/misogi_client/

# Linting
ruff check src/misogi_client/
```

> **Note:** Unit tests mock gRPC channels and do not require a running
> Misogi server. Integration tests against live services are planned
> for future releases.

---

## 📄 License / ライセンス

本サンプルコードのライセンスは親プロジェクト（[LICENSE](../../LICENSE)）に準拠します。
生成された gRPC スタブコード（`pb2/` 内）は Apache 2.0 ライセンスに従います。

---

## 🔗 Related Links / 関連リンク

| Resource | Path |
|----------|------|
| **Proto Definition (V1)** | [`../../proto-dist/v1/misogi.proto`](../../proto-dist/v1/misogi.proto) |
| **Proto Definition (V2)** | [`../../proto-dist/v2/misogi.proto`](../../proto-dist/v2/misogi.proto) |
| **Misogi Core Engine** | [`../../crates/misogi-core/`](../../crates/misogi-core/) |
| **Sender Service** | [`../../crates/misogi-sender/`](../../crates/misogi-sender/) |
| **Receiver Service** | [`../../crates/misogi-receiver/`](../../crates/misogi-receiver/) |
| **Parent Index** | [`../README.md`](../README.md) |
