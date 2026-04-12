# CLI コマンドリファレンス (CLI Command Reference)

Misogi のコマンドラインインターフェース（CLI）の完全リファレンスです。
全サブコマンド、オプション、使用例、終了コードを網羅的に解説します。

**対象読者**: 運用担当者、自動化スクリプト作成者、SIer エンジニア  
**確認バージョン**: Misogi v0.1.0

---

## 1. CLI の概要

### 1-1. 実行ファイル

| ノード | 実行ファイル | 説明 |
|-------|-----------|------|
| Sender | `misogi-sender.exe` | 送信側 CLI |
| Receiver | `misogi-receiver.exe` | 受信側 CLI |

### 1-2: 共通オプション

全サブコマンドで使用できる共通オプションです。

| オプション | 短縮形 | 引数 | 必須 | デフォルト | 説明 |
|----------|--------|------|------|----------|------|
| `--config` | `-c` | ファイルパス | ✅ | — | 設定ファイル（`.toml`）のパス |
| `--help` | `-h` | なし | — | — | ヘルプメッセージ表示 |
| `--version` | `-V` | なし | — | — | バージョン情報表示 |
| `--verbose` | なし | なし | — | `false` | 冗長出力モード |
| `--log-level` | なし | LEVEL | — | `info` | ログレベル上書き (`trace/debug/info/warn/error`) |
| `--no-color` | なし | なし | — | `false` | カラー出力の無効化 |

### 1-3: ヘルプの参照方法

```bash
# トップレベルヘルプ
misogi-sender --help

# サブコマンドのヘルプ
misogi-sender server --help
misogi-sender upload --help
misogi-sender watch --help

# バージョン確認
misogi-sender --version
```

---

## 2. misogi-sender コマンド

### 2-1: server — サーバーモード

HTTP API サーバーおよび gRPC クライアントとして起動し、
常時ファイルアップロードを受け付けます。

```bash
misogi-sender server [OPTIONS]
```

| オプション | 引数 | デフォルト | 説明 |
|----------|------|----------|------|
| `--config`, `-c` | PATH | — | 設定ファイルパス（必須）|
| `--addr` | ADDR | 設定ファイル値 | HTTP リッスンアドレス（設定ファイル上書き）|
| `--log-level` | LEVEL | 設定ファイル値 | ログレベル |

**使用例**:

```bash
# 基本起動
misogi-sender server --config ./misogi-sender.toml

# アドレスを上書きして起動
misogi-sender server --config ./misogi-sender.toml --addr 0.0.0.0:3000

# デバッグモード
misogi-sender server --config ./misogi-sender.toml --log-level debug
```

**期待される出力**:
```
  _ __  _ __ _____      _____  ___ _ ____   _____ _ __
 | '_ \| '__/ _ \ \ /\ / / __|/ _ \ '__\ \ / / _ \ '_ \
 | |_) | | | (_) \ V  V /\__ \  __/ |   \ V /  __/ | | |
 | .__/|_|  \___/ \_/\_/ |___/\___|_|    \_/ \___|_| |_|
 |_|              CDR Secure File Transfer System

[INFO] Starting Misogi Sender...
[INFO] Loading configuration from ./misogi-sender.toml
[INFO] HTTP server listening on 0.0.0.0:3000
[INFO] Misogi Sender is ready. Press Ctrl+C to stop.
```

**終了コード**:

| コード | 意味 |
|-------|------|
| 0 | 正常終了（Ctrl+C などで停止）|
| 1 | 設定エラー |
| 2 | ポートバインド失敗 |
| 3 | CDR エンジン初期化失敗 |

---

### 2-2: daemon — デーモンモード

バックグラウンドプロセスとして起動します。Windows ではサービス登録、
Linux では fork/exec によって実装されます。

```bash
misogi-sender daemon [OPTIONS]
```

| オプション | 引数 | デフォルト | 説明 |
|----------|------|----------|------|
| `--config`, `-c` | PATH | — | 設定ファイルパス（必須）|
| `--pid-file` | PATH | `./misogi-sender.pid` | PID ファイルの出力パス |
| `--log-file` | PATH | `./logs/sender.log` | ログファイルの出力パス |

**使用例**:

```bash
# デーモン起動
misogi-sender daemon --config ./misogi-sender.toml

# PID ファイル指定
misogi-sender daemon --config ./misogi-sender.toml --pid-file /var/run/misogi-sender.pid

# デーモン停止
kill $(cat ./misogi-sender.pid)
# Windows の場合:
# taskkill /PID $(Get-Content .\misogi-sender.pid) /F
```

**終了コード**:

| コード | 意味 |
|-------|------|
| 0 | デーモン起動成功（プロセスはバックグラウンドで継続）|
| 1 | 設定エラー |
| 2 | デーモン化失敗 |

---

### 2-3: upload — ファイルアップロード

単一ファイルを Sender にアップロードし、CDR 処理 → 転送を実行します。

```bash
misogi-sender upload [OPTIONS] <FILE>
```

| オプション | 引数 | デフォルト | 説明 |
|----------|------|----------|------|
| `--config`, `-c` | PATH | — | 設定ファイルパス（必須）|
| `--convert-jtd-to-pdf` | なし | `false` | JTD ファイルを PDF に変換 |
| `--output-dir` | DIR | `./` | 処理結果の出力先ディレクトリ |
| `--dry-run` | なし | `false` | ドライランモード（実際には転送しない）|
| `--verbose` / `-v` | なし | `false` | 詳細出力 |
| `<FILE>` | — | — | アップロードするファイルパス（位置引数）|

**使用例**:

```bash
# 基本的なファイルアップロード
misogi-sender upload --config ./misogi-sender.toml report.pdf

# JTD ファイルを PDF に変換してアップロード
misogi-sender upload --config ./misogi-sender.toml --convert-jtd-to-pdf report.jtd

# ドライラン（処理内容を確認のみ）
misogi-sender upload --config ./misogi-sender.toml --dry-run confidential.docx

# 詳細出力付き
misogi-sender upload -c ./misogi-sender.toml -v data.zip
```

**期待される出力（正常時）**:
```
[INFO] Uploading: report.pdf (2,048,576 bytes)
[INFO] Upload complete: file_id=a1b2c3d4-e5f6-7890-abcd-ef1234567890
[INFO] CDR sanitization: PdfStreamParser → clean
[INFO] PII scan: no PII found (2,048,576 bytes in 45ms)
[INFO] Transfer initiated via gRPC
[INFO] Transfer completed successfully (5,678ms)
[OK] File processed: report.pdf → receiver
```

**期待される出力（PII 検出時）**:
```
[INFO] Uploading: report.pdf
[INFO] Upload complete: file_id=b2c3d4e5-f6a7-8901-bcde-f12345678901
[INFO] CDR sanitization: clean
[WARN] PII detected: my_number (masked: 1**********2)
[INFO] Action taken: mask
[INFO] Transfer completed with masking applied
[OK] File processed (with PII masking): report.pdf
```

**`--convert-jtd-to-pdf` オプションの詳細**:

このオプションは、一太郎 (.jtd) ファイルをアップロードする前に
PDF に変換することを指示します。

| 項目 | 説明 |
|------|------|
| 動作 | LibreOffice (または一太郎ビューア) を呼び出し `.jtd` → `.pdf` 変換 |
| 出力 | 元の `.jtd` ファイル名 + `.pdf` 拡張子（例: `report.jtd` → `report.jtd.pdf`）|
| 事前条件 | LibreOffice がインストールされ、`[jtd_converter].enabled = true` |
| 失敗時 | エラーコード 22 (JTD conversion error) で終了 |

**終了コード**:

| コード | 意味 |
|-------|------|
| 0 | 正常終了（処理・転送完了）|
| 1 | 設定エラー |
| 10 | ファイルが見つかりません |
| 11 | アップロード失敗（ネットワークエラー等）|
| 20 | CDR 処理失敗 |
| 21 | 未サポートのファイル形式 |
| 22 | JTD 変換失敗 |
| 30 | PII ブロック（ファイル拒否）|
| 40 | 転送失敗 |

---

### 2-4: watch — ファイル監視モード

指定ディレクトリを監視し、新規ファイルを自動的にアップロード・処理します。
Windows タスクスケジューラとの併用を想定しています。

```bash
misogi-sender watch [OPTIONS]
```

| オプション | 引数 | デフォルト | 説明 |
|----------|------|----------|------|
| `--config`, `-c` | PATH | — | 設定ファイルパス（必須）|
| `--dir`, `-d` | DIR | `./inbound` | 監視対象ディレクトリ |
| `--convert-jtd-to-pdf` | なし | `false` | JTD → PDF 自動変換 |
| `--once` | なし | `false` | 1 回だけ処理して終了（タスクスケジューラ向け）|
| `--poll-interval` | SECONDS | `5` | ポーリング間隔（秒）|
| `--recursive` / `-r` | なし | `false` | サブディレクトリも再帰的に監視 |
| `--archive-dir` | DIR | — | 処理完了ファイルの移動先（省略時は削除）|

**使用例**:

```bash
# ディレクトリ監視（常駐）
misogi-sender watch --config ./misogi-sender.toml --dir C:\Misogi\Inbound

# JTD 自動変換付き監視
misogi-sender watch -c ./misogi-sender.toml -d ./inbox --convert-jtd-to-pdf

# 1回実行（タスクスケジューラ向け）
misogi-sender watch -c ./misogi-sender.toml -d ./inbox --once

# 再帰的監視 + アーカイブ
misogi-sender watch -c ./misogi-sender.toml -d ./inbox -r --archive-dir ./processed
```

**期待される出力**:
```
[INFO] Watching directory: C:\Misogi\Inbound
[INFO] Poll interval: 5 seconds
[INFO] JTD conversion: enabled
[INFO] Waiting for files...

[INFO] New file detected: report_2024Q1.jtd
[INFO] Converting JTD to PDF: report_2024Q1.jtd → report_2024Q1.jtd.pdf
[INFO] Uploading: report_2024Q1.jtd.pdf
[INFO] CDR: clean, PII: none found
[INFO] Transfer: success
[INFO] Archived: ./processed/report_2024Q1.jtd.pdf

[INFO] Waiting for files...
```

**終了コード**:

| コード | 意味 |
|-------|------|
| 0 | 正常終了（`--once` 時）または中断（常駐時 Ctrl+C）|
| 1 | 設定エラー |
| 2 | 監視ディレクトリが存在しない |
| 20+ | 個別ファイル処理エラー（upload と同じコード体系）|

---

### 2-5: status — ステータス確認

Sender および Receiver の稼働状況を確認します。

```bash
misogi-sender status [OPTIONS]
```

| オプション | 引数 | デフォルト | 説明 |
|----------|------|----------|------|
| `--config`, `-c` | PATH | — | 設定ファイルパス |
| `--receiver-url` | URL | 設定ファイル値 | Receiver のヘルスチェック URL |

**使用例**:
```bash
misogi-sender status --config ./misogi-sender.toml
```

**期待される出力**:
```
=== Misogi System Status ===

Sender (local):
  Status:    ● healthy
  Version:   0.1.0
  Uptime:    2 days, 14 hours, 32 minutes
  HTTP API:  http://0.0.0.0:3000 ✓ listening
  gRPC:      connected to receiver at 192.168.1.200:50051

Components:
  CDR Engine:    ● operational (sanitizers: pdf, ooxml, zip, svg)
  PII Detector:  ● operational (rules: 7)
  JTD Converter: ● operational (type: libreoffice)
  Audit Log:     ● operational (format: json)

Receiver (remote):
  Status:    ● healthy
  Version:   0.1.0
  HTTP API:  http://192.168.1.200:3001 ✓ reachable
  Storage:   15.2 GB free (72% available)

Transfer Stats (last 24h):
  Files processed:  1,245
  Total volume:     2.8 GB
  Success rate:     99.84%
  PII detections:   12
  Errors:           2
```

---

## 3. misogi-receiver コマンド

### 3-1: server — サーバーモード

Receiver を gRPC サーバーおよび HTTP ダウンロードサーバーとして起動します。

```bash
misogi-receiver server [OPTIONS]
```

| オプション | 引数 | デフォルト | 説明 |
|----------|------|----------|------|
| `--config`, `-c` | PATH | — | 設定ファイルパス（必須）|
| `--addr` | ADDR | 設定ファイル値 | HTTP ダウンロード API アドレス |
| `--tunnel-port` | PORT | 設定ファイル値 | gRPC トンネルポート |
| `--log-level` | LEVEL | 設定ファイル値 | ログレベル |

**使用例**:

```bash
# 基本起動
misogi-receiver server --config ./misogi-receiver.toml

# ポート指定
misogi-receiver server --config ./misogi-receiver.toml --addr 0.0.0.0:3001 --tunnel-port 50051
```

**期待される出力**:
```
  _ __  _ __ _____      _____  ___ _ ____   _____ _ __
 | '_ \| '__/ _ \ \ /\ / / __|/ _ \ '__\ \ / / _ \ '_ \
 | |_) | | | (_) \ V  V /\__ \  __/ |   \ V /  __/ | | |
 | .__/|_|  \___/ \_/\_/ |___/\___|_|    \_/ \___|_| |_|
 |_|              CDR Secure File Transfer System

[INFO] Starting Misogi Receiver...
[INFO] Loading configuration from ./misogi-receiver.toml
[INFO] HTTP download server on 0.0.0.0:3001
[INFO] gRPC tunnel on 0.0.0.0:50051
[INFO] Misogi Receiver is ready. Press Ctrl+C to stop.
```

**終了コード**: sender と同じ (0/1/2/3)

### 3-2: daemon — デーモンモード

sender の daemon と同じインターフェースです。

```bash
misogi-receiver daemon --config ./misogi-receiver.toml [--pid-file PATH] [--log-file PATH]
```

### 3-3: download — ファイルダウンロード

Receiver から処理済みファイルをダウンロードします。

```bash
misogi-receiver download [OPTIONS] <FILE_ID>
```

| オプション | 引数 | デフォルト | 説明 |
|----------|------|----------|------|
| `--config`, `-c` | PATH | — | 設定ファイルパス（必須）|
| `--receiver-url` | URL | 設定ファイル値 | Receiver URL |
| `--output`, `-o` | FILE | 元ファイル名 | 出力ファイル名 |
| `<FILE_ID>` | — | — | ダウンロードするファイル ID |

**使用例**:
```bash
# ファイル ID でダウンロード
misogi-receiver download --config ./misogi-receiver.toml a1b2c3d4-e5f6-7890-abcd-ef1234567890

# 出力ファイル名指定
misogi-receiver download -c ./misogi-receiver.toml -o saved_report.pdf a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

### 3-4: list — 処理済みファイル一覧

Receiver 上の処理済みファイルを一覧表示します。

```bash
misogi-receiver list [OPTIONS]
```

| オプション | 引数 | デフォルト | 説明 |
|----------|------|----------|------|
| `--config`, `-c` | PATH | — | 設定ファイルパス |
| `--limit` | N | `20` | 表示件数 |
| `--format` | FMT | `table` | 出力形式: `table`, `json`, `csv` |

**使用例**:
```bash
# 最新 20 件を表示
misogi-receiver list --config ./misogi-receiver.toml

# JSON 形式（自動化スクリプト向け）
misogi-receiver list -c ./misogi-receiver.toml --format json --limit 100

# CSV 出力（Excel で開ける）
misogi-receiver list -c ./misogi-receiver.toml --format csv > files.csv
```

**期待される出力 (table)**:
```
 ID                                   | Filename             | Size    | Status  | Processed At
--------------------------------------|----------------------|---------|---------|-------------
 a1b2c3d4...                          | report_2024Q1.pdf    | 2.0 MB  | success | 2024-01-15 09:23
 b2c3d4e5...                          | budget.xlsx          | 512 KB  | success | 2024-01-15 09:25
 c3d4e5f6...                          | memo.jtd             | 1.5 MB  | masked  | 2024-01-15 09:30
```

---

## 4. よく使うコマンド組み合わせ

### 4-1: バッチファイル処理（for ループ）

```powershell
# ディレクトリ内の全ファイルを一括アップロード
Get-ChildItem "C:\Documents\ToTransfer" -File | ForEach-Object {
    Write-Host "Processing: $($_.Name)"
    .\target\release\misogi-sender.exe upload `
        --config .\misogi-sender.toml `
        --convert-jtd-to-pdf `
        $_.FullName
}
```

### 4-2: JTD ファイルの一括 PDF 変換

```powershell
# Inbound 内の全 .jtd ファイルを PDF に変換してアップロード
Get-ChildItem "C:\Misogi\Inbound\*.jtd" | ForEach-Object {
    .\target\release\misogi-sender.exe upload `
        -c .\misogi-sender.toml `
        --convert-jtd-to-pdf `
        $_.FullName
}
```

### 4-3: 定期ヘルスチェック（スケジュールタスク）

```powershell
# ヘルスチェック結果をメール通知
$result = .\target\release\misogi-sender.exe status -c .\misogi-sender.toml
if ($LASTEXITCODE -ne 0) {
    Send-MailMessage -From "misogi@company.co.jp" `
        -To "admin@company.co.jp" `
        -Subject "Misogi Health Check FAILED" `
        -Body $result `
        -SmtpServer smtp.company.co.jp
}
```

---

## 5. 終了コード一覧

| コード | 名称 | 発生コマンド | 対応 |
|-------|------|------------|------|
| **0** | SUCCESS | 全コマンド | 正常終了 |
| **1** | CONFIG_ERROR | 全コマンド | 設定ファイルエラー |
| **2** | BIND_ERROR | server/daemon | ポートバインド失敗 |
| **3** | INIT_ERROR | server/daemon | コンポーネント初期化失敗 |
| **10** | FILE_NOT_FOUND | upload | アップロード対象ファイル不存在 |
| **11** | UPLOAD_FAILED | upload | アップロード通信エラー |
| **20** | CDR_FAILURE | upload/watch | CDR 無害化処理失敗 |
| **21** | UNSUPPORTED_FORMAT | upload/watch | 未対応ファイル形式 |
| **22** | JTD_CONVERSION_ERROR | upload/watch | JTD→PDF 変換失敗 |
| **30** | PII_BLOCKED | upload/watch | PII によりブロック |
| **40** | TRANSFER_FAILED | upload/watch | Receiver への転送失敗 |
| **99** | UNKNOWN | 全コマンド | 未知のエラー |

---

*関連ドキュメント: [基本設定ガイド](../configuration/basic-config.md) | [トラブルシューティング FAQ](../operation/troubleshooting.md)*
