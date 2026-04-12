# 基本設定ガイド (Basic Configuration Guide)

Misogi の設定ファイル `misogi.toml` の全フィールドを日本語で詳しく解説します。
各設定項目には、コピー＆ペーストで使用できる設定例を含めています。

**対象読者**: SIer 設計担当者、システム管理者  
**前提条件**: Misogi のインストールが完了していること

---

## 1. 設定ファイルの概要

### 1-1. ファイルの場所

| ノード | デフォルト設定ファイル名 | 説明 |
|-------|----------------------|------|
| Sender | `misogi-sender.toml` | 送信側ノードの設定 |
| Receiver | `misogi-receiver.toml` | 受信側ノードの設定 |

### 1-2. 設定ファイルの指定方法

```bash
# コマンドライン引数で明示的に指定
misogi-sender server --config /path/to/misogi-sender.toml
misogi-receiver server --config /path/to/misogi-receiver.toml
```

### 1-3. 設定形式

設定ファイルは **TOML (Tom's Obvious Minimal Language)** 形式です。
コメントは `#` で始めます。文字列はダブルクォーテーションで囲みます。

---

## 2. Sender 設定ファイル完全リファレンス

### 2-1. `[server]` セクション — サーバー基本設定

```toml
[server]
addr = "0.0.0.0:3000"
storage_dir = "./storage/sender"
chunk_size = 1048576
log_level = "info"
```

| フィールド | 型 | デフォルト値 | 必須 | 説明 |
|----------|-----|-----------|------|------|
| `addr` | String | `"127.0.0.1:3000"` | ✅ | HTTP API のリッスンアドレス。`0.0.0.0` ですべてのインターフェースにバインド |
| `storage_dir` | String | `"./storage"` | ✅ | アップロードされたファイルおよびチャンクの一時保存ディレクトリ |
| `chunk_size` | Integer | `1048576` (1MB) | △ | ファイル転送時のチャンクサイズ（バイト単位）。大きいほどスループット向上だがメモリ消費増加 |
| `log_level` | String | `"info"` | △ | ログレベル: `trace`, `debug`, `info`, `warn`, `error` |

**`addr` の設定例**:

```toml
# すべてのネットワークインターフェースで待ち受け（DMZ 配置時）
addr = "0.0.0.0:3000"

# ローカルホストのみ（開発・テスト環境）
addr = "127.0.0.1:3000"

# 特定の IP アドレスにバインド（マルチホーム環境）
addr = "192.168.1.100:3000"
```

**`chunk_size` の推奨値**:

| 環境 | 推奨値 | 理由 |
|------|--------|------|
| 低速回線 (10Mbps) | 262144 (256KB) | 再送時の影響を最小化 |
| 一般的企業 LAN | 1048576 (1MB) | バランス重視（デフォルト） |
| 高速 LAN (1Gbps+) | 4194304 (4MB) | スループット最大化 |
| 大容量ファイル (>100MB) | 8388608 (8MB) | 転送効率優先 |

### 2-2. `[receiver]` セクション — 受信者接続設定

```toml
[receiver]
addr = "127.0.0.1:50051"
```

| フィールド | 型 | デフォルト値 | 必須 | 説明 |
|----------|-----|-----------|------|------|
| `addr` | String | `"127.0.0.1:50051"` | ✅ | Receiver ノードの gRPC エンドポイントアドレス |

> **重要**: Sender から Receiver への gRPC 通信に使用されます。
> ファイアウォールでこのアドレスへの通信が許可されている必要があります。

### 2-3. `[cdr]` セクション — CDR エンジン設定

```toml
[cdr]
enabled = true
sanitizers = ["pdf", "ooxml", "zip", "svg"]
```

| フィールド | 型 | デフォルト値 | 必須 | 説明 |
|----------|-----|-----------|------|------|
| `enabled` | Boolean | `true` | △ | CDR エンジンの有効/無効。無効の場合、ファイルは無害化されずそのまま転送される |
| `sanitizers` | Array[String] | `["pdf","ooxml","zip"]` | △ | 有効にするサニタイザーリスト |

**利用可能なサニタイザー**:

| 名前 | 対応フォーマット | パーサー | 説明 |
|------|---------------|---------|------|
| `"pdf"` | `.pdf` | PdfStreamParser | PDF ストリーム解析による True CDR |
| `"ooxml"` | `.docx`, `.xlsx`, `.pptx` | OoxmlStreamParser | Office Open XML 無害化 |
| `"zip"` | `.zip` | ZipSanitizer | ZIP 内ファイルの再帰的無害化 |
| `"svg"` | `.svg` | SvgSanitizer | SVG スクリプト要素除去 |

**設定例**:

```toml
# 最小構成（PDF と Office 文書のみ）
[cdr]
enabled = true
sanitizers = ["pdf", "ooxml"]

# 全機能有効
[cdr]
enabled = true
sanitizers = ["pdf", "ooxml", "zip", "svg"]

# CDR 無効（信頼済みネットワーク内転送のみ）
[cdr]
enabled = false
```

### 2-4. `[jtd_converter]` セクション — 一太郎変換設定

```toml
[jtd_converter]
type = "libreoffice"
enabled = true
libreoffice_path = ""
```

| フィールド | 型 | デフォルト値 | 必須 | 説明 |
|----------|-----|-----------|------|------|
| `type` | String | `"libreoffice"` | △ | コンバータータイプ: `"libreoffice"`, `"ichitaro_viewer"`, `"dummy"` |
| `enabled` | Boolean | `true` | △ | JTD 変換機能の有効/無効 |
| `libreoffice_path` | String | `""` (自動検出) | △ | LibreOffice 実行ファイルのパス。空欄なら PATH から自動検出 |

> **詳細**: [JTD コンバーター設定ガイド](jtd-converter.md) を参照してください。

### 2-5. `[pii]` セクション — PII 検出設定

```toml
[pii]
enabled = true
action_on_detect = "mask"
```

| フィールド | 型 | デフォルト値 | 必須 | 説明 |
|----------|-----|-----------|------|------|
| `enabled` | Boolean | `true` | △ | PII 検出エンジンの有効/無効 |
| `action_on_detect` | String | `"mask"` | △ | PII 検出時のアクション: `"block"`, `"mask"`, `"alert_only"` |

**アクションの詳細**:

| アクション | 動作 | 使用シナリオ |
|----------|------|-----------|
| `"block"` | ファイル転送を拒否 | 機密性が極めて高い場合 |
| `"mask"` | 検出箇所をマスキングして転送 | バランス重視（デフォルト推奨） |
| `"alert_only"` | 検出ログに記録のみ | 監査目的、運用開始初期など |

> **詳細**: [PII 検出設定ガイド](../security/pii-detection.md) を参照してください。

### 2-6. `[audit_log]` セクション — 監査ログ設定

```toml
[audit_log]
enabled = true
format = "json"
output_path = "./logs/sender_audit.log"
```

| フィールド | 型 | デフォルト値 | 必須 | 説明 |
|----------|-----|-----------|------|------|
| `enabled` | Boolean | `true` | △ | 監査ログ機能の有効/無効 |
| `format` | String | `"json"` | △ | 出力フォーマット: `"json"`, `"syslog"`, `"cef"` |
| `output_path` | String | `"./logs/audit.log"` | △ | ログファイルの出力パス |

**ログフォーマット比較**:

| フォーマット | 特徴 | 推奨用途 |
|------------|------|---------|
| `"json"` | 構造化 JSON、SIEM ツールとの親和性高 | Splunk, Elasticsearch, Fluentd |
| `"syslog"` | RFC 5424 準拠、Syslog サーバへ直接送信可能 | rsyslog, syslog-ng |
| `"cef"` | Common Event Format、ArcSight 等の SIEM 用 | HP ArcSight, QRadar |

---

## 3. Receiver 設定ファイル完全リファレンス

### 3-1. `[server]` セクション — Receiver サーバー基本設定

```toml
[server]
addr = "0.0.0.0:3001"
download_dir = "./downloads"
storage_dir = "./storage/receiver"
tunnel_port = 50051
log_level = "info"
```

| フィールド | 型 | デフォルト値 | 必須 | 説明 |
|----------|-----|-----------|------|------|
| `addr` | String | `"127.0.0.1:3001"` | ✅ | HTTP ダownload API のリッスンアドレス |
| `download_dir` | String | `"./downloads"` | ✅ | 受信ファイルの保存ディレクトリ |
| `storage_dir` | String | `"./storage"` | ✅ | 受信チャンクの一時保存ディレクトリ |
| `tunnel_port` | Integer | `50051` | ✅ | gRPC トンネルのリッスンポート番号 |
| `log_level` | String | `"info"` | △ | ログレベル |

### 3-2. `[audit_log]` セクション — Receiver 側監査ログ

Receiver 側でも監査ログを独立して設定できます。

```toml
[audit_log]
enabled = true
format = "json"
output_path = "./logs/receiver_audit.log"
```

---

## 4. 最小構成設定例（コピー＆ペースト用）

### 4-1. Sender 最小構成

以下は、最低限の動作に必要な Sender 設定です。
テスト環境や初期導入時にご利用ください。

```toml
# ============================================================
# misogi-sender.toml — Minimum Configuration
# Copy, paste, and modify values as needed.
# ============================================================

[server]
addr = "0.0.0.0:3000"
storage_dir = "./storage/sender"
log_level = "info"

[receiver]
addr = "127.0.0.1:50051"

[cdr]
enabled = true
sanitizers = ["pdf", "ooxml"]

[jtd_converter]
type = "libreoffice"
enabled = false

[pii]
enabled = true
action_on_detect = "alert_only"

[audit_log]
enabled = true
format = "json"
output_path = "./logs/sender_audit.log"
```

### 4-2. Receiver 最小構成

```toml
# ============================================================
# misogi-receiver.toml — Minimum Configuration
# ============================================================

[server]
addr = "0.0.0.0:3001"
download_dir = "./downloads"
storage_dir = "./storage/receiver"
tunnel_port = 50051
log_level = "info"

[audit_log]
enabled = true
format = "json"
output_path = "./logs/receiver_audit.log"
```

### 4-3. 本番環境推奨構成

政府機関・金融機関向けのセキュアな設定例です。

```toml
# ============================================================
# misogi-sender.toml — Production (Government/Finance)
# High security configuration with full audit trail.
# ============================================================

[server]
addr = "0.0.0.0:3000"
storage_dir = "C:\ProgramData\Misogi\storage\sender"
chunk_size = 1048576
log_level = "info"

[receiver]
addr = "misogi-receiver.internal.local:50051"

[cdr]
enabled = true
sanitizers = ["pdf", "ooxml", "zip", "svg"]

[jtd_converter]
type = "libreoffice"
enabled = true
libreoffice_path = "C:\Program Files\LibreOffice\program\soffice.exe"

[pii]
enabled = true
action_on_detect = "mask"

[audit_log]
enabled = true
format = "json"
output_path = "C:\ProgramData\Misogi\logs\sender_audit.log"
```

---

## 5. セキュリティ関連設定の解説

### 5-1. CDR 設定のセキュリティ考慮事項

| 設定 | セキュリティ上の意味 | 推奨値 |
|------|-------------------|--------|
| `[cdr].enabled = true` | 無害化処理を強制する | 本番では必ず `true` |
| `[cdr].sanitizers` | 未対応フォーマットは無害化されない | 取扱うフォーマットすべてを含める |
| `[cdr]` 自体を削除 | CDR を完全に無効化 | ⚠️ 信頼済みネットワーク内のみ |

### 5-2. PII 設定のセキュリティ考慮事項

| 設定 | リスクレベル | 説明 |
|------|------------|------|
| `action_on_detect = "block"` | 🔴 最も安全 | マイナンバー等を含むファイルを完全にブロック |
| `action_on_detect = "mask"` | 🟡 バランス | 検出個人情報をマスキングして通過（デフォルト） |
| `action_on_detect = "alert_only"` | 🟢 緩やか | 検出しても通過させる（監査目的） |

### 5-3. ロギング設定の考慮事項

| 設定 | 推奨環境 | 注意点 |
|------|---------|--------|
| `log_level = "trace"` | 障害調査時のみ | 非常に冗長、ディスク消費大 |
| `log_level = "debug"` | 開発・テスト | 詳細なデバッグ情報含む |
| `log_level = "info"` | 本番運用（デフォルト） | 通常の運用情報 |
| `log_level = "warn"` | 安定稼働時 | 警告とエラーのみ記録 |
| `log_level = "error"` | 最小ログ | エラーのみ記録 |

---

## 6. 設定ファイルの検証

設定ファイルを作成後、以下のコマンドで文法エラーがないか確認できます。

```powershell
# Sender 設定のロードテスト
.\target\release\misogi-sender.exe server --config .\misogi-sender.toml 2>&1 | Select-Object -First 20

# Receiver 設定のロードテスト
.\target\release\misogi-receiver.exe server --config .\misogi-receiver.toml 2>&1 | Select-Object -First 20
```

**正常な場合の最初の数行**:
```
  _ __  _ __ _____      _____  ___ _ ____   _____ _ __
 | '_ \| '__/ _ \ \ /\ / / __|/ _ \ '__\ \ / / _ \ '_ \
 ...
[INFO] Loading configuration from .\misogi-sender.toml
[INFO] Configuration loaded successfully
```

**設定エラーがある場合**:
```
Error: Configuration error: missing field `server.addr`
```

---

*次のステップ: [JTD コンバーター設定](jtd-converter.md) または [Active Directory 連携ガイド](active-directory.md) に進んでください*
