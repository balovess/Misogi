# 監査ログフィールドガイド (Audit Log Field Guide)

Misogi の監査ログシステムが生成する各イベントのフィールドを詳細に解説します。
JSON / Syslog / CEF 各フォーマットの読み方、ログ保持ポリシー、分析例を含みます。

**対象読者**: セキュリティ担当者、監査担当者、SIEM 管理者  
**前提条件`: 監査ログ機能が有効 (`[audit_log].enabled = true`) であること

---

## 1. 監査ログの概要

### 1-1. ログイベント一覧

| イベント名 | 説明 | 発生タイミング |
|-----------|------|-------------|
| `FILE_UPLOADED` | ファイル受付完了 | Sender でファイルアップロード受領時 |
| `FILE_PROCESSED` | CDR/PII 処理完了 | 全処理パイプライン完了時 |
| `FILE_TRANSFERRED` | ファイル転送完了 | Receiver へ転送完了時 |
| `FILE_BLOCKED` | ファイルブロック | PII Block アクションまたは CDR 失敗時 |
| `PII_DETECTED` | PII 検出通知 | 個人情報検出時（AlertOnly/Mask/Block 共通） |
| `AUTH_ATTEMPT` | 認証試行 | LDAP/AD 認証実行時 |
| `AUTH_SUCCESS` | 認証成功 | ユーザー認証成功時 |
| `AUTH_FAILURE` | 認証失敗 | ユーザー認証失敗時 |
| `CONFIG_CHANGE` | 設定変更 | 設定ファイルの動的リロード時 |
| `SYSTEM_START` | システム起動 | プロセス起動時 |
| `SYSTEM_STOP` | システム停止 | プロセス停止時 |

---

## 2. FILE_PROCESSED イベントの完全解説

最も重要なイベントである `FILE_PROCESSED` を詳しく解説します。
このイベントは、ファイルが Misogi の全処理パイプラインを通過したことを記録します。

### 2-1: JSON 形式の出力例

```json
{
  "event": "FILE_PROCESSED",
  "event_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "timestamp": "2024-01-15T09:23:45.123+09:00",
  "node_type": "sender",
  "node_id": "sender-tokyo-01",
  "file": {
    "original_name": "report_2024Q1.jtd",
    "file_id": "f9876543-21ab-cdef-0123-456789abcdef",
    "size_bytes": 1048576,
    "mime_type": "application/x-jtd",
    "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  },
  "cdr_result": {
    "sanitizer_used": "jtd_converter",
    "output_format": "pdf",
    "status": "success",
    "duration_ms": 2345,
    "threats_removed": ["macro_scripts", "embedded_objects"]
  },
  "pii_result": {
    "found": true,
    "action_taken": "mask",
    "matches": [
      {
        "pattern_name": "my_number",
        "masked_text": "1**********2",
        "offset": 245,
        "length": 12
      }
    ],
    "scan_duration_ms": 67
  },
  "transfer": {
    "destination": "receiver-osaka-01",
    "status": "completed",
    "method": "grpc_stream",
    "chunks_total": 1024,
    "transfer_duration_ms": 5678
  },
  "user_context": {
    "authenticated_user": "suzuki@tokyo.lg.jp",
    "source_ip": "192.168.1.100",
    "user_agent": "Misogi-CLI/0.1.0"
  },
  "compliance": {
    "regulation_tags": ["appi", "my_number_act"],
    "retention_class": "confidential",
    "data_classification": "internal"
  }
}
```

### 2-2: 各フィールドの解説

#### トップレベルフィールド

| フィールド名 | 型 | 説明 | SIEM 活用例 |
|------------|-----|------|------------|
| `event` | String | イベントタイプ識別子 | イベントフィルタリング |
| `event_id` | String (UUID) | 一意なイベント ID | 相関分析・重複排除 |
| `timestamp` | ISO 8601 | イベント発生時刻（日本標準時） | タイムライン分析 |
| `node_type` | String | `"sender"` or `"receiver"` | ノード別集計 |
| `node_id` | String | ノードの一意識別子 | マルチノード展開時の追跡 |

#### `file` オブジェクト

| フィールド名 | 型 | 説明 | 監査上の重要性 |
|------------|-----|------|------------|
| `original_name` | String | 元のファイル名 | **どのファイルが処理されたか** |
| `file_id` | String (UUID) | Misogi 内部ファイル ID | ライフサイクル追跡 |
| `size_bytes` | Integer | 元ファイルサイズ（バイト） | 容量傾向分析 |
| `mime_type` | String | MIME タイプ | フォーマット分布分析 |
| `sha256_hash` | String | 元ファイルの SHA-256 ハッシュ値 | **改ざん検知・ forensic 用** |

> **⚠️ 重要**: `sha256_hash` は監査証跠として極めて重要です。
> 「ある時点でどのような内容のファイルが処理されたか」を後から証明できます。

#### `cdr_result` オブジェクト

| フィールド名 | 型 | 説明 |
|------------|-----|------|
| `sanitizer_used` | String | 使用されたサニタイザー名（`pdf`, `ooxml`, `zip`, `jtd_converter` 等）|
| `output_format` | String | 出力フォーマット（`pdf`, `sanitized_docx` 等）|
| `status` | String | `"success"` or `"failure"` |
| `duration_ms` | Integer | CDR 処理所要時間（ミリ秒）|
| `threats_removed` | Array[String] | 除去された脅威のリスト（マクロ、スクリプト等）|

#### `pii_result` オブジェクト

| フィールド名 | 型 | 説明 |
|------------|-----|------|
| `found` | Boolean | PII が検出されたかどうか |
| `action_taken` | String | 実行されたアクション: `"block"`, `"mask"`, `"alert_only"` |
| `matches` | Array | 検出された PII の詳細（マスク済みテキスト含む）|
| `scan_duration_ms` | Integer | PII スキャン所要時間 |

#### `transfer` オブジェクト

| フィールド名 | 型 | 説明 |
|------------|-----|------|
| `destination` | String | 転送先 Receiver ノード ID |
| `status` | String | 転送ステータス |
| `method` | String | 転送方式: `"grpc_stream"`, `"local"` 等 |
| `chunks_total` | Integer | 転送チャンク数 |
| `transfer_duration_ms` | Integer | 転送所要時間 |

#### `user_context` オブジェクト

| フィールド名 | 型 | 説明 | プライバシー考慮 |
|------------|-----|------|---------------|
| `authenticated_user` | String | 認証済みユーザー識別子 | AD UID または UPN |
| `source_ip` | String | 送信元 IP アドレス | 内部ログとして保持 |
| `user_agent` | String | クライアント識別子 | デバッグ用 |

#### `compliance` オブジェクト

| フィールド名 | 型 | 説明 |
|------------|-----|------|
| `regulation_tags` | Array[String] | 関連する法規制タグ（`appi`, `my_number_act` 等）|
| `retention_class` | String | 保持分類: `public`, `internal`, `confidential`, `restricted` |
| `data_classification` | String | データ分類ラベル |

---

## 3. ログフォーマット別解説

### 3-1: JSON 形式 (推奨)

**設定**: `[audit_log].format = "json"`

**特徴**:
- 構造化データ、機械可読性が最高
- Elasticsearch, Splunk, Fluentd との親和性が高い
- 1 行 = 1 イベント（JSON Lines 形式）

**SIEM 取り込み例 (Elasticsearch)**:

```json
// Filebeat / Elastic Agent の設定例
{
  "type": "log",
  "paths": ["C:/ProgramData/Misogi/logs/*_audit.log"],
  "json.keys_under_root": true,
  "json.add_error_key": true,
  "fields": {
    "misogi": true,
    "environment": "production"
  }
}
```

### 3-2: Syslog 形式

**設定**: `[audit_log].format = "syslog"`

**特徴**:
- RFC 5424 準拠
- rsyslog, syslog-ng に直接転送可能
- 構造化データ (SD-ELEMENT) 対応

**出力例**:
```
<134>1 2024-01-15T09:23:45.123+09:00 sender-tokyo-01 misogi-sender 12345 - [meta eventId="a1b2c3d4"] FILE_PROCESSED file="report.jtd" cdr_status="success" pii_found="true" action="mask"
```

**フィールドマッピング**:

| Syslog 項目 | 値 | 説明 |
|------------|-----|------|
| PRI | `<134>` | Facility(16=local0) + Severity(6=Info) |
| VERSION | `1` | RFC 5424 バージョン |
| TIMESTAMP | ISO 8601 | イベント発生時刻 |
| HOSTNAME | `sender-tokyo-01` | ホスト名 |
| APP-NAME | `misogi-sender` | アプリケーション名 |
| PROCID | `12345` | プロセス ID |
| MSG | — | 構造化データ |

### 3-3: CEF 形式 (Common Event Format)

**設定**: `[audit_log].format = "cef"`

**特徴**:
- ArcSight, QRadar 等 SIEM と互換
- 拡張キーバリュー形式

**出力例**:
```
CEF:0|Misogi|Misogi CDR|0.1.0|FILE_PROCESSED|File processed through CDR pipeline|INFO|src=192.168.1.100 suid=suzuki@tokyo.lg.jp fname=report_2024Q1.jtd fsize=1048576 cdrStatus=success piiFound=true act=mask rt=8023ms
```

**CEF 拡張キー**:

| CEF キー | 名前 | 型 | 説明 |
|---------|------|-----|------|
| `src` | sourceAddress | IPv4 | 送信元 IP |
| `suid` | sourceUserId | String | 認証ユーザー |
| `fname` | fileName | String | ファイル名 |
| `fsize` | fileSize | Integer | ファイルサイズ |
| `cdrStatus` | customField | String | CDR 処理結果 |
| `piiFound` | customField | Boolean | PII 検出有無 |
| `act` | customField | String | 実行アクション |
| `rt` | rt | Integer | 応答時間(ms) |

---

## 4. ログ保持ポリシーの推奨

### 4-1: 法規制による保持期間要件

| 規制 | 保持期間 | 対象ログ | 根拠 |
|------|---------|---------|------|
| APPI（個人情報保護法） | 3〜7 年 | PII 関連イベント | 事業者の責任 |
| マイナンバー法 | 7 年 | マイナンバー関連 | 特定個人情報取扱事業者義務 |
| 金融商品取引法 | 7 年 | 全イベント | 証跡保存義務 |
| J-SOX | 7 年 | 全イベント | 内部統制報告 |
| 地方自治体情報公開条例 | 3〜5 年 | 公的文書関連 | 各自治体条例による |

### 4-2: 推奨保持ポリシー

```toml
# misogi.toml でのログ保持設定（将来拡張予定）
[audit_log]
enabled = true
format = "json"
output_path = "./logs/sender_audit.log"

# ローテーション設定
max_log_size_mb = 500       # 単一ログファイルの最大サイズ
max_log_files = 50          # 保持する最大ファイル数
# 合計: 500MB × 50 = 25GB (約 3 年分の運用を見込む)
compression = true          # 古いログは gzip 圧縮
```

### 4-3: ログアーカイブ戦略

```
現行ログ (hot)
├── sender_audit.log          ← 現在書き込み中
├── sender_audit.log.1        ← 直近のローテーション分
└── sender_audit.log.2.gz     ← 圧縮済み
         │
         ▼ (30 日経過)
温ログ (warm) → 低速ストレージへ移動
├── archive/2024/01/
├── archive/2024/02/
└── ...
         │
         ▼ (1 年経過)
冷ログ (cold) → オフラインアーカイブへ
├── tape/2023/
└── ...
```

---

## 5. ログ分析例

### 5-1: 1 日あたりの処理件数集計

```powershell
# PowerShell による日次集計
$logFile = ".\logs\sender_audit.log"
$events = Get-Content $logFile | ConvertFrom-Json

$events | Where-Object { $_.event -eq "FILE_PROCESSED" } |
    Group-Object { $_.timestamp.Substring(0,10) } |
    Select-Object Name, Count |
    Sort-Object Name -Descending |
    Format-Table -AutoSize
```

**出力例**:
```
Name            Count
----            -----
2024-01-15        1245
2024-01-14        1198
2024-01-13         987
```

### 5-2: PII 検出率のトレンド分析

```powershell
# PII 検出のあるイベントの割合
$total = ($events | Where-Object { $_.event -eq "FILE_PROCESSED" }).Count
$piiDetected = ($events | Where-Object { $_.pii_result.found -eq $true }).Count
$detectionRate = [math]::Round($piiDetected / $total * 100, 2)

Write-Host "総処理件数: $total"
Write-Host "PII 検出件数: $piiDetected"
Write-Host "検出率: $detectionRate %"
```

### 5-3: 特定ユーザーのアクティビティ追跡

```powershell
# 特定ユーザーの全操作履歴
$user = "suzuki@tokyo.lg.jp"
$events | Where-Object { $_.user_context.authenticated_user -eq $user } |
    Select-Object timestamp, event, file.original_name, pii_result.action_taken |
    Format-Table -AutoSize
```

### 5-4: CDR 処理失敗の一覧抽出

```powershell
# CDR で失敗したファイル
$events | Where-Object {
    $_.event -eq "FILE_PROCESSED" -and $_.cdr_result.status -ne "success"
} | Select-Object timestamp, file.original_name, cdr_result.sanitizer_used |
    Format-Table -AutoSize
```

### 5-5: Elasticsearch Query 例 (Kibana)

```json
// 過去 24 時間の PII Block イベント
GET /misogi-audit-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "range": { "timestamp": { "gte": "now-24h" } } },
        { "match": { "event": "FILE_PROCESSED" } },
        { "match": { "pii_result.action_taken": "block" } }
      ]
    }
  },
  "size": 100,
  "_source": ["timestamp", "file.original_name", "pii_result.matches", "user_context.authenticated_user"]
}
```

---

*関連ドキュメント: [PII 検出設定ガイド](pii-detection.md) | [日常運用手順書](../operation/daily-operation.md)*
