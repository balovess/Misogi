# 日常運用手順書 (Daily Operations Manual)

Misogi システムの日常運用に関する標準手順書です。
日次チェックリスト、ヘルスチェック、バックアップ手順、インシデント対応フローを含みます。

**対象読者**: 運用担当者、オンコールエンジニア  
**適用範囲**: 本番環境の定常運用

---

## 1. 日次チェックリスト (Daily Checklist)

毎日業務開始時（推奨: 午前 9:00 〜 9:30）に以下の項目を確認してください。
すべての項目にチェックをつけた後、署名してください。

### 1-1. サーバー稼働状況確認

| # | 確認項目 | 手順 | 期待される状態 | 結果 |
|---|---------|------|-------------|------|
| 1 | Sender プロセス稼働確認 | `Get-Process misogi-sender` | プロセス存在、CPU/メモリ正常 | ☐ |
| 2 | Receiver プロセス稼働確認 | `Get-Process misogi-receiver` | プロセス存在、CPU/メモリ正常 | ☐ |
| 3 | ポートリッスン確認 | `netstat -an \| findstr :3000` | LISTENING 状態 | ☐ |
| 4 | ディスク空き容量確認 | `Get-PSDrive C \| Select-Object Used,Free` | 空き > 20% | ☐ |
| 5 | メモリ使用量確認 | `tasklist /FI "IMAGENAME eq misogi*"` | 安定値以内 | ☐ |

### 1-2. 転送処理状況確認

| # | 確認項目 | 手順 | 期待される状態 | 結果 |
|---|---------|------|-------------|------|
| 6 | 前日の転送件数確認 | ログ集計 | 異常な 0 件や急増なし | ☐ |
| 7 | エラーログ確認 | `Select-String -Path .\logs\*.log -Pattern "ERROR"` | 致命的エラーなし | ☐ |
| 8 | CDR 処理成功率 | 監査ログ集計 | 成功率 > 99% | ☐ |
| 9 | PII 検出アラート数 | 監査ログ PII イベント | 急激な増加なし | ☐ |

### 1-3. セキュリティ関連確認

| # | 確認項目 | 手順 | 期待される状態 | 結果 |
|---|---------|------|-------------|------|
| 10 | 不正アクセスログ確認 | Windows Event Log Security | 不審な Bind 失敗なし | ☐ |
| 11 | ファイアウォールルール有効 | `Get-NetFirewallRule -DisplayName "Misogi*"` | 全件 Enabled | ☐ |
| 12 | TLS 証明書有効期限 | 証明書 MMC スナップイン | 30 日以上残存 | ☐ |

### 1-4. 確認コマンドセット（コピー＆ペースト用）

```powershell
# ============================================================
# Misogi Daily Health Check Script
# 毎朝実行してシステム状態を確認してください。
# ============================================================

Write-Host "=== Misogi Daily Health Check ===" -ForegroundColor Cyan
Write-Host "実行日時: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
Write-Host ""

# --- 1. プロセス確認 ---
Write-Host "[1] プロセス稼働状況" -ForegroundColor Green
@("misogi-sender", "misogi-receiver") | ForEach-Object {
    $proc = Get-Process -Name $_ -ErrorAction SilentlyContinue
    if ($proc) {
        $cpu = [math]::Round($proc.CPU, 1)
        $memMB = [math]::Round($proc.WorkingSet64 / 1MB, 1)
        Write-Host "  OK: $_ (PID=$($proc.Id), CPU=${cpu}s, Mem=${memMB}MB)" -ForegroundColor White
    } else {
        Write-Host "  NG: $_ — プロセスが見つかりません！" -ForegroundColor Red
    }
}

# --- 2. ポート確認 ---
Write-Host ""
Write-Host "[2] ポートリッスン状況" -ForegroundColor Green
@(3000, 3001, 50051) | ForEach-Object {
    $port = $_
    $listening = netstat -an | Select-String ":${port}.*LISTENING"
    if ($listening) {
        Write-Host "  OK: Port ${port} is LISTENING" -ForegroundColor White
    } else {
        Write-Host "  NG: Port ${port} is NOT listening!" -ForegroundColor Red
    }
}

# --- 3. ディスク容量 ---
Write-Host ""
Write-Host "[3] ディスク容量" -ForegroundColor Green
$c = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'"
$freePct = [math]::Round($c.FreeSpace / $c.Size * 100, 1)
$freeGB = [math]::Round($c.FreeSpace / 1GB, 1)
if ($freePct -gt 20) {
    Write-Host "  OK: C: ドライブ空き ${freeGB}GB (${freePct}%)" -ForegroundColor White
} else {
    Write-Host "  WARNING: C: ドライブ残り ${freeGB}GB (${freePct}%) — 容量不足の恐れ" -ForegroundColor Yellow
}

# --- 4. エラーログ件数 ---
Write-Host ""
Write-Host "[4] 直近 24 時間のエラー件数" -ForegroundColor Green
$logDir = "C:\ProgramData\Misogi\logs"
if (Test-Path $logDir) {
    $errorCount = (Get-ChildItem $logDir -Filter "*.log" |
        ForEach-Object { Select-String -Path $_.FullName -Pattern "ERROR" }).Count
    if ($errorCount -eq 0) {
        Write-Host "  OK: エラー 0 件" -ForegroundColor White
    } elseif ($errorCount -lt 10) {
        Write-Host "  INFO: エラー ${errorCount} 件 — 要確認" -ForegroundColor Yellow
    } else {
        Write-Host "  WARNING: エラー ${errorCount} 件 — 至急確認が必要" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "=== ヘルスチェック完了 ===" -ForegroundColor Cyan
```

---

## 2. ログモニタリングガイド

### 2-1. ログファイルの場所

| ログ種別 | デフォルトパス | 説明 |
|---------|--------------|------|
| Sender アプリケーションログ | `./logs/sender.log` | アプリケーション動作ログ |
| Receiver アプリケーションログ | `./logs/receiver.log` | 同上 |
| Sender 監査ログ | `./logs/sender_audit.log` | JSON 形式の監査トレール |
| Receiver 監査ログ | `./logs/receiver_audit.log` | 同上 |
| Windows イベントログ | `Application`, `Security` | システムレベルのイベント |

### 2-2. ログレベルと意味

| レベル | 表示色 | 使用場面 | 運用上の対応 |
|-------|--------|---------|------------|
| `TRACE` | — | 最も詳細なデバッグ情報 | 障害調査時のみ有効化 |
| `DEBUG` | — | 開発・デバッグ情報 | テスト環境で使用 |
| `INFO` | 緑 | 通常の運用情報 | **本番運用のデフォルト** |
| `WARN` | 黄 | 警告（問題になり得る状態） | 注視が必要 |
| `ERROR` | 赤 | エラー（処理継続可能） | 要調査・要記録 |
| — | — | **FATAL** | 致命的エラー（処理不能） | **即時対応必須** |

### 2-3. 重要なログパターンと対応

#### パターン A: 正常なファイル転送

```
[INFO] File uploaded: document.pdf (size=2048576)
[INFO] CDR sanitization started: document.pdf → PdfStreamParser
[INFO] CDR sanitization completed: clean
[INFO] PII scan completed: no PII found (2048576 bytes in 45ms)
[INFO] Audit log written: FILE_PROCESSED event_id=abc123
[INFO] Transfer initiated via gRPC to receiver
[INFO] Transfer completed: document.pdf (status=success)
```

#### パターン B: PII 検出時

```
[WARN] PII detected in document.pdf: my_number match (masked: 1**********2)
[INFO] Action taken: mask — file forwarded with redaction
[AUDIT] {"event":"FILE_PROCESSED","pii_found":true,"action":"mask",...}
```

→ **対応**: 監査ログを確認し、必要に応じて発信元に通知

#### パターン C: CDR 処理失敗

```
[ERROR] CDR sanitization failed: report.jtd — conversion error
[ERROR] File blocked: report.jtd (reason=cdre_failure)
```

→ **対応**: [トラブルシューティング](troubleshooting.md) 参照

#### パターン D: gRPC 接続エラー

```
[ERROR] gRPC connection failed: receiver at 192.168.1.200:50051 unreachable
[WARN] Retry attempt 1/3 in 5 seconds...
```

→ **対応**: Receiver サーバーの生存確認、ネットワーク疎通確認

### 2-4. リアルタイムログ監視

```powershell
# リアルタイムでログを監視（tail 的な動作）
Get-Content -Path ".\logs\sender.log" -Tail 20 -Wait

# ERROR/WARN のみフィルタリングして監視
Get-Content -Path ".\logs\sender.log" -Wait |
    Where-Object { $_ -match "(ERROR|WARN|FATAL)" }
```

---

## 3. ヘルスチェック手順

### 3-1. API ヘルスチェックエンドポイント

Misogi は HTTP API 経由で簡易ヘルスチェックを受け付けます。

```powershell
# Sender ヘルスチェック
Invoke-RestMethod -Uri "http://localhost:3000/api/v1/health" -Method Get

# Receiver ヘルスチェック
Invoke-RestMethod -Uri "http://localhost:3001/api/v1/health" -Method Get
```

**正常応答 (HTTP 200)**:
```json
{
  "status": "healthy",
  "uptime_seconds": 86400,
  "version": "0.1.0",
  "components": {
    "cdr_engine": "ok",
    "pii_detector": "ok",
    "audit_log": "ok",
    "jtd_converter": "ok",
    "grpc_tunnel": "connected"
  }
}
```

**異常応答 (HTTP 503)**:
```json
{
  "status": "degraded",
  "components": {
    "cdr_engine": "ok",
    "jtd_converter": "error",
    "grpc_tunnel": "disconnected"
  }
}
```

### 3-2. 総合ヘルスチェックスクリプト

```powershell
# ============================================================
# Misogi Comprehensive Health Check
# 定期実行（cron/scheduler）での利用を想定
# ============================================================

$senderHealth = try {
    Invoke-RestMethod -Uri "http://localhost:3000/api/v1/health" -TimeoutSec 10
} catch { @{ status = "unreachable" } }

$receiverHealth = try {
    Invoke-RestMethod -Uri "http://localhost:3001/api/v1/health" -TimeoutSec 10
} catch { @{ status = "unreachable" } }

Write-Host "Sender Status: $($senderHealth.status)"
Write-Host "Receiver Status: $($receiverHealth.status)"

if ($senderHealth.status -ne "healthy" -or $receiverHealth.status -ne "healthy") {
    # アラート送信（メール / Slack / Teams 等）
    $body = "Misogi Alert: Sender=$($senderHealth.status), Receiver=$($receiverHealth.status)"
    Write-Host "ALERT: $body" -ForegroundColor Red
    exit 1
}
exit 0
```

---

## 4. バックアップ手順

### 4-1: バックアップ対象

| 対象 | パス | バックアップ頻度 | 保持期間 |
|------|------|---------------|---------|
| 設定ファイル | `*.toml` | 毎日 | 90 日 |
| 監査ログ | `logs/*.log` | 毎日 | **3 年**（法的要件による） |
| 一時ストレージ | `storage/` | 毎時 | 7 日 |
| 出力ファイル | `downloads/` | 毎日 | 30 日 |

> **⚠️ 重要**: 監査ログは日本のコンプライアンス規制により、
> **最低 3 年間**の保存が推奨されます（業界によっては 7 年）。

### 4-2: バックアップスクリプト

```powershell
# ============================================================
# Misogi Backup Script
# タスクスケジューラで毎日午前 3:00 に実行することを推奨
# ============================================================

$backupRoot = "D:\Backups\Misogi"
$dateStr = Get-Date -Format "yyyyMMdd"
$backupDir = Join-Path $backupRoot $dateStr
$sourceDir = "C:\ProgramData\Misogi"

# バックアップディレクトリ作成
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

# --- 設定ファイルのバックアップ ---
Copy-Item "$sourceDir\misogi-sender.toml" "$backupDir\" -Force
Copy-Item "$sourceDir\misogi-receiver.toml" "$backupDir\" -Force
Write-Host "Config files backed up."

# --- 監査ログのバックアップ ---
$logBackupDir = Join-Path $backupDir "logs"
New-Item -ItemType Directory -Path $logBackupDir -Force | Out-Null
Copy-Item "$sourceDir\logs\*.log" "$logBackupDir\" -Force
Write-Host "Audit logs backed up."

# --- 圧縮 ---
Compress-Archive -Path "$backupDir\*" -DestinationPath "$backupDir.zip" -Force
Remove-Item $backupDir -Recurse -Force

# --- 古いバックアップの削除（保持期間: 90 日） ---
$retentionDays = 90
$cutoffDate = (Get-Date).AddDays(-$retentionDays)
Get-ChildItem $backupRoot -Filter "*.zip" |
    Where-Object { $_.LastWriteTime -lt $cutoffDate } |
    Remove-Item -Force

Write-Host "Backup completed: $backupDir.zip"
Write-Host "Old backups (older than $retentionDays days) cleaned up."
```

### 4-3: リストア手順

```powershell
# ============================================================
# Misogi Restore Procedure
# ============================================================

$backupFile = "D:\Backups\Misogi\20240115.zip"
$restoreDir = "C:\ProgramData\Misogi"

# 1. バックアップの展開
Expand-Archive -Path $backupFile -DestinationPath "$env:TEMP\MisogiRestore" -Force

# 2. 設定ファイルのリストア
Copy-Item "$env:TEMP\MisogiRestore\misogi-sender.toml" "$restoreDir\" -Force
Copy-Item "$env:TEMP\MisogiRestore\misogi-receiver.toml" "$restoreDir\" -Force

# 3. 監査ログのリストア（上書き禁止 — 追加コピー）
Copy-Item "$env:TEMP\MisogiRestore\logs\*.log" "$restoreDir\logs\" -Force

# 4. 一時ファイルのクリーンアップ
Remove-Item "$env:TEMP\MisogiRestore" -Recurse -Force

Write-Host "Restore completed from: $backupFile"
```

---

## 5. インシデント対応フロー

### 5-1: 重大度レベル

| レベル | 名称 | 定義 | 対応目標 | エスカレーション先 |
|-------|------|------|---------|----------------|
| P1 | 致命的 | システム完全停止 | 15 分以内 | マネージャ + ベンダー |
| P2 | 重大 | 機能一部障害 | 1 時間以内 | チームリーダー |
| P3 | 中程度 | 性能低下・軽微なエラー | 4 時間以内 | 当番エンジニア |
| P4 | 低い | 問い合わせ・改善要望 | 次営業日 | 通常フロー |

### 5-2: インシデント対応フローチャート

```
┌──────────────────┐
│  異常検知           │ ← モニタリング / ユーザー報告
└───────┬────────----┘
        │
        ▼
┌──────────────────┐     ┌──────────────────────┐
│  影響範囲評価      │────▶│ P1/P2: 即時エスカレーション │
│  (重大度判定)       │     │  関係者召集             │
└───────┬────────----┘     └──────────────────────┘
        │
        ▼
┌──────────────────┐
│  原因特定           │ ← ログ分析 / ネットワーク確認
│  (診断)            │
└───────┬────────----┘
        │
        ▼
┌──────────────────┐
│  対策実施           │ ← 一時的回避 / 根本修正
└───────┬────────----┘
        │
        ▼
┌──────────────────┐
│  復旧確認           │ ← ヘルスチェック / 機能テスト
└───────┬────────----┘
        │
        ▼
┌──────────────────┐
│  報告書作成         │ ← インシdent報告 / 再発防止策
└──────────────────┘
```

### 5-3: インシデント報告書テンプレート

```markdown
# Misogi インシデント報告書

## 基本情報
| 項目 | 内容 |
|------|------|
| 発生日時 | YYYY-MM-DD HH:MM:SS |
| 発見者 | 氏名 |
| 重大度 | P1 / P2 / P3 / P4 |
| 分類 | Availability / Security / Data / Performance |

## 現象描述
（何が起こったかを客観的に記述）

## 影響範囲
- 影響を受けたユーザー数:
- 影響を受けた機能:
- データ損失の有無:

## 原因
（根本原因を技術的に記述）

## 対策内容
- 即時対策:
- 恒久対策:

## 復旧時刻
- 検知: YYYY-MM-DD HH:MM
- 対策開始: YYYY-MM-DD HH:MM
- 復旧完了: YYYY-MM-DD HH:MM
- 総ダウンタイム: X 時間 Y 分

## 再発防止策
（今後同じ事象を防ぐための施策）

## 添付資料
- ログ抜粋:
- スクリーンショット:
```

---

*関連ドキュメント: [トラブルシューティング FAQ](troubleshooting.md) | [監査ログフィールドガイド](../security/audit-log-guide.md)*
