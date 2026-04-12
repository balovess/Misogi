# トラブルシューティング FAQ (Troubleshooting)

Misogi 運用中に発生しやすい問題とその解決策を Q&A 形式でまとめました。
エラーコード参照表、診断情報の収集方法、サポート窓口への連絡タイミングについて説明します。

**対象読者**: 運用担当者、ヘルプデスクスタッフ  
**前提条件**: Misogi の基本的な設定を理解していること

---

## 1. エラーコード参照表

### 1-1. アプリケーションエラーコード

| エラーコード | 名前 | 説明 | 対応方針 |
|------------|------|------|---------|
| `E0001` | `ConfigurationError` | 設定ファイルの文法エラーまたは必須フィールド欠落 | [基本設定ガイド](../configuration/basic-config.md) を参照し修正 |
| `E0002` | `NetworkError` | ネットワーク接続失敗（Receiver 到達不可等） | ネットワーク経路・ファイアウォールを確認 |
| `E0003` | `ProtocolError` | gRPC プロトコル通信エラー | Sender/Receiver のバージョン一致を確認 |
| `E0004` | `StorageError` | ディスク I/O エラー・容量不足 | ディスク空き容量・権限を確認 |
| `E0005` | `AuthenticationError` | LDAP/AD 認証失敗 | AD 連携設定を確認 |
| `E0010` | `CdrSanitizationFailure` | CDR 無害化処理失敗 | ファイル形式・サニタイザー設定を確認 |
| `E0011` | `UnsupportedFormat` | 未対応のファイル形式 | `[cdr].sanitizers` に対応フォーマットを追加 |
| `E0020` | `JtdConversionError` | JTD → PDF 変換失敗 | LibreOffice 設定・ファイル破損を確認 |
| `E0021` | `ConverterNotFound` | JTD コンバーターが見つからない | LibreOffice/一太郎ビューアのインストールを確認 |
| `E0022` | `ConversionTimeout` | JTD 変換タイムアウト | `timeout_seconds` を増加 |
| `E0030` | `PiiDetectionError` | PII スキャンエラー | ファイルエンコーディングを確認 |
| `E0040` | `AuditLogError` | 監査ログ書き込みエラー | ログディレクトリの権限・容量を確認 |
| `E0050` | `FileTooLarge` | ファイルサイズ上限超過 | `max_file_size` 設定を確認・緩和 |
| `E0051` | `QuotaExceeded` | 転送クォータ超過 | クォータ設定または請求による増枠 |

### 1-2: HTTP ステータスコード

| ステータスコード | 意味 | 主な原因 | 対応 |
|----------------|------|---------|------|
| **200** | OK | 正常処理 | — |
| **400** | Bad Request | リクエストパラメータ不正 | API ドキュメントを参照 |
| **401** | Unauthorized | 認証失敗 | 認証情報を確認 |
| **403** | Forbidden | 権限不足 | AD グループ所属を確認 |
| **404** | Not Found | リソース不存在 | URL パスを確認 |
| **413** | Payload Too Large | ファイルサイズ超過 | `max_file_size` を確認 |
| **422** | Unprocessable Entity | ファイル形式エラー | 対応フォーマットか確認 |
| **500** | Internal Server Error | サーバー内部エラー | ログを収集し調査 |
| **502** | Bad Gateway | gRPC upstream エラー | Receiver の稼働を確認 |
| **503** | Service Unavailable | サービス一時停止 | リソース不足 or メンテナンス |
| **504** | Gateway Timeout | 処理タイムアウト | ファイルサイズ・サーバー負荷を確認 |

---

## 2. よくある問題と解決策 (Q&A)

### Q1: Sender が起動しない

**症状**: `misogi-sender server` 実行時にエラーで終了する

**A**: 以下の手順で順に確認してください。

**Step 1**: 設定ファイルの文法確認
```powershell
# TOML の文法エラーがないか確認
# 最も多い原因: 文字列のエスケープ忘れ、タブ文字混入
Get-Content .\misogi-sender.toml -Raw | Select-String "`t"
# タブ文字が検出されたら、スペースに置き換えてください
```

**Step 2**: 必須フィールドの確認
```powershell
# 最低限必要なフィールド
# [server] addr, storage_dir
# [receiver] addr
```

**Step 3**: ポ競合確認
```powershell
# ポートが既に使用されていないか
netstat -ano | findstr :3000
```

**Step 4**: 詳細ログの出力
```powershell
# debug レベルで起動して詳細エラーを取得
.\target\release\misogi-sender.exe server --config .\misogi-sender.toml 2>&1
```

---

### Q2: Receiver にファイルが届かない

**症状**: Sender ではアップロード成功だが、Receiver 側にファイルが出てこない

**A**:

**Step 1**: gRPC 接続確認
```powershell
# Receiver の gRPC ポートが LISTENING か確認
netstat -ano | findstr :50051

# Sender から Receiver への疎通確認
Test-NetConnection -ComputerName <receiver-host> -Port 50051
```

**Step 2**: `[receiver].addr` 設定の確認
```toml
# Sender 側の設定
[receiver]
addr = "192.168.1.100:50051"   # IP アドレスで指定（DNS 未解決時）
# addr = "misogi-receiver:50051"  # DNS 名（名前解決可能な場合）
```

**Step 3**: ファイアウォール確認
```powershell
# Receiver 側でポート 50051 が許可されているか
Get-NetFirewallRule -DisplayName "Misogi*gRPC"
```

**Step 4**: Receiver ログ確認
```powershell
# Receiver 側のログに gRPC 受信記録があるか
Select-String -Path .\logs\receiver.log -Pattern "gRPC|chunk|receive"
```

---

### Q3: PDF ファイルの CDR 処理が失敗する

**症状**: PDF アップロード時に `CdrSanitizationFailure` エラー

**A**:

**原因 1**: PDF CDR 機能が無効でビルドされている
```bash
# PDF CDR 機能付きでビルドし直す
cargo build --release --features pdf-cdr
```

**原因 2**: PDF がパスワード保護されている
- Misogi は現時点でパスワード保護 PDF の処理をサポートしていません
- 送信者にパスワード解除を依頼してください

**原因 3**: PDF が深刻に破損している
```powershell
# PDF の構造検証（簡易）
$fileBytes = [System.IO.File]::ReadAllBytes("test.pdf")
$header = [System.Text.Encoding]::ASCII.GetString($fileBytes[0..4])
Write-Host "PDF Header: $header"
# 正常: "%PDF-"
```

---

### Q4: 一太郎 (.jtd) ファイルが変換できない

**症状**: JTD アップロード時に `JtdConversionError` または `ConverterNotFound`

**A**:

**確認チェックリスト**:
- [ ] LibreOffice がインストールされている (`soffice.exe --version`)
- [ ] `[jtd_converter].enabled = true` になっている
- [ ] `[jtd_converter].type = "libreoffice"` （または `"ichitaro_viewer"`）
- [ ] ディスクに十分な空き容量がある（元ファイルの 3〜5 倍）
- [ ] JTD ファイル自体が破損していない（一太郎で正常に開けるか）

**詳細なデバッグ**:
```powershell
# LibreOffice で直接変換できるかテスト
& "C:\Program Files\LibreOffice\program\soffice.exe" `
    --headless --convert-to pdf --outdir . "test.jtd"

# 上記が失敗する場合、LibreOffice 側の問題
# 成功する場合、Misogi の呼び出し方に問題
```

→ 詳細は [JTD コンバーター設定ガイド](../configuration/jtd-converter.md) を参照

---

### Q5: マイナンバーが検出されない

**症状**: 明らかにマイナンバー（12桁数字）を含むファイルで PII 検出されない

**A**:

**原因 1**: PII 検出が無効
```toml
# 確認
[pii]
enabled = true    # true になっているか
```

**原因 2**: エンコーディングの問題（Shift-JIS ファイル等）
```powershell
# Shift-JIS ファイルの場合、PII エンジンが正しく読めていない可能性
# log_level = "debug" で encoding 関連のログを確認
```

**原因 3**: マイナンバーが画像内に埋め込まれている
- Misogi の PII 検出は**テキストベース**です
- 画像化されたマイナンバーは検出できません
- OCR 連携は将来の拡張予定です

**原因 4**: 数字が 12 桁ではない、または区切り文字を含む
- 正規表現 `\b\d{12}\b` なので、ハイフン区切りの `123-456-789-012` は❌
- 連続した 12 桁数字 `123456789012` のみ✅

---

### Q6: 処理が極端に遅い

**症状**: 小さいファイルでも数分以上かかる

**A**:

| ボトルネック候診 | 確認方法 | 対策 |
|---------------|---------|------|
| ディスク I/O | Resource Monitor でディスクアクティビティ確認 | SSD 移行、`storage_dir` を高速ディスクに |
| CPU 不足 | Task Manager で CPU 使用率確認 | コア数増加、並列処理数調整 |
| JTD 変換 | LibreOffice プロセスの CPU/メモリ確認 | `timeout_seconds` 増加、LibreOffice チューニング |
| ネットワーク帯域 | `iperf` 等で帯域測定 | `chunk_size` 増加、ネットワーク設備増強 |
| アンチウイルス | リアルタイムスキャンの除外設定 | Misogi ディレクトリをスキャン除外に追加 |

**アンチウイルス除外設定例**:
```powershell
# Windows Defender に Misogi 関連パスを除外追加
Add-MpPreference -ExclusionPath "C:\ProgramData\Misogi"
Add-MpPreference -ExclusionProcess "misogi-sender.exe"
Add-MpPreference -ExclusionProcess "misogi-receiver.exe"
```

---

### Q7: 監査ログが書き込まれない

**症状**: ファイル転送は成功するが、監査ログファイルが空、または更新されない

**A**:

**確認項目**:
```powershell
# 1. 監査ログ設定の確認
# [audit_log] セクションで enabled = true になっているか

# 2. ログディレクトリの権限
icacls "C:\ProgramData\Misogi\logs" 
# Misogi 実行ユーザーに書き込み権限があるか

# 3. ディスク容量
Get-PSDrive C | Select-Object Free
# 空き容量が十分か

# 4. ログローテション（ファイルサイズ上限）
# 設定で max_log_size を超えている場合、ローテーションされている可能性
```

---

### Q8: Active Directory 認証が失敗する

**症状`: ユーザーログイン時に `AuthenticationError`

**A**:

**Step 1**: LDAP URL の確認
```toml
# ldaps:// (ポート 636) か ldap:// (ポート 389) か
url = "ldaps://dc01.example.com:636"
```

**Step 2**: Bind DN とパスワード
```powershell
# サービスアカウントの資格情報が正しいか
# パスワード有効期限切れを確認
Get-ADUser -Identity MisogiService | Select-Object Enabled, PasswordExpired
```

**Step 3**: ネットワーク疎通
```powershell
Test-NetConnection -ComputerName dc01.example.com -Port 636
```

**Step 4**: TLS 証明書
```powershell
# 自己署名 CA の場合、ca_cert_path が正しいか
Test-Path "C:\certs\ad-ca.crt"
```

→ 詳細は [Active Directory 連携ガイド](../configuration/active-directory.md) を参照

---

## 3. 診断情報の収集方法

### 3-1: 標準診断情報パッケージ

サポート窓口へ問い合わせる前に、以下の診断情報を収集してください。

```powershell
# ============================================================
# Misogi Diagnostic Information Collector
# サポート問い合わせ前に実行してください。
# 出力: misogi-diag-YYYYMMDD-HHMMSS.zip
# ============================================================

$diagDir = "misogi-diag-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
New-Item -ItemType Directory -Path $diagDir -Force | Out-Null

Write-Host "診断情報を収集中..." -ForegroundColor Cyan

# --- 1. システム情報 ---
systeminfo | Out-File "$diagDir\systeminfo.txt"
(Get-CimInstance Win32_OperatingSystem).Caption | Out-File -Append "$diagDir\systeminfo.txt"

# --- 2. Misogi バージョン ---
.\target\release\misogi-sender.exe --version 2>&1 | Out-File "$diagDir\version.txt"
.\target\release\misogi-receiver.exe --version 2>&1 | Out-File -Append "$diagDir\version.txt"

# --- 3. 設定ファイル ---
Copy-Item ".\misogi-sender.toml" "$diagDir\" -Force
# 注意: パスワード等の機密情報をマスクしてください
Copy-Item ".\misogi-receiver.toml" "$diagDir\" -Force

# --- 4. 最近のログ（最新 1000 行）---
if (Test-Path ".\logs") {
    Copy-Item ".\logs" "$diagDir\logs" -Recurse -Force
}

# --- 5. ネットワーク状態 ---
netstat -an | Out-File "$diagDir\netstat.txt"
ipconfig /all | Out-File "$diagDir\ipconfig.txt"

# --- 6. ファイアウォールルール ---
Get-NetFirewallRule -DisplayName "Misogi*" |
    Format-Table DisplayName, Enabled, Direction, Action -AutoSize |
    Out-File "$diagDir\firewall.txt"

# --- 7. プロセス状態 ---
Get-Process -Name "misogi*" -ErrorAction SilentlyContinue |
    Format-Table Id, ProcessName, CPU, WorkingSet64 -AutoSize |
    Out-File "$diagDir\processes.txt"

# --- 8. ディスク状態 ---
Get-PSDrive C | Out-File "$diagDir\disk.txt"
Get-ChildItem ".\storage" -Recurse -ErrorAction SilentlyContinue |
    Measure-Object -Property Length -Sum |
    Out-File "$diagDir\storage-usage.txt"

# --- 圧縮 ---
Compress-Archive -Path "$diagDir\*" -DestinationPath "$diagDir.zip" -Force
Remove-Item $diagDir -Recurse -Force

Write-Host ""
Write-Host "診断情報収集完了: $diagDir.zip" -ForegroundColor Green
Write-Host "このファイルをサポート窓口へ添付してください。" -ForegroundColor Yellow
```

### 3-2: 收集时应注意的事项

| 項目 | 注意点 |
|------|--------|
| **機密情報のマスク** | 設定ファイル中のパスワード、API キー、AD bind パスワードを `****` に置換 |
| **個人情報** | ログ中に実ユーザー名、IP アドレス等が含まれる場合は要配慮 |
| **ファイルサイズ** | ログファイルが大きすぎる場合は最新部分のみ抽出 |
| **転送安全** | 診断ファイルは暗号化チャネル（HTTPS/SFTP）で送信 |

---

## 4. サポート窓口への連絡タイミング

### 4-1: 自助で解決できない場合

以下の場合、サポート窓口への連絡を推奨します。

| 状況 | 緊急度 | 対応 |
|------|--------|------|
| システム完全停止（P1） | 🔴 至急 | 電話 + 診断ファイル |
| セキュリティインシデント発生 | 🔴 至急 | 電話 + インシデント報告書 |
| データ損失の疑い | 🟠 早急 | チケット + 診断ファイル |
| 再現不可能な间歇性エラー | 🟡 通常 | チケット + 診断ファイル + 再現手順 |
| 機能要望・改善提案 | 🔵 低 | チケット（次期開発サイクルで検討） |

### 4-2: 問い合わせ時に準備する情報

1. **エラーの正確なメッセージ**（コピー＆ペースト）
2. **再現手順**（どのような操作で発生したか）
3. **診断情報パッケージ**（上記スクリプトで生成）
4. **発生頻度**（常に発生 / 间歇的 / 初回のみ）
5. **影響範囲**（全ユーザー影響 / 特定ユーザーのみ）
6. **直近の変更**（設定変更 / アップデート / メンテナンス）

---

*関連ドキュメント: [日常運用手順書](daily-operation.md) | [CLI コマンドリファレンス](../api-reference/cli-reference.md)*
