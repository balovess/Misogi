# Windows Server 2022 インストールガイド

本ガイドは、Windows Server 2022 への Misogi（禊ぎ）インストール手順を、
ステップバイステップで詳しく解説します。各手順には期待される出力例と、
よくあるエラーへの対処法を含めています。

**対象読者**: SIer 担当者、システム管理者  
**所要時間**: 約 30〜60 分（環境により異なる）  
**前提条件**: [前提条件チェックリスト](prerequisites.md) を完了していること

---

## Step 1: PowerShell 環境の準備

### 1-1. 管理者権限で PowerShell を起動

1. スタートボタンを右クリック
2. 「**Windows PowerShell (管理者)**」または「**ターミナル (管理者)**」を選択

> **[スクリーンショット placeholder]**
> スタートメニュー右クリック時のコンテキストメニュー
> 「Windows PowerShell (管理者)」が表示されている状態

### 1-2. 実行ポリシーを確認・変更

Misogi のビルドスクリプトおよびインストールスクリプトを実行するために、
PowerShell の実行ポリシーを確認・変更します。

```powershell
# 現在の実行ポリシーを確認
Get-ExecutionPolicy
```

**期待される出力**:
```
Restricted    ← デフォルト（制限あり）
```

```powershell
# 実行ポリシーを RemoteSigned に変更（管理者権限が必要）
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force

# 変更確認
Get-ExecutionPolicy
```

**期待される出力**:
```
RemoteSigned
```

### 1-3. 管理者権限の確認

```powershell
# 現在のユーザーが管理者権限を持っているか確認
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
```

**期待される出力**:
```
True
```

`False` が返る場合は、PowerShell を管理者として再起動してください。

---

## Step 2: Rust Toolchain のインストール

### 2-1. rustup のダウンロードと実行

```powershell
# rustup 初期化ツールをダウンロード
Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile "$env:TEMP\rustup-init.exe"

# インストーラーを実行（対話モード）
& "$env:TEMP\rustup-init.exe"
```

> **[スクリーンショット placeholder]**
> rustup-init.exe 実行時のインストール画面
> 「1) Proceed with installation (default)」を選択した状態

### 2-2. インストールオプションの選択

対話的なインストーラーが起動します。以下の選択を推奨します：

| 選択項目 | 推奨値 | 説明 |
|---------|--------|------|
| Default installation | `1` (Enter) | デフォルトのまま進む |
| Modify PATH variable | `Y` | 環境変数 PATH に追加する |

**非対話的（サイレント）インストール**の場合：

```powershell
# 自動応答モードでインストール（CI/CD 環境向け）
& "$env:TEMP\rustup-init.exe" -y --default-toolchain stable
```

### 2-3. インストール結果の確認

```powershell
# 新しい環境変数を反映（再起動せずに即時反映）
$env:PATH = [Environment]::GetEnvironmentVariable("Path", "User") + ";" + [Environment]::GetEnvironmentVariable("Path", "Machine")

# バージョン確認
rustc --version
cargo --version
rustup --version
```

**期待される出力例**:
```
rustc 1.84.0 (66221ab985 2024-11-19)
cargo 1.84.0 (66221ab98 2024-11-19)
rustup 1.27.1 (54dd3d00f 2024-04-24)
```

> **⚠️ 注意**: バージョンはインストール時期により異なりますが、
> **Rust 1.75.0 以降**（Edition 2024 対応）であることを確認してください。

### 2-4. よくあるエラーと解決策

| エラー症状 | 原因 | 解決策 |
|-----------|------|--------|
| `'rustc' が認識されていません` | PATH が反映されていない | PowerShell を再起動、または `$env:PATH` を再設定 |
| SSL/TLS エラーが発生 | 社内プロキシの証明書問題 | `[System.Net.ServicePointManager]::SecurityProtocol = ...` でプロトコル設定 |
| ダウンロードがタイムアウト | ファイアウォール/プロキシ | 社内プロキシ設定を `$env:HTTP_PROXY` / `$env:HTTPS_PROXY` に指定 |
| Access Denied | 書き込み権限不足 | 管理者権限で実行しているか確認 |

---

## Step 3: ソースコードの取得とビルド

### 3-1. Git によるリポジトリのクローン

```powershell
# 作業ディレクトリを作成
New-Item -ItemType Directory -Path "C:\Misogi" -Force
Set-Location "C:\Misogi"

# リポジトリをクローン
git clone https://github.com/balovess/Misogi.git .
```

> **[スクリーンショット placeholder]**
> git clone 実行中の PowerShell 画面
> 「Cloning into '.'...」からの進捗表示

**Git が未インストールの場合**:

```powershell
# winget で Git をインストール
winget install Git.Git

# インストール後、PowerShell を再起動
```

### 3-2. 依存関係のビルド（初回のみ時間がかかります）

```powershell
# リリースビルド（最適化有効）
cargo build --release
```

**期待される出力（抜粋）**:
```
Compiling misogi-core v0.1.0 (C:\Misogi\crates\misogi-core)
Compiling misogi-sender v0.1.0 (C:\Misogi\crates\misogi-sender)
Compiling misogi-receiver v0.1.0 (C:\Misogi\crates\misogi-receiver)
Compiling misogi-cdr v0.1.0 (C:\Misogi\crates\misogi-cdr)
    Finished release [optimized] target(s) in 5m 23s
```

> **💡 所要時間の目安**:
> - 初回ビルド: 5〜15 分（インターネット速度・CPU による）
> - 2回目以降: 30 秒〜2 分（変更分のみ再コンパイル）

### 3-3. ビルド成果物の確認

```powershell
# 生成されたバイナリを確認
Get-ChildItem "target\release\misogi-sender.exe"
Get-ChildItem "target\release\misogi-receiver.exe"

# バージョン情報の確認（--help で代替）
.\target\release\misogi-sender.exe --version
```

**期待される出力**:
```
    Directory: C:\Misogi\target\release
Mode                 LastWriteTime Length Name
----                 ------------- ------ ----
-a---          2024/01/15    14:32  3258240 misogi-sender.exe
-a---          2024/01/15    14:33  3187200 misogi-receiver.exe
```

### 3-4. よくあるビルドエラー

| エラー | 原因 | 解決策 |
|-------|------|--------|
| `error[E0463]: can't find crate for XXX` | Cargo 依存関係解決失敗 | `cargo clean && cargo build --release` を再実行 |
| `linker 'link.exe' not found` | Visual Studio Build Tools 未インストール | `winget install Microsoft.VisualStudio.2022.BuildTools --override "--add Microsoft.VisualStudio.Workload.VCTools"` |
| `Protobuf code generation failed` | protoc 未インストールまたは PATH なし | [前提条件](prerequisites.md) の protoc セクション参照 |
| Out of memory | メモリ不足 | 一時的に `cargo build --release -j 1` で並列数を減らす |

---

## Step 4: LibreOffice のサイレントインストール（JTD サポート用）

一太郎 (.jtd) ファイルのサポートには LibreOffice が必要です。
JTD を使用しない場合は、このステップをスキップできます。

### 4-1. LibreOffice のダウンロード

公式サイトから最新のインストーラーを取得してください：
https://www.libreoffice.org/download/download-libreoffice/

> **推奨バージョン**: LibreOffice 24.2 以降（.jtd インポートフィルターの品質向上版）

### 4-2. サイレントインストールの実行

```powershell
# MSI インストーラーを使用した静默インストール
# 管理者権限が必要です
$libreofficeMsi = "C:\temp\LibreOffice_24.2.5_Win_x64.msi"

if (Test-Path $libreofficeMsi) {
    msiexec /i $libreofficeMsi /quiet /norestart ADDLOCAL=ALL
    Write-Host "LibreOffice インストールを開始しました..."
} else {
    Write-Warning "LibReOffice MSI ファイルが見つかりません: $libreofficeMsi"
}
```

### 4-3. インストール確認

```powershell
# LibreOffice のインストール確認
$sofficePath = "C:\Program Files\LibreOffice\program\soffice.exe"
if (Test-Path $sofficePath) {
    & $sofficePath --version
    Write-Host "LibReOffice インストール確認: OK"
} else {
    Write-Warning "LibReOffice が見つかりません。PATH を確認してください。"
}
```

**期待される出力**:
```
LibreOffice 24.2.5.2 50(build:2)
LibReOffice インストール確認: OK
```

### 4-4. LibreOffice への PATH 追加

```powershell
# システム環境変数に LibreOffice を追加
$libreofficeDir = "C:\Program Files\LibreOffice\program"
$currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($currentPath -notlike "*LibreOffice*") {
    [Environment]::SetEnvironmentVariable("Path", "$currentPath;$libreofficeDir", "Machine")
    Write-Host "LibReOffice を PATH に追加しました"
}
```

---

## Step 5: ファイアウォールポートの設定

### 5-1. 必要なポートの確認

Misogi が使用するデフォルトポート:

| サービス | ポート | プロトコル |
|---------|--------|----------|
| Sender HTTP API | 3000 | TCP |
| Receiver HTTP API | 3001 | TCP |
| gRPC 通信 | 50051 | TCP |

### 5-2. Windows Defender ファイアウォールの設定

```powershell
# ============================================================
# Misogi 用ファイアウォールルール作成スクリプト
# 管理者権限で実行してください
# ============================================================

# --- Sender HTTP API (Port 3000) ---
New-NetFirewallRule -DisplayName "Misogi Sender HTTP API" `
    -Description "Allow inbound HTTP traffic for Misogi Sender file upload API" `
    -Direction Inbound -Protocol TCP -LocalPort 3000 -Action Allow `
    -Profile Domain,Private

# --- Receiver HTTP API (Port 3001) ---
New-NetFirewallRule -DisplayName "Misogi Receiver HTTP API" `
    -Description "Allow inbound HTTP traffic for Misogi Receiver download API" `
    -Direction Inbound -Protocol TCP -LocalPort 3001 -Action Allow `
    -Profile Domain,Private

# --- gRPC Streaming (Port 50051) ---
New-NetFirewallRule -DisplayName "Misogi gRPC Channel" `
    -Description "Allow bidirectional gRPC streaming between Sender and Receiver" `
    -Direction Inbound -Protocol TCP -LocalPort 50051 -Action Allow `
    -Profile Domain,Private

Write-Host "ファイアウォールルールを 3 件作成しました" -ForegroundColor Green
```

**期待される出力**:
```
ファイアウォールルールを 3 件作成しました
```

### 5-3. ルール作成の確認

```powershell
# 作成されたルールの確認
Get-NetFirewallRule -DisplayName "Misogi*" | Format-Table DisplayName, Enabled, Direction, Action -AutoSize
```

**期待される出力**:
```
DisplayName                    Enabled Direction Action
-----------                    ------- --------- ------
Misogi Sender HTTP API            True  Inbound   Allow
Misogi Receiver HTTP API          True  Inbound   Allow
Misogi gRPC Channel               True  Inbound   Allow
```

> **[スクリーンショット placeholder]**
> 「Windows Defender ファイアウォール → 受信の規則」画面
> Misogi 関連の 3 件のルールが表示され、有効になっている状態

### 5-4. （オプション）TLS/SSL のための追加ポート

HTTPS を使用する場合（リバースプロキシ経由等）、追加でポート 443 を許可してください。

---

## Step 6: 初回起動と動作確認

### 6-1. 設定ファイルの作成

まず、最小限の設定ファイルを作成します。
詳細な設定については [基本設定ガイド](../configuration/basic-config.md) を参照してください。

**Sender 設定ファイル** (`misogi-sender.toml`):

```toml
[server]
addr = "0.0.0.0:3000"
storage_dir = "./storage/sender"
chunk_size = 1048576
log_level = "info"

[receiver]
addr = "127.0.0.1:50051"

[cdr]
enabled = true
sanitizers = ["pdf", "ooxml", "zip"]

[jtd_converter]
type = "libreoffice"
enabled = true

[pii]
enabled = true
action_on_detect = "mask"

[audit_log]
enabled = true
format = "json"
output_path = "./logs/sender_audit.log"
```

**Receiver 設定ファイル** (`misogi-receiver.toml`):

```toml
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

### 6-2. 必要なディレクトリの作成

```powershell
# 必要なディレクトリ構造を作成
$dirs = @(
    "./storage/sender",
    "./storage/receiver",
    "./downloads",
    "./logs"
)

foreach ($dir in $dirs) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    Write-Host "ディレクトリ作成: $(Resolve-Path $dir)"
}
```

### 6-3: Sender の起動

```powershell
# Sender をサーバーモードで起動
.\target\release\misogi-sender.exe server --config .\misogi-sender.toml
```

**期待される出力**:
```
  _ __  _ __ _____      _____  ___ _ ____   _____ _ __
 | '_ \| '__/ _ \ \ /\ / / __|/ _ \ '__\ \ / / _ \ '_ \
 | |_) | | | (_) \ V  V /\__ \  __/ |   \ V /  __/ | | |
 | .__/|_|  \___/ \_/\_/ |___/\___|_|    \_/ \___|_| |_|
 |_|              CDR Secure File Transfer System

[INFO] Starting Misogi Sender...
[INFO] Loading configuration from .\misogi-sender.toml
[INFO] HTTP server listening on 0.0.0.0:3000
[INFO] gRPC tunnel endpoint: 127.0.0.1:50051
[INFO] CDR engine initialized: sanitizers=[pdf, ooxml, zip]
[INFO] PII detector initialized: rules=[my_number, email, ip_address_v4, credit_card, phone_jp, postal_code_jp, drivers_license]
[INFO] Audit log engine started: format=json
[INFO] JTD converter: type=libreoffice, enabled=true
[INFO] Misogi Sender is ready. Press Ctrl+C to stop.
```

> **[スクリーンショット placeholder]**
> PowerShell 上で misogi-sender が正常に起動し、
> 「Misogi Sender is ready」と表示されている状態

### 6-4: Receiver の起動（別ターミナル）

新しい PowerShell ウィンドウを開き、Receiver を起動します。

```powershell
# 別の PowerShell ウィンドウで Receiver を起動
Set-Location "C:\Misogi"
.\target\release\misogi-receiver.exe server --config .\misogi-receiver.toml
```

**期待される出力**:
```
  _ __  _ __ _____      _____  ___ _ ____   _____ _ __
 | '_ \| '__/ _ \ \ /\ / / __|/ _ \ '__\ \ / / _ \ '_ \
 | |_) | | | (_) \ V  V /\__ \  __/ |   \ V /  __/ | | |
 | .__/|_|  \___/ \_/\_/ |___/\___|_|    \_/ \___|_| |_|
 |_|              CDR Secure File Transfer System

[INFO] Starting Misogi Receiver...
[INFO] Loading configuration from .\misogi-receiver.toml
[INFO] HTTP server listening on 0.0.0.0:3001
[INFO] gRPC tunnel listening on 0.0.0.0:50051
[INFO] Storage directory: ./storage/receiver
[INFO] Download directory: ./downloads
[INFO] Audit log engine started: format=json
[INFO] Misogi Receiver is ready. Press Ctrl+C to stop.
```

### 6-5: 動作確認（簡易テスト）

Sender が起動しているターミナルで、別の PowerShell を開いてテストします。

```powershell
# テスト用ファイルの作成
"これはテストファイルです。" | Out-File -Encoding UTF8 "test-document.txt"

# HTTP API 経由でファイルアップロード（簡易テスト)
Invoke-RestMethod -Uri "http://localhost:3000/api/v1/files" `
    -Method Post `
    -Form @{file="test-document.txt"} `
    -ContentType "multipart/form-data"
```

**期待される出力**:
```json
{
  "file_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "filename": "test-document.txt",
  "status": "uploaded",
  "size": 28
}
```

---

## よくある問題と解決集

### 問題 1: ポートが既に使用中

**エラーメッセージ**:
```
Error: bind address 0.0.0.0:3000 already in use
```

**解決策**:
```powershell
# ポート 3000 を使用しているプロセスを特定
netstat -ano | findstr :3000

# PID を特定して終了（必要な場合）
Stop-Process -Id <PID> -Force

# または設定ファイルでポート番号を変更
# [server] addr = "0.0.0.0:3001" など
```

### 問題 2: CDR エンジンの初期化失敗

**エラーメッセージ**:
```
Error: Failed to initialize CDR engine: sanitizer not found: pdf
```

**解決策**:
- `cargo build --release --features pdf-cdr` で PDF CDR 機能を有効にしてビルド
- 設定ファイルの `[cdr].sanitizers` から `"pdf"` を削除（PDF CDR 不要の場合）

### 問題 3: LibreOffice が見つからない

**エラーメッセージ**:
```
Error: JTD converter failed: LibreOffice executable not found
```

**解決策**:
1. LibreOffice が正しくインストールされているか確認
2. PATH に LibreOffice の program ディレクトリが含まれているか確認
3. 設定ファイルで `[jtd_converter].libreoffice_path` を明示的に指定

### 問題 4: 監査ログの書き込みエラー

**エラーメッセージ**:
```
Error: Cannot write audit log: Permission denied
```

**解決策**:
```powershell
# ログディレクトリの権限を確認・修正
icacls "./logs" /grant "MisogiService:(OI)(CI)F"
```

### 問題 5: gRPC 接続タイムアウト

**エラーメッセージ**:
```
Error: gRPC connection to receiver timed out
```

**解決策**:
1. Receiver が起動しているか確認
2. `[receiver].addr` のホスト名/ポートが正しいか確認
3. ファイアウォールでポート 50051 が許可されているか確認

---

## インストール完了チェックリスト

- [ ] Rust toolchain がインストールされ、`rustc --version` で確認できる
- [ ] `cargo build --release` がエラーなく完了する
- [ ] `misogi-sender.exe` および `misogi-receiver.exe` が生成されている
- [ ] ファイアウォールルールが 3 件作成されている
- [ ] 設定ファイル (misogi-sender.toml, misogi-receiver.toml) が作成されている
- [ ] 必要なディレクトリ (storage, downloads, logs) が存在する
- [ ] Sender が起動し、「Misogi Sender is ready」と表示される
- [ ] Receiver が起動し、「Misogi Receiver is ready」と表示される
- [ ] 簡易アップロードテストで HTTP 200 応答が返ってくる

---

*次のステップ: [基本設定ガイド](../configuration/basic-config.md) で詳細な設定を行ってください*
