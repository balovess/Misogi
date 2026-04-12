# 前提条件チェックリスト (Prerequisites Checklist)

Misogi（禊ぎ）をインストールする前に、以下の要件を確認してください。
本チェックリストは、SIer 担当者が内部承認書類を作成する際の参考資料としてもご利用いただけます。

---

## 1. サポート対象 OS

### 1-1. Windows Server

| 項目 | 要件 | 備考 |
|------|------|------|
| OS | Windows Server 2019 / 2022 | Datacenter / Standard Edition 両対応 |
| アーキテクチャ | x64 (AMD64) | ARM64 は現時点で非サポート |
| 言語パック | 日本語 | 日本語ロケールで動作確認済み |
| 更新プログラム | 最新の累積更新プログラム適用済み | セキュリティ修正を含む |

**推奨構成**: Windows Server 2022 Standard Edition

> **[スクリーンショット placeholder]**
> Windows Server 2022 の「設定 → システム → バージョン情報」画面
> バージョン: 21H2 (OS ビルド 20348.x) 以上であることを確認

### 1-2. Linux (RHEL / Ubuntu)

| OS | バージョン | サポート状況 |
|----|----------|------------|
| Red Hat Enterprise Linux (RHEL) | 8.x, 9.x | ✅ 公式サポート |
| Ubuntu Server | 22.04 LTS, 24.04 LTS | ✅ 公式サポート |
| CentOS Stream | 9 | △ ベストエフォート |
| Debian | 12 (Bookworm) | △ ベストエフォート |

---

## 2. ハードウェア要件

### 2-1. 最小構成（テスト/検証環境）

| リソース | 最小値 | 備考 |
|---------|-------|------|
| CPU | 2 コア | x86_64 アーキテクチャ |
| メモリ (RAM) | 4 GB | CDR 処理時に一時的に増加 |
| ディスク容量 | 20 GB | システム + 一時ファイル用 |
| ネットワーク | 100 Mbps | 内部通信用 |

### 2-2. 推奨構成（本番環境）

| リソース | 推奨値 | 備考 |
|---------|-------|------|
| CPU | 4 コア以上 | CDR エンジンの並列処理に有利 |
| メモリ (RAM) | 8 GB 以上 | 大容量ファイル処理時のバッファ確保 |
| ディスク容量 | 100 GB 以上 | SSD 推奨（I/O 性能重視） |
| ネットワーク | 1 Gbps | ファイル転送帯域 |
| 冗長化 | RAID 1 / RAID 10 | データ保護のため推奨 |

### 2-3. 高負荷環境向け（大規模導入）

| リソース | 推奨値 | 対象シナリオ |
|---------|-------|------------|
| CPU | 8 コア以上 | 同時 50+ ファイル処理 |
| メモリ | 16 GB+ | 100MB+ の大容量ファイル頻繁処理 |
| ディスク | SSD NVMe | 高スループット要求時 |
| ネットワーク | 10 Gbps | バッチ転送運用 |

---

## 3. ソフトウェア依存関係

### 3-1. 必須ソフトウェア

#### Rust Toolchain (rustup)

Misogi は Rust プログラミング言語で開発されています。ビルドには Rust toolchain が必要です。

```powershell
# インストール方法 (Windows)
winget install Rustlang.Rustup

# または手動ダウンロード
# https://rustup.rs/ から rustup-init.exe を取得し実行

# インストール後の確認
rustc --version    # 期待出力: rustc 1.xx.x (xxxx-xx-xx)
cargo --version    # 期待出力: cargo 1.xx.x (xxxx-xx-xx)
```

**必要なコンポーネント**:
- `rustc` — Rust コンパイラ（Edition 2024 対応）
- `cargo` — パッケージマネージャーおよびビルドツール
- `rust-std` — 標準ライブラリ
- `rustfmt` — コードフォーマッタ（開発時）

#### Protocol Buffers Compiler (protoc)

gRPC サービス定義のコンパイルに必要です。

```powershell
# Windows (Chocolatey)
choco install protoc

# または手動ダウンロード
# https://github.com/protocolbuffers/protobuf/releases

# インストール後の確認
protoc --version   # 期待出力: libprotoc 3.x.x
```

### 3-2. 条件付き必須ソフトウェア

#### LibreOffice（JTD サポートの場合）

日本固有文書形式 **一太郎 (.jtd)** を PDF に変換する場合、LibreOffice が必要です。

```powershell
# Windows (静默インストール - 管理者権限が必要)
# LibreOffice 24.2 以降を推奨
msiexec /i LibreOffice_24.2.x_Win_x64.msi /quiet /norestart
```

**必要な理由**: Misogi の JTD コンバーターは、LibreOffice の `--headless --convert-to pdf` コマンドを
内部呼び出しすることで .jtd ファイルを安全な PDF 形式に変換します。

#### .NET Runtime（一太郎ビューア使用時）

JustSystem 社の一太郎ビューアを使用して JTD を変換する場合、.NET Runtime が必要です。

```powershell
# .NET 8.0 Runtime (Windows Hosting)
winget install Microsoft.DotNet.HostingBundle.8
```

### 3-3. 任意のソフトウェア

| ソフトウェア | 用途 | 推奨バージョン |
|------------|------|-------------|
| Git | ソースコード管理 | 2.40+ |
| Visual Studio Build Tools | C++ ビルドツール（依存関係） | 2022 |
| PowerShell 7+ | 高度な管理操作 | 7.4+ |
| 7-Zip | アーカイブ展開 | 23.01+ |

---

## 4. ネットワーク要件

### 4-1. ファイアウォールポート

Misogi が使用するポートとその用途です。ファイアウォール設定時に参照してください。

| ポート | プロトコル | 方向 | 用途 | 必須 |
|-------|----------|------|------|------|
| 3000 | TCP | Inbound | Sender HTTP API（ファイルアップロード受付） | ✅ |
| 3001 | TCP | Inbound | Receiver HTTP API（ファイルダウンロード） | ✅ |
| 50051 | TCP | 双方向 | gRPC ストリーミング（Sender ↔ Receiver） | ✅ |
| 8080 | TCP | Inbound | Admin Dashboard HTTP（将来拡張用） | △ |

### 4-2. ポート開放コマンド（Windows Firewall）

```powershell
# 管理者権限で PowerShell を起動し実行

# Sender HTTP API ポート (3000)
New-NetFirewallRule -DisplayName "Misogi-Sender-API" `
    -Direction Inbound -Protocol TCP -LocalPort 3000 -Action Allow

# Receiver HTTP API ポート (3001)
New-NetFirewallRule -DisplayName "Misogi-Receiver-API" `
    -Direction Inbound -Protocol TCP -LocalPort 3001 -Action Allow

# gRPC ポート (50051)
New-NetFirewallRule -DisplayName "Misogi-gRPC" `
    -Direction Inbound -Protocol TCP -LocalPort 50051 -Action Allow
```

### 4-3. 通信フロー図

```
  [外部ユーザー]
       │
       │ HTTPS (443) ※リバースプロキシ経由の場合
       ▼
  ┌──────────────────────────────┐
  │   DMZ / 外部ネットワーク        │
  │                               │
  │  ┌─────────────────────┐     │
  │  │ Misogi Sender       │     │
  │  │ :3000 (HTTP Upload) │     │
  │  └──────────┬──────────┘     │
  │             │ gRPC (:50051)  │
  └─────────────┼────────────────┘
                │
         ┌──────┴──────┐
         │  ファイアウォール │
         │  (許可ポート)  │
         └──────┬──────┘
                │
  ┌─────────────┼────────────────┐
  │  業務用イントラネット          │
  │                             │
  │  ┌─────────────────────┐   │
  │  │ Misogi Receiver     │   │
  │  │ :3001 (Download)    │   │
  │  └─────────────────────┘   │
  │                             │
  └─────────────────────────────┘
```

---

## 5. 権限要件

### 5-1. OS レベルの権限

| 操作 | 必要な権限 | 備考 |
|------|-----------|------|
| インストール | 管理者 (Administrator) | システムディレクトリへの書き込み |
| サービス登録 | 管理者 (Administrator) | Windows Service として動作させる場合 |
| ファイアウォール設定 | 管理者 (Administrator) | ポート開放 |
| 通常運用 | 標準ユーザー可 | 専用サービスアカウント推奨 |

### 5-2. 推奨サービスアカウント

本番環境では、以下のように専用のサービスアカウントを作成することを強く推奨します。

```powershell
# 専用サービスアカウントの作成例
$Password = ConvertTo-SecureString "Strong_P@ssw0rd_Here!" -AsPlainText -Force
New-LocalUser -Name "MisogiService" -Password $Password `
    -FullName "Misogi Service Account" `
    -Description "Service account for Misogi CDR system"
```

**最小権限の原則**:
- ドメイン管理者権限は不要
- ローカル Administrators グループへの所属は不要
- 必要なのは：ターゲットディレクトリへの読み書き権限、ネットワーク通信権限のみ

### 5-3. ディレクトリ権限

| パス | 必要なアクセス権 | 用途 |
|------|---------------|------|
| `<install_dir>` | 読み取り・実行 | プログラム本体 |
| `<storage_dir>` | 読み取り・書き込み | 一時ファイル・チャンク保存 |
| `<download_dir>` | 読み取り・書き込み | 受信ファイルの出力先 |
| `<log_dir>` | 読み取り・書き込み | ログファイル出力 |
| `<config_dir>` | 読み取り | 設定ファイル |

---

## 6. 事前チェックリスト（SIer 用承認書類添付用）

以下のチェックリストを印刷し、各項目を確認後に署名してください。

### □ システム要件チェック

- [ ] OS は Windows Server 2019/2022 または RHEL 8+/Ubuntu 22.04+ である
- [ ] OS は最新のセキュリティ更新プログラムが適用されている
- [ ] CPU は x64 アーキテクチャである
- [ ] RAM は 4GB 以上確保されている（本番では 8GB+ 推奨）
- [ ] ディスク空き容量は 20GB 以上ある（本番では 100GB+ 推奨）

### □ ソフトウェアチェック

- [ ] Rust toolchain (rustup) がインストールされている (`rustc --version` 確認)
- [ ] cargo が利用可能である (`cargo --version` 確認)
- [ ] protoc (Protocol Buffers Compiler) がインストールされている
- [ ] JTD サポートが必要な場合: LibreOffice がインストールされている
- [ ] JTD サポートで一太郎ビューアを使用する場合: .NET Runtime がインストールされている

### □ ネットワークチェック

- [ ] ポート 3000 (Sender HTTP) がファイアウォールで許可されている
- [ ] ポート 3001 (Receiver HTTP) がファイアウォールで許可されている
- [ ] ポート 50051 (gRPC) がファイアウォールで許可されている
- [ ] Sender から Receiver へのネットワーク疎通が確認できている

### □ 権限チェック

- [ ] インストール作業を行うアカウントに管理者権限がある
- [ ] 運用用のサービスアカウントが作成されている（推奨）
- [ ] 各ディレクトリに対する適切なアクセス権が設定されている

---

## 7. よくある質問

### Q1: 仮想環境上での動作はサポートされていますか？

A: はい、Hyper-V、VMware ESXi、KVM などの主要な仮想化プラットフォーム上での動作を
サポートしています。ただし、CDR 処理（特に大容量ファイル）は I/O と CPU を多用するため、
十分なリソースを割り当ててください。

### Q2: オフライン環境でインストールできますか？

A: 可能です。事前にオンライン環境で以下をダウンロードし、オフライン環境へ搬入してください：
- Rust toolchain (rustup のオフラインインストーラー)
- Misogi ソースコード（git archive）
- Cargo 依存関係キャッシュ（`cargo vendor` で生成可能）
- LibreOffice（JTD 使用時）
- protoc

### Q3: 既存の CDR ソリューションとの併用は可能ですか？

A: はい、Misogi は既存システムと並行稼働可能です。ポート番号を競合しないよう
設定ファイル（`misogi.toml`）の `[server].addr` で適切な値を指定してください。

---

*次のステップ: [Windows Server 2022 インストールガイド](windows-server-2022.md) に進んでください*
