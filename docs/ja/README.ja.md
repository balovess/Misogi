# Misogi (禊ぎ) — 日本語ドキュメント

**政府・金融機関向け CDR（Content Disarm & Reconstruction）セキュアファイル転送システム**

Misogi（禊ぎ）は、インターネット等の外部ネットワークと業務用イントラネット間で、
ファイルを安全に転送するための Content Disarm & Reconstruction (CDR) システムです。

---

## 1. システム概要

### 1-1. Misogi とは

Misogi は、日本国内の SIer（System Integrator）および政府機関の要件を念頭に設計された、
**政企レベル**のセキュアファイル転送プラットフォームです。Rust 2024 Edition で構築され、
メモリ安全性・並行性・パフォーマンスを保証します。

### 1-2. アーキテクチャ概要

```
                         ┌──────────────────────┐
                         │    インターネット      │
                         │   (External Network)  │
                         └──────────┬───────────┘
                                    │
                                    ▼
                    ┌─────────────────────────────┐
                    │     Misogi Sender (送信側)     │
                    │  ┌─────────────────────────┐ │
                    │  │ • HTTP Upload API        │ │
                    │  │ • File System Watcher    │ │
                    │  │ • CDR Sanitization Engine│ │
                    │  │ • PII Detection          │ │
                    │  │ • JTD Converter (一太郎)  │ │
                    │  └─────────────────────────┘ │
                    └──────────────┬──────────────┘
                                   │ gRPC / HTTP
                                   ▼
                    ┌─────────────────────────────┐
                    │   Misogi Receiver (受信側)    │
                    │  ┌─────────────────────────┐ │
                    │  │ • gRPC Stream Receiver   │ │
                    │  │ • Chunk Reassembly       │ │
                    │  │ • Download API           │ │
                    │  │ • Audit Log Engine       │ │
                    │  └─────────────────────────┘ │
                    └──────────────┬──────────────┘
                                   │
                                   ▼
                    ┌─────────────────────────────┐
                    │   業務用イントラネット         │
                    │   (Business Intranet)        │
                    └─────────────────────────────┘
```

### 1-3. 競品比較表

| 機能 | **Misogi (禊ぎ)** | **FileZen** | **VOTIRO** |
|------|-------------------|-------------|------------|
| 一太郎 (.jtd) サポート | ✅ 完全対応 | ❌ 非対応 | ❌ 非対応 |
| マイナンバー検出 | ✅ 内蔵PIIエンジン | △ オプション | △ オプション |
| 和暦日付処理 | ✅ CalendarProvider | ❌ 非対応 | ❌ 非対応 |
| Shift-JIS エンコーディング | ✅ 自動検出・変換 | △ 制限あり | △ 制限あり |
| EUC-JP / ISO-2022-JP | ✅ 自動検出 | ❌ 非対応 | ❌ 非対応 |
| PDF True CDR | ✅ PdfStreamParser | ✅ 対応 | ✅ 対応 |
| OOXML (Excel/Word/PPT) | ✅ OoxmlStreamParser | ✅ 対応 | ✅ 対応 |
| ZIP 無害化 | ✅ ZipSanitizer | ✅ 対応 | ✅ 対応 |
| SVG 無害化 | ✅ SvgSanitizer | ❌ 非対応 | △ 制限あり |
| LDAP/AD 連携 | ✅ LdapAuthProvider | ✅ 対応 | ✅ 対応 |
| 承認フロー (Approval) | ✅ StateMachine + ApprovalTrigger | △ 限定 | ✅ 対応 |
| ベンダー権限分離 | ✅ VendorIsolationManager | ❌ 非対応 | ❌ 非対応 |
| 監査ログ (JSON/Syslog/CEF) | ✅ LogEngine + MultiFormatter | ✅ 対応 | ✅ 対応 |
| 転送モード多様化 | ✅ Pull/BlindSend/Local | △ Pushのみ | ✅ 対応 |
| 外部ストレージ連携 | ✅ StorageBackend Trait | △ 限定 | △ 限定 |
| ライセンス形態 | Apache 2.0 (オープンソース) | プロプライエタリ | プロプライエタリ |
| プログラミング言語 | Rust (メモリ安全) | Java/C# | C#/.NET |

> **注**: 一太郎（.jtd）形式のサポートは、日本の官公庁・地方自治体での導入において
> **極めて重要な差別化要因**となります。日本独自の文書フォーマットである .jtd ファイルは、
> 多くの政府機関で標準的に使用されており、このサポートなしでは実運用が困難です。

---

## 2. クイックスタートガイド

### Step 1: 環境準備

```powershell
# Rust ツールチェーンのインストール
winget install Rustlang.Rustup

# インストール確認
rustc --version
cargo --version
```

### Step 2: ビルド

```bash
# リポジトリのクローン
git clone https://github.com/balovess/Misogi.git
cd Misogi

# リリースビルド
cargo build --release
```

### Step 3: 設定と起動

```bash
# 設定ファイルを作成（詳細は「基本設定ガイド」参照）
cp config/examples/misogi-sender.toml ./misogi-sender.toml
cp config/examples/misogi-receiver.toml ./misogi-receiver.toml

# 送信ノード起動
./target/release/misogi-sender server --config ./misogi-sender.toml

# 受信ノード起動（別ターミナル）
./target/release/misogi-receiver server --config ./misogi-receiver.toml
```

---

## 3. 主な機能

### 3-1. CDR エンジン（Content Disarm & Reconstruction）

ファイルから悪意のあるコンテンツ（マクロ、スクリプト、埋め込みオブジェクト）を除去し、
安全な状態で再構築する機能です。

| パーサー名 | 対応フォーマット | 説明 |
|-----------|---------------|------|
| `PdfStreamParser` | PDF | PDF のストリーム解析による無害化 |
| `OoxmlStreamParser` | DOCX/XLSX/PPTX | Office Open XML 形式の無害化 |
| `ZipSanitizer` | ZIP | ZIP アーカイブ内ファイルの再帰的無害化 |
| `SvgSanitizer` | SVG | SVG のスクリプト要素除去 |
| `JtdConverter` | JTD (一太郎) | 日本固有文書形式の PDF 変換 |

### 3-2. PII 検出エンジン

日本の個人情報保護法（APPI）およびマイナンバー法に準拠した、
個人情報（Personally Identifiable Information）の自動検出機能です。

| 検出ルール | 対象 | デフォルトアクション |
|----------|------|---------------------|
| `my_number` | マイナンバー（12桁） | Mask（マスキング） |
| `email` | メールアドレス | AlertOnly（警告のみ） |
| `ip_address_v4` | IPv4 アドレス | AlertOnly |
| `credit_card` | クレジットカード番号 | Mask |
| `phone_jp` | 日本の電話番号 | AlertOnly |
| `postal_code_jp` | 郵便番号 | AlertOnly |
| `drivers_license` | 運転免許証番号 | Mask |

### 3-3. 日本語特化機能

| 機能 | 説明 |
|------|------|
| **一太郎 (.jtd) サポート** | LibreOffice / 一太郎ビューア経由で PDF に変換 |
| **和暦処理** | 令和・平成・昭和などの和暦日付の正規化・変換 |
| **Shift-JIS 検出** | レガシーシステム由来の Shift-JIS ファイル自動検出 |
| **EUC-JP / ISO-2022-JP** | Unix系レガシーエンコーディング対応 |
| **PDF フォントセーフティ** | 不明フォントの Preserve/Strip/Replace ポリシー |

### 3-4. セキュリティ機能

| 機能 | 説明 |
|------|------|
| **監査ログ** | JSON / Syslog / CEF 形式の出力対応 |
| **LDAP/AD 連携** | Active Directory による認証・認可 |
| **承認フロー** | StateMachine による多段階承認ワークフロー |
| **ベンダー権限分離** | VendorIsolationManager による委託業者アクセス制御 |
| **TLS 通信** | 送受信間の暗号化通信 |

---

## 4. ドキュメントインデックス

以下のサブドキュメントを参照してください。

### インストール関連

| ドキュメント | 説明 |
|------------|------|
| [前提条件チェックリスト](installation/prerequisites.md) | システム要件・ハードウェア要件・ソフトウェア依存関係 |
| [Windows Server 2022 インストールガイド](installation/windows-server-2022.md) | ステップバイステップの詳細インストール手順 |

### 設定関連

| ドキュメント | 説明 |
|------------|------|
| [基本設定ガイド](configuration/basic-config.md) | misogi.toml の完全フィールドリファレンス |
| [JTD コンバーター設定](configuration/jtd-converter.md) | 一太郎変換の各種モード設定 |
| [Active Directory 連携ガイド](configuration/active-directory.md) | LDAP/AD 接続設定と組織単位例 |

### 運用関連

| ドキュメント | 説明 |
|------------|------|
| [Windows タスクスケジューラ設定](operation/task-scheduler.md) | 定期実行タスクの登録手順 |
| [日常運用手順書](operation/daily-operation.md) | 日次チェックリスト・ヘルスチェック・バックアップ |
| [トラブルシューティング FAQ](operation/troubleshooting.md) | エラーコード一覧・Q&A 形式の解決策 |

### セキュリティ関連

| ドキュメント | 説明 |
|------------|------|
| [監査ログフィールドガイド](security/audit-log-guide.md) | ログイベント解説・フォーマット説明 |
| [PII 検出設定](security/pii-detection.md) | マイナンバー検出・カスタムルール作成 |

### API / リファレンス

| ドキュメント | 説明 |
|------------|------|
| [CLI コマンドリファレンス](api-reference/cli-reference.md) | 全コマンド・オプション・終了コード |

### 合规相关

| ドキュメント | 説明 |
|------------|------|
| [デジタル庁標準ガイドライン準拠対照表](../compliance/デジタル庁標準ガイドライン準拠対照表.md) | 政府調達用コンプライアンス証明資料（DS-100/DS-200 準拠）|

---

## 5. サポート対象環境

### OS

| OS | バージョン | サポート状況 |
|----|----------|------------|
| Windows Server | 2019, 2022 | ✅ 公式サポート |
| RHEL (Red Hat Enterprise Linux) | 8.x, 9.x | ✅ 公式サポート |
| Ubuntu | 22.04 LTS, 24.04 LTS | ✅ 公式サポート |

### 必要ソフトウェア

| ソフトウェア | 用途 | 必須/任意 |
|------------|------|---------|
| Rust toolchain (rustup) | ビルド | ✅ 必須 |
| LibreOffice | JTD → PDF 変換 | ⚠️ JTD使用時必須 |
| .NET Runtime | 一太郎ビューア使用時 | ⚠️ 一太郎使用時必須 |
| Protocol Buffers Compiler (protoc) | gRPC 定義コンパイル | ✅ 必須 |

---

## 6. 免責事項

本ソフトウェアは**「現状のまま（As Is）」**提供され、明示・黙示を問わずいかなる保証も伴いません。
作者は、データ漏洩、情報流出、業務中断、金銭的損失、設定ミスまたは未知の脆弱性（ゼロデイ攻撃を含む）
によるセキュリティインシデント等、本ソフトウェアの使用によって生じたいかなる損害について
**一切の責任を負いません。**

**本ソフトウェアが全ての悪意あるコンテンツを100%検出することを保証するものではありません。**
政府機関、金融機関、重要インフラ等での本番稼働前に、
**各自の責任において十分な内部セキュリティ審査とコンプライアンスレビューを実施してください。**

---

Copyright 2026 Misogi Contributors. Licensed under Apache 2.0.
