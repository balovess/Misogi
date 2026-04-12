# JTD コンバーター設定ガイド (JTD Converter Configuration Guide)

一太郎（JustSystem 社製ワープロソフト）の独自文書形式 **.jtd** ファイルを、
安全な PDF 形式に変換するための設定について詳しく解説します。

**重要性**: 日本の官公庁および地方自治体において、一太郎 (.jtd) は広く使用されている
標準文書フォーマットです。このサポートなしでは、実務的なファイル転送システムとして
機能しません。Misogi は業界で唯一、ネイティブ JTD サポートを提供するオープンソース CDR システムです。

---

## 1. JTD 変換とは

### 1-1. 技術的背景

```
┌─────────────────────────────────────────────┐
│           JTD 変換フロー                      │
│                                             │
│  入力: report.jtd (一太郎文書)               │
│       │                                    │
│       ▼                                    │
│  ┌──────────────────┐                       │
│  │ JtdConverter      │ ← CDR エンジンから呼び出し   │
│  └────────┬─────────┘                       │
│           │                                 │
│     ┌─────┼─────────────────┐              │
│     │     │                 │              │
│     ▼     ▼                 ▼              │
│  ┌──────┐ ┌──────────┐ ┌────────┐         │
│  │Libre │ │一太郎    │ │ Dummy  │         │
│  │Office│ │ビューアー │ │(テスト) │         │
│  └──┬───┘ └────┬─────┘ └───┬────┘         │
│     │          │          │                │
│     ▼          ▼          ▼                │
│  report.pdf  report.pdf  (変換なし)          │
│                                             │
└─────────────────────────────────────────────┘
```

### 1-2. なぜ PDF に変換するのか

| 理由 | 説明 |
|------|------|
| **マクロ除去** | JTD ファイルに埋め込まれたマクロ/スクリプトを完全に排除 |
| **フォーマット統一** | 下流システムでの処理を簡素化 |
| **表示保証** | 元文書の視覚的情報を保持 |
| **検索可能性** | PDF テキスト抽出により内容検索が可能 |

---

## 2. コンバータータイプの選択

### 2-1. 利用可能なコンバーター

| タイプ | 識別子 | 必要なソフトウェア | 特徴 | 推奨度 |
|-------|--------|------------------|------|-------|
| LibreOffice 変換 | `"libreoffice"` | LibreOffice | オープンソース、安定動作 | ⭐⭐⭐ 推奨 |
| 一太郎ビューア | `"ichitaro_viewer"` | 一太郎ビューア + .NET | 公式ビューア、最高品質 | ⭐⭐ ライセンス要 |
| ダミー（テスト用） | `"dummy"` | なし | 変換を行わない | ⭐ テスト専用 |

### 2-2. 自動検出動作

`type` を指定しない場合、以下の順序で自動検出が行われます：

```
自動検出順序:
1. LibreOffice (soffice.exe) が PATH または指定パスに存在 → "libreoffice"
2. 一太郎ビューア (TViewer.exe) が存在 → "ichitaro_viewer"
3. どちらも見つからない → エラー (JtdConversionError::ConverterNotFound)
```

---

## 3. 各コンバーーターの詳細設定

### 3-1. LibreOffice モード (`"libreoffice"`)

最も一般的で推奨されるモードです。LibreOffice のヘッドレスモードを使用して JTD を PDF に変換します。

#### 設定例

```toml
[jtd_converter]
type = "libreoffice"
enabled = true
libreoffice_path = "C:\\Program Files\\LibreOffice\\program\\soffice.exe"
timeout_seconds = 120
```

#### フィールド説明

| フィールド | 型 | デフォルト | 必須 | 説明 |
|----------|-----|---------|------|------|
| `type` | String | `"libreoffice"` | ✅ | コンバータータイプ識別子 |
| `enabled` | Boolean | `true` | ✅ | JTD 変換機能の有効/無効 |
| `libreoffice_path` | String | `""` (自動検出) | △ | soffice.exe の絶対パス。空なら PATH から探索 |
| `timeout_seconds` | Integer | `120` | △ | 変換処理のタイムアウト（秒）。大容量ファイルで増やす |

#### 動作原理

LibreOffice は内部コマンドを実行します：

```bash
soffice.exe --headless --convert-to pdf --outdir <output_dir> <input_file.jtd>
```

このプロセスは Misogi が自動的に管理します：
- 一時ディレクトリの作成とクリーンアップ
- タイムアウト監視
- エラーハンドリング
- プロセスの適切な終了

#### インストール要件

```powershell
# LibreOffice のサイレントインストール（管理者権限）
msiexec /i LibreOffice_24.2.x_Win_x64.msi /quiet /norestart ADDLOCAL=ALL

# インストール確認
& "C:\Program Files\LibreOffice\program\soffice.exe" --version
```

> **推奨バージョン**: LibreOffice 24.2 以降  
> **理由**: JTD インポートフィルターの品質が向上しており、より多くの一太郎バージョンに対応しています。

#### よくある問題

| 問題 | 原因 | 解決策 |
|------|------|--------|
| `ConverterNotFound` | LibreOffice がインストールされていない | [インストールガイド](../installation/windows-server-2022.md) Step 4 参照 |
| `ConversionTimeout` | ファイルが大きすぎる / PC が低スペック | `timeout_seconds` を 300 などに増やす |
| `OutputFileMissing` | 変換は成功したが出力ファイルがない | アンチウイルスソフトが生成 PDF を削除している可能性あり |
| `IOError` | ディスク容量不足 / パーミッションエラー | ストレージ空き容量と権限を確認 |

### 3-2. 一太郎ビューアモード (`"ichitaro_viewer"`)

JustSystem 社公式の一太郎ビューアを使用するモードです。
変換品質は最も高いですが、ライセンスが必要です。

#### 設定例

```toml
[jtd_converter]
type = "ichitaro_viewer"
enabled = true
viewer_path = "C:\\Program Files (x86)\\JustSystem\\TViewer\\TViewer.exe"
timeout_seconds = 180
```

#### フィールド説明

| フィールド | 型 | デフォルト | 必須 | 説明 |
|----------|-----|---------|------|------|
| `type` | String | `"ichitaro_viewer"` | ✅ | コンバータータイプ |
| `enabled` | Boolean | `true` | ✅ | 有効/無効 |
| `viewer_path` | String | `""` (自動検出) | △ | TViewer.exe の絶対パス |
| `timeout_seconds` | Integer | `180` | △ | タイムアウト（秒） |

#### 前提条件

- 一太郎ビューアの正規ライセンス
- .NET Runtime 8.0 以上
- JustSystem 社のライセンスポリーに準拠

> **⚠️ 重要**: 一太郎ビューアモードを使用する場合は、必ず JustSystem 社の
> ライセンス契約をご確認ください。本ドキュメントは技術的な設定方法のみを提供し、
> ライセンスに関する法的助言は行いません。

### 3-3. ダミーモード (`"dummy"`)

開発・テスト用のモードです。実際の変換を行いません。

#### 設定例

```toml
[jtd_converter]
type = "dummy"
enabled = true
```

#### 動作

- JTD ファイルを受けても変換せず、元のファイルをそのまま通過させます
- CI/CD パイプラインやユニットテストで使用することを想定
- **本番環境では絶対に使用しないでください**

---

## 4. 完全設定例集

### 4-1. 標準構成（LibreOffice 使用）

```toml
# ============================================================
# JTD Converter — Standard Configuration (LibreOffice)
# Recommended for most government deployments.
# ============================================================

[jtd_converter]
type = "libreoffice"
enabled = true
libreoffice_path = "C:\\Program Files\\LibreOffice\\program\\soffice.exe"
timeout_seconds = 120
```

### 4-2. 高信頼構成（一太郎ビューア使用）

```toml
# ============================================================
# JTD Converter — High-Fidelity Configuration (Ichitaro Viewer)
# Use when document fidelity is critical (e.g., legal documents).
# Requires valid JustSystem license.
# ============================================================

[jtd_converter]
type = "ichitaro_viewer"
enabled = true
viewer_path = "C:\\Program Files (x86)\\JustSystem\\TViewer\\TViewer.exe"
timeout_seconds = 180
```

### 4-3. 自動検出構成

```toml
# ============================================================
# JTD Converter — Auto-Detect Configuration
# Automatically selects available converter.
# Priority: LibreOffice > Ichitaro Viewer > Error
# ============================================================

[jtd_converter]
enabled = true
# type is omitted → auto-detection enabled
timeout_seconds = 120
```

---

## 5. CDR パイプラインにおける位置づけ

JTD コンバーターは CDR 処理パイプラインの一部として動作します：

```
入力ファイル受付
    │
    ▼
┌─────────────────────┐
│ フォーマット判定      │ ← 拡張子/Magic Byte で判定
└────────┬────────────┘
         │
    ┌────┴────┬──────────┬──────────┐
    ▼        ▼          ▼          ▼
  [.pdf]   [.docx]     [.zip]     [.jtd]
    │        │          │          │
    ▼        ▼          ▼          ▼
 PdfStream  Ooxml      ZipSanit.  JtdConvert
 Parser     Parser                │
    │        │          │          ▼
    └────────┴──────────┘    ┌──────────┐
                              │ PDF 出力  │
                              └─────┬────┘
                                    ▼
                           ┌──────────────┐
                           │ PII 検出エンジン │ ← PDF テキスト抽出後に実行
                           └──────┬───────┘
                                  ▼
                           受信ネットワークへ転送
```

---

## 6. トラブルシューティング

### 6-1. 確認チェックリスト

- [ ] LibreOffice がインストールされている (`soffice.exe --version` で確認)
- [ ] `[jtd_converter].enabled` が `true` になっている
- [ ] `libreoffice_path` が正しい、または空欄（自動検出）
- [ ] 変換対象の .jtd ファイルが破損していない
- [ ] ディスクに十分な空き容量がある（元ファイルの約 3〜5 倍）
- [ ] アンチウイルスソフトが LibreOffice プロセスをブロックしていない

### 6-2. デバッグログの取得

```powershell
# ログレベルを debug に上げて再試行
# misogi-sender.toml:
[server]
log_level = "debug"

# ログ中に以下のような出力を探す
# [DEBUG] JTD converter: type=libreoffice, path="C:\...\soffice.exe"
# [DEBUG] JTD conversion started: input="report.jtd"
# [DEBUG] LibreOffice process spawned: PID=12345
# [DEBUG] JTD conversion completed: output="report.pdf" (elapsed=2345ms)
```

### 6-3. 既知の制限事項

| 制限 | 説明 | 回避策 |
|------|------|--------|
| パスワード保護された JTD | LibreOffice で変換不可 | パスワード解除後に再試行 |
| 埋め込み OLE オブジェクト | 一部の OLE は変換結果に残る可能性 | CDR 後の追加スキャン推奨 |
|非常に大きなファイル (>100MB) | タイムアウトの可能性 | `timeout_seconds` を増加 |
| 古いバージョンの JTD (v5以前) | LibreOffice インポートフィルター非対応 | 一太郎ビューアモードを検討 |

---

*関連ドキュメント: [基本設定ガイド](basic-config.md) | [PII 検出設定](../security/pii-detection.md)*
