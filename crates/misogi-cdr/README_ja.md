# misogi-cdr

Misogi 向け Content Disarm and Reconstruction (CDR) エンジン

## 概要

`misogi-cdr` は、Misogi ファイル転送システムのためにエンタープライズグレードの Content Disarm and Reconstruction 機能を提供します。潜在的に悪意のあるコンテンツを積極的に除去しながら、元の文書の完全性と実用性を維持するセキュリティファーストのアプローチを実装しています。

## 機能

### コア CDR 機能

- **ストリーミング安全な処理**: ファイルサイズに関係なく保証された有界メモリ使用量
- **マルチフォーマットサポート**: 一般的なビジネス文書タイプの包括的なカバレッジ
- **ポリシー駆動型サニタイゼーション**: 異なる脅威レベルに対する設定可能なセキュリティポリシー
- **詳細な監査ロギング**: コンプライアンスのためのすべてのサニタイゼーションアクションの完全な記録

### サポートされているファイルタイプ

#### PDF 文書
- JavaScript とアクティブコンテンツの除去
- 埋め込みファイルと添付ファイルの削除
- フォームフィールドと注釈のサニタイズ
- 文書構造と可読性の保持

#### Microsoft Office ファイル
- **Word (.docx)**: マクロ、アクティブコンテンツ、外部データ接続の削除
- **Excel (.xlsx)**: VBA マクロ、外部リンク、動的数式の除去
- **PowerPoint (.pptx)**: 埋め込みスクリプト、ActiveX コントロール、メディアの削除

#### 画像ファイル
- ステガノグラフィコンテンツを除去するための再エンコード
- メタデータの除去（EXIF、IPTC、XMP）
- フォーマット検証と正規化

#### JTD ファイル（Justsystems Text Document）
- 日本語ワードプロセッサフォーマットのサポート
- アクティブコンテンツの除去
- 構造の保持

### PPAP 検出と処理

PPAP（Password Protected Archive Protocol）ファイルの包括的な検出と処理を実装：

#### 検出機能
- **暗号化検出**: 暗号化された ZIP エントリの識別
- **ヒューリスティック分析**: ファイル名パターン（password、暗号、など）
- **信頼度スコアリング**: 定量化された検出信頼度レベル
- **メソッド識別**: ZipCrypto、AES-256 などの区別

#### 処理ポリシー

1. **ブロック（Block）**: コンプライアンスイベント生成による完全な拒否
2. **警告とサニタイズ（WarnAndSanitize）**: 弱い暗号化を剥奪、CDR 適用、警告ロギング
3. **検疫（Quarantine）**: 管理者レビューのために安全な検疫エリアに移動
4. **安全へ変換（ConvertToSecure）**: 安全なトンネル転送による完全な PPAP 置換ワークフロー

## アーキテクチャ

```
┌─────────────────┐
│  入力ファイル    │
│  （潜在的に      │
│   悪意のある）    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  ファイルタイプ   │
│  検出器         │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  PPAP 検出器     │◄── オプションの事前スキャン
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  ポリシーエンジン│
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  サニタイザー    │
│  （フォーマット   │
│   固有）         │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  出力ファイル    │
│  （サニタイズ済み）│
└─────────────────┘
```

## インストール

`Cargo.toml` に追加：

```toml
[dependencies]
misogi-cdr = { path = "../misogi-cdr" }
```

## 使用方法

### 基本的なサニタイゼーション

```rust
use misogi_cdr::{FileSanitizer, PdfSanitizer, SanitizationPolicy};
use std::path::Path;

// サニタイザーインスタンスの作成
let sanitizer = PdfSanitizer::new();

// サニタイゼーションポリシーの定義
let policy = SanitizationPolicy::StripActiveContent;

// ファイルのサニタイズ
let report = sanitizer
    .sanitize(
        Path::new("/input/suspicious.pdf"),
        Path::new("/output/safe.pdf"),
        &policy,
    )
    .await?;

// レポートの確認
println!("実行されたアクション：{:?}", report.actions);
println!("無効化された脅威：{}", report.threats_detected);
```

### PPAP 検出と処理

```rust
use misogi_cdr::{PpapDetector, PpapHandler, PpapPolicy};
use std::sync::Arc;

// 検出器の作成
let detector = Arc::new(PpapDetector::new());

// PPAP の検出
let detection = detector.detect(Path::new("archive.zip")).await?;

if detection.is_ppap {
    // ポリシーと共にハンドラーを作成
    let handler = PpapHandler::new(
        PpapPolicy::ConvertToSecure,
        detector,
    );
    
    // ポリシーに従って処理
    let report = handler
        .handle(
            Path::new("archive.zip"),
            Path::new("/output/safe.zip"),
            &SanitizationPolicy::StripActiveContent,
        )
        .await?;
    
    println!("PPAP 処理済み：{:?}", report.disposition);
}
```

### ポリシー設定

```rust
use misogi_cdr::SanitizationPolicy;

// すべてのアクティブコンテンツを剥奪（ほとんどの場合に推奨）
let policy = SanitizationPolicy::StripActiveContent;

// フラットフォーマットに変換（最大セキュリティ）
let policy = SanitizationPolicy::ConvertToFlat;

// テキストのみ抽出（究極のオプション）
let policy = SanitizationPolicy::TextOnly;
```

## サニタイゼーションポリシー

### StripActiveContent（アクティブコンテンツの剥奪）
**セキュリティレベル**: 中〜高  
**用途**: 一般的なビジネス文書

除去するもの：
- JavaScript とスクリプティング
- 埋め込み実行ファイル
- ActiveX コントロール
- マクロと VBA コード
- 外部データ接続

保持するもの：
- 文書のフォーマット
- 画像とグラフィック
- テキストコンテンツ
- 基本的な構造

### ConvertToFlat（フラットフォーマットへ変換）
**セキュリティレベル**: 高  
**用途**: 高セキュリティ環境

文書をフラットフォーマットに変換：
- 文書には PDF/A
- 画像には PNG/TIFF
- すべてのインタラクティブ要素を削除
- 視覚的な外観のみ保持

### TextOnly（テキストのみ）
**セキュリティレベル**: 最大  
**用途**: 最大セキュリティ、脅威インテリジェンス

プレーンテキストのみを抽出：
- すべてのフォーマットを削除
- すべての埋め込みコンテンツを削除
- 生のテキストコンテンツを返す
- 最大の脅威除去

## API リファレンス

### FileSanitizer トレイト

すべてのフォーマット固有サニタイザーによって実装されるコアトレイト：

```rust
#[async_trait]
pub trait FileSanitizer: Send + Sync {
    fn supported_extensions(&self) -> &[&str];
    
    async fn sanitize(
        &self,
        input_path: &Path,
        output_path: &Path,
        policy: &SanitizationPolicy,
    ) -> Result<SanitizationReport>;
}
```

### SanitizationReport

サニタイゼーションアクションの詳細レポート：

```rust
pub struct SanitizationReport {
    pub input_file: String,
    pub output_file: String,
    pub actions: Vec<SanitizationAction>,
    pub threats_detected: usize,
    pub processing_time_ms: u64,
    pub success: bool,
}
```

### PpapDetectionResult

PPAP 検出結果：

```rust
pub struct PpapDetectionResult {
    pub is_ppap: bool,
    pub confidence: f64,
    pub indicators: Vec<String>,
    pub encryption_method: Option<String>,
}
```

## セキュリティに関する考慮事項

### メモリ安全性

すべての CDR 操作はストリーミングアーキテクチャで設計されています：
- **ファイル全体の読み込みなし**: ファイルはチャンク単位で処理されます
- **有界メモリ**: メモリ使用量はファイルサイズに依存しません
- **DoS 保護**: メモリ枯渇攻撃を防止します

### 脅威モデル

CDR は以下から保護します：
- **埋め込みマルウェア**: 実行ファイル、スクリプト、マクロ
- **エクスプロイトコード**: バッファオーバフローペイロード、ROP チェーン
- **データ窃取**: 隠されたデータチャネル、ステガノグラフィ
- **ソーシャルエンジニアリング**: 欺瞞的なコンテンツ、フィッシング要素

### 制限事項

CDR は万能薬ではありません：
- **ゼロデイエクスプロイト**: 未知の攻撃ベクトルは残存する可能性があります
- **コンテンツレベルの攻撃**: 正当に見える悪意のあるコンテンツ
- **OCR 回避**: 画像に埋め込まれたテキスト
- **論理的脆弱性**: ビジネスロジック攻撃

以下の補完的なセキュリティ対策を推奨します：
- アンチウイルススキャン
- サンボクシング
- ユーザートレーニング
- アクセス制御

## パフォーマンス

### ベンチマーク

典型的な処理時間（M.2 NVMe SSD、Intel i7）：

| ファイルタイプ | サイズ | 処理時間 |
|---------------|--------|----------|
| PDF | 1 MB | ~50-100 ms |
| DOCX | 500 KB | ~30-60 ms |
| XLSX | 1 MB | ~40-80 ms |
| PPTX | 5 MB | ~200-400 ms |
| ZIP | 10 MB | ~100-200 ms |

### 最適化のヒント

1. **適切なポリシーの使用**: StripActiveContent が最速
2. **バッチ処理**: 複数のファイルを並列処理
3. **非同期 I/O**: Tokio の非同期ランタイムを活用
4. **メモリマッピング**: 非常に大きなファイルに使用

## エラーハンドリング

`thiserror` を通じた包括的なエラータイプ：

```rust
pub enum CdrError {
    #[error("サポートされていないファイルフォーマット：{0}")]
    UnsupportedFormat(String),
    
    #[error("ファイルが破損しているか読み取れません：{0}")]
    CorruptedFile(String),
    
    #[error("サニタイゼーションに失敗しました：{0}")]
    SanitizationFailed(String),
    
    #[error("I/O エラー：{0}")]
    Io(#[from] std::io::Error),
    
    #[error("PPAP 検出エラー：{0}")]
    PpapDetection(String),
}
```

## テスト

テストスイートの実行：

```bash
cargo test -p misogi-cdr
```

### テストカバレッジ

- 各サニタイザーのユニットテスト
- フルパイプラインの統合テスト
- PPAP 検出精度テスト
- パフォーマンス回帰テスト
- 堅牢性のためのファジングテスト

## 依存関係

- `tokio`: 非同期ランタイム
- `serde`: シリアライゼーション
- `thiserror`: エラーハンドリング
- `nom`: パーサーコンビネータ
- `zip`: ZIP アーカイブ処理
- `md-5`: ハッシュ検証
- `regex`: パターンマッチング
- `tempfile`: 一時ファイル処理

## コントリビュート

コントリビューションを歓迎します！以下の点にご注意ください：
- すべてのコードは Rust 2024 Edition でコンパイル可能であること
- 包括的なドキュメントが必要
- 新機能にはテストが必須
- CDR ロジックの変更にはセキュリティレビューが必要

## ライセンス

Apache 2.0 ライセンスの下でライセンスされています。詳細は [LICENSE](../../LICENSE) を参照してください。

---

**セキュリティ通知**: CDR はセキュリティコントロールですが、完全なセキュリティソリューションではありません。多層防御戦略の一部として導入してください。
