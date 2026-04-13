# PII 検出深度拡張ガイド — Part 3: API リファレンス・導入ガイド・トラブルシューティング

> **Part 1**: [概要・コンテキスト分析・構造化データ](pii-detection-enhanced.md)
>
> **Part 2**: [OCR・機密分類・設定リファレンス](pii-detection-enhanced-part2.md)

---

## 目次 (Part 3)

- [8. プログラミング API リファレンス](#8-プログラミング-api-リファレンス)
  - [8-1. Context モジュール API](#81-context-モジュール-api)
  - [8-2. Structured モジュール API](#82-structured-モジュール-api)
  - [8-3. OCR モジュール API](#83-ocr-モジュール-api)
  - [8-4. Secrecy モジュール API](#84-secrecy-モジュール-api)
- [9. 導入ガイドライン](#9-導入ガイドライン)
  - [9-1. シナリオ: 金融機関](#91-シナリオ-金融機関)
  - [9-2. シナリオ: 日本自治体](#92-シナリオ-日本自治体)
  - [9-3. シナリオ: 医療機関 (HIPAA)](#93-シナリオ-医療機関-hipaa)
  - [9-4. 移行ガイド (旧版→新版)](#94-移行ガイド-旧版→新版)
- [10. トラブルシューティング](#10-トラブルシューティング)
  - [10-1. よくある問題 (FAQ)](#101-よくある問題-faq)
  - [10-2. パフォーマンス最適化](#102-パフォーマンス最適化)
  - [10-3. デバッグ方法](#103-デバッグ方法)

---

## 8. プログラミング API リファレンス

### 8-1. Context モジュール API

#### ContextAnalyzer

```rust
pub struct ContextAnalyzer { /* private */ }

impl ContextAnalyzer {
    /// 汎用デフォルトのキーワードエンジンで初期化
    pub fn with_defaults() -> Result<Self>;

    /// カスタムキーワードエンジンで初期化
    pub fn with_keyword_engine(engine: KeywordRuleEngine) -> Self;

    /// 外部 NLP Provider + フォールバックエンジンで初期化
    pub fn with_provider(
        provider: Arc<dyn ContextProvider>,
        fallback_engine: KeywordRuleEngine,
    ) -> Self;

    /// 設定カスタマイズ
    pub fn with_config(self, config: ContextAnalyzerConfig) -> Self;

    /// コンテキスト分析実行 (非同期)
    pub async fn analyze(&self, request: &ContextAnalysisRequest) -> Result<ContextAnalysisResponse>;

    /// 強制的にキーワードエンジン使用 (Provider をバイパス)
    pub fn analyze_with_keywords(&self, request: &ContextAnalysisRequest) -> Result<ContextAnalysisResponse>;

    // 状態確認
    pub fn has_provider(&self) -> bool;
    pub fn provider_name(&self) -> Option<&str>;
    pub fn keyword_engine(&self) -> &Arc<KeywordRuleEngine>;
}
```

#### KeywordRuleEngine

```rust
pub struct KeywordRuleEngine { /* private */ }

impl KeywordRuleEngine {
    /// 汎用デフォルト読込
    pub fn with_defaults() -> Result<Self>;

    /// YAML ファイルから読込
    pub fn from_yaml_file(path: &str) -> Result<Self>;

    /// 複数ソースをマージ
    pub fn merge(sources: Vec<KeywordRuleSource>) -> Result<Self>;

    /// 分析実行
    pub fn analyze(&self, request: &ContextAnalysisRequest) -> Result<ContextAnalysisResponse>;

    /// ランタイムでキーワード追加
    pub fn add_keyword(&self, pii_type: &str, keyword: KeywordRule) -> Result<()>;
    pub fn remove_keyword(&self, pii_type: &str, keyword_text: &str) -> Result<bool>;

    /// ホットリロード
    pub fn reload_from_file(&self, path: &str) -> Result<()>;
}
```

#### RuleEngineBuilder

```rust
pub struct RuleEngineBuilder { /* private */ }

impl RuleEngineBuilder {
    pub fn new() -> Self;
    pub fn set_profile(self, profile: impl Into<String>) -> Self;
    pub fn set_context_window(self, size: usize) -> Self;
    pub fn set_thresholds(self, positive: f64, negative: f64) -> Self;
    pub fn set_case_sensitive(self, sensitive: bool) -> Self;

    pub fn add_pii_type(self, type_id: impl Into<String>, display_name: impl Into<String>)
        -> PiiTypeRuleBuilder<'_>;

    pub fn add_global_anti(self, keyword: impl Into<String>, weight: f64, position: KeywordPosition) -> Self;

    pub fn build(self) -> Result<KeywordRuleEngine>;
}
```

### 8-2. Structured モジュール API

#### CsvPiiScanner / JsonPiiScanner / XmlPiiScanner

```rust
pub struct CsvPiiScanner {
    classifier: FieldClassifier,
    config: CsvScannerConfig,
}

impl CsvPiiScanner {
    pub fn with_defaults() -> Self;
    pub fn new(classifier: FieldClassifier, config: CsvScannerConfig) -> Self;
    pub fn scan(&self, content: &str) -> Result<StructuredScanResult>;
}

// JsonPiiScanner / XmlPiiScanner も同様のインターフェース
```

#### FieldClassifier

```rust
pub struct FieldClassifier { /* private */ }

impl FieldClassifier {
    pub fn with_defaults() -> Self;                    // 汎用デフォルト
    pub fn from_yaml_file(path: &str) -> Result<Self>; // YAML から

    pub fn classify(&self, field_name: &str) -> FieldClassification;
    pub fn add_mapping(&self, mapping: FieldMapping) -> Result<()>;
    pub fn remove_by_pattern(&self, pattern: &str) -> Result<usize>;
    pub fn mapping_count(&self) -> usize;
}
```

#### FieldMapping

```rust
pub struct FieldMapping {
    pub field_pattern: String,   // マッチパターン
    pub pii_type: String,       // PII タイプ
    pub confidence: f64,         // 信頼度
    pub action: FieldAction,     // アクション
}

impl FieldMapping {
    pub fn literal(field, pii_type, confidence, action) -> Self;
    pub fn wildcard(pattern, pii_type, confidence, action) -> Self;
    pub fn matches_field(&self, field_name: &str) -> bool;
}
```

### 8-3. OCR モジュール API

#### OcrPiiDetector

```rust
pub struct OcrPiiDetector {
    ocr_provider: Arc<dyn OcrProvider>,
    text_detector: Arc<RegexPIIDetector>,
    config: OcrDetectorConfig,
}

impl OcrPiiDetector {
    pub fn new(ocr, detector, config) -> Self;
    pub fn with_defaults(ocr, detector) -> Self;

    /// 画像をスキャンして PII を検出
    pub async fn scan_image(&self, image_data: &[u8], file_id: &str)
        -> Result<OcrPiiScanResult>;
}
```

#### OcrPiiScanResult / OcrPiiMatch

```rust
pub struct OcrPiiScanResult {
    pub found: bool,
    pub matches: Vec<OcrPiiMatch>,
    pub action: PIIAction,
    pub image_size_bytes: u64,
    pub ocr_metadata: OcrImageMetadata,
    pub scan_duration_ms: u64,
    pub total_chars_extracted: usize,
}

pub struct OcrPiiMatch {
    pub match_data: PIIMatch,       // 標準 PII マッチ情報
    pub bbox: Option<OcrBoundingBox>, // 位置情報 (有効時)
    pub ocr_block_confidence: f64,   // OCR ブロック信頼度
}
```

### 8-4. Secrecy モジュール API

#### SecrecyClassifier

```rust
pub struct SecrecyClassifier { /* private */ }

impl SecrecyClassifier {
    /// 汎用 4-tier テンプレート
    pub fn with_generic_tier() -> Result<Self>;

    /// YAML ファイルから
    pub fn from_yaml_file(path: &str) -> Result<Self>;

    /// 分類実行
    pub fn classify(&self, pii_types: &[&str]) -> Result<SecrecyClassificationResult>;

    /// ホットリロード
    pub fn reload_scheme(&self, path: &str) -> Result<()>;

    // 問い合わせ
    pub fn level_ids(&self) -> Vec<String>;
    pub fn get_level(&self, level_id: &str) -> Option<SecrecyLevelDef>;
}
```

#### SecrecySchemeBuilder

```rust
pub struct SecrecySchemeBuilder { /* private */ }

impl SecrecySchemeBuilder {
    pub fn new() -> Self;
    pub fn set_scheme(self, name: impl Into<String>) -> Self;

    pub fn add_level(self, id, display_name, rank, color) -> Self;
    pub fn add_rule(self, rule_id, condition, level, reason) -> Self;
    pub fn fallback_default(self, level: impl Into<String>) -> Self;

    pub fn build(self) -> Result<SecrecyClassifier>;
}
```

---

## 9. 導入ガイドライン

### 9-1. シナリオ: 金融機関

**要件**: PCI-DSS 準拠、クレジットカード情報厳格保護、監査証跡必須

**推奨構成**:

```yaml
# finance-pii-context.yaml (L1 追加ルール)
pii_types:
  credit_card:
    positive:
      - { keyword: "card number", weight: 0.98, position: before }
      - { keyword: "PAN", weight: 0.97, position: before }   # PCI 用語
      - { keyword: "カード番号", weight: 0.99, position: before }
    anti:
      - { keyword: "token", weight: 0.70, position: after }    # トークン化済み
      - { keyword: "masked", weight: 0.65, position: either } # 既マスク済み

  cvv_cvc:
    display_name: "CVV/CVC"
    positive:
      - { keyword: "cvv", weight: 0.95, position: before }
      - { keyword: "cvc", weight: 0.95, position: before }
      - { keyword: "セキュリティコード", weight: 0.96, position: before }
```

```yaml
# finance-pii-secrecy.yaml (L4 カスタムスキーマ)
scheme: "pci-dss-compliant"

levels:
  cardholder:
    display_name: "Cardholder Data"
    rank: 4
    color: "#DC2626"
    required_controls:
      - { id: aes256, name: "AES-256 Encryption", required: true }
      - { id: tokenization, name: "Tokenization", required: true }
      - { id: audit_pci, name: "PCI Audit Log", required: true }
    retention_years: 7

  sensitive:
    display_name: "Sensitive"
    rank: 2
    color: "#D97706"
    required_controls:
      - { id: enc_at_rest, name: "Encryption at Rest", required: true }
    retention_years: 3

classification_rules:
  - id: "rule_pan_cardholder"
    condition: { require_any_of: ["credit_card", "credit_card_cvv"] }
    result: { level: "cardholder", reason: "Payment card data per PCI-DSS" }
```

### 9-2. シナリオ: 日本自治体

**要件**: マイナンバー法準拠、特定個人情報保護、3A/3B/3C 分類

**推奨構成**:

```yaml
# jp-govt-pii-context.yaml (マイナンバー特化ルール)
pii_types:
  my_number:
    display_name: "個人番号 (My Number)"
    positive:
      - { keyword: "マイナンバー", weight: 0.95, position: before }
      - { keyword: "個人番号", weight: 0.95, position: before }
      - { keyword: "マイナ", weight: 0.80, position: before }
    anti:
      - { keyword: "伝票", weight: 0.70, position: either }
      - { keyword: "口座", weight: 0.60, position: either }
      - { keyword: "ケース", weight: 0.60, position: either }

  drivers_license:
    display_name: "運転免許証"
    positive:
      - { keyword: "免許証", weight: 0.97, position: before }
      - { keyword: "運転免許", weight: 0.95, position: before }
```

```yaml
# jp-govt-pii-secrecy.yaml (自治体 3A/3B/3C スキーマ)
scheme: "jp-govt-3tier"

levels:
  "3a":
    display_name: "極機密"
    rank: 3
    color: "#DC2626"
    required_controls:
      - { id: enc_aes256, name: "AES-256暗号化", required: true }
      - { id: tls13, name: "TLS 1.3", required: true }
      - { id: mfa, name: "多要素認証", required: true }
      - { id: full_audit, name: "完全監査ログ", required: true }
    retention_years: 7

  "3b":
    display_name: "機密"
    rank: 2
    color: "#D97706"
    required_controls:
      - { id: enc_aes256, name: "AES-256暗号化", required: true }
      - { id: access_log, name: "アクセスログ", required: true }
    retention_years: 5

  "3c":
    display_name: "扱い注意"
    rank: 1
    color: "#65A30D"
    required_controls:
      - { id: basic_auth, name: "基礎認証", required: true }
    retention_years: 3
```

### 9-3. シナリオ: 医療機関 (HIPAA)

**要件**: PHI (Protected Health Information) 保護、患者 ID 厳格管理

**推奨構成**:

```yaml
# hipaa-pii-secrecy.yaml
scheme: "hipaa-compliant"

levels:
  phi_restricted:
    display_name: "PHI-Restricted"
    rank: 3
    color: "#DC2626"
    required_controls:
      - { id: enc_hipaa, name: "HIPAA Encryption", required: true }
      - { id: audit_access, name: "Access Audit Trail", required: true }
      - { id: minimum_necessary, name: "Minimum Necessary Policy", required: true }
    retention_years: 10

  phi_limited:
    display_name: "PHI-Limited"
    rank: 2
    color: "#D97706"
    required_controls:
      - { id: enc_standard, name: "Standard Encryption", required: true }
    retention_years: 6
```

### 9-4. 移行ガイド (旧版→新版)

既存の `RegexPIIDetector` のみを使用しているコードは **変更不要** です。
新機能を段階的に追加できます:

#### Step 1: Cargo.toml に feature 追加

```toml
[dependencies]
misogi-core = { version = "0.1", features = ["pii-enhanced"] }
```

#### Step 2: 既存コード確認 (変更なし)

```rust
// これまで通り動作します
let detector = RegexPIIDetector::with_jp_defaults();
let result = detector.scan(text, file_id, source).await?;
// → 従来と同じ結果
```

#### Step 3: L1 コンテキスト分析を追加 (任意)

```rust
use misogi_core::pii::context::ContextAnalyzer;

let analyzer = ContextAnalyzer::with_defaults()?;  // 新規追加

// RegexPIIDetector の結果に対し、コンテキスト再評価
for match in &result.matches {
    let ctx_req = ContextAnalysisRequest::new(
        &match.matched_text,
        &match.pii_type,
        &text[..match.start.saturating_sub(50)],
        &text[match.end..(match.end + 50).min(text.len())],
    );
    let ctx_result = analyzer.analyze(&ctx_req).await?;
    if !ctx_result.is_pii {
        println!("False positive filtered: {}", match.matched_text);
    }
}
```

#### Step 4: L4 機密分類を追加 (任意)

```rust
use misogi_core::pii::secrecy::SecrecyClassifier;

let classifier = SecrecyClassifier::with_generic_tier()?;
let pii_types: Vec<&str> = result.matches.iter().map(|m| m.pii_type.as_str()).collect();
let secrecy = classifier.classify(&pii_types)?;
println!("Secrecy Level: {} ({})", secrecy.level_display_name, secrecy.level_rank);
```

---

## 10. トラブルシューティング

### 10-1. よくある問題 (FAQ)

#### Q1: コンテキスト分析が常に「PII ではない」を返す

**原因**: 正キーワードが不足、または反キーワードが強すぎる

**解決策**:
```yaml
# pii-context-defaults.yaml を編集
global_settings:
  positive_threshold: 0.5  # 下げる (デフォルト: 0.7)
  negative_threshold: 0.15 # 下げる (デフォルト: 0.3)

pii_types:
  your_custom_type:
    positive:
      - { keyword: "your_strong_indicator", weight: 0.99, position: before }
```

#### Q2: CSV スキャナがフィールドを認識しない

**原因**: フィールド名がプリセットマッピングに含まれていない

**解決策**:
```rust
use misogi_core::pii::structured::{FieldClassifier, FieldMapping, FieldAction};

let fc = FieldClassifier::with_defaults();
fc.add_mapping(FieldMapping::literal("my_custom_field", "email", 0.90, FieldAction::Mask))?;
```

または YAML に追加:
```yaml
field_mappings:
  - { field_pattern: "my_custom_field", pii_type: email, confidence: 0.90, action: mask }
```

#### Q3: OCR Provider がタイムアウトする

**原因**: 画像サイズ超過、または外部サービス応答遅延

**解決策**:
```rust
let config = OcrDetectorConfig {
    max_size_mb: 5,           // 制限強化 (デフォルト: 10)
    min_ocr_confidence: 0.8,  // 閾値上昇 (ブロック数減少)
    ..Default::default()
};
```

#### Q4: 機密分類が常に fallback レベルになる

**原因**: 検出された PII タイプが分類ルールに一致しない

**解決策**:
```rust
// デバッグ: どのタイプが検出されているか確認
let detected: Vec<&str> = result.matches.iter().map(|m| m.pii_type.as_str()).collect();
println!("Detected types: {:?}", detected);

// ルールに不足しているタイプを追加
classifier.add_rule(...)?;
```

### 10-2. パフォーマンス最適化

| 最適化項目 | 方法 | 効果 |
|-----------|------|------|
| **コンテキスト分析キャッシュ** | `ContextAnalyzerConfig.enable_cache = true` | 重複リクエスト高速化 |
| **CSV 最大行制限** | `CsvScannerConfig.max_rows = 50000` | 大ファイル処理安定化 |
| **JSON 深さ制限** | `JsonScannerConfig.max_depth = 5` | ネスト深い JSON 高速化 |
| **OCR 閾値調整** | `min_ocr_confidence: 0.85` | 低品質ブロックスキップ |
| **並列処理** | `tokio::spawn` で複数ファイル同時スキャン | スループット向上 |

### 10-3. デバッグ方法

#### ログ出力有効化

```rust
env_logger::init();  // RUST_LOG=debug で詳細ログ
```

主要なログポイント:
- `ContextAnalyzer::analyze` — ルーティング決定 (provider vs keywords)
- `KeywordRuleEngine::analyze` — 各キーワードのマッチ結果
- `CsvPiiScanner::scan` — 各フィールドの分類結果
- `OcrPiiDetector::scan_image` — OCR 抽出 + PII マッチ件数
- `SecrecyClassifier::classify` — 全ルール評価結果

#### テスト用 Mock 使用

```rust
// L1: 常に PII 確認する Mock
let mock_ctx = MockContextProvider::always_confirm();

// L3: 特定テキストを返す Mock
let mock_ocr = MockOcrProvider::with_text("SSN: 123-45-6789", 0.95);

// L3: 利用不可をシミュレート
let mock_down = MockOcrProvider::unavailable();
```

---

*→ [Part 3 完] PII 検出深度拡張ガイド 完結*

**関連文書**:
- [PII 検出設定ガイド (基礎版)](pii-detection.md) — 正則表現ベースの基本機能
- [English Version](../../en/security/pii-detection-enhanced.md) — 英語版完全ドキュメント
