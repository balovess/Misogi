# PII 検出深度拡張ガイド — Part 2: OCR・機密分類・設定リファレンス

> **Part 1**: [概要・コンテキスト分析・構造化データ](pii-detection-enhanced.md)
>
> **対象読者**: セキュリティエンジニア、コンプライアンス担当者、システムアーキテクト

---

## 目次 (Part 2)

- [5. L3: OCR PII 検出](#5-l3-ocr-pii-検出)
  - [5-1. OcrProvider trait (標準 OCR インターフェース)](#51-ocrprovider-trait-標準-ocr-インターフェース)
  - [5-2. OcrPiiDetector (OCR + Regex パイプライン)](#52-ocrpiidetector-ocr--regex-パイプライン)
  - [5-3. 設定例とコードサンプル](#53-設定例とコードサンプル)
- [6. L4: 機密レベル分類器](#6-l4-機密レベル分類器)
  - [6-1. ユーザー定義レベル体系](#61-ユーザー定義レベル体系)
  - [6-2. 分類ルールエンジン](#62-分類ルールエンジン)
  - [6-3. 決定競合の解決](#63-決定競合の解決)
  - [6-4. 設定例とコードサンプル](#64-設定例とコードサンプル)
- [7. 設定ファイル完全リファレンス](#7-設定ファイル完全リファレンス)
  - [7-1. pii-context-defaults.yaml](#71-pii-context-defaultsyaml)
  - [7-2. pii-structured-defaults.yaml](#72-pii-structured-defaultsyaml)
  - [7-3. pii-secrecy-defaults.yaml](#73-pii-secrecy-defaultsyaml)

---

→ **続きは [Part 3](pii-detection-enhanced-part3.md)** (API リファレンス・導入ガイド・トラブルシューティング)

---

## 5. L3: OCR PII 検出

### 5-1. OcrProvider trait (標準 OCR インターフェース)

#### ⚠️ 重要: Misogi は OCR エンジンをバンドルしません

L1 の ContextProvider と同様、L3 も **trait 定義のみ** を提供します。
ユーザーは以下のいずれかの OCR サービスを実装して接続します:

| カテゴリ | プロバイダー | 特徴 |
|---------|------------|------|
| **オープンソース (ローカル)** | Tesseract | 無料、オフライン動作可能 |
| **クラウド (商用)** | Azure Computer Vision | 高精度、多言語対応 |
| **クラウド (商用)** | Google Cloud Vision | 文書理解強み |
| **クラウド (商用)** | AWS Textract | フォーム/表抽出 |
| **アジア特化** | 百度 OCR / 阿里云 OCR | 中国語/日本語最適化 |

#### Trait 定義

```rust
#[async_trait]
pub trait OcrProvider: Send + Sync {
    async fn extract_text(
        &self,
        image_data: &[u8],           // 生画像バイト (PNG/JPEG/TIFF/BMP/WebP)
    ) -> Result<OcrExtractionResult, OcrError>;

    fn provider_name(&self) -> &str;
    async fn is_available(&self) -> bool;
}
```

#### 抽出結果構造

```rust
pub struct OcrExtractionResult {
    pub full_text: String,              // 全ブロック結合テキスト
    pub blocks: Vec<OcrTextBlock>,      // 位置情報付きテキストブロック
    pub metadata: OcrImageMetadata,     // 画像メタデータ
    pub overall_confidence: f64,        // 全体信頼度
}

pub struct OcrTextBlock {
    pub text: String,                   // 抽出テキスト
    pub bbox: OcrBoundingBox,          // 正規化座標 [0,0,1,1]
    pub confidence: f64,                // ブロック単位信頼度
}

pub struct OcrBoundingBox {
    pub x_min: f64, pub y_min: f64,     // 左上
    pub x_max: f64, pub y_max: f64,     // 右下
}
```

#### 座標系

```
画像全体を [0.0, 0.0] → [1.0, 1.0] の正規化空間で表現:

(0,0) ──────────────── (1,0)
  │                       │
  │   ┌─────────────┐     │
  │   │ Text Block   │     │ ← bbox: {x_min:0.2, y_min:0.3, x_max:0.8, y_max:0.6}
  │   │ "SSN:123"    │     │
  │   └─────────────┘     │
  │                       │
(0,1) ──────────────── (1,1)

用途:
- UI 上で PII 位置をハイライト表示
- 自動マスキング/黒塗り処理
- 監査証跡として位置記録
```

### 5-2. OcrPiiDetector (OCR + Regex パイプライン)

#### 処理フロー

```
画像バイト (PNG/JPEG/TIFF/BMP/WebP)
     │
     ▼
┌──────────────────────────────────┐
│  ① 制約チェック                    │
│  • サイズ ≤ max_size_mb          │
│  • 形式がサポートされているか       │
└──────────────┬───────────────────┘
               ▼
┌──────────────────────────────────┐
│  ② OcrProvider.extract_text()   │
│  → OcrExtractionResult            │
│    .full_text                     │
│    .blocks[] (位置付き)           │
│    .overall_confidence            │
└──────────────┬───────────────────┘
               ▼
┌──────────────────────────────────┐
│  ③ 各ブロックに対し:              │
│  if block.confidence ≥ threshold │
│    → RegexPIIDetector.scan()     │
│    → PIIMatch[] 収集             │
│    + 位置情報 (bbox) 付与         │
└──────────────┬───────────────────┘
               ▼
┌──────────────────────────────────┐
│  ④ OcrPiiScanResult 集約         │
│  • found: bool                   │
│  • matches: Vec<OcrPiiMatch>     │
│  • action: 最も厳しいアクション   │
│  • total_chars_extracted          │
│  • scan_duration_ms               │
└──────────────────────────────────┘
```

#### 設定項目

| 項目 | 型 | デフォルト | 説明 |
|------|-----|----------|------|
| `min_ocr_confidence` | `f64` | 0.7 | これ未満のブロックはスキップ |
| `spatial_annotation` | `bool` | true | 位置情報を出力に含めるか |
| `min_dimension_px` | `u32` | 50 | 最小画像サイズ |
| `max_dimension_px` | `u32` | 10000 | 最大画像サイズ |
| `max_size_mb` | `usize` | 10 | 最大ファイルサイズ (MB) |

### 5-3. 設定例とコードサンプル

#### 例 1: Mock OCR でテスト

```rust
use std::sync::Arc;
use misogi_core::pii::ocr::{
    MockOcrProvider, OcrPiiDetector, OcrDetectorConfig,
};
use misogi_core::pii::RegexPIIDetector;

let mock_ocr = Arc::new(MockOcrProvider::with_text(
    "Email: admin@example.com Phone: 555-1234",
    0.95,
)) as Arc<dyn OcrProvider>;

let detector = Arc::new(RegexPIIDetector::with_jp_defaults());
let ocr_detector = OcrPiiDetector::with_defaults(mock_ocr, detector);

let image_data = include_bytes!("test_document.png");
let result = ocr_detector.scan_image(image_data, "doc-001.png").await?;

assert!(result.found);
assert_eq!(result.matches.len(), 2); // email + phone
println!("Extracted {} chars, found {} PII matches",
    result.total_chars_extracted, result.matches.len());
```

#### 例 2: Azure Computer Vision 接続例

```rust
use std::sync::Arc;
use async_trait::async_trait;
use misogi_core::pii::ocr::{OcrProvider, OcrExtractionResult, OcrError};

struct AzureVisionOcr {
    endpoint: String,
    api_key: String,
    client: reqwest::Client,
}

#[async_trait]
impl OcrProvider for AzureVisionOcr {
    async fn extract_text(&self, image_data: &[u8]) -> Result<OcrExtractionResult, OcrError> {
        let url = format!("{}/vision/v3.2/read/analyze", self.endpoint);

        let resp = self.client.post(&url)
            .header("Ocp-Apim-Subscription-Key", &self.api_key)
            .header("Content-Type", "application/octet-stream")
            .body(image_data.to_vec())
            .send().await
            .map_err(|e| OcrError::Communication(e.to_string()))?;

        let operation_url = resp.headers()
            .get("Operation-Location")
            .ok_or_else(|| OcrError::Internal("No Operation-Location".into()))?
            .to_str()
            .map_err(|_| OcrError::Internal("Invalid header".into()))?;

        let result = loop {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let check = self.client.get(operation_url)
                .header("Ocp-Apim-Subscription-Key", &self.api_key)
                .send().await
                .map_err(|e| OcrError::Communication(e.to_string()))?;

            let body: serde_json::Value = check.json().await
                .map_err(|e| OcrError::Communication(e.to_string()))?;

            if body["status"].as_str() == Some("succeeded") {
                break body;
            }
        };

        // Parse Azure response into OcrExtractionResult...
        Ok(OcrExtractionResult::empty())
    }

    fn provider_name(&self) -> &str { "azure-computer-vision" }
    async fn is_available(&self) -> bool { true }
}
```

---

## 6. L4: 機密レベル分類器

### 6-1. ユーザー定義レベル体系

#### ⚠️ 重要: レベル数・名称・ルールはすべてユーザー定義

Misogi は **特定のレベル命名や段階数を仮定しません**。
ユーザーは組織の要件に合わせて自由に設計できます:

| シナリオ | レベル構成例 | ユーザー定義内容 |
|---------|-------------|----------------|
| **国際汎用** | Critical / High / Medium / Low / Public | 5 段階 |
| **日本自治体** | 極機密(3A) / 機密(3B) / 扱い注意(3C) / 公開 | 4 段階 |
| **米国軍事** | Top Secret / Secret / Confidential / Unclassified | 4 段階 |
| **金融 PCI-DSS** | Cardholder / Sensitive / Public | 3 段階 |
| **医療 HIPAA** | PHI-Restricted / PHI-Limited / De-identified | 3 段階 |
| **自社独自** | *任意* | *任意* |

#### レベル定義構造

```rust
pub struct SecrecyLevelDef {
    pub id: String,                        // "critical", "3a", "top_secret"
    pub display_name: String,              // "Critical", "極機密"
    pub rank: u32,                         // 数値ランク (高いほど機密)
    pub color: String,                     // UI 色 (#DC2626)
    pub required_controls: Vec<ControlRequirement>, // 必須セキュリティ対策
    pub retention_years: u32,              // 保管年数
}

pub struct ControlRequirement {
    pub id: String,                        // "enc_at_rest"
    pub name: String,                      // "暗号化 (保存時)"
    pub required: bool,                    // 必須かどうか
    pub spec: String,                      // "AES-256+" (仕様参照)
}
```

### 6-2. 分類ルールエンジン

#### 条件タイプ (Condition)

```rust
pub enum Condition {
    /// 全ての PII タイプが存在すること (AND)
    RequireAllOf { pii_types: Vec<String> },

    /// いずれかの PII タイプが存在すること (OR)
    RequireAnyOf { pii_types: Vec<String> },

    /// 指定タイプが指定回数以上存在
    PiiTypesPresent { pii_types: Vec<String>, min_count: usize },

    /// 全ての除外タイプが**不在**であること
    ExcludeAllOf { pii_types: Vec<String> },

    /// いずれかの除外タイプが**不在**であること
    ExcludeAnyOf { pii_types: Vec<String> },
}
```

#### ルール評価フロー

```
検出された PII タイプ集合: {"national_id", "email"}
     │
     ▼
┌─────────────────────────────────────┐
│  全ルールを順次評価                  │
│                                     │
│  Rule 1: RequireAllOf["full_name","address","phone"]
│    → ❌ 不一致                      │
│                                     │
│  Rule 2: RequireAnyOf["national_id","credit_card"] + min_count=1
│    → ✅ 一致! national_id 存在      │
│    → result.level = "critical"      │
│                                     │
│  Rule 3: RequireAnyOf["email"] + ExcludeAllOf["full_name","national_id"]
│    → ❌ 不一致 (national_id が除外条件にある)│
│                                     │
│  ... (残りのルールも評価)            │
└──────────────┬──────────────────────┘
               ▼
マッチしたルール集合: [{rule_2: critical}]
     │
     ▼
競合解決: "highest" → rank 最大のものを選択
     │
     ▼
最終結果: level = "critical", reason = "Contains national identity identifier"
```

### 6-3. 決定競合の解決

複数のルールが同時にマッチする場合:

| 戦略 | 挙動 | 使用场景 |
|------|------|---------|
| `"highest"` (デフォルト) | **最高 rank** のレベルを採用 | 安全側に倒す (推奨) |
| `"lowest"` | **最低 rank** のレベルを採用 | 運用負荷軽減 |

#### 例: 競合解決シナリオ

```
検出 PII: {"credit_card", "email"}

マッチしたルール:
  Rule A: credit_card present → Critical (rank=4)
  Rule B: email only (exclude national_id/credit_card) → Medium (rank=2)

戦略 "highest":
  → Critical (rank=4 > rank=2)

戦略 "lowest":
  → Medium (rank=2 < rank=4)
```

### 6-4. 設定例とコードサンプル

#### 例 1: 汎用 4-tier テンプレート使用

```rust
use misogi_core::pii::secrecy::SecrecyClassifier;

let classifier = SecrecyClassifier::with_generic_tier()?;

// 分類実行
let result = classifier.classify(&["national_id", "email"])?;
println!("Level: {} (rank={})", result.level_display_name, result.level_rank);
// 出力: Level: Critical (rank=4)

println!("Required controls:");
for ctrl in &result.required_controls {
    println!("  - {} ({}) {}", ctrl.name, ctrl.spec,
        if ctrl.required { "[必須]" } else { "[推奨]" });
}
// 出力:
//   - Encryption at Rest (AES-256+) [必須]
//   - Encryption in Transit (TLS 1.2+) [必須]
//   - Multi-Factor Authentication () [必須]
//   - Full Audit Logging () [必須]
```

#### 例 2: YAML からカスタムスキーマ読込

```yaml
# my-secrecy-scheme.yaml
scheme: "org-custom"

levels:
  top_secret:
    display_name: "Top Secret"
    rank: 5
    color: "#7C2D12"
    required_controls:
      - { id: aes256_gcm, name: "AES-256-GCM", required: true, spec: "" }
      - { id: mfa_hardware, name: "Hardware MFA", required: true, spec: "" }
      - { id: dlp, name: "DLP Policy", required: true, spec: "" }
    retention_years: 10

  confidential:
    display_name: "Confidential"
    rank: 3
    color: "#B45309"
    required_controls:
      - { id: enc_aes, name: "AES Encryption", required: true, spec: "" }
    retention_years: 5

classification_rules:
  - id: "rule_top_secret_pii"
    condition: { require_any_of: ["national_id", "biometric"] }
    result: { level: "top_secret", reason: "Highly sensitive identity data" }

fallback:
  unknown_default: "confidential"
  conflict_resolution: "highest"
```

```rust
let classifier = SecrecyClassifier::from_yaml_file("my-secrecy-scheme.yaml")?;
```

#### 例 3: Builder パターンで完全プログラム構築

```rust
use misogi_core::pii::secrecy::{
    SecrecySchemeBuilder, Condition, ControlRequirement,
};

let classifier = SecrecySchemeBuilder::new()
    .set_scheme("finance-pci")
    .add_level("cardholder", "Cardholder Data", 4, "#DC2626")
    .add_level("sensitive", "Sensitive", 2, "#D97706")
    .add_level("public", "Public", 0, "#3B82F6")

    .add_rule("rule_cardholder_pan",
        Condition::RequireAnyOf { pii_types: vec!["credit_card".to_string()] },
        "cardholder",
        "Contains payment card number"
    )
    .add_rule("rule_sensitive_identity",
        Condition::RequireAnyOf { pii_types: vec!["full_name".to_string(), "email".to_string()] },
        "sensitive",
        "Contains identifiable information"
    )
    .add_rule("rule_public_clean",
        Condition::PiiTypesPresent { pii_types: vec![], min_count: 0 },
        "public",
        "No personal data detected"
    )

    .fallback_default("public")
    .build()?;

let result = classifier.classify(&["credit_card", "cvv"])?;
assert_eq!(result.level_id, "cardholder");
assert_eq!(result.level_rank, 4);
```

---

## 7. 設定ファイル完全リファレンス

### 7-1. pii-context-defaults.yaml

**場所**: `crates/misogi-core/config/pii-context-defaults.yaml`
**用途**: KeywordRuleEngine の汎用デフォルト設定 (内蔵、自動ロード)

| 項目 | 型 | デフォルト | 説明 |
|------|-----|----------|------|
| `version` | string | "1.0" | 設定フォーマットバージョン |
| `profile` | string | "universal" | プロフィール識別子 |
| `global_settings.context_window_size` | int | 100 | 前後文脈文字数 |
| `global_settings.positive_threshold` | float | 0.7 | PII 確認閾値 |
| `global_settings.negative_threshold` | float | 0.3 | 誤検出棄却閾値 |
| `global_settings.case_sensitive` | bool | false | 大小文字区別 |
| `global_anti_keywords[]` | array | 10項目 | 全タイプ共通反キーワード |
| `pii_types.*.display_name` | string | — | 表示名 |
| `pii_types.*.positive[]` | array | — | 正キーワードルール |
| `pii_types.*.anti[]` | array | — | 反キーワードルール |

**各キーワードルールのフィールド**:

| フィールド | 型 | 必須 | 説明 |
|-----------|-----|------|------|
| `keyword` | string | ✅ | 検索キーワード |
| `weight` | float | ✅ | 重み [0.0, 1.0] |
| `position` | enum | ❌ (default: either) | before / after / before_or_after / either |

### 7-2. pii-structured-defaults.yaml

**場所**: `crates/misogi-core/config/pii-structured-defaults.yaml`
**用途**: FieldClassifier の汎用フィールドマッピング

| 項目 | 型 | デフォルト | 説明 |
|------|-----|----------|------|
| `field_mappings[].field_pattern` | string | — | マッチパターン (literal/wildcard/regex) |
| `field_mappings[].pii_type` | string | — | 対応 PII タイプ |
| `field_mappings[].confidence` | float | 0.8 | 信頼度 [0.0, 1.0] |
| `field_mappings[].action` | enum | alert_only | mask / redact / alert_only / log_only |

**プリセットマッピング一覧**:

| field_pattern | pii_type | confidence | action |
|--------------|----------|------------|--------|
| `full_name` | full_name | 0.99 | mask |
| `email` | email | 0.98 | mask |
| `phone` | phone | 0.92 | mask |
| `card_number` | credit_card | 0.98 | mask |
| `ccv` | credit_card_cvv | 0.95 | redact |
| `*_id` | generic_id | 0.45 | alert_only |
| `*_no` | generic_number | 0.40 | log_only |

### 7-3. pii-secrecy-defaults.yaml

**場所**: `crates/misogi-core/config/pii-secrecy-defaults.yaml`
**用途**: SecrecyClassifier の汎用 4-tier テンプレート

| 項目 | 型 | 説明 |
|------|-----|------|
| `scheme` | string | スキーマ識別子 ("generic-4-tier") |
| `levels.*.id` | string | レベル ID ("critical", "high", ...) |
| `levels.*.rank` | uint | ランク値 (高いほど機密) |
| `levels.*.color` | string | UI 色 (hex) |
| `levels.*.required_controls[]` | array | 必須セキュリティ対策 |
| `levels.*.retention_years` | uint | 保管年数 |
| `classification_rules[].id` | string | ルール ID |
| `classification_rules[].condition` | enum | 条件 (RequireAllOf/AnyOf/Present/Exclude*) |
| `classification_rules[].result.level` | string | 割当レベル ID |
| `classification_rules[].result.reason` | string | 判定理由 |
| `fallback.unknown_default` | string | 未分類時のデフォルト |
| `fallback.conflict_resolution` | string | "highest" or "lowest" |

**プリセットレベル一覧**:

| Level | Rank | Color | Controls | Retention |
|-------|------|-------|----------|------------|
| critical | 4 | #DC2626 | enc_rest, enc_transit, mfa, audit_full | 7 years |
| high | 3 | #EA580C | enc_rest, audit_access | 5 years |
| medium | 2 | #D97706 | access_control, label | 3 years |
| low | 1 | #65A30D | basic_auth | 1 year |
| public | 0 | #3B82F6 | (none) | 1 year |

---

*→ [Part 2 完] 続きは [Part 3](pii-detection-enhanced-part3.md): API リファレンス・導入ガイドライン・トラブルシューティング*
