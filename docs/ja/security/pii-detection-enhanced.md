# PII 検出深度拡張ガイド — Part 1: 概要・コンテキスト分析・構造化データ

> **対象読者**: セキュリティエンジニア、コンプライアンス担当者、システムアーキテクト
>
> **前提知識**: [PII 検出設定ガイド (基礎版)](pii-detection.md) の内容を理解していること
>
> **関連機能**: `pii-enhanced` feature flag (全4層を有効化)

---

## 目次 (Part 1)

- [1. 概要](#1-概要)
  - [1-1. 4 層拡張アーキテクチャ](#11-4-層拡張アーキテクチャ)
  - [1-2. 競合製品との差異化](#12-競合製品との差異化)
  - [1-3. 三大設計原則 (Three Iron Rules)](#13-三大設計原則-three-iron-rules)
- [2. Feature Flags と依存関係](#2-feature-flags-と依存関係)
- [3. L1: コンテキスト分析エンジン](#3-l1-コンテキスト分析エンジン)
  - [3-1. ContextProvider trait (標準 NLP インターフェース)](#31-contextprovider-trait-標準-nlp-インターフェース)
  - [3-2. KeywordRuleEngine (設定可能なキーワードルールエンジン)](#32-keywordruleengine-設定可能なキーワードルールエンジン)
  - [3-3. ContextAnalyzer (統合エントリポイント)](#33-contextanalyzer-統合エントリポイント)
  - [3-4. 設定例とコードサンプル](#34-設定例とコードサンプル)
- [4. L2: 構造化データスキャナ](#4-l2-構造化データスキャナ)
  - [4-1. FieldClassifier (フィールド名→PIIタイプマッピング)](#41-fieldclassifier-フィールド名piiタイプマッピング)
  - [4-2. CSV/JSON/XML スキャナ](#42-csvjsonxml-スキャナ)
  - [4-3. 設定例とコードサンプル](#43-設定例とコードサンプル)

---

→ **続きは [Part 2](pii-detection-enhanced-part2.md)** (L3 OCR + L4 機密分類 + 設定リファレンス)

---

## 1. 概要

### 1-1. 4 層拡張アーキテクチャ

Misogi の PII 検出機能は、従来の正規表現ベース (`RegexPIIDetector`) に加え、**4 層の高度な検出エンジン**を追加しました。

```
┌─────────────────────────────────────────────────────────────┐
│                  入力 (Text / CSV / JSON / XML / Image)      │
└───────────────────────────┬───────────────────────────────┘
                            ▼
              ┌─────────────┴─────────────┐
              │    フォーマット分類器      │
              └──────┬──────────┬────────┘
                     │          │
            ┌──────▼──┐  ┌───▼───┐  ┌──────▼──────┐
            │ テキスト │  │ CSV   │  │   画像      │
            │         │  │ JSON  │  │             │
            │         │  │  XML  │  │             │
            └────┬────┘  └───┬───┘  └──────┬───────┘
                 │           │              │
                 ▼           ▼              ▼
        ┌──────────────────────────────────────┐
        │     RegexPIIDetector (既存)          │
        │     正規表現ベースの PII スキャン      │
        └──────────────┬───────────────────────┘
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
   ┌────────────┐ ┌────────────┐ ┌────────────┐
   │ L1 Context │ │ L2 Struct. │ │ L3 OCR     │
   │ Analyzer   │ │ Scanner    │ │ Detector   │
   │ (コンテキスト│ │ (フィールド  │ │ (画像テキスト│
   │  判断)      │ │ レベル検出) │ │ 抽出+スキャン)│
   └──────┬─────┘ └──────┬─────┘ └──────┬─────┘
          │              │              │
          └──────────────┼──────────────┘
                         ▼
              ┌────────────────────┐
              │  L4 SecrecyClassifier │
              │  (機密レベル自動分類)   │
              │  ユーザー定義可能       │
              └──────────┬─────────┘
                         ▼
              ┌────────────────────┐
              │   最終 PIIScanResult │
              │  • matches[]       │
              │  • action           │
              │  • secrecy_level    │ ← 新規フィールド
              │  • required_controls│ ← 新規フィールド
              └────────────────────┘
```

### 1-2. 競合製品との差異化

| 機能 | Misogi (拡張後) | 競合 A | 競合 B |
|------|----------------|--------|--------|
| 正規表現 PII スキャン | ✅ | ✅ | ✅ |
| **コンテキスト-aware 検出** | ✅ **独有** | ❌ | ❌ |
| **CSV/JSON/XML フィールドレベル** | ✅ **独有** | ❌ | ⚠️ 部分的 |
| **画像 OCR PII (標準インターフェース)** | ✅ **领先** | ❌ | ⚠️ 固定実装 |
| **機密レベル自動分類 (ユーザー定義)** | ✅ **独有** | ❌ | ⚠️ 固定3段階 |
| **NLP/ML エンジン内蔵** | ❌ (traitのみ) | ✅ 内蔵 | ✅ 内蔵 |
| **ルールの外部設定可能性** | ✅ **100%** | ⚠️ 部分 | ❌ 硬コード |
| **デフォルト値の国際対応** | ✅ **汎用** | ⚠️ 特定国 | ⚠️ 特定国 |

### 1-3. 三大設計原則 (Three Iron Rules)

Misogi の PII 拡張機能は、以下の **3 つの鉄の原則** に基づいて設計されています。

#### 原則 ①: 全エンジンは標準インターフェース (trait) のみ提供

⚠️ **重要**: Misogi は **NLP/ML/OCR エンジンを一切バンドルしません**。

```
ユーザー側で実装するもの:
┌─────────────────────────────────────────────┐
│  ContextProvider (trait)                   │
│  ├── OpenAI GPT-4 / Azure OpenAI          │ ← ユーザー実装
│  ├── AWS Comprehend / Google Cloud NLP    │ ← ユーザー実装
│  ├── Ollama (ローカル LLM)                  │ ← ユーザー実装
│  └── 自社構築 NLP サービス                   │ ← ユーザー実装
│                                             │
│  OcrProvider (trait)                        │
│  ├── Tesseract (オープンソース)             │ ← ユーザー実装
│  ├── Azure Computer Vision                  │ ← ユーザー実装
│  ├── Google Cloud Vision                    │ ← ユーザー実装
│  └── 百度 OCR / 阿里云 OCR                  │ ← ユーザー実装
└─────────────────────────────────────────────┘

Misogi が提供するもの:
┌─────────────────────────────────────────────┐
│  • 標準 trait 定義                           │
│  • Mock 実装 (テスト用)                      │
│  • KeywordRuleEngine (ゼロコスト代替)        │ ← 内蔵フォールバック
└─────────────────────────────────────────────┘
```

#### 原則 ②: 全ルール 100% 外部から設定可能

✅ **外部可配**: キーワード辞書、フィールドマッピング、分類ルール、機密レベル定義 — **すべて YAML/JSON/プログラム API で注入、ゼロ硬コード**

#### 原則 ③: デフォルト値は国際汎用

💡 **汎用優先**: 内蔵デフォルト値は **国際的な汎用シナリオ** を対象。
日本政府/特定業界のルールは **オプション設定パッケージ** として配布（コアには結合しない）。

---

## 2. Feature Flags と依存関係

### 2-1. Feature Matrix

| Feature Flag | 有効になるモジュール | 新規依存 | 用途 |
|-------------|-------------------|---------|------|
| `pii-context` | context/ | `serde_yaml` | コンテキスト分析 (L1) |
| `pii-structured` | structured/ | `csv`, `quick-xml` | 構造化データスキャン (L2) |
| `pii-ocr` | ocr/ | *(なし)* | OCR インターフェース (L3) |
| `pii-secrecy` | secrecy/ | `serde_yaml` | 機密レベル分類 (L4) |
| `pii-enhanced` | **全モジュール** | 上記全て | 完全スタック (一括有効化) |

### 2-2. Cargo.toml 設定例

```toml
[dependencies]
misogi-core = { version = "0.1", features = ["pii-enhanced"] }

# または個別に有効化:
# misogi-core = { version = "0.1", features = [
#     "pii-context",      # L1 のみ
#     "pii-structured",  # L2 のみ
#     "pii-secrecy",      # L4 のみ (L3 は依存なし)
# ]}
```

### 2-3. 依存関係図

```
pii-enhanced (meta-feature)
    ├── pii-context ──────────┐
    │   └── dep: serde_yaml  │
    ├── pii-structured ──────┼─── 新規依存
    │   ├── dep: csv         │
    │   └── dep: quick-xml   │
    ├── pii-ocr ─────────────┤ (ゼロ新規依存)
    │   └── (trait only)     │
    └── pii-secrecy ────────┘
        └── dep: serde_yaml
```

---

## 3. L1: コンテキスト分析エンジン

### 3-1. ContextProvider trait (標準 NLP インターフェース)

#### 目的

正規表現でマッチした候補テキストが **真の PII かどうか** を文脈から判断し、誤検出 (False Positive) を低減します。

#### 問題例

```
入力: "123456789012" (12桁数字)

ケース A: "My Number: 123456789012 is your ID"
        → ✅ 真のマイナンバー (前後に "My Number" という強いヒント)

ケース B: "Invoice no. 123456789012, reference code ABC"
        → ❌ 伝票番号 (前後に "Invoice", "reference" という反ヒント)

同じ 12 桁数字でも、周囲の文脈によって意味が異なります。
```

#### Trait 定義

```rust
#[async_trait]
pub trait ContextProvider: Send + Sync {
    async fn analyze_context(
        &self,
        request: &ContextAnalysisRequest,
    ) -> Result<ContextAnalysisResponse, ContextError>;

    async fn analyze_batch(
        &self,
        requests: &[ContextAnalysisRequest],
    ) -> Result<Vec<ContextAnalysisResponse>, ContextError>;

    fn provider_name(&self) -> &str;
    async fn is_available(&self) -> Result<bool, ContextError>;
}
```

#### リクエスト/レスポンス構造

```rust
// リクエスト
pub struct ContextAnalysisRequest {
    pub candidate_text: String,    // 正規マッチしたテキスト (例: "123456789012")
    pub pii_type: String,         // PII タイプ (例: "my_number")
    pub prefix: String,           // マッチ箇所の前文脈
    pub suffix: String,           // マッチ箇所の後文脈
    pub full_text: Option<String>, // 文全体 (オプション)
    pub metadata: ContextMetadata, // 追加メタデータ
}

// レスポンス
pub struct ContextAnalysisResponse {
    pub is_pii: bool,                    // true = PII 確認, false = 棄却
    pub confidence_score: f64,          // 信頼度 [0.0, 1.0]
    pub reason: String,                 // 判定理由 (監査ログ用)
    pub matched_indicators: Vec<String>, // PII 支持証拠
    pub false_positive_signals: Vec<String>, // 誤検出信号
}
```

#### 対応可能な外部サービス

| プロバイダータイプ | レイテンシ | コスト | 精度 | 実装例 |
|---------------|----------|------|------|--------|
| GPT-4 / Claude | 500ms-2s | $$ | Very High | OpenAI API |
| Azure AI Language | 100-300ms | $ | High | Azure SDK |
| AWS Comprehend | 100-200ms | $ | High | AWS SDK |
| Ollama (Local) | 200-800ms | Free | Medium-High | ollama-rs |
| 自社構築 NLP | 要仕様 | 要投資 | 可変 | Custom |

### 3-2. KeywordRuleEngine (設定可能なキーワードルールエンジン)

#### 目的

NLP サービスが利用できない場合 (または導入コストを抑えたい場合)、**キーワード重み付けベースの軽量判定エンジン** が自動的にフォールバックとして使用されます。

#### アルゴリズム

```
1. マッチ箇所の前後テキストを抽出 (context window)
2. 「正キーワード」(PII 支持) を検索 → 正スコア加算
3. 「反キーワード」(誤検出信号) を検索 → 負スコア加算
4. 正味スコア = Σ(正スコア) - Σ(負スコア)
5. 正規化: normalized_score = tanh(raw) / 2 + 0.5  → [0, 1]
6. 閾値比較:
   - positive_threshold 以上 → ✅ PII 確認
   - negative_threshold 以下 → ❌ 誤検出として棄却
```

#### 設定ファイル形式 (YAML)

```yaml
version: "1.0"
profile: "universal"

global_settings:
  context_window_size: 100      # 前後何文字を文脈として使用するか
  positive_threshold: 0.7       # これ以上 → PII 確認
  negative_threshold: 0.3       # これ以下 → 誤検出棄却
  case_sensitive: false        # 大文字小文字を区別しない

# 全 PII タイプ共通の反キーワード (誤検出信号)
global_anti_keywords:
  - { keyword: "invoice", weight: 0.70, position: either }
  - { keyword: "no.", weight: 0.65, position: before }
  - { keyword: "serial", weight: 0.70, position: after }
  - { keyword: "sample", weight: 0.50, position: before }

# PII タイプ別ルール
pii_types:
  national_id:
    display_name: "National ID Number"
    positive:
      - { keyword: "national id", weight: 0.90, position: before }
      - { keyword: "ssn", weight: 0.90, position: before }
      - { keyword: "passport", weight: 0.92, position: before }
      - { keyword: "身份证", weight: 0.93, position: before }  # 中国語サポート
    anti:
      - { keyword: "reference", weight: 0.60, position: either }

  credit_card:
    display_name: "Credit Card"
    positive:
      - { keyword: "credit card", weight: 0.95, position: before }
      - { keyword: "カード番号", weight: 0.95, position: before } # 日本語
    anti:
      - { keyword: "member", weight: 0.55, position: either }
```

#### キーワード位置指定

| Position | 説明 | 例 |
|----------|------|-----|
| `before` | 候補テキストの**前**のみ検索 | `"SSN: 123"` → "SSN:" が前にある |
| `after` | 候補テキストの**後**のみ検索 | `"123 (conf)"` → "(conf)" が後にある |
| `before_or_after` | 前後どちらでも | `"card: 123 or ref 123"` |
| `either` | 前後どちらでも (上記の別名) | 同上 |

### 3-3. ContextAnalyzer (統合エントリポイント)

#### 役割

`ContextAnalyzer` は以下の路由を行います:

```
analyze() リクエスト
     │
     ├─ Provider が設定済み && 利用可能?
     │    └─ YES → ContextProvider.analyze_context()
     │    └─ NO  (or FailFast モ)
     │         └─ KeywordRuleEngine.analyze()  ← ゼロコストフォールバック
```

#### FallbackStrategy オプション

| 戦略 | 挙動 | 使用场景 |
|------|------|---------|
| `GracefulDegradation` | Provider ダウン時はキーワードに降格 | **推奨 (デフォルト)** |
| `FailFast` | Provider エラー時は即座にエラー返却 | 高信頼性必須環境 |
| `KeywordOnly` | 常にキーワードエンジンを使用 | NLP 不要環境 |

### 3-4. 設定例とコードサンプル

#### 例 1: デフォルト設定で即時起動

```rust
use misogi_core::pii::context::ContextAnalyzer;

let analyzer = ContextAnalyzer::with_defaults()?;  // 汎用デフォルト読込

let request = ContextAnalysisRequest::new(
    "123456789012",
    "national_id",
    "Your national id number is ",
    " please keep safe",
);

let result = analyzer.analyze(&request).await?;
assert!(result.is_pii);  // "national id" が前にあるので確認
println!("Confidence: {}, Reason: {}", result.confidence_score, result.reason);
```

#### 例 2: YAML ファイルからカスタムルール読込

```rust
use misogi_core::pii::context::{ContextAnalyzer, KeywordRuleEngine};

let engine = KeywordRuleEngine::from_yaml_file("config/my-context-rules.yaml")?;
let analyzer = ContextAnalyzer::with_keyword_engine(engine);
```

#### 例 3: Builder パターンで完全プログラム構築

```rust
use misogi_core::pii::context::{
    RuleEngineBuilder, KeywordPosition, FallbackStrategy, ContextAnalyzerConfig,
};

let engine = RuleEngineBuilder::new()
    .set_profile("finance")
    .set_context_window(150)
    .set_thresholds(0.8, 0.2)
    .add_pii_type("account_number", "Account Number")
    .add_positive("acct no", 0.95, KeywordPosition::Before)
    .add_anti("transaction", 0.60, KeywordPosition::Either)
    .done()
    .build()?;

let analyzer = ContextAnalyzer::with_keyword_engine(engine)
    .with_config(ContextAnalyzerConfig {
        fallback: FallbackStrategy::GracefulDegradation,
        enable_cache: true,
        cache_size: 2000,
    });
```

#### 例 4: 外部 NLP Provider を接続 (OpenAI 例)

```rust
use std::sync::Arc;
use async_trait::async_trait;
use misogi_core::pii::context::{
    ContextProvider, ContextAnalysisRequest, ContextAnalysisResponse,
    ContextError, ContextAnalyzer,
};

struct OpenAiContextProvider {
    client: reqwest::Client,
    api_key: String,
    model: String,
}

#[async_trait]
impl ContextProvider for OpenAiContextProvider {
    async fn analyze_context(
        &self,
        request: &ContextAnalysisRequest,
    ) -> Result<ContextAnalysisResponse, ContextError> {
        let prompt = format!(
            "Is '{}' in the context '{}' a real {}? \
             Respond with JSON: {{\"is_pii\": bool, \"confidence\": float, \"reason\": string}}",
            request.candidate_text,
            request.combined_context(),
            request.pii_type,
        );

        let response = self.client
            .post("https://api.openai.com/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&serde_json::json!({
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "response_format": {"type": "json_object"},
            }))
            .send()
            .await
            .map_err(|e| ContextError::Communication(e.to_string()))?;

        let body: serde_json::Value = response.json().await
            .map_err(|e| ContextError::Communication(e.to_string()))?;

        Ok(ContextAnalysisResponse {
            is_pii: body["is_pii"].as_bool().unwrap_or(false),
            confidence_score: body["confidence"].as_f64().unwrap_or(0.5),
            reason: body["reason"].as_str().unwrap_or("").to_string(),
            matched_indicators: vec![],
            false_positive_signals: vec![],
        })
    }

    fn provider_name(&self) -> &str { "openai-gpt4" }
    async fn is_available(&self) -> Result<bool, ContextError> { Ok(true) }
}

// 使用例
let provider = Arc::new(OpenAiContextProvider { /* ... */ }) as Arc<dyn ContextProvider>;
let analyzer = ContextAnalyzer::with_provider(provider, KeywordRuleEngine::with_defaults()?);
```

---

## 4. L2: 構造化データスキャナ

### 4-1. FieldClassifier (フィールド名→PIIタイプマッピング)

#### 目的

CSV/JSON/XML のような構造化データにおいて、**フィールド名** からそのフィールドが何种の PII を含むかを判定します。

#### マッチングパターン

| パターン種別 | 例 | 一致条件 |
|------------|-----|---------|
| **Literal (完全一致)** | `"email"` | フィールド名 == "email" |
| **Wildcard suffix** | `"*_id"` | "user_id", "order_id" 等 |
| **Full regex** | `"(?i)^name$"` | 大文字小文字無視の "name" |

#### FieldAction 種別

| Action | 挙動 | 使用场景 |
|--------|------|---------|
| `Mask` | 値をマスキング (`j***n`) | 通常運用 (推奨) |
| `Redact` | 値を完全削除 (`[REDACTED]`) | 高感度データ (CVV等) |
| `AlertOnly` | ログのみ記録 | 監視目的 |
| `LogOnly` | 最軽度のログ | 低信頼度フィールド |

### 4-2. CSV/JSON/XML スキャナ

#### 共通特性

| 特性 | CsvPiiScanner | JsonPiiScanner | XmlPiiScanner |
|------|--------------|----------------|--------------|
| 入力形式 | CSV テキスト | JSON | XML |
| 深さ制限 | なし | `max_depth: 10` | `max_depth: 10` |
| 配列処理 | 行毎スキャン | 各要素スキャン | 子要素スキャン |
| 属性スキャン | 該当なし | 該当なし | ✅ 可能 |

#### 出力構造 (StructuredScanResult)

```rust
pub struct StructuredScanResult {
    pub format: StructuredFormat,           // Csv / Json / Xml
    pub total_fields: usize,               // 全フィールド数
    pub pii_fields: Vec<FieldScanResult>,  // PII 検出フィールド
    pub overall_action: FieldAction,       // 最も厳しいアクション
    pub bytes_processed: u64,              // 処理バイト数
    pub scan_duration_ms: u64,             // スキャン時間
}

pub struct FieldScanResult {
    pub field_path: String,    // "row[2].col[5]" or "users[0].email"
    pub field_name: String,   // "email"
    pub raw_value: String,    // "john@example.com"
    pub masked_value: String, // "j********@com"
    pub pii_type: String,     // "email"
    pub confidence: f64,       // 0.98
    pub action: FieldAction,  // Mask
}
```

### 4-3. 設定例とコードサンプル

#### YAML 設定ファイル例

```yaml
version: "1.0"

field_mappings:
  # --- Identity ---
  - { field_pattern: "full_name", pii_type: full_name, confidence: 0.99, action: mask }
  - { field_pattern: "email", pii_type: email, confidence: 0.98, action: mask }
  - { field_pattern: "national_id", pii_type: national_id, confidence: 0.95, action: mask }

  # --- Payment ---
  - { field_pattern: "card_number", pii_type: credit_card, confidence: 0.98, action: mask }
  - { field_pattern: "ccv", pii_type: credit_card_cvv, confidence: 0.95, action: redact }

  # --- Wildcard (低信頼度) ---
  - { field_pattern: "*_id", pii_type: generic_id, confidence: 0.45, action: alert_only }
  - { field_pattern: "*_no", pii_type: generic_number, confidence: 0.40, action: log_only }
```

#### Rust コード例: CSV スキャン

```rust
use misogi_core::pii::structured::{CsvPiiScanner, FieldClassifier};

let scanner = CsvPiiScanner::with_defaults();  // 汎用デフォルト

let csv_content = "\
name,email,phone,department\n\
John Smith,john@example.com,555-1234,Sales\n\
Jane Doe,jane@test.org,555-5678,Engineering";

let result = scanner.scan(csv_content)?;

assert_eq!(result.format, StructuredFormat::Csv);
assert!(!result.pii_fields.is_empty());

for field in &result.pii_fields {
    println!("Path: {} | Type: {} | Action: {:?}",
        field.field_path, field.pii_type, field.action);
    // 出力例:
    // Path: row[0].col[1] | Type: email | Action: Mask
    // Path: row[0].col[2] | Type: phone | Action: Mask
}
```

#### Rust コード例: JSON スキャン (ネスト構造)

```rust
use misogi_core::pii::structured::JsonPiiScanner;

let scanner = JsonPiiScanner::with_defaults();

let json_content = r#"{
    "users": [
        {"name": "Alice", "email": "alice@test.com", "ssn": "123-45-6789"},
        {"name": "Bob", "email": "bob@example.com"}
    ]
}"#;

let result = scanner.scan(json_content)?;
assert_eq!(result.pii_fields.len(), 3);  // email×2 + ssn×1
```

#### Rust コード例: カスタム FieldClassifier

```rust
use misogi_core::pii::structured::{
    FieldClassifierBuilder, FieldAction,
};

let fc = FieldClassifierBuilder::new()
    .add_literal("my_email", "email", 0.98, FieldAction::Mask)
    .add_literal("secret_key", "api_key", 0.99, FieldAction::Redact)
    .add_wildcard("*_token", "auth_token", 0.85, FieldAction::Mask)
    .default_action(FieldAction::AlertOnly)
    .build();

assert_eq!(fc.mapping_count(), 3);

let classification = fc.classify("user_auth_token");
assert!(classification.matched);
assert_eq!(classification.pii_type, "auth_token");
```

---

*→ [Part 1 完] 続きは [Part 2](pii-detection-enhanced-part2.md): L3 OCR PII 検出 + L4 機密レベル分類 + 設定ファイル完全リファレンス*
