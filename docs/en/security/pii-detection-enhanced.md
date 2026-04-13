# PII Detection Enhancement Guide — Part 1: Overview, Context Analysis & Structured Data

> **Target Audience**: Security Engineers, Compliance Officers, System Architects
>
> **Prerequisites**: Understanding of [PII Detection Guide (Basic)](pii-detection.md)
>
> **Related Feature**: `pii-enhanced` flag (enables all 4 layers)

---

## Table of Contents (Part 1)

- [1. Overview](#1-overview)
  - [1-1. 4-Layer Extended Architecture](#11-4-layer-extended-architecture)
  - [1-2. Competitive Differentiation](#12-competitive-differentiation)
  - [1-3. Three Iron Rules (Design Principles)](#13-three-iron-rules-design-principles)
- [2. Feature Flags & Dependencies](#2-feature--flags--dependencies)
- [3. L1: Context Analysis Engine](#3-l1-context-analysis-engine)
  - [3-1. ContextProvider Trait (Standard NLP Interface)](#31-contextprovider-trait-standard-nlp-interface)
  - [3-2. KeywordRuleEngine (Configurable Rule Engine)](#32-keywordruleengine-configurable-rule-engine)
  - [3-3. ContextAnalyzer (Unified Entry Point)](#33-contextanalyzer-unified-entry-point)
  - [3-4. Configuration Examples & Code Samples](#34-configuration-examples--code-samples)
- [4. L2: Structured Data Scanner](#4-l2-structured-data-scanner)
  - [4-1. FieldClassifier (Field Name → PII Type Mapping)](#41-fieldclassifier-field-name--pii-type-mapping)
  - [4-2. CSV/JSON/XML Scanners](#42-csvjsonxml-scanners)
  - [4-3. Configuration Examples & Code Samples](#43-configuration-examples--code-samples-1)

---

→ **Continue with [Part 2](pii-detection-enhanced-part2.md)** (L3 OCR + L4 Secrecy Classification + Config Reference)

---

## 1. Overview

### 1-1. 4-Layer Extended Architecture

Misogi's PII detection extends beyond the existing regex-based (`RegexPIIDetector`) approach with **4 layers of advanced detection engines**.

```
┌─────────────────────────────────────────────────────────────┐
│              Input (Text / CSV / JSON / XML / Image)         │
└───────────────────────────┬───────────────────────────────┘
                            ▼
              ┌─────────────┴─────────────┐
              │    Format Classifier       │
              └──────┬──────────┬────────┘
                     │          │
            ┌──────▼──┐  ┌───▼───┐  ┌──────▼──────┐
            │  Text   │  │ CSV   │  │    Image     │
            │         │  │ JSON  │  │              │
            │         │  │  XML  │  │              │
            └────┬────┘  └───┬───┘  └──────┬───────┘
                 │           │              │
                 ▼           ▼              ▼
        ┌──────────────────────────────────────┐
        │      RegexPIIDetector (Existing)     │
        │      Regex-based PII scanning        │
        └──────────────┬───────────────────────┘
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
   ┌────────────┐ ┌────────────┐ ┌────────────┐
   │ L1 Context │ │ L2 Struct. │ │ L3 OCR     │
   │ Analyzer   │ │ Scanner    │ │ Detector   │
   │ (Context-  │ │ (Field-    │ │ (Image     │
   │  aware)    │ │  level)    │ │  text+scan)│
   └──────┬─────┘ └──────┬─────┘ └──────┬─────┘
          │              │              │
          └──────────────┼──────────────┘
                         ▼
              ┌────────────────────┐
              │ L4 SecrecyClassifier│
              │ (Auto classification)│
              │ User-definable       │
              └──────────┬─────────┘
                         ▼
              ┌────────────────────┐
              │ Final PIIScanResult │
              │ • matches[]        │
              │ • action            │
              │ • secrecy_level     │ ← NEW field
              │ • required_controls │ ← NEW field
              └────────────────────┘
```

### 1-2. Competitive Differentiation

| Capability | Misogi (Enhanced) | Competitor A | Competitor B |
|------------|-------------------|--------------|---------------|
| Regex PII Scan | ✅ | ✅ | ✅ |
| **Context-aware detection** | ✅ **Unique** | ❌ | ❌ |
| **CSV/JSON/XML field-level** | ✅ **Unique** | ❌ | ⚠️ Partial |
| **Image OCR PII (standard interface)** | ✅ **Leading** | ❌ | ⚠️ Fixed impl |
| **Secrecy auto-classification (user-defined)** | ✅ **Unique** | ❌ | ⚠️ Fixed 3-tier |
| **Bundled NLP/ML engine** | ❌ (trait only) | ✅ Bundled | ✅ Bundled |
| **External rule configurability** | ✅ **100%** | ⚠️ Partial | ❌ Hardcoded |
| **International defaults** | ✅ **Universal** | ⚠️ Country-specific | ⚠️ Country-specific |

### 1-3. Three Iron Rules (Design Principles)

Misogi's PII extension is built on **3 iron rules**:

#### Rule ①: All Engines Provide Standard Interfaces (traits) Only

⚠️ **Important**: Misogi **does NOT bundle any NLP/ML or OCR engine**.

```
What users implement:
┌─────────────────────────────────────────────┐
│  ContextProvider (trait)                   │
│  ├── OpenAI GPT-4 / Azure OpenAI          │ ← User implements
│  ├── AWS Comprehend / Google Cloud NLP    │ ← User implements
│  ├── Ollama (local LLM)                    │ ← User implements
│  └── Custom self-hosted NLP service         │ ← User implements
│                                             │
│  OcrProvider (trait)                        │
│  ├── Tesseract (open-source)               │ ← User implements
│  ├── Azure Computer Vision                  │ ← User implements
│  ├── Google Cloud Vision                    │ ← User implements
│  └── Baidu OCR / Alibaba Cloud OCR          │ ← User implements
└─────────────────────────────────────────────┘

What Misogi provides:
┌─────────────────────────────────────────────┐
│  • Standard trait definitions               │
│  • Mock implementations (for testing)        │
│  • KeywordRuleEngine (zero-cost fallback)   │ ← Built-in fallback
└─────────────────────────────────────────────┘
```

#### Rule ②: All Rules 100% Externally Configurable

✅ **Externally configurable**: Keyword dictionaries, field mappings, classification rules, secrecy level definitions — **all injectable via YAML/JSON/programming API, zero hardcoding**

#### Rule ③: Defaults Are International Universal

💡 **Universal first**: Built-in defaults target **international generic scenarios**.
Japan-government-specific rules are distributed as **optional config packages**, not coupled into core.

---

## 2. Feature Flags & Dependencies

### 2-1. Feature Matrix

| Feature Flag | Enabled Modules | New Dependencies | Purpose |
|-------------|-----------------|------------------|---------|
| `pii-context` | context/ | `serde_yaml` | Context analysis (L1) |
| `pii-structured` | structured/ | `csv`, `quick-xml` | Structured data scanner (L2) |
| `pii-ocr` | ocr/ | *(none)* | OCR interface (L3) |
| `pii-secrecy` | secrecy/ | `serde_yaml` | Secrecy level classifier (L4) |
| `pii-enhanced` | **All modules** | All above | Full stack (enable all at once) |

### 2-2. Cargo.toml Example

```toml
[dependencies]
misogi-core = { version = "0.1", features = ["pii-enhanced"] }

# Or enable individually:
# misogi-core = { version = "0.1", features = [
#     "pii-context",      # L1 only
#     "pii-structured",  # L2 only
#     "pii-secrecy",      # L4 only (L3 has no deps)
# ]}
```

### 2-3. Dependency Graph

```
pii-enhanced (meta-feature)
    ├── pii-context ──────────┐
    │   └── dep: serde_yaml  │
    ├── pii-structured ──────┼─── NEW dependencies
    │   ├── dep: csv         │
    │   └── dep: quick-xml   │
    ├── pii-ocr ─────────────┤ (ZERO new deps)
    │   └── (trait only)     │
    └── pii-secrecy ────────┘
        └── dep: serde_yaml
```

---

## 3. L1: Context Analysis Engine

### 3-1. ContextProvider Trait (Standard NLP Interface)

#### Purpose

Determines whether a regex-matched candidate is **truly PII** based on surrounding context, reducing false positives.

#### Problem Example

```
Input: "123456789012" (12-digit number)

Case A: "My Number: 123456789012 is your ID"
        → ✅ Real My Number (strong hint "My Number" before it)

Case B: "Invoice no. 123456789012, reference code ABC"
        → ❌ Invoice number (anti-hints "Invoice", "reference")

Same 12-digit number, but meaning differs based on context.
```

#### Trait Definition

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

#### Request/Response Structures

```rust
// Request
pub struct ContextAnalysisRequest {
    pub candidate_text: String,    // Regex-matched text (e.g., "123456789012")
    pub pii_type: String,         // PII type (e.g., "my_number")
    pub prefix: String,           // Text before match
    pub suffix: String,           // Text after match
    pub full_text: Option<String>, // Full document (optional)
    pub metadata: ContextMetadata, // Additional metadata
}

// Response
pub struct ContextAnalysisResponse {
    pub is_pii: bool,                    // true = confirmed PII, false = rejected
    pub confidence_score: f64,          // Confidence [0.0, 1.0]
    pub reason: String,                 // Reason for decision (audit log)
    pub matched_indicators: Vec<String>, // Supporting evidence
    pub false_positive_signals: Vec<String>, // False positive signals
}
```

#### Compatible External Services

| Provider Type | Latency | Cost | Accuracy | Implementation |
|---------------|---------|------|----------|----------------|
| GPT-4 / Claude | 500ms-2s | $$ | Very High | OpenAI API |
| Azure AI Language | 100-300ms | $ | High | Azure SDK |
| AWS Comprehend | 100-200ms | $ | High | AWS SDK |
| Ollama (Local) | 200-800ms | Free | Medium-High | ollama-rs |
| Self-hosted NLP | Varies | Investment | Varies | Custom |

### 3-2. KeywordRuleEngine (Configurable Rule Engine)

#### Purpose

When no NLP service is available (or to reduce costs), a **lightweight keyword-weighting engine** automatically serves as fallback.

#### Algorithm

```
1. Extract context window around match location
2. Search for "positive keywords" (PII supporting) → add to positive score
3. Search for "anti-keywords" (false positive signals) → add to negative score
4. Net score = Σ(positive weights) - Σ(negative weights)
5. Normalize: normalized_score = tanh(raw) / 2 + 0.5  → [0, 1]
6. Threshold comparison:
   - ≥ positive_threshold → ✅ Confirm as PII
   - ≤ negative_threshold → ❌ Reject as false positive
```

#### YAML Configuration Format

```yaml
version: "1.0"
profile: "universal"

global_settings:
  context_window_size: 100      # Characters before/after match
  positive_threshold: 0.7       # Above this → confirm PII
  negative_threshold: 0.3       # Below this → reject
  case_sensitive: false        # Case-insensitive matching

# Global anti-keywords (false-positive signals across all PII types)
global_anti_keywords:
  - { keyword: "invoice", weight: 0.70, position: either }
  - { keyword: "no.", weight: 0.65, position: before }
  - { keyword: "serial", weight: 0.70, position: after }
  - { keyword: "sample", weight: 0.50, position: before }

# Per-PII-type rules
pii_types:
  national_id:
    display_name: "National ID Number"
    positive:
      - { keyword: "national id", weight: 0.90, position: before }
      - { keyword: "ssn", weight: 0.90, position: before }
      - { keyword: "passport", weight: 0.92, position: before }
      - { keyword: "身份证", weight: 0.93, position: before }  # Chinese support
    anti:
      - { keyword: "reference", weight: 0.60, position: either }

  credit_card:
    display_name: "Credit Card"
    positive:
      - { keyword: "credit card", weight: 0.95, position: before }
      - { keyword: "カード番号", weight: 0.95, position: before } # Japanese
    anti:
      - { keyword: "member", weight: 0.55, position: either }
```

#### Keyword Position Options

| Position | Description | Example |
|----------|-------------|---------|
| `before` | Only **before** candidate text | `"SSN: 123"` — "SSN:" is before |
| `after` | Only **after** candidate text | `"123 (conf)"` — "(conf)" is after |
| `before_or_after` | Either side | `"card: 123 or ref 123"` |
| `either` | Either side (alias for above) | Same |

### 3-3. ContextAnalyzer (Unified Entry Point)

#### Role

Routes analysis requests:

```
analyze() request
     │
     ├─ Provider configured AND available?
     │    └─ YES → ContextProvider.analyze_context()
     │    └─ NO  (or FailFast mode)
     │         └─ KeywordRuleEngine.analyze()  ← Zero-cost fallback
```

#### FallbackStrategy Options

| Strategy | Behavior | Use Case |
|----------|----------|----------|
| `GracefulDegradation` | Degrade to keywords when provider down | **Recommended (default)** |
| `FailFast` | Return error immediately on provider failure | High-reliability environments |
| `KeywordOnly` | Always use keyword engine | No-NLP environments |

### 3-4. Configuration Examples & Code Samples

#### Example 1: Quick Start with Defaults

```rust
use misogi_core::pii::context::ContextAnalyzer;

let analyzer = ContextAnalyzer::with_defaults()?;  // Load universal defaults

let request = ContextAnalysisRequest::new(
    "123456789012",
    "national_id",
    "Your national id number is ",
    " please keep safe",
);

let result = analyzer.analyze(&request).await?;
assert!(result.is_pii);  // "national id" prefix confirms it
println!("Confidence: {}, Reason: {}", result.confidence_score, result.reason);
```

#### Example 2: Load Custom Rules from YAML

```rust
use misogi_core::pii::context::{ContextAnalyzer, KeywordRuleEngine};

let engine = KeywordRuleEngine::from_yaml_file("config/my-context-rules.yaml")?;
let analyzer = ContextAnalyzer::with_keyword_engine(engine);
```

#### Example 3: Full Programmatic Construction via Builder

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

#### Example 4: Connect External NLP Provider (OpenAI Example)

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
            "Is '{}' in context '{}' a real {}? \
             Respond JSON: {{\"is_pii\":bool,\"confidence\":float,\"reason\":string}}",
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
            .send().await
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

// Usage
let provider = Arc::new(OpenAiContextProvider { /* ... */ }) as Arc<dyn ContextProvider>;
let analyzer = ContextAnalyzer::with_provider(provider, KeywordRuleEngine::with_defaults()?);
```

---

## 4. L2: Structured Data Scanner

### 4-1. FieldClassifier (Field Name → PII Type Mapping)

#### Purpose

For structured data (CSV/JSON/XML), determines what **type of PII** each field contains based on its name.

#### Matching Patterns

| Pattern Type | Example | Match Condition |
|-------------|---------|-----------------|
| **Literal (exact)** | `"email"` | Field name == "email" |
| **Wildcard suffix** | `"*_id"` | "user_id", "order_id", etc. |
| **Full regex** | `"(?i)^name$"` | Case-insensitive "name" |

#### FieldAction Types

| Action | Behavior | Use Case |
|--------|----------|----------|
| `Mask` | Mask value (`j***n`) | Normal operation (recommended) |
| `Redact` | Remove entirely (`[REDACTED]`) | High-sensitivity data (CVV etc.) |
| `AlertOnly` | Log only | Monitoring purposes |
| `LogOnly` | Lightest logging | Low-confidence fields |

### 4-2. CSV/JSON/XML Scanners

#### Common Characteristics

| Feature | CsvPiiScanner | JsonPiiScanner | XmlPiiScanner |
|---------|--------------|----------------|--------------|
| Input format | CSV text | JSON | XML |
| Depth limit | None | `max_depth: 10` | `max_depth: 10` |
| Array handling | Row-by-row | Each element | Child elements |
| Attribute scan | N/A | N/A | ✅ Supported |

#### Output Structure (StructuredScanResult)

```rust
pub struct StructuredScanResult {
    pub format: StructuredFormat,           // Csv / Json / Xml
    pub total_fields: usize,               // Total fields scanned
    pub pii_fields: Vec<FieldScanResult>,  // Fields where PII found
    pub overall_action: FieldAction,       // Strictest action across all
    pub bytes_processed: u64,              // Bytes processed
    pub scan_duration_ms: u64,             // Scan duration
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

### 4-3. Configuration Examples & Code Samples

#### YAML Configuration Example

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

  # --- Wildcard (low confidence) ---
  - { field_pattern: "*_id", pii_type: generic_id, confidence: 0.45, action: alert_only }
  - { field_pattern: "*_no", pii_type: generic_number, confidence: 0.40, action: log_only }
```

#### Rust Code Example: CSV Scanning

```rust
use misogi_core::pii::structured::{CsvPiiScanner, FieldClassifier};

let scanner = CsvPiiScanner::with_defaults();  // Universal defaults

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
}
```

#### Rust Code Example: Custom FieldClassifier via Builder

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

let classification = fc.classify("user_auth_token");
assert!(classification.matched);
assert_eq!(classification.pii_type, "auth_token");
```

---

*→ [Part 1 Complete] Continue with [Part 2](pii-detection-enhanced-part2.md): L3 OCR PII Detection + L4 Secrecy Level Classifier + Complete Config Reference*
