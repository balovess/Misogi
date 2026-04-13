# PII Detection Enhancement Guide — Part 3: API Reference, Adoption & Troubleshooting

> **Part 1**: [Overview, Context Analysis & Structured Data](pii-detection-enhanced.md)
>
> **Part 2**: [OCR, Secrecy Classification & Config Reference](pii-detection-enhanced-part2.md)

---

## Table of Contents (Part 3)

- [8. Programming API Reference](#8-programming-api-reference)
  - [8-1. Context Module API](#81-context-module-api)
  - [8-2. Structured Module API](#82-structured-module-api)
  - [8-3. OCR Module API](#83-ocr-module-api)
  - [8-4. Secrecy Module API](#84-secrecy-module-api)
- [9. Adoption Guidelines](#9-adoption-guidelines)
  - [9-1. Scenario: Financial Institution (PCI-DSS)](#91-scenario-financial-institution-pci-dss)
  - [9-2. Scenario: Japan Government (My Number Act)](#92-scenario-japan-government-my-number-act)
  - [9-3. Scenario: Healthcare (HIPAA)](#93-scenario-healthcare-hipaa)
  - [9-4. Migration Guide (Legacy → Enhanced)](#94-migration-guide-legacy--enhanced)
- [10. Troubleshooting](#10-troubleshooting)
  - [10-1. FAQ](#101-faq)
  - [10-2. Performance Optimization](#102-performance-optimization)
  - [10-3. Debug Methods](#103-debug-methods)

---

## 8. Programming API Reference

### 8-1. Context Module API

#### ContextAnalyzer

```rust
pub struct ContextAnalyzer { /* private */ }

impl ContextAnalyzer {
    pub fn with_defaults() -> Result<Self>;
    pub fn with_keyword_engine(engine: KeywordRuleEngine) -> Self;
    pub fn with_provider(provider: Arc<dyn ContextProvider>, fallback: KeywordRuleEngine) -> Self;
    pub fn with_config(self, config: ContextAnalyzerConfig) -> Self;

    pub async fn analyze(&self, request: &ContextAnalysisRequest) -> Result<ContextAnalysisResponse>;
    pub fn analyze_with_keywords(&self, request: &ContextAnalysisRequest) -> Result<ContextAnalysisResponse>;

    pub fn has_provider(&self) -> bool;
    pub fn provider_name(&self) -> Option<&str>;
    pub fn keyword_engine(&self) -> &Arc<KeywordRuleEngine>;
}
```

#### KeywordRuleEngine

```rust
pub struct KeywordRuleEngine { /* private */ }

impl KeywordRuleEngine {
    pub fn with_defaults() -> Result<Self>;
    pub fn from_yaml_file(path: &str) -> Result<Self>;
    pub fn merge(sources: Vec<KeywordRuleSource>) -> Result<Self>;

    pub fn analyze(&self, request: &ContextAnalysisRequest) -> Result<ContextAnalysisResponse>;

    pub fn add_keyword(&self, pii_type: &str, keyword: KeywordRule) -> Result<()>;
    pub fn remove_keyword(&self, pii_type: &str, keyword_text: &str) -> Result<bool>;
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

### 8-2. Structured Module API

#### Scanners

```rust
// All scanners share similar interface:
impl CsvPiiScanner {
    pub fn with_defaults() -> Self;
    pub fn new(classifier: FieldClassifier, config: CsvScannerConfig) -> Self;
    pub fn scan(&self, content: &str) -> Result<StructuredScanResult>;
}

// Same for JsonPiiScanner, XmlPiiScanner
```

#### FieldClassifier

```rust
impl FieldClassifier {
    pub fn with_defaults() -> Self;
    pub fn from_yaml_file(path: &str) -> Result<Self>;

    pub fn classify(&self, field_name: &str) -> FieldClassification;
    pub fn add_mapping(&self, mapping: FieldMapping) -> Result<()>;
    pub fn remove_by_pattern(&self, pattern: &str) -> Result<usize>;
    pub fn mapping_count(&self) -> usize;
}

impl FieldMapping {
    pub fn literal(field, pii_type, confidence, action) -> Self;
    pub fn wildcard(pattern, pii_type, confidence, action) -> Self;
    pub fn matches_field(&self, field_name: &str) -> bool;
}
```

### 8-3. OCR Module API

#### OcrPiiDetector

```rust
impl OcrPiiDetector {
    pub fn new(ocr: Arc<dyn OcrProvider>, detector: Arc<RegexPIIDetector>, config: OcrDetectorConfig) -> Self;
    pub fn with_defaults(ocr: Arc<dyn OcrProvider>, detector: Arc<RegexPIIDetector>) -> Self;

    pub async fn scan_image(&self, image_data: &[u8], file_id: &str) -> Result<OcrPiiScanResult>;
}
```

#### Key Types

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
    pub match_data: PIIMatch,
    pub bbox: Option<OcrBoundingBox>,
    pub ocr_block_confidence: f64,
}
```

### 8-4. Secrecy Module API

#### SecrecyClassifier

```rust
impl SecrecyClassifier {
    pub fn with_generic_tier() -> Result<Self>;
    pub fn from_yaml_file(path: &str) -> Result<Self>;

    pub fn classify(&self, pii_types: &[&str]) -> Result<SecrecyClassificationResult>;
    pub fn reload_scheme(&self, path: &str) -> Result<()>;

    pub fn level_ids(&self) -> Vec<String>;
    pub fn get_level(&self, level_id: &str) -> Option<SecrecyLevelDef>;
}
```

#### SecrecySchemeBuilder

```rust
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

## 9. Adoption Guidelines

### 9-1. Scenario: Financial Institution (PCI-DSS)

**Requirements**: PCI-DSS compliance, strict cardholder data protection, mandatory audit trails

**Recommended L1 Context Rules**:

```yaml
pii_types:
  credit_card:
    positive:
      - { keyword: "card number", weight: 0.98, position: before }
      - { keyword: "PAN", weight: 0.97, position: before }   # PCI term
      - { keyword: "カード番号", weight: 0.99, position: before }
    anti:
      - { keyword: "token", weight: 0.70, position: after }   # Already tokenized
      - { keyword: "masked", weight: 0.65, position: either } # Already masked
```

**Recommended L4 Secrecy Scheme**:

```yaml
scheme: "pci-dss-compliant"

levels:
  cardholder:
    display_name: "Cardholder Data"
    rank: 4
    required_controls:
      - { id: aes256, name: "AES-256 Encryption", required: true }
      - { id: tokenization, name: "Tokenization", required: true }
      - { id: audit_pci, name: "PCI Audit Log", required: true }
    retention_years: 7

classification_rules:
  - id: "rule_pan_cardholder"
    condition: { require_any_of: ["credit_card", "credit_card_cvv"] }
    result: { level: "cardholder", reason: "Payment card data per PCI-DSS" }
```

### 9-2. Scenario: Japan Government (My Number Act)

**Requirements**: My Number Act compliance, specific personal info protection, 3A/3B/3C classification

**Recommended L1 Context Rules (My Number specialized)**:

```yaml
pii_types:
  my_number:
    display_name: "Individual Number (My Number)"
    positive:
      - { keyword: "マイナンバー", weight: 0.95, position: before }
      - { keyword: "個人番号", weight: 0.95, position: before }
      - { keyword: "マイナ", weight: 0.80, position: before }
    anti:
      - { keyword: "伝票", weight: 0.70, position: either }
      - { keyword: "口座", weight: 0.60, position: either }
      - { keyword: "ケース", weight: 0.60, position: either }
```

**Recommended L4 Secrecy Scheme (Japan government 3-tier)**:

```yaml
scheme: "jp-govt-3tier"

levels:
  "3a":
    display_name: "極機密 (Top Secret)"
    rank: 3
    required_controls:
      - { id: enc_aes256, name: "AES-256 Encryption", required: true }
      - { id: tls13, name: "TLS 1.3", required: true }
      - { id: mfa, name: "Multi-Factor Auth", required: true }
      - { id: full_audit, name: "Full Audit Log", required: true }
    retention_years: 7

  "3b":
    display_name: "機密 (Secret)"
    rank: 2
    required_controls:
      - { id: enc_aes256, name: "AES-256 Encryption", required: true }
      - { id: access_log, name: "Access Log", required: true }
    retention_years: 5

  "3c":
    display_name: "扱い注意 (Handle with Care)"
    rank: 1
    required_controls:
      - { id: basic_auth, name: "Basic Auth", required: true }
    retention_years: 3
```

### 9-3. Scenario: Healthcare (HIPAA)

**Requirements**: PHI protection, strict patient ID management

**Recommended L4 Secrecy Scheme**:

```yaml
scheme: "hipaa-compliant"

levels:
  phi_restricted:
    display_name: "PHI-Restricted"
    rank: 3
    required_controls:
      - { id: enc_hipaa, name: "HIPAA Encryption", required: true }
      - { id: audit_access, name: "Access Audit Trail", required: true }
      - { id: min_necessary, name: "Minimum Necessary Policy", required: true }
    retention_years: 10

  phi_limited:
    display_name: "PHI-Limited"
    rank: 2
    required_controls:
      - { id: enc_standard, name: "Standard Encryption", required: true }
    retention_years: 6
```

### 9-4. Migration Guide (Legacy → Enhanced)

Existing `RegexPIIDetector`-only code requires **NO changes**.
Add new features incrementally:

#### Step 1: Add feature to Cargo.toml

```toml
[dependencies]
misogi-core = { version = "0.1", features = ["pii-enhanced"] }
```

#### Step 2: Verify existing code (no changes needed)

```rust
let detector = RegexPIIDetector::with_jp_defaults();
let result = detector.scan(text, file_id, source).await?;
// → Same results as before
```

#### Step 3: Optionally add L1 context analysis

```rust
use misogi_core::pii::context::ContextAnalyzer;

let analyzer = ContextAnalyzer::with_defaults()?;  // NEW addition

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

#### Step 4: Optionally add L4 secrecy classification

```rust
use misogi_core::pii::secrecy::SecrecyClassifier;

let classifier = SecrecyClassifier::with_generic_tier()?;
let pii_types: Vec<&str> = result.matches.iter().map(|m| m.pii_type.as_str()).collect();
let secrecy = classifier.classify(&pii_types)?;
println!("Secrecy Level: {} ({})", secrecy.level_display_name, secrecy.level_rank);
```

---

## 10. Troubleshooting

### 10-1. FAQ

#### Q1: Context analysis always returns "not PII"

**Cause**: Missing positive keywords, or anti-keywords too strong

**Solution**:
```yaml
global_settings:
  positive_threshold: 0.5  # Lower (default: 0.7)
  negative_threshold: 0.15 # Lower (default: 0.3)

pii_types:
  your_custom_type:
    positive:
      - { keyword: "your_strong_indicator", weight: 0.99, position: before }
```

#### Q2: CSV scanner doesn't recognize my fields

**Cause**: Field names not in preset mappings

**Solution**:
```rust
fc.add_mapping(FieldMapping::literal("my_custom_field", "email", 0.90, FieldAction::Mask))?;
```
Or in YAML:
```yaml
field_mappings:
  - { field_pattern: "my_custom_field", pii_type: email, confidence: 0.90, action: mask }
```

#### Q3: OCR Provider times out

**Cause**: Image size exceeded, or external service slow response

**Solution**:
```rust
let config = OcrDetectorConfig {
    max_size_mb: 5,           // Stricter limit (default: 10)
    min_ocr_confidence: 0.8,  // Higher threshold (fewer blocks)
    ..Default::default()
};
```

#### Q4: Secrecy classification always returns fallback level

**Cause**: Detected PII types don't match any classification rules

**Solution**:
```rust
let detected: Vec<&str> = result.matches.iter().map(|m| m.pii_type.as_str()).collect();
println!("Detected types: {:?}", detected);
// Then add missing rules via builder or YAML
```

### 10-2. Performance Optimization

| Optimization | Method | Effect |
|-------------|--------|--------|
| **Context analysis cache** | `enable_cache: true` | Speed up duplicate requests |
| **CSV max row limit** | `max_rows: 50000` | Stabilize large file processing |
| **JSON depth limit** | `max_depth: 5` | Speed up deeply nested JSON |
| **OCR threshold tuning** | `min_ocr_confidence: 0.85` | Skip low-quality blocks |
| **Parallel processing** | `tokio::spawn` for multiple files | Improve throughput |

### 10-3. Debug Methods

#### Enable Logging

```rust
env_logger::init();  // Set RUST_LOG=debug for verbose output
```

Key log points:
- `ContextAnalyzer::analyze` — Routing decision (provider vs keywords)
- `KeywordRuleEngine::analyze` — Per-keyword match results
- `CsvPiiScanner::scan` — Per-field classification results
- `OcrPiiDetector::scan_image` — OCR extraction + PII match counts
- `SecrecyClassifier::classify` — Full rule evaluation results

#### Using Test Mocks

```rust
// L1: Mock that always confirms PII
let mock_ctx = MockContextProvider::always_confirm();

// L3: Mock returning specific text
let mock_ocr = MockOcrProvider::with_text("SSN: 123-45-6789", 0.95);

// L3: Simulate unavailable service
let mock_down = MockOcrProvider::unavailable();
```

---

*→ [Part 3 Complete] PII Detection Enhancement Guide — FINISHED*

**Related Documents**:
- [PII Detection Guide (Basic)](pii-detection.md) — Regex-based basic functionality
- [日本語版](../../ja/security/pii-detection-enhanced.md) — Japanese complete documentation
