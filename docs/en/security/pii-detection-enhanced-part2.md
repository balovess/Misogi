# PII Detection Enhancement Guide — Part 2: OCR, Secrecy Classification & Config Reference

> **Part 1**: [Overview, Context Analysis & Structured Data](pii-detection-enhanced.md)
>
> **Target Audience**: Security Engineers, Compliance Officers, System Architects

---

## Table of Contents (Part 2)

- [5. L3: OCR PII Detection](#5-l3-ocr-pii-detection)
  - [5-1. OcrProvider Trait (Standard OCR Interface)](#51-ocrprovider-trait-standard-ocr-interface)
  - [5-2. OcrPiiDetector (OCR + Regex Pipeline)](#52-ocrpiidetector-ocr--regex-pipeline)
  - [5-3. Configuration Examples](#53-configuration-examples)
- [6. L4: Secrecy Level Classifier](#6-l4-secrecy-level-classifier)
  - [6-1. User-Defined Level Schemes](#61-user-defined-level-schemes)
  - [6-2. Classification Rule Engine](#62-classification-rule-engine)
  - [6-3. Conflict Resolution](#63-conflict-resolution)
  - [6-4. Configuration Examples](#64-configuration-examples-1)
- [7. Configuration File Complete Reference](#7-configuration-file-complete-reference)

---

→ **Continue with [Part 3](pii-detection-enhanced-part3.md)** (API Reference, Adoption Guidelines, Troubleshooting)

---

## 5. L3: OCR PII Detection

### 5-1. OcrProvider Trait (Standard OCR Interface)

#### ⚠️ Important: Misogi Does NOT Bundle Any OCR Engine

Like L1's ContextProvider, L3 provides **trait definition only**.
Users implement and connect one of these OCR services:

| Category | Provider | Characteristics |
|----------|----------|----------------|
| **Open-source (local)** | Tesseract | Free, offline capable |
| **Cloud (commercial)** | Azure Computer Vision | High accuracy, multilingual |
| **Cloud (commercial)** | Google Cloud Vision | Document understanding |
| **Cloud (commercial)** | AWS Textract | Form/table extraction |
| **Asia-specialized** | Baidu OCR / Alibaba Cloud OCR | Chinese/Japanese optimized |

#### Trait Definition

```rust
#[async_trait]
pub trait OcrProvider: Send + Sync {
    async fn extract_text(
        &self,
        image_data: &[u8],           // Raw image bytes (PNG/JPEG/TIFF/BMP/WebP)
    ) -> Result<OcrExtractionResult, OcrError>;

    fn provider_name(&self) -> &str;
    async fn is_available(&self) -> bool;
}
```

#### Extraction Result Structure

```rust
pub struct OcrExtractionResult {
    pub full_text: String,              // All blocks concatenated
    pub blocks: Vec<OcrTextBlock>,      // Text blocks with position info
    pub metadata: OcrImageMetadata,     // Image metadata
    pub overall_confidence: f64,        // Overall confidence
}

pub struct OcrTextBlock {
    pub text: String,                   // Extracted text
    pub bbox: OcrBoundingBox,          // Normalized coords [0,0,1,1]
    pub confidence: f64,                // Block-level confidence
}

pub struct OcrBoundingBox {
    pub x_min: f64, pub y_min: f64,
    pub x_max: f64, pub y_max: f64,
}
```

#### Coordinate System

```
Entire image in normalized space [0.0, 0.0] → [1.0, 1.0]:

(0,0) ──────────────── (1,0)
  │                       │
  │   ┌─────────────┐     │
  │   │ Text Block   │     │ ← bbox: {x_min:0.2, y_min:0.3, x_max:0.8, y_max:0.6}
  │   │ "SSN:123"    │     │
  │   └─────────────┘     │
  │                       │
(0,1) ──────────────── (1,1)

Use cases:
- Highlight PII location on UI
- Auto-masking/redaction processing
- Position logging for audit trail
```

### 5-2. OcrPiiDetector (OCR + Regex Pipeline)

#### Processing Flow

```
Image Bytes (PNG/JPEG/TIFF/BMP/WebP)
     │
     ▼
┌──────────────────────────────────┐
│  ① Constraint Check              │
│  • Size ≤ max_size_mb            │
│  • Format supported?             │
└──────────────┬───────────────────┘
               ▼
┌──────────────────────────────────┐
│  ② OcrProvider.extract_text()   │
│  → OcrExtractionResult            │
│    .full_text                     │
│    .blocks[] (with positions)     │
│    .overall_confidence            │
└──────────────┬───────────────────┘
               ▼
┌──────────────────────────────────┐
│  ③ For each block:               │
│  if block.confidence ≥ threshold │
│    → RegexPIIDetector.scan()     │
│    → Collect PIIMatch[]          │
│    + Attach position (bbox)      │
└──────────────┬───────────────────┘
               ▼
┌──────────────────────────────────┐
│  ④ Aggregate OcrPiiScanResult    │
│  • found: bool                   │
│  • matches: Vec<OcrPiiMatch>     │
│  • action: strictest action      │
│  • total_chars_extracted          │
│  • scan_duration_ms               │
└──────────────────────────────────┘
```

#### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `min_ocr_confidence` | `f64` | 0.7 | Skip blocks below this |
| `spatial_annotation` | `bool` | true | Include position in output |
| `min_dimension_px` | `u32` | 50 | Minimum image dimension |
| `max_dimension_px` | `u32` | 10000 | Maximum image dimension |
| `max_size_mb` | `usize` | 10 | Max file size (MB) |

### 5-3. Configuration Examples

#### Example 1: Mock OCR for Testing

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
```

---

## 6. L4: Secrecy Level Classifier

### 6-1. User-Defined Level Schemes

#### ⚠️ Important: Level Count, Names, Rules — ALL User-Defined

Misogi does **NOT assume any specific level naming or tier count**.
Users design freely per organizational requirements:

| Scenario | Level Scheme Example | User-Defined Content |
|----------|---------------------|----------------------|
| **International generic** | Critical / High / Medium / Low / Public | 5 tiers |
| **Japan government** | 極機密(3A) / 機密(3B) / 扱い注意(3C) / 公開 | 4 tiers |
| **US Military** | Top Secret / Secret / Confidential / Unclassified | 4 tiers |
| **Finance PCI-DSS** | Cardholder / Sensitive / Public | 3 tiers |
| **Healthcare HIPAA** | PHI-Restricted / PHI-Limited / De-identified | 3 tiers |
| **Custom** | *Any* | *Any* |

#### Level Definition Structure

```rust
pub struct SecrecyLevelDef {
    pub id: String,                        // "critical", "3a", "top_secret"
    pub display_name: String,              // "Critical", "極機密"
    pub rank: u32,                         // Numeric rank (higher = more secret)
    pub color: String,                     // UI color (#DC2626)
    pub required_controls: Vec<ControlRequirement>, // Required security controls
    pub retention_years: u32,              // Retention period in years
}

pub struct ControlRequirement {
    pub id: String,                        // "enc_at_rest"
    pub name: String,                      // "Encryption at Rest"
    pub required: bool,                    // Is mandatory?
    pub spec: String,                      // "AES-256+" (spec reference)
}
```

### 6-2. Classification Rule Engine

#### Condition Types

```rust
pub enum Condition {
    /// ALL listed PII types present (AND logic)
    RequireAllOf { pii_types: Vec<String> },

    /// ANY listed PII type present (OR logic)
    RequireAnyOf { pii_types: Vec<String> },

    /// Listed types present ≥ min_count times
    PiiTypesPresent { pii_types: Vec<String>, min_count: usize },

    /// ALL exclusion types ABSENT
    ExcludeAllOf { pii_types: Vec<String> },

    /// ANY exclusion type ABSENT
    ExcludeAnyOf { pii_types: Vec<String> },
}
```

#### Rule Evaluation Flow

```
Detected PII types: {"national_id", "email"}
     │
     ▼
┌─────────────────────────────────────┐
│  Evaluate all rules sequentially    │
│                                     │
│  Rule 1: RequireAllOf["name","addr","phone"]
│    → ❌ No match                    │
│                                     │
│  Rule 2: RequireAnyOf["national_id","credit_card"] + min=1
│    → ✅ Match! national_id exists   │
│    → result.level = "critical"      │
│                                     │
│  Rule 3: RequireAnyOf["email"] + ExcludeAllOf["name","national_id"]
│    → ❌ No match (national_id in exclude list)│
│                                     │
│  ... (remaining rules evaluated)    │
└──────────────┬──────────────────────┘
               ▼
Matched rules: [{rule_2: critical}]
     │
     ▼
Conflict resolution: "highest" → pick max rank
     │
     ▼
Final result: level="critical", reason="Contains national identity identifier"
```

### 6-3. Conflict Resolution

When multiple rules match simultaneously:

| Strategy | Behavior | Use Case |
|----------|----------|----------|
| `"highest"` (**default**) | Select **highest rank** level | Safety-first (recommended) |
| `"lowest"` | Select **lowest rank** level | Reduce operational burden |

#### Conflict Resolution Example

```
Detected PII: {"credit_card", "email"}

Matching rules:
  Rule A: credit_card present → Critical (rank=4)
  Rule B: email only (exclude national_id/credit_card) → Medium (rank=2)

Strategy "highest":
  → Critical (rank=4 > rank=2)

Strategy "lowest":
  → Medium (rank=2 < rank=4)
```

### 6-4. Configuration Examples

#### Example 1: Generic 4-Tier Template

```rust
use misogi_core::pii::secrecy::SecrecyClassifier;

let classifier = SecrecyClassifier::with_generic_tier()?;

let result = classifier.classify(&["national_id", "email"])?;
println!("Level: {} (rank={})", result.level_display_name, result.level_rank);
// Output: Level: Critical (rank=4)

println!("Required controls:");
for ctrl in &result.required_controls {
    println!("  - {} ({}) {}", ctrl.name, ctrl.spec,
        if ctrl.required { "[REQUIRED]" } else { "[RECOMMENDED]" });
}
// Output:
//   - Encryption at Rest (AES-256+) [REQUIRED]
//   - Encryption in Transit (TLS 1.2+) [REQUIRED]
//   - Multi-Factor Authentication () [REQUIRED]
//   - Full Audit Logging () [REQUIRED]
```

#### Example 2: Custom Scheme via Builder

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

    .fallback_default("public")
    .build()?;
```

---

## 7. Configuration File Complete Reference

### 7-1. pii-context-defaults.yaml

**Location**: `crates/misogi-core/config/pii-context-defaults.yaml`
**Purpose**: KeywordRuleEngine universal defaults (built-in, auto-loaded)

| Item | Type | Default | Description |
|------|-----|---------|-------------|
| `version` | string | "1.0" | Config format version |
| `profile` | string | "universal" | Profile identifier |
| `global_settings.context_window_size` | int | 100 | Context characters before/after |
| `global_settings.positive_threshold` | float | 0.7 | Confirm-as-PII threshold |
| `global_settings.negative_threshold` | float | 0.3 | Reject-as-false-positive threshold |
| `global_settings.case_sensitive` | bool | false | Case-sensitive matching |
| `global_anti_keywords[]` | array | 10 items | Cross-type anti-keywords |
| `pii_types.*.display_name` | string | — | Display name |
| `pii_types.*.positive[]` | array | — | Positive keyword rules |
| `pii_types.*.anti[]` | array | — | Anti-keyword rules |

**Per-keyword rule fields**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `keyword` | string | ✅ | Search keyword |
| `weight` | float | ✅ | Weight [0.0, 1.0] |
| `position` | enum | ❌ (default: either) | before / after / before_or_after / either |

### 7-2. pii-structured-defaults.yaml

**Location**: `crates/misogi-core/config/pii-structured-defaults.yaml`
**Purpose**: FieldClassifier universal field mappings

| Item | Type | Default | Description |
|------|-----|---------|-------------|
| `field_mappings[].field_pattern` | string | — | Match pattern (literal/wildcard/regex) |
| `field_mappings[].pii_type` | string | — | Corresponding PII type |
| `field_mappings[].confidence` | float | 0.8 | Confidence [0.0, 1.0] |
| `field_mappings[].action` | enum | alert_only | mask / redact / alert_only / log_only |

**Preset mappings summary**:

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

**Location**: `crates/misogi-core/config/pii-secrecy-defaults.yaml`
**Purpose**: SecrecyClassifier generic 4-tier template

| Item | Type | Description |
|------|-----|-------------|
| `scheme` | string | Scheme ID ("generic-4-tier") |
| `levels.*.id` | string | Level ID ("critical", "high", ...) |
| `levels.*.rank` | uint | Rank value (higher = more secret) |
| `levels.*.color` | string | UI color (hex) |
| `levels.*.required_controls[]` | array | Required security controls |
| `levels.*.retention_years` | uint | Retention years |
| `classification_rules[].id` | string | Rule ID |
| `classification_rules[].condition` | enum | Condition (RequireAllOf/AnyOf/Present/Exclude*) |
| `classification_rules[].result.level` | string | Assigned level ID |
| `classification_rules[].result.reason` | string | Decision reason |
| `fallback.unknown_default` | string | Default for unclassified content |
| `fallback.conflict_resolution` | string | "highest" or "lowest" |

**Preset levels summary**:

| Level | Rank | Color | Controls | Retention |
|-------|------|-------|----------|------------|
| critical | 4 | #DC2626 | enc_rest, enc_transit, mfa, audit_full | 7 years |
| high | 3 | #EA580C | enc_rest, audit_access | 5 years |
| medium | 2 | #D97706 | access_control, label | 3 years |
| low | 1 | #65A30D | basic_auth | 1 year |
| public | 0 | #3B82F6 | (none) | 1 year |

---

*→ [Part 2 Complete] Continue with [Part 3](pii-detection-enhanced-part3.md): API Reference, Adoption Guidelines & Troubleshooting*
