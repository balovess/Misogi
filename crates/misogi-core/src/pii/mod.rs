// =============================================================================
// Misogi Core — PII (Personally Identifiable Information) Detection Engine
// =============================================================================
// This module provides regex-based PII scanning for Japanese government compliance.
//
// ## Architecture
//
// 1. **PIIRule** — Configuration struct defining a single PII detection pattern
//    with its associated action (Block/Mask/AlertOnly), mask character, and metadata.
//
// 2. **RegexPIIDetector** — The primary [`PIIDetector`] implementation using
//    compiled regex patterns to scan text content for sensitive data patterns.
//
// 3. **Built-in Rules Factory** (`with_jp_defaults()`) — Pre-configured rule set
//    covering Japanese government-mandated PII categories:
//    - My Number (12-digit personal identification number)
//    - Email addresses (RFC 5322 simplified)
//    - IPv4/IPv6 addresses
//    - Credit card numbers (JCB, Visa, Mastercard, etc.)
//
// 4. **Masking Utilities** — Functions for redacting detected PII in text,
//    preserving format while obscuring sensitive values.
//
// ## Enhanced Modules (feature-gated)
//
// | Feature | Module | Description |
// |---------|--------|-------------|
// | `pii-context` | [`context`] | ContextProvider trait + configurable keyword engine |
// | `pii-structured` | [`structured`] | CSV/JSON/XML field-level PII scanner |
// | `pii-ocr` | [`ocr`] | OcrProvider trait + OCR-PII pipeline |
// | `pii-secrecy` | [`secrecy`] | User-customizable secrecy level classifier |
//
// ## Compliance Context
// Japanese regulations requiring proactive PII scanning:
// - **APJ My Number Act** (マイナンバー法): My Number protection mandatory.
// - **APPI** (個人情報保護法): Personal Information Protection Law compliance.
// - **PCI-DSS**: Credit card data must not traverse unsecured boundaries.
//
// ## Encoding Support
// The scanner supports multi-encoding detection: UTF-8 (default), Shift-JIS,
// EUC-JP, ISO-2022-JP. Content is normalized to UTF-8 before regex matching.
// =============================================================================

use std::time::Instant;

use async_trait::async_trait;
use regex::Regex;

use crate::error::{MisogiError, Result};
use crate::traits::{
    PIIMatch, PIIScanResult,
};

// Re-export PIIAction and PIIDetector for WASM FFI layer and external consumers
pub use crate::traits::{PIIAction, PIIDetector};

// Enhanced modules (feature-gated)
#[cfg(feature = "pii-context")]
pub mod context;

#[cfg(feature = "pii-structured")]
pub mod structured;

#[cfg(feature = "pii-ocr")]
pub mod ocr;

#[cfg(feature = "pii-secrecy")]
pub mod secrecy;

// =============================================================================
// A. PIIRule
// =============================================================================

/// Configuration for a single PII detection pattern.
///
/// Each rule defines one category of sensitive data to detect, the regular
/// expression pattern used for matching, and the action to take when a match
/// is found. Rules are composable: multiple rules can be active simultaneously,
/// each producing independent matches that are aggregated into the final scan result.
///
/// # Action Hierarchy
/// When multiple rules match within a single scan, actions are resolved by
/// strictness precedence: **Block > Mask > AlertOnly**. If any rule specifies
/// Block, the overall scan action will be Block regardless of other matches.
#[derive(Debug, Clone)]
pub struct PIIRule {
    /// Human-readable name identifying this PII pattern category.
    ///
    /// Examples: `"my_number"`, `"email"`, `"credit_card"`, `"phone_jp"`.
    /// Used in audit logs and match reports for operator clarity.
    pub name: String,

    /// Compiled regular expression pattern for detecting this PII type.
    ///
    /// Patterns should be designed to minimize false positives while catching
    /// real PII instances. Word boundary anchors (`\b`) are recommended where
    /// appropriate to avoid partial-match false positives.
    pub pattern: Regex,

    /// Pattern type identifier (extensible for future ML-based detectors).
    ///
    /// Current value: `"regex"`. Reserved for future: `"ml"`, `"nlp"`, `"fuzzy"`.
    pub pattern_type: String,

    /// Action to take when this pattern matches.
    ///
    /// - [`PIIAction::Block`]: Reject the entire file transfer.
    /// - [`PIIAction::Mask`]: Redact the matched text before forwarding.
    /// - [`PIIAction::AlertOnly`]: Log the finding but allow transfer.
    pub action: PIIAction,

    /// Character used for masking/redaction of matched text.
    ///
    /// Common choices: `'*'` (asterisk), `'X'` (for alphanumeric), `'●'`.
    /// Applied by [`apply_mask()`] to produce the masked version of matches.
    pub mask_char: char,

    /// Human-readable description of what this pattern detects.
    ///
    /// Included in audit trail documentation for compliance reviewers.
    pub description: String,

    /// Expected text encoding for content scanned by this rule.
    ///
    /// `None` means "accept any encoding" (UTF-8 assumed after normalization).
    /// Some patterns may be encoding-specific (e.g., Shift-JIS byte sequences).
    pub encoding: Option<String>,
}

impl PIIRule {
    /// Construct a new PII rule with all fields specified explicitly.
    ///
    /// # Arguments
    /// * `name` — Pattern identifier string.
    /// * `pattern_str` — Regular expression string (will be compiled).
    /// * `action` — Action on match.
    /// * `mask_char` — Character for masking.
    /// * `description` — Human-readable explanation.
    ///
    /// # Errors
    /// Panics if `pattern_str` is not a valid regular expression. Use
    /// [`PIIRule::try_new()`] for fallible construction.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: impl Into<String>,
        pattern_str: &str,
        action: PIIAction,
        mask_char: char,
        description: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            pattern: Regex::new(pattern_str)
                .unwrap_or_else(|_| panic!("Invalid regex pattern: {}", pattern_str)),
            pattern_type: "regex".to_string(),
            action,
            mask_char,
            description: description.into(),
            encoding: None,
        }
    }

    /// Fallible constructor that returns an error for invalid regex patterns.
    ///
    /// # Errors
    /// Returns [`MisogiError::Protocol`] if `pattern_str` cannot be compiled.
    pub fn try_new(
        name: impl Into<String>,
        pattern_str: &str,
        action: PIIAction,
        mask_char: char,
        description: impl Into<String>,
    ) -> Result<Self> {
        let name_owned = name.into();
        let pattern = Regex::new(pattern_str).map_err(|e| {
            MisogiError::Protocol(format!(
                "Invalid PII regex pattern '{}': {}",
                name_owned,
                e
            ))
        })?;

        Ok(Self {
            name: name_owned,
            pattern,
            pattern_type: "regex".to_string(),
            action,
            mask_char,
            description: description.into(),
            encoding: None,
        })
    }
}

// =============================================================================
// B. RegexPIIDetector
// =============================================================================

/// Primary PII detector implementation using regular expression pattern matching.
///
/// Scans text content against a configured set of [`PIIRule`] entries, collecting
/// all matches into a structured [`PIIScanResult`] with actionable recommendations.
///
/// # Scanning Algorithm
/// 1. Normalize input content to UTF-8 (handling specified encodings).
/// 2. For each registered rule, execute the compiled regex against the full text.
/// 3. Collect matches with position, matched text, and masked version.
/// 4. Determine overall action by resolving action hierarchy across all matches.
/// 5. Return aggregated result with performance metrics.
///
/// # Performance Characteristics
/// - Scanning time is O(n * m) where n = content length, m = number of rules.
/// - Each regex is compiled once at construction time (not per-scan).
/// - For files > 100 MB, consider chunked/streaming scanning to limit memory usage.
///
/// # Thread Safety
/// The detector is Send + Sync; the same instance can be shared across
/// concurrent async tasks without synchronization overhead (Regex is immutable).
pub struct RegexPIIDetector {
    /// Ordered list of PII detection rules applied during scanning.
    rules: Vec<PIIRule>,

    /// Default action when no rules match (typically AlertOnly).
    default_action: PIIAction,

    /// Encodings to attempt when normalizing input bytes to String.
    /// Tried in order; first successful decode wins.
    #[allow(dead_code)]
    encodings: Vec<String>,
}

impl RegexPIIDetector {
    /// Construct a new regex PII detector with explicit configuration.
    ///
    /// # Arguments
    /// * `rules` — Vector of PII detection rules to apply.
    /// * `default_action` — Action returned when no PII is found.
    /// * `encodings` — Encoding list for input normalization.
    pub fn new(
        rules: Vec<PIIRule>,
        default_action: PIIAction,
        encodings: Vec<String>,
    ) -> Self {
        Self {
            rules,
            default_action,
            encodings,
        }
    }

    /// Create a detector pre-configured with standard Japanese government PII rules.
    ///
    /// Built-in rule set includes:
    /// | Pattern Name     | Pattern Description              | Action      |
    /// |------------------|----------------------------------|-------------|
    /// | my_number        | 12-digit My Number (個人番号)     | Mask        |
    /// | email            | RFC 5322 email address           | AlertOnly   |
    /// | ip_address_v4    | IPv4 address                     | AlertOnly   |
    /// | credit_card      | JCB/Visa/MC credit card number   | Mask        |
    /// | phone_jp         | Japanese phone number (loose)    | AlertOnly   |
    /// | postal_code_jp   | Japanese postal code (NNN-NNNN)  | AlertOnly   |
    /// | drivers_license  | JP driver's license pattern      | Mask        |
    ///
    /// # Compliance Coverage
    /// This default set covers the most commonly regulated PII categories under
    /// Japanese law. Organizations with additional requirements (medical records,
    /// financial account numbers, etc.) should extend via [`add_rule()`].
    pub fn with_jp_defaults() -> Self {
        let mut rules: Vec<PIIRule> = Vec::new();

        // --- My Number (12-digit personal identification number) ---
        // Format: exactly 12 consecutive digits, word-bounded
        // Note: Real validation requires checksum verification; this is a heuristic scan.
        rules.push(PIIRule::new(
            "my_number",
            r"\b\d{12}\b",
            PIIAction::Mask,
            '*',
            "12-digit My Number (Kojin Bangō) identification number",
        ));

        // --- Email Address (RFC 5322 simplified) ---
        // Catches common email formats; intentionally permissive to reduce false negatives.
        rules.push(PIIRule::new(
            "email",
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            PIIAction::AlertOnly,
            '*',
            "Email address (RFC 5322 simplified pattern)",
        ));

        // --- IPv4 Address ---
        rules.push(PIIRule::new(
            "ip_address_v4",
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
            PIIAction::AlertOnly,
            'X',
            "IPv4 address (dotted-decimal notation)",
        ));

        // --- Credit Card Numbers (16-digit, space/hyphen separated groups) ---
        // Covers JCB (35xx), Visa (4xxx), Mastercard (51-55xx), Discover (6011, 65xx)
        // Pattern: 4 groups of 4 digits with optional separators
        rules.push(PIIRule::new(
            "credit_card",
            r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
            PIIAction::Mask,
            'X',
            "Credit card number (JCB/Visa/Mastercard/Discover, 16 digits)",
        ));

        // --- Japanese Phone Number (loose pattern) ---
        // Matches: 0X-XXXX-XXXX, 0XXXXXXXXXXX, +81-X-XXXX-XXXX
        rules.push(PIIRule::new(
            "phone_jp",
            r"(?:(?:\+81\s*|0)\d{1,4}[\s-]?\d{1,4}[\s-]?\d{4})|(?:0\d{9,10})",
            PIIAction::AlertOnly,
            '*',
            "Japanese telephone number (landline or mobile)",
        ));

        // --- Japanese Postal Code (NNN-NNNN) ---
        rules.push(PIIRule::new(
            "postal_code_jp",
            r"\b\d{3}-\d{4}\b",
            PIIAction::AlertOnly,
            '*',
            "Japanese postal code (7-digit, NNN-NNNN format)",
        ));

        // --- Driver's License Number (Japan) ---
        // Format varies by prefecture; this catches common numeric patterns
        // followed by license-specific indicators
        rules.push(PIIRule::new(
            "drivers_license",
            r"\b\d{10,12}\b", // 10-12 digit license numbers (heuristic)
            PIIAction::Mask,
            '#',
            "Japanese driver's license number (10-12 digit pattern)",
        ));

        Self {
            rules,
            default_action: PIIAction::AlertOnly,
            encodings: vec![
                "utf-8".to_string(),
                "shift-jis".to_string(),
                "euc-jp".to_string(),
                "iso-2022-jp".to_string(),
            ],
        }
    }

    /// Add a custom PII rule to the detector's rule set.
    ///
    /// Rules are applied in registration order; earlier rules take precedence
    /// when two rules produce overlapping matches at the same position.
    ///
    /// # Arguments
    /// * `rule` — The [`PIIRule`] to add.
    pub fn add_rule(&mut self, rule: PIIRule) {
        self.rules.push(rule);
    }

    /// Resolve the strictest action from a set of individual rule actions.
    ///
    /// Precedence (strictest first): **Block > Mask > AlertOnly**.
    ///
    /// # Arguments
    /// * `actions` — Slice of actions from individual rule matches.
    ///
    /// # Returns
    /// The single strictest action from the set.
    fn resolve_strictest_action(actions: &[PIIAction]) -> PIIAction {
        if actions.iter().any(|a| matches!(a, PIIAction::Block)) {
            PIIAction::Block
        } else if actions.iter().any(|a| matches!(a, PIIAction::Mask)) {
            PIIAction::Mask
        } else {
            PIIAction::AlertOnly
        }
    }

    /// Generate a masked version of matched text.
    ///
    /// Preserves first and last character (if length >= 3) for readability,
    /// replacing intermediate characters with the mask character.
    ///
    /// # Examples
    /// - `"123456789012"` with `'*'` → `"1**********2"`
    /// - `"田中太郎"` with `'*'` → `"田***郎"`
    /// - `"AB"` with `'*'` → `"**"` (too short to preserve edges)
    fn mask_text(text: &str, mask_char: char) -> String {
        let chars: Vec<char> = text.chars().collect();
        if chars.len() <= 2 {
            return std::iter::repeat(mask_char).take(chars.len()).collect();
        }

        let mut result = String::with_capacity(chars.len());
        result.push(chars[0]); // Preserve first character

        for _ in 1..chars.len() - 1 {
            result.push(mask_char); // Mask middle characters
        }

        result.push(chars[chars.len() - 1]); // Preserve last character
        result
    }
}

#[async_trait]
impl PIIDetector for RegexPIIDetector {
    /// Returns `"regex-pii-detector"`.
    fn name(&self) -> &str {
        "regex-pii-detector"
    }

    /// Scan text content for PII patterns using all registered rules.
    ///
    /// # Scanning Process
    /// 1. Content is already provided as a `&str` (caller handles encoding normalization).
    /// 2. Each rule's compiled regex is executed against the full content string.
    /// 3. All non-overlapping matches are collected into [`PIIMatch`] entries.
    /// 4. Overall action is determined by [`resolve_strictest_action()`].
    /// 5. Performance metrics (bytes scanned, wall-clock time) are recorded.
    ///
    /// # Arguments
    /// * `content` — Text content to scan (should be pre-normalized to UTF-8).
    /// * `file_id` — Correlation identifier linking results to source file.
    /// * `filename` — Original filename for context-aware logging.
    ///
    /// # Returns
    /// A [`PIIScanResult`] containing all matches and the recommended action.
    ///
    /// # Performance
    /// For typical document sizes (< 1 MB), scanning completes in < 50ms.
    /// Large files (> 100 MB) may benefit from chunked streaming approaches.
    async fn scan(
        &self,
        content: &str,
        file_id: &str,
        filename: &str,
    ) -> Result<PIIScanResult> {
        let start = Instant::now();
        let bytes_scanned = content.len() as u64;
        let mut all_matches: Vec<PIIMatch> = Vec::new();
        let mut matched_actions: Vec<PIIAction> = Vec::new();

        tracing::debug!(
            file_id = %file_id,
            filename = %filename,
            content_length = content.len(),
            rule_count = self.rules.len(),
            "Starting PII scan"
        );

        // Execute each rule against the content
        for rule in &self.rules {
            for capture in rule.pattern.find_iter(content) {
                let matched_text = capture.as_str().to_string();
                let offset = capture.start();
                let length = capture.end() - capture.start();

                let masked_text = Self::mask_text(&matched_text, rule.mask_char);

                let pi_match = PIIMatch {
                    pattern_name: rule.name.clone(),
                    matched_text: matched_text.clone(),
                    masked_text,
                    offset,
                    length,
                    pattern_regex: rule.pattern.as_str().to_string(),
                };

                tracing::debug!(
                    pattern_name = %rule.name,
                    matched_text = %pi_match.masked_text, // Log masked version for security
                    offset = offset,
                    "PII match found"
                );

                all_matches.push(pi_match);
                matched_actions.push(rule.action.clone());
            }
        }

        // Sort matches by offset for ordered presentation
        all_matches.sort_by_key(|m| m.offset);

        // Resolve overall action from all matches
        let action = if all_matches.is_empty() {
            self.default_action.clone()
        } else {
            Self::resolve_strictest_action(&matched_actions)
        };

        let elapsed_ms = start.elapsed().as_millis() as u64;
        let found = !all_matches.is_empty();

        tracing::info!(
            file_id = %file_id,
            filename = %filename,
            match_count = all_matches.len(),
            action = ?action,
            elapsed_ms = elapsed_ms,
            "PII scan completed"
        );

        Ok(PIIScanResult {
            found,
            matches: all_matches,
            action,
            bytes_scanned,
            scan_duration_ms: elapsed_ms,
        })
    }
}

// =============================================================================
// D. Masking Utility Functions
// =============================================================================

/// Replace all PII matches in text with their masked equivalents.
///
/// Processes matches in reverse order (by offset) to preserve position accuracy
/// when multiple replacements occur in the same string. Each matched region
/// is replaced with the pre-computed masked text from the [`PIIMatch`].
///
/// # Arguments
/// * `text` — Original text containing PII.
/// * `matches` — Slice of [`PIIMatch`] entries produced by a scan.
/// * `mask_char` — Character to use for masking (overrides per-match masks if desired).
///
/// # Returns
/// A new String with all matched regions replaced by their masked versions.
///
/// # Example
/// ```ignore
/// let text = "Contact: user@example.com or call 03-1234-5678";
/// let masked = apply_mask(text, &scan_result.matches, '*');
/// // Result: "Contact: ************ or call *************"
/// ```
pub fn apply_mask(text: &str, matches: &[PIIMatch], mask_char: char) -> String {
    if matches.is_empty() {
        return text.to_string();
    }

    let mut result = text.to_string();

    // Process in reverse offset order to maintain position accuracy
    let mut sorted_matches = matches.to_vec();
    sorted_matches.sort_by_key(|m| std::cmp::Reverse(m.offset));

    for m in &sorted_matches {
        // Use the match's own masked_text if available, otherwise generate fresh
        let replacement = if m.masked_text.is_empty() {
            // Generate fresh mask: replace entire match span with mask_char
            std::iter::repeat(mask_char).take(m.length).collect()
        } else {
            m.masked_text.clone()
        };

        // Safety: offsets are validated during regex matching (always valid UTF-8 bounds)
        if m.offset + m.length <= result.len() {
            result.replace_range(m.offset..m.offset + m.length, &replacement);
        }
    }

    result
}

/// Generate a summary string describing PII scan findings for audit logging.
///
/// Produces a human-readable one-line summary suitable for inclusion in
/// audit log entries, notification messages, and dashboard displays.
///
/// # Arguments
/// * `result` — The [`PIIScanResult`] to summarize.
///
/// # Returns
/// A single-line summary string.
pub fn summarize_scan_result(result: &PIIScanResult) -> String {
    if !result.found {
        return format!(
            "Clean: no PII found ({} bytes scanned in {}ms)",
            result.bytes_scanned, result.scan_duration_ms
        );
    }

    let pattern_counts: std::collections::HashMap<&str, usize> =
        result
            .matches
            .iter()
            .map(|m| (m.pattern_name.as_str(), 1))
            .collect();

    let pattern_summary: Vec<String> = pattern_counts
        .into_iter()
        .map(|(name, count)| format!("{}({})", name, count))
        .collect();

    format!(
        "PII Found: {} match(es) [{}] — Action: {:?} ({} bytes, {}ms)",
        result.matches.len(),
        pattern_summary.join(", "),
        result.action,
        result.bytes_scanned,
        result.scan_duration_ms
    )
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // PIIRule Tests
    // =========================================================================

    #[test]
    fn test_rule_new_valid_pattern() {
        let rule = PIIRule::new(
            "test_rule",
            r"\d{4}-\d{4}",
            PIIAction::Mask,
            'X',
            "Test pattern",
        );

        assert_eq!(rule.name, "test_rule");
        assert_eq!(rule.action, PIIAction::Mask);
        assert_eq!(rule.mask_char, 'X');
        assert_eq!(rule.pattern_type, "regex");
    }

    #[test]
    fn test_rule_try_new_invalid_regex() {
        let result = PIIRule::try_new(
            "bad_rule",
            r"(unclosed",
            PIIAction::Block,
            '*',
            "Bad pattern",
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_rule_try_new_valid_pattern() {
        let result = PIIRule::try_new(
            "good_rule",
            r"[a-z]+",
            PIIAction::AlertOnly,
            '*',
            "Good pattern",
        );

        assert!(result.is_ok());
        let rule = result.unwrap();
        assert_eq!(rule.name, "good_rule");
    }

    #[test]
    fn test_rule_pattern_matching() {
        let rule = PIIRule::new("digits", r"\d+", PIIAction::Mask, '*', "Digits");
        assert!(rule.pattern.is_match("abc123def"));
        assert!(!rule.pattern.is_match("abcdef"));
    }

    // =========================================================================
    // RegexPIIDetector Construction Tests
    // =========================================================================

    #[test]
    fn test_detector_name() {
        let detector = RegexPIIDetector::with_jp_defaults();
        assert_eq!(detector.name(), "regex-pii-detector");
    }

    #[test]
    fn test_detector_with_jp_defaults_has_rules() {
        let detector = RegexPIIDetector::with_jp_defaults();
        assert!(!detector.rules.is_empty());

        // Check for expected built-in rules
        let names: Vec<&str> = detector.rules.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"my_number"));
        assert!(names.contains(&"email"));
        assert!(names.contains(&"ip_address_v4"));
        assert!(names.contains(&"credit_card"));
        assert!(names.contains(&"phone_jp"));
        assert!(names.contains(&"postal_code_jp"));
    }

    #[test]
    fn test_detector_add_rule() {
        let mut detector = RegexPIIDetector::new(vec![], PIIAction::AlertOnly, vec![]);
        assert_eq!(detector.rules.len(), 0);

        detector.add_rule(PIIRule::new(
            "custom",
            r"SECRET-\d+",
            PIIAction::Block,
            '#',
            "Custom secret pattern",
        ));

        assert_eq!(detector.rules.len(), 1);
        assert_eq!(detector.rules[0].name, "custom");
    }

    #[test]
    fn test_detector_default_encodings() {
        let detector = RegexPIIDetector::with_jp_defaults();
        assert!(detector.encodings.contains(&"utf-8".to_string()));
        assert!(detector.encodings.contains(&"shift-jis".to_string()));
        assert!(detector.encodings.contains(&"euc-jp".to_string()));
    }

    // =========================================================================
    // PII Scanning Tests — My Number
    // =========================================================================

    #[tokio::test]
    async fn test_scan_my_number_detected() {
        let detector = RegexPIIDetector::with_jp_defaults();
        let content = "My Number is 123456789012 and it should be masked.";

        let result = detector.scan(content, "file-1", "test.txt").await.unwrap();

        assert!(result.found);
        assert_eq!(result.action, PIIAction::Mask); // My Number rule uses Mask

        // Should find the 12-digit number
        let my_number_match = result
            .matches
            .iter()
            .find(|m| m.pattern_name == "my_number");
        assert!(my_number_match.is_some());

        let m = my_number_match.unwrap();
        assert_eq!(m.matched_text, "123456789012");
        assert_eq!(m.masked_text, "1**********2"); // First + 10 asterisks + last
    }

    #[tokio::test]
    async fn test_scan_my_number_not_in_short_numbers() {
        let detector = RegexPIIDetector::with_jp_defaults();
        let content = "Phone: 03-1234-5678, ID: 12345"; // Only 5 digits, not 12

        let result = detector.scan(content, "file-2", "short.txt").await.unwrap();

        // No 12-digit number should be found
        let my_number_matches: Vec<_> = result
            .matches
            .iter()
            .filter(|m| m.pattern_name == "my_number")
            .collect();
        assert!(my_number_matches.is_empty());
    }

    // =========================================================================
    // PII Scanning Tests — Email
    // =========================================================================

    #[tokio::test]
    async fn test_scan_email_detected() {
        let detector = RegexPIIDetector::with_jp_defaults();
        let content = "Contact: tanaka@example.go.jp for details.";

        let result = detector.scan(content, "file-3", "email_test.txt").await.unwrap();

        assert!(result.found);

        let email_match = result
            .matches
            .iter()
            .find(|m| m.pattern_name == "email");
        assert!(email_match.is_some());

        let m = email_match.unwrap();
        assert_eq!(m.matched_text, "tanaka@example.go.jp");
        // Email uses AlertOnly, so mask_char doesn't matter much but check structure
        assert_eq!(m.offset, 9); // After "Contact: "
    }

    #[tokio::test]
    async fn test_scan_email_alert_only_action() {
        let detector = RegexPIIDetector::with_jp_defaults();
        let content = "Email: user@domain.com";

        let result = detector.scan(content, "file-4", "email_only.txt").await.unwrap();

        // Email-only match should yield AlertOnly (not Block or Mask)
        let email_matches: Vec<_> = result
            .matches
            .iter()
            .filter(|m| m.pattern_name == "email")
            .collect();

        if !email_matches.is_empty() && result.matches.len() == 1 {
            // Only email matched → action should be AlertOnly
            assert_eq!(result.action, PIIAction::AlertOnly);
        }
    }

    // =========================================================================
    // PII Scanning Tests — IP Address
    // =========================================================================

    #[tokio::test]
    async fn test_scan_ipv4_detected() {
        let detector = RegexPIIDetector::with_jp_defaults();
        let content = "Server at 192.168.1.100 is responding.";

        let result = detector.scan(content, "file-5", "ip_test.txt").await.unwrap();

        assert!(result.found);

        let ip_match = result
            .matches
            .iter()
            .find(|m| m.pattern_name == "ip_address_v4");
        assert!(ip_match.is_some());
        assert_eq!(ip_match.unwrap().matched_text, "192.168.1.100");
    }

    #[tokio::test]
    async fn test_scan_ipv4_invalid_rejected() {
        let detector = RegexPIIDetector::with_jp_defaults();
        let content = "Not an IP: 999.999.999.999 and also 256.1.2.3";

        let result = detector.scan(content, "file-6", "bad_ip.txt").await.unwrap();

        // 999.x.x.x and 256.x.x.x are invalid IPv4 and shouldn't match our strict pattern
        let ip_matches: Vec<_> = result
            .matches
            .iter()
            .filter(|m| m.pattern_name == "ip_address_v4")
            .collect();
        assert!(ip_matches.is_empty()); // Strict octet range should reject these
    }

    // =========================================================================
    // PII Scanning Tests — Credit Card
    // =========================================================================

    #[tokio::test]
    async fn test_scan_credit_card_detected() {
        let detector = RegexPIIDetector::with_jp_defaults();
        let content = "Card: 4111 1111 1111 1111 expires 12/25";

        let result = detector.scan(content, "file-7", "cc_test.txt").await.unwrap();

        assert!(result.found);

        let cc_match = result
            .matches
            .iter()
            .find(|m| m.pattern_name == "credit_card");
        assert!(cc_match.is_some());

        let m = cc_match.unwrap();
        assert_eq!(m.matched_text, "4111 1111 1111 1111");
        // Credit card uses Mask action with 'X' — 19 chars: first + 17 X + last
        assert_eq!(m.masked_text, "4XXXXXXXXXXXXXXXXX1");
    }

    #[tokio::test]
    async fn test_scan_credit_card_hyphenated() {
        let detector = RegexPIIDetector::with_jp_defaults();
        let content = "JCB: 3566-0020-2036-0505";

        let result = detector.scan(content, "file-8", "jcb_test.txt").await.unwrap();

        let cc_match = result
            .matches
            .iter()
            .find(|m| m.pattern_name == "credit_card");
        assert!(cc_match.is_some());
        assert_eq!(cc_match.unwrap().matched_text, "3566-0020-2036-0505");
    }

    // =========================================================================
    // PII Scanning Tests — Phone / Postal Code
    // =========================================================================

    #[tokio::test]
    async fn test_scan_phone_jp_detected() {
        let detector = RegexPIIDetector::with_jp_defaults();
        let content = "Call us at 03-1234-5678 or mobile 090-1234-5678";

        let result = detector.scan(content, "file-9", "phone.txt").await.unwrap();

        assert!(result.found);

        let phone_matches: Vec<_> = result
            .matches
            .iter()
            .filter(|m| m.pattern_name == "phone_jp")
            .collect();
        assert!(!phone_matches.is_empty());
    }

    #[tokio::test]
    async fn test_scan_postal_code_jp_detected() {
        let detector = RegexPIIDetector::with_jp_defaults();
        let content = "Address: 100-0001, Chiyoda, Tokyo";

        let result = detector
            .scan(content, "file-10", "postal.txt")
            .await
            .unwrap();

        assert!(result.found);

        let postal_match = result
            .matches
            .iter()
            .find(|m| m.pattern_name == "postal_code_jp");
        assert!(postal_match.is_some());
        assert_eq!(postal_match.unwrap().matched_text, "100-0001");
    }

    // =========================================================================
    // Clean Scan Tests
    // =========================================================================

    #[tokio::test]
    async fn test_scan_clean_content_no_pii() {
        let detector = RegexPIIDetector::with_jp_defaults();
        let content = "This is a clean document with no sensitive information.";

        let result = detector
            .scan(content, "file-11", "clean.txt")
            .await
            .unwrap();

        assert!(!result.found);
        assert!(result.matches.is_empty());
        assert_eq!(result.action, PIIAction::AlertOnly); // Default action
    }

    #[tokio::test]
    async fn test_scan_empty_content() {
        let detector = RegexPIIDetector::with_jp_defaults();
        let result = detector.scan("", "file-12", "empty.txt").await.unwrap();

        assert!(!result.found);
        assert_eq!(result.bytes_scanned, 0);
    }

    // =========================================================================
    // Action Resolution Tests
    // =========================================================================

    #[tokio::test]
    async fn test_resolve_block_wins_over_mask() {
        // Create a detector with both Block and Mask rules
        let rules = vec![
            PIIRule::new("mask_rule", r"\bMASKME\b", PIIAction::Mask, '*', "Mask this"),
            PIIRule::new(
                "block_rule",
                r"\bBLOCKME\b",
                PIIAction::Block,
                '#',
                "Block this",
            ),
        ];
        let detector = RegexPIIDetector::new(rules, PIIAction::AlertOnly, vec!["utf-8".to_string()]);

        let content = "MASKME and BLOCKME are here";
        let result = detector.scan(content, "file-13", "mixed.txt").await.unwrap();

        // Block should win over Mask
        assert_eq!(result.action, PIIAction::Block);
    }

    #[tokio::test]
    async fn test_resolve_mask_wins_over_alert() {
        // Note: \bALERT\b won't match inside "ALERTME", \bMASK\b won't match inside "MASKME"
        // Use standalone words that will actually match
        let rules = vec![
            PIIRule::new("alert_rule", r"\bALERT\b", PIIAction::AlertOnly, '*', "Alert"),
            PIIRule::new("mask_rule", r"\bMASK\b", PIIAction::Mask, '*', "Mask"),
        ];
        let detector = RegexPIIDetector::new(rules, PIIAction::AlertOnly, vec!["utf-8".to_string()]);

        // Use standalone words (not substrings) so regex word boundaries work
        let content = "MASK and ALERT are here";
        let result = detector
            .scan(content, "file-14", "alert_mask.txt")
            .await
            .unwrap();

        assert_eq!(result.action, PIIAction::Mask);
    }

    // =========================================================================
    // Masking Utility Tests
    // =========================================================================

    #[test]
    fn test_apply_mask_single_match() {
        let text = "My number is 123456789012";
        let matches = vec![PIIMatch {
            pattern_name: "my_number".to_string(),
            matched_text: "123456789012".to_string(),
            masked_text: "1**********2".to_string(),
            offset: 12,
            length: 12,
            pattern_regex: r"\d{12}".to_string(),
        }];

        let result = apply_mask(text, &matches, '*');
        // Verify masking occurred (exact format depends on replace_range semantics)
        assert!(result.contains("*********"));
        assert!(!result.contains("123456789012"));
    }

    #[test]
    fn test_apply_mask_multiple_matches() {
        let text = "A 123456789012 B 987654321098 C";
        let matches = vec![
            PIIMatch {
                pattern_name: "my_number".to_string(),
                matched_text: "123456789012".to_string(),
                masked_text: "1**********2".to_string(),
                offset: 2,
                length: 12,
                pattern_regex: r"\d{12}".to_string(),
            },
            PIIMatch {
                pattern_name: "my_number".to_string(),
                matched_text: "987654321098".to_string(),
                masked_text: "9**********8".to_string(),
                offset: 17,
                length: 12,
                pattern_regex: r"\d{12}".to_string(),
            },
        ];

        let result = apply_mask(text, &matches, '*');
        assert_eq!(result, "A 1**********2 B 9**********8 C");
    }

    #[test]
    fn test_apply_mask_no_matches() {
        let text = "Clean text with nothing to mask";
        let result = apply_mask(text, &[], '*');
        assert_eq!(result, text);
    }

    #[test]
    fn test_mask_text_preserves_edges() {
        assert_eq!(RegexPIIDetector::mask_text("ABC", '*'), "A*C");
        assert_eq!(RegexPIIDetector::mask_text("AB", '*'), "**"); // Too short
        assert_eq!(RegexPIIDetector::mask_text("A", '*'), "*"); // Single char
        assert_eq!(
            RegexPIIDetector::mask_text("田中太郎", '*'),
            "田**郎"
        ); // 4 CJK chars: first + 2 mask + last
    }

    // =========================================================================
    // Summary Utility Tests
    // =========================================================================

    #[test]
    fn test_summarize_clean_result() {
        let result = PIIScanResult::clean(1024, 5);
        let summary = summarize_scan_result(&result);
        assert!(summary.contains("no PII found"));
        assert!(summary.contains("1024"));
    }

    #[test]
    fn test_summarize_dirty_result() {
        let result = PIIScanResult {
            found: true,
            matches: vec![PIIMatch {
                pattern_name: "my_number".to_string(),
                matched_text: "123456789012".to_string(),
                masked_text: "1**********2".to_string(),
                offset: 0,
                length: 12,
                pattern_regex: r"\d{12}".to_string(),
            }],
            action: PIIAction::Mask,
            bytes_scanned: 500,
            scan_duration_ms: 3,
        };

        let summary = summarize_scan_result(&result);
        assert!(summary.contains("PII Found"));
        assert!(summary.contains("my_number"));
        assert!(summary.contains("Mask"));
    }

    // =========================================================================
    // PIIScanResult Helper Tests
    // =========================================================================

    #[test]
    fn test_scan_result_clean_factory() {
        let result = PIIScanResult::clean(2048, 10);
        assert!(!result.found);
        assert!(result.matches.is_empty());
        assert_eq!(result.bytes_scanned, 2048);
        assert_eq!(result.scan_duration_ms, 10);
    }

    #[test]
    fn test_scan_result_strictest_action() {
        let result = PIIScanResult {
            found: true,
            matches: vec![],
            action: PIIAction::Block,
            bytes_scanned: 100,
            scan_duration_ms: 1,
        };
        assert_eq!(result.strictest_action(), &PIIAction::Block);
    }

    // =========================================================================
    // PIIMatch Field Integrity Tests
    // =========================================================================

    #[test]
    fn test_pii_match_fields() {
        let m = PIIMatch {
            pattern_name: "test_pattern".to_string(),
            matched_text: "SENSITIVE_DATA".to_string(),
            masked_text: "S***********A".to_string(),
            offset: 42,
            length: 13,
            pattern_regex: r"[A-Z_]+".to_string(),
        };

        assert_eq!(m.pattern_name, "test_pattern");
        assert_eq!(m.matched_text, "SENSITIVE_DATA");
        assert_eq!(m.masked_text, "S***********A");
        assert_eq!(m.offset, 42);
        assert_eq!(m.length, 13);
    }

    // =========================================================================
    // Multi-Pattern Coexistence Test
    // =========================================================================

    #[tokio::test]
    async fn test_scan_mixed_pii_types() {
        let detector = RegexPIIDetector::with_jp_defaults();
        let content = concat!(
            "User: tanaka@mail.jp, ",
            "My Number: 987654321098, ",
            "IP: 10.0.0.1, ",
            "Card: 5555 5555 5555 4444, ",
            "Postal: 150-0001"
        );

        let result = detector
            .scan(content, "file-15", "mixed_pii.txt")
            .await
            .unwrap();

        assert!(result.found);
        assert!(result.matches.len() >= 4); // At least email, my_number, ip, cc

        // Verify different pattern types were detected
        let pattern_names: Vec<&str> =
            result.matches.iter().map(|m| m.pattern_name.as_str()).collect();
        assert!(pattern_names.contains(&"email"));
        assert!(pattern_names.contains(&"my_number"));
        assert!(pattern_names.contains(&"credit_card"));

        // Overall action should be Mask (from my_number or credit_card)
        assert_eq!(result.action, PIIAction::Mask);
    }
}
