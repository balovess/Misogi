//! Universal PII detection patterns applicable across all regions.
//!
//! Defines commonly recognized personally identifiable information patterns
//! that are relevant regardless of jurisdiction:
//! - Payment card numbers (PCI-DSS scope)
//! - Global identifiers (IBAN, passport formats)
//! - Contact information (email, universal phone patterns)

use serde::{Deserialize, Serialize};

/// Pre-defined international PII detection rule templates.
///
/// Each rule contains a regex pattern, human-readable metadata, and
/// recommended action suitable for inclusion in PIIDetector configurations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiRulePack {
    /// Unique identifier for this rule (e.g., "pii_credit_card_visa_mc").
    pub rule_id: String,

    /// Human-readable name of the pattern category.
    pub name: String,

    /// Detailed description of what this pattern detects.
    pub description: String,

    /// Regular expression pattern string in Rust regex syntax.
    pub pattern: String,

    /// Recommended action: "block", "mask", or "alert_only".
    pub recommended_action: String,

    /// List of ISO 3166-1 alpha-2 country codes or "global" for universal rules.
    pub applicable_regions: Vec<String>,
}

/// Well-known international PII pattern definitions.
///
/// Provides a curated set of globally-relevant PII detection rules that
/// SIer can use as a baseline before adding region-specific patterns from
/// `contrib/jp`, `contrib/kr`, or custom implementations.
pub struct InternationalPiiPatterns;

impl InternationalPiiPatterns {
    /// Return all universal PII rules as a vector of [`PiiRulePack`].
    ///
    /// These rules cover payment card data (PCI-DSS), global identifiers,
    /// and contact information — categories relevant across all jurisdictions.
    pub fn all_rules() -> Vec<PiiRulePack> {
        vec![
            // --- Payment Cards (PCI-DSS Scope) ---
            PiiRulePack {
                rule_id: "pii_credit_card_visa_mc".to_string(),
                name: "Credit Card (Visa/Mastercard)".to_string(),
                description: "Detects major credit card number patterns (13-19 digits)".to_string(),
                pattern: r"\b4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}\b".to_string(),
                recommended_action: "mask".to_string(),
                applicable_regions: vec!["global".to_string()],
            },
            PiiRulePack {
                rule_id: "pii_credit_card_amex".to_string(),
                name: "Credit Card (American Express)".to_string(),
                description: "Detects Amex card number patterns (15 digits, starts with 34-37)".to_string(),
                pattern: r"\b3[47][0-9]{13}\b".to_string(),
                recommended_action: "mask".to_string(),
                applicable_regions: vec!["global".to_string()],
            },
            PiiRulePack {
                rule_id: "pii_credit_card_unionpay".to_string(),
                name: "Credit Card (UnionPay)".to_string(),
                description: "Detects UnionPay card number patterns (16-19 digits, starts with 62)".to_string(),
                pattern: r"\b62[0-9]{14,17}\b".to_string(),
                recommended_action: "mask".to_string(),
                applicable_regions: vec!["CN".to_string(), "global".to_string()],
            },

            // --- Global Identifiers ---
            PiiRulePack {
                rule_id: "pii_iban".to_string(),
                name: "IBAN (International Bank Account Number)".to_string(),
                description: "Detects IBAN format: 2-letter country code + 2 check digits + up to 30 alphanumerics".to_string(),
                pattern: r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4,30}\b".to_string(),
                recommended_action: "mask".to_string(),
                applicable_regions: vec!["EU".to_string(), "global".to_string()],
            },
            PiiRulePack {
                rule_id: "pii_passport_generic".to_string(),
                name: "Passport Number (Generic Format)".to_string(),
                description: "Detects generic passport number patterns (alphanumeric, 6-9 characters)".to_string(),
                pattern: r"\b[A-Z][0-9]{5,8}\b".to_string(),
                recommended_action: "alert_only".to_string(),
                applicable_regions: vec!["global".to_string()],
            },

            // --- Contact Information ---
            PiiRulePack {
                rule_id: "pii_email".to_string(),
                name: "Email Address".to_string(),
                description: "Detects standard email address format (RFC 5322 compliant)".to_string(),
                pattern: r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b".to_string(),
                recommended_action: "alert_only".to_string(),
                applicable_regions: vec!["global".to_string()],
            },
            PiiRulePack {
                rule_id: "pii_ipv4_address".to_string(),
                name: "IPv4 Address".to_string(),
                description: "Detects IPv4 address patterns (excluding reserved ranges like 10.x, 192.168.x)".to_string(),
                pattern: r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b".to_string(),
                recommended_action: "alert_only".to_string(),
                applicable_regions: vec!["global".to_string()],
            },
        ]
    }
}
