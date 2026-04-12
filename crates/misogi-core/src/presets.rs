use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Pre-configured compliance profiles for regional regulatory frameworks.
///
/// Each preset encodes a complete set of security and operational parameters
/// that SIer can select via CLI flag or config file without manual tuning.
///
/// # Locale Support
///
/// The [`description`] field serves as the primary (English) description.
/// Region-specific translations are stored in [`localized_descriptions`],
/// keyed by BCP 47 language tag (e.g., `"ja"` for Japanese, `"ko"` for Korean).
///
/// Use [`description_for_locale()`](Self::description_for_locale) to retrieve
/// the best available description for a given locale, falling back to the
/// primary English description when no translation exists.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompliancePreset {
    /// Unique kebab-case identifier for this compliance profile.
    pub name: String,

    /// Primary description in English (universal fallback for all locales).
    pub description: String,

    /// Optional locale-specific descriptions keyed by BCP 47 language tag.
    ///
    /// Example: `{"ja": "地方自治体LGWAN対応プロファイル"}`
    ///
    /// Serialized as an empty map `{}` when no translations exist.
    #[serde(default)]
    pub localized_descriptions: HashMap<String, String>,

    /// Whether file transfer approval workflow is mandatory under this profile.
    pub approval_required: bool,

    /// Whether users must provide a textual reason when submitting transfers.
    pub reason_required: bool,

    /// CDR sanitization policy level applied to uploaded files.
    pub sanitization_policy: SanitizationPolicy,

    /// Maximum nested ZIP archive depth allowed before rejection.
    pub zip_max_depth: u32,

    /// Maximum compression ratio (uncompressed / compressed) before bomb detection triggers.
    pub zip_max_expansion_ratio: u64,

    /// Maximum upload size for PDF files in megabytes.
    pub max_pdf_size_mb: u64,

    /// Maximum upload size for Office documents (doc/xls/ppt) in megabytes.
    pub max_office_size_mb: u64,

    /// Maximum upload size for ZIP archives in megabytes.
    pub max_zip_size_mb: u64,

    /// Number of days audit log entries must be retained before purging.
    pub audit_retention_days: u64,

    /// Whether client IP addresses are recorded in audit logs (privacy consideration).
    pub log_ip_address: bool,

    /// Whether User-Agent strings are recorded in audit logs.
    pub log_user_agent: bool,
}

/// Sanitization policy levels used by compliance presets.
///
/// Mirrors the CDR engine's SanitizationPolicy for configuration purposes.
///
/// | Policy | Behavior |
///|--------|----------|
/// | `StripActiveContent` | Remove macros/scripts/embedded objects; preserve layout |
/// | `ConvertToFlat` | Flatten to safe subset (e.g., PDF → image-only) |
/// | `TextOnly` | Extract text only; discard all formatting |
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SanitizationPolicy {
    StripActiveContent,
    ConvertToFlat,
    TextOnly,
}

impl Default for SanitizationPolicy {
    fn default() -> Self {
        Self::StripActiveContent
    }
}

impl CompliancePreset {
    /// Local government LGWAN compliant profile.
    ///
    /// Maximum security for Japanese government agencies handling citizen PII
    /// on LGWAN (Local Government Wide Area Network).
    ///
    /// Mandatory approval workflow, full audit trail, strict file limits per
    /// 地方公共機関情報システム安全対策基準.
    pub fn lgwan_government() -> Self {
        let mut localized = HashMap::new();
        localized.insert("ja".to_string(), "地方自治体LGWAN対応プロファイル（最強セキュリティ）".to_string());

        Self {
            name: "lgwan_government".to_string(),
            description: "Japanese local government LGWAN compliance profile (maximum security)".to_string(),
            localized_descriptions: localized,
            approval_required: true,
            reason_required: true,
            sanitization_policy: SanitizationPolicy::StripActiveContent,
            zip_max_depth: 2,
            zip_max_expansion_ratio: 5,
            max_pdf_size_mb: 100,
            max_office_size_mb: 50,
            max_zip_size_mb: 200,
            audit_retention_days: 2555,
            log_ip_address: true,
            log_user_agent: true,
        }
    }

    /// Medical institution HIPAA-Japan aligned profile prioritizing patient data privacy.
    ///
    /// Designed for Japanese healthcare providers handling sensitive patient
    /// records under 個人情報保護法 and 医療分野ガイドライン.
    pub fn medical_hipaa_jp() -> Self {
        let mut localized = HashMap::new();
        localized.insert("ja".to_string(), "医療機関向けプライバシー優先プロファイル".to_string());

        Self {
            name: "medical_hipaa_jp".to_string(),
            description: "Medical institution privacy-priority profile (HIPAA-Japan aligned)".to_string(),
            localized_descriptions: localized,
            approval_required: true,
            reason_required: true,
            sanitization_policy: SanitizationPolicy::ConvertToFlat,
            zip_max_depth: 1,
            zip_max_expansion_ratio: 3,
            max_pdf_size_mb: 50,
            max_office_size_mb: 25,
            max_zip_size_mb: 100,
            audit_retention_days: 3650,
            log_ip_address: true,
            log_user_agent: true,
        }
    }

    /// General enterprise efficiency-focused profile for private sector SIers.
    ///
    /// Balanced security posture suitable for non-regulated business environments
    /// where operational throughput takes priority over maximum lockdown.
    pub fn sler_general() -> Self {
        let mut localized = HashMap::new();
        localized.insert("ja".to_string(), "一般企業向け効率重視プロファイル".to_string());

        Self {
            name: "sler_general".to_string(),
            description: "General enterprise efficiency-focused profile for SIers".to_string(),
            localized_descriptions: localized,
            approval_required: false,
            reason_required: false,
            sanitization_policy: SanitizationPolicy::StripActiveContent,
            zip_max_depth: 3,
            zip_max_expansion_ratio: 10,
            max_pdf_size_mb: 500,
            max_office_size_mb: 200,
            max_zip_size_mb: 500,
            audit_retention_days: 365,
            log_ip_address: false,
            log_user_agent: false,
        }
    }

    /// US NIST Zero Trust Architecture aligned profile for DoD/federal deployment.
    ///
    /// Conforms to NIST SP 800-207 Zero Trust Networking recommendations
    /// and DISA STIG security technical implementation guides.
    pub fn nist_zta() -> Self {
        Self {
            name: "nist_zta".to_string(),
            description: "US NIST ZTA-aligned profile for federal/DoD CDS deployment".to_string(),
            localized_descriptions: HashMap::new(),
            approval_required: true,
            reason_required: true,
            sanitization_policy: SanitizationPolicy::ConvertToFlat,
            zip_max_depth: 1,
            zip_max_expansion_ratio: 3,
            max_pdf_size_mb: 50,
            max_office_size_mb: 25,
            max_zip_size_mb: 100,
            audit_retention_days: 2555,
            log_ip_address: true,
            log_user_agent: true,
        }
    }

    /// Australian ACSC (Australian Cyber Security Centre) CDS profile.
    ///
    /// Aligns with ACSC/ASD Cross-Domain Solutions guidance and
    /// Australian Government Information Security Manual (ISM).
    pub fn acsc_au() -> Self {
        Self {
            name: "acsc_au".to_string(),
            description: "Australian ACSC CDS-aligned profile (ISM Controls)".to_string(),
            localized_descriptions: HashMap::new(),
            approval_required: true,
            reason_required: false,
            sanitization_policy: SanitizationPolicy::StripActiveContent,
            zip_max_depth: 3,
            zip_max_expansion_ratio: 10,
            max_pdf_size_mb: 200,
            max_office_size_mb: 100,
            max_zip_size_mb: 500,
            audit_retention_days: 2555,
            log_ip_address: true,
            log_user_agent: false,
        }
    }

    /// Korean Financial Supervisory Service (FSS) aligned profile.
    ///
    /// Designed for Korean financial institutions operating under
    /// Network Separation (네트워크 분리) regulations.
    pub fn fss_kr() -> Self {
        Self {
            name: "fss_kr".to_string(),
            description: "Korean FSS network separation compliance profile".to_string(),
            localized_descriptions: HashMap::new(),
            approval_required: true,
            reason_required: true,
            sanitization_policy: SanitizationPolicy::StripActiveContent,
            zip_max_depth: 2,
            zip_max_expansion_ratio: 5,
            max_pdf_size_mb: 100,
            max_office_size_mb: 50,
            max_zip_size_mb: 200,
            audit_retention_days: 3650,
            log_ip_address: true,
            log_user_agent: true,
        }
    }

    /// List all available presets across all supported regions.
    pub fn all_presets() -> Vec<Self> {
        vec![
            Self::lgwan_government(),
            Self::medical_hipaa_jp(),
            Self::sler_general(),
            Self::nist_zta(),
            Self::acsc_au(),
            Self::fss_kr(),
        ]
    }

    /// Find preset by name (case-insensitive exact match).
    pub fn find_by_name(name: &str) -> Option<Self> {
        Self::all_presets().into_iter()
            .find(|p| p.name.to_lowercase() == name.to_lowercase())
    }

    /// Return the best available description for the requested locale.
    ///
    /// Lookup priority:
    /// 1. Exact match in [`localized_descriptions`] by `locale` key (e.g., `"ja"`)
    /// 2. Fallback to the primary [`description`] (English)
    ///
    /// # Arguments
    ///
    /// * `locale` - BCP 47 language tag (e.g., `"ja"`, `"ko"`, `"en"`, `"zh-Hans"`)
    ///
    /// # Returns
    ///
    /// A `&str` reference to either the localized description or the English default.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let preset = CompliancePreset::lgwan_government();
    /// assert_eq!(preset.description_for_locale("ja"), "地方自治体LGWAN対応プロファイル（最強セキュリティ）");
    /// assert_eq!(preset.description_for_locale("ko"), preset.description); // falls back to EN
    /// ```
    pub fn description_for_locale(&self, locale: &str) -> &str {
        self.localized_descriptions
            .get(locale)
            .map(|s| s.as_str())
            .unwrap_or(&self.description)
    }
}
