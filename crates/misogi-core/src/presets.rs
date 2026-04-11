use serde::{Deserialize, Serialize};

/// Pre-configured compliance profiles matching Japanese regulatory frameworks.
/// Each preset encodes a complete set of security and operational parameters
/// that SIer can select via CLI flag or config file without manual tuning.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompliancePreset {
    pub name: String,
    pub description_jp: String,
    pub description_en: String,
    pub approval_required: bool,
    pub reason_required: bool,
    pub sanitization_policy: SanitizationPolicy,
    pub zip_max_depth: u32,
    pub zip_max_expansion_ratio: u64,
    pub max_pdf_size_mb: u64,
    pub max_office_size_mb: u64,
    pub max_zip_size_mb: u64,
    pub audit_retention_days: u64,
    pub log_ip_address: bool,
    pub log_user_agent: bool,
}

/// Sanitization policy levels used by compliance presets.
/// Mirrors the CDR engine's SanitizationPolicy for configuration purposes.
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
    /// Maximum security for government agencies handling citizen PII.
    /// Mandatory approval workflow, full audit trail, strict file limits.
    pub fn lgwan_government() -> Self {
        Self {
            name: "lgwan_government".to_string(),
            description_jp: "地方自治体LGWAN対応プロファイル（最強セキュリティ）".to_string(),
            description_en: "Japanese local government LGWAN compliance profile (maximum security)".to_string(),
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
    pub fn medical_hipaa_jp() -> Self {
        Self {
            name: "medical_hipaa_jp".to_string(),
            description_jp: "医療機関向けプライバシー優先プロファイル".to_string(),
            description_en: "Medical institution privacy-priority profile (HIPAA-Japan aligned)".to_string(),
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
    pub fn sler_general() -> Self {
        Self {
            name: "sler_general".to_string(),
            description_jp: "一般企業向け効率重視プロファイル".to_string(),
            description_en: "General enterprise efficiency-focused profile for SIers".to_string(),
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
            description_jp: String::new(),
            description_en: "US NIST ZTA-aligned profile for federal/DoD CDS deployment".to_string(),
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
            description_jp: String::new(),
            description_en: "Australian ACSC CDS-aligned profile (ISM Controls)".to_string(),
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
            description_jp: String::new(),
            description_en: "Korean FSS network separation compliance profile".to_string(),
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

    /// List all available presets
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

    /// Find preset by name (case-insensitive)
    pub fn find_by_name(name: &str) -> Option<Self> {
        Self::all_presets().into_iter()
            .find(|p| p.name.to_lowercase() == name.to_lowercase())
    }
}
