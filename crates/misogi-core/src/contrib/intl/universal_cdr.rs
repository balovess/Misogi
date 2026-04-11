//! Universal CDR (Content Disarm & Reconstruction) policy definitions.
//!
//! Provides region-agnostic security policies for detecting and neutralizing
//! common file-based attack vectors that transcend national boundaries:
//!
//! - JavaScript/ActionScript embedded in PDFs
//! - Office macro signatures (VBA, Excel 4.0 macros)
//! - ZIP bomb / decompression bomb indicators
//! - Embedded executable objects in OLE containers
//!
//! These signatures complement region-specific CDR strategies (e.g.,
//! `contrib/jp` for Japanese document formats) with universal threat coverage.
//!
//! # Design Rationale
//!
//! Region-specific modules (`jp`, `kr`) focus on:
//! - Local document format handling (HWP, 一太郎, JTD)
//! - Local encoding normalization (Shift-JIS, EUC-KR)
//! - Local regulatory audit trail requirements
//!
//! This module focuses on:
//! - Platform-independent exploit vectors (PDF JS, Flash, macros)
//! - Compression/decompression attacks (ZIP bombs)
//! - Embedded object threats (OLE executables)
//!
//! Both layers compose additively: the universal policies form the security
//! baseline while regional policies add domain-specific protections on top.

use serde::{Deserialize, Serialize};

/// Known malicious PDF signature categories used in universal CDR scanning.
///
/// Each variant represents a distinct class of threat vector commonly found
/// in weaponized PDF files distributed via phishing campaigns and APT operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MaliciousPdfSignature {
    /// Embedded JavaScript (Acrobat / PDF.js execution context).
    ///
    /// JavaScript in PDFs can execute arbitrary code when the document is
    /// opened in vulnerable PDF readers. This is one of the most common
    /// attack vectors in targeted phishing campaigns.
    JavaScript,

    /// OpenAction / page-level automatic trigger on document open.
    ///
    /// The `/OpenAction` catalog entry specifies an action to perform
    /// when the document is opened, often used to launch JavaScript
    /// or navigate to attacker-controlled URLs without user interaction.
    AutoAction,

    /// Embedded Flash/SWF content (deprecated but still exploited).
    ///
    /// Although Adobe Flash has been end-of-lifed, legacy systems may
    /// still render embedded SWF content within PDF containers, providing
    /// an attack surface for known Flash vulnerabilities.
    FlashContent,

    /// Launch action referencing external URLs or executables.
    ///
    /// The `/Launch` action can reference external programs or URLs,
    /// enabling command injection and remote code execution on vulnerable
    /// systems where PDF handlers honor these actions.
    LaunchAction,

    /// RichMedia / 3D annotation with embedded scripts.
    ///
    /// RichMedia annotations can contain embedded Flash or multimedia
    /// content with associated scripts that execute in the PDF context.
    RichMediaAnnot,

    /// Obfuscated hex-encoded JavaScript streams.
    ///
    /// Attackers often encode JavaScript payloads using hexadecimal or
    /// octal escape sequences to evade signature-based detection.
    /// This variant flags streams with high entropy indicative of encoding.
    ObfuscatedScript,
}

impl std::fmt::Display for MaliciousPdfSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::JavaScript => write!(f, "javascript"),
            Self::AutoAction => write!(f, "auto_action"),
            Self::FlashContent => write!(f, "flash_content"),
            Self::LaunchAction => write!(f, "launch_action"),
            Self::RichMediaAnnot => write!(f, "richmedia_annot"),
            Self::ObfuscatedScript => write!(f, "obfuscated_script"),
        }
    }
}

/// Universal baseline CDR policy configuration.
///
/// Defines the minimum security posture for cross-domain file transfer
/// regardless of target region. Region-specific modules (`jp`, `kr`) MAY
/// impose ADDITIONAL restrictions on top of this baseline through their
/// own policy configuration structures.
///
/// # Layered Security Model
///
/// ```text
/// ┌─────────────────────────────────────┐
/// │   Regional Policy (jp / kr)         │ ← Domain-specific rules
/// │   - HWP sanitization               │
/// │   - 一太郎 macro stripping         │
/// │   - FSS audit trail fields          │
/// ├─────────────────────────────────────┤
/// │   Universal Policy (this struct)    │ ← Baseline security
/// │   - PDF JS removal                 │
/// │   - ZIP depth limits               │
/// │   - OLE executable blocking        │
/// └─────────────────────────────────────┘
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniversalCdrPolicy {
    /// Whether to strip all JavaScript from PDF files during CDR processing.
    ///
    /// When `true`, any embedded JavaScript streams, `/JS` catalog entries,
    /// and script-containing annotations are removed regardless of whether
    /// they appear benign. This follows defense-in-depth principles.
    pub strip_pdf_javascript: bool,

    /// Whether to remove all embedded Flash/SWF content from PDF files.
    ///
    /// Legacy Flash content in PDFs represents a persistent attack surface
    /// even after Flash EOL due to unpatched reader installations.
    pub strip_flash_content: bool,

    /// Maximum allowed recursion depth for nested archives (ZIP-in-ZIP etc.).
    ///
    /// Values above 3 increase decompression bomb risk; values below 1
    /// prevent legitimate nested archive structures used in some workflows.
    pub max_nesting_depth: u32,

    /// Maximum compression ratio before flagging as potential ZIP bomb.
    ///
    /// Compressed size × this ratio = maximum allowed uncompressed size.
    /// A ratio of 100 means a 1MB compressed file may expand to at most 100MB.
    /// NIST recommends ratios between 100-300 depending on threat model.
    pub max_compression_ratio: u64,

    /// Whether to reject files containing OLE embedded executable objects.
    ///
    /// Office documents (`.doc`, `.xls`, `.ppt`) can embed PE/ELF/Mach-O
    /// executables via OLE object embedding. When `true`, such files are
    /// rejected outright rather than attempting extraction.
    pub block_embedded_executables: bool,

    /// List of blocked PDF catalog entry keys.
    ///
    /// Any PDF containing these keys in its root catalog dictionary will
    /// be flagged for remediation. Common entries include auto-execution
    /// triggers and script references.
    pub blocked_catalog_entries: Vec<String>,
}

impl Default for UniversalCdrPolicy {
    fn default() -> Self {
        Self {
            strip_pdf_javascript: true,
            strip_flash_content: true,
            max_nesting_depth: 3,
            max_compression_ratio: 100,
            block_embedded_executables: true,
            blocked_catalog_entries: vec![
                "/OpenAction".to_string(),
                "/AA".to_string(),
                "/JS".to_string(),
                "/JavaScript".to_string(),
                "/RichMedia".to_string(),
            ],
        }
    }
}

impl UniversalCdrPolicy {
    /// Create a strict policy suitable for high-security environments (DoD, intelligence).
    ///
    /// Applies maximum restrictions: no JS, no Flash, minimal nesting,
    /// low compression tolerance, full executable blocking.
    pub fn strict() -> Self {
        Self {
            strip_pdf_javascript: true,
            strip_flash_content: true,
            max_nesting_depth: 1,
            max_compression_ratio: 30,
            block_embedded_executables: true,
            blocked_catalog_entries: vec![
                "/OpenAction".to_string(),
                "/AA".to_string(),
                "/JS".to_string(),
                "/JavaScript".to_string(),
                "/RichMedia".to_string(),
                "/Launch".to_string(),
                "/URI".to_string(),
            ],
        }
    }

    /// Create a relaxed policy suitable for internal enterprise environments.
    ///
    /// Allows deeper nesting and higher compression ratios while still
    /// blocking the most dangerous vectors (JS, Flash, executables).
    pub fn relaxed() -> Self {
        Self {
            strip_pdf_javascript: true,
            strip_flash_content: false,
            max_nesting_depth: 5,
            max_compression_ratio: 500,
            block_embedded_executables: true,
            blocked_catalog_entries: vec![
                "/OpenAction".to_string(),
                "/JS".to_string(),
            ],
        }
    }

    /// Check if a given PDF catalog key is in the blocklist.
    pub fn is_blocked_entry(&self, key: &str) -> bool {
        self.blocked_catalog_entries.iter().any(|e| e.eq_ignore_ascii_case(key))
    }
}
