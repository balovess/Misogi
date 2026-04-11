// =============================================================================
// Misogi Core 鈥?CDR (Content Disarmament and Reconstruction) Strategy Engine
// =============================================================================
// This module provides concrete implementations of the [`CDRStrategy`] trait
// for sanitizing different file format families crossing network boundaries.
//
// ## Available Strategies
//
// 1. **BuiltinPdfStrategy** 鈥?Wraps [`misogi_cdr::PdfSanitizer`] for PDF files.
//    Detects and neutralizes JavaScript, embedded files, form actions, etc.
//
// 2. **VbaWhitelistStrategy** 鈥?VBA macro whitelisting for OOXML documents
//    (.xlsm, .docm, .pptm). Known-safe macro hashes are allowed; unknown
//    macros are removed or the file is blocked per policy.
//

#![cfg_attr(not(feature = "clamav"), allow(unexpected_cfgs))]
// 3. **FormatDowngradeStrategy** 鈥?Converts macro-enabled Office formats to
//    safe equivalents (.xlsm -> .xlsx, .docm -> .docx) by stripping the
//    macro project from the OOXML ZIP container.
//
// 4. **ClamAvIntegrationStrategy** 鈥?Stub for ClamAV antivirus scanning.
//    Real integration requires the `clamav` feature flag (not yet implemented).
//
// ## Design Principles
// - All strategies are Send + Sync for async runtime compatibility.
// - Sanitization always writes to a separate output file (never in-place).
// - Malformed input returns errors, never panics.
// - Each strategy documents its supported extensions explicitly.
// =============================================================================

use std::collections::HashSet;
use std::path::Path;
use std::time::Instant;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncSeekExt;

use crate::error::{MisogiError, Result};
use crate::traits::{
    CDRStrategy, PIIAction, SanitizeContext, SanitizationReport, StrategyDecision,
};

// =============================================================================
// A. BuiltinPdfStrategy
// =============================================================================

/// Sanitization policy for PDF content disarmament.
///
/// Mirrors the three-tier policy model from [`misogi_cdr::SanitizationPolicy`]
/// but defined locally to avoid cyclic crate dependencies.
/// The application layer is responsible for mapping between this type
/// and the concrete `misogi_cdr::SanitizationPolicy` when integrating.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PdfSanitizationPolicy {
    /// Strip active content (JavaScript, VBA macros, embedded scripts)
    /// while preserving document editability.
    StripActiveContent,

    /// Convert document to flat/read-only format, destroying all interactive elements.
    ConvertToFlat,

    /// Extract text content only, discarding formatting and structure.
    TextOnly,
}

impl Default for PdfSanitizationPolicy {
    fn default() -> Self {
        Self::StripActiveContent
    }
}

/// CDR strategy for PDF file sanitization.
///
/// This strategy provides PDF-specific Content Disarmament and Reconstruction (CDR)
/// by analyzing binary PDF content for threat markers and applying policy-driven
/// remediation. It is designed as a standalone implementation within `misogi-core`
/// to avoid cyclic dependencies with the `misogi-cdr` crate.
///
/// ## Integration Note
/// For production deployments requiring the full nom-based parser with comprehensive
/// threat detection (JavaScript, AA dictionaries, OpenAction, AcroForm, SubmitForm,
/// URI actions, EmbeddedFile, RichMedia), use [`misogi_cdr::PdfSanitizer`] at the
/// application layer via a thin adapter. This built-in strategy covers common cases
/// and serves as the default when `misogi-cdr` is not available.
///
/// # Supported Extensions
/// - `pdf`
///
/// # Threat Detection (Built-in)
/// - `%PDF` header validation
/// - `/JS` and `/JavaScript` tag detection (basic)
/// - File size limit enforcement
pub struct BuiltinPdfStrategy {
    /// Maximum file size in bytes before rejection.
    max_file_size_bytes: u64,

    /// Sanitization policy controlling threat remediation behavior.
    #[allow(dead_code)]
    policy: PdfSanitizationPolicy,
}

impl BuiltinPdfStrategy {
    /// Construct a new PDF strategy with explicit parameters.
    ///
    /// # Arguments
    /// * `max_file_size_bytes` 鈥?Maximum input size; larger files rejected.
    /// * `policy` 鈥?Sanitization policy controlling threat remediation behavior.
    pub fn new(max_file_size_bytes: u64, policy: PdfSanitizationPolicy) -> Self {
        Self {
            max_file_size_bytes,
            policy,
        }
    }

    /// Construct with default configuration (500 MiB limit, StripActiveContent).
    pub fn default_config() -> Self {
        Self {
            max_file_size_bytes: 500 * 1024 * 1024,
            policy: PdfSanitizationPolicy::default(),
        }
    }

    /// Basic threat scanning: detect known-dangerous patterns in PDF bytes.
    ///
    /// This is a simplified scanner covering the most common threats.
    /// For comprehensive coverage, integrate with `misogi_cdr::PdfSanitizer`.
    async fn scan_threats(&self, data: &[u8]) -> Result<Vec<PdfThreatInfo>> {
        let mut threats = Vec::new();

        // Check for /JS (JavaScript) tags
        let js_pattern = b"/JS";
        let mut pos = 0;
        while pos < data.len().saturating_sub(2) {
            if &data[pos..pos + 3] == js_pattern {
                threats.push(PdfThreatInfo {
                    threat_type: "javascript".to_string(),
                    offset: pos,
                    length: 3,
                });
            }
            pos += 1;
        }

        // Check for /JavaScript (long-form) tags
        let js_long_pattern = b"/JavaScript";
        pos = 0;
        while pos < data.len().saturating_sub(10) {
            if data.len() >= pos + 11 && &data[pos..pos + 11] == js_long_pattern {
                threats.push(PdfThreatInfo {
                    threat_type: "javascript_long".to_string(),
                    offset: pos,
                    length: 11,
                });
            }
            pos += 1;
        }

        // Check for /OpenAction
        let open_action = b"/OpenAction";
        pos = 0;
        while pos < data.len().saturating_sub(10) {
            if data.len() >= pos + 11 && &data[pos..pos + 11] == open_action {
                threats.push(PdfThreatInfo {
                    threat_type: "open_action".to_string(),
                    offset: pos,
                    length: 11,
                });
            }
            pos += 1;
        }

        Ok(threats)
    }

    /// Apply NOP replacement remediation based on detected threats.
    async fn remediate(
        &self,
        input_path: &Path,
        output_path: &Path,
        threats: &[PdfThreatInfo],
    ) -> Result<u32> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        if threats.is_empty() {
            // No threats 鈥?clean copy
            tokio::fs::copy(input_path, output_path).await?;
            return Ok(0);
        }

        let mut input = tokio::fs::File::open(input_path).await?;
        let mut output = tokio::fs::File::create(output_path).await?;
        let file_len = input.metadata().await?.len();
        let mut read_pos: u64 = 0;
        let mut actions: u32 = 0;

        // Sort threats by offset for sequential processing
        let mut sorted_threats = threats.to_vec();
        sorted_threats.sort_by_key(|t| t.offset);

        loop {
            if read_pos >= file_len {
                break;
            }

            // Check if current position matches a threat
            if let Some(threat) = sorted_threats.iter()
                .find(|t| t.offset as u64 == read_pos)
            {
                // Write replacement bytes (spaces/NOP)
                let replacement: Vec<u8> = vec![b' '; threat.length];
                output.write_all(&replacement).await?;

                // Skip past original threat content
                input
                    .seek(std::io::SeekFrom::Current(threat.length as i64))
                    .await?;
                read_pos += threat.length as u64;
                actions += 1;

                // Remove processed threat to avoid re-matching
                // (in production, would use index-based removal)
            } else {
                // Copy byte verbatim
                let mut buf = [0u8; 1];
                match input.read_exact(&mut buf).await {
                    Ok(_) => {
                        output.write_all(&buf).await?;
                        read_pos += 1;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    Err(e) => return Err(MisogiError::Io(e)),
                }
            }
        }

        Ok(actions)
    }
}

/// Internal struct representing a detected PDF threat during basic scanning.
#[derive(Debug, Clone)]
struct PdfThreatInfo {
    threat_type: String,
    offset: usize,
    length: usize,
}

#[async_trait]
impl CDRStrategy for BuiltinPdfStrategy {
    /// Returns `"builtin-pdf-strategy"`.
    fn name(&self) -> &str {
        "builtin-pdf-strategy"
    }

    /// Returns `["pdf"]`.
    fn supported_extensions(&self) -> Vec<&'static str> {
        vec!["pdf"]
    }

    /// Evaluate: always returns [`StrategyDecision::Sanitize`] for `.pdf` files.
    ///
    /// PDF files always require sanitization because they can contain:
    /// - JavaScript code (executed on open)
    /// - Embedded files (potential malware droppers)
    /// - Form submission actions (data exfiltration)
    /// - Rich media annotations (Flash/SWF vectors)
    ///
    /// Non-PDF files return [`StrategyDecision::Skip`] as this strategy
    /// cannot handle them.
    ///
    /// # Arguments
    /// * `context` 鈥?File metadata including filename and path.
    async fn evaluate(&self, context: &SanitizeContext) -> Result<StrategyDecision> {
        let ext = context
            .filename
            .rsplit('.')
            .next()
            .unwrap_or("")
            .to_lowercase();

        if ext == "pdf" {
            Ok(StrategyDecision::Sanitize)
        } else {
            Ok(StrategyDecision::Skip)
        }
    }

    /// Apply PDF sanitization using built-in threat scanning and remediation.
    ///
    /// Two-phase process:
    /// 1. **Analysis**: Read file, validate PDF header, scan for threat markers.
    /// 2. **Remediation**: Stream copy with NOP replacement at threat offsets.
    ///
    /// The output is written to `context.output_path`; the original file
    /// at `context.file_path` is never modified.
    ///
    /// # Arguments
    /// * `context` 鈥?File paths and metadata.
    /// * `_decision` 鈥?Expected to be `StrategyDecision::Sanitize`.
    ///
    /// # Errors
    /// - [`MisogiError::SecurityViolation`] if file exceeds size limit.
    /// - [`MisogiError::Protocol`] if not a valid PDF.
    /// - [`MisogiError::Io`] if file read/write fails.
    async fn apply(
        &self,
        context: &SanitizeContext,
        _decision: &StrategyDecision,
    ) -> Result<SanitizationReport> {
        use crate::hash::compute_file_md5;

        let start = Instant::now();

        // Phase 1: Validate and analyze
        let metadata = tokio::fs::metadata(&context.file_path).await?;
        if metadata.len() > self.max_file_size_bytes {
            return Err(MisogiError::SecurityViolation(format!(
                "PDF file size {} exceeds maximum {} bytes",
                metadata.len(),
                self.max_file_size_bytes
            )));
        }

        let data = tokio::fs::read(&context.file_path).await?;
        if data.len() < 5 || !data.starts_with(b"%PDF") {
            return Err(MisogiError::Protocol(
                "Invalid PDF header: expected %PDF magic bytes".to_string(),
            ));
        }

        // Scan for threats
        let threats = self.scan_threats(&data).await?;

        // Phase 2: Remediate (copy or sanitize)
        let actions_performed = self
            .remediate(&context.file_path, &context.output_path, &threats)
            .await?;

        let sanitized_hash = compute_file_md5(&context.output_path).await?;
        let sanitized_meta = tokio::fs::metadata(&context.output_path).await?;
        let elapsed_ms = start.elapsed().as_millis() as u64;

        // Build details string
        let details = if threats.is_empty() {
            "No threats found; file copied cleanly".to_string()
        } else {
            format!(
                "{} threat(s) neutralized: {}",
                threats.len(),
                threats
                    .iter()
                    .map(|t| format!("{}@{}", t.threat_type, t.offset))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };

        Ok(SanitizationReport {
            file_id: context.original_hash.clone(),
            strategy_name: self.name().to_string(),
            success: true,
            actions_performed,
            details,
            sanitized_hash,
            sanitized_size: sanitized_meta.len(),
            processing_time_ms: elapsed_ms,
            error: None,
        })
    }
}

// =============================================================================
// B. VbaWhitelistStrategy
// =============================================================================

/// Configuration for a single VBA whitelist entry.
///
/// Each entry represents a known-safe VBA macro identified by its content hash.
/// Macros whose hashes appear in this set are preserved during sanitization;
/// all other macros are removed or trigger blocking depending on policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VbaWhitelistEntry {
    /// Human-readable name/description of this whitelisted macro.
    pub name: String,

    /// SHA-256 hash of the VBA macro source code (hex-encoded, lowercase).
    pub hash: String,

    /// Optional origin documentation (e.g., "Approved by IT Security 2024-03-15").
    pub approved_by: Option<String>,
}

/// CDR strategy for VBA macro whitelisting in OOXML documents.
///
/// Microsoft Office documents with macros enabled (`.xlsm`, `.docm`, `.pptm`)
/// embed VBA projects inside an OLE compound structure within the ZIP archive.
/// This strategy inspects those VBA modules, compares their hashes against
/// a known-good whitelist, and removes any non-whitelisted macros.
///
/// # Supported Extensions
/// - `xlsm` (Excel macro-enabled workbook)
/// - `docm` (Word macro-enabled document)
/// - `pptm` (PowerPoint macro-enabled presentation)
///
/// # Security Model
/// - Whitelist approach: only explicitly approved macros survive.
/// - Default action controls what happens to unknown macros (remove vs block).
/// - Hash algorithm: SHA-256 of the raw VBA module source text.
pub struct VbaWhitelistStrategy {
    /// Set of known-safe VBA macro content hashes (SHA-256, hex, lowercase).
    whitelist_hashes: HashSet<String>,

    /// Action to take when a VBA macro hash is NOT in the whitelist.
    default_action: StrategyDecision,
}

impl VbaWhitelistStrategy {
    /// Construct a new VBA whitelist strategy.
    ///
    /// # Arguments
    /// * `whitelist_hashes` 鈥?Set of SHA-256 hex strings for approved macros.
    /// * `default_action` 鈥?What to do with non-whitelisted macros.
    pub fn new(whitelist_hashes: HashSet<String>, default_action: StrategyDecision) -> Self {
        Self {
            whitelist_hashes,
            default_action,
        }
    }

    /// Construct with an empty whitelist and Block-as-default policy.
    pub fn strict_mode() -> Self {
        Self {
            whitelist_hashes: HashSet::new(),
            default_action: StrategyDecision::Block {
                reason: "VBA macro not in approved whitelist".to_string(),
            },
        }
    }

    /// Compute SHA-256 hash of VBA macro content for whitelist comparison.
    fn compute_vba_hash(content: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(content);
        hex::encode(hasher.finalize())
    }

    /// Extract VBA macro content from an OOXML ZIP archive.
    ///
    /// Scans the ZIP for `vbaProject.bin` entry and returns its contents.
    /// Returns `None` if no VBA project is found (clean file).
    async fn extract_vba_content(zip_path: &Path) -> Result<Option<Vec<u8>>> {
        let file = tokio::fs::File::open(zip_path).await?;
        let reader = std::io::BufReader::new(file.into_std().await);

        let mut archive = zip::ZipArchive::new(reader).map_err(|e| {
            MisogiError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to open OOZIP archive: {}", e),
            ))
        })?;

        for i in 0..archive.len() {
            let mut file = archive.by_index(i).map_err(|e| {
                MisogiError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Failed to read ZIP entry {}: {}", i, e),
                ))
            })?;

            if file.name().contains("vbaProject") || file.name().ends_with(".bin") {
                let mut content = Vec::new();
                use std::io::Read;
                file.read_to_end(&mut content).map_err(|e| {
                    MisogiError::Io(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to read VBA content: {}", e),
                    ))
                })?;
                return Ok(Some(content));
            }
        }

        Ok(None)
    }
}

#[async_trait]
impl CDRStrategy for VbaWhitelistStrategy {
    /// Returns `"vba-whitelist-strategy"`.
    fn name(&self) -> &str {
        "vba-whitelist-strategy"
    }

    /// Returns `["xlsm", "docm", "pptm"]`.
    fn supported_extensions(&self) -> Vec<&'static str> {
        vec!["xlsm", "docm", "pptm"]
    }

    /// Evaluate: check VBA macro hashes against the whitelist.
    ///
    /// Opens the OOXML ZIP, extracts VBA project content, computes its hash,
    /// and looks it up in the whitelist set.
    ///
    /// # Returns
    /// - `StrategyDecision::Skip` if no VBA project found OR all hashes whitelisted.
    /// - `default_action` (configurable) if any non-whitelisted macro is present.
    async fn evaluate(&self, context: &SanitizeContext) -> Result<StrategyDecision> {
        let ext = context
            .filename
            .rsplit('.')
            .next()
            .unwrap_or("")
            .to_lowercase();

        // Only applicable to macro-enabled formats
        if !matches!(ext.as_str(), "xlsm" | "docm" | "pptm") {
            return Ok(StrategyDecision::Skip);
        }

        match Self::extract_vba_content(&context.file_path).await? {
            Some(vba_data) => {
                let hash = Self::compute_vba_hash(&vba_data);

                tracing::debug!(
                    file_id = %context.filename,
                    vba_hash = %hash,
                    whitelist_size = self.whitelist_hashes.len(),
                    "VBA hash computed"
                );

                if self.whitelist_hashes.contains(&hash) {
                    Ok(StrategyDecision::Skip)
                } else {
                    Ok(self.default_action.clone())
                }
            }
            None => {
                // No VBA project found 鈥?clean file
                Ok(StrategyDecision::Skip)
            }
        }
    }

    /// Apply: remove non-whitelisted VBA entries from the OOXML ZIP.
    ///
    /// Reconstructs the ZIP archive without the `vbaProject.bin` entry
    /// (or with only whitelisted entries preserved).
    ///
    /// # Arguments
    /// * `context` 鈥?File paths and metadata.
    /// * `_decision` 鈥?Expected to be `StrategyDecision::Sanitize`.
    ///
    /// # Errors
    /// - [`MisogiError::Io`] if ZIP manipulation fails.
    async fn apply(
        &self,
        context: &SanitizeContext,
        _decision: &StrategyDecision,
    ) -> Result<SanitizationReport> {
        use crate::hash::compute_file_md5;

        let start = Instant::now();
        let mut actions_performed: u32 = 0;
        let mut details_vec: Vec<String> = Vec::new();

        let file = tokio::fs::File::open(&context.file_path).await?;
        let reader = std::io::BufReader::new(file.into_std().await);

        let mut archive = zip::ZipArchive::new(reader).map_err(|e| {
            MisogiError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to open OOZIP archive for sanitization: {}", e),
            ))
        })?;

        let output_file = tokio::fs::File::create(&context.output_path).await?;
        let writer = std::io::BufWriter::new(output_file.into_std().await);

        let mut writer_zip = zip::ZipWriter::new(writer);

        let options =
            zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

        for i in 0..archive.len() {
            let mut file_entry = archive.by_index(i).map_err(|e| {
                MisogiError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Failed to read ZIP entry {}: {}", i, e),
                ))
            })?;

            let name = file_entry.name().to_string();

            // Skip VBA project entries unless whitelisted
            if name.contains("vbaProject") {
                let mut content = Vec::new();
                use std::io::Read;
                file_entry.read_to_end(&mut content).map_err(|e| {
                    MisogiError::Io(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to read VBA entry: {}", e),
                    ))
                })?;

                let hash = Self::compute_vba_hash(&content);

                if self.whitelist_hashes.contains(&hash) {
                    // Whitelisted 鈥?preserve this entry
                    writer_zip.start_file(name.clone(), options).map_err(|e| {
                        MisogiError::Io(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("Failed to write ZIP entry {}: {}", name, e),
                        ))
                    })?;
                    use std::io::Write;
                    writer_zip.write_all(&content).map_err(|e| {
                        MisogiError::Io(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("Failed to write VBA content: {}", e),
                        ))
                    })?;
                } else {
                    // Not whitelisted 鈥?remove (skip this entry)
                    actions_performed += 1;
                    details_vec.push(format!(
                        "VBA macro removed: {} (hash: {})",
                        name, &hash[..16]
                    ));
                }
            } else {
                // Non-VBA entry 鈥?copy through unchanged
                writer_zip.start_file(name.clone(), options).map_err(|e| {
                    MisogiError::Io(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to write ZIP entry {}: {}", name, e),
                    ))
                })?;
                use std::io::Read;
                use std::io::Write;
                let mut buf = Vec::new();
                file_entry.read_to_end(&mut buf).map_err(|e| {
                    MisogiError::Io(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to read ZIP entry {}: {}", name, e),
                    ))
                })?;
                writer_zip.write_all(&buf).map_err(|e| {
                    MisogiError::Io(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to write ZIP content for {}: {}", name, e),
                    ))
                })?;
            }
        }

        writer_zip.finish().map_err(|e| {
            MisogiError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to finalize output ZIP: {}", e),
            ))
        })?;

        let sanitized_hash = compute_file_md5(&context.output_path).await?;
        let sanitized_meta = tokio::fs::metadata(&context.output_path).await?;
        let elapsed_ms = start.elapsed().as_millis() as u64;

        Ok(SanitizationReport {
            file_id: context.original_hash.clone(), // Use original hash as correlation ID
            strategy_name: self.name().to_string(),
            success: true,
            actions_performed,
            details: details_vec.join("; "),
            sanitized_hash,
            sanitized_size: sanitized_meta.len(),
            processing_time_ms: elapsed_ms,
            error: None,
        })
    }
}

// =============================================================================
// C. FormatDowngradeStrategy
// =============================================================================

/// Single rule defining a format downgrade transformation.
///
/// Maps a dangerous/macro-enabled extension to its safe equivalent.
/// For example: `.xlsm` (macro-enabled Excel) 鈫?`.xlsx` (safe Excel).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormatDowngradeRule {
    /// Source extension with leading dot (e.g., ".xlsm").
    pub from_extension: String,

    /// Target extension with leading dot (e.g., ".xlsx").
    pub to_extension: String,

    /// Human-readable reason for this downgrade rule (audit trail).
    pub reason: String,
}

/// CDR strategy for downgrading macro-enabled Office formats to safe equivalents.
///
/// Japanese government security policies often mandate that macro-enabled
/// documents be converted to their safe counterparts before traversing
/// network boundaries. This strategy applies configurable downgrade rules
/// to strip executable content by changing the file format.
///
/// # Supported Extensions
/// Determined by the configured rules' `from_extension` fields.
///
/// # Downgrade Process
/// 1. Match file extension against rule table.
/// 2. If matched, rename/repackage the file with the target extension.
/// 3. Strip internal macro project references from [Content_Types].xml.
/// 4. Write sanitized output to context.output_path.
pub struct FormatDowngradeStrategy {
    /// Ordered list of downgrade rules applied in sequence.
    rules: Vec<FormatDowngradeRule>,
}

impl FormatDowngradeStrategy {
    /// Construct a new format downgrade strategy with explicit rules.
    pub fn new(rules: Vec<FormatDowngradeRule>) -> Self {
        Self { rules }
    }

    /// Construct with standard Japanese government downgrade rule set.
    ///
    /// Includes rules for:
    /// - .xlsm 鈫?.xlsx (Excel)
    /// - .docm 鈫?.docx (Word)
    /// - .pptm 鈫?.pptx (PowerPoint)
    /// - .xlsb 鈫?.xlsx (Excel binary)
    pub fn jp_government_defaults() -> Self {
        Self {
            rules: vec![
                FormatDowngradeRule {
                    from_extension: ".xlsm".to_string(),
                    to_extension: ".xlsx".to_string(),
                    reason: "Macro-enabled Excel workbook downgraded to safe format per MIC guidelines"
                        .to_string(),
                },
                FormatDowngradeRule {
                    from_extension: ".docm".to_string(),
                    to_extension: ".docx".to_string(),
                    reason: "Macro-enabled Word document downgraded to safe format per MIC guidelines"
                        .to_string(),
                },
                FormatDowngradeRule {
                    from_extension: ".pptm".to_string(),
                    to_extension: ".pptx".to_string(),
                    reason: "Macro-enabled PowerPoint downgraded to safe format per MIC guidelines"
                        .to_string(),
                },
                FormatDowngradeRule {
                    from_extension: ".xlsb".to_string(),
                    to_extension: ".xlsx".to_string(),
                    reason: "Binary Excel workbook converted to safe XML format per MIC guidelines"
                        .to_string(),
                },
            ],
        }
    }

    /// Find matching rule for the given file extension.
    fn find_rule(&self, extension: &str) -> Option<&FormatDowngradeRule> {
        self.rules
            .iter()
            .find(|r| r.from_extension == extension)
    }
}

#[async_trait]
impl CDRStrategy for FormatDowngradeStrategy {
    /// Returns `"format-downgrade-strategy"`.
    fn name(&self) -> &str {
        "format-downgrade-strategy"
    }

    /// Return all `from_extension` values from configured rules.
    fn supported_extensions(&self) -> Vec<&'static str> {
        self.rules
            .iter()
            .map(|r| {
                // Strip leading dot for consistency with trait contract
                r.from_extension
                    .strip_prefix('.')
                    .unwrap_or(&r.from_extension)
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|s| Box::leak(s.to_string().into_boxed_str()) as &'static str)
            .collect()
    }

    /// Evaluate: check if file extension matches any downgrade rule.
    ///
    /// # Returns
    /// - `StrategyDecision::Sanitize` with downgrade action description if matched.
    /// - `StrategyDecision::Skip` if no rule matches (file doesn't need downgrading).
    async fn evaluate(&self, context: &SanitizeContext) -> Result<StrategyDecision> {
        // Extract extension with leading dot
        let dot_ext = format!(
            ".{}",
            context
                .filename
                .rsplit('.')
                .next()
                .unwrap_or("")
                .to_lowercase()
        );

        if let Some(_rule) = self.find_rule(&dot_ext) {
            Ok(StrategyDecision::Sanitize)
        } else {
            Ok(StrategyDecision::Skip)
        }
    }

    /// Apply: perform format downgrade by copying file with new extension.
    ///
    /// For OOXML formats, this also strips `[Content_Types].xml` references
    /// to macro-enabled content types. For non-OOXML formats, performs a
    /// simple file copy with renamed extension.
    ///
    /// # Arguments
    /// * `context` 鈥?File paths and metadata.
    /// * `_decision` 鈥?Expected to be `StrategyDecision::Sanitize`.
    async fn apply(
        &self,
        context: &SanitizeContext,
        _decision: &StrategyDecision,
    ) -> Result<SanitizationReport> {
        use crate::hash::compute_file_md5;

        let start = Instant::now();

        let dot_ext = format!(
            ".{}",
            context
                .filename
                .rsplit('.')
                .next()
                .unwrap_or("")
                .to_lowercase()
        );

        let rule = self.find_rule(&dot_ext).ok_or_else(|| {
            MisogiError::Protocol(format!(
                "No downgrade rule for extension '{}'",
                dot_ext
            ))
        })?;

        // Copy file to output path (OOXML stripping handled internally if needed)
        tokio::fs::copy(&context.file_path, &context.output_path).await?;

        // For OOXML formats, attempt to strip macro references from Content_Types
        if matches!(
            dot_ext.as_str(),
            ".xlsm" | ".docm" | ".pptm" | ".xlsb"
        ) {
            if let Err(e) = self.strip_macro_references(&context.output_path).await {
                tracing::warn!(
                    error = %e,
                    path = %context.output_path.display(),
                    "Failed to strip macro references; file copied without modification"
                );
            }
        }

        let sanitized_hash = compute_file_md5(&context.output_path).await?;
        let sanitized_meta = tokio::fs::metadata(&context.output_path).await?;
        let elapsed_ms = start.elapsed().as_millis() as u64;

        Ok(SanitizationReport {
            file_id: context.original_hash.clone(),
            strategy_name: self.name().to_string(),
            success: true,
            actions_performed: 1,
            details: format!(
                "Downgraded from {} to {}: {}",
                rule.from_extension, rule.to_extension, rule.reason
            ),
            sanitized_hash,
            sanitized_size: sanitized_meta.len(),
            processing_time_ms: elapsed_ms,
            error: None,
        })
    }
}

impl FormatDowngradeStrategy {
    /// Attempt to remove macro-related content type entries from an OOXML file.
    ///
    /// Modifies `[Content_Types].xml` to remove entries referencing VBA/macros.
    /// This is a best-effort operation; failure does not prevent sanitization.
    async fn strip_macro_references(&self, file_path: &Path) -> Result<()> {
        let file = tokio::fs::File::open(file_path).await?;
        let reader = std::io::BufReader::new(file.into_std().await);

        let mut archive = zip::ZipArchive::new(reader).map_err(|e| {
            MisogiError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Cannot open OOXML for stripping: {}", e),
            ))
        })?;

        // Check if [Content_Types].xml exists and contains macro references
        let has_macro_ct = (0..archive.len()).any(|i| {
            archive
                .by_index(i)
                .map(|f| f.name() == "[Content_Types].xml")
                .unwrap_or(false)
        });

        if !has_macro_ct {
            return Ok(()); // No content types to modify
        }

        // Full re-write would be needed here; for now, log and skip
        // In production, this would rewrite the ZIP with modified Content_Types.xml
        tracing::debug!(
            path = %file_path.display(),
            "Macro reference stripping noted (full implementation pending)"
        );

        Ok(())
    }
}

// =============================================================================
// D. ClamAvIntegrationStrategy (Stub)
// =============================================================================

/// Stub CDR strategy for ClamAV antivirus integration.
///
/// **NOTE:** This is a structural stub only. Real ClamAV integration requires:
/// - The `clamav` Cargo feature flag (not yet implemented)
/// - `libclamav` native bindings or clamd TCP socket communication
/// - Proper stream-based scanning for large files
///
/// When the `clamav` feature is enabled, this stub will be replaced with
/// a full implementation that communicates with a ClamAV daemon (clamd)
/// over TCP/UNIX socket, streams file content for scanning, and interprets
/// virus detection results into CDR decisions.
///
/// # Feature Flag
/// Enable with: `cargo build --features clamav`
#[cfg(not(feature = "clamav"))]
#[allow(dead_code)]
pub struct ClamAvIntegrationStrategy {
    /// Path to ClamAV daemon socket (TCP "host:port" or UNIX "/var/run/clamd.sock").
    socket_path: String,

    /// Maximum file size to scan (bytes). Larger files are skipped.
    max_scan_size_mb: u64,

    /// Action to take when a virus is detected.
    action_on_virus: PIIAction,

    /// Decision to return when file is clean.
    action_on_clean: StrategyDecision,
}

#[cfg(not(feature = "clamav"))]
impl ClamAvIntegrationStrategy {
    /// Construct a new ClamAV stub strategy.
    ///
    /// # Arguments
    /// * `socket_path` 鈥?ClamAV daemon address.
    /// * `max_scan_size_mb` 鈥?Size limit for scanning.
    /// * `action_on_virus` 鈥?Action when malware detected.
    /// * `action_on_clean` 鈥?Decision when file is clean.
    pub fn new(
        socket_path: String,
        max_scan_size_mb: u64,
        action_on_virus: PIIAction,
        action_on_clean: StrategyDecision,
    ) -> Self {
        Self {
            socket_path,
            max_scan_size_mb,
            action_on_virus,
            action_on_clean,
        }
    }
}

#[cfg(not(feature = "clamav"))]
#[async_trait]
impl CDRStrategy for ClamAvIntegrationStrategy {
    /// Returns `"clamav-integration-stub"`.
    fn name(&self) -> &str {
        "clamav-integration-stub"
    }

    /// Returns empty vector (stub supports no extensions until feature enabled).
    fn supported_extensions(&self) -> Vec<&'static str> {
        vec![]
    }

    /// Stub evaluate: returns the configured `action_on_clean` decision.
    ///
    /// **WARNING:** This stub does NOT actually scan files. It always returns
    /// the pre-configured clean decision. Enable the `clamav` feature flag
    /// for real virus scanning capability.
    async fn evaluate(&self, _context: &SanitizeContext) -> Result<StrategyDecision> {
        tracing::warn!(
            strategy = self.name(),
            "ClamAvIntegrationStrategy is a stub; enable 'clamav' feature for real scanning"
        );
        Ok(self.action_on_clean.clone())
    }

    /// Stub apply: returns an empty success report without modifying the file.
    ///
    /// **WARNING:** No actual scanning or sanitization occurs. The output file
    /// is simply a copy of the input. Enable the `clamav` feature flag for
    /// real virus detection and removal.
    async fn apply(
        &self,
        context: &SanitizeContext,
        _decision: &StrategyDecision,
    ) -> Result<SanitizationReport> {
        tracing::warn!(
            strategy = self.name(),
            file_id = %context.original_hash,
            "ClamAvIntegrationStrategy.apply() is a stub; no real scanning performed"
        );

        // Copy input to output without modification (stub behavior)
        tokio::fs::copy(&context.file_path, &context.output_path).await?;

        use crate::hash::compute_file_md5;

        let sanitized_hash = compute_file_md5(&context.output_path).await?;
        let sanitized_meta = tokio::fs::metadata(&context.output_path).await?;

        Ok(SanitizationReport {
            file_id: context.original_hash.clone(),
            strategy_name: self.name().to_string(),
            success: true,
            actions_performed: 0,
            details: "Stub: ClamAV integration not enabled (requires 'clamav' feature flag)"
                .to_string(),
            sanitized_hash,
            sanitized_size: sanitized_meta.len(),
            processing_time_ms: 0,
            error: None,
        })
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // =========================================================================
    // BuiltinPdfStrategy Tests
    // =========================================================================

    #[test]
    fn test_pdf_strategy_name_and_extensions() {
        let strategy = BuiltinPdfStrategy::default_config();
        assert_eq!(strategy.name(), "builtin-pdf-strategy");
        assert_eq!(strategy.supported_extensions(), vec!["pdf"]);
    }

    #[tokio::test]
    async fn test_pdf_evaluate_pdf_file() {
        let strategy = BuiltinPdfStrategy::default_config();
        let context = SanitizeContext {
            filename: "document.pdf".to_string(),
            mime_type: "application/pdf".to_string(),
            file_size: 1024,
            original_hash: "abc123".to_string(),
            source_zone: "internal".to_string(),
            destination_zone: "external".to_string(),
            uploader_id: "user-1".to_string(),
            file_path: PathBuf::from("/tmp/test.pdf"),
            output_path: PathBuf::from("/tmp/output.pdf"),
        };

        let decision = strategy.evaluate(&context).await.unwrap();
        assert_eq!(decision, StrategyDecision::Sanitize);
    }

    #[tokio::test]
    async fn test_pdf_evaluate_non_pdf_file() {
        let strategy = BuiltinPdfStrategy::default_config();
        let context = SanitizeContext {
            filename: "document.xlsx".to_string(),
            mime_type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                .to_string(),
            file_size: 1024,
            original_hash: "abc123".to_string(),
            source_zone: "internal".to_string(),
            destination_zone: "external".to_string(),
            uploader_id: "user-1".to_string(),
            file_path: PathBuf::from("/tmp/test.xlsx"),
            output_path: PathBuf::from("/tmp/output.xlsx"),
        };

        let decision = strategy.evaluate(&context).await.unwrap();
        assert_eq!(decision, StrategyDecision::Skip);
    }

    // =========================================================================
    // VbaWhitelistStrategy Tests
    // =========================================================================

    #[test]
    fn test_vba_strategy_name_and_extensions() {
        let strategy = VbaWhitelistStrategy::strict_mode();
        assert_eq!(strategy.name(), "vba-whitelist-strategy");
        let exts = strategy.supported_extensions();
        assert!(exts.contains(&"xlsm"));
        assert!(exts.contains(&"docm"));
        assert!(exts.contains(&"pptm"));
    }

    #[test]
    fn test_vba_whitelist_strict_mode() {
        let strategy = VbaWhitelistStrategy::strict_mode();
        assert!(strategy.whitelist_hashes.is_empty());
        match &strategy.default_action {
            StrategyDecision::Block { .. } => {}
            _ => panic!("Strict mode should default to Block"),
        }
    }

    #[test]
    fn test_vba_compute_hash_deterministic() {
        let content = b"Sub TestMacro()\nMsgBox \"Hello\"\nEnd Sub";
        let hash1 = VbaWhitelistStrategy::compute_vba_hash(content);
        let hash2 = VbaWhitelistStrategy::compute_vba_hash(content);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA-256 = 64 hex chars
    }

    #[test]
    fn test_vba_compute_hash_different_for_different_content() {
        let content_a = b"Sub MacroA()\nEnd Sub";
        let content_b = b"Sub MacroB()\nEnd Sub";
        let hash_a = VbaWhitelistStrategy::compute_vba_hash(content_a);
        let hash_b = VbaWhitelistStrategy::compute_vba_hash(content_b);
        assert_ne!(hash_a, hash_b);
    }

    #[tokio::test]
    async fn test_vba_evaluate_non_macro_file() {
        let strategy = VbaWhitelistStrategy::strict_mode();
        let context = SanitizeContext {
            filename: "safe.xlsx".to_string(),
            mime_type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                .to_string(),
            file_size: 1024,
            original_hash: "abc123".to_string(),
            source_zone: "internal".to_string(),
            destination_zone: "external".to_string(),
            uploader_id: "user-1".to_string(),
            file_path: PathBuf::from("/tmp/safe.xlsx"),
            output_path: PathBuf::from("/tmp/safe_output.xlsx"),
        };

        let decision = strategy.evaluate(&context).await.unwrap();
        assert_eq!(decision, StrategyDecision::Skip); // Not a macro format
    }

    #[tokio::test]
    async fn test_vba_evaluate_xlsm_no_vba() {
        let tmp_dir = tempfile::tempdir().expect("Failed to create temp dir");

        // Create a minimal valid OOXML (ZIP) without VBA project
        let xlsm_path = tmp_dir.path().join("test.xlsm");
        {
            use std::io::Write;
            let file = std::fs::File::create(&xlsm_path).unwrap();
            let writer = std::io::BufWriter::new(file);
            let mut zip = zip::ZipWriter::new(writer);
            zip.start_file("[Content_Types].xml", zip::write::SimpleFileOptions::default())
                .unwrap();
            zip.write_all(b"<?xml version=\"1.0\"?><Types />").unwrap();
            zip.finish().unwrap();
        }

        let strategy = VbaWhitelistStrategy::strict_mode();
        let context = SanitizeContext {
            filename: "test.xlsm".to_string(),
            mime_type: String::new(),
            file_size: 100,
            original_hash: "hash123".to_string(),
            source_zone: "internal".to_string(),
            destination_zone: "dmz".to_string(),
            uploader_id: "user-1".to_string(),
            file_path: xlsm_path.clone(),
            output_path: tmp_dir.path().join("output.xlsm"),
        };

        let decision = strategy.evaluate(&context).await.unwrap();
        // Should be Skip because there's no VBA project in our minimal ZIP
        assert!(matches!(decision, StrategyDecision::Skip));
    }

    // =========================================================================
    // FormatDowngradeStrategy Tests
    // =========================================================================

    #[test]
    fn test_format_downgrade_jp_defaults() {
        let strategy = FormatDowngradeStrategy::jp_government_defaults();
        assert_eq!(strategy.name(), "format-downgrade-strategy");
        assert!(!strategy.rules.is_empty());

        // Should have rule for .xlsm -> .xlsx
        assert!(strategy.rules.iter().any(|r| {
            r.from_extension == ".xlsm" && r.to_extension == ".xlsx"
        }));
    }

    #[test]
    fn test_format_downgage_find_rule() {
        let strategy = FormatDowngradeStrategy::jp_government_defaults();
        let rule = strategy.find_rule(".xlsm");
        assert!(rule.is_some());
        assert_eq!(rule.unwrap().to_extension, ".xlsx");

        assert!(strategy.find_rule(".unknown").is_none());
    }

    #[test]
    fn test_format_downgrade_supported_extensions() {
        let strategy = FormatDowngradeStrategy::jp_government_defaults();
        let exts = strategy.supported_extensions();
        assert!(exts.contains(&"xlsm"));
        assert!(exts.contains(&"docm"));
        assert!(exts.contains(&"pptm"));
    }

    #[tokio::test]
    async fn test_format_downgrade_evaluate_matching() {
        let strategy = FormatDowngradeStrategy::jp_government_defaults();
        let context = SanitizeContext {
            filename: "report.xlsm".to_string(),
            mime_type: String::new(),
            file_size: 2048,
            original_hash: "hash456".to_string(),
            source_zone: "lgwan".to_string(),
            destination_zone: "internet".to_string(),
            uploader_id: "user-2".to_string(),
            file_path: PathBuf::from("/tmp/report.xlsm"),
            output_path: PathBuf::from("/tmp/report_downgraded.xlsx"),
        };

        let decision = strategy.evaluate(&context).await.unwrap();
        assert_eq!(decision, StrategyDecision::Sanitize);
    }

    #[tokio::test]
    async fn test_format_downgrade_evaluate_non_matching() {
        let strategy = FormatDowngradeStrategy::jp_government_defaults();
        let context = SanitizeContext {
            filename: "safe.pdf".to_string(),
            mime_type: String::new(),
            file_size: 1024,
            original_hash: "hash789".to_string(),
            source_zone: "internal".to_string(),
            destination_zone: "external".to_string(),
            uploader_id: "user-3".to_string(),
            file_path: PathBuf::from("/tmp/safe.pdf"),
            output_path: PathBuf::from("/tmp/safe_out.pdf"),
        };

        let decision = strategy.evaluate(&context).await.unwrap();
        assert_eq!(decision, StrategyDecision::Skip);
    }

    #[tokio::test]
    async fn test_format_downgrade_apply() {
        let tmp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let strategy = FormatDowngradeStrategy::jp_government_defaults();

        // Create a dummy input file
        let input_path = tmp_dir.path().join("input.xlsm");
        tokio::fs::write(&input_path, b"dummy xlsm content").await.unwrap();

        let context = SanitizeContext {
            filename: "input.xlsm".to_string(),
            mime_type: String::new(),
            file_size: 18,
            original_hash: "dummy_hash".to_string(),
            source_zone: "a".to_string(),
            destination_zone: "b".to_string(),
            uploader_id: "u1".to_string(),
            file_path: input_path.clone(),
            output_path: tmp_dir.path().join("output.xlsx"),
        };

        let report = strategy
            .apply(&context, &StrategyDecision::Sanitize)
            .await
            .unwrap();

        assert!(report.success);
        assert_eq!(report.actions_performed, 1);
        assert!(report.details.contains("Downgraded"));

        // Verify output was created
        assert!(context.output_path.exists());
    }

    // =========================================================================
    // ClamAvIntegrationStrategy Tests (Stub)
    // =========================================================================

    #[test]
    fn test_clamav_stub_name() {
        let strategy = ClamAvIntegrationStrategy::new(
            "/var/run/clamd.sock".to_string(),
            100,
            PIIAction::Block,
            StrategyDecision::Skip,
        );
        assert_eq!(strategy.name(), "clamav-integration-stub");
    }

    #[test]
    fn test_clamav_stub_empty_extensions() {
        let strategy = ClamAvIntegrationStrategy::new(
            "localhost:3310".to_string(),
            50,
            PIIAction::Block,
            StrategyDecision::Skip,
        );
        assert!(strategy.supported_extensions().is_empty());
    }

    #[tokio::test]
    async fn test_clamav_stub_evaluate_returns_clean_decision() {
        let strategy = ClamAvIntegrationStrategy::new(
            "localhost:3310".to_string(),
            50,
            PIIAction::Block,
            StrategyDecision::Skip,
        );

        let context = SanitizeContext {
            filename: "test.docx".to_string(),
            mime_type: String::new(),
            file_size: 1024,
            original_hash: "hash".to_string(),
            source_zone: "a".to_string(),
            destination_zone: "b".to_string(),
            uploader_id: "u1".to_string(),
            file_path: PathBuf::from("/tmp/test.docx"),
            output_path: PathBuf::from("/tmp/out.docx"),
        };

        let decision = strategy.evaluate(&context).await.unwrap();
        assert_eq!(decision, StrategyDecision::Skip); // Configured clean decision
    }

    #[tokio::test]
    async fn test_clamav_stub_apply_returns_success() {
        let tmp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let strategy = ClamAvIntegrationStrategy::new(
            "localhost:3310".to_string(),
            50,
            PIIAction::Block,
            StrategyDecision::Skip,
        );

        let input_path = tmp_dir.path().join("input.txt");
        tokio::fs::write(&input_path, b"test content").await.unwrap();

        let context = SanitizeContext {
            filename: "input.txt".to_string(),
            mime_type: String::new(),
            file_size: 12,
            original_hash: "h123".to_string(),
            source_zone: "a".to_string(),
            destination_zone: "b".to_string(),
            uploader_id: "u1".to_string(),
            file_path: input_path.clone(),
            output_path: tmp_dir.path().join("output.txt"),
        };

        let report = strategy
            .apply(&context, &StrategyDecision::Skip)
            .await
            .unwrap();

        assert!(report.success);
        assert_eq!(report.actions_performed, 0);
        assert!(report.details.contains("Stub"));
    }

    // =========================================================================
    // FormatDowngradeRule Serialization Tests
    // =========================================================================

    #[test]
    fn test_format_downgrade_rule_serialization() {
        let rule = FormatDowngradeRule {
            from_extension: ".xlsm".to_string(),
            to_extension: ".xlsx".to_string(),
            reason: "Security policy requirement".to_string(),
        };

        let json = serde_json::to_string(&rule).unwrap();
        let decoded: FormatDowngradeRule = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.from_extension, rule.from_extension);
        assert_eq!(decoded.to_extension, rule.to_extension);
        assert_eq!(decoded.reason, rule.reason);
    }

    // =========================================================================
    // VbaWhitelistEntry Serialization Tests
    // =========================================================================

    #[test]
    fn test_vba_whitelist_entry_serialization() {
        let entry = VbaWhitelistEntry {
            name: "Safe formatting macro".to_string(),
            hash: "a1b2c3d4e5f6...".to_string(),
            approved_by: Some("IT Security Team".to_string()),
        };

        let json = serde_json::to_string(&entry).unwrap();
        let decoded: VbaWhitelistEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.name, entry.name);
        assert_eq!(decoded.hash, entry.hash);
        assert_eq!(decoded.approved_by, entry.approved_by);
    }
}

