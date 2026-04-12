// =============================================================================
// Misogi Core 鈥?CDR Strategy: VBA Macro Whitelisting
// =============================================================================
// Implements [`VbaWhitelistStrategy`] for VBA macro whitelisting in OOXML
// documents (.xlsm, .docm, .pptm). Known-safe macro hashes are allowed;
// unknown macros are removed or the file is blocked per policy.
//
// # Supported Extensions
// - `xlsm` (Excel macro-enabled workbook)
// - `docm` (Word macro-enabled document)
// - `pptm` (PowerPoint macro-enabled presentation)
//
// # Security Model
// - Whitelist approach: only explicitly approved macros survive.
// - Default action controls what happens to unknown macros (remove vs block).
// - Hash algorithm: SHA-256 of the raw VBA module source text.

use std::collections::HashSet;
use std::path::Path;
use std::time::Instant;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::{MisogiError, Result};
use crate::hash::compute_file_md5;
use crate::traits::{
    CDRStrategy, SanitizeContext, SanitizationReport, StrategyDecision,
};

// =============================================================================
// Types
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

// =============================================================================
// VbaWhitelistStrategy
// =============================================================================

/// CDR strategy for VBA macro whitelisting in OOXML documents.
///
/// Microsoft Office documents with macros enabled (`.xlsm`, `.docm`, `.pptm`)
/// embed VBA projects inside an OLE compound structure within the ZIP archive.
/// This strategy inspects those VBA modules, compares their hashes against
/// a known-good whitelist, and removes any non-whitelisted macros.
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
    /// * `whitelist_hashes` — Set of SHA-256 hex strings for approved macros.
    /// * `default_action` — What to do with non-whitelisted macros.
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
    async fn evaluate(&self, context: &SanitizeContext) -> Result<StrategyDecision> {
        let ext = context
            .filename
            .rsplit('.')
            .next()
            .unwrap_or("")
            .to_lowercase();

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
            None => Ok(StrategyDecision::Skip),
        }
    }

    /// Apply: remove non-whitelisted VBA entries from the OOXML ZIP.
    ///
    /// Reconstructs the ZIP archive without the `vbaProject.bin` entry
    /// (or with only whitelisted entries preserved).
    async fn apply(
        &self,
        context: &SanitizeContext,
        _decision: &StrategyDecision,
    ) -> Result<SanitizationReport> {
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
                    actions_performed += 1;
                    details_vec.push(format!(
                        "VBA macro removed: {} (hash: {})",
                        name, &hash[..16]
                    ));
                }
            } else {
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
            file_id: context.original_hash.clone(),
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
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

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
        assert_eq!(decision, StrategyDecision::Skip);
    }

    #[tokio::test]
    async fn test_vba_evaluate_xlsm_no_vba() {
        let tmp_dir = tempfile::tempdir().expect("Failed to create temp dir");

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
        assert!(matches!(decision, StrategyDecision::Skip));
    }
}
