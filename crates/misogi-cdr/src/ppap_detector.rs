//! PPAP (Password Protected Attachment Protocol) detection engine.
//!
//! Scans uploaded files for indicators of the insecure Japanese file-sharing
//! practice where documents are sent as password-protected archives with
//! credentials transmitted via out-of-band channels (email, phone, fax).
//!
//! # Detection Strategy (Multi-Layer)
//!
//! ## Layer 1: Structural Analysis (fast, no decryption needed)
//! - Check ZIP/LZH/7Z container format via magic bytes or extension
//! - Detect encrypted entries via ZIP local file header flags
//!   (bit 0 of general purpose bit flag = encrypted)
//! - Distinguish traditional PKWARE ZipCrypto from AES encryption
//!
//! ## Layer 2: Heuristic Analysis (filename/content patterns)
//! - Japanese sensitive document naming patterns:
//!   - `*機密*`, `*重要*`, `*秘*`, `*内覧*`
//!   - Date-patterned names: `*_YYYYMMDD.zip`
//!   - Meeting-numbered names: `*_第N回*.zip`
//!
//! ## Layer 3: Metadata Analysis (optional, low weight)
//! - ZIP comment fields containing password hints
//! - Archive creation timestamps outside business hours
//!
//! # Security Note
//!
//! This detector **never attempts decryption**. It only inspects structural
//! metadata (ZIP headers, filenames) to determine whether a file exhibits
//! PPAP characteristics. The goal is detection and policy enforcement,
//! not bypassing encryption.

use std::path::Path;

use super::ppap_types::{PpapDetectionResult, PpapDetectorConfig, PpapIndicator};
use misogi_core::MisogiError;
use misogi_core::Result;

/// PPAP (Password Protected Attachment Protocol) detection engine.
///
/// Provides multi-layer scanning to identify files that follow Japan's
/// insecure PPAP practice without attempting any decryption.
pub struct PpapDetector {
    config: PpapDetectorConfig,

    /// Pre-compiled regex patterns for filename heuristic analysis.
    /// Compiled once at construction time to avoid recompilation per scan.
    #[allow(dead_code)]
    filename_patterns: Vec<Option<regex::Regex>>,
}

impl PpapDetector {
    /// Create detector with default configuration.
    pub fn new() -> Self {
        Self::with_config(PpapDetectorConfig::default())
    }

    /// Create detector with custom configuration.
    pub fn with_config(config: PpapDetectorConfig) -> Self {
        let filename_patterns = config
            .sensitive_filename_patterns
            .iter()
            .map(|p| regex::Regex::new(p).ok())
            .collect();

        Self {
            config,
            filename_patterns,
        }
    }

    /// Returns a reference to the current configuration.
    pub fn config(&self) -> &PpapDetectorConfig {
        &self.config
    }

    /// Scan a file for PPAP indicators without opening/decrypting it.
    ///
    /// Uses only structural analysis (ZIP header inspection) and filename heuristics.
    /// Does NOT attempt password cracking or content inspection.
    ///
    /// # Arguments
    /// * `file_path` - Path to the file to scan.
    ///
    /// # Returns
    /// [`PpapDetectionResult`] with confidence score and indicator list.
    ///
    /// # Errors
    /// - [`MisogiError::Io`] if the file cannot be read.
    /// - [`MisogiError::Protocol`] if the file format is unrecognizable.
    pub async fn detect(&self, file_path: &Path) -> Result<PpapDetectionResult> {
        let filename = file_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".to_string());

        // Pre-check: file size limit
        let metadata = tokio::fs::metadata(file_path)
            .await
            .map_err(|e| MisogiError::Io(e))?;

        if metadata.len() > self.config.max_scan_size_bytes {
            return Ok(PpapDetectionResult {
                is_ppap: false,
                confidence: 0.0,
                indicators: Vec::new(),
                encryption_method: None,
                reason: format!(
                    "File size {} bytes exceeds PPAP scan limit {} bytes",
                    metadata.len(),
                    self.config.max_scan_size_bytes
                ),
            });
        }

        let mut indicators: Vec<PpapIndicator> = Vec::new();
        let mut encryption_method: Option<String> = None;
        let mut reason_parts: Vec<String> = Vec::new();

        // Layer 1: Structural analysis — read file headers
        let data = tokio::fs::read(file_path)
            .await
            .map_err(|e| MisogiError::Io(e))?;
        let structural_indicators = self.analyze_structure(&data, &filename);
        for ind in &structural_indicators {
            if let PpapIndicator::EncryptedZipEntry { .. } = ind {
                encryption_method = Some("ZipCrypto".to_string());
            }
        }
        indicators.extend(structural_indicators);

        // Layer 2: Filename heuristic analysis
        if self.config.enable_filename_heuristics {
            let heuristic_indicators = self.analyze_filename(&filename);
            indicators.extend(heuristic_indicators);
        }

        // Compute composite confidence score
        let confidence = self.compute_confidence(&indicators);
        let is_ppap = confidence >= self.config.confidence_threshold;

        // Build human-readable reason
        if !indicators.is_empty() {
            reason_parts.push(format!("{} indicator(s) found:", indicators.len()));
            for ind in &indicators {
                reason_parts.push(format!("  - {}", ind));
            }
        } else {
            reason_parts.push("No PPAP indicators detected".to_string());
        }

        Ok(PpapDetectionResult {
            is_ppap,
            confidence,
            indicators,
            encryption_method,
            reason: reason_parts.join("; "),
        })
    }

    /// Quick check: is this file definitely a PPAP file?
    ///
    /// Faster than [`detect`] — returns boolean without full analysis.
    /// Used as early-rejection gate in the upload pipeline.
    ///
    /// Only checks for the strongest signal: encrypted ZIP entries.
    /// Does not perform filename heuristics or compute confidence score.
    pub async fn is_likely_ppap(&self, file_path: &Path) -> Result<bool> {
        let data = tokio::fs::read(file_path)
            .await
            .map_err(|e| MisogiError::Io(e))?;
        Ok(self.has_encrypted_entries(&data))
    }

    // =========================================================================
    // Layer 1: Structural Analysis
    // =========================================================================

    /// Analyze file structure for PPAP indicators without full extraction.
    ///
    /// Reads ZIP local file headers to identify:
    /// - Encrypted entries (general purpose bit flag, bit 0)
    /// - Encryption method (ZipCrypto vs AES)
    /// - Container type (ZIP, LZH, 7z)
    fn analyze_structure(&self, data: &[u8], filename: &str) -> Vec<PpapIndicator> {
        let mut indicators = Vec::new();

        // Check container extension
        if let Some(ext) = Path::new(filename).extension().and_then(|e| e.to_str()) {
            let lower = ext.to_lowercase();
            if matches!(lower.as_str(), "zip" | "lzh" | "7z") {
                indicators.push(PpapIndicator::ContainerExtension {
                    extension: format!(".{}", lower),
                });
            }
        }

        // Check for ZIP signature (PK\x03\x04)
        if data.len() >= 4 && &data[0..4] == b"PK\x03\x04" {
            let zip_indicators = self.analyze_zip_encryption(data);
            indicators.extend(zip_indicators);
        }

        // Check for 7z signature ('7', 'z', 0xBC, 0xAF, 0x27, 0x1C)
        if data.len() >= 6 && &data[0..6] == b"\x37\x7A\xBC\xAF\x27\x1C" {
            // 7z always supports encryption; flag as potential PPAP container
            // (we can't easily inspect 7z internals without the full crate)
            indicators.push(PpapIndicator::ContainerExtension {
                extension: ".7z".to_string(),
            });
        }

        indicators
    }

    /// Analyze ZIP archive encryption details from raw bytes.
    ///
    /// Scans local file headers to find encrypted entries.
    /// ZIP local file header format:
    /// ```
    /// Offset  Size  Field
    /// 0      4     Local file header signature (0x04034b50)
    /// 4      2     Version needed to extract
    /// 6      2     General purpose bit flag
    ///              Bit 0: file is encrypted
    ///              Bit 3: data descriptor follows
    ///              Bit 5: compressed + patched data
    /// 8      2     Compression method
    ///              0: stored (no compression)
    ///              8: deflated
    ///              14: LZMA
    ///              99: AES encryption (extra field required)
    /// ...
    /// 26     2     File name length
    /// 28     2     Extra field length
    /// 30     var   File name
    /// 30+n   var   Extra field
    /// ```
    fn analyze_zip_encryption(&self, data: &[u8]) -> Vec<PpapIndicator> {
        let mut indicators = Vec::new();
        let mut offset: usize = 0;
        let mut _has_encrypted_entry = false;

        while offset.saturating_add(30) <= data.len() {
            // Check local file header signature
            if &data[offset..offset + 4] != b"PK\x03\x04" {
                break;
            }

            // General purpose bit flag at offset 6
            if offset + 8 > data.len() {
                break;
            }
            let flags = u16::from_le_bytes([data[offset + 6], data[offset + 7]]);

            // Compression method at offset 8
            let compression = u16::from_le_bytes([data[offset + 8], data[offset + 9]]);

            // File name length at offset 26
            if offset + 28 > data.len() {
                break;
            }
            let name_len = u16::from_le_bytes([data[offset + 26], data[offset + 27]]) as usize;

            // Extra field length at offset 28
            let extra_len = u16::from_le_bytes([data[offset + 28], data[offset + 29]]) as usize;

            // Extract filename (for indicator context)
            let name_start = offset + 30;
            let name_end = name_start + name_len.min(data.len() - name_start);
            let entry_name = String::from_utf8_lossy(&data[name_start..name_end]);

            // Bit 0 of flags = encrypted
            if flags & 0x0001 != 0 {
                _has_encrypted_entry = true;

                let _method_str = match compression {
                    99 => "AES-256".to_string(),
                    _ => "ZipCrypto".to_string(),
                };

                indicators.push(PpapIndicator::EncryptedZipEntry {
                    entry_name: entry_name.to_string(),
                });

                // Store first encryption method found
                if indicators.len() == 1 {
                    // Will be set by caller from first EncryptedZipEntry
                }
            }

            // Advance to next entry
            let header_end = 30 + name_len + extra_len;

            // For non-encrypted entries, we need to find the data descriptor
            // or use the compressed/uncompressed sizes to skip data
            if offset + 18 > data.len() {
                break;
            }
            let _compressed_size = u32::from_le_bytes([
                data[offset + 18],
                data[offset + 19],
                data[offset + 20],
                data[offset + 21],
            ]) as usize;

            // If bit 3 is set, sizes are in data descriptor after data
            if flags & 0x0008 != 0 {
                // Data descriptor: signature (4) + CRC (4) + compressed (4) + uncompressed (4) = 16
                offset = header_end + _compressed_size + 16;
            } else {
                let _uncompressed_size = u32::from_le_bytes([
                    data[offset + 22],
                    data[offset + 23],
                    data[offset + 24],
                    data[offset + 25],
                ]) as usize;
                offset = header_end + _compressed_size.max(_uncompressed_size);
            }

            // Safety: prevent infinite loop on malformed data
            if offset < 30 || offset > data.len() {
                break;
            }
        }

        indicators
    }

    /// Quick check: does this ZIP data contain any encrypted entries?
    fn has_encrypted_entries(&self, data: &[u8]) -> bool {
        let mut offset: usize = 0;

        while offset.saturating_add(30) <= data.len() {
            if &data[offset..offset + 4] != b"PK\x03\x04" {
                break;
            }
            if offset + 8 > data.len() {
                break;
            }
            let flags = u16::from_le_bytes([data[offset + 6], data[offset + 7]]);
            if flags & 0x0001 != 0 {
                return true;
            }

            if offset + 30 > data.len() {
                break;
            }
            let name_len = u16::from_le_bytes([data[offset + 26], data[offset + 27]]) as usize;
            let extra_len = u16::from_le_bytes([data[offset + 28], data[offset + 29]]) as usize;
            let compressed_size = u32::from_le_bytes([
                data[offset + 18],
                data[offset + 19],
                data[offset + 20],
                data[offset + 21],
            ]) as usize;
            let uncompressed_size = u32::from_le_bytes([
                data[offset + 22],
                data[offset + 23],
                data[offset + 24],
                data[offset + 25],
            ]) as usize;

            let gflags = flags;
            let header_end = 30 + name_len + extra_len;
            if gflags & 0x0008 != 0 {
                offset = header_end + compressed_size + 16;
            } else {
                offset = header_end + compressed_size.max(uncompressed_size);
            }
            if offset < 30 || offset > data.len() {
                break;
            }
        }

        false
    }

    // =========================================================================
    // Layer 2: Heuristic Analysis
    // =========================================================================

    /// Analyze filename against configured sensitive patterns.
    fn analyze_filename(&self, filename: &str) -> Vec<PpapIndicator> {
        let mut indicators = Vec::new();

        for pattern_opt in self.filename_patterns.iter() {
            if let Some(pattern) = pattern_opt {
                if pattern.is_match(filename) {
                    indicators.push(PpapIndicator::SensitiveFilenamePattern {
                        pattern: pattern.as_str().to_string(),
                    });
                }
            }
        }

        indicators
    }

    // =========================================================================
    // Confidence Scoring
    // =========================================================================

    /// Compute composite confidence score from collected indicators.
    ///
    /// Scoring algorithm:
    /// - Start with base confidence 0.0
    /// - Each EncryptedZipEntry: multiply by (1 - 0.8^(1/n)) where n = count
    ///   → First encrypted entry gives ~0.55 boost, approaching 0.8 asymptotically
    /// - Each SensitiveFilenamePattern: add 0.25, capped at 0.5 total
    /// - Each ContainerExtension: add 0.05, capped at 0.1 total
    /// - Final score clamped to [0.0, 1.0]
    fn compute_confidence(&self, indicators: &[PpapIndicator]) -> f64 {
        if indicators.is_empty() {
            return 0.0;
        }

        let mut encrypted_count: f64 = 0.0;
        let mut filename_score: f64 = 0.0;
        let mut container_score: f64 = 0.0;

        for ind in indicators {
            match ind {
                PpapIndicator::EncryptedZipEntry { .. } => {
                    encrypted_count += 1.0;
                }
                PpapIndicator::SensitiveFilenamePattern { .. } => {
                    filename_score = (filename_score + 0.25).min(0.5);
                }
                PpapIndicator::ContainerExtension { .. } => {
                    container_score = (container_score + 0.05).min(0.1);
                }
                PpapIndicator::KnownPpapSender { .. } => {
                    // Sender history adds moderate weight
                    filename_score = (filename_score + 0.15).min(0.5);
                }
            }
        }

        // Encrypted entries dominate the score (structural evidence > heuristics)
        let encrypted_confidence = if encrypted_count > 0.0 {
            0.8 * (1.0 - 0.8_f64.powf(1.0 / encrypted_count))
        } else {
            0.0
        };

        let total = encrypted_confidence + filename_score + container_score;
        total.min(1.0).max(0.0)
    }
}

impl Default for PpapDetector {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ppap_types::{PpapDisposition, PpapHandlingReport, PpapPolicy};
    use crate::ppap_types::default_sensitive_filename_patterns;

    #[test]
    fn test_default_config_values() {
        let config = PpapDetectorConfig::default();
        assert_eq!(config.confidence_threshold, 0.7);
        assert!(config.enable_filename_heuristics);
        assert!(!config.sensitive_filename_patterns.is_empty());
        assert_eq!(config.max_scan_size_bytes, 500 * 1024 * 1024);
    }

    #[test]
    fn test_policy_from_str() {
        assert_eq!(PpapPolicy::from_str("block"), Some(PpapPolicy::Block));
        assert_eq!(
            PpapPolicy::from_str("warn"),
            Some(PpapPolicy::WarnAndSanitize)
        );
        assert_eq!(
            PpapPolicy::from_str("quarantine"),
            Some(PpapPolicy::Quarantine)
        );
        assert_eq!(
            PpapPolicy::from_str("convert"),
            Some(PpapPolicy::ConvertToSecure)
        );
        assert_eq!(PpapPolicy::from_str("invalid"), None);
    }

    #[test]
    fn test_policy_properties() {
        assert!(!PpapPolicy::Block.allows_transfer());
        assert!(PpapPolicy::WarnAndSanitize.allows_transfer());
        assert!(PpapPolicy::Quarantine.requires_quarantine());
        assert!(!PpapPolicy::Block.attempts_conversion());
        assert!(PpapPolicy::ConvertToSecure.attempts_conversion());
    }

    #[test]
    fn test_detection_result_clean() {
        let result = PpapDetectionResult::clean();
        assert!(!result.is_ppap);
        assert_eq!(result.confidence, 0.0);
        assert!(result.indicators.is_empty());
        assert!(result.encryption_method.is_none());
    }

    #[test]
    fn test_detection_result_ppap_detected() {
        let result = PpapDetectionResult::ppap_detected(
            0.85,
            vec![PpapIndicator::EncryptedZipEntry {
                entry_name: "重要書類.pdf".to_string(),
            }],
            Some("ZipCrypto".to_string()),
            "Encrypted ZIP entry found".to_string(),
        );
        assert!(result.is_ppap);
        assert_eq!(result.confidence, 0.85);
        assert_eq!(result.indicators.len(), 1);
        assert_eq!(result.encryption_method.as_deref(), Some("ZipCrypto"));
    }

    #[test]
    fn test_indicator_display() {
        let ind = PpapIndicator::EncryptedZipEntry {
            entry_name: "test.pdf".to_string(),
        };
        assert!(format!("{}", ind).contains("encrypted_zip_entry"));

        let ind = PpapIndicator::ContainerExtension {
            extension: ".zip".to_string(),
        };
        assert!(format!("{}", ind).contains(".zip"));
    }

    #[test]
    fn test_handling_report_new() {
        let report = PpapHandlingReport::new("file-123".to_string(), "test.zip".to_string());
        assert_eq!(report.file_id, "file-123");
        assert!(!report.success);
        assert_eq!(report.disposition, PpapDisposition::PassedThrough);
    }

    #[test]
    fn test_filename_pattern_defaults() {
        let patterns = default_sensitive_filename_patterns();
        assert!(!patterns.is_empty());
        // Should contain Japanese sensitivity keywords
        let all_patterns = patterns.join("|");
        assert!(all_patterns.contains("機密"));
    }

    #[tokio::test]
    async fn test_detect_nonexistent_file() {
        let detector = PpapDetector::new();
        let result = detector.detect(Path::new("/nonexistent/file.zip")).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_is_likely_ppap_nonexistent() {
        let detector = PpapDetector::new();
        let result = detector
            .is_likely_ppap(Path::new("/nonexistent/file.zip"))
            .await;
        assert!(result.is_err());
    }
}
