use async_trait::async_trait;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use tokio::fs;
use zip::ZipArchive;
use zip::ZipWriter;
use zip::write::FileOptions;

use super::office_sanitizer::OfficeSanitizer;
use super::pdf_sanitizer::PdfSanitizer;
use super::report::SanitizationAction;
use super::{FileSanitizer, SanitizationPolicy, SanitizationReport};
use misogi_core::MisogiError;
use misogi_core::Result;
use misogi_core::hash::compute_file_md5;

/// Configuration for recursive ZIP archive scanning with security limits to prevent ZIP bomb attacks.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ZipScannerConfig {
    pub max_recursion_depth: u32,
    pub max_expansion_ratio: u64,
    pub max_entry_size_bytes: u64,
    pub allowed_inner_extensions: Vec<String>,
}

impl Default for ZipScannerConfig {
    fn default() -> Self {
        Self {
            max_recursion_depth: 5,
            max_expansion_ratio: 10,
            max_entry_size_bytes: 100 * 1024 * 1024,
            allowed_inner_extensions: vec![
                ".pdf".to_string(),
                ".docx".to_string(),
                ".xlsx".to_string(),
                ".pptx".to_string(),
                ".odt".to_string(),
                ".ods".to_string(),
                ".odp".to_string(),
                ".rtf".to_string(),
                ".jpeg".to_string(),
                ".jpg".to_string(),
                ".png".to_string(),
                ".gif".to_string(),
                ".tiff".to_string(),
                ".tif".to_string(),
                ".bmp".to_string(),
                ".svg".to_string(),
                ".csv".to_string(),
                ".txt".to_string(),
                ".xml".to_string(),
                ".htm".to_string(),
                ".html".to_string(),
            ],
        }
    }
}

/// Descriptor for a single extracted ZIP entry awaiting processing.
///
/// Carries enough metadata to dispatch the entry to the correct handler
/// (recursive descent, format-specific sanitizer, or passthrough copy).
struct PendingEntry {
    entry_name: String,
    data: Vec<u8>,
    ext: String,
}

/// Recursive ZIP scanner that penetrates nested archives and sanitizes each supported inner file.
///
/// ## Processing Pipeline
///
/// 1. **Security Validation** — Each entry is checked against recursion depth limits,
///    size bounds, and path traversal patterns before extraction.
/// 2. **Recursive Descent** — Nested `.zip`/`.jar` entries are extracted to an isolated
///    temporary directory and processed by a recursive call with incremented depth.
/// 3. **Format Dispatch** — Known inner formats (`.pdf`, `.docx`, etc.) are delegated
///    to their respective specialized sanitizers.
/// 4. **Reassembly** — All processed entries are packed into a clean output ZIP archive.
///
/// ## Threading Model
///
/// ZIP entry extraction uses synchronous `std::io` (since `ZipFile` is `!Send`) and
/// completes fully before any `await` point. This guarantees the future is `Send-safe`.
pub struct ZipScanner {
    config: ZipScannerConfig,
}

impl ZipScanner {
    pub fn new(config: ZipScannerConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self {
            config: ZipScannerConfig::default(),
        }
    }

    /// Select the appropriate sanitizer implementation based on file extension.
    ///
    /// Maps each supported inner-file extension to its specialized CDR sanitizer.
    /// Unsupported extensions should never reach this function (they are filtered
    /// by `allowed_inner_extensions` in the config).
    fn get_sanitizer_for_extension(ext: &str) -> Box<dyn FileSanitizer> {
        match ext.to_lowercase().as_str() {
            ".pdf" => Box::new(PdfSanitizer::default_config()),
            _ext @ (".docx" | ".xlsx" | ".pptx" | ".docm" | ".xlsm" | ".pptm" | ".odt" | ".ods"
            | ".odp") => Box::new(OfficeSanitizer::default_config()),
            ".rtf" => Box::new(OfficeSanitizer::default_config()), // RTF handled by office sanitizer
            // Image formats: use image metadata sanitizer if available, otherwise pass through
            _ext @ (".jpeg" | ".jpg" | ".png" | ".gif" | ".tiff" | ".tif" | ".bmp") => {
                // For now, images inside ZIPs are passed through as-is.
                // A future enhancement would integrate ImageMetadataSanitizer here.
                Box::new(OfficeSanitizer::default_config()) // Placeholder — replace with image sanitizer when integrated
            }
            // Text/HTML/SVG/XML: pass through (no binary sanitization needed for text)
            _ext @ (".csv" | ".txt" | ".xml" | ".htm" | ".html" | ".svg") => {
                Box::new(OfficeSanitizer::default_config()) // Placeholder
            }
            ext => unreachable!(
                "get_sanitizer_for_extension called with unsupported/unknown extension: {} \
                 (should have been filtered by allowed_inner_extensions)",
                ext
            ),
        }
    }

    /// Returns true if the given extension indicates a nested archive requiring recursive descent.
    ///
    /// Supports the following nested archive types:
    /// - ZIP-based: `.zip`, `.jar`, `.war`, `.ear`, `.apk` (all share PK signature)
    /// - Note: Other formats (`.tar`, `.gz`, `.bz2`, `.xz`, `.7z`) are not recursively
    ///   extracted inside ZIP archives because they require format-specific decoders.
    ///   They are treated as opaque binary entries and passed through or blocked per policy.
    pub fn is_archive_extension(ext: &str) -> bool {
        matches!(
            ext.to_lowercase().as_str(),
            ".zip" | ".jar" | ".war" | ".ear" | ".apk"
        )
    }

    /// Quick check: does this ZIP data contain any encrypted entries?
    ///
    /// Scans local file headers for the encryption flag (bit 0 of general
    /// purpose bit flag) without extracting or decrypting anything.
    /// Used by the PPAP pre-check gate before Phase 1 extraction.
    fn has_encrypted_entries(&self, data: &[u8]) -> bool {
        let mut offset: usize = 0;

        while offset.saturating_add(30) <= data.len() {
            // Check local file header signature (0x04034b50)
            if data.len() < offset + 4 || &data[offset..offset + 4] != b"PK\x03\x04" {
                break;
            }
            if offset + 8 > data.len() {
                break;
            }

            // General purpose bit flag at offset 6; bit 0 = encrypted
            let flags = u16::from_le_bytes([data[offset + 6], data[offset + 7]]);
            if flags & 0x0001 != 0 {
                return true;
            }

            if offset + 30 > data.len() {
                break;
            }

            // Skip to next entry using sizes from header
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

    /// Create an isolated temporary directory for entry extraction.
    ///
    /// Uses `tempfile::TempDir` which guarantees automatic cleanup on drop,
    /// preventing residual data leaks even on panic paths.
    async fn create_temp_dir(&self) -> Result<TempDir> {
        TempDir::new().map_err(|e| MisogiError::Io(e))
    }

    /// Validate security constraints for a single ZIP entry before processing.
    ///
    /// Enforces three layers of defense:
    /// 1. Recursion depth limit to prevent stack overflow via deeply nested archives
    /// 2. Per-entry size limit to prevent memory exhaustion from decompression bombs
    /// 3. Path traversal detection to prevent writes outside the sandbox directory
    fn validate_entry_security(
        &self,
        entry_name: &str,
        uncompressed_size: u64,
        current_depth: u32,
    ) -> Result<()> {
        if current_depth >= self.config.max_recursion_depth {
            return Err(MisogiError::SecurityViolation(format!(
                "Max recursion depth {} exceeded at '{}'",
                self.config.max_recursion_depth, entry_name
            )));
        }

        if uncompressed_size > self.config.max_entry_size_bytes {
            return Err(MisogiError::SecurityViolation(format!(
                "Entry '{}' uncompressed size {} exceeds maximum {} bytes",
                entry_name, uncompressed_size, self.config.max_entry_size_bytes
            )));
        }

        if entry_name.contains("..") || entry_name.starts_with('/') || entry_name.starts_with('\\')
        {
            return Err(MisogiError::SecurityViolation(format!(
                "Path traversal attempt detected in entry name: '{}'",
                entry_name
            )));
        }

        Ok(())
    }

    /// Synchronously extract all non-directory entries from a ZIP archive into memory.
    ///
    /// Performs security validation during extraction and returns a list of
    /// [`PendingEntry`] descriptors ready for async processing.
    /// This method must complete without any `await` since it borrows `ZipArchive`.
    fn extract_all_entries_sync(
        &self,
        archive: &mut ZipArchive<std::fs::File>,
        current_depth: u32,
    ) -> Result<(Vec<PendingEntry>, u64, u64)> {
        let mut entries = Vec::new();
        let mut total_compressed: u64 = 0;
        let mut total_uncompressed: u64 = 0;

        for i in 0..archive.len() {
            let mut entry = archive.by_index(i).map_err(|e| {
                MisogiError::Protocol(format!("Failed to read ZIP entry {}: {}", i, e))
            })?;

            let entry_name = entry.name().to_string();
            let uncompressed_size = entry.size();

            self.validate_entry_security(&entry_name, uncompressed_size, current_depth)?;

            total_compressed += entry.compressed_size();
            total_uncompressed += uncompressed_size;

            if entry.is_dir() {
                continue;
            }

            let ext = Path::new(&entry_name)
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_string();

            let mut data = Vec::with_capacity(uncompressed_size as usize);
            std::io::copy(&mut entry, &mut data).map_err(|e| MisogiError::Io(e))?;

            entries.push(PendingEntry {
                entry_name,
                data,
                ext,
            });
        }

        Ok((entries, total_compressed, total_uncompressed))
    }

    /// Process a single pending entry and return the path of its sanitized output file.
    ///
    /// Dispatches to the appropriate handler based on entry extension:
    /// - Archive extensions trigger recursive descent via [`sanitize_recursive_boxed`]
    /// - Known inner extensions delegate to their specialized sanitizer
    /// - Unknown extensions are copied as-is with a warning
    async fn process_entry(
        &self,
        entry: PendingEntry,
        temp_dir: &TempDir,
        policy: &SanitizationPolicy,
        current_depth: u32,
    ) -> Result<(String, PathBuf, Vec<SanitizationAction>, Vec<String>)> {
        let entry_path = temp_dir.path().join(&entry.entry_name);
        if let Some(parent) = entry_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        fs::write(&entry_path, &entry.data).await?;

        if Self::is_archive_extension(&entry.ext) && current_depth < self.config.max_recursion_depth
        {
            let nested_output = temp_dir
                .path()
                .join(format!("{}_sanitized", entry.entry_name));
            let nested_report = Box::pin(self.sanitize_recursive_boxed(
                &entry_path,
                &nested_output,
                policy,
                current_depth + 1,
            ))
            .await?;

            let mut actions = vec![SanitizationAction::ZipEntrySanitized {
                entry_name: entry.entry_name.clone(),
            }];
            actions.extend(nested_report.actions_taken);

            Ok((
                entry.entry_name,
                nested_output,
                actions,
                nested_report.warnings,
            ))
        } else if !entry.ext.is_empty()
            && self
                .config
                .allowed_inner_extensions
                .iter()
                .any(|a| a == &entry.ext)
        {
            let inner_output = temp_dir
                .path()
                .join(format!("{}_cleaned", entry.entry_name));

            let sanitizer = Self::get_sanitizer_for_extension(&entry.ext);
            let inner_report = sanitizer
                .sanitize(&entry_path, &inner_output, policy)
                .await?;

            let mut actions = vec![SanitizationAction::ZipEntrySanitized {
                entry_name: entry.entry_name.clone(),
            }];
            actions.extend(inner_report.actions_taken);

            Ok((
                entry.entry_name,
                inner_output,
                actions,
                inner_report.warnings,
            ))
        } else if !entry.ext.is_empty() {
            Ok((
                entry.entry_name.clone(),
                entry_path,
                vec![],
                vec![format!(
                    "Unknown format '{}' copied without sanitization",
                    entry.entry_name
                )],
            ))
        } else {
            Ok((entry.entry_name, entry_path, vec![], vec![]))
        }
    }

    /// Boxed recursive entry point to satisfy Rust's requirement that recursive
    /// async functions must introduce indirection (`Box::pin`) to avoid infinitely-sized futures.
    async fn sanitize_recursive_boxed(
        &self,
        input_path: &Path,
        output_path: &Path,
        policy: &SanitizationPolicy,
        current_depth: u32,
    ) -> Result<SanitizationReport> {
        self.sanitize_recursive_impl(input_path, output_path, policy, current_depth)
            .await
    }

    /// Core recursive sanitization implementation.
    ///
    /// # Phase 1 — Synchronous Extraction
    /// Opens the ZIP and extracts every entry into memory using synchronous I/O.
    /// Security validation runs synchronously alongside extraction; no `await` occurs
    /// while `ZipFile` is borrowed, ensuring `Send` safety for the outer future.
    ///
    /// # Phase 2 — Async Dispatch
    /// Each extracted entry is written to the temp directory, then dispatched:
    /// - Nested archives recurse into [`sanitize_recursive_boxed`] (boxed for indirection)
    /// - Known formats delegate to PdfSanitizer / OfficeSanitizer
    /// - Unknown formats are passed through with a warning
    ///
    /// # Phase 3 — Reassembly
    /// All processed files are packed into a clean output ZIP at `output_path`.
    async fn sanitize_recursive_impl(
        &self,
        input_path: &Path,
        output_path: &Path,
        policy: &SanitizationPolicy,
        current_depth: u32,
    ) -> Result<SanitizationReport> {
        let filename = input_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown.zip".to_string());

        let file_id = uuid::Uuid::new_v4().to_string();
        let original_hash = compute_file_md5(input_path).await?;

        let start_time = std::time::Instant::now();
        let temp_dir = self.create_temp_dir().await?;

        // === PPAP Pre-Check: Inspect ZIP headers for encrypted entries BEFORE extraction ===
        // PPAP (Password Protected Attachment Protocol) is Japan's insecure practice of
        // sending password-protected ZIPs with passwords via email/phone.
        // We detect encrypted entries from ZIP local file header flags (bit 0 of GPBF)
        // WITHOUT extracting or decrypting anything, then delegate to PpapHandler if found.
        {
            let data = fs::read(input_path).await.map_err(|e| MisogiError::Io(e))?;
            if self.has_encrypted_entries(&data) {
                return Err(MisogiError::SecurityViolation(format!(
                    "PPAP detected: encrypted ZIP entries in '{}'. \
                     Use PpapHandler for policy-based disposition.",
                    filename
                )));
            }
        }
        // === END PPAP Pre-Check ===

        // Phase 1: Synchronous extraction (no awaits while ZipArchive is borrowed)
        let file = std::fs::File::open(input_path).map_err(|e| MisogiError::Io(e))?;
        let mut archive = ZipArchive::new(file)
            .map_err(|e| MisogiError::Protocol(format!("Invalid ZIP archive: {}", e)))?;

        let (pending_entries, total_compressed, total_uncompressed) =
            self.extract_all_entries_sync(&mut archive, current_depth)?;

        drop(archive);

        // Expansion ratio check (ZIP bomb detection)
        if total_compressed > 0
            && total_uncompressed / total_compressed > self.config.max_expansion_ratio
        {
            return Err(MisogiError::SecurityViolation(format!(
                "ZIP bomb detected: expansion ratio {} exceeds maximum {}",
                total_uncompressed / total_compressed,
                self.config.max_expansion_ratio
            )));
        }

        // Phase 2: Async dispatch of each entry
        let mut report = SanitizationReport::new(file_id.clone(), filename);
        report.policy = policy.clone();

        let mut processed_entries: Vec<(String, PathBuf)> = Vec::new();

        for entry in pending_entries {
            let (name, out_path, actions, warnings) = self
                .process_entry(entry, &temp_dir, policy, current_depth)
                .await?;

            report.actions_taken.extend(actions);
            report.warnings.extend(warnings);
            processed_entries.push((name, out_path));
        }

        // Phase 3: Reassemble into output ZIP
        self.reassemble_zip(output_path, &processed_entries).await?;

        let sanitized_hash = compute_file_md5(output_path).await?;
        let elapsed_ms = start_time.elapsed().as_millis() as u64;

        report.original_hash = original_hash;
        report.sanitized_hash = sanitized_hash;
        report.processing_time_ms = elapsed_ms;
        report.success = true;

        Ok(report)
    }

    /// Reassemble all processed entries into a clean output ZIP archive.
    ///
    /// Reads each processed file from the temporary directory and writes it into
    /// the output ZIP at its original entry path, preserving directory structure.
    async fn reassemble_zip(
        &self,
        output_path: &Path,
        processed_entries: &[(String, PathBuf)],
    ) -> Result<()> {
        let output_file = fs::File::create(output_path).await?;
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));

        let options: FileOptions<'_, ()> = FileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .unix_permissions(0o644);

        for (entry_name, file_path) in processed_entries {
            let data = fs::read(file_path).await?;

            writer
                .start_file(entry_name, options)
                .map_err(|e| MisogiError::Io(e.into()))?;
            writer.write_all(&data).map_err(|e| MisogiError::Io(e))?;
        }

        let finished = writer
            .finish()
            .map_err(|e| MisogiError::Io(e.into()))?
            .into_inner();

        use tokio::io::AsyncWriteExt;
        let mut output = output_file;
        output.write_all(&finished).await?;
        output.flush().await?;

        Ok(())
    }
}

#[async_trait]
impl FileSanitizer for ZipScanner {
    fn supported_extensions(&self) -> &[&str] {
        &[".zip", ".jar"]
    }

    async fn sanitize(
        &self,
        input_path: &Path,
        output_path: &Path,
        policy: &SanitizationPolicy,
    ) -> Result<SanitizationReport> {
        self.sanitize_recursive_boxed(input_path, output_path, policy, 0)
            .await
    }
}
