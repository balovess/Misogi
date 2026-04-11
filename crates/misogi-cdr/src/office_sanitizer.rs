use std::io::{Read, Seek, Write};
use std::path::Path;
use async_trait::async_trait;
use zip::{ZipArchive, ZipWriter};
use zip::write::FileOptions;

use super::{FileSanitizer, SanitizationPolicy, SanitizationReport};
use super::report::SanitizationAction;
use misogi_core::{hash, Result};
use misogi_core::MisogiError;

const DANGEROUS_ENTRIES: &[&str] = &[
    "vbaProject.bin",
    "word/vbaProject.bin",
    "xl/vbaProject.bin",
    "ppt/vbaProject.bin",
    "word/vbaData.xml",
    "xl/vbaData.xml",
];

const DEFAULT_MAX_FILE_SIZE_BYTES: u64 = 100 * 1024 * 1024;
const MAX_ZIP_EXPANSION_RATIO: u64 = 10;
const STREAM_BUFFER_SIZE: usize = 8192;

pub struct OfficeSanitizer {
    max_file_size_bytes: u64,
}

impl OfficeSanitizer {
    pub fn new(max_file_size_bytes: u64) -> Self {
        Self { max_file_size_bytes }
    }

    pub fn default_config() -> Self {
        Self { max_file_size_bytes: DEFAULT_MAX_FILE_SIZE_BYTES }
    }

    fn is_dangerous_entry(name: &str) -> bool {
        let normalized = name.to_ascii_lowercase();
        DANGEROUS_ENTRIES.iter().any(|dangerous| {
            normalized == *dangerous
                || normalized.ends_with(&format!("/{}", dangerous.to_ascii_lowercase()))
        })
    }

    fn calculate_uncompressed_size(
        archive: &mut ZipArchive<impl Read + Seek>,
    ) -> Result<u64> {
        let mut total: u64 = 0;
        for i in 0..archive.len() {
            let entry = archive.by_index(i).map_err(|e| MisogiError::Io(e.into()))?;
            total = total.saturating_add(entry.size());
        }
        Ok(total)
    }
}

#[async_trait]
impl FileSanitizer for OfficeSanitizer {
    fn supported_extensions(&self) -> &[&str] {
        &[".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"]
    }

    async fn sanitize(
        &self,
        input_path: &Path,
        output_path: &Path,
        policy: &SanitizationPolicy,
    ) -> Result<SanitizationReport> {
        let filename = input_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        let file_id = filename.clone();

        let mut report =
            SanitizationReport::new(file_id, filename).with_policy(policy.clone());

        let file = std::fs::File::open(input_path)?;

        let metadata = std::fs::metadata(input_path)?;
        if metadata.len() > self.max_file_size_bytes {
            return Err(MisogiError::SecurityViolation(format!(
                "Input file size {} bytes exceeds maximum allowed {} bytes",
                metadata.len(),
                self.max_file_size_bytes
            )));
        }

        let mut reader = ZipArchive::new(file).map_err(|e| MisogiError::Io(e.into()))?;

        let total_uncompressed = Self::calculate_uncompressed_size(&mut reader)?;
        let compressed_size = metadata.len().max(1);
        let expansion_ratio = total_uncompressed / compressed_size;

        if expansion_ratio > MAX_ZIP_EXPANSION_RATIO {
            return Err(MisogiError::SecurityViolation(format!(
                "ZIP bomb detected: expansion ratio {}x exceeds maximum {}x (uncompressed={}, compressed={})",
                expansion_ratio,
                MAX_ZIP_EXPANSION_RATIO,
                total_uncompressed,
                metadata.len()
            )));
        }

        let output_file = std::fs::File::create(output_path)?;
        let mut writer = ZipWriter::new(std::io::BufWriter::new(output_file));

        let entry_names: Vec<String> =
            reader.file_names().map(|s| s.to_string()).collect();

        for entry_name in &entry_names {
            if Self::is_dangerous_entry(entry_name) {
                report.actions_taken.push(SanitizationAction::VbaMacroRemoved {
                    filename: entry_name.clone(),
                });
                tracing::warn!(entry = %entry_name, "VBA macro entry removed from OOXML package");
                continue;
            }

            let mut entry_reader = reader
                .by_name(entry_name)
                .map_err(|e| MisogiError::Io(e.into()))?;

            let mut options: zip::write::FileOptions<'_, ()> =
                FileOptions::default().compression_method(entry_reader.compression());

            if let Some(modified) = entry_reader.last_modified() {
                options = options.last_modified_time(modified);
            }

            writer.start_file(entry_name, options)
                .map_err(|e| MisogiError::Io(e.into()))?;

            let mut buffer = [0u8; STREAM_BUFFER_SIZE];
            loop {
                match entry_reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => writer.write_all(&buffer[..n])
                        .map_err(|e| MisogiError::Io(e))?,
                    Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(MisogiError::Io(e)),
                }
            }
        }

        writer.finish().map_err(|e| MisogiError::Io(e.into()))?;

        report.original_hash = hash::compute_file_md5(input_path).await?;
        report.sanitized_hash = hash::compute_file_md5(output_path).await?;
        report.success = true;

        Ok(report)
    }
}
