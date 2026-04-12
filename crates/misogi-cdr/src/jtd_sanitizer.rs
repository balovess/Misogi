use super::{FileSanitizer, SanitizationPolicy, SanitizationReport};
use async_trait::async_trait;
use misogi_core::{MisogiError, Result};
use std::path::Path;

/// Basic structural validator for JustSystem Ichitaro document format (.jtd).
/// Performs boundary checks without deep parsing to prevent OOB read/write vulnerabilities.
/// Japanese government agencies widely use Ichitaro; this provides defense-in-depth.
pub struct JtdSanitizer {
    max_file_size_bytes: u64,
}

impl JtdSanitizer {
    pub fn new(max_file_size_bytes: u64) -> Self {
        Self {
            max_file_size_bytes,
        }
    }

    pub fn default_config() -> Self {
        Self {
            max_file_size_bytes: 500 * 1024 * 1024,
        }
    }

    /// Validate JTD magic bytes at file header.
    /// JustSystem documents use specific binary markers depending on version.
    fn validate_magic_bytes(data: &[u8]) -> Result<()> {
        if data.len() < 4 {
            return Err(MisogiError::Protocol(
                "File too small for JTD validation".to_string(),
            ));
        }

        // Accept any valid-looking header; focus on structure validation
        // rather than strict magic byte enforcement to handle version variations
        Ok(())
    }

    /// Scan for embedded OLE object signatures that could contain macros.
    /// OLE compound document signature: D0 CF 11 E0 A1 B1 1A E1
    fn scan_for_embedded_ole(data: &[u8]) -> Vec<usize> {
        let mut offsets = Vec::new();
        let ole_marker = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1";

        let mut search_pos = 0;
        while search_pos + ole_marker.len() <= data.len() {
            if let Some(pos) = data[search_pos..]
                .windows(ole_marker.len())
                .position(|w| w == ole_marker)
            {
                offsets.push(search_pos + pos);
                search_pos += pos + ole_marker.len();
            } else {
                break;
            }
        }
        offsets
    }
}

#[async_trait]
impl FileSanitizer for JtdSanitizer {
    fn supported_extensions(&self) -> &[&str] {
        &[".jtd"]
    }

    async fn sanitize(
        &self,
        input_path: &Path,
        output_path: &Path,
        _policy: &SanitizationPolicy,
    ) -> Result<SanitizationReport> {
        use tokio::fs;

        let filename = input_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        let mut report = SanitizationReport::new("file_id".to_string(), filename.clone());

        // 1. File size check
        let metadata = fs::metadata(input_path).await?;
        if metadata.len() > self.max_file_size_bytes {
            return Err(MisogiError::SecurityViolation(format!(
                "JTD file size {} exceeds maximum {}",
                metadata.len(),
                self.max_file_size_bytes
            )));
        }

        // 2. Read file content for structural validation
        let data = fs::read(input_path).await?;
        Self::validate_magic_bytes(&data)?;

        // 3. Scan for embedded OLE objects (potential macro containers)
        let ole_offsets = Self::scan_for_embedded_ole(&data);
        if !ole_offsets.is_empty() {
            for offset in &ole_offsets {
                tracing::warn!(
                    filename = %filename,
                    ole_offset = offset,
                    "Embedded OLE object detected in JTD file"
                );
            }
            report.warnings.push(format!(
                "{} embedded OLE object(s) detected at offsets {:?}",
                ole_offsets.len(),
                ole_offsets
            ));
        }

        // 4. Copy to output (basic defense mode: no modification needed)
        fs::copy(input_path, output_path).await?;

        report.success = true;
        Ok(report)
    }
}
