//! Binary entry validation for OOXML True CDR.
//!
//! Validates binary resources before copying to output ZIP.

use std::io::Read;

use misogi_core::{MisogiError, Result};

use super::config::OoxmlTrueCdrConfig;
use super::report::OoxmlCdrReport;
use super::types::ContentTypeFilterMode;

/// Validate a binary entry before copying to output.
///
/// Checks that the binary resource is a safe type (image, font, etc.)
/// and doesn't exceed size limits. Returns None if entry should be skipped.
pub fn validate_binary_entry(
    entry_name: &str,
    entry_reader: &mut zip::read::ZipFile<'_>,
    config: &OoxmlTrueCdrConfig,
    report: &mut OoxmlCdrReport,
) -> Result<Option<Vec<u8>>> {
    let lower = entry_name.to_ascii_lowercase();

    // Determine expected binary type from path/location
    let is_safe_binary = lower.contains("/media/")
        || lower.contains("/image")
        || lower.ends_with(".png")
        || lower.ends_with(".jpg")
        || lower.ends_with(".jpeg")
        || lower.ends_with(".gif")
        || lower.ends_with(".bmp")
        || lower.ends_with(".tif")
        || lower.ends_with(".tiff")
        || lower.ends_with(".svg")
        || lower.contains("/fonts/")
        || lower.ends_with(".ttf")
        || lower.ends_with(".otf")
        || lower.ends_with(".woff")
        || lower.ends_with(".woff2");

    if !is_safe_binary {
        match config.content_type_mode {
            ContentTypeFilterMode::Strict => {
                report.add_warning(format!(
                    "Skipped unknown binary entry (strict mode): {}",
                    entry_name
                ));
                return Ok(None);
            }
            ContentTypeFilterMode::Lenient => {
                report.add_warning(format!(
                    "Keeping unknown binary entry (lenient mode): {}",
                    entry_name
                ));
            }
            ContentTypeFilterMode::Permissive => {}
        }
    }

    // Size check for binary resources (prevent embedded malware via large binaries)
    const MAX_BINARY_RESOURCE_SIZE: u64 = 50 * 1024 * 1024; // 50 MB per resource
    if entry_reader.size() > MAX_BINARY_RESOURCE_SIZE {
        report.add_warning(format!(
            "Skipping oversized binary resource ({} bytes): {}",
            entry_reader.size(),
            entry_name
        ));
        return Ok(None);
    }

    // Read and return the binary data
    let mut data = Vec::with_capacity(entry_reader.size() as usize);
    entry_reader.read_to_end(&mut data)
        .map_err(|e| MisogiError::Io(e))?;

    Ok(Some(data))
}
