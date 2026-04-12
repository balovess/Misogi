// =============================================================================
// JTD Handler — Upload-Time JTD Detection & Conversion Orchestration
// =============================================================================
// This module provides the integration layer between HTTP upload handlers and
// the JTD conversion pipeline (misogi_core::traits::JtdConversionPipeline).
//
// Responsibilities:
//   1. Detect when an uploaded file has a .jtd (Ichitaro) extension
//   2. Decide whether to convert based on configuration
//   3. Execute the conversion pipeline when enabled
//   4. Emit appropriate bilingual warnings/errors
//   5. Return the final file path (converted PDF or original JTD)
//
// Architecture:
//
//   http_routes::upload_file()
//     -> jtd_handler::handle_jtd_upload()
//       |-- Is it a .jtd file? --No--> return Ok(original_path)
//       | Yes + conversion enabled?
//       |     |-- Yes -> run JtdConversionPipeline::process_file()
//       |     |   |-- Success -> return Ok(converted_pdf_path)
//       |     |   +-- Failure -> abort or warn per failure_policy
//       |     +-- No -> print warning, return Ok(original_path)
//
// Design Principles:
// - All user-facing messages are bilingual (English primary, Japanese secondary)
// - Conversion failures are handled per configured failure policy (block/warn/skip)
// - Non-JTD files pass through with zero overhead (no allocation, no I/O)
// - Fully async-compatible for use in Axum handlers
// =============================================================================

use std::path::{Path, PathBuf};

use misogi_core::{
    JtdConversionPipeline, JtdFailurePolicy, JtdPipelineConfig, JtdConverterType,
    should_convert_jtd, DummyAction,
};

use crate::config::SenderConfig;

/// Result of JTD upload handling.
///
/// Indicates what happened to the input file and what path should be used
/// for downstream CDR processing.
#[derive(Debug)]
pub enum JtdHandleResult {
    /// File was not a JTD document; no action taken.
    NotJtd {
        /// Original file path passed through unchanged.
        #[allow(dead_code)]
        original_path: PathBuf,
    },

    /// JTD file detected but conversion is not enabled; warning was emitted.
    SkippedWithWarning {
        /// Original .jtd file path (not converted).
        #[allow(dead_code)]
        original_path: PathBuf,
        /// Warning message that was printed to the user.
        #[allow(dead_code)]
        warning_message: String,
    },

    /// JTD file was successfully converted to PDF.
    Converted {
        /// Path to the successfully converted PDF file.
        pdf_path: PathBuf,
        /// Path to the original .jtd source file.
        #[allow(dead_code)]
        original_path: PathBuf,
    },

    /// JTD conversion failed and failure policy dictated abortion.
    ConversionFailed {
        /// Bilingual error message describing the failure.
        error_message: String,
    },
}

impl JtdHandleResult {
    /// Get the effective file path for downstream processing.
    ///
    /// Returns Some(path) when processing should continue, or None on fatal error.
    #[must_use]
    #[allow(dead_code)]
    pub fn effective_path(&self) -> Option<&Path> {
        match self {
            Self::NotJtd { original_path } => Some(original_path),
            Self::SkippedWithWarning { original_path, .. } => Some(original_path),
            Self::Converted { pdf_path, .. } => Some(pdf_path),
            Self::ConversionFailed { .. } => None,
        }
    }

    /// Check whether this result indicates a fatal error stopping processing.
    #[must_use]
    #[allow(dead_code)]
    pub fn is_fatal(&self) -> bool {
        matches!(self, Self::ConversionFailed { .. })
    }
}

/// Handle an uploaded file, detecting and converting JTD documents if configured.
///
/// This is the primary entry point called from upload handlers before passing
/// files to the CDR sanitization pipeline.
///
/// # Arguments
///
/// * `file_path` - Absolute path to the uploaded file on disk.
/// * `config` - Sender configuration containing JTD conversion settings.
///
/// # Returns
///
/// A [`JtdHandleResult`] indicating what action was taken and which file path
/// to use for downstream processing.
pub async fn handle_jtd_upload(
    file_path: &Path,
    config: &SenderConfig,
) -> JtdHandleResult {
    // Step 1: Quick extension check using core's helper function (zero-cost for non-JTD)
    let ext = file_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    if !should_convert_jtd(ext) {
        return JtdHandleResult::NotJtd {
            original_path: file_path.to_path_buf(),
        };
    }

    // Step 2: JTD file detected -- check if conversion is enabled
    tracing::info!(
        file = %file_path.display(),
        "Detected Ichitaro (.jtd) format \
         \u{4e00}\u{592a}\u{90ce} (.jtd) \u{30d5}\u{30a9}\u{30fc}\u{30de}\u{30c3}\u{30c8}\u{3092}\u{691c}\u{51fa}\u{3057}\u{307e}\u{3057}\u{305f}"
    );

    if !config.jtd_conversion_enabled {
        // Conversion not enabled -- emit clear warning and continue with original file
        // Japanese text: Warning about JTD format, suggestion to use flag, docs link
        let warning = String::from(
            "\u{26a0} Warning: Ichitaro (.jtd) format detected. JTD conversion is not enabled.\n\
             \u{20} To enable automatic JTD->PDF conversion, add --convert-jtd-to-pdf flag.\n\
             \u{20} For more information, see: https://github.com/nicepkg/misogi/docs/ja/configuration/jtd-converter.md\n\
             \n\
             \u{26a0} \u{8b66}\u{544a}: \u{4e00}\u{592a}\u{90ce} (.jtd) \u{30d5}\u{30a9}\u{30fc}\u{30de}\u{30c3}\u{30c8}\u{304c}\u{691c}\u{51fa}\u{3055}\u{308c}\u{307e}\u{3057}\u{305f}\u{3002}\
             JTD\u{5909}\u{63db}\u{306f}\u{6709}\u{52b9}\u{3067}\u{306f}\u{3042}\u{308a}\u{307e}\u{305b}\u{3093}\u{3002}\n\
             \u{20} \u{81ea}\u{52d5}JTD->PDF\u{5909}\u{63db}\u{3092}\u{6709}\u{52b9}\u{306b}\u{3059}\u{308b}\u{306b}\u{306f}\u{3001}--convert-jtd-to-pdf \
             \u{30d5}\u{30e9}\u{30b0}\u{3092}\u{8ffd}\u{52a0}\u{3057}\u{3066}\u{304f}\u{3060}\u{3055}\u{3044}\u{3002}"
        );

        eprintln!("{warning}");
        tracing::warn!(
            file = %file_path.display(),
            "JTD file uploaded but conversion is not enabled; proceeding without conversion"
        );

        return JtdHandleResult::SkippedWithWarning {
            original_path: file_path.to_path_buf(),
            warning_message: warning,
        };
    }

    // Step 3: Conversion enabled -- proceed with pipeline
    println!(
        "Detected Ichitaro (.jtd) format, initiating conversion to PDF... \
         \u{4e00}\u{592a}\u{90ce} (.jtd) \u{30d5}\u{30a9}\u{30fc}\u{30de}\u{30c3}\u{30c8}\u{3092}\u{691c}\u{51fa}\u{3057}\u{307e}\u{3057}\u{305f}\u{3002}\
         PDF\u{3078}\u{306e}\u{5909}\u{63db}\u{3092}\u{958b}\u{59cb}\u{3057}\u{307e}\u{3059}..."
    );

    // Build pipeline config from SenderConfig
    // Map CLI string converter_type to the core JtdConverterType enum
    let converter_type = match config.jtd_converter_type.to_lowercase().as_str() {
        "libreoffice" => JtdConverterType::LibreOffice,
        "ichitaro_viewer" => JtdConverterType::IchitaroViewer,
        "dummy" => JtdConverterType::Dummy {
            action: DummyAction::PlaceholderPdf,
        },
        _ => JtdConverterType::Auto,
    };

    // Map CLI failure policy string to core enum
    // Default to Block for production safety (CLI doesn't expose policy yet)
    let failure_policy = JtdFailurePolicy::Block;

    let pipeline_config = JtdPipelineConfig {
        enabled: true,
        converter_type,
        timeout_secs: config.jtd_timeout_secs,
        on_failure: failure_policy,
    };

    let pipeline = JtdConversionPipeline::new(pipeline_config);

    // Determine output directory (same directory as input file)
    let output_dir = file_path
        .parent()
        .unwrap_or_else(|| Path::new("."));

    // Execute conversion via the existing pipeline API
    match pipeline.process_file(file_path, output_dir).await {
        Ok(output) => {
            if output.was_converted && output.output_path.exists() {
                tracing::info!(
                    input = %file_path.display(),
                    output = %output.output_path.display(),
                    "JTD-to-PDF conversion completed successfully \
                     JTD->PDF\u{5909}\u{63db}\u{304c}\u{6b63}\u{5e38}\u{306b}\u{5b8c}\u{4e86}\u{3057}\u{307e}\u{3057}\u{305f}"
                );

                JtdHandleResult::Converted {
                    pdf_path: output.output_path.clone(),
                    original_path: file_path.to_path_buf(),
                }
            } else {
                // Pipeline returned without conversion (may be disabled or skipped)
                tracing::debug!(
                    input = %file_path.display(),
                    "JTD pipeline completed but no conversion performed"
                );
                JtdHandleResult::SkippedWithWarning {
                    original_path: file_path.to_path_buf(),
                    warning_message: "JTD pipeline did not produce converted output".to_string(),
                }
            }
        }
        Err(error) => {
            let error_msg = format!(
                "Error: JTD conversion pipeline error: {} \
                 \u{30a8}\u{30e9}\u{30fc}: JTD\u{5909}\u{63db}\u{30d1}\u{30a4}\u{30d7}\u{30e9}\u{30a4}\u{30f3}\u{30a8}\u{30e9}\u{30fc}: {}",
                error, error
            );

            eprintln!("{}", error_msg);

            JtdHandleResult::ConversionFailed {
                error_message: error_msg,
            }
        }
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Test: Non-JTD Files Pass Through
    // =========================================================================

    #[tokio::test]
    async fn test_non_jtd_file_returns_not_jtd() {
        let config = SenderConfig::default();
        let result = handle_jtd_upload(Path::new("document.pdf"), &config).await;

        assert!(
            matches!(result, JtdHandleResult::NotJtd { .. }),
            "Non-JTD file should return NotJtd variant"
        );
        assert!(!result.is_fatal(), "Non-JTD result should not be fatal");
        assert!(
            result.effective_path().is_some(),
            "Non-JTD result should have an effective path"
        );
    }

    #[tokio::test]
    async fn test_non_jtd_various_extensions() {
        let config = SenderConfig::default();

        let extensions = ["pdf", "docx", "xlsx", "txt", "zip", "jpg"];
        for ext in &extensions {
            let filename = format!("test.{}", ext);
            let path = Path::new(&filename);
            let result = handle_jtd_upload(path, &config).await;
            assert!(
                matches!(result, JtdHandleResult::NotJtd { .. }),
                "Extension .{} should return NotJtd",
                ext
            );
        }
    }

    // =========================================================================
    // Test: JTD File With Conversion Disabled Emits Warning
    // =========================================================================

    #[tokio::test]
    async fn test_jtd_file_disabled_conversion_emits_warning() {
        let mut config = SenderConfig::default();
        config.jtd_conversion_enabled = false;

        let temp_dir = tempfile::tempdir().expect("tempdir creation must succeed");
        let jtd_path = temp_dir.path().join("test.jtd");
        std::fs::write(&jtd_path, b"fake jtd content").expect("write must succeed");

        let result = handle_jtd_upload(&jtd_path, &config).await;

        match result {
            JtdHandleResult::SkippedWithWarning {
                ref original_path,
                ref warning_message,
            } => {
                assert_eq!(*original_path, jtd_path);
                assert!(
                    warning_message.contains("Ichitaro"),
                    "Warning must mention Ichitaro"
                );
                assert!(
                    warning_message.contains("--convert-jtd-to-pdf"),
                    "Warning must mention the flag name"
                );
                assert!(
                    warning_message.contains("\u{4e00}\u{592a}\u{90ce}"),
                    "Warning must contain Japanese text"
                );
                assert!(!result.is_fatal(), "SkippedWithWarning should not be fatal");
                assert!(
                    result.effective_path().is_some(),
                    "SkippedWithWarning should have effective path"
                );
            }
            other => panic!("Expected SkippedWithWarning, got {:?}", other),
        }
    }

    // =========================================================================
    // Test: JTD File With Conversion Enabled Uses Dummy Converter
    // =========================================================================

    #[tokio::test]
    async fn test_jtd_file_enabled_conversion_succeeds_with_dummy() {
        let mut config = SenderConfig::default();
        config.jtd_conversion_enabled = true;
        config.jtd_converter_type = "dummy".to_string();
        config.jtd_timeout_secs = 30;

        let temp_dir = tempfile::tempdir().expect("tempdir creation must succeed");
        let jtd_path = temp_dir.path().join("test_input.jtd");
        std::fs::write(&jtd_path, b"fake jtd content").expect("write must succeed");

        let result = handle_jtd_upload(&jtd_path, &config).await;

        match result {
            JtdHandleResult::Converted {
                ref pdf_path,
                ref original_path,
            } => {
                assert_eq!(*original_path, jtd_path);
                assert!(
                    pdf_path.exists(),
                    "Converted PDF file must exist on disk"
                );
                assert!(
                    pdf_path.extension().and_then(|e| e.to_str()) == Some("pdf"),
                    "Output must have .pdf extension"
                );
                assert!(!result.is_fatal(), "Converted result should not be fatal");
                assert_eq!(
                    result.effective_path(),
                    Some(pdf_path.as_path()),
                    "Effective path should point to PDF"
                );
            }
            other => panic!("Expected Converted, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_jtd_auto_converter_falls_back_to_dummy() {
        // Auto mode should fall back to dummy in CI where no real converters exist
        let mut config = SenderConfig::default();
        config.jtd_conversion_enabled = true;
        config.jtd_converter_type = "auto".to_string();

        let temp_dir = tempfile::tempdir().expect("tempdir creation must succeed");
        let jtd_path = temp_dir.path().join("auto_test.jtd");
        std::fs::write(&jtd_path, b"auto mode test").expect("write must succeed");

        let result = handle_jtd_upload(&jtd_path, &config).await;

        // Should succeed because Dummy is the final fallback in auto mode
        match result {
            JtdHandleResult::Converted { pdf_path, .. } => {
                assert!(
                    pdf_path.exists(),
                    "Auto mode should produce output via dummy fallback"
                );
            }
            JtdHandleResult::ConversionFailed { error_message } => {
                panic!("Auto mode should not fail with dummy fallback: {}", error_message);
            }
            other => panic!("Unexpected result: {:?}", other),
        }
    }

    // =========================================================================
    // Test: Case-Insensitive JTD Detection
    // =========================================================================

    #[tokio::test]
    async fn test_jtd_detection_case_insensitive() {
        let mut config = SenderConfig::default();
        config.jtd_conversion_enabled = false;

        let variants = [
            ("test.JTD", true),
            ("test.jtd", true),
            ("test.Jtd", true),
            ("test.jTd", true),
            ("test.pdf", false),
            ("test.jtdx", false),
        ];

        for (filename, expect_jtd) in &variants {
            let result = handle_jtd_upload(Path::new(filename), &config).await;
            let is_jtd = !matches!(result, JtdHandleResult::NotJtd { .. });
            assert_eq!(
                is_jtd, *expect_jtd,
                "File '{}' JTD detection mismatch: expected={}, got={}",
                filename, expect_jtd, is_jtd
            );
        }
    }

    // =========================================================================
    // Test: Effective Path Semantics
    // =========================================================================

    #[tokio::test]
    async fn test_effective_path_semantics() {
        let config = SenderConfig::default();

        // NotJtd returns original path
        let r1 = handle_jtd_upload(Path::new("file.pdf"), &config).await;
        assert!(r1.effective_path().is_some());
    }
}
