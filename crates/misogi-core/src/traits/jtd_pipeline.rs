// =============================================================================
// JtdConversionPipeline — JTD-to-PDF Conversion Pipeline Coordinator
// =============================================================================
// This module implements the pipeline orchestrator that integrates multiple
// [`JtdConverter`] backends into Misogi's CDR (Content Disarm & Reconstruction)
// processing flow for Japanese Ichitaro `.jtd` document files.
//
// Architecture Role:
// The pipeline serves as the single entry point for all JTD conversion operations.
// It encapsulates converter selection, failure policy enforcement, and output
// management behind a clean async interface consumed by higher-level CDR stages.
//
// Design Decisions:
// - Opt-in activation: The pipeline is disabled by default (`enabled: false`)
//   to prevent unexpected behavior in deployments without JTD support requirements.
// - Auto-detection mode: When `converter_type` is `Auto`, the pipeline probes
//   converters in priority order (LibreOffice > IchitaroViewer > Dummy) and uses
//   the first available backend.
// - Failure policy: Configurable behavior on conversion failure allows operators
//   to choose between strict blocking (Block), lenient continuation with warning
//   (Warn), or silent skip (Skip) based on organizational security posture.
//
// Integration Point:
// This module is a bridge/adapter — actual routing of `.jtd` files to this
// pipeline happens at a higher level (CLI/engine layer). The [`should_convert_jtd()`]
// helper provides the extension check that routing logic should use.
//
// Thread Safety:
// The pipeline holds `Arc<dyn JtdConverter>` trait objects which are inherently
// `Send + Sync`. Multiple concurrent `process_file()` calls are safe as each
// invocation operates on independent input/output paths.
//
// References:
// - JtdConverter trait: super::jtd_converter::JtdConverter
// - CDR Strategy: super::CDRStrategy
// =============================================================================

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use toml::Value;

use crate::error::{MisogiError, Result};

use super::jtd_converter::{JtdConversionResult, JtdConverter};
use super::jtd_dummy::{DummyAction, DummyJtdConverter};
use super::jtd_ichitaro::IchitaroViewerConverter;
use super::jtd_libreoffice::LibreOfficeJtdConverter;

// =============================================================================
// Configuration Types
// =============================================================================

/// Specifies which converter backend the pipeline should use.
///
/// Each variant maps to a concrete implementation of [`JtdConverter`]:
///
/// | Variant            | Backend                        | Platform       |
/// |--------------------|--------------------------------|----------------|
/// | `LibreOffice`      | LibreOffice headless           | Cross-platform |
/// | `IchitaroViewer`   | Ichitaro Viewer CLI            | Windows only   |
/// | `Dummy`            | Placeholder PDF generator      | Any            |
/// | `Auto`             | Auto-detect (priority order)   | Any            |
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum JtdConverterType {
    /// Use LibreOffice headless conversion backend.
    LibreOffice,

    /// Use Ichitaro Viewer command-line interface (Windows-only).
    IchitaroViewer,

    /// Use placeholder/dummy converter (no external dependencies).
    #[serde(rename = "dummy")]
    Dummy {
        /// Behavior mode for the dummy converter.
        action: DummyAction,
    },

    /// Auto-detect best available converter in priority order:
    /// LibreOffice -> IchitaroViewer -> Dummy.
    Auto,
}

impl Default for JtdConverterType {
    /// Defaults to [`JtdConverterType::Auto`] for maximum compatibility.
    fn default() -> Self {
        Self::Auto
    }
}

/// Policy governing pipeline behavior when conversion fails.
///
/// Selected based on organizational security posture and operational requirements:
/// - **High-security environments**: Use `Block` to reject any unconvertible files.
/// - **Development/testing**: Use `Warn` to continue while logging issues.
/// - **Best-effort processing**: Use `Skip` to silently bypass failures.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum JtdFailurePolicy {
    /// Reject the entire transfer when conversion fails.
    Block,

    /// Log a warning but continue with the original (unconverted) file.
    Warn,

    /// Skip this file silently — return an empty/skip marker.
    Skip,
}

impl Default for JtdFailurePolicy {
    /// Defaults to [`JtdFailurePolicy::Warn`] as a balanced safe default.
    fn default() -> Self {
        Self::Warn
    }
}

/// Configuration for the JTD conversion pipeline.
///
/// Deserialized from TOML configuration under `[jtd_converter]` section:
///
/// ```toml
/// [jtd_converter]
/// enabled = true
/// type = "libreoffice"  # or "ichitaro_viewer", "dummy", "auto"
/// timeout_secs = 120
/// on_failure = "warn"   # or "block", "skip"
///
/// [jtd_converter.dummy]
/// action = "placeholder_pdf"  # or "error"
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JtdPipelineConfig {
    /// Whether the JTD conversion pipeline is active.
    #[serde(default)]
    pub enabled: bool,

    /// Which converter backend to use (or auto-detection strategy).
    #[serde(rename = "type")]
    pub converter_type: JtdConverterType,

    /// Override timeout in seconds for individual conversion operations.
    #[serde(default, rename = "timeout_secs")]
    pub timeout_secs: u64,

    /// How to handle conversion failures.
    #[serde(rename = "on_failure")]
    pub on_failure: JtdFailurePolicy,
}

impl Default for JtdPipelineConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            converter_type: JtdConverterType::Auto,
            timeout_secs: 0,
            on_failure: JtdFailurePolicy::Warn,
        }
    }
}

// =============================================================================
// Output Type
// =============================================================================

/// Result produced by [`JtdConversionPipeline::process_file()`].
///
/// Encapsulates all observable outcomes of a single pipeline execution.
/// Does not derive Clone because [`JtdConversionError`] is not Clone-safe.
#[derive(Debug)]
pub struct PipelineOutput {
    /// Path to the output file (converted PDF or original if skipped/unconverted).
    pub output_path: PathBuf,

    /// Whether an actual JTD-to-PDF conversion was performed.
    pub was_converted: bool,

    /// Conversion result metadata, populated only when `was_converted` is true.
    pub conversion_result: Option<JtdConversionResult>,

    /// Non-fatal warnings collected during processing.
    pub warnings: Vec<String>,
}

// =============================================================================
// Pipeline Implementation
// =============================================================================

/// Orchestrator for JTD-to-PDF conversion within the CDR pipeline.
///
/// Processing flow:
/// ```text
/// Input .jtd --> Enabled? --No--> Return original
///                   Yes
///               Select converter (Auto probes LibreOffice > Ichitaro > Dummy)
///               Execute convert_to_pdf()
///                 Success --> Return PDF path
///                 Failure  --> Apply failure policy (Block/Warn/Skip)
/// ```
pub struct JtdConversionPipeline {
    /// Pipeline configuration controlling behavior and policy.
    config: JtdPipelineConfig,

    /// Registered converter backends in priority order.
    converters: Vec<Arc<dyn JtdConverter>>,
}

impl JtdConversionPipeline {
    /// Create a new pipeline instance from explicit configuration.
    ///
    /// For [`JtdConverterType::Auto`], registers all three backends so that
    /// [`select_converter()`](Self::select_converter) can probe them at runtime.
    pub fn new(config: JtdPipelineConfig) -> Self {
        let converters = Self::build_converters(&config);

        tracing::debug!(
            enabled = config.enabled,
            converter_type = ?config.converter_type,
            converter_count = converters.len(),
            timeout_override = config.timeout_secs,
            failure_policy = ?config.on_failure,
            "JTD conversion pipeline initialized"
        );

        Self { config, converters }
    }

    /// Construct the converter list from the configured type.
    fn build_converters(config: &JtdPipelineConfig) -> Vec<Arc<dyn JtdConverter>> {
        match &config.converter_type {
            JtdConverterType::LibreOffice => {
                vec![Arc::new(LibreOfficeJtdConverter::new()) as Arc<dyn JtdConverter>]
            }
            JtdConverterType::IchitaroViewer => {
                vec![Arc::new(IchitaroViewerConverter::new()) as Arc<dyn JtdConverter>]
            }
            JtdConverterType::Dummy { action } => {
                vec![Arc::new(DummyJtdConverter::new(action.clone())) as Arc<dyn JtdConverter>]
            }
            JtdConverterType::Auto => {
                // Priority order: LibreOffice > IchitaroViewer > Dummy (fallback)
                vec![
                    Arc::new(LibreOfficeJtdConverter::new()) as Arc<dyn JtdConverter>,
                    Arc::new(IchitaroViewerConverter::new()) as Arc<dyn JtdConverter>,
                    Arc::new(DummyJtdConverter::default()) as Arc<dyn JtdConverter>,
                ]
            }
        }
    }

    /// Create a pipeline from parsed TOML configuration value.
    ///
    /// Expects a TOML table matching the `[jtd_converter]` schema.
    pub fn from_toml(toml_value: &Value) -> Result<Self> {
        let config: JtdPipelineConfig = toml_value
            .clone()
            .try_into()
            .map_err(|e| MisogiError::Configuration(format!("invalid jtd_converter config: {e}")))?;

        Ok(Self::new(config))
    }

    /// Process a single `.jtd` file through the conversion pipeline.
    ///
    /// This is the primary entry point invoked by the CDR engine for each
    /// JTD file encountered during transfer processing.
    pub async fn process_file(
        &self,
        input_path: &Path,
        temp_dir: &Path,
    ) -> Result<PipelineOutput> {
        let mut warnings = Vec::new();

        // Step 1: Check if pipeline is enabled
        if !self.config.enabled {
            tracing::debug!(
                input = %input_path.display(),
                "JTD pipeline disabled; returning original file"
            );
            return Ok(PipelineOutput {
                output_path: input_path.to_path_buf(),
                was_converted: false,
                conversion_result: None,
                warnings,
            });
        }

        // Step 2: Select appropriate converter
        let converter = match self.select_converter().await {
            Some(c) => c,
            None => {
                let msg = "No JTD converter available".to_string();
                tracing::warn!(error = %msg, "No usable converter found");
                warnings.push(msg.clone());

                return match &self.config.on_failure {
                    JtdFailurePolicy::Block => Err(MisogiError::Protocol(msg)),
                    JtdFailurePolicy::Warn => Ok(PipelineOutput {
                        output_path: input_path.to_path_buf(),
                        was_converted: false,
                        conversion_result: None,
                        warnings,
                    }),
                    JtdFailurePolicy::Skip => Ok(PipelineOutput {
                        output_path: PathBuf::new(),
                        was_converted: false,
                        conversion_result: None,
                        warnings,
                    }),
                };
            }
        };

        tracing::info!(
            input = %input_path.display(),
            converter = %converter.name(),
            temp_dir = %temp_dir.display(),
            "Starting JTD conversion"
        );

        // Step 3: Determine output path and execute conversion
        let stem = input_path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy();
        let output_path = temp_dir.join(format!("{stem}.pdf"));

        match converter.convert_to_pdf(input_path, &output_path).await {
            Ok(result) => {
                tracing::info!(
                    converter = %result.converter_used,
                    output = %result.output_path.display(),
                    size_bytes = result.converted_size_bytes,
                    time_ms = result.conversion_time_ms,
                    "JTD conversion completed successfully"
                );
                Ok(PipelineOutput {
                    output_path: result.output_path.clone(),
                    was_converted: true,
                    conversion_result: Some(result),
                    warnings,
                })
            }
            Err(err) => {
                let msg = format!("JTD conversion failed: {err}");
                tracing::warn!(
                    error = %err,
                    error_code = %err.error_code(),
                    converter = %converter.name(),
                    policy = ?self.config.on_failure,
                    "{msg}"
                );
                warnings.push(msg);

                match &self.config.on_failure {
                    JtdFailurePolicy::Block => Err(MisogiError::Protocol(format!(
                        "JTD conversion blocked: {err}"
                    ))),
                    JtdFailurePolicy::Warn => Ok(PipelineOutput {
                        output_path: input_path.to_path_buf(),
                        was_converted: false,
                        conversion_result: None,
                        warnings,
                    }),
                    JtdFailurePolicy::Skip => Ok(PipelineOutput {
                        output_path: PathBuf::new(),
                        was_converted: false,
                        conversion_result: None,
                        warnings,
                    }),
                }
            }
        }
    }

    /// Select the first available converter from the registered list.
    ///
    /// Probes each converter via [`JtdConverter::is_available()`] and returns
    /// the first one reporting `Ok(true)`.
    pub async fn select_converter(&self) -> Option<Arc<dyn JtdConverter>> {
        for converter in &self.converters {
            tracing::debug!(
                candidate = %converter.name(),
                "Probing converter availability"
            );

            match converter.is_available().await {
                Ok(true) => {
                    tracing::info!(selected = %converter.name(), "Converter selected");
                    return Some(Arc::clone(converter));
                }
                Ok(false) => {
                    tracing::debug!(
                        candidate = %converter.name(),
                        "Converter not available; trying next"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        candidate = %converter.name(),
                        error = %e,
                        "Availability check errored; trying next"
                    );
                }
            }
        }

        tracing::warn!("No converter available after probing all candidates");
        None
    }

    /// Get a reference to the pipeline configuration.
    #[must_use]
    pub const fn config(&self) -> &JtdPipelineConfig {
        &self.config
    }

    /// Get the number of registered converters.
    #[must_use]
    pub fn converter_count(&self) -> usize {
        self.converters.len()
    }
}

// =============================================================================
// FileTypeDetector Bridge Helper
// =============================================================================

/// Determine whether a file extension indicates a JTD document requiring conversion.
///
/// Higher-level code (CLI/engine) should call this function to decide whether
/// to route a file through [`JtdConversionPipeline`].
#[must_use]
pub fn should_convert_jtd(extension: &str) -> bool {
    let ext = extension.trim_start_matches('.').to_lowercase();
    ext == "jtd"
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "misogi_pipeline_test_{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir creation must succeed");
        dir
    }

    fn create_input_file(path: &Path, size_bytes: usize) {
        let data = vec![0x42u8; size_bytes];
        std::fs::write(path, &data).expect("input file creation must succeed");
    }

    fn make_toml_config(enabled: bool, type_str: &str, timeout: u64, on_failure: &str) -> Value {
        let toml_str = format!(
            r#"
            enabled = {enabled}
            type = "{type_str}"
            timeout_secs = {timeout}
            on_failure = "{on_failure}"
        "#
        );
        toml_str.parse::<Value>().expect("TOML must parse")
    }

    // -----------------------------------------------------------------
    // Group 1: Configuration and Construction
    // -----------------------------------------------------------------

    #[test]
    fn test_default_config_is_disabled() {
        let config = JtdPipelineConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.converter_type, JtdConverterType::Auto);
        assert_eq!(config.on_failure, JtdFailurePolicy::Warn);
        assert_eq!(config.timeout_secs, 0);
    }

    #[test]
    fn test_pipeline_new_with_disabled_config() {
        let pipeline = JtdConversionPipeline::new(JtdPipelineConfig::default());
        assert!(!pipeline.config().enabled);
    }

    #[test]
    fn test_pipeline_new_with_enabled_dummy_config() {
        let config = JtdPipelineConfig {
            enabled: true,
            converter_type: JtdConverterType::Dummy {
                action: DummyAction::PlaceholderPdf,
            },
            ..Default::default()
        };
        let pipeline = JtdConversionPipeline::new(config);
        assert!(pipeline.config().enabled);
        assert_eq!(pipeline.converter_count(), 1);
    }

    #[test]
    fn test_pipeline_auto_mode_registers_three_converters() {
        let config = JtdPipelineConfig {
            enabled: true,
            converter_type: JtdConverterType::Auto,
            ..Default::default()
        };
        let pipeline = JtdConversionPipeline::new(config);
        assert_eq!(pipeline.converter_count(), 3);
    }

    // -----------------------------------------------------------------
    // Group 2: TOML Configuration Parsing
    // -----------------------------------------------------------------

    #[test]
    fn test_from_toml_valid_full_config() {
        let toml_val = make_toml_config(true, "libreoffice", 180, "block");
        let pipeline = JtdConversionPipeline::from_toml(&toml_val).unwrap();

        assert!(pipeline.config().enabled);
        assert_eq!(pipeline.config().converter_type, JtdConverterType::LibreOffice);
        assert_eq!(pipeline.config().timeout_secs, 180);
        assert_eq!(pipeline.config().on_failure, JtdFailurePolicy::Block);
    }

    #[test]
    fn test_from_toml_minimal_config_uses_defaults() {
        // Only provide 'enabled'; converter_type and on_failure are required
        // fields (no #[serde(default)]), so they must be present.
        let toml_val: Value = r#"
            enabled = true
            type = "auto"
            on_failure = "warn"
        "#
        .parse()
        .unwrap();

        let pipeline = JtdConversionPipeline::from_toml(&toml_val).unwrap();

        assert!(pipeline.config().enabled);
        assert_eq!(pipeline.config().converter_type, JtdConverterType::Auto);
        assert_eq!(pipeline.config().on_failure, JtdFailurePolicy::Warn);
        // timeout_secs has #[serde(default)], so it defaults to 0
        assert_eq!(pipeline.config().timeout_secs, 0);
    }

    #[test]
    fn test_from_toml_invalid_type_rejects() {
        // Without #[serde(default)] on converter_type, unknown types cause errors
        let toml_val: Value = r#"
            enabled = true
            type = "nonexistent_converter"
            on_failure = "warn"
        "#.parse()
        .unwrap();

        assert!(JtdConversionPipeline::from_toml(&toml_val).is_err());
    }

    #[test]
    fn test_from_toml_dummy_action_parsing() {
        let toml_val: Value = r#"
            enabled = true
            type = { dummy = { action = "placeholder_pdf" } }
            on_failure = "warn"
        "#.parse().unwrap();

        let pipeline = JtdConversionPipeline::from_toml(&toml_val).unwrap();
        assert!(matches!(
            pipeline.config().converter_type,
            JtdConverterType::Dummy {
                action: DummyAction::PlaceholderPdf
            }
        ));
    }

    // -----------------------------------------------------------------
    // Group 3: Converter Selection Logic (Auto Mode Priority)
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn test_select_converter_auto_returns_available() {
        let config = JtdPipelineConfig {
            enabled: true,
            converter_type: JtdConverterType::Auto,
            ..Default::default()
        };
        let pipeline = JtdConversionPipeline::new(config);

        // At minimum, the dummy converter should be selectable
        assert!(pipeline.select_converter().await.is_some());
    }

    #[tokio::test]
    async fn test_select_converter_specific_type_returns_it() {
        let config = JtdPipelineConfig {
            enabled: true,
            converter_type: JtdConverterType::Dummy {
                action: DummyAction::PlaceholderPdf,
            },
            ..Default::default()
        };
        let pipeline = JtdConversionPipeline::new(config);
        let selected = pipeline.select_converter().await;

        assert!(selected.is_some());
        assert_eq!(selected.unwrap().name(), "dummy");
    }

    // -----------------------------------------------------------------
    // Group 4: Disabled Pipeline Returns Original File
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn test_disabled_pipeline_returns_original_file() {
        let temp_dir = setup_temp_dir();
        let input_path = temp_dir.join("disabled_test.jtd");
        create_input_file(&input_path, 100);

        let pipeline =
            JtdConversionPipeline::new(JtdPipelineConfig::default());
        let output = pipeline.process_file(&input_path, &temp_dir).await.unwrap();

        assert!(!output.was_converted);
        assert_eq!(output.output_path, input_path);
        assert!(output.conversion_result.is_none());
        assert!(output.warnings.is_empty());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    // -----------------------------------------------------------------
    // Group 5: Successful Conversion Flow
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn test_successful_conversion_produces_output() {
        let temp_dir = setup_temp_dir();
        let input_path = temp_dir.join("success_test.jtd");
        create_input_file(&input_path, 2048);

        let config = JtdPipelineConfig {
            enabled: true,
            converter_type: JtdConverterType::Dummy {
                action: DummyAction::PlaceholderPdf,
            },
            ..Default::default()
        };
        let pipeline = JtdConversionPipeline::new(config);
        let output = pipeline.process_file(&input_path, &temp_dir).await.unwrap();

        assert!(output.was_converted);
        assert!(output.output_path.exists());
        assert!(output.conversion_result.is_some());

        let result = output.conversion_result.as_ref().unwrap();
        assert!(result.success);
        assert!(result.converted_size_bytes > 0);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    // -----------------------------------------------------------------
    // Group 6: Failure Handling Per Policy
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn test_failure_policy_block_returns_error() {
        let temp_dir = setup_temp_dir();
        let input_path = temp_dir.join("block_test.jtd");
        create_input_file(&input_path, 100);

        let config = JtdPipelineConfig {
            enabled: true,
            converter_type: JtdConverterType::Dummy {
                action: DummyAction::Error,
            },
            on_failure: JtdFailurePolicy::Block,
            ..Default::default()
        };
        let pipeline = JtdConversionPipeline::new(config);
        let result = pipeline.process_file(&input_path, &temp_dir).await;

        assert!(result.is_err(), "Block policy must return error");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_failure_policy_warn_returns_original_with_warning() {
        let temp_dir = setup_temp_dir();
        let input_path = temp_dir.join("warn_test.jtd");
        create_input_file(&input_path, 100);

        let config = JtdPipelineConfig {
            enabled: true,
            converter_type: JtdConverterType::Dummy {
                action: DummyAction::Error,
            },
            on_failure: JtdFailurePolicy::Warn,
            ..Default::default()
        };
        let pipeline = JtdConversionPipeline::new(config);
        let output = pipeline
            .process_file(&input_path, &temp_dir)
            .await
            .expect("Warn policy must return Ok");

        assert!(!output.was_converted);
        assert_eq!(output.output_path, input_path);
        assert!(!output.warnings.is_empty());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_failure_policy_skip_returns_empty_marker() {
        let temp_dir = setup_temp_dir();
        let input_path = temp_dir.join("skip_test.jtd");
        create_input_file(&input_path, 100);

        let config = JtdPipelineConfig {
            enabled: true,
            converter_type: JtdConverterType::Dummy {
                action: DummyAction::Error,
            },
            on_failure: JtdFailurePolicy::Skip,
            ..Default::default()
        };
        let pipeline = JtdConversionPipeline::new(config);
        let output = pipeline
            .process_file(&input_path, &temp_dir)
            .await
            .expect("Skip policy must return Ok");

        assert!(!output.was_converted);
        assert!(output.output_path.as_os_str().is_empty());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    // -----------------------------------------------------------------
    // Group 7: FileTypeDetector Bridge Helper
    // -----------------------------------------------------------------

    #[test]
    fn test_should_convert_jtd_recognizes_jtd_extensions() {
        assert!(should_convert_jtd("jtd"));
        assert!(should_convert_jtd(".jtd"));
        assert!(should_convert_jtd("JTD"));
        assert!(should_convert_jtd(".JTD"));
        assert!(should_convert_jtd("Jtd"));
    }

    #[test]
    fn test_should_convert_jtd_rejects_non_jtd() {
        assert!(!should_convert_jtd("pdf"));
        assert!(!should_convert_jtd(".pdf"));
        assert!(!should_convert_jtd("docx"));
        assert!(!should_convert_jtd(""));
        assert!(!should_convert_jtd("jtdx"));
    }

    // -----------------------------------------------------------------
    // Group 8: Edge Cases
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn test_process_file_empty_input_file() {
        let temp_dir = setup_temp_dir();
        let input_path = temp_dir.join("empty.jtd");
        std::fs::write(&input_path, b"").unwrap();

        let config = JtdPipelineConfig {
            enabled: true,
            converter_type: JtdConverterType::Dummy {
                action: DummyAction::PlaceholderPdf,
            },
            ..Default::default()
        };
        let pipeline = JtdConversionPipeline::new(config);
        let result = pipeline.process_file(&input_path, &temp_dir).await;

        assert!(result.is_ok(), "Empty input should succeed with dummy converter");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_cleanup_behavior_on_success() {
        let temp_dir = setup_temp_dir();
        let input_path = temp_dir.join("cleanup_test.jtd");
        create_input_file(&input_path, 512);

        let config = JtdPipelineConfig {
            enabled: true,
            converter_type: JtdConverterType::Dummy {
                action: DummyAction::PlaceholderPdf,
            },
            ..Default::default()
        };
        let pipeline = JtdConversionPipeline::new(config);
        let output = pipeline.process_file(&input_path, &temp_dir).await.unwrap();

        assert!(output.output_path.exists());
        let pdf_bytes = std::fs::read(&output.output_path).unwrap();
        assert!(pdf_bytes.starts_with(b"%PDF"));

        // Verify no leftover .tmp files
        let tmp_files: Vec<_> = std::fs::read_dir(&temp_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(tmp_files.is_empty(), "No .tmp files should remain");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_config_serialization_roundtrip() {
        let config = JtdPipelineConfig {
            enabled: true,
            converter_type: JtdConverterType::Auto,
            timeout_secs: 300,
            on_failure: JtdFailurePolicy::Block,
        };

        let json = serde_json::to_string(&config).expect("serialization must succeed");
        let deserialized: JtdPipelineConfig =
            serde_json::from_str(&json).expect("deserialization must succeed");

        assert_eq!(deserialized.enabled, config.enabled);
        assert_eq!(deserialized.converter_type, config.converter_type);
        assert_eq!(deserialized.timeout_secs, config.timeout_secs);
        assert_eq!(deserialized.on_failure, config.on_failure);
    }
}
