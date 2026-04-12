use clap::{ArgAction, Parser};
use std::path::PathBuf;


/// Command-line interface for the Misogi Sender node.
///
/// Provides all runtime configuration options that can override or supplement
/// the `misogi.toml` configuration file. CLI arguments take the highest
/// precedence in the configuration layer chain:
///
/// ```text
/// CLI Arguments > Environment Variables > TOML File > Built-in Defaults
/// ```
///
/// # Phase 5 Extended Options
///
/// Starting from Phase 5, the following new CLI arguments are available:
///
/// | Argument             | Description                                      | Example                  |
/// |----------------------|--------------------------------------------------|--------------------------|
/// | `--driver`           | Transfer driver type selection                   | `--driver storage_relay`  |
/// | `--preset`           | Apply named preset configuration profile         | `--preset lgwan_government`|
/// | `--calendar-file`    | Path to custom calendar.toml file               | `--calendar-file ./cal.toml`|
/// | `--log-format`       | Override audit log output format                 | `--log-format cef`         |
///
/// # Examples
///
/// ## Minimal Launch
///
/// ```bash
/// misogi-sender --config ./misogi.toml
/// ```
///
/// ## With Phase 5 Options
///
/// ```bash
/// misogi-sender \
///     --config ./misogi.toml \
///     --driver storage_relay \
///     --log-format cef \
///     --calendar-file /etc/misogi/calendar.toml \
///     --preset lgwan_government
/// ```
#[derive(Parser, Debug)]
#[command(name = "misogi-sender")]
#[command(about = "Misogi Sender - file upload and transfer initiation node")]
#[command(version)]
pub struct CommandLine {
    // ---- Core Options (Existing) ----

    /// Operational mode: server, client, or validate-config.
    #[arg(long, default_value = "server")]
    pub mode: String,

    /// Path to the configuration file (misogi.toml).
    ///
    /// If not specified, the sender will search for `misogi.toml` in the
    /// current working directory, then fall back to built-in defaults.
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Server bind address (overrides [server] addr in TOML).
    ///
    /// Format: `host:port`, e.g., `0.0.0.0:3001` or `127.0.0.1:8080`
    #[arg(long, default_value = "0.0.0.0:3001")]
    pub addr: Option<String>,

    /// Upload directory path (overrides [storage] upload_dir in TOML).
    #[arg(long, default_value = "./data/sender/uploads")]
    pub storage_dir: Option<String>,

    /// Staging directory path (overrides [storage] staging_dir in TOML).
    #[arg(long, default_value = "./data/sender/staging")]
    pub staging_dir: Option<String>,

    /// Tunnel server port (overrides [tunnel] local_port in TOML).
    #[arg(long, default_value = "9000")]
    pub tunnel_port: Option<u16>,

    /// Output file path for single-file mode (non-server operation).
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// Logging level: trace, debug, info, warn, error (default: info).
    #[arg(long, default_value = "info")]
    pub log_level: Option<String>,

    // ---- Phase 5 Extended Options ----

    /// Transfer driver type selection (overrides [transfer_driver] type in TOML).
    ///
    /// Available drivers:
    ///
    /// - `direct_tcp` — Direct TCP socket connection to receiver (default).
    ///   Requires network reachability between sender and receiver.
    ///
    /// - `storage_relay` — File-based relay through shared storage.
    ///   Used for air-gapped networks. Requires [transfer_driver] output_dir
    ///   and input_dir to be configured in TOML.
    ///
    /// - `external_command` — Delegate to third-party transfer tool.
    ///   Requires [transfer_driver] send_command and status_command in TOML.
    ///
    /// # Examples
    ///
    /// ```bash
    /// # Use storage relay driver
    /// misogi-sender --driver storage_relay
    ///
    /// # Use external command driver
    /// misogi-sender --driver external_command
    /// ```
    #[arg(long)]
    pub driver: Option<String>,

    /// Apply a named preset configuration profile.
    ///
    /// Presets provide pre-tuned configurations for common deployment scenarios.
    /// When specified, preset values are applied AFTER TOML loading but BEFORE
    /// environment variable overrides, allowing per-environment customization.
    ///
    /// # Available Presets
    ///
    /// | Preset                | Description                                           |
    /// |----------------------|-------------------------------------------------------|
    /// | `lgwan_government`   | LGWAN-compliant Japanese government configuration.     |
    /// |                      | Enables: approval_flow, PII detection, CDR, vendor isolation. |
    /// | `medical_hipaa_jp`  | Japanese medical institution (HIPAA-aligned) config.    |
    /// |                      | Enables: strict CDR, ClamAV, PII masking, audit logging. |
    /// | `sler_general`      | General SLER (System Local Emergency Response) config. |
    /// |                      | Balanced security with operational flexibility.        |
    ///
    /// # Preset Application Order
    ///
    /// ```text
    /// 1. Load misogi.toml (base configuration)
    /// 2. Apply preset overlays (modify/add fields)
    /// 3. Apply MISOGI_* environment variables (highest runtime override)
    /// 4. Apply CLI arguments (absolute highest priority)
    /// ```
    ///
    /// # Example
    ///
    /// ```bash
    /// misogi-sender --config base.toml --preset lgwan_government
    /// ```
    #[arg(long)]
    pub preset: Option<String>,

    /// Path to custom calendar.toml file for Japanese calendar integration.
    ///
    /// Overrides [calendar] calendar_file in TOML. Specifies the location of
    /// a supplementary holiday database in TOML format containing organizational
    /// or prefectural non-business days beyond the built-in national holidays.
    ///
    /// # Calendar File Format
    ///
    /// ```toml
    /// [[holidays]]
    /// date = "2026-08-13"
    /// name_jp = "お盆休み"
    /// category = "organizational"
    /// ```
    ///
    /// # Example
    ///
    /// ```bash
    /// misogi-sender --calendar-file /etc/misogi/calendar.toml
    /// ```
    #[arg(long)]
    pub calendar_file: Option<PathBuf>,

    /// Override audit log output format (overrides [log] format in TOML).
    ///
    /// Available formats:
    ///
    /// - `json` — JSON Lines format (default). One JSON object per line.
    ///   Compatible with Fluentd, Vector, and most log aggregators.
    ///
    /// - `syslog` — Syslog-compatible structured text format.
    ///   Suitable for rsyslog/syslog-ng forwarding.
    ///
    /// - `cef` — Common Event Format (CEF) for SIEM integration.
    ///   Required by ArcSight ESM, QRadar, Splunk Enterprise Security.
    ///
    /// - `custom` — User-defined Tera template format.
    ///   Requires [log] template_path to be set in TOML or environment.
    ///
    /// # Example
    ///
    /// ```bash
    /// # Use CEF format for SIEM integration
    /// misogi-sender --log-format cef
    /// ```
    #[arg(long)]
    pub log_format: Option<String>,

    /// Scan a file for PPAP (Password Protected Attachment Protocol) indicators.
    ///
    /// When set, runs standalone PPAP detection on the specified file path
    /// and prints results as JSON to stdout, then exits. Does not start server.
    ///
    /// # Example
    ///
    /// ```bash
    /// misogi-sender --ppap-detect ./sensitive_document.zip
    /// ```
    #[arg(long)]
    pub ppap_detect: Option<PathBuf>,

    // --- JTD (Ichitaro) Conversion Options ---
    // These arguments control automatic JTD-to-PDF conversion before CDR processing.
    // All JTD conversion features are opt-in; they do not affect non-JTD files.

    /// Enable automatic conversion of Ichitaro (.jtd) documents to PDF before CDR sanitization.
    ///
    /// When enabled and a .jtd file is detected as input, the file is first converted
    /// to PDF using the configured converter (LibreOffice or Ichitaro Viewer), then the
    /// resulting PDF proceeds through the normal CDR pipeline.
    ///
    /// Requires LibreOffice (`soffice`) or Ichitaro Viewer installation depending on
    /// the selected converter type. Use --jtd-converter to specify which engine to use.
    ///
    /// 一太郎 (.jtd) ファイルをPDFに自動変換してからCDR処理を行います。
    /// LibreOfficeまたは一太郎ビューアのインストールが必要です。
    #[arg(
        long = "convert-jtd-to-pdf",
        action = ArgAction::SetTrue,
        global = true,
        help_heading = "JTD Conversion Options",
        display_order = 100,
    )]
    pub convert_jtd_to_pdf: bool,

    /// Explicitly disable automatic JTD-to-PDF conversion.
    ///
    /// Overrides any configuration file setting that enables JTD conversion.
    /// Useful when you want to ensure no conversion occurs regardless of config.
    ///
    /// JTD変換を明示的に無効化します。設定ファイルの指定より優先されます。
    #[arg(
        long = "no-convert-jtd-to-pdf",
        action = ArgAction::SetTrue,
        global = true,
        help_heading = "JTD Conversion Options",
        display_order = 101,
        conflicts_with = "convert_jtd_to_pdf",
    )]
    pub no_convert_jtd_to_pdf: bool,

    /// JTD converter backend to use for document transformation.
    ///
    /// Available converters:
    /// - `auto`: Automatically select the best available converter (default).
    ///   Priority: ichitaro_viewer → libreoffice → dummy (fallback)
    /// - `libreoffice`: Use LibreOffice headless mode (cross-platform, high fidelity).
    /// - `ichitaro_viewer`: Use Ichitaro Viewer CLI (Windows-only, native fidelity).
    /// - `dummy`: Generate placeholder PDF without real conversion (testing only).
    ///
    /// 使用するJTD変換エンジンを指定します。デフォルトは自動選択です。
    #[arg(
        long = "jtd-converter",
        value_name = "TYPE",
        default_value = "auto",
        global = true,
        help_heading = "JTD Conversion Options",
        display_order = 102,
        value_parser = validate_jtd_converter_type,
    )]
    pub jtd_converter: String,

    /// Maximum time in seconds allowed for a single JTD-to-PDF conversion operation.
    ///
    /// If the conversion process exceeds this timeout, it will be terminated and
    /// treated as a failure according to the configured failure policy.
    /// Default: 120 seconds. Minimum recommended: 30 seconds.
    ///
    /// JTD変換のタイムアウト時間（秒）。デフォルトは120秒です。
    #[arg(
        long = "jtd-timeout",
        value_name = "SECONDS",
        default_value = "120",
        global = true,
        help_heading = "JTD Conversion Options",
        display_order = 103,
        value_parser = clap::value_parser!(u64).range(10..=3600),
    )]
    pub jtd_timeout_secs: u64,
}

// =============================================================================
// CLI Argument Validators
// =============================================================================

/// Validate that a JTD converter type string is a recognized value.
///
/// Accepts: `auto`, `libreoffice`, `ichitaro_viewer`, `dummy` (case-insensitive).
/// Also accepts common aliases: `lo` (libreoffice), `ichitaro` (ichitaro_viewer),
/// `test`/`placeholder` (dummy).
///
/// # Arguments
/// * `s` - The raw string value from the CLI argument.
///
/// # Returns
/// The normalized lowercase converter type string on success.
///
/// # Errors
/// Returns a clap error with valid options listed if the value is unrecognized.
fn validate_jtd_converter_type(s: &str) -> Result<String, String> {
    let valid_values = ["auto", "libreoffice", "ichitaro_viewer", "dummy"];
    let aliases = [
        ("lo", "libreoffice"),
        ("soffice", "libreoffice"),
        ("automatic", "auto"),
        ("ichitaro", "ichitaro_viewer"),
        ("viewer", "ichitaro_viewer"),
        ("test", "dummy"),
        ("placeholder", "dummy"),
    ];

    // Check direct match (case-insensitive)
    if valid_values.contains(&s.to_lowercase().as_str()) {
        return Ok(s.to_lowercase());
    }

    // Check aliases
    for (alias, canonical) in &aliases {
        if s.eq_ignore_ascii_case(alias) {
            tracing::debug!(
                original = s,
                resolved = canonical,
                "JTD converter alias resolved"
            );
            return Ok(canonical.to_string());
        }
    }

    Err(format!(
        "Invalid JTD converter type: '{s}'. Valid values: {} \
         無効なJTD変換エンジン: '{s}'。有効な値: {}",
        valid_values.join(", "),
        valid_values.join(", ")
    ))
}
