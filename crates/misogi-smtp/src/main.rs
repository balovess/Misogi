//! Misogi SMTP Gateway — Binary entry point.
//!
//! This is the executable entry point for the `misogi-smtp` command-line tool.
//! It loads configuration, initializes logging, and starts the SMTP gateway server.
//!
//! # Usage
//!
//! ```text
//! misogi-smtp --config /etc/misogi/smtp.toml
//! ```
//!
//! # Configuration
//!
//! The configuration file is in TOML format. See `SmtpServerConfig` fields
//! for available options and their defaults.
//!
//! # Signals
//!
//! - SIGTERM / SIGINT (Unix) or Ctrl+C (Windows): Graceful shutdown
//!
//! # Exit Codes
//!
//! | Code | Meaning |
/// |------|---------|
/// | 0    | Normal shutdown (via signal or clean exit) |
/// | 1    | Configuration error (invalid config file, missing required fields) |
/// | 2    | Runtime error (bind failure, permission denied, etc.) |

use clap::Parser;
use std::path::PathBuf;
use tracing::info;

#[derive(Parser, Debug)]
#[command(
    name = "misogi-smtp",
    version,
    about = "Misogi Email Sanitization Gateway — SMTP proxy with CDR pipeline integration",
    long_about = "Intercepts email messages, extracts attachments, routes through \
                  Content Disarm and Reconstruction pipeline, reassembles sanitized emails, \
                  and relays to destination."
)]
struct Cli {
    /// Path to configuration file (TOML format).
    #[arg(short, long, default_value = "/etc/misogi/smtp.toml")]
    config: PathBuf,

    /// Increase logging verbosity (-v=info, -vv=debug, -vvv=trace).
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Validate configuration and exit without starting server.
    #[arg(long)]
    check: bool,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize tracing subscriber based on verbosity level
    let log_level = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| {
                    tracing_subscriber::EnvFilter::new(format!(
                        "misogi_smtp={},tokio=warn,tower_http=warn",
                        log_level
                    ))
                }),
        )
        .with_target(false)
        .with_thread_ids(true)
        .init();

    // Load and validate configuration
    let config = load_config(&cli.config)?;

    if cli.check {
        println!("Configuration file '{}' is valid.", cli.config.display());
        std::process::exit(0);
    }

    // Run the async server
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(num_cpus::get().max(2))
        .enable_all()
        .thread_name("misogi-smtp-worker")
        .build()?;

    runtime.block_on(async {
        let server = misogi_smtp::server::SmtpServer::new(config)?;

        // Register signal handler for graceful shutdown
        let server_clone = server.clone();
        tokio::spawn(async move {
            #[cfg(unix)]
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut sig) => {
                    sig.recv().await;
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to register SIGTERM handler");
                }
            }

            #[cfg(windows)]
            // On Windows, Ctrl+C is handled by tokio's ctrl_c
            if let Ok(()) = tokio::signal::ctrl_c().await {
                // Signal received
            }

            if let Err(e) = server_clone.shutdown().await {
                tracing::error!(error = %e, "Shutdown error");
            }
        });

        // Run the server (blocks until shutdown)
        if let Err(e) = server.run().await {
            tracing::error!(error = %e, "Server error");
            std::process::exit(2);
        }

        anyhow::Ok(())
    })
}

/// Load and parse the TOML configuration file.
///
/// Returns a fully constructed [`SmtpServerConfig`] with all defaults applied
/// for any missing optional values.
fn load_config(path: &PathBuf) -> anyhow::Result<misogi_smtp::server::SmtpServerConfig> {
    use misogi_smtp::server::{SmtpMode, SmtpServerConfig, ZonePolicy};

    info!(config_path = %path.display(), "Loading configuration");

    if !path.exists() {
        anyhow::bail!(
            "Configuration file not found: {}.\n\
             Create a configuration file or specify a different path with --config.",
            path.display()
        );
    }

    let content = std::fs::read_to_string(path)?;
    let value: toml::Value = content.parse().map_err(|e| {
        anyhow::anyhow!("Failed to parse TOML configuration from '{}': {}", path.display(), e)
    })?;

    // Extract configuration sections with sensible defaults
    let listen_addr = value
        .get("server")
        .and_then(|s| s.get("listen_addr"))
        .and_then(|v| v.as_str())
        .unwrap_or("0.0.0.0:25")
        .to_string();

    let hostname = value
        .get("server")
        .and_then(|s| s.get("hostname"))
        .and_then(|v| v.as_str())
        .unwrap_or("mail-misogi.gov.go.jp")
        .to_string();

    let mode_str = value
        .get("server")
        .and_then(|s| s.get("mode"))
        .and_then(|v| v.as_str())
        .unwrap_or("transparent_proxy");

    let mode = match mode_str {
        "pickup" | "Pickup" | "PICKUP" => SmtpMode::Pickup,
        _ => SmtpMode::TransparentProxy,
    };

    let pickup_dir = value
        .get("server")
        .and_then(|s| s.get("pickup_dir"))
        .and_then(|v| v.as_str())
        .map(String::from);

    let relay_host = value
        .get("relay")
        .and_then(|r| r.get("host"))
        .and_then(|v| v.as_str())
        .map(String::from);

    let relay_port = value
        .get("relay")
        .and_then(|r| r.get("port"))
        .and_then(|v| v.as_integer())
        .map(|v| v as u16)
        .unwrap_or(25);

    let max_message_size = value
        .get("server")
        .and_then(|s| s.get("max_message_size"))
        .and_then(|v| v.as_integer())
        .map(|v| v as usize)
        .unwrap_or(50 * 1024 * 1024); // 50 MiB

    let fail_open = value
        .get("security")
        .and_then(|s| s.get("fail_open"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let num_workers = value
        .get("server")
        .and_then(|s| s.get("num_workers"))
        .and_then(|v| v.as_integer())
        .map(|v| v as usize)
        .unwrap_or(4);

    // Zone policy configuration
    let zone_policy_value = value.get("zone_policy");

    let internal_domains: Vec<String> = zone_policy_value
        .and_then(|z| z.get("internal_domains"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let external_policy_override = zone_policy_value
        .and_then(|z| z.get("external_policy_override"))
        .and_then(|v| v.as_str())
        .map(String::from);

    let force_pii_scan_on_external = zone_policy_value
        .and_then(|z| z.get("force_pii_scan_on_external"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let zone_policy = ZonePolicy {
        internal_domains,
        external_policy_override,
        force_pii_scan_on_external,
    };

    let config = SmtpServerConfig {
        listen_addr,
        hostname,
        mode,
        pickup_dir,
        relay_host,
        relay_port,
        max_message_size,
        fail_open,
        zone_policy,
        num_workers,
    };

    info!(
        listen_addr = %config.listen_addr,
        hostname = %config.hostname,
        mode = ?config.mode,
        max_size = config.max_message_size,
        workers = config.num_workers,
        fail_open = config.fail_open,
        "Configuration loaded"
    );

    Ok(config)
}
