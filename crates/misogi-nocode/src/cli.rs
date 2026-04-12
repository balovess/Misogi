//! CLI Tool for Misogi No-Code Operations (`misogi-admin`).
//!
//! This module provides command-line interface commands for IT staff to manage
//! Misogi configurations without writing code or using the web API.
//!
//! # Available Commands
//!
//! | Command                              | Description                          |
//! |--------------------------------------|--------------------------------------|
//! | `misogi-admin config validate <file>` | Validate YAML config offline         |
//! | `misogi-admin config compile <file>`  | Compile YAML to internal config       |
//! | `misogi-admin config diff <f1> <f2>`  | Show config difference               |
//! | `misogi-admin config generate-example`| Output complete example YAML        |
//! | `misogi-admin status`                 | Query running server health          |
//! | `misogi-admin providers list`         | List identity providers              |
//! | `misogi-admin providers test <id>`    | Test provider authentication         |
//! | `misogi-admin watch`                  | Watch config file and show events   |
//!
//! # Usage Examples
//!
//! ```bash
//! # Validate a configuration file
//! misogi-admin config validate /etc/misogi/config.yaml
//!
//! # Show compilation result
//! misogi-admin config compile /etc/misogi/config.yaml
//!
//! # Generate example configuration
//! misogi-admin config generate-example > my-config.yaml
//!
//! # Check server status
//! misogi-admin status --server http://localhost:8080
//!
//! # Watch for config changes
//! misogi-admin watch /etc/misogi/config.yaml
//! ```

use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};
use colored::Colorize;
use tracing::{info, error};

use crate::compiler;
use crate::schema::YamlConfig;

// =============================================================================
// CLI Argument Parser
// =============================================================================

/// Misogi No-Code Administration CLI — Manage configurations without writing code.
///
/// A command-line tool for Japanese government IT staff to validate, compile,
/// and monitor Misogi (禊) secure file transfer system configurations.
#[derive(Debug, Parser)]
#[command(
    name = "misogi-admin",
    version,
    author = "Misogi Project",
    about = "No-Code Administration CLI for Misogi Secure File Transfer System",
    long_about = "\
Misogi No-Code Administration CLI

This tool enables government IT staff to manage Misogi configurations \
without writing Rust code. Use it to validate, compile, diff, and monitor \
YAML-based declarative configurations.

For detailed help on a specific command, use: \
misogi-admin <command> --help"
)]
pub struct Cli {
    /// Enable verbose/debug output.
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Suppress all output except errors.
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Disable colored output.
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Server URL for API operations (default: http://localhost:3000).
    #[arg(long, global = true, env = "MISOGI_ADMIN_SERVER")]
    pub server: Option<String>,

    /// Bearer token for API authentication.
    #[arg(long, global = true, env = "MISOGI_ADMIN_TOKEN")]
    pub token: Option<String>,

    /// Subcommand to execute.
    #[command(subcommand)]
    pub command: Commands,
}

/// Available CLI subcommands.
#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Configuration management commands.
    Config {
        /// Configuration subcommand to execute.
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Query server health and status.
    Status {
        /// Show detailed component status.
        #[arg(long)]
        detailed: bool,
    },

    /// Identity provider management.
    Providers {
        /// Provider subcommand to execute.
        #[command(subcommand)]
        action: ProviderAction,
    },

    /// Watch configuration file for changes and display events.
    Watch {
        /// Path to the YAML configuration file to watch.
        path: PathBuf,

        /// Exit after N reload events (0 = run forever).
        #[arg(short, long, default_value = "0")]
        count: u32,

        /// Polling interval in seconds (fallback if file watching unavailable).
        #[arg(short, long, default_value = "5")]
        poll_interval: u64,
    },
}

/// Configuration management actions.
#[derive(Debug, Subcommand)]
pub enum ConfigAction {
    /// Validate a YAML configuration file without compiling.
    Validate {
        /// Path to the YAML configuration file.
        file: PathBuf,

        /// Output format: text or json.
        #[arg(long, default_value = "text")]
        format: String,
    },

    /// Compile a YAML configuration file and show the result.
    Compile {
        /// Path to the YAML configuration file.
        file: PathBuf,

        /// Show full compiled configuration (not just summary).
        #[arg(long)]
        full: bool,

        /// Output format: text or json.
        #[arg(long, default_value = "text")]
        format: String,
    },

    /// Show differences between two configuration files.
    Diff {
        /// First (original) configuration file.
        file1: PathBuf,

        /// Second (modified) configuration file.
        file2: PathBuf,

        /// Output format: text or json.
        #[arg(long, default_value = "text")]
        format: String,
    },

    /// Generate a complete example YAML configuration file.
    GenerateExample {
        /// Include Japanese comments for government use.
        #[arg(long)]
        japanese_comments: bool,
    },
}

/// Identity provider management actions.
#[derive(Debug, Subcommand)]
pub enum ProviderAction {
    /// List all configured identity providers.
    List {
        /// Output format: text or json.
        #[arg(long, default_value = "text")]
        format: String,
    },

    /// Test authentication against a specific identity provider.
    Test {
        /// Provider name or ID to test.
        id: String,

        /// Username for authentication test.
        #[arg(long)]
        username: String,

        /// Password for authentication test.
        #[arg(long)]
        password: String,
    },
}

// =============================================================================
// CLI Execution Engine
// =============================================================================

/// Execute the parsed CLI command with appropriate error handling.
///
/// This is the primary entry point called from `main()`.
/// Returns exit code: 0 for success, non-zero for failure.
pub async fn execute(cli: Cli) -> i32 {
    // Configure logging based on verbosity
    let log_level = if cli.verbose {
        tracing::Level::DEBUG
    } else if cli.quiet {
        tracing::Level::ERROR
    } else {
        tracing::Level::INFO
    };

    // Initialize tracing subscriber (only if not already initialized)
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_target(false)
        .with_ansi(!cli.no_color && atty::is(atty::Stream::Stderr))
        .finish();

    // Try to set as global default; ignore if already set
    let _ = tracing::subscriber::set_global_default(subscriber);

    // Execute the requested command
    match &cli.command {
        Commands::Config { action } => execute_config_action(action, &cli).await,
        Commands::Status { detailed } => execute_status(detailed, &cli).await,
        Commands::Providers { action } => execute_provider_action(action, &cli).await,
        Commands::Watch { path, count, poll_interval } => {
            execute_watch(path, *count, *poll_interval, &cli).await
        }
    }
}

// -----------------------------------------------------------------
// Command Implementations
// -----------------------------------------------------------------

/// Execute configuration management subcommands.
async fn execute_config_action(action: &ConfigAction, cli: &Cli) -> i32 {
    match action {
        ConfigAction::Validate { file, format } => {
            cmd_config_validate(file, format.as_str(), cli)
        }

        ConfigAction::Compile { file, full, format } => {
            cmd_config_compile(file, *full, format.as_str(), cli)
        }

        ConfigAction::Diff { file1, file2, format } => {
            cmd_config_diff(file1, file2, format.as_str(), cli)
        }

        ConfigAction::GenerateExample { japanese_comments } => {
            cmd_generate_example(*japanese_comments, cli)
        }
    }
}

/// Execute status query command.
async fn execute_status(_detailed: &bool, cli: &Cli) -> i32 {
    let server_url = get_server_url(cli);

    println!("{}", "=== Misogi Server Status ===".bold().cyan());

    info!(server = %server_url, "Querying server status");

    // Build HTTP client
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_default();

    // Make request to /api/v1/status
    let url = format!("{}/api/v1/status", server_url);
    let request = build_authenticated_request(&client, &url, cli.token.as_deref());

    match request.send().await {
        Ok(response) => {
            if response.status().is_success() {
                let body: serde_json::Value = response.json().await.unwrap_or_default();
                print_status_response(&body, cli);
                0
            } else {
                error!(
                    status = %response.status(),
                    "Server returned error status"
                );
                eprintln!("{} {}", "ERROR:".red(), format!("Server returned {}", response.status()));
                1
            }
        }
        Err(e) => {
            error!(error = %e, "Failed to connect to server");
            eprintln!("{} {}", "ERROR:".red(), format!("Cannot connect to {}: {}", server_url, e));
            1
        }
    }
}

/// Execute provider management subcommands.
async fn execute_provider_action(action: &ProviderAction, cli: &Cli) -> i32 {
    let server_url = get_server_url(cli);

    match action {
        ProviderAction::List { format } => {
            cmd_providers_list(&server_url, format.as_str(), cli).await
        }

        ProviderAction::Test { id, username, password } => {
            cmd_providers_test(&server_url, id, username, password, cli).await
        }
    }
}

/// Execute file watcher command.
async fn execute_watch(path: &PathBuf, max_events: u32, _poll_secs: u64, cli: &Cli) -> i32 {
    println!(
        "{} {}",
        "Watching:".green().bold(),
        path.display().to_string().white()
    );
    println!("{} Press Ctrl+C to stop\n", "Hint:".dimmed());

    let mut event_count = 0u32;

    loop {
        // Check if file exists
        if !path.exists() {
            eprintln!("{} {}",
                "ERROR:".red(),
                format!("Configuration file not found: {}", path.display())
            );
            return 1;
        }

        // Read and attempt to parse file
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("{} {}", "WARN:".yellow(), format!("Read error: {}", e));
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
        };

        // Validate
        match YamlConfig::from_yaml_str(&content) {
            Ok(yaml) => {
                match yaml.validate() {
                    Ok(warnings) => {
                        event_count += 1;
                        let timestamp = chrono::Local::now().format("%H:%M:%S");

                        println!(
                            "[{}] {} File is valid{}",
                            timestamp.to_string().dimmed(),
                            "OK".green().bold(),
                            if warnings.is_empty() {
                                String::new()
                            } else {
                                format!(" ({} warning(s))", warnings.len()).yellow().to_string()
                            }
                        );

                        if cli.verbose && !warnings.is_empty() {
                            for w in &warnings {
                                println!("  {} {}: {}", "!".yellow(), w.field, w.message);
                            }
                        }

                        if max_events > 0 && event_count >= max_events {
                            println!("\n{} {} events received, exiting", "Info:".dimmed(), event_count);
                            return 0;
                        }
                    }
                    Err(e) => {
                        event_count += 1;
                        let timestamp = chrono::Local::now().format("%H:%M:%S");

                        println!(
                            "[{}] {} {}",
                            timestamp.to_string().dimmed(),
                            "INVALID".red().bold(),
                            e.message.red()
                        );
                    }
                }
            }
            Err(e) => {
                eprintln!("{} {}", "PARSE ERROR:".red(), e);
            }
        }

        // Wait before next check
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

// =============================================================================
// Individual Command Implementations
// =============================================================================

/// Validate a YAML configuration file.
fn cmd_config_validate(file: &PathBuf, format: &str, _cli: &Cli) -> i32 {
    println!(
        "{} {}",
        "Validating:".white().bold(),
        file.display().to_string().white()
    );

    // Read file
    let content = match read_file_content(file) {
        Ok(c) => c,
        Err(e) => return e,
    };

    // Parse YAML
    let yaml = match YamlConfig::from_yaml_str(&content) {
        Ok(y) => y,
        Err(e) => {
            eprintln!("{} {}", "PARSE ERROR:".red(), e);
            return 1;
        }
    };

    // Validate
    match yaml.validate() {
        Ok(warnings) => {
            println!("\n{}", "✓ Configuration is valid".green().bold());

            // Print summary
            print_validation_summary(&yaml);

            // Print warnings
            if !warnings.is_empty() {
                println!("\n{} ({} total)", "Warnings:".yellow(), warnings.len());
                for w in &warnings {
                    let icon = if w.is_error() { "X".red() } else { "!".yellow() };
                    println!("  {} [{}] {}", icon, w.field.white(), w.message);
                    if let Some(ref suggestion) = w.suggestion {
                        println!("    {} {}", "Suggestion:".dimmed(), suggestion.dimmed());
                    }
                }
            }

            if format == "json" {
                println!("\n{}", "--- JSON Output ---".dimmed());
                let output = serde_json::json!({
                    "valid": true,
                    "warnings": warnings.len(),
                    "config_summary": {
                        "version": yaml.version,
                        "environment": yaml.environment,
                        "providers": yaml.authentication.identity_providers.len(),
                        "sanitization_rules": yaml.sanitization.rules.len(),
                        "routing_rules": yaml.routing.incoming.len(),
                    }
                });
                println!("{}", serde_json::to_string_pretty(&output).unwrap_or_default());
            }

            0
        }
        Err(e) => {
            println!("\n{}", "✗ Validation failed".red().bold());
            println!("  {} {}", "Error:".red(), e.message.red());

            if format == "json" {
                println!("\n{}", "--- JSON Output ---".dimmed());
                let output = serde_json::json!({
                    "valid": false,
                    "error": e.message,
                });
                println!("{}", serde_json::to_string_pretty(&output).unwrap_or_default());
            }

            1
        }
    }
}

/// Compile a YAML configuration file and display the result.
fn cmd_config_compile(file: &PathBuf, full: bool, format: &str, _cli: &Cli) -> i32 {
    println!(
        "{} {}",
        "Compiling:".white().bold(),
        file.display().to_string().white()
    );

    // Read file
    let content = match read_file_content(file) {
        Ok(c) => c,
        Err(e) => return e,
    };

    // Parse YAML
    let yaml = match YamlConfig::from_yaml_str(&content) {
        Ok(y) => y,
        Err(e) => {
            eprintln!("{} {}", "PARSE ERROR:".red(), e);
            return 1;
        }
    };

    // Validate first
    if let Err(e) = yaml.validate() {
        eprintln!("\n{} {}", "Validation Error:".red(), e.message);
        return 1;
    }

    // Compile
    match compiler::compile(&yaml) {
        Ok((config, report)) => {
            println!("\n{}", "✓ Compilation successful".green().bold());

            // Print summary
            println!("\n{}", "=== Compiled Configuration Summary ===".bold().cyan());
            println!("  {}: {}", "Version".white(), config.version);
            println!("  {}: {}", "Environment".white(), config.environment);
            println!("  {}: {}", "JWT Issuer".white(), config.authentication.jwt_issuer);
            println!("  {}: {}", "JWT TTL".white(), format!("{} hours", config.authentication.jwt_ttl_seconds / 3600));
            println!("  {}: {}", "Identity Providers".white(), config.authentication.identity_providers.len());
            println!("  {}: {}", "Sanitization Rules".white(), config.sanitization.rules.len());
            println!("  {}: {}", "Routing Rules".white(), config.routing.incoming.len());

            // Print compilation report
            println!("\n{}", "=== Compilation Report ===".bold().cyan());
            println!("  {}: {}", "Env vars resolved".white(), report.env_vars_resolved);
            println!("  {}: {}", "Cross-references checked".white(), report.cross_references_checked);
            println!("  {}: {}", "Total messages".white(), report.total_messages());

            if report.has_warnings() {
                println!("\n{} ({}):", "Warnings".yellow(), report.warnings.len());
                for w in &report.warnings {
                    println!("  ! {}", w.yellow());
                }
            }

            if report.info.iter().any(|i| i.contains("Compiled")) {
                for info_msg in &report.info {
                    println!("  {} {}", "→".dimmed(), info_msg.dimmed());
                }
            }

            // Full output if requested
            if full {
                println!("\n{}", "=== Full Compiled Configuration ===".bold().cyan());
                let json_output = serde_json::to_string_pretty(&config).unwrap_or_default();
                println!("{}", json_output);
            }

            if format == "json" {
                println!("\n{}", "--- JSON Output ---".dimmed());
                let output = serde_json::json!({
                    "success": true,
                    "config": config,
                    "report": report,
                });
                println!("{}", serde_json::to_string_pretty(&output).unwrap_or_default());
            }

            0
        }
        Err(e) => {
            println!("\n{}", "✗ Compilation failed".red().bold());
            println!("  {} {:?}", "Error:".red(), e);
            1
        }
    }
}

/// Show differences between two configuration files.
fn cmd_config_diff(file1: &PathBuf, file2: &PathBuf, format: &str, _cli: &Cli) -> i32 {
    println!(
        "{}\n  {}\n  {}",
        "Comparing configurations:".white().bold(),
        file1.display().to_string().white(),
        file2.display().to_string().white()
    );

    // Read both files
    let content1 = match read_file_content(file1) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let content2 = match read_file_content(file2) {
        Ok(c) => c,
        Err(e) => return e,
    };

    // Parse both
    let yaml1 = match YamlConfig::from_yaml_str(&content1) {
        Ok(y) => y,
        Err(e) => {
            eprintln!("{} {}:\n  {}", "Parse error in".red(), file1.display(), e);
            return 1;
        }
    };
    let yaml2 = match YamlConfig::from_yaml_str(&content2) {
        Ok(y) => y,
        Err(e) => {
            eprintln!("{} {}:\n  {}", "Parse error in".red(), file2.display(), e);
            return 1;
        }
    };

    // Compare fields
    let mut differences: Vec<(String, String, String)> = vec![];

    // Compare version
    if yaml1.version != yaml2.version {
        differences.push(("version".to_string(), yaml1.version.clone(), yaml2.version.clone()));
    }

    // Compare environment
    if yaml1.environment != yaml2.environment {
        differences.push(("environment".to_string(), yaml1.environment.clone(), yaml2.environment.clone()));
    }

    // Compare JWT settings
    if yaml1.authentication.jwt.issuer != yaml2.authentication.jwt.issuer {
        differences.push(("authentication.jwt.issuer".to_string(), yaml1.authentication.jwt.issuer.clone(), yaml2.authentication.jwt.issuer.clone()));
    }
    if yaml1.authentication.jwt.ttl_hours != yaml2.authentication.jwt.ttl_hours {
        differences.push((
            "authentication.jwt.ttl_hours".to_string(),
            yaml1.authentication.jwt.ttl_hours.to_string(),
            yaml2.authentication.jwt.ttl_hours.to_string(),
        ));
    }

    // Compare provider counts
    let p1_count = yaml1.authentication.identity_providers.len();
    let p2_count = yaml2.authentication.identity_providers.len();
    if p1_count != p2_count {
        differences.push((
            "identity_providers (count)".to_string(),
            p1_count.to_string(),
            p2_count.to_string(),
        ));
    }

    // Display results
    if differences.is_empty() {
        println!("\n{}", "✓ Configurations are identical".green().bold());
    } else {
        println!("\n{} ({} difference(s)):", "Differences found:".yellow(), differences.len());
        println!("{:<50} {:<30} {:<30}", "Field".white().bold(), "File 1".cyan(), "File 2".cyan());
        println!("{}", "-".repeat(110).dimmed());

        for (field, val1, val2) in &differences {
            let marker = if val1 == val2 { " ".white() } else { "≠".yellow() };
            println!("{} {:<48} {:<28} {}", marker, field.white(), val1.cyan(), val2.cyan());
        }
    }

    if format == "json" {
        println!("\n{}", "--- JSON Output ---".dimmed());
        let output = serde_json::json!({
            "identical": differences.is_empty(),
            "difference_count": differences.len(),
            "differences": differences.iter().map(|(f, v1, v2)| {
                serde_json::json!({
                    "field": f,
                    "file1_value": *v1,
                    "file2_value": *v2,
                })
            }).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap_or_default());
    }

    if differences.is_empty() { 0 } else { 2 }
}

/// Generate complete example YAML configuration.
fn cmd_generate_example(japanese_comments: bool, _cli: &Cli) -> i32 {
    let example = if japanese_comments {
        include_str!("../examples/full_example_ja.yaml")
    } else {
        include_str!("../examples/full_example.yaml")
    };

    println!("{}", example);
    0
}

/// List identity providers from running server.
async fn cmd_providers_list(server_url: &str, format: &str, cli: &Cli) -> i32 {
    println!("{}", "=== Identity Providers ===".bold().cyan());

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_default();

    let url = format!("{}/api/v1/providers", server_url);
    let request = build_authenticated_request(&client, &url, cli.token.as_deref());

    match request.send().await {
        Ok(response) => {
            if response.status().is_success() {
                let body: serde_json::Value = response.json().await.unwrap_or_default();

                if let Some(data) = body.get("data") {
                    if let Some(providers) = data.get("providers").and_then(|p| p.as_array()) {
                        if providers.is_empty() {
                            println!("  {}", "No identity providers configured".dimmed());
                        } else {
                            for (i, provider) in providers.iter().enumerate() {
                                let name = provider.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                                let type_str = provider.get("type").and_then(|v| v.as_str()).unwrap_or("?");
                                let enabled = provider.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);

                                let enabled_str = if enabled { "✓".green() } else { "✗".red() };
                                println!("  {}. {} [{}] {}", i + 1, name.white(), type_str.cyan(), enabled_str);
                            }
                        }

                        if let Some(count) = data.get("count") {
                            println!("\n  {}: {}", "Total".white(), count);
                        }
                    }
                }

                if format == "json" {
                    println!("\n{}", "--- JSON Output ---".dimmed());
                    println!("{}", serde_json::to_string_pretty(&body).unwrap_or_default());
                }

                0
            } else {
                eprintln!("{} {}", "ERROR:".red(), format!("Server returned {}", response.status()));
                1
            }
        }
        Err(e) => {
            eprintln!("{} {}", "ERROR:".red(), format!("Cannot connect to {}: {}", server_url, e));
            1
        }
    }
}

/// Test authentication against a specific provider.
async fn cmd_providers_test(
    server_url: &str,
    provider_id: &str,
    username: &str,
    password: &str,
    cli: &Cli,
) -> i32 {
    println!(
        "{} {} [user: {}]",
        "Testing provider:".white().bold(),
        provider_id.white(),
        username.yellow()
    );

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30)) // Auth tests may take longer
        .build()
        .unwrap_or_default();

    let url = format!("{}/api/v1/providers/{}/test", server_url, provider_id);
    let body = serde_json::json!({
        "username": username,
        "password": password,
    });

    let mut request = client.post(&url).json(&body);
    
    if let Some(token) = &cli.token {
        request = request.bearer_auth(token);
    }

    match request.send().await {
        Ok(response) => {
            if response.status().is_success() {
                let body: serde_json::Value = response.json().await.unwrap_or_default();

                if let Some(data) = body.get("data") {
                    let success = data.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
                    let message = data.get("message").and_then(|v| v.as_str()).unwrap_or("");

                    if success {
                        println!("\n{} {}", "✓ Authentication test PASSED".green().bold(), message.green());
                    } else {
                        println!("\n{} {}", "✗ Authentication test FAILED".red().bold(), message.red());
                    }

                    if let Some(details) = data.get("details") {
                        println!("\n{}:", "Details".dimmed());
                        println!("  {}", serde_json::to_string_pretty(details).unwrap_or_default());
                    }
                }

                if success_from_body(&body) { 0 } else { 1 }
            } else {
                eprintln!("{} {}", "ERROR:".red(), format!("Server returned {}", response.status()));
                1
            }
        }
        Err(e) => {
            eprintln!("{} {}", "ERROR:".red(), format!("Request failed: {}", e));
            1
        }
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Read file content with user-friendly error handling.
fn read_file_content(file: &PathBuf) -> std::result::Result<String, i32> {
    std::fs::read_to_string(file).map_err(|e| {
        eprintln!("{} {}", "ERROR:".red(), format!("Cannot read '{}': {}", file.display(), e));
        1
    })
}

/// Get server URL from CLI args or default.
fn get_server_url(cli: &Cli) -> String {
    cli.server.clone().unwrap_or_else(|| "http://localhost:3000".to_string())
}

/// Build an authenticated HTTP request (if token provided).
fn build_authenticated_request<'a>(
    client: &'a reqwest::Client,
    url: &str,
    token: Option<&str>,
) -> reqwest::RequestBuilder {
    let mut builder = client.get(url);
    if let Some(t) = token {
        builder = builder.bearer_auth(t);
    }
    builder
}

/// Extract success flag from API response body.
fn success_from_body(body: &serde_json::Value) -> bool {
    body.get("success").and_then(|v| v.as_bool()).unwrap_or(false)
}

/// Print validation summary information.
fn print_validation_summary(yaml: &YamlConfig) {
    println!("\n{}", "Configuration Summary:".bold());
    println!("  {}: {}", "Version".white(), yaml.version);
    println!("  {}: {}", "Environment".white(), yaml.environment);
    println!("  {}: {}", "Identity Providers".white(), yaml.authentication.identity_providers.len());
    println!("  {}: {}", "Sanitization Rules".white(), yaml.sanitization.rules.len());
    println!("  {}: {}", "Routing Rules".white(), yaml.routing.incoming.len());
    println!("  {}: {}", "Retention Rules".white(), yaml.retention.as_ref().map(|r| r.rules.len()).unwrap_or(0));
    println!("  {}: {}", "Notification Channels".white(), yaml.notifications.as_ref().map(|n| n.on_error.len()).unwrap_or(0));
}

/// Print formatted status response from server.
fn print_status_response(body: &serde_json::Value, _cli: &Cli) {
    if let Some(data) = body.get("data") {
        let status = data.get("status").and_then(|v| v.as_str()).unwrap_or("unknown");

        let status_display = match status {
            "operational" => status.green().bold(),
            "degraded" => status.yellow().bold(),
            "unhealthy" => status.red().bold(),
            _ => status.normal(),
        };

        println!("  Overall Status: {}", status_display);

        if let Some(runtime) = data.get("runtime") {
            if let Some(version) = runtime.get("version").and_then(|v| v.as_str()) {
                println!("  Version: {}", version);
            }
            if let Some(env) = runtime.get("environment").and_then(|v| v.as_str()) {
                println!("  Environment: {}", env);
            }
            if let Some(reloads) = runtime.get("total_reloads").and_then(|v| v.as_u64()) {
                println!("  Total Reloads: {}", reloads);
            }
            if let Some(failures) = runtime.get("total_failures").and_then(|v| v.as_u64()) {
                println!("  Total Failures: {}", failures);
            }
        }

        if let Some(components) = data.get("components").and_then(|v| v.as_object()) {
            println!("\n  Components:");
            for (name, comp) in components {
                let comp_status = comp.get("status").and_then(|v| v.as_str()).unwrap_or("?");
                let icon = match comp_status {
                    "healthy" => "●".green(),
                    "idle" => "○".white(),
                    "degraded" => "◐".yellow(),
                    "unhealthy" => "✗".red(),
                    _ => "?".dimmed(),
                };
                println!("    {} {}: {}", icon, name, comp_status);
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
    use clap::Parser;

    // =========================================================================
    // Test: CLI Parsing - Config Validate
    // =========================================================================

    #[test]
    fn test_cli_parse_config_validate() {
        let cli = Cli::try_parse_from([
            "misogi-admin",
            "config",
            "validate",
            "/path/to/config.yaml",
        ]);

        assert!(cli.is_ok());
        let cli = cli.unwrap();
        assert!(matches!(cli.command, Commands::Config { .. }));
    }

    // =========================================================================
    // Test: CLI Parsing - Config Compile
    // =========================================================================

    #[test]
    fn test_cli_parse_config_compile_with_full_flag() {
        let cli = Cli::try_parse_from([
            "misogi-admin",
            "config",
            "compile",
            "/path/to/config.yaml",
            "--full",
            "--format",
            "json",
        ]);

        assert!(cli.is_ok());
        let cli = cli.unwrap();
        
        if let Commands::Config { action } = cli.command {
            if let ConfigAction::Compile { full, format, .. } = action {
                assert!(full);
                assert_eq!(format, "json");
            } else {
                panic!("Expected Compile action");
            }
        } else {
            panic!("Expected Config command");
        }
    }

    // =========================================================================
    // Test: CLI Parsing - Config Diff
    // =========================================================================

    #[test]
    fn test_cli_parse_config_diff() {
        let cli = Cli::try_parse_from([
            "misogi-admin",
            "config",
            "diff",
            "config1.yaml",
            "config2.yaml",
        ]);

        assert!(cli.is_ok());
        let cli = cli.unwrap();
        assert!(matches!(cli.command, Commands::Config { .. }));
    }

    // =========================================================================
    // Test: CLI Parsing - Status
    // =========================================================================

    #[test]
    fn test_cli_parse_status_detailed() {
        let cli = Cli::try_parse_from(["misogi-admin", "status", "--detailed"]);

        assert!(cli.is_ok());
        let cli = cli.unwrap();
        
        if let Commands::Status { detailed } = cli.command {
            assert!(detailed);
        } else {
            panic!("Expected Status command");
        }
    }

    // =========================================================================
    // Test: CLI Parsing - Providers List
    // =========================================================================

    #[test]
    fn test_cli_parse_providers_list() {
        let cli = Cli::try_parse_from(["misogi-admin", "providers", "list"]);

        assert!(cli.is_ok());
        let cli = cli.unwrap();
        assert!(matches!(cli.command, Commands::Providers { .. }));
    }

    // =========================================================================
    // Test: CLI Parsing - Providers Test
    // =========================================================================

    #[test]
    fn test_cli_parse_providers_test() {
        let cli = Cli::try_parse_from([
            "misogi-admin",
            "providers",
            "test",
            "MyLDAP",
            "--username",
            "admin",
            "--password",
            "secret123",
        ]);

        assert!(cli.is_ok());
        let cli = cli.unwrap();
        
        if let Commands::Providers { action } = cli.command {
            if let ProviderAction::Test { id, username, password } = action {
                assert_eq!(id, "MyLDAP");
                assert_eq!(username, "admin");
                assert_eq!(password, "secret123");
            } else {
                panic!("Expected Test action");
            }
        } else {
            panic!("Expected Providers command");
        }
    }

    // =========================================================================
    // Test: CLI Parsing - Watch
    // =========================================================================

    #[test]
    fn test_cli_parse_watch_with_options() {
        let cli = Cli::try_parse_from([
            "misogi-admin",
            "watch",
            "/etc/misogi/config.yaml",
            "--count",
            "5",
            "--poll-interval",
            "3",
        ]);

        assert!(cli.is_ok());
        let cli = cli.unwrap();
        
        if let Commands::Watch { path, count, poll_interval } = cli.command {
            assert_eq!(path, PathBuf::from("/etc/misogi/config.yaml"));
            assert_eq!(count, 5);
            assert_eq!(poll_interval, 3);
        } else {
            panic!("Expected Watch command");
        }
    }

    // =========================================================================
    // Test: Global Options
    // =========================================================================

    #[test]
    fn test_global_options_verbose_and_quiet() {
        let cli = Cli::try_parse_from([
            "misogi-admin",
            "--verbose",
            "--quiet",
            "--no-color",
            "status",
        ]);

        assert!(cli.is_ok());
        let cli = cli.unwrap();
        assert!(cli.verbose);
        assert!(cli.quiet);
        assert!(cli.no_color);
    }

    #[test]
    fn test_server_url_from_env_var() {
        // This would need integration testing with actual env var setting
        // For unit test, just verify parsing accepts --server option
        let cli = Cli::try_parse_from([
            "misogi-admin",
            "--server",
            "https://admin.misogi.gov.jp",
            "status",
        ]);

        assert!(cli.is_ok());
        let cli = cli.unwrap();
        assert_eq!(cli.server.as_deref(), Some("https://admin.misogi.gov.jp"));
    }

    // =========================================================================
    // Test: Helper Functions
    // =========================================================================

    #[test]
    fn test_get_server_url_default() {
        let cli = Cli::parse_from(["misogi-admin", "status"]);
        assert_eq!(get_server_url(&cli), "http://localhost:3000");
    }

    #[test]
    fn test_get_server_url_custom() {
        let cli = Cli::parse_from(["misogi-admin", "--server", "http://custom:8080", "status"]);
        assert_eq!(get_server_url(&cli), "http://custom:8080");
    }
}
