//! Usability enhancement commands for Misogi.
//!
//! This module provides user-friendly commands that improve the out-of-box
//! experience, including:
//!
//! - `--init`: Interactive configuration wizard
//! - `--check-deps`: Dependency verification
//! - `--list-presets`: List available compliance presets
//! - `--validate-config`: Configuration file validation

use std::path::PathBuf;
use std::process::Command;

use misogi_core::presets::CompliancePreset;

// =============================================================================
// Preset Listing
// =============================================================================

/// List all available compliance presets with descriptions.
pub fn list_presets() {
    println!();
    println!("╔═══════════════════════════════════════════════════════════════╗");
    println!("║              Available Compliance Presets                      ║");
    println!("╚═══════════════════════════════════════════════════════════════╝");
    println!();

    let presets = CompliancePreset::all_presets();

    for preset in &presets {
        println!("┌─────────────────────────────────────────────────────────────────┐");
        println!("│ Preset: {:<54} │", preset.name);
        println!("├─────────────────────────────────────────────────────────────────┤");
        println!("│ {}", wrap_text(&preset.description, 63));
        println!("│");
        println!("│ Security Settings:");
        println!(
            "│   Approval Required: {}",
            if preset.approval_required {
                "Yes"
            } else {
                "No"
            }
        );
        println!(
            "│   Reason Required:   {}",
            if preset.reason_required { "Yes" } else { "No" }
        );
        println!("│   Sanitization:      {:?}", preset.sanitization_policy);
        println!("│");
        println!("│ File Limits:");
        println!("│   Max PDF:    {} MB", preset.max_pdf_size_mb);
        println!("│   Max Office: {} MB", preset.max_office_size_mb);
        println!("│   Max ZIP:    {} MB", preset.max_zip_size_mb);
        println!("│");
        println!("│ Audit:");
        println!("│   Retention: {} days", preset.audit_retention_days);
        println!(
            "│   Log IP:    {}",
            if preset.log_ip_address { "Yes" } else { "No" }
        );
        println!("└─────────────────────────────────────────────────────────────────┘");
        println!();
    }

    println!("Usage:");
    println!("  misogi-sender --preset lgwan_government");
    println!("  misogi-sender --config config/examples/lgwan.toml");
    println!();
}

fn wrap_text(text: &str, max_width: usize) -> String {
    if text.len() <= max_width {
        return format!("{:<width$}", text, width = max_width);
    }

    let mut result = String::new();
    let mut current_line = String::new();

    for word in text.split_whitespace() {
        if current_line.len() + word.len() + 1 > max_width {
            if !current_line.is_empty() {
                result.push_str(&format!(
                    "{:<width$}",
                    current_line.trim(),
                    width = max_width
                ));
                result.push_str("\n│ ");
            }
            current_line = word.to_string();
        } else {
            if !current_line.is_empty() {
                current_line.push(' ');
            }
            current_line.push_str(word);
        }
    }

    if !current_line.is_empty() {
        result.push_str(&format!(
            "{:<width$}",
            current_line.trim(),
            width = max_width
        ));
    }

    result
}

// =============================================================================
// Dependency Checking
// =============================================================================

/// Check system dependencies and report status.
pub fn check_dependencies() {
    println!();
    println!("╔═══════════════════════════════════════════════════════════════╗");
    println!("║                  Dependency Check                              ║");
    println!("╚═══════════════════════════════════════════════════════════════╝");
    println!();

    let mut all_required = true;
    let mut has_optional = false;

    // Check Rust
    if let Some(version) = check_command("rustc", &["--version"]) {
        print_success(&format!("Rust toolchain: {} (required: 1.85+)", version));
    } else {
        print_warning("Rust toolchain: not found (required for source build)");
        print_info("Install: https://rustup.rs/");
        all_required = false;
    }

    // Check protoc
    if let Some(version) = check_command("protoc", &["--version"]) {
        print_success(&format!("protoc: {} (required: 3.0+)", version));
    } else {
        print_warning("protoc: not found (required for source build)");
        print_info("Install: apt install protobuf-compiler (Linux)");
        print_info("         brew install protobuf (macOS)");
    }

    // Check Docker
    if let Some(version) = check_command("docker", &["--version"]) {
        print_success(&format!("Docker: {} (required: 24.0+)", version));
    } else {
        print_warning("Docker: not found (required for Docker deployment)");
        print_info("Install: https://docs.docker.com/get-docker/");
        all_required = false;
    }

    // Check Docker Compose
    if check_command("docker", &["compose", "version"]).is_some() {
        print_success("Docker Compose: available");
    } else if check_command("docker-compose", &["--version"]).is_some() {
        print_success("Docker Compose: available (legacy)");
    } else {
        print_warning("Docker Compose: not found");
    }

    // Check OpenSSL
    if let Some(version) = check_command("openssl", &["version"]) {
        print_success(&format!(
            "OpenSSL: {} (required for key generation)",
            version
        ));
    } else {
        print_warning("OpenSSL: not found");
        print_info("Install: apt install openssl (Linux)");
    }

    // Check git
    if check_command("git", &["--version"]).is_some() {
        print_success("Git: available");
    } else {
        print_warning("Git: not found (optional)");
        has_optional = true;
    }

    // Check curl
    if check_command("curl", &["--version"]).is_some() {
        print_success("curl: available");
    } else {
        print_warning("curl: not found (needed for health checks)");
        has_optional = true;
    }

    // Check LibreOffice (optional)
    if check_command("soffice", &["--version"]).is_some() {
        print_success("LibreOffice: available (for JTD conversion)");
    } else {
        print_warning("LibreOffice: not found (optional, for JTD conversion)");
        print_info("Install: apt install libreoffice-headless (Linux)");
        has_optional = true;
    }

    println!();

    if all_required {
        print_success("All required dependencies satisfied.");
        if has_optional {
            println!();
            println!("Note: Some optional dependencies are missing.");
            println!("      JTD (.jtd) file conversion requires LibreOffice.");
        }
    } else {
        print_error("Missing required dependencies.");
        println!();
        println!("Please install the missing dependencies before proceeding.");
    }

    println!();
}

fn check_command(cmd: &str, args: &[&str]) -> Option<String> {
    Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| {
            String::from_utf8_lossy(&output.stdout)
                .split_whitespace()
                .next()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        })
}

// =============================================================================
// Configuration Validation
// =============================================================================

/// Validate a configuration file.
pub fn validate_config(config_path: &Option<PathBuf>) {
    println!();
    println!("╔═══════════════════════════════════════════════════════════════╗");
    println!("║                  Configuration Validation                      ║");
    println!("╚═══════════════════════════════════════════════════════════════╝");
    println!();

    let path = config_path
        .clone()
        .unwrap_or_else(|| PathBuf::from("misogi.toml"));

    println!("Validating: {}", path.display());
    println!();

    // Check file exists
    if !path.exists() {
        print_error(&format!("Configuration file not found: {}", path.display()));
        println!();
        println!("To create a configuration file:");
        println!("  1. Run: misogi-sender --init");
        println!("  2. Or copy: cp config/misogi.toml.default misogi.toml");
        return;
    }

    // Read file content
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            print_error(&format!("Failed to read file: {}", e));
            return;
        }
    };

    // Parse TOML
    let parsed: Result<toml::Value, _> = toml::from_str(&content);

    match parsed {
        Ok(value) => {
            print_success("TOML syntax: valid");

            // Check required sections
            let has_server = value.get("server").is_some();
            let has_storage = value.get("storage").is_some();

            if has_server {
                print_success("[server] section: present");
            } else {
                print_error("[server] section: missing (required)");
            }

            if has_storage {
                print_success("[storage] section: present");
            } else {
                print_error("[storage] section: missing (required)");
            }

            // Check optional sections
            let optional_sections = [
                "tunnel",
                "daemon",
                "approval_flow",
                "transfer_driver",
                "cdr_strategies",
                "file_types",
                "pii_detector",
                "log",
                "vendor_isolation",
                "calendar",
                "encoding",
                "external_sanitizers",
                "ppap",
                "blast",
                "versioning",
            ];

            let mut found_optional = Vec::new();
            for section in &optional_sections {
                if value.get(section).is_some() {
                    found_optional.push(*section);
                }
            }

            if !found_optional.is_empty() {
                print_success(&format!("Optional sections: {}", found_optional.join(", ")));
            }

            println!();

            if has_server && has_storage {
                print_success("Configuration is valid and complete.");
                println!();
                println!("You can now start Misogi:");
                println!("  docker compose up -d");
                println!("  # or");
                println!("  misogi-sender --config {}", path.display());
            } else {
                print_error("Configuration is incomplete.");
                println!();
                println!("Please add the missing required sections.");
            }
        }
        Err(e) => {
            print_error(&format!("TOML syntax error: {}", e));
            println!();
            println!("Please fix the syntax errors in the configuration file.");
        }
    }

    println!();
}

// =============================================================================
// Interactive Configuration Wizard
// =============================================================================

/// Run the interactive configuration wizard.
pub async fn run_init_wizard() {
    println!();
    println!("╔═══════════════════════════════════════════════════════════════╗");
    println!("║              Misogi Configuration Wizard                       ║");
    println!("║                   (対話型設定ウィザード)                        ║");
    println!("╚═══════════════════════════════════════════════════════════════╝");
    println!();

    // Step 1: Deployment mode
    println!("[1/4] Select deployment mode:");
    println!("  1. Docker Compose (recommended)");
    println!("  2. Kubernetes / Helm");
    println!("  3. Bare metal (direct binary)");
    println!();

    let mode = read_input("Select [1-3]", "1");
    let deployment_mode = match mode.as_str() {
        "2" => "kubernetes",
        "3" => "baremetal",
        _ => "docker",
    };
    println!();

    // Step 2: Compliance preset
    println!("[2/4] Select compliance preset:");
    println!("  1. lgwan_government  - Japanese local government (LGWAN)");
    println!("  2. medical_hipaa_jp - Medical institution (HIPAA-aligned)");
    println!("  3. sler_general     - General enterprise");
    println!("  4. nist_zta         - US NIST Zero Trust");
    println!("  5. minimal          - Minimal (development/testing)");
    println!();

    let preset_choice = read_input("Select [1-5]", "5");
    let preset = match preset_choice.as_str() {
        "1" => "lgwan",
        "2" => "medical",
        "3" => "enterprise",
        "4" => "nist_zta",
        _ => "minimal",
    };
    println!();

    // Step 3: Network configuration
    println!("[3/4] Configure network:");
    let sender_port = read_input("Sender port [3001]", "3001");
    let receiver_port = read_input("Receiver port [3002]", "3002");
    let tunnel_port = read_input("Tunnel port [9000]", "9000");
    println!();

    // Step 4: Optional features
    println!("[4/4] Enable optional features:");
    let pii_enabled = read_bool("PII detection", false);
    let vendor_isolation = read_bool("Vendor isolation", false);
    let cef_logging = read_bool("CEF logging (SIEM)", false);
    println!();

    // Generate configuration
    println!("Generating configuration...");
    println!("==========================");
    println!();

    // Create config file
    let config_content = generate_config(
        deployment_mode,
        preset,
        &sender_port,
        &receiver_port,
        &tunnel_port,
        pii_enabled,
        vendor_isolation,
        cef_logging,
    );

    let config_path = PathBuf::from("misogi.toml");
    match std::fs::write(&config_path, &config_content) {
        Ok(_) => print_success(&format!("Created: {}", config_path.display())),
        Err(e) => print_error(&format!("Failed to create config: {}", e)),
    }

    // Create data directories
    let dirs = [
        "data/uploads",
        "data/staging",
        "data/chunks",
        "data/downloads",
    ];
    for dir in &dirs {
        if let Err(e) = std::fs::create_dir_all(dir) {
            print_warning(&format!("Could not create {}: {}", dir, e));
        }
    }
    print_success("Created data directories");

    // Generate RSA keypair
    generate_keypair().await;

    // Create .env file
    if !std::path::Path::new(".env").exists() && std::path::Path::new("docker/env.example").exists()
    {
        if let Err(e) = std::fs::copy("docker/env.example", ".env") {
            print_warning(&format!("Could not create .env: {}", e));
        } else {
            print_success("Created: .env");
        }
    }

    println!();
    println!("╔═══════════════════════════════════════════════════════════════╗");
    println!("║                    Setup Complete!                             ║");
    println!("╚═══════════════════════════════════════════════════════════════╝");
    println!();
    println!("Next steps:");
    println!();

    match deployment_mode {
        "docker" => {
            println!("  docker compose up -d");
            println!("  curl http://localhost:{}/api/v1/health", sender_port);
        }
        "kubernetes" => {
            println!("  helm install misogi ./helm/misogi");
        }
        _ => {
            println!("  cargo build --release");
            println!("  ./target/release/misogi-sender --config misogi.toml &");
            println!("  ./target/release/misogi-receiver --config misogi.toml &");
        }
    }
    println!();
}

fn read_input(prompt: &str, default: &str) -> String {
    print!("{} [{}]: ", prompt, default);
    use std::io::{self, Write};
    io::stdout().flush().ok();

    let mut input = String::new();
    io::stdin().read_line(&mut input).ok();

    let trimmed = input.trim();
    if trimmed.is_empty() {
        default.to_string()
    } else {
        trimmed.to_string()
    }
}

fn read_bool(prompt: &str, default: bool) -> bool {
    let default_str = if default { "Y/n" } else { "y/N" };
    let input = read_input(prompt, default_str);
    match input.to_lowercase().as_str() {
        "y" | "yes" | "1" => true,
        "n" | "no" | "0" => false,
        _ => default,
    }
}

#[allow(clippy::too_many_arguments)]
fn generate_config(
    mode: &str,
    preset: &str,
    sender_port: &str,
    receiver_port: &str,
    tunnel_port: &str,
    pii_enabled: bool,
    vendor_isolation: bool,
    cef_logging: bool,
) -> String {
    let log_format = if cef_logging { "cef" } else { "json" };

    // Try to load from preset file
    let preset_path = format!("config/examples/{}.toml", preset);
    if std::path::Path::new(&preset_path).exists()
        && let Ok(content) = std::fs::read_to_string(&preset_path)
    {
        // Customize ports
        return content
            .replace(
                "addr = \"0.0.0.0:3001\"",
                &format!("addr = \"0.0.0.0:{}\"", sender_port),
            )
            .replace(
                "addr = \"0.0.0.0:3002\"",
                &format!("addr = \"0.0.0.0:{}\"", receiver_port),
            )
            .replace(
                "local_port = 9000",
                &format!("local_port = {}", tunnel_port),
            );
    }

    // Generate minimal config
    format!(
        r#"# Misogi Configuration
# Generated by: misogi-sender --init
# Preset: {}
# Mode: {}

[server]
addr = "0.0.0.0:{}"

[storage]
upload_dir = "./data/uploads"
staging_dir = "./data/staging"

[tunnel]
local_port = {}

[pii_detector]
enabled = {}

[log]
format = "{}"

[vendor_isolation]
enabled = {}
"#,
        preset, mode, sender_port, tunnel_port, pii_enabled, log_format, vendor_isolation
    )
}

async fn generate_keypair() {
    let keys_dir = PathBuf::from("keys");

    if keys_dir.join("private.pem").exists() && keys_dir.join("public.pem").exists() {
        print_info("RSA keypair already exists, skipping");
        return;
    }

    if std::fs::create_dir_all(&keys_dir).is_err() {
        print_warning("Could not create keys directory");
        return;
    }

    // Try openssl
    let private_path = keys_dir.join("private.pem");
    let public_path = keys_dir.join("public.pem");

    let private_result = Command::new("openssl")
        .args(["genrsa", "-out"])
        .arg(&private_path)
        .arg("2048")
        .output();

    match private_result {
        Ok(output) if output.status.success() => {
            let public_result = Command::new("openssl")
                .args(["rsa", "-in"])
                .arg(&private_path)
                .args(["-pubout", "-out"])
                .arg(&public_path)
                .output();

            match public_result {
                Ok(_) => print_success("Generated RSA keypair in keys/"),
                Err(_) => print_warning("Failed to generate public key"),
            }
        }
        _ => {
            print_warning("OpenSSL not found, skipping key generation");
            print_info(
                "Generate keys: cargo run --package misogi-auth --example generate-keys -- ./keys",
            );
        }
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

fn print_success(msg: &str) {
    println!("[✓] {}", msg);
}

fn print_warning(msg: &str) {
    println!("[!] {}", msg);
}

fn print_error(msg: &str) {
    println!("[✗] {}", msg);
}

fn print_info(msg: &str) {
    println!("    {}", msg);
}
