use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReceiverConfig {
    pub server_addr: String,
    pub download_dir: String,
    pub storage_dir: String,
    pub tunnel_port: u16,
    pub log_level: String,
    #[serde(default)]
    pub output_dir: Option<String>,
}

impl Default for ReceiverConfig {
    fn default() -> Self {
        Self {
            server_addr: "0.0.0.0:3002".to_string(),
            download_dir: "./data/receiver/downloads".to_string(),
            storage_dir: "./data/receiver/chunks".to_string(),
            tunnel_port: 9000,
            log_level: "info".to_string(),
            output_dir: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
struct TomlServerConfig {
    addr: Option<String>,
    log_level: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
struct TomlStorageConfig {
    dir: Option<String>,
    download_dir: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
struct TomlTunnelConfig {
    port: Option<u16>,
    heartbeat_interval_secs: Option<u64>,
    timeout_secs: Option<u64>,
    direction: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
struct TomlDaemonConfig {
    output_dir: Option<String>,
    poll_interval_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
struct TomlConfig {
    server: Option<TomlServerConfig>,
    storage: Option<TomlStorageConfig>,
    tunnel: Option<TomlTunnelConfig>,
    daemon: Option<TomlDaemonConfig>,
}

impl ReceiverConfig {
    pub fn from_toml_file(path: &Path) -> Option<Self> {
        let content = std::fs::read_to_string(path).ok()?;
        let toml_config: TomlConfig = toml::from_str(&content).ok()?;
        Some(Self::from_toml(toml_config))
    }

    fn from_toml(toml: TomlConfig) -> Self {
        let mut config = Self::default();

        if let Some(server) = &toml.server {
            if let Some(addr) = &server.addr {
                config.server_addr = addr.clone();
            }
            if let Some(level) = &server.log_level {
                config.log_level = level.clone();
            }
        }

        if let Some(storage) = &toml.storage {
            if let Some(dir) = &storage.dir {
                config.storage_dir = dir.clone();
            }
            if let Some(dir) = &storage.download_dir {
                config.download_dir = dir.clone();
            }
        }

        if let Some(tunnel) = &toml.tunnel {
            if let Some(port) = tunnel.port {
                config.tunnel_port = port;
            }
        }

        if let Some(daemon) = &toml.daemon {
            if let Some(dir) = &daemon.output_dir {
                config.output_dir = Some(dir.clone());
            }
        }

        config
    }

    pub fn from_env(mut config: Self) -> Self {
        if let Ok(addr) = std::env::var("MISOGI_SERVER_ADDR") {
            config.server_addr = addr;
        }
        if let Ok(dir) = std::env::var("MISOGI_DOWNLOAD_DIR") {
            config.download_dir = dir;
        }
        if let Ok(dir) = std::env::var("MISOGI_STORAGE_DIR") {
            config.storage_dir = dir;
        }
        if let Ok(port) = std::env::var("MISOGI_TUNNEL_PORT") {
            if let Ok(p) = port.parse::<u16>() {
                config.tunnel_port = p;
            }
        }
        if let Ok(level) = std::env::var("MISOGI_LOG_LEVEL") {
            config.log_level = level;
        }
        if let Ok(dir) = std::env::var("MISOGI_OUTPUT_DIR") {
            config.output_dir = Some(dir);
        }
        config
    }

    pub fn from_cli(cli: &crate::cli::CommandLine, mut config: Self) -> Self {
        if cli.addr.is_some() {
            config.server_addr = cli.addr.clone().unwrap();
        }
        if cli.storage_dir.is_some() {
            config.storage_dir = cli.storage_dir.clone().unwrap();
        }
        if cli.download_dir.is_some() {
            config.download_dir = cli.download_dir.clone().unwrap();
        }
        if cli.tunnel_port.is_some() {
            config.tunnel_port = cli.tunnel_port.unwrap();
        }
        if cli.log_level.is_some() {
            config.log_level = cli.log_level.clone().unwrap();
        }
        if cli.output.is_some() {
            config.output_dir = cli.output.as_ref().map(|p| p.to_string_lossy().to_string());
        }
        config
    }

    pub fn load_with_cli(cli: &crate::cli::CommandLine) -> Self {
        let mut config = Self::default();

        if let Some(ref path) = cli.config {
            if let Some(toml_config) = Self::from_toml_file(path.as_path()) {
                config = toml_config;
            }
        } else if Path::new("misogi.toml").exists() {
            if let Some(toml_config) = Self::from_toml_file(Path::new("misogi.toml")) {
                config = toml_config;
            }
        }

        config = Self::from_env(config);

        config = Self::from_cli(cli, config);

        config
    }

    pub fn load() -> Self {
        let mut config = Self::default();

        if Path::new("misogi.toml").exists() {
            if let Some(toml_config) = Self::from_toml_file(Path::new("misogi.toml")) {
                config = toml_config;
            }
        }

        config = Self::from_env(config);

        config
    }
}
