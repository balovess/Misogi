use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SenderConfig {
    pub server_addr: String,
    pub storage_dir: String,
    pub receiver_addr: Option<String>,
    pub chunk_size: usize,
    pub log_level: String,
    #[serde(default)]
    pub watch_dir: Option<String>,
    #[serde(default)]
    pub output_dir: Option<String>,
}

fn default_server_addr() -> String {
    "0.0.0.0:3001".to_string()
}

fn default_storage_dir() -> String {
    "./data/sender/uploads".to_string()
}

fn default_chunk_size() -> usize {
    8 * 1024 * 1024
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Default for SenderConfig {
    fn default() -> Self {
        Self {
            server_addr: default_server_addr(),
            storage_dir: default_storage_dir(),
            receiver_addr: None,
            chunk_size: default_chunk_size(),
            log_level: default_log_level(),
            watch_dir: None,
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
    chunk_size: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
struct TomlTunnelConfig {
    receiver_addr: Option<String>,
    heartbeat_interval_secs: Option<u64>,
    timeout_secs: Option<u64>,
    direction: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
struct TomlDaemonConfig {
    watch_dir: Option<String>,
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

impl SenderConfig {
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
            if let Some(size) = storage.chunk_size {
                config.chunk_size = size;
            }
        }

        if let Some(tunnel) = &toml.tunnel {
            if let Some(addr) = &tunnel.receiver_addr {
                config.receiver_addr = Some(addr.clone());
            }
        }

        if let Some(daemon) = &toml.daemon {
            if let Some(dir) = &daemon.watch_dir {
                config.watch_dir = Some(dir.clone());
            }
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
        if let Ok(dir) = std::env::var("MISOGI_STORAGE_DIR") {
            config.storage_dir = dir;
        }
        if let Ok(addr) = std::env::var("MISOGI_RECEIVER_ADDR") {
            config.receiver_addr = Some(addr);
        }
        if let Ok(size) = std::env::var("MISOGI_CHUNK_SIZE") {
            if let Ok(parsed) = size.parse::<usize>() {
                config.chunk_size = parsed;
            }
        }
        if let Ok(level) = std::env::var("MISOGI_LOG_LEVEL") {
            config.log_level = level;
        }
        if let Ok(dir) = std::env::var("MISOGI_WATCH_DIR") {
            config.watch_dir = Some(dir);
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
        if cli.receiver.is_some() {
            config.receiver_addr = cli.receiver.clone();
        }
        if cli.chunk_size.is_some() {
            config.chunk_size = cli.chunk_size.unwrap();
        }
        if cli.log_level.is_some() {
            config.log_level = cli.log_level.clone().unwrap();
        }
        if cli.watch.is_some() {
            config.watch_dir = cli.watch.as_ref().map(|p| p.to_string_lossy().to_string());
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
