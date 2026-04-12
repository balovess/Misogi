//! Transfer mode factory — runtime driver selection via configuration.
//!
//! Provides [`TransferMode`], [`TransferFactoryConfig`], and [`BuiltDriver`] for
//! selecting and instantiating the appropriate [`TransferDriver`](crate::traits::TransferDriver)
//! from a single TOML/JSON config block.
//!
//! # Modes
//!
//! | Mode        | Driver                  | Transport          |
//! |-------------|------------------------|--------------------|
//! | `push`      | [`DirectTcpDriver`]     | TCP tunnel         |
//! | `pull`      | [`PullDriver`]          | In-memory buffer   |
//! | `blind_send`| [`BlindSendDriver`]     | UDP broadcast + FEC|
//!
//! # Example (TOML)
//!
//! ```toml
//! [transfer]
//! mode = "pull"
//! [transfer.pull_config]
//! poll_interval_ms = 5000
//! ```

use std::fmt;
use std::str::FromStr;

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::{MisogiError, Result};
use crate::traits::{
    ChunkAck, DriverHealthStatus, TransferDriver, TransferDriverConfig,
};

use super::blind_send_driver::{BlindSendConfig, BlindSendDriver};
use super::pull_driver::{PullConfig, PullDriver};
// DirectTcpDriver lives in crate::drivers, not in blast module.
// We import it here for Push mode construction.
use crate::drivers::DirectTcpDriver;
use crate::drivers::DirectTcpDriverConfig;

// =============================================================================
// A. TransferMode Enumeration
// =============================================================================

/// Selects which transport driver to instantiate at runtime.
///
/// Each variant maps to a concrete [`TransferDriver`] implementation.
/// Parse from config strings via [`FromStr`] (accepts `"push"`, `"pull"`, `"blind_send"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferMode {
    /// Push mode: direct TCP tunnel via [`DirectTcpDriver`].
    Push,
    /// Pull mode: receiver polls buffer zone via [`PullDriver`].
    Pull,
    /// Blind send mode: fire-and-forget UDP + FEC via [`BlindSendDriver`].
    BlindSend,
}

impl Default for TransferMode {
    /// Default transfer mode is `Push` (direct TCP).
    fn default() -> Self {
        Self::Push
    }
}

impl fmt::Display for TransferMode {
    /// Format as lowercase snake_case string suitable for config files and logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Push => write!(f, "push"),
            Self::Pull => write!(f, "pull"),
            Self::BlindSend => write!(f, "blind_send"),
        }
    }
}

impl FromStr for TransferMode {
    /// Parse a case-insensitive string into a [`TransferMode`] variant.
    ///
    /// Accepted values: `"push"`, `"pull"`, `"blind_send"`.
    ///
    /// # Errors
    ///
    /// Returns [`MisogiError::Configuration`] if the string does not match
    /// any known transfer mode. The error message lists all valid modes.
    type Err = MisogiError;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_lowercase().as_str() {
            "push" => Ok(Self::Push),
            "pull" => Ok(Self::Pull),
            "blind_send" => Ok(Self::BlindSend),
            other => Err(MisogiError::Configuration(format!(
                "Invalid transfer mode '{}'. Valid modes: push, pull, blind_send",
                other,
            ))),
        }
    }
}

// =============================================================================
// B. TransferFactoryConfig — Unified Configuration Structure
// =============================================================================

/// Unified configuration for transfer driver selection and instantiation.
///
/// Single entry point for Misogi transport layer config. The `mode` field selects
/// the driver via [`build_driver()`](Self::build_driver); mode-specific fields
/// provide per-driver parameters. All mode-specific configs are `Option<T>` — missing
/// fields fall back to their `Default` implementations.
///
/// # Example (TOML)
///
/// ```toml
/// mode = "pull"
/// [pull_config]
/// poll_interval_ms = 5000
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferFactoryConfig {
    /// Transfer mode determining which driver to instantiate.
    #[serde(default)]
    pub mode: TransferMode,

    /// Configuration for Push mode ([`DirectTcpDriver`]).
    ///
    /// Required when `mode` is `Push`; ignored otherwise.
    #[serde(default)]
    pub push_config: Option<DirectTcpFactoryConfig>,

    /// Configuration for Pull mode ([`PullDriver`]).
    ///
    /// Required when `mode` is `Pull`; ignored otherwise.
    /// Falls back to [`PullConfig::default()`] if `None`.
    #[serde(default)]
    pub pull_config: Option<PullConfig>,

    /// Configuration for BlindSend mode ([`BlindSendDriver`]).
    ///
    /// Required when `mode` is `BlindSend`; ignored otherwise.
    /// Falls back to [`BlindSendConfig::default()`] if `None`.
    #[serde(default)]
    pub blind_send_config: Option<BlindSendConfig>,
}

impl Default for TransferFactoryConfig {
    /// Default factory config: Push mode with empty address/node_id.
    fn default() -> Self {
        Self {
            mode: TransferMode::Push,
            push_config: None,
            pull_config: None,
            blind_send_config: None,
        }
    }
}

// =============================================================================
// C. DirectTcpFactoryConfig — Simplified Push-mode config wrapper
// =============================================================================

/// Simplified configuration for constructing [`DirectTcpDriver`] in factory context.
///
/// This is a lightweight wrapper around the essential fields needed by
/// [`DirectTcpDriver::new()`]. For advanced TCP options, use
/// [`DirectTcpDriverConfig`](crate::drivers::DirectTcpDriverConfig) directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectTcpFactoryConfig {
    /// TCP address of the receiver endpoint (e.g., "192.168.1.100:9000").
    pub receiver_addr: String,

    /// Unique identifier for this node in the Misogi network topology.
    pub node_id: String,
}

impl Default for DirectTcpFactoryConfig {
    fn default() -> Self {
        Self {
            receiver_addr: String::from("127.0.0.1:9000"),
            node_id: String::from("misogi-node"),
        }
    }
}

// =============================================================================
// D. BuiltDriver — Enum Wrapper Implementing TransferDriver
// =============================================================================

/// Type-erased driver instance produced by [`TransferFactoryConfig::build_driver()`].
///
/// Wraps one of three concrete drivers behind a common [`TransferDriver`] impl,
/// enabling runtime polymorphism without trait objects (impossible due to
/// associated `Config` type on [`TransferDriver`]).
#[derive(Debug)]
pub enum BuiltDriver {
    /// Wraps [`DirectTcpDriver`] for Push/TCP mode.
    Push(DirectTcpDriver),
    /// Wraps [`PullDriver`] for Pull/buffer mode.
    Pull(PullDriver),
    /// Wraps [`BlindSendDriver`] for BlindSend/UDP+FEC mode.
    BlindSend(BlindSendDriver),
}

/// Unified configuration enum for [`BuiltDriver::init()`].
///
/// Each variant carries the configuration for its corresponding driver type.
/// Callers match on the active [`TransferMode`] to construct the correct variant.
#[derive(Debug, Clone)]
pub enum BuiltDriverConfig {
    /// Configuration for [`DirectTcpDriver`] (Push mode).
    Push(DirectTcpDriverConfig),

    /// Configuration for [`PullDriver`] (Pull mode).
    Pull(PullConfig),

    /// Configuration for [`BlindSendDriver`] (BlindSend mode).
    BlindSend(BlindSendConfig),
}

impl TransferDriverConfig for BuiltDriverConfig {
    /// Validate whichever config variant is held.
    fn validate(&self) -> Result<()> {
        match self {
            Self::Push(c) => c.validate(),
            Self::Pull(c) => c.validate(),
            Self::BlindSend(c) => c.validate(),
        }
    }
}

#[async_trait]
impl TransferDriver for BuiltDriver {
    type Config = BuiltDriverConfig;

    fn name(&self) -> &str {
        match self {
            Self::Push(d) => d.name(),
            Self::Pull(d) => d.name(),
            Self::BlindSend(d) => d.name(),
        }
    }

    async fn init(&mut self, config: Self::Config) -> Result<()> {
        match (self, config) {
            (Self::Push(d), BuiltDriverConfig::Push(c)) => d.init(c).await,
            (Self::Pull(d), BuiltDriverConfig::Pull(c)) => d.init(c).await,
            (Self::BlindSend(d), BuiltDriverConfig::BlindSend(c)) => d.init(c).await,
            _ => Err(MisogiError::Configuration(
                "BuiltDriver init(): config variant mismatch with driver mode".into(),
            )),
        }
    }

    async fn send_chunk(
        &self,
        file_id: &str,
        chunk_index: u32,
        data: Bytes,
    ) -> Result<ChunkAck> {
        match self {
            Self::Push(d) => d.send_chunk(file_id, chunk_index, data).await,
            Self::Pull(d) => d.send_chunk(file_id, chunk_index, data).await,
            Self::BlindSend(d) => d.send_chunk(file_id, chunk_index, data).await,
        }
    }

    async fn send_complete(
        &self,
        file_id: &str,
        total_chunks: u32,
        file_md5: &str,
    ) -> Result<ChunkAck> {
        match self {
            Self::Push(d) => d.send_complete(file_id, total_chunks, file_md5).await,
            Self::Pull(d) => d.send_complete(file_id, total_chunks, file_md5).await,
            Self::BlindSend(d) => d.send_complete(file_id, total_chunks, file_md5).await,
        }
    }

    async fn health_check(&self) -> Result<DriverHealthStatus> {
        match self {
            Self::Push(d) => d.health_check().await,
            Self::Pull(d) => d.health_check().await,
            Self::BlindSend(d) => d.health_check().await,
        }
    }

    async fn shutdown(&self) -> Result<()> {
        match self {
            Self::Push(d) => d.shutdown().await,
            Self::Pull(d) => d.shutdown().await,
            Self::BlindSend(d) => d.shutdown().await,
        }
    }
}

// =============================================================================
// E. Factory Implementation
// =============================================================================

impl TransferFactoryConfig {
    /// Construct a new factory config with the specified transfer mode.
    ///
    /// Mode-specific configurations are left as `None` and will use defaults
    /// when [`build_driver()`](Self::build_driver) is called.
    pub fn new(mode: TransferMode) -> Self {
        Self {
            mode,
            ..Default::default()
        }
    }

    /// Instantiate the appropriate [`BuiltDriver`] based on `self.mode`.
    ///
    /// Core factory method: decouples driver selection from construction.
    /// Returns a [`BuiltDriver`] ready for [`TransferDriver::init()`].
    ///
    /// # Errors
    ///
    /// [`MisogiError::Configuration`] if Push mode has empty `receiver_addr`.
    pub fn build_driver(&self) -> Result<BuiltDriver> {
        match self.mode {
            TransferMode::Push => {
                let cfg = self.push_config.clone().unwrap_or_default();
                if cfg.receiver_addr.is_empty() {
                    return Err(MisogiError::Configuration(
                        "push_config.receiver_addr is required for Push mode".into(),
                    ));
                }
                let addr = cfg.receiver_addr.clone();
                let node_id = cfg.node_id.clone();
                let driver = DirectTcpDriver::new(addr.clone(), node_id.clone());
                tracing::info!(
                    mode = %self.mode,
                    addr = %addr,
                    node_id = %node_id,
                    "TransferFactory: created DirectTcpDriver (Push mode)"
                );
                Ok(BuiltDriver::Push(driver))
            }
            TransferMode::Pull => {
                let cfg = self.pull_config.clone().unwrap_or_default();
                let driver = PullDriver::with_config(cfg.clone());
                tracing::info!(
                    mode = %self.mode,
                    poll_interval_ms = cfg.poll_interval.as_millis(),
                    "TransferFactory: created PullDriver (Pull mode)"
                );
                Ok(BuiltDriver::Pull(driver))
            }
            TransferMode::BlindSend => {
                let cfg = self.blind_send_config.clone().unwrap_or_default();
                let driver = BlindSendDriver::new(cfg.clone());
                tracing::info!(
                    mode = %self.mode,
                    udp_port = cfg.udp_port,
                    redundancy = cfg.redundancy_factor,
                    "TransferFactory: created BlindSendDriver (BlindSend mode)"
                );
                Ok(BuiltDriver::BlindSend(driver))
            }
        }
    }

    /// Build the matching [`BuiltDriverConfig`] for the current mode.
    ///
    /// Returns the configuration wrapped in the correct [`BuiltDriverConfig`] variant
    /// so it can be passed to [`BuiltDriver::init()`].
    ///
    /// # Errors
    ///
    /// Returns [`MisogiError::Configuration`] if required fields are missing.
    pub fn build_init_config(&self) -> Result<BuiltDriverConfig> {
        match self.mode {
            TransferMode::Push => {
                let cfg = self.push_config.clone().unwrap_or_default();
                if cfg.receiver_addr.is_empty() {
                    return Err(MisogiError::Configuration(
                        "push_config.receiver_addr is required".into(),
                    ));
                }
                let addr = cfg.receiver_addr;
                let node_id = cfg.node_id;
                Ok(BuiltDriverConfig::Push(DirectTcpDriverConfig {
                    receiver_addr: addr,
                    node_id,
                    connect_timeout_secs: 30,
                }))
            }
            TransferMode::Pull => {
                let cfg = self.pull_config.clone().unwrap_or_default();
                Ok(BuiltDriverConfig::Pull(cfg))
            }
            TransferMode::BlindSend => {
                let cfg = self.blind_send_config.clone().unwrap_or_default();
                Ok(BuiltDriverConfig::BlindSend(cfg))
            }
        }
    }

    /// Validate config consistency for the selected mode (no driver construction).
    ///
    /// - `Push`: `receiver_addr` and `node_id` must be non-empty.
    /// - `Pull`: delegates to [`PullConfig::validate()`](super::pull_driver::types::PullConfig::validate).
    /// - `BlindSend`: delegates to [`BlindSendConfig::validate()`](super::blind_send_driver::driver::BlindSendConfig::validate).
    pub fn validate(&self) -> Result<()> {
        match self.mode {
            TransferMode::Push => {
                let cfg = self.push_config.clone().unwrap_or_default();
                if cfg.receiver_addr.is_empty() {
                    return Err(MisogiError::Configuration(
                        "Push mode requires non-empty push_config.receiver_addr".into(),
                    ));
                }
                if cfg.node_id.is_empty() {
                    return Err(MisogiError::Configuration(
                        "Push mode requires non-empty push_config.node_id".into(),
                    ));
                }
            }
            TransferMode::Pull => {
                let cfg = self.pull_config.clone().unwrap_or_default();
                cfg.validate()?;
            }
            TransferMode::BlindSend => {
                let cfg = self.blind_send_config.clone().unwrap_or_default();
                cfg.validate()?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
include!("factory_tests.rs");
