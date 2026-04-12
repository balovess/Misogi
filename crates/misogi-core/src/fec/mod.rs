//! Forward Error Correction (FEC) engine for lossy transport protocols.
//!
//! When operating over air-gapped networks with physical data diodes,
//! packet loss is inevitable and there is no mechanism for retransmission.
//! FEC encodes redundancy into each transmission so that the receiver can
//! reconstruct the original data even when a percentage of packets are lost.
//!
//! # Algorithm Selection
//!
//! Misogi uses **Reed-Solomon erasure coding** as the primary FEC algorithm:
//!
//! - Encodes N data shards into M total shards (N data + M parity)
//! - Can recover from up to M missing shards (any combination)
//! - Optimal for burst loss patterns common in optical diode environments
//! - Computationally efficient for typical file sizes (KB to GB range)
//!
//! # Parameters
//!
//! | Parameter | Default | Description |
//! |-----------|---------|-------------|
//! | data_shards | 16 | Number of original data shards per block |
//! | parity_shards | 4 | Number of parity shards (tolerates 20% loss) |
//! | max_loss_rate | 0.25 | Maximum tolerable packet loss rate (25%) |
//! | shard_size | 4096 | Bytes per shard (matches MTU-friendly sizing) |
//!
//! # Loss Tolerance Table
//!
//! | Data Shards | Parity Shards | Max Recoverable Loss |
//! |-------------|---------------|---------------------|
//! | 16 | 4 | 20% |
//! | 16 | 6 | 27.3% |
//! | 32 | 10 | 23.8% |
//! | 64 | 16 | 20% |
//! | 32 | 24 | 42.9% (extreme mode) |

pub mod reed_solomon;
pub mod interleaver;

use serde::{Deserialize, Serialize};

/// Configuration parameters for the FEC encoding engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FecConfig {
    /// Number of original data shards per encoding block.
    ///
    /// Higher values increase parallelism but require more memory
    /// and slightly increase decoding complexity (O(n²) in shard count).
    #[serde(default = "default_data_shards")]
    pub data_shards: usize,

    /// Number of parity (redundancy) shards generated per block.
    ///
    /// Determines the maximum tolerable packet loss:
    /// - `parity_shards / (data_shards + parity_shards)` = max loss rate
    /// - E.g., 4/20 = 20%, 8/40 = 20%, 16/48 = 33.3%
    #[serde(default = "default_parity_shards")]
    pub parity_shards: usize,

    /// Size of each individual shard in bytes.
    ///
    /// Should be chosen to fit within a single UDP datagram payload
    /// after accounting for Blast header (55 bytes) and trailer (4 bytes).
    /// For standard Ethernet MTU (1500), use ≤ 1400 bytes.
    /// For jumbo frames (9000), use ≤ 8900 bytes.
    #[serde(default = "default_shard_size")]
    pub shard_size: usize,
}

impl Default for FecConfig {
    fn default() -> Self {
        Self {
            data_shards: default_data_shards(),
            parity_shards: default_parity_shards(),
            shard_size: default_shard_size(),
        }
    }
}

impl FecConfig {
    /// Total number of shards (data + parity) per encoded block.
    pub fn total_shards(&self) -> usize {
        self.data_shards + self.parity_shards
    }

    /// Maximum number of lost shards that can still be recovered from.
    pub fn recoverable_loss(&self) -> usize {
        self.parity_shards
    }

    /// Maximum tolerable packet loss rate as a fraction (0.0 to 1.0).
    pub fn max_loss_rate(&self) -> f64 {
        self.parity_shards as f64 / self.total_shards() as f64
    }

    /// Returns true if this configuration can tolerate the given loss rate.
    pub fn can_tolerate_loss(&self, loss_rate: f64) -> bool {
        loss_rate <= self.max_loss_rate()
    }
}

fn default_data_shards() -> usize { 16 }
fn default_parity_shards() -> usize { 4 }
fn default_shard_size() -> usize { 1400 }

/// Result of FEC encoding operation.
///
/// Contains all encoded shards plus metadata needed for reconstruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FecEncodedBlock {
    /// Original data length before encoding (needed for padding removal).
    pub original_len: usize,

    /// Encoded data shards (length = `data_shards`).
    pub data_shards: Vec<Vec<u8>>,

    /// Encoded parity/redundancy shards (length = `parity_shards`).
    pub parity_shards: Vec<Vec<u8>>,

    /// Configuration used for encoding (must match decoder config).
    pub config: FecConfig,
}

impl FecEncodedBlock {
    /// Total number of shards in this block.
    pub fn total_shards(&self) -> usize {
        self.data_shards.len() + self.parity_shards.len()
    }

    /// Get a specific shard by index.
    ///
    /// Indices 0..data_shards-1 are data shards,
    /// indices data_shards..total are parity shards.
    pub fn get_shard(&self, index: usize) -> Option<&[u8]> {
        if index < self.data_shards.len() {
            Some(&self.data_shards[index])
        } else if index < self.total_shards() {
            let pidx = index - self.data_shards.len();
            Some(&self.parity_shards[pidx])
        } else {
            None
        }
    }
}

/// Preset configurations for common scenarios.
impl FecConfig {
    /// Standard configuration: 16+4 shards, 20% loss tolerance.
    /// Suitable for typical optical diode environments with moderate noise.
    pub fn standard() -> Self {
        Self::default()
    }

    /// High-reliability configuration: 16+8 shards, 33% loss tolerance.
    /// Use when the data diode has known high error rates or interference.
    pub fn high_reliability() -> Self {
        Self {
            data_shards: 16,
            parity_shards: 8,
            shard_size: 1400,
        }
    }

    /// Extreme configuration: 32+24 shards, ~43% loss tolerance.
    /// Only use when extreme packet loss is expected (e.g., RF links).
    pub fn extreme() -> Self {
        Self {
            data_shards: 32,
            parity_shards: 24,
            shard_size: 1024,
        }
    }

    /// Low-latency configuration: fewer, larger shards.
    /// Reduces encoding overhead at the cost of lower loss tolerance.
    pub fn low_latency() -> Self {
        Self {
            data_shards: 8,
            parity_shards: 2,
            shard_size: 8000,
        }
    }
}
