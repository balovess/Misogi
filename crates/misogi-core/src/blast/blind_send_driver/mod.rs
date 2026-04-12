//! Blind Send Driver — Mode C: UDP broadcast + FEC for air-gap file transfer.
//!
//! This module implements a **pure fire-and-forget** transport driver designed
//! for physical unidirectional data diodes (光閘 / optical diode) where **zero**
//! reverse communication is possible. Unlike [`UdpBlastDriver`](super::UdpBlastDriver)
//! which wraps the full blast sender/receiver pipeline, this driver operates at
//! a lower level with direct FEC encoding and raw UDP broadcast.
//!
//! # Architecture Overview
//!
//! ```text
//!  ┌──────────────┐     ┌─────────────────┐     ┌──────────────────┐
//!  │ BlindSend    │     │ BlindSend       │     │ BlindSend        │
//!  │ Encoder      │──UDP─▶│ [Air Gap /      │──UDP─▶│ Decoder          │
//!  │ (FEC + Seq)  │Broadcast│ Optical Diode]  │Recv │ (Reconstruct)    │
//!  └──────────────┘     └─────────────────┘     └──────────────────┘
//!        Fire-and-Forget         No ACK Possible        Loss-Tolerant
//! ```
//!
//! # Design Principles
//!
//! 1. **No Feedback Channel**: The sender never expects or waits for any response.
//!    All reliability comes from Forward Error Correction (Reed-Solomon).
//! 2. **Broadcast Transmission**: Uses UDP broadcast to reach all receivers on the
//!    subnet without knowing their specific addresses.
//! 3. **Configurable Redundancy**: The `redundancy_factor` controls the parity-to-data
//!    ratio, allowing tuning for different loss environments (1.5x = mild, 3x = extreme).
//! 4. **Ordered Reconstruction**: Each packet carries sequence numbers enabling the
//!    receiver to reassemble data in correct order even with out-of-order arrival.
//!
//! # FEC Integration
//!
//! This driver integrates with the existing [`ReedSolomonCodec`](crate::fec::reed_solomon::ReedSolomonCodec)
//! from the `fec` module. The `redundancy_factor` parameter is mapped to concrete
//! `data_shards` / `parity_shards` counts as follows:
//!
//! | redundancy_factor | data_shards | parity_shards | Max Tolerable Loss |
//! |-------------------|-------------|---------------|-------------------|
//! | 1.5               | 16          | 7             | ~30%              |
//! | 2.0               | 16          | 15            | ~48%              |
//! | 2.5               | 16          | 24→capped→15  | ~48%              |
//! | 3.0               | 16          | 32→capped→15  | ~48%              |
//!
//! # Thread Safety
//!
//! `BlindSendDriver` implements `Send + Sync` as required by the [`TransferDriver`](crate::traits::TransferDriver)
//! trait. Internal state uses `Arc<AtomicBool>` for lock-free initialization tracking.

pub(crate) mod decoder;
pub(crate) mod driver;
#[cfg(test)] mod driver_tests;
pub(crate) mod encoder;
pub(crate) mod packet;

pub use decoder::BlindSendDecoder;
pub use driver::{BlindSendConfig, BlindSendDriver};
pub use encoder::BlindSendEncoder;
pub use packet::FecPacket;
