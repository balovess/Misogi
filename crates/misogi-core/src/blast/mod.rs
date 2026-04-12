//! UDP Blast transport protocol for air-gap / data-diode environments.
//!
//! This module implements transfer protocols designed for use over physical
//! data diodes or unidirectional network links where traditional bidirectional
//! TCP connections are not possible.
//!
//! # Architecture
//!
//! ## Mode A: UDP Blast (Fire-and-Forget)
//!
//! ```text
//! Sender ──[FEC Encode]──► [Interleave] ──[UDP Blast]──► Receiver
//!                              │                        │
//!                              │  No ACK, no handshake   │  Collect shards
//!                              │  Fire-and-forget        │  FEC Decode → File
//! ```
//!
//! ## Mode B: Pull Driver (Poll-Based)
//!
//! ```text
//! Sender                    Buffer Zone                  Receiver
//! ┌──────┐    write()     ┌──────────────┐   poll()   ┌──────────┐
//! │      │ ─────────────► │ PullBuffer   │ ◄───────── │          │
//! │ Send │                │ [entry, ...] │            │  Receive │
//! │ er   │                ├──────────────┤   pull()   │          │
//! │      │                │              │ ─────────► │          │
//! └──────┘                └──────────────┘   ack()    └──────────┘
//! ```
//!
//! ## Mode C: Blind Send (Broadcast + FEC)
//!
//! ```text
//! BlindSend Encoder ──[FEC+Seq]──► [UDP Broadcast]──► [Air Gap] ──► Decoder
//! ```
//!
//! # Modules
//!
//! - [`frame`] — Wire format definition (header, payload, CRC32)
//! - [`sender`] — UdpBlastSender (encode -> interleave -> fire)
//! - [`receiver`] — UdpBlastReceiver (passive listen -> collect -> decode)
//! - [`pull_driver`] — PullDriver (Mode B: poll-based pull transfer)
//! - [`blind_send_driver`] — BlindSendDriver (Mode C: UDP broadcast + FEC)
//! - [`factory`] — TransferFactoryConfig / TransferMode (mode selection & driver construction)

pub mod blind_send_driver;
pub mod factory;
pub mod frame;
pub mod pull_driver;
pub mod sender;
pub mod receiver;

pub use frame::{
    BlastFlags, BlastHeader, BlastPacket, BlastManifest, FecConfigInfo,
    BLAST_MAGIC, BLAST_VERSION, BLAST_HEADER_SIZE, BLAST_TRAILER_SIZE,
};
pub use sender::{UdpBlastSender, BlastSenderConfig, BlastSendReport};
pub use receiver::{UdpBlastReceiver, BlastReceiverConfig, BlastReceiveReport};
pub use pull_driver::{
    PullDriver, PullConfig, PullBufferEntry, PullEntryStatus,
};
pub use blind_send_driver::{
    BlindSendDriver, BlindSendConfig,
    FecPacket, BlindSendEncoder, BlindSendDecoder,
};
pub use factory::{
    TransferMode, TransferFactoryConfig, DirectTcpFactoryConfig,
    BuiltDriver, BuiltDriverConfig,
};
