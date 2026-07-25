// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Incremental push MQTT frame codec.
//!
//! - [`varint`] — the MQTT variable-length integer encoding used for
//!   Remaining Length and property length.
//! - [`properties`] — MQTT 5.0 properties (`Properties`, property id
//!   constants).
//! - [`packet`] — packet type / protocol version / QoS enums, reason code
//!   constants, and the packet structs (`ConnectPacket`, `PublishHeader`,
//!   `SubscribeFilter`).
//! - [`decode`] / [`encode`] — free functions to/from complete wire bytes
//!   for each packet type.
//! - [`parser`] — [`parser::MqttFrameParser`], the incremental push parser
//!   that streams PUBLISH payloads instead of buffering them whole.

pub mod decode;
pub mod encode;
pub mod packet;
pub mod parser;
pub mod properties;
pub mod varint;

pub use packet::{
    reason, ConnectPacket, PacketType, ProtocolVersion, PublishHeader, QoS, SubscribeFilter, Will,
};
pub use parser::{MqttFrameHandler, MqttFrameParser, DEFAULT_MAX_PACKET_SIZE};
pub use properties::{property, PropertyValue, Properties};

/// Errors from parsing or decoding MQTT wire data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MqttError {
    /// Malformed encoding (bad varint, truncated field, invalid UTF-8, ...).
    Malformed(&'static str),
    /// Fixed header named an unassigned packet type value.
    UnknownPacketType(u8),
    /// CONNECT named a protocol level this crate doesn't support.
    UnsupportedProtocolVersion(u8),
    /// A packet's Remaining Length exceeded the configured maximum.
    PacketTooLarge {
        /// The packet's declared Remaining Length.
        remaining_length: u32,
        /// The configured maximum.
        max: u32,
    },
}

impl std::fmt::Display for MqttError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(msg) => write!(f, "malformed MQTT packet: {msg}"),
            Self::UnknownPacketType(v) => write!(f, "unknown MQTT packet type: {v}"),
            Self::UnsupportedProtocolVersion(v) => {
                write!(f, "unsupported MQTT protocol version: {v}")
            }
            Self::PacketTooLarge { remaining_length, max } => write!(
                f,
                "MQTT packet too large: {remaining_length} bytes exceeds max {max}"
            ),
        }
    }
}

impl std::error::Error for MqttError {}
