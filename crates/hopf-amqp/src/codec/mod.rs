// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Incremental push AMQP 0-9-1 frame codec.

pub mod encode;
pub mod methods;
pub mod parser;
pub mod properties;
pub mod table;
pub mod types;

pub use parser::{AmqpFrameHandler, AmqpFrameParser, DEFAULT_MAX_FRAME};
pub use properties::BasicProperties;
pub use table::{encode_amqplain, FieldTable, FieldValue};
pub use types::{
    class, PROTOCOL_HEADER, FRAME_BODY, FRAME_END, FRAME_HEADER, FRAME_HEARTBEAT, FRAME_METHOD,
};

/// Errors from parsing or decoding AMQP wire data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AmqpError {
    /// Malformed encoding.
    Malformed(&'static str),
    /// Unknown frame type octet.
    UnknownFrameType(u8),
    /// Frame size exceeds the negotiated / configured maximum.
    FrameTooLarge {
        /// Declared payload size.
        size: u32,
        /// Configured maximum.
        max: u32,
    },
}

impl std::fmt::Display for AmqpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(msg) => write!(f, "malformed AMQP frame: {msg}"),
            Self::UnknownFrameType(v) => write!(f, "unknown AMQP frame type: {v}"),
            Self::FrameTooLarge { size, max } => {
                write!(f, "AMQP frame too large: {size} exceeds max {max}")
            }
        }
    }
}

impl std::error::Error for AmqpError {}
