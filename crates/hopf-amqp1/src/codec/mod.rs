// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! AMQP 1.0 wire codec: the type system, frame parser, performatives, SASL
//! frame bodies, and message sections.

pub mod frame;
pub mod message;
pub mod performative;
pub mod sasl;
pub mod serial;
pub mod types;

pub use frame::{
    Amqp1FrameHandler, Amqp1FrameParser, FrameOutcome, DEFAULT_MAX_FRAME_SIZE, FRAME_TYPE_AMQP,
    FRAME_TYPE_SASL, MIN_MAX_FRAME_SIZE, PROTOCOL_ID_AMQP, PROTOCOL_ID_SASL, PROTOCOL_ID_TLS,
};
pub use message::{
    data_section_header, encode_application_properties, MessageHandler, MessageHeader,
    MessageParser, MessageProperties,
};
pub use performative::{
    decode_performative, Attach, Begin, Close, DeliveryState, Detach, Disposition, End,
    Error as Amqp1CompositeError, Flow, Open, Performative, Source, Target, Transfer,
};
pub use sasl::SaslBody;
pub use types::{decode, Encoder, Value};

/// Errors from decoding or encoding AMQP 1.0 wire data.
#[derive(Debug, Clone, PartialEq)]
pub enum Amqp1Error {
    /// Malformed encoding, with a short static description of what was wrong.
    Malformed(&'static str),
    /// A type-system format code this decoder doesn't recognize.
    UnknownFormatCode(u8),
    /// A frame-layer type octet other than AMQP (`0x00`) or SASL (`0x01`).
    UnknownFrameType(u8),
    /// A described type whose descriptor doesn't match any known
    /// performative, message section, or SASL frame body.
    UnknownDescriptor(u64),
    /// Frame size exceeds the negotiated / configured maximum.
    FrameTooLarge {
        /// Declared frame size.
        size: u32,
        /// Configured maximum.
        max: u32,
    },
    /// A performative/section field the spec marks mandatory was absent.
    RequiredFieldMissing(&'static str),
    /// A field was present but not the wire type the spec requires for it.
    WrongFieldType(&'static str),
}

impl std::fmt::Display for Amqp1Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(msg) => write!(f, "malformed AMQP 1.0 data: {msg}"),
            Self::UnknownFormatCode(v) => write!(f, "unknown AMQP 1.0 format code: {v:#04x}"),
            Self::UnknownFrameType(v) => write!(f, "unknown AMQP 1.0 frame type: {v:#04x}"),
            Self::UnknownDescriptor(v) => write!(f, "unknown AMQP 1.0 descriptor: {v:#x}"),
            Self::FrameTooLarge { size, max } => {
                write!(f, "AMQP 1.0 frame too large: {size} exceeds max {max}")
            }
            Self::RequiredFieldMissing(name) => write!(f, "missing required field: {name}"),
            Self::WrongFieldType(name) => write!(f, "wrong field type for: {name}"),
        }
    }
}

impl std::error::Error for Amqp1Error {}
