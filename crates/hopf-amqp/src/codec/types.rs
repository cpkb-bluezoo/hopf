// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! AMQP 0-9-1 wire constants and shared types.

#![allow(missing_docs)]

/// Protocol header: `AMQP` + `\0` + major `0` + minor `9` + revision `1`.
pub const PROTOCOL_HEADER: &[u8; 8] = &[b'A', b'M', b'Q', b'P', 0, 0, 9, 1];

/// Frame-end octet.
pub const FRAME_END: u8 = 0xCE;

/// Method frame.
pub const FRAME_METHOD: u8 = 1;
/// Content header frame.
pub const FRAME_HEADER: u8 = 2;
/// Content body frame.
pub const FRAME_BODY: u8 = 3;
/// Heartbeat frame.
pub const FRAME_HEARTBEAT: u8 = 8;

/// Default frame max when the broker advertises 0 (unlimited) — 128 KiB.
pub const DEFAULT_FRAME_MAX: u32 = 131_072;
/// Default channel max when the broker advertises 0 — 2047.
pub const DEFAULT_CHANNEL_MAX: u16 = 2047;
/// Default heartbeat seconds when both sides advertise 0 — disabled.
pub const DEFAULT_HEARTBEAT: u16 = 0;

/// Class identifiers.
pub mod class {
    /// Connection class.
    pub const CONNECTION: u16 = 10;
    /// Channel class.
    pub const CHANNEL: u16 = 20;
    /// Exchange class.
    pub const EXCHANGE: u16 = 40;
    /// Queue class.
    pub const QUEUE: u16 = 50;
    /// Basic class.
    pub const BASIC: u16 = 60;
    /// Confirm class (RabbitMQ extension).
    pub const CONFIRM: u16 = 85;
}

/// Connection method ids.
pub mod connection {
    pub const START: u16 = 10;
    pub const START_OK: u16 = 11;
    pub const SECURE: u16 = 20;
    pub const SECURE_OK: u16 = 21;
    pub const TUNE: u16 = 30;
    pub const TUNE_OK: u16 = 31;
    pub const OPEN: u16 = 40;
    pub const OPEN_OK: u16 = 41;
    pub const CLOSE: u16 = 50;
    pub const CLOSE_OK: u16 = 51;
}

/// Channel method ids.
pub mod channel {
    pub const OPEN: u16 = 10;
    pub const OPEN_OK: u16 = 11;
    pub const FLOW: u16 = 20;
    pub const FLOW_OK: u16 = 21;
    pub const CLOSE: u16 = 40;
    pub const CLOSE_OK: u16 = 41;
}

/// Exchange method ids.
pub mod exchange {
    pub const DECLARE: u16 = 10;
    pub const DECLARE_OK: u16 = 11;
    pub const DELETE: u16 = 20;
    pub const DELETE_OK: u16 = 21;
}

/// Queue method ids.
pub mod queue {
    pub const DECLARE: u16 = 10;
    pub const DECLARE_OK: u16 = 11;
    pub const BIND: u16 = 20;
    pub const BIND_OK: u16 = 21;
    pub const PURGE: u16 = 30;
    pub const PURGE_OK: u16 = 31;
    pub const DELETE: u16 = 40;
    pub const DELETE_OK: u16 = 41;
    pub const UNBIND: u16 = 50;
    pub const UNBIND_OK: u16 = 51;
}

/// Basic method ids.
pub mod basic {
    pub const QOS: u16 = 10;
    pub const QOS_OK: u16 = 11;
    pub const CONSUME: u16 = 20;
    pub const CONSUME_OK: u16 = 21;
    pub const CANCEL: u16 = 30;
    pub const CANCEL_OK: u16 = 31;
    pub const PUBLISH: u16 = 40;
    pub const RETURN: u16 = 50;
    pub const DELIVER: u16 = 60;
    pub const ACK: u16 = 80;
    pub const REJECT: u16 = 90;
    pub const NACK: u16 = 120;
}

/// Confirm method ids (RabbitMQ).
pub mod confirm {
    pub const SELECT: u16 = 10;
    pub const SELECT_OK: u16 = 11;
}

/// Soft / hard error reply codes used in close methods (subset).
pub mod reply {
    pub const SUCCESS: u16 = 200;
    pub const CONTENT_TOO_LARGE: u16 = 311;
    pub const NO_ROUTE: u16 = 312;
    pub const NO_CONSUMERS: u16 = 313;
    pub const ACCESS_REFUSED: u16 = 403;
    pub const NOT_FOUND: u16 = 404;
    pub const RESOURCE_LOCKED: u16 = 405;
    pub const PRECONDITION_FAILED: u16 = 406;
    pub const CONNECTION_FORCED: u16 = 320;
    pub const INVALID_PATH: u16 = 402;
    pub const FRAME_ERROR: u16 = 501;
    pub const SYNTAX_ERROR: u16 = 502;
    pub const COMMAND_INVALID: u16 = 503;
    pub const CHANNEL_ERROR: u16 = 504;
    pub const UNEXPECTED_FRAME: u16 = 505;
    pub const RESOURCE_ERROR: u16 = 506;
    pub const NOT_ALLOWED: u16 = 530;
    pub const NOT_IMPLEMENTED: u16 = 540;
    pub const INTERNAL_ERROR: u16 = 541;
}
