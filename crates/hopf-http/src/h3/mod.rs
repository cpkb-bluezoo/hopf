// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP/3 over Hopf QUIC (server and client).

pub(crate) mod client;
mod endpoint;
mod response;
mod frame;
mod parser;
pub mod qpack;
mod varint;

pub use client::{connect_h3, H3ClientConnection};
pub use endpoint::{listen_h3, H3ServerConnection};
pub use frame::{
    H3_CLOSED_CRITICAL_STREAM, H3_CONNECT_ERROR, H3_EXCESSIVE_LOAD, H3_FRAME_ERROR,
    H3_FRAME_UNEXPECTED, H3_GENERAL_PROTOCOL_ERROR, H3_ID_ERROR, H3_INTERNAL_ERROR,
    H3_MESSAGE_ERROR, H3_MISSING_SETTINGS, H3_NO_ERROR, H3_REQUEST_CANCELLED,
    H3_REQUEST_INCOMPLETE, H3_REQUEST_REJECTED, H3_SETTINGS_ERROR, H3_STREAM_CREATION_ERROR,
    H3_VERSION_FALLBACK, QPACK_DECODER_STREAM_ERROR, QPACK_DECOMPRESSION_FAILED,
    QPACK_ENCODER_STREAM_ERROR,
};
pub use parser::{H3FrameHandler, H3Parser};
