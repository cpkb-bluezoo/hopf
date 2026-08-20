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
pub use parser::{H3FrameHandler, H3Parser};
