// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP/1.x adapter: one transport [`Endpoint`](hopf_core::Endpoint) → serialized [`HttpStream`]s.
//!
//! Bind or dial creates the Endpoint the same way; [`HttpRole`] selects server vs
//! client codecs. H1 presents Streams one at a time on a single byte pipe.

mod client_codec;
mod encode_request;
mod endpoint;
pub mod parse;
mod response;
mod server_codec;
mod session_client_codec;

pub use client_codec::H1ClientCodec;
pub use endpoint::H1Endpoint;
#[allow(deprecated)]
pub use endpoint::HttpConnection;
pub use server_codec::H1ServerCodec;
pub(crate) use session_client_codec::H1SessionClientCodec;
