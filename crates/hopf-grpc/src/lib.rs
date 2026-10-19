// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Unary and streaming gRPC over Hopf HTTP Streams.
//!
//! Length-prefixed framing, runtime `.proto` model, schema-aware push events via
//! [`rprotobuf`], and HTTP Stream server/client bindings. No generated stubs.
//!
//! Messages may be compressed per the gRPC HTTP/2 protocol (`grpc-encoding`
//! and `grpc-accept-encoding`): see [`compression`]. `gzip` and `deflate`
//! are decoded by default, and `br` when enabled; the server compresses
//! responses the client accepts and the client can compress requests.

#![forbid(unsafe_code)]

pub mod client;
pub mod codec;
pub mod compression;
pub mod framing;
pub mod proto;
pub mod server;

pub use client::{GrpcClient, GrpcClientCall, GrpcResponseHandler, GrpcStreamingCall, GrpcUnaryCall};
pub use codec::{parse_grpc_content_type, GrpcCodec};
pub use compression::{
    accept_encoding_header, select_encoding, MessageCoding, DEFAULT_COMPRESSION_THRESHOLD,
    DEFAULT_ENCODINGS,
};
pub use hopf_http::ContentCoding;
pub use framing::{
    effective_max_message_size, frame, frame_compressed, framed_size, GrpcEventHandler,
    GrpcFrameParser, DEFAULT_MAX_MESSAGE_SIZE,
};
pub use proto::*;
pub use server::{
    GrpcHandlerFactory, GrpcResponseChannel, GrpcResponseMessage, GrpcService,
};

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
