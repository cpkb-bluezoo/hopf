// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Unary gRPC over Hopf HTTP Streams (Gumdrop `org.bluezoo.gumdrop.grpc` port).
//!
//! Length-prefixed framing, runtime `.proto` model, schema-aware push events via
//! [`rprotobuf`], and HTTP Stream server/client bindings. No generated stubs.

#![forbid(unsafe_code)]

pub mod client;
pub mod codec;
pub mod framing;
pub mod proto;
pub mod server;

pub use client::{GrpcClient, GrpcResponseHandler, GrpcUnaryCall};
pub use codec::{parse_grpc_content_type, GrpcCodec};
pub use framing::{
    effective_max_message_size, frame, framed_size, GrpcEventHandler, GrpcFrameParser,
    DEFAULT_MAX_MESSAGE_SIZE,
};
pub use proto::*;
pub use server::{
    GrpcHandlerFactory, GrpcResponseChannel, GrpcResponseMessage, GrpcService,
};

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
