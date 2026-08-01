// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP Stream — the app-facing session unit for all HTTP versions.
//!
//! H1/H2/H3 adapters birth [`HttpStream`]s on transport [`hopf_core::Endpoint`]s.
//! Bind vs dial only affects how the Endpoint was created; the Stream API is shared.
//! Server and client roles are peers — the framework does not centre either one.

mod client;
mod server;

pub use client::{ClientHandler, ClientHandlerFactory, ClientWriter};
pub use server::{
    ConnectionInfo, ProtocolUpgradeHandler, ServerHandler, ServerHandlerFactory,
    ServerResponseHandle, ServerWriter,
};
pub(crate) use server::ResponseControl;

/// How this peer participates in an HTTP request/response exchange.
///
/// Independent of listen vs dial (transport birth). Usually listen→[`Server`]
/// and dial→[`Client`], but relays may combine them differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpRole {
    /// Receives requests and sends responses.
    Server,
    /// Sends requests and receives responses.
    Client,
}

/// One HTTP request/response exchange (H1/H2/H3).
///
/// Version adapters map this onto TCP serialization (H1), H2 stream ids, or
/// QUIC stream endpoints (H3). Application handlers must not depend on that.
#[derive(Debug, Clone)]
pub struct HttpStream {
    id: u64,
    role: HttpRole,
}

impl HttpStream {
    /// Create a stream with the given id and role.
    pub fn new(id: u64, role: HttpRole) -> Self {
        Self { id, role }
    }

    /// Stream identifier (odd client-initiated ids match H2/H3 conventions when used).
    pub fn id(&self) -> u64 {
        self.id
    }

    /// HTTP role for this exchange.
    pub fn role(&self) -> HttpRole {
        self.role
    }
}
