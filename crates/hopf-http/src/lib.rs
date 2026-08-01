// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Hopf HTTP: Stream-first codecs for bind and dial.
//!
//! Applications program against [`HttpStream`] + server / client handlers.
//! H1 (and later H2/H3) adapt transport [`hopf_core::Endpoint`]s into Streams.
//! Neither role is privileged — listen and dial are equal birth paths.
//!
//! For dialling by hostname with DNS resolution and timeouts, see [`client`].

#![warn(missing_docs)]

pub mod auth;
pub mod client;
pub mod h1;
pub mod h2;
pub mod server;
#[cfg(feature = "h3")]
pub mod h3;
pub mod stream;

mod dispatch;

#[cfg(all(test, feature = "integration"))]
mod integration;

mod error;
mod headers;
mod limits;
mod pseudo_headers;
mod status;
mod utils;
mod version;

pub use auth::{
    build_digest_authorization, parse_basic_authorization, BasicAuthConfig, BasicAuthFactory,
    BearerAuthFactory, DigestAuthConfig, DigestAuthFactory,
};
pub use client::{
    connect_http, connect_http2_upgrade, HttpClient, HttpClientError, HttpClientSessionHandle,
    HttpClientTimeouts, HttpConnectionHandler, HttpRequest, HttpResponseHandler,
};
#[cfg(feature = "h3")]
pub use client::connect_h3_by_name;
pub use server::HttpServer;
pub use dispatch::AlpnHttpEndpoint;
pub use error::{HttpError, HttpResult};
pub use h1::{
    H1ClientCodec, H1Endpoint, H1ServerCodec,
};
pub use h2::CleartextHttpEndpoint;
pub use h2::H2Endpoint;
pub use h2::H2cUpgradeClientEndpoint;
#[cfg(feature = "h3")]
pub use h3::{connect_h3, listen_h3, H3ClientConnection, H3ServerConnection};
pub use headers::{Header, Headers};
pub use limits::HttpLimits;
pub use status::reason_phrase;
pub use stream::{
    ClientHandler, ClientHandlerFactory, ClientWriter, ConnectionInfo, HttpRole, HttpStream,
    ProtocolUpgradeHandler, ServerHandler, ServerHandlerFactory, ServerResponseHandle,
    ServerWriter,
};
pub use utils::{
    is_chunked_te, is_default_method, is_invalid_te, is_token, is_valid_header_name, is_valid_host,
    is_valid_request_target, method_implies_no_body, parse_content_length,
};
pub use version::HttpVersion;
pub use hopf_core::VERSION;
