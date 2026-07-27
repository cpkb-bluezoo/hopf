// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP client connect helpers with DNS resolution and per-phase timeouts.

pub(crate) mod api;
pub(crate) mod connect;
pub(crate) mod connection;
pub(crate) mod facade;
pub(crate) mod h2_session;
pub(crate) mod session_config;

pub use api::{
    HttpClientError, HttpClientSessionHandle, HttpConnectionHandler, HttpRequest, HttpResponseHandler,
};
pub use connect::{connect_http, connect_http2_upgrade, HttpClientTimeouts};
#[cfg(feature = "h3")]
pub use connect::connect_h3_by_name;
pub use facade::HttpClient;
