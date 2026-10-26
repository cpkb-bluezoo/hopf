// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Shared configuration for [`super::connection::HttpClientConnection`] session adapters.

use std::sync::Mutex;
use std::time::Duration;

use crate::limits::HttpLimits;

use super::api::HttpConnectionHandler;

/// Host, limits, and connection handler for one outbound HTTP client connection.
///
/// Public (alongside [`super::connection::HttpClientConnection`]) for callers
/// building their own dial — see that type's doc comment.
pub struct HttpClientSessionConfig {
    /// Origin host — used for `Host`/`:authority` and content-coding lookups,
    /// not for dialing (the caller already decided how to reach it).
    pub host: String,
    /// Origin port.
    pub port: u16,
    /// Response/body size limits.
    pub limits: HttpLimits,
    /// Whether this connection is secured (TLS) — must agree with how the
    /// caller's own transport actually behaves; see
    /// [`super::connection::HttpClientConnection::new`].
    pub secure: bool,
    /// The application's connection handler, taken once `on_connected`/`on_error` fires.
    pub handler: Mutex<Option<Box<dyn HttpConnectionHandler>>>,
    /// [`crate::HttpClientTimeouts::stage`] — budget for one request/response
    /// round trip once bytes are on the wire. `Duration::ZERO` disables it.
    pub stage: Duration,
}
