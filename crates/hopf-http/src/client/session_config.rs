// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Shared configuration for [`super::connection::HttpClientConnection`] session adapters.

use std::sync::Mutex;

use crate::limits::HttpLimits;

use super::api::HttpConnectionHandler;

/// Host, limits, and connection handler for one outbound HTTP client connection.
pub(crate) struct HttpClientSessionConfig {
    pub host: String,
    pub port: u16,
    pub limits: HttpLimits,
    pub secure: bool,
    pub handler: Mutex<Option<Box<dyn HttpConnectionHandler>>>,
}
