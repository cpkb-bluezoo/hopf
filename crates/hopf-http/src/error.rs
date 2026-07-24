// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP parse / protocol errors.

use std::fmt;

/// Error from the incremental HTTP/1.x parser or connection framing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpError {
    /// Suggested status code to send before closing (0 = close without response).
    pub status: u16,
    /// Short reason for logs.
    pub message: &'static str,
}

impl HttpError {
    pub(crate) fn new(status: u16, message: &'static str) -> Self {
        Self { status, message }
    }
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HTTP error {}: {}", self.status, self.message)
    }
}

impl std::error::Error for HttpError {}

/// Result alias for HTTP parsing.
pub type HttpResult<T> = Result<T, HttpError>;
