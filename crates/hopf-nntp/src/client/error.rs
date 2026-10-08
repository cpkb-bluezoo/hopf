// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Client-side error type.

use std::io;

/// What went wrong with a command or the connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NntpClientError {
    /// NNTP status code when the server answered (`0` for transport
    /// failures and timeouts).
    pub code: u16,
    pub message: String,
}

impl NntpClientError {
    pub fn new(code: u16, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }

    /// A failure with no status line behind it.
    pub fn transport(message: impl Into<String>) -> Self {
        Self::new(0, message)
    }

    /// The server rejected the command with `code`.
    pub fn rejected(command: &str, code: u16, text: &str) -> Self {
        Self::new(code, format!("{command} failed: {code} {text}"))
    }
}

impl std::fmt::Display for NntpClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for NntpClientError {}

impl From<io::Error> for NntpClientError {
    fn from(e: io::Error) -> Self {
        Self::transport(e.to_string())
    }
}

impl From<NntpClientError> for io::Error {
    fn from(e: NntpClientError) -> Self {
        let kind = if e.code == 0 { io::ErrorKind::ConnectionAborted } else { io::ErrorKind::Other };
        io::Error::new(kind, e.message)
    }
}
