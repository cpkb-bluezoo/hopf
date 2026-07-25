// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! IMAP client errors.

use std::fmt;
use std::io;

/// Result alias for the IMAP client.
pub type ImapResult<T> = Result<T, ImapError>;

/// Client-side IMAP failure.
#[derive(Debug)]
pub enum ImapError {
    /// Underlying I/O.
    Io(io::Error),
    /// Unexpected or malformed wire data.
    Parse(String),
    /// Missing builder configuration.
    Config(String),
    /// Server returned NO or BAD.
    Server(String),
    /// Protocol violation (e.g. unknown tag, pipeline exceeded).
    Protocol(String),
}

impl fmt::Display for ImapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "imap i/o: {e}"),
            Self::Parse(s) => write!(f, "imap parse: {s}"),
            Self::Config(s) => write!(f, "imap config: {s}"),
            Self::Server(s) => write!(f, "imap server: {s}"),
            Self::Protocol(s) => write!(f, "imap protocol: {s}"),
        }
    }
}

impl std::error::Error for ImapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for ImapError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
