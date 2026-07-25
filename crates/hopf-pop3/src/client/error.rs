// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! POP3 client errors.

use std::fmt;
use std::io;

/// Result alias for the POP3 client.
pub type Pop3Result<T> = Result<T, Pop3Error>;

/// Client-side POP3 failure.
#[derive(Debug)]
pub enum Pop3Error {
    /// Underlying I/O.
    Io(io::Error),
    /// Unexpected wire data.
    Parse(String),
    /// Missing builder configuration.
    Config(String),
    /// Server returned -ERR.
    ServerError(String),
}

impl fmt::Display for Pop3Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "pop3 i/o: {e}"),
            Self::Parse(s) => write!(f, "pop3 parse: {s}"),
            Self::Config(s) => write!(f, "pop3 config: {s}"),
            Self::ServerError(s) => write!(f, "pop3 server error: {s}"),
        }
    }
}

impl std::error::Error for Pop3Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Pop3Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
