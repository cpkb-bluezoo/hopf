// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SMTP client errors.

use std::fmt;
use std::io;

/// Result alias for the SMTP client.
pub type SmtpResult<T> = Result<T, SmtpError>;

/// Client-side SMTP failure.
#[derive(Debug)]
pub enum SmtpError {
    /// Underlying I/O.
    Io(io::Error),
    /// Malformed reply.
    Parse(String),
    /// Missing builder configuration.
    Config(String),
}

impl fmt::Display for SmtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "smtp i/o: {e}"),
            Self::Parse(s) => write!(f, "smtp parse: {s}"),
            Self::Config(s) => write!(f, "smtp config: {s}"),
        }
    }
}

impl std::error::Error for SmtpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for SmtpError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
