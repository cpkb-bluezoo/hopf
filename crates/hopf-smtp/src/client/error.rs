// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SMTP client errors.

use std::fmt;
use std::io;

use super::reply::SmtpReply;

/// Result alias for the blocking client.
pub type SmtpResult<T> = Result<T, SmtpError>;

/// Client-side SMTP failure.
#[derive(Debug)]
pub enum SmtpError {
    /// Underlying I/O.
    Io(io::Error),
    /// Unexpected reply code.
    Protocol {
        /// Expected code if known.
        expected: Option<u16>,
        /// Reply received.
        reply: SmtpReply,
    },
    /// Malformed reply.
    Parse(String),
    /// Missing builder configuration.
    Config(String),
}

impl SmtpError {
    pub(crate) fn unexpected(expected: Option<u16>, reply: SmtpReply) -> Self {
        Self::Protocol { expected, reply }
    }
}

impl fmt::Display for SmtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "smtp i/o: {e}"),
            Self::Protocol { expected, reply } => match expected {
                Some(c) => write!(f, "smtp expected {c}, got {} {}", reply.code, reply.text()),
                None => write!(f, "smtp protocol: {} {}", reply.code, reply.text()),
            },
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
