// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! FTP client errors.

use std::fmt;
use std::io;

use super::reply::FtpReply;

/// Result alias for the blocking client.
pub type FtpResult<T> = Result<T, FtpError>;

/// Client-side FTP failure.
#[derive(Debug)]
pub enum FtpError {
    /// Underlying I/O.
    Io(io::Error),
    /// Unexpected reply code.
    Protocol {
        /// Expected code if known.
        expected: Option<u16>,
        /// Reply received.
        reply: FtpReply,
    },
    /// Malformed reply or PASV/EPSV text.
    Parse(String),
    /// Missing builder configuration.
    Config(String),
}

impl FtpError {
    pub(crate) fn unexpected(expected: Option<u16>, reply: FtpReply) -> Self {
        Self::Protocol { expected, reply }
    }
}

impl fmt::Display for FtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "ftp i/o: {e}"),
            Self::Protocol { expected, reply } => match expected {
                Some(c) => write!(f, "ftp expected {c}, got {} {}", reply.code, reply.text()),
                None => write!(f, "ftp protocol: {} {}", reply.code, reply.text()),
            },
            Self::Parse(s) => write!(f, "ftp parse: {s}"),
            Self::Config(s) => write!(f, "ftp config: {s}"),
        }
    }
}

impl std::error::Error for FtpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for FtpError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
