// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! FTP client errors.

use std::fmt;
use std::io;

/// Result alias for the FTP client.
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
        /// The server's actual reply code.
        code: u16,
        /// The server's diagnostic text.
        message: String,
    },
    /// Malformed reply or PASV/EPSV text.
    Parse(String),
    /// Missing builder configuration.
    Config(String),
}

impl FtpError {
    pub(crate) fn unexpected(expected: Option<u16>, code: u16, message: String) -> Self {
        Self::Protocol { expected, code, message }
    }

    /// Convert to [`io::Error`], preserving the kind for I/O failures
    /// (e.g. `TimedOut` from stage timers).
    pub fn into_io(self) -> io::Error {
        match self {
            Self::Io(e) => e,
            other => io::Error::new(io::ErrorKind::Other, other.to_string()),
        }
    }
}

impl fmt::Display for FtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "ftp i/o: {e}"),
            Self::Protocol { expected, code, message } => match expected {
                Some(c) => write!(f, "ftp expected {c}, got {code} {message}"),
                None => write!(f, "ftp protocol: {code} {message}"),
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
