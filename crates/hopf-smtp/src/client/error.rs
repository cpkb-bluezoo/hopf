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

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn each_kind_says_what_it_is() {
        assert_eq!(SmtpError::Parse("bad reply".into()).to_string(), "smtp parse: bad reply");
        assert_eq!(SmtpError::Config("no host".into()).to_string(), "smtp config: no host");
        let io = SmtpError::from(io::Error::new(io::ErrorKind::BrokenPipe, "pipe"));
        assert_eq!(io.to_string(), "smtp i/o: pipe");
    }

    #[test]
    fn only_an_io_error_has_a_cause() {
        assert!(SmtpError::from(io::Error::other("x")).source().is_some());
        assert!(SmtpError::Parse("x".into()).source().is_none());
        assert!(SmtpError::Config("x".into()).source().is_none());
    }
}
