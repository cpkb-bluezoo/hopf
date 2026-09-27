// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! AMQP 1.0 client errors.

use std::fmt;
use std::io;

use crate::codec::Amqp1CompositeError;

/// Result alias for the AMQP 1.0 client.
pub type Amqp1ClientResult<T> = Result<T, Amqp1ClientError>;

/// Client-side AMQP 1.0 failure.
#[derive(Debug)]
pub enum Amqp1ClientError {
    /// Underlying I/O (including DNS / connect / handshake timeouts).
    Io(io::Error),
    /// Missing or invalid builder configuration.
    Config(String),
    /// Peer closed the connection, with an AMQP error composite if one was given.
    ConnectionClosed(Option<Amqp1CompositeError>),
    /// SASL authentication failed or was rejected by the peer.
    SaslFailed,
    /// Caller tried to send on a link with no available link-credit.
    NoLinkCredit,
}

impl fmt::Display for Amqp1ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "amqp1 i/o: {e}"),
            Self::Config(s) => write!(f, "amqp1 config: {s}"),
            Self::ConnectionClosed(Some(err)) => write!(f, "amqp1 connection closed: {err}"),
            Self::ConnectionClosed(None) => write!(f, "amqp1 connection closed"),
            Self::SaslFailed => write!(f, "amqp1 SASL authentication failed"),
            Self::NoLinkCredit => write!(f, "amqp1 send attempted with no link credit available"),
        }
    }
}

impl std::error::Error for Amqp1ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Amqp1ClientError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
