// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! AMQP client errors.

use std::fmt;
use std::io;

/// Result alias for the AMQP client.
pub type AmqpClientResult<T> = Result<T, AmqpClientError>;

/// Client-side AMQP failure.
#[derive(Debug)]
pub enum AmqpClientError {
    /// Underlying I/O (including DNS / connect / handshake timeouts).
    Io(io::Error),
    /// Missing builder configuration.
    Config(String),
    /// Broker closed the connection during handshake or afterwards.
    ConnectionClosed {
        /// Reply code.
        reply_code: u16,
        /// Reply text.
        reply_text: String,
    },
}

impl fmt::Display for AmqpClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "amqp i/o: {e}"),
            Self::Config(s) => write!(f, "amqp config: {s}"),
            Self::ConnectionClosed {
                reply_code,
                reply_text,
            } => write!(f, "amqp connection closed: {reply_code} {reply_text}"),
        }
    }
}

impl std::error::Error for AmqpClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for AmqpClientError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
