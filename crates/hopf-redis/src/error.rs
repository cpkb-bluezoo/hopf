// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Why a command did not produce a reply.

use std::io;

use crate::resp::ServerError;

/// An error from a command.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum RedisError {
    /// The server answered with an error (`ERR`, `WRONGTYPE`, `WRONGPASS`,
    /// `MOVED`, ...).
    Server(ServerError),
    /// The connection could not be made, or the handshake (`HELLO`, `AUTH`,
    /// `SELECT`) failed.
    Connect(String),
    /// The connection was lost with the command sent and unanswered. It may or
    /// may not have been run; the client does not send it again.
    ConnectionLost(String),
    /// No reply within the command timeout. The command may still be run.
    Timeout,
    /// The server sent something that is not RESP, or a reply nobody asked for.
    Protocol(String),
    /// A reply was not the kind a typed helper expects.
    Unexpected(String),
    /// More commands are waiting than [`RedisConfig::max_pending`](crate::RedisConfig::max_pending) allows.
    Overloaded,
    /// The client was closed.
    Closed,
}

impl RedisError {
    /// The code word of a [`Server`](Self::Server) error, such as `WRONGTYPE`.
    pub fn server_code(&self) -> Option<&str> {
        match self {
            Self::Server(e) if !e.code.is_empty() => Some(&e.code),
            _ => None,
        }
    }
}

impl std::fmt::Display for RedisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Server(e) => write!(f, "server error: {e}"),
            Self::Connect(why) => write!(f, "could not connect: {why}"),
            Self::ConnectionLost(why) => write!(f, "connection lost: {why}"),
            Self::Timeout => f.write_str("the command timed out"),
            Self::Protocol(why) => write!(f, "protocol error: {why}"),
            Self::Unexpected(why) => write!(f, "unexpected reply: {why}"),
            Self::Overloaded => f.write_str("too many commands waiting"),
            Self::Closed => f.write_str("the client is closed"),
        }
    }
}

impl std::error::Error for RedisError {}

impl From<RedisError> for io::Error {
    fn from(e: RedisError) -> Self {
        let kind = match &e {
            RedisError::Server(_) => io::ErrorKind::Other,
            RedisError::Connect(_) => io::ErrorKind::ConnectionRefused,
            RedisError::ConnectionLost(_) => io::ErrorKind::ConnectionAborted,
            RedisError::Timeout => io::ErrorKind::TimedOut,
            RedisError::Protocol(_) | RedisError::Unexpected(_) => io::ErrorKind::InvalidData,
            RedisError::Overloaded => io::ErrorKind::WouldBlock,
            RedisError::Closed => io::ErrorKind::NotConnected,
        };
        io::Error::new(kind, e.to_string())
    }
}
