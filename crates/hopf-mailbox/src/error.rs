// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Mailbox errors.

use std::error::Error as StdError;
use std::fmt;
use std::io;

/// Result alias for mailbox operations.
pub type MailboxResult<T> = Result<T, MailboxError>;

/// Failure from a mailbox or store operation.
#[derive(Debug)]
pub enum MailboxError {
    /// Underlying I/O failure.
    Io(io::Error),
    /// Operation not supported by this backend.
    Unsupported(&'static str),
    /// Invalid argument or mailbox state.
    Invalid(String),
    /// Corrupt sidecar / index data.
    Corrupt(String),
    /// Mailbox or message not found.
    NotFound(String),
    /// Read-only mailbox rejected a write.
    ReadOnly,
}

impl fmt::Display for MailboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "mailbox i/o: {e}"),
            Self::Unsupported(op) => write!(f, "unsupported: {op}"),
            Self::Invalid(msg) => write!(f, "invalid: {msg}"),
            Self::Corrupt(msg) => write!(f, "corrupt: {msg}"),
            Self::NotFound(msg) => write!(f, "not found: {msg}"),
            Self::ReadOnly => write!(f, "mailbox is read-only"),
        }
    }
}

impl StdError for MailboxError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for MailboxError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl MailboxError {
    /// Box this error for [`hopf_core::StorageExecutor`] task results.
    pub fn boxed(self) -> Box<dyn StdError + Send + Sync> {
        Box::new(self)
    }
}
