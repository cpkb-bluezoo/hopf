// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

use std::fmt;

/// Malformed DNS wire message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsFormatError {
    message: String,
}

impl DnsFormatError {
    /// Create an error with a static or owned message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for DnsFormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DnsFormatError {}

impl From<DnsFormatError> for std::io::Error {
    fn from(e: DnsFormatError) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e.message)
    }
}
