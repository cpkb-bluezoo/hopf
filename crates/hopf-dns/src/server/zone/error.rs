// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

use std::fmt;
use std::io;

/// A zone file, zone transfer or zone update could not be processed.
#[derive(Debug)]
pub struct ZoneError {
    /// 1-based line in the zone file, when the error came from parsing one.
    pub line: Option<usize>,
    /// What went wrong.
    pub message: String,
}

impl ZoneError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            line: None,
            message: message.into(),
        }
    }

    pub(crate) fn at(line: usize, message: impl Into<String>) -> Self {
        Self {
            line: Some(line),
            message: message.into(),
        }
    }
}

impl fmt::Display for ZoneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(line) => write!(f, "zone file line {line}: {}", self.message),
            None => f.write_str(&self.message),
        }
    }
}

impl std::error::Error for ZoneError {}

impl From<io::Error> for ZoneError {
    fn from(e: io::Error) -> Self {
        Self::new(e.to_string())
    }
}

impl From<ZoneError> for io::Error {
    fn from(e: ZoneError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, e)
    }
}
