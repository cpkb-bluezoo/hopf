// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Error thrown when a `.proto` file or protobuf message cannot be parsed.

use std::error::Error;
use std::fmt;

/// Error thrown when a `.proto` file or protobuf message cannot be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtoParseError {
    message: String,
}

impl ProtoParseError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ProtoParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for ProtoParseError {}
