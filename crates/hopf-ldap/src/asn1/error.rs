// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Error type for ASN.1 encoding and decoding failures.

use std::fmt;

/// Error thrown when ASN.1 encoding or decoding fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asn1Error {
    message: String,
}

impl Asn1Error {
    /// Creates a new ASN.1 error with the specified message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for Asn1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Asn1Error {}

impl From<&str> for Asn1Error {
    fn from(message: &str) -> Self {
        Self::new(message)
    }
}

impl From<String> for Asn1Error {
    fn from(message: String) -> Self {
        Self::new(message)
    }
}

#[cfg(test)]
mod tests {
    use super::Asn1Error;

    #[test]
    fn display_message() {
        let err = Asn1Error::new("Indefinite length encoding not supported");
        assert_eq!(
            err.to_string(),
            "Indefinite length encoding not supported"
        );
        assert_eq!(err.message(), "Indefinite length encoding not supported");
    }
}
