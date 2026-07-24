// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Shared error types for the core substrate.

use std::fmt;

/// `Endpoint::start_tls` failed or is not supported on this transport.
#[derive(Debug)]
pub enum StartTlsError {
    /// TLS upgrade is not available (plaintext TCP before Tranche 3, or QUIC).
    Unsupported,
    /// TLS was already established.
    AlreadySecure,
    /// Underlying I/O or handshake setup failure.
    Io(std::io::Error),
}

impl fmt::Display for StartTlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => write!(f, "start_tls is not supported on this endpoint"),
            Self::AlreadySecure => write!(f, "endpoint is already secure"),
            Self::Io(e) => write!(f, "start_tls I/O error: {e}"),
        }
    }
}

impl std::error::Error for StartTlsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}
