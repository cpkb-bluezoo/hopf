// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Session transfer mode state.

/// TYPE A / TYPE I.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransferType {
    /// ASCII (CRLF normalisation).
    Ascii,
    /// Image / binary.
    #[default]
    Image,
}

/// Active vs passive data connection setup.
#[derive(Debug, Clone)]
pub enum DataMode {
    /// No data endpoint yet.
    None,
    /// PORT/EPRT target.
    Active {
        /// Peer to dial.
        addr: std::net::SocketAddr,
    },
    /// PASV/EPSV listening.
    Passive {
        /// Binding created for the data accept.
        binding: hopf_core::BindingId,
        /// Bound local address (for replies).
        local: std::net::SocketAddr,
    },
}
