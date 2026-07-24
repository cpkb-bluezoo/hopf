// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Security metadata exposed to protocol handlers after TLS/QUIC handshake.

/// Negotiated security parameters. Plaintext endpoints use [`SecurityInfo::plaintext`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SecurityInfo {
    secure: bool,
    alpn: Option<Vec<u8>>,
    protocol: Option<String>,
    cipher_suite: Option<String>,
}

impl SecurityInfo {
    /// No security layer is active.
    pub fn plaintext() -> Self {
        Self::default()
    }

    /// Whether a cryptographic protocol is active.
    pub fn is_secure(&self) -> bool {
        self.secure
    }

    /// ALPN protocol selected during handshake, if any.
    pub fn alpn(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    /// Human-readable protocol version (e.g. `TLSv1.3`), if known.
    pub fn protocol(&self) -> Option<&str> {
        self.protocol.as_deref()
    }

    /// Cipher suite name, if known.
    pub fn cipher_suite(&self) -> Option<&str> {
        self.cipher_suite.as_deref()
    }

    /// Builder used by TLS/QUIC layers (Tranche 3+).
    pub fn secure(alpn: Option<Vec<u8>>, protocol: Option<String>, cipher_suite: Option<String>) -> Self {
        Self {
            secure: true,
            alpn,
            protocol,
            cipher_suite,
        }
    }
}
