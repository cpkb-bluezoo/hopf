// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Security metadata exposed to protocol handlers after TLS/QUIC handshake.

/// Negotiated security parameters. Plaintext endpoints use [`SecurityInfo::plaintext`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SecurityInfo {
    secure: bool,
    alpn: Option<Vec<u8>>,
    protocol: Option<String>,
    cipher_suite: Option<String>,
    sni: Option<String>,
    peer_certificate_fingerprint: Option<String>,
    peer_certificate_chain: Option<Vec<Vec<u8>>>,
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

    /// Server Name Indication the peer requested during the handshake
    /// (server side only — the client already knows the name it dialed).
    pub fn sni(&self) -> Option<&str> {
        self.sni.as_deref()
    }

    /// SHA-256 fingerprint (lowercase hex) of the peer's leaf certificate,
    /// when client-certificate authentication (mTLS) presented one — server
    /// side only. Suitable as the `cert_key` passed to
    /// `CredentialStore::authenticate_certificate` (SASL EXTERNAL).
    pub fn peer_certificate_fingerprint(&self) -> Option<&str> {
        self.peer_certificate_fingerprint.as_deref()
    }

    /// The peer's full certificate chain (DER-encoded, leaf certificate
    /// first), when one was presented during the handshake. Server side
    /// this is the client certificate chain (mTLS); client side it is the
    /// server's certificate chain.
    pub fn peer_certificate_chain(&self) -> Option<&[Vec<u8>]> {
        self.peer_certificate_chain.as_deref()
    }

    /// Builder used by TLS/QUIC layers (Tranche 3+).
    pub fn secure(alpn: Option<Vec<u8>>, protocol: Option<String>, cipher_suite: Option<String>) -> Self {
        Self {
            secure: true,
            alpn,
            protocol,
            cipher_suite,
            sni: None,
            peer_certificate_fingerprint: None,
            peer_certificate_chain: None,
        }
    }

    /// Attach the SNI hostname the peer requested (server side).
    pub fn with_sni(mut self, sni: Option<String>) -> Self {
        self.sni = sni;
        self
    }

    /// Attach the peer's client-certificate fingerprint (server side, mTLS).
    pub fn with_peer_certificate_fingerprint(mut self, fingerprint: Option<String>) -> Self {
        self.peer_certificate_fingerprint = fingerprint;
        self
    }

    /// Attach the peer's full certificate chain (DER, leaf first).
    pub fn with_peer_certificate_chain(mut self, chain: Option<Vec<Vec<u8>>>) -> Self {
        self.peer_certificate_chain = chain;
        self
    }
}
