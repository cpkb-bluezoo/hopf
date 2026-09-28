// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! TLS 1.2 / 1.3 selection policy for TCP and DTLS (QUIC is always 1.3).

use super::version_pick::PickedTls;

/// How an endpoint chooses between TLS/DTLS 1.2 and 1.3 on one port.
///
/// QUIC is always TLS 1.3 ([`super::HandshakeMode::Quic`]). On TCP use
/// [`super::pem::acceptor_from_pem_with_tcp_version_policy`]; on UDP use
/// [`crate::dtls::dtls_server_engine`] / [`crate::dtls::dtls_client_engine`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TcpTlsVersionPolicy {
    /// Inspect the first handshake flight and pick one engine (prefer 1.3).
    /// Default for [`super::pem::acceptor_from_pem`] /
    /// [`super::pem::connector_from_pem`].
    #[default]
    Negotiate,
    /// TLS 1.3 only; refuse a peer that does not negotiate 1.3.
    Tls13Only,
    /// TLS 1.2 only; refuse a peer that negotiates 1.3.
    Tls12Only,
}

impl TcpTlsVersionPolicy {
    pub(crate) fn allows_server_pick(&self, pick: PickedTls) -> bool {
        matches!(
            (self, pick),
            (Self::Negotiate, _) | (Self::Tls13Only, PickedTls::V13) | (Self::Tls12Only, PickedTls::V12)
        )
    }

    pub(crate) fn allows_client_pick(&self, pick: PickedTls) -> bool {
        self.allows_server_pick(pick)
    }
}
