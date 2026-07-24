// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Connection-level hooks so HTTP/3 (in `-http`) can own control/uni streams
//! without putting HTTP into this crate.

use hopf_core::ProtocolHandler;

/// Factory for one [`QuicConnection`] per accepted/dialed QUIC connection.
pub type ConnectionFactory = std::sync::Arc<dyn Fn() -> Box<dyn QuicConnection> + Send + Sync>;

/// Application logic for one QUIC connection (control streams + request streams).
pub trait QuicConnection: Send {
    /// Called after the QUIC handshake completes. Open control streams here.
    fn connected(&mut self, api: &mut dyn QuicConnApi);

    /// A peer-opened bidirectional stream — return its [`ProtocolHandler`].
    fn accept_bi(&mut self) -> Box<dyn ProtocolHandler>;

    /// A peer-opened unidirectional stream — return its [`ProtocolHandler`].
    fn accept_uni(&mut self) -> Box<dyn ProtocolHandler>;
}

/// API available during [`QuicConnection::connected`] on the driver thread.
pub trait QuicConnApi {
    /// Open a local unidirectional stream; returns an opaque stream key for [`write`](Self::write).
    fn open_uni(&mut self) -> Option<u64>;

    /// Open a local bidirectional stream.
    fn open_bi(&mut self) -> Option<u64>;

    /// Queue bytes on a stream opened via this API (or later accepted and keyed).
    fn write(&mut self, stream_key: u64, data: &[u8]);

    /// Finish the send side of a stream.
    fn finish(&mut self, stream_key: u64);
}
