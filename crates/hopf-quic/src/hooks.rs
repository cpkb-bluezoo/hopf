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

    /// A new bidirectional stream — peer-opened, or locally opened via
    /// [`QuicConnApi::open_bi`] (either during [`Self::connected`]/[`Self::drive`]
    /// or queued from outside the driver thread and applied on a later
    /// `drive` tick) — return its [`ProtocolHandler`]. `stream_id` is the
    /// real QUIC stream id (RFC 9000 §2.1), stable for this stream's
    /// lifetime; apps that key per-stream state (e.g. HTTP/3 QPACK field
    /// section instructions, RFC 9204 §4.5) by stream id need this to
    /// avoid every stream colliding on the same key.
    fn accept_bi(&mut self, stream_id: u64) -> Box<dyn ProtocolHandler>;

    /// A new unidirectional stream — see [`Self::accept_bi`] for
    /// `stream_id`.
    fn accept_uni(&mut self, stream_id: u64) -> Box<dyn ProtocolHandler>;

    /// Called once for every still-live connection right before a local,
    /// explicit [`crate::QuicDriverHandle::shutdown`] tears the driver
    /// down — a last chance to write a final message on an already-open
    /// stream (e.g. HTTP/3's GOAWAY, RFC 9114 §5.2) via `api`. Not called
    /// for a connection lost to the peer or the network, since there is
    /// nothing useful to send at that point. Default: do nothing.
    fn disconnecting(&mut self, api: &mut dyn QuicConnApi) {
        let _ = api;
    }

    /// Called once per driver loop tick for every still-live connection,
    /// outside the `connected`/`accept_bi`/`accept_uni` lifecycle hooks —
    /// the only opportunity for an app to write additional bytes onto an
    /// already-open local stream at an arbitrary later time (e.g. flushing
    /// queued QPACK instruction traffic generated while processing an
    /// unrelated stream). Tick cadence follows the soonest
    /// [`quinn_proto::Connection::poll_timeout`] / app timer (or blocks
    /// until UDP / a wake), not a fixed poll interval. Default: do
    /// nothing.
    fn drive(&mut self, api: &mut dyn QuicConnApi) {
        let _ = api;
    }

    /// Inspect an inbound QUIC DATAGRAM payload (RFC 9221) and tell the
    /// driver how to route it. HTTP/3 demuxes by quarter-stream-ID here
    /// (RFC 9297 §2.1). Default: drop.
    fn decode_datagram(&mut self, _data: &[u8]) -> DatagramDecode {
        DatagramDecode::Drop
    }

    /// An outbound RFC 9221 DATAGRAM could not be queued (peer has no
    /// DATAGRAM support, payload too large, or DATAGRAM disabled locally).
    /// Default: ignore.
    fn datagram_send_failed(&mut self, _err: &std::io::Error) {}
}

/// How the driver should treat an inbound QUIC DATAGRAM (RFC 9221) after
/// the connection app has inspected it (e.g. HTTP/3 quarter-stream demux).
#[derive(Debug)]
pub enum DatagramDecode {
    /// Silently drop (no matching stream yet, or deliberately ignored).
    Drop,
    /// Deliver `payload` to the bidirectional stream with this QUIC stream id.
    Deliver {
        /// Real QUIC stream id (RFC 9000 §2.1).
        stream_id: u64,
        /// Bytes after any application demux prefix (e.g. HTTP Datagram payload).
        payload: Vec<u8>,
    },
    /// Abort one stream with an application error code.
    AbortStream {
        /// Real QUIC stream id.
        stream_id: u64,
        /// Application error code (e.g. HTTP/3 `H3_DATAGRAM_ERROR`).
        error_code: u32,
    },
    /// Close the whole connection with an application error code.
    CloseConnection {
        /// Application error code.
        error_code: u32,
    },
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

    /// Queue a QUIC DATAGRAM (RFC 9221) for the connection. Default: no-op
    /// (returns `Unsupported`).
    fn send_datagram(&mut self, _payload: &[u8]) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "datagrams not supported by this QuicConnApi",
        ))
    }

    /// Set quinn-proto send priority for a stream (higher = sooner). Used by
    /// HTTP/3 to apply RFC 9218 urgency. `stream_id` is the real QUIC id.
    /// Default: ignore.
    fn set_stream_priority(&mut self, _stream_id: u64, _priority: i32) {}
}
