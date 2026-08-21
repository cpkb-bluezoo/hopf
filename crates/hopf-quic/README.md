# hopf-quic

QUIC transport for Hopf: **`quinn-proto`** state machine + **in-tree mio UDP** driver.

HTTP/3 codecs live in **`hopf-http`** (feature `h3`), not in this crate.
Each bidirectional QUIC stream is a [`QuicStreamEndpoint`] implementing
[`hopf_core::Endpoint`].

Abnormal teardown (peer CONNECTION_CLOSE, idle timeout, STOP_SENDING) reaches
[`ProtocolHandler::error`](hopf_core::ProtocolHandler) with
[`QuicConnectionCloseError`] / [`QuicStreamStoppedError`] (downcast via
[`connection_close_error`] / [`stream_stopped_error`]). Clean local shutdown
and graceful stream FIN still use `disconnected`.

## Status

Tranche 7: listen/dial seams (`listen_quic` / `connect_quic`), stream endpoints,
shared rustls identity helpers (PEM / self-signed).
