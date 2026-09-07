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

**Today:** quinn-proto for RFC 9000 transport; rustls TLS 1.3 configs for
RFC 9001 (PQC-first). **Planned:** in-tree RFC 9000 transport and in-tree TLS
1.3 handshake for QUIC; retire quinn-proto and rustls on this path. See
[docs/quic-h3.html#implementation-status](../../docs/quic-h3.html#implementation-status).
