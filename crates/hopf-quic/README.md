# hopf-quic

QUIC transport for Hopf: **in-tree RFC 9000 transport** + **mio UDP** driver.

HTTP/3 codecs live in **`hopf-http`** (feature `h3`), not in this crate.
Each bidirectional QUIC stream is a [`QuicStreamEndpoint`] implementing
[`hopf_core::Endpoint`].

Abnormal teardown (peer CONNECTION_CLOSE, idle timeout, STOP_SENDING) reaches
[`ProtocolHandler::error`](hopf_core::ProtocolHandler) with
[`QuicConnectionCloseError`] / [`QuicStreamStoppedError`] (downcast via
[`connection_close_error`] / [`stream_stopped_error`]). Clean local shutdown
and graceful stream FIN still use `disconnected`.

## Status

**Today:** in-tree transport (no `quinn-proto`); TLS 1.3 handshake via
`hopf-core::tls` for QUIC. Loopback echo works
(`spike_echo_one_stream_hopf` with `QuicListenHardening::permissive()`).
Retry, GSO, and loopback-quality 0-RTT/early data are wired; broader interop
and H3 remain Phase 3 follow-ups. See
[docs/quic-h3.html#implementation-status](../../docs/quic-h3.html#implementation-status)
and [crypto-migration-plan.md](../../crypto-migration-plan.md).
