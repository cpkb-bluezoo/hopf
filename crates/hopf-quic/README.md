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
`hopf-core::tls` for QUIC. HTTP/3 (RFC 9114) and QPACK (RFC 9204) ship
in-tree in `hopf-http` on top of this crate. Retry, GSO, 0-RTT/early data,
QUIC version 2 (RFC 9369), version negotiation, and QUIC-LB connection IDs
are all implemented. Remaining gaps: connection migration is structurally
inert, `NEW_TOKEN`-based address validation doesn't exist, and the 3×
anti-amplification byte cap isn't enforced (moot under the default
high-security Retry hardening). See
[docs/quic-h3.html#implementation-status](../../docs/quic-h3.html#implementation-status)
and [docs/conformance.html#quic](../../docs/conformance.html#quic) for the
full row-by-row detail.
