# hopf-quic

QUIC transport for Hopf: **`quinn-proto`** state machine + **in-tree mio UDP** driver.

HTTP/3 codecs live in **`hopf-http`** (feature `h3`), not in this crate.
Each bidirectional QUIC stream is a [`QuicStreamEndpoint`] implementing
[`hopf_core::Endpoint`].

## Status

Tranche 7: listen/dial seams (`listen_quic` / `connect_quic`), stream endpoints,
shared rustls identity helpers (PEM / self-signed).
