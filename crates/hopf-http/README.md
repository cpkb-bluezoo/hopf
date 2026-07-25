# hopf-http

Stream-first HTTP for Hopf. Applications use [`HttpStream`] plus
**server** / **client** handlers; H1, H2, and (feature `h3`) H3 adapt transport
`Endpoint`s into Streams. Listen and dial are equal; neither role is the
product centre.

- **H1 / H2:** `H1Endpoint`, `H2Endpoint`, `AlpnHttpEndpoint`, `CleartextHttpEndpoint`
- **Async client dial:** `connect_http(&Arc<Runtime>, host, port, …)` resolves
  hostnames (or skips DNS for literals), applies `HttpClientTimeouts`
  (`dns` / `connect` / `stage`), and returns immediately
- **H2 framing:** push-incremental `H2Parser` + zero-copy frame-handler callbacks;
  HPACK lives under `h2::hpack`
- **H3** (feature `h3`): QPACK + push `H3Parser`; `listen_h3` / `connect_h3` over
  `hopf-quic` (UDP stays in `-quic`). Demos: `http3-hello`,
  `http-get --http3 --ca …`. Smoke:
  `cargo test -p hopf-http --features h3 h3_get_hello`

Depends on `hopf-core` (and optionally `hopf-quic`). See
[docs/http/overview.html](../../docs/http/overview.html).
