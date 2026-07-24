# Hopf

Native, asynchronous, non-blocking, event-driven **multi-protocol networking
framework** in Rust. Successor to
[Gumdrop](https://github.com/cpkb-bluezoo/gumdrop) without the servlet
container.

Hopf uses a **thread-per-core** readiness model on
[mio](https://github.com/tokio-rs/mio), plain buffers, and **rustls** for TCP TLS
and QUIC ([quinn-proto](https://docs.rs/quinn-proto) + in-tree mio glue).
**Listen and dial** are equal bindings on one Runtime. Codecs are **incremental
push parsers** (chunked, resumable ingress; handler-callback egress), including
grammar-driven tokens on a shared `ByteStreamLexer`.

Sibling parsers ([crates.io](https://crates.io); local path override via
`[patch.crates-io]` when hacking):
[tractrix](https://crates.io/crates/tractrix) (XML — WebDAV + composition),
[rjsonparser](https://crates.io/crates/rjsonparser),
[rmimeparser](https://crates.io/crates/rmimeparser),
[rprotobuf](https://crates.io/crates/rprotobuf).

## Status

Greenfield. **Tranche 8** complete (composition, dynamic bindings, auth vocabulary,
CIDR/rate limits, quota/telemetry seams). **DNS** (`hopf-dns`) and
**QUIC/H3** (Tranche 7) landed. Design locks:
[issues #1–#8](https://github.com/cpkb-bluezoo/hopf/issues).

| Document | Role |
| -------- | ---- |
| [docs/index.html](docs/index.html) | User guides and cookbook (GitHub Pages) |
| [PLAN.md](PLAN.md) | Architecture and product decisions |
| [TRANCHES.md](TRANCHES.md) | Implementation order and exit criteria |

## Documentation

Browse the HTML reference at [docs/index.html](docs/index.html) (enable GitHub
Pages from the `/docs` folder for the published site). Covers getting started,
services/clients, composition, HTTP, TLS, DNS, auth, and access control. Crate
READMEs stay short and link there; PLAN/TRANCHES remain architecture/tranche
sources of truth.

## Workspace

```
crates/
  hopf-core/       # TPC reactor, Endpoint, ProtocolHandler, Composition, ACL
  hopf-tls/        # rustls (TCP TLS + STARTTLS; shared identity for QUIC)
  hopf-http/       # HTTP/1.x + H2 + in-tree H3; Stream app API; Basic auth
  hopf-quic/       # quinn-proto + mio glue
  hopf-dns/        # stub resolver + caching forwarder (UDP/TCP/DoT/DoQ/DoH)
  hopf-auth/       # TrustPolicy / IdentityMaterial / SASL
  hopf-otel/       # OTLP/HTTP + JSONL telemetry exporters
  hopf-webdav/     # RFC 4918 filesystem WebDAV
  hopf-websocket/  # RFC 6455 (+ H2/H3 Extended CONNECT)
  hopf-grpc/       # unary gRPC over HTTP Streams
  hopf-ftp/        # FTP / FTPS server + blocking client
  hopf-smtp/       # SMTP / SMTPS server + client + simple MX relay
  hopf-mailbox/    # mbox / Maildir++ storage SPI
examples/
  echo/              # TCP echo
  tls-echo/          # TLS echo
  http-hello/        # HTTP hello (H1/H2)
  http-get/          # HTTP client
  http3-hello/       # HTTP/3
  dns-proxy/         # caching DNS forwarder
  webdav/            # WebDAV file server
  websocket/         # WebSocket echo
  grpc/              # unary gRPC echo
  ftp/               # FTP filesystem server
  ftp-get/           # FTP client LIST/RETR
  smtp/              # accept-all SMTP server
  smtp-send/         # blocking SMTP client
```

## Build

```bash
cargo check --workspace
cargo test --workspace
cargo run -p echo -- 127.0.0.1:8080
cargo run -p tls-echo -- 127.0.0.1:8443
cargo run -p http-hello -- 127.0.0.1:8080
```

Requires Rust 1.70+ (edition 2021). Sibling parsers resolve from crates.io.

## Non-goals

- Async app runtimes (Tokio et al.) / Hyper / Axum / Tower as the application stack
- Servlet / JSP / Java EE APIs; reflective XML DI
- serde as the codec layer; TOML/YAML as primary composition formats

## License

[GNU Lesser General Public License v2.1 or later](LICENSE).
