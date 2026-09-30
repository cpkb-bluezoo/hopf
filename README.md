# Hopf

<p align="center">
  <img src="docs/assets/hopf.png" alt="Hopf fibration" width="360">
</p>

Native, asynchronous, non-blocking, event-driven **multi-protocol networking
framework** in Rust. Successor to
[Gumdrop](https://github.com/cpkb-bluezoo/gumdrop) without the servlet
container.

Hopf uses a **thread-per-core** readiness model on
[mio](https://github.com/tokio-rs/mio) where connections are multiplexed
over the thread and plain buffers. **Listen and dial** are equal bindings on
one Runtime. Codecs are **incremental push parsers**: chunked, resumable
ingress; handler-callback egress.

**Security:** cryptography is consolidated under
[`hopf-core`](crates/hopf-core) on **AWS-LC** (BoringSSL lineage, reached
through `aws-lc-rs`/`aws-lc-sys`), with TLS, DTLS, and QUIC implemented
in-tree on the same thread-per-core reactor model — TCP TLS 1.2/1.3
(`hopf-core::tls`), UDP DTLS 1.2/1.3 with per-peer version negotiation
(`hopf-core::dtls`/`dtls12`), and QUIC's RFC 9000 transport plus its TLS 1.3
handshake (`hopf-quic`), hybrid-first PQC key exchange. No `rustls` or
`quinn-proto` dependency remains in any production crate; `hopf-tls` is
kept only as a `rustls`-based interop test harness for `hopf-core::tls`.
Remaining work — DTLS's generic `Endpoint` integration, optional
GSSAPI/Kerberos SASL — is tracked in
[Architecture](https://cpkb-bluezoo.github.io/hopf/architecture.html#security-substrate)
and the [conformance audit](https://cpkb-bluezoo.github.io/hopf/conformance.html#security-substrate).

Sibling parsers ([crates.io](https://crates.io); local path override via
`[patch.crates-io]` when hacking):
[tractrix](https://crates.io/crates/tractrix) (XML — WebDAV + composition),
[rjsonparser](https://crates.io/crates/rjsonparser) (JSON),
[rmimeparser](https://crates.io/crates/rmimeparser) (MIME and RFC5322),
[rprotobuf](https://crates.io/crates/rprotobuf) (Protobuf).

## Install

The [`hopf`](https://crates.io/crates/hopf) umbrella crate re-exports every
`hopf-*` crate as a module (`hopf::core`, `hopf::http`, `hopf::smtp`,
`hopf::imap`, …):

```toml
[dependencies]
hopf = "0.4.0"   # everything
# or pick crates individually:
hopf = { version = "0.4.0", default-features = false, features = ["http", "tls"] }
```

Individual crates (`hopf-core`, `hopf-http`, …) can also be depended on
directly.

## Documentation

Browse the [HTML reference](https://cpkb-bluezoo.github.io/hopf/).
Covers what Hopf can do, architecture, services/clients, composition, and
every protocol crate.

## Build

```bash
cargo check --workspace
# Same unit-test command used by CI (does not enable integration features):
cargo test --workspace --lib
# Opt-in I/O smoke suites, run locally per crate when needed:
cargo test -p hopf-smtp --features integration
cargo test -p hopf-imap --features integration
cargo run -p echo -- 127.0.0.1:8080
cargo run -p tls-echo -- 127.0.0.1:8443
cargo run -p http-hello -- 127.0.0.1:8080
```

Requires Rust 1.85+ (edition 2021).

## License

[GNU Lesser General Public License v3 or later](COPYING.LESSER) (incorporates
the terms of the [GNU General Public License v3](COPYING), per LGPLv3 §0).
