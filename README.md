# Hopf

<p align="center">
  <img src="docs/assets/hopf.png" alt="Hopf fibration" width="360">
</p>

Native, asynchronous, non-blocking, event-driven **multi-protocol networking
framework** in Rust. Servers and clients are equal: **listen and dial** are
peer bindings on one `Runtime`, and every protocol crate provides both roles
where the protocol has them. A process can be a server, a client, a proxy or
any mixture.

Hopf uses a **thread-per-core** readiness model on
[mio](https://github.com/tokio-rs/mio): each connection is owned by one
reactor thread for its whole life, and blocking work runs on a separate
storage pool. Bytes arrive in a fixed-size
[loopbuf](https://github.com/cpkb-bluezoo/loopbuf) ring per connection that
protocol handlers read in place, consuming whole tokens. Codecs are
**incremental push parsers** with bounded state, so nothing buffers a
message or a stream, and a full ring stops the socket from being read
(backpressure). Egress is a handler callback appending to a capped outbound
buffer.

**Security:** cryptography is consolidated under
[`hopf-core`](crates/hopf-core) on **AWS-LC** (BoringSSL lineage, reached
through `aws-lc-rs`/`aws-lc-sys`), with TLS, DTLS and QUIC implemented
in-tree on the same thread-per-core reactor model: TCP TLS 1.2/1.3
(`hopf-core::tls`), UDP DTLS 1.2/1.3 with per-peer version negotiation
(`hopf-core::dtls`/`dtls12`), and QUIC's RFC 9000 transport plus its TLS 1.3
handshake (`hopf-quic`), with hybrid-first post-quantum key exchange. TLS is
AEAD-only, and an opt-in FIPS profile is available (the `fips` feature).

## Protocols

| Area | Crates | Roles |
|---|---|---|
| Transport | `hopf-core` (TCP, UNIX sockets, UDP, TLS, DTLS), `hopf-quic` | both |
| Web | `hopf-http` (HTTP/1.1, HTTP/2, HTTP/3), `hopf-websocket`, `hopf-grpc`, `hopf-webdav`, `hopf-masque` | both (WebDAV: server) |
| Naming | `hopf-dns` (resolver, forwarder, authoritative server; DoT, DoQ, DoH), `hopf-mdns` | both |
| Mail and news | `hopf-smtp`, `hopf-pop3`, `hopf-imap`, `hopf-mailbox` (storage), `hopf-nntp` | server and client |
| File transfer | `hopf-ftp` | both |
| Messaging and data | `hopf-mqtt`, `hopf-amqp` (0-9-1), `hopf-amqp1` (1.0), `hopf-redis` | MQTT: both; others: client |
| Proxying | `hopf-socks` (SOCKS4/4a/5), `hopf-masque` | both |
| Identity | `hopf-auth` (TrustPolicy, SASL), `hopf-ldap` | both; LDAP: client |
| Observability | `hopf-otel` (OTLP/HTTP and JSONL exporters) | client |

Sibling parsers ([crates.io](https://crates.io); local path override via
`[patch.crates-io]` when hacking):
[tractrix](https://crates.io/crates/tractrix) (XML - WebDAV + composition),
[rjsonparser](https://crates.io/crates/rjsonparser) (JSON),
[rmimeparser](https://crates.io/crates/rmimeparser) (MIME and RFC5322),
[rprotobuf](https://crates.io/crates/rprotobuf) (Protobuf).

## Install

The [`hopf`](https://crates.io/crates/hopf) umbrella crate re-exports every
`hopf-*` crate as a module (`hopf::core`, `hopf::http`, `hopf::smtp`,
`hopf::imap`, …):

```toml
[dependencies]
hopf = "0.8.0"   # everything
# or pick crates individually:
hopf = { version = "0.8.0", default-features = false, features = ["http", "tls"] }
```

Individual crates (`hopf-core`, `hopf-http`, …) can also be depended on
directly.

## Documentation

Browse the [HTML reference](https://cpkb-bluezoo.github.io/hopf/).
Covers what Hopf can do, the
[architecture](https://cpkb-bluezoo.github.io/hopf/architecture.html),
services and clients, composition, and every protocol crate.

## Build

```bash
cargo check --workspace
# Same unit-test command used by CI (does not enable integration features):
cargo test --workspace --lib
# The same tests with no network and a read-only filesystem, as CI also runs
# them: a unit test that does socket or file I/O fails here.
./scripts/check-hermetic-tests.sh
# Opt-in I/O smoke suites, run locally per crate when needed:
cargo test -p hopf-smtp --features integration
cargo test -p hopf-imap --features integration
cargo run -p echo -- 127.0.0.1:8080
cargo run -p tls-echo -- 127.0.0.1:8443
cargo run -p http-hello -- 127.0.0.1:8080
```

The [`examples/`](examples) directory has runnable servers and clients for
the main protocols. Requires Rust 1.85+ (edition 2021).

## License

[GNU Lesser General Public License v3 or later](COPYING.LESSER) (incorporates
the terms of the [GNU General Public License v3](COPYING), per LGPLv3 §0).
