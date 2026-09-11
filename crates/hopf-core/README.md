# hopf-core

Thread-per-core (TPC) readiness reactor, `Endpoint` / `ProtocolHandler` /
`Service` / `Listener` / `Connector` traits, buffer pools, timers, and
`StorageExecutor` for blocking filesystem work. Bind
(`Runtime::add_tcp_listener`) and dial (`Runtime::connect`) are peer birth
paths for TCP Endpoints.

## Quick start

```rust
use hopf_core::{Endpoint, ProtocolHandler, Runtime, RuntimeConfig, TcpListenerConfig};

struct Echo;
impl ProtocolHandler for Echo {
    fn connected(&mut self, _: &mut dyn Endpoint) {}
    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        endpoint.send(data);
        *data = &[];
    }
    fn disconnected(&mut self, _: &mut dyn Endpoint) {}
    fn error(&mut self, _: &mut dyn Endpoint, _: &std::io::Error) {}
}

fn main() -> std::io::Result<()> {
    let rt = Runtime::start(RuntimeConfig::default())?;
    rt.add_tcp_listener(TcpListenerConfig::new(
        "127.0.0.1:8080".parse().unwrap(),
        || Box::new(Echo),
    ))?;
    // Blocking FS: rt.storage().submit(endpoint, || std::fs::read(...), |result| { ... });
    Ok(())
}
```

See [docs/architecture.html](../../docs/architecture.html) and
[Security substrate](../../docs/conformance.html#security-substrate) for what
ships today (TCP TLS via rustls, QUIC via quinn-proto, cleartext UDP) versus
planned in-tree TLS/DTLS/QUIC on AWS-LC in core.
Run `cargo run -p echo` for a live echo server.

## Crypto facade (Phase 1+)

`hopf_core::crypto` is the AWS-LC entry point for hashes, signatures, cert
fingerprints, HKDF, and X25519 (feature `ed448` for DNSSEC Ed448). Protocol
crates should use it instead of calling `aws-lc-rs` directly.

## TLS handshake engine (Phase 2+)

`hopf_core::tls::HandshakeEngine` is the reactive QUIC-first TLS 1.3 handshake
(`TlsEventSink`, `QuicSecrets`). Interim TCP TLS remains on `hopf-tls`/rustls
until Phase 4.
