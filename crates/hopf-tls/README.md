# hopf-tls

A thin `hopf-core::tls` re-export shim, kept permanently as this
workspace's real-`rustls`-interop test harness for TCP TLS.

**Today:** TCP TLS 1.2/1.3 is implemented in-tree in `hopf-core::tls`
(AWS-LC via `aws-lc-rs`, hybrid-first PQC) — `TcpConnection` doesn't know
anything about `rustls`, and no other crate in this workspace depends on
this one for production code. Every real caller goes straight to
`hopf_core::tls::*`.

**What's left here:** a small shim re-exporting the `hopf-core::tls`
PEM/acceptor/connector helpers under their pre-migration names, plus an
opt-in `integration` feature with real wire interop against `rustls` as an
independent TLS 1.3/1.2 implementation. `rustls` is a `[dev-dependencies]`-only
test peer here — it doesn't appear anywhere else in this workspace's
production dependency graph. This is the *only* independent-implementation
cross-check TCP TLS gets in this workspace, so the crate stays: not
because anything still needs its API, but because deleting it would
silently regress that coverage down to Hopf-talking-to-itself.

See [docs/tls.html](../../docs/tls.html) for the full `hopf-core::tls`
reference (standards, architecture, configuration, PEM helper functions).

Handlers continue to see **plaintext** only. Configure listeners with PEM
certificate + key via [`acceptor_from_pem`](fn@acceptor_from_pem).

```rust
use hopf_core::TcpListenerConfig;
use hopf_tls::acceptor_from_pem;

let acceptor = acceptor_from_pem(
    "cert.pem".as_ref(),
    "key.pem".as_ref(),
    &[b"h2", b"http/1.1"],
)?;
let listener = TcpListenerConfig::new(addr, factory).with_tls(acceptor);
```
