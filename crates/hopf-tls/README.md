# hopf-tls

rustls glue for Hopf `Endpoint`s: TLS-from-accept and STARTTLS.

**Today:** thin adapter over rustls (aws-lc-rs provider, hybrid-first PQC).
**Planned:** in-tree TLS 1.2/1.3 on AWS-LC in `hopf-core`; retire rustls once
parity is proven. See [docs/tls.html#roadmap](../../docs/tls.html#roadmap).

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
