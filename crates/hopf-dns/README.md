# hopf-dns

DNS stub resolver and caching forwarder for Hopf (Gumdrop-parity).

## Features

| Feature | Enables |
|---------|---------|
| (default) | Wire format, cache, hosts, UDP/TCP resolver, system resolvers |
| `server` | `DnsService` + UDP listener |
| `dot` | DoT client helpers + DoT server (`server`+`dot`) |
| `doq` | DoQ client/server (`hopf-quic`) |
| `doh` | DoH client (RFC 8484 POST) |
| `dnssec` | Cryptographic validation: RSASHA256/512, ECDSAP256/384, Ed25519; IANA root DS |

## Not in scope (same as Gumdrop)

Authoritative zones, AXFR/IXFR, TSIG, dynamic UPDATE, DNSSEC signing, DoH server.

## Quick start (resolver)

```rust
use std::sync::Arc;
use hopf_core::{Runtime, RuntimeConfig};
use hopf_dns::{DnsResolver, RuntimeDnsExt};

let rt = Arc::new(Runtime::start(RuntimeConfig::default())?);
let resolver = DnsResolver::for_runtime(rt.as_ref())?;
resolver.query_a("example.com", Box::new(|result| {
    // ...
}));
```

## Dial by name

`RuntimeDnsExt` is implemented for `Arc<Runtime>`. `connect_by_name` schedules
DNS asynchronously and returns immediately; the TCP dial runs from the
callback (literal IPs skip DNS).

```rust
use hopf_dns::RuntimeDnsExt;
// rt.connect_by_name("example.com", 80, || Box::new(MyHandler))?;
```

## Transports

`DnsClientTransport` / `DnsClientTransportHandler` — callback-driven only (no
blocking query). DoH (`DohClientTransport`) and DoQ (`DoqClientTransport`)
implement that trait; each `send_query` schedules I/O and delivers via the
handler.

See `examples/dns-proxy` for a UDP caching forwarder.
