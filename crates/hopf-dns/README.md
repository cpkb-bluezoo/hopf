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
use hopf_core::Runtime;
use hopf_dns::{DnsResolver, RuntimeDnsExt};

let rt = Runtime::start(Default::default())?;
let resolver = DnsResolver::for_runtime(&rt)?;
resolver.query_a("example.com", Box::new(|result| {
    // ...
}));
```

## Dial by name

```rust
use hopf_dns::RuntimeDnsExt;
// rt.connect_by_name("example.com", 80, || Box::new(MyHandler))?;
```

See `examples/dns-proxy` for a UDP caching forwarder.
