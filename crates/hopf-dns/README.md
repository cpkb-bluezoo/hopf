# hopf-dns

DNS stub resolver and DNS server for Hopf: a caching forwarder and an
authoritative zone server, composed from pluggable handlers.

## Features

| Feature | Enables |
|---------|---------|
| (default) | Wire format, cache, hosts, UDP/TCP resolver, system resolvers |
| `server` | `DnsService` shell, `ForwarderHandler`, `AuthoritativeZoneHandler`, UDP and TCP listeners |
| `dot` | DoT client helpers + DoT server (`server`+`dot`) |
| `doq` | DoQ client/server (`hopf-quic`) |
| `doh` | DoH client (RFC 8484 POST) |
| `dnssec` | Cryptographic validation: RSASHA256/512, ECDSAP256/384, Ed25519; IANA root DS |

## Not in scope

DNSSEC signing of authoritative zones (an externally signed zone is served as
data), DoH server.

## Quick start (authoritative server)

`DnsService` is a protocol shell; with no handler it answers every query with
an empty `NOERROR`. Behaviour comes from a `DnsQueryHandler`:

```rust
use hopf_dns::server::zone::{Acl, AuthoritativeZoneHandler, ZoneFileMode, ZoneOptions};
use hopf_dns::server::{listen_dns_tcp, listen_dns_udp, DnsService, DnsServiceHandle, DnsUdpListenConfig};

let zones = AuthoritativeZoneHandler::builder()
    .zone_file(
        "example.com.zone".as_ref(),
        None,
        ZoneFileMode::ReadWrite,
        ZoneOptions::new()
            .allow_transfer(Acl::from_cidrs(["127.0.0.0/8"])?)
            .allow_update(Acl::from_cidrs(["127.0.0.0/8"])?),
    )?
    .build()?;
let service = DnsService::with_handler(zones);
service.start(&rt)?; // NOTIFY, write-back, secondary refresh
let handle = DnsServiceHandle::new(service);
listen_dns_udp(rt.pick_worker(), DnsUdpListenConfig { addr, service: handle.clone() })?;
listen_dns_tcp(&rt, addr, handle)?;
```

Transfers and updates are refused unless a `ZoneOptions` ACL (source network
and/or TSIG key) allows them. `ChainHandler` puts zones ahead of a
`ForwarderHandler` for split-horizon setups; `secondary(...)` serves a zone
transferred from a primary, refreshing on NOTIFY and the SOA timers. See
`docs/dns.html`.

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
handler. DoQ reuses a live QUIC connection per destination across queries
(`DoqConnectionPool`, RFC 9250 §5.5.1), opening one bidirectional stream per
query.

See `examples/dns-proxy` for a UDP caching forwarder and
`examples/dns-authoritative` for an authoritative server.
