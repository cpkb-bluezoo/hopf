// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! UDP caching DNS forwarder (Gumdrop `gumdroprc.dns` UDP portion).

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hopf_core::Runtime;
use hopf_dns::server::{
    listen_dns_udp, parse_upstream_list, DnsService, DnsServiceHandle, DnsUdpListenConfig,
};
use hopf_dns::{DnsCache, DnsResolver};

fn main() -> std::io::Result<()> {
    let bind: SocketAddr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:5353".into())
        .parse()
        .expect("bind addr");
    let upstreams = env::var("DNS_UPSTREAM").unwrap_or_else(|_| "8.8.8.8 1.1.1.1".into());
    let upstream_addrs = parse_upstream_list(&upstreams)?;

    let rt = Runtime::start(Default::default())?;
    let cache = Arc::new(DnsCache::default());
    let resolver = DnsResolver::new(rt.pick_worker().clone());
    resolver.set_cache(Arc::clone(&cache));
    for a in &upstream_addrs {
        resolver.add_server(*a);
    }
    resolver.open()?;

    let mut service = DnsService::new(Arc::clone(&cache));
    service.set_upstream(resolver);
    let handle = DnsServiceHandle::new(service);

    let worker = rt.pick_worker();
    let (local, _token) = listen_dns_udp(
        worker,
        DnsUdpListenConfig {
            addr: bind,
            service: handle,
        },
    )?;
    eprintln!("dns-proxy listening on {local} → {upstreams}");

    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}
