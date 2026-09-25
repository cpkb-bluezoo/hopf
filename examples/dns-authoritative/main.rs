// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Authoritative DNS server for one zone file (UDP + TCP).
//!
//! ```text
//! dns-authoritative [ZONE_FILE [BIND_ADDR]]
//! ```
//!
//! Defaults to `example.com.zone` next to this file and `127.0.0.1:5353`.
//! Transfers and dynamic updates are allowed from loopback only; updates are
//! written back to the zone file. Set `DNS_UPSTREAM` (for example
//! `"8.8.8.8 1.1.1.1"`) to forward every name outside the zone instead of
//! answering `REFUSED`. Set `DNS_TSIG_KEY` to `name:algorithm:base64secret`
//! (for example `transfer-key:hmac-sha256:c2VjcmV0MTIzNDU2Nw==`) to also
//! accept TSIG-signed transfers and updates from any address.

use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use hopf_core::Runtime;
use hopf_dns::server::zone::{Acl, AuthoritativeZoneHandler, ZoneFileMode, ZoneOptions};
use hopf_dns::server::{
    listen_dns_tcp, listen_dns_udp, parse_upstream_list, ChainHandler, DnsService, DnsServiceHandle,
    DnsUdpListenConfig, ForwarderHandler,
};
use hopf_dns::tsig::{TsigAlgorithm, TsigKey, TsigKeyring};
use hopf_dns::{DnsCache, DnsResolver};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let zone_file: PathBuf = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("example.com.zone"));
    let bind: SocketAddr = env::args().nth(2).unwrap_or_else(|| "127.0.0.1:5353".into()).parse()?;
    let upstreams = env::var("DNS_UPSTREAM").ok();

    let rt = Runtime::start(Default::default())?;

    let tsig_key = match env::var("DNS_TSIG_KEY") {
        Ok(spec) => {
            let mut parts = spec.splitn(3, ':');
            let (name, alg, secret) = (parts.next(), parts.next(), parts.next());
            let (Some(name), Some(alg), Some(secret)) = (name, alg, secret) else {
                return Err("DNS_TSIG_KEY must be name:algorithm:base64secret".into());
            };
            let alg = TsigAlgorithm::from_name(alg).ok_or("unsupported TSIG algorithm")?;
            Some(TsigKey::from_base64(name, alg, secret)?)
        }
        Err(_) => None,
    };
    let mut acl_transfer = Acl::from_cidrs(["127.0.0.0/8", "::1"])?;
    let mut acl_update = Acl::from_cidrs(["127.0.0.0/8", "::1"])?;
    if let Some(key) = &tsig_key {
        acl_transfer = acl_transfer.or_tsig_key(key.name());
        acl_update = acl_update.or_tsig_key(key.name());
    }
    let options = ZoneOptions::new()
        .allow_transfer(acl_transfer)
        .allow_update(acl_update)
        .notify_ns_records(false);
    let zones = AuthoritativeZoneHandler::builder()
        .zone_file(&zone_file, None, ZoneFileMode::ReadWrite, options)?
        .decline_outside_zones(upstreams.is_some())
        .build()?;

    let service = match &upstreams {
        None => DnsService::with_handler(zones),
        Some(list) => {
            let cache = Arc::new(DnsCache::default());
            let resolver = DnsResolver::new(rt.pick_worker().clone());
            resolver.set_cache(Arc::clone(&cache));
            for addr in parse_upstream_list(list)? {
                resolver.add_server(addr);
            }
            resolver.open()?;
            DnsService::with_handler(
                ChainHandler::new()
                    .then(zones)
                    .then(ForwarderHandler::new(cache).with_upstream(resolver)),
            )
        }
    };
    let mut service = service;
    if let Some(key) = tsig_key {
        service.set_tsig_keyring(TsigKeyring::new().with_key(key));
    }
    // Starts the zone maintenance thread (NOTIFY, write-back, secondaries).
    service.start(&rt)?;
    let handle = DnsServiceHandle::new(service);

    let (udp, _token) = listen_dns_udp(
        rt.pick_worker(),
        DnsUdpListenConfig {
            addr: bind,
            service: handle.clone(),
        },
    )?;
    let tcp = listen_dns_tcp(&rt, bind, handle)?;
    eprintln!("dns-authoritative: {} on udp {udp} / tcp {tcp}", zone_file.display());

    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}
