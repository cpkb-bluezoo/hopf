// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Encrypted Client Hello bootstrap from DNS HTTPS records (RFC 9849 §1,
//! RFC 9460 §9).
//!
//! A client that wants to use ECH for `host` needs the server's `ECHConfig`,
//! which the server publishes in the `ech` SvcParam of an HTTPS (or SVCB)
//! record. This module resolves it and hands it to the TLS layer without ever
//! blocking:
//!
//! 1. [`resolve_ech`] sends the HTTPS query through a [`DnsResolver`] (whose
//!    callbacks run on the reactor) and stores the answer in an
//!    [`EchConfigCache`].
//! 2. [`connector_with_ech_cache`] wraps a TLS connector; on each connection
//!    it *reads the cache* - a plain lookup, never DNS - and offers ECH if a
//!    config is there. No record (or a lookup that has not finished) means an
//!    ordinary ClientHello: behaviour is unchanged for hosts without ECH.
//!
//! A caller that wants ECH to be a requirement calls [`resolve_ech`] first and
//! connects from its callback, using
//! [`EchClientConfig::require`](hopf_core::tls::ech::EchClientConfig::require)
//! (see [`EchConfigCache::set_static`]).
//!
//! # Trust model
//!
//! A config from DNS is only as trustworthy as the answer. On a plain
//! (unauthenticated, unsigned) path an on-path attacker can strip the `ech`
//! parameter, which silently downgrades the connection to a cleartext SNI, or
//! substitute a config of their own. Mitigations, strongest first:
//!
//! * **Static configuration** - [`EchConfigCache::set_static`] pins a config
//!   for a host and overrides DNS entirely; use it where the deployment knows
//!   the server's config.
//! * **An authenticated resolver path** - DoT, DoH or DoQ to a trusted
//!   resolver (see the [`DnsResolver`] `add_server_*` methods) - or DNSSEC
//!   validation ([`DnsResolver::set_dnssec_enabled`]).
//! * **`require`** - to make a missing config a failure rather than a
//!   downgrade, set `required` on the config you connect with.
//!
//! This module does not itself decide that an answer is authentic; it uses
//! whatever the resolver hands back. The `retry_configs` a server sends after
//! rejecting ECH are handled separately, and are authenticated by the TLS
//! handshake (see [`hopf_core::tls::ech`]).
//!
//! # Protocols
//!
//! Lookups are for the HTTPS record type (RFC 9460 §9.5), so HTTPS clients use
//! this path first. Other TLS clients can call [`resolve_ech_at`] with the
//! SVCB name their protocol defines.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hopf_core::tls::ech::EchClientConfig;
use hopf_core::tls::{connector_with_ech, SharedTlsConnector};

use crate::client::DnsResolver;
use crate::wire::{DnsMessage, DnsQuestion, DnsResourceRecord, DnsType};

/// How long "this host has no ECH record" is remembered, so a host without ECH
/// is not re-queried on every connection.
const NEGATIVE_TTL: Duration = Duration::from_secs(60);
/// Longest a DNS-supplied config is kept, whatever its TTL.
const MAX_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// Alias hops followed before giving up (RFC 9460 §3 suggests a small limit).
const MAX_ALIAS_HOPS: usize = 8;

/// An ECH config found in DNS, with the service parameters that came with it.
#[derive(Debug, Clone)]
pub struct EchDiscovery {
    /// The client configuration to connect with (its configs are in the
    /// server's order of preference; GREASE is off, since a config exists).
    pub config: EchClientConfig,
    /// The service endpoint's TargetName, or `None` when it is the origin
    /// itself (`.`). Connect to this name's addresses, but keep the origin as
    /// the TLS server name.
    pub target: Option<String>,
    /// The record's `port` SvcParam, if any.
    pub port: Option<u16>,
    /// The record's `alpn` protocol ids.
    pub alpn: Vec<String>,
    /// The record's TTL in seconds.
    pub ttl: u32,
}

/// The query name for `host` at `port` under RFC 9460 §9.5: the host itself
/// for port 443, otherwise `_<port>._https.<host>`.
pub fn ech_query_name(host: &str, port: u16) -> String {
    let host = host.trim_end_matches('.');
    if port == 443 {
        host.to_owned()
    } else {
        format!("_{port}._https.{host}")
    }
}

fn same_name(a: &str, b: &str) -> bool {
    a.trim_end_matches('.').eq_ignore_ascii_case(b.trim_end_matches('.'))
}

/// Pick the ECH config out of an HTTPS/SVCB response for `qname`.
///
/// The names that may carry the answer are `qname` and everything reachable
/// from it through CNAMEs and AliasMode records *present in this message*
/// (recursive resolvers usually chase these for us). ServiceMode records are
/// tried in ascending priority; the first whose `ech` parameter parses as a
/// usable `ECHConfigList` wins. A record whose config is malformed is skipped
/// rather than ending the search.
///
/// Returns `Err(alias)` with an AliasMode target when the answer names one that
/// it does not itself resolve, so the caller can follow it.
pub fn discover_from_response(msg: &DnsMessage, qname: &str) -> Result<Option<EchDiscovery>, String> {
    let mut names = vec![qname.trim_end_matches('.').to_ascii_lowercase()];
    // Grow the reachable set to a fixed point (bounded by the record count).
    loop {
        let before = names.len();
        for rr in &msg.answers {
            if !names.iter().any(|n| same_name(n, &rr.name)) {
                continue;
            }
            let next = match rr.rtype {
                Some(DnsType::Cname) => rr.as_domain_name(),
                Some(DnsType::Https | DnsType::Svcb) if rr.is_svcb_alias_form() => rr.svcb_target_name(),
                _ => None,
            };
            if let Some(n) = next {
                let n = n.trim_end_matches('.').to_ascii_lowercase();
                if !n.is_empty() && !names.contains(&n) {
                    names.push(n);
                }
            }
        }
        if names.len() == before {
            break;
        }
    }

    let mut candidates: Vec<&DnsResourceRecord> = msg
        .answers
        .iter()
        .filter(|rr| matches!(rr.rtype, Some(DnsType::Https | DnsType::Svcb)))
        .filter(|rr| !rr.is_svcb_alias_form())
        .filter(|rr| names.iter().any(|n| same_name(n, &rr.name)))
        .collect();
    candidates.sort_by_key(|rr| rr.svcb_priority().unwrap_or(u16::MAX));

    for rr in candidates {
        let Some(raw) = rr.svcb_ech() else {
            continue;
        };
        let Ok(config) = EchClientConfig::from_config_list(&raw) else {
            continue;
        };
        if !config.configs.iter().any(|c| c.is_usable_by_client()) {
            continue;
        }
        let target = rr.svcb_target_name().filter(|t| !t.is_empty() && t != ".");
        return Ok(Some(EchDiscovery {
            config,
            target,
            port: rr.svcb_port(),
            alpn: rr.svcb_alpn_protocols(),
            ttl: rr.ttl,
        }));
    }

    // Nothing usable here: an AliasMode record pointing at a name the answer
    // does not include is worth following.
    let unresolved_alias = msg
        .answers
        .iter()
        .filter(|rr| matches!(rr.rtype, Some(DnsType::Https | DnsType::Svcb)) && rr.is_svcb_alias_form())
        .filter(|rr| names.iter().any(|n| same_name(n, &rr.name)))
        .filter_map(|rr| rr.svcb_target_name())
        .map(|t| t.trim_end_matches('.').to_owned())
        .find(|t| !t.is_empty() && !msg.answers.iter().any(|rr| same_name(&rr.name, t)));
    match unresolved_alias {
        Some(alias) => Err(alias),
        None => Ok(None),
    }
}

struct Entry {
    config: Option<EchClientConfig>,
    expires: Option<Instant>,
}

/// Per-host ECH configs, filled by [`resolve_ech`] and read (without
/// blocking) by [`connector_with_ech_cache`].
///
/// Keyed by lower-cased host name only: a TLS connector is handed just the
/// server name, not the port.
#[derive(Default)]
pub struct EchConfigCache {
    entries: Mutex<HashMap<String, Entry>>,
}

impl EchConfigCache {
    /// A new, empty cache.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn key(host: &str) -> String {
        host.trim_end_matches('.').to_ascii_lowercase()
    }

    /// Pin `config` for `host`, overriding DNS and never expiring - the
    /// strongest trust model (see the module docs).
    pub fn set_static(&self, host: &str, config: EchClientConfig) {
        self.entries
            .lock()
            .expect("ech cache lock")
            .insert(Self::key(host), Entry { config: Some(config), expires: None });
    }

    /// The config to connect to `host` with, if there is a live one. Never
    /// touches the network.
    pub fn get(&self, host: &str) -> Option<EchClientConfig> {
        let entries = self.entries.lock().expect("ech cache lock");
        let e = entries.get(&Self::key(host))?;
        if e.expires.is_some_and(|t| t <= Instant::now()) {
            return None;
        }
        e.config.clone()
    }

    /// Whether the cache holds a live answer for `host`, positive or negative.
    pub fn is_fresh(&self, host: &str) -> bool {
        let entries = self.entries.lock().expect("ech cache lock");
        entries
            .get(&Self::key(host))
            .is_some_and(|e| e.expires.is_none_or(|t| t > Instant::now()))
    }

    fn store(&self, host: &str, config: Option<EchClientConfig>, ttl: Duration) {
        let mut entries = self.entries.lock().expect("ech cache lock");
        let key = Self::key(host);
        // A pinned config is never replaced by DNS.
        if entries.get(&key).is_some_and(|e| e.expires.is_none() && e.config.is_some()) {
            return;
        }
        entries.insert(key, Entry { config, expires: Some(Instant::now() + ttl) });
    }
}

/// Completion callback for [`resolve_ech`]: the discovery, or `None` when the
/// host publishes no usable ECH config (or the lookup failed).
pub type EchCallback = Box<dyn FnOnce(Option<EchDiscovery>) + Send>;

/// Look up the ECH config for `host` at `port` and store it in `cache`.
///
/// Never blocks: the query goes through `resolver`'s reactor and `cb` runs
/// when it completes. A host that has a pinned config
/// ([`EchConfigCache::set_static`]) is not queried at all. Failures and
/// missing records are cached briefly as "no ECH", and reported as `None`, so
/// the connection proceeds as a plain one.
pub fn resolve_ech(resolver: &DnsResolver, cache: &Arc<EchConfigCache>, host: &str, port: u16, cb: EchCallback) {
    resolve_ech_at(resolver, cache, host, &ech_query_name(host, port), cb);
}

/// [`resolve_ech`] with an explicit query name, for protocols whose SVCB name
/// is not the HTTPS mapping. The result is cached under `host`.
pub fn resolve_ech_at(resolver: &DnsResolver, cache: &Arc<EchConfigCache>, host: &str, qname: &str, cb: EchCallback) {
    if let Some(cfg) = cache.get(host) {
        // Pinned or already known: answer from the cache.
        cb(Some(EchDiscovery { config: cfg, target: None, port: None, alpn: Vec::new(), ttl: 0 }));
        return;
    }
    query_hop(resolver.clone(), Arc::clone(cache), host.to_owned(), qname.to_owned(), 0, cb);
}

fn query_hop(resolver: DnsResolver, cache: Arc<EchConfigCache>, host: String, qname: String, hop: usize, cb: EchCallback) {
    let question = DnsQuestion::in_class(qname.clone(), DnsType::Https);
    let again = resolver.clone();
    resolver.query(
        question,
        Box::new(move |result| {
            let outcome = match result {
                Ok(msg) if msg.rcode() == 0 => discover_from_response(&msg, &qname),
                _ => Ok(None),
            };
            match outcome {
                Ok(found) => {
                    match &found {
                        Some(d) => cache.store(&host, Some(d.config.clone()), Duration::from_secs(u64::from(d.ttl)).min(MAX_TTL)),
                        None => cache.store(&host, None, NEGATIVE_TTL),
                    }
                    cb(found);
                }
                Err(alias) if hop < MAX_ALIAS_HOPS => query_hop(again, cache, host, alias, hop + 1, cb),
                Err(_) => {
                    cache.store(&host, None, NEGATIVE_TTL);
                    cb(None);
                }
            }
        }),
    );
}

/// Wrap `inner` so every connection offers ECH when `cache` holds a config for
/// the server name. A cache miss is a plain ClientHello - never a DNS lookup on
/// the connecting thread. Populate the cache first with [`resolve_ech`].
pub fn connector_with_ech_cache(inner: SharedTlsConnector, cache: Arc<EchConfigCache>) -> SharedTlsConnector {
    connector_with_ech(inner, move |name| cache.get(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hopf_core::crypto::hpke::Kem;
    use hopf_core::tls::ech::{EchConfig, HpkeCipherSuite};

    use crate::wire::SVCB_PARAM_ECH;

    fn config_list(id: u8, name: &str) -> Vec<u8> {
        let (c, _) = EchConfig::generate(
            id,
            Kem::DhkemX25519HkdfSha256,
            vec![HpkeCipherSuite { kdf_id: 1, aead_id: 1 }],
            0,
            name,
        )
        .unwrap();
        EchConfig::encode_list(&[c]).unwrap()
    }

    fn https(owner: &str, prio: u16, target: &str, ech: Option<&[u8]>) -> DnsResourceRecord {
        let params: Vec<(u16, Vec<u8>)> = ech.map(|e| (SVCB_PARAM_ECH, e.to_vec())).into_iter().collect();
        DnsResourceRecord::https(owner, 300, prio, target, &params).unwrap()
    }

    fn msg(answers: Vec<DnsResourceRecord>) -> DnsMessage {
        let q = DnsMessage::query(0, DnsQuestion::in_class("x.example", DnsType::Https), true);
        let mut m = q.response_template(0);
        m.answers = answers;
        m
    }

    #[test]
    fn query_names_follow_rfc_9460_section_9_5() {
        assert_eq!(ech_query_name("www.example.com", 443), "www.example.com");
        assert_eq!(ech_query_name("www.example.com.", 8443), "_8443._https.www.example.com");
    }

    #[test]
    fn picks_the_ech_config_from_a_service_mode_record() {
        let list = config_list(1, "public.example");
        let d = discover_from_response(&msg(vec![https("x.example", 1, ".", Some(&list))]), "x.example")
            .unwrap()
            .expect("discovery");
        assert_eq!(d.config.configs[0].public_name, "public.example");
        assert!(d.target.is_none());
        assert_eq!(d.ttl, 300);
    }

    #[test]
    fn lowest_priority_usable_record_wins_and_malformed_ones_are_skipped() {
        let (good, better) = (config_list(1, "good.example"), config_list(2, "better.example"));
        let m = msg(vec![
            https("x.example", 3, ".", Some(&good)),
            https("x.example", 1, ".", Some(&[0, 1, 2])), // malformed: skipped
            https("x.example", 2, "svc.example", Some(&better)),
        ]);
        let d = discover_from_response(&m, "x.example").unwrap().unwrap();
        assert_eq!(d.config.configs[0].public_name, "better.example");
        assert_eq!(d.target.as_deref(), Some("svc.example"));
    }

    #[test]
    fn no_record_or_no_ech_parameter_means_no_config() {
        assert!(discover_from_response(&msg(vec![]), "x.example").unwrap().is_none());
        let m = msg(vec![https("x.example", 1, ".", None)]);
        assert!(discover_from_response(&m, "x.example").unwrap().is_none());
        // A record for a different name is not ours.
        let list = config_list(1, "p.example");
        let m = msg(vec![https("other.example", 1, ".", Some(&list))]);
        assert!(discover_from_response(&m, "x.example").unwrap().is_none());
    }

    #[test]
    fn a_config_this_stack_cannot_use_is_ignored() {
        // DHKEM(X448) is not implemented here, so the record is unusable.
        let unusable = EchConfig::new(
            1, 0x21, vec![1; 56], vec![HpkeCipherSuite { kdf_id: 1, aead_id: 1 }], 0, "p.example", vec![],
        )
        .unwrap();
        let list = EchConfig::encode_list(&[unusable]).unwrap();
        let m = msg(vec![https("x.example", 1, ".", Some(&list))]);
        assert!(discover_from_response(&m, "x.example").unwrap().is_none());
    }

    #[test]
    fn cname_and_alias_chains_in_the_answer_are_followed() {
        let list = config_list(1, "p.example");
        let m = msg(vec![
            DnsResourceRecord::cname("x.example", 300, "cdn.example").unwrap(),
            https("cdn.example", 0, "pool.example", None),
            https("pool.example", 1, ".", Some(&list)),
        ]);
        assert!(discover_from_response(&m, "x.example").unwrap().is_some());
    }

    #[test]
    fn an_alias_the_answer_does_not_resolve_is_returned_for_following() {
        let m = msg(vec![https("x.example", 0, "pool.example", None)]);
        assert!(matches!(discover_from_response(&m, "x.example"), Err(a) if a == "pool.example"));
    }

    #[test]
    fn the_cache_pins_static_configs_and_expires_dns_ones() {
        let cache = EchConfigCache::new();
        let pinned = EchClientConfig::from_config_list(&config_list(1, "pinned.example")).unwrap();
        cache.set_static("Host.Example.", pinned);
        // DNS may not displace a pinned config.
        let dns = EchClientConfig::from_config_list(&config_list(2, "dns.example")).unwrap();
        cache.store("host.example", Some(dns.clone()), Duration::from_secs(60));
        assert_eq!(cache.get("host.example").unwrap().configs[0].public_name, "pinned.example");

        cache.store("other.example", Some(dns), Duration::from_secs(0));
        assert!(cache.get("other.example").is_none(), "expired");
        assert!(!cache.is_fresh("other.example"));
        cache.store("none.example", None, NEGATIVE_TTL);
        assert!(cache.get("none.example").is_none());
        assert!(cache.is_fresh("none.example"), "a negative answer is remembered");
        assert!(!cache.is_fresh("never-asked.example"));
    }
}
