// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Caching DNS forwarder service + listeners.

#[cfg(feature = "server")]
mod udp;

#[cfg(all(feature = "server", feature = "dot"))]
mod dot;

#[cfg(all(feature = "server", feature = "doq"))]
mod doq;

#[cfg(feature = "server")]
pub use udp::{listen_dns_udp, DnsUdpListenConfig};

#[cfg(all(feature = "server", feature = "dot"))]
pub use dot::listen_dns_dot;

#[cfg(all(feature = "server", feature = "doq"))]
pub use doq::listen_dns_doq;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::cache::DnsCache;
use crate::client::DnsResolver;
use crate::cookie::DnsCookie;
use crate::wire::{DnsMessage, OPCODE_QUERY, RCODE_NOTIMP, RCODE_REFUSED, RCODE_SERVFAIL};

/// Simple server metrics counters.
#[derive(Debug, Default, Clone)]
pub struct DnsServerMetrics {
    /// Queries received.
    pub queries: u64,
    /// Cache hits.
    pub cache_hits: u64,
    /// Upstream forwards.
    pub upstreams: u64,
    /// Errors.
    pub errors: u64,
}

/// Caching forwarder (Gumdrop `DNSService`).
pub struct DnsService {
    cache: Arc<DnsCache>,
    upstream: Option<DnsResolver>,
    cookies: DnsCookie,
    metrics: std::sync::Mutex<DnsServerMetrics>,
    /// Optional local resolve hook: return `Some` to answer, `None` to forward.
    local: Option<Box<dyn Fn(&DnsMessage) -> Option<DnsMessage> + Send + Sync>>,
}

impl DnsService {
    /// New service with shared cache.
    pub fn new(cache: Arc<DnsCache>) -> Self {
        Self {
            cache,
            upstream: None,
            cookies: DnsCookie::new(),
            metrics: std::sync::Mutex::new(DnsServerMetrics::default()),
            local: None,
        }
    }

    /// Attach upstream stub resolver for forwarding.
    pub fn set_upstream(&mut self, resolver: DnsResolver) {
        self.upstream = Some(resolver);
    }

    /// Custom local answers (override `resolve`).
    pub fn set_local_resolver<F>(&mut self, f: F)
    where
        F: Fn(&DnsMessage) -> Option<DnsMessage> + Send + Sync + 'static,
    {
        self.local = Some(Box::new(f));
    }

    /// Shared cache.
    pub fn cache(&self) -> &Arc<DnsCache> {
        &self.cache
    }

    /// Snapshot metrics.
    pub fn metrics(&self) -> DnsServerMetrics {
        self.metrics.lock().unwrap().clone()
    }

    /// Process one query message; returns response (may be async via callback for upstream).
    pub fn process_query_sync(&self, query: &DnsMessage) -> DnsMessage {
        {
            let mut m = self.metrics.lock().unwrap();
            m.queries += 1;
        }
        if query.opcode() != OPCODE_QUERY {
            return query.response_template(RCODE_NOTIMP);
        }
        if query.questions.is_empty() {
            return query.response_template(RCODE_REFUSED);
        }
        let q = &query.questions[0];

        // Cookie-only amplification defence: empty question already handled.
        if let Some(ref local) = self.local {
            if let Some(resp) = local(query) {
                return resp;
            }
        }

        if self.cache.is_negatively_cached(&q.name) {
            let mut m = self.metrics.lock().unwrap();
            m.cache_hits += 1;
            return query.response_template(crate::wire::RCODE_NXDOMAIN);
        }
        if let Some(answers) = self.cache.lookup(q) {
            let mut m = self.metrics.lock().unwrap();
            m.cache_hits += 1;
            let mut resp = query.response_template(0);
            resp.answers = answers;
            return resp;
        }

        // Sync upstream via TCP fallback path when resolver available — for UDP
        // server we use blocking TCP to upstream as a pragmatic Stage-D forward.
        if let Some(ref upstream) = self.upstream {
            let mut m = self.metrics.lock().unwrap();
            m.upstreams += 1;
            drop(m);
            let (tx, rx) = std::sync::mpsc::channel();
            upstream.query(q.clone(), Box::new(move |r| {
                let _ = tx.send(r);
            }));
            match rx.recv_timeout(std::time::Duration::from_secs(5)) {
                Ok(Ok(mut resp)) => {
                    resp.id = query.id;
                    if !query.has_do() {
                        // Strip DNSSEC RRs when client lacks DO (Gumdrop behaviour).
                        resp.answers
                            .retain(|rr| !matches!(rr.rtype, Some(crate::wire::DnsType::Rrsig)
                                | Some(crate::wire::DnsType::Nsec)
                                | Some(crate::wire::DnsType::Nsec3)
                                | Some(crate::wire::DnsType::Dnskey)
                                | Some(crate::wire::DnsType::Ds)));
                    }
                    self.cache.put_response(&resp);
                    resp
                }
                _ => {
                    let mut m = self.metrics.lock().unwrap();
                    m.errors += 1;
                    query.response_template(RCODE_SERVFAIL)
                }
            }
        } else {
            query.response_template(RCODE_SERVFAIL)
        }
    }

    /// Server cookie helper.
    pub fn cookies(&self) -> &DnsCookie {
        &self.cookies
    }
}

/// Config shared by listeners.
#[derive(Clone)]
pub struct DnsServiceHandle {
    inner: Arc<DnsService>,
}

impl DnsServiceHandle {
    /// Wrap service.
    pub fn new(service: DnsService) -> Self {
        Self {
            inner: Arc::new(service),
        }
    }

    /// Process query.
    pub fn process(&self, query: &DnsMessage) -> DnsMessage {
        self.inner.process_query_sync(query)
    }

    /// Arc access.
    pub fn service(&self) -> &Arc<DnsService> {
        &self.inner
    }
}

/// Upstream server list helper.
pub fn parse_upstream_list(s: &str) -> io::Result<Vec<SocketAddr>> {
    let mut out = Vec::new();
    for part in s.split_whitespace() {
        if let Ok(addr) = part.parse::<SocketAddr>() {
            out.push(addr);
        } else if let Ok(ip) = part.parse::<std::net::IpAddr>() {
            out.push(SocketAddr::new(ip, crate::client::DEFAULT_DNS_PORT));
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("bad upstream {part}"),
            ));
        }
    }
    Ok(out)
}
