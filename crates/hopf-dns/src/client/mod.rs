// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Asynchronous stub DNS resolver and client transports.

mod hosts;
mod tcp;
mod udp;

#[cfg(feature = "doq")]
pub mod doq;
#[cfg(feature = "doh")]
mod doh;

pub use hosts::{HostsFile, parse_literal_ip};
pub use tcp::{TcpDnsClientTransport, TcpDnsConnectionPool};
pub use udp::UdpDnsClientTransport;

#[cfg(feature = "doq")]
pub use doq::DoqClientTransport;
#[cfg(feature = "doh")]
pub use doh::DohClientTransport;

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mio::Token;
use hopf_core::{ReactorHandle, Runtime, UdpDatagramHandler};

use crate::bailiwick::filter_answers_in_bailiwick;
use crate::cache::DnsCache;
use crate::cookie::DnsCookie;
use crate::wire::{
    normalize_name, DnsMessage, DnsQueryIdGenerator, DnsQuestion, DnsResourceRecord, DnsType,
    OPT_UDP_PAYLOAD, RCODE_NXDOMAIN,
};

/// Default DNS port.
pub const DEFAULT_DNS_PORT: u16 = 53;
/// Default query timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CNAME_DEPTH: usize = 8;

/// High-level resolve callback (Happy Eyeballs-style A+AAAA).
pub type ResolveCallback = Box<dyn FnOnce(io::Result<Vec<SocketAddr>>) + Send>;

/// Single-question callback.
pub type QueryCallback = Box<dyn FnOnce(io::Result<DnsMessage>) + Send>;

/// Pluggable client transport.
pub trait DnsClientTransport: Send {
    /// Send a query; responses arrive via [`DnsClientTransportHandler`].
    ///
    /// `handler` is an owned, `Send` callback. Implementations **must not** block the
    /// caller — they should schedule the I/O (spawn a thread, fire-and-forget connect,
    /// etc.) and return `Ok(())` immediately. The handler may be called from any thread.
    fn send_query(
        &mut self,
        server: SocketAddr,
        message: &[u8],
        handler: Box<dyn DnsClientTransportHandler>,
    ) -> io::Result<()>;
}

/// Transport → resolver callbacks.
///
/// Must be `Send` so that transports can deliver responses from background threads.
pub trait DnsClientTransportHandler: Send {
    /// Response bytes from `server`.
    fn on_response(&mut self, server: SocketAddr, data: &[u8]);
    /// Transport error.
    fn on_error(&mut self, server: SocketAddr, err: io::Error);
}

struct PendingQuery {
    callback: QueryCallback,
    question: DnsQuestion,
    server_idx: usize,
    cname_depth: usize,
    /// Original query id for matching.
    id: u16,
    /// The exact server address this query was sent to (RFC 5452 §2.2) —
    /// an inbound response is only accepted from this address, not from
    /// any source that happens to guess the matching id.
    server: SocketAddr,
    /// RFC 4035 §3.2.2 CD: when set, a Bogus DNSSEC validation result
    /// doesn't fail the query — the caller explicitly asked not to have
    /// validation enforced (e.g. a forwarder relaying a downstream
    /// client's own CD=1 query). Only consulted with the `dnssec` feature
    /// enabled, but always accepted/stored so `query_with_cd`'s signature
    /// doesn't change shape based on the feature.
    #[cfg_attr(not(feature = "dnssec"), allow(dead_code))]
    cd: bool,
    cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

/// Allocate a query id that isn't already in use by another outstanding
/// query — a CSPRNG-drawn id (unlike a monotonic counter) can collide with
/// one still in flight, which would corrupt that query's own tracking.
fn alloc_id(g: &ResolverInner) -> u16 {
    loop {
        let id = g.ids.next_id();
        if !g.pending.contains_key(&id) {
            return id;
        }
    }
}

/// On timeout, retry against the next configured server instead of failing
/// outright — a single slow/dead upstream shouldn't fail every query when
/// redundant servers are configured (`add_server`/`add_server_str`).
/// Exhausting every server fails the query as `TimedOut`, same as when
/// only one server was ever configured. Also used to (re-)arm the timeout
/// for a CNAME-chase re-query, which previously had none at all.
fn retry_or_fail(inner: &Arc<Mutex<ResolverInner>>, id: u16) {
    let mut g = inner.lock().unwrap();
    let Some(mut pending) = g.pending.remove(&id) else {
        return; // already answered, or a stale timer from an earlier retry
    };
    let next_idx = pending.server_idx + 1;
    let Some(&next_server) = g.servers.get(next_idx) else {
        drop(g);
        (pending.callback)(Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "DNS query timed out",
        )));
        return;
    };
    pending.server_idx = next_idx;
    pending.server = next_server;
    let new_id = alloc_id(&g);
    pending.id = new_id;
    let timeout = g.timeout;
    let inner2 = Arc::clone(inner);
    let cancel = g.reactor.schedule_timer(timeout, Box::new(move || retry_or_fail(&inner2, new_id)));
    pending.cancel = Some(cancel);
    let question = pending.question.clone();
    g.pending.insert(new_id, pending);
    if let Err(e) = send_udp_query(&mut g, new_id, &question, next_server) {
        if let Some(p) = g.pending.remove(&new_id) {
            if let Some(c) = &p.cancel {
                c.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            drop(g);
            (p.callback)(Err(e));
        }
    }
}

/// What to do once [`drive_chain_walk`] reaches a trusted zone key: either
/// [`Self::validate_chain_of_trust`]'s per-message check, or
/// [`Self::validate_denial_of_existence`]'s NSEC/NSEC3 proof.
#[cfg(feature = "dnssec")]
enum ChainWalkFinish {
    ValidateMessage,
    ValidateDenial { qname: String, qtype: DnsType },
}

/// Drives one [`crate::dnssec::DnssecChainWalk`] to completion, issuing
/// whatever DS/DNSKEY query each step needs through `resolver`'s own
/// `query()` (so intermediate lookups share the normal cache/retry/id
/// machinery) and recursing on the response. Terminates via `finish`
/// against the chain's final trusted key.
#[cfg(feature = "dnssec")]
fn drive_chain_walk(
    resolver: DnsResolver,
    mut walk: crate::dnssec::DnssecChainWalk,
    step: crate::dnssec::ChainStep,
    original_msg: DnsMessage,
    finish: ChainWalkFinish,
    cb: Box<dyn FnOnce(DnsMessage, crate::dnssec::DnssecStatus) + Send>,
) {
    use crate::dnssec::ChainStep;
    match step {
        ChainStep::NeedDnskey(zone) => {
            let resolver2 = resolver.clone();
            resolver.query(
                DnsQuestion::in_class(&zone, DnsType::Dnskey),
                Box::new(move |r| match r {
                    Ok(msg) => {
                        let next = walk.on_dnskey_response(&msg);
                        drive_chain_walk(resolver2, walk, next, original_msg, finish, cb);
                    }
                    Err(_) => cb(original_msg, crate::dnssec::DnssecStatus::Indeterminate),
                }),
            );
        }
        ChainStep::NeedDs(zone) => {
            let resolver2 = resolver.clone();
            resolver.query(
                DnsQuestion::in_class(&zone, DnsType::Ds),
                Box::new(move |r| match r {
                    Ok(msg) => {
                        let next = walk.on_ds_response(&msg);
                        drive_chain_walk(resolver2, walk, next, original_msg, finish, cb);
                    }
                    Err(_) => cb(original_msg, crate::dnssec::DnssecStatus::Indeterminate),
                }),
            );
        }
        ChainStep::Done { zone, key } => {
            let status = match finish {
                ChainWalkFinish::ValidateMessage => validate_against_key(&zone, &key, &original_msg),
                ChainWalkFinish::ValidateDenial { qname, qtype } => {
                    crate::dnssec::verify_denial(&original_msg, &zone, &key, &qname, qtype)
                }
            };
            cb(original_msg, status);
        }
        ChainStep::Failed(status) => cb(original_msg, status),
    }
}

/// Validate `msg`'s own RRSIGs against a single already-chain-verified
/// `key` for `zone`, by seeding a throwaway trust anchor with `key`'s own
/// digest and reusing [`DnssecValidator`]'s existing per-message logic.
/// [`DnssecValidator::validate_message`] only looks for a matching DNSKEY
/// *inside* the message it's validating (single-message design) — `msg`
/// itself never carries one, since the chain walk fetched `key` via
/// separate DNSKEY/DS round trips, so it's added as glue in a throwaway
/// clone before delegating (the caller's own `original_msg` is untouched).
#[cfg(feature = "dnssec")]
fn validate_against_key(zone: &str, key: &DnsResourceRecord, msg: &DnsMessage) -> crate::dnssec::DnssecStatus {
    let Some(key_tag) = key.dnskey_key_tag() else {
        return crate::dnssec::DnssecStatus::Bogus;
    };
    let Some(algorithm) = key.dnskey_algorithm() else {
        return crate::dnssec::DnssecStatus::Bogus;
    };
    let owner_wire = if zone == "." {
        vec![0u8]
    } else {
        match crate::wire::encode_name(zone) {
            Ok(w) => w,
            Err(_) => return crate::dnssec::DnssecStatus::Bogus,
        }
    };
    let Some(digest) = crate::dnssec::compute_ds_digest(&owner_wire, &key.rdata, 2) else {
        return crate::dnssec::DnssecStatus::Bogus;
    };
    let mut anchor = crate::dnssec::DnssecTrustAnchor::empty();
    anchor.add_anchor(zone, key_tag, algorithm, 2, &digest);
    let mut msg = msg.clone();
    msg.additionals.push(key.clone());
    crate::dnssec::DnssecValidator::new(anchor).validate_message(&msg)
}

/// RFC 5452 §2.2: an accepted response's question section must match the
/// question actually sent — compared case-insensitively on the name since
/// DNS names are case-insensitive and some resolvers normalize case.
/// Compares the *raw* type/class wire values rather than the parsed
/// `Option<DnsType>`/`Option<DnsClass>`: two different unrecognized types
/// both parse to `None`, which must not compare equal to each other.
fn questions_match(a: &DnsQuestion, b: &DnsQuestion) -> bool {
    // Compare normalized names, not raw strings: the root zone is "." on
    // the construction side (`DnsQuestion::in_class(".", ...)`, never
    // itself wire-round-tripped) but decodes to "" once a response's own
    // question section is parsed back off the wire — both denote the same
    // name and must compare equal.
    a.raw_qtype == b.raw_qtype
        && a.raw_qclass == b.raw_qclass
        && normalize_name(&a.name) == normalize_name(&b.name)
}

struct ResolverInner {
    reactor: ReactorHandle,
    udp_token: Option<Token>,
    servers: Vec<SocketAddr>,
    pending: HashMap<u16, PendingQuery>,
    ids: DnsQueryIdGenerator,
    cache: Arc<DnsCache>,
    cookies: DnsCookie,
    timeout: Duration,
    use_edns: bool,
    use_cookies: bool,
    use_bailiwick: bool,
    tcp_fallback: bool,
    tcp_pool: TcpDnsConnectionPool,
    #[cfg(feature = "dnssec")]
    dnssec_enabled: bool,
    #[cfg(feature = "dnssec")]
    dnssec: Option<crate::dnssec::DnssecValidator>,
}

/// Reactor-affine stub resolver (Gumdrop `DNSResolver`). Cheap to clone —
/// every clone shares the same underlying state.
#[derive(Clone)]
pub struct DnsResolver {
    inner: Arc<Mutex<ResolverInner>>,
}

impl DnsResolver {
    /// Create an unopened resolver bound to a reactor handle.
    pub fn new(reactor: ReactorHandle) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ResolverInner {
                reactor,
                udp_token: None,
                servers: Vec::new(),
                pending: HashMap::new(),
                ids: DnsQueryIdGenerator::new(),
                cache: Arc::new(DnsCache::default()),
                cookies: DnsCookie::new(),
                timeout: DEFAULT_TIMEOUT,
                use_edns: true,
                use_cookies: true,
                use_bailiwick: true,
                tcp_fallback: true,
                tcp_pool: TcpDnsConnectionPool::new(),
                #[cfg(feature = "dnssec")]
                dnssec_enabled: false,
                #[cfg(feature = "dnssec")]
                dnssec: None,
            })),
        }
    }

    /// Per-worker resolver (opens UDP; does not configure upstreams).
    pub fn for_reactor(reactor: ReactorHandle) -> io::Result<Self> {
        let r = Self::new(reactor);
        r.open()?;
        Ok(r)
    }

    /// Attach to `Runtime::pick_worker()` and load system nameservers.
    pub fn for_runtime(rt: &Runtime) -> io::Result<Self> {
        let r = Self::new(rt.pick_worker().clone());
        r.open_with_system_resolvers()?;
        Ok(r)
    }

    /// Shared cache.
    pub fn set_cache(&self, cache: Arc<DnsCache>) {
        self.inner.lock().unwrap().cache = cache;
    }

    /// Shared cache handle.
    pub fn cache(&self) -> Arc<DnsCache> {
        Arc::clone(&self.inner.lock().unwrap().cache)
    }

    /// Query timeout.
    pub fn set_timeout(&self, timeout: Duration) {
        self.inner.lock().unwrap().timeout = timeout;
    }

    /// Add upstream (`addr` already resolved).
    pub fn add_server(&self, addr: SocketAddr) {
        self.inner.lock().unwrap().servers.push(addr);
    }

    /// Add upstream by IP string + port.
    pub fn add_server_str(&self, ip: &str, port: u16) -> io::Result<()> {
        let ip: IpAddr = ip
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        self.add_server(SocketAddr::new(ip, port));
        Ok(())
    }

    /// Use Google + Cloudflare public resolvers.
    pub fn use_public_resolvers(&self) {
        let _ = self.add_server_str("8.8.8.8", DEFAULT_DNS_PORT);
        let _ = self.add_server_str("1.1.1.1", DEFAULT_DNS_PORT);
    }

    /// Parse `/etc/resolv.conf` nameservers (Unix).
    pub fn use_system_resolvers(&self) -> io::Result<()> {
        let servers = crate::system::system_nameservers()?;
        let mut g = self.inner.lock().unwrap();
        for s in servers {
            g.servers.push(s);
        }
        Ok(())
    }

    /// Enable DNSSEC validation (sets EDNS DO; validates responses when keys/anchors allow).
    #[cfg(feature = "dnssec")]
    pub fn set_dnssec_enabled(&self, enabled: bool) {
        let mut g = self.inner.lock().unwrap();
        g.dnssec_enabled = enabled;
        if enabled && g.dnssec.is_none() {
            g.dnssec = Some(crate::dnssec::DnssecValidator::new(
                crate::dnssec::DnssecTrustAnchor::with_iana_root(),
            ));
        }
    }

    /// Replace DNSSEC trust anchors / validator.
    #[cfg(feature = "dnssec")]
    pub fn set_dnssec_validator(&self, validator: crate::dnssec::DnssecValidator) {
        let mut g = self.inner.lock().unwrap();
        g.dnssec_enabled = true;
        g.dnssec = Some(validator);
    }

    /// DNSSEC enabled?
    #[cfg(feature = "dnssec")]
    pub fn is_dnssec_enabled(&self) -> bool {
        self.inner.lock().unwrap().dnssec_enabled
    }

    /// Validate `msg` (an answer for `name`) against the full DNSSEC chain
    /// of trust, walking from the closest configured trust anchor down
    /// through each zone cut to `name`'s own zone (RFC 4035 §5.3.1) — DS
    /// and DNSKEY at each hop are actually resolved and cryptographically
    /// verified, via the same query machinery (and cache) as any other
    /// lookup. Unlike the per-message check `query()` runs automatically,
    /// this works for a name under a signed root even when only the root
    /// itself is a directly configured trust anchor.
    ///
    /// Requires a DNSSEC validator to already be configured (see
    /// [`Self::set_dnssec_enabled`]/[`Self::set_dnssec_validator`]) —
    /// calls back with `Indeterminate` immediately if none is set.
    #[cfg(feature = "dnssec")]
    pub fn validate_chain_of_trust(
        &self,
        name: &str,
        msg: DnsMessage,
        cb: Box<dyn FnOnce(DnsMessage, crate::dnssec::DnssecStatus) + Send>,
    ) {
        let trust = {
            let g = self.inner.lock().unwrap();
            g.dnssec.as_ref().map(|v| v.trust_anchors().clone())
        };
        let Some(trust) = trust else {
            cb(msg, crate::dnssec::DnssecStatus::Indeterminate);
            return;
        };
        let (walk, step) = crate::dnssec::DnssecChainWalk::start(trust, name);
        drive_chain_walk(self.clone(), walk, step, msg, ChainWalkFinish::ValidateMessage, cb);
    }

    /// Authenticated denial-of-existence (RFC 4035 §5.4): walks the same
    /// DNSSEC chain of trust as [`Self::validate_chain_of_trust`] toward
    /// `qname`'s own zone, then checks that `msg`'s authority-section
    /// NSEC/NSEC3 records are validly signed by that zone's key *and*
    /// actually prove `qname`/`qtype` doesn't exist (see
    /// [`crate::dnssec::verify_denial`]) — for validating an NXDOMAIN or
    /// NODATA response, which [`Self::validate_chain_of_trust`] can't (it
    /// only validates records that ARE present).
    #[cfg(feature = "dnssec")]
    pub fn validate_denial_of_existence(
        &self,
        qname: &str,
        qtype: DnsType,
        msg: DnsMessage,
        cb: Box<dyn FnOnce(DnsMessage, crate::dnssec::DnssecStatus) + Send>,
    ) {
        let trust = {
            let g = self.inner.lock().unwrap();
            g.dnssec.as_ref().map(|v| v.trust_anchors().clone())
        };
        let Some(trust) = trust else {
            cb(msg, crate::dnssec::DnssecStatus::Indeterminate);
            return;
        };
        let (walk, step) = crate::dnssec::DnssecChainWalk::start(trust, qname);
        let finish = ChainWalkFinish::ValidateDenial {
            qname: qname.to_string(),
            qtype,
        };
        drive_chain_walk(self.clone(), walk, step, msg, finish, cb);
    }

    /// Bind UDP socket on the reactor.
    pub fn open(&self) -> io::Result<()> {
        let mut g = self.inner.lock().unwrap();
        if g.udp_token.is_some() {
            return Ok(());
        }
        let std_sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
        std_sock.set_nonblocking(true)?;
        let socket = mio::net::UdpSocket::from_std(std_sock);
        let handler = Box::new(ResolverUdpHandler {
            inner: Arc::clone(&self.inner),
        });
        let token = g.reactor.register_udp(socket, handler)?;
        g.udp_token = Some(token);
        Ok(())
    }

    /// Open with system nameservers if none configured.
    pub fn open_with_system_resolvers(&self) -> io::Result<()> {
        {
            let g = self.inner.lock().unwrap();
            if g.servers.is_empty() {
                drop(g);
                self.use_system_resolvers()?;
            }
        }
        self.open()
    }

    /// Close UDP registration.
    pub fn close(&self) {
        let mut g = self.inner.lock().unwrap();
        if let Some(token) = g.udp_token.take() {
            g.reactor.deregister_udp(token);
        }
        g.pending.clear();
    }

    /// Query A records.
    pub fn query_a(&self, name: &str, cb: QueryCallback) {
        self.query(DnsQuestion::in_class(name, DnsType::A), cb);
    }

    /// Query AAAA.
    pub fn query_aaaa(&self, name: &str, cb: QueryCallback) {
        self.query(DnsQuestion::in_class(name, DnsType::Aaaa), cb);
    }

    /// Query MX.
    pub fn query_mx(&self, name: &str, cb: QueryCallback) {
        self.query(DnsQuestion::in_class(name, DnsType::Mx), cb);
    }

    /// Query TXT.
    pub fn query_txt(&self, name: &str, cb: QueryCallback) {
        self.query(DnsQuestion::in_class(name, DnsType::Txt), cb);
    }

    /// Query PTR.
    pub fn query_ptr(&self, name: &str, cb: QueryCallback) {
        self.query(DnsQuestion::in_class(name, DnsType::Ptr), cb);
    }

    /// Query SRV.
    pub fn query_srv(&self, name: &str, cb: QueryCallback) {
        self.query(DnsQuestion::in_class(name, DnsType::Srv), cb);
    }

    /// Generic query.
    pub fn query(&self, question: DnsQuestion, cb: QueryCallback) {
        self.query_with_cd(question, false, cb);
    }

    /// Generic query with an explicit RFC 4035 §3.2.2 CD flag: when `cd` is
    /// `true`, a Bogus DNSSEC validation result doesn't fail the query —
    /// used by the forwarder to relay a downstream client's own CD=1
    /// request through to upstream validation.
    pub fn query_with_cd(&self, question: DnsQuestion, cd: bool, cb: QueryCallback) {
        let _ = self.open();
        let mut g = self.inner.lock().unwrap();
        // Hosts file / literals
        if let Some(addrs) = hosts_answers(&question) {
            let mut msg = DnsMessage::query(0, question.clone(), true);
            msg.flags |= crate::wire::FLAG_QR | crate::wire::FLAG_RA;
            msg.answers = addrs;
            drop(g);
            cb(Ok(msg));
            return;
        }
        if g.cache.is_negatively_cached(&question.name) {
            let mut msg = DnsMessage::query(0, question, true);
            msg.flags |= crate::wire::FLAG_QR;
            msg.flags = (msg.flags & !0x0F) | RCODE_NXDOMAIN;
            drop(g);
            cb(Ok(msg));
            return;
        }
        if g.cache.is_nodata_cached(&question) {
            // RFC 2308 §2 NODATA: NOERROR with an empty answer set, not NXDOMAIN.
            let mut msg = DnsMessage::query(0, question, true);
            msg.flags |= crate::wire::FLAG_QR | crate::wire::FLAG_RA;
            drop(g);
            cb(Ok(msg));
            return;
        }
        if let Some(records) = g.cache.lookup(&question) {
            let mut msg = DnsMessage::query(0, question, true);
            msg.flags |= crate::wire::FLAG_QR | crate::wire::FLAG_RA;
            msg.answers = records;
            drop(g);
            cb(Ok(msg));
            return;
        }
        if g.servers.is_empty() {
            drop(g);
            cb(Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no DNS servers configured",
            )));
            return;
        }
        let id = alloc_id(&g);
        let server = g.servers[0];
        let timeout = g.timeout;
        let cancel = g.reactor.schedule_timer(
            timeout,
            Box::new({
                let inner = Arc::clone(&self.inner);
                move || retry_or_fail(&inner, id)
            }),
        );
        g.pending.insert(
            id,
            PendingQuery {
                callback: cb,
                question: question.clone(),
                server_idx: 0,
                cname_depth: 0,
                id,
                server,
                cd,
                cancel: Some(cancel),
            },
        );
        if let Err(e) = send_udp_query(&mut g, id, &question, server) {
            if let Some(p) = g.pending.remove(&id) {
                if let Some(c) = &p.cancel {
                    c.store(true, std::sync::atomic::Ordering::SeqCst);
                }
                drop(g);
                (p.callback)(Err(e));
            }
        }
    }

    /// Parallel A+AAAA; IPv6 preferred in result order. Port applied to each.
    pub fn resolve(&self, host: &str, port: u16, cb: ResolveCallback) {
        if let Some(ip) = parse_literal_ip(host) {
            cb(Ok(vec![SocketAddr::new(ip, port)]));
            return;
        }
        if let Some(list) = HostsFile::lookup(host) {
            cb(Ok(list
                .into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect()));
            return;
        }
        let pending = Arc::new(Mutex::new(ResolveMerge {
            v4: None,
            v6: None,
            done: false,
            cb: Some(cb),
            port,
        }));
        let p4 = Arc::clone(&pending);
        let p6 = Arc::clone(&pending);
        self.query_a(host, Box::new(move |r| {
            let addrs = r.ok().map(|m| {
                m.answers
                    .iter()
                    .filter_map(|rr| rr.as_a().map(IpAddr::V4))
                    .collect::<Vec<_>>()
            });
            finish_merge(&p4, true, addrs);
        }));
        self.query_aaaa(host, Box::new(move |r| {
            let addrs = r.ok().map(|m| {
                m.answers
                    .iter()
                    .filter_map(|rr| rr.as_aaaa().map(IpAddr::V6))
                    .collect::<Vec<_>>()
            });
            finish_merge(&p6, false, addrs);
        }));
    }
}

struct ResolveMerge {
    v4: Option<Vec<IpAddr>>,
    v6: Option<Vec<IpAddr>>,
    done: bool,
    cb: Option<ResolveCallback>,
    port: u16,
}

fn finish_merge(pending: &Arc<Mutex<ResolveMerge>>, is_v4: bool, addrs: Option<Vec<IpAddr>>) {
    let mut g = pending.lock().unwrap();
    if g.done {
        return;
    }
    if is_v4 {
        g.v4 = Some(addrs.unwrap_or_default());
    } else {
        g.v6 = Some(addrs.unwrap_or_default());
    }
    if g.v4.is_some() && g.v6.is_some() {
        g.done = true;
        let port = g.port;
        let mut out = Vec::new();
        for ip in g.v6.as_ref().unwrap() {
            out.push(SocketAddr::new(*ip, port));
        }
        for ip in g.v4.as_ref().unwrap() {
            out.push(SocketAddr::new(*ip, port));
        }
        if let Some(cb) = g.cb.take() {
            if out.is_empty() {
                cb(Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "no addresses",
                )));
            } else {
                cb(Ok(out));
            }
        }
    }
}

fn hosts_answers(question: &DnsQuestion) -> Option<Vec<DnsResourceRecord>> {
    let addrs = HostsFile::lookup(&question.name)?;
    let mut out = Vec::new();
    for ip in addrs {
        match (question.qtype, ip) {
            (Some(DnsType::A), IpAddr::V4(v4)) => out.push(DnsResourceRecord::a(&question.name, 0, v4)),
            (Some(DnsType::Aaaa), IpAddr::V6(v6)) => {
                out.push(DnsResourceRecord::aaaa(&question.name, 0, v6))
            }
            (Some(DnsType::A), IpAddr::V6(_)) | (Some(DnsType::Aaaa), IpAddr::V4(_)) => {}
            _ => {}
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn send_udp_query(
    g: &mut ResolverInner,
    id: u16,
    question: &DnsQuestion,
    server: SocketAddr,
) -> io::Result<()> {
    let token = g
        .udp_token
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "resolver not open"))?;
    let mut msg = DnsMessage::query(id, question.clone(), true);
    if g.use_edns {
        let opt_rdata = if g.use_cookies {
            g.cookies.encode_edns_option(&server.to_string())
        } else {
            Vec::new()
        };
        #[cfg(feature = "dnssec")]
        let do_bit = g.dnssec_enabled;
        #[cfg(not(feature = "dnssec"))]
        let do_bit = false;
        msg.additionals
            .push(DnsResourceRecord::opt(OPT_UDP_PAYLOAD, do_bit, &opt_rdata));
    }
    let bytes = msg
        .serialize()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    g.reactor.udp_send(token, server, bytes);
    Ok(())
}

struct ResolverUdpHandler {
    inner: Arc<Mutex<ResolverInner>>,
}

impl UdpDatagramHandler for ResolverUdpHandler {
    fn on_datagram(&mut self, peer: SocketAddr, data: &[u8]) {
        let Ok(msg) = DnsMessage::parse(data) else {
            return;
        };
        if !msg.is_response() {
            return;
        }
        let mut g = self.inner.lock().unwrap();

        // RFC 5452 §2.2: only accept a response from the exact server the
        // matching query was sent to, with a matching question — checked
        // *before* removing the pending entry, so a spoofed/mismatched
        // datagram doesn't discard a query that's still legitimately
        // outstanding and may yet get its real answer.
        match g.pending.get(&msg.id) {
            Some(candidate)
                if candidate.server == peer
                    && msg.questions.first().is_some_and(|q| questions_match(q, &candidate.question)) => {}
            _ => return,
        }
        let pending = g.pending.remove(&msg.id).expect("checked above");
        if let Some(c) = &pending.cancel {
            c.store(true, std::sync::atomic::Ordering::SeqCst);
        }

        // Only trust cookie data from a response that just passed the
        // source/question checks above — otherwise an off-path attacker
        // could poison our cookie cache for a server's address even
        // though they can no longer poison an answer.
        g.cookies
            .store_from_message(&peer.to_string(), &msg.additionals);

        // Truncation → TCP retry
        if msg.is_truncated() && g.tcp_fallback {
            let question = pending.question.clone();
            let id = pending.id;
            let server = peer;
            drop(g);
            let inner = Arc::clone(&self.inner);
            std::thread::Builder::new()
                .name("hopf-dns-tcp".into())
                .spawn(move || {
                    let result = {
                        let mut g = inner.lock().unwrap();
                        g.tcp_pool.query(server, &question, id)
                    };
                    match result {
                        Ok(msg) => complete_response(&inner, pending, msg, server),
                        Err(e) => (pending.callback)(Err(e)),
                    }
                })
                .ok();
            return;
        }

        drop(g);
        complete_response(&self.inner, pending, msg, peer);
    }
}

fn complete_response(
    inner: &Arc<Mutex<ResolverInner>>,
    mut pending: PendingQuery,
    mut msg: DnsMessage,
    server: SocketAddr,
) {
    let mut g = inner.lock().unwrap();
    if !pending.question.name.is_empty() && g.use_bailiwick {
        msg.answers = filter_answers_in_bailiwick(&pending.question.name, &msg.answers);
    }
    // CNAME chase
    if let Some(qtype @ (DnsType::A | DnsType::Aaaa)) = pending.question.qtype {
        let has_addr = msg.answers.iter().any(|rr| {
            (qtype == DnsType::A && rr.as_a().is_some()) || (qtype == DnsType::Aaaa && rr.as_aaaa().is_some())
        });
        if !has_addr {
            if let Some(cname) = msg
                .answers
                .iter()
                .find(|rr| rr.rtype == Some(DnsType::Cname))
                .and_then(|rr| rr.as_domain_name())
            {
                if pending.cname_depth < MAX_CNAME_DEPTH {
                    pending.cname_depth += 1;
                    pending.question = DnsQuestion::in_class(cname, qtype);
                    let id = alloc_id(&g);
                    pending.id = id;
                    let server = g.servers.get(pending.server_idx).copied().unwrap_or(server);
                    pending.server = server;
                    let timeout = g.timeout;
                    let inner2 = Arc::clone(inner);
                    let cancel = g.reactor.schedule_timer(timeout, Box::new(move || retry_or_fail(&inner2, id)));
                    pending.cancel = Some(cancel);
                    let q = pending.question.clone();
                    g.pending.insert(id, pending);
                    let _ = send_udp_query(&mut g, id, &q, server);
                    return;
                }
            }
        }
    }
    g.cache.put_response(&msg);
    #[cfg(feature = "dnssec")]
    {
        if g.dnssec_enabled {
            if let Some(ref v) = g.dnssec {
                let status = v.validate_message(&msg);
                if status == crate::dnssec::DnssecStatus::Bogus && !pending.cd {
                    // RFC 4035 §3.2.2: a CD=1 query asked not to have
                    // validation enforced — only fail the query on Bogus
                    // when the caller didn't request that.
                    drop(g);
                    (pending.callback)(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "DNSSEC validation failed (bogus)",
                    )));
                    return;
                }
                if status == crate::dnssec::DnssecStatus::Secure {
                    // RFC 4035 §3.2.3: assert that everything in this
                    // response was cryptographically validated.
                    msg.flags |= crate::wire::FLAG_AD;
                }
            }
        }
    }
    drop(g);
    (pending.callback)(Ok(msg));
}

/// Extension: dial TCP by hostname on the Runtime.
pub trait RuntimeDnsExt {
    /// Resolve `host` then call [`Runtime::connect`] with the first address.
    ///
    /// Schedules DNS asynchronously and returns `Ok(())` immediately. The TCP
    /// connect runs from the DNS callback. Prefer [`Arc<Runtime>`] so the
    /// callback can call `connect` without parking the caller.
    fn connect_by_name<F>(&self, host: &str, port: u16, factory: F) -> io::Result<()>
    where
        F: Fn() -> Box<dyn hopf_core::ProtocolHandler> + Send + Sync + 'static;
}

impl RuntimeDnsExt for Arc<Runtime> {
    fn connect_by_name<F>(&self, host: &str, port: u16, factory: F) -> io::Result<()>
    where
        F: Fn() -> Box<dyn hopf_core::ProtocolHandler> + Send + Sync + 'static,
    {
        use hopf_core::TcpConnectorConfig;
        if let Some(ip) = parse_literal_ip(host) {
            return self.connect(TcpConnectorConfig::new(SocketAddr::new(ip, port), factory));
        }
        let resolver = DnsResolver::for_runtime(self.as_ref())?;
        let rt = Arc::clone(self);
        resolver.resolve(
            host,
            port,
            Box::new(move |result| {
                let addrs = match result {
                    Ok(a) => a,
                    Err(_) => return,
                };
                if let Some(addr) = addrs.into_iter().next() {
                    let cfg = TcpConnectorConfig::new(addr, factory);
                    let _ = rt.connect(cfg);
                }
            }),
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{DnsClass, DnsType};

    #[test]
    fn questions_match_is_case_insensitive_on_name() {
        let a = DnsQuestion::new("Example.COM", DnsType::A, DnsClass::In);
        let b = DnsQuestion::new("example.com", DnsType::A, DnsClass::In);
        assert!(questions_match(&a, &b));
    }

    #[test]
    fn questions_match_rejects_different_name_type_or_class() {
        let base = DnsQuestion::new("example.com", DnsType::A, DnsClass::In);
        assert!(!questions_match(&base, &DnsQuestion::new("other.com", DnsType::A, DnsClass::In)));
        assert!(!questions_match(&base, &DnsQuestion::new("example.com", DnsType::Aaaa, DnsClass::In)));
    }

    #[test]
    fn alloc_id_avoids_colliding_with_a_pending_query() {
        let rt = hopf_core::Runtime::start(Default::default()).unwrap();
        let mut inner = ResolverInner {
            reactor: rt.pick_worker().clone(),
            udp_token: None,
            servers: Vec::new(),
            pending: HashMap::new(),
            ids: DnsQueryIdGenerator::new(),
            cache: Arc::new(DnsCache::default()),
            cookies: DnsCookie::new(),
            timeout: DEFAULT_TIMEOUT,
            use_edns: true,
            use_cookies: true,
            use_bailiwick: true,
            tcp_fallback: true,
            tcp_pool: TcpDnsConnectionPool::new(),
            #[cfg(feature = "dnssec")]
            dnssec_enabled: false,
            #[cfg(feature = "dnssec")]
            dnssec: None,
        };
        let taken = alloc_id(&inner);
        inner.pending.insert(
            taken,
            PendingQuery {
                callback: Box::new(|_| {}),
                question: DnsQuestion::in_class("example.com", DnsType::A),
                server_idx: 0,
                cname_depth: 0,
                id: taken,
                server: "127.0.0.1:53".parse().unwrap(),
                cd: false,
                cancel: None,
            },
        );
        for _ in 0..1000 {
            assert_ne!(alloc_id(&inner), taken, "must never hand out an id already in flight");
        }
        rt.shutdown();
    }

    /// Builds a real signed DNSKEY + RRSIG-over-A rrset (same construction
    /// as `dnssec::validator::tests::ed25519_rrsig_verifies`), plus a trust
    /// anchor that matches it, so `complete_response` genuinely validates
    /// the message rather than being told the answer.
    #[cfg(feature = "dnssec")]
    fn signed_secure_message(name: &str, id: u16) -> (DnsMessage, crate::dnssec::DnssecValidator) {
        use ring::signature::{Ed25519KeyPair, KeyPair};

        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let pub_bytes = pair.public_key().as_ref().to_vec();

        let dnskey = DnsResourceRecord::dnskey(name, 3600, 257, 15, &pub_bytes);
        let a = DnsResourceRecord::a(name, 3600, std::net::Ipv4Addr::new(192, 0, 2, 7));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let key_tag = dnskey.dnskey_key_tag().unwrap();

        let mut rrsig_rdata = Vec::new();
        rrsig_rdata.extend_from_slice(&DnsType::A.value().to_be_bytes());
        rrsig_rdata.push(15); // Ed25519
        rrsig_rdata.push(2); // labels
        rrsig_rdata.extend_from_slice(&3600u32.to_be_bytes());
        rrsig_rdata.extend_from_slice(&(now + 3600).to_be_bytes());
        rrsig_rdata.extend_from_slice(&(now - 60).to_be_bytes());
        rrsig_rdata.extend_from_slice(&key_tag.to_be_bytes());
        rrsig_rdata.extend_from_slice(&crate::wire::encode_name(name).unwrap());

        let mut rrsig = DnsResourceRecord::new(name, DnsType::Rrsig, DnsClass::In, 3600, rrsig_rdata.clone());
        let signed = {
            let mut out = rrsig_rdata.clone();
            // Mirrors build_canonical_rrset's owner+type+class+ttl+rdlen+rdata framing.
            let owner_wire = crate::wire::encode_name(name).unwrap();
            out.extend_from_slice(&owner_wire);
            out.extend_from_slice(&DnsType::A.value().to_be_bytes());
            out.extend_from_slice(&1u16.to_be_bytes());
            out.extend_from_slice(&3600u32.to_be_bytes());
            out.extend_from_slice(&(a.rdata.len() as u16).to_be_bytes());
            out.extend_from_slice(&a.rdata);
            out
        };
        let sig = pair.sign(&signed);
        rrsig.rdata.extend_from_slice(sig.as_ref());

        let owner_wire = crate::wire::encode_name(name).unwrap();
        let digest = crate::dnssec::compute_ds_digest(&owner_wire, &dnskey.rdata, 2).unwrap();
        let mut anchor = crate::dnssec::DnssecTrustAnchor::empty();
        anchor.add_anchor(name, key_tag, 15, 2, &digest);
        let validator = crate::dnssec::DnssecValidator::new(anchor);

        let msg = DnsMessage::new(
            id,
            crate::wire::FLAG_QR,
            vec![DnsQuestion::in_class(name, DnsType::A)],
            vec![a],
            vec![],
            vec![dnskey, rrsig],
        );
        (msg, validator)
    }

    #[cfg(feature = "dnssec")]
    fn dnssec_test_inner(rt: &hopf_core::Runtime, validator: crate::dnssec::DnssecValidator) -> ResolverInner {
        ResolverInner {
            reactor: rt.pick_worker().clone(),
            udp_token: None,
            servers: Vec::new(),
            pending: HashMap::new(),
            ids: DnsQueryIdGenerator::new(),
            cache: Arc::new(DnsCache::default()),
            cookies: DnsCookie::new(),
            timeout: DEFAULT_TIMEOUT,
            use_edns: true,
            use_cookies: true,
            use_bailiwick: false, // bailiwick would strip an out-of-zone A for this synthetic name
            tcp_fallback: true,
            tcp_pool: TcpDnsConnectionPool::new(),
            dnssec_enabled: true,
            dnssec: Some(validator),
        }
    }

    #[cfg(feature = "dnssec")]
    fn test_pending(cd: bool, cb: QueryCallback) -> PendingQuery {
        PendingQuery {
            callback: cb,
            question: DnsQuestion::in_class("secure.example", DnsType::A),
            server_idx: 0,
            cname_depth: 0,
            id: 1,
            server: "127.0.0.1:53".parse().unwrap(),
            cd,
            cancel: None,
        }
    }

    #[cfg(feature = "dnssec")]
    #[test]
    fn complete_response_sets_ad_when_dnssec_validation_is_secure() {
        let (msg, validator) = signed_secure_message("secure.example", 1);
        let rt = hopf_core::Runtime::start(Default::default()).unwrap();
        let inner = Arc::new(Mutex::new(dnssec_test_inner(&rt, validator)));

        let ad = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ad2 = Arc::clone(&ad);
        let pending = test_pending(
            false,
            Box::new(move |r| {
                ad2.store(r.expect("secure response must not fail").is_authenticated_data(), std::sync::atomic::Ordering::SeqCst);
            }),
        );

        complete_response(&inner, pending, msg, "127.0.0.1:53".parse().unwrap());
        assert!(ad.load(std::sync::atomic::Ordering::SeqCst), "AD must be set once validation reports Secure");
        rt.shutdown();
    }

    #[cfg(feature = "dnssec")]
    #[test]
    fn complete_response_honors_cd_and_lets_a_bogus_message_through_without_ad() {
        let (mut msg, validator) = signed_secure_message("secure.example", 1);
        // Tamper with the signed answer after signing: now Bogus, not Secure.
        msg.answers[0] = DnsResourceRecord::a("secure.example", 3600, std::net::Ipv4Addr::new(203, 0, 113, 9));

        let rt = hopf_core::Runtime::start(Default::default()).unwrap();
        let inner = Arc::new(Mutex::new(dnssec_test_inner(&rt, validator)));

        let result = Arc::new(Mutex::new(None));
        let result2 = Arc::clone(&result);
        let pending = test_pending(
            true, // CD=1: don't fail on Bogus
            Box::new(move |r| {
                *result2.lock().unwrap() = Some(r);
            }),
        );

        complete_response(&inner, pending, msg, "127.0.0.1:53".parse().unwrap());
        let r = result.lock().unwrap().take().expect("callback must fire");
        let delivered = r.expect("CD=1 must not fail the query even though validation is Bogus");
        assert!(!delivered.is_authenticated_data(), "a Bogus response must never carry AD");
        rt.shutdown();
    }
}
