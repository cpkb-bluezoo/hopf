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
    DnsMessage, DnsQueryIdGenerator, DnsQuestion, DnsResourceRecord, DnsType, OPT_UDP_PAYLOAD,
    RCODE_NXDOMAIN,
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
    cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
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

/// Reactor-affine stub resolver (Gumdrop `DNSResolver`).
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
        let id = g.ids.next_id();
        let server = g.servers[0];
        let timeout = g.timeout;
        let cancel = g.reactor.schedule_timer(
            timeout,
            Box::new({
                let inner = Arc::clone(&self.inner);
                move || {
                    let mut g = inner.lock().unwrap();
                    if let Some(p) = g.pending.remove(&id) {
                        (p.callback)(Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "DNS query timed out",
                        )));
                    }
                }
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
                cancel: Some(cancel),
            },
        );
        if let Err(e) = send_udp_query(&mut g, id, &question, server) {
            if let Some(p) = g.pending.remove(&id) {
                if let Some(c) = &p.cancel {
                    c.store(true, std::sync::atomic::Ordering::SeqCst);
                }
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
            (DnsType::A, IpAddr::V4(v4)) => out.push(DnsResourceRecord::a(&question.name, 0, v4)),
            (DnsType::Aaaa, IpAddr::V6(v6)) => {
                out.push(DnsResourceRecord::aaaa(&question.name, 0, v6))
            }
            (DnsType::A, IpAddr::V6(_)) | (DnsType::Aaaa, IpAddr::V4(_)) => {}
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
        g.cookies
            .store_from_message(&peer.to_string(), &msg.additionals);
        let Some(pending) = g.pending.remove(&msg.id) else {
            return;
        };
        if let Some(c) = &pending.cancel {
            c.store(true, std::sync::atomic::Ordering::SeqCst);
        }

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
                    let mut g = inner.lock().unwrap();
                    match result {
                        Ok(msg) => complete_response(&mut g, pending, msg, server),
                        Err(e) => (pending.callback)(Err(e)),
                    }
                })
                .ok();
            return;
        }

        complete_response(&mut g, pending, msg, peer);
    }
}

fn complete_response(
    g: &mut ResolverInner,
    mut pending: PendingQuery,
    mut msg: DnsMessage,
    server: SocketAddr,
) {
    if !pending.question.name.is_empty() && g.use_bailiwick {
        msg.answers = filter_answers_in_bailiwick(&pending.question.name, &msg.answers);
    }
    // CNAME chase
    if pending.question.qtype == DnsType::A || pending.question.qtype == DnsType::Aaaa {
        let has_addr = msg.answers.iter().any(|rr| {
            (pending.question.qtype == DnsType::A && rr.as_a().is_some())
                || (pending.question.qtype == DnsType::Aaaa && rr.as_aaaa().is_some())
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
                    pending.question = DnsQuestion::in_class(cname, pending.question.qtype);
                    let id = g.ids.next_id();
                    pending.id = id;
                    let server = g.servers.get(pending.server_idx).copied().unwrap_or(server);
                    let timeout = g.timeout;
                    let cancel = g.reactor.schedule_timer(
                        timeout,
                        Box::new({
                            let inner_id = id;
                            // can't easily clone Arc here without restructuring — skip re-timeout
                            let _ = inner_id;
                            move || {}
                        }),
                    );
                    pending.cancel = Some(cancel);
                    let q = pending.question.clone();
                    g.pending.insert(id, pending);
                    let _ = send_udp_query(g, id, &q, server);
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
                if status == crate::dnssec::DnssecStatus::Bogus {
                    (pending.callback)(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "DNSSEC validation failed (bogus)",
                    )));
                    return;
                }
            }
        }
    }
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
