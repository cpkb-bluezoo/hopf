// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Low-level HTTP dial helpers ([`connect_http`], timeouts).

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hopf_core::{ProtocolHandler, Runtime, TcpConnectorConfig};
use hopf_dns::{parse_literal_ip, DnsResolver};

use crate::{ClientHandlerFactory, H1Endpoint, H2Endpoint, H2cUpgradeClientEndpoint, HttpLimits};

#[cfg(feature = "h3")]
use crate::client::alt_svc::AltSvcCache;
#[cfg(feature = "h3")]
use crate::h3::connect_h3;
#[cfg(feature = "h3")]
use crate::{ClientHandler, ClientWriter, Headers};
#[cfg(feature = "h3")]
use hopf_dns::wire::{DnsResourceRecord, DnsType};
#[cfg(feature = "h3")]
use hopf_quic::{QuicClientConfig, QuicDriverHandle};
#[cfg(feature = "h3")]
use std::net::IpAddr;
#[cfg(feature = "h3")]
use std::sync::Mutex;

/// Timeouts applied at each phase of an outbound HTTP connection.
#[derive(Clone, Debug)]
pub struct HttpClientTimeouts {
    /// DNS resolution budget (ignored for literal IPs).
    pub dns: Duration,
    /// TCP connect handshake budget.
    pub connect: Duration,
    /// Time budget waiting for each HTTP response stage (headers, etc.).
    pub stage: Duration,
}

impl Default for HttpClientTimeouts {
    fn default() -> Self {
        Self {
            dns: Duration::from_secs(5),
            connect: Duration::from_secs(30),
            stage: Duration::from_secs(60),
        }
    }
}

/// Dial an HTTP/1.1 or HTTP/2 cleartext peer by hostname or socket-address.
pub fn connect_http(
    rt: &Arc<Runtime>,
    host_or_addr: &str,
    port: u16,
    factory: Arc<dyn ClientHandlerFactory>,
    limits: HttpLimits,
    http2: bool,
    timeouts: HttpClientTimeouts,
    resolver: Option<Arc<DnsResolver>>,
) -> io::Result<()> {
    let make_handler: Arc<dyn Fn() -> Box<dyn ProtocolHandler> + Send + Sync> =
        Arc::new(move || -> Box<dyn ProtocolHandler> {
            if http2 {
                Box::new(H2Endpoint::client(Arc::clone(&factory), limits, false))
            } else {
                Box::new(H1Endpoint::client(Arc::clone(&factory), limits, false))
            }
        });
    dial(rt, host_or_addr, port, &timeouts, resolver, make_handler)
}

/// Dial an HTTP/2 peer via HTTP/1.1 h2c Upgrade (RFC 7540 §3.2).
pub fn connect_http2_upgrade(
    rt: &Arc<Runtime>,
    host_or_addr: &str,
    port: u16,
    factory: Arc<dyn ClientHandlerFactory>,
    limits: HttpLimits,
    timeouts: HttpClientTimeouts,
    resolver: Option<Arc<DnsResolver>>,
) -> io::Result<()> {
    let make_handler: Arc<dyn Fn() -> Box<dyn ProtocolHandler> + Send + Sync> =
        Arc::new(move || -> Box<dyn ProtocolHandler> {
            Box::new(H2cUpgradeClientEndpoint::new(Arc::clone(&factory), limits))
        });
    dial(rt, host_or_addr, port, &timeouts, resolver, make_handler)
}

/// Shared DNS-resolve-then-connect plumbing.
pub(crate) fn dial(
    rt: &Arc<Runtime>,
    host_or_addr: &str,
    port: u16,
    timeouts: &HttpClientTimeouts,
    resolver: Option<Arc<DnsResolver>>,
    make_handler: Arc<dyn Fn() -> Box<dyn ProtocolHandler> + Send + Sync>,
) -> io::Result<()> {
    let connect_timeout = Some(timeouts.connect);

    if let Some(addr) = resolve_literal(host_or_addr, port) {
        let mh = Arc::clone(&make_handler);
        return rt.connect(
            TcpConnectorConfig::new(addr, move || mh()).connect_timeout(connect_timeout),
        );
    }

    let res = match resolver {
        Some(r) => r,
        None => Arc::new(DnsResolver::for_runtime(rt)?),
    };
    let rt2 = Arc::clone(rt);
    res.resolve(
        host_or_addr,
        port,
        Box::new(move |result| {
            let addrs = match result {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("hopf-http: DNS error: {e}");
                    return;
                }
            };
            if let Some(addr) = addrs.into_iter().next() {
                let mh = Arc::clone(&make_handler);
                let cfg = TcpConnectorConfig::new(addr, move || mh())
                    .connect_timeout(connect_timeout);
                if let Err(e) = rt2.connect(cfg) {
                    eprintln!("hopf-http: connect error: {e}");
                }
            }
        }),
    );
    Ok(())
}

/// Wraps a [`ClientHandlerFactory`] so the [`QuicDriverHandle`] returned by
/// [`connect_h3`] — which owns the connection's background driver thread
/// and tears it down on `Drop` — stays alive for exactly as long as the
/// one request stream hopf's H3 client opens per connection today (see
/// [`crate::h3::H3ClientConnection::accept_bi`]), instead of being dropped
/// the instant the fire-and-forget dial functions in this module return.
/// Modeled on [`hopf_dns`]'s `DoqConnectionPool`, which solves the same
/// "someone must own the handle" problem by keeping it in a pool instead.
#[cfg(feature = "h3")]
struct H3KeepAliveFactory {
    inner: Arc<dyn ClientHandlerFactory>,
    keepalive: Arc<Mutex<Option<QuicDriverHandle>>>,
}

#[cfg(feature = "h3")]
impl ClientHandlerFactory for H3KeepAliveFactory {
    fn create_handler(&self) -> Box<dyn ClientHandler> {
        Box::new(H3KeepAliveHandler {
            inner: self.inner.create_handler(),
            keepalive: Arc::clone(&self.keepalive),
        })
    }
}

#[cfg(feature = "h3")]
struct H3KeepAliveHandler {
    inner: Box<dyn ClientHandler>,
    keepalive: Arc<Mutex<Option<QuicDriverHandle>>>,
}

#[cfg(feature = "h3")]
impl ClientHandler for H3KeepAliveHandler {
    fn start(&mut self, request: &mut dyn ClientWriter) {
        self.inner.start(request);
    }
    fn informational_response(&mut self, request: &mut dyn ClientWriter, headers: &Headers) {
        self.inner.informational_response(request, headers);
    }
    fn switching_protocols(&mut self, request: &mut dyn ClientWriter, headers: &Headers) {
        self.inner.switching_protocols(request, headers);
    }
    fn response_headers(&mut self, request: &mut dyn ClientWriter, headers: &Headers) {
        self.inner.response_headers(request, headers);
    }
    fn start_response_body(&mut self, request: &mut dyn ClientWriter) {
        self.inner.start_response_body(request);
    }
    fn response_body_content(&mut self, request: &mut dyn ClientWriter, data: &[u8]) {
        self.inner.response_body_content(request, data);
    }
    fn end_response_body(&mut self, request: &mut dyn ClientWriter) {
        self.inner.end_response_body(request);
    }
    fn response_trailers(&mut self, request: &mut dyn ClientWriter, headers: &Headers) {
        self.inner.response_trailers(request, headers);
    }
    fn response_complete(&mut self, request: &mut dyn ClientWriter) {
        self.inner.response_complete(request);
        self.keepalive.lock().unwrap().take();
    }
    fn request_failed(&mut self, request: &mut dyn ClientWriter, err: &std::io::Error) {
        self.inner.request_failed(request, err);
        self.keepalive.lock().unwrap().take();
    }
}

/// [`connect_h3`], but keeping the returned [`QuicDriverHandle`] alive
/// (via [`H3KeepAliveFactory`]) until the request completes or fails,
/// instead of it being dropped — and the connection torn down — the
/// instant this function returns.
#[cfg(feature = "h3")]
fn connect_h3_with_keepalive(
    addr: SocketAddr,
    client_config: Arc<QuicClientConfig>,
    sni: String,
    factory: Arc<dyn ClientHandlerFactory>,
    limits: HttpLimits,
) -> io::Result<()> {
    let keepalive: Arc<Mutex<Option<QuicDriverHandle>>> = Arc::new(Mutex::new(None));
    let wrapped: Arc<dyn ClientHandlerFactory> = Arc::new(H3KeepAliveFactory {
        inner: factory,
        keepalive: Arc::clone(&keepalive),
    });
    let handle = connect_h3(addr, client_config, sni, wrapped, limits)?;
    keepalive.lock().unwrap().replace(handle);
    Ok(())
}

/// Dial an HTTP/3 peer by hostname or socket-address.
///
/// Resolves through `resolver` (or a fresh one attached to `rt`'s system
/// nameservers, matching [`connect_http`]'s own default) — like every other
/// dial path in this module, not the OS resolver. DNS resolution is
/// asynchronous, so — also like [`connect_http`]/[`connect_http2_upgrade`]
/// — this returns as soon as the dial has been scheduled, not once it
/// completes; a resolution or connect failure is logged rather than
/// returned, since there's no synchronous point left to report it through.
#[cfg(feature = "h3")]
pub fn connect_h3_by_name(
    rt: &Arc<Runtime>,
    host_or_addr: &str,
    port: u16,
    client_config: Arc<QuicClientConfig>,
    server_name: Option<String>,
    factory: Arc<dyn ClientHandlerFactory>,
    limits: HttpLimits,
    resolver: Option<Arc<DnsResolver>>,
) -> io::Result<()> {
    let sni = server_name.unwrap_or_else(|| host_or_addr.to_string());
    if let Some(addr) = resolve_literal(host_or_addr, port) {
        connect_h3_with_keepalive(addr, client_config, sni, factory, limits)?;
        return Ok(());
    }
    let res = match resolver {
        Some(r) => r,
        None => Arc::new(DnsResolver::for_runtime(rt)?),
    };
    let host_owned = host_or_addr.to_string();
    res.resolve(
        host_or_addr,
        port,
        Box::new(move |result| {
            let addrs = match result {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("hopf-http: DNS error resolving {host_owned} for h3: {e}");
                    return;
                }
            };
            let Some(addr) = addrs.into_iter().next() else {
                eprintln!("hopf-http: no address for {host_owned}");
                return;
            };
            if let Err(e) = connect_h3_with_keepalive(addr, client_config, sni, factory, limits) {
                eprintln!("hopf-http: h3 connect error: {e}");
            }
        }),
    );
    Ok(())
}

/// Automatic transport negotiation for a secure origin: a DNS HTTPS record
/// (RFC 9460) advertising `h3` support (tier 1), then a cached Alt-Svc
/// discovery from an earlier connection to the same origin (tier 2),
/// falling back to today's TCP-first [`connect_http`] — HTTP/2 via ALPN,
/// else HTTP/1.1 — when neither applies (tier 3). Mirrors Gumdrop's
/// `HTTPClient.discoverAndConnect`.
///
/// Skipped straight to tier 3 for a literal IP/socket-address `host` (no
/// hostname to query) or when `quic_client_config` is `None` (nothing to
/// dial an h3 tier with even if discovered).
///
/// The tier-1 HTTPS-record lookup batches the A/AAAA/HTTPS query (RFC
/// 10029 where the upstream resolver supports it — see
/// [`hopf_dns::DnsResolver::query_batch`]) so a successful h3 discovery
/// costs no more than today's plain address resolution already did.
///
/// The tier-3 fallback factory is wrapped to watch for an `Alt-Svc`
/// response header, feeding `alt_svc_cache` for the *next* connection
/// attempt to this origin — this call's own connection does not
/// opportunistically upgrade itself mid-flight.
#[cfg(feature = "h3")]
#[allow(clippy::too_many_arguments)]
pub fn connect_auto(
    rt: &Arc<Runtime>,
    host: &str,
    port: u16,
    factory: Arc<dyn ClientHandlerFactory>,
    limits: HttpLimits,
    http2: bool,
    timeouts: HttpClientTimeouts,
    resolver: Option<Arc<DnsResolver>>,
    quic_client_config: Option<Arc<QuicClientConfig>>,
    alt_svc_cache: Arc<AltSvcCache>,
) -> io::Result<()> {
    if resolve_literal(host, port).is_some() {
        return connect_http(rt, host, port, factory, limits, http2, timeouts, resolver);
    }
    let Some(quic_config) = quic_client_config else {
        return connect_http(rt, host, port, factory, limits, http2, timeouts, resolver);
    };

    let res = match &resolver {
        Some(r) => Arc::clone(r),
        None => Arc::new(DnsResolver::for_runtime(rt)?),
    };

    let rt2 = Arc::clone(rt);
    let host_owned = host.to_string();
    let host_for_tier3 = host_owned.clone();

    let collected: Arc<Mutex<Vec<DnsResourceRecord>>> = Arc::new(Mutex::new(Vec::new()));
    let collected_for_result = Arc::clone(&collected);

    res.query_batch(
        host,
        &[DnsType::Aaaa, DnsType::A, DnsType::Https],
        Box::new(move |_qtype, result| {
            if let Ok(records) = result {
                collected_for_result.lock().unwrap().extend(records);
            }
        }),
        Box::new(move || {
            let records = collected.lock().unwrap().clone();
            if let Some(addr) = pick_h3_target(&records, port) {
                if connect_h3_with_keepalive(
                    addr,
                    Arc::clone(&quic_config),
                    host_owned.clone(),
                    Arc::clone(&factory),
                    limits,
                )
                .is_ok()
                {
                    return;
                }
                // Synchronous h3 dial setup failed (e.g. transport start
                // error) -- fall through to the remaining tiers below.
            }
            if let Some(entry) = alt_svc_cache.get(&host_owned, port) {
                let alt_host = entry.h3_host.unwrap_or_else(|| host_owned.clone());
                if connect_h3_by_name(
                    &rt2,
                    &alt_host,
                    entry.h3_port,
                    Arc::clone(&quic_config),
                    Some(host_owned.clone()),
                    Arc::clone(&factory),
                    limits,
                    resolver.clone(),
                )
                .is_ok()
                {
                    return;
                }
            }
            let observing_factory: Arc<dyn ClientHandlerFactory> =
                Arc::new(crate::client::alt_svc::AltSvcObservingFactory::new(
                    Arc::clone(&factory),
                    Arc::clone(&alt_svc_cache),
                    host_owned.clone(),
                    port,
                ));
            if let Err(e) = connect_http(
                &rt2,
                &host_for_tier3,
                port,
                observing_factory,
                limits,
                http2,
                timeouts.clone(),
                resolver.clone(),
            ) {
                eprintln!("hopf-http: connect error: {e}");
            }
        }),
    );
    Ok(())
}

/// Scans `records` (answers from a batched A/AAAA/HTTPS query) for a
/// non-alias-form HTTPS record (RFC 9460) advertising `h3` ALPN support,
/// returning the address to dial QUIC on directly if found. Prefers the
/// record's own `ipv4hint`/`ipv6hint` SvcParams (IPv6 first); falls back to
/// the plain A/AAAA answers from the same batch when the HTTPS record
/// carries no hints of its own.
#[cfg(feature = "h3")]
fn pick_h3_target(records: &[DnsResourceRecord], origin_port: u16) -> Option<SocketAddr> {
    let https = records.iter().find(|rr| {
        rr.rtype == Some(DnsType::Https)
            && !rr.is_svcb_alias_form()
            && rr.svcb_alpn_protocols().iter().any(|p| p == "h3")
    })?;
    let port = https.svcb_port().unwrap_or(origin_port);

    if let Some(ip) = https.svcb_ipv6hint().into_iter().next() {
        return Some(SocketAddr::new(IpAddr::V6(ip), port));
    }
    if let Some(ip) = https.svcb_ipv4hint().into_iter().next() {
        return Some(SocketAddr::new(IpAddr::V4(ip), port));
    }
    for rr in records {
        if let Some(ip) = rr.as_aaaa() {
            return Some(SocketAddr::new(IpAddr::V6(ip), port));
        }
    }
    for rr in records {
        if let Some(ip) = rr.as_a() {
            return Some(SocketAddr::new(IpAddr::V4(ip), port));
        }
    }
    None
}

fn resolve_literal(host: &str, port: u16) -> Option<SocketAddr> {
    if let Ok(addr) = host.parse::<SocketAddr>() {
        return Some(addr);
    }
    parse_literal_ip(host).map(|ip| SocketAddr::new(ip, port))
}

