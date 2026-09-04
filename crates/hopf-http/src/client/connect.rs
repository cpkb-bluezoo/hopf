// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Low-level HTTP dial helpers ([`connect_http`], timeouts).

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use hopf_core::{
    Endpoint, ProtocolHandler, Runtime, SecurityInfo, SharedTlsConnector, TcpConnectorConfig,
    UnixConnectorConfig,
};
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

/// Dial an HTTP/1.1 or HTTP/2 cleartext peer over a UNIX domain socket
/// instead of TCP/IP — UNIX-domain counterpart of [`connect_http`].
pub fn connect_http_unix(
    rt: &Arc<Runtime>,
    path: impl Into<PathBuf>,
    factory: Arc<dyn ClientHandlerFactory>,
    limits: HttpLimits,
    http2: bool,
    timeouts: HttpClientTimeouts,
) -> io::Result<()> {
    let make_handler: Arc<dyn Fn() -> Box<dyn ProtocolHandler> + Send + Sync> =
        Arc::new(move || -> Box<dyn ProtocolHandler> {
            if http2 {
                Box::new(H2Endpoint::client(Arc::clone(&factory), limits, false))
            } else {
                Box::new(H1Endpoint::client(Arc::clone(&factory), limits, false))
            }
        });
    rt.connect_unix(
        UnixConnectorConfig::new(path, move || make_handler())
            .connect_timeout(Some(timeouts.connect)),
    )
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

/// Dial an HTTP/2 peer via HTTP/1.1 h2c Upgrade over a UNIX domain socket
/// instead of TCP/IP — UNIX-domain counterpart of [`connect_http2_upgrade`].
pub fn connect_http2_upgrade_unix(
    rt: &Arc<Runtime>,
    path: impl Into<PathBuf>,
    factory: Arc<dyn ClientHandlerFactory>,
    limits: HttpLimits,
    timeouts: HttpClientTimeouts,
) -> io::Result<()> {
    let make_handler: Arc<dyn Fn() -> Box<dyn ProtocolHandler> + Send + Sync> =
        Arc::new(move || -> Box<dyn ProtocolHandler> {
            Box::new(H2cUpgradeClientEndpoint::new(Arc::clone(&factory), limits))
        });
    rt.connect_unix(
        UnixConnectorConfig::new(path, move || make_handler())
            .connect_timeout(Some(timeouts.connect)),
    )
}

/// Dial a peer over TLS, negotiating `h2`/`http/1.1` via ALPN — the
/// `ClientHandler`-layer counterpart of [`crate::HttpClient`]'s own
/// TLS-ALPN dial (`client/facade.rs`'s `start_tls`), for callers (like a
/// CONNECT-UDP/CONNECT-IP client) that need the low-level
/// [`ClientHandler`](crate::ClientHandler) API's protocol-upgrade support
/// rather than the request/response session API.
///
/// Unlike [`connect_http`], which is cleartext-only with a caller-fixed
/// h1-vs-h2 choice, this negotiates the version from what the peer's TLS
/// handshake actually offers — the right fallback once an h3 attempt
/// (always TLS 1.3 via QUIC) has been ruled out, since a peer reachable
/// over HTTPS at all has no reason to also expect a cleartext h2c dial.
#[cfg(feature = "h3")]
pub fn connect_https(
    rt: &Arc<Runtime>,
    host_or_addr: &str,
    port: u16,
    factory: Arc<dyn ClientHandlerFactory>,
    limits: HttpLimits,
    tls_connector: SharedTlsConnector,
    server_name: impl Into<String>,
    timeouts: HttpClientTimeouts,
    resolver: Option<Arc<DnsResolver>>,
) -> io::Result<()> {
    let server_name = server_name.into();
    let make_handler: Arc<dyn Fn() -> Box<dyn ProtocolHandler> + Send + Sync> =
        Arc::new(move || -> Box<dyn ProtocolHandler> {
            Box::new(TlsAlpnClientEndpoint::new(Arc::clone(&factory), limits))
        });
    dial_tls(
        rt,
        host_or_addr,
        port,
        &timeouts,
        resolver,
        tls_connector,
        server_name,
        make_handler,
    )
}

/// [`ProtocolHandler`] that waits for the TLS handshake to complete, then
/// picks [`H1Endpoint::client`] or [`H2Endpoint::client`] based on the
/// negotiated ALPN — mirrors `client/connection.rs`'s `HttpClientConnection`
/// (session API), adapted to the `ClientHandler` layer.
#[cfg(feature = "h3")]
struct TlsAlpnClientEndpoint {
    factory: Arc<dyn ClientHandlerFactory>,
    limits: HttpLimits,
    inner: Option<Box<dyn ProtocolHandler>>,
    pending_receive: Vec<u8>,
}

#[cfg(feature = "h3")]
impl TlsAlpnClientEndpoint {
    fn new(factory: Arc<dyn ClientHandlerFactory>, limits: HttpLimits) -> Self {
        Self {
            factory,
            limits,
            inner: None,
            pending_receive: Vec::new(),
        }
    }

    fn install(&mut self, is_h2: bool) {
        let handler: Box<dyn ProtocolHandler> = if is_h2 {
            Box::new(H2Endpoint::client(Arc::clone(&self.factory), self.limits, true))
        } else {
            Box::new(H1Endpoint::client(Arc::clone(&self.factory), self.limits, true))
        };
        self.inner = Some(handler);
    }
}

#[cfg(feature = "h3")]
impl ProtocolHandler for TlsAlpnClientEndpoint {
    fn connected(&mut self, _endpoint: &mut dyn Endpoint) {
        // Nothing to do yet — this dial is always secure, so the request
        // only goes out once `security_established` reveals ALPN.
    }

    fn security_established(&mut self, endpoint: &mut dyn Endpoint, info: &SecurityInfo) {
        let is_h2 = info.alpn().map(|a| a == b"h2").unwrap_or(false);
        self.install(is_h2);
        let inner = self.inner.as_mut().expect("just installed");
        inner.connected(endpoint);
        inner.security_established(endpoint, info);
        if !self.pending_receive.is_empty() {
            let buf = std::mem::take(&mut self.pending_receive);
            let mut slice: &[u8] = &buf;
            inner.receive(endpoint, &mut slice);
        }
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        if let Some(inner) = self.inner.as_mut() {
            inner.receive(endpoint, data);
        } else {
            // Arrived before the TLS handshake finished informing us of
            // ALPN — buffer it (matches the same-shaped race
            // `HttpClientConnection::receive` already has to handle).
            self.pending_receive.extend_from_slice(data);
            *data = &[];
        }
    }

    fn disconnected(&mut self, endpoint: &mut dyn Endpoint) {
        if let Some(inner) = self.inner.as_mut() {
            inner.disconnected(endpoint);
        }
        // No app-visible handler exists yet if the connection never got
        // past the TLS handshake — the same limitation `connect_http`'s
        // single-path dial already has for a pre-handshake failure
        // (`H1Endpoint`/`H2Endpoint::error` don't forward to a
        // `ClientHandler` either), not a new gap introduced here.
    }

    fn error(&mut self, endpoint: &mut dyn Endpoint, err: &std::io::Error) {
        if let Some(inner) = self.inner.as_mut() {
            inner.error(endpoint, err);
        }
    }
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

/// [`dial`], additionally configuring the connector for TLS (ALPN offered
/// via whatever `tls_connector` itself is set up for — `h2`/`http/1.1` for
/// [`connect_https`]'s use).
#[cfg(feature = "h3")]
fn dial_tls(
    rt: &Arc<Runtime>,
    host_or_addr: &str,
    port: u16,
    timeouts: &HttpClientTimeouts,
    resolver: Option<Arc<DnsResolver>>,
    tls_connector: SharedTlsConnector,
    server_name: String,
    make_handler: Arc<dyn Fn() -> Box<dyn ProtocolHandler> + Send + Sync>,
) -> io::Result<()> {
    let connect_timeout = Some(timeouts.connect);

    if let Some(addr) = resolve_literal(host_or_addr, port) {
        let mh = Arc::clone(&make_handler);
        return rt.connect(
            TcpConnectorConfig::new(addr, move || mh())
                .connect_timeout(connect_timeout)
                .with_tls(tls_connector, server_name),
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
                    .connect_timeout(connect_timeout)
                    .with_tls(tls_connector, server_name);
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

/// Fallback transport for [`connect_auto`] once an h3 attempt is off the
/// table (no [`QuicClientConfig`] supplied, nothing discovered, or a
/// literal address with no DNS to query).
#[cfg(feature = "h3")]
#[derive(Clone)]
pub enum HttpFallback {
    /// TLS, negotiating `h2`/`http/1.1` via ALPN (see [`connect_https`]) —
    /// the right choice for a secure origin once h3 is ruled out: a peer
    /// reachable over HTTPS at all has no reason to also expect a
    /// cleartext dial, so there's no cleartext tier to try underneath it.
    Tls(SharedTlsConnector, String),
    /// Cleartext, attempting HTTP/1.1 Upgrade to h2c (RFC 7540 §3.2, see
    /// [`connect_http2_upgrade`]) and completing as plain HTTP/1.1 if the
    /// peer doesn't accept it.
    PlaintextH2c,
    /// Cleartext HTTP/1.1 only — no h2c attempt.
    PlaintextH1,
}

#[cfg(feature = "h3")]
fn dial_with_fallback(
    rt: &Arc<Runtime>,
    host: &str,
    port: u16,
    factory: Arc<dyn ClientHandlerFactory>,
    limits: HttpLimits,
    fallback: HttpFallback,
    timeouts: HttpClientTimeouts,
    resolver: Option<Arc<DnsResolver>>,
) -> io::Result<()> {
    match fallback {
        HttpFallback::Tls(connector, server_name) => connect_https(
            rt, host, port, factory, limits, connector, server_name, timeouts, resolver,
        ),
        HttpFallback::PlaintextH2c => {
            connect_http2_upgrade(rt, host, port, factory, limits, timeouts, resolver)
        }
        HttpFallback::PlaintextH1 => {
            connect_http(rt, host, port, factory, limits, false, timeouts, resolver)
        }
    }
}

/// UNIX-domain counterpart of [`dial_with_fallback`] — used by
/// [`crate::capsule`]-layer callers (CONNECT-UDP/CONNECT-IP) dialing a
/// proxy over a local socket. There's no QUIC/h3 transport for a UNIX
/// domain socket, so this only ever dials `fallback` directly — no tier-1/
/// tier-2 h3 discovery to attempt first, unlike the TCP/IP path.
///
/// [`HttpFallback::Tls`] is not supported here yet (mTLS over a local
/// socket is a real but rare need) — returns an `Unsupported` error rather
/// than silently dialing plaintext.
#[cfg(feature = "h3")]
fn dial_with_fallback_unix(
    rt: &Arc<Runtime>,
    path: PathBuf,
    factory: Arc<dyn ClientHandlerFactory>,
    limits: HttpLimits,
    fallback: HttpFallback,
    timeouts: HttpClientTimeouts,
) -> io::Result<()> {
    match fallback {
        HttpFallback::Tls(_, _) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "HttpFallback::Tls is not yet supported for a UNIX domain socket dial",
        )),
        HttpFallback::PlaintextH2c => {
            connect_http2_upgrade_unix(rt, path, factory, limits, timeouts)
        }
        HttpFallback::PlaintextH1 => {
            connect_http_unix(rt, path, factory, limits, false, timeouts)
        }
    }
}

/// Automatic transport negotiation for an origin: a DNS HTTPS record (RFC
/// 9460) advertising `h3` support (tier 1), then a cached Alt-Svc
/// discovery from an earlier connection to the same origin (tier 2),
/// falling back to `fallback` (tier 3) when neither applies.
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
    fallback: HttpFallback,
    timeouts: HttpClientTimeouts,
    resolver: Option<Arc<DnsResolver>>,
    quic_client_config: Option<Arc<QuicClientConfig>>,
    alt_svc_cache: Arc<AltSvcCache>,
) -> io::Result<()> {
    if resolve_literal(host, port).is_some() {
        return dial_with_fallback(rt, host, port, factory, limits, fallback, timeouts, resolver);
    }
    let Some(quic_config) = quic_client_config else {
        return dial_with_fallback(rt, host, port, factory, limits, fallback, timeouts, resolver);
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
            if let Err(e) = dial_with_fallback(
                &rt2,
                &host_for_tier3,
                port,
                observing_factory,
                limits,
                fallback,
                timeouts.clone(),
                resolver.clone(),
            ) {
                eprintln!("hopf-http: connect error: {e}");
            }
        }),
    );
    Ok(())
}

/// UNIX-domain counterpart of [`connect_auto`] — dials `fallback` directly
/// over a local socket. QUIC/h3 has no UNIX-domain transport, so there's no
/// tier-1 (DNS HTTPS record) or tier-2 (Alt-Svc cache) discovery to attempt
/// first; unlike [`connect_auto`], this needs no `resolver`,
/// `quic_client_config`, or `alt_svc_cache` at all.
#[cfg(feature = "h3")]
pub fn connect_auto_unix(
    rt: &Arc<Runtime>,
    path: impl Into<PathBuf>,
    factory: Arc<dyn ClientHandlerFactory>,
    limits: HttpLimits,
    fallback: HttpFallback,
    timeouts: HttpClientTimeouts,
) -> io::Result<()> {
    dial_with_fallback_unix(rt, path.into(), factory, limits, fallback, timeouts)
}

/// Scans `records` (answers from a batched A/AAAA/HTTPS query) for a
/// non-alias-form HTTPS record (RFC 9460) advertising `h3` ALPN support,
/// returning the address to dial QUIC on directly if found. Prefers the
/// record's own `ipv4hint`/`ipv6hint` SvcParams (IPv6 first); falls back to
/// the plain A/AAAA answers from the same batch when the HTTPS record
/// carries no hints of its own.
#[cfg(feature = "h3")]
pub(crate) fn pick_h3_target(records: &[DnsResourceRecord], origin_port: u16) -> Option<SocketAddr> {
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

pub(crate) fn resolve_literal(host: &str, port: u16) -> Option<SocketAddr> {
    if let Ok(addr) = host.parse::<SocketAddr>() {
        return Some(addr);
    }
    parse_literal_ip(host).map(|ip| SocketAddr::new(ip, port))
}

