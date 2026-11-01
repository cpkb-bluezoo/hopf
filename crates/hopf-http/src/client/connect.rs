// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Low-level HTTP dial helpers ([`connect_http`], timeouts).

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use hopf_core::{
    subsystem_log, Endpoint, LogLevel, LoopBuf, ProtocolHandler, Runtime, SecurityInfo,
    SharedTlsConnector, TcpConnectorConfig, UnixConnectorConfig,
};
use hopf_dns::{parse_literal_ip, DnsResolver};

use super::race::{connect_any, Dial, MakeHandler};
use crate::{
    ClientHandlerFactory, DiscardingClientWriter, H1Endpoint, H2Endpoint, H2cUpgradeClientEndpoint, HttpLimits,
    HttpVersion,
};

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
    /// When a name resolves to several addresses, how long an attempt may be
    /// under way before the next address is tried alongside it (RFC 8305
    /// section 5 recommends 250 ms). An attempt that fails starts the next
    /// at once.
    pub attempt_delay: Duration,
}

impl Default for HttpClientTimeouts {
    fn default() -> Self {
        Self {
            dns: Duration::from_secs(5),
            connect: Duration::from_secs(30),
            stage: Duration::from_secs(60),
            attempt_delay: super::race::DEFAULT_ATTEMPT_DELAY,
        }
    }
}

/// Shared "how to dial" settings threaded through every cleartext/TLS
/// `connect_*`/`dial_*` helper below: response/body size limits, per-phase
/// timeouts, and which DNS resolver to use (`None` = a fresh one attached
/// to the runtime's system nameservers). Not used by the h3/QUIC path
/// ([`connect_h3_by_name`]) — see [`H3DialSettings`], since QUIC connection
/// timing comes from its own `QuicClientConfig` rather than
/// [`HttpClientTimeouts`].
#[derive(Clone)]
pub struct DialSettings {
    /// Response/body size limits.
    pub limits: HttpLimits,
    /// Per-phase timeouts.
    pub timeouts: HttpClientTimeouts,
    /// DNS resolver to use (`None` = a fresh one attached to the runtime).
    pub resolver: Option<Arc<DnsResolver>>,
}

/// Shared "how to dial" settings for the h3/QUIC path
/// ([`connect_h3_by_name`]) — see [`DialSettings`] for the cleartext/TLS
/// counterpart. No timeouts field: QUIC connection timing comes from the
/// dial's own `QuicClientConfig`.
#[cfg(feature = "h3")]
#[derive(Clone)]
pub struct H3DialSettings {
    /// Response/body size limits.
    pub limits: HttpLimits,
    /// DNS resolver to use (`None` = a fresh one attached to the runtime).
    pub resolver: Option<Arc<DnsResolver>>,
}

/// Dial an HTTP/1.1 or HTTP/2 cleartext peer by hostname or socket-address.
pub fn connect_http(
    rt: &Arc<Runtime>,
    host_or_addr: &str,
    port: u16,
    factory: Arc<dyn ClientHandlerFactory>,
    http2: bool,
    settings: DialSettings,
) -> io::Result<()> {
    let limits = settings.limits;
    let on_failure = request_failed(rt, Arc::clone(&factory));
    let make_handler: Arc<dyn Fn() -> Box<dyn ProtocolHandler> + Send + Sync> =
        Arc::new(move || -> Box<dyn ProtocolHandler> {
            if http2 {
                Box::new(H2Endpoint::client(Arc::clone(&factory), limits, false))
            } else {
                Box::new(H1Endpoint::client(Arc::clone(&factory), limits, false))
            }
        });
    dial(rt, host_or_addr, port, &settings, make_handler, on_failure)
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
    settings: DialSettings,
) -> io::Result<()> {
    let limits = settings.limits;
    let on_failure = request_failed(rt, Arc::clone(&factory));
    let make_handler: Arc<dyn Fn() -> Box<dyn ProtocolHandler> + Send + Sync> =
        Arc::new(move || -> Box<dyn ProtocolHandler> {
            Box::new(H2cUpgradeClientEndpoint::new(Arc::clone(&factory), limits))
        });
    dial(rt, host_or_addr, port, &settings, make_handler, on_failure)
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
pub fn connect_https(
    rt: &Arc<Runtime>,
    host_or_addr: &str,
    port: u16,
    factory: Arc<dyn ClientHandlerFactory>,
    tls_connector: SharedTlsConnector,
    server_name: impl Into<String>,
    settings: DialSettings,
) -> io::Result<()> {
    let server_name = server_name.into();
    let limits = settings.limits;
    let on_failure = request_failed(rt, Arc::clone(&factory));
    let make_handler: Arc<dyn Fn() -> Box<dyn ProtocolHandler> + Send + Sync> =
        Arc::new(move || -> Box<dyn ProtocolHandler> {
            Box::new(TlsAlpnClientEndpoint::new(Arc::clone(&factory), limits))
        });
    dial_tls(rt, host_or_addr, port, &settings, tls_connector, server_name, make_handler, on_failure)
}

/// [`ProtocolHandler`] that waits for the TLS handshake to complete, then
/// picks [`H1Endpoint::client`] or [`H2Endpoint::client`] based on the
/// negotiated ALPN — mirrors `client/connection.rs`'s `HttpClientConnection`
/// (session API), adapted to the `ClientHandler` layer.
struct TlsAlpnClientEndpoint {
    factory: Arc<dyn ClientHandlerFactory>,
    limits: HttpLimits,
    inner: Option<Box<dyn ProtocolHandler>>,
}

impl TlsAlpnClientEndpoint {
    fn new(factory: Arc<dyn ClientHandlerFactory>, limits: HttpLimits) -> Self {
        Self {
            factory,
            limits,
            inner: None,
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
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, buf: &mut LoopBuf) {
        // Data that arrives before the TLS handshake has told us the ALPN
        // protocol is left in the ring, not buffered here.
        if let Some(inner) = self.inner.as_mut() {
            inner.receive(endpoint, buf);
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

/// What to do, once, when no connection could be made to a peer: the DNS
/// lookup failed, there was no address, or every address failed.
pub(crate) type OnFailure = Arc<dyn Fn(io::Error) + Send + Sync>;

/// The application hears of a dial that failed before any connection
/// existed, as a request that failed ([`ClientHandler::request_failed`]): a
/// handler is made for the purpose, since none was, and is given a writer
/// that discards what is written.
fn request_failed(rt: &Arc<Runtime>, factory: Arc<dyn ClientHandlerFactory>) -> OnFailure {
    let reactor = rt.pick_worker().clone();
    Arc::new(move |err: io::Error| {
        let reactor = reactor.clone();
        let conn = hopf_core::ConnHandle::from_execute(Arc::new(move |task| reactor.execute(task)));
        let mut handler = factory.create_handler();
        handler.request_failed(&mut DiscardingClientWriter::new(conn, HttpVersion::Http11), &err);
    })
}

/// Shared DNS-resolve-then-connect plumbing.
pub(crate) fn dial(
    rt: &Arc<Runtime>,
    host_or_addr: &str,
    port: u16,
    settings: &DialSettings,
    make_handler: Arc<dyn Fn() -> Box<dyn ProtocolHandler> + Send + Sync>,
    on_failure: OnFailure,
) -> io::Result<()> {
    dial_resolved(rt, host_or_addr, port, settings, None, make_handler, on_failure)
}

/// [`dial`], additionally configuring the connector for TLS (ALPN offered
/// via whatever `tls_connector` itself is set up for — `h2`/`http/1.1` for
/// [`connect_https`]'s use).
#[allow(clippy::too_many_arguments)]
fn dial_tls(
    rt: &Arc<Runtime>,
    host_or_addr: &str,
    port: u16,
    settings: &DialSettings,
    tls_connector: SharedTlsConnector,
    server_name: String,
    make_handler: Arc<dyn Fn() -> Box<dyn ProtocolHandler> + Send + Sync>,
    on_failure: OnFailure,
) -> io::Result<()> {
    dial_resolved(rt, host_or_addr, port, settings, Some((tls_connector, server_name)), make_handler, on_failure)
}

/// The connector for one attempt to `addr`.
fn tcp_connector(
    addr: SocketAddr,
    make: impl Fn() -> Box<dyn ProtocolHandler> + Send + Sync + 'static,
    connect_timeout: Option<Duration>,
    tls: &Option<(SharedTlsConnector, String)>,
) -> TcpConnectorConfig {
    let cfg = TcpConnectorConfig::new(addr, make).connect_timeout(connect_timeout);
    match tls {
        Some((connector, server_name)) => cfg.with_tls(Arc::clone(connector), server_name.clone()),
        None => cfg,
    }
}

/// Resolve `host_or_addr` and connect to the first of its addresses to
/// answer (see [`super::race`]). A literal address is dialed directly. If no
/// connection can be made, `on_failure` is told why.
fn dial_resolved(
    rt: &Arc<Runtime>,
    host_or_addr: &str,
    port: u16,
    settings: &DialSettings,
    tls: Option<(SharedTlsConnector, String)>,
    make_handler: Arc<dyn Fn() -> Box<dyn ProtocolHandler> + Send + Sync>,
    on_failure: OnFailure,
) -> io::Result<()> {
    let connect_timeout = Some(settings.timeouts.connect);
    let attempt_delay = settings.timeouts.attempt_delay;

    if let Some(addr) = resolve_literal(host_or_addr, port) {
        let mh = Arc::clone(&make_handler);
        return rt.connect(tcp_connector(addr, move || mh(), connect_timeout, &tls));
    }

    let res = match &settings.resolver {
        Some(r) => Arc::clone(r),
        None => Arc::new(DnsResolver::for_runtime(rt)?),
    };
    let rt2 = Arc::clone(rt);
    let host = host_or_addr.to_string();
    res.resolve(
        host_or_addr,
        port,
        Box::new(move |result| {
            let addrs = match result {
                Ok(a) if !a.is_empty() => a,
                Ok(_) => {
                    let err = io::Error::new(io::ErrorKind::NotFound, format!("no address for {host}"));
                    subsystem_log(LogLevel::Warn, "hopf-http", "http.dns.error", err.to_string());
                    return on_failure(err);
                }
                Err(e) => {
                    subsystem_log(LogLevel::Warn, "hopf-http", "http.dns.error", format!("DNS error: {e}"));
                    return on_failure(io::Error::new(e.kind(), format!("DNS error resolving {host}: {e}")));
                }
            };
            let rt3 = Arc::clone(&rt2);
            let dial: Dial = Arc::new(move |addr, attempt| {
                // The connector's factory runs once, for this attempt.
                let attempt = std::sync::Mutex::new(Some(attempt));
                let make: MakeHandler = Arc::clone(&make_handler);
                let gated = move || -> Box<dyn ProtocolHandler> {
                    let attempt = attempt.lock().unwrap().take().expect("an attempt is dialed once");
                    attempt.gate(Arc::clone(&make))
                };
                rt3.connect(tcp_connector(addr, gated, connect_timeout, &tls))
            });
            connect_any(
                &rt2,
                addrs,
                attempt_delay,
                dial,
                Box::new(move |e| {
                    subsystem_log(LogLevel::Warn, "hopf-http", "http.connect.error", format!("connect error: {e}"));
                    on_failure(e);
                }),
            );
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
    settings: H3DialSettings,
) -> io::Result<()> {
    let limits = settings.limits;
    let sni = server_name.unwrap_or_else(|| host_or_addr.to_string());
    if let Some(addr) = resolve_literal(host_or_addr, port) {
        connect_h3_with_keepalive(addr, client_config, sni, factory, limits)?;
        return Ok(());
    }
    let res = match settings.resolver {
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
                    subsystem_log(
                        LogLevel::Warn,
                        "hopf-http",
                        "http.h3.dns.error",
                        format!("DNS error resolving {host_owned} for h3: {e}"),
                    );
                    return;
                }
            };
            let Some(addr) = addrs.into_iter().next() else {
                subsystem_log(
                    LogLevel::Warn,
                    "hopf-http",
                    "http.h3.no_address",
                    format!("no address for {host_owned}"),
                );
                return;
            };
            if let Err(e) = connect_h3_with_keepalive(addr, client_config, sni, factory, limits) {
                subsystem_log(
                    LogLevel::Warn,
                    "hopf-http",
                    "http.h3.connect.error",
                    format!("h3 connect error: {e}"),
                );
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
    fallback: HttpFallback,
    settings: DialSettings,
) -> io::Result<()> {
    match fallback {
        HttpFallback::Tls(connector, server_name) => {
            connect_https(rt, host, port, factory, connector, server_name, settings)
        }
        HttpFallback::PlaintextH2c => connect_http2_upgrade(rt, host, port, factory, settings),
        HttpFallback::PlaintextH1 => connect_http(rt, host, port, factory, false, settings),
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

/// h3-tier discovery settings for [`connect_auto`]: the QUIC config to
/// dial with if an h3 tier is found (`None` skips h3 discovery entirely,
/// going straight to tier 3), and the Alt-Svc cache to feed for the next
/// connection attempt to this origin.
#[cfg(feature = "h3")]
#[derive(Clone)]
pub struct H3Discovery {
    /// QUIC client config to dial an h3 tier with, if one is found.
    pub quic_client_config: Option<Arc<QuicClientConfig>>,
    /// Cache fed with any `Alt-Svc` response header seen on the fallback
    /// tier, for the *next* connection attempt to this origin.
    pub alt_svc_cache: Arc<AltSvcCache>,
}

/// Automatic transport negotiation for an origin: a DNS HTTPS record (RFC
/// 9460) advertising `h3` support (tier 1), then a cached Alt-Svc
/// discovery from an earlier connection to the same origin (tier 2),
/// falling back to `fallback` (tier 3) when neither applies.
///
/// Skipped straight to tier 3 for a literal IP/socket-address `host` (no
/// hostname to query) or when `discovery.quic_client_config` is `None`
/// (nothing to dial an h3 tier with even if discovered).
///
/// The tier-1 HTTPS-record lookup batches the A/AAAA/HTTPS query (RFC
/// 10029 where the upstream resolver supports it — see
/// [`hopf_dns::DnsResolver::query_batch`]) so a successful h3 discovery
/// costs no more than today's plain address resolution already did.
///
/// The tier-3 fallback factory is wrapped to watch for an `Alt-Svc`
/// response header, feeding `discovery.alt_svc_cache` for the *next*
/// connection attempt to this origin — this call's own connection does
/// not opportunistically upgrade itself mid-flight.
#[cfg(feature = "h3")]
pub fn connect_auto(
    rt: &Arc<Runtime>,
    host: &str,
    port: u16,
    factory: Arc<dyn ClientHandlerFactory>,
    fallback: HttpFallback,
    settings: DialSettings,
    discovery: H3Discovery,
) -> io::Result<()> {
    if resolve_literal(host, port).is_some() {
        return dial_with_fallback(rt, host, port, factory, fallback, settings);
    }
    let Some(quic_config) = discovery.quic_client_config else {
        return dial_with_fallback(rt, host, port, factory, fallback, settings);
    };

    let res = match &settings.resolver {
        Some(r) => Arc::clone(r),
        None => Arc::new(DnsResolver::for_runtime(rt)?),
    };

    let rt2 = Arc::clone(rt);
    let host_owned = host.to_string();
    let host_for_tier3 = host_owned.clone();
    let alt_svc_cache = discovery.alt_svc_cache;
    let limits = settings.limits;

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
                    H3DialSettings { limits, resolver: settings.resolver.clone() },
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
            if let Err(e) =
                dial_with_fallback(&rt2, &host_for_tier3, port, observing_factory, fallback, settings.clone())
            {
                subsystem_log(LogLevel::Warn, "hopf-http", "http.connect.error", format!("connect error: {e}"));
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
/// non-alias-form HTTPS record (RFC 9460) advertising `h3` ALPN support -
/// the one with the lowest SvcPriority - returning the address to dial QUIC on directly if found. Prefers the
/// record's own `ipv4hint`/`ipv6hint` SvcParams (IPv6 first); falls back to
/// the plain A/AAAA answers from the same batch when the HTTPS record
/// carries no hints of its own.
#[cfg(feature = "h3")]
pub(crate) fn pick_h3_target(records: &[DnsResourceRecord], origin_port: u16) -> Option<SocketAddr> {
    // The lowest SvcPriority first (RFC 9460 section 2.4.1), whatever order
    // the answer came in.
    let https = records
        .iter()
        .filter(|rr| {
            rr.rtype == Some(DnsType::Https)
                && !rr.is_svcb_alias_form()
                && rr.svcb_alpn_protocols().iter().any(|p| p == "h3")
        })
        .min_by_key(|rr| rr.svcb_priority().unwrap_or(u16::MAX))?;
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


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_addresses_are_recognised_with_the_port_given() {
        assert_eq!(resolve_literal("127.0.0.1", 8080), Some("127.0.0.1:8080".parse().unwrap()));
        assert_eq!(resolve_literal("::1", 443), Some("[::1]:443".parse().unwrap()));
        assert_eq!(resolve_literal("2001:db8::7", 80), Some("[2001:db8::7]:80".parse().unwrap()));
    }

    #[test]
    fn a_socket_address_brings_its_own_port() {
        assert_eq!(resolve_literal("10.0.0.1:81", 80), Some("10.0.0.1:81".parse().unwrap()));
        assert_eq!(resolve_literal("[::1]:8443", 443), Some("[::1]:8443".parse().unwrap()));
    }

    #[test]
    fn names_are_not_literals() {
        for host in ["localhost", "example.com", "", "256.1.1.1", "1.2.3", "host:80"] {
            assert_eq!(resolve_literal(host, 80), None, "{host:?}");
        }
    }

    #[test]
    fn default_timeouts_are_bounded() {
        let t = HttpClientTimeouts::default();
        assert!(t.dns < t.connect && t.connect < t.stage + t.stage);
        assert!(!t.dns.is_zero() && !t.connect.is_zero() && !t.stage.is_zero());
    }

    #[cfg(feature = "h3")]
    mod h3_target {
        use super::*;
        use hopf_dns::wire::{
            SVCB_PARAM_ALPN, SVCB_PARAM_IPV4HINT, SVCB_PARAM_IPV6HINT, SVCB_PARAM_PORT,
        };
        use std::net::{Ipv4Addr, Ipv6Addr};

        fn alpn(names: &[&str]) -> (u16, Vec<u8>) {
            let mut v = Vec::new();
            for n in names {
                v.push(n.len() as u8);
                v.extend_from_slice(n.as_bytes());
            }
            (SVCB_PARAM_ALPN, v)
        }

        fn https(priority: u16, params: &[(u16, Vec<u8>)]) -> DnsResourceRecord {
            DnsResourceRecord::https("example.test", 60, priority, ".", params).unwrap()
        }

        fn a(ip: [u8; 4]) -> DnsResourceRecord {
            DnsResourceRecord::a("example.test", 60, Ipv4Addr::from(ip))
        }

        fn aaaa(last: u16) -> DnsResourceRecord {
            DnsResourceRecord::aaaa("example.test", 60, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, last))
        }

        fn sock(s: &str) -> Option<SocketAddr> {
            Some(s.parse().unwrap())
        }

        #[test]
        fn no_https_record_means_no_h3_target() {
            assert_eq!(pick_h3_target(&[a([192, 0, 2, 1]), aaaa(1)], 443), None);
            assert_eq!(pick_h3_target(&[], 443), None);
        }

        #[test]
        fn an_https_record_without_h3_is_not_enough() {
            let r = https(1, &[alpn(&["h2", "http/1.1"])]);
            assert_eq!(pick_h3_target(&[r, a([192, 0, 2, 1])], 443), None);
        }

        #[test]
        fn an_alias_form_record_is_not_a_service() {
            let r = DnsResourceRecord::https("example.test", 60, 0, "svc.example.test", &[]).unwrap();
            assert_eq!(pick_h3_target(&[r, a([192, 0, 2, 1])], 443), None);
        }

        #[test]
        fn the_addresses_come_from_the_batch_when_the_record_has_no_hints() {
            let r = https(1, &[alpn(&["h3"])]);
            assert_eq!(pick_h3_target(&[r.clone(), a([192, 0, 2, 1])], 443), sock("192.0.2.1:443"));
            assert_eq!(
                pick_h3_target(&[r, a([192, 0, 2, 1]), aaaa(7)], 443),
                sock("[2001:db8::7]:443"),
                "IPv6 first"
            );
        }

        #[test]
        fn the_records_own_hints_and_port_win() {
            let r = https(
                1,
                &[
                    alpn(&["h3"]),
                    (SVCB_PARAM_PORT, 8443u16.to_be_bytes().to_vec()),
                    (SVCB_PARAM_IPV4HINT, vec![198, 51, 100, 9]),
                ],
            );
            assert_eq!(pick_h3_target(&[r.clone(), a([192, 0, 2, 1])], 443), sock("198.51.100.9:8443"));
            let mut v6 = vec![0x20, 0x01, 0x0d, 0xb8];
            v6.extend_from_slice(&[0; 11]);
            v6.push(5);
            let r6 = https(1, &[alpn(&["h3"]), (SVCB_PARAM_IPV6HINT, v6), (SVCB_PARAM_IPV4HINT, vec![198, 51, 100, 9])]);
            assert_eq!(pick_h3_target(&[r6], 443), sock("[2001:db8::5]:443"), "an IPv6 hint beats an IPv4 one");
        }

        #[test]
        fn the_best_service_priority_is_chosen_whatever_order_the_answer_is_in() {
            // RFC 9460 section 2.4.1: the lowest SvcPriority is tried first.
            let low = https(1, &[alpn(&["h3"]), (SVCB_PARAM_IPV4HINT, vec![192, 0, 2, 1])]);
            let high = https(5, &[alpn(&["h3"]), (SVCB_PARAM_IPV4HINT, vec![192, 0, 2, 5])]);
            assert_eq!(pick_h3_target(&[high.clone(), low.clone()], 443), sock("192.0.2.1:443"));
            assert_eq!(pick_h3_target(&[low, high], 443), sock("192.0.2.1:443"));
        }

        #[test]
        fn a_lower_priority_record_without_h3_does_not_hide_one_with_it() {
            let h2 = https(1, &[alpn(&["h2"]), (SVCB_PARAM_IPV4HINT, vec![192, 0, 2, 1])]);
            let h3 = https(2, &[alpn(&["h3"]), (SVCB_PARAM_IPV4HINT, vec![192, 0, 2, 2])]);
            assert_eq!(pick_h3_target(&[h2, h3], 443), sock("192.0.2.2:443"));
        }
    }
}
