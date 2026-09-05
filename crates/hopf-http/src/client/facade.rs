// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Gumdrop-shaped [`HttpClient`] facade (connect + request factory after handshake).

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use hopf_core::{ProtocolHandler, Runtime, SharedTlsConnector, TcpConnectorConfig, UnixConnectorConfig};
use hopf_dns::{parse_literal_ip, DnsResolver};

use crate::headers::Headers;
use crate::HttpLimits;

use super::api::{HttpConnectionHandler, HttpResponseHandler};
use super::connection::HttpClientConnection;
use super::redirect::{FetchState, PlainFetchConnectionHandler, RedirectPolicy, RedirectTarget};
use super::session_config::HttpClientSessionConfig;
use super::HttpClientTimeouts;

/// Async HTTP client with Gumdrop-style request objects.
///
/// Transport (HTTP/1.1, HTTP/2 via ALPN or prior-knowledge, later HTTP/3) is
/// negotiated by [`HttpClientConnection`]; applications use
/// [`HttpClientSessionHandle`](crate::HttpClientSessionHandle) and
/// [`crate::HttpRequest`] only.
///
/// Build with [`HttpClient::new`], optionally [`Self::tls`], then [`HttpClient::connect`].
pub struct HttpClient {
    host: String,
    port: u16,
    addr: Option<SocketAddr>,
    unix_path: Option<PathBuf>,
    limits: HttpLimits,
    timeouts: HttpClientTimeouts,
    secure: bool,
    h2_prior_knowledge: bool,
    tls_connector: Option<SharedTlsConnector>,
    tls_server_name: Option<String>,
    resolver: Option<Arc<DnsResolver>>,
    /// See [`Self::follow_redirects`]. `None` (the default): [`Self::fetch`]
    /// delivers a 3xx response unchanged, following nothing.
    redirect_policy: Option<RedirectPolicy>,
    #[cfg(feature = "h3")]
    quic_client_config: Option<Arc<hopf_quic::QuicClientConfig>>,
    #[cfg(feature = "h3")]
    h3_disabled: bool,
    #[cfg(feature = "h3")]
    h3_prior_knowledge: bool,
    #[cfg(feature = "h3")]
    alt_svc_cache: Arc<super::alt_svc::AltSvcCache>,
}

impl HttpClient {
    /// Client that resolves `host` before connecting.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            addr: None,
            unix_path: None,
            limits: HttpLimits::default(),
            timeouts: HttpClientTimeouts::default(),
            secure: false,
            h2_prior_knowledge: false,
            tls_connector: None,
            tls_server_name: None,
            resolver: None,
            redirect_policy: None,
            #[cfg(feature = "h3")]
            quic_client_config: None,
            #[cfg(feature = "h3")]
            h3_disabled: false,
            #[cfg(feature = "h3")]
            h3_prior_knowledge: false,
            #[cfg(feature = "h3")]
            alt_svc_cache: Arc::new(super::alt_svc::AltSvcCache::new()),
        }
    }

    /// Client with a pre-resolved address (skips DNS).
    pub fn from_addr(addr: SocketAddr) -> Self {
        Self {
            host: addr.ip().to_string(),
            port: addr.port(),
            addr: Some(addr),
            unix_path: None,
            limits: HttpLimits::default(),
            timeouts: HttpClientTimeouts::default(),
            secure: false,
            h2_prior_knowledge: false,
            tls_connector: None,
            tls_server_name: None,
            resolver: None,
            redirect_policy: None,
            #[cfg(feature = "h3")]
            quic_client_config: None,
            #[cfg(feature = "h3")]
            h3_disabled: false,
            #[cfg(feature = "h3")]
            h3_prior_knowledge: false,
            #[cfg(feature = "h3")]
            alt_svc_cache: Arc::new(super::alt_svc::AltSvcCache::new()),
        }
    }

    /// Client that dials a UNIX domain socket instead of TCP/IP — skips DNS
    /// and h3/QUIC negotiation entirely (QUIC has no UNIX-domain transport,
    /// so [`Self::connect`] always uses cleartext or TLS-ALPN H1/H2 for a
    /// UNIX-domain client, regardless of any [`Self::quic_client_config`]).
    pub fn from_unix_path(path: impl Into<PathBuf>) -> Self {
        Self {
            host: String::new(),
            port: 0,
            addr: None,
            unix_path: Some(path.into()),
            limits: HttpLimits::default(),
            timeouts: HttpClientTimeouts::default(),
            secure: false,
            h2_prior_knowledge: false,
            tls_connector: None,
            tls_server_name: None,
            resolver: None,
            redirect_policy: None,
            #[cfg(feature = "h3")]
            quic_client_config: None,
            #[cfg(feature = "h3")]
            h3_disabled: false,
            #[cfg(feature = "h3")]
            h3_prior_knowledge: false,
            #[cfg(feature = "h3")]
            alt_svc_cache: Arc::new(super::alt_svc::AltSvcCache::new()),
        }
    }

    /// Override [`HttpLimits`].
    pub fn limits(mut self, limits: HttpLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Override dial timeouts.
    pub fn timeouts(mut self, t: HttpClientTimeouts) -> Self {
        self.timeouts = t;
        self
    }

    /// Cleartext HTTP/2 with prior knowledge (RFC 9113 §3.4); default is HTTP/1.1
    /// (with optional upgrade handled by the connection layer in a later tranche).
    pub fn h2_prior_knowledge(mut self, enabled: bool) -> Self {
        self.h2_prior_knowledge = enabled;
        self
    }

    /// TLS dial with ALPN (`h2`, `http/1.1`). Negotiated version is opaque to the app.
    pub fn tls(
        mut self,
        connector: SharedTlsConnector,
        server_name: impl Into<String>,
    ) -> Self {
        self.tls_connector = Some(connector);
        self.tls_server_name = Some(server_name.into());
        self.secure = true;
        self
    }

    /// Use a specific [`DnsResolver`] for hostname lookup.
    pub fn resolver(mut self, resolver: Arc<DnsResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// Supplies the QUIC client config used for HTTP/3 — `h3` is only ever
    /// attempted once this is set. There's no default/system-trust-root
    /// config built automatically (neither `hopf-quic` nor `hopf-tls` has
    /// one today — [`Self::tls`] already requires an explicit connector for
    /// the same reason), so this mirrors that existing precedent rather
    /// than being a new asymmetry.
    ///
    /// When set (and h3 isn't disabled — see [`Self::disable_h3`]),
    /// [`Self::connect`] negotiates the transport automatically: a DNS
    /// HTTPS record (RFC 9460) advertising `h3` (tier 1), then a cached
    /// `Alt-Svc` discovery from an earlier connection to this origin (tier
    /// 2), then today's TCP-first ALPN h2/h1.1 dial (tier 3) — which
    /// itself watches for a fresh `Alt-Svc` response header and upgrades
    /// to h3, once the connection goes idle, for later requests on the
    /// same session. Mirrors Gumdrop's `HTTPClient.discoverAndConnect`.
    /// h3 (tiers 1/2) is used regardless of [`Self::secure`]/[`Self::tls`]
    /// (it's always TLS 1.3 via QUIC either way) — but the tier-3 TCP
    /// fallback is not: call [`Self::tls`] too if that fallback should be
    /// secure as well, same as if h3 weren't in the picture at all.
    #[cfg(feature = "h3")]
    pub fn quic_client_config(mut self, config: Arc<hopf_quic::QuicClientConfig>) -> Self {
        self.quic_client_config = Some(config);
        self
    }

    /// Disables HTTP/3 entirely — skips DNS HTTPS-record discovery and the
    /// Alt-Svc h3 upgrade, capping at h2/h1.1 — even if
    /// [`Self::quic_client_config`] was set.
    #[cfg(feature = "h3")]
    pub fn disable_h3(mut self, disabled: bool) -> Self {
        self.h3_disabled = disabled;
        self
    }

    /// Skips h3 discovery and dials HTTP/3 directly, with no fallback —
    /// mirrors Gumdrop's `HTTPClient.setH3Enabled(true)`. Requires
    /// [`Self::quic_client_config`]; [`Self::connect`] reports a clear
    /// error via `on_error` otherwise.
    #[cfg(feature = "h3")]
    pub fn h3_prior_knowledge(mut self, enabled: bool) -> Self {
        self.h3_prior_knowledge = enabled;
        self
    }

    /// Shares an [`super::alt_svc::AltSvcCache`] across multiple
    /// `HttpClient` instances (e.g. a connection pool dialing the same
    /// origins repeatedly), instead of the fresh, instance-private one
    /// [`Self::new`] otherwise creates.
    #[cfg(feature = "h3")]
    pub fn alt_svc_cache(mut self, cache: Arc<super::alt_svc::AltSvcCache>) -> Self {
        self.alt_svc_cache = cache;
        self
    }

    /// Builds the dial config, plus the shared session config so the caller
    /// can still reach the stashed `handler` for `on_error` if `rt.connect`
    /// itself fails synchronously (before any `ProtocolHandler` exists to
    /// report the failure through).
    fn connector_for_addr(
        &self,
        addr: SocketAddr,
        handler: Box<dyn HttpConnectionHandler>,
    ) -> (TcpConnectorConfig, Arc<HttpClientSessionConfig>) {
        let config = Arc::new(HttpClientSessionConfig {
            host: self.host.clone(),
            port: self.port,
            limits: self.limits,
            secure: self.secure,
            handler: Mutex::new(Some(handler)),
            stage: self.timeouts.stage,
        });
        let limits = self.limits;
        let secure = self.secure;
        let h2_prior = self.h2_prior_knowledge;
        let connect_timeout = Some(self.timeouts.connect);
        let config_for_factory = Arc::clone(&config);

        let mut cfg = TcpConnectorConfig::new(addr, move || {
            Box::new(HttpClientConnection::new(
                Arc::clone(&config_for_factory),
                limits,
                secure,
                h2_prior,
            )) as Box<dyn ProtocolHandler>
        })
        .connect_timeout(connect_timeout);

        if let (Some(tls), Some(name)) = (&self.tls_connector, &self.tls_server_name) {
            cfg = cfg.with_tls(Arc::clone(tls), name.clone());
        }
        (cfg, config)
    }

    /// UNIX-domain counterpart of [`Self::connector_for_addr`].
    fn connector_for_unix_path(
        &self,
        path: PathBuf,
        handler: Box<dyn HttpConnectionHandler>,
    ) -> (UnixConnectorConfig, Arc<HttpClientSessionConfig>) {
        let config = Arc::new(HttpClientSessionConfig {
            host: self.host.clone(),
            port: self.port,
            limits: self.limits,
            secure: self.secure,
            handler: Mutex::new(Some(handler)),
            stage: self.timeouts.stage,
        });
        let limits = self.limits;
        let secure = self.secure;
        let h2_prior = self.h2_prior_knowledge;
        let connect_timeout = Some(self.timeouts.connect);
        let config_for_factory = Arc::clone(&config);

        let mut cfg = UnixConnectorConfig::new(path, move || {
            Box::new(HttpClientConnection::new(
                Arc::clone(&config_for_factory),
                limits,
                secure,
                h2_prior,
            )) as Box<dyn ProtocolHandler>
        })
        .connect_timeout(connect_timeout);

        if let (Some(tls), Some(name)) = (&self.tls_connector, &self.tls_server_name) {
            cfg = cfg.with_tls(Arc::clone(tls), name.clone());
        }
        (cfg, config)
    }

    /// DNS (if needed) then dial. Returns immediately.
    ///
    /// When h3 is enabled ([`Self::quic_client_config`] set, and not
    /// [`Self::disable_h3`]d) and `self.addr`/a literal host don't already
    /// pin the connection to a bare TCP dial, transport negotiation is
    /// automatic — h3 if discoverable, else h2 via ALPN, else h1.1 — see
    /// [`Self::negotiate_connect`]. [`Self::from_unix_path`] dials a UNIX
    /// domain socket instead — skips DNS and h3 negotiation entirely.
    pub fn connect(
        &self,
        rt: &Arc<Runtime>,
        handler: Box<dyn HttpConnectionHandler>,
    ) -> io::Result<()> {
        if let Some(path) = self.unix_path.clone() {
            let (cfg, config) = self.connector_for_unix_path(path, handler);
            return rt.connect_unix(cfg).inspect_err(|e| {
                if let Some(mut h) = config.handler.lock().unwrap().take() {
                    h.on_error(e);
                }
            });
        }
        if let Some(addr) = self.addr {
            let (cfg, config) = self.connector_for_addr(addr, handler);
            return rt.connect(cfg).inspect_err(|e| {
                if let Some(mut h) = config.handler.lock().unwrap().take() {
                    h.on_error(e);
                }
            });
        }
        if let Some(addr) = resolve_literal(&self.host, self.port) {
            let (cfg, config) = self.connector_for_addr(addr, handler);
            return rt.connect(cfg).inspect_err(|e| {
                if let Some(mut h) = config.handler.lock().unwrap().take() {
                    h.on_error(e);
                }
            });
        }

        #[cfg(feature = "h3")]
        if !self.h3_disabled {
            if let Some(quic_config) = self.quic_client_config.clone() {
                return self.negotiate_connect(rt, quic_config, handler);
            }
        }

        let client = self.clone_for_dial();
        let resolver = match &self.resolver {
            Some(r) => Arc::clone(r),
            None => {
                let r = Arc::new(DnsResolver::for_runtime(rt)?);
                // Only apply `timeouts.dns` to a resolver we created
                // ourselves — a caller-supplied one (`.resolver(...)`) may
                // be shared elsewhere with its own timeout already set.
                r.set_timeout(self.timeouts.dns);
                r
            }
        };
        let host = self.host.clone();
        let host_for_error = host.clone();
        let port = self.port;
        let rt2 = Arc::clone(rt);
        resolver.resolve(
            &host,
            port,
            Box::new(move |result| {
                let mut handler = handler;
                let addrs = match result {
                    Ok(a) => a,
                    Err(e) => {
                        handler.on_error(&e);
                        return;
                    }
                };
                let Some(addr) = addrs.into_iter().next() else {
                    handler.on_error(&io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("no address for {host_for_error}"),
                    ));
                    return;
                };
                let (cfg, config) = client.connector_for_addr(addr, handler);
                if let Err(e) = rt2.connect(cfg) {
                    if let Some(mut h) = config.handler.lock().unwrap().take() {
                        h.on_error(&e);
                    }
                }
            }),
        );
        Ok(())
    }

    /// Tier 1 (DNS HTTPS-record discovery) and [`Self::h3_prior_knowledge`],
    /// falling through to [`Self::dial_tier2_or_tier3`] — see
    /// [`Self::connect`].
    #[cfg(feature = "h3")]
    fn negotiate_connect(
        &self,
        rt: &Arc<Runtime>,
        quic_config: Arc<hopf_quic::QuicClientConfig>,
        handler: Box<dyn HttpConnectionHandler>,
    ) -> io::Result<()> {
        use super::negotiate::{dial_h3_by_name, SpeculativeHandler};
        use hopf_dns::wire::{DnsResourceRecord, DnsType};

        let real_handler: Arc<Mutex<Box<dyn HttpConnectionHandler>>> = Arc::new(Mutex::new(handler));
        let resolver = match &self.resolver {
            Some(r) => Arc::clone(r),
            None => {
                let r = Arc::new(DnsResolver::for_runtime(rt)?);
                r.set_timeout(self.timeouts.dns);
                r
            }
        };
        let host = self.host.clone();
        let port = self.port;
        let limits = self.limits;

        if self.h3_prior_knowledge {
            let fh: Box<dyn HttpConnectionHandler> = Box::new(super::negotiate::ForwardingHandler::plain(Arc::clone(&real_handler)));
            dial_h3_by_name(&resolver, &host, port, host.clone(), host.clone(), port, quic_config, limits, fh);
            return Ok(());
        }

        let client = self.clone_for_dial();
        let rt2 = Arc::clone(rt);
        let resolver2 = Arc::clone(&resolver);
        let collected: Arc<Mutex<Vec<DnsResourceRecord>>> = Arc::new(Mutex::new(Vec::new()));
        let collected_for_result = Arc::clone(&collected);

        let host_for_query = host.clone();
        resolver.query_batch(
            &host_for_query,
            &[DnsType::Aaaa, DnsType::A, DnsType::Https],
            Box::new(move |_qtype, result| {
                if let Ok(records) = result {
                    collected_for_result.lock().unwrap().extend(records);
                }
            }),
            Box::new(move || {
                let records = collected.lock().unwrap().clone();
                if let Some(addr) = super::connect::pick_h3_target(&records, port) {
                    let real_handler2 = Arc::clone(&real_handler);
                    let quic2 = Arc::clone(&quic_config);
                    let host2 = host.clone();
                    let client2 = client.clone_for_dial();
                    let rt3 = Arc::clone(&rt2);
                    let resolver3 = Arc::clone(&resolver2);
                    let quic3 = Arc::clone(&quic_config);
                    let fallback: Box<dyn FnOnce(io::Error) + Send> = Box::new(move |_e| {
                        client2.dial_tier2_or_tier3(&rt3, &resolver3, quic3, real_handler2);
                    });
                    let sh: Box<dyn HttpConnectionHandler> =
                        Box::new(SpeculativeHandler::new(Arc::clone(&real_handler), fallback));
                    let _ = super::h3_session::connect_h3_session(addr, quic2, host2, &host, port, limits, sh);
                    return;
                }
                client.dial_tier2_or_tier3(&rt2, &resolver2, quic_config, real_handler);
            }),
        );
        Ok(())
    }

    /// Tier 2 (cached `Alt-Svc` h3 entry from an earlier connection to this
    /// origin), falling through to [`Self::dial_tier3`].
    #[cfg(feature = "h3")]
    fn dial_tier2_or_tier3(
        &self,
        rt: &Arc<Runtime>,
        resolver: &Arc<DnsResolver>,
        quic_config: Arc<hopf_quic::QuicClientConfig>,
        real_handler: Arc<Mutex<Box<dyn HttpConnectionHandler>>>,
    ) {
        use super::negotiate::{dial_h3_by_name, SpeculativeHandler};

        if let Some(entry) = self.alt_svc_cache.get(&self.host, self.port) {
            let alt_host = entry.h3_host.clone().unwrap_or_else(|| self.host.clone());
            let client2 = self.clone_for_dial();
            let rt2 = Arc::clone(rt);
            let resolver2 = Arc::clone(resolver);
            let real_handler2 = Arc::clone(&real_handler);
            let quic2 = Arc::clone(&quic_config);
            let fallback: Box<dyn FnOnce(io::Error) + Send> = Box::new(move |_e| {
                client2.dial_tier3(&rt2, &resolver2, quic2, real_handler2);
            });
            let sh: Box<dyn HttpConnectionHandler> =
                Box::new(SpeculativeHandler::new(Arc::clone(&real_handler), fallback));
            dial_h3_by_name(
                resolver,
                &alt_host,
                entry.h3_port,
                self.host.clone(),
                self.host.clone(),
                self.port,
                quic_config,
                self.limits,
                sh,
            );
            return;
        }
        self.dial_tier3(rt, resolver, quic_config, real_handler);
    }

    /// Tier 3: today's TCP-first ALPN h2/h1.1 dial, wrapped to observe
    /// `Alt-Svc` on every response and upgrade to h3 (tier-2-style, via the
    /// now-cached entry) once the connection goes idle with none pending —
    /// see [`super::negotiate::AutoNegotiatingOps`].
    #[cfg(feature = "h3")]
    fn dial_tier3(
        &self,
        rt: &Arc<Runtime>,
        resolver: &Arc<DnsResolver>,
        quic_config: Arc<hopf_quic::QuicClientConfig>,
        real_handler: Arc<Mutex<Box<dyn HttpConnectionHandler>>>,
    ) {
        use super::negotiate::{dial_h3_by_name, ForwardingHandler, NegotiationState, NegotiationWrap};

        let conn_handle: Arc<Mutex<Option<hopf_core::ConnHandle>>> = Arc::new(Mutex::new(None));
        let state = Arc::new(Mutex::new(NegotiationState {
            in_flight: 0,
            host: self.host.clone(),
            port: self.port,
            alt_svc_cache: Arc::clone(&self.alt_svc_cache),
            h3_seen: false,
            on_idle_upgrade: None,
        }));

        let upgrade_conn = Arc::clone(&conn_handle);
        let upgrade_real_handler = Arc::clone(&real_handler);
        let upgrade_resolver = Arc::clone(resolver);
        let upgrade_quic = Arc::clone(&quic_config);
        let upgrade_alt_svc = Arc::clone(&self.alt_svc_cache);
        let host_for_upgrade = self.host.clone();
        let port_for_upgrade = self.port;
        let limits = self.limits;
        let on_idle_upgrade: Box<dyn FnOnce() + Send> = Box::new(move || {
            // Nothing else calls `on_disconnected` today (see
            // `HttpConnectionHandler`'s doc comment) — this is the one
            // place that actually needs the Gumdrop-parity "disconnected,
            // then reconnected on a new transport" sequence, so it's
            // driven explicitly here rather than relying on the TCP
            // session noticing its own (requested) close.
            if let Some(ch) = upgrade_conn.lock().unwrap().take() {
                ch.close();
            }
            upgrade_real_handler.lock().unwrap().on_disconnected();
            let Some(entry) = upgrade_alt_svc.get(&host_for_upgrade, port_for_upgrade) else {
                return;
            };
            let alt_host = entry.h3_host.unwrap_or_else(|| host_for_upgrade.clone());
            let fh: Box<dyn HttpConnectionHandler> =
                Box::new(ForwardingHandler::plain(Arc::clone(&upgrade_real_handler)));
            dial_h3_by_name(
                &upgrade_resolver,
                &alt_host,
                entry.h3_port,
                host_for_upgrade.clone(),
                host_for_upgrade,
                port_for_upgrade,
                upgrade_quic,
                limits,
                fh,
            );
        });
        state.lock().unwrap().on_idle_upgrade = Some(on_idle_upgrade);

        let wrap = NegotiationWrap { state, conn_handle };
        let fh: Box<dyn HttpConnectionHandler> = Box::new(ForwardingHandler::observing(real_handler, wrap));

        if let Some(addr) = resolve_literal(&self.host, self.port) {
            let (cfg, config) = self.connector_for_addr(addr, fh);
            if let Err(e) = rt.connect(cfg) {
                if let Some(mut h) = config.handler.lock().unwrap().take() {
                    h.on_error(&e);
                }
            }
            return;
        }
        let client2 = self.clone_for_dial();
        let rt2 = Arc::clone(rt);
        let host_for_error = self.host.clone();
        resolver.resolve(
            &self.host,
            self.port,
            Box::new(move |result| {
                let mut fh = fh;
                let addrs = match result {
                    Ok(a) => a,
                    Err(e) => {
                        fh.on_error(&e);
                        return;
                    }
                };
                let Some(addr) = addrs.into_iter().next() else {
                    fh.on_error(&io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("no address for {host_for_error}"),
                    ));
                    return;
                };
                let (cfg, config) = client2.connector_for_addr(addr, fh);
                if let Err(e) = rt2.connect(cfg) {
                    if let Some(mut h) = config.handler.lock().unwrap().take() {
                        h.on_error(&e);
                    }
                }
            }),
        );
    }

    fn clone_for_dial(&self) -> Self {
        Self {
            host: self.host.clone(),
            port: self.port,
            addr: self.addr,
            unix_path: self.unix_path.clone(),
            limits: self.limits,
            timeouts: self.timeouts.clone(),
            secure: self.secure,
            h2_prior_knowledge: self.h2_prior_knowledge,
            tls_connector: self.tls_connector.clone(),
            tls_server_name: self.tls_server_name.clone(),
            resolver: self.resolver.clone(),
            redirect_policy: self.redirect_policy.clone(),
            #[cfg(feature = "h3")]
            quic_client_config: self.quic_client_config.clone(),
            #[cfg(feature = "h3")]
            h3_disabled: self.h3_disabled,
            #[cfg(feature = "h3")]
            h3_prior_knowledge: self.h3_prior_knowledge,
            #[cfg(feature = "h3")]
            alt_svc_cache: Arc::clone(&self.alt_svc_cache),
        }
    }

    /// Follow redirects (301/302/303/307/308) up to `policy`'s hop cap when
    /// using [`Self::fetch`] — see [`RedirectPolicy`]. Not set by default:
    /// without this, [`Self::fetch`] delivers a 3xx response to the
    /// caller's handler exactly like any other response, following
    /// nothing. Has no effect on [`Self::connect`]'s low-level
    /// session/request API.
    pub fn follow_redirects(mut self, policy: RedirectPolicy) -> Self {
        self.redirect_policy = Some(policy);
        self
    }

    /// Issue one request to `path` on this client's configured origin,
    /// following redirects per [`Self::follow_redirects`] if configured —
    /// otherwise behaves exactly like [`Self::connect`] plus issuing one
    /// request, and a 3xx response reaches `handler` unchanged.
    ///
    /// `body`, if given, is sent as one unit (not streamed) — buffered so
    /// it can be resent unmodified on a 307/308 redirect, which needs the
    /// original request replayed exactly. A large or genuinely streamed
    /// request body should use [`Self::connect`] directly instead.
    ///
    /// Redirect-driven dials (every hop after the first) don't attempt
    /// HTTP/3 negotiation even if this client has a QUIC config configured
    /// — they always dial via the same TCP/TLS path the first hop's
    /// scheme implies. This is a scope boundary, not a fallback: h3
    /// redirect-dialing may be added later.
    pub fn fetch(
        &self,
        rt: &Arc<Runtime>,
        method: &str,
        path: &str,
        headers: Headers,
        body: Option<Vec<u8>>,
        handler: Box<dyn HttpResponseHandler>,
    ) -> io::Result<()> {
        let Some(policy) = self.redirect_policy.clone() else {
            // No policy configured: behave exactly like plain `connect` +
            // one request — no interception, no wrapping, 3xx passes
            // through untouched.
            return self.connect(
                rt,
                Box::new(PlainFetchConnectionHandler {
                    method: method.to_string(),
                    path: path.to_string(),
                    headers,
                    body,
                    handler: Mutex::new(Some(handler)),
                }),
            );
        };

        let target = self.initial_redirect_target(path);
        let state = Arc::new(Mutex::new(FetchState::new(
            Arc::clone(rt),
            self.clone_for_dial(),
            policy,
            handler,
        )));
        FetchState::dial_hop(state, target, method.to_string(), headers, body);
        Ok(())
    }

    /// This client's configured TLS connector, if any — used by a redirect
    /// to a `https://` target to decide whether that hop can even dial
    /// (issue #349).
    pub(crate) fn tls_connector(&self) -> Option<&SharedTlsConnector> {
        self.tls_connector.as_ref()
    }

    /// The [`RedirectTarget`] this client's own configured origin
    /// represents for `path` — the starting point a redirect chain resolves
    /// subsequent `Location` values against.
    pub(crate) fn initial_redirect_target(&self, path: &str) -> RedirectTarget {
        let host = self
            .addr
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|| self.host.clone());
        let port = self.addr.map(|a| a.port()).unwrap_or(self.port);
        RedirectTarget {
            secure: self.secure,
            host,
            port,
            path: path.to_string(),
        }
    }

    /// Build a fresh client targeting `target` — used to dial a redirect
    /// hop, possibly to a different host/port/scheme than this client's own
    /// (issue #349). Carries over TLS connector/timeouts/limits/resolver;
    /// never a UNIX-domain path (a redirect target is always a network
    /// origin) and never HTTP/3 (see [`Self::fetch`]'s doc comment).
    pub(crate) fn for_redirect_target(&self, target: &RedirectTarget) -> Self {
        Self {
            host: target.host.clone(),
            port: target.port,
            addr: None,
            unix_path: None,
            limits: self.limits,
            timeouts: self.timeouts.clone(),
            secure: target.secure,
            h2_prior_knowledge: self.h2_prior_knowledge,
            tls_connector: self.tls_connector.clone(),
            tls_server_name: target.secure.then(|| target.host.clone()),
            resolver: self.resolver.clone(),
            redirect_policy: None,
            #[cfg(feature = "h3")]
            quic_client_config: None,
            #[cfg(feature = "h3")]
            h3_disabled: true,
            #[cfg(feature = "h3")]
            h3_prior_knowledge: false,
            #[cfg(feature = "h3")]
            alt_svc_cache: Arc::clone(&self.alt_svc_cache),
        }
    }
}

fn resolve_literal(host: &str, port: u16) -> Option<SocketAddr> {
    if let Ok(addr) = host.parse::<SocketAddr>() {
        return Some(addr);
    }
    parse_literal_ip(host).map(|ip| SocketAddr::new(ip, port))
}
