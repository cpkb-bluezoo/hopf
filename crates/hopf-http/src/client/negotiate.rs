// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Transport-negotiation wrapper types shared by [`super::facade::HttpClient`]'s
//! `connect()`: a fresh [`ForwardingHandler`] lets the same long-lived,
//! caller-supplied [`HttpConnectionHandler`] receive `on_connected`/
//! `on_disconnected` more than once (once per transport attempt) without
//! changing [`super::session_config::HttpClientSessionConfig`]'s existing
//! "handler taken once" ownership; [`AutoNegotiatingOps`] wraps a TCP
//! session's [`SessionRequestOps`] to observe `Alt-Svc` response headers
//! and trigger an h3 upgrade once the connection goes idle.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use hopf_core::{ConnHandle, SecurityInfo};
use hopf_dns::DnsResolver;
use hopf_quic::QuicClientConfig;

use crate::client::alt_svc::{parse_alt_svc_h3, AltSvcCache};
use crate::client::api::{
    HttpClientError, HttpClientSessionHandle, HttpConnectionHandler, HttpResponseHandler,
    SessionRequestOps,
};
use crate::headers::Headers;
use crate::limits::HttpLimits;

/// Wraps the caller's real, long-lived [`HttpConnectionHandler`] so a fresh
/// instance can be handed to each transport attempt
/// (`HttpClientSessionConfig`'s handler slot is taken exactly once per
/// attempt) while the real handler legitimately receives
/// `on_connected`/`on_disconnected`/`on_error` more than once over the
/// `HttpClient`'s lifetime — once per transport attempt, same as Gumdrop's
/// `HTTPClientHandler`.
pub(crate) struct ForwardingHandler {
    inner: Arc<Mutex<Box<dyn HttpConnectionHandler>>>,
    /// Present only for a tier-3 (plain TCP) attempt: wraps the session's
    /// ops in [`AutoNegotiatingOps`] before forwarding `on_connected`, so
    /// every request on this connection is watched for `Alt-Svc`. `None`
    /// for an h3 attempt — nothing left to discover once already on h3.
    wrap: Option<NegotiationWrap>,
}

/// What [`ForwardingHandler::on_connected`] needs to wrap a tier-3
/// session's ops.
#[derive(Clone)]
pub(crate) struct NegotiationWrap {
    pub state: Arc<Mutex<NegotiationState>>,
    /// Filled in by `on_connected` with this TCP connection's real
    /// [`ConnHandle`], so the idle-triggered upgrade (constructed earlier,
    /// before the connection even existed) can close it later.
    pub conn_handle: Arc<Mutex<Option<ConnHandle>>>,
}

impl ForwardingHandler {
    /// For an h3 attempt (tier 1, or the Alt-Svc-triggered upgrade) — no
    /// Alt-Svc observation, nothing left to discover.
    pub(crate) fn plain(inner: Arc<Mutex<Box<dyn HttpConnectionHandler>>>) -> Self {
        Self { inner, wrap: None }
    }

    /// For the tier-3 (plain TCP) attempt.
    pub(crate) fn observing(inner: Arc<Mutex<Box<dyn HttpConnectionHandler>>>, wrap: NegotiationWrap) -> Self {
        Self { inner, wrap: Some(wrap) }
    }
}

impl HttpConnectionHandler for ForwardingHandler {
    fn on_security_established(&mut self, info: &SecurityInfo) {
        self.inner.lock().unwrap().on_security_established(info);
    }

    fn on_connected(&mut self, session: &mut HttpClientSessionHandle) {
        let mut inner = self.inner.lock().unwrap();
        match &self.wrap {
            None => inner.on_connected(session),
            Some(wrap) => {
                // Stash the raw TCP connection's handle before anything
                // else can run — the idle-triggered upgrade needs it to
                // close this connection later (see
                // `NegotiationState::conn_handle`).
                *wrap.conn_handle.lock().unwrap() = session.conn_handle();
                let ops: Arc<Mutex<dyn SessionRequestOps + Send>> = Arc::new(Mutex::new(AutoNegotiatingOps {
                    inner: Arc::clone(&session.ops),
                    state: Arc::clone(&wrap.state),
                }));
                let mut wrapped = HttpClientSessionHandle::new(ops, session.version(), session.conn_handle());
                inner.on_connected(&mut wrapped);
            }
        }
    }

    fn on_disconnected(&mut self) {
        self.inner.lock().unwrap().on_disconnected();
    }

    fn on_error(&mut self, err: &io::Error) {
        self.inner.lock().unwrap().on_error(err);
    }
}

/// Shared between [`AutoNegotiatingOps`] and every request's
/// [`AltSvcObservingResponseHandler`] on one tier-3 connection: how many
/// requests are currently in flight, whether an `Alt-Svc` h3 entry has been
/// seen on *this* connection, and the callback to run once both "idle" and
/// "h3 seen" are true — the "upgrade after the current stream(s) finish,
/// not mid-flight" trigger.
pub(crate) struct NegotiationState {
    pub in_flight: usize,
    pub host: String,
    pub port: u16,
    pub alt_svc_cache: Arc<AltSvcCache>,
    pub h3_seen: bool,
    pub on_idle_upgrade: Option<Box<dyn FnOnce() + Send>>,
}

impl NegotiationState {
    fn request_done(&mut self) -> Option<Box<dyn FnOnce() + Send>> {
        self.in_flight = self.in_flight.saturating_sub(1);
        if self.in_flight == 0 && self.h3_seen {
            self.on_idle_upgrade.take()
        } else {
            None
        }
    }
}

pub(crate) struct AutoNegotiatingOps {
    inner: Arc<Mutex<dyn SessionRequestOps + Send>>,
    state: Arc<Mutex<NegotiationState>>,
}

impl SessionRequestOps for AutoNegotiatingOps {
    fn is_open(&self) -> bool {
        self.inner.lock().unwrap().is_open()
    }

    fn send_no_body(
        &mut self,
        method: &str,
        path: &str,
        headers: Headers,
        handler: Box<dyn HttpResponseHandler>,
    ) -> Result<(), HttpClientError> {
        let wrapped = Box::new(AltSvcObservingResponseHandler {
            inner: handler,
            state: Arc::clone(&self.state),
        });
        let result = self.inner.lock().unwrap().send_no_body(method, path, headers, wrapped);
        if result.is_ok() {
            self.state.lock().unwrap().in_flight += 1;
        }
        result
    }

    fn start_body(
        &mut self,
        method: &str,
        path: &str,
        headers: Headers,
        handler: Box<dyn HttpResponseHandler>,
    ) -> Result<(), HttpClientError> {
        let wrapped = Box::new(AltSvcObservingResponseHandler {
            inner: handler,
            state: Arc::clone(&self.state),
        });
        let result = self.inner.lock().unwrap().start_body(method, path, headers, wrapped);
        if result.is_ok() {
            self.state.lock().unwrap().in_flight += 1;
        }
        result
    }

    fn body_content(&mut self, data: &[u8]) -> Result<usize, HttpClientError> {
        self.inner.lock().unwrap().body_content(data)
    }

    fn end_body(&mut self) -> Result<(), HttpClientError> {
        self.inner.lock().unwrap().end_body()
    }

    fn cancel_request(&mut self) -> Result<(), HttpClientError> {
        let result = self.inner.lock().unwrap().cancel_request();
        let cb = self.state.lock().unwrap().request_done();
        if let Some(cb) = cb {
            cb();
        }
        result
    }

    fn on_body_writable(&mut self, cb: Box<dyn FnOnce() + Send>) {
        self.inner.lock().unwrap().on_body_writable(cb);
    }
}

struct AltSvcObservingResponseHandler {
    inner: Box<dyn HttpResponseHandler>,
    state: Arc<Mutex<NegotiationState>>,
}

impl HttpResponseHandler for AltSvcObservingResponseHandler {
    fn ok(&mut self, status: u16) {
        self.inner.ok(status);
    }

    fn error(&mut self, status: u16) {
        self.inner.error(status);
    }

    fn header(&mut self, name: &str, value: &str) {
        if name.eq_ignore_ascii_case("alt-svc") {
            if let Some(entry) = parse_alt_svc_h3(value) {
                let mut g = self.state.lock().unwrap();
                let (host, port) = (g.host.clone(), g.port);
                g.alt_svc_cache.put(&host, port, &entry);
                g.h3_seen = true;
            }
        }
        self.inner.header(name, value);
    }

    fn start_response_body(&mut self) {
        self.inner.start_response_body();
    }

    fn response_body_content(&mut self, data: &[u8]) {
        self.inner.response_body_content(data);
    }

    fn end_response_body(&mut self) {
        self.inner.end_response_body();
    }

    fn response_trailers(&mut self, headers: &Headers) {
        self.inner.response_trailers(headers);
    }

    fn close(&mut self) {
        self.inner.close();
        let cb = self.state.lock().unwrap().request_done();
        if let Some(cb) = cb {
            cb();
        }
    }

    fn failed(&mut self, err: io::Error) {
        self.inner.failed(err);
        let cb = self.state.lock().unwrap().request_done();
        if let Some(cb) = cb {
            cb();
        }
    }
}

/// Wraps the real handler for a *speculative* transport attempt — one that
/// might still fall through to another tier on failure (tier 1 DNS
/// HTTPS-record h3, tier 2 cached Alt-Svc h3): forwards
/// `on_security_established`/`on_connected`/`on_disconnected` normally,
/// but routes a failure to `on_fallback` (try the next tier) instead of
/// the real handler's `on_error` — only the *last* tier actually attempted
/// should ever report a failure to the caller.
pub(crate) struct SpeculativeHandler {
    inner: Arc<Mutex<Box<dyn HttpConnectionHandler>>>,
    on_fallback: Mutex<Option<Box<dyn FnOnce(io::Error) + Send>>>,
}

impl SpeculativeHandler {
    pub(crate) fn new(
        inner: Arc<Mutex<Box<dyn HttpConnectionHandler>>>,
        on_fallback: Box<dyn FnOnce(io::Error) + Send>,
    ) -> Self {
        Self {
            inner,
            on_fallback: Mutex::new(Some(on_fallback)),
        }
    }
}

impl HttpConnectionHandler for SpeculativeHandler {
    fn on_security_established(&mut self, info: &SecurityInfo) {
        self.inner.lock().unwrap().on_security_established(info);
    }

    fn on_connected(&mut self, session: &mut HttpClientSessionHandle) {
        self.inner.lock().unwrap().on_connected(session);
    }

    fn on_disconnected(&mut self) {
        self.inner.lock().unwrap().on_disconnected();
    }

    fn on_error(&mut self, err: &io::Error) {
        if let Some(cb) = self.on_fallback.lock().unwrap().take() {
            cb(io::Error::new(err.kind(), err.to_string()));
        }
    }
}

/// Resolve `dial_host`/`dial_port` (or use it directly if it's already a
/// literal address), then dial an h3 *session* there — `sni` is the TLS
/// server name (the origin host, even when `dial_host` is an Alt-Svc
/// alternate — RFC 7838's alternate must present a certificate valid for
/// the origin it's serving on behalf of), `authority_host`/`authority_port`
/// become the `:authority` pseudo-header or every request on the resulting
/// session.
///
/// Fire-and-forget: `handler`'s `on_error` (whatever it resolves to — see
/// [`ForwardingHandler`]/[`SpeculativeHandler`]) receives any resolution or
/// dial failure; there's no synchronous result to return once a real
/// hostname needs an async resolve.
#[allow(clippy::too_many_arguments)]
pub(crate) fn dial_h3_by_name(
    resolver: &Arc<DnsResolver>,
    dial_host: &str,
    dial_port: u16,
    sni: String,
    authority_host: String,
    authority_port: u16,
    quic_config: Arc<QuicClientConfig>,
    limits: HttpLimits,
    handler: Box<dyn HttpConnectionHandler>,
) {
    if let Some(addr) = super::connect::resolve_literal(dial_host, dial_port) {
        let _ = super::h3_session::connect_h3_session(
            addr, quic_config, sni, &authority_host, authority_port, limits, handler,
        );
        return;
    }
    let handler = Arc::new(Mutex::new(Some(handler)));
    let dial_host_owned = dial_host.to_string();
    resolver.resolve(
        dial_host,
        dial_port,
        Box::new(move |result| {
            let addr: Option<SocketAddr> = result.ok().and_then(|a| a.into_iter().next());
            let Some(addr) = addr else {
                if let Some(mut h) = handler.lock().unwrap().take() {
                    h.on_error(&io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("no address for {dial_host_owned}"),
                    ));
                }
                return;
            };
            let Some(h) = handler.lock().unwrap().take() else {
                return;
            };
            let _ = super::h3_session::connect_h3_session(
                addr, quic_config, sni, &authority_host, authority_port, limits, h,
            );
        }),
    );
}
