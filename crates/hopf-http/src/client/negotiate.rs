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

use crate::client::alt_svc::AltSvcCache;
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

impl AutoNegotiatingOps {
    /// Count a request as in flight, then send it. The count goes up
    /// *before* the send: the response can complete (on the reactor thread)
    /// before the send call returns, and its completion must find the
    /// request already counted or the count would never get back to zero.
    /// A send that is refused is taken back out.
    fn sent_one(
        &mut self,
        send: impl FnOnce(&mut (dyn SessionRequestOps + Send)) -> Result<(), HttpClientError>,
    ) -> Result<(), HttpClientError> {
        self.state.lock().unwrap().in_flight += 1;
        let result = send(&mut *self.inner.lock().unwrap());
        if result.is_err() {
            let mut st = self.state.lock().unwrap();
            st.in_flight = st.in_flight.saturating_sub(1);
        }
        result
    }
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
        self.sent_one(|inner| inner.send_no_body(method, path, headers, wrapped))
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
        self.sent_one(|inner| inner.start_body(method, path, headers, wrapped))
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
            let mut g = self.state.lock().unwrap();
            let (host, port) = (g.host.clone(), g.port);
            if g.alt_svc_cache.observe(&host, port, value).is_some() {
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
type FallbackFn = Box<dyn FnOnce(io::Error) + Send>;

pub(crate) struct SpeculativeHandler {
    inner: Arc<Mutex<Box<dyn HttpConnectionHandler>>>,
    on_fallback: Mutex<Option<FallbackFn>>,
    /// The session was handed to the real handler: from then on a failure
    /// is the caller's to hear about, not a reason to try another tier.
    connected: bool,
}

impl SpeculativeHandler {
    pub(crate) fn new(
        inner: Arc<Mutex<Box<dyn HttpConnectionHandler>>>,
        on_fallback: FallbackFn,
    ) -> Self {
        Self {
            inner,
            on_fallback: Mutex::new(Some(on_fallback)),
            connected: false,
        }
    }
}

impl HttpConnectionHandler for SpeculativeHandler {
    fn on_security_established(&mut self, info: &SecurityInfo) {
        self.inner.lock().unwrap().on_security_established(info);
    }

    fn on_connected(&mut self, session: &mut HttpClientSessionHandle) {
        self.connected = true;
        self.inner.lock().unwrap().on_connected(session);
    }

    fn on_disconnected(&mut self) {
        self.inner.lock().unwrap().on_disconnected();
    }

    fn on_error(&mut self, err: &io::Error) {
        if self.connected {
            self.inner.lock().unwrap().on_error(err);
            return;
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::version::HttpVersion;

    /// What the fake connection does when a request is sent on it.
    #[derive(Clone, Copy, PartialEq)]
    enum Mode {
        /// Answer straight away, inside `send_no_body` (as a connection that
        /// already has the response buffered would).
        Inline,
        /// Keep the handler; the test finishes it later.
        Hold,
    }

    struct FakeOps {
        mode: Mode,
        alt_svc: Option<&'static str>,
        held: Arc<Mutex<Vec<Box<dyn HttpResponseHandler>>>>,
        sent: Arc<Mutex<Vec<String>>>,
    }

    impl SessionRequestOps for FakeOps {
        fn is_open(&self) -> bool {
            true
        }
        fn send_no_body(
            &mut self,
            method: &str,
            path: &str,
            _headers: Headers,
            mut handler: Box<dyn HttpResponseHandler>,
        ) -> Result<(), HttpClientError> {
            self.sent.lock().unwrap().push(format!("{method} {path}"));
            match self.mode {
                Mode::Inline => {
                    handler.ok(200);
                    if let Some(v) = self.alt_svc {
                        handler.header("Alt-Svc", v);
                    }
                    handler.close();
                }
                Mode::Hold => {
                    if let Some(v) = self.alt_svc {
                        handler.ok(200);
                        handler.header("alt-svc", v);
                    }
                    self.held.lock().unwrap().push(handler);
                }
            }
            Ok(())
        }
        fn start_body(
            &mut self,
            _m: &str,
            _p: &str,
            _h: Headers,
            _handler: Box<dyn HttpResponseHandler>,
        ) -> Result<(), HttpClientError> {
            Err(HttpClientError::new("not used"))
        }
        fn body_content(&mut self, _d: &[u8]) -> Result<usize, HttpClientError> {
            Ok(0)
        }
        fn end_body(&mut self) -> Result<(), HttpClientError> {
            Ok(())
        }
        fn cancel_request(&mut self) -> Result<(), HttpClientError> {
            Ok(())
        }
        fn on_body_writable(&mut self, _cb: Box<dyn FnOnce() + Send>) {}
    }

    struct Quiet;
    impl HttpResponseHandler for Quiet {
        fn ok(&mut self, _s: u16) {}
        fn error(&mut self, _s: u16) {}
        fn header(&mut self, _n: &str, _v: &str) {}
        fn response_body_content(&mut self, _d: &[u8]) {}
        fn close(&mut self) {}
        fn failed(&mut self, _e: io::Error) {}
    }

    struct Rig {
        ops: Arc<Mutex<dyn SessionRequestOps + Send>>,
        state: Arc<Mutex<NegotiationState>>,
        cache: Arc<AltSvcCache>,
        upgrades: Arc<AtomicUsize>,
        held: Arc<Mutex<Vec<Box<dyn HttpResponseHandler>>>>,
    }

    fn rig(mode: Mode, alt_svc: Option<&'static str>) -> Rig {
        let cache = Arc::new(AltSvcCache::new());
        let upgrades = Arc::new(AtomicUsize::new(0));
        let u2 = Arc::clone(&upgrades);
        let state = Arc::new(Mutex::new(NegotiationState {
            in_flight: 0,
            host: "example.test".into(),
            port: 443,
            alt_svc_cache: Arc::clone(&cache),
            h3_seen: false,
            on_idle_upgrade: Some(Box::new(move || {
                u2.fetch_add(1, Ordering::SeqCst);
            })),
        }));
        let held = Arc::new(Mutex::new(Vec::new()));
        let inner: Arc<Mutex<dyn SessionRequestOps + Send>> = Arc::new(Mutex::new(FakeOps {
            mode,
            alt_svc,
            held: Arc::clone(&held),
            sent: Arc::default(),
        }));
        let ops: Arc<Mutex<dyn SessionRequestOps + Send>> =
            Arc::new(Mutex::new(AutoNegotiatingOps { inner, state: Arc::clone(&state) }));
        Rig { ops, state, cache, upgrades, held }
    }

    fn send(rig: &Rig) {
        rig.ops.lock().unwrap().send_no_body("GET", "/", Headers::new(), Box::new(Quiet)).unwrap();
    }

    fn finish_one(rig: &Rig) {
        let mut h = rig.held.lock().unwrap().remove(0);
        h.close();
    }

    #[test]
    fn an_h3_alt_svc_is_cached_and_the_upgrade_runs_when_the_connection_goes_idle() {
        let rig = rig(Mode::Hold, Some("h3=\":8443\"; ma=60"));
        send(&rig);
        assert_eq!(rig.upgrades.load(Ordering::SeqCst), 0, "not while a request is in flight");
        assert!(rig.cache.get("example.test", 443).is_some());
        finish_one(&rig);
        assert_eq!(rig.upgrades.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn the_upgrade_waits_for_every_request_in_flight() {
        let rig = rig(Mode::Hold, Some("h3=\":8443\""));
        send(&rig);
        send(&rig);
        finish_one(&rig);
        assert_eq!(rig.upgrades.load(Ordering::SeqCst), 0, "one request is still running");
        finish_one(&rig);
        assert_eq!(rig.upgrades.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn the_upgrade_runs_once() {
        let rig = rig(Mode::Hold, Some("h3=\":8443\""));
        send(&rig);
        finish_one(&rig);
        send(&rig);
        finish_one(&rig);
        assert_eq!(rig.upgrades.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn no_alt_svc_means_no_upgrade() {
        let rig = rig(Mode::Hold, None);
        send(&rig);
        finish_one(&rig);
        assert_eq!(rig.upgrades.load(Ordering::SeqCst), 0);
        assert_eq!(rig.state.lock().unwrap().in_flight, 0);
    }

    #[test]
    fn an_alt_svc_for_something_other_than_h3_means_no_upgrade() {
        let rig = rig(Mode::Hold, Some("h2=\":443\""));
        send(&rig);
        finish_one(&rig);
        assert_eq!(rig.upgrades.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_response_that_completes_inside_the_send_still_counts_as_done() {
        // The request is counted before it is sent: a response can finish
        // (on the reactor thread, say) before `send_no_body` returns.
        let rig = rig(Mode::Inline, Some("h3=\":8443\""));
        send(&rig);
        assert_eq!(rig.state.lock().unwrap().in_flight, 0, "nothing is left in flight");
        assert_eq!(rig.upgrades.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_failed_request_counts_as_done_too() {
        let rig = rig(Mode::Hold, Some("h3=\":8443\""));
        send(&rig);
        let mut h = rig.held.lock().unwrap().remove(0);
        h.failed(io::Error::other("reset"));
        assert_eq!(rig.upgrades.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_send_that_is_refused_is_not_counted() {
        let rig = rig(Mode::Hold, None);
        let r = rig.ops.lock().unwrap().start_body("POST", "/", Headers::new(), Box::new(Quiet));
        assert!(r.is_err());
        assert_eq!(rig.state.lock().unwrap().in_flight, 0);
    }

    #[test]
    fn an_alt_svc_clear_withdraws_what_was_cached_and_does_not_upgrade() {
        let rig = rig(Mode::Hold, Some("clear"));
        rig.cache.observe("example.test", 443, "h3=\":8443\"");
        send(&rig);
        finish_one(&rig);
        assert_eq!(rig.cache.get("example.test", 443), None);
        assert_eq!(rig.upgrades.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn an_alt_svc_with_a_zero_max_age_does_not_upgrade() {
        let rig = rig(Mode::Hold, Some("h3=\":8443\"; ma=0"));
        send(&rig);
        finish_one(&rig);
        assert_eq!(rig.upgrades.load(Ordering::SeqCst), 0);
    }

    // -- the handler wrappers ------------------------------------------------

    #[derive(Default)]
    struct Events(Mutex<Vec<String>>);

    struct Recorder(Arc<Events>);
    impl HttpConnectionHandler for Recorder {
        fn on_connected(&mut self, session: &mut HttpClientSessionHandle) {
            self.0 .0.lock().unwrap().push(format!("connected {:?}", session.version()));
        }
        fn on_disconnected(&mut self) {
            self.0 .0.lock().unwrap().push("disconnected".into());
        }
        fn on_error(&mut self, err: &io::Error) {
            self.0 .0.lock().unwrap().push(format!("error {err}"));
        }
    }

    fn shared(events: &Arc<Events>) -> Arc<Mutex<Box<dyn HttpConnectionHandler>>> {
        Arc::new(Mutex::new(Box::new(Recorder(Arc::clone(events)))))
    }

    fn session() -> HttpClientSessionHandle {
        let ops: Arc<Mutex<dyn SessionRequestOps + Send>> = Arc::new(Mutex::new(FakeOps {
            mode: Mode::Hold,
            alt_svc: None,
            held: Arc::default(),
            sent: Arc::default(),
        }));
        HttpClientSessionHandle::new(ops, HttpVersion::Http11, None)
    }

    #[test]
    fn the_plain_forwarding_handler_passes_every_event_on() {
        let events = Arc::new(Events::default());
        let mut h = ForwardingHandler::plain(shared(&events));
        h.on_connected(&mut session());
        h.on_disconnected();
        h.on_error(&io::Error::other("boom"));
        assert_eq!(*events.0.lock().unwrap(), ["connected Http11", "disconnected", "error boom"]);
    }

    #[test]
    fn the_same_real_handler_can_be_connected_more_than_once() {
        let events = Arc::new(Events::default());
        let real = shared(&events);
        ForwardingHandler::plain(Arc::clone(&real)).on_connected(&mut session());
        ForwardingHandler::plain(real).on_connected(&mut session());
        assert_eq!(events.0.lock().unwrap().len(), 2);
    }

    #[test]
    fn the_observing_handler_watches_the_requests_it_forwards() {
        let events = Arc::new(Events::default());
        let rig = rig(Mode::Hold, None);
        let wrap = NegotiationWrap { state: Arc::clone(&rig.state), conn_handle: Arc::default() };
        let mut h = ForwardingHandler::observing(shared(&events), wrap);
        h.on_connected(&mut session());
        assert_eq!(*events.0.lock().unwrap(), ["connected Http11"]);
    }

    #[test]
    fn a_speculative_failure_falls_back_once_and_does_not_reach_the_real_handler() {
        let events = Arc::new(Events::default());
        let fallbacks = Arc::new(Mutex::new(Vec::new()));
        let f2 = Arc::clone(&fallbacks);
        let mut h = SpeculativeHandler::new(
            shared(&events),
            Box::new(move |e| f2.lock().unwrap().push(e.to_string())),
        );
        h.on_error(&io::Error::new(io::ErrorKind::ConnectionRefused, "no h3 here"));
        h.on_error(&io::Error::other("second"));
        assert_eq!(*fallbacks.lock().unwrap(), ["no h3 here"], "once, with the first error");
        assert!(events.0.lock().unwrap().is_empty());
    }

    #[test]
    fn a_speculative_handler_forwards_a_successful_connection() {
        let events = Arc::new(Events::default());
        let mut h = SpeculativeHandler::new(shared(&events), Box::new(|_| panic!("no fallback expected")));
        h.on_connected(&mut session());
        h.on_disconnected();
        assert_eq!(*events.0.lock().unwrap(), ["connected Http11", "disconnected"]);
    }

    #[test]
    fn an_error_after_a_speculative_connection_was_made_is_the_real_handlers() {
        // Falling back means "that tier could not be dialed"; once the
        // session was handed to the caller, a later failure is theirs to
        // hear about, not a reason to dial another tier behind their back.
        let events = Arc::new(Events::default());
        let fallbacks = Arc::new(AtomicUsize::new(0));
        let f2 = Arc::clone(&fallbacks);
        let mut h = SpeculativeHandler::new(
            shared(&events),
            Box::new(move |_| {
                f2.fetch_add(1, Ordering::SeqCst);
            }),
        );
        h.on_connected(&mut session());
        h.on_error(&io::Error::other("connection lost"));
        assert_eq!(fallbacks.load(Ordering::SeqCst), 0);
        assert_eq!(*events.0.lock().unwrap(), ["connected Http11", "error connection lost"]);
    }
}
