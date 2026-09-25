// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Reactor-driven UDP driver for the DTLS engines.
//!
//! This is the low-level seam between a real UDP socket and
//! [`DtlsRecordEngine`] (DTLS 1.3) / [`Dtls12RecordEngine`] (DTLS 1.2): it owns
//! the socket on a reactor, keeps one engine per remote address, feeds it
//! datagrams and retransmit timers, writes what it emits, and reports raw
//! events to a [`DtlsObserver`]. It deliberately stops there - no
//! `ProtocolHandler`/`Endpoint` layer, no message framing - so DoDTLS, CoAPS
//! and similar protocols can build their own on top.
//!
//! ```ignore
//! let rt = Runtime::start(Default::default())?;
//! // Server: an engine per peer, built by the acceptor.
//! let socket = listen(rt.pick_worker(), udp_socket, Arc::new(move |peer| {
//!     DtlsEngine::V13(DtlsRecordEngine::new(server_config(peer)))
//! }), Box::new(MyObserver), DtlsSocketConfig::default())?;
//! socket.send(peer, b"hello")?; // once `established` has fired for `peer`
//! ```
//!
//! # Model
//!
//! * One UDP socket lives on one reactor. Every session on it is driven from
//!   that reactor's thread, so a listener scales by binding several sockets
//!   (e.g. `SO_REUSEPORT`), not by spreading sessions across reactors.
//! * A session is keyed by the peer's socket address. A datagram from an
//!   unknown address makes a session (server sockets only, up to
//!   [`DtlsSocketConfig::max_sessions`]); a client socket only ever talks to
//!   its one peer and ignores datagrams from anywhere else.
//! * The engines' retransmit timers run on the reactor's timer queue. A
//!   periodic sweep drops handshakes that never finish
//!   ([`DtlsSocketConfig::handshake_timeout`]) and, if configured, idle
//!   sessions.
//! * Certificate verification: the engines resolve a configured trust store or
//!   verify override inline; a request that reaches the driver (a connector
//!   deliberately configured without one) is accepted, exactly as
//!   `TcpConnection` does.
//! * Each `send` is one datagram: keep it within the path MTU. The engines
//!   refuse a payload over the negotiated record limit, reported as a
//!   [`DtlsObserver::closed`] error.
//!
//! # Anti-spoofing and the cookie
//!
//! A server session is allocated when the first datagram from an address
//! arrives, so a flood of spoofed sources costs memory until the handshake
//! timeout ([`DtlsSocketConfig::max_sessions`] bounds it). What it must not
//! also do is elicit a large server flight towards a victim. For DTLS 1.2 that
//! is the `HelloVerifyRequest` cookie (RFC 6347 §4.2.1): set
//! `Dtls12Config::require_cookie` and
//! `Dtls12Config::cookie_binding` to [`peer_cookie_binding`]`(peer)`, and a
//! spoofed source cannot get past the first, tiny, reply. DTLS 1.3's
//! equivalent is a `HelloRetryRequest` cookie (RFC 9147 §5.1), which the
//! DTLS 1.3 engine does not send yet: a DTLS 1.3 listener is amplification-
//! prone against spoofed sources.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use mio::Token;

use crate::cmd::ReactorHandle;
use crate::dtls12::Dtls12RecordEngine;
use crate::security::SecurityInfo;
use crate::tls::{AlertDescription, TlsProtocolError, VerifyRequest, VerifyResult};
use crate::udp::UdpDatagramHandler;

use super::engine::{DtlsRecordEngine, DtlsRecordSink};

/// A DTLS engine of either version, driven identically.
pub enum DtlsEngine {
    /// DTLS 1.3 (RFC 9147).
    V13(DtlsRecordEngine),
    /// DTLS 1.2 (RFC 6347).
    V12(Dtls12RecordEngine),
}

impl From<DtlsRecordEngine> for DtlsEngine {
    fn from(e: DtlsRecordEngine) -> Self {
        Self::V13(e)
    }
}

impl From<Dtls12RecordEngine> for DtlsEngine {
    fn from(e: Dtls12RecordEngine) -> Self {
        Self::V12(e)
    }
}

impl DtlsEngine {
    fn start<S: DtlsRecordSink + ?Sized>(&mut self, sink: &mut S) {
        match self {
            Self::V13(e) => e.start(sink),
            Self::V12(e) => e.start(sink),
        }
    }

    fn feed_datagram<S: DtlsRecordSink + ?Sized>(&mut self, data: &[u8], sink: &mut S) {
        match self {
            Self::V13(e) => e.feed_datagram(data, sink),
            Self::V12(e) => e.feed_datagram(data, sink),
        }
    }

    fn feed_timer<S: DtlsRecordSink + ?Sized>(&mut self, sink: &mut S) {
        match self {
            Self::V13(e) => e.feed_timer(sink),
            Self::V12(e) => e.feed_timer(sink),
        }
    }

    fn send_application_data<S: DtlsRecordSink + ?Sized>(&mut self, data: &[u8], sink: &mut S) {
        match self {
            Self::V13(e) => e.send_application_data(data, sink),
            Self::V12(e) => e.send_application_data(data, sink),
        }
    }

    fn feed_verification_result<S: DtlsRecordSink + ?Sized>(&mut self, result: VerifyResult, sink: &mut S) {
        match self {
            Self::V13(e) => e.feed_verification_result(result, sink),
            Self::V12(e) => e.feed_verification_result(result, sink),
        }
    }

    fn send_close_notify<S: DtlsRecordSink + ?Sized>(&mut self, sink: &mut S) {
        match self {
            Self::V13(e) => e.send_close_notify(sink),
            Self::V12(e) => e.send_close_notify(sink),
        }
    }

    /// Whether the handshake has completed.
    pub fn is_complete(&self) -> bool {
        match self {
            Self::V13(e) => e.is_complete(),
            Self::V12(e) => e.is_complete(),
        }
    }
}

/// Builds the server-role engine for a new peer. The peer's address is passed
/// so a DTLS 1.2 engine can bind its cookie to it ([`peer_cookie_binding`]).
/// Any `Fn(SocketAddr) -> DtlsEngine` is an acceptor.
pub trait DtlsAcceptor: Send + Sync {
    /// The engine for a session with `peer`.
    fn accept(&self, peer: SocketAddr) -> DtlsEngine;
}

impl<F> DtlsAcceptor for F
where
    F: Fn(SocketAddr) -> DtlsEngine + Send + Sync,
{
    fn accept(&self, peer: SocketAddr) -> DtlsEngine {
        self(peer)
    }
}

/// The bytes a DTLS 1.2 cookie should be bound to for `peer`: its IP address
/// and port (RFC 6347 §4.2.1 suggests at least the address). Use as
/// `Dtls12Config::cookie_binding`.
pub fn peer_cookie_binding(peer: SocketAddr) -> Bytes {
    let mut b = Vec::with_capacity(18);
    match peer.ip() {
        IpAddr::V4(ip) => b.extend_from_slice(&ip.octets()),
        IpAddr::V6(ip) => b.extend_from_slice(&ip.octets()),
    }
    b.extend_from_slice(&peer.port().to_be_bytes());
    Bytes::from(b)
}

/// Receives session events. Called on the driver's reactor thread (and, for
/// events a `send` on another thread causes, on that thread), never while the
/// driver holds its session lock, so it may call [`DtlsSocket`] methods.
pub trait DtlsObserver: Send {
    /// The handshake with `peer` completed; [`DtlsSocket::send`] now works.
    fn established(&mut self, peer: SocketAddr, info: &SecurityInfo);
    /// One decrypted application-data record from `peer` (one datagram's worth).
    fn data(&mut self, peer: SocketAddr, data: &[u8]);
    /// The session with `peer` ended and has been dropped: `None` for an
    /// orderly close (the peer's `close_notify`) or an idle timeout, `Some`
    /// for a protocol error or a handshake that timed out.
    fn closed(&mut self, peer: SocketAddr, error: Option<&TlsProtocolError>);
}

/// Limits and timers for a [`DtlsSocket`].
#[derive(Debug, Clone)]
pub struct DtlsSocketConfig {
    /// Most concurrent sessions on a server socket; datagrams from new
    /// addresses beyond it are dropped. Default 1024.
    pub max_sessions: usize,
    /// How long a session may take to complete its handshake before it is
    /// dropped. Default 15 s. (The engine's own retransmission gives up
    /// sooner on a dead peer; this bounds the rest.)
    pub handshake_timeout: Duration,
    /// Drop an established session that has neither sent nor received for
    /// this long. `None` (the default) never does.
    pub idle_timeout: Option<Duration>,
    /// How often expired sessions are looked for. Default 5 s.
    pub sweep_interval: Duration,
}

impl Default for DtlsSocketConfig {
    fn default() -> Self {
        Self {
            max_sessions: 1024,
            handshake_timeout: Duration::from_secs(15),
            idle_timeout: None,
            sweep_interval: Duration::from_secs(5),
        }
    }
}

/// Everything an engine call produced, gathered so it can be acted on after
/// the call returns.
#[derive(Default)]
struct Collected {
    datagrams: Vec<Vec<u8>>,
    app: Vec<Vec<u8>>,
    complete: Option<SecurityInfo>,
    verify: Vec<u64>,
    error: Option<TlsProtocolError>,
    peer_closed: bool,
    /// `Some(x)` when the engine armed (`Some`) or cancelled (`None`) its timer.
    timer: Option<Option<Duration>>,
}

impl DtlsRecordSink for Collected {
    fn datagram_ready(&mut self, data: &[u8]) {
        self.datagrams.push(data.to_vec());
    }
    fn application_data(&mut self, plaintext: &[u8]) {
        self.app.push(plaintext.to_vec());
    }
    fn handshake_complete(&mut self, info: SecurityInfo) {
        self.complete = Some(info);
    }
    fn verification_requested(&mut self, req: VerifyRequest) {
        self.verify.push(req.id);
    }
    fn protocol_error(&mut self, err: TlsProtocolError) {
        if self.error.is_none() {
            self.error = Some(err);
        }
    }
    fn peer_closed(&mut self) {
        self.peer_closed = true;
    }
    fn arm_retransmit_timer(&mut self, after: Option<Duration>) {
        self.timer = Some(after);
    }
}

enum Event {
    Established(SecurityInfo),
    Data(Vec<u8>),
    Closed(Option<TlsProtocolError>),
}

struct Session {
    engine: DtlsEngine,
    timer: Option<Arc<AtomicBool>>,
    established: bool,
    created: Instant,
    last_seen: Instant,
}

impl Session {
    fn new(engine: DtlsEngine) -> Self {
        let now = Instant::now();
        Self {
            engine,
            timer: None,
            established: false,
            created: now,
            last_seen: now,
        }
    }

    fn cancel_timer(&mut self) {
        if let Some(flag) = self.timer.take() {
            flag.store(true, Ordering::Release);
        }
    }
}

struct Shared {
    reactor: ReactorHandle,
    token: OnceLock<Token>,
    local: SocketAddr,
    sessions: Mutex<HashMap<SocketAddr, Session>>,
    observer: Mutex<Box<dyn DtlsObserver>>,
    acceptor: Option<Arc<dyn DtlsAcceptor>>,
    /// Client sockets: the only address that may talk to us.
    fixed_peer: Option<SocketAddr>,
    config: DtlsSocketConfig,
    closed: AtomicBool,
}

impl Shared {
    fn send_raw(&self, peer: SocketAddr, data: Vec<u8>) {
        if let Some(token) = self.token.get() {
            self.reactor.udp_send(*token, peer, data);
        }
    }

    /// Run `op` against `peer`'s engine and act on everything it produced.
    /// Returns the events to deliver once the session lock is released.
    fn drive(
        self: &Arc<Self>,
        sessions: &mut HashMap<SocketAddr, Session>,
        peer: SocketAddr,
        op: impl FnOnce(&mut DtlsEngine, &mut Collected),
    ) -> Vec<Event> {
        let Some(session) = sessions.get_mut(&peer) else {
            return Vec::new();
        };
        let mut out = Collected::default();
        op(&mut session.engine, &mut out);
        // A verification request that reaches us has no trust store behind it
        // (a configured one is resolved inside the engine): accept it.
        while let Some(id) = out.verify.pop() {
            session.engine.feed_verification_result(VerifyResult { id, ok: true }, &mut out);
        }

        if let Some(timer) = out.timer.take() {
            session.cancel_timer();
            if let Some(after) = timer {
                let me = Arc::clone(self);
                session.timer = Some(self.reactor.schedule_timer(after, Box::new(move || me.fire_timer(peer))));
            }
        }
        for datagram in out.datagrams.drain(..) {
            self.send_raw(peer, datagram);
        }

        let mut events = Vec::new();
        if let Some(info) = out.complete.take() {
            session.established = true;
            events.push(Event::Established(info));
        }
        events.extend(out.app.drain(..).map(Event::Data));
        if out.error.is_some() || out.peer_closed {
            session.cancel_timer();
            sessions.remove(&peer);
            events.push(Event::Closed(out.error.take()));
        }
        events
    }

    fn deliver(&self, peer: SocketAddr, events: Vec<Event>) {
        if events.is_empty() {
            return;
        }
        let mut observer = self.observer.lock().expect("dtls observer lock");
        for event in events {
            match event {
                Event::Established(info) => observer.established(peer, &info),
                Event::Data(data) => observer.data(peer, &data),
                Event::Closed(err) => observer.closed(peer, err.as_ref()),
            }
        }
    }

    fn on_datagram(self: &Arc<Self>, peer: SocketAddr, data: &[u8]) {
        if self.closed.load(Ordering::Acquire) || self.fixed_peer.is_some_and(|p| p != peer) {
            return;
        }
        let events = {
            let mut sessions = self.sessions.lock().expect("dtls sessions lock");
            match sessions.get_mut(&peer) {
                Some(session) => {
                    session.last_seen = Instant::now();
                    self.drive(&mut sessions, peer, |e, c| e.feed_datagram(data, c))
                }
                None => {
                    let Some(acceptor) = self.acceptor.as_ref() else {
                        return;
                    };
                    if sessions.len() >= self.config.max_sessions {
                        return;
                    }
                    sessions.insert(peer, Session::new(acceptor.accept(peer)));
                    self.drive(&mut sessions, peer, |e, c| {
                        e.start(c);
                        e.feed_datagram(data, c);
                    })
                }
            }
        };
        self.deliver(peer, events);
    }

    fn fire_timer(self: &Arc<Self>, peer: SocketAddr) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        let events = {
            let mut sessions = self.sessions.lock().expect("dtls sessions lock");
            self.drive(&mut sessions, peer, |e, c| e.feed_timer(c))
        };
        self.deliver(peer, events);
    }

    /// Drop sessions past their handshake or idle limits, then re-arm.
    fn sweep(self: &Arc<Self>) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        let mut ended: Vec<(SocketAddr, Option<TlsProtocolError>)> = Vec::new();
        {
            let mut sessions = self.sessions.lock().expect("dtls sessions lock");
            let handshake = self.config.handshake_timeout;
            let idle = self.config.idle_timeout;
            let expired: Vec<(SocketAddr, bool)> = sessions
                .iter()
                .filter_map(|(peer, s)| {
                    if !s.established && s.created.elapsed() > handshake {
                        Some((*peer, true))
                    } else if s.established && idle.is_some_and(|i| s.last_seen.elapsed() > i) {
                        Some((*peer, false))
                    } else {
                        None
                    }
                })
                .collect();
            for (peer, handshake_failed) in expired {
                if let Some(mut s) = sessions.remove(&peer) {
                    s.cancel_timer();
                }
                let err = handshake_failed
                    .then(|| TlsProtocolError::new(AlertDescription::HandshakeFailure, "DTLS handshake timed out"));
                ended.push((peer, err));
            }
        }
        for (peer, err) in ended {
            self.deliver(peer, vec![Event::Closed(err)]);
        }
        let me = Arc::clone(self);
        self.reactor
            .schedule_timer(self.config.sweep_interval, Box::new(move || me.sweep()));
    }
}

struct Handler(Arc<Shared>);

impl UdpDatagramHandler for Handler {
    fn on_datagram(&mut self, peer: SocketAddr, data: &[u8]) {
        self.0.on_datagram(peer, data);
    }
}

/// A DTLS UDP socket registered on a reactor. Cheap to clone; every clone
/// drives the same sessions.
#[derive(Clone)]
pub struct DtlsSocket {
    shared: Arc<Shared>,
}

/// Bind `socket` on `reactor` as a DTLS server: sessions are created for new
/// peers using `acceptor`.
pub fn listen(
    reactor: &ReactorHandle,
    socket: UdpSocket,
    acceptor: Arc<dyn DtlsAcceptor>,
    observer: Box<dyn DtlsObserver>,
    config: DtlsSocketConfig,
) -> io::Result<DtlsSocket> {
    start(reactor, socket, Some(acceptor), None, observer, config)
}

/// Register `socket` on `reactor` as a DTLS client of `peer` and start the
/// handshake with `engine` (a client-role engine).
pub fn connect(
    reactor: &ReactorHandle,
    socket: UdpSocket,
    peer: SocketAddr,
    engine: DtlsEngine,
    observer: Box<dyn DtlsObserver>,
    config: DtlsSocketConfig,
) -> io::Result<DtlsSocket> {
    let dtls = start(reactor, socket, None, Some(peer), observer, config)?;
    let events = {
        let mut sessions = dtls.shared.sessions.lock().expect("dtls sessions lock");
        sessions.insert(peer, Session::new(engine));
        dtls.shared.drive(&mut sessions, peer, |e, c| e.start(c))
    };
    dtls.shared.deliver(peer, events);
    Ok(dtls)
}

fn start(
    reactor: &ReactorHandle,
    socket: UdpSocket,
    acceptor: Option<Arc<dyn DtlsAcceptor>>,
    fixed_peer: Option<SocketAddr>,
    observer: Box<dyn DtlsObserver>,
    config: DtlsSocketConfig,
) -> io::Result<DtlsSocket> {
    socket.set_nonblocking(true)?;
    let local = socket.local_addr()?;
    let shared = Arc::new(Shared {
        reactor: reactor.clone(),
        token: OnceLock::new(),
        local,
        sessions: Mutex::new(HashMap::new()),
        observer: Mutex::new(observer),
        acceptor,
        fixed_peer,
        config,
        closed: AtomicBool::new(false),
    });
    let token = reactor.register_udp(mio::net::UdpSocket::from_std(socket), Box::new(Handler(Arc::clone(&shared))))?;
    let _ = shared.token.set(token);
    let me = Arc::clone(&shared);
    reactor.schedule_timer(shared.config.sweep_interval, Box::new(move || me.sweep()));
    Ok(DtlsSocket { shared })
}

impl DtlsSocket {
    /// The socket's bound address.
    pub fn local_addr(&self) -> SocketAddr {
        self.shared.local
    }

    /// Number of live sessions (handshaking or established).
    pub fn session_count(&self) -> usize {
        self.shared.sessions.lock().expect("dtls sessions lock").len()
    }

    /// Whether the handshake with `peer` has completed.
    pub fn is_established(&self, peer: SocketAddr) -> bool {
        self.shared
            .sessions
            .lock()
            .expect("dtls sessions lock")
            .get(&peer)
            .is_some_and(|s| s.established)
    }

    /// Send one application-data record to `peer` (one datagram: keep it
    /// within the path MTU). Fails with `NotConnected` until the handshake has
    /// completed. Safe from any thread.
    pub fn send(&self, peer: SocketAddr, data: &[u8]) -> io::Result<()> {
        let events = {
            let mut sessions = self.shared.sessions.lock().expect("dtls sessions lock");
            match sessions.get(&peer) {
                Some(s) if s.established => {}
                Some(_) => return Err(io::Error::new(io::ErrorKind::NotConnected, "DTLS handshake in progress")),
                None => return Err(io::Error::new(io::ErrorKind::NotConnected, "no DTLS session with that peer")),
            }
            self.shared.drive(&mut sessions, peer, |e, c| e.send_application_data(data, c))
        };
        self.shared.deliver(peer, events);
        Ok(())
    }

    /// Send `close_notify` to `peer` and drop the session. No
    /// [`DtlsObserver::closed`] is reported for a close you asked for.
    pub fn close_session(&self, peer: SocketAddr) {
        let mut sessions = self.shared.sessions.lock().expect("dtls sessions lock");
        let _ = self.shared.drive(&mut sessions, peer, |e, c| e.send_close_notify(c));
        if let Some(mut s) = sessions.remove(&peer) {
            s.cancel_timer();
        }
    }

    /// Stop the socket: cancel every timer, drop every session without
    /// notifying peers, and release the UDP socket. Later calls are no-ops.
    pub fn close(&self) {
        if self.shared.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let mut sessions = self.shared.sessions.lock().expect("dtls sessions lock");
        for s in sessions.values_mut() {
            s.cancel_timer();
        }
        sessions.clear();
        if let Some(token) = self.shared.token.get() {
            self.shared.reactor.deregister_udp(*token);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::{channel, Receiver, Sender};

    use super::*;
    use crate::crypto::kx_policy::KxPolicy;
    use crate::crypto::trust::TrustStore;
    use crate::dtls12::Dtls12Config;
    use crate::tls::tls12::engine::{Config as Tls12Config, Role as Tls12Role};
    use crate::tls::{HandshakeConfig, HandshakeMode, HandshakeRole, ServerCredentials};
    use crate::Runtime;

    #[derive(Debug)]
    enum Ev {
        Established(SocketAddr, Option<String>),
        Data(Vec<u8>),
        Closed(SocketAddr, Option<String>),
    }

    struct Recorder(Sender<Ev>);

    impl DtlsObserver for Recorder {
        fn established(&mut self, peer: SocketAddr, info: &SecurityInfo) {
            let _ = self.0.send(Ev::Established(peer, info.sni().map(str::to_owned)));
        }
        fn data(&mut self, _peer: SocketAddr, data: &[u8]) {
            let _ = self.0.send(Ev::Data(data.to_vec()));
        }
        fn closed(&mut self, peer: SocketAddr, error: Option<&TlsProtocolError>) {
            let _ = self.0.send(Ev::Closed(peer, error.map(|e| e.message.clone())));
        }
    }

    fn observer() -> (Box<dyn DtlsObserver>, Receiver<Ev>) {
        let (tx, rx) = channel();
        (Box::new(Recorder(tx)), rx)
    }

    fn next(rx: &Receiver<Ev>) -> Ev {
        rx.recv_timeout(Duration::from_secs(10)).expect("event within 10 s")
    }

    fn creds() -> (ServerCredentials, TrustStore) {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap().self_signed(&kp).unwrap();
        let creds = ServerCredentials {
            cert_chain: vec![Bytes::copy_from_slice(cert.der())],
            signing_key_pkcs8: Bytes::from(kp.serialize_der()),
        };
        let mut trust = TrustStore::new();
        trust.add_anchor(creds.cert_chain[0].clone());
        (creds, trust)
    }

    fn udp() -> UdpSocket {
        UdpSocket::bind("127.0.0.1:0").unwrap()
    }

    fn server13(creds: &ServerCredentials) -> Arc<dyn DtlsAcceptor> {
        let creds = creds.clone();
        Arc::new(move |_peer: SocketAddr| {
            DtlsEngine::V13(DtlsRecordEngine::new(HandshakeConfig {
                role: HandshakeRole::Server,
                mode: HandshakeMode::Dtls,
                server: Some(creds.clone()),
                kx_policy: KxPolicy::classical_only(),
                ..Default::default()
            }))
        })
    }

    fn client13(trust: &TrustStore) -> DtlsEngine {
        DtlsEngine::V13(DtlsRecordEngine::new(HandshakeConfig {
            role: HandshakeRole::Client,
            mode: HandshakeMode::Dtls,
            server_name: Some("localhost".into()),
            trust_store: Some(trust.clone()),
            kx_policy: KxPolicy::classical_only(),
            ..Default::default()
        }))
    }

    fn expect_established(rx: &Receiver<Ev>) -> SocketAddr {
        match next(rx) {
            Ev::Established(peer, _) => peer,
            other => panic!("expected Established, got {other:?}"),
        }
    }

    /// Like [`expect_established`], also returning the SNI the session reports.
    fn expect_established_sni(rx: &Receiver<Ev>) -> (SocketAddr, Option<String>) {
        match next(rx) {
            Ev::Established(peer, sni) => (peer, sni),
            other => panic!("expected Established, got {other:?}"),
        }
    }

    fn expect_data(rx: &Receiver<Ev>, want: &[u8]) {
        match next(rx) {
            Ev::Data(got) => assert_eq!(got, want),
            other => panic!("expected Data, got {other:?}"),
        }
    }

    #[test]
    fn dtls13_handshake_and_data_over_a_real_udp_socket() {
        let rt = Runtime::start(Default::default()).unwrap();
        let (creds, trust) = creds();
        let (s_obs, s_rx) = observer();
        let server = listen(rt.pick_worker(), udp(), server13(&creds), s_obs, DtlsSocketConfig::default()).unwrap();
        let (c_obs, c_rx) = observer();
        let client_sock = udp();
        let client_addr = client_sock.local_addr().unwrap();
        let client = connect(rt.pick_worker(), client_sock, server.local_addr(), client13(&trust), c_obs, DtlsSocketConfig::default()).unwrap();

        let (peer, sni) = expect_established_sni(&s_rx);
        assert_eq!(peer, client_addr);
        assert_eq!(sni.as_deref(), Some("localhost"), "the server sees the client's SNI");
        assert_eq!(expect_established(&c_rx), server.local_addr());
        assert!(server.is_established(client_addr) && client.is_established(server.local_addr()));

        client.send(server.local_addr(), b"hello over DTLS 1.3").unwrap();
        expect_data(&s_rx, b"hello over DTLS 1.3");
        server.send(client_addr, b"and back").unwrap();
        expect_data(&c_rx, b"and back");

        // A stray datagram from anywhere else does not disturb a client socket.
        udp().send_to(&[0x17, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff], client.local_addr()).unwrap();
        client.send(server.local_addr(), b"still fine").unwrap();
        expect_data(&s_rx, b"still fine");

        client.close();
        server.close();
        rt.shutdown();
    }

    #[test]
    fn dtls12_over_udp_with_an_address_bound_cookie() {
        let rt = Runtime::start(Default::default()).unwrap();
        let (creds, trust) = creds();
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret).unwrap();
        let acceptor: Arc<dyn DtlsAcceptor> = {
            let creds = creds.clone();
            Arc::new(move |peer: SocketAddr| {
                DtlsEngine::V12(Dtls12RecordEngine::new(Dtls12Config {
                    base: Tls12Config { role: Tls12Role::Server, server: Some(creds.clone()), ..Default::default() },
                    require_cookie: true,
                    cookie_secret: secret,
                    cookie_binding: peer_cookie_binding(peer),
                }))
            })
        };
        let (s_obs, s_rx) = observer();
        let server = listen(rt.pick_worker(), udp(), acceptor, s_obs, DtlsSocketConfig::default()).unwrap();
        let (c_obs, c_rx) = observer();
        let client_engine = DtlsEngine::V12(Dtls12RecordEngine::new(Dtls12Config {
            base: Tls12Config { role: Tls12Role::Client, server_name: Some("localhost".into()), trust_store: Some(trust), ..Default::default() },
            require_cookie: false,
            cookie_secret: [0; 32],
            cookie_binding: Bytes::new(),
        }));
        let client = connect(rt.pick_worker(), udp(), server.local_addr(), client_engine, c_obs, DtlsSocketConfig::default()).unwrap();

        // Completes through the HelloVerifyRequest round trip.
        expect_established(&s_rx);
        expect_established(&c_rx);
        client.send(server.local_addr(), b"hello over DTLS 1.2").unwrap();
        expect_data(&s_rx, b"hello over DTLS 1.2");
        client.close();
        server.close();
        rt.shutdown();
    }

    /// Forward datagrams between `client` and `server`, dropping the first
    /// `drop_server_to_client` the server sends. Returns the proxy's address.
    fn lossy_proxy(server: SocketAddr, drop_server_to_client: usize, stop: Arc<AtomicBool>) -> SocketAddr {
        let sock = udp();
        sock.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        let addr = sock.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut client: Option<SocketAddr> = None;
            let mut dropped = 0;
            let mut buf = [0u8; 2048];
            while !stop.load(Ordering::Acquire) {
                let Ok((n, from)) = sock.recv_from(&mut buf) else {
                    continue;
                };
                if from == server {
                    if dropped < drop_server_to_client {
                        dropped += 1;
                        continue;
                    }
                    if let Some(c) = client {
                        let _ = sock.send_to(&buf[..n], c);
                    }
                } else {
                    client = Some(from);
                    let _ = sock.send_to(&buf[..n], server);
                }
            }
        });
        addr
    }

    #[test]
    fn the_engines_retransmit_timers_recover_lost_datagrams() {
        // Nothing gets through from the server until its flight has been
        // resent, so the handshake only completes if the retransmit timer the
        // engine arms is actually running on the reactor.
        let rt = Runtime::start(Default::default()).unwrap();
        let (creds, trust) = creds();
        let (s_obs, s_rx) = observer();
        let server = listen(rt.pick_worker(), udp(), server13(&creds), s_obs, DtlsSocketConfig::default()).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let proxy = lossy_proxy(server.local_addr(), 2, Arc::clone(&stop));
        let (c_obs, c_rx) = observer();
        let started = Instant::now();
        let client = connect(rt.pick_worker(), udp(), proxy, client13(&trust), c_obs, DtlsSocketConfig::default()).unwrap();

        expect_established(&s_rx);
        expect_established(&c_rx);
        assert!(started.elapsed() >= Duration::from_millis(900), "needed a retransmission (initial timeout 1 s)");
        client.send(proxy, b"after loss").unwrap();
        expect_data(&s_rx, b"after loss");
        stop.store(true, Ordering::Release);
        client.close();
        server.close();
        rt.shutdown();
    }

    #[test]
    fn send_needs_an_established_session_and_close_session_notifies_the_peer() {
        let rt = Runtime::start(Default::default()).unwrap();
        let (creds, trust) = creds();
        let (s_obs, s_rx) = observer();
        let server = listen(rt.pick_worker(), udp(), server13(&creds), s_obs, DtlsSocketConfig::default()).unwrap();
        let stranger: SocketAddr = "127.0.0.1:9".parse().unwrap();
        assert_eq!(server.send(stranger, b"x").unwrap_err().kind(), io::ErrorKind::NotConnected);

        let (c_obs, c_rx) = observer();
        let client = connect(rt.pick_worker(), udp(), server.local_addr(), client13(&trust), c_obs, DtlsSocketConfig::default()).unwrap();
        // The handshake cannot have finished before the first flight is even sent.
        assert_eq!(client.send(server.local_addr(), b"early").unwrap_err().kind(), io::ErrorKind::NotConnected);
        let client_addr = expect_established(&s_rx);
        expect_established(&c_rx);

        client.close_session(server.local_addr());
        assert_eq!(client.session_count(), 0);
        match next(&s_rx) {
            Ev::Closed(peer, None) => assert_eq!(peer, client_addr),
            other => panic!("expected an orderly close, got {other:?}"),
        }
        assert_eq!(server.session_count(), 0, "the server dropped it too");
        client.close();
        server.close();
        rt.shutdown();
    }

    #[test]
    fn unfinished_handshakes_are_swept_and_the_session_limit_holds() {
        let rt = Runtime::start(Default::default()).unwrap();
        let (creds, trust) = creds();
        let config = DtlsSocketConfig {
            max_sessions: 1,
            handshake_timeout: Duration::from_millis(300),
            sweep_interval: Duration::from_millis(100),
            ..Default::default()
        };
        let (s_obs, s_rx) = observer();
        let server = listen(rt.pick_worker(), udp(), server13(&creds), s_obs, config).unwrap();

        // Two peers start a handshake and then go silent: only one is admitted.
        let first_flight = |trust: &TrustStore| {
            #[derive(Default)]
            struct Grab(Vec<Vec<u8>>);
            impl DtlsRecordSink for Grab {
                fn datagram_ready(&mut self, d: &[u8]) {
                    self.0.push(d.to_vec());
                }
                fn application_data(&mut self, _p: &[u8]) {}
                fn handshake_complete(&mut self, _i: SecurityInfo) {}
                fn verification_requested(&mut self, _r: VerifyRequest) {}
                fn protocol_error(&mut self, _e: TlsProtocolError) {}
                fn peer_closed(&mut self) {}
                fn arm_retransmit_timer(&mut self, _a: Option<Duration>) {}
            }
            let mut engine = client13(trust);
            let mut grab = Grab::default();
            engine.start(&mut grab);
            grab.0
        };
        let (a, b) = (udp(), udp());
        for sock in [&a, &b] {
            for d in first_flight(&trust) {
                sock.send_to(&d, server.local_addr()).unwrap();
            }
        }
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(server.session_count(), 1, "the limit admitted one and dropped the other");

        match next(&s_rx) {
            Ev::Closed(_, Some(msg)) => assert!(msg.contains("timed out"), "{msg}"),
            other => panic!("expected the stalled handshake to be reported, got {other:?}"),
        }
        assert_eq!(server.session_count(), 0);
        server.close();
        rt.shutdown();
    }

    #[test]
    fn cookie_bindings_differ_by_address_and_port() {
        let (a, b, c) = (
            peer_cookie_binding("203.0.113.7:4433".parse().unwrap()),
            peer_cookie_binding("203.0.113.8:4433".parse().unwrap()),
            peer_cookie_binding("203.0.113.7:4434".parse().unwrap()),
        );
        assert!(a != b && a != c && b != c);
        assert_eq!(a.len(), 6);
        assert_eq!(peer_cookie_binding("[2001:db8::1]:4433".parse().unwrap()).len(), 18);
    }
}
