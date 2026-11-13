// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! A callback-shaped, pipelined client for one encrypted upstream resolver:
//! DNS over TLS (RFC 7858, feature `dot`) or DNS over QUIC (RFC 9250, feature
//! `doq`).
//!
//! [`UpstreamClient::query`] takes a message and a callback and returns at
//! once; the callback is called exactly once, on the client's reactor, with the
//! answer or an [`UpstreamError`]. Nothing here blocks a thread, so a slow
//! upstream delays only the queries sent to it.
//!
//! # DoT
//!
//! Queries are pipelined on a connection (RFC 7766 section 6.2.1.1): each is
//! written as soon as the connection is up, without waiting for the answer to
//! the one before, and the answers are matched by message ID, so they may
//! arrive in any order. The ID on the wire is the connection's own (the
//! caller's ID is restored on the answer), so two callers who both used ID 1
//! never clash. The connection is opened by the first query, kept for the next
//! (a pool of up to [`UpstreamConfig::max_connections`], each bound to the
//! client's reactor), closed after [`UpstreamConfig::idle_timeout`] without
//! traffic or outstanding queries, and reopened by the next query.
//!
//! If a connection is lost, a query that was waiting on it is sent again on a
//! fresh connection, up to [`UpstreamConfig::retries`] times, and then fails
//! with [`UpstreamError::ConnectionLost`]. A connection that could not be
//! established fails its queries with [`UpstreamError::Connect`] without a
//! retry. Either way each callback runs once. A query that has not been
//! answered after [`UpstreamConfig::timeout`] fails with
//! [`UpstreamError::Timeout`], and an answer that arrives after that is
//! discarded.
//!
//! # DoQ
//!
//! Each query is one stream on a shared QUIC connection (RFC 9250 section
//! 4.2), so queries are pipelined by the protocol itself. The connection is
//! pooled and redialled when it is gone. The callback is run on the client's
//! reactor here too.
//!
//! A QUIC transport fault can leave a connection that looks alive unable to
//! carry any new stream (seen after several streams are opened at once). To
//! stay clear of it a new connection is proved by one query before the rest
//! are sent, and a query that times out on a connection that has answered
//! nothing in the latter half of its wait gets the connection replaced, so the
//! client recovers on the next query instead of staying stuck.

// With only one of the two transports built, the `Backend` enum has a single
// variant and the matches on it are irrefutable; the code is written for both.
#![allow(irrefutable_let_patterns)]

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[cfg(feature = "dot")]
use hopf_core::{Bytes, ConnHandle, Endpoint, ProtocolHandler, SharedTlsConnector, TcpConnectorConfig};
use hopf_core::ReactorHandle;

use super::questions_match;
use crate::telemetry::{DnsUpstreamTelemetry, UpstreamEvent};
#[cfg(feature = "doq")]
use crate::wire::DnsQuestion;
use crate::wire::DnsMessage;

/// Why a query to an upstream failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UpstreamError {
    /// No answer arrived within the query timeout.
    Timeout,
    /// The connection could not be established (refused, unreachable, the TLS
    /// handshake or certificate verification failed).
    Connect(String),
    /// The connection was lost while the query was outstanding, and the
    /// retries allowed for it are used up.
    ConnectionLost(String),
    /// The upstream sent something that is not an answer to the query.
    Protocol(String),
    /// The connection already has as many queries in flight as it has IDs.
    Overloaded,
    /// The client was closed.
    Closed,
}

impl std::fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout => f.write_str("upstream query timed out"),
            Self::Connect(why) => write!(f, "could not connect to the upstream: {why}"),
            Self::ConnectionLost(why) => write!(f, "upstream connection lost: {why}"),
            Self::Protocol(why) => write!(f, "upstream protocol error: {why}"),
            Self::Overloaded => f.write_str("too many queries in flight to the upstream"),
            Self::Closed => f.write_str("upstream client closed"),
        }
    }
}

impl std::error::Error for UpstreamError {}

impl From<UpstreamError> for io::Error {
    fn from(e: UpstreamError) -> Self {
        let kind = match &e {
            UpstreamError::Timeout => io::ErrorKind::TimedOut,
            UpstreamError::Connect(_) => io::ErrorKind::ConnectionRefused,
            UpstreamError::ConnectionLost(_) => io::ErrorKind::ConnectionAborted,
            UpstreamError::Protocol(_) => io::ErrorKind::InvalidData,
            UpstreamError::Overloaded => io::ErrorKind::WouldBlock,
            UpstreamError::Closed => io::ErrorKind::NotConnected,
        };
        io::Error::new(kind, e.to_string())
    }
}

/// What a query completes with.
pub type UpstreamResult = Result<DnsMessage, UpstreamError>;

type Callback = Box<dyn FnOnce(UpstreamResult) + Send>;

/// Tuning for an [`UpstreamClient`].
#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    /// How long a query may go unanswered, counted from the call to
    /// [`UpstreamClient::query`] and covering the connect and handshake.
    /// Default 5 s.
    pub timeout: Duration,
    /// How long to wait for the TCP connect. Default 5 s.
    pub connect_timeout: Duration,
    /// Close a DoT connection after this long with no query outstanding and
    /// nothing sent or received; the next query opens a new one. Default 30 s.
    pub idle_timeout: Duration,
    /// The most DoT connections to keep. A second is opened only when every
    /// existing one is already carrying a query. Default 1: pipelining makes
    /// one connection enough for most loads.
    pub max_connections: usize,
    /// How many times a query that was waiting on a lost connection is sent
    /// again on a new one. Default 1.
    pub retries: u32,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(30),
            max_connections: 1,
            retries: 1,
        }
    }
}

/// Counters for one upstream, for export as metrics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpstreamMetrics {
    /// Queries accepted by [`UpstreamClient::query`].
    pub queries: u64,
    /// Answers delivered.
    pub responses: u64,
    /// Queries that timed out.
    pub timeouts: u64,
    /// Queries that failed for any reason other than a timeout.
    pub failures: u64,
    /// Queries sent again on a new connection after a loss.
    pub retries: u64,
    /// Connections established.
    pub connects: u64,
    /// Connection attempts that failed before the connection was usable.
    pub connect_failures: u64,
    /// Connections dialled after an earlier one had already been established:
    /// the reconnects.
    pub reconnects: u64,
    /// Connections currently open (the pool size).
    pub connections: u64,
    /// Queries sent or waiting for a connection, not yet completed.
    pub in_flight: u64,
    /// Sum of the time answered queries took, in microseconds. With
    /// `responses` it gives the mean latency.
    pub latency_micros_total: u64,
    /// The longest an answered query took, in microseconds.
    pub latency_micros_max: u64,
}

/// How to reach an upstream over TLS: the name to present and verify, and the
/// connector that holds the trust and any client certificate.
#[cfg(feature = "dot")]
#[derive(Clone)]
pub struct UpstreamTls {
    pub(crate) server_name: String,
    pub(crate) connector: SharedTlsConnector,
}

#[cfg(feature = "dot")]
impl UpstreamTls {
    /// TLS to `server_name` (the SNI and the name the certificate must carry)
    /// through an existing connector.
    pub fn new(server_name: impl Into<String>, connector: SharedTlsConnector) -> Self {
        Self {
            server_name: server_name.into(),
            connector,
        }
    }

    /// Start building the TLS settings for `server_name`: trust, a client
    /// certificate for mutual TLS and public-key pins.
    pub fn builder(server_name: impl Into<String>) -> UpstreamTlsBuilder {
        UpstreamTlsBuilder {
            server_name: server_name.into(),
            trust: hopf_core::ClientTlsBuilder::new(),
            anchors: None,
            credentials: None,
            pins: Vec::new(),
            chain_validation: true,
        }
    }

    /// The name this client presents and verifies.
    pub fn server_name(&self) -> &str {
        &self.server_name
    }
}

/// Builds an [`UpstreamTls`].
///
/// With nothing set it trusts the public WebPKI and presents no certificate.
/// A pinned public key (RFC 7858 section 4.2's SPKI pin set, in the form RFC
/// 7858's authentication profiles use) is checked in addition to the
/// certificate chain, unless the chain check is switched off for a private
/// resolver with a self-signed certificate.
#[cfg(feature = "dot")]
pub struct UpstreamTlsBuilder {
    server_name: String,
    trust: hopf_core::ClientTlsBuilder,
    anchors: Option<hopf_core::crypto::TrustStore>,
    credentials: Option<hopf_core::ServerCredentials>,
    pins: Vec<[u8; 32]>,
    chain_validation: bool,
}

#[cfg(feature = "dot")]
impl UpstreamTlsBuilder {
    /// Trust only these DER certificates (CA or the resolver's own) instead of
    /// the public WebPKI.
    pub fn trust_anchors(mut self, anchors: impl IntoIterator<Item = Bytes>) -> Self {
        let mut store = hopf_core::crypto::TrustStore::new();
        for a in anchors {
            store.add_anchor(a);
        }
        self.anchors = Some(store);
        self
    }

    /// Present this certificate chain and key when the resolver asks for a
    /// client certificate (mutual TLS).
    pub fn client_credentials(mut self, credentials: hopf_core::ServerCredentials) -> Self {
        self.credentials = Some(credentials);
        self
    }

    /// Require the resolver's certificate to carry a public key whose
    /// SubjectPublicKeyInfo has this SHA-256 digest. May be given more than
    /// once: any one matching is enough, which lets a pin be rolled.
    pub fn pin_spki_sha256(mut self, digest: [u8; 32]) -> Self {
        self.pins.push(digest);
        self
    }

    /// Check only the pins, not the certificate chain: for a private resolver
    /// whose certificate is self-signed, where the pin is the whole trust
    /// decision. Needs at least one pin, or [`build`](Self::build) fails.
    pub fn pins_only(mut self) -> Self {
        self.chain_validation = false;
        self
    }

    /// Build the settings.
    pub fn build(self) -> io::Result<UpstreamTls> {
        if !self.chain_validation && self.pins.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pins_only needs at least one pin: with neither a chain check nor a pin nothing would be verified",
            ));
        }
        let mut b = self.trust.alpn(&[b"dot"]);
        if let Some(credentials) = self.credentials {
            b = b.client_credentials(credentials);
        }
        let store = self.anchors;
        if self.pins.is_empty() {
            if let Some(store) = store {
                b = b.trust_store(store);
            }
        } else {
            let pins = self.pins;
            let chain_store = if self.chain_validation {
                Some(store.unwrap_or_else(hopf_core::crypto::trust::public_trust_store))
            } else {
                None
            };
            b = b.verify(Arc::new(move |chain: &[Bytes], name: Option<&str>| {
                if let Some(store) = &chain_store {
                    if store.verify_server_chain(chain, name).is_err() {
                        return false;
                    }
                }
                chain
                    .first()
                    .and_then(|leaf| hopf_core::crypto::spki_sha256(leaf))
                    .is_some_and(|digest| pins.iter().any(|pin| digest.as_ref() == pin.as_slice()))
            }));
        }
        Ok(UpstreamTls {
            server_name: self.server_name,
            connector: b.build(),
        })
    }
}

/// One query in the client's hands.
struct Job {
    /// Identifies the job to its timeout timer, across retries.
    qid: u64,
    /// The message as the caller wrote it, ID included.
    message: DnsMessage,
    callback: Callback,
    /// Times this query has been sent again after a connection loss.
    attempts: u32,
    started: Instant,
    /// Set to stop the timeout timer once the job is complete.
    cancel: Arc<AtomicBool>,
}

#[cfg(feature = "dot")]
struct Conn {
    id: u64,
    handle: Option<ConnHandle>,
    /// The TLS handshake is done and queries can be written.
    ready: bool,
    next_wire_id: u16,
    in_flight: HashMap<u16, Job>,
    /// Queued until the connection is ready.
    waiting: Vec<Job>,
    /// When a query was last sent or an answer last received: the idle
    /// timeout counts from here.
    last_active: Instant,
}

#[cfg(feature = "dot")]
impl Conn {
    fn load(&self) -> usize {
        self.in_flight.len() + self.waiting.len()
    }

    /// An ID not used by a query in flight on this connection.
    fn allocate_id(&mut self) -> Option<u16> {
        if self.in_flight.len() >= u16::MAX as usize {
            return None;
        }
        loop {
            let id = self.next_wire_id;
            self.next_wire_id = self.next_wire_id.wrapping_add(1);
            if !self.in_flight.contains_key(&id) {
                return Some(id);
            }
        }
    }
}

#[cfg(feature = "dot")]
#[derive(Default)]
struct DotState {
    conns: Vec<Conn>,
    next_conn_id: u64,
}

#[derive(Default)]
struct Counters {
    queries: AtomicU64,
    responses: AtomicU64,
    timeouts: AtomicU64,
    failures: AtomicU64,
    retries: AtomicU64,
    connects: AtomicU64,
    connect_failures: AtomicU64,
    reconnects: AtomicU64,
    latency_micros_total: AtomicU64,
    latency_micros_max: AtomicU64,
}

enum Backend {
    #[cfg(feature = "dot")]
    Dot {
        tls: UpstreamTls,
        state: Mutex<DotState>,
    },
    #[cfg(feature = "doq")]
    Doq {
        client: Arc<hopf_quic::QuicClientConfig>,
        server_name: String,
        pool: Mutex<super::doq::DoqConnectionPool>,
        /// Jobs sent and not yet completed, for the in-flight gauge and for
        /// the timeout timer to find.
        jobs: Mutex<HashMap<u64, Arc<DoqJob>>>,
        /// Holds queries back while a fresh connection is being proved.
        gate: Mutex<DoqGate>,
        /// When an answer last arrived on the connection.
        last_answer: Mutex<Option<Instant>>,
    },
}

struct Inner {
    reactor: ReactorHandle,
    addr: SocketAddr,
    config: UpstreamConfig,
    backend: Backend,
    counters: Counters,
    closed: AtomicBool,
    next_qid: AtomicU64,
    ever_connected: AtomicBool,
    /// Where events are reported, if anywhere.
    telemetry: std::sync::OnceLock<Arc<dyn DnsUpstreamTelemetry>>,
    /// `addr` as text, and the transport's name, for reported events.
    label: String,
    transport: &'static str,
    /// Queries accepted and not yet completed (the in-flight gauge).
    pending: std::sync::atomic::AtomicI64,
}

impl Inner {
    /// Count `event`, and report it.
    fn note(&self, event: UpstreamEvent) {
        let c = &self.counters;
        let counter = match event {
            UpstreamEvent::Query => &c.queries,
            UpstreamEvent::Timeout => &c.timeouts,
            UpstreamEvent::Failure => &c.failures,
            UpstreamEvent::Retry => &c.retries,
            UpstreamEvent::Connect => &c.connects,
            UpstreamEvent::ConnectFailure => &c.connect_failures,
            UpstreamEvent::Reconnect => &c.reconnects,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        if let Some(t) = self.telemetry.get() {
            t.event(&self.label, self.transport, event);
        }
    }

    /// A query was accepted.
    fn query_accepted(&self) {
        self.note(UpstreamEvent::Query);
        let now = self.pending.fetch_add(1, Ordering::Relaxed) + 1;
        if let Some(t) = self.telemetry.get() {
            t.in_flight(&self.label, self.transport, now);
        }
    }

    /// A query completed, either way.
    fn query_done(&self) {
        let now = self.pending.fetch_sub(1, Ordering::Relaxed) - 1;
        if let Some(t) = self.telemetry.get() {
            t.in_flight(&self.label, self.transport, now.max(0));
        }
    }

    /// An answer arrived `micros` after the query was made.
    fn answered(&self, micros: u64) {
        let c = &self.counters;
        c.responses.fetch_add(1, Ordering::Relaxed);
        c.latency_micros_total.fetch_add(micros, Ordering::Relaxed);
        c.latency_micros_max.fetch_max(micros, Ordering::Relaxed);
        if let Some(t) = self.telemetry.get() {
            t.response(&self.label, self.transport, Duration::from_micros(micros));
        }
    }

    /// The pool now holds `n` connections.
    fn connections(&self, n: i64) {
        if let Some(t) = self.telemetry.get() {
            t.connections(&self.label, self.transport, n);
        }
    }
}

/// A client for one encrypted upstream resolver. See the
/// [module documentation](self).
///
/// Cheap to clone; clones share the connections.
#[derive(Clone)]
pub struct UpstreamClient {
    inner: Arc<Inner>,
}

impl UpstreamClient {
    /// A DoT client for the resolver at `addr`. It dials nothing until the
    /// first query.
    #[cfg(feature = "dot")]
    pub fn dot(reactor: ReactorHandle, addr: SocketAddr, tls: UpstreamTls, config: UpstreamConfig) -> Self {
        Self::with_backend(
            reactor,
            addr,
            config,
            Backend::Dot {
                tls,
                state: Mutex::new(DotState::default()),
            },
        )
    }

    /// A DoQ client for the resolver at `addr`; `client` should advertise ALPN
    /// `doq`. It dials nothing until the first query.
    #[cfg(feature = "doq")]
    pub fn doq(
        reactor: ReactorHandle,
        addr: SocketAddr,
        server_name: impl Into<String>,
        client: Arc<hopf_quic::QuicClientConfig>,
        config: UpstreamConfig,
    ) -> Self {
        Self::with_backend(
            reactor,
            addr,
            config,
            Backend::Doq {
                client,
                server_name: server_name.into(),
                pool: Mutex::new(super::doq::DoqConnectionPool::new()),
                jobs: Mutex::new(HashMap::new()),
                gate: Mutex::new(DoqGate::default()),
                last_answer: Mutex::new(None),
            },
        )
    }

    fn with_backend(reactor: ReactorHandle, addr: SocketAddr, config: UpstreamConfig, backend: Backend) -> Self {
        Self {
            inner: Arc::new(Inner {
                reactor,
                addr,
                config,
                counters: Counters::default(),
                closed: AtomicBool::new(false),
                next_qid: AtomicU64::new(0),
                ever_connected: AtomicBool::new(false),
                telemetry: std::sync::OnceLock::new(),
                label: addr.to_string(),
                transport: match &backend {
                    #[cfg(feature = "dot")]
                    Backend::Dot { .. } => "dot",
                    #[cfg(feature = "doq")]
                    Backend::Doq { .. } => "doq",
                },
                pending: std::sync::atomic::AtomicI64::new(0),
                backend,
            }),
        }
    }

    /// Which encrypted transport this client speaks, for the resolver's
    /// capability bookkeeping.
    pub(crate) fn encrypted_transport(&self) -> super::capability_cache::EncryptedTransport {
        match &self.inner.backend {
            #[cfg(feature = "dot")]
            Backend::Dot { .. } => super::capability_cache::EncryptedTransport::Dot,
            #[cfg(feature = "doq")]
            Backend::Doq { .. } => super::capability_cache::EncryptedTransport::Doq,
        }
    }

    /// The resolver this client talks to.
    pub fn addr(&self) -> SocketAddr {
        self.inner.addr
    }

    /// Send `message` and call `callback` with the answer, or the reason there
    /// is none. Returns at once, and never calls `callback` before it returns:
    /// the callback runs on the client's reactor.
    ///
    /// The answer carries `message`'s own ID, whatever ID went on the wire.
    pub fn query(&self, message: DnsMessage, callback: impl FnOnce(UpstreamResult) + Send + 'static) {
        self.query_within(message, self.inner.config.timeout, callback);
    }

    /// [`query`](Self::query) with a timeout of its own in place of
    /// [`UpstreamConfig::timeout`].
    pub fn query_within(
        &self,
        message: DnsMessage,
        timeout: Duration,
        callback: impl FnOnce(UpstreamResult) + Send + 'static,
    ) {
        let inner = &self.inner;
        inner.query_accepted();
        // The timeout covers the connect, so the timer starts now. Its flag
        // is the job's `cancel`: completing the job stops the timer.
        let qid = inner.next_qid.fetch_add(1, Ordering::Relaxed);
        let weak = Arc::downgrade(inner);
        let cancel = inner.reactor.schedule_timer(
            timeout,
            Box::new(move || {
                if let Some(inner) = weak.upgrade() {
                    expire(&inner, qid);
                }
            }),
        );
        self.dispatch(Job {
            qid,
            message,
            callback: Box::new(callback),
            attempts: 0,
            started: Instant::now(),
            cancel,
        });
    }

    fn dispatch(&self, job: Job) {
        dispatch(&self.inner, job);
    }

    /// Report this client's events to `telemetry`: queries, answers and their
    /// latency, timeouts, failures, retries, connects, connect failures,
    /// reconnects, the pool size and the number of queries in flight, each
    /// labelled with this upstream's address and transport. To export them over
    /// OTLP or JSONL pass a `hopf_otel` pipeline's `dns_upstream_metrics()`.
    /// Only the first call takes effect; the counters of [`Self::metrics`] are
    /// unchanged.
    pub fn set_telemetry(&self, telemetry: Arc<dyn DnsUpstreamTelemetry>) {
        let _ = self.inner.telemetry.set(telemetry);
    }

    /// A snapshot of the counters.
    pub fn metrics(&self) -> UpstreamMetrics {
        let c = &self.inner.counters;
        let (connections, in_flight) = match &self.inner.backend {
            #[cfg(feature = "dot")]
            Backend::Dot { state, .. } => {
                let st = state.lock().unwrap();
                (
                    st.conns.iter().filter(|c| c.ready).count() as u64,
                    st.conns.iter().map(|c| c.load() as u64).sum(),
                )
            }
            #[cfg(feature = "doq")]
            Backend::Doq { pool, jobs, .. } => (
                pool.lock().unwrap().pooled_connections() as u64,
                jobs.lock().unwrap().len() as u64,
            ),
        };
        UpstreamMetrics {
            queries: c.queries.load(Ordering::Relaxed),
            responses: c.responses.load(Ordering::Relaxed),
            timeouts: c.timeouts.load(Ordering::Relaxed),
            failures: c.failures.load(Ordering::Relaxed),
            retries: c.retries.load(Ordering::Relaxed),
            connects: c.connects.load(Ordering::Relaxed),
            connect_failures: c.connect_failures.load(Ordering::Relaxed),
            reconnects: c.reconnects.load(Ordering::Relaxed),
            connections,
            in_flight,
            latency_micros_total: c.latency_micros_total.load(Ordering::Relaxed),
            latency_micros_max: c.latency_micros_max.load(Ordering::Relaxed),
        }
    }

    /// Close the connections and fail every query still waiting with
    /// [`UpstreamError::Closed`]. Later queries fail the same way.
    pub fn close(&self) {
        let inner = &self.inner;
        inner.closed.store(true, Ordering::SeqCst);
        match &inner.backend {
            #[cfg(feature = "dot")]
            Backend::Dot { state, .. } => {
                let conns = std::mem::take(&mut state.lock().unwrap().conns);
                inner.connections(0);
                for mut conn in conns {
                    if let Some(handle) = conn.handle.take() {
                        handle.close();
                    }
                    let jobs: Vec<Job> = conn.in_flight.drain().map(|(_, j)| j).chain(conn.waiting.drain(..)).collect();
                    for job in jobs {
                        fail(inner, job, UpstreamError::Closed);
                    }
                }
            }
            #[cfg(feature = "doq")]
            Backend::Doq { jobs, pool, .. } => {
                let all: Vec<Arc<DoqJob>> = jobs.lock().unwrap().values().cloned().collect();
                for job in all {
                    doq_complete(inner, &job, Err(UpstreamError::Closed));
                }
                *pool.lock().unwrap() = super::doq::DoqConnectionPool::new();
                inner.connections(0);
            }
        }
    }
}

/// Run `callback` with `result` on the reactor, never inline: a caller holding
/// its own lock when it calls `query` must not see the callback re-enter it.
fn finish(inner: &Inner, callback: Callback, result: UpstreamResult) {
    inner.reactor.execute(Box::new(move || callback(result)));
}

/// Complete `job` successfully, counting its latency.
#[cfg(feature = "dot")]
fn succeed(inner: &Inner, job: Job, message: DnsMessage) {
    job.cancel.store(true, Ordering::SeqCst);
    let micros = job.started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
    inner.answered(micros);
    inner.query_done();
    finish(inner, job.callback, Ok(message));
}

/// Complete `job` with `error`.
fn fail(inner: &Inner, job: Job, error: UpstreamError) {
    job.cancel.store(true, Ordering::SeqCst);
    inner.note(if error == UpstreamError::Timeout {
        UpstreamEvent::Timeout
    } else {
        UpstreamEvent::Failure
    });
    inner.query_done();
    finish(inner, job.callback, Err(error));
}

/// The timeout timer for `qid` fired: complete it if it is still waiting.
fn expire(inner: &Arc<Inner>, qid: u64) {
    match &inner.backend {
        #[cfg(feature = "dot")]
        Backend::Dot { state, .. } => {
            let job = {
                let mut st = state.lock().unwrap();
                let mut found = None;
                for conn in &mut st.conns {
                    if let Some(wire) = conn.in_flight.iter().find(|(_, j)| j.qid == qid).map(|(w, _)| *w) {
                        found = conn.in_flight.remove(&wire);
                        break;
                    }
                    if let Some(pos) = conn.waiting.iter().position(|j| j.qid == qid) {
                        found = Some(conn.waiting.remove(pos));
                        break;
                    }
                }
                found
            };
            if let Some(job) = job {
                fail(inner, job, UpstreamError::Timeout);
            }
        }
        #[cfg(feature = "doq")]
        Backend::Doq { jobs, .. } => {
            let job = jobs.lock().unwrap().get(&qid).cloned();
            if let Some(job) = job {
                doq_complete(inner, &job, Err(UpstreamError::Timeout));
            }
        }
    }
}

fn dispatch(inner: &Arc<Inner>, job: Job) {
    if inner.closed.load(Ordering::SeqCst) {
        fail(inner, job, UpstreamError::Closed);
        return;
    }
    match &inner.backend {
        #[cfg(feature = "dot")]
        Backend::Dot { .. } => dot_dispatch(inner, job),
        #[cfg(feature = "doq")]
        Backend::Doq { .. } => doq_dispatch(inner, job),
    }
}

// ---------------------------------------------------------------------------
// DoT
// ---------------------------------------------------------------------------

/// `message` with `wire_id` as its ID, framed for a stream (RFC 7766 section
/// 8: a two-octet length first).
#[cfg(feature = "dot")]
fn frame(message: &DnsMessage, wire_id: u16) -> Result<Vec<u8>, UpstreamError> {
    let mut m = message.clone();
    m.id = wire_id;
    let bytes = m.serialize().map_err(|e| UpstreamError::Protocol(e.to_string()))?;
    let len = u16::try_from(bytes.len()).map_err(|_| UpstreamError::Protocol("message too long for a stream".into()))?;
    let mut out = Vec::with_capacity(2 + bytes.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&bytes);
    Ok(out)
}

#[cfg(feature = "dot")]
fn dot_state(inner: &Inner) -> &Mutex<DotState> {
    match &inner.backend {
        Backend::Dot { state, .. } => state,
        #[cfg(feature = "doq")]
        _ => unreachable!("a DoT call on a DoQ client"),
    }
}

/// Report the number of ready DoT connections.
#[cfg(feature = "dot")]
fn dot_report_pool(inner: &Inner) {
    let ready = dot_state(inner).lock().unwrap().conns.iter().filter(|c| c.ready).count();
    inner.connections(ready as i64);
}

#[cfg(feature = "dot")]
fn dot_dispatch(inner: &Arc<Inner>, job: Job) {
    enum Next {
        Send(ConnHandle, Vec<u8>),
        Queued,
        Dial(u64),
        Failed(Job, UpstreamError),
    }
    let next = {
        let mut st = dot_state(inner).lock().unwrap();
        let has_idle = st.conns.iter().map(Conn::load).min() == Some(0);
        let can_grow = st.conns.len() < inner.config.max_connections.max(1);
        // Reuse the least loaded connection; open another only if every one
        // is already carrying a query and the pool may grow.
        let pick = st
            .conns
            .iter()
            .enumerate()
            .min_by_key(|(_, c)| c.load())
            .map(|(i, _)| i)
            .filter(|_| has_idle || !can_grow);
        match pick {
            Some(i) => {
                let conn = &mut st.conns[i];
                if conn.ready {
                    match conn.allocate_id() {
                        None => Next::Failed(job, UpstreamError::Overloaded),
                        Some(wire) => match frame(&job.message, wire) {
                            Err(e) => Next::Failed(job, e),
                            Ok(bytes) => match conn.handle.clone() {
                                Some(handle) => {
                                    conn.in_flight.insert(wire, job);
                                    conn.last_active = Instant::now();
                                    Next::Send(handle, bytes)
                                }
                                None => {
                                    conn.waiting.push(job);
                                    Next::Queued
                                }
                            },
                        },
                    }
                } else {
                    conn.waiting.push(job);
                    Next::Queued
                }
            }
            None => {
                let id = st.next_conn_id;
                st.next_conn_id += 1;
                let mut seed = [0u8; 2];
                let _ = getrandom::getrandom(&mut seed);
                st.conns.push(Conn {
                    id,
                    handle: None,
                    ready: false,
                    next_wire_id: u16::from_be_bytes(seed),
                    in_flight: HashMap::new(),
                    waiting: vec![job],
                    last_active: Instant::now(),
                });
                Next::Dial(id)
            }
        }
    };
    match next {
        Next::Send(handle, bytes) => handle.with_endpoint(move |ep| ep.send(&bytes)),
        Next::Queued => {}
        Next::Failed(job, e) => fail(inner, job, e),
        Next::Dial(id) => dot_dial(inner, id),
    }
}

#[cfg(feature = "dot")]
fn dot_dial(inner: &Arc<Inner>, conn_id: u64) {
    let Backend::Dot { tls, .. } = &inner.backend else {
        return;
    };
    if inner.ever_connected.load(Ordering::SeqCst) {
        inner.note(UpstreamEvent::Reconnect);
    }
    let handler_inner = Arc::clone(inner);
    let mut config = TcpConnectorConfig::new(inner.addr, move || {
        Box::new(DotConn {
            inner: Arc::clone(&handler_inner),
            conn_id,
            buf: Vec::new(),
        }) as Box<dyn ProtocolHandler>
    })
    .with_tls(Arc::clone(&tls.connector), tls.server_name.clone());
    config.connect_timeout = Some(inner.config.connect_timeout);
    if let Err(e) = inner.reactor.connect(config) {
        dot_lost(inner, conn_id, &e.to_string());
    }
}

/// Look at connection `conn_id` again after `after`, to close it if it has
/// been idle. (The reactor stores a connection's idle timeout but does not
/// enforce one, so the client keeps its own.)
#[cfg(feature = "dot")]
fn dot_arm_idle(inner: &Arc<Inner>, conn_id: u64, after: Duration) {
    let weak = Arc::downgrade(inner);
    inner.reactor.schedule_timer(
        after,
        Box::new(move || {
            if let Some(inner) = weak.upgrade() {
                dot_idle_check(&inner, conn_id);
            }
        }),
    );
}

/// Close `conn_id` if nothing has been outstanding on it, and nothing sent or
/// received, for the idle timeout; otherwise look again when it would be due.
#[cfg(feature = "dot")]
fn dot_idle_check(inner: &Arc<Inner>, conn_id: u64) {
    let idle = inner.config.idle_timeout;
    let again = {
        let mut st = dot_state(inner).lock().unwrap();
        let Some(pos) = st.conns.iter().position(|c| c.id == conn_id) else {
            return; // already gone
        };
        let conn = &st.conns[pos];
        let quiet = conn.last_active.elapsed();
        if conn.load() > 0 {
            idle
        } else if quiet < idle {
            idle - quiet
        } else {
            // Taken out of the pool under the lock, so no query can be given
            // to it between this decision and the close.
            let conn = st.conns.remove(pos);
            drop(st);
            if let Some(handle) = conn.handle {
                handle.close();
            }
            dot_report_pool(inner);
            return;
        }
    };
    dot_arm_idle(inner, conn_id, again);
}

/// Connection `conn_id` is gone (or never came up). Complete or resend what
/// was waiting on it, once each.
#[cfg(feature = "dot")]
fn dot_lost(inner: &Arc<Inner>, conn_id: u64, reason: &str) {
    let (jobs, was_ready) = {
        let mut st = dot_state(inner).lock().unwrap();
        let Some(pos) = st.conns.iter().position(|c| c.id == conn_id) else {
            return; // already handled: `error` and `disconnected` both report a loss
        };
        let mut conn = st.conns.remove(pos);
        let was_ready = conn.ready;
        let jobs: Vec<Job> = conn.in_flight.drain().map(|(_, j)| j).chain(conn.waiting.drain(..)).collect();
        (jobs, was_ready)
    };
    if !was_ready {
        inner.note(UpstreamEvent::ConnectFailure);
    }
    dot_report_pool(inner);
    for mut job in jobs {
        if !was_ready {
            fail(inner, job, UpstreamError::Connect(reason.to_string()));
        } else if job.attempts < inner.config.retries && !inner.closed.load(Ordering::SeqCst) {
            job.attempts += 1;
            inner.note(UpstreamEvent::Retry);
            dot_dispatch(inner, job);
        } else {
            fail(inner, job, UpstreamError::ConnectionLost(reason.to_string()));
        }
    }
}

/// The reactor-side half of one DoT connection.
#[cfg(feature = "dot")]
struct DotConn {
    inner: Arc<Inner>,
    conn_id: u64,
    /// Bytes received and not yet a whole message.
    buf: Vec<u8>,
}

#[cfg(feature = "dot")]
impl DotConn {
    fn answer(&self, message: DnsMessage) {
        let inner = &self.inner;
        let job = {
            let mut st = dot_state(inner).lock().unwrap();
            st.conns.iter_mut().find(|c| c.id == self.conn_id).and_then(|c| {
                c.last_active = Instant::now();
                c.in_flight.remove(&message.id)
            })
        };
        // No such query in flight: it timed out, or was never ours. Drop it.
        let Some(job) = job else {
            return;
        };
        let asked = job.message.questions.first();
        let matches = match (asked, message.questions.first()) {
            (Some(a), Some(b)) => questions_match(a, b),
            (None, None) => true,
            _ => false,
        };
        if !matches {
            fail(inner, job, UpstreamError::Protocol("the answer is to a different question".into()));
            return;
        }
        let mut message = message;
        message.id = job.message.id;
        succeed(inner, job, message);
    }
}

#[cfg(feature = "dot")]
impl ProtocolHandler for DotConn {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        let mut st = dot_state(&self.inner).lock().unwrap();
        if let Some(conn) = st.conns.iter_mut().find(|c| c.id == self.conn_id) {
            conn.handle = Some(endpoint.handle());
        }
    }

    fn security_established(&mut self, endpoint: &mut dyn Endpoint, _info: &hopf_core::SecurityInfo) {
        let inner = Arc::clone(&self.inner);
        inner.note(UpstreamEvent::Connect);
        inner.ever_connected.store(true, Ordering::SeqCst);
        let mut outbound = Vec::new();
        let mut failed = Vec::new();
        {
            let mut st = dot_state(&inner).lock().unwrap();
            let Some(conn) = st.conns.iter_mut().find(|c| c.id == self.conn_id) else {
                // Closed while connecting.
                endpoint.close();
                return;
            };
            conn.ready = true;
            conn.last_active = Instant::now();
            for job in std::mem::take(&mut conn.waiting) {
                match conn.allocate_id() {
                    None => failed.push((job, UpstreamError::Overloaded)),
                    Some(wire) => match frame(&job.message, wire) {
                        Ok(bytes) => {
                            outbound.push(bytes);
                            conn.in_flight.insert(wire, job);
                        }
                        Err(e) => failed.push((job, e)),
                    },
                }
            }
        }
        for bytes in outbound {
            endpoint.send(&bytes);
        }
        for (job, e) in failed {
            fail(&inner, job, e);
        }
        dot_arm_idle(&inner, self.conn_id, inner.config.idle_timeout);
        dot_report_pool(&inner);
    }

    fn receive(&mut self, _endpoint: &mut dyn Endpoint, buf: &mut hopf_core::LoopBuf) {
        let mut messages = Vec::new();
        let mut bad = false;
        hopf_core::with_slice(buf, |data| {
            self.buf.extend_from_slice(data);
            *data = &[];
            while self.buf.len() >= 2 {
                let len = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
                if self.buf.len() < 2 + len {
                    break;
                }
                match DnsMessage::parse(&self.buf[2..2 + len]) {
                    Ok(m) => messages.push(m),
                    Err(_) => bad = true,
                }
                self.buf.drain(..2 + len);
            }
        });
        for m in messages {
            self.answer(m);
        }
        if bad {
            // An unparseable message: the stream cannot be trusted any more.
            dot_lost(&self.inner, self.conn_id, "the upstream sent a malformed message");
        }
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
        dot_lost(&self.inner, self.conn_id, "the connection closed");
    }

    fn error(&mut self, _endpoint: &mut dyn Endpoint, err: &io::Error) {
        dot_lost(&self.inner, self.conn_id, &err.to_string());
    }
}

// ---------------------------------------------------------------------------
// DoQ
// ---------------------------------------------------------------------------

#[cfg(feature = "doq")]
struct DoqJob {
    qid: u64,
    message: DnsMessage,
    question: Option<DnsQuestion>,
    callback: Mutex<Option<Callback>>,
    attempts: Mutex<u32>,
    started: Instant,
    cancel: Arc<AtomicBool>,
}

/// Complete a DoQ job once; later completions find the callback gone.
#[cfg(feature = "doq")]
fn doq_complete(inner: &Arc<Inner>, job: &DoqJob, result: UpstreamResult) {
    let Some(callback) = job.callback.lock().unwrap().take() else {
        return;
    };
    job.cancel.store(true, Ordering::SeqCst);
    if let Backend::Doq { jobs, .. } = &inner.backend {
        jobs.lock().unwrap().remove(&job.qid);
    }
    doq_settle(inner, job, &result);
    match &result {
        Ok(_) => inner.answered(job.started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64),
        Err(UpstreamError::Timeout) => inner.note(UpstreamEvent::Timeout),
        Err(_) => inner.note(UpstreamEvent::Failure),
    }
    inner.query_done();
    finish(inner, callback, result);
}

#[cfg(feature = "doq")]
fn doq_dispatch(inner: &Arc<Inner>, job: Job) {
    let djob = Arc::new(DoqJob {
        qid: job.qid,
        question: job.message.questions.first().cloned(),
        message: job.message,
        callback: Mutex::new(Some(job.callback)),
        attempts: Mutex::new(job.attempts),
        started: job.started,
        cancel: job.cancel,
    });
    let Backend::Doq { jobs, .. } = &inner.backend else {
        return;
    };
    jobs.lock().unwrap().insert(djob.qid, Arc::clone(&djob));
    // Admission runs on the reactor, like the gate's other changes, so they
    // are applied in the order they happened: a query cannot slip in between
    // a failed probe being recorded and the connection being replaced.
    let inner = Arc::clone(inner);
    let reactor = inner.reactor.clone();
    reactor.execute(Box::new(move || doq_admit(&inner, djob)));
}

/// What the client knows about the health of its DoQ connection.
///
/// A new connection is proved by one query before the rest are sent on it:
/// opening several streams in the instant a QUIC handshake completes can
/// leave the connection unable to carry any of them (a fault in the QUIC
/// transport, not in the upstream), and a connection in that state looks
/// alive. So the first query goes alone as a probe; once it is answered the
/// connection is `warm` and every query goes straight out, pipelined. If the
/// probe fails, the connection is thrown away and the next queued query
/// probes a new one. The cost is that queries arriving in the first round trip
/// of a fresh connection wait for the probe's answer.
#[cfg(feature = "doq")]
#[derive(Default)]
struct DoqGate {
    warm: bool,
    /// The query probing the current connection, if one is outstanding.
    probe: Option<u64>,
    /// Queries waiting for the probe.
    queue: std::collections::VecDeque<Arc<DoqJob>>,
}

/// Send `job` now, or hold it behind the probe.
#[cfg(feature = "doq")]
fn doq_admit(inner: &Arc<Inner>, job: Arc<DoqJob>) {
    let Backend::Doq { gate, .. } = &inner.backend else {
        return;
    };
    let send_now = {
        let mut g = gate.lock().unwrap();
        if g.warm || g.probe == Some(job.qid) {
            true
        } else if g.probe.is_none() {
            g.probe = Some(job.qid);
            true
        } else {
            if !g.queue.iter().any(|j| j.qid == job.qid) {
                g.queue.push_back(Arc::clone(&job));
            }
            false
        }
    };
    if send_now {
        doq_send(inner, &job);
    }
}

/// `job` is complete with `result`. Keep the gate in step.
///
/// * A queued job leaves the queue.
/// * An answered probe warms the connection and releases the queue.
/// * A failed probe discards the connection and promotes the next queued
///   query to probe a new one.
/// * A query that times out while the connection has delivered no answer for
///   the latter half of the time the query waited means the connection is not carrying anything,
///   however alive it looks (a QUIC transport fault can leave it so after a
///   burst of new streams): it is discarded too, and the next query probes a
///   new one. A query that is merely slow, on a connection that is answering
///   others, does not do this.
#[cfg(feature = "doq")]
fn doq_settle(inner: &Arc<Inner>, job: &DoqJob, result: &UpstreamResult) {
    let Backend::Doq { gate, last_answer, .. } = &inner.backend else {
        return;
    };
    let answered = result.is_ok();
    // Silent: nothing has arrived on the connection in the latter half of the
    // time this query waited.
    let silent = matches!(result, Err(UpstreamError::Timeout)) && {
        let waited = job.started.elapsed();
        last_answer
            .lock()
            .unwrap()
            .is_none_or(|at| at.elapsed() * 2 >= waited)
    };
    let (release, recycle) = {
        let mut g = gate.lock().unwrap();
        g.queue.retain(|j| j.qid != job.qid);
        if g.probe == Some(job.qid) {
            g.probe = None;
            if answered {
                g.warm = true;
                inner.connections(1);
                (g.queue.drain(..).collect::<Vec<_>>(), false)
            } else {
                g.warm = false;
                // The next query still waiting becomes the probe. One that
                // has completed already (it timed out in the same tick) is
                // skipped.
                let mut next = None;
                while let Some(j) = g.queue.pop_front() {
                    if j.callback.lock().unwrap().is_some() {
                        next = Some(j);
                        break;
                    }
                }
                g.probe = next.as_ref().map(|j| j.qid);
                (next.into_iter().collect(), true)
            }
        } else if silent && g.warm {
            g.warm = false;
            (Vec::new(), true)
        } else {
            return;
        }
    };
    if recycle || !release.is_empty() {
        // This may run on the QUIC driver thread (when it is delivering an
        // answer), which must not wait on itself: `open_bi` waits for the
        // driver, and dropping the pool's old driver joins its thread. Both
        // happen on the reactor instead.
        let inner = Arc::clone(inner);
        let reactor = inner.reactor.clone();
        reactor.execute(Box::new(move || {
            if recycle {
                // Closes the connection that failed to carry the query; the
                // next send dials a new one.
                if let Backend::Doq { pool, .. } = &inner.backend {
                    *pool.lock().unwrap() = super::doq::DoqConnectionPool::new();
                    inner.connections(0);
                }
            }
            for job in release {
                if job.callback.lock().unwrap().is_some() {
                    doq_send(&inner, &job);
                }
            }
        }));
    }
}

#[cfg(feature = "doq")]
fn doq_send(inner: &Arc<Inner>, job: &Arc<DoqJob>) {
    let Backend::Doq { client, server_name, pool, .. } = &inner.backend else {
        return;
    };
    let bytes = match job.message.serialize() {
        Ok(b) => b,
        Err(e) => return doq_complete(inner, job, Err(UpstreamError::Protocol(e.to_string()))),
    };
    let handler = Box::new(DoqAnswer {
        inner: Arc::clone(inner),
        job: Arc::clone(job),
    });
    let sent = pool.lock().unwrap().send_query(inner.addr, client, server_name, &bytes, handler);
    if let Err(e) = sent {
        inner.note(UpstreamEvent::ConnectFailure);
        doq_complete(inner, job, Err(UpstreamError::Connect(e.to_string())));
    }
}

#[cfg(feature = "doq")]
struct DoqAnswer {
    inner: Arc<Inner>,
    job: Arc<DoqJob>,
}

#[cfg(feature = "doq")]
impl super::DnsClientTransportHandler for DoqAnswer {
    fn on_response(&mut self, _server: SocketAddr, data: &[u8]) {
        let inner = &self.inner;
        inner.ever_connected.store(true, Ordering::SeqCst);
        if let Backend::Doq { last_answer, .. } = &inner.backend {
            *last_answer.lock().unwrap() = Some(Instant::now());
        }
        let mut message = match DnsMessage::parse(data) {
            Ok(m) => m,
            Err(_) => return doq_complete(inner, &self.job, Err(UpstreamError::Protocol("malformed answer".into()))),
        };
        let matches = match (&self.job.question, message.questions.first()) {
            (Some(a), Some(b)) => questions_match(a, b),
            (None, None) => true,
            _ => false,
        };
        if !matches {
            return doq_complete(
                inner,
                &self.job,
                Err(UpstreamError::Protocol("the answer is to a different question".into())),
            );
        }
        // The wire ID was zero (RFC 9250 section 4.2.1); the caller's comes back.
        message.id = self.job.message.id;
        doq_complete(inner, &self.job, Ok(message));
    }

    fn on_error(&mut self, _server: SocketAddr, err: io::Error) {
        let inner = &self.inner;
        let retry = {
            let mut attempts = self.job.attempts.lock().unwrap();
            let again = *attempts < inner.config.retries && !inner.closed.load(Ordering::SeqCst);
            if again {
                *attempts += 1;
            }
            again
        };
        if retry && self.job.callback.lock().unwrap().is_some() {
            inner.note(UpstreamEvent::Retry);
            // Through the gate, on the reactor: this is the QUIC driver
            // thread, and sending waits on the driver.
            let (inner, job) = (Arc::clone(inner), Arc::clone(&self.job));
            self.inner.reactor.execute(Box::new(move || doq_admit(&inner, job)));
        } else {
            doq_complete(inner, &self.job, Err(UpstreamError::ConnectionLost(err.to_string())));
        }
    }
}
