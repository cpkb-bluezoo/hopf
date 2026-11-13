// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Application logic for a [`DnsService`](super::DnsService): the
//! [`DnsQueryHandler`] trait and its small stock implementations.
//!
//! DNS is stateless at the application layer, so a handler sees each message
//! independently. The [`DnsService`](super::DnsService) shell owns everything
//! that is protocol rather than policy (cookies, header validation, transport
//! framing); a handler only decides what the answer is. With no handler
//! attached the shell answers every query with an empty `NOERROR`.
//!
//! # Callback shape
//!
//! Like every I/O operation in hopf, a handler takes a callback and returns
//! nothing: [`DnsQueryHandler::handle_query`] is given a
//! [`DnsQueryCallback`] and completes it, exactly once, with
//! [`respond`](DnsQueryCallback::respond),
//! [`respond_sequence`](DnsQueryCallback::respond_sequence),
//! [`decline`](DnsQueryCallback::decline) or
//! [`error`](DnsQueryCallback::error). It may do so before returning (no extra
//! hop; this is what a table lookup does) or later, from any thread, once an
//! upstream client or a store has answered. The listener thread is never held
//! while a handler waits. Dropping the callback without completing it is a
//! bug in the handler; it is logged and the query is answered `SERVFAIL`, so a
//! query is never left hanging.
//!
//! A handler whose answer is available at once implements the simpler
//! [`SyncDnsQueryHandler`] instead, and is adapted automatically.
//!
//! Stock handlers:
//!
//! - [`EmptyHandler`] - the no-op default.
//! - [`ForwarderHandler`](super::ForwarderHandler) - caching forwarder.
//! - [`AuthoritativeZoneHandler`](super::zone::AuthoritativeZoneHandler) -
//!   authoritative zones.
//! - [`FnHandler`] - closures, for tests and small local overrides.
//! - [`ChainHandler`] - first handler that does not decline wins, e.g.
//!   authoritative zones ahead of a forwarder for split-horizon setups.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use hopf_core::{Bytes, Runtime, SecurityInfo};

use super::DnsServerMetrics;
use crate::wire::DnsMessage;

/// Transport a message arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsTransport {
    /// Datagram (RFC 1035 §4.2.1). Responses are limited by the client's
    /// advertised payload size; zone transfers are answered with TC.
    Udp,
    /// Cleartext TCP (RFC 1035 §4.2.2).
    Tcp,
    /// DNS over TLS (RFC 7858).
    Dot,
    /// DNS over QUIC (RFC 9250).
    Doq,
}

impl DnsTransport {
    /// Whether one query may be answered with several messages
    /// (AXFR/IXFR, RFC 5936 §2.2). True for every stream transport.
    pub fn supports_multi_message(self) -> bool {
        !matches!(self, Self::Udp)
    }
}

/// Write-only view of the shell's counters, handed to handlers.
///
/// Owned and cheap to clone, so a handler that answers later can keep it.
#[derive(Clone)]
pub struct MetricsSink(pub(super) Arc<Mutex<DnsServerMetrics>>);

impl MetricsSink {
    /// Count a cache hit.
    pub fn cache_hit(&self) {
        self.0.lock().unwrap().cache_hits += 1;
    }

    /// Count an upstream forward.
    pub fn upstream(&self) {
        self.0.lock().unwrap().upstreams += 1;
    }

    /// Count an answer served stale (RFC 8767) because the upstream failed.
    pub fn stale_served(&self) {
        self.0.lock().unwrap().stale_served += 1;
    }

    /// Count a negative answer synthesised from cached NSEC/NSEC3 proofs.
    pub fn aggressive_nsec(&self) {
        self.0.lock().unwrap().aggressive_nsec_hits += 1;
    }

    /// Count an error.
    pub fn error(&self) {
        self.0.lock().unwrap().errors += 1;
    }
}

/// What the listener knows about the connection a message arrived on.
///
/// Built once per message from the endpoint and handed to
/// [`DnsService::dispatch_wire_with`](super::DnsService::dispatch_wire_with).
/// The [`SecurityInfo`] is shared between every message on the connection, not
/// copied per query.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ConnectionInfo {
    /// The peer's address.
    pub peer: SocketAddr,
    /// The local address the message arrived on, when known. For UDP this is
    /// the address the socket is bound to, which is the wildcard address if
    /// the listener is.
    pub local: Option<SocketAddr>,
    /// The negotiated TLS or QUIC parameters, with the client's certificate
    /// chain when it presented one. `None` for UDP and cleartext TCP.
    pub security: Option<Arc<SecurityInfo>>,
}

impl ConnectionInfo {
    /// A connection known only by its peer address.
    pub fn new(peer: SocketAddr) -> Self {
        Self {
            peer,
            local: None,
            security: None,
        }
    }

    /// Set the local address.
    pub fn with_local(mut self, local: Option<SocketAddr>) -> Self {
        self.local = local;
        self
    }

    /// Set the shared security parameters.
    pub fn with_security(mut self, security: Option<Arc<SecurityInfo>>) -> Self {
        self.security = security;
        self
    }
}

/// Per-message context supplied by the shell.
///
/// Owned and cheap to clone (a shared [`SecurityInfo`], a few `Copy` fields
/// and two reference-counted handles), so a handler that completes its
/// callback later keeps it and reads the peer's identity again from there:
/// move a clone into the closure that runs when a store or an upstream
/// answers. New fields can be added without breaking handlers, so read it
/// through the accessors.
#[derive(Clone)]
#[non_exhaustive]
pub struct QueryContext {
    peer: SocketAddr,
    local: Option<SocketAddr>,
    transport: DnsTransport,
    tsig_key: Option<Arc<str>>,
    security: Option<Arc<SecurityInfo>>,
    metrics: MetricsSink,
}

impl QueryContext {
    /// A context for `peer` over `transport`, with no TSIG key, no local
    /// address, no security layer and counters that go nowhere. The shell
    /// builds the real one; this is for exercising a handler directly.
    pub fn new(peer: SocketAddr, transport: DnsTransport) -> Self {
        Self {
            peer,
            local: None,
            transport,
            tsig_key: None,
            security: None,
            metrics: MetricsSink(Arc::new(Mutex::new(DnsServerMetrics::default()))),
        }
    }

    pub(crate) fn from_connection(
        conn: &ConnectionInfo,
        transport: DnsTransport,
        tsig_key: Option<&str>,
        metrics: MetricsSink,
    ) -> Self {
        Self {
            peer: conn.peer,
            local: conn.local,
            transport,
            tsig_key: tsig_key.map(Arc::from),
            security: conn.security.clone(),
            metrics,
        }
    }

    /// Set the local address.
    pub fn with_local(mut self, local: Option<SocketAddr>) -> Self {
        self.local = local;
        self
    }

    /// Set the shared security parameters.
    pub fn with_security(mut self, security: Option<Arc<SecurityInfo>>) -> Self {
        self.security = security;
        self
    }

    /// Set the name of the TSIG key that authenticated the message.
    pub fn with_tsig_key(mut self, name: Option<&str>) -> Self {
        self.tsig_key = name.map(Arc::from);
        self
    }

    /// The peer's address. An UPDATE or transfer handler needs the source to
    /// authorise the request.
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// The local address the message arrived on, when the listener knows it.
    /// A handler serving several listeners can tell them apart by this.
    pub fn local(&self) -> Option<SocketAddr> {
        self.local
    }

    /// Transport the message arrived on.
    pub fn transport(&self) -> DnsTransport {
        self.transport
    }

    /// Name of the TSIG key (RFC 8945) that authenticated this message, if it
    /// carried a valid signature. A signature that fails to verify never
    /// reaches a handler.
    pub fn tsig_key(&self) -> Option<&str> {
        self.tsig_key.as_deref()
    }

    /// The connection's negotiated security parameters: `Some` over DoT and
    /// DoQ, `None` over UDP and cleartext TCP.
    pub fn security(&self) -> Option<&SecurityInfo> {
        self.security.as_deref()
    }

    /// The Server Name Indication the client requested in its handshake.
    pub fn sni(&self) -> Option<&str> {
        self.security().and_then(SecurityInfo::sni)
    }

    /// The client's certificate chain (DER, leaf first) when it presented one
    /// during the handshake (mTLS). A handler authorises a client by its
    /// identity here.
    pub fn peer_certificate_chain(&self) -> Option<&[Bytes]> {
        self.security().and_then(SecurityInfo::peer_certificate_chain)
    }

    /// Shell counters.
    pub fn metrics(&self) -> &MetricsSink {
        &self.metrics
    }
}

impl std::fmt::Debug for QueryContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueryContext")
            .field("peer", &self.peer)
            .field("local", &self.local)
            .field("transport", &self.transport)
            .field("tsig_key", &self.tsig_key)
            .field("security", &self.security)
            .finish_non_exhaustive()
    }
}

/// What a handler decided.
#[derive(Debug, Clone)]
pub(crate) enum HandlerOutcome {
    /// One response message.
    Respond(DnsMessage),
    /// Several response messages for one query (AXFR/IXFR on stream
    /// transports). Never empty.
    Sequence(Vec<DnsMessage>),
    /// Not this handler's business; try the next handler in a chain.
    ///
    /// For a QUERY the shell falls back to an empty `NOERROR`; for another
    /// opcode it falls back to `NOTIMP`.
    Decline,
    /// Answer with this rcode and nothing else.
    Error(u16),
}

impl HandlerOutcome {
    /// Complete `callback` with this outcome.
    pub(crate) fn deliver(self, callback: DnsQueryCallback) {
        callback.complete(self);
    }
}

type Completion = Box<dyn FnOnce(HandlerOutcome) + Send>;

/// How a handler reports its decision for one message.
///
/// An owned, `Send` value with consuming methods: **exactly one** of
/// [`respond`](Self::respond), [`respond_sequence`](Self::respond_sequence),
/// [`decline`](Self::decline) and [`error`](Self::error) must be called on it,
/// once. It may be moved to another thread and completed there; the shell
/// then delivers the response on the connection's own reactor, so a handler
/// never writes to a connection itself. If it is dropped without being
/// completed, the drop is logged and the query is answered `SERVFAIL`.
#[must_use = "a DnsQueryCallback must be completed with respond, respond_sequence, decline or error"]
pub struct DnsQueryCallback {
    done: Option<Completion>,
}

impl DnsQueryCallback {
    pub(crate) fn new(done: impl FnOnce(HandlerOutcome) + Send + 'static) -> Self {
        Self {
            done: Some(Box::new(done)),
        }
    }

    pub(crate) fn complete(mut self, outcome: HandlerOutcome) {
        if let Some(done) = self.done.take() {
            done(outcome);
        }
    }

    /// Answer with one message. Build it with [`DnsMessage::response_template`].
    pub fn respond(self, response: DnsMessage) {
        self.complete(HandlerOutcome::Respond(response));
    }

    /// Answer with several messages (AXFR/IXFR, RFC 5936 §2.2). On a
    /// transport that cannot carry more than one (UDP) only the first is
    /// sent; an empty list is a [`decline`](Self::decline).
    pub fn respond_sequence(self, responses: Vec<DnsMessage>) {
        if responses.is_empty() {
            self.decline();
        } else {
            self.complete(HandlerOutcome::Sequence(responses));
        }
    }

    /// Not this handler's business: offer the message to the next handler in
    /// a chain. With none left, a QUERY is answered with an empty `NOERROR`
    /// and any other opcode with `NOTIMP`.
    pub fn decline(self) {
        self.complete(HandlerOutcome::Decline);
    }

    /// Answer with `rcode` (for example `SERVFAIL`) and no records.
    pub fn error(self, rcode: u16) {
        self.complete(HandlerOutcome::Error(rcode));
    }
}

impl Drop for DnsQueryCallback {
    fn drop(&mut self) {
        if let Some(done) = self.done.take() {
            hopf_core::subsystem_log(
                hopf_core::LogLevel::Error,
                "hopf-dns",
                "server.callback.dropped",
                "a DnsQueryCallback was dropped without being completed; answering SERVFAIL",
            );
            done(HandlerOutcome::Error(crate::wire::RCODE_SERVFAIL));
        }
    }
}

/// Resolves or declines DNS messages. See the module documentation above.
///
/// Every method that handles a message completes the [`DnsQueryCallback`] it
/// is given, exactly once, before or after returning. Handlers with nothing
/// to wait for can implement [`SyncDnsQueryHandler`] instead.
pub trait DnsQueryHandler: Send + Sync {
    /// Handle a standard `QUERY` (opcode 0) with a non-empty question
    /// section. Build responses with [`DnsMessage::response_template`].
    fn handle_query(&self, query: &DnsMessage, ctx: &QueryContext, callback: DnsQueryCallback);

    /// Handle a request whose opcode is not `QUERY`: NOTIFY (RFC 1996),
    /// UPDATE (RFC 2136) and the rest. Decline (the default) to leave it to
    /// the next handler, or `NOTIMP`.
    ///
    /// Only requests reach this method: a message with QR set is a response,
    /// refused by the shell. Update sections arrive in the question (zone),
    /// answer (prerequisite), authority (update) and additional fields, with
    /// the RFC 2136 `NONE` class (254) preserved in each record's `raw_class`.
    fn handle_non_query_opcode(
        &self,
        query: &DnsMessage,
        ctx: &QueryContext,
        callback: DnsQueryCallback,
    ) {
        let _ = (query, ctx);
        callback.decline();
    }

    /// Acquire resources (background refresh, persistence). Called by
    /// [`DnsService::start`](super::DnsService::start) before listeners are
    /// bound.
    fn start(&self, rt: &Runtime) -> io::Result<()> {
        let _ = rt;
        Ok(())
    }

    /// Release resources. Called by
    /// [`DnsService::stop`](super::DnsService::stop).
    fn stop(&self) {}
}

impl<T: DnsQueryHandler + ?Sized> DnsQueryHandler for Arc<T> {
    fn handle_query(&self, query: &DnsMessage, ctx: &QueryContext, callback: DnsQueryCallback) {
        (**self).handle_query(query, ctx, callback)
    }
    fn handle_non_query_opcode(
        &self,
        query: &DnsMessage,
        ctx: &QueryContext,
        callback: DnsQueryCallback,
    ) {
        (**self).handle_non_query_opcode(query, ctx, callback)
    }
    fn start(&self, rt: &Runtime) -> io::Result<()> {
        (**self).start(rt)
    }
    fn stop(&self) {
        (**self).stop()
    }
}

/// A handler whose answer is known by the time it returns: a table lookup, a
/// closure, a computed reply.
///
/// Implementing this is all it takes; a blanket impl adapts it to
/// [`DnsQueryHandler`], answering (or declining) inline with no extra hop.
/// Reach for [`DnsQueryHandler`] directly only to wait on I/O.
pub trait SyncDnsQueryHandler: Send + Sync {
    /// Answer a standard `QUERY`, or `None` to decline.
    fn resolve(&self, query: &DnsMessage, ctx: &QueryContext) -> Option<DnsMessage>;

    /// Answer a request whose opcode is not `QUERY` (NOTIFY, UPDATE, ...), or
    /// `None` (the default) to decline.
    fn resolve_non_query_opcode(
        &self,
        query: &DnsMessage,
        ctx: &QueryContext,
    ) -> Option<DnsMessage> {
        let _ = (query, ctx);
        None
    }
}

impl<T: SyncDnsQueryHandler> DnsQueryHandler for T {
    fn handle_query(&self, query: &DnsMessage, ctx: &QueryContext, callback: DnsQueryCallback) {
        match self.resolve(query, ctx) {
            Some(response) => callback.respond(response),
            None => callback.decline(),
        }
    }

    fn handle_non_query_opcode(
        &self,
        query: &DnsMessage,
        ctx: &QueryContext,
        callback: DnsQueryCallback,
    ) {
        match self.resolve_non_query_opcode(query, ctx) {
            Some(response) => callback.respond(response),
            None => callback.decline(),
        }
    }
}

/// The default handler: `NOERROR` with an empty answer section.
#[derive(Debug, Clone, Copy, Default)]
pub struct EmptyHandler;

impl SyncDnsQueryHandler for EmptyHandler {
    fn resolve(&self, query: &DnsMessage, _ctx: &QueryContext) -> Option<DnsMessage> {
        Some(query.response_template(crate::wire::RCODE_NOERROR))
    }
}

type QueryFn = dyn Fn(&DnsMessage, &QueryContext) -> Option<DnsMessage> + Send + Sync;
type OpcodeFn = dyn Fn(&DnsMessage, &QueryContext) -> Option<DnsMessage> + Send + Sync;

/// Closure-backed handler for tests and small local overrides.
///
/// Each closure returns `Some(response)` to answer or `None` to decline, so
/// an `FnHandler` chained ahead of a forwarder overrides selected names.
#[derive(Default)]
pub struct FnHandler {
    query: Option<Box<QueryFn>>,
    opcode: Option<Box<OpcodeFn>>,
}

impl FnHandler {
    /// A handler that declines everything until closures are attached.
    pub fn new() -> Self {
        Self::default()
    }

    /// Answer standard queries.
    pub fn on_query<F>(self, f: F) -> Self
    where
        F: Fn(&DnsMessage) -> Option<DnsMessage> + Send + Sync + 'static,
    {
        self.on_query_ctx(move |query, _ctx| f(query))
    }

    /// Answer standard queries, with the [`QueryContext`] (peer, local
    /// address, transport, TLS identity) alongside the message.
    pub fn on_query_ctx<F>(mut self, f: F) -> Self
    where
        F: Fn(&DnsMessage, &QueryContext) -> Option<DnsMessage> + Send + Sync + 'static,
    {
        self.query = Some(Box::new(f));
        self
    }

    /// Answer messages whose opcode is not QUERY (NOTIFY, UPDATE, ...). The
    /// closure receives the peer's address.
    pub fn on_opcode<F>(self, f: F) -> Self
    where
        F: Fn(&DnsMessage, SocketAddr) -> Option<DnsMessage> + Send + Sync + 'static,
    {
        self.on_opcode_ctx(move |query, ctx| f(query, ctx.peer()))
    }

    /// Answer messages whose opcode is not QUERY, with the full
    /// [`QueryContext`].
    pub fn on_opcode_ctx<F>(mut self, f: F) -> Self
    where
        F: Fn(&DnsMessage, &QueryContext) -> Option<DnsMessage> + Send + Sync + 'static,
    {
        self.opcode = Some(Box::new(f));
        self
    }
}

impl SyncDnsQueryHandler for FnHandler {
    fn resolve(&self, query: &DnsMessage, ctx: &QueryContext) -> Option<DnsMessage> {
        self.query.as_ref().and_then(|f| f(query, ctx))
    }

    fn resolve_non_query_opcode(&self, query: &DnsMessage, ctx: &QueryContext) -> Option<DnsMessage> {
        self.opcode.as_ref().and_then(|f| f(query, ctx))
    }
}

/// Tries handlers in order; the first that does not decline answers.
///
/// Each handler is given a callback whose `decline` offers the message to the
/// next, so a handler that goes asynchronous does not hold up the chain's
/// bookkeeping and the later handlers still run when it declines.
#[derive(Default)]
pub struct ChainHandler {
    handlers: Arc<Vec<Arc<dyn DnsQueryHandler>>>,
}

#[derive(Clone, Copy)]
enum Dispatch {
    Query,
    NonQuery,
}

impl ChainHandler {
    /// An empty chain (declines everything).
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a handler.
    pub fn then<H: DnsQueryHandler + 'static>(mut self, handler: H) -> Self {
        Arc::make_mut(&mut self.handlers).push(Arc::new(handler));
        self
    }

    fn run(
        handlers: Arc<Vec<Arc<dyn DnsQueryHandler>>>,
        index: usize,
        kind: Dispatch,
        query: Arc<DnsMessage>,
        ctx: QueryContext,
        callback: DnsQueryCallback,
    ) {
        let Some(handler) = handlers.get(index).cloned() else {
            callback.decline();
            return;
        };
        let next = {
            let (handlers, query, ctx) = (Arc::clone(&handlers), Arc::clone(&query), ctx.clone());
            DnsQueryCallback::new(move |outcome| match outcome {
                HandlerOutcome::Decline => Self::run(handlers, index + 1, kind, query, ctx, callback),
                other => callback.complete(other),
            })
        };
                match kind {
            Dispatch::Query => handler.handle_query(&query, &ctx, next),
            Dispatch::NonQuery => handler.handle_non_query_opcode(&query, &ctx, next),
        }
    }

    fn dispatch(
        &self,
        kind: Dispatch,
        query: &DnsMessage,
        ctx: &QueryContext,
        callback: DnsQueryCallback,
    ) {
        Self::run(
            Arc::clone(&self.handlers),
            0,
            kind,
            Arc::new(query.clone()),
            ctx.clone(),
            callback,
        );
    }
}

impl DnsQueryHandler for ChainHandler {
    fn handle_query(&self, query: &DnsMessage, ctx: &QueryContext, callback: DnsQueryCallback) {
        self.dispatch(Dispatch::Query, query, ctx, callback);
    }

    fn handle_non_query_opcode(
        &self,
        query: &DnsMessage,
        ctx: &QueryContext,
        callback: DnsQueryCallback,
    ) {
        self.dispatch(Dispatch::NonQuery, query, ctx, callback);
    }

    fn start(&self, rt: &Runtime) -> io::Result<()> {
        for (i, h) in self.handlers.iter().enumerate() {
            if let Err(e) = h.start(rt) {
                // Unwind the handlers already started.
                for started in self.handlers[..i].iter().rev() {
                    started.stop();
                }
                return Err(e);
            }
        }
        Ok(())
    }

    fn stop(&self) {
        for h in self.handlers.iter().rev() {
            h.stop();
        }
    }
}
