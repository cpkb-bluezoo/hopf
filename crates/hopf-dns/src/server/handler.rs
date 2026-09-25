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

use hopf_core::Runtime;

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
pub struct MetricsSink<'a>(pub(super) &'a Mutex<DnsServerMetrics>);

impl MetricsSink<'_> {
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

/// Per-message context supplied by the shell.
pub struct QueryContext<'a> {
    /// The peer's address. An UPDATE or transfer handler needs the source to
    /// authorise the request.
    pub peer: SocketAddr,
    /// Transport the message arrived on.
    pub transport: DnsTransport,
    /// Name of the TSIG key (RFC 8945) that authenticated this message, if
    /// it carried a valid signature. A signature that fails to verify never
    /// reaches a handler.
    pub tsig_key: Option<&'a str>,
    /// Shell counters.
    pub metrics: MetricsSink<'a>,
}

/// What a handler decided.
#[derive(Debug, Clone)]
pub enum HandlerOutcome {
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
}

/// Resolves or declines DNS messages. See the module documentation above.
///
/// Handlers run on the listener's thread and should not block, with the
/// long-standing exception of [`ForwarderHandler`](super::ForwarderHandler),
/// which waits (bounded) for its upstream.
pub trait DnsQueryHandler: Send + Sync {
    /// Handle a standard `QUERY` (opcode 0) with a non-empty question
    /// section. Build responses with [`DnsMessage::response_template`].
    fn handle_query(&self, query: &DnsMessage, ctx: &QueryContext<'_>) -> HandlerOutcome;

    /// Handle a request whose opcode is not `QUERY`: NOTIFY (RFC 1996),
    /// UPDATE (RFC 2136) and the rest. Return [`HandlerOutcome::Decline`]
    /// (the default) to leave it to the next handler, or `NOTIMP`.
    ///
    /// Only requests reach this method: a message with QR set is a response,
    /// refused by the shell. Update sections arrive in the question (zone),
    /// answer (prerequisite), authority (update) and additional fields, with
    /// the RFC 2136 `NONE` class (254) preserved in each record's `raw_class`.
    fn handle_non_query_opcode(
        &self,
        query: &DnsMessage,
        ctx: &QueryContext<'_>,
    ) -> HandlerOutcome {
        let _ = (query, ctx);
        HandlerOutcome::Decline
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
    fn handle_query(&self, query: &DnsMessage, ctx: &QueryContext<'_>) -> HandlerOutcome {
        (**self).handle_query(query, ctx)
    }
    fn handle_non_query_opcode(
        &self,
        query: &DnsMessage,
        ctx: &QueryContext<'_>,
    ) -> HandlerOutcome {
        (**self).handle_non_query_opcode(query, ctx)
    }
    fn start(&self, rt: &Runtime) -> io::Result<()> {
        (**self).start(rt)
    }
    fn stop(&self) {
        (**self).stop()
    }
}

/// The default handler: `NOERROR` with an empty answer section.
#[derive(Debug, Clone, Copy, Default)]
pub struct EmptyHandler;

impl DnsQueryHandler for EmptyHandler {
    fn handle_query(&self, query: &DnsMessage, _ctx: &QueryContext<'_>) -> HandlerOutcome {
        HandlerOutcome::Respond(query.response_template(crate::wire::RCODE_NOERROR))
    }
}

type QueryFn = dyn Fn(&DnsMessage) -> Option<DnsMessage> + Send + Sync;
type OpcodeFn = dyn Fn(&DnsMessage, SocketAddr) -> Option<DnsMessage> + Send + Sync;

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
    pub fn on_query<F>(mut self, f: F) -> Self
    where
        F: Fn(&DnsMessage) -> Option<DnsMessage> + Send + Sync + 'static,
    {
        self.query = Some(Box::new(f));
        self
    }

    /// Answer messages whose opcode is not QUERY (NOTIFY, UPDATE, ...). The
    /// closure receives the peer's address.
    pub fn on_opcode<F>(mut self, f: F) -> Self
    where
        F: Fn(&DnsMessage, SocketAddr) -> Option<DnsMessage> + Send + Sync + 'static,
    {
        self.opcode = Some(Box::new(f));
        self
    }
}

impl DnsQueryHandler for FnHandler {
    fn handle_query(&self, query: &DnsMessage, _ctx: &QueryContext<'_>) -> HandlerOutcome {
        match self.query.as_ref().and_then(|f| f(query)) {
            Some(resp) => HandlerOutcome::Respond(resp),
            None => HandlerOutcome::Decline,
        }
    }

    fn handle_non_query_opcode(
        &self,
        query: &DnsMessage,
        ctx: &QueryContext<'_>,
    ) -> HandlerOutcome {
        match self.opcode.as_ref().and_then(|f| f(query, ctx.peer)) {
            Some(resp) => HandlerOutcome::Respond(resp),
            None => HandlerOutcome::Decline,
        }
    }
}

/// Tries handlers in order; the first that does not decline answers.
#[derive(Default)]
pub struct ChainHandler {
    handlers: Vec<Arc<dyn DnsQueryHandler>>,
}

impl ChainHandler {
    /// An empty chain (declines everything).
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a handler.
    pub fn then<H: DnsQueryHandler + 'static>(mut self, handler: H) -> Self {
        self.handlers.push(Arc::new(handler));
        self
    }
}

impl DnsQueryHandler for ChainHandler {
    fn handle_query(&self, query: &DnsMessage, ctx: &QueryContext<'_>) -> HandlerOutcome {
        for h in &self.handlers {
            match h.handle_query(query, ctx) {
                HandlerOutcome::Decline => continue,
                other => return other,
            }
        }
        HandlerOutcome::Decline
    }

    fn handle_non_query_opcode(
        &self,
        query: &DnsMessage,
        ctx: &QueryContext<'_>,
    ) -> HandlerOutcome {
        for h in &self.handlers {
            match h.handle_non_query_opcode(query, ctx) {
                HandlerOutcome::Decline => continue,
                other => return other,
            }
        }
        HandlerOutcome::Decline
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
