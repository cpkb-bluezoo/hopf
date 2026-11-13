// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Hooks for exporting what the DNS server and the upstream client count.
//!
//! These traits are how `hopf-dns` reports without depending on an exporter:
//! `hopf-otel` implements them for its DNS metrics, so with a
//! `hopf_otel::TelemetryPipeline` in hand
//!
//! ```ignore
//! service.set_telemetry(pipeline.dns_metrics());
//! upstream.set_telemetry(pipeline.dns_upstream_metrics());
//! ```
//!
//! exports them over OTLP/JSONL. Any other sink can implement the traits.
//! Methods are called on the thread that did the work (a reactor, a handler's
//! thread, a QUIC driver) and must return quickly and never block: an exporter
//! should only enqueue.
//!
//! The transport arguments are `udp`, `tcp`, `dot` or `doq`.

use std::time::Duration;

/// What the DNS server shell reports. Every method has the transport the
/// message arrived on.
pub trait DnsServerTelemetry: Send + Sync {
    /// A message was received.
    fn query_received(&self, transport: &str);
    /// The answer to a message is ready, `duration` after it arrived, with
    /// this response code.
    fn response_sent(&self, transport: &str, rcode: u16, duration: Duration);
    /// An answer was served from the cache.
    fn cache_hit(&self, transport: &str);
    /// A query was forwarded to an upstream.
    fn upstream_query(&self, transport: &str);
    /// An answer was served stale (RFC 8767) because the upstream failed.
    fn stale_served(&self, transport: &str);
    /// A negative answer was built from cached NSEC/NSEC3 proofs (RFC 8198).
    fn aggressive_nsec_hit(&self, transport: &str);
    /// A handler error.
    fn error(&self, transport: &str);
    /// A query carried a DNS Cookie (RFC 7873).
    fn cookie_presented(&self, transport: &str);
    /// A presented server cookie was verified.
    fn cookie_verified(&self, transport: &str);
    /// A multiple-QTYPE query (RFC 10029) was acted on and expanded into
    /// `subqueries` queries for the handler (none if it could not be).
    fn multi_qtype(&self, transport: &str, subqueries: u64);
}

/// A counted event of an upstream client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UpstreamEvent {
    /// A query was accepted.
    Query,
    /// A query timed out.
    Timeout,
    /// A query failed for another reason.
    Failure,
    /// A query was sent again on a new connection after a loss.
    Retry,
    /// A connection was established.
    Connect,
    /// A connection did not come up.
    ConnectFailure,
    /// A connection was dialled after an earlier one had been established.
    Reconnect,
}

/// What an upstream client reports. `upstream` is the resolver's address.
pub trait DnsUpstreamTelemetry: Send + Sync {
    /// Something happened.
    fn event(&self, upstream: &str, transport: &str, event: UpstreamEvent);
    /// An answer arrived `duration` after the query was made.
    fn response(&self, upstream: &str, transport: &str, duration: Duration);
    /// The number of open connections (the pool size) is now `value`.
    fn connections(&self, upstream: &str, transport: &str, value: i64);
    /// The number of queries sent or waiting, not yet completed, is now `value`.
    fn in_flight(&self, upstream: &str, transport: &str, value: i64);
}
