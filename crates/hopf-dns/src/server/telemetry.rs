// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The server shell's side of [`DnsServerTelemetry`]: every place it bumps one
//! of its [`DnsServerMetrics`](super::DnsServerMetrics) snapshot counters also
//! reports here, with the transport the message arrived on. With nothing
//! attached ([`DnsService::set_telemetry`](super::DnsService::set_telemetry))
//! every call does nothing.

use std::sync::Arc;
use std::time::Duration;

use super::DnsTransport;
use crate::telemetry::DnsServerTelemetry;

/// Where the server's points go, if anywhere. Cheap to clone.
#[derive(Clone, Default)]
pub(crate) struct Telemetry(Option<Arc<dyn DnsServerTelemetry>>);

impl Telemetry {
    pub(crate) fn new(sink: Arc<dyn DnsServerTelemetry>) -> Self {
        Self(Some(sink))
    }

    /// Whether points are being exported.
    pub(crate) fn enabled(&self) -> bool {
        self.0.is_some()
    }

    fn with(&self, f: impl FnOnce(&dyn DnsServerTelemetry)) {
        if let Some(sink) = &self.0 {
            f(sink.as_ref());
        }
    }

    pub(crate) fn query(&self, t: DnsTransport) {
        self.with(|s| s.query_received(t.as_str()));
    }

    pub(crate) fn response(&self, t: DnsTransport, rcode: u16, took: Duration) {
        self.with(|s| s.response_sent(t.as_str(), rcode, took));
    }

    pub(crate) fn cache_hit(&self, t: DnsTransport) {
        self.with(|s| s.cache_hit(t.as_str()));
    }

    pub(crate) fn upstream(&self, t: DnsTransport) {
        self.with(|s| s.upstream_query(t.as_str()));
    }

    pub(crate) fn stale_served(&self, t: DnsTransport) {
        self.with(|s| s.stale_served(t.as_str()));
    }

    pub(crate) fn aggressive_nsec(&self, t: DnsTransport) {
        self.with(|s| s.aggressive_nsec_hit(t.as_str()));
    }

    pub(crate) fn error(&self, t: DnsTransport) {
        self.with(|s| s.error(t.as_str()));
    }

    pub(crate) fn cookie(&self, t: DnsTransport, verified: bool) {
        self.with(|s| {
            s.cookie_presented(t.as_str());
            if verified {
                s.cookie_verified(t.as_str());
            }
        });
    }

    pub(crate) fn in_flight(&self, t: DnsTransport, total: i64) {
        self.with(|s| s.in_flight(t.as_str(), total));
    }

    pub(crate) fn backpressure(&self, t: DnsTransport) {
        self.with(|s| s.backpressure(t.as_str()));
    }

    pub(crate) fn multi_qtype(&self, t: DnsTransport, subqueries: u64) {
        self.with(|s| s.multi_qtype(t.as_str(), subqueries));
    }
}
