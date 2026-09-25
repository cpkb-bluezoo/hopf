// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Caching forwarder handler.

use std::sync::Arc;

use super::handler::{DnsQueryHandler, HandlerOutcome, QueryContext};
use crate::cache::DnsCache;
use crate::client::DnsResolver;
use crate::wire::{DnsMessage, DnsType, RCODE_NXDOMAIN, RCODE_SERVFAIL};

/// Answers from a shared [`DnsCache`], forwarding misses to an upstream
/// [`DnsResolver`]. With no upstream a miss is `SERVFAIL`.
///
/// This never declines, so in a [`ChainHandler`](super::ChainHandler) it
/// belongs last.
pub struct ForwarderHandler {
    cache: Arc<DnsCache>,
    upstream: Option<DnsResolver>,
}

impl ForwarderHandler {
    /// New forwarder over `cache`.
    pub fn new(cache: Arc<DnsCache>) -> Self {
        Self {
            cache,
            upstream: None,
        }
    }

    /// Attach the upstream stub resolver misses are forwarded to.
    pub fn with_upstream(mut self, resolver: DnsResolver) -> Self {
        self.upstream = Some(resolver);
        self
    }

    /// Shared cache.
    pub fn cache(&self) -> &Arc<DnsCache> {
        &self.cache
    }
}

impl DnsQueryHandler for ForwarderHandler {
    fn handle_query(&self, query: &DnsMessage, ctx: &QueryContext<'_>) -> HandlerOutcome {
        let q = &query.questions[0];

        if self.cache.is_negatively_cached(&q.name) {
            ctx.metrics.cache_hit();
            return HandlerOutcome::Respond(query.response_template(RCODE_NXDOMAIN));
        }
        if self.cache.is_nodata_cached(q) {
            // RFC 2308 §2 NODATA: NOERROR with an empty answer set, not NXDOMAIN.
            ctx.metrics.cache_hit();
            return HandlerOutcome::Respond(query.response_template(0));
        }
        if let Some(answers) = self.cache.lookup(q) {
            ctx.metrics.cache_hit();
            let mut resp = query.response_template(0);
            resp.answers = answers;
            return HandlerOutcome::Respond(resp);
        }

        // Sync upstream via TCP fallback path when resolver available - for UDP
        // server we use blocking TCP to upstream as a pragmatic Stage-D forward.
        let Some(ref upstream) = self.upstream else {
            return HandlerOutcome::Respond(query.response_template(RCODE_SERVFAIL));
        };
        ctx.metrics.upstream();
        let (tx, rx) = std::sync::mpsc::channel();
        upstream.query_with_cd(
            q.clone(),
            query.is_checking_disabled(),
            Box::new(move |r| {
                let _ = tx.send(r);
            }),
        );
        match rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(Ok(mut resp)) => {
                resp.id = query.id;
                if !query.has_do() {
                    // Strip DNSSEC RRs when the client lacks DO (RFC 4035 §3.2.1).
                    resp.answers.retain(|rr| {
                        !matches!(
                            rr.rtype,
                            Some(DnsType::Rrsig)
                                | Some(DnsType::Nsec)
                                | Some(DnsType::Nsec3)
                                | Some(DnsType::Dnskey)
                                | Some(DnsType::Ds)
                        )
                    });
                }
                self.cache.put_response(&resp);
                HandlerOutcome::Respond(resp)
            }
            _ => {
                ctx.metrics.error();
                HandlerOutcome::Respond(query.response_template(RCODE_SERVFAIL))
            }
        }
    }
}
