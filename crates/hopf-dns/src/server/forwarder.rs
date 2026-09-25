// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Caching forwarder handler.
//!
//! Beyond plain caching it applies three resolver behaviours that the RFCs
//! recommend but do not require. Each is a policy the deployment can replace
//! or disable (see [`policy`](super::policy)):
//!
//! * **RFC 8767 Serve-Stale** - when the upstream cannot be reached, an
//!   expired positive answer still inside the cache's stale window is served
//!   with a short TTL instead of `SERVFAIL`, and the refresh carries on in the
//!   background so the next query finds fresh data once the upstream is back.
//! * **RFC 8020 NXDOMAIN cut** - a cached NXDOMAIN answers queries for every
//!   name beneath it.
//! * **RFC 8482 minimal `ANY`** - an `ANY` answer is reduced to one synthesised
//!   `HINFO` record.
//! * **RFC 8198 aggressive NSEC/NSEC3** (feature `dnssec`) - while the upstream
//!   resolver validates DNSSEC, a negative answer whose denial it has verified
//!   is remembered as a proof, and later queries the proof covers are answered
//!   locally.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::handler::{DnsQueryHandler, HandlerOutcome, QueryContext};
use super::minimal_any::{MinimalAnyEnabled, MinimalAnyPolicy};
#[cfg(feature = "dnssec")]
use super::policy::{AggressiveNsecEnabled, AggressiveNsecPolicy};
use super::policy::{NxdomainCutEnabled, NxdomainCutPolicy, ServeStale, StalePolicy};
use crate::cache::DnsCache;
use crate::client::DnsResolver;
use crate::wire::{normalize_name, DnsMessage, DnsQuestion, DnsResourceRecord, DnsType, RCODE_NXDOMAIN, RCODE_SERVFAIL};

/// How long to wait for the upstream when there is nothing stale to fall back
/// on.
const DEFAULT_UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);
/// RFC 8767 §5's client response timer: how long to wait for the upstream
/// before answering from stale data instead (it suggests 1.8 s, just under a
/// common 2 s client timeout). The query itself keeps running.
const DEFAULT_CLIENT_RESPONSE_TIMER: Duration = Duration::from_millis(1800);
/// RFC 8767 §5's failure recheck timer: after a failed lookup, serve stale
/// without re-asking for this long (it recommends no more often than 30 s).
const DEFAULT_FAILURE_RECHECK: Duration = Duration::from_secs(30);
/// TTL of the synthesised HINFO (RFC 8482 §4.2 leaves it to the operator).
const DEFAULT_MINIMAL_ANY_TTL: u32 = 3600;
/// Bound on remembered failures; older ones are pruned first.
const MAX_TRACKED_FAILURES: usize = 4096;

type Failures = Arc<Mutex<HashMap<String, Instant>>>;

/// Answers from a shared [`DnsCache`], forwarding misses to an upstream
/// [`DnsResolver`]. With no upstream a miss is `SERVFAIL` (or a stale answer,
/// if the policy allows one).
///
/// This never declines, so in a [`ChainHandler`](super::ChainHandler) it
/// belongs last.
pub struct ForwarderHandler {
    cache: Arc<DnsCache>,
    upstream: Option<DnsResolver>,
    stale: Box<dyn StalePolicy>,
    nxdomain_cut: Box<dyn NxdomainCutPolicy>,
    minimal_any: Box<dyn MinimalAnyPolicy>,
    #[cfg(feature = "dnssec")]
    aggressive_nsec: Box<dyn AggressiveNsecPolicy>,
    minimal_any_ttl: u32,
    upstream_timeout: Duration,
    client_response_timer: Duration,
    failure_recheck: Duration,
    failures: Failures,
}

impl ForwarderHandler {
    /// New forwarder over `cache`, with RFC 8767 Serve-Stale, the RFC 8020
    /// NXDOMAIN cut and RFC 8482 minimal `ANY` all enabled on their
    /// recommended terms.
    pub fn new(cache: Arc<DnsCache>) -> Self {
        Self {
            cache,
            upstream: None,
            stale: Box::new(ServeStale::default()),
            nxdomain_cut: Box::new(NxdomainCutEnabled),
            minimal_any: Box::new(MinimalAnyEnabled),
            #[cfg(feature = "dnssec")]
            aggressive_nsec: Box::new(AggressiveNsecEnabled),
            minimal_any_ttl: DEFAULT_MINIMAL_ANY_TTL,
            upstream_timeout: DEFAULT_UPSTREAM_TIMEOUT,
            client_response_timer: DEFAULT_CLIENT_RESPONSE_TIMER,
            failure_recheck: DEFAULT_FAILURE_RECHECK,
            failures: Arc::default(),
        }
    }

    /// Attach the upstream stub resolver misses are forwarded to.
    pub fn with_upstream(mut self, resolver: DnsResolver) -> Self {
        self.upstream = Some(resolver);
        self
    }

    /// Replace the Serve-Stale policy (RFC 8767); see [`StalePolicy`]. Use
    /// [`ServeStaleDisabled`](super::ServeStaleDisabled) to turn it off.
    pub fn with_stale_policy(mut self, policy: impl StalePolicy + 'static) -> Self {
        self.stale = Box::new(policy);
        self
    }

    /// Replace the NXDOMAIN-cut policy (RFC 8020); see [`NxdomainCutPolicy`].
    pub fn with_nxdomain_cut_policy(mut self, policy: impl NxdomainCutPolicy + 'static) -> Self {
        self.nxdomain_cut = Box::new(policy);
        self
    }

    /// Replace the minimal-`ANY` policy (RFC 8482); see [`MinimalAnyPolicy`].
    pub fn with_minimal_any_policy(mut self, policy: impl MinimalAnyPolicy + 'static) -> Self {
        self.minimal_any = Box::new(policy);
        self
    }

    /// Replace the aggressive-NSEC policy (RFC 8198); see
    /// [`AggressiveNsecPolicy`]. It has an effect only while the upstream
    /// resolver has DNSSEC validation enabled.
    #[cfg(feature = "dnssec")]
    pub fn with_aggressive_nsec_policy(mut self, policy: impl AggressiveNsecPolicy + 'static) -> Self {
        self.aggressive_nsec = Box::new(policy);
        self
    }

    /// TTL of the synthesised `HINFO` record (default 3600 s).
    pub fn with_minimal_any_ttl(mut self, ttl: u32) -> Self {
        self.minimal_any_ttl = ttl;
        self
    }

    /// How long to wait for the upstream when there is no stale answer to fall
    /// back on (default 5 s).
    pub fn with_upstream_timeout(mut self, timeout: Duration) -> Self {
        self.upstream_timeout = timeout;
        self
    }

    /// How long to wait for the upstream before answering from stale data
    /// (RFC 8767 §5's client response timer, default 1.8 s). The upstream
    /// query is not abandoned: a late answer still refreshes the cache.
    pub fn with_client_response_timer(mut self, timer: Duration) -> Self {
        self.client_response_timer = timer;
        self
    }

    /// After a failed lookup, serve stale for this long without asking the
    /// upstream again (RFC 8767 §5's failure recheck timer, default 30 s).
    pub fn with_failure_recheck(mut self, interval: Duration) -> Self {
        self.failure_recheck = interval;
        self
    }

    /// Shared cache.
    pub fn cache(&self) -> &Arc<DnsCache> {
        &self.cache
    }

    fn failure_key(q: &DnsQuestion) -> String {
        format!("{}/{}/{}", normalize_name(&q.name), q.raw_qtype, q.raw_qclass)
    }

    fn recently_failed(&self, q: &DnsQuestion) -> bool {
        if self.failure_recheck.is_zero() {
            return false;
        }
        let failures = self.failures.lock().unwrap();
        failures
            .get(&Self::failure_key(q))
            .is_some_and(|at| at.elapsed() < self.failure_recheck)
    }

    fn note_failure(&self, q: &DnsQuestion) {
        let mut failures = self.failures.lock().unwrap();
        if failures.len() >= MAX_TRACKED_FAILURES {
            let horizon = self.failure_recheck;
            failures.retain(|_, at| at.elapsed() < horizon);
            if failures.len() >= MAX_TRACKED_FAILURES {
                failures.clear();
            }
        }
        failures.insert(Self::failure_key(q), Instant::now());
    }

    fn respond_stale(query: &DnsMessage, ctx: &QueryContext<'_>, answers: Vec<DnsResourceRecord>) -> HandlerOutcome {
        ctx.metrics.stale_served();
        let mut resp = query.response_template(0);
        resp.answers = answers;
        HandlerOutcome::Respond(resp)
    }
}

/// Strip DNSSEC records a client that did not set DO must not see (RFC 4035
/// §3.2.1).
fn strip_dnssec(resp: &mut DnsMessage) {
    resp.answers.retain(|rr| {
        !matches!(
            rr.rtype,
            Some(DnsType::Rrsig) | Some(DnsType::Nsec) | Some(DnsType::Nsec3) | Some(DnsType::Dnskey) | Some(DnsType::Ds)
        )
    });
}

/// RFC 8482 §4.2: reduce an existing name's `ANY` answer to one synthesised
/// `HINFO "RFC8482" ""`. `NXDOMAIN`, `NODATA` and errors are left alone, so
/// non-existence is still reported truthfully.
fn minimise_any(resp: &mut DnsMessage, q: &DnsQuestion, ttl: u32) {
    if resp.rcode() != 0 || resp.answers.is_empty() {
        return;
    }
    let Some(hinfo) = DnsResourceRecord::hinfo(&q.name, ttl, "RFC8482", "") else {
        return;
    };
    resp.answers = vec![hinfo];
    resp.authorities.clear();
    resp.additionals.retain(|rr| rr.rtype == Some(DnsType::Opt));
}

/// Remember the NSEC/NSEC3 proof in a negative response for RFC 8198, but only
/// once the resolver has verified it: the denial is validated up its own chain
/// of trust in the background, and a proof that does not come out `Secure` is
/// discarded. The client's own answer never waits for this.
#[cfg(feature = "dnssec")]
fn learn_denial(resolver: &DnsResolver, cache: &Arc<DnsCache>, q: &DnsQuestion, resp: &DnsMessage) {
    let negative = resp.rcode() == RCODE_NXDOMAIN || (resp.rcode() == 0 && resp.answers.is_empty());
    let proof = resp.authorities.iter().any(|rr| matches!(rr.rtype, Some(DnsType::Nsec | DnsType::Nsec3)));
    let Some(qtype) = q.qtype else {
        return;
    };
    if !negative || !proof {
        return;
    }
    let cache = Arc::clone(cache);
    resolver.validate_denial_of_existence(
        &q.name,
        qtype,
        resp.clone(),
        Box::new(move |msg, status| {
            if status == crate::dnssec::DnssecStatus::Secure {
                cache.denials().store_validated(&msg);
            }
        }),
    );
}

impl DnsQueryHandler for ForwarderHandler {
    fn handle_query(&self, query: &DnsMessage, ctx: &QueryContext<'_>) -> HandlerOutcome {
        let q = &query.questions[0];

        if self.cache.is_negatively_cached(&q.name) {
            ctx.metrics.cache_hit();
            return HandlerOutcome::Respond(query.response_template(RCODE_NXDOMAIN));
        }
        // RFC 8020: nothing exists beneath a name that does not.
        if self.nxdomain_cut.nxdomain_cut(q) && self.cache.has_nxdomain_ancestor(&q.name) {
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

        // RFC 8198: a cached, validated NSEC/NSEC3 proof may already answer.
        #[cfg(feature = "dnssec")]
        let learn_proofs = self.upstream.as_ref().is_some_and(DnsResolver::is_dnssec_enabled)
            && self.aggressive_nsec.aggressive_nsec(q);
        #[cfg(feature = "dnssec")]
        if learn_proofs {
            if let Some(denial) = self.cache.denials().synthesize(q) {
                ctx.metrics.aggressive_nsec();
                let has_do = query.has_do();
                let mut resp = query.response_template(denial.rcode);
                resp.authorities = denial.authorities(has_do);
                if has_do {
                    // We validated these proofs when we cached them.
                    resp.flags |= crate::wire::FLAG_AD;
                }
                return HandlerOutcome::Respond(resp);
            }
        }

        // Anything expired but still inside the stale window that policy lets
        // us serve if the refresh fails.
        let stale = self
            .stale
            .stale_terms(q)
            .and_then(|t| self.cache.lookup_stale(q, t.max_age, t.answer_ttl));

        // RFC 8767 §5 failure recheck: the upstream just failed for this
        // question, so do not make the client wait for it to fail again.
        if let Some(answers) = stale.as_ref().filter(|_| self.recently_failed(q)) {
            return Self::respond_stale(query, ctx, answers.clone());
        }

        let Some(ref upstream) = self.upstream else {
            return match stale {
                Some(answers) => Self::respond_stale(query, ctx, answers),
                None => HandlerOutcome::Respond(query.response_template(RCODE_SERVFAIL)),
            };
        };

        ctx.metrics.upstream();
        let has_do = query.has_do();
        // A DNSSEC-aware client cannot verify a synthesised HINFO, so it gets
        // the full answer.
        let minimal_ttl = (q.qtype == Some(DnsType::Any) && !has_do && self.minimal_any.should_return_minimal_any(q))
            .then_some(self.minimal_any_ttl);

        let (tx, rx) = std::sync::mpsc::channel();
        // Everything that must happen whether or not anyone is still waiting -
        // caching, and clearing the failure record - happens in the callback,
        // so a late answer still refreshes the cache after a stale reply.
        let cache = Arc::clone(&self.cache);
        let failures = Arc::clone(&self.failures);
        let (id, question, key) = (query.id, q.clone(), Self::failure_key(q));
        #[cfg(feature = "dnssec")]
        let resolver = learn_proofs.then(|| upstream.clone());
        upstream.query_with_cd(
            q.clone(),
            query.is_checking_disabled(),
            Box::new(move |r| {
                let processed = r.map(|mut resp| {
                    resp.id = id;
                    if !has_do {
                        strip_dnssec(&mut resp);
                    }
                    if let Some(ttl) = minimal_ttl {
                        minimise_any(&mut resp, &question, ttl);
                    }
                    cache.put_response(&resp);
                    #[cfg(feature = "dnssec")]
                    if let Some(resolver) = resolver.as_ref() {
                        learn_denial(resolver, &cache, &question, &resp);
                    }
                    if matches!(resp.rcode(), 0 | RCODE_NXDOMAIN) {
                        failures.lock().unwrap().remove(&key);
                    }
                    resp
                });
                let _ = tx.send(processed);
            }),
        );

        // With stale data in hand there is no point waiting the full timeout.
        let wait = if stale.is_some() {
            self.client_response_timer.min(self.upstream_timeout)
        } else {
            self.upstream_timeout
        };
        match rx.recv_timeout(wait) {
            // RFC 8767 §4: only NOERROR and NXDOMAIN count as having refreshed
            // the data.
            Ok(Ok(resp)) if matches!(resp.rcode(), 0 | RCODE_NXDOMAIN) => HandlerOutcome::Respond(resp),
            Ok(Ok(resp)) => {
                self.note_failure(q);
                match stale {
                    Some(answers) => Self::respond_stale(query, ctx, answers),
                    None => HandlerOutcome::Respond(resp),
                }
            }
            _ => {
                self.note_failure(q);
                match stale {
                    Some(answers) => Self::respond_stale(query, ctx, answers),
                    None => {
                        ctx.metrics.error();
                        HandlerOutcome::Respond(query.response_template(RCODE_SERVFAIL))
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::server::{DnsService, NxdomainCutDisabled, ServeStale, ServeStaleDisabled, StaleTerms};
    use crate::wire::FLAG_QR;

    const PEER: &str = "127.0.0.1:5353";

    fn query(name: &str, qtype: DnsType) -> DnsMessage {
        DnsMessage::query(7, DnsQuestion::in_class(name, qtype), true)
    }

    fn a(name: &str) -> Vec<DnsResourceRecord> {
        vec![DnsResourceRecord::a(name, 60, Ipv4Addr::new(192, 0, 2, 7))]
    }

    /// A forwarder with no upstream, so every miss is a failed refresh.
    fn offline(cache: &Arc<DnsCache>, tune: impl FnOnce(ForwarderHandler) -> ForwarderHandler) -> DnsService {
        DnsService::with_handler(tune(ForwarderHandler::new(Arc::clone(cache))))
    }

    fn ask(service: &DnsService, name: &str, qtype: DnsType) -> DnsMessage {
        service.process_query_sync(&query(name, qtype), PEER.parse().unwrap())
    }

    // ---- RFC 8767 Serve-Stale ----

    #[test]
    fn an_expired_answer_is_served_stale_when_the_upstream_is_unreachable() {
        let cache = Arc::new(DnsCache::default());
        let q = DnsQuestion::in_class("stale.example", DnsType::A);
        cache.put_aged(&q, a("stale.example"), 60, Duration::from_secs(3600));
        let service = offline(&cache, |f| f);

        let resp = ask(&service, "stale.example", DnsType::A);
        assert_eq!(resp.rcode(), 0, "stale data instead of SERVFAIL");
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(resp.answers[0].as_a(), Some(Ipv4Addr::new(192, 0, 2, 7)));
        assert_eq!(resp.answers[0].ttl, 30, "RFC 8767 section 4: capped, non-zero TTL");
        let m = service.metrics();
        assert_eq!((m.stale_served, m.cache_hits), (1, 0), "counted apart from ordinary hits");
    }

    #[test]
    fn serve_stale_is_off_when_the_policy_says_so() {
        let cache = Arc::new(DnsCache::default());
        cache.put_aged(&DnsQuestion::in_class("s.example", DnsType::A), a("s.example"), 60, Duration::from_secs(3600));
        let service = offline(&cache, |f| f.with_stale_policy(ServeStaleDisabled));
        assert_eq!(ask(&service, "s.example", DnsType::A).rcode(), RCODE_SERVFAIL);
        assert_eq!(service.metrics().stale_served, 0);
    }

    #[test]
    fn the_stale_window_and_ttl_come_from_the_policy() {
        let cache = Arc::new(DnsCache::default());
        cache.put_aged(&DnsQuestion::in_class("w.example", DnsType::A), a("w.example"), 60, Duration::from_secs(60 + 600));
        // Ten minutes stale is outside a five-minute window...
        let tight = StaleTerms { max_age: Duration::from_secs(300), answer_ttl: 10 };
        let service = offline(&cache, |f| f.with_stale_policy(ServeStale(tight)));
        assert_eq!(ask(&service, "w.example", DnsType::A).rcode(), RCODE_SERVFAIL);
        // ...and inside a one-hour one, served with that policy's TTL.
        let loose = StaleTerms { max_age: Duration::from_secs(3600), answer_ttl: 5 };
        let service = offline(&cache, |f| f.with_stale_policy(ServeStale(loose)));
        let resp = ask(&service, "w.example", DnsType::A);
        assert_eq!(resp.answers[0].ttl, 5);
    }

    #[test]
    fn the_stale_policy_can_decide_per_question() {
        let cache = Arc::new(DnsCache::default());
        for name in ["public.example", "internal.corp.example"] {
            cache.put_aged(&DnsQuestion::in_class(name, DnsType::A), a(name), 60, Duration::from_secs(3600));
        }
        let service = offline(&cache, |f| {
            f.with_stale_policy(|q: &DnsQuestion| (!q.name.ends_with(".corp.example")).then(StaleTerms::default))
        });
        assert_eq!(ask(&service, "public.example", DnsType::A).rcode(), 0);
        assert_eq!(ask(&service, "internal.corp.example", DnsType::A).rcode(), RCODE_SERVFAIL);
    }

    #[test]
    fn a_fresh_entry_is_a_normal_hit_not_a_stale_serve() {
        let cache = Arc::new(DnsCache::default());
        cache.put(&DnsQuestion::in_class("fresh.example", DnsType::A), a("fresh.example"), 60);
        let service = offline(&cache, |f| f);
        let resp = ask(&service, "fresh.example", DnsType::A);
        assert!(resp.answers[0].ttl > 30);
        let m = service.metrics();
        assert_eq!((m.cache_hits, m.stale_served), (1, 0));
    }

    #[test]
    fn negative_answers_are_never_served_stale() {
        // RFC 8767 is about data: an expired NXDOMAIN is simply re-asked.
        let cache = Arc::new(DnsCache::new(16, 0));
        cache.put_response(&DnsMessage::new(
            1,
            FLAG_QR | RCODE_NXDOMAIN,
            vec![DnsQuestion::in_class("gone.example", DnsType::A)],
            vec![],
            vec![],
            vec![],
        ));
        let service = offline(&cache, |f| f);
        assert_eq!(ask(&service, "gone.example", DnsType::A).rcode(), RCODE_SERVFAIL);
    }

    // ---- RFC 8020 NXDOMAIN cut ----

    fn cache_with_nxdomain(name: &str) -> Arc<DnsCache> {
        let cache = Arc::new(DnsCache::default());
        cache.put_response(&DnsMessage::new(
            1,
            FLAG_QR | RCODE_NXDOMAIN,
            vec![DnsQuestion::in_class(name, DnsType::A)],
            vec![],
            vec![],
            vec![],
        ));
        cache
    }

    #[test]
    fn a_cached_nxdomain_answers_for_names_beneath_it_without_the_upstream() {
        let cache = cache_with_nxdomain("nothing.example");
        let service = offline(&cache, |f| f);
        for name in ["www.nothing.example", "a.b.c.nothing.example"] {
            assert_eq!(ask(&service, name, DnsType::Aaaa).rcode(), RCODE_NXDOMAIN, "{name}");
        }
        assert_eq!(ask(&service, "other.example", DnsType::A).rcode(), RCODE_SERVFAIL, "siblings still go upstream");
        let m = service.metrics();
        assert_eq!((m.cache_hits, m.upstreams), (2, 0));
    }

    #[test]
    fn the_nxdomain_cut_can_be_disabled_or_scoped() {
        let cache = cache_with_nxdomain("nothing.example");
        let service = offline(&cache, |f| f.with_nxdomain_cut_policy(NxdomainCutDisabled));
        assert_eq!(ask(&service, "www.nothing.example", DnsType::A).rcode(), RCODE_SERVFAIL);

        // Split horizon: names under `internal.nothing.example` may exist.
        let service = offline(&cache, |f| {
            f.with_nxdomain_cut_policy(|q: &DnsQuestion| !q.name.ends_with(".internal.nothing.example"))
        });
        assert_eq!(ask(&service, "www.nothing.example", DnsType::A).rcode(), RCODE_NXDOMAIN);
        assert_eq!(ask(&service, "x.internal.nothing.example", DnsType::A).rcode(), RCODE_SERVFAIL);
    }

    // ---- RFC 8482 minimal ANY ----

    fn any_response(answers: Vec<DnsResourceRecord>) -> DnsMessage {
        let mut resp = query("any.example", DnsType::Any).response_template(0);
        resp.answers = answers;
        resp.authorities.push(DnsResourceRecord::a("ns.example", 60, Ipv4Addr::LOCALHOST));
        resp
    }

    #[test]
    fn an_existing_names_any_answer_becomes_one_hinfo() {
        let mut resp = any_response(vec![
            DnsResourceRecord::a("any.example", 60, Ipv4Addr::LOCALHOST),
            DnsResourceRecord::txt("any.example", 60, "a large TXT").unwrap(),
        ]);
        minimise_any(&mut resp, &DnsQuestion::in_class("any.example", DnsType::Any), 900);
        assert_eq!(resp.answers.len(), 1);
        let hinfo = &resp.answers[0];
        assert_eq!((hinfo.raw_type, hinfo.ttl, hinfo.name.as_str()), (13, 900, "any.example"));
        assert_eq!(hinfo.rdata, [&[7u8][..], b"RFC8482", &[0u8][..]].concat(), "CPU \"RFC8482\", empty OS");
        assert!(resp.authorities.is_empty());
    }

    #[test]
    fn nxdomain_nodata_and_errors_are_not_disguised_as_hinfo() {
        let q = DnsQuestion::in_class("any.example", DnsType::Any);
        let mut nodata = any_response(vec![]);
        minimise_any(&mut nodata, &q, 900);
        assert!(nodata.answers.is_empty(), "no data stays no data");
        let mut nx = query("any.example", DnsType::Any).response_template(RCODE_NXDOMAIN);
        minimise_any(&mut nx, &q, 900);
        assert_eq!(nx.rcode(), RCODE_NXDOMAIN);
        assert!(nx.answers.is_empty());
    }

    #[test]
    fn a_cached_minimal_any_answer_is_served_from_the_cache() {
        // The forwarder caches the minimised answer, so a repeat is a hit.
        let cache = Arc::new(DnsCache::default());
        let hinfo = DnsResourceRecord::hinfo("any.example", 600, "RFC8482", "").unwrap();
        cache.put(&DnsQuestion::in_class("any.example", DnsType::Any), vec![hinfo], 600);
        let service = offline(&cache, |f| f);
        let resp = ask(&service, "any.example", DnsType::Any);
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(resp.answers[0].raw_type, 13);
    }
}
