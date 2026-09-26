// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! [`AuthPipeline`] — SPF/DKIM/DMARC wired into [`crate::SmtpPipeline`].

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use rmimeparser::dkim::{DkimMessageParser, RawHeader};
use rmimeparser::{EmailAddress, EmailAddressParser, MessageHandler, MimeHandler};

use crate::auth::arc::{
    self, ArcAuthSnapshot, ArcDmarcPolicy, ArcSealError, ArcSealer, ArcSetHeaders,
    ArcValidationResult,
};
use crate::auth::dkim::{self, BodyHashMap, Canonicalization, DkimSignatureResult, IncrementalBodyCanon};
use crate::auth::dmarc::{self, AuthVerdict, DmarcOutcome};
use crate::auth::dns_lookup::DnsLookup;
use crate::auth::psl::PublicSuffixList;
use crate::auth::spf::{self, SpfOutcome};
use crate::SmtpPipeline;

mod authentication_results;
pub use authentication_results::AuthResultsHandle;
use authentication_results::render_authentication_results;

/// A one-shot, callback-or-poll value shared between the async producer and
/// whoever wants the result (possibly before it's ready).
struct Relay<T>(Mutex<RelayState<T>>);

enum RelayState<T> {
    Pending(Vec<Box<dyn FnOnce(T) + Send>>),
    Ready(T),
}

impl<T: Clone + Send + 'static> Relay<T> {
    fn new() -> Self {
        Self(Mutex::new(RelayState::Pending(Vec::new())))
    }

    fn resolve(&self, value: T) {
        let waiters = {
            let mut g = self.0.lock().unwrap();
            match &*g {
                RelayState::Ready(_) => return, // already resolved; ignore duplicate.
                RelayState::Pending(_) => {
                    match std::mem::replace(&mut *g, RelayState::Ready(value.clone())) {
                        RelayState::Pending(w) => w,
                        RelayState::Ready(_) => unreachable!(),
                    }
                }
            }
        };
        for w in waiters {
            w(value.clone());
        }
    }

    fn peek(&self) -> Option<T> {
        match &*self.0.lock().unwrap() {
            RelayState::Ready(v) => Some(v.clone()),
            RelayState::Pending(_) => None,
        }
    }

    fn on_ready(&self, cb: Box<dyn FnOnce(T) + Send>) {
        let mut g = self.0.lock().unwrap();
        match &mut *g {
            RelayState::Ready(v) => {
                let v = v.clone();
                drop(g);
                cb(v);
            }
            RelayState::Pending(waiters) => waiters.push(cb),
        }
    }
}

/// Shared, cloneable handle to an [`AuthPipeline`]'s final [`AuthVerdict`] —
/// resolves once DKIM+DMARC evaluation completes (which may be after
/// end-of-DATA, since it depends on DNS). Meant to be captured by a
/// [`crate::server::MessageEndState::defer`] continuation so the final SMTP
/// reply can wait for it without blocking the reactor.
#[derive(Clone)]
pub struct AuthVerdictHandle(Arc<Relay<AuthVerdict>>);

impl AuthVerdictHandle {
    fn new() -> Self {
        Self(Arc::new(Relay::new()))
    }

    fn resolve(&self, verdict: AuthVerdict) {
        self.0.resolve(verdict);
    }

    /// Non-blocking check: `Some(verdict)` if evaluation has completed.
    pub fn poll(&self) -> Option<AuthVerdict> {
        self.0.peek()
    }

    /// Run `cb` once the verdict is available (immediately, if it already is).
    pub fn on_ready(&self, cb: impl FnOnce(AuthVerdict) + Send + 'static) {
        self.0.on_ready(Box::new(cb));
    }
}

/// Shared handle to the message's [`ArcValidationResult`] - see
/// [`AuthPipeline::arc_result`].
#[derive(Clone)]
pub struct ArcResultHandle(Arc<Relay<ArcValidationResult>>);

impl ArcResultHandle {
    /// Non-blocking check: `Some(result)` once validation has completed.
    pub fn poll(&self) -> Option<ArcValidationResult> {
        self.0.peek()
    }

    /// Run `cb` once the result is available (immediately, if it already is).
    pub fn on_ready(&self, cb: impl FnOnce(ArcValidationResult) + Send + 'static) {
        self.0.on_ready(Box::new(cb));
    }
}

/// Shared handle to this hop's sealed ARC set - see [`AuthPipeline::arc_seal`].
#[derive(Clone)]
pub struct ArcSealHandle(Arc<Relay<Result<ArcSetHeaders, ArcSealError>>>);

impl ArcSealHandle {
    /// Non-blocking check: `Some(..)` once sealing has completed.
    pub fn poll(&self) -> Option<Result<ArcSetHeaders, ArcSealError>> {
        self.0.peek()
    }

    /// Run `cb` once sealing has completed (immediately, if it already has).
    pub fn on_ready(&self, cb: impl FnOnce(Result<ArcSetHeaders, ArcSealError>) + Send + 'static) {
        self.0.on_ready(Box::new(cb));
    }
}

struct NoopMessageHandler;
impl MimeHandler for NoopMessageHandler {}
impl MessageHandler for NoopMessageHandler {}

/// Builds an [`AuthPipeline`] (Gumdrop `AuthPipeline.Builder`).
pub struct AuthPipelineBuilder {
    dns: Arc<dyn DnsLookup>,
    client_ip: IpAddr,
    helo_domain: String,
    receiver: String,
    on_spf: Option<Box<dyn FnOnce(SpfOutcome) + Send>>,
    on_dkim: Option<Box<dyn FnOnce(DkimSignatureResult) + Send>>,
    on_dmarc: Option<Box<dyn FnOnce(DmarcOutcome) + Send>>,
    inner: Option<Box<dyn SmtpPipeline>>,
    authserv_id: Option<String>,
    arc_validate: bool,
    arc_policy: Option<Arc<dyn ArcDmarcPolicy>>,
    arc_sealer: Option<Arc<ArcSealer>>,
    on_arc: Option<Box<dyn FnOnce(ArcValidationResult) + Send>>,
}

impl AuthPipelineBuilder {
    /// New builder for a connection from `client_ip`, with `helo_domain` as
    /// seen in the `HELO`/`EHLO` command. `dns` is a shared resolver — an
    /// `Arc<hopf_dns::DnsResolver>` coerces automatically since
    /// `DnsResolver` implements [`DnsLookup`] directly.
    pub fn new(dns: Arc<dyn DnsLookup>, client_ip: IpAddr, helo_domain: impl Into<String>) -> Self {
        let helo_domain = helo_domain.into();
        Self {
            dns,
            client_ip,
            receiver: helo_domain.clone(),
            helo_domain,
            on_spf: None,
            on_dkim: None,
            on_dmarc: None,
            inner: None,
            authserv_id: None,
            arc_validate: false,
            arc_policy: None,
            arc_sealer: None,
            on_arc: None,
        }
    }

    /// Override the hostname used for `%{r}` in SPF `exp=` explanation text
    /// (defaults to the `helo_domain` given to [`Self::new`]).
    pub fn receiver(mut self, host: impl Into<String>) -> Self {
        self.receiver = host.into();
        self
    }

    /// Called once with the SPF outcome (as soon as it resolves — typically
    /// well before end-of-DATA).
    pub fn on_spf(mut self, cb: impl FnOnce(SpfOutcome) + Send + 'static) -> Self {
        self.on_spf = Some(Box::new(cb));
        self
    }

    /// Called once, at end-of-DATA, with the result for the *first*
    /// `DKIM-Signature` header found (matching Gumdrop's documented
    /// pipeline behavior). DMARC evaluation still considers every signature.
    pub fn on_dkim(mut self, cb: impl FnOnce(DkimSignatureResult) + Send + 'static) -> Self {
        self.on_dkim = Some(Box::new(cb));
        self
    }

    /// Called once DMARC evaluation completes (after SPF, DKIM, and any
    /// necessary DNS lookups all finish).
    pub fn on_dmarc(mut self, cb: impl FnOnce(DmarcOutcome) + Send + 'static) -> Self {
        self.on_dmarc = Some(Box::new(cb));
        self
    }

    /// Tee envelope/content notifications to another pipeline (e.g. a
    /// buffering or relay pipeline) alongside auth processing.
    pub fn message_handler(mut self, inner: Box<dyn SmtpPipeline>) -> Self {
        self.inner = Some(inner);
        self
    }

    /// Opt in to synthesizing an RFC 8601 `Authentication-Results` header
    /// field once SPF/DKIM/DMARC evaluation completes, identified by
    /// `authserv_id` (RFC 8601 §2.3 — typically this server's own
    /// hostname). Default: no header is synthesized (current behavior).
    ///
    /// This does **not** insert the header into the message itself —
    /// [`AuthPipeline`] never rewrites bytes flowing through
    /// [`Self::message_handler`]'s `inner` tee (e.g. a spool file), and by
    /// the time the header is ready (after end-of-DATA, DNS-bound) any such
    /// tee has typically already streamed the whole message onward. Fetch
    /// the rendered field via [`AuthPipeline::authentication_results`] and
    /// apply it yourself wherever your `message_complete`/delivery logic
    /// already has a chance to touch the stored message (e.g. before
    /// streaming a spool file onward) — this also keeps the header out of
    /// DKIM's own signed-header set, since `Authentication-Results` must be
    /// added by the receiver *after* signing, never before.
    pub fn authentication_results(mut self, authserv_id: impl Into<String>) -> Self {
        self.authserv_id = Some(authserv_id.into());
        self
    }

    /// Validate any RFC 8617 ARC chain on the message at end-of-DATA.
    /// The result is available from [`AuthPipeline::arc_result`] and
    /// [`Self::on_arc`], and is recorded as an `arc=` result in a
    /// synthesized `Authentication-Results` field.
    pub fn arc_validation(mut self) -> Self {
        self.arc_validate = true;
        self
    }

    /// Called once with the ARC chain validation result (implies
    /// [`Self::arc_validation`]).
    pub fn on_arc(mut self, cb: impl FnOnce(ArcValidationResult) + Send + 'static) -> Self {
        self.arc_validate = true;
        self.on_arc = Some(Box::new(cb));
        self
    }

    /// Let a validated ARC chain inform DMARC (implies
    /// [`Self::arc_validation`]). After validation, `policy` is asked which
    /// SPF/DKIM results DMARC should evaluate; returning `None` (or a
    /// snapshot that overrides nothing) leaves this hop's own results in
    /// force. Which sealers to trust is entirely the policy's decision.
    pub fn arc_dmarc_policy(mut self, policy: Arc<dyn ArcDmarcPolicy>) -> Self {
        self.arc_validate = true;
        self.arc_policy = Some(policy);
        self
    }

    /// Seal the message with this hop's ARC set once SPF, DKIM, DMARC and
    /// chain validation are known (implies [`Self::arc_validation`]; the
    /// sealer's `cv=` is that validation result). Fetch the headers via
    /// [`AuthPipeline::arc_seal`] and prepend them to the forwarded
    /// message; like `Authentication-Results`, they cannot be applied
    /// automatically for the reasons given on [`Self::authentication_results`].
    pub fn arc_sealer(mut self, sealer: Arc<ArcSealer>) -> Self {
        self.arc_validate = true;
        self.arc_sealer = Some(sealer);
        self
    }

    /// Build the pipeline.
    pub fn build(self) -> AuthPipeline {
        AuthPipeline {
            dns: self.dns,
            client_ip: self.client_ip,
            helo_domain: self.helo_domain,
            receiver: self.receiver,
            on_spf: self.on_spf,
            on_dkim: self.on_dkim,
            on_dmarc: self.on_dmarc,
            inner: self.inner,
            spf_relay: Arc::new(Relay::new()),
            spf_domain: None,
            verdict: AuthVerdictHandle::new(),
            header_buf: Vec::new(),
            headers: None,
            body_canons: None,
            authserv_id: self.authserv_id,
            auth_results: AuthResultsHandle(Arc::new(Relay::new())),
            arc_validate: self.arc_validate,
            arc_policy: self.arc_policy,
            arc_sealer: self.arc_sealer,
            on_arc: self.on_arc,
            arc_result: ArcResultHandle(Arc::new(Relay::new())),
            arc_seal: ArcSealHandle(Arc::new(Relay::new())),
        }
    }
}

/// SPF + DKIM + DMARC transaction pipeline (Gumdrop `AuthPipeline` port).
///
/// SPF starts at `mail_from`. DKIM verification and DMARC evaluation start
/// at `end_data`. Because these depend on DNS, none of them complete
/// synchronously — use the `on_*` callbacks and/or [`AuthPipeline::verdict`]
/// to observe results.
///
/// # Memory model
///
/// Only the message *headers* are ever buffered in full (`header_buf`,
/// cleared once headers are complete and replaced by the parsed
/// [`RawHeader`] list) — real messages keep these to a few KB even in
/// pathological cases. The *body*, which is what dominates memory for large
/// mail, is never retained: each `message_content` chunk is fed straight
/// into one [`IncrementalBodyCanon`] per distinct DKIM body
/// canonicalization the message's `DKIM-Signature` header(s) actually
/// use (typically 0 or 1, rarely more), each holding only a running SHA-256
/// digest plus a bounded current-line buffer — see
/// [`IncrementalBodyCanon`]'s own docs for the (rare, still-bounded) worst
/// case. Peak `AuthPipeline` memory is therefore O(headers) + O(number of
/// distinct signature canonicalizations), not O(message size) — issue #86.
pub struct AuthPipeline {
    dns: Arc<dyn DnsLookup>,
    client_ip: IpAddr,
    helo_domain: String,
    receiver: String,
    on_spf: Option<Box<dyn FnOnce(SpfOutcome) + Send>>,
    on_dkim: Option<Box<dyn FnOnce(DkimSignatureResult) + Send>>,
    on_dmarc: Option<Box<dyn FnOnce(DmarcOutcome) + Send>>,
    inner: Option<Box<dyn SmtpPipeline>>,
    spf_relay: Arc<Relay<SpfOutcome>>,
    spf_domain: Option<String>,
    verdict: AuthVerdictHandle,
    /// Raw bytes accumulated until the header/body separator is found —
    /// cleared (and replaced by `headers`) as soon as it is.
    header_buf: Vec<u8>,
    /// Parsed headers, available from the moment the separator is found.
    headers: Option<Arc<Vec<RawHeader>>>,
    /// One streaming canonicalizer per distinct `(c=body-side, l=)` pair
    /// this message's signature(s) need — see
    /// [`dkim::required_body_hash_keys`]. `None` until `headers` is set;
    /// taken (finished) at `end_data`.
    body_canons: Option<Vec<(Canonicalization, Option<u64>, IncrementalBodyCanon)>>,
    /// `Some` only if [`AuthPipelineBuilder::authentication_results`] was
    /// used — gates whether [`Self::authentication_results`] exposes
    /// `auth_results` at all, and whether `end_data` bothers rendering it.
    authserv_id: Option<String>,
    auth_results: AuthResultsHandle,
    arc_validate: bool,
    arc_policy: Option<Arc<dyn ArcDmarcPolicy>>,
    arc_sealer: Option<Arc<ArcSealer>>,
    on_arc: Option<Box<dyn FnOnce(ArcValidationResult) + Send>>,
    arc_result: ArcResultHandle,
    arc_seal: ArcSealHandle,
}

impl AuthPipeline {
    /// Start building a pipeline for this connection.
    pub fn builder(
        dns: Arc<dyn DnsLookup>,
        client_ip: IpAddr,
        helo_domain: impl Into<String>,
    ) -> AuthPipelineBuilder {
        AuthPipelineBuilder::new(dns, client_ip, helo_domain)
    }

    /// A cloneable handle to the final [`AuthVerdict`] — resolves once DMARC
    /// evaluation completes.
    pub fn verdict(&self) -> AuthVerdictHandle {
        self.verdict.clone()
    }

    /// A cloneable handle to the synthesized `Authentication-Results`
    /// header field — `None` unless
    /// [`AuthPipelineBuilder::authentication_results`] was used to opt in.
    pub fn authentication_results(&self) -> Option<AuthResultsHandle> {
        self.authserv_id.as_ref()?;
        Some(self.auth_results.clone())
    }

    /// A cloneable handle to the ARC chain validation result; `None`
    /// unless ARC validation was enabled on the builder
    /// ([`AuthPipelineBuilder::arc_validation`], `on_arc`,
    /// `arc_dmarc_policy` or `arc_sealer`).
    pub fn arc_result(&self) -> Option<ArcResultHandle> {
        self.arc_validate.then(|| self.arc_result.clone())
    }

    /// A cloneable handle to the ARC set this hop sealed the message with,
    /// or the reason it could not; `None` unless
    /// [`AuthPipelineBuilder::arc_sealer`] was used.
    pub fn arc_seal(&self) -> Option<ArcSealHandle> {
        self.arc_sealer.as_ref()?;
        Some(self.arc_seal.clone())
    }
}

impl SmtpPipeline for AuthPipeline {
    fn mail_from(&mut self, sender: Option<&EmailAddress>) {
        let sender_email = sender
            .map(|s| s.address())
            .unwrap_or_else(|| format!("postmaster@{}", self.helo_domain));
        let sender_domain = sender
            .map(|s| s.domain().to_string())
            .unwrap_or_else(|| self.helo_domain.clone());
        self.spf_domain = Some(sender_domain.clone());

        let relay = Arc::clone(&self.spf_relay);
        let on_spf = self.on_spf.take();
        spf::check_host(
            Arc::clone(&self.dns),
            self.client_ip,
            &sender_domain,
            &sender_email,
            &self.helo_domain,
            &self.receiver,
            Box::new(move |outcome| {
                if let Some(cb) = on_spf {
                    cb(outcome.clone());
                }
                relay.resolve(outcome);
            }),
        );

        if let Some(inner) = &mut self.inner {
            inner.mail_from(sender);
        }
    }

    fn rcpt_to(&mut self, recipient: &EmailAddress) {
        if let Some(inner) = &mut self.inner {
            inner.rcpt_to(recipient);
        }
    }

    fn message_content(&mut self, chunk: &[u8]) -> bool {
        if let Some(canons) = self.body_canons.as_mut() {
            for (_, _, canon) in canons.iter_mut() {
                canon.feed(chunk);
            }
        } else {
            self.header_buf.extend_from_slice(chunk);
            if let Some(boundary) = find_header_boundary(&self.header_buf) {
                let (header_bytes, leftover_body) = self.header_buf.split_at(boundary);
                let mut handler = NoopMessageHandler;
                let mut parser = DkimMessageParser::new(&mut handler);
                let mut data: &[u8] = header_bytes;
                let _ = parser.receive(&mut data);
                let headers = parser.raw_headers().to_vec();

                let mut keys = dkim::required_body_hash_keys(&headers);
                if self.arc_validate {
                    keys.extend(arc::required_body_hash_keys(&headers));
                }
                if let Some(sealer) = &self.arc_sealer {
                    keys.push(sealer.body_canonicalization_key());
                }
                keys.sort_by_key(|&(c, l)| (c as u8, l));
                keys.dedup();
                let mut canons: Vec<_> = keys
                    .into_iter()
                    .map(|(c, l)| (c, l, IncrementalBodyCanon::new(c, l)))
                    .collect();
                for (_, _, canon) in canons.iter_mut() {
                    canon.feed(leftover_body);
                }
                self.headers = Some(Arc::new(headers));
                self.body_canons = Some(canons);
                self.header_buf = Vec::new();
            }
        }
        match &mut self.inner {
            Some(inner) => inner.message_content(chunk),
            None => true,
        }
    }

    fn end_data(&mut self) {
        // Normal case: the header/body separator arrived during
        // message_content, so `headers` is already parsed and every needed
        // body canonicalization has been streaming since. Fallback: no
        // separator ever arrived (empty, truncated, or header-only
        // message) — best-effort parse whatever was accumulated, matching
        // what the old whole-buffer implementation did for this same edge
        // case (an empty/absent body).
        let headers = match self.headers.take() {
            Some(h) => h,
            None => {
                let mut handler = NoopMessageHandler;
                let mut parser = DkimMessageParser::new(&mut handler);
                let mut data: &[u8] = &self.header_buf;
                let _ = parser.receive(&mut data);
                let _ = parser.close();
                Arc::new(parser.raw_headers().to_vec())
            }
        };
        let body_hashes: BodyHashMap = match self.body_canons.take() {
            Some(canons) => canons
                .into_iter()
                .map(|(c, l, canon)| ((c, l), canon.finish().as_ref().to_vec()))
                .collect(),
            None => BodyHashMap::new(),
        };
        let from_header = from_header_domain(&headers);
        let body_hashes = Arc::new(body_hashes);

        let dns = Arc::clone(&self.dns);
        let psl = PublicSuffixList::bundled();
        let on_dkim = self.on_dkim.take();
        let on_dmarc = self.on_dmarc.take();
        let verdict = self.verdict.clone();
        let spf_relay = Arc::clone(&self.spf_relay);
        let spf_domain = self.spf_domain.clone();
        // `authserv_id`/`spf_domain_for_ar` travel alongside the existing
        // callback chain purely to feed render_authentication_results once
        // every input (SPF, DKIM, and DMARC when evaluated) is known —
        // None end to end when authentication_results() was never opted
        // into, so this adds no work in the common case.
        let finish = Finish {
            authserv_id: self.authserv_id.clone(),
            auth_results: self.auth_results.clone(),
            sealer: self.arc_sealer.clone(),
            arc_seal: self.arc_seal.clone(),
            headers: Arc::clone(&headers),
            body_hashes: Arc::clone(&body_hashes),
            spf_domain: self.spf_domain.clone(),
        };
        let arc_enabled = self.arc_validate;
        let arc_policy = self.arc_policy.clone();
        let on_arc = self.on_arc.take();
        let arc_result = self.arc_result.clone();
        let headers_for_arc = Arc::clone(&headers);
        let body_hashes_for_arc = Arc::clone(&body_hashes);
        let dns_for_arc = Arc::clone(&dns);

        dkim::verify_all_with_body_hashes(
            Arc::clone(&dns),
            headers,
            body_hashes,
            Box::new(move |dkim_results| {
                if let Some(cb) = on_dkim {
                    cb(dkim_results
                        .first()
                        .cloned()
                        .unwrap_or(DkimSignatureResult {
                            result: dkim::DkimResult::None,
                            signing_domain: None,
                            selector: None,
                        }));
                }
                let dkim_results = Arc::new(dkim_results);
                let has_duplicate_from = from_header.has_duplicate;
                // Everything after DKIM: DMARC (informed by the ARC chain,
                // if any) and the final Authentication-Results / ARC seal.
                let proceed = move |arc: Option<ArcValidationResult>| {
                    let Some(from_domain) = from_header.domain else {
                        // No usable `From:` header — DMARC cannot be evaluated;
                        // fail open (no enforcement) rather than block forever.
                        verdict.resolve(AuthVerdict::None);
                        spf_relay.on_ready(Box::new(move |spf_outcome| {
                            finish.run(&spf_outcome, &dkim_results, None, arc.as_ref());
                        }));
                        return;
                    };
                    spf_relay.on_ready(Box::new(move |spf_outcome| {
                        let (eval_spf, eval_spf_domain, eval_dkim) = match (&arc, &arc_policy) {
                            (Some(chain), Some(policy)) => {
                                let snapshot = policy.auth_snapshot(
                                    chain,
                                    &from_domain,
                                    spf_outcome.result,
                                    spf_domain.as_deref(),
                                    &dkim_results,
                                );
                                apply_snapshot(
                                    snapshot,
                                    spf_outcome.result,
                                    spf_domain.clone(),
                                    Arc::clone(&dkim_results),
                                )
                            }
                            _ => (
                                spf_outcome.result,
                                spf_domain.clone(),
                                Arc::clone(&dkim_results),
                            ),
                        };
                        dmarc::evaluate(
                            dns,
                            psl,
                            &from_domain,
                            has_duplicate_from,
                            eval_spf,
                            eval_spf_domain,
                            eval_dkim,
                            Box::new(move |outcome| {
                                let v = outcome.verdict;
                                finish.run(&spf_outcome, &dkim_results, Some(&outcome), arc.as_ref());
                                if let Some(cb) = on_dmarc {
                                    cb(outcome);
                                }
                                verdict.resolve(v);
                            }),
                        );
                    }));
                };

                if arc_enabled {
                    arc::validate(
                        dns_for_arc,
                        headers_for_arc,
                        body_hashes_for_arc,
                        Box::new(move |result| {
                            arc_result.0.resolve(result.clone());
                            if let Some(cb) = on_arc {
                                cb(result.clone());
                            }
                            proceed(Some(result));
                        }),
                    );
                } else {
                    proceed(None);
                }
            }),
        );

        if let Some(inner) = &mut self.inner {
            inner.end_data();
        }
    }

    fn reset(&mut self) {
        self.header_buf.clear();
        self.headers = None;
        self.body_canons = None;
        if let Some(inner) = &mut self.inner {
            inner.reset();
        }
    }
}

/// What happens once every authentication result for a message is known:
/// resolve the synthesized `Authentication-Results` field (if opted in) and
/// this hop's ARC seal (if a sealer is configured).
struct Finish {
    authserv_id: Option<String>,
    auth_results: AuthResultsHandle,
    sealer: Option<Arc<ArcSealer>>,
    arc_seal: ArcSealHandle,
    headers: Arc<Vec<RawHeader>>,
    body_hashes: Arc<BodyHashMap>,
    spf_domain: Option<String>,
}

impl Finish {
    fn run(
        self,
        spf: &SpfOutcome,
        dkim_results: &[DkimSignatureResult],
        dmarc: Option<&DmarcOutcome>,
        arc_result: Option<&ArcValidationResult>,
    ) {
        let spf_domain = self.spf_domain.as_deref().unwrap_or("");
        if let Some(authserv_id) = &self.authserv_id {
            self.auth_results.0.resolve(render_authentication_results(
                authserv_id,
                spf,
                spf_domain,
                dkim_results,
                dmarc,
                arc_result,
            ));
        }
        if let (Some(sealer), Some(arc_result)) = (&self.sealer, arc_result) {
            let rendered = render_authentication_results(
                sealer.authserv_id(),
                spf,
                spf_domain,
                dkim_results,
                dmarc,
                Some(arc_result),
            );
            self.arc_seal.0.resolve(sealer.seal(
                &self.headers,
                &self.body_hashes,
                arc_result,
                &rendered,
            ));
        }
    }
}

/// Merge an [`ArcDmarcPolicy`]'s snapshot over this hop's own results.
fn apply_snapshot(
    snapshot: Option<ArcAuthSnapshot>,
    local_spf: spf::SpfResult,
    local_spf_domain: Option<String>,
    local_dkim: Arc<Vec<DkimSignatureResult>>,
) -> (spf::SpfResult, Option<String>, Arc<Vec<DkimSignatureResult>>) {
    let Some(snapshot) = snapshot else {
        return (local_spf, local_spf_domain, local_dkim);
    };
    let (spf_result, spf_domain) = snapshot.spf.unwrap_or((local_spf, local_spf_domain));
    let dkim = snapshot.dkim.map(Arc::new).unwrap_or(local_dkim);
    (spf_result, spf_domain, dkim)
}

/// The offset right after the first blank line in `buf` (i.e. where the
/// body starts), or `None` if no blank line has arrived yet.
///
/// A line is a header-folding continuation (never the separator) if it
/// starts with whitespace — RFC 5322 §2.2.3 — so a genuinely empty line
/// (zero bytes of content once its own terminator is stripped) can only be
/// the header/body separator; a byte-level line scan for this is
/// unambiguous without needing full RFC 5322 folding awareness, which is
/// why this can safely run ahead of (and independently from) the real
/// [`DkimMessageParser`] parse of the header block itself.
pub(crate) fn find_header_boundary(buf: &[u8]) -> Option<usize> {
    let mut line_start = 0usize;
    for i in 0..buf.len() {
        if buf[i] != b'\n' {
            continue;
        }
        let line = &buf[line_start..i];
        let content = line.strip_suffix(b"\r").unwrap_or(line);
        if content.is_empty() {
            return Some(i + 1);
        }
        line_start = i + 1;
    }
    None
}

/// The result of resolving the message's `From:` header domain for DMARC
/// alignment.
struct FromHeader {
    /// Domain parsed from the first `From:` header occurrence, if any.
    domain: Option<String>,
    /// Whether more than one `From:` header was present. RFC 5322 §3.6.2
    /// permits at most one; mail clients disagree on which one they
    /// display when a message illegally has more, so DMARC must not grant
    /// a PASS on the strength of whichever domain this resolves to — see
    /// RFC 7489 §7.6.
    has_duplicate: bool,
}

fn from_header_domain(headers: &[RawHeader]) -> FromHeader {
    let mut froms = headers
        .iter()
        .filter(|h| h.name().eq_ignore_ascii_case("From"));
    let first = froms.next();
    let has_duplicate = froms.next().is_some();
    let domain = first.and_then(|from| {
        let s = from.as_string_unfolded();
        let value = s.split_once(':').map(|(_, v)| v.trim()).unwrap_or("");
        let addresses = EmailAddressParser::parse_email_address_list(value)?;
        addresses
            .iter()
            .find_map(|addr| addr.as_mailbox().map(|m| m.domain().to_string()))
    });
    FromHeader { domain, has_duplicate }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::auth::dmarc::DmarcPolicy;
    use crate::auth::dns_lookup::Lookup;

    use super::*;

    #[derive(Default)]
    struct FakeDns {
        txt: HashMap<String, Vec<String>>,
    }

    impl FakeDns {
        fn with_txt(mut self, name: &str, record: &str) -> Self {
            self.txt
                .entry(name.to_ascii_lowercase())
                .or_default()
                .push(record.to_string());
            self
        }
    }

    impl DnsLookup for FakeDns {
        fn query_txt(&self, name: &str, cb: Box<dyn FnOnce(Lookup<String>) + Send>) {
            match self.txt.get(&name.to_ascii_lowercase()) {
                None => cb(Lookup::NxDomain),
                Some(v) => cb(Lookup::Answers(v.clone())),
            }
        }
        fn query_a(&self, _name: &str, cb: Box<dyn FnOnce(Lookup<Ipv4Addr>) + Send>) {
            cb(Lookup::NxDomain);
        }
        fn query_aaaa(&self, _name: &str, cb: Box<dyn FnOnce(Lookup<Ipv6Addr>) + Send>) {
            cb(Lookup::NxDomain);
        }
        fn query_mx(&self, _name: &str, cb: Box<dyn FnOnce(Lookup<(u16, String)>) + Send>) {
            cb(Lookup::NxDomain);
        }
        fn query_ptr(&self, _name: &str, cb: Box<dyn FnOnce(Lookup<String>) + Send>) {
            cb(Lookup::NxDomain);
        }
    }

    fn message(from: &str) -> Vec<u8> {
        format!("From: {from}\r\nSubject: hi\r\n\r\nBody text.\r\n").into_bytes()
    }

    fn message_with_duplicate_from(first: &str, second: &str) -> Vec<u8> {
        format!("From: {first}\r\nFrom: {second}\r\nSubject: hi\r\n\r\nBody text.\r\n").into_bytes()
    }

    #[test]
    fn duplicate_from_header_does_not_grant_dmarc_pass() {
        // RFC 5322 §3.6.2 permits at most one `From:` header. A message
        // with two is ambiguous about which one a recipient's mail client
        // will actually display (RFC 7489 §7.6), so DMARC must not PASS
        // merely because *a* `From:` domain happens to align — even when,
        // as here, the domain this pipeline resolves for alignment is SPF-
        // aligned and would otherwise pass outright.
        let dns: Arc<dyn DnsLookup> = Arc::new(
            FakeDns::default()
                .with_txt("example.com", "v=spf1 ip4:192.0.2.0/24 -all")
                .with_txt("_dmarc.example.com", "v=DMARC1; p=reject"),
        );
        let mut pipeline =
            AuthPipeline::builder(dns, "192.0.2.5".parse().unwrap(), "mail.example.com").build();
        let verdict = pipeline.verdict();

        let sender = EmailAddress::new(None, "alice", "example.com", true);
        pipeline.mail_from(Some(&sender));
        pipeline.message_content(&message_with_duplicate_from(
            "alice@example.com",
            "spoofed@attacker.example",
        ));
        pipeline.end_data();

        assert_ne!(verdict.poll(), Some(AuthVerdict::Pass));
    }

    #[test]
    fn spf_aligned_pass_resolves_verdict_pass() {
        let dns: Arc<dyn DnsLookup> = Arc::new(
            FakeDns::default()
                .with_txt("example.com", "v=spf1 ip4:192.0.2.0/24 -all")
                .with_txt("_dmarc.example.com", "v=DMARC1; p=reject"),
        );
        let mut pipeline =
            AuthPipeline::builder(dns, "192.0.2.5".parse().unwrap(), "mail.example.com").build();
        let verdict = pipeline.verdict();

        let sender = EmailAddress::new(None, "alice", "example.com", true);
        pipeline.mail_from(Some(&sender));
        pipeline.message_content(&message("alice@example.com"));
        pipeline.end_data();

        assert_eq!(verdict.poll(), Some(AuthVerdict::Pass));
    }

    #[test]
    fn spf_fail_and_no_dkim_resolves_reject_policy() {
        let dns: Arc<dyn DnsLookup> = Arc::new(
            FakeDns::default()
                .with_txt("example.com", "v=spf1 ip4:192.0.2.0/24 -all")
                .with_txt("_dmarc.example.com", "v=DMARC1; p=reject"),
        );
        let mut pipeline =
            AuthPipeline::builder(dns, "10.0.0.1".parse().unwrap(), "mail.example.com").build();
        let verdict = pipeline.verdict();

        let sender = EmailAddress::new(None, "alice", "example.com", true);
        pipeline.mail_from(Some(&sender));
        pipeline.message_content(&message("alice@example.com"));
        pipeline.end_data();

        assert_eq!(verdict.poll(), Some(AuthVerdict::Reject));
    }

    #[test]
    fn callbacks_fire_with_expected_outcomes() {
        let dns: Arc<dyn DnsLookup> = Arc::new(
            FakeDns::default()
                .with_txt("example.com", "v=spf1 ip4:192.0.2.0/24 -all")
                .with_txt("_dmarc.example.com", "v=DMARC1; p=none"),
        );
        let spf_seen: Arc<Mutex<Option<spf::SpfResult>>> = Arc::new(Mutex::new(None));
        let dmarc_seen: Arc<Mutex<Option<DmarcOutcome>>> = Arc::new(Mutex::new(None));
        let spf_seen2 = Arc::clone(&spf_seen);
        let dmarc_seen2 = Arc::clone(&dmarc_seen);

        let mut pipeline =
            AuthPipeline::builder(dns, "192.0.2.5".parse().unwrap(), "mail.example.com")
                .on_spf(move |outcome| *spf_seen2.lock().unwrap() = Some(outcome.result))
                .on_dmarc(move |outcome| *dmarc_seen2.lock().unwrap() = Some(outcome))
                .build();

        let sender = EmailAddress::new(None, "alice", "example.com", true);
        pipeline.mail_from(Some(&sender));
        pipeline.message_content(&message("alice@example.com"));
        pipeline.end_data();

        assert_eq!(*spf_seen.lock().unwrap(), Some(spf::SpfResult::Pass));
        assert_eq!(
            dmarc_seen.lock().unwrap().as_ref().map(|o| o.policy),
            Some(DmarcPolicy::None)
        );
    }

    #[test]
    fn message_without_from_header_fails_open() {
        let dns: Arc<dyn DnsLookup> =
            Arc::new(FakeDns::default().with_txt("example.com", "v=spf1 ip4:192.0.2.0/24 -all"));
        let mut pipeline =
            AuthPipeline::builder(dns, "192.0.2.5".parse().unwrap(), "mail.example.com").build();
        let verdict = pipeline.verdict();

        let sender = EmailAddress::new(None, "alice", "example.com", true);
        pipeline.mail_from(Some(&sender));
        pipeline.message_content(b"Subject: no from header\r\n\r\nBody.\r\n");
        pipeline.end_data();

        assert_eq!(verdict.poll(), Some(AuthVerdict::None));
    }

    /// Default (no `.authentication_results(...)` opt-in): no handle at
    /// all — issue #87's "builder opt-in; default remains no injection".
    #[test]
    fn authentication_results_is_none_by_default() {
        let dns: Arc<dyn DnsLookup> =
            Arc::new(FakeDns::default().with_txt("example.com", "v=spf1 ip4:192.0.2.0/24 -all"));
        let pipeline =
            AuthPipeline::builder(dns, "192.0.2.5".parse().unwrap(), "mail.example.com").build();
        assert!(pipeline.authentication_results().is_none());
    }

    /// Opting in resolves a real `Authentication-Results` field once
    /// end_data's SPF+DKIM+DMARC evaluation completes, reflecting the same
    /// SPF-pass/DMARC-none outcome the existing on_spf/on_dmarc callbacks
    /// see in `callbacks_fire_with_expected_outcomes`.
    #[test]
    fn authentication_results_resolves_after_end_data() {
        let dns: Arc<dyn DnsLookup> = Arc::new(
            FakeDns::default()
                .with_txt("example.com", "v=spf1 ip4:192.0.2.0/24 -all")
                .with_txt("_dmarc.example.com", "v=DMARC1; p=none"),
        );
        let mut pipeline =
            AuthPipeline::builder(dns, "192.0.2.5".parse().unwrap(), "mail.example.com")
                .authentication_results("mail.example.com")
                .build();
        let auth_results = pipeline.authentication_results().expect("opted in");
        assert_eq!(auth_results.poll(), None, "not ready before end_data");

        let sender = EmailAddress::new(None, "alice", "example.com", true);
        pipeline.mail_from(Some(&sender));
        pipeline.message_content(&message("alice@example.com"));
        pipeline.end_data();

        let rendered = auth_results.poll().expect("resolved synchronously with FakeDns");
        assert!(rendered.starts_with("Authentication-Results: mail.example.com;"));
        assert!(rendered.contains("spf=pass smtp.mailfrom=example.com;"));
        assert!(rendered.contains("dkim=none;"));
        // SPF-aligned pass under a p=none (monitor-only) policy — result is
        // still `pass`; `p=none` only affects `.policy`/enforcement, not
        // `.result` (see callbacks_fire_with_expected_outcomes).
        assert!(rendered.ends_with("dmarc=pass header.from=example.com"));
    }

    /// The fail-open ("no usable From:") path also resolves an
    /// Authentication-Results field (with dmarc=none, since DMARC was
    /// never evaluated) rather than leaving the handle pending forever.
    #[test]
    fn authentication_results_resolves_on_the_fail_open_path_too() {
        let dns: Arc<dyn DnsLookup> =
            Arc::new(FakeDns::default().with_txt("example.com", "v=spf1 ip4:192.0.2.0/24 -all"));
        let mut pipeline =
            AuthPipeline::builder(dns, "192.0.2.5".parse().unwrap(), "mail.example.com")
                .authentication_results("mail.example.com")
                .build();
        let auth_results = pipeline.authentication_results().expect("opted in");

        let sender = EmailAddress::new(None, "alice", "example.com", true);
        pipeline.mail_from(Some(&sender));
        pipeline.message_content(b"Subject: no from header\r\n\r\nBody.\r\n");
        pipeline.end_data();

        let rendered = auth_results.poll().expect("resolved on the fail-open path");
        assert!(rendered.contains("spf=pass"));
        assert!(rendered.ends_with("dmarc=none"));
    }

    // --- ARC (RFC 8617) -------------------------------------------------

    const ARC_ED25519_PKCS8_B64: &str =
        "MC4CAQAwBQYDK2VwBCIEIJOr3cUYESkwGr3t08+NHi5fO++QEUtI7YDNn9ruV59R";
    const ARC_ED25519_RAW_PUB_B64: &str = "7qcUfZUf3KQSvsFseKVzOm5hlukTWGugsb87LtL2Wuo=";

    fn arc_sealer(domain: &str) -> Arc<ArcSealer> {
        let der = rmimeparser::charset::base64::decode(ARC_ED25519_PKCS8_B64).unwrap();
        let key = Arc::new(crate::auth::dkim::DkimPrivateKey::ed25519_from_pkcs8(&der).unwrap());
        Arc::new(ArcSealer::new(key, domain, "arc", domain).timestamp(1_753_700_000))
    }

    fn arc_dns() -> FakeDns {
        FakeDns::default()
            .with_txt("example.com", "v=spf1 ip4:192.0.2.0/24 -all")
            .with_txt("_dmarc.example.com", "v=DMARC1; p=reject")
            .with_txt(
                "arc._domainkey.list.example",
                &format!("v=DKIM1; k=ed25519; p={ARC_ED25519_RAW_PUB_B64}"),
            )
    }

    /// Runs `message` through a pipeline (as if delivered by `client_ip`
    /// for envelope sender alice@example.com) configured by `configure`,
    /// returning the pipeline for handle inspection.
    fn run_pipeline(
        client_ip: &str,
        message: &[u8],
        configure: impl FnOnce(AuthPipelineBuilder) -> AuthPipelineBuilder,
    ) -> AuthPipeline {
        let dns: Arc<dyn DnsLookup> = Arc::new(arc_dns());
        let mut pipeline = configure(AuthPipeline::builder(
            dns,
            client_ip.parse().unwrap(),
            "mail.example.com",
        ))
        .build();
        let sender = EmailAddress::new(None, "alice", "example.com", true);
        pipeline.mail_from(Some(&sender));
        pipeline.message_content(message);
        pipeline.end_data();
        pipeline
    }

    /// A message an intermediary at `list.example` received from an
    /// authorised sender (SPF pass, DMARC pass) and forwarded with an ARC
    /// set recording that.
    fn forwarded_message() -> Vec<u8> {
        let original = message("alice@example.com");
        let sealed = run_pipeline("192.0.2.5", &original, |b| {
            b.arc_sealer(arc_sealer("list.example"))
        })
        .arc_seal()
        .unwrap()
        .poll()
        .expect("sealing resolved")
        .expect("sealing succeeded");
        let mut out = sealed.to_prepend().into_bytes();
        out.extend_from_slice(&original);
        out
    }

    /// Trusts `list.example` and takes the SPF/DKIM verdicts it recorded.
    struct TrustList;
    impl ArcDmarcPolicy for TrustList {
        fn auth_snapshot(
            &self,
            chain: &ArcValidationResult,
            _from_domain: &str,
            _local_spf: spf::SpfResult,
            _local_spf_domain: Option<&str>,
            _local_dkim: &[DkimSignatureResult],
        ) -> Option<ArcAuthSnapshot> {
            if chain.cv != crate::auth::arc::ArcCv::Pass {
                return None;
            }
            let first = chain.chain.sets.first()?;
            if first.sealer_domain().as_deref() != Some("list.example") {
                return None;
            }
            let recorded = first.recorded_results();
            Some(ArcAuthSnapshot {
                spf: recorded.spf,
                dkim: None,
            })
        }
    }

    #[test]
    fn sealer_produces_a_set_a_second_pipeline_validates() {
        let forwarded = forwarded_message();
        let text = String::from_utf8(forwarded.clone()).unwrap();
        assert!(text.starts_with("ARC-Seal: i=1; a=ed25519-sha256; t=1753700000; cv=none;"));
        assert!(text.contains("ARC-Authentication-Results: i=1; list.example;"));
        assert!(text.contains("spf=pass smtp.mailfrom=example.com"));

        let pipeline = run_pipeline("10.0.0.1", &forwarded, |b| b.arc_validation());
        let result = pipeline.arc_result().unwrap().poll().unwrap();
        assert_eq!(result.cv, crate::auth::arc::ArcCv::Pass);
        assert_eq!(result.chain.sets.len(), 1);
    }

    #[test]
    fn forwarded_mail_is_rejected_without_an_arc_policy() {
        // At the receiving hop the forwarder's IP is not in example.com's
        // SPF record, and there is no DKIM: plain DMARC rejects.
        let pipeline = run_pipeline("10.0.0.1", &forwarded_message(), |b| b.arc_validation());
        assert_eq!(pipeline.verdict().poll(), Some(AuthVerdict::Reject));
    }

    #[test]
    fn trusted_arc_chain_rescues_forwarded_mail_under_dmarc() {
        let pipeline = run_pipeline("10.0.0.1", &forwarded_message(), |b| {
            b.arc_dmarc_policy(Arc::new(TrustList))
        });
        assert_eq!(pipeline.verdict().poll(), Some(AuthVerdict::Pass));
    }

    #[test]
    fn broken_arc_chain_does_not_rescue_forwarded_mail() {
        // Tampering with the body invalidates the newest message signature,
        // so the policy sees a failed chain and declines to override.
        let mut forwarded = forwarded_message();
        let len = forwarded.len();
        forwarded[len - 8..len - 2].copy_from_slice(b"XXXXXX");
        let pipeline = run_pipeline("10.0.0.1", &forwarded, |b| {
            b.arc_dmarc_policy(Arc::new(TrustList))
        });
        assert_eq!(
            pipeline.arc_result().unwrap().poll().unwrap().cv,
            crate::auth::arc::ArcCv::Fail
        );
        assert_eq!(pipeline.verdict().poll(), Some(AuthVerdict::Reject));
    }

    #[test]
    fn arc_handles_are_absent_unless_opted_in() {
        let pipeline = run_pipeline("192.0.2.5", &message("alice@example.com"), |b| b);
        assert!(pipeline.arc_result().is_none());
        assert!(pipeline.arc_seal().is_none());
    }

    #[test]
    fn arc_result_is_recorded_in_authentication_results() {
        let pipeline = run_pipeline("10.0.0.1", &forwarded_message(), |b| {
            b.authentication_results("mail.example.com").arc_validation()
        });
        let rendered = pipeline.authentication_results().unwrap().poll().unwrap();
        assert!(rendered.contains(";\r\n\tarc=pass"), "{rendered}");
    }
}
