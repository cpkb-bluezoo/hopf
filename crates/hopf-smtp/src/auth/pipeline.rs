// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! [`AuthPipeline`] — SPF/DKIM/DMARC wired into [`crate::SmtpPipeline`].

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use rmimeparser::dkim::{DkimMessageParser, RawHeader};
use rmimeparser::{EmailAddress, EmailAddressParser, MessageHandler, MimeHandler};

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

    fn message_content(&mut self, chunk: &[u8]) {
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

                let keys = dkim::required_body_hash_keys(&headers);
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
        if let Some(inner) = &mut self.inner {
            inner.message_content(chunk);
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
        let from_domain = from_header_domain(&headers);

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
        let authserv_id = self.authserv_id.clone();
        let auth_results = self.auth_results.clone();
        let spf_domain_for_ar = self.spf_domain.clone();

        dkim::verify_all_with_body_hashes(
            Arc::clone(&dns),
            headers,
            Arc::new(body_hashes),
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
                let Some(from_domain) = from_domain else {
                    // No usable `From:` header — DMARC cannot be evaluated;
                    // fail open (no enforcement) rather than block forever.
                    verdict.resolve(AuthVerdict::None);
                    if let Some(authserv_id) = authserv_id {
                        let dkim_results = Arc::clone(&dkim_results);
                        spf_relay.on_ready(Box::new(move |spf_outcome| {
                            auth_results.0.resolve(render_authentication_results(
                                &authserv_id,
                                &spf_outcome,
                                spf_domain_for_ar.as_deref().unwrap_or(""),
                                &dkim_results,
                                None,
                            ));
                        }));
                    }
                    return;
                };
                spf_relay.on_ready(Box::new(move |spf_outcome| {
                    let spf_outcome_for_ar = spf_outcome.clone();
                    let dkim_results_for_ar = Arc::clone(&dkim_results);
                    dmarc::evaluate(
                        dns,
                        psl,
                        &from_domain,
                        spf_outcome.result,
                        spf_domain,
                        dkim_results,
                        Box::new(move |outcome| {
                            let v = outcome.verdict;
                            if let Some(authserv_id) = authserv_id {
                                auth_results.0.resolve(render_authentication_results(
                                    &authserv_id,
                                    &spf_outcome_for_ar,
                                    spf_domain_for_ar.as_deref().unwrap_or(""),
                                    &dkim_results_for_ar,
                                    Some(&outcome),
                                ));
                            }
                            if let Some(cb) = on_dmarc {
                                cb(outcome);
                            }
                            verdict.resolve(v);
                        }),
                    );
                }));
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
fn find_header_boundary(buf: &[u8]) -> Option<usize> {
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

fn from_header_domain(headers: &[RawHeader]) -> Option<String> {
    let from = headers
        .iter()
        .find(|h| h.name().eq_ignore_ascii_case("From"))?;
    let s = from.as_string_unfolded();
    let value = s.split_once(':').map(|(_, v)| v.trim()).unwrap_or("");
    let addresses = EmailAddressParser::parse_email_address_list(value)?;
    for addr in &addresses {
        if let Some(mailbox) = addr.as_mailbox() {
            return Some(mailbox.domain().to_string());
        }
    }
    None
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
}
