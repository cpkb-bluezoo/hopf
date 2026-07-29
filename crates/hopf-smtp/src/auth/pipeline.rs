// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! [`AuthPipeline`] — SPF/DKIM/DMARC wired into [`crate::SmtpPipeline`].

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use rmimeparser::dkim::{DkimMessageParser, RawHeader};
use rmimeparser::{EmailAddress, EmailAddressParser, MessageHandler, MimeHandler};

use crate::auth::dkim::{self, DkimSignatureResult};
use crate::auth::dmarc::{self, AuthVerdict, DmarcOutcome};
use crate::auth::dns_lookup::DnsLookup;
use crate::auth::psl::PublicSuffixList;
use crate::auth::spf::{self, SpfOutcome};
use crate::SmtpPipeline;

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
            message_buf: Vec::new(),
        }
    }
}

/// SPF + DKIM + DMARC transaction pipeline (Gumdrop `AuthPipeline` port).
///
/// SPF starts at `mail_from`. DKIM verification and DMARC evaluation start
/// at `end_data`, once the full message (buffered internally) is available.
/// Because these depend on DNS, none of them complete synchronously — use
/// the `on_*` callbacks and/or [`AuthPipeline::verdict`] to observe results.
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
    message_buf: Vec<u8>,
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
        self.message_buf.extend_from_slice(chunk);
        if let Some(inner) = &mut self.inner {
            inner.message_content(chunk);
        }
    }

    fn end_data(&mut self) {
        let headers;
        let body;
        {
            let mut handler = NoopMessageHandler;
            let mut parser = DkimMessageParser::new(&mut handler);
            let mut data: &[u8] = &self.message_buf;
            let _ = parser.receive(&mut data);
            let _ = parser.close();
            headers = parser.raw_headers().to_vec();
            body = parser.raw_body().to_vec();
        }
        let from_domain = from_header_domain(&headers);

        let headers = Arc::new(headers);
        let body = Arc::new(body);
        let dns = Arc::clone(&self.dns);
        let psl = PublicSuffixList::bundled();
        let on_dkim = self.on_dkim.take();
        let on_dmarc = self.on_dmarc.take();
        let verdict = self.verdict.clone();
        let spf_relay = Arc::clone(&self.spf_relay);
        let spf_domain = self.spf_domain.clone();

        dkim::verify_all(
            Arc::clone(&dns),
            headers,
            body,
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
                let Some(from_domain) = from_domain else {
                    // No usable `From:` header — DMARC cannot be evaluated;
                    // fail open (no enforcement) rather than block forever.
                    verdict.resolve(AuthVerdict::None);
                    return;
                };
                let dkim_results = Arc::new(dkim_results);
                spf_relay.on_ready(Box::new(move |spf_outcome| {
                    dmarc::evaluate(
                        dns,
                        psl,
                        &from_domain,
                        spf_outcome.result,
                        spf_domain,
                        dkim_results,
                        Box::new(move |outcome| {
                            let v = outcome.verdict;
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
        self.message_buf.clear();
        if let Some(inner) = &mut self.inner {
            inner.reset();
        }
    }
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
}
