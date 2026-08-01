// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! `SmtpSend` — auto-pilot delivery pipeline.
//!
//! Drives: greeting → EHLO → (STARTTLS) → (AUTH) → MAIL FROM → RCPT TO(s) →
//! DATA → message body → QUIT.
//!
//! Users supply the envelope and message at construction; optional hook
//! closures allow overriding any step.

use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use hopf_auth::{create_client, SaslClient, SaslClientStep, SaslMechanism};
use hopf_core::Endpoint;

use crate::DsnRecipientParams;

use super::handlers::{SmtpClientDriver, SmtpClientHandlerFactory};
use super::state::{
    MailFromParams, SmtpCapabilities, SmtpClientAuthExchange, SmtpClientEnvelope,
    SmtpClientHello, SmtpClientMessageData, SmtpClientPostTls, SmtpClientSession,
};
use super::DotStuffer;

/// Where [`SmtpSend`] reads the message body from.
enum MessageSource {
    /// No content at all (a genuinely empty message).
    Empty,
    /// Streamed off disk in bounded chunks at DATA time — the message is
    /// never held whole in memory by the client (see [`SmtpSend::message_file`]).
    File(PathBuf),
    /// Pulled from a caller-supplied source one chunk at a time —
    /// `None` signals end of message. Never buffers more than one chunk
    /// at a time (see [`SmtpSend::message_with`]).
    Chunks(Box<dyn FnMut() -> Option<Vec<u8>> + Send>),
}

impl Default for MessageSource {
    fn default() -> Self {
        MessageSource::Empty
    }
}

// ── SmtpSendState ─────────────────────────────────────────────────────────────

struct SmtpSendState {
    /// EHLO hostname presented to the server.
    hostname: String,
    /// Envelope sender (None = null sender `<>`).
    sender: Option<String>,
    /// Envelope recipients (at least one required).
    recipients: Vec<String>,
    /// Message source (RFC 5322; will be dot-stuffed).
    message: MessageSource,
    /// Require STARTTLS before sending (skip delivery if unavailable).
    require_starttls: bool,
    /// AUTH credentials (username/password, driven via the strongest
    /// mechanism the server advertises — see [`SmtpSendDriver::choose_mechanism`]).
    auth: Option<(String, String)>,
    /// In-progress SASL exchange, between the `334` challenge and our reply.
    sasl_client: Option<Box<dyn SaslClient>>,
    /// Index of the next recipient to send.
    rcpt_idx: usize,
    /// Count of accepted recipients.
    accepted_rcpts: usize,
    /// Completion callback.
    on_complete: Option<Box<dyn FnOnce(bool) + Send>>,
}

// ── SmtpSend ─────────────────────────────────────────────────────────────────

/// Auto-pilot SMTP delivery pipeline.
///
/// Implements [`SmtpClientHandlerFactory`]; pass to
/// [`crate::client::SmtpClient::connect`].
///
/// # Example
///
/// ```no_run
/// use std::sync::Arc;
/// use hopf_core::{Runtime, RuntimeConfig};
/// use hopf_smtp::SmtpClient;
/// use hopf_smtp::client::SmtpSend;
///
/// let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
/// let mut body = Some(&b"Subject: test\r\n\r\nhello\r\n"[..]);
/// let send = SmtpSend::new("smtp-send.local")
///     .mail_from("from@example.com")
///     .rcpt_to("to@example.com")
///     .message_with(move || body.take().map(|b| b.to_vec()))
///     .on_complete(Box::new(|ok| eprintln!("delivery: {ok}")));
/// SmtpClient::new("127.0.0.1", 25)
///     .connect(&rt, Arc::new(send))
///     .unwrap();
/// ```
pub struct SmtpSend(Arc<Mutex<SmtpSendState>>);

impl SmtpSend {
    /// Create a new pipeline. `hostname` is the EHLO identity.
    pub fn new(hostname: impl Into<String>) -> Self {
        SmtpSend(Arc::new(Mutex::new(SmtpSendState {
            hostname: hostname.into(),
            sender: None,
            recipients: Vec::new(),
            message: MessageSource::default(),
            require_starttls: false,
            auth: None,
            sasl_client: None,
            rcpt_idx: 0,
            accepted_rcpts: 0,
            on_complete: None,
        })))
    }

    /// Set the envelope sender (`MAIL FROM`). Pass empty string for null sender.
    pub fn mail_from(self, sender: impl Into<String>) -> Self {
        let s = sender.into();
        self.0.lock().unwrap().sender = if s.is_empty() { None } else { Some(s) };
        self
    }

    /// Add an envelope recipient (`RCPT TO`).
    pub fn rcpt_to(self, recipient: impl Into<String>) -> Self {
        self.0.lock().unwrap().recipients.push(recipient.into());
        self
    }

    /// Set envelope recipients, replacing any previously added.
    pub fn recipients(self, recipients: Vec<String>) -> Self {
        self.0.lock().unwrap().recipients = recipients;
        self
    }

    /// Set the message body to genuinely empty content (no `Vec<u8>`
    /// buffering needed — there's nothing to buffer).
    pub fn message_empty(self) -> Self {
        self.0.lock().unwrap().message = MessageSource::Empty;
        self
    }

    /// Set the message body to be pulled from `next_chunk`, called
    /// repeatedly at DATA time until it returns `None` — never more than
    /// one chunk held in memory at a time. Use this for an in-memory or
    /// otherwise caller-controlled source; prefer [`Self::message_file`]
    /// when the content is already staged on disk.
    pub fn message_with(
        self,
        next_chunk: impl FnMut() -> Option<Vec<u8>> + Send + 'static,
    ) -> Self {
        self.0.lock().unwrap().message = MessageSource::Chunks(Box::new(next_chunk));
        self
    }

    /// Set the message body to be streamed from a file at DATA time, in
    /// bounded chunks, rather than held in memory as a `Vec<u8>` — for
    /// senders (like a relay fanning the same message out to several MX
    /// hosts) that already have the message staged on disk and want to
    /// avoid buffering it again per outbound connection.
    pub fn message_file(self, path: impl Into<PathBuf>) -> Self {
        self.0.lock().unwrap().message = MessageSource::File(path.into());
        self
    }

    /// Require STARTTLS; abort delivery if the server does not support it.
    pub fn require_starttls(self, require: bool) -> Self {
        self.0.lock().unwrap().require_starttls = require;
        self
    }

    /// Set AUTH PLAIN credentials.
    pub fn auth_plain(self, user: impl Into<String>, pass: impl Into<String>) -> Self {
        self.0.lock().unwrap().auth = Some((user.into(), pass.into()));
        self
    }

    /// Register a completion callback: `ok = true` on success, `false` on error.
    pub fn on_complete(self, cb: Box<dyn FnOnce(bool) + Send>) -> Self {
        self.0.lock().unwrap().on_complete = Some(cb);
        self
    }
}

impl SmtpClientHandlerFactory for SmtpSend {
    fn create(&self) -> Box<dyn SmtpClientDriver> {
        Box::new(SmtpSendDriver { state: Arc::clone(&self.0) })
    }
}

// ── SmtpSendDriver ────────────────────────────────────────────────────────────

struct SmtpSendDriver {
    state: Arc<Mutex<SmtpSendState>>,
}

impl SmtpSendDriver {
    fn complete(&self, ok: bool) {
        let mut st = self.state.lock().unwrap();
        if let Some(cb) = st.on_complete.take() {
            cb(ok);
        }
    }

    /// The strongest mechanism this auto-pilot can drive with a bare
    /// username/password that the server actually advertises. Excludes
    /// DIGEST-MD5 (deprecated, needs a hostname this pipeline doesn't
    /// track), OAUTHBEARER (needs a bearer token, not a password), and
    /// EXTERNAL (needs a client certificate) — a custom driver can still
    /// use any of those directly via [`SmtpClientSession::auth`].
    fn choose_mechanism(auth_methods: &[String]) -> Option<SaslMechanism> {
        const PREFERENCE: &[SaslMechanism] = &[
            SaslMechanism::ScramSha256,
            SaslMechanism::CramMd5,
            SaslMechanism::Plain,
            SaslMechanism::Login,
        ];
        PREFERENCE
            .iter()
            .copied()
            .find(|m| auth_methods.iter().any(|s| s.eq_ignore_ascii_case(m.name())))
    }
}

impl SmtpClientDriver for SmtpSendDriver {
    fn on_greeting(&mut self, hello: &mut dyn SmtpClientHello, _ep: &mut dyn Endpoint, esmtp: bool) {
        let hostname = self.state.lock().unwrap().hostname.clone();
        if esmtp {
            hello.ehlo(&hostname);
        } else {
            hello.helo(&hostname);
        }
    }

    fn on_service_unavailable(&mut self, ep: &mut dyn Endpoint, _message: &str) {
        self.complete(false);
        ep.close();
    }

    fn on_ehlo(
        &mut self,
        session: &mut dyn SmtpClientSession,
        ep: &mut dyn Endpoint,
        caps: &SmtpCapabilities,
    ) {
        let mut st = self.state.lock().unwrap();

        // STARTTLS path (skip if the session is already secure — post-TLS EHLO).
        if st.require_starttls && !ep.is_secure() {
            if caps.starttls {
                drop(st);
                session.starttls();
                return;
            } else {
                drop(st);
                // STARTTLS required but not advertised.
                self.complete(false);
                session.quit();
                return;
            }
        }

        // AUTH path.
        if let Some((user, pass)) = st.auth.clone() {
            if let Some(mech) = Self::choose_mechanism(&caps.auth_methods) {
                let mut client = create_client(mech, &user, &pass, "", None);
                if client.has_initial_response() {
                    if let SaslClientStep::Response(initial) = client.evaluate(None) {
                        st.sasl_client = Some(client);
                        drop(st);
                        session.auth(mech.name(), Some(&initial));
                        return;
                    }
                } else {
                    st.sasl_client = Some(client);
                    drop(st);
                    session.auth(mech.name(), None);
                    return;
                }
            }
        }

        // Proceed to envelope.
        let sender = st.sender.clone();
        drop(st);
        session.mail_from(sender.as_deref(), &MailFromParams::default());
    }

    fn on_ehlo_not_supported(
        &mut self,
        session: &mut dyn SmtpClientSession,
        _ep: &mut dyn Endpoint,
    ) {
        let hostname = self.state.lock().unwrap().hostname.clone();
        session.helo(&hostname);
    }

    fn on_ehlo_error(&mut self, ep: &mut dyn Endpoint, _message: &str) {
        self.complete(false);
        ep.close();
    }

    fn on_helo(&mut self, session: &mut dyn SmtpClientSession, _ep: &mut dyn Endpoint) {
        let sender = self.state.lock().unwrap().sender.clone();
        session.mail_from(sender.as_deref(), &MailFromParams::default());
    }

    fn on_helo_error(&mut self, ep: &mut dyn Endpoint, _message: &str) {
        self.complete(false);
        ep.close();
    }

    fn on_tls_established(
        &mut self,
        post_tls: &mut dyn SmtpClientPostTls,
        _ep: &mut dyn Endpoint,
    ) {
        let hostname = self.state.lock().unwrap().hostname.clone();
        post_tls.ehlo(&hostname);
    }

    fn on_tls_unavailable(
        &mut self,
        session: &mut dyn SmtpClientSession,
        _ep: &mut dyn Endpoint,
    ) {
        // STARTTLS was required — abort.
        self.complete(false);
        session.quit();
    }

    fn on_tls_error(&mut self, ep: &mut dyn Endpoint, _message: &str) {
        self.complete(false);
        ep.close();
    }

    fn on_auth_ok(&mut self, session: &mut dyn SmtpClientSession, _ep: &mut dyn Endpoint) {
        let sender = self.state.lock().unwrap().sender.clone();
        session.mail_from(sender.as_deref(), &MailFromParams::default());
    }

    fn on_auth_challenge(
        &mut self,
        exchange: &mut dyn SmtpClientAuthExchange,
        _ep: &mut dyn Endpoint,
        challenge: &[u8],
    ) {
        let mut st = self.state.lock().unwrap();
        let Some(mut client) = st.sasl_client.take() else {
            // No in-progress exchange (e.g. AUTH PLAIN never has a
            // challenge to answer): an unexpected challenge can't be
            // driven — abort.
            drop(st);
            exchange.abort();
            return;
        };
        match client.evaluate(Some(challenge)) {
            SaslClientStep::Response(r) => {
                st.sasl_client = Some(client);
                drop(st);
                exchange.respond(&r);
            }
            SaslClientStep::Complete(r) => {
                // Some mechanisms (e.g. SCRAM-SHA-256) send a trailing
                // informational challenge (the server's `v=` verifier)
                // after the exchange is otherwise done; our server sends
                // it without waiting for a reply. Keep the client so a
                // further `on_auth_challenge` call can absorb that
                // instead of falling into the "no exchange" abort path.
                st.sasl_client = Some(client);
                drop(st);
                if !r.is_empty() {
                    exchange.respond(&r);
                }
            }
            SaslClientStep::Failure => {
                drop(st);
                exchange.abort();
            }
        }
    }

    fn on_auth_failed(
        &mut self,
        session: &mut dyn SmtpClientSession,
        _ep: &mut dyn Endpoint,
        _code: u16,
    ) {
        self.complete(false);
        session.quit();
    }

    fn on_auth_aborted(&mut self, session: &mut dyn SmtpClientSession, _ep: &mut dyn Endpoint) {
        // PLAIN never issues its own abort — this only fires if the server
        // sent an unexpected challenge, which `on_auth_challenge` answers
        // with `exchange.abort()`. Treat the same as a failed AUTH.
        self.complete(false);
        session.quit();
    }

    fn on_mail_ok(&mut self, envelope: &mut dyn SmtpClientEnvelope, _ep: &mut dyn Endpoint) {
        // Send first recipient.
        let rcpt = {
            let st = self.state.lock().unwrap();
            st.recipients.first().cloned()
        };
        if let Some(r) = rcpt {
            self.state.lock().unwrap().rcpt_idx = 1;
            envelope.rcpt_to(&r, &DsnRecipientParams::default());
        } else {
            // No recipients — abort.
            self.complete(false);
            envelope.rset();
        }
    }

    fn on_mail_rejected(
        &mut self,
        session: &mut dyn SmtpClientSession,
        _ep: &mut dyn Endpoint,
        _code: u16,
        _message: &str,
    ) {
        self.complete(false);
        session.quit();
    }

    fn on_rcpt_ok(
        &mut self,
        envelope: &mut dyn SmtpClientEnvelope,
        _ep: &mut dyn Endpoint,
        _recipient: &str,
    ) {
        // Try next recipient or start DATA.
        let next = {
            let mut st = self.state.lock().unwrap();
            st.accepted_rcpts += 1;
            let idx = st.rcpt_idx;
            st.rcpt_idx += 1;
            st.recipients.get(idx).cloned()
        };
        if let Some(r) = next {
            envelope.rcpt_to(&r, &DsnRecipientParams::default());
        } else {
            envelope.start_data();
        }
    }

    fn on_rcpt_rejected(
        &mut self,
        envelope: &mut dyn SmtpClientEnvelope,
        _ep: &mut dyn Endpoint,
        _recipient: &str,
        _code: u16,
        _message: &str,
    ) {
        // Try next recipient even if this one was rejected.
        let next = {
            let mut st = self.state.lock().unwrap();
            let idx = st.rcpt_idx;
            st.rcpt_idx += 1;
            st.recipients.get(idx).cloned()
        };
        if let Some(r) = next {
            envelope.rcpt_to(&r, &DsnRecipientParams::default());
        } else if envelope.has_accepted_recipients() {
            envelope.start_data();
        } else {
            // All rejected.
            self.complete(false);
            envelope.rset();
        }
    }

    fn on_ready_for_data(&mut self, data: &mut dyn SmtpClientMessageData, ep: &mut dyn Endpoint) {
        let source = std::mem::take(&mut self.state.lock().unwrap().message);
        match source {
            MessageSource::Empty => {}
            MessageSource::Chunks(mut next_chunk) => {
                let mut stuffer = DotStuffer::new();
                let mut out = Vec::with_capacity(8192);
                while let Some(chunk) = next_chunk() {
                    out.clear();
                    stuffer.feed(&chunk, &mut out);
                    ep.send(&out);
                }
                out.clear();
                stuffer.finish(&mut out);
                if !out.is_empty() {
                    ep.send(&out);
                }
            }
            MessageSource::File(path) => {
                // Streamed in bounded chunks straight to the wire via
                // `ep.send()` (bypassing `write_content`'s own internal
                // buffer, which only flushes once this whole callback
                // returns — see `DotStuffer`'s doc comment) so a relay
                // fanning one spooled message out to several MX hosts never
                // holds the whole message in memory again per host.
                let mut stuffer = DotStuffer::new();
                let mut out = Vec::with_capacity(8192);
                if let Ok(mut f) = std::fs::File::open(&path) {
                    let mut buf = [0u8; 8192];
                    loop {
                        let n = f.read(&mut buf).unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        out.clear();
                        stuffer.feed(&buf[..n], &mut out);
                        ep.send(&out);
                    }
                }
                out.clear();
                stuffer.finish(&mut out);
                if !out.is_empty() {
                    ep.send(&out);
                }
            }
        }
        data.end_message();
    }

    fn on_data_rejected(
        &mut self,
        envelope: &mut dyn SmtpClientEnvelope,
        _ep: &mut dyn Endpoint,
        _code: u16,
        _message: &str,
    ) {
        // The auto-pilot pipeline doesn't retry — give up like every other
        // rejection path.
        self.complete(false);
        envelope.quit();
    }

    fn on_message_accepted(
        &mut self,
        session: &mut dyn SmtpClientSession,
        _ep: &mut dyn Endpoint,
        _queue_id: Option<&str>,
    ) {
        self.complete(true);
        session.quit();
    }

    fn on_message_rejected(
        &mut self,
        session: &mut dyn SmtpClientSession,
        _ep: &mut dyn Endpoint,
        _code: u16,
        _message: &str,
    ) {
        self.complete(false);
        session.quit();
    }

    fn on_rset_ok(&mut self, session: &mut dyn SmtpClientSession, _ep: &mut dyn Endpoint) {
        session.quit();
    }

    // SmtpSend's auto-pilot flow never issues VRFY/EXPN itself, so these
    // callbacks are unreachable in practice — implemented only to satisfy
    // the trait.
    fn on_vrfy_ok(
        &mut self,
        _session: &mut dyn SmtpClientSession,
        _ep: &mut dyn Endpoint,
        _code: u16,
        _text: &str,
    ) {
    }

    fn on_vrfy_failed(
        &mut self,
        _session: &mut dyn SmtpClientSession,
        _ep: &mut dyn Endpoint,
        _code: u16,
        _message: &str,
    ) {
    }

    fn on_expn_ok(
        &mut self,
        _session: &mut dyn SmtpClientSession,
        _ep: &mut dyn Endpoint,
        _members: &[String],
    ) {
    }

    fn on_expn_failed(
        &mut self,
        _session: &mut dyn SmtpClientSession,
        _ep: &mut dyn Endpoint,
        _code: u16,
        _message: &str,
    ) {
    }

    fn on_error(&mut self, ep: &mut dyn Endpoint, _err: &io::Error) {
        self.complete(false);
        ep.close();
    }

    fn on_timeout(&mut self, ep: &mut dyn Endpoint) {
        self.complete(false);
        ep.close();
    }

    fn on_disconnected(&mut self, _ep: &mut dyn Endpoint) {
        // Completion already called on QUIT path; this is a no-op fallback.
        let _ = self.state.lock().unwrap().on_complete.take();
    }
}
