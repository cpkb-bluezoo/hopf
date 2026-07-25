// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! `SmtpSend` — auto-pilot delivery pipeline.
//!
//! Drives: greeting → EHLO → (STARTTLS) → (AUTH) → MAIL FROM → RCPT TO(s) →
//! DATA → message body → QUIT.
//!
//! Users supply the envelope and message at construction; optional hook
//! closures allow overriding any step.

use std::io;
use std::sync::{Arc, Mutex};

use hopf_core::Endpoint;

use super::handlers::{SmtpClientDriver, SmtpClientHandlerFactory};
use super::state::{
    SmtpCapabilities, SmtpClientAuthExchange, SmtpClientEnvelope, SmtpClientHello,
    SmtpClientMessageData, SmtpClientPostTls, SmtpClientSession,
};

// ── SmtpSendState ─────────────────────────────────────────────────────────────

struct SmtpSendState {
    /// EHLO hostname presented to the server.
    hostname: String,
    /// Envelope sender (None = null sender `<>`).
    sender: Option<String>,
    /// Envelope recipients (at least one required).
    recipients: Vec<String>,
    /// Message bytes (RFC 5322; will be dot-stuffed).
    message: Vec<u8>,
    /// Require STARTTLS before sending (skip delivery if unavailable).
    require_starttls: bool,
    /// AUTH PLAIN credentials.
    auth: Option<(String, String)>,
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
/// let send = SmtpSend::new("smtp-send.local")
///     .mail_from("from@example.com")
///     .rcpt_to("to@example.com")
///     .message(b"Subject: test\r\n\r\nhello\r\n".to_vec())
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
            message: Vec::new(),
            require_starttls: false,
            auth: None,
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

    /// Set the message bytes.
    pub fn message(self, bytes: Vec<u8>) -> Self {
        self.0.lock().unwrap().message = bytes;
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

    /// Build AUTH PLAIN initial response bytes.
    fn auth_plain_initial(user: &str, pass: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(0u8);
        buf.extend_from_slice(user.as_bytes());
        buf.push(0u8);
        buf.extend_from_slice(pass.as_bytes());
        buf
    }
}

impl SmtpClientDriver for SmtpSendDriver {
    fn on_greeting(
        &mut self,
        hello: &mut dyn SmtpClientHello,
        _ep: &mut dyn Endpoint,
        _message: &str,
        esmtp: bool,
    ) {
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
        let st = self.state.lock().unwrap();

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
        if let Some((ref user, ref pass)) = st.auth {
            if caps.auth_methods.iter().any(|m| m == "PLAIN") {
                let initial = Self::auth_plain_initial(user, pass);
                drop(st);
                session.auth("PLAIN", Some(&initial));
                return;
            }
        }

        // Proceed to envelope.
        let sender = st.sender.clone();
        drop(st);
        session.mail_from(sender.as_deref());
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
        session.mail_from(sender.as_deref());
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

    fn on_auth_ok(&mut self, session: &mut dyn SmtpClientSession, _ep: &mut dyn Endpoint) {
        let sender = self.state.lock().unwrap().sender.clone();
        session.mail_from(sender.as_deref());
    }

    fn on_auth_challenge(
        &mut self,
        exchange: &mut dyn SmtpClientAuthExchange,
        _ep: &mut dyn Endpoint,
        _challenge: &[u8],
    ) {
        // PLAIN doesn't use challenges; abort.
        exchange.abort();
    }

    fn on_auth_failed(&mut self, session: &mut dyn SmtpClientSession, _ep: &mut dyn Endpoint) {
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
            envelope.rcpt_to(&r);
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
            envelope.rcpt_to(&r);
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
            envelope.rcpt_to(&r);
        } else if envelope.has_accepted_recipients() {
            envelope.start_data();
        } else {
            // All rejected.
            self.complete(false);
            envelope.rset();
        }
    }

    fn on_ready_for_data(&mut self, data: &mut dyn SmtpClientMessageData, _ep: &mut dyn Endpoint) {
        let message = self.state.lock().unwrap().message.clone();
        data.write_content(&message);
        data.end_message();
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
