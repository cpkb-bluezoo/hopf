// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! `SmtpSend` — auto-pilot delivery pipeline.
//!
//! Drives: greeting → EHLO → (STARTTLS) → (AUTH) → MAIL FROM → RCPT TO(s) →
//! DATA or BDAT → message body → QUIT.
//!
//! Users supply the envelope and message at construction; optional hook
//! closures allow overriding any step.

use std::fs::File;
use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use hopf_auth::{create_client, SaslClient, SaslClientStep, SaslMechanism};
use hopf_core::{ConnHandle, Endpoint, Runtime, StorageError};

use crate::{BodyType, DsnRecipientParams};

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
    /// Streamed off disk in bounded chunks at DATA/BDAT time — the message is
    /// never held whole in memory by the client (see [`SmtpSend::message_file`]).
    File(PathBuf),
    /// Open file handle while streaming BDAT / DATA chunks.
    Reading(File),
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

/// Why an [`SmtpSend`] attempt ended (issue #344) — set via
/// [`SmtpSend::on_result`] for callers that need to decide whether the
/// failure is worth retrying. [`SmtpSend::on_complete`]'s plain `bool`
/// collapses all of this to success/failure and stays unaffected by
/// whether `on_result` is also set.
#[derive(Debug, Clone)]
pub enum SmtpSendOutcome {
    /// The message was accepted for delivery.
    Delivered,
    /// The remote server rejected the message with an explicit SMTP reply
    /// code.
    Rejected {
        /// The SMTP reply code (e.g. 550, 452).
        code: u16,
        /// The reply's text.
        message: String,
    },
    /// The attempt ended with no explicit reply code to classify: a
    /// connection failure, a protocol-level desync, TLS/AUTH failure
    /// before any MAIL/RCPT/DATA reply, or similar.
    Failed(String),
}

/// Result of an offloaded DATA/BDAT chunk read (issue #184), stashed by
/// the storage callback for [`SmtpSendDriver::resume_pending_data`] to
/// apply once back on the reactor thread (see
/// [`super::handlers::SmtpClientDriver::resume_pending_data`]).
enum PendingDataOutcome {
    /// Plain-DATA file source exhausted — call `end_message()`.
    EndMessage,
    /// Next BDAT chunk (or the empty-message `BDAT 0 LAST` case).
    BdatChunk { content: Vec<u8>, last: bool },
}

// ── SmtpSendState ─────────────────────────────────────────────────────────────

struct SmtpSendState {
    /// EHLO hostname presented to the server.
    hostname: String,
    /// Envelope sender (None = null sender `<>`).
    sender: Option<String>,
    /// MAIL FROM extension parameters (DSN / REQUIRETLS / …).
    mail_params: MailFromParams,
    /// Envelope recipients with optional per-RCPT DSN params.
    recipients: Vec<(String, DsnRecipientParams)>,
    /// Message source (RFC 5322; will be dot-stuffed for DATA, raw for BDAT).
    message: MessageSource,
    /// Small, already-in-memory bytes to send immediately ahead of `message`
    /// when it's a [`MessageSource::File`] (issue #212 — e.g. a relay
    /// prepending extra header lines ahead of a spooled body). Set via
    /// [`SmtpSend::message_file_with_prefix`]; consumed by the same
    /// offloaded read/send as the file itself, so it costs nothing extra
    /// to include. Meaningless (never consulted) for any other source.
    message_prefix: Option<Vec<u8>>,
    /// Lookahead chunk for BDAT LAST detection.
    bdat_lookahead: Option<Vec<u8>>,
    /// Require STARTTLS before sending (skip delivery if unavailable).
    require_starttls: bool,
    /// Upgrade via STARTTLS if the server advertises it, but proceed in
    /// plaintext rather than failing if it doesn't (issue #353) — RFC
    /// 3207/7672's "opportunistic" mode. Ignored when
    /// [`require_starttls`](Self::require_starttls) is also set; that
    /// takes precedence.
    opportunistic_starttls: bool,
    /// AUTH credentials (username/password, driven via the strongest
    /// mechanism the server advertises — see [`SmtpSendDriver::choose_mechanism`]).
    auth: Option<(String, String)>,
    /// In-progress SASL exchange, between the `334` challenge and our reply.
    sasl_client: Option<Box<dyn SaslClient>>,
    /// Index of the next recipient to send.
    rcpt_idx: usize,
    /// Count of accepted recipients.
    accepted_rcpts: usize,
    /// PIPELINING group failed (e.g. MAIL rejected); drain replies then quit.
    pipeline_abort: bool,
    /// Completion callback.
    on_complete: Option<Box<dyn FnOnce(bool) + Send>>,
    /// Richer completion callback (issue #344) — see [`SmtpSend::on_result`].
    on_result: Option<Box<dyn FnOnce(SmtpSendOutcome) + Send>>,
    /// Set by an offloaded DATA/BDAT chunk read's storage callback (issue
    /// #184); applied by `SmtpSendDriver::resume_pending_data`.
    pending_data: Option<PendingDataOutcome>,
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
            mail_params: MailFromParams::default(),
            recipients: Vec::new(),
            message: MessageSource::default(),
            message_prefix: None,
            bdat_lookahead: None,
            require_starttls: false,
            opportunistic_starttls: false,
            auth: None,
            sasl_client: None,
            rcpt_idx: 0,
            accepted_rcpts: 0,
            pipeline_abort: false,
            on_complete: None,
            on_result: None,
            pending_data: None,
        })))
    }

    /// Set the envelope sender (`MAIL FROM`). Pass empty string for null sender.
    pub fn mail_from(self, sender: impl Into<String>) -> Self {
        let s = sender.into();
        self.0.lock().unwrap().sender = if s.is_empty() { None } else { Some(s) };
        self
    }

    /// Set MAIL FROM extension parameters (SIZE, BODY, REQUIRETLS, RET, ENVID, …).
    pub fn mail_from_params(self, params: MailFromParams) -> Self {
        let require_tls = params.require_tls;
        let mut st = self.0.lock().unwrap();
        st.mail_params = params;
        if require_tls {
            st.require_starttls = true;
        }
        drop(st);
        self
    }

    /// Add an envelope recipient (`RCPT TO`) with default DSN parameters.
    pub fn rcpt_to(self, recipient: impl Into<String>) -> Self {
        self.0
            .lock()
            .unwrap()
            .recipients
            .push((recipient.into(), DsnRecipientParams::default()));
        self
    }

    /// Add an envelope recipient with DSN NOTIFY/ORCPT parameters (RFC 3461).
    pub fn rcpt_to_with(
        self,
        recipient: impl Into<String>,
        params: DsnRecipientParams,
    ) -> Self {
        self.0
            .lock()
            .unwrap()
            .recipients
            .push((recipient.into(), params));
        self
    }

    /// Set envelope recipients, replacing any previously added (default DSN params).
    pub fn recipients(self, recipients: Vec<String>) -> Self {
        self.0.lock().unwrap().recipients = recipients
            .into_iter()
            .map(|r| (r, DsnRecipientParams::default()))
            .collect();
        self
    }

    /// Set envelope recipients with per-recipient DSN parameters.
    pub fn recipients_with(self, recipients: Vec<(String, DsnRecipientParams)>) -> Self {
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

    /// Like [`Self::message_file`], but with `prefix` — small,
    /// already-in-memory bytes (e.g. a relay's extra header lines,
    /// issue #212) — sent immediately ahead of the file's content. The
    /// file itself is still streamed off the reactor thread exactly as
    /// [`Self::message_file`] does (issue #184); `prefix` rides along in
    /// that same offloaded unit of work rather than being read/sent
    /// synchronously on the reactor thread the way a
    /// [`Self::message_with`] closure would be.
    pub fn message_file_with_prefix(self, path: impl Into<PathBuf>, prefix: Vec<u8>) -> Self {
        let mut st = self.0.lock().unwrap();
        st.message = MessageSource::File(path.into());
        st.message_prefix = Some(prefix);
        drop(st);
        self
    }

    /// Require STARTTLS; abort delivery if the server does not support it.
    pub fn require_starttls(self, require: bool) -> Self {
        self.0.lock().unwrap().require_starttls = require;
        self
    }

    /// Upgrade via STARTTLS if the server advertises it, but proceed in
    /// plaintext (rather than aborting) if it doesn't — RFC 3207/7672's
    /// "opportunistic" TLS. Meaningless combined with
    /// [`Self::require_starttls(true)`](Self::require_starttls), which
    /// already upgrades unconditionally when offered and aborts otherwise.
    pub fn opportunistic_starttls(self, enable: bool) -> Self {
        self.0.lock().unwrap().opportunistic_starttls = enable;
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

    /// Register a richer completion callback (issue #344) carrying the
    /// SMTP reply code when one is available — use this instead of (or
    /// alongside) [`Self::on_complete`] when the caller needs to decide
    /// whether a failure is worth retrying (e.g. [`super::RetryingSend`]).
    /// Both callbacks fire independently if both are set.
    pub fn on_result(self, cb: Box<dyn FnOnce(SmtpSendOutcome) + Send>) -> Self {
        self.0.lock().unwrap().on_result = Some(cb);
        self
    }
}

impl SmtpClientHandlerFactory for SmtpSend {
    fn create(&self, runtime: &Arc<Runtime>) -> Box<dyn SmtpClientDriver> {
        Box::new(SmtpSendDriver {
            state: Arc::clone(&self.0),
            runtime: Arc::clone(runtime),
        })
    }
}

// ── SmtpSendDriver ────────────────────────────────────────────────────────────

struct SmtpSendDriver {
    state: Arc<Mutex<SmtpSendState>>,
    runtime: Arc<Runtime>,
}

impl SmtpSendDriver {
    /// Coarse completion — used everywhere a caller only ever distinguished
    /// success from failure. Reported as [`SmtpSendOutcome::Delivered`] /
    /// [`SmtpSendOutcome::Failed`] to any [`SmtpSend::on_result`] callback
    /// too, so a generic failure with no reply code is treated as
    /// retryable there (matching connection-level failures being worth
    /// retrying) rather than silently never reaching that callback at all.
    fn complete(&self, ok: bool) {
        self.finish(if ok {
            SmtpSendOutcome::Delivered
        } else {
            SmtpSendOutcome::Failed(String::new())
        });
    }

    /// Completion with an explicit SMTP reply code — used at the sites
    /// that actually have one (message-level accept/reject).
    fn complete_rejected(&self, code: u16, message: &str) {
        self.finish(SmtpSendOutcome::Rejected {
            code,
            message: message.to_string(),
        });
    }

    fn finish(&self, outcome: SmtpSendOutcome) {
        let ok = matches!(outcome, SmtpSendOutcome::Delivered);
        let on_result = self.state.lock().unwrap().on_result.take();
        if let Some(cb) = on_result {
            cb(outcome);
        }
        let on_complete = self.state.lock().unwrap().on_complete.take();
        if let Some(cb) = on_complete {
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

    /// Pull the next body chunk for BDAT, with one-chunk lookahead so the
    /// LAST flag can be set correctly. A file-backed source (issue #184)
    /// offloads its read(s) to the storage pool and resumes asynchronously
    /// via [`Self::resume_pending_data`]; an in-memory source
    /// (`Chunks`/`Empty`) resolves inline as before.
    fn send_next_bdat_chunk(&self, data: &mut dyn SmtpClientMessageData, ep: &mut dyn Endpoint) {
        let mut st = self.state.lock().unwrap();
        if matches!(st.message, MessageSource::File(_) | MessageSource::Reading(_)) {
            // `message_prefix` (issue #212), if still set, is treated as an
            // already-known first chunk exactly like a real BDAT lookahead
            // would be — `offload_bdat_read` sends it as-is (BDAT chunks
            // aren't dot-stuffed) ahead of reading the file.
            let known_current = st.bdat_lookahead.take().or_else(|| st.message_prefix.take());
            drop(st);
            self.offload_bdat_read(ep, known_current);
            return;
        }
        let current = st
            .bdat_lookahead
            .take()
            .or_else(|| Self::read_one_chunk(&mut st.message));
        let Some(cur) = current else {
            // Empty message → BDAT 0 LAST.
            drop(st);
            data.write_bdat_chunk(&[], true);
            return;
        };
        let following = Self::read_one_chunk(&mut st.message);
        match following {
            None => {
                drop(st);
                data.write_bdat_chunk(&cur, true);
            }
            Some(next) => {
                st.bdat_lookahead = Some(next);
                drop(st);
                data.write_bdat_chunk(&cur, false);
            }
        }
    }

    /// Off-reactor counterpart of the tail of [`Self::send_next_bdat_chunk`]
    /// for a file-backed `message` — reads `known_current` (if not already
    /// known from a previous lookahead) plus the one-chunk lookahead, all
    /// on the storage pool, then stashes a [`PendingDataOutcome::BdatChunk`]
    /// and pokes the endpoint so `resume_pending_data` can apply it.
    fn offload_bdat_read(&self, ep: &mut dyn Endpoint, known_current: Option<Vec<u8>>) {
        let handle = ep.handle();
        let handle_for_cb = handle.clone();
        let state = Arc::clone(&self.state);
        let message = std::mem::replace(&mut state.lock().unwrap().message, MessageSource::Empty);
        // (new `message` state, current chunk, following/lookahead chunk).
        type BdatReadResult = (MessageSource, Option<Vec<u8>>, Option<Vec<u8>>);
        self.runtime.storage().submit_on(
            handle,
            move || -> Result<BdatReadResult, Box<dyn std::error::Error + Send + Sync>> {
                let mut message = message;
                let current = match known_current {
                    Some(c) => Some(c),
                    None => Self::read_one_chunk(&mut message),
                };
                let Some(cur) = current else {
                    return Ok((message, None, None));
                };
                let following = Self::read_one_chunk(&mut message);
                Ok((message, Some(cur), following))
            },
            move |result: Result<BdatReadResult, StorageError>| {
                let (message, current, following) = result.unwrap_or((MessageSource::Empty, None, None));
                let mut st = state.lock().unwrap();
                st.message = message;
                st.bdat_lookahead = following.clone();
                st.pending_data = Some(match current {
                    Some(content) => PendingDataOutcome::BdatChunk {
                        content,
                        last: following.is_none(),
                    },
                    // Empty message → BDAT 0 LAST.
                    None => PendingDataOutcome::BdatChunk {
                        content: Vec::new(),
                        last: true,
                    },
                });
                drop(st);
                handle_for_cb.with_endpoint(|ep| ep.poke_handler());
            },
        );
    }

    fn read_one_chunk(message: &mut MessageSource) -> Option<Vec<u8>> {
        match message {
            MessageSource::Empty => None,
            MessageSource::Chunks(next) => next(),
            MessageSource::File(_) => {
                let path = match std::mem::replace(message, MessageSource::Empty) {
                    MessageSource::File(p) => p,
                    other => {
                        *message = other;
                        return None;
                    }
                };
                match File::open(&path) {
                    Ok(f) => {
                        *message = MessageSource::Reading(f);
                        Self::read_one_chunk(message)
                    }
                    Err(_) => None,
                }
            }
            MessageSource::Reading(f) => {
                let mut buf = [0u8; 8192];
                match f.read(&mut buf) {
                    Ok(0) => {
                        *message = MessageSource::Empty;
                        None
                    }
                    Ok(n) => Some(buf[..n].to_vec()),
                    Err(_) => {
                        *message = MessageSource::Empty;
                        None
                    }
                }
            }
        }
    }

    /// Start MAIL FROM, optionally pipelining RCPT(+DATA) when advertised.
    fn begin_mail(&self, session: &mut dyn SmtpClientSession) {
        let mut st = self.state.lock().unwrap();
        let sender = st.sender.clone();
        let params = st.mail_params.clone();
        let recipients = st.recipients.clone();
        let pipelining = session.capabilities().pipelining;
        let chunking = session.capabilities().chunking;
        if pipelining {
            st.rcpt_idx = recipients.len();
        }
        drop(st);
        // With CHUNKING, defer DATA/BDAT until all RCPT replies arrive.
        let defer_data = chunking;
        session.start_mail(sender.as_deref(), &params, &recipients, defer_data);
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
        if !ep.is_secure() {
            if st.require_starttls {
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
            } else if st.opportunistic_starttls && caps.starttls {
                // Upgrade because it's offered, but this isn't a hard
                // requirement — a server that didn't advertise it falls
                // through to the plaintext path below unremarked.
                drop(st);
                session.starttls();
                return;
            }
        }

        // AUTH path.
        if let Some((user, pass)) = st.auth.clone() {
            if let Some(mech) = Self::choose_mechanism(&caps.auth_methods) {
                let mut client = create_client(mech, &user, &pass, "", "smtp", None);
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
        let params = st.mail_params.clone();
        if params.require_tls && !caps.require_tls {
            drop(st);
            // RFC 8689 §4.2.1: next hop must advertise REQUIRETLS after TLS.
            self.complete(false);
            session.quit();
            return;
        }
        if params.body == Some(BodyType::BinaryMime)
            && (!caps.binary_mime || !caps.chunking)
        {
            drop(st);
            // RFC 3030: BINARYMIME requires CHUNKING.
            self.complete(false);
            session.quit();
            return;
        }
        if let (Some(size), max) = (params.size, caps.max_size) {
            if max > 0 && size > max {
                drop(st);
                self.complete(false);
                session.quit();
                return;
            }
        }
        drop(st);
        self.begin_mail(session);
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
        self.begin_mail(session);
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
        self.begin_mail(session);
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
        if envelope.awaiting_more_replies() {
            // PIPELINING: RCPT(+DATA) already queued.
            return;
        }
        // Send first recipient.
        let rcpt = {
            let st = self.state.lock().unwrap();
            st.recipients.first().cloned()
        };
        if let Some((r, params)) = rcpt {
            self.state.lock().unwrap().rcpt_idx = 1;
            envelope.rcpt_to(&r, &params);
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
        if session.awaiting_more_replies() {
            self.state.lock().unwrap().pipeline_abort = true;
            return;
        }
        self.complete(false);
        session.quit();
    }

    fn on_rcpt_ok(
        &mut self,
        envelope: &mut dyn SmtpClientEnvelope,
        _ep: &mut dyn Endpoint,
        _recipient: &str,
    ) {
        self.state.lock().unwrap().accepted_rcpts += 1;
        if envelope.awaiting_more_replies() {
            return;
        }
        if self.state.lock().unwrap().pipeline_abort {
            self.complete(false);
            envelope.quit();
            return;
        }
        // Try next recipient or start DATA/BDAT.
        let next = {
            let mut st = self.state.lock().unwrap();
            let idx = st.rcpt_idx;
            st.rcpt_idx += 1;
            st.recipients.get(idx).cloned()
        };
        if let Some((r, params)) = next {
            envelope.rcpt_to(&r, &params);
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
        if envelope.awaiting_more_replies() {
            return;
        }
        if self.state.lock().unwrap().pipeline_abort {
            self.complete(false);
            envelope.quit();
            return;
        }
        // Try next recipient even if this one was rejected.
        let next = {
            let mut st = self.state.lock().unwrap();
            let idx = st.rcpt_idx;
            st.rcpt_idx += 1;
            st.recipients.get(idx).cloned()
        };
        if let Some((r, params)) = next {
            envelope.rcpt_to(&r, &params);
        } else if envelope.has_accepted_recipients() {
            envelope.start_data();
        } else {
            // All rejected.
            self.complete(false);
            envelope.rset();
        }
    }

    fn on_ready_for_data(&mut self, data: &mut dyn SmtpClientMessageData, ep: &mut dyn Endpoint) {
        if self.state.lock().unwrap().pipeline_abort {
            // MAIL failed earlier in a pipelined group — close DATA without a body.
            if !data.is_bdat_mode() {
                data.end_message();
            }
            return;
        }
        if data.is_bdat_mode() {
            self.send_next_bdat_chunk(data, ep);
            return;
        }
        let source = std::mem::take(&mut self.state.lock().unwrap().message);
        match source {
            MessageSource::Empty | MessageSource::Reading(_) => {}
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
                // Read + dot-stuff the file off the reactor thread (issue
                // #184) via `submit_streamed`, sending each stuffed chunk
                // straight to the wire (`h.send()`, bypassing
                // `write_content`'s own internal buffer — see `DotStuffer`'s
                // doc comment) so a relay fanning one spooled message out
                // to several MX hosts never holds the whole message in
                // memory again per host. `end_message()` needs `data`
                // (only reachable via `resume_pending_data`, since the
                // storage callback only has a bare `ConnHandle`), so it
                // runs there instead of inline below.
                //
                // `message_prefix` (issue #212), if set, is fed through the
                // same `stuffer` first — its own dot-stuffing state must be
                // continuous across the prefix→file boundary, and since the
                // whole read is already offloaded here, folding the (small,
                // already-in-memory) prefix into this same closure costs
                // nothing extra rather than dot-stuffing it separately on
                // the reactor thread.
                let prefix = self.state.lock().unwrap().message_prefix.take();
                let handle = ep.handle();
                let handle_for_cb = handle.clone();
                let state = Arc::clone(&self.state);
                self.runtime.storage().submit_streamed(
                    handle,
                    move |h: &ConnHandle| -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                        let mut stuffer = DotStuffer::new();
                        if let Some(prefix) = prefix {
                            let mut out = Vec::with_capacity(prefix.len() + 16);
                            stuffer.feed(&prefix, &mut out);
                            h.send(out);
                        }
                        if let Ok(mut f) = File::open(&path) {
                            let mut buf = [0u8; 8192];
                            loop {
                                let n = f.read(&mut buf).unwrap_or(0);
                                if n == 0 {
                                    break;
                                }
                                let mut out = Vec::with_capacity(n + 16);
                                stuffer.feed(&buf[..n], &mut out);
                                h.send(out);
                            }
                        }
                        let mut out = Vec::new();
                        stuffer.finish(&mut out);
                        if !out.is_empty() {
                            h.send(out);
                        }
                        Ok(())
                    },
                    move |_result: Result<(), StorageError>| {
                        state.lock().unwrap().pending_data = Some(PendingDataOutcome::EndMessage);
                        handle_for_cb.with_endpoint(|ep| ep.poke_handler());
                    },
                );
                return;
            }
        }
        data.end_message();
    }

    fn on_bdat_chunk_ok(&mut self, data: &mut dyn SmtpClientMessageData, ep: &mut dyn Endpoint) {
        self.send_next_bdat_chunk(data, ep);
    }

    fn on_data_rejected(
        &mut self,
        envelope: &mut dyn SmtpClientEnvelope,
        _ep: &mut dyn Endpoint,
        code: u16,
        message: &str,
    ) {
        // This one-shot pipeline doesn't retry itself — a caller that
        // wants retry behavior wraps it (see `SmtpSend::on_result` /
        // `super::RetryingSend`, issue #344).
        self.complete_rejected(code, message);
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
        code: u16,
        message: &str,
    ) {
        self.complete_rejected(code, message);
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

    fn resume_pending_data(&mut self, data: &mut dyn SmtpClientMessageData, _ep: &mut dyn Endpoint) {
        let outcome = self.state.lock().unwrap().pending_data.take();
        match outcome {
            None => {}
            Some(PendingDataOutcome::EndMessage) => data.end_message(),
            Some(PendingDataOutcome::BdatChunk { content, last }) => {
                data.write_bdat_chunk(&content, last)
            }
        }
    }
}

/// Issue #184: plain-DATA and BDAT file-source reads are offloaded to
/// [`hopf_core::StorageExecutor`] rather than read inline on the reactor
/// thread. Drives [`SmtpClientEndpoint`] directly (no real TCP) against a
/// mock [`Endpoint`] whose `handle()` is backed by
/// [`hopf_core::ConnHandleBackend`] — unlike a task-only `ConnHandle`
/// (`from_execute`), this makes the storage callback's `with_endpoint`
/// (and the offloaded op's own `ConnHandle::send`) actually reach the mock,
/// which is what these tests need to observe.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::endpoint::SmtpClientEndpoint;
    use hopf_core::{ConnHandleBackend, ProtocolHandler, RuntimeConfig, SecurityInfo, StartTlsError, TimerHandle, WriteReadyCallback};
    use std::net::SocketAddr;
    use std::time::Duration;

    #[derive(Default)]
    struct SharedMockEp {
        sent: Vec<u8>,
        open: bool,
    }

    struct MockEndpoint {
        shared: Arc<Mutex<SharedMockEp>>,
    }

    struct TestBackend {
        shared: Arc<Mutex<SharedMockEp>>,
    }

    impl ConnHandleBackend for TestBackend {
        fn with_endpoint(&self, task: Box<dyn FnOnce(&mut dyn Endpoint) + Send>) {
            let mut ep = MockEndpoint {
                shared: Arc::clone(&self.shared),
            };
            task(&mut ep);
        }
        fn execute(&self, task: Box<dyn FnOnce() + Send>) {
            task();
        }
        fn is_probably_open(&self) -> bool {
            self.shared.lock().unwrap().open
        }
        fn schedule_timer(&self, _delay: Duration, _callback: Box<dyn FnOnce() + Send>) -> TimerHandle {
            TimerHandle::from_cancel(|| {})
        }
    }

    impl Endpoint for MockEndpoint {
        fn send(&mut self, data: &[u8]) {
            self.shared.lock().unwrap().sent.extend_from_slice(data);
        }
        fn is_open(&self) -> bool {
            self.shared.lock().unwrap().open
        }
        fn is_closing(&self) -> bool {
            false
        }
        fn close(&mut self) {
            self.shared.lock().unwrap().open = false;
        }
        fn local_addr(&self) -> io::Result<hopf_core::PeerAddr> {
            Ok(hopf_core::PeerAddr::Inet("127.0.0.1:25".parse().unwrap()))
        }
        fn remote_addr(&self) -> io::Result<hopf_core::PeerAddr> {
            Ok(hopf_core::PeerAddr::Inet("127.0.0.1:9999".parse().unwrap()))
        }
        fn security_info(&self) -> &SecurityInfo {
            static PLAINTEXT: std::sync::OnceLock<SecurityInfo> = std::sync::OnceLock::new();
            PLAINTEXT.get_or_init(SecurityInfo::plaintext)
        }
        fn start_tls(&mut self) -> Result<(), StartTlsError> {
            Err(StartTlsError::Unsupported)
        }
        fn pause_read(&mut self) {}
        fn resume_read(&mut self) {}
        fn on_write_ready(&mut self, _callback: Option<WriteReadyCallback>) {}
        fn execute(&self, task: Box<dyn FnOnce() + Send>) {
            task();
        }
        fn schedule_timer(
            &self,
            _delay: std::time::Duration,
            _callback: Box<dyn FnOnce() + Send>,
        ) -> TimerHandle {
            TimerHandle::from_cancel(|| {})
        }
        fn handle(&self) -> ConnHandle {
            ConnHandle::from_backend(Arc::new(TestBackend {
                shared: Arc::clone(&self.shared),
            }))
        }
    }

    impl MockEndpoint {
        fn new() -> Self {
            Self {
                shared: Arc::new(Mutex::new(SharedMockEp {
                    sent: Vec::new(),
                    open: true,
                })),
            }
        }
        fn sent(&self) -> Vec<u8> {
            self.shared.lock().unwrap().sent.clone()
        }
    }

    fn feed(client: &mut SmtpClientEndpoint, ep: &mut MockEndpoint, line: &[u8]) {
        let mut data = line;
        client.receive(ep, &mut data);
    }

    /// Feed `line`, retrying (to let a poked-but-not-really-poked async
    /// offload — `poke_handler`'s default is a no-op on this mock — apply
    /// once ready) until `sent()` satisfies `ready`.
    fn feed_and_wait_until(
        client: &mut SmtpClientEndpoint,
        ep: &mut MockEndpoint,
        line: &[u8],
        ready: impl Fn(&[u8]) -> bool,
        max_ms: u64,
    ) {
        let mut data = line;
        client.receive(ep, &mut data);
        for _ in 0..(max_ms / 5).max(1) {
            if ready(&ep.sent()) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
            let mut empty: &[u8] = &[];
            client.receive(ep, &mut empty);
        }
        assert!(ready(&ep.sent()), "condition never satisfied: {:?}", String::from_utf8_lossy(&ep.sent()));
    }

    #[test]
    fn plain_data_file_source_is_offloaded_and_dot_stuffed() {
        let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("msg.eml");
        std::fs::write(&path, b"Subject: hi\r\n\r\n.leading dot\r\nbody\r\n").unwrap();

        let done: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
        let done2 = Arc::clone(&done);
        let send = SmtpSend::new("client.example")
            .mail_from("a@example.com")
            .rcpt_to("b@example.com")
            .message_file(&path)
            .on_complete(Box::new(move |ok| *done2.lock().unwrap() = Some(ok)));

        let mut client = SmtpClientEndpoint::new(
            &send,
            &rt,
            Duration::from_secs(5),
            Duration::from_secs(60),
            None,
            None,
        );
        let mut ep = MockEndpoint::new();

        client.connected(&mut ep);
        feed(&mut client, &mut ep, b"220 test.example ESMTP\r\n");
        feed(&mut client, &mut ep, b"250-test.example\r\n250 OK\r\n"); // EHLO — no PIPELINING/CHUNKING
        feed(&mut client, &mut ep, b"250 OK\r\n"); // MAIL FROM
        feed(&mut client, &mut ep, b"250 OK\r\n"); // RCPT TO
        ep.shared.lock().unwrap().sent.clear();

        // Triggers `on_ready_for_data`, which offloads the file read.
        feed_and_wait_until(
            &mut client,
            &mut ep,
            b"354 Start mail input\r\n",
            |sent| sent.ends_with(b".\r\n"),
            2000,
        );
        let sent = ep.sent();
        // Dot-stuffing must still apply even though the read moved off the
        // reactor thread: the leading dot on its own line is doubled.
        assert!(
            sent.windows(6).any(|w| w == b"..lead"),
            "leading dot must be stuffed: {:?}",
            String::from_utf8_lossy(&sent)
        );
        assert!(sent.ends_with(b".\r\n"), "must end with the DATA terminator");

        feed(&mut client, &mut ep, b"250 2.0.0 Message accepted\r\n");
        assert_eq!(*done.lock().unwrap(), Some(true));
    }

    #[test]
    fn bdat_file_source_is_offloaded_across_multiple_chunks() {
        let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("msg.eml");
        // Larger than the 8192-byte read buffer, so the lookahead logic
        // must offload (at least) two reads across two BDAT chunks.
        let body = vec![b'x'; 9000];
        std::fs::write(&path, &body).unwrap();

        let done: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
        let done2 = Arc::clone(&done);
        let send = SmtpSend::new("client.example")
            .mail_from("a@example.com")
            .rcpt_to("b@example.com")
            .message_file(&path)
            .on_complete(Box::new(move |ok| *done2.lock().unwrap() = Some(ok)));

        let mut client = SmtpClientEndpoint::new(
            &send,
            &rt,
            Duration::from_secs(5),
            Duration::from_secs(60),
            None,
            None,
        );
        let mut ep = MockEndpoint::new();

        client.connected(&mut ep);
        feed(&mut client, &mut ep, b"220 test.example ESMTP\r\n");
        feed(&mut client, &mut ep, b"250-test.example\r\n250 CHUNKING\r\n"); // EHLO — advertise CHUNKING
        feed(&mut client, &mut ep, b"250 OK\r\n"); // MAIL FROM
        ep.shared.lock().unwrap().sent.clear();

        // RCPT TO accepted → `start_data()` enters BDAT mode immediately
        // (no DATA/354 exchange) → `on_ready_for_data` → offloaded read.
        feed_and_wait_until(
            &mut client,
            &mut ep,
            b"250 OK\r\n",
            |sent| sent.starts_with(b"BDAT 8192\r\n") && sent.len() >= b"BDAT 8192\r\n".len() + 8192,
            2000,
        );
        let first = ep.sent();
        assert!(
            first.starts_with(b"BDAT 8192\r\n"),
            "first chunk must be the full 8192-byte read, not LAST: {:?}",
            &first[..first.len().min(40)]
        );
        ep.shared.lock().unwrap().sent.clear();

        // Ack the first chunk → the driver already knows the next 808
        // bytes (from round 1's lookahead read); it offloads one more read
        // to discover EOF and mark this chunk LAST.
        feed_and_wait_until(
            &mut client,
            &mut ep,
            b"250 OK\r\n",
            |sent| sent.starts_with(b"BDAT 808 LAST\r\n"),
            2000,
        );
        let second = ep.sent();
        assert!(
            second.starts_with(b"BDAT 808 LAST\r\n"),
            "second chunk must be the remaining 808 bytes, marked LAST: {:?}",
            &second[..second.len().min(40)]
        );

        feed(&mut client, &mut ep, b"250 2.0.0 Message accepted\r\n");
        assert_eq!(*done.lock().unwrap(), Some(true));
    }

    /// Issue #212: a relay's extra header lines, prepended via
    /// `message_file_with_prefix`, must appear before the (offloaded, dot-
    /// stuffed) file content — and dot-stuffing state must carry
    /// continuously across the prefix→file boundary, proven here by a file
    /// that itself starts with a leading dot.
    #[test]
    fn message_file_with_prefix_prepends_prefix_ahead_of_dot_stuffed_file_content() {
        let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("msg.eml");
        std::fs::write(&path, b".leading dot\r\nbody\r\n").unwrap();
        let prefix = b"X-Relay-Added: yes\r\n".to_vec();

        let done: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
        let done2 = Arc::clone(&done);
        let send = SmtpSend::new("client.example")
            .mail_from("a@example.com")
            .rcpt_to("b@example.com")
            .message_file_with_prefix(&path, prefix.clone())
            .on_complete(Box::new(move |ok| *done2.lock().unwrap() = Some(ok)));

        let mut client = SmtpClientEndpoint::new(
            &send,
            &rt,
            Duration::from_secs(5),
            Duration::from_secs(60),
            None,
            None,
        );
        let mut ep = MockEndpoint::new();

        client.connected(&mut ep);
        feed(&mut client, &mut ep, b"220 test.example ESMTP\r\n");
        feed(&mut client, &mut ep, b"250-test.example\r\n250 OK\r\n"); // EHLO — no PIPELINING/CHUNKING
        feed(&mut client, &mut ep, b"250 OK\r\n"); // MAIL FROM
        feed(&mut client, &mut ep, b"250 OK\r\n"); // RCPT TO
        ep.shared.lock().unwrap().sent.clear();

        feed_and_wait_until(
            &mut client,
            &mut ep,
            b"354 Start mail input\r\n",
            |sent| sent.ends_with(b".\r\n"),
            2000,
        );
        let sent = ep.sent();
        assert!(
            sent.starts_with(&prefix),
            "prefix must be sent first, ahead of the file content: {:?}",
            String::from_utf8_lossy(&sent[..sent.len().min(64)])
        );
        assert!(
            sent.windows(14).any(|w| w == b"\r\n..leading do"),
            "leading dot in the file content (after the prefix) must still be stuffed: {:?}",
            String::from_utf8_lossy(&sent)
        );

        feed(&mut client, &mut ep, b"250 2.0.0 Message accepted\r\n");
        assert_eq!(*done.lock().unwrap(), Some(true));
    }

    /// Issue #212: for BDAT (no dot-stuffing), the prefix must arrive as
    /// its own first chunk, verbatim, ahead of the file's content chunk(s).
    #[test]
    fn message_file_with_prefix_sent_as_first_bdat_chunk() {
        let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("msg.eml");
        std::fs::write(&path, b"body content\r\n").unwrap();
        let prefix = b"X-Relay-Added: yes\r\n".to_vec();

        let done: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
        let done2 = Arc::clone(&done);
        let send = SmtpSend::new("client.example")
            .mail_from("a@example.com")
            .rcpt_to("b@example.com")
            .message_file_with_prefix(&path, prefix.clone())
            .on_complete(Box::new(move |ok| *done2.lock().unwrap() = Some(ok)));

        let mut client = SmtpClientEndpoint::new(
            &send,
            &rt,
            Duration::from_secs(5),
            Duration::from_secs(60),
            None,
            None,
        );
        let mut ep = MockEndpoint::new();

        client.connected(&mut ep);
        feed(&mut client, &mut ep, b"220 test.example ESMTP\r\n");
        feed(&mut client, &mut ep, b"250-test.example\r\n250 CHUNKING\r\n"); // EHLO — advertise CHUNKING
        feed(&mut client, &mut ep, b"250 OK\r\n"); // MAIL FROM
        ep.shared.lock().unwrap().sent.clear();

        let expected_first = format!("BDAT {}\r\n", prefix.len());
        feed_and_wait_until(
            &mut client,
            &mut ep,
            b"250 OK\r\n",
            |sent| sent.starts_with(expected_first.as_bytes()),
            2000,
        );
        let first = ep.sent();
        assert!(
            first.ends_with(&prefix),
            "first BDAT chunk must be exactly the prefix, unstuffed: {:?}",
            String::from_utf8_lossy(&first)
        );
        ep.shared.lock().unwrap().sent.clear();

        feed_and_wait_until(
            &mut client,
            &mut ep,
            b"250 OK\r\n",
            |sent| sent.starts_with(b"BDAT 14 LAST\r\n"),
            2000,
        );
        let second = ep.sent();
        assert!(
            second.ends_with(b"body content\r\n"),
            "second BDAT chunk must be the file content, marked LAST: {:?}",
            String::from_utf8_lossy(&second)
        );

        feed(&mut client, &mut ep, b"250 2.0.0 Message accepted\r\n");
        assert_eq!(*done.lock().unwrap(), Some(true));
    }
}
