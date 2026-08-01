// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! `Pop3Fetch` — auto-pilot message-fetch pipeline.
//!
//! Drives: greeting → CAPA → (STLS) → CAPA → USER/PASS or APOP → STAT →
//! LIST → RETR each message → (DELE each) → QUIT.
//!
//! # Example
//!
//! ```no_run
//! use std::sync::Arc;
//! use hopf_core::{Runtime, RuntimeConfig};
//! use hopf_pop3::{Pop3Client, Pop3Fetch};
//!
//! let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
//! use hopf_pop3::client::MessageReceiveCallback;
//!
//! #[derive(Default)]
//! struct PrintSizes { total: usize }
//! impl MessageReceiveCallback for PrintSizes {
//!     fn message_content(&mut self, chunk: &[u8]) -> bool {
//!         self.total += chunk.len();
//!         true
//!     }
//!     fn end_message(&mut self) {
//!         println!("message: {} bytes", self.total);
//!         self.total = 0;
//!     }
//! }
//!
//! let fetch = Pop3Fetch::new()
//!     .credentials("alice", "s3cr3t")
//!     .delete_after_fetch(true)
//!     .on_message(Box::new(PrintSizes::default()))
//!     .on_complete(Box::new(|ok| println!("done: {ok}")));
//! Pop3Client::new("pop3.example.com", 110)
//!     .connect(&rt, Arc::new(fetch))
//!     .unwrap();
//! ```

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};

use hopf_auth::{create_client, SaslClient, SaslClientStep, SaslMechanism};
use hopf_core::Endpoint;

use super::handlers::{Pop3ClientDriver, Pop3ClientHandlerFactory};
use super::reply::ContentId;
use super::state::{
    Pop3Capabilities, Pop3ClientAuthExchange, Pop3ClientAuthorization, Pop3ClientPassword,
    Pop3ClientPostStls, Pop3ClientTransaction,
};

// ── State ─────────────────────────────────────────────────────────────────────

/// Callback for [`Pop3Fetch::on_message`] — driven per message, across
/// however many wire chunks it takes to arrive; [`Pop3Fetch`] never
/// buffers a message whole to deliver it.
pub trait MessageReceiveCallback: Send {
    /// Called once, before any content. `uid` is always `None` in the
    /// default RETR-driven flow (UIDL isn't requested as part of it).
    fn start_message(&mut self, id: u32, uid: Option<&str>) {
        let _ = (id, uid);
    }

    /// Called with each already dot-unstuffed chunk of RFC 822 bytes, in
    /// order. Returning `false` stops further chunks from being delivered
    /// to this callback for the current message (the connection still has
    /// to consume them off the wire to stay in sync — POP3 has no way to
    /// abort a RETR response mid-stream).
    fn message_content(&mut self, chunk: &[u8]) -> bool;

    /// Called once, after the last chunk (or after an early stop).
    fn end_message(&mut self) {}
}

struct Pop3FetchState {
    credentials: Option<(String, String)>,
    prefer_apop: bool,
    delete_after_fetch: bool,
    require_stls: bool,
    /// APOP challenge from the greeting, e.g. `<timestamp@host>`.
    apop_timestamp: Option<String>,
    /// In-progress SASL exchange (mechanism beyond PLAIN's single-shot
    /// initial response), awaiting the next server challenge.
    sasl_client: Option<Box<dyn SaslClient>>,
    /// IDs of messages to fetch (populated after LIST).
    pending: VecDeque<u32>,
    /// Message currently being fetched (for DELE).
    current_id: u32,
    /// Once the current message's callback has signaled "stop", further
    /// `message_content` chunks are consumed but not forwarded.
    current_stopped: bool,
    /// Whether the session ended successfully.
    success: bool,
    /// Per-message callback.
    on_message: Option<Box<dyn MessageReceiveCallback>>,
    /// Session-complete callback.
    on_complete: Option<Box<dyn FnOnce(bool) + Send>>,
}

// ── Pop3Fetch ─────────────────────────────────────────────────────────────────

/// Auto-pilot POP3 fetch pipeline.
///
/// Implements [`Pop3ClientHandlerFactory`]; pass to [`Pop3Client::connect`].
pub struct Pop3Fetch(Arc<Mutex<Pop3FetchState>>);

impl Pop3Fetch {
    /// Create a new fetch pipeline with default settings.
    pub fn new() -> Self {
        Pop3Fetch(Arc::new(Mutex::new(Pop3FetchState {
            credentials: None,
            prefer_apop: true,
            delete_after_fetch: false,
            require_stls: false,
            apop_timestamp: None,
            sasl_client: None,
            pending: VecDeque::new(),
            current_id: 0,
            current_stopped: false,
            success: false,
            on_message: None,
            on_complete: None,
        })))
    }

    /// Set USER/PASS (or APOP) credentials.
    pub fn credentials(
        self,
        user: impl Into<String>,
        pass: impl Into<String>,
    ) -> Self {
        self.0.lock().unwrap().credentials = Some((user.into(), pass.into()));
        self
    }

    /// Prefer APOP when the server provides a timestamp in the greeting.
    /// Default: `true`.
    pub fn prefer_apop(self, prefer: bool) -> Self {
        self.0.lock().unwrap().prefer_apop = prefer;
        self
    }

    /// Delete each message from the server after a successful RETR.
    /// Default: `false`.
    pub fn delete_after_fetch(self, delete: bool) -> Self {
        self.0.lock().unwrap().delete_after_fetch = delete;
        self
    }

    /// Require STLS before authentication. If the server doesn't support
    /// STLS, authentication is aborted. Default: `false`.
    pub fn require_stls(self, require: bool) -> Self {
        self.0.lock().unwrap().require_stls = require;
        self
    }

    /// Register a per-message callback — see [`MessageReceiveCallback`].
    pub fn on_message(self, cb: Box<dyn MessageReceiveCallback>) -> Self {
        self.0.lock().unwrap().on_message = Some(cb);
        self
    }

    /// Register a session-complete callback. `ok = true` on success.
    pub fn on_complete(self, cb: Box<dyn FnOnce(bool) + Send>) -> Self {
        self.0.lock().unwrap().on_complete = Some(cb);
        self
    }
}

impl Default for Pop3Fetch {
    fn default() -> Self {
        Self::new()
    }
}

impl Pop3ClientHandlerFactory for Pop3Fetch {
    fn create(&self) -> Box<dyn Pop3ClientDriver> {
        Box::new(Pop3FetchDriver { state: Arc::clone(&self.0) })
    }
}

// ── Pop3FetchDriver ───────────────────────────────────────────────────────────

struct Pop3FetchDriver {
    state: Arc<Mutex<Pop3FetchState>>,
}

impl Pop3FetchDriver {
    fn complete(&self, ok: bool) {
        let mut st = self.state.lock().unwrap();
        st.success = ok;
        if let Some(cb) = st.on_complete.take() {
            cb(ok);
        }
    }

    /// Compute APOP digest: MD5(timestamp || password) as lowercase hex.
    fn apop_digest(timestamp: &str, password: &str) -> String {
        use md5::{Digest, Md5};
        let mut h = Md5::new();
        h.update(timestamp.as_bytes());
        h.update(password.as_bytes());
        let result = h.finalize();
        result.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The strongest mechanism this auto-pilot can drive with a bare
    /// username/password that the server actually advertises. Excludes
    /// DIGEST-MD5 (deprecated, needs a hostname this pipeline doesn't
    /// track), OAUTHBEARER (needs a bearer token, not a password), and
    /// EXTERNAL (needs a client certificate) — a custom driver can still
    /// use any of those directly via [`Pop3ClientAuthorization::auth`].
    fn choose_mechanism(sasl_mechs: &[String]) -> Option<SaslMechanism> {
        const PREFERENCE: &[SaslMechanism] = &[
            SaslMechanism::ScramSha256,
            SaslMechanism::CramMd5,
            SaslMechanism::Plain,
            SaslMechanism::Login,
        ];
        PREFERENCE
            .iter()
            .copied()
            .find(|m| sasl_mechs.iter().any(|s| s.eq_ignore_ascii_case(m.name())))
    }

    /// Try to authenticate using the best available method.
    fn authenticate(
        &self,
        auth: &mut dyn Pop3ClientAuthorization,
        caps: &Pop3Capabilities,
    ) -> bool {
        let mut st = self.state.lock().unwrap();
        let Some((user, pass)) = st.credentials.clone() else {
            return false;
        };
        // Prefer APOP if available and desired.
        if st.prefer_apop {
            if let Some(ts) = st.apop_timestamp.clone() {
                let digest = Self::apop_digest(&ts, &pass);
                drop(st);
                auth.apop(&user, &digest);
                return true;
            }
        }
        if let Some(mech) = Self::choose_mechanism(&caps.sasl_mechs) {
            let mut client = create_client(mech, &user, &pass, "", None);
            if client.has_initial_response() {
                if let SaslClientStep::Response(initial) = client.evaluate(None) {
                    st.sasl_client = Some(client);
                    drop(st);
                    auth.auth(mech.name(), Some(&initial));
                    return true;
                }
            } else {
                st.sasl_client = Some(client);
                drop(st);
                auth.auth(mech.name(), None);
                return true;
            }
        }
        // Fall back to USER/PASS.
        drop(st);
        auth.user(&user);
        true
    }

    /// Authenticate after STLS (no APOP possible here).
    fn authenticate_post_stls(
        &self,
        post_stls: &mut dyn Pop3ClientPostStls,
        caps: &Pop3Capabilities,
    ) -> bool {
        let mut st = self.state.lock().unwrap();
        let Some((user, pass)) = st.credentials.clone() else {
            return false;
        };
        if let Some(mech) = Self::choose_mechanism(&caps.sasl_mechs) {
            let mut client = create_client(mech, &user, &pass, "", None);
            if client.has_initial_response() {
                if let SaslClientStep::Response(initial) = client.evaluate(None) {
                    st.sasl_client = Some(client);
                    drop(st);
                    post_stls.auth(mech.name(), Some(&initial));
                    return true;
                }
            } else {
                st.sasl_client = Some(client);
                drop(st);
                post_stls.auth(mech.name(), None);
                return true;
            }
        }
        drop(st);
        post_stls.user(&user);
        true
    }

    /// Fetch the next pending message, or QUIT if all done.
    ///
    /// When there are no more messages, calls `on_complete(true)` BEFORE
    /// sending QUIT so that the completion is delivered even if the QUIT
    /// response triggers an early-return in `disconnected()`.
    fn fetch_next(&self, transaction: &mut dyn Pop3ClientTransaction) {
        let mut st = self.state.lock().unwrap();
        if let Some(id) = st.pending.pop_front() {
            st.current_id = id;
            st.current_stopped = false;
            if let Some(cb) = st.on_message.as_mut() {
                cb.start_message(id, None);
            }
            drop(st);
            transaction.retr(id);
        } else {
            // All messages fetched — fire on_complete(true) before QUIT.
            st.success = true;
            let cb = st.on_complete.take();
            drop(st);
            if let Some(cb) = cb {
                cb(true);
            }
            transaction.quit();
        }
    }
}

impl Pop3ClientDriver for Pop3FetchDriver {
    fn on_greeting(
        &mut self,
        auth: &mut dyn Pop3ClientAuthorization,
        _ep: &mut dyn Endpoint,
        apop_challenge: Option<&ContentId>,
    ) {
        if let Some(challenge) = apop_challenge {
            // APOP's digest is computed over the literal `<local@domain>`
            // banner text, which `ContentId`'s Display reproduces exactly.
            self.state.lock().unwrap().apop_timestamp = Some(challenge.to_string());
        }
        // CAPA first either way, to discover STLS/SASL support.
        auth.capa();
    }

    fn on_capa(
        &mut self,
        auth: &mut dyn Pop3ClientAuthorization,
        ep: &mut dyn Endpoint,
        caps: &Pop3Capabilities,
    ) {
        let require_stls = self.state.lock().unwrap().require_stls;
        if require_stls && !ep.is_secure() {
            if caps.stls {
                auth.stls();
                return;
            } else {
                // STLS required but not available.
                self.complete(false);
                auth.quit();
                return;
            }
        }
        if !self.authenticate(auth, caps) {
            self.complete(false);
            auth.quit();
        }
    }

    fn on_capa_error(
        &mut self,
        auth: &mut dyn Pop3ClientAuthorization,
        _ep: &mut dyn Endpoint,
        _message: &str,
    ) {
        // Some servers don't support CAPA at all — fall back to plain
        // USER/PASS rather than giving up.
        let caps = Pop3Capabilities { user: true, ..Default::default() };
        if !self.authenticate(auth, &caps) {
            self.complete(false);
            auth.quit();
        }
    }

    fn on_capa_post_stls(
        &mut self,
        post_stls: &mut dyn Pop3ClientPostStls,
        ep: &mut dyn Endpoint,
        caps: &Pop3Capabilities,
    ) {
        let _ = ep;
        if !self.authenticate_post_stls(post_stls, caps) {
            self.complete(false);
            post_stls.quit();
        }
    }

    fn on_capa_post_stls_error(
        &mut self,
        post_stls: &mut dyn Pop3ClientPostStls,
        _ep: &mut dyn Endpoint,
        _message: &str,
    ) {
        let caps = Pop3Capabilities { user: true, ..Default::default() };
        if !self.authenticate_post_stls(post_stls, &caps) {
            self.complete(false);
            post_stls.quit();
        }
    }

    fn on_user_ok(&mut self, password: &mut dyn Pop3ClientPassword, _ep: &mut dyn Endpoint) {
        let pass = self
            .state
            .lock()
            .unwrap()
            .credentials
            .as_ref()
            .map(|(_, p)| p.clone())
            .unwrap_or_default();
        password.pass(&pass);
    }

    fn on_authenticated(
        &mut self,
        transaction: &mut dyn Pop3ClientTransaction,
        _ep: &mut dyn Endpoint,
    ) {
        transaction.stat();
    }

    fn on_auth_failed(
        &mut self,
        auth: &mut dyn Pop3ClientAuthorization,
        _ep: &mut dyn Endpoint,
        _message: &str,
    ) {
        self.complete(false);
        auth.quit();
    }

    fn on_auth_aborted(&mut self, auth: &mut dyn Pop3ClientAuthorization, _ep: &mut dyn Endpoint) {
        // PLAIN never issues its own abort — this only fires if the server
        // sent an unexpected challenge, which `on_auth_challenge` answers
        // with `exchange.abort()`. Treat the same as a failed AUTH.
        self.complete(false);
        auth.quit();
    }

    fn on_auth_challenge(
        &mut self,
        exchange: &mut dyn Pop3ClientAuthExchange,
        _ep: &mut dyn Endpoint,
        challenge: &[u8],
    ) {
        let mut st = self.state.lock().unwrap();
        let Some(mut client) = st.sasl_client.take() else {
            // PLAIN/USER-PASS/APOP never reach here; an unexpected
            // challenge with no in-progress exchange can't be answered.
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

    fn on_tls_established(
        &mut self,
        post_stls: &mut dyn Pop3ClientPostStls,
        _ep: &mut dyn Endpoint,
    ) {
        post_stls.capa();
    }

    fn on_tls_unavailable(
        &mut self,
        auth: &mut dyn Pop3ClientAuthorization,
        _ep: &mut dyn Endpoint,
    ) {
        // require_stls is already checked in on_capa; reaching here means
        // the server rejected STLS despite advertising it.
        self.complete(false);
        auth.quit();
    }

    fn on_stat(
        &mut self,
        transaction: &mut dyn Pop3ClientTransaction,
        _ep: &mut dyn Endpoint,
        count: u32,
        _octets: u64,
    ) {
        if count == 0 {
            // Empty maildrop — nothing to fetch.
            self.complete(true);
            transaction.quit();
            return;
        }
        transaction.list(None);
    }

    fn on_stat_error(
        &mut self,
        transaction: &mut dyn Pop3ClientTransaction,
        _ep: &mut dyn Endpoint,
        _message: &str,
    ) {
        // Nothing to fetch without a message count — give up gracefully.
        self.complete(false);
        transaction.quit();
    }

    fn on_list_entry(&mut self, message: u32, _size: u64) {
        self.state.lock().unwrap().pending.push_back(message);
    }

    fn on_list_complete(
        &mut self,
        transaction: &mut dyn Pop3ClientTransaction,
        _ep: &mut dyn Endpoint,
    ) {
        self.fetch_next(transaction);
    }

    fn on_list_single(
        &mut self,
        transaction: &mut dyn Pop3ClientTransaction,
        _ep: &mut dyn Endpoint,
        message: u32,
        _size: u64,
    ) {
        self.state.lock().unwrap().pending.push_back(message);
        self.fetch_next(transaction);
    }

    fn on_list_error(
        &mut self,
        transaction: &mut dyn Pop3ClientTransaction,
        _ep: &mut dyn Endpoint,
        _message: &str,
    ) {
        self.complete(false);
        transaction.quit();
    }

    fn on_uidl_entry(&mut self, _message: u32, _uid: &str) {}

    fn on_uidl_complete(
        &mut self,
        transaction: &mut dyn Pop3ClientTransaction,
        _ep: &mut dyn Endpoint,
    ) {
        self.fetch_next(transaction);
    }

    fn on_uidl_error(
        &mut self,
        transaction: &mut dyn Pop3ClientTransaction,
        _ep: &mut dyn Endpoint,
        _message: &str,
    ) {
        self.complete(false);
        transaction.quit();
    }

    fn on_uidl_single(
        &mut self,
        _transaction: &mut dyn Pop3ClientTransaction,
        _ep: &mut dyn Endpoint,
        _message: u32,
        _uid: &str,
    ) {
    }



    fn on_message_content(&mut self, data: &[u8], _ep: &mut dyn Endpoint) {
        let mut st = self.state.lock().unwrap();
        if st.current_stopped {
            return;
        }
        if let Some(cb) = st.on_message.as_mut() {
            if !cb.message_content(data) {
                st.current_stopped = true;
            }
        }
    }

    fn on_message_complete(
        &mut self,
        transaction: &mut dyn Pop3ClientTransaction,
        _ep: &mut dyn Endpoint,
        _is_top: bool,
        message: u32,
    ) {
        let delete_after_fetch = {
            let mut st = self.state.lock().unwrap();
            if let Some(cb) = st.on_message.as_mut() {
                cb.end_message();
            }
            st.delete_after_fetch
        };

        if delete_after_fetch {
            transaction.dele(message);
        } else {
            self.fetch_next(transaction);
        }
    }

    fn on_dele_ok(
        &mut self,
        transaction: &mut dyn Pop3ClientTransaction,
        _ep: &mut dyn Endpoint,
    ) {
        self.fetch_next(transaction);
    }

    fn on_rset_ok(
        &mut self,
        transaction: &mut dyn Pop3ClientTransaction,
        _ep: &mut dyn Endpoint,
    ) {
        transaction.quit();
    }

    fn on_noop_ok(
        &mut self,
        _transaction: &mut dyn Pop3ClientTransaction,
        _ep: &mut dyn Endpoint,
    ) {
    }

    fn on_no_such_message(
        &mut self,
        transaction: &mut dyn Pop3ClientTransaction,
        _ep: &mut dyn Endpoint,
        _message: &str,
    ) {
        // Skip this message and try the next.
        self.fetch_next(transaction);
    }

    fn on_message_deleted(
        &mut self,
        transaction: &mut dyn Pop3ClientTransaction,
        _ep: &mut dyn Endpoint,
        _message: &str,
    ) {
        // Already deleted — nothing to fetch, move on.
        self.fetch_next(transaction);
    }

    fn on_already_deleted(
        &mut self,
        transaction: &mut dyn Pop3ClientTransaction,
        _ep: &mut dyn Endpoint,
        _message: &str,
    ) {
        // DELE's goal (the message gone) is already achieved either way.
        self.fetch_next(transaction);
    }


    fn on_error(&mut self, ep: &mut dyn Endpoint, _err: &io::Error) {
        self.complete(false);
        ep.close();
    }

    fn on_timeout(&mut self, ep: &mut dyn Endpoint) {
        self.complete(false);
        ep.close();
    }

    fn on_disconnected(&mut self, _ep: &mut dyn Endpoint, _message: Option<&str>) {
        // If we sent QUIT successfully, success flag was already set to true.
        // Otherwise, fire on_complete(false) if it hasn't been called yet.
        let mut st = self.state.lock().unwrap();
        if let Some(cb) = st.on_complete.take() {
            cb(st.success);
        }
    }
}
