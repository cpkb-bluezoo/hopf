// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Default client pipelines: [`ImapFetch`], [`ImapIdle`], and pipelining helpers.

use std::io;
use std::sync::{Arc, Mutex};

use hopf_core::Endpoint;

use super::handlers::{ImapClientDriver, ImapClientHandlerFactory, MailboxEventListener};
use super::reply::ImapStatus;
use super::state::{
    ImapCapabilities, ImapClientAppend, ImapClientAuthExchange, ImapClientAuthenticated,
    ImapClientIdle, ImapClientNotAuthenticated, ImapClientPostStarttls, ImapClientSelected,
    ImapFetchData, ImapMailboxInfo,
};

struct ImapFetchState {
    username: String,
    password: String,
    mailbox: String,
    /// FETCH sequence set (default `"1:*"`).
    sequence_set: String,
    /// FETCH items (default `"(RFC822)"`).
    fetch_items: String,
    require_starttls: bool,
    prefer_auth_plain: bool,
    body_buf: Vec<u8>,
    success: bool,
    on_message: Option<Box<dyn FnMut(u32, Option<u32>, Vec<u8>) + Send>>,
    on_complete: Option<Box<dyn FnOnce(bool) + Send>>,
    events: Option<Box<dyn MailboxEventListener>>,
}

/// Auto-pilot IMAP fetch pipeline.
///
/// Drives: greeting → CAPABILITY → (STARTTLS → CAPABILITY) → LOGIN/AUTH PLAIN
/// → SELECT → FETCH → LOGOUT.
pub struct ImapFetch(Arc<Mutex<ImapFetchState>>);

impl ImapFetch {
    /// Create a new fetch pipeline.
    pub fn new() -> Self {
        ImapFetch(Arc::new(Mutex::new(ImapFetchState {
            username: String::new(),
            password: String::new(),
            mailbox: "INBOX".into(),
            sequence_set: "1:*".into(),
            fetch_items: "(RFC822)".into(),
            require_starttls: false,
            prefer_auth_plain: true,
            body_buf: Vec::new(),
            success: false,
            on_message: None,
            on_complete: None,
            events: None,
        })))
    }

    /// Set LOGIN / AUTH PLAIN credentials.
    pub fn credentials(self, user: impl Into<String>, pass: impl Into<String>) -> Self {
        let mut st = self.0.lock().unwrap();
        st.username = user.into();
        st.password = pass.into();
        drop(st);
        self
    }

    /// Mailbox to SELECT (default `INBOX`).
    pub fn mailbox(self, name: impl Into<String>) -> Self {
        self.0.lock().unwrap().mailbox = name.into();
        self
    }

    /// FETCH sequence set (default `1:*`).
    pub fn sequence_set(self, set: impl Into<String>) -> Self {
        self.0.lock().unwrap().sequence_set = set.into();
        self
    }

    /// FETCH items (default `(RFC822)`).
    pub fn fetch_items(self, items: impl Into<String>) -> Self {
        self.0.lock().unwrap().fetch_items = items.into();
        self
    }

    /// Require STARTTLS before authentication.
    pub fn require_starttls(self, require: bool) -> Self {
        self.0.lock().unwrap().require_starttls = require;
        self
    }

    /// Prefer AUTHENTICATE PLAIN when advertised (default true).
    pub fn prefer_auth_plain(self, prefer: bool) -> Self {
        self.0.lock().unwrap().prefer_auth_plain = prefer;
        self
    }

    /// Per-message callback: `(seq, uid, bytes)`.
    pub fn on_message(self, cb: Box<dyn FnMut(u32, Option<u32>, Vec<u8>) + Send>) -> Self {
        self.0.lock().unwrap().on_message = Some(cb);
        self
    }

    /// Session-complete callback. `ok = true` on success.
    pub fn on_complete(self, cb: Box<dyn FnOnce(bool) + Send>) -> Self {
        self.0.lock().unwrap().on_complete = Some(cb);
        self
    }

    /// Optional mailbox event listener.
    pub fn mailbox_events(self, listener: Box<dyn MailboxEventListener>) -> Self {
        self.0.lock().unwrap().events = Some(listener);
        self
    }
}

impl Default for ImapFetch {
    fn default() -> Self {
        Self::new()
    }
}

impl ImapClientHandlerFactory for ImapFetch {
    fn create(&self) -> Box<dyn ImapClientDriver> {
        Box::new(ImapFetchDriver {
            state: Arc::clone(&self.0),
        })
    }
}

struct ImapFetchDriver {
    state: Arc<Mutex<ImapFetchState>>,
}

impl ImapFetchDriver {
    fn complete(&self, ok: bool) {
        let mut st = self.state.lock().unwrap();
        st.success = ok;
        if let Some(cb) = st.on_complete.take() {
            cb(ok);
        }
    }

    fn auth_plain_initial(user: &str, pass: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(0u8);
        buf.extend_from_slice(user.as_bytes());
        buf.push(0u8);
        buf.extend_from_slice(pass.as_bytes());
        buf
    }

    fn do_authenticate(&self, auth: &mut dyn ImapClientNotAuthenticated) {
        let st = self.state.lock().unwrap();
        let user = st.username.clone();
        let pass = st.password.clone();
        let prefer = st.prefer_auth_plain;
        let caps = auth.capabilities().clone();
        drop(st);
        if prefer && caps.auth_plain {
            let initial = Self::auth_plain_initial(&user, &pass);
            auth.authenticate("PLAIN", Some(&initial));
        } else {
            auth.login(&user, &pass);
        }
    }
}

impl ImapClientDriver for ImapFetchDriver {
    fn mailbox_events(&mut self) -> Option<&mut dyn MailboxEventListener> {
        None
    }

    fn on_greeting(
        &mut self,
        auth: &mut dyn ImapClientNotAuthenticated,
        _ep: &mut dyn Endpoint,
        _text: &str,
        _preauth: bool,
    ) {
        auth.capability();
    }

    fn on_capability(
        &mut self,
        auth: &mut dyn ImapClientNotAuthenticated,
        ep: &mut dyn Endpoint,
        caps: &ImapCapabilities,
    ) {
        let require = self.state.lock().unwrap().require_starttls;
        if require && !ep.is_secure() {
            if caps.starttls {
                auth.starttls();
                return;
            }
            self.complete(false);
            ep.close();
            return;
        }
        if !ep.is_secure() && caps.starttls && require {
            auth.starttls();
            return;
        }
        self.do_authenticate(auth);
    }

    fn on_tls_established(
        &mut self,
        post: &mut dyn ImapClientPostStarttls,
        _ep: &mut dyn Endpoint,
    ) {
        post.capability();
    }

    fn on_tls_unavailable(
        &mut self,
        _auth: &mut dyn ImapClientNotAuthenticated,
        ep: &mut dyn Endpoint,
        _message: &str,
    ) {
        self.complete(false);
        ep.close();
    }

    fn on_authenticated(
        &mut self,
        session: &mut dyn ImapClientAuthenticated,
        _ep: &mut dyn Endpoint,
    ) {
        let mailbox = self.state.lock().unwrap().mailbox.clone();
        session.select(&mailbox);
    }

    fn on_auth_failed(
        &mut self,
        _auth: &mut dyn ImapClientNotAuthenticated,
        ep: &mut dyn Endpoint,
        _message: &str,
    ) {
        self.complete(false);
        ep.close();
    }

    fn on_auth_continue(
        &mut self,
        exchange: &mut dyn ImapClientAuthExchange,
        _ep: &mut dyn Endpoint,
        _text: &str,
    ) {
        let st = self.state.lock().unwrap();
        let initial = Self::auth_plain_initial(&st.username, &st.password);
        drop(st);
        exchange.respond(&initial);
    }

    fn on_selected(
        &mut self,
        selected: &mut dyn ImapClientSelected,
        _ep: &mut dyn Endpoint,
        _info: &ImapMailboxInfo,
        _read_only: bool,
    ) {
        let st = self.state.lock().unwrap();
        let set = st.sequence_set.clone();
        let items = st.fetch_items.clone();
        drop(st);
        selected.fetch(&set, &items);
    }

    fn on_select_failed(
        &mut self,
        _session: &mut dyn ImapClientAuthenticated,
        ep: &mut dyn Endpoint,
        _message: &str,
    ) {
        self.complete(false);
        ep.close();
    }

    fn on_fetch_line(&mut self, _line: &str) {}

    fn on_fetch_literal(&mut self, data: &[u8]) {
        self.state.lock().unwrap().body_buf.extend_from_slice(data);
    }

    fn on_fetch_data(&mut self, data: &ImapFetchData) {
        let mut st = self.state.lock().unwrap();
        if !data.body.is_empty() {
            st.body_buf = data.body.clone();
        }
        let body = std::mem::take(&mut st.body_buf);
        let seq = data.seq;
        let uid = data.uid;
        let has_flags = !data.flags.is_empty();
        if let Some(ref mut cb) = st.on_message {
            if !body.is_empty() || uid.is_some() || has_flags {
                cb(seq, uid, body);
            }
        }
    }

    fn on_fetch_complete(
        &mut self,
        selected: &mut dyn ImapClientSelected,
        _ep: &mut dyn Endpoint,
        status: ImapStatus,
        _message: &str,
    ) {
        if status == ImapStatus::Ok {
            self.state.lock().unwrap().success = true;
            selected.logout();
            self.complete(true);
        } else {
            self.complete(false);
            selected.logout();
        }
    }

    fn on_append_continue(
        &mut self,
        _append: &mut dyn ImapClientAppend,
        _ep: &mut dyn Endpoint,
        _text: &str,
    ) {
    }

    fn on_append_complete(
        &mut self,
        _session: &mut dyn ImapClientAuthenticated,
        _ep: &mut dyn Endpoint,
        _status: ImapStatus,
        _message: &str,
    ) {
    }

    fn on_error(&mut self, _ep: &mut dyn Endpoint, _err: &io::Error) {
        self.complete(false);
    }

    fn on_timeout(&mut self, _ep: &mut dyn Endpoint) {
        self.complete(false);
    }

    fn on_disconnected(&mut self, _ep: &mut dyn Endpoint) {
        let ok = self.state.lock().unwrap().success;
        let mut st = self.state.lock().unwrap();
        if st.on_complete.is_some() {
            if let Some(cb) = st.on_complete.take() {
                cb(ok);
            }
        }
    }
}

// ── ImapIdle ──────────────────────────────────────────────────────────────────

struct ImapIdleState {
    username: String,
    password: String,
    mailbox: String,
    require_starttls: bool,
    prefer_auth_plain: bool,
    /// When true, send DONE after the first mailbox event.
    done_on_event: bool,
    success: bool,
    idle_started: bool,
    on_complete: Option<Box<dyn FnOnce(bool) + Send>>,
    events: Option<Box<dyn MailboxEventListener>>,
}

/// Auto-pilot IMAP IDLE pipeline.
///
/// Drives: greeting → CAPABILITY → LOGIN → SELECT → IDLE → (events) → DONE →
/// LOGOUT. Mailbox events are delivered through the optional
/// [`MailboxEventListener`].
pub struct ImapIdle(Arc<Mutex<ImapIdleState>>);

impl ImapIdle {
    /// Create a new IDLE pipeline.
    pub fn new() -> Self {
        ImapIdle(Arc::new(Mutex::new(ImapIdleState {
            username: String::new(),
            password: String::new(),
            mailbox: "INBOX".into(),
            require_starttls: false,
            prefer_auth_plain: true,
            done_on_event: false,
            success: false,
            idle_started: false,
            on_complete: None,
            events: None,
        })))
    }

    /// Set LOGIN / AUTH PLAIN credentials.
    pub fn credentials(self, user: impl Into<String>, pass: impl Into<String>) -> Self {
        let mut st = self.0.lock().unwrap();
        st.username = user.into();
        st.password = pass.into();
        drop(st);
        self
    }

    /// Mailbox to SELECT (default `INBOX`).
    pub fn mailbox(self, name: impl Into<String>) -> Self {
        self.0.lock().unwrap().mailbox = name.into();
        self
    }

    /// Require STARTTLS before authentication.
    pub fn require_starttls(self, require: bool) -> Self {
        self.0.lock().unwrap().require_starttls = require;
        self
    }

    /// Prefer AUTHENTICATE PLAIN when advertised (default true).
    pub fn prefer_auth_plain(self, prefer: bool) -> Self {
        self.0.lock().unwrap().prefer_auth_plain = prefer;
        self
    }

    /// Automatically send `DONE` after the first EXISTS/EXPUNGE/FLAGS event.
    pub fn done_on_event(self, enable: bool) -> Self {
        self.0.lock().unwrap().done_on_event = enable;
        self
    }

    /// Session-complete callback. `ok = true` on success.
    pub fn on_complete(self, cb: Box<dyn FnOnce(bool) + Send>) -> Self {
        self.0.lock().unwrap().on_complete = Some(cb);
        self
    }

    /// Mailbox event listener (EXISTS / EXPUNGE / FLAGS during IDLE).
    pub fn mailbox_events(self, listener: Box<dyn MailboxEventListener>) -> Self {
        self.0.lock().unwrap().events = Some(listener);
        self
    }
}

impl Default for ImapIdle {
    fn default() -> Self {
        Self::new()
    }
}

struct ImapIdleDriver {
    state: Arc<Mutex<ImapIdleState>>,
    events: Option<Box<dyn MailboxEventListener>>,
    done_on_event: bool,
}

impl ImapIdleDriver {
    fn complete(&self, ok: bool) {
        let mut st = self.state.lock().unwrap();
        st.success = ok;
        if let Some(cb) = st.on_complete.take() {
            cb(ok);
        }
    }

    fn auth_plain_initial(user: &str, pass: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(0u8);
        buf.extend_from_slice(user.as_bytes());
        buf.push(0u8);
        buf.extend_from_slice(pass.as_bytes());
        buf
    }

    fn do_authenticate(&self, auth: &mut dyn ImapClientNotAuthenticated) {
        let st = self.state.lock().unwrap();
        let user = st.username.clone();
        let pass = st.password.clone();
        let prefer = st.prefer_auth_plain;
        let caps = auth.capabilities().clone();
        drop(st);
        if prefer && caps.auth_plain {
            let initial = Self::auth_plain_initial(&user, &pass);
            auth.authenticate("PLAIN", Some(&initial));
        } else {
            auth.login(&user, &pass);
        }
    }
}

impl ImapClientHandlerFactory for ImapIdle {
    fn create(&self) -> Box<dyn ImapClientDriver> {
        let mut st = self.0.lock().unwrap();
        let events = st.events.take();
        let done_on_event = st.done_on_event;
        drop(st);
        Box::new(ImapIdleDriver {
            state: Arc::clone(&self.0),
            events,
            done_on_event,
        })
    }
}

impl ImapClientDriver for ImapIdleDriver {
    fn mailbox_events(&mut self) -> Option<&mut dyn MailboxEventListener> {
        match self.events {
            Some(ref mut e) => Some(e.as_mut()),
            None => None,
        }
    }

    fn on_greeting(
        &mut self,
        auth: &mut dyn ImapClientNotAuthenticated,
        _ep: &mut dyn Endpoint,
        _text: &str,
        _preauth: bool,
    ) {
        auth.capability();
    }

    fn on_capability(
        &mut self,
        auth: &mut dyn ImapClientNotAuthenticated,
        ep: &mut dyn Endpoint,
        caps: &ImapCapabilities,
    ) {
        let require = self.state.lock().unwrap().require_starttls;
        if require && !ep.is_secure() {
            if caps.starttls {
                auth.starttls();
                return;
            }
            self.complete(false);
            ep.close();
            return;
        }
        self.do_authenticate(auth);
    }

    fn on_tls_established(
        &mut self,
        post: &mut dyn ImapClientPostStarttls,
        _ep: &mut dyn Endpoint,
    ) {
        post.capability();
    }

    fn on_tls_unavailable(
        &mut self,
        _auth: &mut dyn ImapClientNotAuthenticated,
        ep: &mut dyn Endpoint,
        _message: &str,
    ) {
        self.complete(false);
        ep.close();
    }

    fn on_authenticated(
        &mut self,
        session: &mut dyn ImapClientAuthenticated,
        _ep: &mut dyn Endpoint,
    ) {
        let mailbox = self.state.lock().unwrap().mailbox.clone();
        session.select(&mailbox);
    }

    fn on_auth_failed(
        &mut self,
        _auth: &mut dyn ImapClientNotAuthenticated,
        ep: &mut dyn Endpoint,
        _message: &str,
    ) {
        self.complete(false);
        ep.close();
    }

    fn on_auth_continue(
        &mut self,
        exchange: &mut dyn ImapClientAuthExchange,
        _ep: &mut dyn Endpoint,
        _text: &str,
    ) {
        let st = self.state.lock().unwrap();
        let initial = Self::auth_plain_initial(&st.username, &st.password);
        drop(st);
        exchange.respond(&initial);
    }

    fn on_selected(
        &mut self,
        selected: &mut dyn ImapClientSelected,
        ep: &mut dyn Endpoint,
        _info: &ImapMailboxInfo,
        _read_only: bool,
    ) {
        if !selected.capabilities().idle {
            self.complete(false);
            ep.close();
            return;
        }
        selected.idle();
    }

    fn on_select_failed(
        &mut self,
        _session: &mut dyn ImapClientAuthenticated,
        ep: &mut dyn Endpoint,
        _message: &str,
    ) {
        self.complete(false);
        ep.close();
    }

    fn on_fetch_line(&mut self, _line: &str) {}

    fn on_fetch_literal(&mut self, _data: &[u8]) {}

    fn on_fetch_complete(
        &mut self,
        _selected: &mut dyn ImapClientSelected,
        _ep: &mut dyn Endpoint,
        _status: ImapStatus,
        _message: &str,
    ) {
    }

    fn on_idle_started(&mut self, idle: &mut dyn ImapClientIdle, _ep: &mut dyn Endpoint) {
        self.state.lock().unwrap().idle_started = true;
        let _ = idle;
    }

    fn on_idle_mailbox_event(&mut self, idle: &mut dyn ImapClientIdle) {
        if self.done_on_event && self.state.lock().unwrap().idle_started {
            // Only DONE once.
            self.done_on_event = false;
            idle.done();
        }
    }

    fn on_idle_complete(
        &mut self,
        selected: &mut dyn ImapClientSelected,
        _ep: &mut dyn Endpoint,
        status: ImapStatus,
        _message: &str,
    ) {
        if status == ImapStatus::Ok {
            self.state.lock().unwrap().success = true;
            selected.logout();
            self.complete(true);
        } else {
            self.complete(false);
            selected.logout();
        }
    }

    fn on_append_continue(
        &mut self,
        _append: &mut dyn ImapClientAppend,
        _ep: &mut dyn Endpoint,
        _text: &str,
    ) {
    }

    fn on_append_complete(
        &mut self,
        _session: &mut dyn ImapClientAuthenticated,
        _ep: &mut dyn Endpoint,
        _status: ImapStatus,
        _message: &str,
    ) {
    }

    fn on_error(&mut self, _ep: &mut dyn Endpoint, _err: &io::Error) {
        self.complete(false);
    }

    fn on_timeout(&mut self, _ep: &mut dyn Endpoint) {
        self.complete(false);
    }

    fn on_disconnected(&mut self, _ep: &mut dyn Endpoint) {
        let ok = self.state.lock().unwrap().success;
        let mut st = self.state.lock().unwrap();
        if let Some(cb) = st.on_complete.take() {
            cb(ok);
        }
    }
}

/// Issue `STATUS` and `LIST` back-to-back so both are outstanding before
/// either tagged reply arrives.
///
/// This is the pipelining demonstration helper for tests and docs: after the
/// call, [`super::endpoint::ImapClientEndpoint::pending_len`] is `2` (when the
/// pipeline cap allows) and untagged `STATUS` / `LIST` lines route by prefix
/// to the matching oldest pending command even if replies complete out of
/// tag order.
///
/// ```ignore
/// use hopf_imap::client::pipeline_status_and_list;
/// pipeline_status_and_list(session, "INBOX", "MESSAGES UIDNEXT", "", "*");
/// ```
pub fn pipeline_status_and_list(
    session: &mut dyn ImapClientAuthenticated,
    mailbox: &str,
    status_items: &str,
    list_reference: &str,
    list_pattern: &str,
) {
    session.status(mailbox, status_items);
    session.list(list_reference, list_pattern);
}

#[cfg(test)]
mod idle_pipeline_tests {
    use super::*;

    #[test]
    fn imap_idle_builder_defaults() {
        let idle = ImapIdle::new()
            .credentials("u", "p")
            .mailbox("Archive")
            .done_on_event(true);
        let st = idle.0.lock().unwrap();
        assert_eq!(st.username, "u");
        assert_eq!(st.mailbox, "Archive");
        assert!(st.done_on_event);
    }
}
