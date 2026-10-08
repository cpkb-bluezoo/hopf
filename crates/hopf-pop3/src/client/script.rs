// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! `Pop3Script`: an auto-pilot that logs in, runs a fixed list of
//! transaction commands in order, and `QUIT`s — reporting every result
//! together, once.
//!
//! POP3 has no long-lived session worth keeping: a mail client opens a
//! connection for "what is in the maildrop?" (STAT, UIDL, LIST), another
//! for "show me the headers of these" (TOP), another for "give me this
//! one" (RETR). [`Pop3Fetch`] covers the fetch-everything case; this
//! covers everything else a client does, without a hand-written driver
//! per operation. Same TLS and authentication policy as `Pop3Fetch`:
//! CAPA first, STLS when required or offered, then APOP (if preferred and
//! offered), the strongest SASL mechanism the server advertises, or
//! USER/PASS.
//!
//! [`Pop3Fetch`]: super::Pop3Fetch

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

/// One transaction-state command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pop3Op {
    /// `STAT`.
    Stat,
    /// `LIST` (every message).
    List,
    /// `UIDL` (every message).
    Uidl,
    /// `TOP message lines`.
    Top {
        /// Message number.
        message: u32,
        /// Body lines after the headers.
        lines: u32,
    },
    /// `RETR message`.
    Retr(u32),
    /// `DELE message`.
    Dele(u32),
}

/// What one [`Pop3Op`] produced, in the order the ops were given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pop3OpResult {
    /// `STAT`: message count and total octets.
    Stat {
        /// Messages in the maildrop.
        count: u32,
        /// Their total size.
        octets: u64,
    },
    /// `LIST`: `(message, size)` per message.
    List(Vec<(u32, u64)>),
    /// `UIDL`: `(message, unique id)` per message.
    Uidl(Vec<(u32, String)>),
    /// `TOP` or `RETR`: the (dot-unstuffed) content.
    Message {
        /// Message number.
        message: u32,
        /// `true` for `TOP`.
        is_top: bool,
        /// Headers (+ lines) for `TOP`, the whole message for `RETR`.
        body: Vec<u8>,
    },
    /// `DELE` accepted.
    Deleted(u32),
}

/// How a [`Pop3Script`] session ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pop3ScriptOutcome {
    /// Every op ran; results in op order.
    Done(Vec<Pop3OpResult>),
    /// The server refused the credentials (`-ERR` to PASS / APOP / AUTH),
    /// with its text. The connection was closed cleanly.
    AuthFailed(String),
    /// Anything else, with whatever ops had completed by then.
    Failed {
        /// Results of the ops that did complete.
        completed: Vec<Pop3OpResult>,
        /// Why the session ended.
        error: String,
    },
}

struct ScriptState {
    credentials: Option<(String, String)>,
    prefer_apop: bool,
    require_stls: bool,
    opportunistic_stls: bool,
    apop_timestamp: Option<String>,
    sasl_client: Option<Box<dyn SaslClient>>,
    ops: std::collections::VecDeque<Pop3Op>,
    results: Vec<Pop3OpResult>,
    /// Content of the `TOP` / `RETR` in progress.
    body: Vec<u8>,
    /// Entries of the `LIST` / `UIDL` in progress.
    list: Vec<(u32, u64)>,
    uidl: Vec<(u32, String)>,
    /// The `DELE` in flight (`+OK` carries no number back).
    last_dele: Option<u32>,
    on_result: Option<Box<dyn FnOnce(Pop3ScriptOutcome) + Send>>,
}

/// Builder and [`Pop3ClientHandlerFactory`] for one scripted session.
///
/// ```rust,ignore
/// let script = Pop3Script::new()
///     .credentials("alice", "secret")
///     .require_stls(true)
///     .ops(vec![Pop3Op::Stat, Pop3Op::Uidl, Pop3Op::List])
///     .on_result(Box::new(|outcome| println!("{outcome:?}")));
/// Pop3Client::new("pop.example", 110)
///     .stls(connector, "pop.example")
///     .connect(&rt, Arc::new(script))?;
/// ```
///
/// With no credentials and no ops the session is a reachability and
/// capability probe: greeting, CAPA, (STLS), QUIT, reported as
/// `Done(vec![])`. With ops but no credentials it fails before any
/// command is sent.
pub struct Pop3Script(Arc<Mutex<ScriptState>>);

impl Default for Pop3Script {
    fn default() -> Self {
        Self::new()
    }
}

impl Pop3Script {
    /// An empty script: add credentials, policy and ops with the builders.
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(ScriptState {
            credentials: None,
            prefer_apop: false,
            require_stls: false,
            opportunistic_stls: false,
            apop_timestamp: None,
            sasl_client: None,
            ops: Default::default(),
            results: Vec::new(),
            body: Vec::new(),
            list: Vec::new(),
            uidl: Vec::new(),
            last_dele: None,
            on_result: None,
        })))
    }

    /// Username and password.
    pub fn credentials(self, user: impl Into<String>, pass: impl Into<String>) -> Self {
        self.0.lock().unwrap().credentials = Some((user.into(), pass.into()));
        self
    }

    /// Use APOP when the greeting offers it (the password never crosses
    /// the wire, but the server must hold it in the clear).
    pub fn prefer_apop(self, prefer: bool) -> Self {
        self.0.lock().unwrap().prefer_apop = prefer;
        self
    }

    /// Insist on STLS before anything else: a server that does not offer
    /// it is a failure.
    pub fn require_stls(self, require: bool) -> Self {
        self.0.lock().unwrap().require_stls = require;
        self
    }

    /// Upgrade with STLS when offered, carry on in the clear otherwise.
    pub fn opportunistic_stls(self, enable: bool) -> Self {
        self.0.lock().unwrap().opportunistic_stls = enable;
        self
    }

    /// The commands to run, in order, once authenticated.
    pub fn ops(self, ops: Vec<Pop3Op>) -> Self {
        self.0.lock().unwrap().ops = ops.into();
        self
    }

    /// Called exactly once with how the session ended.
    pub fn on_result(self, cb: Box<dyn FnOnce(Pop3ScriptOutcome) + Send>) -> Self {
        self.0.lock().unwrap().on_result = Some(cb);
        self
    }
}

impl Pop3ClientHandlerFactory for Pop3Script {
    fn create(&self) -> Box<dyn Pop3ClientDriver> {
        Box::new(ScriptDriver { state: Arc::clone(&self.0) })
    }

    fn connect_failed(&self, host: &str, error: &io::Error) {
        let cb = self.0.lock().unwrap().on_result.take();
        if let Some(cb) = cb {
            cb(Pop3ScriptOutcome::Failed { completed: Vec::new(), error: format!("connect to {host} failed: {error}") });
        }
    }
}

struct ScriptDriver {
    state: Arc<Mutex<ScriptState>>,
}

/// The strongest mechanism this auto-pilot can drive with a bare
/// username/password that the server actually advertises (same choice as
/// `Pop3Fetch`).
fn choose_mechanism(sasl_mechs: &[String]) -> Option<SaslMechanism> {
    const PREFERENCE: &[SaslMechanism] =
        &[SaslMechanism::ScramSha256, SaslMechanism::CramMd5, SaslMechanism::Plain, SaslMechanism::Login];
    PREFERENCE.iter().copied().find(|m| sasl_mechs.iter().any(|s| s.eq_ignore_ascii_case(m.name())))
}

fn apop_digest(timestamp: &str, password: &str) -> String {
    let mut data = Vec::with_capacity(timestamp.len() + password.len());
    data.extend_from_slice(timestamp.as_bytes());
    data.extend_from_slice(password.as_bytes());
    hopf_auth::crypto::md5_hex(&data)
}

impl ScriptDriver {
    fn finish(&self, outcome: Pop3ScriptOutcome) {
        let cb = self.state.lock().unwrap().on_result.take();
        if let Some(cb) = cb {
            cb(outcome);
        }
    }

    fn fail(&self, error: impl Into<String>) {
        let completed = std::mem::take(&mut self.state.lock().unwrap().results);
        self.finish(Pop3ScriptOutcome::Failed { completed, error: error.into() });
    }

    /// Issue the next op, or finish when there is none left.
    fn next_op(&self, transaction: &mut dyn Pop3ClientTransaction) {
        let mut st = self.state.lock().unwrap();
        let Some(op) = st.ops.pop_front() else {
            let results = std::mem::take(&mut st.results);
            drop(st);
            self.finish(Pop3ScriptOutcome::Done(results));
            transaction.quit();
            return;
        };
        st.body.clear();
        st.list.clear();
        st.uidl.clear();
        drop(st);
        match op {
            Pop3Op::Stat => transaction.stat(),
            Pop3Op::List => transaction.list(None),
            Pop3Op::Uidl => transaction.uidl(None),
            Pop3Op::Top { message, lines } => transaction.top(message, lines),
            Pop3Op::Retr(n) => transaction.retr(n),
            Pop3Op::Dele(n) => {
                self.state.lock().unwrap().last_dele = Some(n);
                transaction.dele(n)
            }
        }
    }

    fn push_result(&self, transaction: &mut dyn Pop3ClientTransaction, result: Pop3OpResult) {
        self.state.lock().unwrap().results.push(result);
        self.next_op(transaction);
    }

    /// Authenticate on a pre-STLS or plaintext session. `false` when there
    /// are no credentials.
    fn authenticate(&self, auth: &mut dyn Pop3ClientAuthorization, caps: &Pop3Capabilities) -> bool {
        let mut st = self.state.lock().unwrap();
        let Some((user, pass)) = st.credentials.clone() else {
            return false;
        };
        if st.prefer_apop {
            if let Some(ts) = st.apop_timestamp.clone() {
                let digest = apop_digest(&ts, &pass);
                drop(st);
                auth.apop(&user, &digest);
                return true;
            }
        }
        if let Some(mech) = choose_mechanism(&caps.sasl_mechs) {
            let mut client = create_client(mech, &user, &pass, "", "pop", None);
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
        drop(st);
        auth.user(&user);
        true
    }

    /// Authenticate after STLS (APOP is not possible there).
    fn authenticate_post_stls(&self, post_stls: &mut dyn Pop3ClientPostStls, caps: &Pop3Capabilities) -> bool {
        let mut st = self.state.lock().unwrap();
        let Some((user, pass)) = st.credentials.clone() else {
            return false;
        };
        if let Some(mech) = choose_mechanism(&caps.sasl_mechs) {
            let mut client = create_client(mech, &user, &pass, "", "pop", None);
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

    /// No credentials: a probe is done here; ops cannot run.
    fn unauthenticated_end(&self, quit: impl FnOnce()) {
        let has_ops = !self.state.lock().unwrap().ops.is_empty();
        if has_ops {
            self.fail("credentials required to run POP3 commands");
        } else {
            self.finish(Pop3ScriptOutcome::Done(Vec::new()));
        }
        quit();
    }
}

impl Pop3ClientDriver for ScriptDriver {
    fn on_greeting(&mut self, auth: &mut dyn Pop3ClientAuthorization, _ep: &mut dyn Endpoint, apop_challenge: Option<&ContentId>) {
        if let Some(challenge) = apop_challenge {
            self.state.lock().unwrap().apop_timestamp = Some(challenge.to_string());
        }
        auth.capa();
    }

    fn on_capa(&mut self, auth: &mut dyn Pop3ClientAuthorization, ep: &mut dyn Endpoint, caps: &Pop3Capabilities) {
        let (require, opportunistic) = {
            let st = self.state.lock().unwrap();
            (st.require_stls, st.opportunistic_stls)
        };
        if !ep.is_secure() {
            if require {
                if caps.stls {
                    auth.stls();
                } else {
                    self.fail("STLS required but the server does not offer it");
                    auth.quit();
                }
                return;
            }
            if opportunistic && caps.stls {
                auth.stls();
                return;
            }
        }
        if !self.authenticate(auth, caps) {
            self.unauthenticated_end(|| auth.quit());
        }
    }

    fn on_capa_error(&mut self, auth: &mut dyn Pop3ClientAuthorization, ep: &mut dyn Endpoint, _message: &str) {
        // No CAPA at all: nothing to upgrade with, USER/PASS it is — unless
        // STLS was a requirement.
        if self.state.lock().unwrap().require_stls && !ep.is_secure() {
            self.fail("STLS required but the server does not support CAPA");
            auth.quit();
            return;
        }
        let caps = Pop3Capabilities { user: true, ..Default::default() };
        if !self.authenticate(auth, &caps) {
            self.unauthenticated_end(|| auth.quit());
        }
    }

    fn on_capa_post_stls(&mut self, post_stls: &mut dyn Pop3ClientPostStls, _ep: &mut dyn Endpoint, caps: &Pop3Capabilities) {
        if !self.authenticate_post_stls(post_stls, caps) {
            self.unauthenticated_end(|| post_stls.quit());
        }
    }

    fn on_capa_post_stls_error(&mut self, post_stls: &mut dyn Pop3ClientPostStls, _ep: &mut dyn Endpoint, _message: &str) {
        let caps = Pop3Capabilities { user: true, ..Default::default() };
        if !self.authenticate_post_stls(post_stls, &caps) {
            self.unauthenticated_end(|| post_stls.quit());
        }
    }

    fn on_user_ok(&mut self, password: &mut dyn Pop3ClientPassword, _ep: &mut dyn Endpoint) {
        let pass = self.state.lock().unwrap().credentials.as_ref().map(|(_, p)| p.clone()).unwrap_or_default();
        password.pass(&pass);
    }

    fn on_authenticated(&mut self, transaction: &mut dyn Pop3ClientTransaction, _ep: &mut dyn Endpoint) {
        self.next_op(transaction);
    }

    fn on_auth_failed(&mut self, auth: &mut dyn Pop3ClientAuthorization, _ep: &mut dyn Endpoint, message: &str) {
        self.finish(Pop3ScriptOutcome::AuthFailed(message.to_string()));
        auth.quit();
    }

    fn on_auth_challenge(&mut self, exchange: &mut dyn Pop3ClientAuthExchange, _ep: &mut dyn Endpoint, challenge: &[u8]) {
        let mut st = self.state.lock().unwrap();
        let Some(mut client) = st.sasl_client.take() else {
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

    fn on_auth_aborted(&mut self, auth: &mut dyn Pop3ClientAuthorization, _ep: &mut dyn Endpoint) {
        self.finish(Pop3ScriptOutcome::AuthFailed("AUTH exchange aborted".into()));
        auth.quit();
    }

    fn on_tls_established(&mut self, post_stls: &mut dyn Pop3ClientPostStls, _ep: &mut dyn Endpoint) {
        post_stls.capa();
    }

    fn on_tls_unavailable(&mut self, auth: &mut dyn Pop3ClientAuthorization, _ep: &mut dyn Endpoint) {
        self.fail("STLS refused by the server");
        auth.quit();
    }

    fn on_stat(&mut self, transaction: &mut dyn Pop3ClientTransaction, _ep: &mut dyn Endpoint, count: u32, octets: u64) {
        self.push_result(transaction, Pop3OpResult::Stat { count, octets });
    }

    fn on_stat_error(&mut self, transaction: &mut dyn Pop3ClientTransaction, _ep: &mut dyn Endpoint, message: &str) {
        self.fail(format!("STAT failed: {message}"));
        transaction.quit();
    }

    fn on_list_entry(&mut self, message: u32, size: u64) {
        self.state.lock().unwrap().list.push((message, size));
    }

    fn on_list_complete(&mut self, transaction: &mut dyn Pop3ClientTransaction, _ep: &mut dyn Endpoint) {
        let list = std::mem::take(&mut self.state.lock().unwrap().list);
        self.push_result(transaction, Pop3OpResult::List(list));
    }

    fn on_list_single(&mut self, transaction: &mut dyn Pop3ClientTransaction, _ep: &mut dyn Endpoint, message: u32, size: u64) {
        self.push_result(transaction, Pop3OpResult::List(vec![(message, size)]));
    }

    fn on_list_error(&mut self, transaction: &mut dyn Pop3ClientTransaction, _ep: &mut dyn Endpoint, message: &str) {
        self.fail(format!("LIST failed: {message}"));
        transaction.quit();
    }

    fn on_uidl_entry(&mut self, message: u32, uid: &str) {
        self.state.lock().unwrap().uidl.push((message, uid.to_string()));
    }

    fn on_uidl_complete(&mut self, transaction: &mut dyn Pop3ClientTransaction, _ep: &mut dyn Endpoint) {
        let uidl = std::mem::take(&mut self.state.lock().unwrap().uidl);
        self.push_result(transaction, Pop3OpResult::Uidl(uidl));
    }

    fn on_uidl_single(&mut self, transaction: &mut dyn Pop3ClientTransaction, _ep: &mut dyn Endpoint, message: u32, uid: &str) {
        self.push_result(transaction, Pop3OpResult::Uidl(vec![(message, uid.to_string())]));
    }

    fn on_uidl_error(&mut self, transaction: &mut dyn Pop3ClientTransaction, _ep: &mut dyn Endpoint, message: &str) {
        self.fail(format!("UIDL failed: {message}"));
        transaction.quit();
    }

    fn on_message_content(&mut self, data: &[u8], _ep: &mut dyn Endpoint) {
        self.state.lock().unwrap().body.extend_from_slice(data);
    }

    fn on_message_complete(&mut self, transaction: &mut dyn Pop3ClientTransaction, _ep: &mut dyn Endpoint, is_top: bool, message: u32) {
        let body = std::mem::take(&mut self.state.lock().unwrap().body);
        self.push_result(transaction, Pop3OpResult::Message { message, is_top, body });
    }

    fn on_dele_ok(&mut self, transaction: &mut dyn Pop3ClientTransaction, _ep: &mut dyn Endpoint) {
        let deleted = self.state.lock().unwrap().last_dele.take().unwrap_or(0);
        self.push_result(transaction, Pop3OpResult::Deleted(deleted));
    }

    fn on_rset_ok(&mut self, transaction: &mut dyn Pop3ClientTransaction, _ep: &mut dyn Endpoint) {
        self.next_op(transaction);
    }

    fn on_noop_ok(&mut self, transaction: &mut dyn Pop3ClientTransaction, _ep: &mut dyn Endpoint) {
        self.next_op(transaction);
    }

    fn on_no_such_message(&mut self, transaction: &mut dyn Pop3ClientTransaction, _ep: &mut dyn Endpoint, message: &str) {
        self.fail(format!("no such message: {message}"));
        transaction.quit();
    }

    fn on_message_deleted(&mut self, transaction: &mut dyn Pop3ClientTransaction, _ep: &mut dyn Endpoint, message: &str) {
        self.fail(format!("message deleted: {message}"));
        transaction.quit();
    }

    fn on_already_deleted(&mut self, transaction: &mut dyn Pop3ClientTransaction, _ep: &mut dyn Endpoint, message: &str) {
        self.fail(format!("message already deleted: {message}"));
        transaction.quit();
    }

    fn on_error(&mut self, ep: &mut dyn Endpoint, err: &io::Error) {
        self.fail(format!("connection error: {err}"));
        ep.close();
    }

    fn on_timeout(&mut self, ep: &mut dyn Endpoint) {
        self.fail("timed out waiting for the server");
        ep.close();
    }

    fn on_disconnected(&mut self, _ep: &mut dyn Endpoint, message: Option<&str>) {
        // Already reported before QUIT on every normal path; a drop before
        // that is a failure the callback has not heard about.
        self.fail(match message {
            Some(m) => format!("connection closed: {m}"),
            None => "connection closed before the session completed".to_string(),
        });
    }
}
