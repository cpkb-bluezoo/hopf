// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! [`RedisClient`]: one pipelined connection to a Redis or Valkey server,
//! bound to a reactor.
//!
//! Commands may be issued from any thread. Each is written to the connection
//! at once, without waiting for the replies to earlier ones, and replies are
//! matched to commands in the order they were sent (FIFO), which is all RESP
//! gives. Every callback runs on the reactor the client is bound to, exactly
//! once, and never before the call that issued the command has returned.
//!
//! # Connecting
//!
//! The client dials when it is created and again, when a command arrives,
//! after a connection is lost. On the new connection it first negotiates the
//! protocol and authenticates: `HELLO 3` (with `AUTH` and `SETNAME` when
//! configured) and, for a server that does not know `HELLO` (Redis before
//! 6.0), `AUTH` / `CLIENT SETNAME` in RESP2; then `SELECT` for a non-zero
//! database. Commands issued meanwhile wait, and are sent in order once the
//! connection is ready, so a command never runs before the connection is
//! authenticated.
//!
//! # Failure
//!
//! A command that was sent when its connection was lost fails with
//! [`RedisError::ConnectionLost`]. It is not sent again: it may have run, and
//! most commands are not safe to repeat. After a connection fails to come up,
//! commands fail at once for a short and growing time instead of each dialling
//! again.

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hopf_core::{ConnHandle, Endpoint, ProtocolHandler, ReactorHandle, TcpConnectorConfig};
use hopf_dns::DnsResolver;

use crate::config::RedisConfig;
use crate::error::RedisError;
use crate::pubsub::{self, Desired, Push, SubscriberHandler};
use crate::resp::{encode_command, encode_words, RespParser, ServerError, Value};

/// What a command's callback is given.
pub type Reply = Result<Value, RedisError>;

/// A command's callback.
pub type Callback = Box<dyn FnOnce(Reply) + Send>;

/// A command written as an array of bulk strings, ready to send. Cloning one
/// shares its arguments rather than copying them, so a large value is not
/// copied when a cluster client keeps the command to send it again.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Command {
    args: Arc<Vec<Vec<u8>>>,
}

impl Command {
    /// A command named `name`.
    pub fn new(name: impl AsRef<[u8]>) -> Self {
        Self {
            args: Arc::new(vec![name.as_ref().to_vec()]),
        }
    }

    /// Add an argument.
    pub fn arg(mut self, arg: impl AsRef<[u8]>) -> Self {
        Arc::make_mut(&mut self.args).push(arg.as_ref().to_vec());
        self
    }

    /// Add several arguments.
    pub fn args<I>(mut self, args: I) -> Self
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
    {
        let own = Arc::make_mut(&mut self.args);
        for a in args {
            own.push(a.as_ref().to_vec());
        }
        self
    }

    /// The command's words, name first.
    pub fn words(&self) -> &[Vec<u8>] {
        &self.args
    }

    /// The command as it goes on the wire.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_words(&self.args, &mut out);
        out
    }
}

/// Part of the connection handshake, and what to do with its reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Hello,
    Auth,
    SetName,
    Select,
}

enum Kind {
    User(Option<Callback>),
    Internal(Step),
}

/// Written to the connection, awaiting its reply.
struct Sent {
    qid: u64,
    kind: Kind,
    /// Stops the command's timeout timer once it is answered.
    cancel: Option<Arc<AtomicBool>>,
    /// The server may legitimately sit on this command for longer than the
    /// health check waits (a blocking command, a `WAIT`, or one given no
    /// limit), so its silence says nothing.
    held: bool,
}

/// Not yet written: waiting for the connection.
struct Waiting {
    qid: u64,
    bytes: Vec<u8>,
    callback: Callback,
    cancel: Option<Arc<AtomicBool>>,
    held: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Phase {
    /// No connection, and none being made.
    Idle,
    /// Resolving the host name or connecting (and, over TLS, handshaking).
    Connecting,
    /// Connected; negotiating the protocol and authenticating.
    Handshaking,
    /// Ready: commands go straight out.
    Ready,
}

pub(crate) struct State {
    pub(crate) phase: Phase,
    /// Identifies the connection attempt, so a late event from an earlier one
    /// is ignored.
    pub(crate) conn_id: u64,
    pub(crate) handle: Option<ConnHandle>,
    waiting: VecDeque<Waiting>,
    pending: VecDeque<Sent>,
    /// Bytes for the connection not yet handed to it.
    outbox: Vec<u8>,
    flush_scheduled: bool,
    /// Addresses still to try for this attempt.
    addrs: VecDeque<SocketAddr>,
    /// RESP3 was negotiated on this connection.
    resp3: bool,
    /// Connection attempts that failed in a row, and when the next may start.
    pub(crate) failures: u32,
    pub(crate) retry_at: Option<Instant>,
    pub(crate) last_error: Option<RedisError>,
    /// What a subscriber wants to be subscribed to.
    pub(crate) desired: Desired,
    /// When anything last arrived on the connection, or, on a command
    /// connection, when it last began to owe a reply, if later: how long it has
    /// been silent while something is owed (the health check).
    pub(crate) last_rx: Instant,
    /// A `MULTI` has been sent on the connection and not yet an `EXEC` or
    /// `DISCARD`.
    in_multi: bool,
}

pub(crate) struct Inner {
    pub(crate) reactor: ReactorHandle,
    pub(crate) config: RedisConfig,
    pub(crate) state: Mutex<State>,
    pub(crate) closed: AtomicBool,
    /// No new commands are taken; the connection closes once those it has are
    /// answered.
    retiring: AtomicBool,
    next_qid: AtomicU64,
    resolver: Mutex<Option<Arc<DnsResolver>>>,
    /// Where RESP3 pushes go on a command connection.
    push: Mutex<Option<Box<dyn FnMut(Push) + Send>>>,
    /// Set for a subscriber: its handler.
    pub(crate) sub: Option<Mutex<Box<dyn SubscriberHandler>>>,
    /// A subscriber has been connected at least once.
    pub(crate) sub_connected_before: AtomicBool,
    /// Told when the health check gives up on a connection, so a layer above
    /// (the cluster) can look for another route even if no command was waiting.
    unresponsive: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

/// Build the shared state for a connection and dial it. A subscriber passes its
/// handler.
pub(crate) fn start(reactor: &ReactorHandle, config: RedisConfig, sub: Option<Box<dyn SubscriberHandler>>) -> Arc<Inner> {
    let inner = Arc::new(Inner {
        reactor: reactor.clone(),
        config,
        state: Mutex::new(State {
            phase: Phase::Idle,
            conn_id: 0,
            handle: None,
            waiting: VecDeque::new(),
            pending: VecDeque::new(),
            outbox: Vec::new(),
            flush_scheduled: false,
            addrs: VecDeque::new(),
            resp3: false,
            failures: 0,
            retry_at: None,
            last_error: None,
            desired: Desired::default(),
            last_rx: Instant::now(),
            in_multi: false,
        }),
        closed: AtomicBool::new(false),
        retiring: AtomicBool::new(false),
        next_qid: AtomicU64::new(0),
        resolver: Mutex::new(None),
        push: Mutex::new(None),
        sub: sub.map(Mutex::new),
        sub_connected_before: AtomicBool::new(false),
        unresponsive: Mutex::new(None),
    });
    let first = {
        let mut st = inner.state.lock().unwrap();
        begin_dial(&mut st)
    };
    if let Some(conn_id) = first {
        dial(&inner, conn_id);
    }
    inner
}

/// Dial again (a subscriber, after a failure and its hold-off).
pub(crate) fn redial(inner: &Arc<Inner>) {
    if inner.closed.load(Ordering::SeqCst) {
        return;
    }
    let start = {
        let mut st = inner.state.lock().unwrap();
        begin_dial(&mut st)
    };
    if let Some(conn_id) = start {
        dial(inner, conn_id);
    }
}

/// Write bytes to the connection outside the queue of commands (a subscriber's
/// subscriptions and pings have no reply to wait for). Dropped if the
/// connection is not ready.
pub(crate) fn write_raw(inner: &Arc<Inner>, bytes: Vec<u8>) {
    let need_flush = {
        let mut st = inner.state.lock().unwrap();
        if st.phase != Phase::Ready {
            return;
        }
        st.outbox.extend_from_slice(&bytes);
        !std::mem::replace(&mut st.flush_scheduled, true)
    };
    if need_flush {
        flush(inner);
    }
}

/// Close the connection, fail what is waiting, and refuse later commands.
pub(crate) fn close(inner: &Arc<Inner>) {
    inner.closed.store(true, Ordering::SeqCst);
    let (handle, waiting, pending) = {
        let mut st = inner.state.lock().unwrap();
        st.phase = Phase::Idle;
        st.in_multi = false;
        st.conn_id += 1;
        st.outbox.clear();
        (st.handle.take(), std::mem::take(&mut st.waiting), std::mem::take(&mut st.pending))
    };
    if let Some(h) = handle {
        h.close();
    }
    for w in waiting {
        cancel_timer(&w.cancel);
        finish(inner, w.callback, Err(RedisError::Closed));
    }
    for s in pending {
        cancel_timer(&s.cancel);
        if let Kind::User(Some(cb)) = s.kind {
            finish(inner, cb, Err(RedisError::Closed));
        }
    }
}

/// Stop taking commands, and close once the ones already taken are answered
/// (at once if there are none). What a caller sent before is not failed, and
/// what it sends after fails with [`RedisError::Closed`] without having been
/// sent, so it is safe to send elsewhere.
pub(crate) fn retire(inner: &Arc<Inner>) {
    inner.retiring.store(true, Ordering::SeqCst);
    close_if_drained(inner);
}

/// Close a retiring connection that has nothing left to answer.
fn close_if_drained(inner: &Arc<Inner>) {
    if !inner.retiring.load(Ordering::SeqCst) {
        return;
    }
    let drained = {
        let st = inner.state.lock().unwrap();
        st.waiting.is_empty() && !st.pending.iter().any(|s| matches!(s.kind, Kind::User(_)))
    };
    if drained {
        close(inner);
    }
}

/// A pipelined connection to one server. Cheap to clone; clones share the
/// connection. See the module documentation.
#[derive(Clone)]
pub struct RedisClient {
    pub(crate) inner: Arc<Inner>,
}

impl RedisClient {
    /// A client bound to `reactor`, dialling `config`'s server now. Its
    /// callbacks run on `reactor`.
    pub fn connect(reactor: &ReactorHandle, config: RedisConfig) -> Self {
        Self {
            inner: start(reactor, config, None),
        }
    }

    /// Receive the RESP3 pushes this connection gets: key invalidations
    /// (`CLIENT TRACKING`), and anything else a server pushes, of whatever kind
    /// (see [`Push`]). `handler` runs on the client's reactor. Without one,
    /// pushes are discarded. Subscriptions are not made here: they need a
    /// [`RedisSubscriber`](crate::RedisSubscriber).
    pub fn set_push_handler(&self, handler: impl FnMut(Push) + Send + 'static) {
        *self.inner.push.lock().unwrap() = Some(Box::new(handler));
    }

    /// Stop passing pushes to the handler.
    pub fn clear_push_handler(&self) {
        *self.inner.push.lock().unwrap() = None;
    }

    /// Send `command` and call `callback` with the reply. Returns at once.
    pub fn send(&self, command: &Command, callback: impl FnOnce(Reply) + Send + 'static) {
        if command.words().first().is_some_and(|w| pubsub::is_subscription_command(w)) {
            return refuse_subscription(&self.inner, Box::new(callback));
        }
        submit(&self.inner, vec![(command.encode(), Box::new(callback))]);
    }

    /// Send the command made of `words` (the name first) and call `callback`
    /// with the reply. Returns at once.
    pub fn command(&self, words: &[&[u8]], callback: impl FnOnce(Reply) + Send + 'static) {
        if words.first().is_some_and(|w| pubsub::is_subscription_command(w)) {
            return refuse_subscription(&self.inner, Box::new(callback));
        }
        let mut bytes = Vec::new();
        encode_command(words, &mut bytes);
        submit(&self.inner, vec![(bytes, Box::new(callback))]);
    }

    /// Send several commands as one write, in order, with nothing from another
    /// caller between them. Each has its own callback, called in the order the
    /// commands were given.
    pub fn send_batch(&self, commands: Vec<(Command, Callback)>) {
        if commands.iter().any(|(c, _)| c.words().first().is_some_and(|w| pubsub::is_subscription_command(w))) {
            for (_, cb) in commands {
                refuse_subscription(&self.inner, cb);
            }
            return;
        }
        submit(&self.inner, commands.into_iter().map(|(c, cb)| (c.encode(), cb)).collect());
    }

    /// Whether the connection is up and past its handshake.
    pub fn is_ready(&self) -> bool {
        self.inner.state.lock().unwrap().phase == Phase::Ready
    }

    /// Whether RESP3 was negotiated on the current connection.
    pub fn is_resp3(&self) -> bool {
        self.inner.state.lock().unwrap().resp3
    }

    /// Close the connection and fail every command still waiting with
    /// [`RedisError::Closed`]. Later commands fail the same way.
    pub fn close(&self) {
        close(&self.inner);
    }

    /// [`send`](Self::send) with a deadline of its own instead of the
    /// configured command timeout: [`Deadline::After`] for a time, or
    /// [`Deadline::Never`] for a command that blocks for as long as the server
    /// likes. A command that is not answered in time calls back with
    /// [`RedisError::Timeout`]; its reply, if it comes later, is dropped.
    pub fn send_with_deadline(&self, command: &Command, deadline: Deadline, callback: impl FnOnce(Reply) + Send + 'static) {
        if command.words().first().is_some_and(|w| pubsub::is_subscription_command(w)) {
            return refuse_subscription(&self.inner, Box::new(callback));
        }
        submit_timed(&self.inner, vec![(command.encode(), Box::new(callback))], deadline);
    }

    /// [`send_batch`](Self::send_batch) with one deadline for every command.
    pub(crate) fn send_batch_with_deadline(&self, commands: Vec<(Command, Callback)>, deadline: Deadline) {
        submit_timed(&self.inner, commands.into_iter().map(|(c, cb)| (c.encode(), cb)).collect(), deadline);
    }

    /// Call `f` when the health check closes a connection because the server
    /// stopped answering, whether or not any command was waiting.
    pub(crate) fn on_unresponsive(&self, f: impl Fn() + Send + Sync + 'static) {
        *self.inner.unresponsive.lock().unwrap() = Some(Arc::new(f));
    }

    /// Whether a `MULTI` is open on the connection: it was sent, and no `EXEC`
    /// or `DISCARD` since.
    pub(crate) fn in_multi(&self) -> bool {
        self.inner.state.lock().unwrap().in_multi
    }

    /// Have the cluster layer let go of this client: see [`retire`].
    pub(crate) fn retire(&self) {
        retire(&self.inner);
    }
}

/// A command connection does not take subscriptions: in RESP3 the server
/// answers them with pushes, not a reply, which would put every later reply out
/// of step with its command, and in RESP2 it would stop accepting commands.
fn refuse_subscription(inner: &Inner, callback: Callback) {
    finish(
        inner,
        callback,
        Err(RedisError::Unexpected(
            "subscriptions need a RedisSubscriber, not a command connection".into(),
        )),
    );
}

fn cancel_timer(cancel: &Option<Arc<AtomicBool>>) {
    if let Some(c) = cancel {
        c.store(true, Ordering::SeqCst);
    }
}

/// Run `callback` on the reactor, never inline: a caller holding a lock when it
/// issues a command must not see its callback re-enter that lock.
fn finish(inner: &Inner, callback: Callback, reply: Reply) {
    inner.reactor.execute(Box::new(move || callback(reply)));
}

/// An error reply is an error; anything else is the reply.
fn into_reply(value: Value) -> Reply {
    match value {
        Value::Error(e) => Err(RedisError::Server(e)),
        v => Ok(v),
    }
}

/// How long to hold off after `failures` failed connection attempts in a row.
fn backoff(initial: Duration, max: Duration, failures: u32) -> Duration {
    let shift = failures.saturating_sub(1).min(20);
    initial.saturating_mul(1u32 << shift).min(max)
}

/// Whether `HELLO` failed because this server predates it (or is a proxy that
/// does not carry it), so RESP2 and a plain `AUTH` should be tried.
fn hello_unsupported(e: &ServerError) -> bool {
    let text = e.message.to_ascii_lowercase();
    e.code == "NOPROTO"
        || (e.code == "ERR"
            && (text.contains("unknown command") || text.contains("unknown subcommand") || text.contains("protocol")))
}

/// The commands that start a connection, and what each is for.
fn handshake_plan(config: &RedisConfig, resp3: bool) -> Vec<(Step, Vec<u8>)> {
    fn enc(words: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        encode_command(words, &mut out);
        out
    }
    let mut plan = Vec::new();
    if resp3 {
        let mut words: Vec<&[u8]> = vec![b"HELLO", b"3"];
        if let Some(password) = &config.password {
            words.push(b"AUTH");
            words.push(config.username.as_deref().unwrap_or("default").as_bytes());
            words.push(password.as_bytes());
        }
        if let Some(name) = &config.client_name {
            words.push(b"SETNAME");
            words.push(name.as_bytes());
        }
        plan.push((Step::Hello, enc(&words)));
        return plan;
    }
    plan.extend(resp2_plan(config));
    plan
}

/// The RESP2 handshake: `AUTH`, `CLIENT SETNAME`, `SELECT`.
fn resp2_plan(config: &RedisConfig) -> Vec<(Step, Vec<u8>)> {
    fn enc(words: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        encode_command(words, &mut out);
        out
    }
    let mut plan = Vec::new();
    if let Some(password) = &config.password {
        plan.push((
            Step::Auth,
            match &config.username {
                Some(u) => enc(&[b"AUTH", u.as_bytes(), password.as_bytes()]),
                None => enc(&[b"AUTH", password.as_bytes()]),
            },
        ));
    }
    if let Some(name) = &config.client_name {
        plan.push((Step::SetName, enc(&[b"CLIENT", b"SETNAME", name.as_bytes()])));
    }
    if config.database != 0 {
        plan.push((Step::Select, enc(&[b"SELECT", config.database.to_string().as_bytes()])));
    }
    plan
}

/// Move an idle client to connecting, if it may start now. Returns the id of
/// the attempt to dial.
fn begin_dial(st: &mut State) -> Option<u64> {
    if st.phase != Phase::Idle || st.retry_at.is_some_and(|at| at > Instant::now()) {
        return None;
    }
    st.phase = Phase::Connecting;
    st.conn_id += 1;
    st.addrs.clear();
    Some(st.conn_id)
}

/// How long one command may go unanswered, counted from when it is issued,
/// the connect and handshake included. See [`RedisClient::send_with_deadline`].
///
/// Every variant but `Default` says something about how long the server may
/// take, and the connection's health check (see
/// [`RedisConfig::ping_interval`](crate::RedisConfig::ping_interval)) takes
/// the hint: while a command with no limit, or with a limit longer than the
/// configured command timeout, is outstanding, the connection is not closed
/// for being silent, because a server holding such a command says nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Deadline {
    /// The configured command timeout.
    Default,
    /// The configured command timeout and this much more: for a command that
    /// the server itself holds for a time, such as `WAIT`.
    Extra(Duration),
    /// Exactly this long, whatever the configured command timeout is (and
    /// whether or not one is set): shorter to fail fast, or longer for a
    /// command the server holds, such as `BLPOP key 30`.
    After(Duration),
    /// No limit.
    Never,
}

/// The name of the command in `encoded` (an array of bulk strings), in upper
/// case.
fn command_name(encoded: &[u8]) -> Option<Vec<u8>> {
    // *<n>\r\n$<len>\r\n<name>\r\n
    let first = encoded.windows(2).position(|w| w == b"\r\n")? + 2;
    let rest = encoded.get(first..)?;
    let len_end = rest.windows(2).position(|w| w == b"\r\n")?;
    let len: usize = std::str::from_utf8(rest.get(1..len_end)?).ok()?.parse().ok()?;
    let name = rest.get(len_end + 2..len_end + 2 + len)?;
    Some(name.to_ascii_uppercase())
}

/// Track whether the connection is inside a transaction, from what is sent.
fn note_transaction_state(st: &mut State, batch: &[Waiting]) {
    for w in batch {
        match command_name(&w.bytes).as_deref() {
            Some(b"MULTI") => st.in_multi = true,
            Some(b"EXEC") | Some(b"DISCARD") => st.in_multi = false,
            _ => {}
        }
    }
}

/// Accept commands from a caller: send them, queue them for the connection, or
/// fail them.
fn submit(inner: &Arc<Inner>, items: Vec<(Vec<u8>, Callback)>) {
    submit_timed(inner, items, Deadline::Default);
}

fn submit_timed(inner: &Arc<Inner>, items: Vec<(Vec<u8>, Callback)>, deadline: Deadline) {
    if inner.closed.load(Ordering::SeqCst) || inner.retiring.load(Ordering::SeqCst) {
        for (_, cb) in items {
            finish(inner, cb, Err(RedisError::Closed));
        }
        return;
    }
    // Each command's timeout starts now, covering the connect.
    let mut prepared = Vec::with_capacity(items.len());
    for (bytes, callback) in items {
        let qid = inner.next_qid.fetch_add(1, Ordering::Relaxed);
        let limit = match deadline {
            Deadline::Default => inner.config.command_timeout,
            Deadline::Extra(more) => inner.config.command_timeout.map(|t| t + more),
            Deadline::After(d) => Some(d),
            Deadline::Never => None,
        };
        // A command with no limit, or one the server is expected to hold, may
        // be answered after any length of silence.
        let held = match deadline {
            Deadline::Default => limit.is_none(),
            Deadline::Extra(_) | Deadline::Never => true,
            Deadline::After(d) => inner.config.command_timeout.is_none_or(|t| d > t),
        };
        let cancel = limit.map(|timeout| {
            let weak = Arc::downgrade(inner);
            inner.reactor.schedule_timer(
                timeout,
                Box::new(move || {
                    if let Some(inner) = weak.upgrade() {
                        expire(&inner, qid);
                    }
                }),
            )
        });
        prepared.push(Waiting {
            qid,
            bytes,
            callback,
            cancel,
            held,
        });
    }

    enum Next {
        Flush,
        Queued,
        Dial(u64),
        Fail(Vec<Waiting>, RedisError),
    }
    let next = {
        let mut st = inner.state.lock().unwrap();
        let max = inner.config.max_pending;
        // What the connection sends for itself while it handshakes is not the
        // callers' to count: only their commands use up the room.
        let in_hand = if st.phase == Phase::Handshaking { 0 } else { st.pending.len() } + st.waiting.len();
        if max > 0 && in_hand + prepared.len() > max {
            Next::Fail(prepared, RedisError::Overloaded)
        } else {
            if st.phase != Phase::Idle || st.retry_at.is_none_or(|at| at <= Instant::now()) {
                note_transaction_state(&mut st, &prepared);
            }
            match st.phase {
                Phase::Ready => {
                    // The health check counts the silence from here, not from
                    // whenever the connection last heard something.
                    if !st.pending.iter().any(|s| matches!(s.kind, Kind::User(_))) {
                        st.last_rx = Instant::now();
                    }
                    for w in prepared {
                        append_to_outbox(&mut st.outbox, w.bytes);
                        st.pending.push_back(Sent {
                            qid: w.qid,
                            kind: Kind::User(Some(w.callback)),
                            cancel: w.cancel,
                            held: w.held,
                        });
                    }
                    if std::mem::replace(&mut st.flush_scheduled, true) {
                        Next::Queued
                    } else {
                        Next::Flush
                    }
                }
                Phase::Connecting | Phase::Handshaking => {
                    st.waiting.extend(prepared);
                    Next::Queued
                }
                Phase::Idle => {
                    if st.retry_at.is_some_and(|at| at > Instant::now()) {
                        let why = st
                            .last_error
                            .clone()
                            .unwrap_or_else(|| RedisError::Connect("the server is unreachable".into()));
                        Next::Fail(prepared, why)
                    } else {
                        st.waiting.extend(prepared);
                        match begin_dial(&mut st) {
                            Some(id) => Next::Dial(id),
                            None => Next::Queued,
                        }
                    }
                }
            }
        }
    };
    match next {
        Next::Flush => flush(inner),
        Next::Queued => {}
        Next::Dial(id) => dial(inner, id),
        Next::Fail(jobs, why) => {
            for w in jobs {
                cancel_timer(&w.cancel);
                finish(inner, w.callback, Err(why.clone()));
            }
        }
    }
}

/// Watch a command connection that may have died without saying so (a
/// black-holed route, a paused or partitioned server: no reset, no close).
///
/// It only watches while the connection owes replies; with nothing owed it is
/// idle, and idle is not dead. When replies are owed and nothing at all has
/// arrived for `ping_interval`, the connection is closed: what it owed fails
/// with [`RedisError::ConnectionLost`], and the next command dials afresh.
/// Traffic of any kind counts as life. A handshake that is not answered is
/// given up on the same way.
///
/// No `PING` is sent first. Replies come back in the order commands were sent,
/// so a probe queued behind an unanswered command is answered only after it:
/// it could tell nothing that the command's own reply would not. It would also
/// be queued into an open `MULTI`.
///
/// Not watched: a connection with a command outstanding that the server may
/// hold for longer than the interval, a blocking command or a `WAIT` (see
/// [`Deadline`]), whose silence means nothing. Those are left to their own
/// timeouts.
fn arm_health(inner: &Arc<Inner>, conn_id: u64) {
    let Some(interval) = inner.config.ping_interval else {
        return;
    };
    if inner.sub.is_some() {
        return; // a subscriber has its own
    }
    let weak = Arc::downgrade(inner);
    inner.reactor.schedule_timer(
        (interval / 2).max(Duration::from_millis(1)),
        Box::new(move || {
            let Some(inner) = weak.upgrade() else {
                return;
            };
            enum Act {
                Stop,
                Wait,
                Drop,
            }
            let act = {
                let st = inner.state.lock().unwrap();
                if st.conn_id != conn_id || !matches!(st.phase, Phase::Handshaking | Phase::Ready) {
                    Act::Stop
                } else {
                    let watched = st.phase == Phase::Handshaking
                        || (st.pending.iter().any(|s| matches!(s.kind, Kind::User(_)))
                            && !st.pending.iter().any(|s| s.held));
                    if watched && st.last_rx.elapsed() >= interval {
                        Act::Drop
                    } else {
                        Act::Wait
                    }
                }
            };
            match act {
                Act::Stop => return,
                Act::Wait => {}
                Act::Drop => {
                    let handle = inner.state.lock().unwrap().handle.clone();
                    lost(&inner, conn_id, "the server stopped answering");
                    if let Some(h) = handle {
                        h.close();
                    }
                    let hook = inner.unresponsive.lock().unwrap().clone();
                    if let Some(f) = hook {
                        f();
                    }
                    return;
                }
            }
            arm_health(&inner, conn_id);
        }),
    );
}

/// Add an encoded command to the outbox. When the outbox is empty, which is
/// the usual case, the command's own buffer becomes the outbox: a large value
/// is not copied again on its way to the connection.
fn append_to_outbox(outbox: &mut Vec<u8>, bytes: Vec<u8>) {
    if outbox.is_empty() {
        *outbox = bytes;
    } else {
        outbox.extend_from_slice(&bytes);
    }
}

/// Hand what is in the outbox to the connection, on the reactor.
fn flush(inner: &Arc<Inner>) {
    let (handle, conn_id) = {
        let st = inner.state.lock().unwrap();
        (st.handle.clone(), st.conn_id)
    };
    let Some(handle) = handle else {
        return;
    };
    let inner = Arc::clone(inner);
    handle.with_endpoint(move |ep| {
        let bytes = {
            let mut st = inner.state.lock().unwrap();
            if st.conn_id != conn_id {
                return;
            }
            st.flush_scheduled = false;
            std::mem::take(&mut st.outbox)
        };
        if !bytes.is_empty() {
            ep.send(&bytes);
        }
    });
}

/// A command's timeout fired: fail it if it is still unanswered.
fn expire(inner: &Arc<Inner>, qid: u64) {
    let callback = {
        let mut st = inner.state.lock().unwrap();
        if let Some(pos) = st.waiting.iter().position(|w| w.qid == qid) {
            st.waiting.remove(pos).map(|w| w.callback)
        } else {
            // Sent: the reply is still to come and still takes its place in the
            // queue, so the entry stays and only loses its callback.
            st.pending.iter_mut().find(|s| s.qid == qid).and_then(|s| match &mut s.kind {
                Kind::User(cb) => cb.take(),
                Kind::Internal(_) => None,
            })
        }
    };
    if let Some(cb) = callback {
        finish(inner, cb, Err(RedisError::Timeout));
    }
}

/// The resolver for a host name: the configured one, or one made on first use.
fn resolver(inner: &Inner) -> Result<Arc<DnsResolver>, RedisError> {
    if let Some(r) = &inner.config.resolver {
        return Ok(Arc::clone(r));
    }
    let mut slot = inner.resolver.lock().unwrap();
    if let Some(r) = slot.as_ref() {
        return Ok(Arc::clone(r));
    }
    let r = DnsResolver::new(inner.reactor.clone());
    r.open_with_system_resolvers()
        .map_err(|e| RedisError::Connect(format!("no name resolver: {e}")))?;
    let r = Arc::new(r);
    *slot = Some(Arc::clone(&r));
    Ok(r)
}

/// Find the server's address and connect to it, for attempt `conn_id`.
fn dial(inner: &Arc<Inner>, conn_id: u64) {
    let config = &inner.config;
    let literal = config
        .addr
        .or_else(|| config.host.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, config.port)));
    if let Some(addr) = literal {
        inner.state.lock().unwrap().addrs = VecDeque::from([addr]);
        dial_next(inner, conn_id);
        return;
    }
    let resolver = match resolver(inner) {
        Ok(r) => r,
        Err(e) => return connect_failed(inner, conn_id, e),
    };
    let inner2 = Arc::clone(inner);
    resolver.resolve(
        &config.host,
        config.port,
        Box::new(move |result| match result {
            Ok(addrs) if !addrs.is_empty() => {
                {
                    let mut st = inner2.state.lock().unwrap();
                    if st.conn_id != conn_id || st.phase != Phase::Connecting {
                        return;
                    }
                    st.addrs = addrs.into();
                }
                dial_next(&inner2, conn_id);
            }
            Ok(_) => connect_failed(
                &inner2,
                conn_id,
                RedisError::Connect(format!("{} has no address", inner2.config.host)),
            ),
            Err(e) => connect_failed(
                &inner2,
                conn_id,
                RedisError::Connect(format!("could not resolve {}: {e}", inner2.config.host)),
            ),
        }),
    );
}

/// Connect to the next address left for attempt `conn_id`.
fn dial_next(inner: &Arc<Inner>, conn_id: u64) {
    loop {
        let addr = {
            let mut st = inner.state.lock().unwrap();
            if st.conn_id != conn_id || st.phase != Phase::Connecting {
                return;
            }
            st.addrs.pop_front()
        };
        let Some(addr) = addr else {
            return connect_failed(inner, conn_id, RedisError::Connect("no address to try".into()));
        };
        let handler_inner = Arc::clone(inner);
        let tls = inner.config.tls.is_some();
        let mut cfg = TcpConnectorConfig::new(addr, move || {
            Box::new(Conn {
                inner: Arc::clone(&handler_inner),
                conn_id,
                parser: RespParser::with_limits(handler_inner.config.limits),
                tls,
            }) as Box<dyn ProtocolHandler>
        });
        if let Some((connector, name)) = &inner.config.tls {
            cfg = cfg.with_tls(connector.clone(), name.clone());
        }
        cfg.connect_timeout = Some(inner.config.connect_timeout);
        match inner.reactor.connect(cfg) {
            Ok(()) => return,
            Err(e) => {
                // Try the next address, or give up when none is left.
                let more = !inner.state.lock().unwrap().addrs.is_empty();
                if !more {
                    return connect_failed(inner, conn_id, RedisError::Connect(format!("{addr}: {e}")));
                }
            }
        }
    }
}

/// Attempt `conn_id` could not be made: fail what waited for it, and hold off
/// further attempts for a while.
fn connect_failed(inner: &Arc<Inner>, conn_id: u64, error: RedisError) {
    let waiting = {
        let mut st = inner.state.lock().unwrap();
        if st.conn_id != conn_id || st.phase == Phase::Idle {
            return;
        }
        st.phase = Phase::Idle;
        st.in_multi = false;
        st.handle = None;
        st.outbox.clear();
        st.flush_scheduled = false;
        st.failures += 1;
        st.retry_at = Some(
            Instant::now() + backoff(inner.config.backoff_initial, inner.config.backoff_max, st.failures),
        );
        st.last_error = Some(error.clone());
        std::mem::take(&mut st.waiting)
    };
    for w in waiting {
        cancel_timer(&w.cancel);
        finish(inner, w.callback, Err(error.clone()));
    }
    pubsub::schedule_redial(inner);
}

/// Connection `conn_id` ended. Fail what was sent on it, and what was waiting
/// if it never became ready.
pub(crate) fn lost(inner: &Arc<Inner>, conn_id: u64, reason: &str) {
    let (pending, waiting, was_ready, more_addrs) = {
        let mut st = inner.state.lock().unwrap();
        if st.conn_id != conn_id || st.phase == Phase::Idle {
            return;
        }
        let was_ready = st.phase == Phase::Ready;
        let more_addrs = st.phase == Phase::Connecting && !st.addrs.is_empty();
        if more_addrs {
            // Connecting failed on one address; the next is tried.
            (VecDeque::new(), VecDeque::new(), false, true)
        } else {
            st.phase = Phase::Idle;
            st.in_multi = false;
            st.handle = None;
            st.outbox.clear();
            st.flush_scheduled = false;
            st.resp3 = false;
            if was_ready && inner.sub.is_none() {
                st.failures = 0;
                st.retry_at = None;
            } else if was_ready {
                // A subscriber dials again by itself, after a short pause so a
                // server that drops it as soon as it connects is not hammered.
                st.failures = 1;
                st.retry_at = Some(Instant::now() + backoff(inner.config.backoff_initial, inner.config.backoff_max, 1));
                st.last_error = Some(RedisError::ConnectionLost(reason.to_string()));
            } else {
                st.failures += 1;
                st.retry_at = Some(
                    Instant::now() + backoff(inner.config.backoff_initial, inner.config.backoff_max, st.failures),
                );
                st.last_error = Some(RedisError::Connect(reason.to_string()));
            }
            (std::mem::take(&mut st.pending), std::mem::take(&mut st.waiting), was_ready, false)
        }
    };
    if more_addrs {
        dial_next(inner, conn_id);
        return;
    }
    for s in pending {
        cancel_timer(&s.cancel);
        if let Kind::User(Some(cb)) = s.kind {
            finish(inner, cb, Err(RedisError::ConnectionLost(reason.to_string())));
        }
    }
    let why = if was_ready {
        RedisError::ConnectionLost(reason.to_string())
    } else {
        RedisError::Connect(reason.to_string())
    };
    for w in waiting {
        cancel_timer(&w.cancel);
        finish(inner, w.callback, Err(why.clone()));
    }
    if inner.sub.is_some() {
        if was_ready {
            pubsub::sub_lost(inner, &why);
        }
        pubsub::schedule_redial(inner);
    }
}

/// The reactor-side half of a connection.
struct Conn {
    inner: Arc<Inner>,
    conn_id: u64,
    parser: RespParser,
    tls: bool,
}

impl Conn {
    /// Send the handshake. Runs once the connection (and any TLS) is up.
    fn begin_handshake(&mut self, endpoint: &mut dyn Endpoint) {
        let inner = &self.inner;
        let plan = {
            let mut st = inner.state.lock().unwrap();
            if st.conn_id != self.conn_id || st.phase != Phase::Connecting {
                return;
            }
            st.phase = Phase::Handshaking;
            let plan = handshake_plan(&inner.config, inner.config.resp3);
            for (step, _) in &plan {
                st.pending.push_back(Sent {
                    qid: u64::MAX,
                    kind: Kind::Internal(*step),
                    cancel: None,
                    held: false,
                });
            }
            st.last_rx = Instant::now();
            plan
        };
        arm_health(&self.inner, self.conn_id);
        if plan.is_empty() {
            return self.ready(endpoint);
        }
        let mut bytes = Vec::new();
        for (_, b) in &plan {
            bytes.extend_from_slice(b);
        }
        endpoint.send(&bytes);
    }

    /// The handshake is done: send what waited.
    fn ready(&mut self, endpoint: &mut dyn Endpoint) {
        let inner = &self.inner;
        if inner.sub.is_some() {
            return pubsub::sub_ready(inner, self.conn_id, endpoint);
        }
        let bytes = {
            let mut st = inner.state.lock().unwrap();
            if st.conn_id != self.conn_id {
                return;
            }
            st.phase = Phase::Ready;
            st.failures = 0;
            st.retry_at = None;
            st.last_error = None;
            while let Some(w) = st.waiting.pop_front() {
                append_to_outbox(&mut st.outbox, w.bytes);
                st.pending.push_back(Sent {
                    qid: w.qid,
                    kind: Kind::User(Some(w.callback)),
                    cancel: w.cancel,
                    held: w.held,
                });
            }
            st.flush_scheduled = false;
            std::mem::take(&mut st.outbox)
        };
        if !bytes.is_empty() {
            endpoint.send(&bytes);
        }
    }

    /// The handshake failed for good: fail what waited and drop the connection.
    fn handshake_failed(&mut self, endpoint: &mut dyn Endpoint, error: RedisError) {
        connect_failed(&self.inner, self.conn_id, error);
        endpoint.close();
    }

    /// One reply from the server.
    fn on_reply(&mut self, endpoint: &mut dyn Endpoint, value: Value) {
        let inner = Arc::clone(&self.inner);
        // A subscriber's connection, once past its handshake, gets messages and
        // acknowledgements, not replies.
        if inner.sub.is_some() && inner.state.lock().unwrap().phase == Phase::Ready {
            return pubsub::sub_reply(&inner, value);
        }
        if let Value::Push(mut items) = value {
            // Out-of-band data belongs to no command: to the push handler, of
            // whatever kind.
            if inner.state.lock().unwrap().conn_id != self.conn_id {
                return;
            }
            let kind = items.first().and_then(Value::as_str).unwrap_or("").to_string();
            let data = if items.is_empty() { Vec::new() } else { items.split_off(1) };
            if let Some(handler) = inner.push.lock().unwrap().as_mut() {
                handler(Push { kind, data });
            }
            return;
        }
        let sent = {
            let mut st = inner.state.lock().unwrap();
            if st.conn_id != self.conn_id {
                return;
            }
            st.pending.pop_front()
        };
        let Some(sent) = sent else {
            // A reply for nothing: the stream has lost step with us.
            lost(&inner, self.conn_id, "the server sent a reply nobody asked for");
            endpoint.close();
            return;
        };
        cancel_timer(&sent.cancel);
        match sent.kind {
            Kind::User(Some(cb)) => cb(into_reply(value)),
            Kind::User(None) => {} // timed out: the reply is discarded
            Kind::Internal(step) => self.on_handshake_reply(endpoint, step, value),
        }
        close_if_drained(&inner);
    }

    fn on_handshake_reply(&mut self, endpoint: &mut dyn Endpoint, step: Step, value: Value) {
        let inner = Arc::clone(&self.inner);
        let error = match value {
            Value::Error(e) => Some(e),
            _ => None,
        };
        match (step, error) {
            (Step::Hello, None) => {
                inner.state.lock().unwrap().resp3 = true;
                // HELLO carries no database: select it now.
                if inner.config.database != 0 {
                    return self.push_internal(endpoint, Step::Select, &select_command(inner.config.database));
                }
            }
            (Step::Hello, Some(e)) if hello_unsupported(&e) => {
                // An older server: start again in RESP2.
                for (step, bytes) in resp2_plan(&inner.config) {
                    self.push_internal(endpoint, step, &bytes);
                }
            }
            (Step::SetName, _) => {} // a name is a convenience; a proxy may refuse it
            (_, Some(e)) => {
                return self.handshake_failed(endpoint, RedisError::Server(e));
            }
            (_, None) => {}
        }
        let outstanding = {
            let st = inner.state.lock().unwrap();
            st.pending.iter().any(|s| matches!(s.kind, Kind::Internal(_)))
        };
        if !outstanding {
            self.ready(endpoint);
        }
    }

    /// Send one more handshake command, and expect its reply.
    fn push_internal(&mut self, endpoint: &mut dyn Endpoint, step: Step, bytes: &[u8]) {
        self.inner.state.lock().unwrap().pending.push_back(Sent {
            qid: u64::MAX,
            kind: Kind::Internal(step),
            cancel: None,
            held: false,
        });
        endpoint.send(bytes);
    }
}

fn select_command(database: u32) -> Vec<u8> {
    let mut out = Vec::new();
    encode_command(&[b"SELECT", database.to_string().as_bytes()], &mut out);
    out
}

impl ProtocolHandler for Conn {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        {
            let mut st = self.inner.state.lock().unwrap();
            if st.conn_id == self.conn_id {
                st.handle = Some(endpoint.handle());
            }
        }
        if !self.tls {
            self.begin_handshake(endpoint);
        }
    }

    fn security_established(&mut self, endpoint: &mut dyn Endpoint, _info: &hopf_core::SecurityInfo) {
        self.begin_handshake(endpoint);
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, buf: &mut hopf_core::LoopBuf) {
        {
            let mut st = self.inner.state.lock().unwrap();
            if st.conn_id == self.conn_id {
                st.last_rx = Instant::now();
            }
        }
        let mut replies = Vec::new();
        let mut bad = None;
        hopf_core::with_slice(buf, |data| {
            if let Err(e) = self.parser.feed(data, &mut |v| replies.push(v)) {
                bad = Some(e);
                *data = &[];
            }
        });
        for v in replies {
            self.on_reply(endpoint, v);
        }
        if let Some(e) = bad {
            lost(&self.inner, self.conn_id, &format!("protocol error: {e}"));
            endpoint.close();
        }
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
        lost(&self.inner, self.conn_id, "the connection closed");
    }

    fn error(&mut self, _endpoint: &mut dyn Endpoint, err: &std::io::Error) {
        lost(&self.inner, self.conn_id, &err.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_name_is_read_from_the_encoding() {
        assert_eq!(command_name(&Command::new("multi").encode()).as_deref(), Some(&b"MULTI"[..]));
        assert_eq!(command_name(&Command::new("GET").arg("k").encode()).as_deref(), Some(&b"GET"[..]));
        assert_eq!(command_name(b"garbage"), None);
        assert_eq!(command_name(b""), None);
    }

    #[test]
    fn backoff_doubles_to_a_ceiling() {
        let (i, m) = (Duration::from_millis(100), Duration::from_secs(5));
        let secs: Vec<u128> = (1..=8).map(|n| backoff(i, m, n).as_millis()).collect();
        assert_eq!(secs, vec![100, 200, 400, 800, 1600, 3200, 5000, 5000]);
        assert_eq!(backoff(i, m, 1000), m, "no overflow");
    }

    #[test]
    fn hello_is_treated_as_unsupported_only_for_an_old_server() {
        let old = ServerError::parse("ERR unknown command 'HELLO', with args beginning with: '3'");
        assert!(hello_unsupported(&old));
        assert!(hello_unsupported(&ServerError::parse("NOPROTO sorry, this protocol version is not supported")));
        // A wrong password is not a reason to try again in RESP2.
        assert!(!hello_unsupported(&ServerError::parse("WRONGPASS invalid username-password pair")));
        assert!(!hello_unsupported(&ServerError::parse("NOAUTH Authentication required.")));
    }

    #[test]
    fn the_resp3_handshake_is_one_hello_with_auth_and_a_name() {
        let cfg = RedisConfig::new("h", 1).username("u").password("p").client_name("n");
        let plan = handshake_plan(&cfg, true);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].0, Step::Hello);
        assert_eq!(
            plan[0].1,
            b"*7\r\n$5\r\nHELLO\r\n$1\r\n3\r\n$4\r\nAUTH\r\n$1\r\nu\r\n$1\r\np\r\n$7\r\nSETNAME\r\n$1\r\nn\r\n"
        );
        // With a password and no user, the default user.
        let cfg = RedisConfig::new("h", 1).password("p");
        let plan = handshake_plan(&cfg, true);
        assert!(String::from_utf8_lossy(&plan[0].1).contains("default"));
    }

    #[test]
    fn the_resp2_handshake_is_auth_setname_select() {
        let cfg = RedisConfig::new("h", 1).password("p").client_name("n").database(3);
        let steps: Vec<Step> = resp2_plan(&cfg).into_iter().map(|(s, _)| s).collect();
        assert_eq!(steps, vec![Step::Auth, Step::SetName, Step::Select]);
        // Nothing configured, nothing sent.
        assert!(resp2_plan(&RedisConfig::new("h", 1)).is_empty());
        assert!(handshake_plan(&RedisConfig::new("h", 1).resp2_only(), false).is_empty());
    }

    #[test]
    fn cloning_a_command_shares_its_arguments_and_extending_a_clone_leaves_the_original_alone() {
        let original = Command::new("SET").arg("k").arg(vec![b'v'; 64 * 1024]);
        let copy = original.clone();
        assert!(Arc::ptr_eq(&original.args, &copy.args), "no argument was copied");
        let longer = copy.clone().arg("EX");
        assert_eq!(longer.words().len(), 4);
        assert_eq!(original.words().len(), 3, "the original is not changed");
        assert_eq!(copy, original);
        assert_ne!(longer, original);
    }

    #[test]
    fn commands_encode_and_expose_their_words() {
        let c = Command::new("SET").arg("k").args(["v", "EX"]).arg(b"10");
        assert_eq!(c.words().len(), 5);
        assert_eq!(c.encode(), b"*5\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n$2\r\nEX\r\n$2\r\n10\r\n");
    }

    #[test]
    fn the_config_does_not_print_its_password() {
        let shown = format!("{:?}", RedisConfig::new("h", 6379).password("hunter2"));
        assert!(!shown.contains("hunter2"), "{shown}");
        assert!(shown.contains("redacted"));
    }
}
