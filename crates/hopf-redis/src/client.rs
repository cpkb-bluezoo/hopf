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
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use hopf_core::{ConnHandle, Endpoint, ProtocolHandler, ReactorHandle, TcpConnectorConfig};
use hopf_dns::DnsResolver;

use crate::config::RedisConfig;
use crate::error::RedisError;
use crate::pubsub::{self, Desired, Push, SubscriberHandler};
use crate::argstream::{ArgFactory, ArgSource, SourceCtl, SourceRead, SourceWaker, StreamArg};
use crate::collect::{Collector, TooLarge};
use crate::resp::{
    encode_command, encode_words, AggKind, Feed, Flow, ReplyKind, ReplySink, RespParser, Scalar, ServerError, StrKind,
    Value,
};

/// What a command's callback is given.
pub type Reply = Result<Value, RedisError>;

/// A command's callback.
pub type Callback = Box<dyn FnOnce(Reply) + Send>;

/// A command written as an array of bulk strings, ready to send. Cloning one
/// shares its arguments rather than copying them, so a large value is not
/// copied when a cluster client keeps the command to send it again.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Command {
    /// The arguments, name first; a streamed argument is an empty placeholder.
    args: Arc<Vec<Vec<u8>>>,
    /// The streamed arguments, by position in `args`.
    streams: Option<Arc<Vec<(usize, StreamArg)>>>,
}

impl Command {
    /// A command named `name`.
    pub fn new(name: impl AsRef<[u8]>) -> Self {
        Self {
            args: Arc::new(vec![name.as_ref().to_vec()]),
            streams: None,
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

    /// Add an argument whose bytes are pulled from a source as the connection
    /// takes them, so a value of any size is never held whole: see [`StreamArg`].
    /// A streamed argument cannot be a key, which a cluster must read to route the
    /// command, and cannot be in a transaction.
    pub fn arg_stream(mut self, arg: StreamArg) -> Self {
        let at = self.args.len();
        Arc::make_mut(&mut self.args).push(Vec::new());
        Arc::make_mut(self.streams.get_or_insert_with(Default::default)).push((at, arg));
        self
    }

    /// The command's words, name first. A streamed argument is an empty
    /// placeholder here: see [`is_streamed`](Self::is_streamed).
    pub fn words(&self) -> &[Vec<u8>] {
        &self.args
    }

    /// Whether the word at `index` is a streamed argument.
    pub fn is_streamed(&self, index: usize) -> bool {
        self.streams.as_ref().is_some_and(|s| s.iter().any(|(at, _)| *at == index))
    }

    /// Whether any argument is streamed.
    pub fn has_streams(&self) -> bool {
        self.streams.is_some()
    }

    /// The command as it goes on the wire: for one with no streamed argument.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_words(&self.args, &mut out);
        out
    }

    /// The command ready to be written: one buffer, or, with a streamed
    /// argument, the buffers before and after it and the stream between them.
    pub(crate) fn encoded(&self) -> Encoded {
        let Some(streams) = &self.streams else {
            return Encoded::Plain(self.encode());
        };
        let mut parts = VecDeque::new();
        let mut head = format!("*{}\r\n", self.args.len()).into_bytes();
        for (i, word) in self.args.iter().enumerate() {
            match streams.iter().find(|(at, _)| *at == i) {
                Some((_, arg)) => {
                    head.extend_from_slice(format!("${}\r\n", arg.len()).as_bytes());
                    parts.push_back(Part::Bytes(std::mem::take(&mut head), 0));
                    parts.push_back(Part::Stream {
                        len: arg.len(),
                        factory: Arc::clone(arg.factory()),
                    });
                    // The CRLF that ends the argument follows its bytes.
                    head.extend_from_slice(b"\r\n");
                }
                None => {
                    head.extend_from_slice(format!("${}\r\n", word.len()).as_bytes());
                    head.extend_from_slice(word);
                    head.extend_from_slice(b"\r\n");
                }
            }
        }
        if !head.is_empty() {
            parts.push_back(Part::Bytes(head, 0));
        }
        Encoded::Streamed(parts)
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
    /// A command: its reply goes to the sink in the cell, unless the command
    /// was abandoned (it timed out), when the reply is discarded as it arrives.
    User(Arc<Cmd>),
    Internal(Step),
}

/// How a command ended, for its sink to be told.
pub(crate) enum Outcome {
    /// The reply is complete, or was discarded to its end because the sink chose
    /// [`Flow::Skip`] (`skipped`).
    Complete { skipped: bool },
    /// The command did not get a reply.
    Failed(RedisError),
}

/// What receives a command's reply, event by event, and hears how it ended.
pub(crate) trait CmdSink: Send {
    fn events(&mut self) -> &mut dyn ReplySink;
    /// Exactly once, and last.
    fn finish(self: Box<Self>, outcome: Outcome);
}

/// A callback that takes the reply as a [`Value`]: the events are assembled by a
/// [`Collector`] under the configured limits.
struct Collecting<F> {
    collector: Collector,
    callback: F,
}

impl<F: FnOnce(Reply) + Send> CmdSink for Collecting<F> {
    fn events(&mut self) -> &mut dyn ReplySink {
        &mut self.collector
    }

    fn finish(self: Box<Self>, outcome: Outcome) {
        let Collecting { mut collector, callback } = *self;
        callback(match outcome {
            Outcome::Complete { .. } => match collector.take() {
                Ok(value) => into_reply(value),
                Err(TooLarge(why)) => Err(RedisError::Protocol(why)),
            },
            Outcome::Failed(e) => Err(e),
        });
    }
}

/// A sink the caller wrote: the events go to it as they arrive, and it is told
/// how the command ended.
struct Streaming<S> {
    sink: S,
}

impl<S: ReplySink + Send> CmdSink for Streaming<S> {
    fn events(&mut self) -> &mut dyn ReplySink {
        &mut self.sink
    }

    fn finish(mut self: Box<Self>, outcome: Outcome) {
        self.sink.finished(match outcome {
            Outcome::Complete { skipped: false } => Ok(()),
            Outcome::Complete { skipped: true } => Err(RedisError::Cancelled),
            Outcome::Failed(e) => Err(e),
        });
    }
}

/// Nothing is holding up the reply.
const FLOW_RUNNING: u8 = 0;
/// The sink returned [`Flow::Pause`]: the connection is to stop reading.
const FLOW_PAUSE_REQUESTED: u8 = 1;
/// The connection has stopped reading until [`StreamHandle::resume`].
const FLOW_PAUSED: u8 = 2;
/// [`StreamHandle::resume`] was called while the sink was still running, so
/// before the pause it is about to return: it is held to cancel that pause. It
/// exists only during a call of the sink, so a resume that comes at any other
/// time and finds nothing to resume cannot cancel a later pause.
const FLOW_PERMIT: u8 = 4;

/// Nanoseconds from a fixed point, for a timestamp that fits an atomic.
fn now_nanos() -> u64 {
    static BASE: OnceLock<Instant> = OnceLock::new();
    BASE.get_or_init(Instant::now).elapsed().as_nanos() as u64
}

/// One command, shared between the queue and the connection that reads its
/// reply, so that a timeout can take the sink out from under a reply that has
/// begun, and a consumer on another thread can pause, resume or cancel it.
pub(crate) struct Cmd {
    /// The sink, until the command ends; `None` once it has, so that a reply
    /// still to come is discarded as it arrives.
    sink: Mutex<Option<Box<dyn CmdSink>>>,
    /// The caller's own sink: its timeout is one of inactivity, not of the whole
    /// reply, and stops while the consumer has paused.
    streaming: bool,
    limit: Option<Duration>,
    /// When the sink last heard something (or the command was issued).
    activity: AtomicU64,
    /// How the command ended while the sink was being called, so it could not be
    /// taken: the call that is running finishes it when it returns. Set when a
    /// sink closes the client from inside its own callback, or a timer or a
    /// caller on another thread ends the command during one.
    deferred: Mutex<Option<Outcome>>,
    has_deferred: AtomicBool,
    flow: AtomicU8,
    /// The sink is being called, on the reactor.
    in_sink: AtomicBool,
    cancelled: AtomicBool,
    /// A streamed argument of the command is being written: the connection holds
    /// part of it, and cannot be used for anything else until it is done.
    writing: AtomicBool,
    /// Stops the command's first timeout timer once it has ended. Set once, so
    /// no lock is needed for the commands that are only timed from issue to reply.
    timer: OnceLock<Arc<AtomicBool>>,
    /// A streaming command's timer is set again when it fires and there has been
    /// activity since: the one that is current, to be stopped when it ends. Only
    /// such a command has the lock.
    rearmed: Option<Mutex<Option<Arc<AtomicBool>>>>,
}

impl Cmd {
    fn new(sink: Box<dyn CmdSink>, streaming: bool, limit: Option<Duration>) -> Arc<Self> {
        Arc::new(Self {
            sink: Mutex::new(Some(sink)),
            streaming,
            limit,
            activity: AtomicU64::new(now_nanos()),
            deferred: Mutex::new(None),
            has_deferred: AtomicBool::new(false),
            flow: AtomicU8::new(FLOW_RUNNING),
            in_sink: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
            writing: AtomicBool::new(false),
            timer: OnceLock::new(),
            rearmed: streaming.then(|| Mutex::new(None)),
        })
    }

    fn cancel_timer(&self) {
        if let Some(flag) = self.timer.get() {
            flag.store(true, Ordering::SeqCst);
        }
        if let Some(rearmed) = &self.rearmed {
            if let Some(flag) = rearmed.lock().unwrap().take() {
                flag.store(true, Ordering::SeqCst);
            }
        }
    }

    fn take_sink(&self) -> Option<Box<dyn CmdSink>> {
        self.sink.lock().unwrap().take()
    }

    /// The command has ended (it timed out, say), so what is left of it is not
    /// wanted.
    fn ended(&self) -> bool {
        self.sink.lock().unwrap().is_none()
    }

    fn touch(&self) {
        self.activity.store(now_nanos(), Ordering::Relaxed);
    }

    /// What the sink's `flow` comes to: a pause is requested, unless the consumer
    /// has already resumed, in which case there is none.
    fn settle(&self, flow: Flow) -> Flow {
        if flow != Flow::Pause {
            self.flow.fetch_and(!FLOW_PERMIT, Ordering::SeqCst);
            return flow;
        }
        loop {
            let cur = self.flow.load(Ordering::SeqCst);
            if cur & FLOW_PERMIT != 0 {
                if self.flow.compare_exchange(cur, cur & !FLOW_PERMIT, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
                    return Flow::Continue;
                }
            } else if self.flow.compare_exchange(cur, FLOW_PAUSE_REQUESTED, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
                return Flow::Pause;
            }
        }
    }
}

/// End a command with `outcome`, on the reactor and never inline: a caller
/// holding a lock when it issues a command must not see its sink re-enter it.
///
/// If the sink is in the middle of a call, which is possible when the call itself
/// ends the command (a sink that closes the client), it cannot be taken and the
/// outcome is left for the call to act on when it returns.
fn end_cmd(inner: &Inner, cmd: &Cmd, outcome: Outcome) {
    cmd.cancel_timer();
    let taken = match cmd.sink.try_lock() {
        Ok(mut slot) => Some(slot.take()),
        Err(std::sync::TryLockError::Poisoned(p)) => Some(p.into_inner().take()),
        Err(std::sync::TryLockError::WouldBlock) => None,
    };
    match taken {
        Some(Some(sink)) => inner.reactor.execute(Box::new(move || sink.finish(outcome))),
        Some(None) => {} // it had already ended
        None => {
            cmd.deferred.lock().unwrap().get_or_insert(outcome);
            cmd.has_deferred.store(true, Ordering::SeqCst);
        }
    }
}

/// Act on how a command ended during a call of its sink, now that the call has
/// returned.
fn run_deferred(inner: &Inner, cmd: &Cmd) {
    if !cmd.has_deferred.load(Ordering::SeqCst) {
        return;
    }
    cmd.has_deferred.store(false, Ordering::SeqCst);
    let outcome = cmd.deferred.lock().unwrap().take();
    if let (Some(outcome), Some(sink)) = (outcome, cmd.take_sink()) {
        inner.reactor.execute(Box::new(move || sink.finish(outcome)));
    }
}

/// A handle on a command sent with [`RedisClient::send_streaming`] or
/// [`RedisCluster::send_streaming`](crate::RedisCluster::send_streaming), for the
/// consumer of its reply: to resume it after pausing, or to cancel it.
///
/// Clones are cheap and share the command. Calls may come from any thread. For a
/// command sent through a cluster, which may be sent again before any of its
/// reply reaches the sink, a handle follows whichever attempt is current.
#[derive(Clone)]
pub struct StreamHandle {
    target: HandleTarget,
}

#[derive(Clone)]
enum HandleTarget {
    /// One command on one connection.
    Command { cmd: Arc<Cmd>, inner: Weak<Inner> },
    /// A command through a cluster.
    Cluster(Arc<ClusterStream>),
}

/// What a cluster's streaming command shares with its handle: that it has been
/// cancelled, and the handle of the attempt now under way.
#[derive(Default)]
pub(crate) struct ClusterStream {
    pub(crate) cancelled: AtomicBool,
    pub(crate) current: Mutex<Option<StreamHandle>>,
}

impl StreamHandle {
    pub(crate) fn command(cmd: Arc<Cmd>, inner: Weak<Inner>) -> Self {
        Self {
            target: HandleTarget::Command { cmd, inner },
        }
    }

    pub(crate) fn cluster(state: Arc<ClusterStream>) -> Self {
        Self {
            target: HandleTarget::Cluster(state),
        }
    }

    /// Resume reading after the sink returned [`Flow::Pause`]. It may be called
    /// from any thread at any time: even while the sink is still running, before
    /// it has returned the `Pause` (the pause is then cancelled), or after the
    /// command has ended (when it does nothing).
    pub fn resume(&self) {
        let (cmd, weak) = match &self.target {
            HandleTarget::Command { cmd, inner } => (cmd, inner),
            HandleTarget::Cluster(state) => {
                let current = state.current.lock().unwrap().clone();
                if let Some(h) = current {
                    h.resume();
                }
                return;
            }
        };
        let flow = &cmd.flow;
        loop {
            let cur = flow.load(Ordering::SeqCst);
            let released = |to: u8| flow.compare_exchange(cur, to, Ordering::SeqCst, Ordering::SeqCst).is_ok();
            if cur & FLOW_PAUSED != 0 {
                if released(FLOW_RUNNING) {
                    if let Some(inner) = weak.upgrade() {
                        let inner2 = Arc::clone(&inner);
                        inner.reactor.execute(Box::new(move || resume_read(&inner2)));
                    }
                    return;
                }
            } else if cur & FLOW_PAUSE_REQUESTED != 0 {
                if released(FLOW_RUNNING) {
                    return;
                }
            } else if cmd.in_sink.load(Ordering::SeqCst) {
                if released(cur | FLOW_PERMIT) {
                    return;
                }
            } else {
                return;
            }
        }
    }

    /// The consumer wants no more of this reply: it is discarded as it arrives,
    /// in constant memory, and the sink is finished with
    /// [`RedisError::Cancelled`]. The connection is not closed and the commands
    /// pipelined behind it are unaffected. Does nothing once the command has
    /// ended. Through a cluster, a command that has not yet begun to reply is not
    /// sent again.
    pub fn cancel(&self) {
        match &self.target {
            HandleTarget::Command { cmd, .. } => {
                cmd.cancelled.store(true, Ordering::SeqCst);
                self.resume();
            }
            HandleTarget::Cluster(state) => {
                state.cancelled.store(true, Ordering::SeqCst);
                let current = state.current.lock().unwrap().clone();
                if let Some(h) = current {
                    h.cancel();
                }
            }
        }
    }
}

/// Start reading again, on the reactor: the consumer is ready for more.
fn resume_read(inner: &Arc<Inner>) {
    let handle = {
        let mut st = inner.state.lock().unwrap();
        st.read_paused = false;
        st.handle.clone()
    };
    if let Some(h) = handle {
        h.with_endpoint(|ep| {
            ep.resume_read();
            // What is already in the ring is read without waiting for more.
            ep.poke_handler();
        });
    }
}

/// Written to the connection, awaiting its reply.
struct Sent {
    kind: Kind,
    /// The server may legitimately sit on this command for longer than the
    /// health check waits (a blocking command, a `WAIT`, or one given no
    /// limit), so its silence says nothing.
    held: bool,
}

/// Not yet written: waiting for the connection.
struct Waiting {
    qid: u64,
    bytes: Encoded,
    cmd: Arc<Cmd>,
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
    /// What is to be written to the connection, in order.
    wq: WriteQ,
    /// The streamed command being written, between blocks.
    active: Option<Box<Active>>,
    /// A block has been written and the next waits for the outbound buffer to
    /// drain.
    drain_wait: bool,
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
    /// The consumer of a streamed reply has paused the connection: it is not
    /// being read, and its silence is the consumer's doing, not the server's.
    read_paused: bool,
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
            wq: WriteQ::default(),
            active: None,
            drain_wait: false,
            flush_scheduled: false,
            addrs: VecDeque::new(),
            resp3: false,
            failures: 0,
            retry_at: None,
            last_error: None,
            desired: Desired::default(),
            last_rx: Instant::now(),
            in_multi: false,
            read_paused: false,
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
        st.wq.push_plain(bytes);
        !(st.drain_wait || st.active.is_some() || std::mem::replace(&mut st.flush_scheduled, true))
    };
    if need_flush {
        flush(inner);
    }
}

/// Forget what was to be written: the connection it was for has gone.
fn reset_writes(st: &mut State) {
    st.wq.clear();
    if let Some(active) = st.active.take() {
        active.cmd.writing.store(false, Ordering::SeqCst);
    }
    st.drain_wait = false;
    st.flush_scheduled = false;
}

/// Close the connection, fail what is waiting, and refuse later commands.
pub(crate) fn close(inner: &Arc<Inner>) {
    inner.closed.store(true, Ordering::SeqCst);
    let (handle, waiting, pending) = {
        let mut st = inner.state.lock().unwrap();
        st.phase = Phase::Idle;
        st.in_multi = false;
        st.read_paused = false;
        st.conn_id += 1;
        reset_writes(&mut st);
        (st.handle.take(), std::mem::take(&mut st.waiting), std::mem::take(&mut st.pending))
    };
    if let Some(h) = handle {
        h.close();
    }
    for w in waiting {
        end_cmd(inner, &w.cmd, Outcome::Failed(RedisError::Closed));
    }
    for s in pending {
        if let Kind::User(cmd) = s.kind {
            end_cmd(inner, &cmd, Outcome::Failed(RedisError::Closed));
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
        self.send_one(command, self.collecting(callback), Deadline::Default, false);
    }

    /// Send the command made of `words` (the name first) and call `callback`
    /// with the reply. Returns at once.
    pub fn command(&self, words: &[&[u8]], callback: impl FnOnce(Reply) + Send + 'static) {
        if words.first().is_some_and(|w| pubsub::is_subscription_command(w)) {
            return self.refuse(self.collecting(callback));
        }
        let mut bytes = Vec::new();
        encode_command(words, &mut bytes);
        submit_timed(&self.inner, vec![(Encoded::Plain(bytes), self.collecting(callback))], Deadline::Default, false, false);
    }

    /// Send several commands as one write, in order, with nothing from another
    /// caller between them. Each has its own callback, called in the order the
    /// commands were given.
    pub fn send_batch(&self, commands: Vec<(Command, Callback)>) {
        self.send_batch_with_deadline(commands, Deadline::Default);
    }

    /// Send `command` and tell `sink` what its reply is, as the reply arrives:
    /// the events of [`ReplySink`], with a string's payload as chunks that
    /// borrow from the connection's buffer, so nothing of a large reply is held.
    /// Returns at once, with a handle to resume the reply after pausing it, or to
    /// cancel it.
    ///
    /// The sink runs on the client's reactor and must not block: to wait for
    /// something, return [`Flow::Pause`] and call [`StreamHandle::resume`] when
    /// ready. Replies come back in the order commands were sent, so a streamed
    /// reply holds the connection until it ends, and so does a pause: use a
    /// connection of its own for a large value.
    ///
    /// The command timeout is for the first byte of the reply and then for
    /// silence from the server: it is reset by every chunk and stops while the
    /// consumer has paused. [`ReplySink::finished`] is the sink's last call, with
    /// how the command ended.
    pub fn send_streaming(&self, command: &Command, sink: impl ReplySink + Send + 'static) -> StreamHandle {
        self.send_streaming_with_deadline(command, Deadline::Default, sink)
    }

    /// [`send_streaming`](Self::send_streaming) with a deadline of its own
    /// instead of the configured command timeout.
    pub fn send_streaming_with_deadline(
        &self,
        command: &Command,
        deadline: Deadline,
        sink: impl ReplySink + Send + 'static,
    ) -> StreamHandle {
        let sink: Box<dyn CmdSink> = Box::new(Streaming { sink });
        let cmd = self.send_one(command, sink, deadline, true).expect("a streaming command is returned");
        StreamHandle::command(cmd, Arc::downgrade(&self.inner))
    }

    /// [`send_streaming_with_deadline`](Self::send_streaming_with_deadline) behind
    /// an `ASKING`, in one write with nothing between them: a cluster sending the
    /// command to the node its slot is moving to.
    pub(crate) fn send_asking_streaming(
        &self,
        command: &Command,
        deadline: Deadline,
        sink: impl ReplySink + Send + 'static,
    ) -> StreamHandle {
        let asking = self.collecting(|_: Reply| {});
        let streamed: Box<dyn CmdSink> = Box::new(Streaming { sink });
        let items = vec![(Command::new("ASKING").encoded(), asking), (command.encoded(), streamed)];
        let cmd = submit_timed(&self.inner, items, deadline, true, false).expect("a streaming command is returned");
        StreamHandle::command(cmd, Arc::downgrade(&self.inner))
    }

    /// A sink that assembles the reply as a value, under the configured limits,
    /// for `callback`.
    fn collecting<F: FnOnce(Reply) + Send + 'static>(&self, callback: F) -> Box<dyn CmdSink> {
        Box::new(Collecting {
            collector: Collector::new(&self.inner.config.limits),
            callback,
        })
    }

    /// Fail `sink` as a refused subscription.
    fn refuse(&self, sink: Box<dyn CmdSink>) {
        self.inner.reactor.execute(Box::new(move || sink.finish(Outcome::Failed(subscription_refused()))));
    }

    /// Send one command with the sink that takes its reply. Returns the command
    /// if `streaming`, for its handle.
    fn send_one(&self, command: &Command, sink: Box<dyn CmdSink>, deadline: Deadline, streaming: bool) -> Option<Arc<Cmd>> {
        let refused = command.words().first().is_some_and(|w| pubsub::is_subscription_command(w));
        submit_timed(&self.inner, vec![(command.encoded(), sink)], deadline, streaming, refused)
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
        self.send_one(command, self.collecting(callback), deadline, false);
    }

    /// [`send_batch`](Self::send_batch) with one deadline for every command.
    pub(crate) fn send_batch_with_deadline(&self, commands: Vec<(Command, Callback)>, deadline: Deadline) {
        let refused = commands
            .iter()
            .any(|(c, _)| c.words().first().is_some_and(|w| pubsub::is_subscription_command(w)));
        let items = commands.into_iter().map(|(c, cb)| (c.encoded(), self.collecting(cb))).collect();
        submit_timed(&self.inner, items, deadline, false, refused);
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
fn subscription_refused() -> RedisError {
    RedisError::Unexpected("subscriptions need a RedisSubscriber, not a command connection".into())
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
        match w.bytes.name().as_deref() {
            Some(b"MULTI") => st.in_multi = true,
            Some(b"EXEC") | Some(b"DISCARD") => st.in_multi = false,
            _ => {}
        }
    }
}

/// Accept commands from a caller: send them, queue them for the connection, or
/// fail them. `refused` fails them all as subscriptions. Returns the command if
/// `streaming`, whether or not it was sent.
fn submit_timed(
    inner: &Arc<Inner>,
    items: Vec<(Encoded, Box<dyn CmdSink>)>,
    deadline: Deadline,
    streaming: bool,
    refused: bool,
) -> Option<Arc<Cmd>> {
    let mut prepared = Vec::with_capacity(items.len());
    for (bytes, sink) in items {
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
        // A command with a streamed argument is timed by activity too: it may
        // take minutes to write.
        let by_activity = streaming || matches!(bytes, Encoded::Streamed(_));
        let cmd = Cmd::new(sink, by_activity, limit);
        prepared.push(Waiting { qid, bytes, cmd, held });
    }
    // A streaming command is sent alone (or behind an `ASKING`), and its caller
    // is given it.
    let handle = if streaming { prepared.last().map(|w| Arc::clone(&w.cmd)) } else { None };
    if refused {
        for w in prepared {
            end_cmd(inner, &w.cmd, Outcome::Failed(subscription_refused()));
        }
        return handle;
    }
    if inner.closed.load(Ordering::SeqCst) || inner.retiring.load(Ordering::SeqCst) {
        for w in prepared {
            end_cmd(inner, &w.cmd, Outcome::Failed(RedisError::Closed));
        }
        return handle;
    }
    // Each command's timeout starts now, covering the connect.
    for w in &prepared {
        if let Some(limit) = w.cmd.limit {
            arm_timer(inner, &w.cmd, w.qid, limit);
        }
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
                        match w.bytes {
                            Encoded::Plain(bytes) => st.wq.push_plain(bytes),
                            Encoded::Streamed(parts) => st.wq.push_streamed(Streamed {
                                cmd: Arc::clone(&w.cmd),
                                parts,
                            }),
                        }
                        st.pending.push_back(Sent {
                            kind: Kind::User(w.cmd),
                            held: w.held,
                        });
                    }
                    // A block that is draining, or a streamed command being written,
                    // carries on to what was just queued by itself.
                    if st.drain_wait || st.active.is_some() || std::mem::replace(&mut st.flush_scheduled, true) {
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
                end_cmd(inner, &w.cmd, Outcome::Failed(why.clone()));
            }
        }
    }
    handle
}

/// Start the timer that ends `cmd` if it is not answered in `delay`.
fn arm_timer(inner: &Arc<Inner>, cmd: &Arc<Cmd>, qid: u64, delay: Duration) {
    let (weak, cmd2) = (Arc::downgrade(inner), Arc::clone(cmd));
    let flag = inner.reactor.schedule_timer(
        delay,
        Box::new(move || {
            if let Some(inner) = weak.upgrade() {
                expire(&inner, &cmd2, qid);
            }
        }),
    );
    // The first timer is kept without a lock; one set again replaces the last.
    match cmd.timer.set(Arc::clone(&flag)) {
        Ok(()) => {}
        Err(_) => {
            if let Some(rearmed) = &cmd.rearmed {
                *rearmed.lock().unwrap() = Some(flag);
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
                    // A connection the consumer has paused is silent by choice.
                    let watched = st.phase == Phase::Handshaking
                        || (st.pending.iter().any(|s| matches!(s.kind, Kind::User(_)))
                            && !st.pending.iter().any(|s| s.held)
                            && !st.read_paused
                            // The server waits for the rest of a command being written.
                            && st.active.is_none());
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

/// What is written for a command.
pub(crate) enum Encoded {
    /// All in memory, as one buffer.
    Plain(Vec<u8>),
    /// With a streamed argument: the buffers and streams in the order they go.
    Streamed(VecDeque<Part>),
}

impl Encoded {
    /// The name of the command, in upper case.
    fn name(&self) -> Option<Vec<u8>> {
        match self {
            Encoded::Plain(bytes) => command_name(bytes),
            Encoded::Streamed(parts) => match parts.front() {
                Some(Part::Bytes(head, _)) => command_name(head),
                _ => None,
            },
        }
    }
}

/// A piece of a command with a streamed argument.
pub(crate) enum Part {
    /// Bytes in memory, from an offset, which is where a large one has got to.
    Bytes(Vec<u8>, usize),
    /// A streamed argument of `len` bytes, opened when the command is written.
    Stream { len: u64, factory: Arc<dyn ArgFactory> },
}

/// A command with a streamed argument, waiting to be written.
pub(crate) struct Streamed {
    cmd: Arc<Cmd>,
    parts: VecDeque<Part>,
}

/// What is to be written, in order. The plain commands, which are nearly all of
/// them, share one buffer as they always did; a command with a streamed argument
/// splits it, and what is submitted after it waits behind it.
#[derive(Default)]
struct WriteQ {
    /// Plain bytes to go first, from `from`.
    head: Vec<u8>,
    from: usize,
    /// Streamed commands, each followed by the plain bytes submitted after it and
    /// before the next.
    rest: VecDeque<(Streamed, Vec<u8>)>,
}

impl WriteQ {
    fn push_plain(&mut self, bytes: Vec<u8>) {
        let target = match self.rest.back_mut() {
            Some((_, tail)) => tail,
            None => {
                if self.head.is_empty() {
                    // The common case: the command's own buffer becomes the queue,
                    // so a large value is not copied again.
                    self.head = bytes;
                    self.from = 0;
                    return;
                }
                &mut self.head
            }
        };
        if target.is_empty() {
            *target = bytes;
        } else {
            target.extend_from_slice(&bytes);
        }
    }

    fn push_streamed(&mut self, streamed: Streamed) {
        self.rest.push_back((streamed, Vec::new()));
    }

    fn clear(&mut self) {
        self.head = Vec::new();
        self.from = 0;
        self.rest.clear();
    }
}

/// A streamed command being written: its sources are open, and some of it has
/// been sent.
pub(crate) struct Active {
    cmd: Arc<Cmd>,
    parts: VecDeque<ActivePart>,
    /// The streamed argument being read, and how much of it is still to come.
    cur: Option<(Box<dyn ArgSource>, u64)>,
    waker: SourceWaker,
    buf: Vec<u8>,
}

enum ActivePart {
    Bytes(Vec<u8>, usize),
    Stream { len: u64, source: Box<dyn ArgSource> },
}

/// Plain bytes up to this much are written at once, without waiting for the
/// connection's outbound buffer to drain.
const SMALL_WRITE: usize = 64 * 1024;
/// The most written before waiting for the outbound buffer to drain: well within
/// its default limit of 4 MiB, so a large command never overflows it.
const WRITE_BLOCK: usize = 1024 * 1024;
/// How much of a streamed argument is read at a time.
const STREAM_BLOCK: usize = 256 * 1024;

/// Write what is queued for the connection, on the reactor.
///
/// Small writes go straight to the connection. A large buffer, or a streamed
/// argument, goes a block at a time with the next not sent until the buffer has
/// drained (`from_drain` says it has): memory stays constant however large the
/// command, and the connection's outbound buffer is never overflowed. A streamed
/// argument whose source has nothing yet waits to be woken.
fn drain_writes(inner: &Arc<Inner>, conn_id: u64, ep: &mut dyn Endpoint, from_drain: bool) {
    {
        let mut st = inner.state.lock().unwrap();
        if st.conn_id != conn_id || st.phase != Phase::Ready {
            return;
        }
        if from_drain {
            st.drain_wait = false;
        } else if st.drain_wait {
            // A block is still draining; its callback carries on.
            return;
        }
        st.flush_scheduled = false;
    }
    loop {
        enum Step {
            Send(Vec<u8>, usize),
            Active(Box<Active>),
            Start(Streamed),
            Done,
        }
        let step = {
            let mut st = inner.state.lock().unwrap();
            if st.conn_id != conn_id || st.phase != Phase::Ready {
                return;
            }
            if let Some(active) = st.active.take() {
                Step::Active(active)
            } else if st.wq.head.len() > st.wq.from {
                let from = std::mem::take(&mut st.wq.from);
                Step::Send(std::mem::take(&mut st.wq.head), from)
            } else if let Some((streamed, tail)) = st.wq.rest.pop_front() {
                st.wq.head = tail;
                st.wq.from = 0;
                Step::Start(streamed)
            } else {
                Step::Done
            }
        };
        match step {
            Step::Done => return,
            Step::Send(bytes, from) => {
                if bytes.len() - from <= SMALL_WRITE {
                    ep.send(&bytes[from..]);
                    continue;
                }
                let n = (bytes.len() - from).min(WRITE_BLOCK);
                ep.send(&bytes[from..from + n]);
                let more = {
                    let mut st = inner.state.lock().unwrap();
                    if st.conn_id != conn_id {
                        return;
                    }
                    if from + n < bytes.len() {
                        // What is left goes first, then whatever was queued meanwhile.
                        let newer = std::mem::replace(&mut st.wq.head, bytes);
                        st.wq.from = from + n;
                        st.wq.head.extend_from_slice(&newer);
                    }
                    !st.wq.head.is_empty() || st.active.is_some() || !st.wq.rest.is_empty()
                };
                if more {
                    wait_for_drain(inner, conn_id, ep);
                    return;
                }
            }
            Step::Start(streamed) => match start_streamed(inner, streamed) {
                Some(active) => {
                    let mut st = inner.state.lock().unwrap();
                    st.active = Some(active);
                }
                None => continue,
            },
            Step::Active(active) => match pump(inner, conn_id, ep, active) {
                Pump::Finished => continue,
                Pump::Drain(active) => {
                    inner.state.lock().unwrap().active = Some(active);
                    wait_for_drain(inner, conn_id, ep);
                    return;
                }
                Pump::Parked(active) => {
                    inner.state.lock().unwrap().active = Some(active);
                    return;
                }
                Pump::Failed => return,
            },
        }
    }
}

/// Ask to be called again when the connection's outbound buffer has drained.
fn wait_for_drain(inner: &Arc<Inner>, conn_id: u64, ep: &mut dyn Endpoint) {
    inner.state.lock().unwrap().drain_wait = true;
    let inner = Arc::clone(inner);
    ep.on_write_ready(Some(Box::new(move |ep| drain_writes(&inner, conn_id, ep, true))));
}

/// Open the sources of a streamed command and make it the one being written. If
/// one will not open, the command fails, and nothing of it has been written.
fn start_streamed(inner: &Arc<Inner>, streamed: Streamed) -> Option<Box<Active>> {
    let Streamed { cmd, parts } = streamed;
    let fail = |why: Option<RedisError>| {
        // Its reply will never come: take its place in the queue away.
        let mut st = inner.state.lock().unwrap();
        st.pending.retain(|s| !matches!(&s.kind, Kind::User(c) if Arc::ptr_eq(c, &cmd)));
        drop(st);
        if let Some(e) = why {
            end_cmd(inner, &cmd, Outcome::Failed(e));
        }
    };
    if cmd.ended() {
        // It timed out while it waited behind others: do not send a value for
        // nobody.
        fail(None);
        return None;
    }
    let mut opened = VecDeque::with_capacity(parts.len());
    for part in parts {
        match part {
            Part::Bytes(b, from) => opened.push_back(ActivePart::Bytes(b, from)),
            Part::Stream { len, factory } => match factory.open() {
                Ok(source) => opened.push_back(ActivePart::Stream { len, source }),
                Err(e) => {
                    fail(Some(e));
                    return None;
                }
            },
        }
    }
    cmd.writing.store(true, Ordering::SeqCst);
    cmd.touch();
    let (weak, conn_id) = (Arc::downgrade(inner), inner.state.lock().unwrap().conn_id);
    let waker = SourceWaker::new(move || {
        if let Some(inner) = weak.upgrade() {
            let inner2 = Arc::clone(&inner);
            inner.reactor.execute(Box::new(move || {
                let handle = {
                    let st = inner2.state.lock().unwrap();
                    (st.conn_id == conn_id).then(|| st.handle.clone()).flatten()
                };
                if let Some(h) = handle {
                    let inner3 = Arc::clone(&inner2);
                    h.with_endpoint(move |ep| drain_writes(&inner3, conn_id, ep, false));
                }
            }));
        }
    });
    Some(Box::new(Active {
        cmd,
        parts: opened,
        cur: None,
        waker,
        buf: vec![0; STREAM_BLOCK],
    }))
}

enum Pump {
    /// All of the command is written.
    Finished,
    /// A block is sent: wait for the buffer to drain.
    Drain(Box<Active>),
    /// A source has nothing yet: wait to be woken.
    Parked(Box<Active>),
    /// The command failed, and the connection with it.
    Failed,
}

/// Write the next of a streamed command: one block, then wait.
fn pump(inner: &Arc<Inner>, conn_id: u64, ep: &mut dyn Endpoint, mut a: Box<Active>) -> Pump {
    loop {
        if let Some((source, left)) = a.cur.as_mut() {
            if *left == 0 {
                a.cur = None;
                continue;
            }
            let want = (*left).min(STREAM_BLOCK as u64) as usize;
            let mut ctl = SourceCtl::new(&a.waker);
            match source.read(&mut a.buf[..want], &mut ctl) {
                SourceRead::Data(n) if n > 0 && n <= want => {
                    ep.send(&a.buf[..n]);
                    *left -= n as u64;
                    a.cmd.touch();
                    return Pump::Drain(a);
                }
                SourceRead::Data(_) => {
                    return fail_write(inner, conn_id, ep, &a, RedisError::Protocol("a source returned a bad length".into()))
                }
                SourceRead::Pending => return Pump::Parked(a),
                SourceRead::Failed(e) => return fail_write(inner, conn_id, ep, &a, e),
            }
        }
        match a.parts.pop_front() {
            None => {
                a.cmd.writing.store(false, Ordering::SeqCst);
                a.cmd.touch();
                return Pump::Finished;
            }
            Some(ActivePart::Bytes(bytes, from)) => {
                let len = bytes.len() - from;
                if len <= SMALL_WRITE {
                    ep.send(&bytes[from..]);
                } else {
                    let n = len.min(WRITE_BLOCK);
                    ep.send(&bytes[from..from + n]);
                    if n < len {
                        a.parts.push_front(ActivePart::Bytes(bytes, from + n));
                    }
                    a.cmd.touch();
                    return Pump::Drain(a);
                }
            }
            Some(ActivePart::Stream { len, source }) => a.cur = Some((source, len)),
        }
    }
}

/// A streamed argument failed after the start of the command was written: the
/// command fails with why, and the connection, which can be recovered no other
/// way, is closed.
fn fail_write(inner: &Arc<Inner>, conn_id: u64, ep: &mut dyn Endpoint, a: &Active, why: RedisError) -> Pump {
    a.cmd.writing.store(false, Ordering::SeqCst);
    end_cmd(inner, &a.cmd, Outcome::Failed(why));
    lost(inner, conn_id, "a streamed argument failed part-way, so the connection was closed");
    ep.close();
    Pump::Failed
}

/// Hand what is queued to the connection, on the reactor.
fn flush(inner: &Arc<Inner>) {
    let (handle, conn_id) = {
        let st = inner.state.lock().unwrap();
        (st.handle.clone(), st.conn_id)
    };
    let Some(handle) = handle else {
        return;
    };
    let inner = Arc::clone(inner);
    handle.with_endpoint(move |ep| drain_writes(&inner, conn_id, ep, false));
}

/// A command's timer fired: end it if it is still unanswered. For the caller's
/// own sink the patience is for silence, not for the whole reply: if the sink
/// has heard something since, or the consumer has paused, the timer is set again
/// for what is left.
fn expire(inner: &Arc<Inner>, cmd: &Arc<Cmd>, qid: u64) {
    if cmd.streaming {
        if let Some(limit) = cmd.limit {
            let paused = cmd.flow.load(Ordering::SeqCst) != FLOW_RUNNING;
            let idle = Duration::from_nanos(now_nanos().saturating_sub(cmd.activity.load(Ordering::Relaxed)));
            if paused || idle < limit {
                let wait = if paused { limit } else { limit - idle };
                return arm_timer(inner, cmd, qid, wait);
            }
        }
    }
    // Not yet sent: take it out of the queue. Sent: the reply is still to come
    // and still takes its place in the queue, so the entry stays, and only its
    // sink goes, so that the reply is discarded as it arrives.
    {
        let mut st = inner.state.lock().unwrap();
        if let Some(pos) = st.waiting.iter().position(|w| w.qid == qid) {
            st.waiting.remove(pos);
        }
    }
    end_cmd(inner, cmd, Outcome::Failed(RedisError::Timeout));
    // Part of a streamed argument is on the wire and the rest will not follow:
    // the connection cannot be used again, so it is closed.
    if cmd.writing.swap(false, Ordering::SeqCst) {
        let (conn_id, handle) = {
            let st = inner.state.lock().unwrap();
            (st.conn_id, st.handle.clone())
        };
        lost(inner, conn_id, "a streamed argument stopped part-way, so the connection was closed");
        if let Some(h) = handle {
            h.close();
        }
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
                collector: Collector::new(&handler_inner.config.limits),
                completed: Vec::new(),
                target: Target::None,
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
        st.read_paused = false;
        st.handle = None;
        reset_writes(&mut st);
        st.failures += 1;
        st.retry_at = Some(
            Instant::now() + backoff(inner.config.backoff_initial, inner.config.backoff_max, st.failures),
        );
        st.last_error = Some(error.clone());
        std::mem::take(&mut st.waiting)
    };
    for w in waiting {
        end_cmd(inner, &w.cmd, Outcome::Failed(error.clone()));
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
            st.read_paused = false;
            st.handle = None;
            reset_writes(&mut st);
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
        if let Kind::User(cmd) = s.kind {
            end_cmd(inner, &cmd, Outcome::Failed(RedisError::ConnectionLost(reason.to_string())));
        }
    }
    let why = if was_ready {
        RedisError::ConnectionLost(reason.to_string())
    } else {
        RedisError::Connect(reason.to_string())
    };
    for w in waiting {
        end_cmd(inner, &w.cmd, Outcome::Failed(why.clone()));
    }
    if inner.sub.is_some() {
        if was_ready {
            pubsub::sub_lost(inner, &why);
        }
        pubsub::schedule_redial(inner);
    }
}

/// What answers the command at the head of the queue.
enum Answer {
    /// A reply the connection built itself.
    Value(Result<Value, RedisError>),
    /// A reply that went to the command's sink as it arrived.
    Streamed { skipped: bool },
}

/// The reactor-side half of a connection.
struct Conn {
    inner: Arc<Inner>,
    conn_id: u64,
    parser: RespParser,
    /// Assembles the one reply being read into a value, for the callbacks that
    /// take one. Reused for every reply.
    collector: Collector,
    /// What the replies of the last read came to, to be acted on once it has
    /// been fully read. Reused.
    completed: Vec<Completed>,
    /// Where the reply being read goes, until it is complete: it may take
    /// several reads.
    target: Target,
    tls: bool,
}

/// What one reply, as the parser delivered it, came to.
enum Completed {
    /// A reply the handshake or a stray one: built whole, for the connection's
    /// own use.
    Reply(Result<Value, RedisError>),
    /// The reply to the command at the head of the queue is over: its events have
    /// all gone to the command's sink (or been discarded, if it was abandoned).
    Done { skipped: bool },
    /// Out-of-band data, built whole.
    Push(Value),
    /// Out-of-band data that was too large to build: dropped.
    PushDropped,
}

/// Where the events of the reply being read go.
#[derive(Clone)]
enum Target {
    /// Between replies.
    None,
    /// Into the connection's own collector: a handshake reply, a push, a
    /// subscriber's message.
    Collect(ReplyKind),
    /// To the sink of the command at the head of the queue, or, if the command
    /// has ended (it timed out) and its sink is gone, nowhere: the reply is
    /// skipped as it arrives.
    Command(Arc<Cmd>),
}

/// Routes the parser's events: to the sink of the command the reply answers,
/// to the collector, for a push or the connection's own, or nowhere, for a reply
/// whose command has ended. A reply that is skipped costs no memory however
/// large it is.
struct Router<'a> {
    collector: &'a mut Collector,
    inner: &'a Inner,
    /// A subscriber past its handshake: everything it is sent is for its
    /// handler, whatever the kind.
    sub_ready: bool,
    /// How many replies to commands this read has completed so far, so which
    /// entry of the queue the next belongs to.
    head: usize,
    /// Where the reply in progress goes. It lives on the connection, not here:
    /// a reply may take several reads.
    target: &'a mut Target,
    /// A sink asked for a pause, and which command it was.
    paused: &'a mut Option<Arc<Cmd>>,
    out: &'a mut Vec<Completed>,
}

impl Router<'_> {
    /// Deliver an event to where the reply goes.
    fn event(&mut self, f: impl FnOnce(&mut dyn ReplySink) -> Flow) -> Flow {
        match &*self.target {
            Target::Collect(_) => f(&mut *self.collector),
            Target::Command(cmd) if !cmd.streaming => {
                // A callback that takes a value: its collector never pauses and
                // it is timed from issue to reply, so nothing more is tracked.
                let flow = match cmd.sink.lock().unwrap().as_mut() {
                    Some(sink) => f(sink.events()),
                    // The command ended (it timed out) while its reply was coming.
                    None => Flow::Skip,
                };
                run_deferred(self.inner, cmd);
                flow
            }
            Target::Command(cmd) => {
                if cmd.cancelled.load(Ordering::Relaxed) {
                    return Flow::Skip;
                }
                cmd.in_sink.store(true, Ordering::SeqCst);
                let flow = match cmd.sink.lock().unwrap().as_mut() {
                    Some(sink) => f(sink.events()),
                    None => {
                        cmd.in_sink.store(false, Ordering::SeqCst);
                        return Flow::Skip;
                    }
                };
                cmd.touch();
                let flow = cmd.settle(flow);
                cmd.in_sink.store(false, Ordering::SeqCst);
                run_deferred(self.inner, cmd);
                if flow == Flow::Pause {
                    *self.paused = Some(Arc::clone(cmd));
                }
                flow
            }
            _ => Flow::Skip,
        }
    }
}

impl ReplySink for Router<'_> {
    fn begin_reply(&mut self, kind: ReplyKind) {
        *self.target = match kind {
            ReplyKind::Push => Target::Collect(ReplyKind::Push),
            ReplyKind::Normal if self.sub_ready => Target::Collect(ReplyKind::Normal),
            ReplyKind::Normal => {
                let st = self.inner.state.lock().unwrap();
                match st.pending.get(self.head) {
                    // Even a command that has ended: its sink is gone, so the
                    // events find none and the reply is skipped as it arrives.
                    Some(Sent { kind: Kind::User(cmd), .. }) => Target::Command(Arc::clone(cmd)),
                    // A handshake reply, or one nobody asked for.
                    _ => Target::Collect(ReplyKind::Normal),
                }
            }
        };
        match &*self.target {
            Target::Collect(_) => self.collector.begin_reply(kind),
            Target::Command(cmd) => {
                if let Some(sink) = cmd.sink.lock().unwrap().as_mut() {
                    sink.events().begin_reply(kind);
                }
            }
            _ => {}
        }
    }

    fn scalar(&mut self, v: Scalar<'_>) -> Flow {
        self.event(|s| s.scalar(v))
    }

    fn error(&mut self, line: &str) -> Flow {
        self.event(|s| s.error(line))
    }

    fn begin_aggregate(&mut self, kind: AggKind, len: Option<usize>) -> Flow {
        self.event(|s| s.begin_aggregate(kind, len))
    }

    fn end_aggregate(&mut self) -> Flow {
        self.event(|s| s.end_aggregate())
    }

    fn begin_string(&mut self, kind: StrKind, len: Option<usize>) -> Flow {
        self.event(|s| s.begin_string(kind, len))
    }

    fn string_chunk(&mut self, data: &[u8]) -> Flow {
        self.event(|s| s.string_chunk(data))
    }

    fn end_string(&mut self) -> Flow {
        self.event(|s| s.end_string())
    }

    fn end_reply(&mut self, skipped: bool) {
        match std::mem::replace(&mut *self.target, Target::None) {
            Target::None => {}
            Target::Command(cmd) => {
                if let Some(sink) = cmd.sink.lock().unwrap().as_mut() {
                    sink.events().end_reply(skipped);
                }
                self.head += 1;
                self.out.push(Completed::Done { skipped });
            }
            Target::Collect(kind) => {
                let built = self.collector.take();
                if kind == ReplyKind::Normal {
                    self.head += 1;
                }
                self.out.push(match (kind, built) {
                    (ReplyKind::Normal, Ok(v)) => Completed::Reply(Ok(v)),
                    (ReplyKind::Normal, Err(TooLarge(why))) => Completed::Reply(Err(RedisError::Protocol(why))),
                    (ReplyKind::Push, Ok(v)) => Completed::Push(v),
                    (ReplyKind::Push, Err(_)) => Completed::PushDropped,
                });
            }
        }
    }
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
                    kind: Kind::Internal(*step),
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
        {
            let mut st = inner.state.lock().unwrap();
            if st.conn_id != self.conn_id {
                return;
            }
            st.phase = Phase::Ready;
            st.failures = 0;
            st.retry_at = None;
            st.last_error = None;
            while let Some(w) = st.waiting.pop_front() {
                match w.bytes {
                    Encoded::Plain(bytes) => st.wq.push_plain(bytes),
                    Encoded::Streamed(parts) => st.wq.push_streamed(Streamed {
                        cmd: Arc::clone(&w.cmd),
                        parts,
                    }),
                }
                st.pending.push_back(Sent {
                    kind: Kind::User(w.cmd),
                    held: w.held,
                });
            }
        };
        drain_writes(inner, self.conn_id, endpoint, false);
    }

    /// The handshake failed for good: fail what waited and drop the connection.
    fn handshake_failed(&mut self, endpoint: &mut dyn Endpoint, error: RedisError) {
        connect_failed(&self.inner, self.conn_id, error);
        endpoint.close();
    }

    /// What the last read came to.
    fn on_completed(&mut self, endpoint: &mut dyn Endpoint, completed: Completed) {
        let inner = Arc::clone(&self.inner);
        // A subscriber's connection, once past its handshake, gets messages and
        // acknowledgements, not replies.
        let sub_ready = inner.sub.is_some() && inner.state.lock().unwrap().phase == Phase::Ready;
        match completed {
            Completed::PushDropped => {}
            Completed::Push(value) | Completed::Reply(Ok(value)) if sub_ready => pubsub::sub_reply(&inner, value),
            Completed::Reply(Err(_)) if sub_ready => {}
            Completed::Push(Value::Push(mut items)) => {
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
            }
            Completed::Push(_) => {}
            Completed::Reply(reply) => self.on_reply(endpoint, Answer::Value(reply)),
            Completed::Done { skipped } => self.on_reply(endpoint, Answer::Streamed { skipped }),
        }
    }

    /// The reply to the command at the head of the queue.
    fn on_reply(&mut self, endpoint: &mut dyn Endpoint, answer: Answer) {
        let inner = Arc::clone(&self.inner);
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
        match (sent.kind, answer) {
            // The command's sink has heard the whole reply, or none of it if the
            // command had ended: it is told how it went, if it is still there.
            (Kind::User(cmd), Answer::Streamed { skipped }) => {
                cmd.cancel_timer();
                if let Some(sink) = cmd.take_sink() {
                    sink.finish(Outcome::Complete { skipped });
                }
            }
            (Kind::Internal(step), Answer::Value(Ok(value))) => self.on_handshake_reply(endpoint, step, value),
            (Kind::Internal(_), Answer::Value(Err(e))) => return self.handshake_failed(endpoint, e),
            // The reply was read for something other than the command that was
            // waiting for it: the stream has lost step with us.
            (Kind::User(cmd), Answer::Value(_)) => {
                end_cmd(&inner, &cmd, Outcome::Failed(RedisError::Protocol("a reply did not match its command".into())));
            }
            (Kind::Internal(_), Answer::Streamed { .. }) => {}
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
            kind: Kind::Internal(step),
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
        let sub_ready = {
            let mut st = self.inner.state.lock().unwrap();
            if st.read_paused {
                // The consumer of a streamed reply holds the connection: what is
                // in the ring stays there until it resumes.
                return;
            }
            if st.conn_id == self.conn_id {
                st.last_rx = Instant::now();
            }
            self.inner.sub.is_some() && st.phase == Phase::Ready
        };
        let mut completed = std::mem::take(&mut self.completed);
        let mut bad = None;
        loop {
            let mut paused = None;
            let consumed = {
                // Read the ring where it lies: a payload is handed on as it arrives
                // and the parser keeps none of it.
                let mut router = Router {
                    collector: &mut self.collector,
                    inner: &self.inner,
                    sub_ready,
                    head: 0,
                    target: &mut self.target,
                    paused: &mut paused,
                    out: &mut completed,
                };
                let (first, second) = buf.readable_spans();
                let mut consumed = 0;
                for span in [first, second] {
                    if span.is_empty() {
                        continue;
                    }
                    let mut data = span;
                    match self.parser.feed(&mut data, &mut router) {
                        Ok(Feed::Consumed) => consumed += span.len() - data.len(),
                        Ok(Feed::Paused) => {
                            consumed += span.len() - data.len();
                            break;
                        }
                        Err(e) => {
                            // The stream cannot be trusted: nothing more of it is read.
                            consumed += span.len();
                            bad = Some(e);
                            break;
                        }
                    }
                }
                consumed
            };
            buf.advance(consumed);
            if bad.is_some() {
                buf.advance(buf.len());
            }
            for c in completed.drain(..) {
                self.on_completed(endpoint, c);
            }
            let Some(cmd) = paused else {
                break;
            };
            // Stop reading, unless the consumer has already resumed or cancelled.
            if cmd
                .flow
                .compare_exchange(FLOW_PAUSE_REQUESTED, FLOW_PAUSED, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                self.inner.state.lock().unwrap().read_paused = true;
                endpoint.pause_read();
                break;
            }
        }
        self.completed = completed;
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

    /// A sink that wants nothing, for a command cell.
    struct Nothing;

    impl ReplySink for Nothing {
        fn scalar(&mut self, _v: Scalar<'_>) -> Flow {
            Flow::Continue
        }
        fn error(&mut self, _line: &str) -> Flow {
            Flow::Continue
        }
        fn begin_aggregate(&mut self, _kind: AggKind, _len: Option<usize>) -> Flow {
            Flow::Continue
        }
        fn end_aggregate(&mut self) -> Flow {
            Flow::Continue
        }
        fn begin_string(&mut self, _kind: StrKind, _len: Option<usize>) -> Flow {
            Flow::Continue
        }
        fn string_chunk(&mut self, _data: &[u8]) -> Flow {
            Flow::Continue
        }
        fn end_string(&mut self) -> Flow {
            Flow::Continue
        }
    }

    fn cell() -> (Arc<Cmd>, StreamHandle) {
        let cmd = Cmd::new(Box::new(Streaming { sink: Nothing }), true, None);
        let handle = StreamHandle::command(Arc::clone(&cmd), Weak::new());
        (cmd, handle)
    }

    #[test]
    fn a_resume_during_the_call_that_pauses_cancels_that_pause() {
        let (cmd, handle) = cell();
        // The sink is running; the consumer, on another thread, resumes before the
        // sink has returned the Pause it is about to.
        cmd.in_sink.store(true, Ordering::SeqCst);
        handle.resume();
        assert_eq!(cmd.settle(Flow::Pause), Flow::Continue, "there is no pause to take effect");
        assert_eq!(cmd.flow.load(Ordering::SeqCst), FLOW_RUNNING, "and nothing is left over");
        cmd.in_sink.store(false, Ordering::SeqCst);
    }

    #[test]
    fn a_resume_when_nothing_is_paused_does_not_cancel_a_later_pause() {
        let (cmd, handle) = cell();
        // Not in the sink, not paused: nothing to resume, and nothing kept.
        handle.resume();
        handle.resume();
        cmd.in_sink.store(true, Ordering::SeqCst);
        assert_eq!(cmd.settle(Flow::Pause), Flow::Pause, "a stray resume did not use up this pause");
        assert_eq!(cmd.flow.load(Ordering::SeqCst), FLOW_PAUSE_REQUESTED);
        // A resume during the call that did not pause leaves nothing for the next.
        let (cmd, handle) = cell();
        cmd.in_sink.store(true, Ordering::SeqCst);
        handle.resume();
        assert_eq!(cmd.settle(Flow::Continue), Flow::Continue);
        assert_eq!(cmd.flow.load(Ordering::SeqCst), FLOW_RUNNING, "the permit went with the call");
        assert_eq!(cmd.settle(Flow::Pause), Flow::Pause);
    }

    #[test]
    fn a_resume_between_the_pause_and_its_taking_effect_cancels_it_and_one_after_releases_it() {
        let (cmd, handle) = cell();
        assert_eq!(cmd.settle(Flow::Pause), Flow::Pause);
        handle.resume(); // before the connection has stopped reading
        assert_eq!(cmd.flow.load(Ordering::SeqCst), FLOW_RUNNING);
        assert!(
            cmd.flow
                .compare_exchange(FLOW_PAUSE_REQUESTED, FLOW_PAUSED, Ordering::SeqCst, Ordering::SeqCst)
                .is_err(),
            "so the connection does not stop"
        );
        // And once it has stopped, a resume releases it.
        assert_eq!(cmd.settle(Flow::Pause), Flow::Pause);
        cmd.flow.store(FLOW_PAUSED, Ordering::SeqCst);
        handle.resume();
        assert_eq!(cmd.flow.load(Ordering::SeqCst), FLOW_RUNNING);
    }

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
    fn a_command_with_a_streamed_argument_is_written_in_parts_that_add_up_to_the_command() {
        let arg = StreamArg::from_fn(5, || Err(RedisError::Closed));
        // SET k <5 streamed bytes> EX 10
        let command = Command::new("SET").arg("k").arg_stream(arg).arg("EX").arg("10");
        assert!(command.has_streams() && command.is_streamed(2) && !command.is_streamed(1));
        let Encoded::Streamed(parts) = command.encoded() else {
            panic!("streamed");
        };
        let shape: Vec<String> = parts
            .iter()
            .map(|p| match p {
                Part::Bytes(b, 0) => format!("{:?}", String::from_utf8_lossy(b)),
                Part::Bytes(..) => "bytes from an offset".into(),
                Part::Stream { len, .. } => format!("<{len} streamed>"),
            })
            .collect();
        assert_eq!(
            shape,
            vec![
                r#""*5\r\n$3\r\nSET\r\n$1\r\nk\r\n$5\r\n""#.to_string(),
                "<5 streamed>".to_string(),
                r#""\r\n$2\r\nEX\r\n$2\r\n10\r\n""#.to_string(),
            ],
            "the CRLF that ends the streamed argument leads what follows it"
        );
        // One with no streamed argument is one buffer.
        assert!(matches!(Command::new("GET").arg("k").encoded(), Encoded::Plain(_)));
        // And what is submitted after a streamed command waits behind it, in order.
        let mut q = WriteQ::default();
        q.push_plain(b"one".to_vec());
        q.push_plain(b"two".to_vec());
        let (cmd, _) = (Cmd::new(Box::new(Streaming { sink: Nothing }), true, None), ());
        q.push_streamed(Streamed { cmd, parts: VecDeque::new() });
        q.push_plain(b"three".to_vec());
        q.push_plain(b"four".to_vec());
        assert_eq!(q.head, b"onetwo");
        assert_eq!(q.rest.len(), 1);
        assert_eq!(q.rest[0].1, b"threefour", "behind the stream, not before it");
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
