// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! [`RedisCluster`]: a client for Redis Cluster and Valkey Cluster.
//!
//! The client learns the cluster's layout from `CLUSTER SHARDS` (or, for a
//! server without it, `CLUSTER SLOTS`), keeps one pipelined
//! [`RedisClient`](crate::RedisClient) connection to each master, and sends
//! every command to the master that owns the slot its key hashes to. Each
//! connection has the authentication, `HELLO`, TLS and timeouts the template
//! [`RedisConfig`] gives it, and reconnects with backoff by itself.
//!
//! # Routing
//!
//! A command's slot comes from its keys (see [`key_indexes`](crate::key_indexes)):
//! with one key it is that key's slot, with several they must share a slot or
//! the command fails at once with a `CROSSSLOT` error, without touching the
//! network. Use `{hash tags}` to put related keys in one slot. A command with
//! no key goes to any master. A key the table does not know can be named with
//! [`command_for_key`](RedisCluster::command_for_key).
//!
//! # Redirections and failure
//!
//! `MOVED` means a slot has a new owner: the client takes the new owner,
//! refreshes its map, and sends the command again. `ASK` means the slot is
//! being migrated and this one command belongs on the other node: it is sent
//! there, once, right behind an `ASKING`. Each such hop spends one of
//! [`max_redirects`](ClusterConfig::max_redirects). A node that cannot be
//! reached makes the client refresh its map and, since the command was never
//! sent, try again where the map now says it lives. A command that was sent
//! when its connection failed is not sent again. `CLUSTERDOWN` and `TRYAGAIN`
//! mean the command did not run, because the slot has no master for the moment
//! or is being migrated: the map is fetched again and the command tried once
//! more, as many times as it has redirections left, and then the error is the
//! caller's. (`WAIT` is never sent again: see
//! [`wait_replicas`](RedisCluster::wait_replicas).)
//!
//! Refreshes are one at a time and at most one in
//! [`min_refresh_interval`](ClusterConfig::min_refresh_interval), however many
//! commands ask for one. A node that is no longer a master is let go of
//! gracefully: commands already sent to it are answered, and one that arrives
//! as it goes, never having been sent, is sent again to the owner.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hopf_core::ReactorHandle;

use crate::client::{Callback, Command, Deadline, RedisClient, Reply};
use crate::commands::{
    aof_counts, is_connection_scoped, server_timeout_ms, wait_command, wait_count, wait_deadline, waitaof_command,
};
use crate::config::RedisConfig;
use crate::error::RedisError;
use crate::keys::{command_slot, key_slot, SLOTS};
use crate::pubsub::is_subscription_command;
use crate::resp::{ServerError, Value};
use crate::topology::{parse_redirect, parse_shards, parse_slots, NodeAddr, SlotRange};

/// Settings for a [`RedisCluster`].
#[derive(Clone)]
pub struct ClusterConfig {
    seeds: Vec<NodeAddr>,
    node: RedisConfig,
    tls_server_name: Option<String>,
    max_redirects: u32,
    min_refresh_interval: Duration,
}

impl ClusterConfig {
    /// A cluster reachable through any of `seeds` (`(host, port)`): the client
    /// asks them for the layout, and needs only one to answer.
    pub fn new<H: Into<String>>(seeds: impl IntoIterator<Item = (H, u16)>) -> Self {
        Self {
            seeds: seeds
                .into_iter()
                .map(|(host, port)| NodeAddr {
                    host: host.into(),
                    port,
                })
                .collect(),
            node: RedisConfig::new("", 0),
            tls_server_name: None,
            max_redirects: 5,
            min_refresh_interval: Duration::from_millis(500),
        }
    }

    /// Change how every connection to a node is made: its password and user,
    /// TLS connector, protocol, timeouts and the rest of [`RedisConfig`]. Its
    /// host and port are ignored (each node's own are used), and so is
    /// `database`, which a cluster does not have.
    pub fn node_config(mut self, f: impl FnOnce(RedisConfig) -> RedisConfig) -> Self {
        self.node = f(self.node);
        self
    }

    /// The name to verify a node's TLS certificate against, instead of the
    /// node's own host. Only matters when the node config has TLS.
    pub fn tls_server_name(mut self, name: impl Into<String>) -> Self {
        self.tls_server_name = Some(name.into());
        self
    }

    /// How many redirections and retries one command may spend before it fails
    /// with the error that sent it on. Default 5.
    pub fn max_redirects(mut self, n: u32) -> Self {
        self.max_redirects = n;
        self
    }

    /// The least time between two refreshes of the cluster's layout.
    /// Default 500 ms.
    pub fn min_refresh_interval(mut self, interval: Duration) -> Self {
        self.min_refresh_interval = interval;
        self
    }

    /// The configuration for the connection to `addr`.
    fn for_node(&self, addr: &NodeAddr) -> RedisConfig {
        let mut c = self.node.clone();
        c.host = addr.host.clone();
        c.port = addr.port;
        c.addr = None;
        c.database = 0;
        if let Some((connector, _)) = &self.node.tls {
            let name = self.tls_server_name.clone().unwrap_or_else(|| addr.host.clone());
            c.tls = Some((connector.clone(), name));
        }
        c
    }
}

/// What a command waits for or is sent to.
enum Target {
    /// The owner of its slot, or any master for a keyless command.
    Owner,
    /// This node, because `MOVED` named it.
    Node(NodeAddr),
    /// This node, behind an `ASKING`.
    Asking(NodeAddr),
}

struct Job {
    command: Command,
    /// The slot of the command's keys, if it has any.
    slot: Option<u16>,
    target: Target,
    /// Redirections and retries left.
    budget: u32,
    callback: Callback,
    /// What a `WAIT` for this command's slot is bound to while it is unanswered.
    track: Option<Arc<Track>>,
    /// How long each try may go unanswered.
    deadline: Deadline,
}

/// Work that cannot go anywhere until the layout is known.
enum Parked {
    Command(Job),
    Tx(TxJob),
}

impl Parked {
    /// Fail it with `error`.
    fn fail(self, inner: &Inner, error: RedisError) {
        match self {
            Parked::Command(j) => finish(inner, j.callback, Err(error)),
            Parked::Tx(j) => finish_tx(inner, j.callback, Err(error)),
        }
    }
}

#[derive(Default)]
struct Refresh {
    running: bool,
    last_start: Option<Instant>,
    timer_pending: bool,
}

struct State {
    /// Who serves each slot; `None` until the layout is known.
    slots: Vec<Option<Arc<NodeAddr>>>,
    /// A connection to each node in use.
    pool: HashMap<NodeAddr, RedisClient>,
    refresh: Refresh,
    /// Work waiting for a layout, and the error to give it if there is none to
    /// be had.
    parked: Vec<(Parked, Option<RedisError>)>,
    /// Turns keyless commands over the masters.
    next_keyless: usize,
    /// The last command submitted for each slot, until it is answered.
    last: HashMap<u16, Arc<Track>>,
}

struct Inner {
    reactor: ReactorHandle,
    config: ClusterConfig,
    state: Mutex<State>,
    closed: AtomicBool,
    refreshes: AtomicUsize,
    /// Numbers each sending of a `WAIT`.
    wait_sends: AtomicU64,
}

/// A Redis Cluster client. Cheap to clone; clones share the connections. See
/// the documentation of this module.
#[derive(Clone)]
pub struct RedisCluster {
    inner: Arc<Inner>,
}

impl RedisCluster {
    /// A client bound to `reactor`. It asks the seeds for the cluster's layout
    /// at once; its callbacks run on `reactor`.
    pub fn connect(reactor: &ReactorHandle, config: ClusterConfig) -> Self {
        let inner = Arc::new(Inner {
            reactor: reactor.clone(),
            config,
            state: Mutex::new(State {
                slots: vec![None; SLOTS],
                pool: HashMap::new(),
                refresh: Refresh::default(),
                parked: Vec::new(),
                next_keyless: 0,
                last: HashMap::new(),
            }),
            closed: AtomicBool::new(false),
            refreshes: AtomicUsize::new(0),
            wait_sends: AtomicU64::new(0),
        });
        request_refresh(&inner);
        Self { inner }
    }

    /// Send `command` to the master that owns its slot, and call `callback`
    /// with the reply. Returns at once. See the documentation of this
    /// module for how redirections, failures and commands with several keys are
    /// handled.
    pub fn send(&self, command: &Command, callback: impl FnOnce(Reply) + Send + 'static) {
        self.submit(command, None, Deadline::Default, Box::new(callback));
    }

    /// [`send`](Self::send) with a deadline of its own instead of the node
    /// connections' command timeout: [`Deadline::After`] for a time,
    /// [`Deadline::Never`] for a command that blocks for as long as the server
    /// likes. The deadline applies to each try: a command that is redirected
    /// (`MOVED`, `ASK`) or sent again after the layout changed gets it afresh.
    /// `WAIT` and `WAITAOF` keep the deadline [`wait_replicas`](Self::wait_replicas)
    /// gives them.
    pub fn send_with_deadline(&self, command: &Command, deadline: Deadline, callback: impl FnOnce(Reply) + Send + 'static) {
        self.submit(command, None, deadline, Box::new(callback));
    }

    /// [`send`](Self::send) for the command made of `words`.
    pub fn command(&self, words: &[&[u8]], callback: impl FnOnce(Reply) + Send + 'static) {
        let command = Command::new(words.first().copied().unwrap_or(b"")).args(words.iter().skip(1));
        self.submit(&command, None, Deadline::Default, Box::new(callback));
    }

    /// [`send`](Self::send) to the master that owns `routing_key`'s slot,
    /// whatever the command's own keys are: for a command the key table does
    /// not know, or a keyless one that has to run on a particular node. If the
    /// command names keys of its own they must be in that slot, or it fails
    /// with `CROSSSLOT`. An ordinary command follows `MOVED` and `ASK`.
    ///
    /// `WAIT` and `WAITAOF` mean something only on the connection that carried
    /// the writes they ask about, so they are never redirected or sent again,
    /// and one sent here behaves as [`wait_replicas`](Self::wait_replicas)
    /// does: it is bound to the last command submitted for the key's slot.
    pub fn command_for_key(&self, routing_key: impl AsRef<[u8]>, command: &Command, callback: impl FnOnce(Reply) + Send + 'static) {
        self.submit(command, Some(key_slot(routing_key.as_ref())), Deadline::Default, Box::new(callback));
    }

    fn submit(&self, command: &Command, routed: Option<u16>, deadline: Deadline, callback: Callback) {
        let inner = &self.inner;
        if inner.closed.load(Ordering::SeqCst) {
            return finish(inner, callback, Err(RedisError::Closed));
        }
        if command.words().first().is_some_and(|w| is_subscription_command(w)) {
            return finish(
                inner,
                callback,
                Err(RedisError::Unexpected(
                    "subscriptions need a RedisSubscriber, not a cluster command connection".into(),
                )),
            );
        }
        if command.words().first().is_some_and(|w| is_connection_scoped(w)) {
            return match routed {
                Some(slot) => {
                    let deadline = wait_deadline(server_timeout_ms(command.words()));
                    self.bound(slot, command.clone(), deadline, callback)
                }
                None => finish(
                    inner,
                    callback,
                    Err(RedisError::Unexpected(
                        "WAIT and WAITAOF act on the connection that carried the writes: use wait_replicas or wait_aof, \
                         or command_for_key with the key of the write"
                            .into(),
                    )),
                ),
            };
        }
        let slot = match (command_slot(command.words()), routed) {
            (Err(_), _) => return finish(inner, callback, Err(crossslot())),
            (Ok(own), Some(r)) if own.is_some_and(|s| s != r) => return finish(inner, callback, Err(crossslot())),
            (Ok(own), r) => r.or(own),
        };
        let track = slot.map(|s| register(inner, s));
        let callback = match &track {
            Some(t) => on_completion(inner, t, callback),
            None => callback,
        };
        dispatch(
            inner,
            Job {
                command: command.clone(),
                slot,
                target: Target::Owner,
                budget: inner.config.max_redirects,
                callback,
                track,
                deadline,
            },
            true,
        );
    }

    /// `WAIT num_replicas timeout_ms`, for the writes just made to the slot of
    /// `slot_key`: it blocks until `num_replicas` replicas of that slot's
    /// master have acknowledged every write made on the connection to it, or
    /// `timeout_ms` passes, and calls back with how many did. Fewer than asked
    /// for is `Ok(n)`, not an error.
    ///
    /// A replica count means something only on the connection that carried the
    /// write, so the `WAIT` is bound to the last command submitted for the
    /// slot. If that command is still unanswered, the `WAIT` goes on the
    /// connection it was sent on, right behind it; if it is redirected
    /// (`MOVED`, `ASK`), the `WAIT` goes with it, and the first node's answer
    /// to it is thrown away. If nothing is in flight for the slot it goes to
    /// the connection that serves the slot now. It is never sent again on
    /// another connection: if the connection is lost, or the node leaves the
    /// layout, before the reply, the callback gets the error; so does
    /// `CLUSTERDOWN`. `slot_key` is a key of the write, or a hash tag shared
    /// with it.
    ///
    /// The server holds the reply for up to `timeout_ms`, so the client's
    /// deadline is its command timeout plus `timeout_ms`; with `timeout_ms` 0
    /// the server waits for ever and there is no client deadline, so pass a
    /// positive value. A cluster has no connection-wide `MULTI`:
    /// [`transaction`](Self::transaction) is one batch, so `WAIT` cannot fall
    /// inside it.
    pub fn wait_replicas(
        &self,
        slot_key: impl AsRef<[u8]>,
        num_replicas: u32,
        timeout_ms: u64,
        callback: impl FnOnce(Result<u32, RedisError>) + Send + 'static,
    ) {
        let slot = key_slot(slot_key.as_ref());
        let command = wait_command(num_replicas, timeout_ms);
        self.bound(slot, command, wait_deadline(timeout_ms), Box::new(move |r| callback(r.and_then(wait_count))));
    }

    /// `WAITAOF num_local num_replicas timeout_ms`, bound to the slot of
    /// `slot_key` exactly as [`wait_replicas`](Self::wait_replicas) is. The
    /// callback gets `(local, replicas)`: how many of the master's own append-only
    /// file and its replicas' files have the writes fsynced.
    pub fn wait_aof(
        &self,
        slot_key: impl AsRef<[u8]>,
        num_local: u32,
        num_replicas: u32,
        timeout_ms: u64,
        callback: impl FnOnce(Result<(u32, u32), RedisError>) + Send + 'static,
    ) {
        let slot = key_slot(slot_key.as_ref());
        let command = waitaof_command(num_local, num_replicas, timeout_ms);
        self.bound(slot, command, wait_deadline(timeout_ms), Box::new(move |r| callback(r.and_then(aof_counts))));
    }

    /// Send a connection-scoped `command` for `slot`: behind the command in
    /// flight for it, on its connection, or to the slot's owner if there is
    /// none.
    fn bound(&self, slot: u16, command: Command, deadline: Deadline, callback: Callback) {
        let inner = &self.inner;
        if inner.closed.load(Ordering::SeqCst) {
            return finish(inner, callback, Err(RedisError::Closed));
        }
        let track = inner.state.lock().unwrap().last.get(&slot).cloned();
        if let Some(track) = track {
            let mut ts = track.st.lock().unwrap();
            if !ts.finished {
                let wait = Arc::new(Wait {
                    command,
                    deadline,
                    sent: AtomicU64::new(0),
                    callback: Mutex::new(Some(callback)),
                });
                ts.waits.push(Arc::clone(&wait));
                if let Some(client) = ts.client.clone() {
                    send_wait(inner, &track, &wait, &client);
                }
                return;
            }
        }
        // Nothing in flight for the slot: the connection that serves it now.
        match route(inner, &Target::Owner, Some(slot)) {
            None => finish(inner, callback, Err(unserved())),
            Some((client, _, _)) => {
                let inner2 = Arc::clone(inner);
                client.send_with_deadline(&command, deadline, move |reply| callback(unsent_closed(&inner2, reply)));
            }
        }
    }

    /// Run `commands` as one transaction on the master that owns their slot:
    /// `MULTI`, the commands and `EXEC` written together. Their keys must share
    /// a slot (use hash tags), or it fails with `CROSSSLOT` without touching the
    /// network. See [`RedisClient::transaction`] for the results.
    pub fn transaction(
        &self,
        commands: Vec<Command>,
        callback: impl FnOnce(Result<Option<Vec<Value>>, RedisError>) + Send + 'static,
    ) {
        let inner = &self.inner;
        let mut slot: Option<u16> = None;
        for c in &commands {
            match command_slot(c.words()) {
                Err(_) => return finish_tx(inner, Box::new(callback), Err(crossslot())),
                Ok(None) => {}
                Ok(Some(s)) => match slot {
                    Some(prev) if prev != s => return finish_tx(inner, Box::new(callback), Err(crossslot())),
                    _ => slot = Some(s),
                },
            }
        }
        if inner.closed.load(Ordering::SeqCst) {
            return finish_tx(inner, Box::new(callback), Err(RedisError::Closed));
        }
        let track = slot.map(|s| register(inner, s));
        let callback: TxCallback = match &track {
            Some(t) => {
                let (inner2, track2) = (Arc::clone(inner), Arc::clone(t));
                Box::new(move |result| {
                    complete(&inner2, &track2, result.as_ref().err());
                    callback(result)
                })
            }
            None => Box::new(callback),
        };
        dispatch_tx(
            inner,
            TxJob {
                commands,
                slot,
                target: Target::Owner,
                budget: inner.config.max_redirects,
                callback,
                track,
            },
            true,
        );
    }

    /// The slot `key` hashes to.
    pub fn slot_of(&self, key: impl AsRef<[u8]>) -> u16 {
        key_slot(key.as_ref())
    }

    /// The master that serves `slot`, if the layout is known.
    pub fn owner_of(&self, slot: u16) -> Option<(String, u16)> {
        let st = self.inner.state.lock().unwrap();
        st.slots.get(slot as usize).and_then(Option::as_ref).map(|a| (a.host.clone(), a.port))
    }

    /// The masters in the current layout.
    pub fn masters(&self) -> Vec<(String, u16)> {
        let st = self.inner.state.lock().unwrap();
        let mut seen: Vec<(String, u16)> = Vec::new();
        for a in st.slots.iter().flatten() {
            let m = (a.host.clone(), a.port);
            if !seen.contains(&m) {
                seen.push(m);
            }
        }
        seen
    }

    /// Whether the layout is known.
    pub fn is_ready(&self) -> bool {
        self.inner.state.lock().unwrap().slots.iter().any(Option::is_some)
    }

    /// How many times the layout has been fetched, for diagnostics and tests.
    pub fn refresh_count(&self) -> usize {
        self.inner.refreshes.load(Ordering::SeqCst)
    }

    /// Ask for the layout again, as soon as the minimum interval allows.
    pub fn refresh(&self) {
        request_refresh(&self.inner);
    }

    /// Close every connection and fail what is waiting with
    /// [`RedisError::Closed`]. Later commands fail the same way.
    pub fn close(&self) {
        let inner = &self.inner;
        inner.closed.store(true, Ordering::SeqCst);
        let (pool, parked) = {
            let mut st = inner.state.lock().unwrap();
            (std::mem::take(&mut st.pool), std::mem::take(&mut st.parked))
        };
        for (_, c) in pool {
            c.close();
        }
        for (work, _) in parked {
            work.fail(inner, RedisError::Closed);
        }
    }
}

fn crossslot() -> RedisError {
    RedisError::Server(ServerError {
        code: "CROSSSLOT".into(),
        message: "Keys in request don't hash to the same slot".into(),
    })
}

/// Run `callback` on the reactor, never inline.
fn finish(inner: &Inner, callback: Callback, reply: Reply) {
    inner.reactor.execute(Box::new(move || callback(reply)));
}

type TxCallback = Box<dyn FnOnce(Result<Option<Vec<Value>>, RedisError>) + Send>;

fn finish_tx(inner: &Inner, callback: TxCallback, result: Result<Option<Vec<Value>>, RedisError>) {
    inner.reactor.execute(Box::new(move || callback(result)));
}

/// The connection to `addr`, made if there is none.
fn client_for(inner: &Arc<Inner>, st: &mut State, addr: &NodeAddr) -> RedisClient {
    st.pool
        .entry(addr.clone())
        .or_insert_with(|| {
            let client = RedisClient::connect(&inner.reactor, inner.config.for_node(addr));
            // A node the health check gave up on may have been replaced by a
            // failover; whether or not any command was waiting to say so, look
            // at the layout again.
            let weak = Arc::downgrade(inner);
            client.on_unresponsive(move || {
                if let Some(inner) = weak.upgrade() {
                    request_refresh(&inner);
                }
            });
            client
        })
        .clone()
}

/// Where a job goes, or `None` if the layout is not known yet.
fn route(inner: &Arc<Inner>, target: &Target, slot: Option<u16>) -> Option<(RedisClient, NodeAddr, bool)> {
    let mut st = inner.state.lock().unwrap();
    let (addr, asking) = match target {
        Target::Node(a) => (a.clone(), false),
        Target::Asking(a) => (a.clone(), true),
        Target::Owner => match slot {
            Some(s) => ((**st.slots[s as usize].as_ref()?).clone(), false),
            None => {
                // No key: any master, in turn.
                let mut masters: Vec<Arc<NodeAddr>> = Vec::new();
                for a in st.slots.iter().flatten() {
                    if !masters.iter().any(|m| **m == **a) {
                        masters.push(Arc::clone(a));
                    }
                }
                if masters.is_empty() {
                    return None;
                }
                st.next_keyless = st.next_keyless.wrapping_add(1);
                ((*masters[st.next_keyless % masters.len()]).clone(), false)
            }
        },
    };
    let client = client_for(inner, &mut st, &addr);
    Some((client, addr, asking))
}

/// Park `work` until a layout is known, and ask for one.
fn park(inner: &Arc<Inner>, work: Parked, why: Option<RedisError>) {
    inner.state.lock().unwrap().parked.push((work, why));
    request_refresh(inner);
}

/// The error for a slot nobody serves.
fn unserved() -> RedisError {
    RedisError::Server(ServerError {
        code: "CLUSTERDOWN".into(),
        message: "Hash slot not served".into(),
    })
}

/// Send `job` where it belongs. `fresh` is whether this is its first try since
/// the layout was last fetched: if its node is unknown, a fresh job waits for a
/// layout, and one that has had its layout fails, since fetching it again would
/// only find the slot unserved again.
fn dispatch(inner: &Arc<Inner>, mut job: Job, fresh: bool) {
    // A `WAIT` bound to this command must not be answered by where it was
    // before; it is sent again behind the command wherever it goes now.
    if let Some(t) = &job.track {
        detach(t);
    }
    let Some((client, addr, asking)) = route(inner, &job.target, job.slot) else {
        return if fresh {
            park(inner, Parked::Command(job), None)
        } else if job.budget > 0 {
            // The layout just fetched has no master for the slot: a failover
            // is probably under way. Wait for the next layout.
            job.budget -= 1;
            park(inner, Parked::Command(job), Some(unserved()))
        } else {
            finish(inner, job.callback, Err(unserved()))
        };
    };
    let sent = job.command.clone();
    let deadline = job.deadline;
    let track = job.track.clone();
    let inner2 = Arc::clone(inner);
    let reply = move |reply: Reply| on_reply(&inner2, job, addr, reply);
    if asking {
        // ASKING applies to the next command on the connection and no other, so
        // the two go in one batch with nothing between them.
        client.send_batch_with_deadline(
            vec![(Command::new("ASKING"), Box::new(|_: Reply| {})), (sent, Box::new(reply))],
            deadline,
        );
    } else {
        client.send_with_deadline(&sent, deadline, reply);
    }
    if let Some(t) = track {
        attach(inner, &t, &client);
    }
}

/// A node answered, or failed to.
fn on_reply(inner: &Arc<Inner>, mut job: Job, from: NodeAddr, reply: Reply) {
    let error = match reply {
        Ok(v) => return (job.callback)(Ok(v)),
        Err(e) => e,
    };
    match &error {
        RedisError::Server(e) if (e.code == "MOVED" || e.code == "ASK") && job.budget > 0 => {
            if let Some((slot, node)) = parse_redirect(&e.message) {
                job.budget -= 1;
                if e.code == "MOVED" {
                    // The slot has a new owner for good: remember it, and
                    // refresh the rest of the map.
                    inner.state.lock().unwrap().slots[slot as usize] = Some(Arc::new(node.clone()));
                    request_refresh(inner);
                    job.target = Target::Node(node);
                } else {
                    job.target = Target::Asking(node);
                }
                return dispatch(inner, job, true);
            }
        }
        // Nothing ran: the cluster, or this slot of it, is between masters (a
        // failover, say). Look at the layout again, and try then.
        RedisError::Server(e) if (e.code == "CLUSTERDOWN" || e.code == "TRYAGAIN") && job.budget > 0 => {
            job.budget -= 1;
            job.target = Target::Owner;
            return park(inner, Parked::Command(job), Some(error));
        }
        RedisError::Server(e) if e.code == "CLUSTERDOWN" => request_refresh(inner),
        // Nothing was sent: the node is unreachable. Find out where the slot
        // lives now, and try there.
        RedisError::Connect(_) if job.budget > 0 => {
            job.budget -= 1;
            job.target = Target::Owner;
            forget_node(inner, &from);
            return park(inner, Parked::Command(job), Some(error));
        }
        // Sent, and the connection went: not repeated, but the layout has
        // probably changed. The same goes for a connection closed because its
        // node stopped answering, whether or not a command was waiting (see
        // `client_for`).
        RedisError::ConnectionLost(_) => request_refresh(inner),
        // A command that merely timed out does not ask for a new layout: a slow
        // node is not a moved one, and a refresh on every timeout would turn a
        // slow server into a storm of `CLUSTER SHARDS`. A node that has really
        // gone quiet is found by the connection's health check, which closes
        // it and asks for the layout itself.
        RedisError::Timeout => {}
        // The node's client was let go of while this command was on its way to
        // it, so the command was not sent: to the owner as the layout now has it.
        RedisError::Closed if job.budget > 0 && !inner.closed.load(Ordering::SeqCst) => {
            job.budget -= 1;
            job.target = Target::Owner;
            return dispatch(inner, job, true);
        }
        _ => {}
    }
    (job.callback)(Err(error));
}

/// A node could not be reached: drop its connection so a refresh starts afresh
/// (the node client would only keep failing fast).
fn forget_node(inner: &Arc<Inner>, addr: &NodeAddr) {
    let gone = inner.state.lock().unwrap().pool.remove(addr);
    if let Some(c) = gone {
        c.retire();
    }
}

struct TxJob {
    commands: Vec<Command>,
    slot: Option<u16>,
    target: Target,
    budget: u32,
    callback: TxCallback,
    track: Option<Arc<Track>>,
}

fn dispatch_tx(inner: &Arc<Inner>, mut job: TxJob, fresh: bool) {
    if let Some(t) = &job.track {
        detach(t);
    }
    let Some((client, addr, asking)) = route(inner, &job.target, job.slot) else {
        return if fresh {
            park(inner, Parked::Tx(job), None)
        } else if job.budget > 0 {
            job.budget -= 1;
            park(inner, Parked::Tx(job), Some(unserved()))
        } else {
            finish_tx(inner, job.callback, Err(unserved()))
        };
    };
    let inner2 = Arc::clone(inner);
    let commands = job.commands.clone();
    let track = job.track.clone();
    client.transaction_asking(asking, commands, move |result| on_tx_reply(&inner2, job, addr, result));
    if let Some(t) = track {
        attach(inner, &t, &client);
    }
}

fn on_tx_reply(inner: &Arc<Inner>, mut job: TxJob, from: NodeAddr, result: Result<Option<Vec<Value>>, RedisError>) {
    let error = match result {
        Ok(v) => return (job.callback)(Ok(v)),
        Err(e) => e,
    };
    match &error {
        RedisError::Server(e) if (e.code == "MOVED" || e.code == "ASK") && job.budget > 0 => {
            if let Some((slot, node)) = parse_redirect(&e.message) {
                job.budget -= 1;
                if e.code == "MOVED" {
                    inner.state.lock().unwrap().slots[slot as usize] = Some(Arc::new(node.clone()));
                    request_refresh(inner);
                    job.target = Target::Node(node);
                } else {
                    job.target = Target::Asking(node);
                }
                return dispatch_tx(inner, job, true);
            }
        }
        RedisError::Server(e) if (e.code == "CLUSTERDOWN" || e.code == "TRYAGAIN") && job.budget > 0 => {
            job.budget -= 1;
            job.target = Target::Owner;
            return park(inner, Parked::Tx(job), Some(error));
        }
        RedisError::Server(e) if e.code == "CLUSTERDOWN" => request_refresh(inner),
        RedisError::Connect(_) if job.budget > 0 => {
            job.budget -= 1;
            job.target = Target::Owner;
            forget_node(inner, &from);
            return park(inner, Parked::Tx(job), Some(error));
        }
        RedisError::ConnectionLost(_) => request_refresh(inner),
        RedisError::Closed if job.budget > 0 && !inner.closed.load(Ordering::SeqCst) => {
            job.budget -= 1;
            job.target = Target::Owner;
            return dispatch_tx(inner, job, true);
        }
        _ => {}
    }
    (job.callback)(Err(error));
}

// ---- commands bound to the connection of a write ----

/// The last command submitted for a slot, while it is unanswered: what a `WAIT`
/// for the slot is bound to.
struct Track {
    slot: u16,
    st: Mutex<TrackState>,
}

#[derive(Default)]
struct TrackState {
    /// The connection the command is on now; `None` until it is dispatched, and
    /// while it is being redirected.
    client: Option<RedisClient>,
    /// The `WAIT`s that have not been answered.
    waits: Vec<Arc<Wait>>,
    /// The command has been answered.
    finished: bool,
}

struct Wait {
    command: Command,
    deadline: Deadline,
    /// The sending of this `WAIT` whose reply counts, or 0 when it is not
    /// sent: an answer to an earlier sending, from before the command was
    /// redirected, is not an answer.
    sent: AtomicU64,
    callback: Mutex<Option<Callback>>,
}

/// Make `slot`'s new last command.
fn register(inner: &Arc<Inner>, slot: u16) -> Arc<Track> {
    let track = Arc::new(Track {
        slot,
        st: Mutex::new(TrackState::default()),
    });
    inner.state.lock().unwrap().last.insert(slot, Arc::clone(&track));
    track
}

/// `callback`, preceded by the end of `track`: a `WAIT` made from `callback`
/// finds nothing in flight.
fn on_completion(inner: &Arc<Inner>, track: &Arc<Track>, callback: Callback) -> Callback {
    let (inner, track) = (Arc::clone(inner), Arc::clone(track));
    Box::new(move |reply| {
        complete(&inner, &track, reply.as_ref().err());
        callback(reply)
    })
}

/// The command has its answer. A `WAIT` that was never sent fails with its
/// error; one that was has its own reply coming.
fn complete(inner: &Arc<Inner>, track: &Arc<Track>, error: Option<&RedisError>) {
    let unsent: Vec<Arc<Wait>> = {
        let mut ts = track.st.lock().unwrap();
        ts.finished = true;
        ts.client = None;
        let (unsent, sent): (Vec<_>, Vec<_>) = ts.waits.drain(..).partition(|w| w.sent.load(Ordering::SeqCst) == 0);
        ts.waits = sent;
        unsent
    };
    {
        let mut st = inner.state.lock().unwrap();
        if st.last.get(&track.slot).is_some_and(|t| Arc::ptr_eq(t, track)) {
            st.last.remove(&track.slot);
        }
    }
    for w in unsent {
        let why = error
            .cloned()
            .unwrap_or_else(|| RedisError::Unexpected("the command the WAIT was bound to was never sent".into()));
        if let Some(cb) = w.callback.lock().unwrap().take() {
            finish(inner, cb, Err(why));
        }
    }
}

/// The command is being sent again: what was sent behind it where it was no
/// longer counts.
fn detach(track: &Arc<Track>) {
    let mut ts = track.st.lock().unwrap();
    ts.client = None;
    for w in &ts.waits {
        w.sent.store(0, Ordering::SeqCst);
    }
}

/// The command has been written to `client`: send the `WAIT`s behind it.
fn attach(inner: &Arc<Inner>, track: &Arc<Track>, client: &RedisClient) {
    let mut ts = track.st.lock().unwrap();
    if ts.finished {
        // Answered before this thread got here.
        return;
    }
    ts.client = Some(client.clone());
    for w in ts.waits.clone() {
        send_wait(inner, track, &w, client);
    }
}

fn send_wait(inner: &Arc<Inner>, track: &Arc<Track>, wait: &Arc<Wait>, client: &RedisClient) {
    let id = inner.wait_sends.fetch_add(1, Ordering::SeqCst) + 1;
    wait.sent.store(id, Ordering::SeqCst);
    let (inner2, track2, wait2) = (Arc::clone(inner), Arc::clone(track), Arc::clone(wait));
    client.send_with_deadline(&wait.command, wait.deadline, move |reply| {
        // Not this sending's reply: the command was redirected since, and the
        // `WAIT` has been sent again where it went.
        if wait2.sent.load(Ordering::SeqCst) != id {
            return;
        }
        track2.st.lock().unwrap().waits.retain(|w| !Arc::ptr_eq(w, &wait2));
        if let Some(cb) = wait2.callback.lock().unwrap().take() {
            cb(unsent_closed(&inner2, reply));
        }
    });
}

/// A node's client that refuses a command because it is being let go of has
/// not sent it, but a `WAIT` cannot go anywhere else: say that, not `Closed`.
fn unsent_closed(inner: &Inner, reply: Reply) -> Reply {
    match reply {
        Err(RedisError::Closed) if !inner.closed.load(Ordering::SeqCst) => Err(RedisError::ConnectionLost(
            "the node left the cluster layout before the command was sent".into(),
        )),
        other => other,
    }
}

// ---- the layout ----

/// Fetch the layout, unless one is being fetched or one was fetched too
/// recently; in that case, when it is allowed.
fn request_refresh(inner: &Arc<Inner>) {
    if inner.closed.load(Ordering::SeqCst) {
        return;
    }
    let candidates = {
        let mut st = inner.state.lock().unwrap();
        if st.refresh.running {
            return;
        }
        let now = Instant::now();
        if let Some(last) = st.refresh.last_start {
            let ready_at = last + inner.config.min_refresh_interval;
            if ready_at > now {
                if !st.refresh.timer_pending {
                    st.refresh.timer_pending = true;
                    let weak = Arc::downgrade(inner);
                    inner.reactor.schedule_timer(
                        ready_at - now,
                        Box::new(move || {
                            if let Some(inner) = weak.upgrade() {
                                inner.state.lock().unwrap().refresh.timer_pending = false;
                                request_refresh(&inner);
                            }
                        }),
                    );
                }
                return;
            }
        }
        st.refresh.running = true;
        st.refresh.last_start = Some(now);
        // Ask the nodes we know first, then the seeds.
        let mut order: Vec<NodeAddr> = Vec::new();
        for a in st.slots.iter().flatten() {
            if !order.contains(a) {
                order.push((**a).clone());
            }
        }
        for s in &inner.config.seeds {
            if !order.contains(s) {
                order.push(s.clone());
            }
        }
        order
    };
    inner.refreshes.fetch_add(1, Ordering::SeqCst);
    ask(inner, candidates, 0, false);
}

/// Ask `candidates[i]` for the layout, with `CLUSTER SHARDS` or, once that has
/// been refused, `CLUSTER SLOTS`; on failure ask the next.
fn ask(inner: &Arc<Inner>, candidates: Vec<NodeAddr>, i: usize, slots_form: bool) {
    let Some(addr) = candidates.get(i).cloned() else {
        return refresh_failed(inner, RedisError::Connect("no node in the cluster answered".into()));
    };
    let client = {
        let mut st = inner.state.lock().unwrap();
        client_for(inner, &mut st, &addr)
    };
    let tls = inner.config.node.tls.is_some();
    let inner2 = Arc::clone(inner);
    let sub: &[u8] = if slots_form { b"SLOTS" } else { b"SHARDS" };
    client.command(&[b"CLUSTER", sub], move |reply| {
        let ranges = reply.and_then(|v| {
            if slots_form {
                parse_slots(v, &addr)
            } else {
                parse_shards(v, tls, &addr)
            }
        });
        match ranges {
            Ok(r) if !r.is_empty() => apply(&inner2, r),
            // A server without CLUSTER SHARDS: the older command.
            Err(RedisError::Server(e)) if !slots_form && e.code == "ERR" => ask(&inner2, candidates, i, true),
            // Nothing from this node, or nonsense: another.
            _ => ask(&inner2, candidates, i + 1, false),
        }
    });
}

/// Take a layout.
fn apply(inner: &Arc<Inner>, ranges: Vec<SlotRange>) {
    let (retired, parked) = {
        let mut st = inner.state.lock().unwrap();
        let mut slots: Vec<Option<Arc<NodeAddr>>> = vec![None; SLOTS];
        let mut masters: Vec<Arc<NodeAddr>> = Vec::new();
        for r in &ranges {
            let m = match masters.iter().find(|m| ***m == r.master) {
                Some(m) => Arc::clone(m),
                None => {
                    let m = Arc::new(r.master.clone());
                    masters.push(Arc::clone(&m));
                    m
                }
            };
            for s in r.start..=r.end {
                slots[s as usize] = Some(Arc::clone(&m));
            }
        }
        st.slots = slots;
        // Connections to nodes that are no longer masters are closed; those that
        // are keep theirs, and a new master is connected to when first needed.
        let keep: Vec<NodeAddr> = masters.iter().map(|m| (**m).clone()).collect();
        let retired: Vec<RedisClient> = {
            let gone: Vec<NodeAddr> = st.pool.keys().filter(|a| !keep.contains(a)).cloned().collect();
            gone.into_iter().filter_map(|a| st.pool.remove(&a)).collect()
        };
        st.refresh.running = false;
        (retired, std::mem::take(&mut st.parked))
    };
    // Commands may be pipelined behind the one that fetched this layout: they
    // are answered before the connection goes.
    for c in retired {
        c.retire();
    }
    for (work, _) in parked {
        match work {
            Parked::Command(job) => dispatch(inner, job, false),
            Parked::Tx(job) => dispatch_tx(inner, job, false),
        }
    }
}

/// No node would say what the cluster looks like: fail what waits for it.
fn refresh_failed(inner: &Arc<Inner>, error: RedisError) {
    let parked = {
        let mut st = inner.state.lock().unwrap();
        st.refresh.running = false;
        std::mem::take(&mut st.parked)
    };
    for (work, why) in parked {
        work.fail(inner, why.unwrap_or_else(|| error.clone()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_node_config_takes_the_node_s_own_address_and_no_database() {
        let cfg = ClusterConfig::new([("seed", 7000)]).node_config(|c| c.password("pw").database(3).client_name("n"));
        let node = cfg.for_node(&NodeAddr {
            host: "10.0.0.5".into(),
            port: 7005,
        });
        assert_eq!((node.host(), node.port()), ("10.0.0.5", 7005));
        assert_eq!(node.database, 0, "a cluster has no databases");
        assert_eq!(node.password.as_deref(), Some("pw"));
        assert_eq!(node.client_name.as_deref(), Some("n"));
    }

    #[test]
    fn seeds_and_limits_are_configurable() {
        let cfg = ClusterConfig::new([("a", 1), ("b", 2)]).max_redirects(2).min_refresh_interval(Duration::from_secs(3));
        assert_eq!(cfg.seeds.len(), 2);
        assert_eq!(cfg.max_redirects, 2);
        assert_eq!(cfg.min_refresh_interval, Duration::from_secs(3));
    }
}
