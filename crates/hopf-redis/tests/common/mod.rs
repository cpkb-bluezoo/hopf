// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Helpers shared by the integration tests.

#![allow(dead_code)]

pub mod collect;
pub mod scripted_server;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use hopf_core::{Runtime, RuntimeConfig};
use hopf_redis::{RedisClient, RedisConfig};

/// Run an operation that takes a callback and wait for the one value it passes.
#[macro_export]
macro_rules! call {
    (|$cb:ident| $e:expr) => {{
        let (tx, rx) = std::sync::mpsc::channel();
        let $cb = move |v| {
            let _ = tx.send(v);
        };
        $e;
        rx.recv_timeout(std::time::Duration::from_secs(10)).expect("the callback ran")
    }};
}

pub fn runtime() -> Runtime {
    Runtime::start(RuntimeConfig {
        worker_threads: 1,
        ..Default::default()
    })
    .unwrap()
}

/// `host:port` of the real server for the tests that need one, from
/// `HOPF_TEST_REDIS`; `None` (and the test returns) when it is not set.
pub fn real_server() -> Option<(String, u16)> {
    parse_env("HOPF_TEST_REDIS")
}

/// A server started with `--requirepass hunter2`, from `HOPF_TEST_REDIS_AUTH`.
pub fn auth_server() -> Option<(String, u16)> {
    parse_env("HOPF_TEST_REDIS_AUTH")
}

fn parse_env(var: &str) -> Option<(String, u16)> {
    let v = std::env::var(var).ok()?;
    let (host, port) = v.rsplit_once(':')?;
    Some((host.to_string(), port.parse().ok()?))
}

/// A key prefix no other test shares.
pub fn unique(label: &str) -> String {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    format!("hopf-test:{}:{}:{label}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed))
}

pub fn client(rt: &Runtime, host: &str, port: u16) -> RedisClient {
    RedisClient::connect(rt.pick_worker(), RedisConfig::new(host, port))
}

pub fn recv_within<T>(rx: &mpsc::Receiver<T>, secs: u64) -> Option<T> {
    rx.recv_timeout(Duration::from_secs(secs)).ok()
}

/// A message as a test handler gathered it: the test accumulates the body in
/// its own handler, as an application that knows its messages are small would.
#[derive(Debug, Clone, PartialEq)]
pub struct Msg {
    pub kind: hopf_redis::SubscriptionKind,
    pub pattern: Option<Vec<u8>>,
    pub channel: Vec<u8>,
    pub payload: Vec<u8>,
}

impl Msg {
    pub fn channel(channel: &str, payload: &str) -> Self {
        Self {
            kind: hopf_redis::SubscriptionKind::Channel,
            pattern: None,
            channel: channel.as_bytes().to_vec(),
            payload: payload.as_bytes().to_vec(),
        }
    }
}

/// What a subscriber's handler saw, in order.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    Message(Msg),
    Change(hopf_redis::SubscriptionChange),
    Dropped(String),
    Error(hopf_redis::ServerError),
    Connected(bool),
    Disconnected,
}

/// A handler that records what it is told.
#[derive(Clone, Default)]
pub struct Recorder {
    events: std::sync::Arc<std::sync::Mutex<Vec<Event>>>,
    current: std::sync::Arc<std::sync::Mutex<Option<Msg>>>,
    /// Skip messages to this channel.
    pub skip_channel: std::sync::Arc<std::sync::Mutex<Option<Vec<u8>>>>,
    /// Give pushes of kind `invalidate` to a sink telling this.
    pub invalidations: Option<Invalidated>,
}

impl Recorder {
    pub fn events(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }

    pub fn messages(&self) -> Vec<Msg> {
        self.events()
            .into_iter()
            .filter_map(|e| if let Event::Message(m) = e { Some(m) } else { None })
            .collect()
    }

    /// Wait until `cond` holds of the events, or fail the test.
    pub fn wait_for(&self, what: &str, cond: impl Fn(&[Event]) -> bool) {
        for _ in 0..1000 {
            if cond(&self.events()) {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("timed out waiting for {what}; saw {:?}", self.events());
    }
}

impl hopf_redis::SubscriberHandler for Recorder {
    fn message_begin(&mut self, h: &hopf_redis::MessageHeader<'_>, _len: Option<u64>) -> hopf_redis::Flow {
        if self.skip_channel.lock().unwrap().as_deref() == Some(h.channel()) {
            return hopf_redis::Flow::Skip;
        }
        *self.current.lock().unwrap() = Some(Msg {
            kind: h.kind(),
            pattern: h.pattern().map(<[u8]>::to_vec),
            channel: h.channel().to_vec(),
            payload: Vec::new(),
        });
        hopf_redis::Flow::Continue
    }
    fn message_chunk(&mut self, data: &[u8]) -> hopf_redis::Flow {
        if let Some(m) = self.current.lock().unwrap().as_mut() {
            m.payload.extend_from_slice(data);
        }
        hopf_redis::Flow::Continue
    }
    fn message_end(&mut self) {
        if let Some(m) = self.current.lock().unwrap().take() {
            self.events.lock().unwrap().push(Event::Message(m));
        }
    }
    fn on_subscription(&mut self, c: hopf_redis::SubscriptionChange) {
        self.events.lock().unwrap().push(Event::Change(c));
    }
    fn on_push(&mut self, kind: &str) -> Option<Box<dyn hopf_redis::ReplySink + Send>> {
        match (&self.invalidations, kind) {
            (Some(inv), "invalidate") => Some(Box::new(hopf_redis::InvalidationSink::new(inv.clone()))),
            _ => None,
        }
    }
    fn on_dropped(&mut self, why: &hopf_redis::RedisError) {
        self.events.lock().unwrap().push(Event::Dropped(why.to_string()));
    }
    fn on_error(&mut self, e: hopf_redis::ServerError) {
        self.events.lock().unwrap().push(Event::Error(e));
    }
    fn on_connected(&mut self, reconnect: bool) {
        self.events.lock().unwrap().push(Event::Connected(reconnect));
    }
    fn on_disconnected(&mut self, _reason: &hopf_redis::RedisError) {
        self.events.lock().unwrap().push(Event::Disconnected);
    }
}

/// An [`InvalidationHandler`](hopf_redis::InvalidationHandler) that records
/// what it is told: each key, or `*` for everything.
#[derive(Clone, Default)]
pub struct Invalidated(pub std::sync::Arc<std::sync::Mutex<Vec<String>>>);

impl Invalidated {
    pub fn seen(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

impl hopf_redis::InvalidationHandler for Invalidated {
    fn key(&mut self, key: &[u8]) {
        self.0.lock().unwrap().push(String::from_utf8_lossy(key).into_owned());
    }
    fn all(&mut self) {
        self.0.lock().unwrap().push("*".into());
    }
}

/// A subscriber handler that holds nothing of a message: it counts, and pauses
/// when told to.
#[derive(Clone, Default)]
pub struct Counter {
    pub bytes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    pub chunks: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    pub messages: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    pub lengths: std::sync::Arc<std::sync::Mutex<Vec<Option<u64>>>>,
    /// Return `Pause` from the next chunk, once.
    pub pause_next: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub paused: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    pub disconnects: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl hopf_redis::SubscriberHandler for Counter {
    fn message_begin(&mut self, _h: &hopf_redis::MessageHeader<'_>, len: Option<u64>) -> hopf_redis::Flow {
        self.lengths.lock().unwrap().push(len);
        hopf_redis::Flow::Continue
    }
    fn message_chunk(&mut self, data: &[u8]) -> hopf_redis::Flow {
        use std::sync::atomic::Ordering::SeqCst;
        self.bytes.fetch_add(data.len(), SeqCst);
        self.chunks.fetch_add(1, SeqCst);
        if self.pause_next.swap(false, SeqCst) {
            self.paused.fetch_add(1, SeqCst);
            return hopf_redis::Flow::Pause;
        }
        hopf_redis::Flow::Continue
    }
    fn message_end(&mut self) {
        self.messages.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    fn on_disconnected(&mut self, _reason: &hopf_redis::RedisError) {
        self.disconnects.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}
