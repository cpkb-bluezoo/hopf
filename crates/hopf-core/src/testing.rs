// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Test support (feature `testing`): drive a [`ProtocolHandler`] in-process,
//! with no sockets and no reactor.
//!
//! A [`Peer`] stands in for the connection. It records everything the handler
//! sends, feeds it the bytes a test writes, and plays the reactor's part for
//! work the handler hands to the storage pool: the callbacks a worker posts
//! with [`ConnHandle::with_endpoint`] are queued, and run against the
//! recording endpoint on the test's own thread, so a whole session can be
//! scripted and its replies asserted on. Timers the handler schedules fire
//! on that thread too, once they are due and while the peer is being pumped
//! (a handler that waits for one reports itself busy, as it does for the
//! storage pool, so the peer keeps pumping until it has gone off).
//!
//! ```ignore
//! let mut peer = Peer::connect(handler, |h| h.is_busy());
//! assert!(peer.take().starts_with("+OK"));
//! assert_eq!(peer.run("NOOP\r\n"), "+OK\r\n");
//! ```

use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::endpoint::Endpoint;
use crate::handle::{ConnHandle, ConnHandleBackend};
use crate::handler::ProtocolHandler;
use crate::peer_addr::PeerAddr;
use crate::security::SecurityInfo;
use crate::{LoopBuf, StartTlsError, TimerHandle};

type Job = Box<dyn FnOnce(&mut dyn Endpoint) + Send>;

/// A timer the handler scheduled, run by [`Peer::pump`] when it is due.
struct Timer {
    due: Instant,
    cancelled: Arc<AtomicBool>,
    callback: Box<dyn FnOnce() + Send>,
}

/// What the connection has seen, shared by the endpoint and its handle.
#[derive(Default)]
pub struct Wire {
    out: Mutex<Vec<u8>>,
    jobs: Mutex<VecDeque<Job>>,
    timers: Mutex<Vec<Timer>>,
    poked: AtomicBool,
    paused: AtomicBool,
    closed: AtomicBool,
}

impl Wire {
    fn add_timer(&self, delay: Duration, callback: Box<dyn FnOnce() + Send>) -> TimerHandle {
        let cancelled = Arc::new(AtomicBool::new(false));
        self.timers.lock().unwrap().push(Timer {
            due: Instant::now() + delay,
            cancelled: Arc::clone(&cancelled),
            callback,
        });
        TimerHandle::from_cancel(move || cancelled.store(true, Ordering::Relaxed))
    }

    /// Run the timers that are due, oldest first; a cancelled one is dropped.
    fn fire_due_timers(&self) {
        let now = Instant::now();
        let mut due = Vec::new();
        {
            let mut timers = self.timers.lock().unwrap();
            let mut i = 0;
            while i < timers.len() {
                if timers[i].cancelled.load(Ordering::Relaxed) {
                    timers.remove(i);
                } else if timers[i].due <= now {
                    due.push(timers.remove(i));
                } else {
                    i += 1;
                }
            }
        }
        due.sort_by_key(|t| t.due);
        for timer in due {
            (timer.callback)();
        }
    }
}

struct Backend(Arc<Wire>);

impl ConnHandleBackend for Backend {
    fn with_endpoint(&self, task: Job) {
        self.0.jobs.lock().unwrap().push_back(task);
    }

    fn execute(&self, task: Box<dyn FnOnce() + Send>) {
        task();
    }

    fn is_probably_open(&self) -> bool {
        !self.0.closed.load(Ordering::Relaxed)
    }

    fn schedule_timer(&self, delay: Duration, callback: Box<dyn FnOnce() + Send>) -> TimerHandle {
        self.0.add_timer(delay, callback)
    }
}

/// A plaintext [`Endpoint`] that records what is sent to it.
pub struct TestEndpoint(Arc<Wire>);

impl Endpoint for TestEndpoint {
    fn send(&mut self, data: &[u8]) {
        self.0.out.lock().unwrap().extend_from_slice(data);
    }
    fn is_open(&self) -> bool {
        !self.0.closed.load(Ordering::Relaxed)
    }
    fn is_closing(&self) -> bool {
        self.0.closed.load(Ordering::Relaxed)
    }
    fn close(&mut self) {
        self.0.closed.store(true, Ordering::Relaxed);
    }
    fn local_addr(&self) -> io::Result<PeerAddr> {
        Ok(PeerAddr::Inet("127.0.0.1:143".parse().unwrap()))
    }
    fn remote_addr(&self) -> io::Result<PeerAddr> {
        Ok(PeerAddr::Inet("127.0.0.1:9999".parse().unwrap()))
    }
    fn security_info(&self) -> &SecurityInfo {
        static PLAINTEXT: std::sync::OnceLock<SecurityInfo> = std::sync::OnceLock::new();
        PLAINTEXT.get_or_init(SecurityInfo::plaintext)
    }
    fn start_tls(&mut self) -> Result<(), StartTlsError> {
        Err(StartTlsError::Unsupported)
    }
    fn pause_read(&mut self) {
        self.0.paused.store(true, Ordering::Relaxed);
    }
    fn resume_read(&mut self) {
        self.0.paused.store(false, Ordering::Relaxed);
    }
    fn on_write_ready(&mut self, _callback: Option<crate::endpoint::WriteReadyCallback>) {}
    fn execute(&self, task: Box<dyn FnOnce() + Send>) {
        task();
    }
    fn schedule_timer(&self, delay: Duration, callback: Box<dyn FnOnce() + Send>) -> TimerHandle {
        self.0.add_timer(delay, callback)
    }
    fn handle(&self) -> ConnHandle {
        ConnHandle::from_backend(Arc::new(Backend(Arc::clone(&self.0))))
    }
    fn poke_handler(&mut self) {
        self.0.poked.store(true, Ordering::Relaxed);
    }
}

/// A handler connected to a recording endpoint.
pub struct Peer<H: ProtocolHandler> {
    /// The handler under test.
    pub handler: H,
    endpoint: TestEndpoint,
    wire: Arc<Wire>,
    input: LoopBuf,
    /// Is the handler waiting for something it started (a storage operation,
    /// a queued command)? The peer keeps playing the reactor until it is not.
    busy: fn(&H) -> bool,
    /// The last `receive` consumed nothing: the handler is waiting for more
    /// bytes (a partial line it leaves in the ring), so it is not run again
    /// until some arrive, it is poked, or a job has run.
    stalled: bool,
}

impl<H: ProtocolHandler> Peer<H> {
    /// Connects `handler` (its `connected` runs, and whatever it starts is
    /// seen through). `busy` says whether it is still working.
    pub fn connect(handler: H, busy: fn(&H) -> bool) -> Self {
        let wire = Arc::new(Wire::default());
        let mut peer = Self {
            handler,
            endpoint: TestEndpoint(Arc::clone(&wire)),
            wire,
            input: LoopBuf::with_capacity(1 << 20),
            busy,
            stalled: false,
        };
        peer.handler.connected(&mut peer.endpoint);
        peer.pump();
        peer
    }

    /// Everything the handler has written since the last call.
    pub fn take(&mut self) -> String {
        String::from_utf8_lossy(&std::mem::take(&mut *self.wire.out.lock().unwrap())).into_owned()
    }

    /// Everything the handler has written since the last call, as bytes: for
    /// binary protocols, where `take` would mangle what is not UTF-8.
    pub fn take_bytes(&mut self) -> Vec<u8> {
        std::mem::take(&mut *self.wire.out.lock().unwrap())
    }

    /// As [`Self::run`], for binary input and output.
    pub fn run_bytes(&mut self, wire: &[u8]) -> Vec<u8> {
        self.input.extend_from_slice(wire);
        self.stalled = false;
        self.pump();
        self.take_bytes()
    }

    /// As [`Self::run_chunked`], for binary input and output.
    pub fn run_chunked_bytes(&mut self, wire: &[u8], chunk: usize) -> Vec<u8> {
        for piece in wire.chunks(chunk) {
            self.input.extend_from_slice(piece);
            self.stalled = false;
            self.pump();
        }
        self.take_bytes()
    }

    /// Writes `wire` and returns what the handler answered by the time it is idle.
    pub fn run(&mut self, wire: &str) -> String {
        self.input.extend_from_slice(wire.as_bytes());
        self.stalled = false;
        self.pump();
        self.take()
    }

    /// Writes `wire` in chunks of `chunk` bytes, waiting for idle after each.
    pub fn run_chunked(&mut self, wire: &str, chunk: usize) -> String {
        for piece in wire.as_bytes().chunks(chunk) {
            self.input.extend_from_slice(piece);
            self.stalled = false;
            self.pump();
        }
        self.take()
    }

    /// Writes `bytes` and lets the handler see them once, without waiting for it
    /// to finish: for tests that step through what it does.
    pub fn write_and_receive_once(&mut self, bytes: &[u8]) {
        self.input.extend_from_slice(bytes);
        self.stalled = false;
        self.handler.receive(&mut self.endpoint, &mut self.input);
    }

    /// The peer goes away: the handler is told, and whatever it starts in answer
    /// (closing a mailbox, say) is seen through.
    pub fn disconnect(&mut self) {
        self.handler.disconnected(&mut self.endpoint);
        self.pump();
    }

    /// The connection fails: the handler is told, and whatever it starts in
    /// answer is seen through.
    pub fn fail(&mut self, err: &std::io::Error) {
        self.handler.error(&mut self.endpoint, err);
        self.pump();
    }

    /// The connection becomes secure: the handler is told, and whatever it
    /// starts in answer is seen through.
    pub fn secure(&mut self, info: &crate::SecurityInfo) {
        self.handler.security_established(&mut self.endpoint, info);
        self.pump();
    }

    /// Has the handler closed the connection?
    pub fn is_closed(&self) -> bool {
        self.wire.closed.load(Ordering::Relaxed)
    }

    /// The endpoint, for a test that calls the handler's own methods.
    pub fn endpoint(&mut self) -> &mut TestEndpoint {
        &mut self.endpoint
    }

    /// Plays the reactor until the handler has nothing left to do.
    pub fn pump(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            self.wire.fire_due_timers();
            loop {
                let job = self.wire.jobs.lock().unwrap().pop_front();
                match job {
                    Some(job) => {
                        self.stalled = false;
                        job(&mut self.endpoint)
                    }
                    None => break,
                }
            }
            let poked = self.wire.poked.swap(false, Ordering::Relaxed);
            let paused = self.wire.paused.load(Ordering::Relaxed);
            if poked || (!paused && !self.stalled && !self.input.is_empty()) {
                let before = self.input.len();
                self.handler.receive(&mut self.endpoint, &mut self.input);
                self.stalled = !poked && self.input.len() == before;
                continue;
            }
            let working = (self.busy)(&self.handler) || !self.wire.jobs.lock().unwrap().is_empty();
            if !working {
                return;
            }
            assert!(Instant::now() < deadline, "the handler never went idle; output so far: {:?}", self.take());
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
