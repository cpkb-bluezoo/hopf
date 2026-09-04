// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Accept loop (Gumdrop `AcceptSelectorLoop`).

use std::io::{self, ErrorKind};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use mio::net::{TcpListener as MioTcpListener, UnixListener as MioUnixListener};
use mio::{Events, Interest, Poll, Token, Waker};

use crate::binding::BindingId;
use crate::cmd::{ReactorCmd, ReactorHandle};
use crate::listener::{Listener, TcpListenerConfig, UnixListenerConfig};
use crate::telemetry::TelemetryHook;

const WAKER_TOKEN: Token = Token(0);
const FIRST_LISTENER_TOKEN: usize = 1;
const ACCEPT_BACKOFF: Duration = Duration::from_millis(1000);
/// Upper bound on `poll()`'s wait when nothing else needs attention.
const DEFAULT_POLL_TIMEOUT: Duration = Duration::from_millis(500);

struct BoundListener {
    id: BindingId,
    token: Token,
    listener: MioTcpListener,
    config: TcpListenerConfig,
}

struct BoundUnixListener {
    id: BindingId,
    token: Token,
    listener: MioUnixListener,
    config: UnixListenerConfig,
}

pub(crate) struct AcceptLoop {
    poll: Poll,
    events: Events,
    listeners: Vec<BoundListener>,
    unix_listeners: Vec<BoundUnixListener>,
    next_token: usize,
    workers: Vec<ReactorHandle>,
    rr: AtomicUsize,
    active: Arc<AtomicBool>,
    cmd_rx: std::sync::mpsc::Receiver<AcceptCmd>,
    telemetry: Option<Arc<dyn TelemetryHook>>,
    /// Set on EMFILE/ENFILE (issue #189): while in the future, `run()`
    /// skips attempting `accept()` on any listener — fd exhaustion is a
    /// process-wide condition, so retrying immediately on another listener
    /// would just fail the same way — but keeps polling/`drain_cmds`ing
    /// normally instead of blocking the thread with `thread::sleep`, so
    /// listeners that were *already* readable in the same batch this
    /// backoff started in still get serviced, and `AddListener`/
    /// `RemoveListener` commands never stall behind it.
    backoff_until: Option<Instant>,
}

pub(crate) enum AcceptCmd {
    AddListener {
        id: BindingId,
        listener: MioTcpListener,
        config: TcpListenerConfig,
    },
    AddUnixListener {
        id: BindingId,
        listener: MioUnixListener,
        config: UnixListenerConfig,
    },
    RemoveListener {
        id: BindingId,
    },
    Shutdown,
}

#[derive(Clone)]
pub(crate) struct AcceptHandle {
    tx: std::sync::mpsc::Sender<AcceptCmd>,
    waker: Arc<Waker>,
}

impl AcceptHandle {
    pub fn add_listener(
        &self,
        id: BindingId,
        listener: MioTcpListener,
        config: TcpListenerConfig,
    ) {
        let _ = self.tx.send(AcceptCmd::AddListener {
            id,
            listener,
            config,
        });
        let _ = self.waker.wake();
    }

    pub fn add_unix_listener(
        &self,
        id: BindingId,
        listener: MioUnixListener,
        config: UnixListenerConfig,
    ) {
        let _ = self.tx.send(AcceptCmd::AddUnixListener {
            id,
            listener,
            config,
        });
        let _ = self.waker.wake();
    }

    /// Removes a previously added listener binding — TCP or UNIX domain
    /// socket, whichever `id` refers to.
    pub fn remove_listener(&self, id: BindingId) {
        let _ = self.tx.send(AcceptCmd::RemoveListener { id });
        let _ = self.waker.wake();
    }

    pub fn shutdown(&self) {
        let _ = self.tx.send(AcceptCmd::Shutdown);
        let _ = self.waker.wake();
    }
}

impl AcceptLoop {
    pub fn spawn(
        workers: Vec<ReactorHandle>,
        active: Arc<AtomicBool>,
        telemetry: Option<Arc<dyn TelemetryHook>>,
    ) -> io::Result<(AcceptHandle, JoinHandle<()>)> {
        let poll = Poll::new()?;
        let waker = Arc::new(Waker::new(poll.registry(), WAKER_TOKEN)?);
        let (tx, cmd_rx) = std::sync::mpsc::channel();
        let handle = AcceptHandle {
            tx,
            waker: Arc::clone(&waker),
        };
        let thread = thread::Builder::new()
            .name("hopf-accept".into())
            .spawn(move || {
                let mut accept = AcceptLoop {
                    poll,
                    events: Events::with_capacity(128),
                    listeners: Vec::new(),
                    unix_listeners: Vec::new(),
                    next_token: FIRST_LISTENER_TOKEN,
                    workers,
                    rr: AtomicUsize::new(0),
                    active,
                    cmd_rx,
                    telemetry,
                    backoff_until: None,
                };
                if let Err(e) = accept.run() {
                    eprintln!("hopf: accept loop exited with error: {e}");
                }
            })?;
        Ok((handle, thread))
    }

    fn run(&mut self) -> io::Result<()> {
        while self.active.load(Ordering::Acquire) {
            self.drain_cmds()?;
            let timeout = self.poll_timeout();
            match self.poll.poll(&mut self.events, Some(timeout)) {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
            if self.backoff_until.is_some_and(|until| Instant::now() >= until) {
                self.backoff_until = None;
            }
            let mut readable_tokens = Vec::new();
            for event in self.events.iter() {
                if event.token() == WAKER_TOKEN {
                    continue;
                }
                if event.is_readable() {
                    readable_tokens.push(event.token());
                }
            }
            // Still backing off (issue #189): fd exhaustion is process-wide,
            // so a fresh `accept()` attempt right now would just fail the
            // same way on any listener — skip trying until the backoff
            // clears, rather than spinning on repeated failures. Listeners
            // already readable in whichever batch *started* the backoff
            // were serviced before `accept_on` set it, so nothing already
            // in flight this iteration is held up by this check.
            if self.backoff_until.is_none() {
                for token in readable_tokens {
                    if self.unix_listeners.iter().any(|l| l.token == token) {
                        self.accept_unix_on(token)?;
                    } else {
                        self.accept_on(token)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// How long `poll()` should wait: the usual default, or less if a
    /// backoff is due to expire sooner — so `run()` wakes up promptly to
    /// retry (and keeps `drain_cmds()` responsive throughout) instead of
    /// blocking the thread for the whole backoff window (issue #189).
    fn poll_timeout(&self) -> Duration {
        match self.backoff_until {
            Some(until) => until
                .saturating_duration_since(Instant::now())
                .min(DEFAULT_POLL_TIMEOUT),
            None => DEFAULT_POLL_TIMEOUT,
        }
    }

    fn drain_cmds(&mut self) -> io::Result<()> {
        loop {
            match self.cmd_rx.try_recv() {
                Ok(AcceptCmd::AddListener {
                    id,
                    listener,
                    config,
                }) => {
                    self.register_listener(id, listener, config)?;
                }
                Ok(AcceptCmd::AddUnixListener {
                    id,
                    listener,
                    config,
                }) => {
                    self.register_unix_listener(id, listener, config)?;
                }
                Ok(AcceptCmd::RemoveListener { id }) => {
                    self.unregister_listener(id)?;
                }
                Ok(AcceptCmd::Shutdown) => {
                    self.active.store(false, Ordering::Release);
                    break;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.active.store(false, Ordering::Release);
                    break;
                }
            }
        }
        Ok(())
    }

    fn register_listener(
        &mut self,
        id: BindingId,
        mut listener: MioTcpListener,
        config: TcpListenerConfig,
    ) -> io::Result<()> {
        let token = Token(self.next_token);
        self.next_token += 1;
        self.poll
            .registry()
            .register(&mut listener, token, Interest::READABLE)?;
        self.listeners.push(BoundListener {
            id,
            token,
            listener,
            config,
        });
        Ok(())
    }

    fn register_unix_listener(
        &mut self,
        id: BindingId,
        mut listener: MioUnixListener,
        config: UnixListenerConfig,
    ) -> io::Result<()> {
        let token = Token(self.next_token);
        self.next_token += 1;
        self.poll
            .registry()
            .register(&mut listener, token, Interest::READABLE)?;
        self.unix_listeners.push(BoundUnixListener {
            id,
            token,
            listener,
            config,
        });
        Ok(())
    }

    fn unregister_listener(&mut self, id: BindingId) -> io::Result<()> {
        if let Some(idx) = self.listeners.iter().position(|l| l.id == id) {
            let mut bound = self.listeners.remove(idx);
            let _ = self.poll.registry().deregister(&mut bound.listener);
            return Ok(());
        }
        if let Some(idx) = self.unix_listeners.iter().position(|l| l.id == id) {
            let mut bound = self.unix_listeners.remove(idx);
            let _ = self.poll.registry().deregister(&mut bound.listener);
        }
        Ok(())
    }

    fn accept_on(&mut self, token: Token) -> io::Result<()> {
        let Some(idx) = self.listeners.iter().position(|l| l.token == token) else {
            return Ok(());
        };
        loop {
            let result = self.listeners[idx].listener.accept();
            match result {
                Ok((stream, addr)) => {
                    let config = &self.listeners[idx].config;
                    if !config.acl.allows(addr) {
                        drop(stream);
                        if let Some(t) = &self.telemetry {
                            t.on_error(Some(addr), "ACL denied");
                        }
                        continue;
                    }
                    if let Some(ref lim) = config.rate_limit {
                        if !lim.try_acquire(addr) {
                            drop(stream);
                            if let Some(t) = &self.telemetry {
                                t.on_error(Some(addr), "rate limited");
                            }
                            continue;
                        }
                    }
                    if let Some(t) = &self.telemetry {
                        t.on_accept(addr);
                    }
                    let handler = config.create_handler();
                    let params = config.conn_params(addr);
                    let worker = self.next_worker();
                    worker.send(ReactorCmd::Register {
                        stream: stream.into(),
                        handler,
                        params,
                        connecting: false,
                        telemetry: self.telemetry.clone(),
                    });
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if is_fd_exhaustion(&e) => {
                    eprintln!("hopf: accept EMFILE/ENFILE, backing off");
                    self.backoff_until = Some(Instant::now() + ACCEPT_BACKOFF);
                    break;
                }
                Err(e) => {
                    eprintln!("hopf: accept error: {e}");
                    break;
                }
            }
        }
        Ok(())
    }

    fn accept_unix_on(&mut self, token: Token) -> io::Result<()> {
        let Some(idx) = self.unix_listeners.iter().position(|l| l.token == token) else {
            return Ok(());
        };
        loop {
            let result = self.unix_listeners[idx].listener.accept();
            match result {
                Ok((stream, _addr)) => {
                    let config = &self.unix_listeners[idx].config;
                    // UNIX-domain analogue of the IP ACL/rate-limit checks
                    // in `accept_on` — filesystem permissions on the
                    // socket path are the primary gate; this is an
                    // additional, opt-in check against the kernel-reported
                    // peer credentials (not self-reported by the peer).
                    if !config.peer_allowlist.allow_uids.is_empty()
                        || !config.peer_allowlist.allow_gids.is_empty()
                    {
                        match crate::peer_cred::peer_credentials(&stream) {
                            Ok(creds) if config.peer_allowlist.allows(creds) => {}
                            Ok(_) => {
                                drop(stream);
                                if let Some(t) = &self.telemetry {
                                    t.on_error(None, "peer credential allowlist denied");
                                }
                                continue;
                            }
                            Err(e) => {
                                drop(stream);
                                if let Some(t) = &self.telemetry {
                                    t.on_error(None, &format!("peer credentials unavailable: {e}"));
                                }
                                continue;
                            }
                        }
                    }
                    let handler = config.create_handler();
                    let params = config.conn_params();
                    let worker = self.next_worker();
                    worker.send(ReactorCmd::Register {
                        stream: stream.into(),
                        handler,
                        params,
                        connecting: false,
                        telemetry: self.telemetry.clone(),
                    });
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if is_fd_exhaustion(&e) => {
                    eprintln!("hopf: accept EMFILE/ENFILE, backing off");
                    self.backoff_until = Some(Instant::now() + ACCEPT_BACKOFF);
                    break;
                }
                Err(e) => {
                    eprintln!("hopf: accept error: {e}");
                    break;
                }
            }
        }
        Ok(())
    }

    fn next_worker(&self) -> &ReactorHandle {
        let n = self.workers.len();
        debug_assert!(n > 0);
        let idx = self.rr.fetch_add(1, Ordering::Relaxed) % n;
        &self.workers[idx]
    }
}

fn is_fd_exhaustion(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(24) | Some(23))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real (but socket-free) `AcceptLoop`, enough to exercise
    /// `poll_timeout` directly without needing a spawned thread or actual
    /// listeners.
    fn test_loop() -> AcceptLoop {
        let poll = Poll::new().unwrap();
        let (_tx, cmd_rx) = std::sync::mpsc::channel();
        AcceptLoop {
            poll,
            events: Events::with_capacity(1),
            listeners: Vec::new(),
            unix_listeners: Vec::new(),
            next_token: FIRST_LISTENER_TOKEN,
            workers: Vec::new(),
            rr: AtomicUsize::new(0),
            active: Arc::new(AtomicBool::new(true)),
            cmd_rx,
            telemetry: None,
            backoff_until: None,
        }
    }

    /// Issue #189: `poll_timeout` — not a blocking `thread::sleep` — is
    /// what now enforces the EMFILE/ENFILE backoff, so `run()`'s loop
    /// (and thus `drain_cmds`/other listeners) stays responsive throughout
    /// the backoff window instead of the whole accept-loop thread being
    /// blocked for it.
    #[test]
    fn poll_timeout_is_default_with_no_backoff() {
        let l = test_loop();
        assert_eq!(l.poll_timeout(), DEFAULT_POLL_TIMEOUT);
    }

    #[test]
    fn poll_timeout_is_bounded_by_a_fresh_backoff() {
        let mut l = test_loop();
        l.backoff_until = Some(Instant::now() + ACCEPT_BACKOFF);
        let t = l.poll_timeout();
        // Never waits longer than the default even though the backoff
        // itself (1s) is longer — `run()` must keep waking up to service
        // `drain_cmds`/already-readable listeners, not block for the full
        // window in one `poll()` call.
        assert!(t <= DEFAULT_POLL_TIMEOUT, "{t:?} exceeds the default poll timeout");
        assert!(t > Duration::from_millis(400), "{t:?} should be close to the default, backoff just started");
    }

    #[test]
    fn poll_timeout_is_zero_once_backoff_has_elapsed() {
        let mut l = test_loop();
        l.backoff_until = Some(Instant::now() - Duration::from_millis(1));
        assert_eq!(l.poll_timeout(), Duration::ZERO);
    }
}
