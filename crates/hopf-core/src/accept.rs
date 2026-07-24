// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Accept loop (Gumdrop `AcceptSelectorLoop`).

use std::io::{self, ErrorKind};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use mio::net::TcpListener as MioTcpListener;
use mio::{Events, Interest, Poll, Token, Waker};

use crate::binding::BindingId;
use crate::cmd::{ReactorCmd, ReactorHandle};
use crate::listener::{Listener, TcpListenerConfig};
use crate::telemetry::TelemetryHook;

const WAKER_TOKEN: Token = Token(0);
const FIRST_LISTENER_TOKEN: usize = 1;
const ACCEPT_BACKOFF: Duration = Duration::from_millis(1000);

struct BoundListener {
    id: BindingId,
    token: Token,
    listener: MioTcpListener,
    config: TcpListenerConfig,
}

pub(crate) struct AcceptLoop {
    poll: Poll,
    events: Events,
    listeners: Vec<BoundListener>,
    next_token: usize,
    workers: Vec<ReactorHandle>,
    rr: AtomicUsize,
    active: Arc<AtomicBool>,
    cmd_rx: std::sync::mpsc::Receiver<AcceptCmd>,
    telemetry: Option<Arc<dyn TelemetryHook>>,
}

pub(crate) enum AcceptCmd {
    AddListener {
        id: BindingId,
        listener: MioTcpListener,
        config: TcpListenerConfig,
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
                    next_token: FIRST_LISTENER_TOKEN,
                    workers,
                    rr: AtomicUsize::new(0),
                    active,
                    cmd_rx,
                    telemetry,
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
            match self.poll.poll(&mut self.events, Some(Duration::from_millis(500))) {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
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
            for token in readable_tokens {
                self.accept_on(token)?;
            }
        }
        Ok(())
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

    fn unregister_listener(&mut self, id: BindingId) -> io::Result<()> {
        if let Some(idx) = self.listeners.iter().position(|l| l.id == id) {
            let mut bound = self.listeners.remove(idx);
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
                        stream,
                        handler,
                        params,
                        connecting: false,
                        telemetry: self.telemetry.clone(),
                    });
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if is_fd_exhaustion(&e) => {
                    eprintln!("hopf: accept EMFILE/ENFILE, backing off");
                    thread::sleep(ACCEPT_BACKOFF);
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
