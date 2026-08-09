// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Connection handle for hopping work back onto an endpoint's reactor.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use mio::Token;

use crate::cmd::{ReactorCmd, ReactorHandle};
use crate::endpoint::{Endpoint, TimerHandle};

/// Cloneable handle to a connection pinned to one reactor.
///
/// Use this from storage workers (or any non-reactor thread) to `send` /
/// `close` / run code with `&mut dyn Endpoint` on the owning loop.
#[derive(Clone)]
pub struct ConnHandle {
    inner: ConnHandleInner,
}

#[derive(Clone)]
enum ConnHandleInner {
    /// TCP connection on a worker reactor.
    Tcp {
        reactor: ReactorHandle,
        token: Token,
        open: Arc<AtomicBool>,
    },
    /// Task queue only (e.g. QUIC stream endpoints on a dedicated driver).
    Tasks {
        execute: std::sync::Arc<dyn Fn(Box<dyn FnOnce() + Send>) + Send + Sync>,
    },
    /// `inner` with outbound bytes piped through `frame` before `send`.
    ///
    /// `send` writes straight to the raw transport `Endpoint` (see
    /// [`ConnHandle::send`]), which is correct only when nothing sits
    /// between the application and the wire. A protocol layered on top of
    /// the transport (e.g. WebSocket framing) needs this wrapper so
    /// asynchronous, cross-connection deliveries (like a pub/sub fan-out)
    /// still go out correctly framed — see `hopf_websocket::framed_ws_conn_handle`.
    Framed {
        inner: Box<ConnHandle>,
        frame: std::sync::Arc<dyn Fn(Vec<u8>) -> Vec<u8> + Send + Sync>,
    },
}

impl ConnHandle {
    pub(crate) fn new(reactor: ReactorHandle, token: Token, open: Arc<AtomicBool>) -> Self {
        Self {
            inner: ConnHandleInner::Tcp { reactor, token, open },
        }
    }

    /// Handle that only supports [`execute`](Self::execute) (no TCP `with_endpoint`).
    ///
    /// Used by QUIC stream endpoints whose I/O lives on a dedicated driver thread.
    pub fn from_execute(
        execute: std::sync::Arc<dyn Fn(Box<dyn FnOnce() + Send>) + Send + Sync>,
    ) -> Self {
        Self {
            inner: ConnHandleInner::Tasks { execute },
        }
    }

    /// Wrap `self` so every [`send`](Self::send) pipes its payload through
    /// `frame` first — e.g. WebSocket framing — before it reaches the raw
    /// transport. `execute`/`with_endpoint`/`close` delegate straight
    /// through to `self` unchanged.
    pub fn framed(&self, frame: std::sync::Arc<dyn Fn(Vec<u8>) -> Vec<u8> + Send + Sync>) -> Self {
        Self {
            inner: ConnHandleInner::Framed {
                inner: Box::new(self.clone()),
                frame,
            },
        }
    }

    /// Queue a task on the owning reactor (no endpoint borrow).
    pub fn execute(&self, task: Box<dyn FnOnce() + Send>) {
        match &self.inner {
            ConnHandleInner::Tcp { reactor, .. } => reactor.execute(task),
            ConnHandleInner::Tasks { execute } => execute(task),
            ConnHandleInner::Framed { inner, .. } => inner.execute(task),
        }
    }

    /// Run `task` on the owning reactor with `&mut dyn Endpoint`.
    ///
    /// If the connection is already gone, the task is dropped.
    ///
    /// **Task-only handles** (built via [`Self::from_execute`] — e.g. a QUIC
    /// stream's [`Endpoint::handle`](crate::Endpoint::handle), which has no
    /// TCP-style reactor token to hop back through) have no endpoint to run
    /// `task` against: the task is dropped, and this prints a warning so the
    /// drop is at least observable rather than silent. [`Self::send`],
    /// [`Self::close`], and [`Self::poke`] are all implemented via this
    /// method, so the same applies to them — use [`Self::execute`] instead
    /// for a task-only handle (it doesn't need an endpoint).
    pub fn with_endpoint(&self, task: impl FnOnce(&mut dyn Endpoint) + Send + 'static) {
        match &self.inner {
            ConnHandleInner::Tcp { reactor, token, .. } => {
                let token = *token;
                reactor.send(ReactorCmd::WithConn {
                    token,
                    task: Box::new(move |conn| task(conn)),
                });
            }
            ConnHandleInner::Tasks { .. } => {
                eprintln!(
                    "hopf-core: ConnHandle::with_endpoint (or send/close/poke, which are \
                     built on it) called on a task-only handle — dropped, no endpoint to \
                     run it against. Use ConnHandle::execute instead for this handle."
                );
                let _ = task;
            }
            ConnHandleInner::Framed { inner, .. } => inner.with_endpoint(task),
        }
    }

    /// Queue plaintext bytes for sending on the connection — or, for a
    /// [`framed`](Self::framed) handle, bytes piped through the frame
    /// transform first (e.g. wrapped in a WebSocket frame) so an
    /// asynchronous, cross-connection delivery (like a broker fan-out)
    /// still reaches the peer correctly framed instead of landing on the
    /// wire raw.
    ///
    /// Silently dropped for a task-only handle — see [`Self::with_endpoint`].
    pub fn send(&self, data: Vec<u8>) {
        if let ConnHandleInner::Framed { inner, frame } = &self.inner {
            return inner.send(frame(data));
        }
        self.with_endpoint(move |ep| {
            if ep.is_open() {
                ep.send(&data);
            }
        });
    }

    /// Request a graceful close on the owning reactor.
    ///
    /// Silently dropped for a task-only handle — see [`Self::with_endpoint`].
    pub fn close(&self) {
        self.with_endpoint(|ep| ep.close());
    }

    /// Cheap, lock-free liveness probe callable from any thread (no reactor
    /// hop) — advisory only, not a correctness gate. Lets a storage-thread
    /// chunk-streaming loop (see `StorageExecutor::submit_streamed`) stop
    /// reading a doomed file early once a peer is unmistakably gone;
    /// `send`/`with_endpoint` already silently drop work for a closed
    /// connection regardless of what this returns.
    ///
    /// Always `true` for non-TCP handles ([`Self::from_execute`],
    /// [`Self::framed`]) — there's no cheap liveness signal to read for
    /// those, so this doesn't pretend to have one.
    pub fn is_probably_open(&self) -> bool {
        match &self.inner {
            ConnHandleInner::Tcp { open, .. } => open.load(Ordering::Acquire),
            ConnHandleInner::Tasks { .. } => true,
            ConnHandleInner::Framed { inner, .. } => inner.is_probably_open(),
        }
    }

    /// Re-invoke the owning connection's protocol handler on its reactor,
    /// without waiting for new inbound data — see [`Endpoint::poke_handler`].
    ///
    /// For a handler whose `receive` unconditionally flushes any
    /// buffered-but-unsent outbound state (as the H1/H2 HTTP client session
    /// codecs do), this is how code that mutated that state from *another*
    /// connection's callback (stashing this handle first) asks the owning
    /// reactor to actually push the bytes onto the wire, without blocking or
    /// busy-polling.
    ///
    /// Silently dropped for a task-only handle — see [`Self::with_endpoint`].
    pub fn poke(&self) {
        self.with_endpoint(|ep| ep.poke_handler());
    }

    /// Schedule `callback` after `delay` on this connection's reactor (TCP /
    /// framed handles). Task-only handles run the timer on a detached thread
    /// and invoke `execute` when it fires.
    ///
    /// Used by layered protocols (e.g. MQTT-over-WebSocket) that hold a
    /// [`ConnHandle`] but not a live [`Endpoint`] borrow.
    pub fn schedule_timer(&self, delay: Duration, callback: Box<dyn FnOnce() + Send>) -> TimerHandle {
        match &self.inner {
            ConnHandleInner::Tcp { reactor, .. } => {
                let cancelled = reactor.schedule_timer(delay, callback);
                TimerHandle::new(move || {
                    cancelled.store(true, Ordering::Release);
                })
            }
            ConnHandleInner::Framed { inner, .. } => inner.schedule_timer(delay, callback),
            ConnHandleInner::Tasks { execute } => {
                let cancelled = Arc::new(AtomicBool::new(false));
                let flag = Arc::clone(&cancelled);
                let exec = Arc::clone(execute);
                std::thread::spawn(move || {
                    std::thread::sleep(delay);
                    if !flag.load(Ordering::Acquire) {
                        exec(callback);
                    }
                });
                TimerHandle::new(move || {
                    cancelled.store(true, Ordering::Release);
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// `with_endpoint` (and `send`/`close`/`poke`, built on it) must not
    /// panic for a task-only handle — the task is dropped, not run, but
    /// that drop must stay silent-safe (no crash), just observable (see the
    /// `eprintln!` in `with_endpoint`, not asserted here since this crate
    /// has no stderr-capturing test infra).
    #[test]
    fn with_endpoint_on_task_only_handle_drops_without_panicking() {
        let ran = Arc::new(AtomicBool::new(false));
        let ran2 = Arc::clone(&ran);
        let handle = ConnHandle::from_execute(Arc::new(|task| task()));

        handle.with_endpoint(move |_ep| {
            ran2.store(true, Ordering::SeqCst);
        });

        assert!(!ran.load(Ordering::SeqCst), "task-only handle must not run an with_endpoint task");
    }

    #[test]
    fn send_close_poke_on_task_only_handle_do_not_panic() {
        let handle = ConnHandle::from_execute(Arc::new(|task| task()));
        // None of these have an endpoint to act on for a task-only handle;
        // the contract is just "don't panic," which this exercises for all
        // three (each is implemented via with_endpoint).
        handle.send(b"hello".to_vec());
        handle.close();
        handle.poke();
    }

    /// `execute` is the one primitive that *does* work for a task-only
    /// handle — the documented escape hatch `with_endpoint`'s doc comment
    /// points callers at.
    #[test]
    fn execute_on_task_only_handle_actually_runs_the_task() {
        let count = Arc::new(AtomicUsize::new(0));
        let count2 = Arc::clone(&count);
        let handle = ConnHandle::from_execute(Arc::new(|task| task()));

        handle.execute(Box::new(move || {
            count2.fetch_add(1, Ordering::SeqCst);
        }));

        assert_eq!(count.load(Ordering::SeqCst), 1);
    }
}
