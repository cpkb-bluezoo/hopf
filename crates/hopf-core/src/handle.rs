// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Connection handle for hopping work back onto an endpoint's reactor.

use mio::Token;

use crate::cmd::{ReactorCmd, ReactorHandle};
use crate::endpoint::Endpoint;

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
    pub(crate) fn new(reactor: ReactorHandle, token: Token) -> Self {
        Self {
            inner: ConnHandleInner::Tcp { reactor, token },
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
    /// For task-only handles, the task is dropped (no endpoint).
    pub fn with_endpoint(&self, task: impl FnOnce(&mut dyn Endpoint) + Send + 'static) {
        match &self.inner {
            ConnHandleInner::Tcp { reactor, token } => {
                let token = *token;
                reactor.send(ReactorCmd::WithConn {
                    token,
                    task: Box::new(move |conn| task(conn)),
                });
            }
            ConnHandleInner::Tasks { .. } => {
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
    pub fn close(&self) {
        self.with_endpoint(|ep| ep.close());
    }
}
