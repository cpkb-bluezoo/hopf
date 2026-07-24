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

    /// Queue a task on the owning reactor (no endpoint borrow).
    pub fn execute(&self, task: Box<dyn FnOnce() + Send>) {
        match &self.inner {
            ConnHandleInner::Tcp { reactor, .. } => reactor.execute(task),
            ConnHandleInner::Tasks { execute } => execute(task),
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
        }
    }

    /// Queue plaintext bytes for sending on the connection.
    pub fn send(&self, data: Vec<u8>) {
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
