// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Transport-agnostic endpoint trait (Gumdrop `Endpoint`).

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use crate::error::StartTlsError;
use crate::handle::ConnHandle;
use crate::security::SecurityInfo;

/// Cancels a scheduled timer callback.
pub struct TimerHandle {
    cancel: Box<dyn Fn() + Send + Sync>,
}

impl TimerHandle {
    /// Create a handle that runs `cancel` when [`cancel`](Self::cancel) is called.
    pub fn from_cancel(cancel: impl Fn() + Send + Sync + 'static) -> Self {
        Self::new(cancel)
    }

    pub(crate) fn new(cancel: impl Fn() + Send + Sync + 'static) -> Self {
        Self {
            cancel: Box::new(cancel),
        }
    }

    /// Cancel the timer. Idempotent; the callback will not run after this returns
    /// (unless it already started on the reactor thread).
    pub fn cancel(&self) {
        (self.cancel)();
    }
}

/// Plaintext bidirectional channel (TCP today; UDP/QUIC stream seams later).
///
/// All I/O methods except where noted run on the endpoint's owning reactor
/// thread when invoked via [`crate::ProtocolHandler`] callbacks.
pub trait Endpoint: Send {
    /// Queue plaintext application data for sending.
    fn send(&mut self, data: &[u8]);

    /// Whether the endpoint can still perform I/O.
    fn is_open(&self) -> bool;

    /// Whether [`close`](Self::close) has been requested but not yet finished.
    fn is_closing(&self) -> bool;

    /// Graceful close after flushing outbound data.
    fn close(&mut self);

    /// Local socket address.
    fn local_addr(&self) -> io::Result<SocketAddr>;

    /// Remote socket address.
    fn remote_addr(&self) -> io::Result<SocketAddr>;

    /// Whether a security layer is active.
    fn is_secure(&self) -> bool {
        self.security_info().is_secure()
    }

    /// Security metadata (never fails; plaintext returns a null object).
    fn security_info(&self) -> &SecurityInfo;

    /// Initiate STARTTLS. Stub until Tranche 3 / unsupported on QUIC.
    fn start_tls(&mut self) -> Result<(), StartTlsError>;

    /// Stop delivering inbound data (`OP_READ` off) — TCP backpressure.
    fn pause_read(&mut self);

    /// Resume inbound delivery after [`pause_read`](Self::pause_read).
    fn resume_read(&mut self);

    /// One-shot callback when the outbound buffer has been fully drained.
    ///
    /// Replaces any previously registered callback. Pass `None` to clear.
    /// Runs on the reactor thread. Not cleared automatically after firing —
    /// the callback should re-arm or clear as needed.
    fn on_write_ready(&mut self, callback: Option<WriteReadyCallback>);

    /// Run `task` on this endpoint's reactor thread.
    ///
    /// If already on that thread, runs immediately; otherwise enqueued + wakeup.
    fn execute(&self, task: Box<dyn FnOnce() + Send>);

    /// Schedule `callback` on the reactor thread after `delay`.
    fn schedule_timer(&self, delay: Duration, callback: Box<dyn FnOnce() + Send>) -> TimerHandle;

    /// Cloneable handle for hopping work back to this connection from other threads.
    fn handle(&self) -> ConnHandle;
}

/// Callback type for [`Endpoint::on_write_ready`].
pub type WriteReadyCallback = Box<dyn FnOnce(&mut dyn Endpoint) + Send>;
