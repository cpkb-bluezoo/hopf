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

    /// Initiate client-side STARTTLS upgrade on a plaintext connection.
    ///
    /// Stores the TLS connector; the handshake runs asynchronously and
    /// [`ProtocolHandler::security_established`] fires once it completes.
    fn start_client_tls(
        &mut self,
        connector: crate::tls::SharedTlsConnector,
        server_name: &str,
    ) -> Result<(), StartTlsError> {
        let _ = (connector, server_name);
        Err(StartTlsError::Unsupported)
    }

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

    /// Deliver `err` to the protocol handler and force-close the connection.
    ///
    /// Used by stage-timeout timers and other cross-thread failure paths that
    /// already hold a [`ConnHandle`] but need to surface an error to the app.
    fn fail(&mut self, err: io::Error) {
        let _ = err;
    }

    /// Re-invoke the protocol handler's `receive` without waiting for new
    /// inbound data (redelivering any buffered residual first).
    ///
    /// Storage-offload completion callbacks (via [`ConnHandle::with_endpoint`])
    /// use this after `resume_read` so handlers that defer reply emission /
    /// queued-command dispatch to their `receive` path make progress even when
    /// the peer is waiting for a reply and sends nothing further. No-op when
    /// called re-entrantly from inside `receive`. Default is a no-op (mocks).
    fn poke_handler(&mut self) {}

    /// Abruptly abort this stream with an application-level error code
    /// (e.g. QUIC RESET_STREAM + STOP_SENDING, RFC 9000 §3.5/§3.6) instead
    /// of a graceful [`close`](Self::close). Intended for protocol-level
    /// stream errors (e.g. HTTP/3's `H3_MESSAGE_ERROR`) where the peer
    /// should be told immediately rather than waiting for a clean FIN.
    ///
    /// Default falls back to [`close`](Self::close) for transports with no
    /// native abrupt-abort primitive, or where "this stream" and "the
    /// connection" are the same thing (e.g. plain TCP).
    fn abort(&mut self, error_code: u32) {
        let _ = error_code;
        self.close();
    }

    /// Abruptly close the entire underlying connection — not just this
    /// stream — with an application-level error code (e.g. a QUIC
    /// CONNECTION_CLOSE frame, RFC 9000 §10.2). Intended for
    /// connection-level protocol errors (e.g. HTTP/3's
    /// `H3_GENERAL_PROTOCOL_ERROR`) that corrupt shared connection state
    /// (QPACK, the control stream) rather than just one request.
    ///
    /// Default falls back to [`abort`](Self::abort) — for single-stream
    /// transports like TCP, "this stream" and "the connection" are the
    /// same thing, so there is nothing more to close.
    fn close_connection(&mut self, error_code: u32) {
        self.abort(error_code);
    }

    /// Queue an unreliable QUIC DATAGRAM frame (RFC 9221) on the underlying
    /// connection. `payload` is the DATAGRAM frame's application data (for
    /// HTTP/3 Datagrams this already includes the quarter-stream-ID prefix,
    /// RFC 9297 §2.1).
    ///
    /// Default: not supported (`ErrorKind::Unsupported`).
    fn send_datagram(&mut self, _payload: &[u8]) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "datagrams not supported on this endpoint",
        ))
    }
}

/// Callback type for [`Endpoint::on_write_ready`].
pub type WriteReadyCallback = Box<dyn FnOnce(&mut dyn Endpoint) + Send>;
