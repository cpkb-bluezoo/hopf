// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! [`QuicStreamEndpoint`] — one bidirectional QUIC stream as an [`Endpoint`].

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use quinn_proto::{ConnectionHandle, StreamId};
use hopf_core::{
    ConnHandle, ConnHandleBackend, Endpoint, SecurityInfo, StartTlsError, TimerHandle,
    WriteReadyCallback,
};

use crate::driver::DriverCmd;

/// [`ConnHandleBackend`] for a QUIC stream — routes `with_endpoint` through
/// the driver thread's command channel (`DriverCmd::WithStream`), the same
/// way `hopf_core::Reactor` routes a TCP `ConnHandle`'s `with_endpoint`
/// through `ReactorCmd::WithConn`. Constructed fresh per [`ConnHandle`]
/// (see [`QuicStreamEndpoint::handle`]) from the same fields the endpoint
/// itself already holds.
struct QuicStreamBackend {
    conn: ConnectionHandle,
    stream_id: StreamId,
    cmd_tx: std::sync::mpsc::Sender<DriverCmd>,
    waker: Arc<mio::Waker>,
    execute: Arc<dyn Fn(Box<dyn FnOnce() + Send>) + Send + Sync>,
}

impl ConnHandleBackend for QuicStreamBackend {
    fn with_endpoint(&self, task: Box<dyn FnOnce(&mut dyn Endpoint) + Send>) {
        let _ = self.cmd_tx.send(DriverCmd::WithStream {
            conn: self.conn,
            stream_id: self.stream_id,
            task,
        });
        let _ = self.waker.wake();
    }

    fn execute(&self, task: Box<dyn FnOnce() + Send>) {
        (self.execute)(task);
    }

    fn is_probably_open(&self) -> bool {
        // Same answer the old from_execute-based handle gave — no cheap
        // liveness flag threaded through yet (the driver thread owns that
        // state); a real one is future work, not a regression here.
        true
    }

    fn schedule_timer(&self, delay: Duration, callback: Box<dyn FnOnce() + Send>) -> TimerHandle {
        // Route through the driver's own timer queue (DriverCmd::
        // ScheduleTimer, already handled in drain_cmds) — the same
        // mechanism QuicStreamEndpoint::schedule_timer already uses, now
        // reachable from other threads too since this backend has a real
        // cmd_tx, unlike a bare from_execute closure.
        let cancelled = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&cancelled);
        let _ = self.cmd_tx.send(DriverCmd::ScheduleTimer {
            delay,
            callback,
            cancelled: flag,
        });
        let _ = self.waker.wake();
        TimerHandle::from_cancel(move || {
            cancelled.store(true, Ordering::Release);
        })
    }
}

/// Shared outbound/inbound queues between the stream endpoint and the driver.
pub(crate) struct StreamQueues {
    pub out: Vec<u8>,
    pub closed: bool,
    pub finish_write: bool,
    /// Set by [`QuicStreamEndpoint::abort`] to request an abrupt
    /// RESET_STREAM + STOP_SENDING (RFC 9000 §3.5/§3.6) instead of a
    /// graceful FIN. Consumed (taken) once by the driver's stream loop.
    pub reset_error_code: Option<u64>,
}

impl StreamQueues {
    pub fn new() -> Self {
        Self {
            out: Vec::new(),
            closed: false,
            finish_write: false,
            reset_error_code: None,
        }
    }
}

/// One bidirectional QUIC stream implementing [`Endpoint`].
pub struct QuicStreamEndpoint {
    stream_id: StreamId,
    conn: ConnectionHandle,
    local: SocketAddr,
    remote: SocketAddr,
    security: SecurityInfo,
    open: bool,
    closing: bool,
    queues: Arc<Mutex<StreamQueues>>,
    cmd_tx: std::sync::mpsc::Sender<DriverCmd>,
    waker: Arc<mio::Waker>,
    execute: Arc<dyn Fn(Box<dyn FnOnce() + Send>) + Send + Sync>,
    write_ready: Option<WriteReadyCallback>,
    read_paused: bool,
    /// Set by [`Endpoint::poke_handler`], consumed by the driver right
    /// after running the `DriverCmd::WithStream` task that set it — see
    /// [`Self::take_wants_poke`].
    wants_poke: bool,
}

impl QuicStreamEndpoint {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        stream_id: StreamId,
        conn: ConnectionHandle,
        local: SocketAddr,
        remote: SocketAddr,
        security: SecurityInfo,
        queues: Arc<Mutex<StreamQueues>>,
        cmd_tx: std::sync::mpsc::Sender<DriverCmd>,
        waker: Arc<mio::Waker>,
        execute: Arc<dyn Fn(Box<dyn FnOnce() + Send>) + Send + Sync>,
    ) -> Self {
        Self {
            stream_id,
            conn,
            local,
            remote,
            security,
            open: true,
            closing: false,
            queues,
            cmd_tx,
            waker,
            execute,
            write_ready: None,
            read_paused: false,
            wants_poke: false,
        }
    }

    pub(crate) fn is_read_paused(&self) -> bool {
        self.read_paused
    }

    /// Take-and-clear the poke flag set by [`Endpoint::poke_handler`] — the
    /// driver calls this right after running a `DriverCmd::WithStream` task,
    /// and if it comes back `true`, re-invokes the stream's protocol
    /// handler with an empty slice (mirroring the TCP reactor's
    /// `poke_handler`, which redelivers/re-calls `receive` with no new
    /// data so deferred replies queued from another thread's callback get
    /// flushed without waiting on the peer to send more bytes).
    pub(crate) fn take_wants_poke(&mut self) -> bool {
        std::mem::take(&mut self.wants_poke)
    }

    pub(crate) fn take_write_ready(&mut self) -> Option<WriteReadyCallback> {
        self.write_ready.take()
    }

    pub(crate) fn mark_closed(&mut self) {
        self.open = false;
        self.closing = false;
    }

    /// Refresh the cached remote address after a real connection migration
    /// (RFC 9000 §9) — `remote_addr()` would otherwise keep returning the
    /// address captured when this stream was opened.
    pub(crate) fn set_remote(&mut self, remote: SocketAddr) {
        self.remote = remote;
    }

    fn wake(&self) {
        let _ = self.waker.wake();
    }
}

impl Endpoint for QuicStreamEndpoint {
    fn send(&mut self, data: &[u8]) {
        if !self.open || self.closing {
            return;
        }
        {
            let mut q = self.queues.lock().unwrap();
            q.out.extend_from_slice(data);
        }
        let _ = self.cmd_tx.send(DriverCmd::StreamWritable {
            stream_id: self.stream_id,
        });
        self.wake();
    }

    fn is_open(&self) -> bool {
        self.open
    }

    fn is_closing(&self) -> bool {
        self.closing
    }

    fn close(&mut self) {
        if self.closing || !self.open {
            return;
        }
        self.closing = true;
        {
            let mut q = self.queues.lock().unwrap();
            q.finish_write = true;
            q.closed = true;
        }
        let _ = self.cmd_tx.send(DriverCmd::StreamClose {
            stream_id: self.stream_id,
        });
        self.wake();
    }

    fn abort(&mut self, error_code: u32) {
        if self.closing || !self.open {
            return;
        }
        self.closing = true;
        {
            let mut q = self.queues.lock().unwrap();
            q.reset_error_code = Some(error_code as u64);
            q.closed = true;
        }
        // Reuses the same wake-up command as a graceful close — the real
        // state (the reset request) lives in the shared queue; the driver
        // checks it on its next stream pass.
        let _ = self.cmd_tx.send(DriverCmd::StreamClose {
            stream_id: self.stream_id,
        });
        self.wake();
    }

    fn close_connection(&mut self, error_code: u32) {
        let _ = self.cmd_tx.send(DriverCmd::ConnectionClose {
            conn: self.conn,
            error_code: error_code as u64,
        });
        self.wake();
    }

    fn send_datagram(&mut self, payload: &[u8]) -> io::Result<()> {
        let _ = self.cmd_tx.send(DriverCmd::SendDatagram {
            conn: self.conn,
            payload: payload.to_vec(),
            stream_id: Some(self.stream_id),
        });
        self.wake();
        Ok(())
    }

    fn set_stream_priority(&mut self, priority: i32) {
        let _ = self.cmd_tx.send(DriverCmd::SetStreamPriority {
            conn: self.conn,
            stream_id: self.stream_id,
            priority,
        });
        self.wake();
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn remote_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.remote)
    }

    fn security_info(&self) -> &SecurityInfo {
        &self.security
    }

    fn start_tls(&mut self) -> Result<(), StartTlsError> {
        Err(StartTlsError::Unsupported)
    }

    fn pause_read(&mut self) {
        self.read_paused = true;
    }

    fn resume_read(&mut self) {
        self.read_paused = false;
        let _ = self.cmd_tx.send(DriverCmd::StreamReadable {
            stream_id: self.stream_id,
        });
        self.wake();
    }

    fn on_write_ready(&mut self, callback: Option<WriteReadyCallback>) {
        self.write_ready = callback;
    }

    fn poke_handler(&mut self) {
        self.wants_poke = true;
    }

    fn execute(&self, task: Box<dyn FnOnce() + Send>) {
        (self.execute)(task);
    }

    fn schedule_timer(&self, delay: Duration, callback: Box<dyn FnOnce() + Send>) -> TimerHandle {
        let cancelled = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&cancelled);
        let _ = self.cmd_tx.send(DriverCmd::ScheduleTimer {
            delay,
            callback,
            cancelled: flag,
        });
        self.wake();
        TimerHandle::from_cancel(move || {
            cancelled.store(true, Ordering::Release);
        })
    }

    fn handle(&self) -> ConnHandle {
        ConnHandle::from_backend(Arc::new(QuicStreamBackend {
            conn: self.conn,
            stream_id: self.stream_id,
            cmd_tx: self.cmd_tx.clone(),
            waker: Arc::clone(&self.waker),
            execute: Arc::clone(&self.execute),
        }))
    }
}
