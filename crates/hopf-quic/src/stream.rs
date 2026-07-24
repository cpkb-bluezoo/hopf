// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! [`QuicStreamEndpoint`] — one bidirectional QUIC stream as an [`Endpoint`].

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use quinn_proto::StreamId;
use hopf_core::{
    ConnHandle, Endpoint, SecurityInfo, StartTlsError, TimerHandle, WriteReadyCallback,
};

use crate::driver::DriverCmd;

/// Shared outbound/inbound queues between the stream endpoint and the driver.
pub(crate) struct StreamQueues {
    pub out: Vec<u8>,
    pub closed: bool,
    pub finish_write: bool,
}

impl StreamQueues {
    pub fn new() -> Self {
        Self {
            out: Vec::new(),
            closed: false,
            finish_write: false,
        }
    }
}

/// One bidirectional QUIC stream implementing [`Endpoint`].
pub struct QuicStreamEndpoint {
    stream_id: StreamId,
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
}

impl QuicStreamEndpoint {
    pub(crate) fn new(
        stream_id: StreamId,
        local: SocketAddr,
        remote: SocketAddr,
        queues: Arc<Mutex<StreamQueues>>,
        cmd_tx: std::sync::mpsc::Sender<DriverCmd>,
        waker: Arc<mio::Waker>,
        execute: Arc<dyn Fn(Box<dyn FnOnce() + Send>) + Send + Sync>,
    ) -> Self {
        Self {
            stream_id,
            local,
            remote,
            security: SecurityInfo::secure(Some(b"h3".to_vec()), Some("TLSv1.3".into()), None),
            open: true,
            closing: false,
            queues,
            cmd_tx,
            waker,
            execute,
            write_ready: None,
            read_paused: false,
        }
    }

    pub(crate) fn is_read_paused(&self) -> bool {
        self.read_paused
    }

    pub(crate) fn take_write_ready(&mut self) -> Option<WriteReadyCallback> {
        self.write_ready.take()
    }

    pub(crate) fn mark_closed(&mut self) {
        self.open = false;
        self.closing = false;
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
        ConnHandle::from_execute(Arc::clone(&self.execute))
    }
}
