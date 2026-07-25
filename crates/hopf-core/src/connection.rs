// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! TCP connection state implementing [`Endpoint`].

use std::io::{self, ErrorKind, Read, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use mio::net::TcpStream;
use mio::{Interest, Token};

use crate::bufpool::BufferPool;
use crate::cmd::{ReactorCmd, ReactorHandle};
use crate::connector::TcpConnParams;
use crate::endpoint::{Endpoint, TimerHandle, WriteReadyCallback};
use crate::error::StartTlsError;
use crate::handle::ConnHandle;
use crate::handler::ProtocolHandler;
use crate::listener::DEFAULT_BUFFER_SIZE;
use crate::security::SecurityInfo;
use crate::telemetry::TelemetryHook;
use crate::tls::{SharedTlsAcceptor, TlsSession};

pub(crate) struct TcpConnection {
    pub token: Token,
    pub stream: TcpStream,
    handler: Option<Box<dyn ProtocolHandler>>,
    /// Wire buffer (ciphertext when TLS is active, plaintext otherwise).
    net_in: Vec<u8>,
    net_out: Vec<u8>,
    /// Plaintext inbound when TLS is active.
    app_in: Vec<u8>,
    max_net_in: usize,
    max_net_out: usize,
    read_paused: bool,
    pub interest: Interest,
    pub registered: bool,
    open: bool,
    closing: bool,
    close_requested: bool,
    /// Nonblocking dial in progress — defer `connected` until SO_ERROR / peer_addr.
    connecting: bool,
    /// Cancel flag for the dial connect-timeout timer (`None` if no timer armed).
    connect_timeout_cancel: Option<Arc<AtomicBool>>,
    write_ready: Option<WriteReadyCallback>,
    local: SocketAddr,
    remote: SocketAddr,
    security: SecurityInfo,
    security_notified: bool,
    tls: Option<Box<dyn TlsSession>>,
    tls_acceptor: Option<SharedTlsAcceptor>,
    reactor: ReactorHandle,
    pool: Arc<BufferPool>,
    telemetry: Option<Arc<dyn TelemetryHook>>,
    pub interest_dirty: bool,
}

pub(crate) enum ReadOutcome {
    Bytes,
    Eof,
    WouldBlock,
}

pub(crate) enum WriteOutcome {
    Drained,
    WouldBlock,
    CloseAfterFlush,
    Closed,
}

impl TcpConnection {
    pub fn new(
        token: Token,
        stream: TcpStream,
        handler: Box<dyn ProtocolHandler>,
        params: TcpConnParams,
        reactor: ReactorHandle,
        pool: Arc<BufferPool>,
        connecting: bool,
        telemetry: Option<Arc<dyn TelemetryHook>>,
    ) -> io::Result<Self> {
        let remote = stream.peer_addr().unwrap_or(params.remote_hint);
        let local = stream
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
        let net_in = pool.acquire(DEFAULT_BUFFER_SIZE);
        let net_out = pool.acquire(DEFAULT_BUFFER_SIZE);
        let tls = if params.secure {
            if let Some(connector) = params.tls_connector.as_ref() {
                let name = params.server_name.as_deref().unwrap_or("localhost");
                Some(connector.connect(name)?)
            } else if let Some(acceptor) = params.tls_acceptor.as_ref() {
                Some(acceptor.accept())
            } else {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    "secure endpoint requires a TLS acceptor or connector",
                ));
            }
        } else {
            None
        };
        Ok(Self {
            token,
            stream,
            handler: Some(handler),
            net_in,
            net_out,
            app_in: Vec::new(),
            max_net_in: params.max_net_in,
            max_net_out: params.max_net_out,
            read_paused: false,
            interest: Interest::READABLE,
            registered: false,
            open: true,
            closing: false,
            close_requested: false,
            connecting,
            connect_timeout_cancel: None,
            write_ready: None,
            local,
            remote,
            security: SecurityInfo::plaintext(),
            security_notified: false,
            tls,
            tls_acceptor: params.tls_acceptor,
            reactor,
            pool,
            telemetry,
            interest_dirty: false,
        })
    }

    /// Complete a nonblocking dial if ready. Returns true once when TCP connect succeeds.
    pub fn poll_connect(&mut self) -> bool {
        if !self.connecting {
            return false;
        }
        match self.stream.take_error() {
            Ok(Some(e)) => {
                self.cancel_connect_timeout();
                self.call_error(&e);
                self.force_close();
                return false;
            }
            Ok(None) => {}
            Err(e) => {
                self.cancel_connect_timeout();
                self.call_error(&e);
                self.force_close();
                return false;
            }
        }
        match self.stream.peer_addr() {
            Ok(addr) => {
                self.remote = addr;
                if let Ok(local) = self.stream.local_addr() {
                    self.local = local;
                }
                self.connecting = false;
                self.cancel_connect_timeout();
                self.interest_dirty = true;
                true
            }
            Err(e) if e.kind() == ErrorKind::NotConnected || e.kind() == ErrorKind::WouldBlock => {
                false
            }
            Err(e) => {
                self.cancel_connect_timeout();
                self.call_error(&e);
                self.force_close();
                false
            }
        }
    }

    /// Whether a nonblocking dial is still in progress.
    pub fn is_connecting(&self) -> bool {
        self.connecting
    }

    /// Arm a connect-timeout cancel flag (reactor schedules the timer itself).
    pub fn set_connect_timeout_cancel(&mut self, cancel: Arc<AtomicBool>) {
        self.connect_timeout_cancel = Some(cancel);
    }

    /// Cancel any armed connect-timeout timer.
    pub fn cancel_connect_timeout(&mut self) {
        if let Some(flag) = self.connect_timeout_cancel.take() {
            flag.store(true, Ordering::Release);
        }
    }

    /// Fire connect timeout while still connecting (called from timer → WithConn).
    pub fn on_connect_timeout(&mut self) {
        if !self.connecting {
            return;
        }
        self.connect_timeout_cancel = None;
        let err = io::Error::new(ErrorKind::TimedOut, "TCP connect timed out");
        self.call_error(&err);
        self.force_close();
    }

    pub fn compute_interest(&self) -> Option<Interest> {
        if !self.open {
            return None;
        }
        if self.read_paused {
            if self.wants_write() {
                Some(Interest::WRITABLE)
            } else {
                None
            }
        } else {
            let mut i = Interest::READABLE;
            if self.wants_write() {
                i = i.add(Interest::WRITABLE);
            }
            Some(i)
        }
    }

    fn wants_write(&self) -> bool {
        self.connecting
            || !self.net_out.is_empty()
            || self.close_requested
            || self.tls.as_ref().is_some_and(|t| t.wants_write())
    }

    pub fn prepare_net_in(&mut self) -> io::Result<()> {
        let remaining_cap = self.net_in.capacity() - self.net_in.len();
        if remaining_cap >= DEFAULT_BUFFER_SIZE {
            return Ok(());
        }
        if self.net_in.len() >= self.max_net_in {
            return Err(io::Error::new(
                ErrorKind::OutOfMemory,
                "inbound buffer full",
            ));
        }
        let needed = (self.net_in.len() + DEFAULT_BUFFER_SIZE).min(self.max_net_in);
        let grow_to = needed.next_power_of_two().min(self.max_net_in).max(needed);
        if grow_to <= self.net_in.capacity() {
            return Ok(());
        }
        let mut new_buf = self.pool.acquire(grow_to);
        new_buf.clear();
        new_buf.extend_from_slice(&self.net_in);
        let old = std::mem::replace(&mut self.net_in, new_buf);
        self.pool.release(old);
        Ok(())
    }

    pub fn read_from_socket(&mut self) -> io::Result<ReadOutcome> {
        self.prepare_net_in()?;
        let cap = self.net_in.capacity();
        let len = self.net_in.len();
        unsafe {
            self.net_in.set_len(cap);
        }
        let result = self.stream.read(&mut self.net_in[len..]);
        match result {
            Ok(0) => {
                unsafe {
                    self.net_in.set_len(len);
                }
                Ok(ReadOutcome::Eof)
            }
            Ok(n) => {
                unsafe {
                    self.net_in.set_len(len + n);
                }
                Ok(ReadOutcome::Bytes)
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                unsafe {
                    self.net_in.set_len(len);
                }
                Ok(ReadOutcome::WouldBlock)
            }
            Err(e) => {
                unsafe {
                    self.net_in.set_len(len);
                }
                Err(e)
            }
        }
    }

    pub fn process_inbound(&mut self) {
        if self.tls.is_some() {
            if let Err(e) = self.process_tls_inbound() {
                self.call_error(&e);
                self.force_close();
            }
        } else {
            self.deliver_plaintext_buffer();
            // STARTTLS may have been invoked from receive with leftover ciphertext
            // already in net_in — process it without waiting for another read.
            if self.tls.is_some() && !self.net_in.is_empty() && self.open {
                if let Err(e) = self.process_tls_inbound() {
                    self.call_error(&e);
                    self.force_close();
                }
            }
        }
        self.interest_dirty = true;
    }

    fn process_tls_inbound(&mut self) -> io::Result<()> {
        // Feed ciphertext into the session.
        {
            let tls = self.tls.as_mut().unwrap();
            let mut slice = self.net_in.as_slice();
            while !slice.is_empty() {
                match tls.read_tls(&mut slice) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }
            let remaining = slice.len();
            let consumed = self.net_in.len() - remaining;
            if consumed > 0 {
                self.net_in.drain(..consumed);
            }
        }

        let progress = {
            let tls = self.tls.as_mut().unwrap();
            tls.process_new_packets()?
        };
        self.flush_tls_outbound()?;

        if progress.handshake_just_completed && !self.security_notified {
            self.security = self.tls.as_ref().unwrap().security_info();
            self.security_notified = true;
            self.call_security_established();
            if !self.open {
                return Ok(());
            }
        }

        // Drain plaintext into app_in.
        {
            let tls = self.tls.as_mut().unwrap();
            let mut tmp = [0u8; 16 * 1024];
            loop {
                match tls.read_plaintext(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => self.app_in.extend_from_slice(&tmp[..n]),
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }
        }

        self.deliver_app_in();
        Ok(())
    }

    fn deliver_app_in(&mut self) {
        if self.app_in.is_empty() {
            return;
        }
        let Some(mut handler) = self.handler.take() else {
            return;
        };
        let mut buf = std::mem::take(&mut self.app_in);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut slice = buf.as_slice();
            handler.receive(self, &mut slice);
            let remaining = slice.len();
            let consumed = buf.len() - remaining;
            if consumed > 0 {
                buf.drain(..consumed);
            }
        }));
        self.app_in = buf;
        self.handler = Some(handler);
        if let Err(payload) = outcome {
            eprintln!(
                "hopf: protocol handler panicked in receive on {}: {payload:?}",
                self.remote
            );
            self.force_close();
        }
    }

    fn deliver_plaintext_buffer(&mut self) {
        if self.net_in.is_empty() {
            return;
        }
        let Some(mut handler) = self.handler.take() else {
            return;
        };
        let mut buf = std::mem::take(&mut self.net_in);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut slice = buf.as_slice();
            handler.receive(self, &mut slice);
            let remaining = slice.len();
            let consumed = buf.len() - remaining;
            if consumed > 0 {
                buf.drain(..consumed);
            }
        }));
        self.net_in = buf;
        self.handler = Some(handler);
        if let Err(payload) = outcome {
            eprintln!(
                "hopf: protocol handler panicked in receive on {}: {payload:?}",
                self.remote
            );
            self.force_close();
        }
    }

    pub fn flush_tls_outbound(&mut self) -> io::Result<()> {
        let Some(tls) = self.tls.as_mut() else {
            return Ok(());
        };
        while tls.wants_write() {
            let before = self.net_out.len();
            // Ensure capacity for a TLS record.
            if self.net_out.capacity() - self.net_out.len() < 4096 {
                let grow_to = (self.net_out.len() + 16 * 1024)
                    .next_power_of_two()
                    .min(self.max_net_out)
                    .max(self.net_out.len() + 4096);
                if grow_to > self.max_net_out && self.net_out.len() >= self.max_net_out {
                    return Err(io::Error::new(
                        ErrorKind::OutOfMemory,
                        "outbound buffer full during TLS flush",
                    ));
                }
                if grow_to > self.net_out.capacity() {
                    let mut new_buf = self.pool.acquire(grow_to.min(self.max_net_out));
                    new_buf.clear();
                    new_buf.extend_from_slice(&self.net_out);
                    let old = std::mem::replace(&mut self.net_out, new_buf);
                    self.pool.release(old);
                }
            }
            match tls.write_tls(&mut self.net_out) {
                Ok(0) => break,
                Ok(_) => {
                    if self.net_out.len() == before {
                        break;
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
            if self.net_out.len() > self.max_net_out {
                return Err(io::Error::new(
                    ErrorKind::OutOfMemory,
                    "outbound buffer overflow during TLS flush",
                ));
            }
        }
        self.interest_dirty = true;
        Ok(())
    }

    pub fn write_to_socket(&mut self) -> io::Result<WriteOutcome> {
        let _ = self.flush_tls_outbound();
        if self.connecting {
            self.interest_dirty = true;
            return Ok(WriteOutcome::WouldBlock);
        }
        while !self.net_out.is_empty() {
            match self.stream.write(&self.net_out) {
                Ok(0) => {
                    return Err(io::Error::new(ErrorKind::WriteZero, "write returned 0"));
                }
                Ok(n) => {
                    self.net_out.drain(..n);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    self.interest_dirty = true;
                    return Ok(WriteOutcome::WouldBlock);
                }
                Err(e) => return Err(e),
            }
        }
        if self.close_requested {
            self.interest_dirty = true;
            return Ok(WriteOutcome::CloseAfterFlush);
        }
        if let Some(cb) = self.write_ready.take() {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                cb(self);
            }));
            if let Err(payload) = outcome {
                eprintln!(
                    "hopf: on_write_ready panicked on {}: {payload:?}",
                    self.remote
                );
                self.force_close();
                return Ok(WriteOutcome::Closed);
            }
        }
        self.interest_dirty = true;
        Ok(WriteOutcome::Drained)
    }

    pub fn call_connected(&mut self) {
        let Some(mut handler) = self.handler.take() else {
            return;
        };
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            handler.connected(self);
        }));
        self.handler = Some(handler);
        if let Err(payload) = outcome {
            eprintln!(
                "hopf: protocol handler panicked in connected on {}: {payload:?}",
                self.remote
            );
            self.force_close();
        }
        self.interest_dirty = true;
    }

    pub fn call_security_established(&mut self) {
        let info = self.security.clone();
        let Some(mut handler) = self.handler.take() else {
            return;
        };
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            handler.security_established(self, &info);
        }));
        self.handler = Some(handler);
        if let Err(payload) = outcome {
            eprintln!(
                "hopf: protocol handler panicked in security_established on {}: {payload:?}",
                self.remote
            );
            self.force_close();
        }
        self.interest_dirty = true;
    }

    pub fn call_disconnected(&mut self) {
        let Some(mut handler) = self.handler.take() else {
            return;
        };
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            handler.disconnected(self);
        }));
        self.handler = Some(handler);
    }

    pub fn call_error(&mut self, err: &io::Error) {
        if let Some(t) = &self.telemetry {
            t.on_error(Some(self.remote), &err.to_string());
        }
        let Some(mut handler) = self.handler.take() else {
            return;
        };
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            handler.error(self, err);
        }));
        self.handler = Some(handler);
    }

    pub fn force_close(&mut self) {
        self.cancel_connect_timeout();
        self.open = false;
        self.closing = true;
        self.close_requested = true;
        self.net_out.clear();
        self.interest_dirty = true;
    }

    pub fn finish_close(&mut self) {
        self.open = false;
        self.closing = true;
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
        self.call_disconnected();
        if let Some(t) = &self.telemetry {
            t.on_close(self.remote);
        }
    }

    pub fn release_buffers(&mut self) {
        let inn = std::mem::take(&mut self.net_in);
        let out = std::mem::take(&mut self.net_out);
        self.pool.release(inn);
        self.pool.release(out);
        self.app_in.clear();
    }

    fn append_out(&mut self, data: &[u8]) {
        if !self.open || self.closing {
            return;
        }
        let new_len = self.net_out.len() + data.len();
        if new_len > self.max_net_out {
            eprintln!(
                "hopf: outbound buffer overflow on {} ({} > {})",
                self.remote, new_len, self.max_net_out
            );
            self.force_close();
            return;
        }
        if new_len > self.net_out.capacity() {
            let grow_to = new_len
                .next_power_of_two()
                .min(self.max_net_out)
                .max(new_len);
            let mut new_buf = self.pool.acquire(grow_to);
            new_buf.clear();
            new_buf.extend_from_slice(&self.net_out);
            let old = std::mem::replace(&mut self.net_out, new_buf);
            self.pool.release(old);
        }
        self.net_out.extend_from_slice(data);
        self.interest_dirty = true;
    }

    fn send_plaintext(&mut self, data: &[u8]) {
        if !self.open || self.closing {
            return;
        }
        if let Some(tls) = self.tls.as_mut() {
            let mut offset = 0;
            while offset < data.len() {
                match tls.write_plaintext(&data[offset..]) {
                    Ok(0) => break,
                    Ok(n) => offset += n,
                    Err(e) => {
                        eprintln!("hopf: TLS write_plaintext failed on {}: {e}", self.remote);
                        self.force_close();
                        return;
                    }
                }
            }
            if let Err(e) = self.flush_tls_outbound() {
                eprintln!("hopf: TLS flush failed on {}: {e}", self.remote);
                self.force_close();
            }
        } else {
            self.append_out(data);
        }
    }
}

impl Endpoint for TcpConnection {
    fn send(&mut self, data: &[u8]) {
        self.send_plaintext(data);
    }

    fn is_open(&self) -> bool {
        self.open
    }

    fn is_closing(&self) -> bool {
        self.closing
    }

    fn close(&mut self) {
        if self.closing {
            return;
        }
        self.closing = true;
        self.close_requested = true;
        if let Some(tls) = self.tls.as_mut() {
            tls.send_close_notify();
            let _ = self.flush_tls_outbound();
        }
        self.interest_dirty = true;
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
        if self.tls.is_some() || self.security.is_secure() {
            return Err(StartTlsError::AlreadySecure);
        }
        let Some(acceptor) = self.tls_acceptor.clone() else {
            return Err(StartTlsError::Unsupported);
        };
        self.tls = Some(acceptor.accept());
        self.security_notified = false;
        self.interest_dirty = true;
        Ok(())
    }

    fn start_client_tls(
        &mut self,
        connector: crate::tls::SharedTlsConnector,
        server_name: &str,
    ) -> Result<(), StartTlsError> {
        if self.tls.is_some() || self.security.is_secure() {
            return Err(StartTlsError::AlreadySecure);
        }
        let session = connector.connect(server_name).map_err(StartTlsError::Io)?;
        self.tls = Some(session);
        self.security_notified = false;
        self.interest_dirty = true;
        Ok(())
    }

    fn pause_read(&mut self) {
        if self.read_paused {
            return;
        }
        self.read_paused = true;
        self.interest_dirty = true;
    }

    fn resume_read(&mut self) {
        if !self.read_paused {
            return;
        }
        self.read_paused = false;
        self.interest_dirty = true;
    }

    fn on_write_ready(&mut self, callback: Option<WriteReadyCallback>) {
        self.write_ready = callback;
    }

    fn execute(&self, task: Box<dyn FnOnce() + Send>) {
        self.reactor.execute(task);
    }

    fn schedule_timer(&self, delay: Duration, callback: Box<dyn FnOnce() + Send>) -> TimerHandle {
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancel_flag = Arc::clone(&cancelled);
        self.reactor.send(ReactorCmd::ScheduleTimer {
            delay,
            callback,
            cancelled: cancel_flag,
        });
        TimerHandle::new(move || {
            cancelled.store(true, Ordering::Release);
        })
    }

    fn handle(&self) -> ConnHandle {
        ConnHandle::new(self.reactor.clone(), self.token)
    }

    fn fail(&mut self, err: io::Error) {
        self.call_error(&err);
        self.force_close();
    }

    fn poke_handler(&mut self) {
        if !self.open {
            return;
        }
        // Redeliver buffered residual first (bytes the handler left
        // unconsumed while paused); otherwise call receive with no data so
        // deferred replies / queued commands can be flushed.
        if self.tls.is_some() {
            if !self.app_in.is_empty() {
                self.deliver_app_in();
                return;
            }
        } else if !self.net_in.is_empty() {
            self.deliver_plaintext_buffer();
            return;
        }
        let Some(mut handler) = self.handler.take() else {
            // Re-entrant call from inside `receive` — nothing to do.
            return;
        };
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut slice: &[u8] = &[];
            handler.receive(self, &mut slice);
        }));
        self.handler = Some(handler);
        if let Err(payload) = outcome {
            eprintln!(
                "hopf: protocol handler panicked in receive on {}: {payload:?}",
                self.remote
            );
            self.force_close();
        }
    }
}
