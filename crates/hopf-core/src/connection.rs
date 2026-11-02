// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! TCP connection state implementing [`Endpoint`].

use std::io::{self, ErrorKind, Read, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use mio::event::Source;
use mio::net::{TcpStream, UnixStream};
use loopbuf::LoopBuf;
use mio::{Interest, Registry, Token};

use crate::bufpool::BufferPool;
use crate::cmd::{ReactorCmd, ReactorHandle};
use crate::connector::TcpConnParams;
use crate::endpoint::{Endpoint, TimerHandle, WriteReadyCallback};
use crate::error::StartTlsError;
use crate::handle::{ConnHandle, Task};
use crate::handler::ProtocolHandler;
use crate::listener::DEFAULT_BUFFER_SIZE;
use crate::peer_addr::PeerAddr;
use crate::proxy_protocol::{self, ProxyHeaderOutcome};
use crate::security::SecurityInfo;
use crate::telemetry::{emit_connection_log, LogLevel, LogRecord, TelemetryHook};
use crate::tls::{SharedTlsAcceptor, TlsProtocolError, TlsRecordSink, TlsVariant, VerifyRequest, VerifyResult};

/// Either half of a stream-oriented connection — TCP or UNIX domain socket.
/// `std::net::TcpStream` and `std::os::unix::net::UnixStream` don't share a
/// common trait for the handful of operations [`TcpConnection`] needs
/// ([`Read`]/[`Write`]/[`mio::event::Source`], plus `peer_addr`/`local_addr`/
/// `take_error`/`shutdown`), so this wraps whichever one a connection is
/// actually running over and delegates.
pub(crate) enum Stream {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl Stream {
    pub(crate) fn peer_addr(&self) -> io::Result<PeerAddr> {
        match self {
            Stream::Tcp(s) => s.peer_addr().map(PeerAddr::Inet),
            Stream::Unix(s) => s
                .peer_addr()
                .map(|a| PeerAddr::Unix(a.as_pathname().map(|p| p.to_path_buf()))),
        }
    }

    pub(crate) fn local_addr(&self) -> io::Result<PeerAddr> {
        match self {
            Stream::Tcp(s) => s.local_addr().map(PeerAddr::Inet),
            Stream::Unix(s) => s
                .local_addr()
                .map(|a| PeerAddr::Unix(a.as_pathname().map(|p| p.to_path_buf()))),
        }
    }

    pub(crate) fn take_error(&self) -> io::Result<Option<io::Error>> {
        match self {
            Stream::Tcp(s) => s.take_error(),
            Stream::Unix(s) => s.take_error(),
        }
    }

    pub(crate) fn shutdown(&self, how: std::net::Shutdown) -> io::Result<()> {
        match self {
            Stream::Tcp(s) => s.shutdown(how),
            Stream::Unix(s) => s.shutdown(how),
        }
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Tcp(s) => s.read(buf),
            Stream::Unix(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Tcp(s) => s.write(buf),
            Stream::Unix(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Tcp(s) => s.flush(),
            Stream::Unix(s) => s.flush(),
        }
    }
}

impl Source for Stream {
    fn register(&mut self, registry: &Registry, token: Token, interests: Interest) -> io::Result<()> {
        match self {
            Stream::Tcp(s) => s.register(registry, token, interests),
            Stream::Unix(s) => s.register(registry, token, interests),
        }
    }

    fn reregister(&mut self, registry: &Registry, token: Token, interests: Interest) -> io::Result<()> {
        match self {
            Stream::Tcp(s) => s.reregister(registry, token, interests),
            Stream::Unix(s) => s.reregister(registry, token, interests),
        }
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        match self {
            Stream::Tcp(s) => s.deregister(registry),
            Stream::Unix(s) => s.deregister(registry),
        }
    }
}

impl From<TcpStream> for Stream {
    fn from(s: TcpStream) -> Self {
        Stream::Tcp(s)
    }
}

impl From<UnixStream> for Stream {
    fn from(s: UnixStream) -> Self {
        Stream::Unix(s)
    }
}

pub(crate) struct TcpConnection {
    pub token: Token,
    pub stream: Stream,
    handler: Option<Box<dyn ProtocolHandler>>,
    /// Wire ring (ciphertext when TLS is active, plaintext otherwise). Its
    /// size is fixed for the life of the connection.
    net_in: LoopBuf,
    net_out: Vec<u8>,
    /// Plaintext inbound when TLS is active: a ring too, fed from `net_in`
    /// only while it has room for what the next ciphertext can decrypt to.
    app_in: LoopBuf,
    max_net_out: usize,
    read_paused: bool,
    pub interest: Interest,
    pub registered: bool,
    open: bool,
    closing: bool,
    close_requested: bool,
    /// Why the connection was force-closed from inside a callback, where the
    /// handler is out of the connection and cannot be told yet; delivered by
    /// [`Self::finish_close`] ahead of `disconnected`.
    close_error: Option<io::Error>,
    /// Nonblocking dial in progress — defer `connected` until SO_ERROR / peer_addr.
    connecting: bool,
    /// Cancel flag for the dial connect-timeout timer (`None` if no timer armed).
    connect_timeout_cancel: Option<Arc<AtomicBool>>,
    write_ready: Option<WriteReadyCallback>,
    local: PeerAddr,
    remote: PeerAddr,
    /// Set from `TcpConnParams::expect_proxy_protocol` at construction;
    /// cleared once a PROXY protocol header has been parsed off the front
    /// of `net_in` and `remote` rewritten from it. While true, no bytes in
    /// `net_in` are handed to TLS or the protocol handler.
    proxy_protocol_pending: bool,
    security: SecurityInfo,
    security_notified: bool,
    tls: Option<TlsVariant>,
    tls_acceptor: Option<SharedTlsAcceptor>,
    reactor: ReactorHandle,
    pool: Arc<BufferPool>,
    telemetry: Option<Arc<dyn TelemetryHook>>,
    pub interest_dirty: bool,
    /// Mirrors `open`, but lock-free and cloneable so a [`ConnHandle`] can
    /// cheaply check liveness from any thread without hopping onto the
    /// reactor — see [`ConnHandle::is_probably_open`].
    open_flag: Arc<AtomicBool>,
}

/// What a ring is made of when the real one is lent to a handler.
fn placeholder_ring() -> LoopBuf {
    LoopBuf::with_capacity(1)
}

/// The smallest inbound ring a connection gets: a TLS record is up to 16 KiB
/// and the ring must hold one whole.
const MIN_NET_IN_BYTES: usize = 32 * 1024;

/// Size of the plaintext ring of a connection that has TLS.
const APP_IN_BYTES: usize = 64 * 1024;

/// Room the plaintext ring must keep free before the next record is
/// decrypted into it: a record carries at most 16 KiB of plaintext.
const TLS_PLAINTEXT_RESERVE: usize = 16 * 1024 + 512;

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

/// What happened during one `TlsRecordEngine` pump call — recorded by
/// [`TlsSinkAdapter`] while `net_out`/`app_in` are borrowed, then applied by
/// [`TcpConnection::apply_tls_outcome`] once that borrow ends (mirroring
/// `deliver_app_in`'s take-then-restore pattern elsewhere in this file).
#[derive(Default)]
struct TlsPumpOutcome {
    established: Option<SecurityInfo>,
    error: Option<String>,
    peer_closed: bool,
    verification_id: Option<u64>,
    /// Plaintext arrived that the plaintext ring had no room for.
    app_in_overflow: bool,
}

/// Bridges [`TlsRecordEngine`]'s sink events onto `TcpConnection`'s buffers —
/// ciphertext and decrypted application data are pushed straight into
/// `net_out`/`app_in`; everything else is recorded into `outcome` for the
/// caller to act on once this adapter's borrow ends (handler callbacks need
/// `&mut TcpConnection` as a whole, which this partial borrow can't offer).
struct TlsSinkAdapter<'a> {
    net_out: &'a mut Vec<u8>,
    app_in: &'a mut LoopBuf,
    outcome: &'a mut TlsPumpOutcome,
}

impl TlsRecordSink for TlsSinkAdapter<'_> {
    fn ciphertext_ready(&mut self, data: &[u8]) {
        self.net_out.extend_from_slice(data);
    }

    fn application_data(&mut self, plaintext: &[u8]) {
        if self.app_in.extend_from_slice(plaintext) < plaintext.len() {
            self.outcome.app_in_overflow = true;
        }
    }

    fn handshake_complete(&mut self, info: SecurityInfo) {
        self.outcome.established = Some(info);
    }

    fn verification_requested(&mut self, req: VerifyRequest) {
        self.outcome.verification_id = Some(req.id);
    }

    fn protocol_error(&mut self, err: TlsProtocolError) {
        self.outcome.error = Some(err.message);
    }

    fn peer_closed(&mut self) {
        self.outcome.peer_closed = true;
    }
}

impl TcpConnection {
    // TCP connection constructor; each parameter is an independently-configurable handshake/socket setting.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        token: Token,
        stream: Stream,
        handler: Box<dyn ProtocolHandler>,
        params: TcpConnParams,
        reactor: ReactorHandle,
        pool: Arc<BufferPool>,
        connecting: bool,
        telemetry: Option<Arc<dyn TelemetryHook>>,
    ) -> io::Result<Self> {
        let remote = stream
            .peer_addr()
            .unwrap_or_else(|_| params.remote_hint.clone());
        let local = stream
            .local_addr()
            .unwrap_or_else(|_| PeerAddr::Inet(SocketAddr::from(([0, 0, 0, 0], 0))));
        let net_in = pool.acquire_ring(params.max_net_in.max(MIN_NET_IN_BYTES));
        let net_out = pool.acquire(DEFAULT_BUFFER_SIZE);
        let tls = if params.secure {
            if let Some(connector) = params.tls_connector.as_ref() {
                let name = params.server_name.as_deref().ok_or_else(|| {
                    io::Error::new(
                        ErrorKind::InvalidInput,
                        "TLS client connector requires server_name (SNI) to be set",
                    )
                })?;
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
        let has_tls = tls.is_some();
        let app_in = if has_tls {
            pool.acquire_ring(APP_IN_BYTES)
        } else {
            placeholder_ring()
        };
        let mut conn = Self {
            token,
            stream,
            handler: Some(handler),
            net_in,
            net_out,
            app_in,
            max_net_out: params.max_net_out,
            read_paused: false,
            interest: Interest::READABLE,
            registered: false,
            open: true,
            closing: false,
            close_requested: false,
            close_error: None,
            connecting,
            connect_timeout_cancel: None,
            write_ready: None,
            local,
            remote,
            proxy_protocol_pending: params.expect_proxy_protocol,
            security: SecurityInfo::plaintext(),
            security_notified: false,
            tls,
            tls_acceptor: params.tls_acceptor,
            reactor,
            pool,
            telemetry,
            interest_dirty: false,
            open_flag: Arc::new(AtomicBool::new(true)),
        };
        if has_tls {
            // Client role emits ClientHello here; server role is a no-op until
            // ciphertext arrives (HandshakeEngine::start no-ops for the server).
            conn.pump_tls_start();
        }
        Ok(conn)
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
        if self.read_paused || self.inbound_backed_up() {
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
        // TlsRecordEngine pushes ciphertext straight into net_out as it's
        // produced (sink-based, unlike the old pull-based TlsSession::write_tls),
        // so net_out already reflects everything pending — no separate check needed.
        self.connecting || !self.net_out.is_empty() || self.close_requested || self.write_ready.is_some()
    }

    /// Gives the plaintext ring a real size once TLS is on the connection.
    fn ensure_app_in(&mut self) {
        if self.app_in.capacity() < APP_IN_BYTES {
            let old = std::mem::replace(&mut self.app_in, self.pool.acquire_ring(APP_IN_BYTES));
            debug_assert!(old.is_empty());
        }
    }

    /// Reading stops while the ring holds as much ciphertext as it can and
    /// the plaintext ring cannot take more of it: the handler is behind.
    fn inbound_backed_up(&self) -> bool {
        self.tls.is_some() && self.net_in.is_full()
    }

    pub fn read_from_socket(&mut self) -> io::Result<ReadOutcome> {
        if self.net_in.is_full() {
            // Full after the handler has had its turn. With TLS the handler
            // may simply be behind (backpressure: read again once it has
            // caught up); otherwise it left a whole ring's worth unconsumed,
            // which is a token the ring can never hold.
            if self.inbound_backed_up() {
                return Ok(ReadOutcome::WouldBlock);
            }
            return Err(io::Error::new(
                ErrorKind::OutOfMemory,
                "inbound buffer full",
            ));
        }
        let (spare, _) = self.net_in.spare_capacity_mut();
        match self.stream.read(spare) {
            Ok(0) => Ok(ReadOutcome::Eof),
            Ok(n) => {
                self.net_in.commit_write(n);
                Ok(ReadOutcome::Bytes)
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(ReadOutcome::WouldBlock),
            Err(e) => Err(e),
        }
    }

    pub fn process_inbound(&mut self) {
        if self.proxy_protocol_pending {
            if let Err(e) = self.process_proxy_protocol() {
                self.call_error(&e);
                self.force_close();
                self.interest_dirty = true;
                return;
            }
            if self.proxy_protocol_pending {
                // Header not fully buffered yet — wait for more bytes
                // before treating anything in `net_in` as TLS/plaintext.
                self.interest_dirty = true;
                return;
            }
        }
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

    /// Try to consume a PROXY protocol header off the front of `net_in`.
    /// Leaves `proxy_protocol_pending` set (and `net_in` untouched) if the
    /// header hasn't fully arrived yet; clears it and rewrites `remote`
    /// once one has. Runs strictly before any TLS/plaintext processing, so
    /// this must never look at or consume bytes belonging to the
    /// connection's real traffic.
    fn process_proxy_protocol(&mut self) -> io::Result<()> {
        // Nothing has been consumed yet, so the ring has not wrapped.
        let (header, _) = self.net_in.readable_spans();
        match proxy_protocol::try_parse_proxy_header(header)? {
            ProxyHeaderOutcome::Incomplete => Ok(()),
            ProxyHeaderOutcome::Parsed { consumed, peer } => {
                self.net_in.advance(consumed);
                if let Some(peer) = peer {
                    self.remote = peer;
                }
                self.proxy_protocol_pending = false;
                Ok(())
            }
        }
    }

    /// Feeds the TLS engine the records in `net_in` one at a time, as long as
    /// the plaintext ring has room for what one may decrypt to, handing the
    /// plaintext to the handler after each.
    fn process_tls_inbound(&mut self) -> io::Result<()> {
        loop {
            if self.app_in.spare_len() < TLS_PLAINTEXT_RESERVE || self.net_in.is_empty() {
                break;
            }
            let mut outcome = TlsPumpOutcome::default();
            let consumed = {
                let tls = self.tls.as_mut().expect("process_tls_inbound called with tls active");
                let mut adapter = TlsSinkAdapter {
                    net_out: &mut self.net_out,
                    app_in: &mut self.app_in,
                    outcome: &mut outcome,
                };
                tls.feed_ciphertext(&mut self.net_in, &mut adapter)
            };

            // Chain verification: this pass doesn't wire an async StorageExecutor
            // gate, so any trust decision must already be baked into the engine's
            // HandshakeConfig::trust_store (resolved inline before this fires - see
            // HandshakeEngine::on_certificate) or the connector is deliberately
            // insecure (crate::tls::insecure_connector). Either way, resolving the
            // gate here is always safe: a trust_store-backed verification has
            // already settled verify_pending by the time we get here, making this
            // call an inert no-op; only the insecure/no-trust_store case actually
            // needs it to unblock the handshake.
            if let Some(id) = outcome.verification_id.take() {
                let tls = self.tls.as_mut().expect("process_tls_inbound called with tls active");
                let mut adapter = TlsSinkAdapter {
                    net_out: &mut self.net_out,
                    app_in: &mut self.app_in,
                    outcome: &mut outcome,
                };
                tls.feed_verification_result(VerifyResult { id, ok: true }, &mut adapter);
            }

            self.apply_tls_outcome(outcome)?;
            if !self.open || !consumed {
                break;
            }
        }
        if self.net_in.is_empty() {
            self.net_in.clear();
        }
        Ok(())
    }

    fn apply_tls_outcome(&mut self, outcome: TlsPumpOutcome) -> io::Result<()> {
        if let Some(msg) = outcome.error {
            return Err(io::Error::new(ErrorKind::InvalidData, msg));
        }
        if outcome.app_in_overflow {
            return Err(io::Error::new(
                ErrorKind::OutOfMemory,
                "plaintext buffer overflow",
            ));
        }
        if self.net_out.len() > self.max_net_out {
            return Err(io::Error::new(ErrorKind::OutOfMemory, "outbound buffer overflow during TLS flush"));
        }
        if let Some(info) = outcome.established {
            if !self.security_notified {
                self.security = info;
                self.security_notified = true;
                self.call_security_established();
                if !self.open {
                    return Ok(());
                }
            }
        }
        if outcome.peer_closed && !self.closing {
            self.closing = true;
            self.close_requested = true;
        }
        self.interest_dirty = true;
        self.deliver_app_in();
        Ok(())
    }

    /// Pump `HandshakeEngine::start` through the active TLS engine — client
    /// role emits ClientHello into `net_out`; server role no-ops until
    /// ciphertext arrives. Shared by `TcpConnection::new`, `start_tls`, and
    /// `start_client_tls`.
    fn pump_tls_start(&mut self) {
        let mut outcome = TlsPumpOutcome::default();
        {
            let tls = self.tls.as_mut().expect("pump_tls_start called with tls active");
            let mut adapter = TlsSinkAdapter {
                net_out: &mut self.net_out,
                app_in: &mut self.app_in,
                outcome: &mut outcome,
            };
            tls.start(&mut adapter);
        }
        let _ = self.apply_tls_outcome(outcome);
    }

    fn deliver_app_in(&mut self) {
        if self.app_in.is_empty() {
            return;
        }
        let Some(mut handler) = self.handler.take() else {
            return;
        };
        let mut ring = std::mem::replace(&mut self.app_in, placeholder_ring());
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            handler.receive(self, &mut ring);
        }));
        if ring.is_empty() {
            // Back to the start, so the same few pages are used.
            ring.clear();
        }
        self.app_in = ring;
        self.handler = Some(handler);
        self.after_receive(outcome);
    }

    fn deliver_plaintext_buffer(&mut self) {
        if self.net_in.is_empty() {
            return;
        }
        let Some(mut handler) = self.handler.take() else {
            return;
        };
        let mut ring = std::mem::replace(&mut self.net_in, placeholder_ring());
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            handler.receive(self, &mut ring);
        }));
        if ring.is_empty() {
            ring.clear();
        }
        self.net_in = ring;
        self.handler = Some(handler);
        self.after_receive(outcome);
    }

    fn after_receive(&mut self, outcome: std::thread::Result<()>) {
        if let Err(payload) = outcome {
            self.log_runtime_error(
                "connection.handler.panic",
                format!(
                    "protocol handler panicked in receive on {}: {payload:?}",
                    self.remote
                ),
            );
            self.force_close();
        }
    }

    pub fn write_to_socket(&mut self) -> io::Result<WriteOutcome> {
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
                self.log_runtime_error(
                    "connection.write_ready.panic",
                    format!("on_write_ready panicked on {}: {payload:?}", self.remote),
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
            self.log_runtime_error(
                "connection.handler.panic",
                format!(
                    "protocol handler panicked in connected on {}: {payload:?}",
                    self.remote
                ),
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
            self.log_runtime_error(
                "connection.handler.panic",
                format!(
                    "protocol handler panicked in security_established on {}: {payload:?}",
                    self.remote
                ),
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
            t.on_error(Some(self.remote.clone()), &err.to_string());
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
        self.open_flag.store(false, Ordering::Release);
        self.closing = true;
        self.close_requested = true;
        self.net_out.clear();
        self.interest_dirty = true;
    }

    /// Force-close for a failure the handler must hear about. This runs
    /// while the handler is mid-callback (it is out of the connection), so
    /// the error is held for [`Self::finish_close`] rather than delivered
    /// here. The first reason wins.
    fn close_with_error(&mut self, err: io::Error) {
        if self.close_error.is_none() {
            self.close_error = Some(err);
        }
        self.force_close();
    }

    pub fn finish_close(&mut self) {
        self.open = false;
        self.open_flag.store(false, Ordering::Release);
        self.closing = true;
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
        if let Some(err) = self.close_error.take() {
            self.call_error(&err);
        }
        self.call_disconnected();
        if let Some(t) = &self.telemetry {
            t.on_close(self.remote.clone());
        }
    }

    pub fn release_buffers(&mut self) {
        let inn = std::mem::replace(&mut self.net_in, placeholder_ring());
        let out = std::mem::take(&mut self.net_out);
        self.pool.release_ring(inn);
        self.pool.release(out);
        let app = std::mem::replace(&mut self.app_in, placeholder_ring());
        self.pool.release_ring(app);
    }

    fn append_out(&mut self, data: &[u8]) {
        if !self.open || self.closing {
            return;
        }
        let new_len = self.net_out.len() + data.len();
        if new_len > self.max_net_out {
            let message = format!(
                "outbound buffer overflow on {} ({new_len} > {})",
                self.remote, self.max_net_out
            );
            self.log_runtime_error("connection.outbound.overflow", message.clone());
            self.close_with_error(io::Error::new(ErrorKind::OutOfMemory, message));
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
        if self.tls.is_some() {
            let mut outcome = TlsPumpOutcome::default();
            {
                let tls = self.tls.as_mut().expect("checked above");
                let mut adapter = TlsSinkAdapter {
                    net_out: &mut self.net_out,
                    app_in: &mut self.app_in,
                    outcome: &mut outcome,
                };
                tls.send_application_data(data, &mut adapter);
            }
            if let Err(e) = self.apply_tls_outcome(outcome) {
                self.log_runtime_error(
                    "connection.tls.send_failed",
                    format!("TLS send failed on {}: {e}", self.remote),
                );
                self.close_with_error(e);
            }
        } else {
            self.append_out(data);
        }
    }

    fn log_runtime_error(&self, name: &str, message: String) {
        emit_connection_log(
            self.telemetry.as_ref(),
            LogRecord::new(LogLevel::Error, name)
                .with_scope("hopf-core")
                .with_body(message),
        );
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
            let mut outcome = TlsPumpOutcome::default();
            let mut adapter = TlsSinkAdapter {
                net_out: &mut self.net_out,
                app_in: &mut self.app_in,
                outcome: &mut outcome,
            };
            tls.send_close_notify(&mut adapter);
        }
        self.interest_dirty = true;
    }

    fn local_addr(&self) -> io::Result<PeerAddr> {
        Ok(self.local.clone())
    }

    fn remote_addr(&self) -> io::Result<PeerAddr> {
        Ok(self.remote.clone())
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
        self.ensure_app_in();
        self.security_notified = false;
        self.interest_dirty = true;
        self.pump_tls_start();
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
        let engine = connector.connect(server_name).map_err(StartTlsError::Io)?;
        self.tls = Some(engine);
        self.ensure_app_in();
        self.security_notified = false;
        self.interest_dirty = true;
        self.pump_tls_start();
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
        // A registered callback needs a write event to run it, even when there
        // is nothing buffered to provoke one.
        self.interest_dirty = true;
    }

    fn execute(&self, task: Task) {
        self.reactor.execute(task);
    }

    fn schedule_timer(&self, delay: Duration, callback: Task) -> TimerHandle {
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
        ConnHandle::new(self.reactor.clone(), self.token, Arc::clone(&self.open_flag))
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
            if !self.app_in.is_empty() || !self.net_in.is_empty() {
                // Plaintext the handler left, then the ciphertext that
                // waited for room to decrypt into.
                self.deliver_app_in();
                if self.open && !self.net_in.is_empty() {
                    if let Err(e) = self.process_tls_inbound() {
                        self.call_error(&e);
                        self.force_close();
                    }
                }
                self.interest_dirty = true;
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
            let mut empty = placeholder_ring();
            handler.receive(self, &mut empty);
        }));
        self.handler = Some(handler);
        self.after_receive(outcome);
    }
}

#[cfg(all(test, feature = "integration"))]
mod tests {
    use super::*;
    use crate::handler::NopHandler;
    use crate::reactor::Reactor;
    use crate::tls::TlsVariant;
    use std::net::TcpListener as StdTcpListener;
    use std::sync::atomic::AtomicBool;

    /// Never actually dials out — the missing-`server_name` check must
    /// reject the connection before this is ever invoked.
    struct UnreachableConnector;

    impl crate::tls::TlsConnector for UnreachableConnector {
        fn connect(&self, _server_name: &str) -> io::Result<TlsVariant> {
            unreachable!("connector.connect must not be called without a server_name (issue #198)")
        }
    }

    fn connected_stream_pair() -> mio::net::TcpStream {
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let std_stream = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        std_stream.set_nonblocking(true).unwrap();
        let _ = listener.accept().unwrap();
        mio::net::TcpStream::from_std(std_stream)
    }

    #[test]
    fn tls_dial_without_server_name_is_rejected_not_defaulted_to_localhost() {
        let active = Arc::new(AtomicBool::new(true));
        let (reactor_handle, _thread) = Reactor::spawn(0, active).unwrap();
        let pool = Arc::new(BufferPool::default());
        let stream = connected_stream_pair();
        let addr = stream.peer_addr().unwrap();

        let mut params = TcpConnParams::plaintext(addr);
        params.secure = true;
        params.tls_connector = Some(Arc::new(UnreachableConnector));
        // server_name left unset — this must not silently become "localhost".

        let result = TcpConnection::new(
            Token(1),
            stream.into(),
            Box::new(NopHandler),
            params,
            reactor_handle,
            pool,
            false,
            None,
        );
        match result {
            Ok(_) => panic!("TLS dial with no server_name must fail, not default to \"localhost\""),
            Err(e) => assert_eq!(e.kind(), ErrorKind::InvalidInput),
        }
    }

    /// Reports each lifecycle callback it receives, and sends more than the
    /// connection's outbound cap as soon as it is connected.
    struct Overfill(std::sync::mpsc::Sender<String>);

    impl crate::handler::ProtocolHandler for Overfill {
        fn connected(&mut self, endpoint: &mut dyn Endpoint) {
            endpoint.send(&[0u8; 4096]);
        }
        fn receive(&mut self, _endpoint: &mut dyn Endpoint, _buf: &mut loopbuf::LoopBuf) {}
        fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
            let _ = self.0.send("disconnected".into());
        }
        fn error(&mut self, _endpoint: &mut dyn Endpoint, err: &io::Error) {
            let _ = self.0.send(format!("error {:?}", err.kind()));
        }
    }

    /// An outbound buffer overflow closes the connection, and the protocol
    /// handler must be told why before it is told the connection is gone;
    /// otherwise whatever it had in flight waits forever.
    #[test]
    fn outbound_overflow_reports_an_error_to_the_handler_before_disconnecting() {
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let rt = crate::Runtime::start(crate::RuntimeConfig::default()).unwrap();
        rt.connect(
            crate::TcpConnectorConfig::new(addr, move || Box::new(Overfill(tx.clone())))
                .max_net_out(1024),
        )
        .unwrap();
        // The peer accepts and never reads.
        let _peer = listener.accept().unwrap();

        let timeout = std::time::Duration::from_secs(5);
        assert_eq!(rx.recv_timeout(timeout).unwrap(), "error OutOfMemory");
        assert_eq!(rx.recv_timeout(timeout).unwrap(), "disconnected");
    }

    /// Hands its endpoint's handle to the test, then does nothing.
    struct HandOut(std::sync::mpsc::Sender<crate::ConnHandle>);

    impl crate::handler::ProtocolHandler for HandOut {
        fn connected(&mut self, endpoint: &mut dyn Endpoint) {
            let _ = self.0.send(endpoint.handle());
        }
        fn receive(&mut self, _endpoint: &mut dyn Endpoint, _buf: &mut loopbuf::LoopBuf) {}
        fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}
        fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &io::Error) {}
    }

    /// `on_write_ready` promises a call once the outbound buffer is drained.
    /// Registered on an idle connection, whose buffer is already empty, that
    /// is straight away; waiting for a write event that nothing will provoke
    /// would leave the caller stalled.
    #[test]
    fn write_ready_fires_on_an_idle_connection_with_nothing_buffered() {
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (handle_tx, handle_rx) = std::sync::mpsc::channel();
        let rt = crate::Runtime::start(crate::RuntimeConfig::default()).unwrap();
        rt.connect(crate::TcpConnectorConfig::new(addr, move || Box::new(HandOut(handle_tx.clone()))))
            .unwrap();
        let _peer = listener.accept().unwrap();
        let timeout = std::time::Duration::from_secs(5);
        let handle = handle_rx.recv_timeout(timeout).unwrap();
        // Let the connect settle so nothing else is about to provoke a write.
        std::thread::sleep(std::time::Duration::from_millis(200));

        let (fired_tx, fired_rx) = std::sync::mpsc::channel();
        handle.with_endpoint(move |ep| {
            ep.on_write_ready(Some(Box::new(move |_| {
                let _ = fired_tx.send(());
            })));
        });
        fired_rx.recv_timeout(timeout).expect("write-ready callback never ran");
    }
}
