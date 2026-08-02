// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Mio UDP driver around `quinn-proto` endpoint + connections.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use bytes::Bytes;
use mio::net::UdpSocket;
use mio::{Events, Interest, Poll, Token, Waker};
use quinn_proto::{
    Connection, ConnectionHandle, DatagramEvent, Dir, Endpoint as QuinnEndpoint, EndpointConfig,
    Event, StreamEvent, StreamId, Transmit, VarInt,
};
use hopf_core::{Endpoint, HandlerFactory, ProtocolHandler, SecurityInfo};

use crate::config::{QuicConnectConfig, QuicListenConfig, QuicListenHooksConfig};
use crate::hooks::{ConnectionFactory, QuicConnApi, QuicConnection};
use crate::stream::{QuicStreamEndpoint, StreamQueues};

const UDP_TOKEN: Token = Token(0);
const WAKE_TOKEN: Token = Token(1);

/// Build a [`SecurityInfo`] from `conn`'s real negotiated handshake data
/// (RFC 7301 ALPN, SNI) instead of a hardcoded guess. The protocol version
/// is always `TLSv1.3` by construction — hopf-quic's own TLS configs
/// (`config.rs`) only ever build TLS 1.3, so a mismatched handshake would
/// already have failed before any stream exists to report on. Cipher
/// suite isn't exposed by quinn-proto's crypto session abstraction, so it
/// stays `None` (honest "unknown", not a fabricated value).
fn security_info_from_conn(conn: &Connection) -> SecurityInfo {
    let handshake_data = conn
        .crypto_session()
        .handshake_data()
        .and_then(|d| d.downcast::<quinn_proto::crypto::rustls::HandshakeData>().ok());
    let alpn = handshake_data.as_ref().and_then(|d| d.protocol.clone());
    let sni = handshake_data.and_then(|d| d.server_name.clone());
    SecurityInfo::secure(alpn, Some("TLSv1.3".into()), None).with_sni(sni)
}

pub(crate) enum DriverCmd {
    StreamWritable { stream_id: StreamId },
    StreamReadable { stream_id: StreamId },
    StreamClose { stream_id: StreamId },
    /// Abruptly close the whole connection with an application error code
    /// (RFC 9000 §10.2 CONNECTION_CLOSE), e.g. an HTTP/3 connection-level
    /// protocol error.
    ConnectionClose { conn: ConnectionHandle, error_code: u64 },
    ScheduleTimer {
        delay: Duration,
        callback: Box<dyn FnOnce() + Send>,
        cancelled: Arc<AtomicBool>,
    },
    Task(Box<dyn FnOnce() + Send>),
    Shutdown,
}

/// Handle to a running QUIC driver thread (listen or dial).
pub struct QuicDriverHandle {
    cmd_tx: Sender<DriverCmd>,
    waker: Arc<Waker>,
    active: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
    /// Local UDP address after bind.
    pub local_addr: SocketAddr,
}

impl QuicDriverHandle {
    /// Request shutdown and join the driver thread.
    pub fn shutdown(mut self) {
        self.active.store(false, Ordering::Release);
        let _ = self.cmd_tx.send(DriverCmd::Shutdown);
        let _ = self.waker.wake();
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

impl Drop for QuicDriverHandle {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
        let _ = self.cmd_tx.send(DriverCmd::Shutdown);
        let _ = self.waker.wake();
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

/// Bind UDP and accept QUIC connections; each bi-stream gets a handler from `config.factory`.
pub fn listen_quic(config: QuicListenConfig) -> io::Result<QuicDriverHandle> {
    let std_sock = std::net::UdpSocket::bind(config.addr)?;
    std_sock.set_nonblocking(true)?;
    let local_addr = std_sock.local_addr()?;
    let socket = UdpSocket::from_std(std_sock);

    let endpoint = QuinnEndpoint::new(
        Arc::new(EndpointConfig::default()),
        Some(Arc::clone(&config.server)),
        true,
        None,
    );

    spawn_driver(DriverMode::Server {
        factory: config.factory,
    }, endpoint, socket, local_addr, None)
}

/// Bind UDP and accept QUIC connections using connection-level hooks (H3).
pub fn listen_quic_hooks(config: QuicListenHooksConfig) -> io::Result<QuicDriverHandle> {
    let std_sock = std::net::UdpSocket::bind(config.addr)?;
    std_sock.set_nonblocking(true)?;
    let local_addr = std_sock.local_addr()?;
    let socket = UdpSocket::from_std(std_sock);

    let endpoint = QuinnEndpoint::new(
        Arc::new(EndpointConfig::default()),
        Some(Arc::clone(&config.server)),
        true,
        None,
    );

    spawn_driver(
        DriverMode::ServerHooks {
            connection_factory: config.connection_factory,
        },
        endpoint,
        socket,
        local_addr,
        None,
    )
}

/// Dial a peer, open one bidirectional stream, and attach `config.factory` handler.
pub fn connect_quic(config: QuicConnectConfig) -> io::Result<QuicDriverHandle> {
    let std_sock = std::net::UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0)))?;
    std_sock.set_nonblocking(true)?;
    let local_addr = std_sock.local_addr()?;
    let socket = UdpSocket::from_std(std_sock);

    let endpoint = QuinnEndpoint::new(Arc::new(EndpointConfig::default()), None, true, None);

    spawn_driver(
        DriverMode::Client {
            factory: config.factory,
            peer: config.addr,
            client_config: Arc::clone(&config.client),
            server_name: config.server_name,
        },
        endpoint,
        socket,
        local_addr,
        Some(config.addr),
    )
}

/// Dial with connection-level hooks (HTTP/3 client).
pub fn connect_quic_hooks(
    addr: SocketAddr,
    client: Arc<quinn_proto::ClientConfig>,
    server_name: impl Into<String>,
    connection_factory: ConnectionFactory,
) -> io::Result<QuicDriverHandle> {
    let std_sock = std::net::UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0)))?;
    std_sock.set_nonblocking(true)?;
    let local_addr = std_sock.local_addr()?;
    let socket = UdpSocket::from_std(std_sock);

    let endpoint = QuinnEndpoint::new(Arc::new(EndpointConfig::default()), None, true, None);

    spawn_driver(
        DriverMode::ClientHooks {
            connection_factory,
            peer: addr,
            client_config: client,
            server_name: server_name.into(),
        },
        endpoint,
        socket,
        local_addr,
        Some(addr),
    )
}

enum DriverMode {
    Server {
        factory: HandlerFactory,
    },
    ServerHooks {
        connection_factory: ConnectionFactory,
    },
    Client {
        factory: HandlerFactory,
        peer: SocketAddr,
        client_config: Arc<quinn_proto::ClientConfig>,
        server_name: String,
    },
    ClientHooks {
        connection_factory: ConnectionFactory,
        peer: SocketAddr,
        client_config: Arc<quinn_proto::ClientConfig>,
        server_name: String,
    },
}

struct StreamSlot {
    queues: Arc<Mutex<StreamQueues>>,
    endpoint: QuicStreamEndpoint,
    handler: Box<dyn ProtocolHandler>,
    /// Locally-opened unidirectional stream (send-only; never recv_stream).
    send_only: bool,
}

struct ConnSlot {
    conn: Connection,
    remote: SocketAddr,
    streams: HashMap<StreamId, StreamSlot>,
    /// Client: open first bi stream after Connected.
    client_pending_open: bool,
    /// Hooks-mode application connection (H3).
    app: Option<Box<dyn QuicConnection>>,
    /// Keys from ConnRecorder → StreamId for locally opened streams.
    local_keys: HashMap<u64, StreamId>,
}

fn spawn_driver(
    mode: DriverMode,
    endpoint: QuinnEndpoint,
    mut socket: UdpSocket,
    local_addr: SocketAddr,
    _peer_hint: Option<SocketAddr>,
) -> io::Result<QuicDriverHandle> {
    let mut poll = Poll::new()?;
    let waker = Arc::new(Waker::new(poll.registry(), WAKE_TOKEN)?);
    poll.registry()
        .register(&mut socket, UDP_TOKEN, Interest::READABLE)?;

    let (cmd_tx, cmd_rx) = mpsc::channel::<DriverCmd>();
    let active = Arc::new(AtomicBool::new(true));
    let active2 = Arc::clone(&active);
    let waker2 = Arc::clone(&waker);
    let cmd_tx2 = cmd_tx.clone();

    let execute: Arc<dyn Fn(Box<dyn FnOnce() + Send>) + Send + Sync> = {
        let tx = cmd_tx.clone();
        let w = Arc::clone(&waker);
        Arc::new(move |task| {
            let _ = tx.send(DriverCmd::Task(task));
            let _ = w.wake();
        })
    };

    let join = thread::Builder::new()
        .name("hopf-quic".into())
        .spawn(move || {
            let mut driver = Driver {
                mode,
                endpoint,
                socket,
                local_addr,
                connections: HashMap::new(),
                cmd_rx,
                cmd_tx: cmd_tx2,
                waker: waker2,
                execute,
                active: active2,
                timers: Vec::new(),
                recv_buf: vec![0u8; 65536],
                send_buf: Vec::with_capacity(2048),
            };
            if let Err(e) = driver.run(&mut poll) {
                eprintln!("hopf-quic driver error: {e}");
            }
        })?;

    Ok(QuicDriverHandle {
        cmd_tx,
        waker,
        active,
        join: Some(join),
        local_addr,
    })
}

struct PendingTimer {
    when: Instant,
    callback: Box<dyn FnOnce() + Send>,
    cancelled: Arc<AtomicBool>,
}

struct Driver {
    mode: DriverMode,
    endpoint: QuinnEndpoint,
    socket: UdpSocket,
    local_addr: SocketAddr,
    connections: HashMap<ConnectionHandle, ConnSlot>,
    cmd_rx: Receiver<DriverCmd>,
    cmd_tx: Sender<DriverCmd>,
    waker: Arc<Waker>,
    execute: Arc<dyn Fn(Box<dyn FnOnce() + Send>) + Send + Sync>,
    active: Arc<AtomicBool>,
    timers: Vec<PendingTimer>,
    recv_buf: Vec<u8>,
    send_buf: Vec<u8>,
}

impl Driver {
    fn run(&mut self, poll: &mut Poll) -> io::Result<()> {
        // Client: start connect immediately.
        let client_connect = match &self.mode {
            DriverMode::Client {
                peer,
                client_config,
                server_name,
                ..
            }
            | DriverMode::ClientHooks {
                peer,
                client_config,
                server_name,
                ..
            } => Some((*peer, Arc::clone(client_config), server_name.clone())),
            _ => None,
        };
        if let Some((peer, client_config, server_name)) = client_connect {
            let pending_open = matches!(self.mode, DriverMode::Client { .. });
            let now = Instant::now();
            match self.endpoint.connect(
                now,
                (*client_config).clone(),
                peer,
                &server_name,
            ) {
                Ok((ch, conn)) => {
                    self.connections.insert(
                        ch,
                        ConnSlot {
                            conn,
                            remote: peer,
                            streams: HashMap::new(),
                            client_pending_open: pending_open,
                            app: None,
                            local_keys: HashMap::new(),
                        },
                    );
                }
                Err(e) => {
                    eprintln!("hopf-quic connect: {e}");
                    return Ok(());
                }
            }
        }

        let mut events = Events::with_capacity(256);
        while self.active.load(Ordering::Acquire) {
            self.flush_all_transmits();
            self.drain_cmds();
            self.fire_timers();

            let timeout = self.next_timeout();
            poll.poll(&mut events, timeout)?;

            let now = Instant::now();
            for ev in events.iter() {
                match ev.token() {
                    UDP_TOKEN => self.on_udp_readable(now)?,
                    WAKE_TOKEN => {}
                    _ => {}
                }
            }

            self.handle_timeouts(now);
            self.poll_connections(now);
            self.detect_migrations();
            self.drive_apps();
            self.flush_all_transmits();
        }
        Ok(())
    }

    fn next_timeout(&self) -> Option<Duration> {
        let now = Instant::now();
        let mut soon: Option<Instant> = None;
        for t in &self.timers {
            if !t.cancelled.load(Ordering::Acquire) {
                soon = Some(soon.map_or(t.when, |s| s.min(t.when)));
            }
        }
        // Always wake at least every 10ms to drive quinn timers.
        let max_wait = Duration::from_millis(10);
        match soon {
            Some(when) if when > now => Some((when - now).min(max_wait)),
            Some(_) => Some(Duration::ZERO),
            None => Some(max_wait),
        }
    }

    fn fire_timers(&mut self) {
        let now = Instant::now();
        let mut i = 0;
        while i < self.timers.len() {
            if self.timers[i].cancelled.load(Ordering::Acquire) {
                self.timers.swap_remove(i);
                continue;
            }
            if self.timers[i].when <= now {
                let t = self.timers.swap_remove(i);
                if !t.cancelled.load(Ordering::Acquire) {
                    (t.callback)();
                }
            } else {
                i += 1;
            }
        }
    }

    fn drain_cmds(&mut self) {
        while let Ok(cmd) = self.cmd_rx.try_recv() {
            match cmd {
                DriverCmd::Shutdown => {
                    self.notify_disconnecting();
                    self.active.store(false, Ordering::Release);
                }
                DriverCmd::Task(task) => task(),
                DriverCmd::ScheduleTimer {
                    delay,
                    callback,
                    cancelled,
                } => {
                    self.timers.push(PendingTimer {
                        when: Instant::now() + delay,
                        callback,
                        cancelled,
                    });
                }
                DriverCmd::StreamWritable { stream_id }
                | DriverCmd::StreamReadable { stream_id }
                | DriverCmd::StreamClose { stream_id } => {
                    let _ = stream_id;
                    // Handled in poll_connections via queue state.
                }
                DriverCmd::ConnectionClose { conn, error_code } => {
                    if let Some(slot) = self.connections.get_mut(&conn) {
                        if let Ok(code) = VarInt::from_u64(error_code) {
                            slot.conn.close(Instant::now(), code, Bytes::new());
                        }
                    }
                }
            }
        }
    }

    fn on_udp_readable(&mut self, now: Instant) -> io::Result<()> {
        loop {
            let (n, remote) = match self.socket.recv_from(&mut self.recv_buf) {
                Ok(x) => x,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            };
            let data = bytes::BytesMut::from(&self.recv_buf[..n]);
            self.send_buf.clear();
            if let Some(event) =
                self.endpoint
                    .handle(now, remote, None, None, data, &mut self.send_buf)
            {
                match event {
                    DatagramEvent::NewConnection(incoming) => {
                        match self.endpoint.accept(incoming, now, &mut self.send_buf, None) {
                            Ok((ch, conn)) => {
                                self.connections.insert(
                                    ch,
                                    ConnSlot {
                                        conn,
                                        remote,
                                        streams: HashMap::new(),
                                        client_pending_open: false,
                                        app: None,
                                        local_keys: HashMap::new(),
                                    },
                                );
                            }
                            Err(e) => {
                                if let Some(tx) = e.response {
                                    self.send_transmit(tx);
                                }
                            }
                        }
                    }
                    DatagramEvent::ConnectionEvent(ch, event) => {
                        if let Some(slot) = self.connections.get_mut(&ch) {
                            slot.conn.handle_event(event);
                        }
                    }
                    DatagramEvent::Response(tx) => {
                        self.send_transmit(tx);
                    }
                }
            }
            if !self.send_buf.is_empty() {
                // Response already sent via Transmit.
                self.send_buf.clear();
            }
        }
        Ok(())
    }

    fn handle_timeouts(&mut self, now: Instant) {
        let handles: Vec<_> = self.connections.keys().copied().collect();
        for ch in handles {
            if let Some(slot) = self.connections.get_mut(&ch) {
                if let Some(t) = slot.conn.poll_timeout() {
                    if t <= now {
                        slot.conn.handle_timeout(now);
                    }
                }
            }
        }
    }

    fn poll_connections(&mut self, now: Instant) {
        let handles: Vec<_> = self.connections.keys().copied().collect();
        for ch in handles {
            self.poll_one_connection(ch, now);
        }
    }

    fn poll_one_connection(&mut self, ch: ConnectionHandle, now: Instant) {
        // Endpoint events first.
        let mut endpoint_events = Vec::new();
        if let Some(slot) = self.connections.get_mut(&ch) {
            while let Some(ev) = slot.conn.poll_endpoint_events() {
                endpoint_events.push(ev);
            }
        }
        for ev in endpoint_events {
            if let Some(reply) = self.endpoint.handle_event(ch, ev) {
                if let Some(slot) = self.connections.get_mut(&ch) {
                    slot.conn.handle_event(reply);
                }
            }
        }

        // App events.
        loop {
            let event = match self.connections.get_mut(&ch) {
                Some(slot) => slot.conn.poll(),
                None => break,
            };
            let Some(event) = event else { break };
            match event {
                Event::HandshakeDataReady => {}
                Event::Connected => {
                    self.on_connected(ch);
                }
                Event::ConnectionLost { .. } => {
                    self.on_connection_lost(ch);
                    return;
                }
                Event::Stream(se) => self.on_stream_event(ch, se),
                Event::DatagramReceived => {}
                _ => {}
            }
        }

        // Drive stream I/O.
        self.drive_streams(ch, now);

        // Transmits.
        loop {
            self.send_buf.clear();
            let tx = match self.connections.get_mut(&ch) {
                Some(slot) => slot.conn.poll_transmit(now, 4, &mut self.send_buf),
                None => break,
            };
            match tx {
                Some(t) => self.send_transmit(t),
                None => break,
            }
        }
    }

    fn on_connected(&mut self, ch: ConnectionHandle) {
        if matches!(
            self.mode,
            DriverMode::ServerHooks { .. } | DriverMode::ClientHooks { .. }
        ) {
            let factory = match &self.mode {
                DriverMode::ServerHooks {
                    connection_factory,
                }
                | DriverMode::ClientHooks {
                    connection_factory,
                    ..
                } => Arc::clone(connection_factory),
                _ => unreachable!(),
            };
            let mut app = factory();
            let mut recorder = ConnRecorder::default();
            app.connected(&mut recorder);
            self.apply_recorder(ch, &mut *app, recorder);
            if let Some(slot) = self.connections.get_mut(&ch) {
                slot.app = Some(app);
            }
            while let Some(id) = self
                .connections
                .get_mut(&ch)
                .and_then(|s| s.conn.streams().accept(Dir::Bi))
            {
                self.attach_stream_dir(ch, id, Dir::Bi);
            }
            while let Some(id) = self
                .connections
                .get_mut(&ch)
                .and_then(|s| s.conn.streams().accept(Dir::Uni))
            {
                self.attach_stream_dir(ch, id, Dir::Uni);
            }
            return;
        }

        let open_client = matches!(
            (
                &self.mode,
                self.connections.get(&ch).map(|s| s.client_pending_open)
            ),
            (DriverMode::Client { .. }, Some(true))
        );
        if open_client {
            if let Some(slot) = self.connections.get_mut(&ch) {
                slot.client_pending_open = false;
                if let Some(id) = slot.conn.streams().open(Dir::Bi) {
                    self.attach_stream_dir(ch, id, Dir::Bi);
                }
            }
        }
        if matches!(self.mode, DriverMode::Server { .. }) {
            while let Some(id) = self
                .connections
                .get_mut(&ch)
                .and_then(|s| s.conn.streams().accept(Dir::Bi))
            {
                self.attach_stream_dir(ch, id, Dir::Bi);
            }
        }
    }

    fn apply_recorder(
        &mut self,
        ch: ConnectionHandle,
        app: &mut dyn QuicConnection,
        recorder: ConnRecorder,
    ) {
        for action in recorder.actions {
            match action {
                RecorderAction::Open { dir, key } => {
                    let Some(slot) = self.connections.get_mut(&ch) else {
                        continue;
                    };
                    let Some(id) = slot.conn.streams().open(dir) else {
                        continue;
                    };
                    let remote = slot.remote;
                    let local = self.local_addr;
                    let security = security_info_from_conn(&slot.conn);
                    let queues = Arc::new(Mutex::new(StreamQueues::new()));
                    let mut endpoint = QuicStreamEndpoint::new(
                        id,
                        ch,
                        local,
                        remote,
                        security,
                        Arc::clone(&queues),
                        self.cmd_tx.clone(),
                        Arc::clone(&self.waker),
                        Arc::clone(&self.execute),
                    );
                    let mut handler = match dir {
                        Dir::Bi => app.accept_bi(),
                        Dir::Uni => Box::new(hopf_core::NopHandler),
                    };
                    handler.connected(&mut endpoint);
                    let sec = endpoint.security_info().clone();
                    handler.security_established(&mut endpoint, &sec);
                    slot.streams.insert(
                        id,
                        StreamSlot {
                            queues,
                            endpoint,
                            handler,
                            send_only: matches!(dir, Dir::Uni),
                        },
                    );
                    slot.local_keys.insert(key, id);
                }
                RecorderAction::Write { key, data } => {
                    if let Some(slot) = self.connections.get_mut(&ch) {
                        if let Some(&id) = slot.local_keys.get(&key) {
                            if let Some(stream) = slot.streams.get_mut(&id) {
                                stream.queues.lock().unwrap().out.extend_from_slice(&data);
                            }
                        }
                    }
                }
                RecorderAction::Finish { key } => {
                    if let Some(slot) = self.connections.get_mut(&ch) {
                        if let Some(&id) = slot.local_keys.get(&key) {
                            if let Some(stream) = slot.streams.get_mut(&id) {
                                stream.queues.lock().unwrap().finish_write = true;
                            }
                        }
                    }
                }
            }
        }
    }

    /// Give every still-live connection's app a last chance to write a
    /// final message (e.g. GOAWAY) before an explicit driver shutdown.
    /// Bytes queued here are flushed normally by the same loop iteration's
    /// subsequent `poll_connections` + `flush_all_transmits` before the
    /// driver thread actually stops (see [`Self::run`]).
    fn notify_disconnecting(&mut self) {
        let handles: Vec<ConnectionHandle> = self
            .connections
            .iter()
            .filter(|(_, s)| s.app.is_some())
            .map(|(ch, _)| *ch)
            .collect();
        for ch in handles {
            let Some(mut app) = self.connections.get_mut(&ch).and_then(|s| s.app.take()) else {
                continue;
            };
            let mut recorder = ConnRecorder::default();
            app.disconnecting(&mut recorder);
            self.apply_recorder(ch, &mut *app, recorder);
            if let Some(slot) = self.connections.get_mut(&ch) {
                slot.app = Some(app);
            }
        }
    }

    /// Give every still-live connection's app a chance to write additional
    /// bytes onto already-open local streams (see
    /// [`QuicConnection::drive`]), once per loop tick.
    fn drive_apps(&mut self) {
        let handles: Vec<ConnectionHandle> = self
            .connections
            .iter()
            .filter(|(_, s)| s.app.is_some())
            .map(|(ch, _)| *ch)
            .collect();
        for ch in handles {
            let Some(mut app) = self.connections.get_mut(&ch).and_then(|s| s.app.take()) else {
                continue;
            };
            let mut recorder = ConnRecorder::default();
            app.drive(&mut recorder);
            self.apply_recorder(ch, &mut *app, recorder);
            if let Some(slot) = self.connections.get_mut(&ch) {
                slot.app = Some(app);
            }
        }
    }

    /// Refresh `ConnSlot.remote` (and every already-open stream's cached
    /// remote address) once quinn-proto's active path actually changes
    /// (RFC 9000 §9) — `remote_address()` is the only way to observe this,
    /// there's no dedicated migration event to react to instead.
    fn detect_migrations(&mut self) {
        for slot in self.connections.values_mut() {
            let current = slot.conn.remote_address();
            if current == slot.remote {
                continue;
            }
            slot.remote = current;
            for stream in slot.streams.values_mut() {
                stream.endpoint.set_remote(current);
                stream.handler.migrated(&mut stream.endpoint);
            }
        }
    }

    fn on_stream_event(&mut self, ch: ConnectionHandle, ev: StreamEvent) {
        match ev {
            StreamEvent::Opened { dir } => {
                while let Some(id) = self
                    .connections
                    .get_mut(&ch)
                    .and_then(|s| s.conn.streams().accept(dir))
                {
                    self.attach_stream_dir(ch, id, dir);
                }
            }
            StreamEvent::Readable { id } => {
                self.read_stream(ch, id);
            }
            StreamEvent::Finished { id } | StreamEvent::Stopped { id, .. } => {
                // Drain any remaining data before tearing down the stream.
                self.read_stream(ch, id);
                self.finish_stream(ch, id);
            }
            _ => {}
        }
    }

    fn attach_stream_dir(&mut self, ch: ConnectionHandle, id: StreamId, dir: Dir) {
        let (remote, local, security) = match self.connections.get(&ch) {
            Some(s) => (s.remote, self.local_addr, security_info_from_conn(&s.conn)),
            None => return,
        };
        let queues = Arc::new(Mutex::new(StreamQueues::new()));
        let mut endpoint = QuicStreamEndpoint::new(
            id,
            ch,
            local,
            remote,
            security,
            Arc::clone(&queues),
            self.cmd_tx.clone(),
            Arc::clone(&self.waker),
            Arc::clone(&self.execute),
        );

        let mut handler: Box<dyn ProtocolHandler> =
            if self.connections.get(&ch).and_then(|s| s.app.as_ref()).is_some() {
                let mut app = self
                    .connections
                    .get_mut(&ch)
                    .and_then(|s| s.app.take())
                    .unwrap();
                let h = match dir {
                    Dir::Bi => app.accept_bi(),
                    Dir::Uni => app.accept_uni(),
                };
                if let Some(slot) = self.connections.get_mut(&ch) {
                    slot.app = Some(app);
                }
                h
            } else {
                let factory = match &self.mode {
                    DriverMode::Server { factory } | DriverMode::Client { factory, .. } => {
                        Arc::clone(factory)
                    }
                    DriverMode::ServerHooks { .. } | DriverMode::ClientHooks { .. } => return,
                };
                factory()
            };

        handler.connected(&mut endpoint);
        let sec = endpoint.security_info().clone();
        handler.security_established(&mut endpoint, &sec);

        if let Some(slot) = self.connections.get_mut(&ch) {
            slot.streams.insert(
                id,
                StreamSlot {
                    queues,
                    endpoint,
                    handler,
                    send_only: false,
                },
            );
        }
    }

    fn read_stream(&mut self, ch: ConnectionHandle, id: StreamId) {
        let Some(slot) = self.connections.get_mut(&ch) else {
            return;
        };
        if slot
            .streams
            .get(&id)
            .map(|s| s.send_only || s.endpoint.is_read_paused())
            .unwrap_or(true)
        {
            return;
        }

        let mut recv = slot.conn.recv_stream(id);
        let mut chunks = match recv.read(true) {
            Ok(c) => c,
            Err(_) => return,
        };
        let mut data = Vec::new();
        loop {
            match chunks.next(usize::MAX) {
                Ok(Some(chunk)) => {
                    data.extend_from_slice(&chunk.bytes);
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
        let _ = chunks.finalize();
        if data.is_empty() {
            return;
        }

        if let Some(stream) = slot.streams.get_mut(&id) {
            let mut slice = data.as_slice();
            stream
                .handler
                .receive(&mut stream.endpoint, &mut slice);
        }
    }

    fn drive_streams(&mut self, ch: ConnectionHandle, _now: Instant) {
        let ids: Vec<StreamId> = self
            .connections
            .get(&ch)
            .map(|s| s.streams.keys().copied().collect())
            .unwrap_or_default();

        for id in ids {
            // Abrupt abort requested (RESET_STREAM + STOP_SENDING) takes
            // priority over any pending graceful write/finish for this
            // stream — the peer should see the reset, not more data.
            let reset_code = self
                .connections
                .get(&ch)
                .and_then(|s| s.streams.get(&id))
                .and_then(|st| st.queues.lock().unwrap().reset_error_code.take());
            if let Some(code) = reset_code {
                if let Ok(vc) = VarInt::from_u64(code) {
                    if let Some(slot) = self.connections.get_mut(&ch) {
                        let _ = slot.conn.send_stream(id).reset(vc);
                        let _ = slot.conn.recv_stream(id).stop(vc);
                    }
                }
                continue;
            }

            // Write pending bytes.
            let pending = self
                .connections
                .get(&ch)
                .and_then(|s| s.streams.get(&id))
                .map(|st| {
                    let mut q = st.queues.lock().unwrap();
                    std::mem::take(&mut q.out)
                })
                .unwrap_or_default();

            if !pending.is_empty() {
                if let Some(slot) = self.connections.get_mut(&ch) {
                    let mut send = slot.conn.send_stream(id);
                    match send.write(&pending) {
                        Ok(n) if n < pending.len() => {
                            if let Some(st) = slot.streams.get_mut(&id) {
                                let mut q = st.queues.lock().unwrap();
                                let rest = pending[n..].to_vec();
                                q.out.splice(0..0, rest);
                            }
                        }
                        Ok(_) => {
                            if let Some(st) = slot.streams.get_mut(&id) {
                                if let Some(cb) = st.endpoint.take_write_ready() {
                                    cb(&mut st.endpoint);
                                }
                            }
                        }
                        Err(quinn_proto::WriteError::Blocked) => {
                            if let Some(st) = slot.streams.get_mut(&id) {
                                let mut q = st.queues.lock().unwrap();
                                q.out.splice(0..0, pending);
                            }
                        }
                        Err(_) => {}
                    }
                }
            }

            // Finish if requested and out empty.
            let should_finish = self
                .connections
                .get(&ch)
                .and_then(|s| s.streams.get(&id))
                .map(|st| {
                    let q = st.queues.lock().unwrap();
                    q.finish_write && q.out.is_empty()
                })
                .unwrap_or(false);
            if should_finish {
                if let Some(slot) = self.connections.get_mut(&ch) {
                    let _ = slot.conn.send_stream(id).finish();
                    if let Some(st) = slot.streams.get_mut(&id) {
                        let mut q = st.queues.lock().unwrap();
                        q.finish_write = false;
                    }
                }
            }

            // Opportunistic read.
            self.read_stream(ch, id);
        }
    }

    fn finish_stream(&mut self, ch: ConnectionHandle, id: StreamId) {
        if let Some(slot) = self.connections.get_mut(&ch) {
            if let Some(mut stream) = slot.streams.remove(&id) {
                stream.endpoint.mark_closed();
                stream.handler.disconnected(&mut stream.endpoint);
            }
        }
    }

    fn on_connection_lost(&mut self, ch: ConnectionHandle) {
        if let Some(mut slot) = self.connections.remove(&ch) {
            let ids: Vec<_> = slot.streams.keys().copied().collect();
            for id in ids {
                if let Some(mut stream) = slot.streams.remove(&id) {
                    stream.endpoint.mark_closed();
                    stream.handler.disconnected(&mut stream.endpoint);
                }
            }
        }
    }

    fn flush_all_transmits(&mut self) {
        // Endpoint-level transmits (if any) are handled via DatagramEvent::Response.
        let now = Instant::now();
        let handles: Vec<_> = self.connections.keys().copied().collect();
        for ch in handles {
            loop {
                self.send_buf.clear();
                let tx = match self.connections.get_mut(&ch) {
                    Some(slot) => slot.conn.poll_transmit(now, 8, &mut self.send_buf),
                    None => break,
                };
                match tx {
                    Some(t) => self.send_transmit(t),
                    None => break,
                }
            }
        }
    }

    fn send_transmit(&mut self, transmit: Transmit) {
        let dest = transmit.destination;
        let size = transmit.size;
        if size == 0 || size > self.send_buf.len() {
            // poll_transmit writes into send_buf; if empty, nothing to send.
            if size == 0 {
                return;
            }
        }
        let buf = if self.send_buf.len() >= size {
            &self.send_buf[..size]
        } else {
            return;
        };
        match self.socket.send_to(buf, dest) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => eprintln!("hopf-quic send_to: {e}"),
        }
        let _ = Bytes::new(); // silence unused if feature changes
    }
}


#[derive(Default)]
struct ConnRecorder {
    next_key: u64,
    actions: Vec<RecorderAction>,
}

enum RecorderAction {
    Open { dir: Dir, key: u64 },
    Write { key: u64, data: Vec<u8> },
    Finish { key: u64 },
}

impl QuicConnApi for ConnRecorder {
    fn open_uni(&mut self) -> Option<u64> {
        let key = self.next_key;
        self.next_key += 1;
        self.actions.push(RecorderAction::Open {
            dir: Dir::Uni,
            key,
        });
        Some(key)
    }

    fn open_bi(&mut self) -> Option<u64> {
        let key = self.next_key;
        self.next_key += 1;
        self.actions.push(RecorderAction::Open {
            dir: Dir::Bi,
            key,
        });
        Some(key)
    }

    fn write(&mut self, stream_key: u64, data: &[u8]) {
        self.actions.push(RecorderAction::Write {
            key: stream_key,
            data: data.to_vec(),
        });
    }

    fn finish(&mut self, stream_key: u64) {
        self.actions.push(RecorderAction::Finish { key: stream_key });
    }
}

#[cfg(all(test, feature = "integration"))]
mod tests {
    use super::*;
    use crate::config::{client_config_for_pem_bytes, server_config_self_signed};
    use std::sync::Mutex as StdMutex;
    use hopf_core::{Endpoint, ProtocolHandler};

    struct Echo;

    impl ProtocolHandler for Echo {
        fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}
        fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
            endpoint.send(data);
            *data = &[];
        }
        fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}
        fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &io::Error) {}
    }

    struct ClientProbe {
        sent: bool,
        got: Arc<StdMutex<Vec<u8>>>,
    }

    impl ProtocolHandler for ClientProbe {
        fn connected(&mut self, endpoint: &mut dyn Endpoint) {
            if !self.sent {
                endpoint.send(b"ping");
                self.sent = true;
            }
        }
        fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
            self.got.lock().unwrap().extend_from_slice(data);
            *data = &[];
            endpoint.close();
        }
        fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}
        fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &io::Error) {}
    }

    #[test]
    fn spike_echo_one_stream() {
        let (server_cfg, pem) =
            server_config_self_signed(&["localhost"], &[b"hq-interop"]).unwrap();
        let client_cfg = client_config_for_pem_bytes(&pem, &[b"hq-interop"]).unwrap();

        let server = listen_quic(QuicListenConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            server_cfg,
            Arc::new(|| Box::new(Echo) as Box<dyn ProtocolHandler>),
        ))
        .unwrap();

        let got = Arc::new(StdMutex::new(Vec::new()));
        let got2 = Arc::clone(&got);
        let _client = connect_quic(QuicConnectConfig::new(
            server.local_addr,
            client_cfg,
            "localhost",
            Arc::new(move || {
                Box::new(ClientProbe {
                    sent: false,
                    got: Arc::clone(&got2),
                }) as Box<dyn ProtocolHandler>
            }),
        ))
        .unwrap();

        for _ in 0..200 {
            if got.lock().unwrap().as_slice() == b"ping" {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(got.lock().unwrap().as_slice(), b"ping");
        server.shutdown();
    }

    struct SecurityRecorder {
        out: Arc<StdMutex<Option<hopf_core::SecurityInfo>>>,
    }

    impl ProtocolHandler for SecurityRecorder {
        fn connected(&mut self, endpoint: &mut dyn Endpoint) {
            *self.out.lock().unwrap() = Some(endpoint.security_info().clone());
            // A stream that never sends anything never actually reaches the
            // peer (no STREAM frame implies its existence) — write a byte
            // so the server side sees it and its own connected() fires.
            endpoint.send(b"x");
        }
        fn receive(&mut self, _endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
            *data = &[];
        }
        fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}
        fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &io::Error) {}
    }

    /// The server offers two ALPNs; the client only offers the second, so
    /// the real negotiated protocol can't be the old hardcoded `h3` guess
    /// — proves `SecurityInfo` on both sides reflects the actual handshake
    /// (RFC 7301 ALPN, plus SNI on the server side), not a constant.
    #[test]
    fn security_info_reflects_real_negotiated_alpn_and_sni() {
        let (server_cfg, pem) =
            server_config_self_signed(&["localhost"], &[b"h3", b"custom-proto"]).unwrap();
        let client_cfg = client_config_for_pem_bytes(&pem, &[b"custom-proto"]).unwrap();

        let server_seen = Arc::new(StdMutex::new(None));
        let server_seen2 = Arc::clone(&server_seen);
        let server = listen_quic(QuicListenConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            server_cfg,
            Arc::new(move || {
                Box::new(SecurityRecorder { out: Arc::clone(&server_seen2) }) as Box<dyn ProtocolHandler>
            }),
        ))
        .unwrap();

        let client_seen = Arc::new(StdMutex::new(None));
        let client_seen2 = Arc::clone(&client_seen);
        let _client = connect_quic(QuicConnectConfig::new(
            server.local_addr,
            client_cfg,
            "localhost",
            Arc::new(move || {
                Box::new(SecurityRecorder { out: Arc::clone(&client_seen2) }) as Box<dyn ProtocolHandler>
            }),
        ))
        .unwrap();

        for _ in 0..200 {
            if client_seen.lock().unwrap().is_some() && server_seen.lock().unwrap().is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }

        let client_info = client_seen.lock().unwrap().clone().expect("client never connected");
        let server_info = server_seen.lock().unwrap().clone().expect("server never accepted");
        assert_eq!(client_info.alpn(), Some(&b"custom-proto"[..]));
        assert_eq!(server_info.alpn(), Some(&b"custom-proto"[..]));
        assert_eq!(server_info.protocol(), Some("TLSv1.3"));
        assert_eq!(server_info.sni(), Some("localhost"));

        server.shutdown();
    }

    struct DisconnectRecorder {
        disconnected: Arc<std::sync::atomic::AtomicBool>,
    }

    impl ProtocolHandler for DisconnectRecorder {
        fn connected(&mut self, endpoint: &mut dyn Endpoint) {
            // Force the stream onto the wire so the peer's own connected()
            // fires too (a stream that never sends anything is never
            // observed by the peer at all).
            endpoint.send(b"x");
        }
        fn receive(&mut self, _endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
            *data = &[];
        }
        fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
            self.disconnected.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &io::Error) {}
    }

    /// A real, much-shorter-than-default idle timeout applied via
    /// [`QuicTransportOptions`] actually tears the connection down on its
    /// own — proves the config is wired into quinn-proto's real transport
    /// parameters, not just accepted and ignored.
    #[test]
    fn transport_options_shorten_the_idle_timeout() {
        use crate::config::{apply_client_transport_options, apply_server_transport_options, QuicTransportOptions};

        let (mut server_cfg, pem) =
            server_config_self_signed(&["localhost"], &[b"idle-test"]).unwrap();
        let mut client_cfg = client_config_for_pem_bytes(&pem, &[b"idle-test"]).unwrap();

        let opts = QuicTransportOptions::new().max_idle_timeout(Duration::from_millis(200));
        apply_server_transport_options(&mut server_cfg, &opts).unwrap();
        apply_client_transport_options(&mut client_cfg, &opts).unwrap();

        let server_disconnected = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let server_disconnected2 = Arc::clone(&server_disconnected);
        let server = listen_quic(QuicListenConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            server_cfg,
            Arc::new(move || {
                Box::new(DisconnectRecorder { disconnected: Arc::clone(&server_disconnected2) })
                    as Box<dyn ProtocolHandler>
            }),
        ))
        .unwrap();

        let client_disconnected = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let client_disconnected2 = Arc::clone(&client_disconnected);
        let _client = connect_quic(QuicConnectConfig::new(
            server.local_addr,
            client_cfg,
            "localhost",
            Arc::new(move || {
                Box::new(DisconnectRecorder { disconnected: Arc::clone(&client_disconnected2) })
                    as Box<dyn ProtocolHandler>
            }),
        ))
        .unwrap();

        // No further traffic after the initial byte — with a 200ms idle
        // timeout, both sides must tear the connection down well within
        // this window; the default (30s) never would.
        for _ in 0..150 {
            if server_disconnected.load(std::sync::atomic::Ordering::SeqCst)
                && client_disconnected.load(std::sync::atomic::Ordering::SeqCst)
            {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert!(server_disconnected.load(std::sync::atomic::Ordering::SeqCst), "server never saw the idle timeout");
        assert!(client_disconnected.load(std::sync::atomic::Ordering::SeqCst), "client never saw the idle timeout");

        server.shutdown();
    }

    /// Keep-alive probes applied via [`QuicTransportOptions`] keep a
    /// connection alive past what the idle timeout alone would allow —
    /// proves `keep_alive_interval` is wired into quinn-proto, not just
    /// accepted and ignored.
    #[test]
    fn transport_options_keepalive_prevents_idle_timeout() {
        use crate::config::{apply_client_transport_options, apply_server_transport_options, QuicTransportOptions};

        let (mut server_cfg, pem) =
            server_config_self_signed(&["localhost"], &[b"ka-test"]).unwrap();
        let mut client_cfg = client_config_for_pem_bytes(&pem, &[b"ka-test"]).unwrap();

        // Same short idle as the teardown test, but with keep-alive well
        // under it on the client (one side is enough).
        let opts = QuicTransportOptions::new()
            .max_idle_timeout(Duration::from_millis(200))
            .keep_alive_interval(Duration::from_millis(50));
        apply_server_transport_options(
            &mut server_cfg,
            &QuicTransportOptions::new().max_idle_timeout(Duration::from_millis(200)),
        )
        .unwrap();
        apply_client_transport_options(&mut client_cfg, &opts).unwrap();

        let server_disconnected = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let server_disconnected2 = Arc::clone(&server_disconnected);
        let server = listen_quic(QuicListenConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            server_cfg,
            Arc::new(move || {
                Box::new(DisconnectRecorder {
                    disconnected: Arc::clone(&server_disconnected2),
                }) as Box<dyn ProtocolHandler>
            }),
        ))
        .unwrap();

        let client_disconnected = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let client_disconnected2 = Arc::clone(&client_disconnected);
        let _client = connect_quic(QuicConnectConfig::new(
            server.local_addr,
            client_cfg,
            "localhost",
            Arc::new(move || {
                Box::new(DisconnectRecorder {
                    disconnected: Arc::clone(&client_disconnected2),
                }) as Box<dyn ProtocolHandler>
            }),
        ))
        .unwrap();

        // Without keepalive, both sides disconnect by ~200ms. Wait several
        // idle periods; keep-alive must keep the connection up.
        thread::sleep(Duration::from_millis(800));
        assert!(
            !server_disconnected.load(std::sync::atomic::Ordering::SeqCst),
            "server disconnected despite client keep-alive"
        );
        assert!(
            !client_disconnected.load(std::sync::atomic::Ordering::SeqCst),
            "client disconnected despite its own keep-alive"
        );

        server.shutdown();
    }
}
