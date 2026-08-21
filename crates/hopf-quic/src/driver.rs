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
    Connection, ConnectionError, ConnectionHandle, DatagramEvent, Dir, Endpoint as QuinnEndpoint,
    EndpointConfig, Event, Incoming, StreamEvent, StreamId, Transmit, VarInt,
};
use hopf_core::{Endpoint, HandlerFactory, ProtocolHandler, SecurityInfo};

use crate::config::{
    apply_listen_hardening, QuicConnectConfig, QuicListenConfig, QuicListenHooksConfig,
};
use crate::error::{connection_lost_io_error, stream_stopped_io_error};
use crate::hooks::{ConnectionFactory, DatagramDecode, QuicConnApi, QuicConnection};
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
    /// Client mode: open another bidirectional stream on the live connection
    /// and attach a handler from `factory`. `reply` reports whether the
    /// open was accepted (queued until Connected, or opened immediately).
    OpenBi {
        factory: HandlerFactory,
        reply: std::sync::mpsc::SyncSender<io::Result<()>>,
    },
    ScheduleTimer {
        delay: Duration,
        callback: Box<dyn FnOnce() + Send>,
        cancelled: Arc<AtomicBool>,
    },
    Task(Box<dyn FnOnce() + Send>),
    /// Run `task` against a specific stream's endpoint — the QUIC side of
    /// [`hopf_core::ConnHandle::with_endpoint`] (see `stream.rs`'s
    /// `QuicStreamBackend`), mirroring how `hopf_core::Reactor` handles
    /// `ReactorCmd::WithConn` for TCP. Dropped silently if the connection
    /// or stream is already gone, matching `with_endpoint`'s documented
    /// "already gone → dropped" contract.
    WithStream {
        conn: ConnectionHandle,
        stream_id: StreamId,
        task: Box<dyn FnOnce(&mut dyn Endpoint) + Send>,
    },
    /// Queue a QUIC DATAGRAM (RFC 9221) on `conn`.
    SendDatagram {
        conn: ConnectionHandle,
        payload: Vec<u8>,
    },
    /// Set send priority for a stream (RFC 9218 via quinn-proto).
    SetStreamPriority {
        conn: ConnectionHandle,
        stream_id: StreamId,
        priority: i32,
    },
    Shutdown,
}

/// Handle to a running QUIC driver thread (listen or dial).
pub struct QuicDriverHandle {
    cmd_tx: Sender<DriverCmd>,
    waker: Arc<Waker>,
    active: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
    /// The driver thread's own id, captured at spawn — lets `shutdown`/
    /// `Drop` detect the (real, reachable) case of being dropped *from*
    /// the driver thread itself (e.g. a `QuicConnection` impl's own state
    /// ends up holding the last strong reference to this handle, dropped
    /// while running on the very thread it represents — see
    /// `hopf-http`'s H3 session code for a concrete case). `JoinHandle::join`
    /// panics (not just errors) when a thread tries to join itself
    /// (`EDEADLK`), so that case must skip the join entirely, not attempt
    /// and recover from it.
    driver_thread_id: std::thread::ThreadId,
    /// Local UDP address after bind.
    pub local_addr: SocketAddr,
}

impl QuicDriverHandle {
    fn join_driver_thread(&mut self) {
        if std::thread::current().id() == self.driver_thread_id {
            // Joining ourselves would panic (EDEADLK) rather than error --
            // and is unnecessary anyway: we're already running on the
            // driver thread, past the point of executing this code, so it
            // needs no one to wait for it. The Shutdown command already
            // sent will make it stop on its own once this call stack
            // unwinds back to the driver's own loop.
            self.join = None;
            return;
        }
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }

    /// Request shutdown and join the driver thread — unless called from
    /// the driver thread itself, in which case the join is skipped (see
    /// [`Self::join_driver_thread`]).
    pub fn shutdown(mut self) {
        self.active.store(false, Ordering::Release);
        let _ = self.cmd_tx.send(DriverCmd::Shutdown);
        let _ = self.waker.wake();
        self.join_driver_thread();
    }

    /// Whether the driver thread is still running (not shut down). A live
    /// driver may still have lost its QUIC connection — use [`Self::open_bi`]
    /// to probe that.
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    /// Open another client-initiated bidirectional stream on the live
    /// client connection, attaching a handler from `factory`.
    ///
    /// Intended for connection reuse (e.g. DNS-over-QUIC: one QUIC
    /// connection, one stream per query). Returns `Err` if the driver is
    /// gone or there is no usable client connection — callers should dial
    /// fresh in that case. If the handshake is still in progress and
    /// 0-RTT is not available the open is queued and applied once
    /// [`Event::Connected`] fires; when [`Connection::has_0rtt`] is true
    /// the stream is opened immediately so data can ride as early data.
    /// If the peer's stream-concurrency limit is exhausted (`MAX_STREAMS`,
    /// RFC 9000 §4.6), the open is queued and applied when
    /// [`StreamEvent::Available`] reports new credit — callers do not
    /// need to retry.
    pub fn open_bi(&self, factory: HandlerFactory) -> io::Result<()> {
        if !self.active.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "QUIC driver shut down",
            ));
        }
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        self.cmd_tx
            .send(DriverCmd::OpenBi {
                factory,
                reply: tx,
            })
            .map_err(|_| {
                io::Error::new(io::ErrorKind::NotConnected, "QUIC driver shut down")
            })?;
        let _ = self.waker.wake();
        rx.recv().unwrap_or_else(|_| {
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "QUIC driver shut down before open_bi",
            ))
        })
    }

    /// Wake a hooks-mode (H3) connection's [`crate::QuicConnection::drive`]
    /// on demand, from any thread.
    ///
    /// The driver loop already calls `drive_apps()` (which calls every
    /// live hooks connection's `drive`) unconditionally on every
    /// iteration, and `RecorderAction::Open` — the mechanism that turns a
    /// `drive`-time [`crate::QuicConnApi::open_bi`] call into a real,
    /// handler-attached stream — already works identically whether it's
    /// recorded during `connected` or a later `drive` tick. The only piece
    /// missing for "open another client-initiated stream on a live H3
    /// connection whenever the app has new work" is prompting the loop to
    /// run again *promptly* instead of waiting for the next incoming
    /// packet or timer — this does that, reusing the same `DriverCmd`
    /// channel and [`mio::Waker`] every other cross-thread operation here
    /// already goes through (see [`Self::open_bi`]). Unlike `open_bi`,
    /// this carries no payload: the app-level queue of pending work (e.g.
    /// hopf-http's `H3ClientConnection`'s own pending-opens queue) lives
    /// entirely on the `QuicConnection` implementor's side, checked by its
    /// own `drive`.
    pub fn poke_hooks(&self) -> io::Result<()> {
        if !self.active.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "QUIC driver shut down",
            ));
        }
        let _ = self.cmd_tx.send(DriverCmd::Task(Box::new(|| {})));
        let _ = self.waker.wake();
        Ok(())
    }
}

impl Drop for QuicDriverHandle {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
        let _ = self.cmd_tx.send(DriverCmd::Shutdown);
        let _ = self.waker.wake();
        self.join_driver_thread();
    }
}

/// Bind UDP and accept QUIC connections; each bi-stream gets a handler from `config.factory`.
pub fn listen_quic(config: QuicListenConfig) -> io::Result<QuicDriverHandle> {
    let std_sock = std::net::UdpSocket::bind(config.addr)?;
    std_sock.set_nonblocking(true)?;
    let local_addr = std_sock.local_addr()?;
    let socket = UdpSocket::from_std(std_sock);

    let mut server = config.server;
    apply_listen_hardening(&mut server, &config.hardening);
    let require_address_validation = config.hardening.require_address_validation;

    let endpoint = QuinnEndpoint::new(
        Arc::new(EndpointConfig::default()),
        Some(server),
        true,
        None,
    );

    spawn_driver(
        DriverMode::Server {
            factory: config.factory,
        },
        endpoint,
        socket,
        local_addr,
        None,
        require_address_validation,
    )
}

/// Bind UDP and accept QUIC connections using connection-level hooks (H3).
pub fn listen_quic_hooks(config: QuicListenHooksConfig) -> io::Result<QuicDriverHandle> {
    let std_sock = std::net::UdpSocket::bind(config.addr)?;
    std_sock.set_nonblocking(true)?;
    let local_addr = std_sock.local_addr()?;
    let socket = UdpSocket::from_std(std_sock);

    let mut server = config.server;
    apply_listen_hardening(&mut server, &config.hardening);
    let require_address_validation = config.hardening.require_address_validation;

    let endpoint = QuinnEndpoint::new(
        Arc::new(EndpointConfig::default()),
        Some(server),
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
        require_address_validation,
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
        false,
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
        false,
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
    /// Bytes read from the stream but left unconsumed by the handler's
    /// last `receive()` call (NIO compact-buffer semantics — mirrors
    /// `TcpConnection`'s `net_in`/`app_in`). Without this, a handler
    /// waiting on a token split across two QUIC STREAM frames loses the
    /// first half the moment `read_stream` returns.
    pending_in: Vec<u8>,
}

struct ConnSlot {
    conn: Connection,
    remote: SocketAddr,
    streams: HashMap<StreamId, StreamSlot>,
    /// Client: still waiting to open the first bi stream (and drain any
    /// queued [`DriverCmd::OpenBi`]s). Cleared once those opens run —
    /// either immediately after `connect()` when [`Connection::has_0rtt`]
    /// is true, or later in [`Driver::on_connected`].
    client_pending_open: bool,
    /// Client: additional [`DriverCmd::OpenBi`] requests waiting for either
    /// handshake completion / 0-RTT, or for peer `MAX_STREAMS` credit
    /// ([`StreamEvent::Available`]). Drained by
    /// [`Driver::drain_pending_open_bi`].
    pending_open_bi: std::collections::VecDeque<HandlerFactory>,
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
    require_address_validation: bool,
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
                require_address_validation,
            };
            if let Err(e) = driver.run(&mut poll) {
                eprintln!("hopf-quic driver error: {e}");
            }
        })?;

    Ok(QuicDriverHandle {
        cmd_tx,
        waker,
        active,
        driver_thread_id: join.thread().id(),
        join: Some(join),
        local_addr,
    })
}

struct PendingTimer {
    when: Instant,
    callback: Box<dyn FnOnce() + Send>,
    cancelled: Arc<AtomicBool>,
}

/// NIO compact-buffer delivery (mirrors `hopf_core::TcpConnection`'s
/// `net_in`/`app_in` handling): append `new_data` to whatever was left
/// unconsumed by the last call, hand `deliver` a cursor into the combined
/// buffer, then retain only the unconsumed suffix in `pending` for next
/// time — so a handler waiting on a token split across two separately
/// delivered chunks (e.g. two QUIC STREAM frames) never loses the first
/// half just because this call returned.
fn deliver_with_residual(pending: &mut Vec<u8>, new_data: &[u8], deliver: impl FnOnce(&mut &[u8])) {
    pending.extend_from_slice(new_data);
    let mut buf = std::mem::take(pending);
    let mut slice = buf.as_slice();
    deliver(&mut slice);
    let remaining = slice.len();
    let consumed = buf.len() - remaining;
    if consumed > 0 {
        buf.drain(..consumed);
    }
    *pending = buf;
}

/// Translate the soonest absolute deadline into a mio poll wait.
///
/// `None` means block indefinitely (no timer / no quinn deadline); a past
/// or equal deadline becomes a zero wait so the loop services it immediately.
fn poll_wait(now: Instant, soonest: Option<Instant>) -> Option<Duration> {
    match soonest {
        Some(when) if when > now => Some(when - now),
        Some(_) => Some(Duration::ZERO),
        None => None,
    }
}

#[cfg(test)]
mod residual_tests {
    use super::{deliver_with_residual, poll_wait};
    use std::time::{Duration, Instant};

    /// Regression test for a bug where `read_stream` dropped whatever
    /// bytes the handler left unconsumed instead of preserving them for
    /// the next call. A handler that refuses to consume anything until it
    /// has seen a full 9-byte token, fed 3 bytes then 6 bytes across two
    /// separate calls, must still see the complete, correctly-reassembled
    /// token on the second call.
    #[test]
    fn preserves_unconsumed_bytes_across_calls() {
        let mut pending = Vec::new();
        let mut seen: Option<Vec<u8>> = None;

        deliver_with_residual(&mut pending, b"PIN", |data| {
            if data.len() < 9 {
                return; // not enough yet — consume nothing
            }
            seen = Some(data.to_vec());
            *data = &[];
        });
        assert_eq!(pending, b"PIN", "unconsumed bytes must be preserved, not dropped");
        assert!(seen.is_none());

        deliver_with_residual(&mut pending, b"G-1234", |data| {
            if data.len() < 9 {
                return;
            }
            seen = Some(data.to_vec());
            *data = &[];
        });
        assert_eq!(seen.as_deref(), Some(&b"PING-1234"[..]));
        assert!(pending.is_empty(), "fully-consumed bytes must not linger");
    }

    #[test]
    fn partial_consumption_retains_only_the_unconsumed_suffix() {
        let mut pending = Vec::new();
        let mut got = Vec::new();

        // Handler consumes one 3-byte record at a time, leaving any
        // trailing partial record for next call.
        deliver_with_residual(&mut pending, b"ABCDEFG", |data| {
            while data.len() >= 3 {
                got.push(data[..3].to_vec());
                *data = &data[3..];
            }
        });
        assert_eq!(got, vec![b"ABC".to_vec(), b"DEF".to_vec()]);
        assert_eq!(pending, b"G");

        deliver_with_residual(&mut pending, b"HI", |data| {
            while data.len() >= 3 {
                got.push(data[..3].to_vec());
                *data = &data[3..];
            }
        });
        assert_eq!(got, vec![b"ABC".to_vec(), b"DEF".to_vec(), b"GHI".to_vec()]);
        assert!(pending.is_empty());
    }

    #[test]
    fn fully_consumed_each_call_never_accumulates() {
        let mut pending = Vec::new();
        let mut total = Vec::new();
        for chunk in [&b"foo"[..], b"bar", b"baz"] {
            deliver_with_residual(&mut pending, chunk, |data| {
                total.extend_from_slice(data);
                *data = &[];
            });
        }
        assert_eq!(total, b"foobarbaz");
        assert!(pending.is_empty());
    }

    /// Issue #249: without a deadline the driver must not invent a 10ms
    /// cap — `None` lets mio block until UDP or a wake command.
    #[test]
    fn poll_wait_with_no_deadline_blocks_indefinitely() {
        assert_eq!(poll_wait(Instant::now(), None), None);
    }

    #[test]
    fn poll_wait_honours_a_future_deadline_exactly() {
        let now = Instant::now();
        let when = now + Duration::from_millis(250);
        assert_eq!(poll_wait(now, Some(when)), Some(Duration::from_millis(250)));
    }

    #[test]
    fn poll_wait_past_deadline_is_immediate() {
        let now = Instant::now();
        let when = now - Duration::from_millis(1);
        assert_eq!(poll_wait(now, Some(when)), Some(Duration::ZERO));
    }
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
    /// When true, unvalidated Incoming get Retry before handshake (RFC 9000 §8.1.2).
    require_address_validation: bool,
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
                    let early = pending_open && conn.has_0rtt();
                    self.connections.insert(
                        ch,
                        ConnSlot {
                            conn,
                            remote: peer,
                            streams: HashMap::new(),
                            client_pending_open: pending_open,
                            pending_open_bi: std::collections::VecDeque::new(),
                            app: None,
                            local_keys: HashMap::new(),
                        },
                    );
                    // 0-RTT: open the first bi stream (and any queued
                    // open_bi) right away so application writes can leave
                    // with the ClientHello. Drive the new stream before the
                    // main loop's first flush so early data is not left
                    // sitting only in handler out-queues.
                    if early {
                        #[cfg(all(test, feature = "integration"))]
                        early_open_probe::note();
                        self.open_pending_client_streams(ch);
                        self.drive_streams(ch, now);
                    }
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

    /// How long the mio poll should sleep before the next wake — the
    /// soonest of any app-level [`PendingTimer`] and every live connection's
    /// [`Connection::poll_timeout`] (idle / PTO / loss detection, …).
    ///
    /// Returns `None` when there is no deadline (block until UDP or a wake
    /// command). Previously this hard-capped at 10ms so idle connections
    /// spun the driver ~100×/s for their whole lifetime.
    fn next_timeout(&mut self) -> Option<Duration> {
        let now = Instant::now();
        let mut soon: Option<Instant> = None;
        for t in &self.timers {
            if !t.cancelled.load(Ordering::Acquire) {
                soon = Some(soon.map_or(t.when, |s| s.min(t.when)));
            }
        }
        for slot in self.connections.values_mut() {
            if let Some(t) = slot.conn.poll_timeout() {
                soon = Some(soon.map_or(t, |s| s.min(t)));
            }
        }
        poll_wait(now, soon)
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
                DriverCmd::OpenBi { factory, reply } => {
                    let result = self.open_bi_stream(factory);
                    let _ = reply.send(result);
                }
                DriverCmd::WithStream { conn, stream_id, task } => {
                    if let Some(slot) = self.connections.get_mut(&conn) {
                        if let Some(stream) = slot.streams.get_mut(&stream_id) {
                            task(&mut stream.endpoint);
                        }
                    }
                }
                DriverCmd::SendDatagram { conn, payload } => {
                    if let Some(slot) = self.connections.get_mut(&conn) {
                        let _ = slot.conn.datagrams().send(Bytes::from(payload), true);
                    }
                }
                DriverCmd::SetStreamPriority {
                    conn,
                    stream_id,
                    priority,
                } => {
                    if let Some(slot) = self.connections.get_mut(&conn) {
                        let _ = slot.conn.send_stream(stream_id).set_priority(priority);
                    }
                }
            }
        }
    }

    /// Open (or queue) a client-initiated bi stream with an explicit factory.
    fn open_bi_stream(&mut self, factory: HandlerFactory) -> io::Result<()> {
        if !matches!(self.mode, DriverMode::Client { .. }) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "open_bi is only supported on client (non-hooks) drivers",
            ));
        }
        let Some(ch) = self.connections.keys().next().copied() else {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "no QUIC connection to open a stream on",
            ));
        };
        let (pending, has_0rtt) = self
            .connections
            .get(&ch)
            .map(|s| (s.client_pending_open, s.conn.has_0rtt()))
            .unwrap_or((true, false));
        // Without 0-RTT, wait for Event::Connected. With 0-RTT available,
        // open immediately (and clear the first-stream pending latch if it
        // is still set — e.g. a raced open_bi before run() finished the
        // early-open path).
        if pending && !has_0rtt {
            if let Some(slot) = self.connections.get_mut(&ch) {
                slot.pending_open_bi.push_back(factory);
            }
            return Ok(());
        }
        if pending {
            // Promote the dial's factory stream first, then this open_bi.
            self.open_pending_client_streams(ch);
        }
        let Some(id) = self
            .connections
            .get_mut(&ch)
            .and_then(|s| s.conn.streams().open(Dir::Bi))
        else {
            // Peer concurrency limit (RFC 9000 §4.6) — queue until
            // StreamEvent::Available grants more credit.
            if let Some(slot) = self.connections.get_mut(&ch) {
                slot.pending_open_bi.push_back(factory);
            }
            return Ok(());
        };
        self.attach_stream_with_factory(ch, id, factory);
        Ok(())
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
                        self.handle_incoming(incoming, remote, now);
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

    /// Accept, Retry, or refuse a new Incoming per listen hardening.
    ///
    /// With [`crate::QuicListenHardening::require_address_validation`], an
    /// unvalidated address gets a Retry packet (RFC 9000 §8.1.2) so spoofed
    /// Initials never start a TLS handshake. Validated peers (Retry token or
    /// NEW_TOKEN) are accepted immediately.
    fn handle_incoming(&mut self, incoming: Incoming, remote: SocketAddr, now: Instant) {
        if self.require_address_validation && !incoming.remote_address_validated() {
            match self.endpoint.retry(incoming, &mut self.send_buf) {
                Ok(tx) => self.send_transmit(tx),
                Err(err) => {
                    // Already carried a Retry token but still unvalidated —
                    // refuse rather than looping Retry forever.
                    let tx = self
                        .endpoint
                        .refuse(err.into_incoming(), &mut self.send_buf);
                    self.send_transmit(tx);
                }
            }
            return;
        }

        match self.endpoint.accept(incoming, now, &mut self.send_buf, None) {
            Ok((ch, conn)) => {
                self.connections.insert(
                    ch,
                    ConnSlot {
                        conn,
                        remote,
                        streams: HashMap::new(),
                        client_pending_open: false,
                        pending_open_bi: std::collections::VecDeque::new(),
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
                Event::ConnectionLost { reason } => {
                    self.on_connection_lost(ch, reason);
                    return;
                }
                Event::Stream(se) => self.on_stream_event(ch, se),
                Event::DatagramReceived => {
                    self.drain_datagrams(ch);
                }
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

        // Plain client: open the first bi stream once Connected (unless
        // 0-RTT already did so right after connect()).
        self.open_pending_client_streams(ch);
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

    /// Open the dial's first bi stream and drain any queued `open_bi`
    /// factories. No-op unless this is a plain client still marked
    /// `client_pending_open`. Called from the 0-RTT path right after
    /// `connect()`, from [`Self::on_connected`] for the 1-RTT path, and
    /// from [`Self::open_bi_stream`] when a late `open_bi` races with an
    /// available 0-RTT window.
    fn open_pending_client_streams(&mut self, ch: ConnectionHandle) {
        let open_client = matches!(
            (
                &self.mode,
                self.connections.get(&ch).map(|s| s.client_pending_open)
            ),
            (DriverMode::Client { .. }, Some(true))
        );
        if !open_client {
            return;
        }
        if let Some(slot) = self.connections.get_mut(&ch) {
            slot.client_pending_open = false;
            if let Some(id) = slot.conn.streams().open(Dir::Bi) {
                self.attach_stream_dir(ch, id, Dir::Bi);
            }
        }
        self.drain_pending_open_bi(ch);
    }

    /// Apply as many queued [`DriverCmd::OpenBi`] factories as the peer's
    /// current bi-stream credit allows. Stops (leaving the rest queued)
    /// when `streams().open(Dir::Bi)` returns `None`;
    /// [`StreamEvent::Available`] will call this again.
    fn drain_pending_open_bi(&mut self, ch: ConnectionHandle) {
        loop {
            let Some(factory) = self
                .connections
                .get_mut(&ch)
                .and_then(|s| s.pending_open_bi.pop_front())
            else {
                return;
            };
            let Some(id) = self
                .connections
                .get_mut(&ch)
                .and_then(|s| s.conn.streams().open(Dir::Bi))
            else {
                if let Some(slot) = self.connections.get_mut(&ch) {
                    slot.pending_open_bi.push_front(factory);
                }
                return;
            };
            self.attach_stream_with_factory(ch, id, factory);
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
                        Dir::Bi => app.accept_bi(u64::from(id)),
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
                            pending_in: Vec::new(),
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
                RecorderAction::SendDatagram { data } => {
                    if let Some(slot) = self.connections.get_mut(&ch) {
                        let _ = slot.conn.datagrams().send(Bytes::from(data), true);
                    }
                }
                RecorderAction::SetStreamPriority {
                    stream_id,
                    priority,
                } => {
                    if let Some(slot) = self.connections.get_mut(&ch) {
                        if let Ok(vid) = VarInt::from_u64(stream_id) {
                            let sid = StreamId::from(vid);
                            let _ = slot.conn.send_stream(sid).set_priority(priority);
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

    /// Drain inbound QUIC DATAGRAMs (RFC 9221), ask the connection app how
    /// to route each payload, and deliver / abort / close accordingly.
    fn drain_datagrams(&mut self, ch: ConnectionHandle) {
        loop {
            let raw = {
                let Some(slot) = self.connections.get_mut(&ch) else {
                    return;
                };
                match slot.conn.datagrams().recv() {
                    Some(b) => b,
                    None => return,
                }
            };
            let decode = {
                let Some(slot) = self.connections.get_mut(&ch) else {
                    return;
                };
                match slot.app.as_mut() {
                    Some(app) => app.decode_datagram(&raw),
                    None => DatagramDecode::Drop,
                }
            };
            match decode {
                DatagramDecode::Drop => {}
                DatagramDecode::Deliver { stream_id, payload } => {
                    let Ok(vid) = VarInt::from_u64(stream_id) else {
                        continue;
                    };
                    let sid = StreamId::from(vid);
                    if let Some(slot) = self.connections.get_mut(&ch) {
                        if let Some(stream) = slot.streams.get_mut(&sid) {
                            stream
                                .handler
                                .datagram_received(&mut stream.endpoint, &payload);
                        }
                    }
                }
                DatagramDecode::AbortStream {
                    stream_id,
                    error_code,
                } => {
                    let Ok(vid) = VarInt::from_u64(stream_id) else {
                        continue;
                    };
                    let sid = StreamId::from(vid);
                    if let Some(slot) = self.connections.get_mut(&ch) {
                        if let Some(stream) = slot.streams.get_mut(&sid) {
                            stream.endpoint.abort(error_code);
                        }
                    }
                }
                DatagramDecode::CloseConnection { error_code } => {
                    if let Some(slot) = self.connections.get_mut(&ch) {
                        if let Ok(code) = VarInt::from_u64(u64::from(error_code)) {
                            slot.conn.close(Instant::now(), code, Bytes::new());
                        }
                    }
                    return;
                }
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
            StreamEvent::Finished { id } => {
                // Our send half is fully acknowledged. Drain any final peer
                // data/FIN first (which may already have torn the stream
                // down via read_stream), then drop the handler if still live.
                self.read_stream(ch, id);
                self.finish_stream(ch, id, None);
            }
            StreamEvent::Stopped { id, error_code } => {
                // Peer STOP_SENDING (RFC 9000 §19.5) — surface the app error
                // code via ProtocolHandler::error, not the argument-free
                // disconnected() path used for a clean FIN.
                self.read_stream(ch, id);
                self.finish_stream(ch, id, Some(stream_stopped_io_error(error_code)));
            }
            StreamEvent::Available { dir: Dir::Bi } => {
                // Peer raised MAX_STREAMS (or freed credit after a finished
                // stream) — retry any open_bi that hit the concurrency cap.
                self.drain_pending_open_bi(ch);
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
                    Dir::Bi => app.accept_bi(u64::from(id)),
                    Dir::Uni => app.accept_uni(u64::from(id)),
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
                    send_only: matches!(dir, Dir::Uni),
                    pending_in: Vec::new(),
                },
            );
        }
    }

    /// Like [`Self::attach_stream_dir`] for a client-opened bi stream whose
    /// handler comes from an explicit factory (connection-reuse path).
    fn attach_stream_with_factory(
        &mut self,
        ch: ConnectionHandle,
        id: StreamId,
        factory: HandlerFactory,
    ) {
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
        let mut handler = factory();
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
                    pending_in: Vec::new(),
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
        let mut new_data = Vec::new();
        let mut peer_finished = false;
        loop {
            match chunks.next(usize::MAX) {
                Ok(Some(chunk)) => {
                    new_data.extend_from_slice(&chunk.bytes);
                }
                Ok(None) => {
                    // Peer FIN (or reset path already freed recv) — both
                    // directions must close before MAX_STREAMS credit returns.
                    peer_finished = true;
                    break;
                }
                Err(_) => break,
            }
        }
        let _ = chunks.finalize();

        if !new_data.is_empty() {
            if let Some(stream) = slot.streams.get_mut(&id) {
                let handler = &mut stream.handler;
                let endpoint = &mut stream.endpoint;
                deliver_with_residual(&mut stream.pending_in, &new_data, |slice| {
                    handler.receive(endpoint, slice);
                });
            }
        }

        if peer_finished {
            // Finish our send half so a bidi stream becomes fully closed and
            // the peer can raise MAX_STREAMS (RFC 9000 §4.6).
            if let Some(slot) = self.connections.get_mut(&ch) {
                let _ = slot.conn.send_stream(id).finish();
            }
            self.finish_stream(ch, id, None);
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

    /// Tear down a stream. `err` is `Some` for abnormal teardown
    /// (STOP_SENDING / connection lost with a reason) and reaches
    /// [`ProtocolHandler::error`]; `None` is a clean FIN → `disconnected`.
    fn finish_stream(&mut self, ch: ConnectionHandle, id: StreamId, err: Option<io::Error>) {
        if let Some(slot) = self.connections.get_mut(&ch) {
            if let Some(mut stream) = slot.streams.remove(&id) {
                stream.endpoint.mark_closed();
                match &err {
                    Some(e) => stream.handler.error(&mut stream.endpoint, e),
                    None => stream.handler.disconnected(&mut stream.endpoint),
                }
            }
        }
    }

    /// Tear down every stream on a lost connection. Clean local shutdown
    /// (`LocallyClosed`) still calls `disconnected`; every other
    /// [`ConnectionError`] is mapped to an `io::Error` and delivered via
    /// `ProtocolHandler::error` (Gumdrop `QuicConnectionCloseException`
    /// pattern) so protocols can read application / transport error codes.
    fn on_connection_lost(&mut self, ch: ConnectionHandle, reason: ConnectionError) {
        let err = connection_lost_io_error(reason);
        if let Some(mut slot) = self.connections.remove(&ch) {
            let ids: Vec<_> = slot.streams.keys().copied().collect();
            for id in ids {
                if let Some(mut stream) = slot.streams.remove(&id) {
                    stream.endpoint.mark_closed();
                    match &err {
                        Some(e) => stream.handler.error(&mut stream.endpoint, e),
                        None => stream.handler.disconnected(&mut stream.endpoint),
                    }
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


/// Integration-test seam: set when the client driver opens its first bi
/// stream immediately after `connect()` because [`Connection::has_0rtt`]
/// was true (see `early_data_second_dial_opens_stream_before_connected`).
#[cfg(all(test, feature = "integration"))]
mod early_open_probe {
    use std::sync::atomic::{AtomicBool, Ordering};

    static DID_EARLY_OPEN: AtomicBool = AtomicBool::new(false);

    pub(super) fn reset() {
        DID_EARLY_OPEN.store(false, Ordering::SeqCst);
    }

    pub(super) fn note() {
        DID_EARLY_OPEN.store(true, Ordering::SeqCst);
    }

    pub(super) fn took() -> bool {
        DID_EARLY_OPEN.load(Ordering::SeqCst)
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
    SendDatagram { data: Vec<u8> },
    SetStreamPriority { stream_id: u64, priority: i32 },
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

    fn send_datagram(&mut self, payload: &[u8]) -> io::Result<()> {
        self.actions.push(RecorderAction::SendDatagram {
            data: payload.to_vec(),
        });
        Ok(())
    }

    fn set_stream_priority(&mut self, stream_id: u64, priority: i32) {
        self.actions.push(RecorderAction::SetStreamPriority {
            stream_id,
            priority,
        });
    }
}

#[cfg(all(test, feature = "integration"))]
mod tests {
    use super::*;
    use crate::config::{client_config_for_pem_bytes, server_config_self_signed};
    use std::sync::Mutex as StdMutex;
    use hopf_core::{Endpoint, NopHandler, ProtocolHandler};

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

    /// Default listen hardening requires Retry before accept; a normal
    /// quinn client still completes the handshake (extra localhost RTT).
    #[test]
    fn listen_hardening_retry_still_completes_handshake() {
        let (server_cfg, pem) =
            server_config_self_signed(&["localhost"], &[b"hq-interop"]).unwrap();
        let client_cfg = client_config_for_pem_bytes(&pem, &[b"hq-interop"]).unwrap();

        let server = listen_quic(
            QuicListenConfig::new(
                "127.0.0.1:0".parse().unwrap(),
                server_cfg,
                Arc::new(|| Box::new(Echo) as Box<dyn ProtocolHandler>),
            )
            .with_hardening(crate::QuicListenHardening::high_security()),
        )
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
        assert_eq!(
            got.lock().unwrap().as_slice(),
            b"ping",
            "handshake through Retry must succeed"
        );
        server.shutdown();
    }

    /// A handler that only consumes once it has the full expected message,
    /// otherwise leaves everything unconsumed — exercises the NIO
    /// compact-buffer fix from #179 (a token split across two chunks must
    /// reassemble) *and* proves `Endpoint::handle().with_endpoint(...)` now
    /// genuinely dispatches for a QUIC stream, which is what let this test
    /// actually be written for real instead of via a pure unit test of the
    /// extracted buffer logic.
    struct SplitTokenProbe {
        expected: &'static [u8],
        done: Arc<StdMutex<Option<Vec<u8>>>>,
    }

    impl ProtocolHandler for SplitTokenProbe {
        fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}
        fn receive(&mut self, _endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
            if data.len() < self.expected.len() {
                return; // not enough yet — consume nothing, wait for more
            }
            *self.done.lock().unwrap() = Some(data.to_vec());
            *data = &[];
        }
        fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}
        fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &io::Error) {}
    }

    /// Sends `first` on `connected()`, then `second` ~40ms later via a real
    /// timer + `ConnHandle::with_endpoint` — the exact path that was a
    /// silent no-op before `QuicStreamEndpoint::handle()` returned a
    /// `ConnHandleBackend`-based handle instead of a bare `from_execute`
    /// one.
    struct FirstThenSecondSender {
        first: &'static [u8],
        second: &'static [u8],
    }

    impl ProtocolHandler for FirstThenSecondSender {
        fn connected(&mut self, endpoint: &mut dyn Endpoint) {
            endpoint.send(self.first);
            let second = self.second;
            let handle = endpoint.handle();
            endpoint.schedule_timer(
                Duration::from_millis(40),
                Box::new(move || {
                    handle.with_endpoint(move |ep| ep.send(second));
                }),
            );
        }
        fn receive(&mut self, _endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
            *data = &[];
        }
        fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}
        fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &io::Error) {}
    }

    #[test]
    fn conn_handle_with_endpoint_delivers_a_second_chunk_from_a_timer() {
        const FIRST: &[u8] = b"PIN";
        const SECOND: &[u8] = b"G-1234";
        const WHOLE: &[u8] = b"PING-1234";

        let (server_cfg, pem) =
            server_config_self_signed(&["localhost"], &[b"hq-interop"]).unwrap();
        let client_cfg = client_config_for_pem_bytes(&pem, &[b"hq-interop"]).unwrap();

        let done = Arc::new(StdMutex::new(None));
        let done2 = Arc::clone(&done);
        let server = listen_quic(QuicListenConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            server_cfg,
            Arc::new(move || {
                Box::new(SplitTokenProbe { expected: WHOLE, done: Arc::clone(&done2) })
                    as Box<dyn ProtocolHandler>
            }),
        ))
        .unwrap();

        let _client = connect_quic(QuicConnectConfig::new(
            server.local_addr,
            client_cfg,
            "localhost",
            Arc::new(move || {
                Box::new(FirstThenSecondSender { first: FIRST, second: SECOND })
                    as Box<dyn ProtocolHandler>
            }),
        ))
        .unwrap();

        for _ in 0..200 {
            if done.lock().unwrap().is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            done.lock().unwrap().as_deref(),
            Some(WHOLE),
            "ConnHandle::with_endpoint never delivered the second chunk for a QUIC stream"
        );

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

    /// Records both clean `disconnected` and abnormal `error` teardown.
    struct TeardownRecorder {
        disconnected: Arc<std::sync::atomic::AtomicBool>,
        errored: Arc<std::sync::atomic::AtomicBool>,
        last_error: Arc<StdMutex<Option<io::Error>>>,
    }

    impl ProtocolHandler for TeardownRecorder {
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
        fn error(&mut self, _endpoint: &mut dyn Endpoint, err: &io::Error) {
            self.errored.store(true, std::sync::atomic::Ordering::SeqCst);
            // Prefer retaining a typed close error when present so tests can
            // downcast; otherwise keep kind + Display text.
            let stored = if let Some(close) = crate::connection_close_error(err) {
                close.clone().into_io()
            } else {
                io::Error::new(err.kind(), err.to_string())
            };
            *self.last_error.lock().unwrap() = Some(stored);
        }
    }

    /// A real, much-shorter-than-default idle timeout applied via
    /// [`QuicTransportOptions`] actually tears the connection down on its
    /// own — proves the config is wired into quinn-proto's real transport
    /// parameters, not just accepted and ignored. Idle timeout is abnormal
    /// teardown, so it reaches `ProtocolHandler::error` (TimedOut), not
    /// the clean-close `disconnected` path.
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
        let server_errored = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let server_last = Arc::new(StdMutex::new(None));
        let server_disconnected2 = Arc::clone(&server_disconnected);
        let server_errored2 = Arc::clone(&server_errored);
        let server_last2 = Arc::clone(&server_last);
        let server = listen_quic(QuicListenConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            server_cfg,
            Arc::new(move || {
                Box::new(TeardownRecorder {
                    disconnected: Arc::clone(&server_disconnected2),
                    errored: Arc::clone(&server_errored2),
                    last_error: Arc::clone(&server_last2),
                }) as Box<dyn ProtocolHandler>
            }),
        ))
        .unwrap();

        let client_disconnected = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let client_errored = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let client_last = Arc::new(StdMutex::new(None));
        let client_disconnected2 = Arc::clone(&client_disconnected);
        let client_errored2 = Arc::clone(&client_errored);
        let client_last2 = Arc::clone(&client_last);
        let _client = connect_quic(QuicConnectConfig::new(
            server.local_addr,
            client_cfg,
            "localhost",
            Arc::new(move || {
                Box::new(TeardownRecorder {
                    disconnected: Arc::clone(&client_disconnected2),
                    errored: Arc::clone(&client_errored2),
                    last_error: Arc::clone(&client_last2),
                }) as Box<dyn ProtocolHandler>
            }),
        ))
        .unwrap();

        // No further traffic after the initial byte — with a 200ms idle
        // timeout, both sides must tear the connection down well within
        // this window; the default (30s) never would.
        for _ in 0..150 {
            if server_errored.load(std::sync::atomic::Ordering::SeqCst)
                && client_errored.load(std::sync::atomic::Ordering::SeqCst)
            {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert!(
            server_errored.load(std::sync::atomic::Ordering::SeqCst),
            "server never saw the idle timeout via error()"
        );
        assert!(
            client_errored.load(std::sync::atomic::Ordering::SeqCst),
            "client never saw the idle timeout via error()"
        );
        assert!(
            !server_disconnected.load(std::sync::atomic::Ordering::SeqCst),
            "idle timeout must not use the clean disconnected() path"
        );
        assert!(
            !client_disconnected.load(std::sync::atomic::Ordering::SeqCst),
            "idle timeout must not use the clean disconnected() path"
        );
        assert_eq!(
            server_last.lock().unwrap().as_ref().map(|e| e.kind()),
            Some(io::ErrorKind::TimedOut)
        );

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
        let server_errored = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let server_last = Arc::new(StdMutex::new(None));
        let server_disconnected2 = Arc::clone(&server_disconnected);
        let server_errored2 = Arc::clone(&server_errored);
        let server_last2 = Arc::clone(&server_last);
        let server = listen_quic(QuicListenConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            server_cfg,
            Arc::new(move || {
                Box::new(TeardownRecorder {
                    disconnected: Arc::clone(&server_disconnected2),
                    errored: Arc::clone(&server_errored2),
                    last_error: Arc::clone(&server_last2),
                }) as Box<dyn ProtocolHandler>
            }),
        ))
        .unwrap();

        let client_disconnected = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let client_errored = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let client_last = Arc::new(StdMutex::new(None));
        let client_disconnected2 = Arc::clone(&client_disconnected);
        let client_errored2 = Arc::clone(&client_errored);
        let client_last2 = Arc::clone(&client_last);
        let _client = connect_quic(QuicConnectConfig::new(
            server.local_addr,
            client_cfg,
            "localhost",
            Arc::new(move || {
                Box::new(TeardownRecorder {
                    disconnected: Arc::clone(&client_disconnected2),
                    errored: Arc::clone(&client_errored2),
                    last_error: Arc::clone(&client_last2),
                }) as Box<dyn ProtocolHandler>
            }),
        ))
        .unwrap();

        // Without keepalive, both sides disconnect by ~200ms. Wait several
        // idle periods; keep-alive must keep the connection up.
        thread::sleep(Duration::from_millis(800));
        assert!(
            !server_disconnected.load(std::sync::atomic::Ordering::SeqCst)
                && !server_errored.load(std::sync::atomic::Ordering::SeqCst),
            "server disconnected despite client keep-alive"
        );
        assert!(
            !client_disconnected.load(std::sync::atomic::Ordering::SeqCst)
                && !client_errored.load(std::sync::atomic::Ordering::SeqCst),
            "client disconnected despite its own keep-alive"
        );

        server.shutdown();
    }

    /// Peer `close_connection(app_error_code)` must reach the other side's
    /// `ProtocolHandler::error` as a [`crate::QuicConnectionCloseError`]
    /// carrying that code — not the argument-free `disconnected()` path.
    #[test]
    fn peer_application_close_delivers_connection_close_error() {
        const APP_CODE: u64 = 0x010c; // H3_REQUEST_CANCELLED

        let (server_cfg, pem) =
            server_config_self_signed(&["localhost"], &[b"close-test"]).unwrap();
        let client_cfg = client_config_for_pem_bytes(&pem, &[b"close-test"]).unwrap();

        let server_disconnected = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let server_errored = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let server_last = Arc::new(StdMutex::new(None));
        let server_disconnected2 = Arc::clone(&server_disconnected);
        let server_errored2 = Arc::clone(&server_errored);
        let server_last2 = Arc::clone(&server_last);
        let server = listen_quic(QuicListenConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            server_cfg,
            Arc::new(move || {
                Box::new(TeardownRecorder {
                    disconnected: Arc::clone(&server_disconnected2),
                    errored: Arc::clone(&server_errored2),
                    last_error: Arc::clone(&server_last2),
                }) as Box<dyn ProtocolHandler>
            }),
        ))
        .unwrap();

        struct CloseAfterSend;
        impl ProtocolHandler for CloseAfterSend {
            fn connected(&mut self, endpoint: &mut dyn Endpoint) {
                endpoint.send(b"x");
                endpoint.close_connection(APP_CODE as u32);
            }
            fn receive(&mut self, _endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
                *data = &[];
            }
            fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}
            fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &io::Error) {}
        }

        let _client = connect_quic(QuicConnectConfig::new(
            server.local_addr,
            client_cfg,
            "localhost",
            Arc::new(|| Box::new(CloseAfterSend) as Box<dyn ProtocolHandler>),
        ))
        .unwrap();

        for _ in 0..200 {
            if server_errored.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }

        assert!(
            server_errored.load(std::sync::atomic::Ordering::SeqCst),
            "server never received ProtocolHandler::error for the peer application close"
        );
        assert!(
            !server_disconnected.load(std::sync::atomic::Ordering::SeqCst),
            "application CONNECTION_CLOSE must not use disconnected()"
        );
        let last = server_last.lock().unwrap();
        let err = last.as_ref().expect("error payload");
        let close = crate::connection_close_error(err).expect("QuicConnectionCloseError");
        assert!(close.application_error);
        assert_eq!(close.error_code, APP_CODE);

        server.shutdown();
    }

    /// With early data opted in on both peers and a shared client config
    /// (so rustls can cache the session ticket), the second dial must open
    /// its first bi stream immediately after `connect()` — before
    /// `Event::Connected` — so application writes can ride as 0-RTT.
    #[test]
    fn early_data_second_dial_opens_stream_before_connected() {
        use crate::config::{
            client_config_for_pem_bytes_with, server_config_self_signed_with, QuicTlsOptions,
        };

        let tls = QuicTlsOptions::new().with_early_data();
        let (server_cfg, pem) =
            server_config_self_signed_with(&["localhost"], &[b"hq-interop"], tls).unwrap();
        let client_cfg =
            client_config_for_pem_bytes_with(&pem, &[b"hq-interop"], tls).unwrap();

        let server = listen_quic(QuicListenConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            server_cfg,
            Arc::new(|| Box::new(Echo) as Box<dyn ProtocolHandler>),
        ))
        .unwrap();

        let echo_once = |client_cfg: Arc<crate::QuicClientConfig>| {
            let got = Arc::new(StdMutex::new(Vec::new()));
            let got2 = Arc::clone(&got);
            let client = connect_quic(QuicConnectConfig::new(
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
            client.shutdown();
        };

        // First dial: full handshake, fills the rustls session-ticket cache.
        early_open_probe::reset();
        echo_once(Arc::clone(&client_cfg));
        assert!(
            !early_open_probe::took(),
            "cold dial must not 0-RTT-open (no ticket yet)"
        );

        // Second dial: same ClientConfig Arc → ticket available → has_0rtt.
        early_open_probe::reset();
        echo_once(Arc::clone(&client_cfg));
        for _ in 0..50 {
            if early_open_probe::took() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            early_open_probe::took(),
            "resumed dial with early data enabled must open the first stream before Connected"
        );

        server.shutdown();
    }

    /// Holds the dial's first bi stream open until `release` is set, polling
    /// via the QUIC timer path so we can open a second stream against a
    /// peer that only grants one concurrent bidi at a time.
    struct HoldUntilRelease {
        release: Arc<std::sync::atomic::AtomicBool>,
        signaled: Arc<std::sync::atomic::AtomicBool>,
    }

    impl HoldUntilRelease {
        fn arm_poll(endpoint: &mut dyn Endpoint, release: Arc<std::sync::atomic::AtomicBool>) {
            let handle = endpoint.handle();
            endpoint.schedule_timer(
                Duration::from_millis(10),
                Box::new(move || {
                    handle.with_endpoint(move |ep| {
                        if release.load(std::sync::atomic::Ordering::SeqCst) {
                            ep.close();
                        } else {
                            Self::arm_poll(ep, release);
                        }
                    });
                }),
            );
        }
    }

    impl ProtocolHandler for HoldUntilRelease {
        fn connected(&mut self, endpoint: &mut dyn Endpoint) {
            endpoint.send(b"hold");
            self.signaled
                .store(true, std::sync::atomic::Ordering::SeqCst);
            Self::arm_poll(endpoint, Arc::clone(&self.release));
        }
        fn receive(&mut self, _endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
            *data = &[];
        }
        fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}
        fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &io::Error) {}
    }

    /// When the peer advertises only one concurrent bidi stream, a second
    /// `open_bi` must queue (not fail) and complete once
    /// `StreamEvent::Available` reports new `MAX_STREAMS` credit.
    #[test]
    fn open_bi_queues_until_stream_credit_available() {
        use crate::config::{apply_server_transport_options, QuicTransportOptions};
        use std::sync::atomic::{AtomicBool, Ordering};

        let (mut server_cfg, pem) =
            server_config_self_signed(&["localhost"], &[b"hq-interop"]).unwrap();
        apply_server_transport_options(
            &mut server_cfg,
            &QuicTransportOptions::new().max_concurrent_bidi_streams(1),
        )
        .unwrap();
        let client_cfg = client_config_for_pem_bytes(&pem, &[b"hq-interop"]).unwrap();

        let server = listen_quic(QuicListenConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            server_cfg,
            Arc::new(|| Box::new(Echo) as Box<dyn ProtocolHandler>),
        ))
        .unwrap();

        let release = Arc::new(AtomicBool::new(false));
        let first_up = Arc::new(AtomicBool::new(false));
        let client = connect_quic(QuicConnectConfig::new(
            server.local_addr,
            client_cfg,
            "localhost",
            {
                let release = Arc::clone(&release);
                let first_up = Arc::clone(&first_up);
                Arc::new(move || {
                    Box::new(HoldUntilRelease {
                        release: Arc::clone(&release),
                        signaled: Arc::clone(&first_up),
                    }) as Box<dyn ProtocolHandler>
                })
            },
        ))
        .unwrap();

        for _ in 0..200 {
            if first_up.load(Ordering::SeqCst) {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            first_up.load(Ordering::SeqCst),
            "first (sole) stream never opened"
        );

        let second_up = Arc::new(AtomicBool::new(false));
        let second_up2 = Arc::clone(&second_up);
        client
            .open_bi(Arc::new(move || {
                Box::new(MarkConnected {
                    flag: Arc::clone(&second_up2),
                }) as Box<dyn ProtocolHandler>
            }))
            .expect("open_bi should queue under MAX_STREAMS, not fail");

        // While the first stream still occupies the only credit slot, the
        // queued open must not have attached yet.
        thread::sleep(Duration::from_millis(50));
        assert!(
            !second_up.load(Ordering::SeqCst),
            "second stream opened before MAX_STREAMS credit was freed"
        );

        release.store(true, Ordering::SeqCst);
        for _ in 0..200 {
            if second_up.load(Ordering::SeqCst) {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            second_up.load(Ordering::SeqCst),
            "queued open_bi never drained after StreamEvent::Available"
        );

        client.shutdown();
        server.shutdown();
    }

    struct MarkConnected {
        flag: Arc<std::sync::atomic::AtomicBool>,
    }

    impl ProtocolHandler for MarkConnected {
        fn connected(&mut self, endpoint: &mut dyn Endpoint) {
            self.flag
                .store(true, std::sync::atomic::Ordering::SeqCst);
            endpoint.send(b"second");
            endpoint.close();
        }
        fn receive(&mut self, _endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
            *data = &[];
        }
        fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}
        fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &io::Error) {}
    }

    /// RFC 9221: connection-scoped DATAGRAM send/recv via hooks.
    struct DatagramEchoConn {
        got: Arc<StdMutex<Vec<u8>>>,
        reply: Option<Vec<u8>>,
    }

    impl QuicConnection for DatagramEchoConn {
        fn connected(&mut self, _api: &mut dyn QuicConnApi) {}
        fn accept_bi(&mut self, _stream_id: u64) -> Box<dyn ProtocolHandler> {
            Box::new(NopHandler)
        }
        fn accept_uni(&mut self, _stream_id: u64) -> Box<dyn ProtocolHandler> {
            Box::new(NopHandler)
        }
        fn decode_datagram(&mut self, data: &[u8]) -> crate::DatagramDecode {
            self.got.lock().unwrap().extend_from_slice(data);
            self.reply = Some(b"pong".to_vec());
            crate::DatagramDecode::Drop
        }
        fn drive(&mut self, api: &mut dyn QuicConnApi) {
            if let Some(payload) = self.reply.take() {
                let _ = api.send_datagram(&payload);
            }
        }
    }

    struct DatagramClientConn {
        sent: bool,
        got: Arc<StdMutex<Vec<u8>>>,
    }

    impl QuicConnection for DatagramClientConn {
        fn connected(&mut self, api: &mut dyn QuicConnApi) {
            let _ = api.send_datagram(b"ping");
            self.sent = true;
        }
        fn accept_bi(&mut self, _stream_id: u64) -> Box<dyn ProtocolHandler> {
            Box::new(NopHandler)
        }
        fn accept_uni(&mut self, _stream_id: u64) -> Box<dyn ProtocolHandler> {
            Box::new(NopHandler)
        }
        fn decode_datagram(&mut self, data: &[u8]) -> crate::DatagramDecode {
            self.got.lock().unwrap().extend_from_slice(data);
            crate::DatagramDecode::Drop
        }
    }

    #[test]
    fn quic_datagram_echo_round_trip() {
        let (server_cfg, pem) =
            server_config_self_signed(&["localhost"], &[b"hq-interop"]).unwrap();
        let client_cfg = client_config_for_pem_bytes(&pem, &[b"hq-interop"]).unwrap();

        let server_got = Arc::new(StdMutex::new(Vec::new()));
        let server_got2 = Arc::clone(&server_got);
        let server = listen_quic_hooks(crate::QuicListenHooksConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            server_cfg,
            Arc::new(move || {
                Box::new(DatagramEchoConn {
                    got: Arc::clone(&server_got2),
                    reply: None,
                }) as Box<dyn QuicConnection>
            }),
        ))
        .unwrap();

        let client_got = Arc::new(StdMutex::new(Vec::new()));
        let client_got2 = Arc::clone(&client_got);
        let _client = connect_quic_hooks(
            server.local_addr,
            client_cfg,
            "localhost",
            Arc::new(move || {
                Box::new(DatagramClientConn {
                    sent: false,
                    got: Arc::clone(&client_got2),
                }) as Box<dyn QuicConnection>
            }),
        )
        .unwrap();

        for _ in 0..200 {
            if client_got.lock().unwrap().as_slice() == b"pong"
                && server_got.lock().unwrap().as_slice() == b"ping"
            {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(server_got.lock().unwrap().as_slice(), b"ping");
        assert_eq!(client_got.lock().unwrap().as_slice(), b"pong");
        server.shutdown();
    }
}
