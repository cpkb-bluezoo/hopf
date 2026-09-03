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
    EndpointConfig, Event, Incoming, SendDatagramError, StreamEvent, StreamId, Transmit, VarInt,
};
use hopf_core::{Endpoint, HandlerFactory, ProtocolHandler, SecurityInfo};

use crate::config::{
    apply_listen_hardening, QuicConnectConfig, QuicListenConfig, QuicListenHooksConfig,
};
use crate::error::{connection_lost_io_error, datagram_send_io_error, stream_stopped_io_error};
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
        stream_id: Option<StreamId>,
    },
    /// Set send priority for a stream (RFC 9218 via quinn-proto).
    SetStreamPriority {
        conn: ConnectionHandle,
        stream_id: StreamId,
        priority: i32,
    },
    /// A datagram arrived on a [`crate::path::QuicDatagramPath`] with no
    /// file descriptor to register with `mio::Poll` — the push-based
    /// counterpart to the default socket's poll-driven
    /// [`Driver::on_udp_readable`]. See
    /// [`QuicDriverHandle::receive_path_datagram`].
    PathDatagram {
        data: Vec<u8>,
        source: SocketAddr,
        ecn: Option<u8>,
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
    ///
    /// The driver will flush any queued application writes (e.g. H3 GOAWAY),
    /// then send CONNECTION_CLOSE on every open connection, transmit those
    /// datagrams, and only then stop.  Using just `active.store(false)` would
    /// skip all of that.
    pub fn shutdown(mut self) {
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

    /// Deliver a datagram received on a [`crate::path::QuicDatagramPath`]
    /// to this connection — the push-based counterpart to the default
    /// socket transport's poll-driven receive, for a path with no file
    /// descriptor to register with a `Selector`/`mio::Poll`.
    ///
    /// Safe to call from any thread: the datagram is handed to the
    /// driver's own worker thread via the same command channel every other
    /// externally-triggered entry point into a connection already goes
    /// through (e.g. [`Self::open_bi`]), never processed inline on the
    /// calling thread.
    pub fn receive_path_datagram(&self, data: Vec<u8>, source: SocketAddr) -> io::Result<()> {
        self.receive_path_datagram_with_ecn(data, source, None)
    }

    /// [`Self::receive_path_datagram`], additionally reporting the ECN
    /// codepoint the path itself observed for this datagram, if it can
    /// recover one (most non-socket paths won't have one to report — `None`
    /// is the normal case).
    pub fn receive_path_datagram_with_ecn(
        &self,
        data: Vec<u8>,
        source: SocketAddr,
        ecn: Option<u8>,
    ) -> io::Result<()> {
        if !self.active.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "QUIC driver shut down",
            ));
        }
        self.cmd_tx
            .send(DriverCmd::PathDatagram { data, source, ecn })
            .map_err(|_| io::Error::new(io::ErrorKind::NotConnected, "QUIC driver shut down"))?;
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
    let (socket, local_addr) = crate::udp::bind_udp(config.addr)?;

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
        DatagramTransport::Socket(socket),
        local_addr,
        None,
        require_address_validation,
    )
}

/// [`listen_quic`], but accepting connections over `path` instead of a
/// real UDP socket — see [`crate::QuicDatagramPath`].
pub fn listen_quic_with_path(
    config: QuicListenConfig,
    path: Box<dyn crate::path::QuicDatagramPath>,
    local_addr: SocketAddr,
) -> io::Result<QuicDriverHandle> {
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
        DatagramTransport::Path(path),
        local_addr,
        None,
        require_address_validation,
    )
}

/// Bind UDP and accept QUIC connections using connection-level hooks (H3).
pub fn listen_quic_hooks(config: QuicListenHooksConfig) -> io::Result<QuicDriverHandle> {
    let (socket, local_addr) = crate::udp::bind_udp(config.addr)?;

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
        DatagramTransport::Socket(socket),
        local_addr,
        None,
        require_address_validation,
    )
}

/// [`listen_quic_hooks`], but accepting connections over `path` instead of
/// a real UDP socket — see [`crate::QuicDatagramPath`].
pub fn listen_quic_hooks_with_path(
    config: QuicListenHooksConfig,
    path: Box<dyn crate::path::QuicDatagramPath>,
    local_addr: SocketAddr,
) -> io::Result<QuicDriverHandle> {
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
        DatagramTransport::Path(path),
        local_addr,
        None,
        require_address_validation,
    )
}

/// Dial a peer, open one bidirectional stream, and attach `config.factory` handler.
pub fn connect_quic(config: QuicConnectConfig) -> io::Result<QuicDriverHandle> {
    let (socket, local_addr) =
        crate::udp::bind_udp(crate::udp::unspecified_bind_addr(config.addr))?;

    let endpoint = QuinnEndpoint::new(Arc::new(EndpointConfig::default()), None, true, None);

    spawn_driver(
        DriverMode::Client {
            factory: config.factory,
            peer: config.addr,
            client_config: Arc::clone(&config.client),
            server_name: config.server_name,
        },
        endpoint,
        DatagramTransport::Socket(socket),
        local_addr,
        Some(config.addr),
        false,
    )
}

/// [`connect_quic`], but over `path` instead of a real UDP socket — see
/// [`crate::QuicDatagramPath`]. `local_addr` is reported back to the
/// application (e.g. via [`QuicDriverHandle::local_addr`]) exactly as
/// given; it does not have to be routable, since `path` (not the OS
/// network stack) is what actually carries the datagrams.
pub fn connect_quic_with_path(
    config: QuicConnectConfig,
    path: Box<dyn crate::path::QuicDatagramPath>,
    local_addr: SocketAddr,
) -> io::Result<QuicDriverHandle> {
    let endpoint = QuinnEndpoint::new(Arc::new(EndpointConfig::default()), None, true, None);

    spawn_driver(
        DriverMode::Client {
            factory: config.factory,
            peer: config.addr,
            client_config: Arc::clone(&config.client),
            server_name: config.server_name,
        },
        endpoint,
        DatagramTransport::Path(path),
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
    let (socket, local_addr) =
        crate::udp::bind_udp(crate::udp::unspecified_bind_addr(addr))?;

    let endpoint = QuinnEndpoint::new(Arc::new(EndpointConfig::default()), None, true, None);

    spawn_driver(
        DriverMode::ClientHooks {
            connection_factory,
            peer: addr,
            client_config: client,
            server_name: server_name.into(),
        },
        endpoint,
        DatagramTransport::Socket(socket),
        local_addr,
        Some(addr),
        false,
    )
}

/// [`connect_quic_hooks`], but over `path` instead of a real UDP socket —
/// see [`crate::QuicDatagramPath`]. `local_addr` is reported back to the
/// application exactly as given; it does not have to be routable, since
/// `path` (not the OS network stack) is what actually carries the
/// datagrams — the intended use is a QUIC (HTTP/3) connection tunnelled
/// inside another protocol's payload, e.g. an RFC 9298 CONNECT-UDP client.
pub fn connect_quic_hooks_with_path(
    addr: SocketAddr,
    client: Arc<quinn_proto::ClientConfig>,
    server_name: impl Into<String>,
    connection_factory: ConnectionFactory,
    path: Box<dyn crate::path::QuicDatagramPath>,
    local_addr: SocketAddr,
) -> io::Result<QuicDriverHandle> {
    let endpoint = QuinnEndpoint::new(Arc::new(EndpointConfig::default()), None, true, None);

    spawn_driver(
        DriverMode::ClientHooks {
            connection_factory,
            peer: addr,
            client_config: client,
            server_name: server_name.into(),
        },
        endpoint,
        DatagramTransport::Path(path),
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
    /// Peer has FINed (or reset) the receive half.
    recv_finished: bool,
    /// Local send half is fully acknowledged ([`StreamEvent::Finished`]).
    send_finished: bool,
    /// [`ProtocolHandler::disconnected`] / `error` already delivered.
    app_notified: bool,
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
    /// RFC 9221 DATAGRAMs that hit `SendDatagramError::Blocked`.
    pending_app_datagrams: std::collections::VecDeque<Bytes>,
}

fn spawn_driver(
    mode: DriverMode,
    endpoint: QuinnEndpoint,
    mut transport: DatagramTransport,
    local_addr: SocketAddr,
    _peer_hint: Option<SocketAddr>,
    require_address_validation: bool,
) -> io::Result<QuicDriverHandle> {
    let mut poll = Poll::new()?;
    let waker = Arc::new(Waker::new(poll.registry(), WAKE_TOKEN)?);
    // A `Path` transport has no file descriptor at all — its inbound
    // datagrams arrive via `QuicDriverHandle::receive_path_datagram`
    // instead, so there's nothing to register with `poll` here.
    if let DatagramTransport::Socket(socket) = &mut transport {
        poll.registry()
            .register(socket, UDP_TOKEN, Interest::READABLE)?;
    }

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
                transport,
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
                pending_sends: crate::udp::PendingUdpSends::default(),
                udp_interest: Interest::READABLE,
                require_address_validation,
                shutting_down: false,
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

/// What a [`Driver`] actually sends and receives datagrams on.
///
/// `Socket` is the default, used by every existing `connect_quic`/
/// `listen_quic` entry point and their `_hooks` counterparts — it keeps
/// the exact ECN/GSO-aware fast path [`crate::udp`] already has, and is
/// the only variant registered with the driver's `mio::Poll` (a
/// [`crate::path::QuicDatagramPath`] has no file descriptor to register;
/// its inbound datagrams arrive via [`QuicDriverHandle::receive_path_datagram`]
/// instead — see [`Driver::handle_datagram`]).
enum DatagramTransport {
    Socket(UdpSocket),
    Path(Box<dyn crate::path::QuicDatagramPath>),
}

struct Driver {
    mode: DriverMode,
    endpoint: QuinnEndpoint,
    transport: DatagramTransport,
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
    /// Datagrams that hit `WouldBlock` on `send_to`, retried when writable.
    pending_sends: crate::udp::PendingUdpSends,
    udp_interest: Interest,
    /// When true, unvalidated Incoming get Retry before handshake (RFC 9000 §8.1.2).
    require_address_validation: bool,
    /// Set when a `Shutdown` command has been processed.  The run loop
    /// performs a final flush + CONNECTION_CLOSE pass before exiting.
    shutting_down: bool,
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
                            pending_app_datagrams: std::collections::VecDeque::new(),
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
            self.flush_pending_sends()?;
            self.sync_udp_interest(poll)?;
            self.flush_all_transmits()?;
            self.sync_udp_interest(poll)?;
            self.drain_cmds();
            self.fire_timers();

            if self.shutting_down {
                break;
            }

            let timeout = self.next_timeout();
            poll.poll(&mut events, timeout)?;

            let now = Instant::now();
            for ev in events.iter() {
                match ev.token() {
                    UDP_TOKEN => {
                        if !self.pending_sends.is_empty() {
                            self.flush_pending_sends()?;
                            self.sync_udp_interest(poll)?;
                        }
                        self.on_udp_readable(now)?;
                    }
                    WAKE_TOKEN => {}
                    _ => {}
                }
            }

            self.handle_timeouts(now);
            self.poll_connections(now)?;
            self.detect_migrations();
            self.drive_apps();
            self.flush_all_transmits()?;
            self.sync_udp_interest(poll)?;
        }

        if self.shutting_down {
            // Final pass: flush any application bytes written during
            // `notify_disconnecting` (e.g. H3 GOAWAY on the control stream),
            // then send QUIC CONNECTION_CLOSE on every open connection and
            // transmit the resulting datagrams before the thread exits.
            let now = Instant::now();
            let chs: Vec<ConnectionHandle> = self.connections.keys().copied().collect();
            for ch in &chs {
                self.drive_streams(*ch, now);
            }
            let _ = self.flush_all_transmits();
            for ch in &chs {
                if let Some(slot) = self.connections.get_mut(ch) {
                    slot.conn.close(now, VarInt::from_u32(0), Bytes::new());
                }
            }
            let _ = self.flush_all_transmits();
            self.active.store(false, Ordering::Release);
        }
        Ok(())
    }

    fn sync_udp_interest(&mut self, poll: &mut Poll) -> io::Result<()> {
        // A `Path` transport has no file descriptor registered with `poll`
        // at all — nothing to keep in sync.
        let DatagramTransport::Socket(socket) = &mut self.transport else {
            return Ok(());
        };
        let desired = if self.pending_sends.is_empty() {
            Interest::READABLE
        } else {
            Interest::READABLE | Interest::WRITABLE
        };
        if desired != self.udp_interest {
            self.udp_interest = desired;
            poll.registry().reregister(socket, UDP_TOKEN, desired)?;
        }
        Ok(())
    }

    fn flush_pending_sends(&mut self) -> io::Result<()> {
        let transport = &mut self.transport;
        self.pending_sends.flush(|pending| match transport {
            DatagramTransport::Socket(socket) => crate::udp::send_pending(socket, pending),
            DatagramTransport::Path(path) => path
                .send(
                    pending.destination,
                    &pending.data,
                    pending.ecn,
                    pending.segment_size,
                )
                .map(|_| ()),
        })
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
                    self.shutting_down = true;
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
                DriverCmd::SendDatagram {
                    conn,
                    payload,
                    stream_id,
                } => {
                    if let Some(err) = self.try_queue_datagram(conn, payload) {
                        self.notify_datagram_send_error(conn, stream_id, err);
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
                DriverCmd::PathDatagram { data, source, ecn } => {
                    let now = Instant::now();
                    let data = bytes::BytesMut::from(&data[..]);
                    let _ = self.handle_datagram(now, source, ecn, data);
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
            let DatagramTransport::Socket(socket) = &self.transport else {
                // Never actually reached — a `Path` transport has no fd
                // registered with `poll`, so no `UDP_TOKEN` event fires for
                // it in the first place (see `sync_udp_interest`).
                // Defensive only.
                return Ok(());
            };
            let (n, remote, ecn) = match crate::udp::recv_one(socket, &mut self.recv_buf) {
                Ok(x) => x,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            };
            let data = bytes::BytesMut::from(&self.recv_buf[..n]);
            let ecn = ecn.map(|c| c as u8);
            self.handle_datagram(now, remote, ecn, data)?;
        }
        Ok(())
    }

    /// Process one received datagram through the `quinn-proto` endpoint,
    /// regardless of which [`DatagramTransport`] it arrived on — shared by
    /// [`Self::on_udp_readable`] (the default socket's poll-driven receive)
    /// and [`DriverCmd::PathDatagram`] (a custom
    /// [`crate::path::QuicDatagramPath`]'s push-based receive).
    fn handle_datagram(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        ecn: Option<u8>,
        data: bytes::BytesMut,
    ) -> io::Result<()> {
        let ecn = ecn.and_then(quinn_proto::EcnCodepoint::from_bits);
        self.send_buf.clear();
        if let Some(event) =
            self.endpoint
                .handle(now, remote, None, ecn, data, &mut self.send_buf)
        {
            match event {
                DatagramEvent::NewConnection(incoming) => {
                    self.handle_incoming(incoming, remote, now)?;
                }
                DatagramEvent::ConnectionEvent(ch, event) => {
                    if let Some(slot) = self.connections.get_mut(&ch) {
                        slot.conn.handle_event(event);
                    }
                }
                DatagramEvent::Response(tx) => {
                    self.send_transmit(tx)?;
                }
            }
        }
        if !self.send_buf.is_empty() {
            // Response already sent via Transmit.
            self.send_buf.clear();
        }
        Ok(())
    }

    /// Accept, Retry, or refuse a new Incoming per listen hardening.
    ///
    /// With [`crate::QuicListenHardening::require_address_validation`], an
    /// unvalidated address gets a Retry packet (RFC 9000 §8.1.2) so spoofed
    /// Initials never start a TLS handshake. Validated peers (Retry token or
    /// NEW_TOKEN) are accepted immediately.
    fn handle_incoming(
        &mut self,
        incoming: Incoming,
        remote: SocketAddr,
        now: Instant,
    ) -> io::Result<()> {
        if self.require_address_validation && !incoming.remote_address_validated() {
            match self.endpoint.retry(incoming, &mut self.send_buf) {
                Ok(tx) => self.send_transmit(tx)?,
                Err(err) => {
                    // Already carried a Retry token but still unvalidated —
                    // refuse rather than looping Retry forever.
                    let tx = self
                        .endpoint
                        .refuse(err.into_incoming(), &mut self.send_buf);
                    self.send_transmit(tx)?;
                }
            }
            return Ok(());
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
                        pending_app_datagrams: std::collections::VecDeque::new(),
                    },
                );
            }
            Err(e) => {
                if let Some(tx) = e.response {
                    self.send_transmit(tx)?;
                }
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

    fn poll_connections(&mut self, now: Instant) -> io::Result<()> {
        let handles: Vec<_> = self.connections.keys().copied().collect();
        for ch in handles {
            self.poll_one_connection(ch, now)?;
        }
        Ok(())
    }

    fn poll_one_connection(&mut self, ch: ConnectionHandle, now: Instant) -> io::Result<()> {
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
                    return Ok(());
                }
                Event::Stream(se) => self.on_stream_event(ch, se),
                Event::DatagramReceived => {
                    self.drain_datagrams(ch);
                }
                Event::DatagramsUnblocked => {
                    self.flush_pending_app_datagrams(ch);
                }
            }
        }

        // Drive stream I/O.
        self.drive_streams(ch, now);

        // Transmits.
        loop {
            self.send_buf.clear();
            let tx = match self.connections.get_mut(&ch) {
                Some(slot) => {
                    slot.conn
                        .poll_transmit(now, crate::udp::max_gso_segments(), &mut self.send_buf)
                }
                None => break,
            };
            match tx {
                Some(t) => self.send_transmit(t)?,
                None => break,
            }
        }
        Ok(())
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
                            recv_finished: false,
                            send_finished: false,
                            app_notified: false,
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
                    if let Some(err) = self.try_queue_datagram(ch, data) {
                        self.notify_datagram_send_error(ch, None, err);
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
                // Local send half is fully acknowledged. This is *not* the
                // end of a bidirectional stream — the peer may still be
                // sending (e.g. an HTTP/3 response after we FINed the
                // request). Only retire send-only streams, or bi streams
                // whose receive half is already done.
                self.read_stream(ch, id);
                if let Some(slot) = self.connections.get_mut(&ch) {
                    if let Some(stream) = slot.streams.get_mut(&id) {
                        stream.send_finished = true;
                    }
                }
                self.maybe_retire_stream(ch, id);
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
                    // This is a stream the *peer* opened (accepted via
                    // `StreamEvent::Opened`/`conn.streams().accept(dir)`),
                    // never one we opened ourselves — for a uni stream that
                    // means we're the only side that can read it, so unlike
                    // `apply_recorder`'s `send_only: matches!(dir, Dir::Uni)`
                    // (correct there: that path is for our *own* outbound
                    // `open_uni()` streams), it must always be `false` here,
                    // matching `attach_stream_with_factory`'s same reasoning.
                    send_only: false,
                    recv_finished: false,
                    send_finished: false,
                    app_notified: false,
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
                    recv_finished: false,
                    send_finished: false,
                    app_notified: false,
                    pending_in: Vec::new(),
                },
            );
        }
    }

    fn read_stream(&mut self, ch: ConnectionHandle, id: StreamId) {
        let (new_data, peer_finished) = {
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
                        // Peer FIN (or reset path already freed recv).
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
            (new_data, peer_finished)
        };
        let _ = new_data;

        if peer_finished {
            // Peer FIN: deliver half-close to the app (so H3 can flush a
            // response / complete the request) but keep the stream slot
            // alive until our send half is also Finished — otherwise we
            // would drop queued response bytes and tear down before the
            // client could read them.
            if let Some(stream) = self
                .connections
                .get_mut(&ch)
                .and_then(|s| s.streams.get_mut(&id))
            {
                stream.recv_finished = true;
                if !stream.app_notified {
                    stream.app_notified = true;
                    // Keep the endpoint open so `disconnected` can still
                    // `send()` or defer work via timers / execute. Peer FIN
                    // only closes the receive half; the local send half must
                    // stay application-controlled (true QUIC half-close).
                    stream.handler.disconnected(&mut stream.endpoint);
                }
            }
            self.maybe_retire_stream(ch, id);
        }
    }

    /// Retire a stream slot once both halves are done (or for send-only
    /// streams, once the local send is acknowledged). Does not re-notify
    /// the application — that already happened on peer FIN / error.
    fn maybe_retire_stream(&mut self, ch: ConnectionHandle, id: StreamId) {
        let retire = self
            .connections
            .get(&ch)
            .and_then(|s| s.streams.get(&id))
            .map(|st| {
                if st.send_only {
                    st.send_finished
                } else {
                    st.recv_finished && st.send_finished
                }
            })
            .unwrap_or(false);
        if !retire {
            return;
        }
        if let Some(slot) = self.connections.get_mut(&ch) {
            let _ = slot.streams.remove(&id);
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
                if !stream.app_notified {
                    stream.app_notified = true;
                    stream.endpoint.mark_closed();
                    match &err {
                        Some(e) => stream.handler.error(&mut stream.endpoint, e),
                        None => stream.handler.disconnected(&mut stream.endpoint),
                    }
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

    fn flush_all_transmits(&mut self) -> io::Result<()> {
        // Endpoint-level transmits (if any) are handled via DatagramEvent::Response.
        let now = Instant::now();
        let handles: Vec<_> = self.connections.keys().copied().collect();
        for ch in handles {
            loop {
                self.send_buf.clear();
                let tx = match self.connections.get_mut(&ch) {
                    Some(slot) => slot.conn.poll_transmit(
                        now,
                        crate::udp::max_gso_segments(),
                        &mut self.send_buf,
                    ),
                    None => break,
                };
                match tx {
                    Some(t) => self.send_transmit(t)?,
                    None => break,
                }
            }
        }
        Ok(())
    }

    fn send_transmit(&mut self, transmit: Transmit) -> io::Result<()> {
        let size = transmit.size;
        if size == 0 {
            return Ok(());
        }
        if size > self.send_buf.len() {
            return Ok(());
        }
        let buf = &self.send_buf[..size];
        let result = match &mut self.transport {
            DatagramTransport::Socket(socket) => crate::udp::send_transmit(socket, &transmit, buf),
            DatagramTransport::Path(path) => {
                let ecn = transmit.ecn.map(|c| c as u8);
                path.send(transmit.destination, buf, ecn, transmit.segment_size)
                    .map(|_| ())
            }
        };
        match result {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.pending_sends.enqueue_transmit(&transmit, buf);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Queue an RFC 9221 DATAGRAM. `None` = accepted (or buffered until
    /// `DatagramsUnblocked`). `Some` = a hard failure the application must see.
    fn try_queue_datagram(&mut self, ch: ConnectionHandle, payload: Vec<u8>) -> Option<io::Error> {
        let Some(slot) = self.connections.get_mut(&ch) else {
            return Some(io::Error::new(
                io::ErrorKind::NotConnected,
                "no QUIC connection for DATAGRAM",
            ));
        };
        match slot.conn.datagrams().send(Bytes::from(payload), false) {
            Ok(()) => None,
            Err(SendDatagramError::Blocked(data)) => {
                slot.pending_app_datagrams.push_back(data);
                None
            }
            Err(e) => Some(datagram_send_io_error(e)),
        }
    }

    fn flush_pending_app_datagrams(&mut self, ch: ConnectionHandle) {
        loop {
            let Some(slot) = self.connections.get_mut(&ch) else {
                return;
            };
            let Some(data) = slot.pending_app_datagrams.pop_front() else {
                return;
            };
            match slot.conn.datagrams().send(data, false) {
                Ok(()) => {}
                Err(SendDatagramError::Blocked(data)) => {
                    slot.pending_app_datagrams.push_front(data);
                    return;
                }
                Err(e) => {
                    let err = datagram_send_io_error(e);
                    self.notify_datagram_send_error(ch, None, err);
                    return;
                }
            }
        }
    }

    fn notify_datagram_send_error(
        &mut self,
        ch: ConnectionHandle,
        stream_id: Option<StreamId>,
        err: io::Error,
    ) {
        if let Some(id) = stream_id {
            if let Some(stream) = self
                .connections
                .get_mut(&ch)
                .and_then(|s| s.streams.get_mut(&id))
            {
                stream.handler.error(&mut stream.endpoint, &err);
            }
            return;
        }
        let ids: Vec<StreamId> = self
            .connections
            .get(&ch)
            .map(|s| s.streams.keys().copied().collect())
            .unwrap_or_default();
        for id in ids {
            if let Some(stream) = self
                .connections
                .get_mut(&ch)
                .and_then(|s| s.streams.get_mut(&id))
            {
                stream.handler.error(&mut stream.endpoint, &err);
            }
        }
        if let Some(app) = self.connections.get_mut(&ch).and_then(|s| s.app.as_mut()) {
            app.datagram_send_failed(&err);
        }
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

    /// [`crate::QuicDatagramPath`] backed by nothing but a channel to the
    /// peer's own [`QuicDriverHandle`] — no real socket, no OS network
    /// stack, proving the pluggable-transport seam itself works rather
    /// than just compiling.
    struct InMemoryDatagramPath {
        local_addr: SocketAddr,
        peer: Arc<StdMutex<Option<QuicDriverHandle>>>,
        open: Arc<AtomicBool>,
    }

    impl crate::path::QuicDatagramPath for InMemoryDatagramPath {
        fn send(
            &mut self,
            _dest: SocketAddr,
            data: &[u8],
            _ecn: Option<u8>,
            _segment_size: Option<usize>,
        ) -> io::Result<usize> {
            // There's only ever one peer on this pipe — `_dest` (which
            // `quinn-proto` always sets to the address `connect()`/`accept()`
            // negotiated) carries no extra routing information a real
            // multi-destination socket would need.
            let len = data.len();
            let guard = self.peer.lock().unwrap();
            let Some(handle) = guard.as_ref() else {
                return Err(io::Error::new(io::ErrorKind::NotConnected, "peer not yet attached"));
            };
            handle.receive_path_datagram(data.to_vec(), self.local_addr)?;
            Ok(len)
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.local_addr)
        }

        fn is_open(&self) -> bool {
            self.open.load(Ordering::Acquire)
        }

        fn close(&mut self) -> io::Result<()> {
            self.open.store(false, Ordering::Release);
            Ok(())
        }
    }

    /// A full QUIC handshake plus one echoed stream, over two
    /// [`InMemoryDatagramPath`]s instead of real UDP sockets — the same
    /// scenario [`spike_echo_one_stream`] exercises over real loopback
    /// sockets, but proving [`listen_quic_with_path`]/
    /// [`connect_quic_with_path`] and [`QuicDriverHandle::receive_path_datagram`]
    /// are what actually carry it end to end.
    #[test]
    fn spike_echo_one_stream_over_a_pluggable_path() {
        let (server_cfg, pem) =
            server_config_self_signed(&["localhost"], &[b"hq-interop"]).unwrap();
        let client_cfg = client_config_for_pem_bytes(&pem, &[b"hq-interop"]).unwrap();

        // Addresses need only be distinct and stable — nothing routes on
        // them; every send is handed directly to the peer's driver.
        let server_addr: SocketAddr = "127.0.0.1:44433".parse().unwrap();
        let client_addr: SocketAddr = "127.0.0.1:44434".parse().unwrap();

        let server_handle_cell: Arc<StdMutex<Option<QuicDriverHandle>>> =
            Arc::new(StdMutex::new(None));
        let client_handle_cell: Arc<StdMutex<Option<QuicDriverHandle>>> =
            Arc::new(StdMutex::new(None));

        let server_path = Box::new(InMemoryDatagramPath {
            local_addr: server_addr,
            peer: Arc::clone(&client_handle_cell),
            open: Arc::new(AtomicBool::new(true)),
        });
        let client_path = Box::new(InMemoryDatagramPath {
            local_addr: client_addr,
            peer: Arc::clone(&server_handle_cell),
            open: Arc::new(AtomicBool::new(true)),
        });

        let server = listen_quic_with_path(
            QuicListenConfig::new(
                server_addr,
                server_cfg,
                Arc::new(|| Box::new(Echo) as Box<dyn ProtocolHandler>),
            ),
            server_path,
            server_addr,
        )
        .unwrap();
        *server_handle_cell.lock().unwrap() = Some(server);

        let got = Arc::new(StdMutex::new(Vec::new()));
        let got2 = Arc::clone(&got);
        let client = connect_quic_with_path(
            QuicConnectConfig::new(
                server_addr,
                client_cfg,
                "localhost",
                Arc::new(move || {
                    Box::new(ClientProbe {
                        sent: false,
                        got: Arc::clone(&got2),
                    }) as Box<dyn ProtocolHandler>
                }),
            ),
            client_path,
            client_addr,
        )
        .unwrap();
        *client_handle_cell.lock().unwrap() = Some(client);

        for _ in 0..200 {
            if got.lock().unwrap().as_slice() == b"ping" {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(got.lock().unwrap().as_slice(), b"ping");

        server_handle_cell.lock().unwrap().take().unwrap().shutdown();
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
        struct EchoCloseOnPeerFin;
        impl ProtocolHandler for EchoCloseOnPeerFin {
            fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}
            fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
                endpoint.send(data);
                *data = &[];
            }
            fn disconnected(&mut self, endpoint: &mut dyn Endpoint) {
                endpoint.close();
            }
            fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &io::Error) {}
        }

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
            Arc::new(|| Box::new(EchoCloseOnPeerFin) as Box<dyn ProtocolHandler>),
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

    /// Peer FIN must not force-close our send half: a handler should still be
    /// able to send later (e.g. from a timer) after `disconnected()`.
    #[test]
    fn peer_fin_does_not_force_finish_write() {
        struct DelayedReplyAfterPeerFin {
            payload: &'static [u8],
        }
        impl ProtocolHandler for DelayedReplyAfterPeerFin {
            fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}
            fn receive(&mut self, _endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
                *data = &[];
            }
            fn disconnected(&mut self, endpoint: &mut dyn Endpoint) {
                let handle = endpoint.handle();
                let payload = self.payload.to_vec();
                endpoint.schedule_timer(
                    Duration::from_millis(20),
                    Box::new(move || {
                        handle.with_endpoint(move |ep| {
                            ep.send(&payload);
                            ep.close();
                        });
                    }),
                );
            }
            fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &io::Error) {}
        }

        struct CollectReply {
            got: Arc<StdMutex<Vec<u8>>>,
        }
        impl ProtocolHandler for CollectReply {
            fn connected(&mut self, endpoint: &mut dyn Endpoint) {
                endpoint.send(b"request");
                endpoint.close(); // send FIN immediately after request bytes
            }
            fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
                self.got.lock().unwrap().extend_from_slice(data);
                *data = &[];
                endpoint.close();
            }
            fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}
            fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &io::Error) {}
        }

        let (server_cfg, pem) =
            server_config_self_signed(&["localhost"], &[b"hq-interop"]).unwrap();
        let client_cfg = client_config_for_pem_bytes(&pem, &[b"hq-interop"]).unwrap();

        let server = listen_quic(QuicListenConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            server_cfg,
            Arc::new(|| {
                Box::new(DelayedReplyAfterPeerFin {
                    payload: b"late-reply",
                }) as Box<dyn ProtocolHandler>
            }),
        ))
        .unwrap();

        let got = Arc::new(StdMutex::new(Vec::new()));
        let got2 = Arc::clone(&got);
        let _client = connect_quic(QuicConnectConfig::new(
            server.local_addr,
            client_cfg,
            "localhost",
            Arc::new(move || Box::new(CollectReply { got: Arc::clone(&got2) }) as Box<dyn ProtocolHandler>),
        ))
        .unwrap();

        for _ in 0..200 {
            if got.lock().unwrap().as_slice() == b"late-reply" {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(got.lock().unwrap().as_slice(), b"late-reply");
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
                api.send_datagram(&payload)
                    .expect("echo DATAGRAM send");
            }
        }
    }

    struct DatagramClientConn {
        sent: bool,
        got: Arc<StdMutex<Vec<u8>>>,
    }

    impl QuicConnection for DatagramClientConn {
        fn connected(&mut self, api: &mut dyn QuicConnApi) {
            api.send_datagram(b"ping").expect("client DATAGRAM send");
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

    /// `QuicConnection` that opens one uni stream on `connected()` and
    /// writes a fixed payload to it — stands in for a peer's H3 control
    /// stream (SETTINGS) or QPACK streams, the scenario this regression
    /// test is really about.
    struct OpensUniAndWrites {
        payload: &'static [u8],
    }

    impl QuicConnection for OpensUniAndWrites {
        fn connected(&mut self, api: &mut dyn QuicConnApi) {
            let stream = api.open_uni().expect("open_uni");
            api.write(stream, self.payload);
        }
        fn accept_bi(&mut self, _stream_id: u64) -> Box<dyn ProtocolHandler> {
            Box::new(NopHandler)
        }
        fn accept_uni(&mut self, _stream_id: u64) -> Box<dyn ProtocolHandler> {
            Box::new(NopHandler)
        }
    }

    /// `ProtocolHandler` recording every byte read off a peer-opened uni
    /// stream — the receiving side of [`OpensUniAndWrites`].
    struct RecordsUniBytes {
        got: Arc<StdMutex<Vec<u8>>>,
    }

    impl ProtocolHandler for RecordsUniBytes {
        fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}
        fn receive(&mut self, _endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
            self.got.lock().unwrap().extend_from_slice(data);
            *data = &[];
        }
        fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}
        fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &io::Error) {}
    }

    struct AcceptsUniIntoRecorder {
        got: Arc<StdMutex<Vec<u8>>>,
    }

    impl QuicConnection for AcceptsUniIntoRecorder {
        fn connected(&mut self, _api: &mut dyn QuicConnApi) {}
        fn accept_bi(&mut self, _stream_id: u64) -> Box<dyn ProtocolHandler> {
            Box::new(NopHandler)
        }
        fn accept_uni(&mut self, _stream_id: u64) -> Box<dyn ProtocolHandler> {
            Box::new(RecordsUniBytes { got: Arc::clone(&self.got) })
        }
    }

    /// Regression test for #330: a stream *we* open (`open_uni`, the
    /// `apply_recorder` path) is correctly `send_only` — there's nothing to
    /// read from our own outbound stream. But `attach_stream_dir`, used
    /// exclusively for streams the *peer* opens (`StreamEvent::Opened` →
    /// `conn.streams().accept(dir)`), copied that same
    /// `send_only: matches!(dir, Dir::Uni)` — backwards for this case: a
    /// peer-opened uni stream is one *we* can only read, never write, so
    /// marking it `send_only` makes `read_stream` skip it forever. This is
    /// exactly the shape of H3's peer control/QPACK streams (SETTINGS,
    /// GOAWAY) — reading them is how a client ever learns
    /// `SETTINGS_ENABLE_CONNECT_PROTOCOL`, which CONNECT-UDP/CONNECT-IP
    /// (hopf-masque) depend on to send Extended CONNECT at all.
    #[test]
    fn client_reads_a_peer_opened_uni_stream() {
        let (server_cfg, pem) =
            server_config_self_signed(&["localhost"], &[b"hq-interop"]).unwrap();
        let client_cfg = client_config_for_pem_bytes(&pem, &[b"hq-interop"]).unwrap();

        let server = listen_quic_hooks(crate::QuicListenHooksConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            server_cfg,
            Arc::new(|| Box::new(OpensUniAndWrites { payload: b"hello-uni" }) as Box<dyn QuicConnection>),
        ))
        .unwrap();

        let client_got = Arc::new(StdMutex::new(Vec::new()));
        let client_got2 = Arc::clone(&client_got);
        let _client = connect_quic_hooks(
            server.local_addr,
            client_cfg,
            "localhost",
            Arc::new(move || {
                Box::new(AcceptsUniIntoRecorder { got: Arc::clone(&client_got2) }) as Box<dyn QuicConnection>
            }),
        )
        .unwrap();

        for _ in 0..200 {
            if client_got.lock().unwrap().as_slice() == b"hello-uni" {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            client_got.lock().unwrap().as_slice(),
            b"hello-uni",
            "the client never read the peer-opened uni stream"
        );
        server.shutdown();
    }

    /// Calling `shutdown()` must flush queued application bytes (e.g. a GOAWAY
    /// written by `disconnecting()`) **and** send QUIC CONNECTION_CLOSE to every
    /// open peer before the driver thread exits.  The peer should therefore
    /// receive a `QuicConnectionCloseError` rather than an idle-timeout or
    /// transport-reset error.
    ///
    /// Regression test for: shutdown skipped GOAWAY + CONNECTION_CLOSE (#294).
    #[test]
    fn shutdown_sends_connection_close_to_peer() {
        let (server_cfg, pem) =
            server_config_self_signed(&["localhost"], &[b"shutdown-cc"]).unwrap();
        let client_cfg = client_config_for_pem_bytes(&pem, &[b"shutdown-cc"]).unwrap();

        let client_got_error = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let client_got_disconnect = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let client_error_ref = Arc::clone(&client_got_error);
        let client_disconnect_ref = Arc::clone(&client_got_disconnect);

        let server = listen_quic(QuicListenConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            server_cfg,
            Arc::new(|| Box::new(NopHandler) as Box<dyn ProtocolHandler>),
        ))
        .unwrap();

        struct IdleClient {
            errored: Arc<std::sync::atomic::AtomicBool>,
            disconnected: Arc<std::sync::atomic::AtomicBool>,
        }
        impl ProtocolHandler for IdleClient {
            fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}
            fn receive(&mut self, _endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
                *data = &[];
            }
            fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
                self.disconnected.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &io::Error) {
                self.errored.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }

        let _client = connect_quic(QuicConnectConfig::new(
            server.local_addr,
            client_cfg,
            "localhost",
            Arc::new(move || {
                Box::new(IdleClient {
                    errored: Arc::clone(&client_error_ref),
                    disconnected: Arc::clone(&client_disconnect_ref),
                }) as Box<dyn ProtocolHandler>
            }),
        ))
        .unwrap();

        // Wait for the connection to be established.
        thread::sleep(Duration::from_millis(100));

        // Trigger a clean driver shutdown — this must send CONNECTION_CLOSE.
        server.shutdown();

        // Give the client a moment to receive and process the CONNECTION_CLOSE.
        for _ in 0..100 {
            if client_got_error.load(std::sync::atomic::Ordering::SeqCst)
                || client_got_disconnect.load(std::sync::atomic::Ordering::SeqCst)
            {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }

        assert!(
            client_got_error.load(std::sync::atomic::Ordering::SeqCst),
            "client must receive a CONNECTION_CLOSE error when server shuts down cleanly"
        );
        assert!(
            !client_got_disconnect.load(std::sync::atomic::Ordering::SeqCst),
            "CONNECTION_CLOSE must use error(), not disconnected()"
        );
    }

    /// RFC 9221: sending a DATAGRAM to a peer that did not advertise
    /// `max_datagram_frame_size` must surface [`crate::QuicDatagramSendError::UnsupportedByPeer`]
    /// instead of being swallowed.
    #[test]
    fn datagram_send_unsupported_by_peer_is_surfaced() {
        use crate::config::{apply_server_transport_options, QuicTransportOptions};

        let (mut server_cfg, pem) =
            server_config_self_signed(&["localhost"], &[b"dgram-off"]).unwrap();
        apply_server_transport_options(
            &mut server_cfg,
            &QuicTransportOptions::new().datagram_receive_buffer_size(None),
        )
        .unwrap();
        let client_cfg = client_config_for_pem_bytes(&pem, &[b"dgram-off"]).unwrap();

        let server = listen_quic(QuicListenConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            server_cfg,
            Arc::new(|| Box::new(NopHandler) as Box<dyn ProtocolHandler>),
        ))
        .unwrap();

        let got = Arc::new(StdMutex::new(None));
        let got2 = Arc::clone(&got);
        struct SendDatagramOnConnect {
            got: Arc<StdMutex<Option<crate::QuicDatagramSendError>>>,
        }
        impl ProtocolHandler for SendDatagramOnConnect {
            fn connected(&mut self, endpoint: &mut dyn Endpoint) {
                let _ = endpoint.send_datagram(b"ping");
            }
            fn receive(&mut self, _endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
                *data = &[];
            }
            fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}
            fn error(&mut self, _endpoint: &mut dyn Endpoint, err: &io::Error) {
                *self.got.lock().unwrap() = crate::datagram_send_error(err);
            }
        }

        let _client = connect_quic(QuicConnectConfig::new(
            server.local_addr,
            client_cfg,
            "localhost",
            Arc::new(move || {
                Box::new(SendDatagramOnConnect {
                    got: Arc::clone(&got2),
                }) as Box<dyn ProtocolHandler>
            }),
        ))
        .unwrap();

        for _ in 0..200 {
            if got.lock().unwrap().is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        let err = *got.lock().unwrap();
        assert_eq!(err, Some(crate::QuicDatagramSendError::UnsupportedByPeer));
        server.shutdown();
    }

    /// Payload larger than the path MTU / DATAGRAM limit is TooLarge, not silent.
    #[test]
    fn datagram_send_too_large_is_surfaced() {
        let (server_cfg, pem) =
            server_config_self_signed(&["localhost"], &[b"dgram-big"]).unwrap();
        let client_cfg = client_config_for_pem_bytes(&pem, &[b"dgram-big"]).unwrap();

        let server = listen_quic(QuicListenConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            server_cfg,
            Arc::new(|| Box::new(NopHandler) as Box<dyn ProtocolHandler>),
        ))
        .unwrap();

        let got = Arc::new(StdMutex::new(None));
        let got2 = Arc::clone(&got);
        struct SendHuge {
            got: Arc<StdMutex<Option<crate::QuicDatagramSendError>>>,
        }
        impl ProtocolHandler for SendHuge {
            fn connected(&mut self, endpoint: &mut dyn Endpoint) {
                let huge = vec![0u8; 65535];
                let _ = endpoint.send_datagram(&huge);
            }
            fn receive(&mut self, _endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
                *data = &[];
            }
            fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}
            fn error(&mut self, _endpoint: &mut dyn Endpoint, err: &io::Error) {
                *self.got.lock().unwrap() = crate::datagram_send_error(err);
            }
        }

        let _client = connect_quic(QuicConnectConfig::new(
            server.local_addr,
            client_cfg,
            "localhost",
            Arc::new(move || {
                Box::new(SendHuge {
                    got: Arc::clone(&got2),
                }) as Box<dyn ProtocolHandler>
            }),
        ))
        .unwrap();

        for _ in 0..200 {
            if got.lock().unwrap().is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            *got.lock().unwrap(),
            Some(crate::QuicDatagramSendError::TooLarge)
        );
        server.shutdown();
    }
}
