// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Length-prefixed DNS over a byte stream (RFC 1035 §4.2.2): cleartext TCP
//! here, and the shared framing handler used by the DoT listener.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use hopf_core::{ConnHandle, Endpoint, ProtocolHandler, Runtime, SecurityInfo, TcpListenerConfig};

use super::{ConnectionInfo, DnsServiceHandle, DnsTransport, WireSink};

/// Cleartext DNS over TCP (RFC 1035 §4.2.2, RFC 7766). Required for zone
/// transfers and for clients that retry a truncated UDP answer.
///
/// A connection may have at most [`DnsServiceHandle::max_in_flight`] queries
/// outstanding; past that it is not read until an answer is complete.
pub fn listen_dns_tcp(
    rt: &Runtime,
    addr: SocketAddr,
    service: DnsServiceHandle,
) -> io::Result<SocketAddr> {
    listen_dns_tcp_with(rt, addr, service, |config| config)
}

/// [`listen_dns_tcp`] with a say in the listener's own settings: the peer
/// allow and deny lists, the accept rate limit, the buffer caps, the idle
/// timeout and PROXY protocol, which are those of
/// [`TcpListenerConfig`](hopf_core::TcpListenerConfig). `configure` is given the
/// listener's configuration, with its address and handler set, and returns it.
pub fn listen_dns_tcp_with(
    rt: &Runtime,
    addr: SocketAddr,
    service: DnsServiceHandle,
    configure: impl FnOnce(TcpListenerConfig) -> TcpListenerConfig,
) -> io::Result<SocketAddr> {
    let svc = Arc::new(service);
    let config = TcpListenerConfig::new(addr, move || {
        Box::new(FramedServerHandler::new(Arc::clone(&svc), DnsTransport::Tcp))
            as Box<dyn ProtocolHandler>
    });
    let (bound, _) = rt.add_tcp_listener(configure(config))?;
    Ok(bound)
}

/// The queries one stream connection has outstanding, started and not yet
/// answered, and whether the connection has stopped being read for it.
pub(super) struct InFlight {
    count: AtomicUsize,
    /// Reading has been stopped, or is being stopped, until an answer completes.
    paused: AtomicBool,
    limit: Option<usize>,
    service: Arc<DnsServiceHandle>,
    transport: DnsTransport,
}

impl InFlight {
    fn new(service: Arc<DnsServiceHandle>, transport: DnsTransport) -> Arc<Self> {
        Arc::new(Self {
            count: AtomicUsize::new(0),
            paused: AtomicBool::new(false),
            limit: service.max_in_flight(),
            service,
            transport,
        })
    }

    fn at_limit(&self) -> bool {
        self.limit.is_some_and(|l| self.count.load(Ordering::SeqCst) >= l)
    }
}

/// A started query, until its answer is complete: finishing it (dropping it, with
/// the answer written or abandoned) lets the connection be read again if it was
/// stopped for being at its limit.
pub(super) struct Outstanding {
    inflight: Arc<InFlight>,
    handle: ConnHandle,
}

impl Outstanding {
    fn begin(inflight: &Arc<InFlight>, handle: ConnHandle) -> Self {
        let n = inflight.count.fetch_add(1, Ordering::SeqCst) + 1;
        inflight.service.service().query_started(inflight.transport, n);
        Self {
            inflight: Arc::clone(inflight),
            handle,
        }
    }
}

impl Drop for Outstanding {
    fn drop(&mut self) {
        let inflight = &self.inflight;
        inflight.count.fetch_sub(1, Ordering::SeqCst);
        inflight.service.service().query_finished(inflight.transport);
        // The connection stopped being read for being at its limit, and no longer is.
        if inflight.paused.load(Ordering::SeqCst) && !inflight.at_limit() {
            let inflight = Arc::clone(inflight);
            self.handle.with_endpoint(move |ep| {
                if inflight.paused.swap(false, Ordering::SeqCst) && ep.is_open() {
                    ep.resume_read();
                    // What was held back in the handler goes on being dispatched.
                    ep.poke_handler();
                }
            });
        }
    }
}

/// Where one query's answer goes on a stream.
enum ReplyState {
    /// The query is still being dispatched on the reactor thread: an answer
    /// that arrives now is written directly, with no hop.
    Dispatching,
    /// Answered during dispatch; the dispatcher writes it on its way out.
    Answered(Vec<Vec<u8>>),
    /// Dispatch has returned: an answer must re-enter the connection's
    /// reactor.
    Detached,
}

/// Hand `payload` to the service and arrange for its answer to reach
/// `endpoint`, however and wherever it is produced. Returns `false` if
/// `payload` is not a DNS message.
///
/// Answered inline, the responses are written to `endpoint` before this
/// returns. Answered later, possibly from another thread, they are written
/// when the connection's own reactor runs the task queued through its
/// [`ConnHandle`](hopf_core::ConnHandle), so the endpoint is only ever
/// touched on its reactor and several queries may be outstanding at once
/// (RFC 7766 §6.2.1.1 lets their answers come back in any order).
/// `write` frames and sends one response.
pub(super) fn dispatch_to_endpoint(
    service: &DnsServiceHandle,
    endpoint: &mut dyn Endpoint,
    payload: &[u8],
    conn: &ConnectionInfo,
    transport: DnsTransport,
    write: fn(&mut dyn Endpoint, &[u8]),
    in_flight: Option<&Arc<InFlight>>,
) -> bool {
    let state = Arc::new(Mutex::new(ReplyState::Dispatching));
    let handle = endpoint.handle();
    let shared = Arc::clone(&state);
    // Finished when the answer is written, or when the service lets go of
    // `reply` without ever calling it.
    let outstanding = in_flight.map(|f| Outstanding::begin(f, handle.clone()));
    let reply: WireSink = Box::new(move |responses| {
        let mut state = shared.lock().unwrap();
        match *state {
            ReplyState::Dispatching => *state = ReplyState::Answered(responses),
            _ => {
                drop(state);
                handle.with_endpoint(move |ep| {
                    if ep.is_open() {
                        for bytes in &responses {
                            write(ep, bytes);
                        }
                    }
                    drop(outstanding);
                });
            }
        }
    });
    let accepted = service.dispatch_wire_with(payload, conn, transport, reply);
    let answered = std::mem::replace(&mut *state.lock().unwrap(), ReplyState::Detached);
    if let ReplyState::Answered(responses) = answered {
        for bytes in &responses {
            write(endpoint, bytes);
        }
    }
    accepted
}

/// RFC 1035 §4.2.2 / RFC 7858 §3.3 framing: a two-byte length, then the
/// message.
pub(super) fn write_length_prefixed(endpoint: &mut dyn Endpoint, bytes: &[u8]) {
    let mut out = Vec::with_capacity(2 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
    endpoint.send(&out);
}

/// What a stream handler remembers about its connection between messages: the
/// local address and the [`SecurityInfo`], read from the endpoint once (the
/// handshake is over by the first byte of application data) and shared by
/// every query after that.
#[derive(Default)]
pub(super) struct ConnectionState {
    local: Option<Option<SocketAddr>>,
    security: Option<Option<Arc<SecurityInfo>>>,
}

impl ConnectionState {
    /// The connection as of now. The peer is read each time, since QUIC can
    /// migrate it.
    pub(super) fn info(&mut self, endpoint: &dyn Endpoint) -> ConnectionInfo {
        let socket_addr = |addr: io::Result<hopf_core::PeerAddr>| addr.ok().and_then(|a| a.as_socket_addr());
        let peer = socket_addr(endpoint.remote_addr())
            .unwrap_or_else(|| SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0));
        let local = *self
            .local
            .get_or_insert_with(|| socket_addr(endpoint.local_addr()));
        let security = self
            .security
            .get_or_insert_with(|| {
                let info = endpoint.security_info();
                info.is_secure().then(|| Arc::new(info.clone()))
            })
            .clone();
        ConnectionInfo::new(peer).with_local(local).with_security(security)
    }
}

/// Frames DNS messages on a stream and dispatches them to the service.
///
/// With a limit on the queries a connection may have outstanding, a connection at
/// the limit is not read: what has been read but not yet started waits in `buf`
/// (never more than one read's worth), the rest waits in the socket where TCP
/// holds the client back, and the connection is read again when an answer
/// completes.
pub(super) struct FramedServerHandler {
    service: Arc<DnsServiceHandle>,
    transport: DnsTransport,
    buf: Vec<u8>,
    conn: ConnectionState,
    in_flight: Arc<InFlight>,
}

impl FramedServerHandler {
    pub(super) fn new(service: Arc<DnsServiceHandle>, transport: DnsTransport) -> Self {
        let in_flight = InFlight::new(Arc::clone(&service), transport);
        Self {
            service,
            transport,
            buf: Vec::new(),
            conn: ConnectionState::default(),
            in_flight,
        }
    }

    /// Stop reading until an answer completes, if the connection is at its limit.
    /// Returns whether it did.
    fn hold(&self, endpoint: &mut dyn Endpoint) -> bool {
        let f = &self.in_flight;
        // Say it is paused first, then look: an answer that completes after the
        // flag is set sees it and resumes the connection, and one that completed
        // before is seen by the look.
        f.paused.store(true, Ordering::SeqCst);
        if f.at_limit() {
            endpoint.pause_read();
            self.service.service().backpressure(self.transport);
            true
        } else {
            f.paused.store(false, Ordering::SeqCst);
            false
        }
    }

    /// Start every complete message in `buf` that the limit allows.
    fn dispatch_buffered(&mut self, endpoint: &mut dyn Endpoint) {
        let mut used = 0;
        loop {
            if self.in_flight.at_limit() && self.hold(endpoint) {
                break;
            }
            let rest = &self.buf[used..];
            if rest.len() < 2 {
                break;
            }
            let len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
            if rest.len() < 2 + len {
                break;
            }
            let payload = rest[2..2 + len].to_vec();
            used += 2 + len;
            let conn = self.conn.info(endpoint);
            // A message that is not DNS is dropped; the stream carries on.
            let _ = dispatch_to_endpoint(
                &self.service,
                endpoint,
                &payload,
                &conn,
                self.transport,
                write_length_prefixed,
                Some(&self.in_flight),
            );
        }
        self.buf.drain(..used);
        // At the limit with nothing more waiting to start: do not read more either.
        if self.in_flight.at_limit() && !self.in_flight.paused.load(Ordering::SeqCst) {
            self.hold(endpoint);
        }
    }
}

impl ProtocolHandler for FramedServerHandler {
    fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}

    fn receive(&mut self, endpoint: &mut dyn Endpoint, buf: &mut hopf_core::LoopBuf) {
        hopf_core::with_slice(buf, |data| {
            self.buf.extend_from_slice(data);
            *data = &[];
        });
        self.dispatch_buffered(endpoint);
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}

    fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &io::Error) {}
}
