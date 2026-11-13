// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Length-prefixed DNS over a byte stream (RFC 1035 §4.2.2): cleartext TCP
//! here, and the shared framing handler used by the DoT listener.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use hopf_core::{Endpoint, ProtocolHandler, Runtime, SecurityInfo, TcpListenerConfig};

use super::{ConnectionInfo, DnsServiceHandle, DnsTransport, WireSink};

/// Cleartext DNS over TCP (RFC 1035 §4.2.2, RFC 7766). Required for zone
/// transfers and for clients that retry a truncated UDP answer.
pub fn listen_dns_tcp(
    rt: &Runtime,
    addr: SocketAddr,
    service: DnsServiceHandle,
) -> io::Result<SocketAddr> {
    let svc = Arc::new(service);
    let (bound, _) = rt.add_tcp_listener(TcpListenerConfig::new(addr, move || {
        Box::new(FramedServerHandler::new(Arc::clone(&svc), DnsTransport::Tcp))
            as Box<dyn ProtocolHandler>
    }))?;
    Ok(bound)
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
) -> bool {
    let state = Arc::new(Mutex::new(ReplyState::Dispatching));
    let handle = endpoint.handle();
    let shared = Arc::clone(&state);
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
pub(super) struct FramedServerHandler {
    service: Arc<DnsServiceHandle>,
    transport: DnsTransport,
    buf: Vec<u8>,
    conn: ConnectionState,
}

impl FramedServerHandler {
    pub(super) fn new(service: Arc<DnsServiceHandle>, transport: DnsTransport) -> Self {
        Self {
            service,
            transport,
            buf: Vec::new(),
            conn: ConnectionState::default(),
        }
    }
}

impl ProtocolHandler for FramedServerHandler {
    fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}

    fn receive(&mut self, endpoint: &mut dyn Endpoint, buf: &mut hopf_core::LoopBuf) {
        hopf_core::with_slice(buf, |data| {
            self.buf.extend_from_slice(data);
            *data = &[];
            while self.buf.len() >= 2 {
                let len = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
                if self.buf.len() < 2 + len {
                    break;
                }
                let payload = self.buf[2..2 + len].to_vec();
                self.buf.drain(..2 + len);
                let conn = self.conn.info(endpoint);
                // A message that is not DNS is dropped; the stream carries on.
                let _ = dispatch_to_endpoint(
                    &self.service,
                    endpoint,
                    &payload,
                    &conn,
                    self.transport,
                    write_length_prefixed,
                );
            }
        });
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}

    fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &io::Error) {}
}
