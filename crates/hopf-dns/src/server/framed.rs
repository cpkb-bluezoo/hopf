// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Length-prefixed DNS over a byte stream (RFC 1035 §4.2.2): cleartext TCP
//! here, and the shared framing handler used by the DoT listener.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use hopf_core::{Endpoint, ProtocolHandler, Runtime, TcpListenerConfig};

use super::{DnsServiceHandle, DnsTransport};

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

/// Frames DNS messages on a stream and dispatches them to the service.
pub(super) struct FramedServerHandler {
    service: Arc<DnsServiceHandle>,
    transport: DnsTransport,
    buf: Vec<u8>,
}

impl FramedServerHandler {
    pub(super) fn new(service: Arc<DnsServiceHandle>, transport: DnsTransport) -> Self {
        Self {
            service,
            transport,
            buf: Vec::new(),
        }
    }
}

impl ProtocolHandler for FramedServerHandler {
    fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        self.buf.extend_from_slice(data);
        *data = &[];
        while self.buf.len() >= 2 {
            let len = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
            if self.buf.len() < 2 + len {
                break;
            }
            let payload = self.buf[2..2 + len].to_vec();
            self.buf.drain(..2 + len);
            let peer = endpoint
                .remote_addr()
                .ok()
                .and_then(|a| a.as_socket_addr())
                .unwrap_or_else(|| {
                    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
                });
            let Some(responses) = self.service.process_wire(&payload, peer, self.transport) else {
                continue;
            };
            for bytes in responses {
                let mut out = Vec::with_capacity(2 + bytes.len());
                out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                out.extend_from_slice(&bytes);
                endpoint.send(&out);
            }
        }
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}

    fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &io::Error) {}
}
