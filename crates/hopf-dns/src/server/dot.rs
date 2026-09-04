// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! DNS-over-TLS server listener — feature `server` + `dot`.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use hopf_core::{
    Endpoint, ProtocolHandler, Runtime, SharedTlsAcceptor, TcpListenerConfig,
};

use crate::server::DnsServiceHandle;
use crate::wire::DnsMessage;

/// DoT listen (TCP + TLS, length-prefixed DNS).
pub fn listen_dns_dot(
    rt: &Runtime,
    addr: SocketAddr,
    acceptor: SharedTlsAcceptor,
    service: DnsServiceHandle,
) -> io::Result<SocketAddr> {
    let svc = Arc::new(service);
    let (bound, _) = rt.add_tcp_listener(
        TcpListenerConfig::new(addr, move || {
            Box::new(DotServerHandler {
                service: Arc::clone(&svc),
                buf: Vec::new(),
            }) as Box<dyn ProtocolHandler>
        })
        .with_tls(acceptor),
    )?;
    Ok(bound)
}

struct DotServerHandler {
    service: Arc<DnsServiceHandle>,
    buf: Vec<u8>,
}

impl ProtocolHandler for DotServerHandler {
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
            let Ok(query) = DnsMessage::parse(&payload) else {
                continue;
            };
            let peer = endpoint
                .remote_addr()
                .ok()
                .and_then(|a| a.as_socket_addr())
                .unwrap_or_else(|| SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0));
            let resp = self.service.process(&query, peer);
            if let Ok(bytes) = resp.serialize() {
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
