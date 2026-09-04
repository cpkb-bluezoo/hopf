// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! DNS-over-QUIC server — feature `server` + `doq`.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use hopf_core::{Endpoint, ProtocolHandler};
use hopf_quic::{listen_quic, QuicDriverHandle, QuicListenConfig, QuicServerConfig};

use crate::server::DnsServiceHandle;
use crate::wire::DnsMessage;

/// ALPN for DoQ.
#[allow(dead_code)]
pub const DOQ_ALPN: &[u8] = b"doq";

/// Listen for DoQ (ALPN `doq`) on `addr`.
pub fn listen_dns_doq(
    addr: SocketAddr,
    server: Arc<QuicServerConfig>,
    service: DnsServiceHandle,
) -> io::Result<QuicDriverHandle> {
    let svc = service;
    listen_quic(QuicListenConfig::new(
        addr,
        server,
        Arc::new(move || {
            Box::new(DoqServerHandler {
                service: svc.clone(),
                buf: Vec::new(),
            }) as Box<dyn ProtocolHandler>
        }),
    ))
}

struct DoqServerHandler {
    service: DnsServiceHandle,
    buf: Vec<u8>,
}

impl ProtocolHandler for DoqServerHandler {
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
                // RFC 9250 §4.3: a malformed DNS message on the stream is
                // a protocol violation, not something to silently drop.
                endpoint.abort(crate::client::doq::DOQ_PROTOCOL_ERROR);
                return;
            };
            let peer = endpoint
                .remote_addr()
                .ok()
                .and_then(|a| a.as_socket_addr())
                .unwrap_or_else(|| SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0));
            let mut resp = self.service.process(&query, peer);
            // RFC 9250 §4.2.1: the DNS message ID MUST be 0 over DoQ,
            // regardless of what the query itself carried.
            resp.id = 0;
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
