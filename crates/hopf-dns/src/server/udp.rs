// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! UDP DNS listener on a worker reactor.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use mio::Token;
use hopf_core::{ReactorHandle, UdpDatagramHandler};

use super::{ConnectionInfo, DnsServiceHandle, DnsTransport};

/// UDP listen configuration.
pub struct DnsUdpListenConfig {
    /// Bind address (e.g. 0.0.0.0:53 or 127.0.0.1:5353).
    pub addr: SocketAddr,
    /// Service handle.
    pub service: DnsServiceHandle,
}

struct DnsUdpHandler {
    service: DnsServiceHandle,
    local: SocketAddr,
    reactor: ReactorHandle,
    token: Arc<std::sync::Mutex<Option<Token>>>,
}

impl UdpDatagramHandler for DnsUdpHandler {
    fn on_datagram(&mut self, peer: SocketAddr, data: &[u8]) {
        let Some(token) = *self.token.lock().unwrap() else {
            return;
        };
        // `udp_send` queues onto the socket's reactor from any thread, so a
        // handler that answers later needs no hop of its own.
        let reactor = self.reactor.clone();
        let conn = ConnectionInfo::new(peer).with_local(Some(self.local));
        self.service.dispatch_wire_with(
            data,
            &conn,
            DnsTransport::Udp,
            Box::new(move |responses| {
                for bytes in responses {
                    reactor.udp_send(token, peer, bytes);
                }
            }),
        );
    }
}

/// Bind UDP DNS and register on `reactor`. Returns local addr + token.
pub fn listen_dns_udp(
    reactor: &ReactorHandle,
    config: DnsUdpListenConfig,
) -> io::Result<(SocketAddr, Token)> {
    let std_sock = std::net::UdpSocket::bind(config.addr)?;
    std_sock.set_nonblocking(true)?;
    let local = std_sock.local_addr()?;
    let socket = mio::net::UdpSocket::from_std(std_sock);
    let token_slot = Arc::new(std::sync::Mutex::new(None));
    let handler = Box::new(DnsUdpHandler {
        service: config.service,
        local,
        reactor: reactor.clone(),
        token: Arc::clone(&token_slot),
    });
    let token = reactor.register_udp(socket, handler)?;
    *token_slot.lock().unwrap() = Some(token);
    Ok((local, token))
}
