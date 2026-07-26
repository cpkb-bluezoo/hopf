// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! UDP DNS listener on a worker reactor.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use mio::Token;
use hopf_core::{ReactorHandle, UdpDatagramHandler};

use super::DnsServiceHandle;
use crate::wire::{DnsMessage, FLAG_TC};

/// UDP listen configuration.
pub struct DnsUdpListenConfig {
    /// Bind address (e.g. 0.0.0.0:53 or 127.0.0.1:5353).
    pub addr: SocketAddr,
    /// Service handle.
    pub service: DnsServiceHandle,
}

struct DnsUdpHandler {
    service: DnsServiceHandle,
    reactor: ReactorHandle,
    token: Arc<std::sync::Mutex<Option<Token>>>,
}

impl UdpDatagramHandler for DnsUdpHandler {
    fn on_datagram(&mut self, peer: SocketAddr, data: &[u8]) {
        let Ok(query) = DnsMessage::parse(data) else {
            return;
        };
        let mut resp = self.service.process(&query);
        let Ok(mut bytes) = resp.serialize() else {
            return;
        };
        // RFC 1035 §4.1.1 / RFC 2181 §9: a response too large for what the
        // client advertised (RFC 6891 §6.2.3 OPT payload size, or the
        // legacy 512-octet limit with no EDNS at all) gets its records
        // dropped and TC set instead of being sent oversized — the client
        // is expected to retry over TCP for the full answer.
        let limit = query.requested_udp_payload_size() as usize;
        if bytes.len() > limit {
            resp.answers.clear();
            resp.authorities.clear();
            resp.additionals.clear();
            resp.flags |= FLAG_TC;
            let Ok(truncated) = resp.serialize() else {
                return;
            };
            bytes = truncated;
        }
        if let Some(token) = *self.token.lock().unwrap() {
            self.reactor.udp_send(token, peer, bytes);
        }
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
        reactor: reactor.clone(),
        token: Arc::clone(&token_slot),
    });
    let token = reactor.register_udp(socket, handler)?;
    *token_slot.lock().unwrap() = Some(token);
    Ok((local, token))
}
