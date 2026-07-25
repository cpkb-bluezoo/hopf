// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! UDP client transport (default).

use std::io;
use std::net::SocketAddr;

use super::{DnsClientTransport, DnsClientTransportHandler};

/// Stateless UDP send helper (reactor owns the socket; this is for tests / direct use).
pub struct UdpDnsClientTransport;

impl DnsClientTransport for UdpDnsClientTransport {
    fn send_query(
        &mut self,
        _server: SocketAddr,
        _message: &[u8],
        _handler: Box<dyn DnsClientTransportHandler>,
    ) -> io::Result<()> {
        // UDP queries go through the reactor-owned socket in DnsResolver.
        // Returning Err here drops the handler.
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "use DnsResolver UDP path (reactor-owned socket)",
        ))
    }
}
