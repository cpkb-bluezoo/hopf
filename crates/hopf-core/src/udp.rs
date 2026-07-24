// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! UDP datagram registration on worker reactors (DNS substrate).

use std::net::SocketAddr;

/// Handler for datagrams received on a reactor-owned UDP socket.
pub trait UdpDatagramHandler: Send {
    /// Called on the reactor thread when a datagram arrives.
    fn on_datagram(&mut self, peer: SocketAddr, data: &[u8]);
}
