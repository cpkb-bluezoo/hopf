// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Multicast UDP socket setup and reactor registration for mDNS (RFC 6762
//! §11: port 5353, group 224.0.0.251, IP TTL 255). Deliberately mirrors
//! `hopf-dns`'s own `listen_dns_udp` (`hopf_dns::server::listen_dns_udp`)
//! — bind, configure, `set_nonblocking`, hand off to
//! [`ReactorHandle::register_udp`] — the one inherently synchronous
//! stretch in this crate (a one-time setup sequence, not steady-state
//! work; see the crate's top-level docs).

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};

use mio::Token;
use hopf_core::{ReactorHandle, UdpDatagramHandler};

/// mDNS multicast group (RFC 6762 §3).
pub const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
/// mDNS UDP port (RFC 6762 §3).
pub const MDNS_PORT: u16 = 5353;

/// Bind the mDNS multicast socket and register it on `reactor`. Returns
/// the local address and reactor token (needed for
/// [`ReactorHandle::udp_send`]).
///
/// `multicast_if`, when `Some`, both joins the group on and sends via that
/// one specific local interface — for a multi-homed host that wants mDNS
/// scoped to a single interface (or a test that needs it pinned to
/// loopback, since not every host's default route is multicast-capable —
/// e.g. some sandboxed/firewalled environments). `None` (the normal case)
/// joins on `INADDR_ANY` and leaves the outgoing interface to the OS's
/// routing, which is the right default for a typical single-homed host —
/// RFC 6762 doesn't mandate one interface-selection policy over the
/// other. Sets IP TTL and multicast TTL to 255 (§11), and enables
/// multicast loopback (harmless in the `None` case — RFC 6762 doesn't
/// forbid a responder hearing its own packets, and this crate's query/
/// response handling already tolerates that via the same de-duplication a
/// real second responder would need anyway — and required for this
/// crate's own loopback-based integration tests). Sets
/// `SO_REUSEADDR`/`SO_REUSEPORT` (via `socket2`, unavailable on a plain
/// `std::net::UdpSocket`) so more than one mDNS-aware process can coexist
/// on this host, per RFC 6762 §15.1.
pub fn listen_mdns_udp(
    reactor: &ReactorHandle,
    handler: Box<dyn UdpDatagramHandler>,
    multicast_if: Option<Ipv4Addr>,
) -> io::Result<(SocketAddr, Token)> {
    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT);
    let socket2 = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket2.set_reuse_address(true)?;
    #[cfg(unix)]
    socket2.set_reuse_port(true)?;
    socket2.bind(&addr.into())?;
    if let Some(iface) = multicast_if {
        socket2.set_multicast_if_v4(&iface)?;
    }
    let std_sock: std::net::UdpSocket = socket2.into();

    std_sock.join_multicast_v4(&MDNS_GROUP, &multicast_if.unwrap_or(Ipv4Addr::UNSPECIFIED))?;
    std_sock.set_multicast_ttl_v4(255)?;
    std_sock.set_ttl(255)?;
    std_sock.set_multicast_loop_v4(true)?;
    std_sock.set_nonblocking(true)?;

    let local = std_sock.local_addr()?;
    let socket = mio::net::UdpSocket::from_std(std_sock);
    let token = reactor.register_udp(socket, handler)?;
    Ok((local, token))
}

/// [`ReactorHandle::register_udp`] needs the handler before it can hand
/// back the [`Token`] `udp_send` calls need — this cell lets a handler
/// close over "my own token", filled in immediately after registration
/// (mirrors `hopf-dns`'s `DnsUdpHandler` — see `hopf_dns::server::udp`).
pub type TokenCell = Arc<Mutex<Option<Token>>>;
