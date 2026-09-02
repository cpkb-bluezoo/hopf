// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Pluggable datagram transport underneath a QUIC connection.
//!
//! The default transport (used by [`crate::connect_quic`]/[`crate::listen_quic`]
//! and their `_hooks` counterparts) is a real UDP socket, and stays on its
//! own fast path — ECN/GSO-aware sends, mio-driven receive — entirely
//! unaffected by this trait. [`QuicDatagramPath`] exists for everything
//! else a QUIC connection's datagrams might actually travel over: an
//! in-memory pipe for tests (no real socket needed to prove two endpoints
//! can complete a handshake), or a QUIC connection tunnelled inside
//! another protocol's payload — e.g. an RFC 9298 CONNECT-UDP client
//! carrying QUIC packets as HTTP Datagrams instead of raw UDP.

use std::io;
use std::net::SocketAddr;

/// A datagram transport a QUIC connection can send on and receive from,
/// standing in for a real UDP socket.
///
/// Use [`crate::connect_quic_with_path`]/[`crate::connect_quic_hooks_with_path`]
/// to dial a connection over one instead of a real socket. Since there's
/// no file descriptor to register with a poll loop, inbound datagrams for
/// a custom path arrive by calling
/// [`QuicDriverHandle::receive_path_datagram`](crate::QuicDriverHandle::receive_path_datagram)
/// instead — from any thread; the driver marshals it onto its own worker
/// thread the same way every other externally-triggered entry point into
/// a connection already has to.
///
/// Connection migration / path validation / NAT rebinding (RFC 9000 §9)
/// are only implemented against the default socket-backed transport — a
/// custom path that never changes address doesn't need them, and one that
/// does is free to handle it below this trait (e.g. by keeping the tunnel
/// itself stable across whatever is moving underneath it).
pub trait QuicDatagramPath: Send {
    /// Send one UDP-equivalent payload to `dest`.
    ///
    /// `ecn`/`segment_size` are the same optional per-datagram hints
    /// [`quinn_proto::Transmit`] carries for a real socket (ECN codepoint,
    /// GSO segment size) — implementations that aren't backed by an actual
    /// IP-layer socket are free to ignore them; they're optimizations, not
    /// something QUIC's correctness depends on.
    fn send(
        &mut self,
        dest: SocketAddr,
        data: &[u8],
        ecn: Option<u8>,
        segment_size: Option<usize>,
    ) -> io::Result<usize>;

    /// This path's local address, as reported to the application
    /// (e.g. [`QuicDriverHandle::local_addr`](crate::QuicDriverHandle)).
    fn local_addr(&self) -> io::Result<SocketAddr>;

    /// Whether this path can still be used to send.
    fn is_open(&self) -> bool;

    /// Release any resources this path holds. Default: nothing to do —
    /// most implementations can rely on `Drop` instead; override when
    /// closing needs to be fallible or needs to happen before the value is
    /// actually dropped (e.g. signalling the other end of a tunnel).
    fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}
