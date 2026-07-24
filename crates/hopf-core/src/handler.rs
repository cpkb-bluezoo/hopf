// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Protocol handler callbacks (Gumdrop `ProtocolHandler`).

use std::io;

use crate::endpoint::Endpoint;
use crate::security::SecurityInfo;

/// Protocol implementation receiving events from an [`Endpoint`].
///
/// All methods are invoked on the endpoint's owning reactor thread and must
/// not block. Panics are caught at the connection boundary (log + close).
pub trait ProtocolHandler: Send {
    /// Endpoint is ready for protocol traffic.
    ///
    /// Called on the **worker reactor** after the socket is registered (cleaner
    /// than Gumdrop's accept-thread `connected`).
    fn connected(&mut self, endpoint: &mut dyn Endpoint);

    /// Plaintext application data arrived.
    ///
    /// `data` is a cursor into the connection's inbound buffer. Advance it past
    /// bytes you consume (`*data = &data[n..]`). Any remaining suffix is
    /// preserved for the next call (NIO compact semantics).
    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]);

    /// Peer closed the connection or the endpoint finished closing.
    fn disconnected(&mut self, endpoint: &mut dyn Endpoint);

    /// Security layer became active (TLS/QUIC).
    ///
    /// For TLS-from-accept, this runs after `connected` once the handshake
    /// finishes (with ALPN). Defer protocol greetings that require TLS until here.
    fn security_established(&mut self, _endpoint: &mut dyn Endpoint, _info: &SecurityInfo) {}

    /// Unrecoverable I/O or protocol error on the endpoint.
    fn error(&mut self, endpoint: &mut dyn Endpoint, err: &io::Error);
}

/// No-op handler defaults for tests.
pub struct NopHandler;

impl ProtocolHandler for NopHandler {
    fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}

    fn receive(&mut self, _endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        *data = &[];
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}

    fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &io::Error) {}
}
