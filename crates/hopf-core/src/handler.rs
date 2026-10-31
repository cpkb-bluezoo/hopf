// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Protocol handler callbacks (Gumdrop `ProtocolHandler`).

use std::cell::RefCell;
use std::io;

use loopbuf::LoopBuf;

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
    /// `buf` is the connection's inbound ring, fixed in size for the life of
    /// the endpoint. Consume (`advance`) only whole tokens: what is left is
    /// presented again at the front of the next call, once more has arrived.
    /// A handler holds none of the stream itself. A token that cannot fit
    /// the ring at all is an error to report with [`Endpoint::fail`], never a
    /// reason to start buffering for yourself.
    ///
    /// While the ring is full and the handler consumes nothing, the
    /// connection stops reading (backpressure) or, with nothing more to
    /// wait for, fails.
    fn receive(&mut self, endpoint: &mut dyn Endpoint, buf: &mut LoopBuf) {
        with_slice(buf, |data| self.receive_slice(endpoint, data));
    }

    /// Stepping stone for handlers not yet converted to read the ring
    /// directly: the same as [`Self::receive`] but over a contiguous cursor.
    /// A handler implements exactly one of the two; this goes once every
    /// handler has been converted.
    #[doc(hidden)]
    fn receive_slice(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        // A handler already converted to read the ring is reached through a
        // copy of the cursor in one.
        let mut ring = LoopBuf::with_capacity(data.len().max(1));
        ring.extend_from_slice(data);
        self.receive(endpoint, &mut ring);
        *data = &data[data.len() - ring.len()..];
    }

    /// Peer closed the connection or the endpoint finished closing.
    fn disconnected(&mut self, endpoint: &mut dyn Endpoint);

    /// Security layer became active (TLS/QUIC).
    ///
    /// For TLS-from-accept, this runs after `connected` once the handshake
    /// finishes (with ALPN). Defer protocol greetings that require TLS until here.
    fn security_established(&mut self, _endpoint: &mut dyn Endpoint, _info: &SecurityInfo) {}

    /// The connection migrated to a new network path (RFC 9000 §9), e.g.
    /// after a client's Wi-Fi-to-cellular handoff or a NAT rebinding.
    /// `endpoint` already reflects the new address via `remote_addr()`.
    /// QUIC-only — TCP-based transports never call this. Default: do
    /// nothing.
    fn migrated(&mut self, _endpoint: &mut dyn Endpoint) {}

    /// Unrecoverable I/O or protocol error on the endpoint.
    fn error(&mut self, endpoint: &mut dyn Endpoint, err: &io::Error);

    /// An unreliable datagram associated with this stream arrived (e.g. an
    /// HTTP/3 Datagram demuxed by quarter-stream-ID, RFC 9297 §2.1).
    /// Default: ignore. HTTP/3 request streams override this to abort with
    /// `H3_DATAGRAM_ERROR` when the request has no datagram semantics, or
    /// to forward into an upgraded handler that opted in.
    fn datagram_received(&mut self, _endpoint: &mut dyn Endpoint, _data: &[u8]) {}
}

/// No-op handler defaults for tests.
pub struct NopHandler;

impl ProtocolHandler for NopHandler {
    fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}

    fn receive(&mut self, _endpoint: &mut dyn Endpoint, buf: &mut LoopBuf) {
        buf.advance(buf.len());
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}

    fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &io::Error) {}
}

/// Presents `data` to a handler that reads the ring, from code that still
/// has a cursor: copies it into a ring, and advances `data` past what the
/// handler consumed. A stepping stone for forwarders not yet converted to
/// pass their own ring on.
pub fn forward_slice(inner: &mut dyn ProtocolHandler, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
    let mut ring = LoopBuf::with_capacity(data.len().max(1));
    ring.extend_from_slice(data);
    inner.receive(endpoint, &mut ring);
    *data = &data[data.len() - ring.len()..];
}

thread_local! {
    /// Where a ring that has wrapped is copied to be seen as one slice.
    static WRAPPED: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// Presents what is readable in `buf` to `f` as a single cursor, and
/// consumes from `buf` what `f` advanced past. The ring is read in place
/// unless it has wrapped, when it is copied out first (the ring itself is
/// never rearranged).
pub fn with_slice(buf: &mut LoopBuf, f: impl FnOnce(&mut &[u8])) {
    let (first, second) = buf.readable_spans();
    let total = first.len() + second.len();
    let consumed = if second.is_empty() {
        let mut cursor = first;
        f(&mut cursor);
        total - cursor.len()
    } else {
        // Taken out of the cell for the call, so a handler that reenters
        // finds it empty rather than borrowed.
        let mut copy = WRAPPED.with(|c| std::mem::take(&mut *c.borrow_mut()));
        copy.clear();
        copy.extend_from_slice(first);
        copy.extend_from_slice(second);
        let mut cursor = copy.as_slice();
        f(&mut cursor);
        let consumed = total - cursor.len();
        WRAPPED.with(|c| *c.borrow_mut() = copy);
        consumed
    };
    buf.advance(consumed);
}
