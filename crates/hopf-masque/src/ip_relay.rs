// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The accepted CONNECT-IP tunnel: decodes/encodes RFC 9484 capsules and
//! hands the application decoded IP packets and address requests via
//! [`ConnectIpHandler`] — what actually happens to a packet (a TUN device,
//! a userspace forwarder, a test echo) is entirely the application's job,
//! not this crate's (hopf has no kernel network stack dependency anywhere
//! in the workspace, and this crate isn't the place to add one).

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use hopf_core::ConnHandle;
use hopf_http::capsule::Capsule;
use hopf_http::context_id;
use hopf_http::ProtocolUpgradeHandler;

use crate::ip_capsule::{self, AddressEntry, RouteEntry};

/// Builds one [`ConnectIpHandler`] per accepted CONNECT-IP request.
pub trait ConnectIpHandlerFactory: Send + Sync {
    /// Create a handler for the next accepted tunnel.
    fn create_handler(&self) -> Box<dyn ConnectIpHandler>;
}

/// Application callbacks for an accepted CONNECT-IP tunnel.
///
/// Kept deliberately separate from [`ConnectIpSession`] (the crate hands
/// the app one of each, not one type playing both roles) — see
/// [`crate::ConnectUdpEventHandler`]'s docs for why that split holds up
/// better than it might look at first.
pub trait ConnectIpHandler: Send {
    /// The tunnel is open; `session` sends packets, assigns addresses, and
    /// advertises routes.
    fn opened(&mut self, session: Arc<dyn ConnectIpSession>);

    /// A full IP packet arrived from the client (RFC 9484 §5: the
    /// Context-ID-0 payload, from the IP Version field through the last
    /// byte of the IP payload).
    fn packet_received(&mut self, packet: &[u8]);

    /// The client requested `address` (RFC 9484 §4.2 `ADDRESS_REQUEST`) —
    /// reply with [`ConnectIpSession::assign_address`] using the same
    /// `request_id`, once a decision is made. Default: ignore (a relay
    /// with nothing to assign need not implement this).
    fn address_requested(&mut self, request_id: u64, address: IpAddr, prefix_length: u8) {
        let _ = (request_id, address, prefix_length);
    }

    /// The tunnel closed (peer FIN, or the effect of
    /// [`ConnectIpSession::close`] landing). Default: ignore.
    fn closed(&mut self) {}
}

/// App-facing handle for an open CONNECT-IP tunnel, handed to
/// [`ConnectIpHandler::opened`]. Safe to hold and call from any thread,
/// not just the one `opened` itself ran on.
pub trait ConnectIpSession: Send + Sync {
    /// Queue a full IP packet to send to the client.
    fn send_packet(&self, packet: &[u8]);

    /// Assign `address`/`prefix_length` to the client, in reply to a
    /// `request_id` from [`ConnectIpHandler::address_requested`] (or
    /// unsolicited, with an application-chosen `request_id`) — RFC 9484
    /// §4.2 `ADDRESS_ASSIGN`.
    fn assign_address(&self, request_id: u64, address: IpAddr, prefix_length: u8);

    /// Advertise that the client may send packets in `start..=end` for
    /// `ip_protocol` (`0` = all protocols) — RFC 9484 §4.3
    /// `ROUTE_ADVERTISEMENT`. A no-op if `start`/`end` are different IP
    /// versions or `start` sorts after `end` (RFC 9484 §4.3's own
    /// requirement — silently dropped rather than panicking the caller for
    /// what's usually a locally-computed range, not untrusted input).
    fn advertise_route(&self, start: IpAddr, end: IpAddr, ip_protocol: u8);

    /// Close this tunnel.
    fn close(&self);
}

struct IpRelayShared {
    outbound_packets: Mutex<VecDeque<Vec<u8>>>,
    outbound_assign: Mutex<VecDeque<AddressEntry>>,
    outbound_routes: Mutex<VecDeque<RouteEntry>>,
    closing: AtomicBool,
    /// Re-enters the HTTP connection's own handler on any of the above, so
    /// activity queued from the app's own thread — not necessarily the
    /// connection's — gets flushed out promptly via `take_outbound`
    /// instead of only whenever the connection next hears from the client.
    /// See `hopf_masque::client::ClientShared`'s identical reasoning on
    /// the CONNECT-UDP client side.
    conn: ConnHandle,
}

struct IpSessionHandle {
    shared: Arc<IpRelayShared>,
}

impl ConnectIpSession for IpSessionHandle {
    fn send_packet(&self, packet: &[u8]) {
        self.shared.outbound_packets.lock().unwrap().push_back(packet.to_vec());
        self.shared.conn.poke();
    }

    fn assign_address(&self, request_id: u64, address: IpAddr, prefix_length: u8) {
        self.shared
            .outbound_assign
            .lock()
            .unwrap()
            .push_back(AddressEntry { request_id, address, prefix_length });
        self.shared.conn.poke();
    }

    fn advertise_route(&self, start: IpAddr, end: IpAddr, ip_protocol: u8) {
        let Some(entry) = RouteEntry::new(start, end, ip_protocol) else {
            return;
        };
        self.shared.outbound_routes.lock().unwrap().push_back(entry);
        self.shared.conn.poke();
    }

    fn close(&self) {
        self.shared.closing.store(true, Ordering::Release);
        self.shared.conn.poke();
    }
}

/// [`ProtocolUpgradeHandler`] for an accepted CONNECT-IP request.
pub(crate) struct ConnectIpRelay {
    shared: Arc<IpRelayShared>,
    handler: Box<dyn ConnectIpHandler>,
}

impl ConnectIpRelay {
    /// Build the relay and immediately notify `handler` the tunnel is
    /// open — call this once the HTTP side is ready to install it (the
    /// `200`/`101` accept response is already decided by this point, so
    /// there's nothing left to wait for, unlike CONNECT-UDP's relay, which
    /// defers this handshake until an outbound UDP socket — a resource
    /// this crate itself owns — is also ready).
    pub(crate) fn accept(conn: ConnHandle, mut handler: Box<dyn ConnectIpHandler>) -> Self {
        let shared = Arc::new(IpRelayShared {
            outbound_packets: Mutex::new(VecDeque::new()),
            outbound_assign: Mutex::new(VecDeque::new()),
            outbound_routes: Mutex::new(VecDeque::new()),
            closing: AtomicBool::new(false),
            conn,
        });
        let session: Arc<dyn ConnectIpSession> = Arc::new(IpSessionHandle { shared: Arc::clone(&shared) });
        handler.opened(session);
        Self { shared, handler }
    }
}

impl ProtocolUpgradeHandler for ConnectIpRelay {
    fn receive(&mut self, _data: &[u8]) {
        // Real payloads always arrive via `datagram_received`/
        // `capsule_received` (Capsule Protocol is mandatory for this relay
        // — see `ip_handler.rs`'s accept response). An empty call is the
        // cross-thread poke signal; nothing to do here for it either,
        // since `take_outbound` below always drains whatever's queued
        // regardless of what triggered re-entry.
    }

    fn take_outbound(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut q = self.shared.outbound_packets.lock().unwrap();
            while let Some(packet) = q.pop_front() {
                let with_context = context_id::encode(context_id::REGISTERED_CONTEXT_ID, &packet);
                Capsule::datagram(with_context).encode(&mut out);
            }
        }
        {
            let mut q = self.shared.outbound_assign.lock().unwrap();
            while let Some(entry) = q.pop_front() {
                let value = ip_capsule::encode_address_entries(std::slice::from_ref(&entry));
                Capsule { ty: ip_capsule::CAPSULE_ADDRESS_ASSIGN, value }.encode(&mut out);
            }
        }
        {
            let mut q = self.shared.outbound_routes.lock().unwrap();
            while let Some(entry) = q.pop_front() {
                let value = ip_capsule::encode_route_entries(std::slice::from_ref(&entry));
                Capsule { ty: ip_capsule::CAPSULE_ROUTE_ADVERTISEMENT, value }.encode(&mut out);
            }
        }
        out
    }

    fn closed(&mut self) {
        self.handler.closed();
    }

    fn wants_close(&self) -> bool {
        self.shared.closing.load(Ordering::Acquire)
    }

    fn wants_datagrams(&self) -> bool {
        true
    }

    fn datagram_received(&mut self, data: &[u8]) {
        let Some((cid, payload)) = context_id::decode(data) else {
            return;
        };
        // RFC 9484 §5: Context ID 0 is reserved for IP payloads; a
        // nonzero, currently-unallocated value is ignored rather than
        // treated as an error.
        if cid == context_id::REGISTERED_CONTEXT_ID {
            self.handler.packet_received(payload);
        }
    }

    fn capsule_received(&mut self, ty: u64, value: &[u8]) {
        if ty == ip_capsule::CAPSULE_ADDRESS_REQUEST {
            if let Some(entries) = ip_capsule::decode_address_entries(value) {
                for e in entries {
                    self.handler.address_requested(e.request_id, e.address, e.prefix_length);
                }
            }
        }
        // Every other type (including ROUTE_ADVERTISEMENT and
        // ADDRESS_ASSIGN, which only ever flow server-to-client on this
        // side) is ignored, per this trait's own default behaviour.
    }
}
