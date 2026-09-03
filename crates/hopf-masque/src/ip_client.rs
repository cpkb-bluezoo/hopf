// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Client side of RFC 9484 CONNECT-IP: establish a tunnel to a proxy and
//! exchange IP packets, address requests, and address/route capsules with
//! it, over whichever of h1/h2/h3 the shared, transport-negotiating dial
//! path ends up using — mirrors [`crate::client`] (RFC 9298 CONNECT-UDP's
//! client) closely enough that most of this module's docs are that one's,
//! updated for IP's extra capsule types; see [`connect_ip`].

use std::collections::VecDeque;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use hopf_core::{ConnHandle, Runtime};
use hopf_dns::DnsResolver;
use hopf_http::capsule::{capsule_protocol_enabled, Capsule};
use hopf_http::{
    connect_auto, context_id, ClientHandler, ClientHandlerFactory, ClientWriter, Headers,
    HttpClientTimeouts, HttpFallback, HttpLimits, HttpVersion, ProtocolUpgradeHandler,
};

use crate::ip_capsule::{self, AddressEntry};
use crate::ip_target::{self, IpProto, IpTarget};

/// One address this client is requesting from the proxy, for
/// [`ConnectIpClientSession::send_address_request`] — RFC 9484 §4.2's
/// `Requested Address`. `request_id` is caller-chosen and echoed back on
/// the matching [`ConnectIpEventHandler::address_assigned`] (RFC 9484
/// §4.2: request IDs "MUST NOT be reused" within a tunnel and "MUST NOT be
/// zero").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestedAddress {
    /// Caller-chosen, nonzero correlation id.
    pub request_id: u64,
    /// The address being requested (a wildcard request typically uses the
    /// unspecified address, `0.0.0.0`/`::`, with `prefix_length: 0`).
    pub address: IpAddr,
    /// Requested prefix length.
    pub prefix_length: u8,
}

/// App callbacks for an outbound CONNECT-IP tunnel — kept deliberately
/// separate from [`ConnectIpClientSession`], same reasoning as
/// [`crate::ConnectUdpEventHandler`]'s docs.
pub trait ConnectIpEventHandler: Send {
    /// The tunnel is open; `session` sends packets, requests addresses, or
    /// closes the tunnel.
    fn opened(&mut self, session: Arc<dyn ConnectIpClientSession>);

    /// A full IP packet arrived from the proxy.
    fn packet_received(&mut self, packet: &[u8]) {
        let _ = packet;
    }

    /// The proxy assigned `address`/`prefix_length`, in reply to
    /// `request_id` from an earlier [`ConnectIpClientSession::send_address_request`]
    /// (or unsolicited) — RFC 9484 §4.2 `ADDRESS_ASSIGN`.
    fn address_assigned(&mut self, request_id: u64, address: IpAddr, prefix_length: u8) {
        let _ = (request_id, address, prefix_length);
    }

    /// The proxy advertised that this tunnel may send packets in
    /// `start..=end` for `ip_protocol` (`0` = all protocols) — RFC 9484
    /// §4.3 `ROUTE_ADVERTISEMENT`.
    fn route_advertised(&mut self, start: IpAddr, end: IpAddr, ip_protocol: u8) {
        let _ = (start, end, ip_protocol);
    }

    /// The tunnel closed (peer FIN, or the effect of
    /// [`ConnectIpClientSession::close`] landing). Default: ignore.
    fn closed(&mut self) {}

    /// The request failed before ever opening — the proxy rejected it, or
    /// the underlying connection failed. Default: ignore.
    fn error(&mut self, err: &io::Error) {
        let _ = err;
    }
}

/// App-facing handle for an open CONNECT-IP tunnel, handed to
/// [`ConnectIpEventHandler::opened`]. Safe to hold and call from any
/// thread, not just the one `opened` itself ran on.
pub trait ConnectIpClientSession: Send + Sync {
    /// Queue a full IP packet to send to the proxy.
    fn send_packet(&self, packet: &[u8]);

    /// Request one or more addresses from the proxy — RFC 9484 §4.2
    /// `ADDRESS_REQUEST`. Every entry passed in one call is encoded into
    /// one capsule together; call again separately if a later, distinct
    /// request should not share a capsule with an earlier one still
    /// in flight. A no-op if `requests` is empty.
    fn send_address_request(&self, requests: &[RequestedAddress]);

    /// Ask the proxy to close this tunnel.
    fn close(&self);
}

struct ClientShared {
    /// Packets queued by [`ConnectIpClientSession::send_packet`].
    outbound_packets: Mutex<VecDeque<Vec<u8>>>,
    /// One entry per [`ConnectIpClientSession::send_address_request`] call — kept
    /// as separate batches (rather than flattened into one queue of
    /// entries) so each call's entries land in their own capsule, matching
    /// what the caller actually asked for.
    outbound_address_requests: Mutex<VecDeque<Vec<AddressEntry>>>,
    closing: AtomicBool,
    /// See [`crate::client::ClientShared`]'s identical field — same
    /// cross-thread poke reasoning applies unchanged.
    conn: ConnHandle,
}

struct ClientSessionHandle {
    shared: Arc<ClientShared>,
}

impl ConnectIpClientSession for ClientSessionHandle {
    fn send_packet(&self, packet: &[u8]) {
        self.shared.outbound_packets.lock().unwrap().push_back(packet.to_vec());
        self.shared.conn.poke();
    }

    fn send_address_request(&self, requests: &[RequestedAddress]) {
        if requests.is_empty() {
            return;
        }
        let entries: Vec<AddressEntry> = requests
            .iter()
            .map(|r| AddressEntry { request_id: r.request_id, address: r.address, prefix_length: r.prefix_length })
            .collect();
        self.shared.outbound_address_requests.lock().unwrap().push_back(entries);
        self.shared.conn.poke();
    }

    fn close(&self) {
        self.shared.closing.store(true, Ordering::Release);
        self.shared.conn.poke();
    }
}

/// [`ProtocolUpgradeHandler`] for an accepted CONNECT-IP tunnel — bridges
/// the HTTP Datagram / Context ID / RFC 9484 capsule layer to
/// [`ConnectIpEventHandler`].
struct ConnectIpClientUpgrade {
    event: Box<dyn ConnectIpEventHandler>,
    shared: Arc<ClientShared>,
    opened: bool,
}

impl ConnectIpClientUpgrade {
    fn ensure_opened(&mut self) {
        if self.opened {
            return;
        }
        self.opened = true;
        let session: Arc<dyn ConnectIpClientSession> = Arc::new(ClientSessionHandle {
            shared: Arc::clone(&self.shared),
        });
        self.event.opened(session);
    }
}

impl ProtocolUpgradeHandler for ConnectIpClientUpgrade {
    fn receive(&mut self, _data: &[u8]) {
        // Same reasoning as `ConnectUdpClientUpgrade::receive`: real
        // payloads always arrive via `datagram_received`/`capsule_received`
        // (Capsule Protocol is mandatory here too), so this is only ever
        // the cross-thread poke signal — `ensure_opened` plus
        // `take_outbound` draining below cover it either way.
        self.ensure_opened();
    }

    fn take_outbound(&mut self) -> Vec<u8> {
        self.ensure_opened();
        let mut out = Vec::new();
        {
            let mut q = self.shared.outbound_packets.lock().unwrap();
            while let Some(packet) = q.pop_front() {
                let with_context = context_id::encode(context_id::REGISTERED_CONTEXT_ID, &packet);
                Capsule::datagram(with_context).encode(&mut out);
            }
        }
        {
            let mut q = self.shared.outbound_address_requests.lock().unwrap();
            while let Some(entries) = q.pop_front() {
                let value = ip_capsule::encode_address_entries(&entries);
                Capsule { ty: ip_capsule::CAPSULE_ADDRESS_REQUEST, value }.encode(&mut out);
            }
        }
        out
    }

    fn closed(&mut self) {
        self.event.closed();
    }

    fn wants_close(&self) -> bool {
        self.shared.closing.load(Ordering::Acquire)
    }

    fn wants_datagrams(&self) -> bool {
        true
    }

    fn datagram_received(&mut self, data: &[u8]) {
        self.ensure_opened();
        let Some((cid, payload)) = context_id::decode(data) else {
            return;
        };
        // RFC 9484 §5: ignore a datagram for a Context ID we don't use,
        // rather than treating it as an error.
        if cid == context_id::REGISTERED_CONTEXT_ID {
            self.event.packet_received(payload);
        }
    }

    fn capsule_received(&mut self, ty: u64, value: &[u8]) {
        self.ensure_opened();
        if ty == ip_capsule::CAPSULE_ADDRESS_ASSIGN {
            if let Some(entries) = ip_capsule::decode_address_entries(value) {
                for e in entries {
                    self.event.address_assigned(e.request_id, e.address, e.prefix_length);
                }
            }
        } else if ty == ip_capsule::CAPSULE_ROUTE_ADVERTISEMENT {
            if let Some(entries) = ip_capsule::decode_route_entries(value) {
                for e in entries {
                    self.event.route_advertised(e.start, e.end, e.ip_protocol);
                }
            }
        }
        // Every other type (including ADDRESS_REQUEST, which only ever
        // flows client-to-server on this side) is ignored, per this
        // trait's own default behaviour.
    }
}

/// [`ClientHandler`] that builds the CONNECT-IP request and, once the
/// proxy accepts, installs [`ConnectIpClientUpgrade`].
struct ConnectIpClientHandler {
    target: IpTarget,
    ipproto: IpProto,
    event: Option<Box<dyn ConnectIpEventHandler>>,
}

impl ClientHandler for ConnectIpClientHandler {
    fn start(&mut self, request: &mut dyn ClientWriter) {
        let path = ip_target::encode(&self.target, &self.ipproto);
        let mut h = Headers::new();
        // Same transport-shape split as CONNECT-UDP's client — see
        // `ConnectUdpClientHandler::start`'s doc comment for why this is
        // the one place a CONNECT-IP client needs to know its transport.
        match request.version() {
            HttpVersion::Http10 | HttpVersion::Http11 => {
                h.set(":method", "GET");
                h.set(":path", &path);
                h.set("Upgrade", "connect-ip");
                h.set("Connection", "Upgrade");
            }
            HttpVersion::Http2 | HttpVersion::Http3 => {
                h.set(":method", "CONNECT");
                h.set(":protocol", "connect-ip");
                h.set(":path", &path);
            }
        }
        h.set("Capsule-Protocol", "?1");
        request.headers(h);
        request.complete_request();
    }

    fn switching_protocols(&mut self, request: &mut dyn ClientWriter, headers: &Headers) {
        let h1_shape_ok = !matches!(request.version(), HttpVersion::Http10 | HttpVersion::Http11)
            || headers
                .get("upgrade")
                .is_some_and(|u| u.split(',').map(str::trim).any(|p| p.eq_ignore_ascii_case("connect-ip")));
        if !h1_shape_ok || !capsule_protocol_enabled(headers) {
            if let Some(mut event) = self.event.take() {
                event.error(&io::Error::new(
                    io::ErrorKind::InvalidData,
                    "proxy accepted with an unexpected response shape",
                ));
            }
            return;
        }
        let Some(event) = self.event.take() else {
            return;
        };
        let shared = Arc::new(ClientShared {
            outbound_packets: Mutex::new(VecDeque::new()),
            outbound_address_requests: Mutex::new(VecDeque::new()),
            closing: AtomicBool::new(false),
            conn: request.conn_handle(),
        });
        let handler = ConnectIpClientUpgrade {
            event,
            shared,
            opened: false,
        };
        request.upgrade(Box::new(handler));
    }

    fn response_headers(&mut self, _request: &mut dyn ClientWriter, headers: &Headers) {
        if let Some(mut event) = self.event.take() {
            event.error(&io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("CONNECT-IP request rejected: {}", headers.status_code()),
            ));
        }
    }

    fn response_complete(&mut self, _request: &mut dyn ClientWriter) {}

    fn request_failed(&mut self, _request: &mut dyn ClientWriter, err: &io::Error) {
        if let Some(mut event) = self.event.take() {
            event.error(err);
        }
    }
}

struct ConnectIpClientFactory {
    target: IpTarget,
    ipproto: IpProto,
    event: Arc<Mutex<Option<Box<dyn ConnectIpEventHandler>>>>,
}

impl ClientHandlerFactory for ConnectIpClientFactory {
    fn create_handler(&self) -> Box<dyn ClientHandler> {
        // Same reasoning as `ConnectUdpClientFactory::create_handler`:
        // `connect_auto` may construct a handler per dial attempt; only
        // the attempt that actually succeeds should get the app's real
        // event handler.
        let event = self.event.lock().unwrap().take();
        Box::new(ConnectIpClientHandler {
            target: self.target.clone(),
            ipproto: self.ipproto,
            event,
        })
    }
}

/// Establish a CONNECT-IP tunnel to the proxy at `proxy_host:proxy_port`,
/// scoped to `target`/`ipproto` (either may be a wildcard — see
/// [`IpTarget`]/[`IpProto`]).
///
/// Transport is negotiated exactly the way [`crate::connect_udp`]'s is —
/// see that function's own doc comment, which applies unchanged.
#[allow(clippy::too_many_arguments)]
pub fn connect_ip(
    rt: &Arc<Runtime>,
    proxy_host: &str,
    proxy_port: u16,
    target: IpTarget,
    ipproto: IpProto,
    fallback: HttpFallback,
    event_handler: Box<dyn ConnectIpEventHandler>,
    quic_client_config: Option<Arc<hopf_quic::QuicClientConfig>>,
    alt_svc_cache: Arc<hopf_http::AltSvcCache>,
    timeouts: HttpClientTimeouts,
    resolver: Option<Arc<DnsResolver>>,
) -> io::Result<()> {
    let factory: Arc<dyn ClientHandlerFactory> = Arc::new(ConnectIpClientFactory {
        target,
        ipproto,
        event: Arc::new(Mutex::new(Some(event_handler))),
    });
    connect_auto(
        rt,
        proxy_host,
        proxy_port,
        factory,
        HttpLimits::default(),
        fallback,
        timeouts,
        resolver,
        quic_client_config,
        alt_svc_cache,
    )
}
