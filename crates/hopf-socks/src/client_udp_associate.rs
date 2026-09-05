// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SOCKS5 UDP ASSOCIATE client (no SOCKS4 equivalent, RFC 1928 §7): unlike
//! [`crate::client`]'s CONNECT and [`crate::client_bind`]'s BIND, the data
//! plane here is never the TCP control connection itself — it's a
//! separate UDP socket the client opens once the association is
//! confirmed, exchanging RFC 1928 §7-framed datagrams with the proxy's
//! relay address (reusing the exact codec in [`crate::udp_header`] the
//! server side already uses). The TCP connection carries no further
//! protocol traffic of its own once established; its only remaining job
//! is to anchor the association's lifetime (RFC 1928 §7 ties the two
//! together — closing one ends the other).
//!
//! This goes beyond this crate's own reference scope, which only ever
//! implemented a CONNECT client — the server side here already supports
//! UDP ASSOCIATE, so a CONNECT-only client would be asymmetric with what
//! this crate's own server can do.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use hopf_core::{ConnHandle, Endpoint, ProtocolHandler, ReactorHandle, Runtime, SecurityInfo, TcpConnectorConfig, UdpDatagramHandler};
use mio::Token;

use crate::client::{SocksClientConfig, SocksClientVersion};
use crate::udp_header;
use crate::wire::{self, ParseResult, SocksAddress, SocksCommand};

/// Caller-supplied handler for datagrams received through an established
/// UDP ASSOCIATE session.
pub trait SocksUdpDatagramHandler: Send {
    /// A datagram from `target` arrived, already unwrapped from its RFC
    /// 1928 §7 header. `target` is whatever the proxy's relay reported as
    /// the datagram's source — an IPv4 or IPv6 address (a domain name
    /// never appears in a reply header, since replies always carry a
    /// resolved socket address).
    fn on_datagram(&mut self, target: SocketAddr, data: &[u8]);
}

/// Handle for sending datagrams through an established UDP ASSOCIATE
/// session, delivered to the caller via the `on_ready` callback passed to
/// [`SocksUdpAssociateHandler::new`] / [`socks_udp_associate_config`].
/// Cheap to clone; safe to hold onto and use from any thread for as long
/// as the association stays open.
#[derive(Clone)]
pub struct SocksUdpSender {
    reactor: ReactorHandle,
    token: Token,
    relay_addr: SocketAddr,
}

impl SocksUdpSender {
    /// Wrap `payload` for `target` and send it to the proxy's relay.
    pub fn send_to(&self, target: SocketAddr, payload: &[u8]) {
        let encoded = udp_header::encode(target, payload);
        self.reactor.udp_send(self.token, self.relay_addr, encoded);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum UdpClientState {
    AwaitingMethodSelection,
    AwaitingAuthReply,
    AwaitingAssociateReply,
    AwaitingUdpSocket,
    Established,
}

enum UdpSetupOutcome {
    Ready(ReactorHandle, Token),
    Failed,
}

/// State shared between the TCP control connection and the UDP socket
/// setup thread (registering a UDP socket on a worker reactor blocks
/// briefly waiting for its assigned token, which would deadlock if
/// attempted from that worker's own thread — the actual registration
/// always happens on a dedicated, non-reactor thread, exactly as the
/// server side's own UDP ASSOCIATE setup does).
struct UdpSetupShared {
    outcome: Mutex<Option<UdpSetupOutcome>>,
    client: ConnHandle,
    /// Set if the control connection disconnects before setup finishes —
    /// closes the race between that and the setup thread finishing; see
    /// the server-side `UdpAssociateShared::abandoned` for the identical
    /// concern and why both sides need to check.
    abandoned: AtomicBool,
}

impl UdpSetupShared {
    fn new(client: ConnHandle) -> Arc<Self> {
        Arc::new(Self {
            outcome: Mutex::new(None),
            client,
            abandoned: AtomicBool::new(false),
        })
    }

    fn set_outcome(&self, outcome: UdpSetupOutcome) {
        *self.outcome.lock().unwrap() = Some(outcome);
        self.client.poke();
    }

    fn take_outcome(&self) -> Option<UdpSetupOutcome> {
        self.outcome.lock().unwrap().take()
    }
}

/// [`ProtocolHandler`] for a UDP ASSOCIATE session's TCP control
/// connection. Build via [`socks_udp_associate_config`] for the common
/// case of dialing a proxy with [`hopf_core::Runtime::connect`].
pub struct SocksUdpAssociateHandler {
    config: SocksClientConfig,
    runtime: Arc<Runtime>,
    on_ready: Arc<dyn Fn(SocksUdpSender) + Send + Sync>,
    datagram_handler: Option<Box<dyn SocksUdpDatagramHandler>>,
    state: UdpClientState,
    handshake_done: Arc<AtomicBool>,
    /// The relay's address, known once the ASSOCIATE reply succeeds.
    relay_addr: Option<SocketAddr>,
    /// Set while [`UdpClientState::AwaitingUdpSocket`], so a poke-driven
    /// re-entry into `receive()` can find it again to poll.
    pending_udp_setup: Option<Arc<UdpSetupShared>>,
    /// Set once the UDP socket is registered, so `disconnected()` can
    /// deregister it — the association's lifetime is tied to this TCP
    /// connection (RFC 1928 §7).
    udp_socket: Option<(ReactorHandle, Token)>,
}

impl SocksUdpAssociateHandler {
    /// `on_ready` is called exactly once, with a [`SocksUdpSender`], once
    /// the association is fully established (both the SOCKS reply and the
    /// client's own UDP socket are ready). `datagram_handler` receives
    /// every datagram the proxy relays back, for the life of the
    /// association. `config`'s version must be
    /// [`SocksClientVersion::Socks5`] — UDP ASSOCIATE has no SOCKS4
    /// equivalent.
    pub fn new(
        config: SocksClientConfig,
        runtime: Arc<Runtime>,
        on_ready: Arc<dyn Fn(SocksUdpSender) + Send + Sync>,
        datagram_handler: Box<dyn SocksUdpDatagramHandler>,
    ) -> Self {
        Self {
            config,
            runtime,
            on_ready,
            datagram_handler: Some(datagram_handler),
            state: UdpClientState::AwaitingMethodSelection,
            handshake_done: Arc::new(AtomicBool::new(false)),
            relay_addr: None,
            pending_udp_setup: None,
            udp_socket: None,
        }
    }

    /// There is no `inner: ProtocolHandler` to notify of a failure here
    /// (unlike CONNECT/BIND) — a failed association simply never calls
    /// `on_ready`. The caller learns about it by that absence (typically
    /// paired with a timeout of their own) rather than an explicit error
    /// callback, since there's no established-then-forwarding target to
    /// deliver one to.
    fn fail(&mut self, endpoint: &mut dyn Endpoint) {
        endpoint.close();
    }

    fn send_associate_request(&mut self, endpoint: &mut dyn Endpoint) {
        // The client doesn't know its own outbound UDP socket's address
        // yet (it isn't opened until the reply confirms success) — RFC
        // 1928 §7 doesn't mandate a real value here, and most real-world
        // clients just send the wildcard, so this crate does too rather
        // than adding the complexity of opening the UDP socket before the
        // TCP handshake even completes.
        let wildcard = SocksAddress::Ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        match wire::encode_socks5_request(SocksCommand::UdpAssociate, &wildcard, 0) {
            Some(req) => {
                endpoint.send(&req);
                self.state = UdpClientState::AwaitingAssociateReply;
            }
            None => self.fail(endpoint),
        }
    }

    fn begin_udp_socket_setup(&mut self, endpoint: &mut dyn Endpoint) {
        let relay_addr = self.relay_addr.expect("relay_addr set before UDP socket setup begins");
        let shared = UdpSetupShared::new(endpoint.handle());
        let shared2 = Arc::clone(&shared);
        let runtime = Arc::clone(&self.runtime);
        let Some(datagram_handler) = self.datagram_handler.take() else {
            self.fail(endpoint);
            return;
        };
        let spawned = std::thread::Builder::new().name("socks-client-udp-setup".into()).spawn(move || {
            match open_client_udp_socket(&runtime, relay_addr, datagram_handler) {
                Ok((reactor, token)) => {
                    if shared2.abandoned.load(Ordering::Acquire) {
                        reactor.deregister_udp(token);
                    } else {
                        shared2.set_outcome(UdpSetupOutcome::Ready(reactor, token));
                    }
                }
                Err(_) => shared2.set_outcome(UdpSetupOutcome::Failed),
            }
        });
        if spawned.is_err() {
            self.fail(endpoint);
            return;
        }
        self.state = UdpClientState::AwaitingUdpSocket;
        self.pending_udp_setup = Some(shared);
    }

    fn poll_udp_socket_outcome(&mut self, endpoint: &mut dyn Endpoint) {
        let Some(shared) = &self.pending_udp_setup else {
            return;
        };
        let Some(outcome) = shared.take_outcome() else {
            return;
        };
        self.pending_udp_setup = None;
        match outcome {
            UdpSetupOutcome::Ready(reactor, token) => {
                self.udp_socket = Some((reactor.clone(), token));
                self.handshake_done.store(true, Ordering::Release);
                self.state = UdpClientState::Established;
                let sender = SocksUdpSender {
                    reactor,
                    token,
                    relay_addr: self.relay_addr.expect("relay_addr set before UDP socket setup begins"),
                };
                (self.on_ready)(sender);
            }
            UdpSetupOutcome::Failed => self.fail(endpoint),
        }
    }
}

impl ProtocolHandler for SocksUdpAssociateHandler {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        if self.config.version() == SocksClientVersion::Socks4 {
            // UDP ASSOCIATE has no SOCKS4 equivalent (RFC 1928 §7 is
            // SOCKS5-only) — fail immediately rather than sending
            // something a SOCKS4 proxy could never make sense of.
            self.fail(endpoint);
            return;
        }

        let flag = Arc::clone(&self.handshake_done);
        let conn = endpoint.handle();
        endpoint.schedule_timer(
            self.config.handshake_timeout(),
            Box::new(move || {
                if !flag.load(Ordering::Acquire) {
                    conn.close();
                }
            }),
        );

        let methods: &[u8] = if self.config.credentials().is_some() { &[0x00, 0x02] } else { &[0x00] };
        endpoint.send(&wire::encode_socks5_greeting(methods));
        self.state = UdpClientState::AwaitingMethodSelection;
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        if self.state == UdpClientState::AwaitingUdpSocket {
            self.poll_udp_socket_outcome(endpoint);
        }

        loop {
            match self.state {
                UdpClientState::AwaitingMethodSelection => match wire::parse_method_selection(data) {
                    ParseResult::Incomplete => return,
                    ParseResult::Invalid => {
                        self.fail(endpoint);
                        return;
                    }
                    ParseResult::Complete(method, n) => {
                        *data = &data[n..];
                        match method {
                            0x00 => self.send_associate_request(endpoint),
                            0x02 if self.config.credentials().is_some() => {
                                let (username, password) = self.config.credentials().cloned().unwrap();
                                match wire::encode_user_password_request(&username, &password) {
                                    Some(req) => {
                                        endpoint.send(&req);
                                        self.state = UdpClientState::AwaitingAuthReply;
                                    }
                                    None => {
                                        self.fail(endpoint);
                                        return;
                                    }
                                }
                            }
                            _ => {
                                self.fail(endpoint);
                                return;
                            }
                        }
                    }
                },
                UdpClientState::AwaitingAuthReply => match wire::parse_user_password_reply(data) {
                    ParseResult::Incomplete => return,
                    ParseResult::Invalid => {
                        self.fail(endpoint);
                        return;
                    }
                    ParseResult::Complete(ok, n) => {
                        *data = &data[n..];
                        if ok {
                            self.send_associate_request(endpoint);
                        } else {
                            self.fail(endpoint);
                            return;
                        }
                    }
                },
                UdpClientState::AwaitingAssociateReply => match wire::parse_socks5_reply(data) {
                    ParseResult::Incomplete => return,
                    ParseResult::Invalid => {
                        self.fail(endpoint);
                        return;
                    }
                    ParseResult::Complete(reply, n) => {
                        *data = &data[n..];
                        if reply.reply != 0x00 {
                            self.fail(endpoint);
                            return;
                        }
                        let SocksAddress::Ip(ip) = reply.address else {
                            self.fail(endpoint);
                            return;
                        };
                        self.relay_addr = Some(SocketAddr::new(ip, reply.port));
                        self.begin_udp_socket_setup(endpoint);
                        return;
                    }
                },
                UdpClientState::AwaitingUdpSocket | UdpClientState::Established => return,
            }
        }
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
        if let Some((reactor, token)) = self.udp_socket.take() {
            reactor.deregister_udp(token);
        } else if let Some(shared) = &self.pending_udp_setup {
            // The UDP socket setup thread is still running — mark it
            // abandoned so it deregisters the socket itself once it
            // finishes, instead of leaking it (see `UdpSetupShared`'s own
            // doc comment for the race this closes).
            shared.abandoned.store(true, Ordering::Release);
        }
    }

    fn security_established(&mut self, _endpoint: &mut dyn Endpoint, _info: &SecurityInfo) {}

    fn error(&mut self, endpoint: &mut dyn Endpoint, _err: &io::Error) {
        endpoint.close();
    }
}

/// Bind and register the client's own UDP socket. Called only from a
/// plain (non-reactor) thread — see [`SocksUdpAssociateHandler::begin_udp_socket_setup`].
fn open_client_udp_socket(
    runtime: &Runtime,
    relay_addr: SocketAddr,
    datagram_handler: Box<dyn SocksUdpDatagramHandler>,
) -> io::Result<(ReactorHandle, Token)> {
    let bind_ip = match relay_addr.ip() {
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    };
    let std_sock = std::net::UdpSocket::bind(SocketAddr::new(bind_ip, 0))?;
    std_sock.set_nonblocking(true)?;
    let mio_sock = mio::net::UdpSocket::from_std(std_sock);
    let worker = runtime.pick_worker().clone();
    let handler: Box<dyn UdpDatagramHandler> = Box::new(ClientUdpRelayHandler {
        relay_addr,
        inner: datagram_handler,
    });
    let token = worker.register_udp(mio_sock, handler)?;
    Ok((worker, token))
}

/// Datagram handler for the client's own UDP socket: unwraps the RFC 1928
/// §7 header and forwards the payload to the caller-supplied
/// [`SocksUdpDatagramHandler`].
struct ClientUdpRelayHandler {
    relay_addr: SocketAddr,
    inner: Box<dyn SocksUdpDatagramHandler>,
}

impl UdpDatagramHandler for ClientUdpRelayHandler {
    fn on_datagram(&mut self, peer: SocketAddr, data: &[u8]) {
        // Only the relay itself is ever expected to send to this socket.
        if peer != self.relay_addr {
            return;
        }
        let Some(header) = udp_header::parse(data) else {
            return;
        };
        if header.frag != udp_header::FRAG_STANDALONE {
            return;
        }
        let SocksAddress::Ip(ip) = header.address else {
            // A reply header never names a domain (see the header's own
            // doc comment) — an implementation sending one anyway is
            // malformed, and there is nowhere meaningful to report that.
            return;
        };
        self.inner.on_datagram(SocketAddr::new(ip, header.port), header.payload);
    }
}

/// Build a [`TcpConnectorConfig`] that dials `proxy_addr` and performs the
/// SOCKS5 UDP ASSOCIATE handshake per `config` — see
/// [`SocksUdpAssociateHandler`] for the full behavior. The common-case
/// entry point — pass the result to [`hopf_core::Runtime::connect`].
pub fn socks_udp_associate_config(
    proxy_addr: SocketAddr,
    config: SocksClientConfig,
    runtime: Arc<Runtime>,
    on_ready: Arc<dyn Fn(SocksUdpSender) + Send + Sync>,
    datagram_handler_factory: impl Fn() -> Box<dyn SocksUdpDatagramHandler> + Send + Sync + 'static,
) -> TcpConnectorConfig {
    TcpConnectorConfig::new(proxy_addr, move || {
        Box::new(SocksUdpAssociateHandler::new(
            config.clone(),
            Arc::clone(&runtime),
            Arc::clone(&on_ready),
            datagram_handler_factory(),
        )) as Box<dyn ProtocolHandler>
    })
}
