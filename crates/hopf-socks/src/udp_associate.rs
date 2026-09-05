// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! UDP ASSOCIATE (SOCKS5 only, RFC 1928 §7): two ephemeral UDP sockets —
//! one client-facing, one upstream-facing — relaying datagrams for the
//! life of the request's TCP control connection.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_core::{ConnHandle, ReactorHandle, Runtime, UdpDatagramHandler};
use hopf_dns::DnsResolver;
use mio::Token;

use crate::metrics::SocksServerMetrics;
use crate::policy::SocksPolicy;
use crate::udp_header;
use crate::wire::{Socks5Reply, SocksAddress};

/// How long a UDP association may sit with no datagrams in either
/// direction before it's torn down (along with the TCP control
/// connection it's tied to). RFC 1928 sets no lifetime bound itself.
pub const DEFAULT_UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Outcome of opening the association's pair of UDP sockets.
pub(crate) enum UdpAssociateOutcome {
    /// Both sockets are open — the client-facing one's bound address
    /// (the SOCKS reply's `BND.ADDR:BND.PORT`) is available via
    /// [`UdpAssociateShared::bound_addr`].
    Ready,
    Failed(Socks5Reply),
}

/// State shared between the client-facing TCP connection and both UDP
/// sockets' datagram handlers (which run on a worker reactor thread that
/// may differ from the TCP connection's own) for one association's
/// lifetime.
pub(crate) struct UdpAssociateShared {
    outcome: Mutex<Option<UdpAssociateOutcome>>,
    client: ConnHandle,
    bound_addr: Mutex<Option<SocketAddr>>,
    reactor: Mutex<Option<ReactorHandle>>,
    client_token: Mutex<Option<Token>>,
    upstream_token: Mutex<Option<Token>>,
    /// The client's most recently seen source address — where an
    /// upstream reply gets sent back to. `None` until the first valid
    /// client datagram arrives; a reply with nowhere to go yet is dropped.
    last_client_addr: Mutex<Option<SocketAddr>>,
    /// Only a datagram whose source IP matches this is accepted from the
    /// client-facing socket (RFC 1928 §7's client-address expectation is
    /// spec'd as a courtesy, not a hard authentication mechanism — this
    /// is a plausibility check, not a security boundary against a
    /// spoofed source on a hostile network).
    expected_client_ip: IpAddr,
    dns: Arc<DnsResolver>,
    policy: Arc<dyn SocksPolicy>,
    metrics: Arc<SocksServerMetrics>,
    activity: AtomicBool,
    /// Guards the `active_udp_associations` counter decrement — both the
    /// idle timeout and the control connection's `disconnected()` may
    /// observe the end of the same association, but it must be counted
    /// exactly once.
    released: AtomicBool,
    /// Set by [`Self::abandon`] when the client disconnects while the
    /// sockets are still being opened on the setup thread — closes the
    /// race between that disconnect and [`open_pair`] finishing, since
    /// whichever of the two runs first would otherwise find nothing to
    /// tear down (the sockets not registered yet, or the abandonment not
    /// yet recorded) and leave the other's work permanently leaked.
    abandoned: AtomicBool,
}

impl UdpAssociateShared {
    fn set_outcome(&self, outcome: UdpAssociateOutcome) {
        *self.outcome.lock().unwrap() = Some(outcome);
        self.client.poke();
    }

    fn mark_activity(&self) {
        self.activity.store(true, Ordering::Release);
    }

    fn fail(&self, reply: Socks5Reply) {
        self.set_outcome(UdpAssociateOutcome::Failed(reply));
    }

    /// Take the outcome, if one has arrived — called from the client
    /// handler's `receive()` (including poke-triggered re-entry) while
    /// awaiting the sockets to open.
    pub(crate) fn take_outcome(&self) -> Option<UdpAssociateOutcome> {
        self.outcome.lock().unwrap().take()
    }

    /// The client-facing socket's bound address, once known — this is
    /// the SOCKS reply's `BND.ADDR:BND.PORT`.
    pub(crate) fn bound_addr(&self) -> SocketAddr {
        self.bound_addr
            .lock()
            .unwrap()
            .unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
    }

    /// Deregister both UDP sockets. Idempotent — safe to call from both
    /// the control connection's `disconnected()` and the idle timeout.
    pub(crate) fn teardown(&self) {
        let reactor = self.reactor.lock().unwrap().clone();
        let Some(reactor) = reactor else { return };
        if let Some(t) = self.client_token.lock().unwrap().take() {
            reactor.deregister_udp(t);
        }
        if let Some(t) = self.upstream_token.lock().unwrap().take() {
            reactor.deregister_udp(t);
        }
    }

    /// Decrement `active_udp_associations` exactly once, however many of
    /// {idle timeout, client disconnect} end up observing this
    /// association's end.
    pub(crate) fn release_once(&self) {
        if !self.released.swap(true, Ordering::AcqRel) {
            self.metrics.active_udp_associations.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Record that the client disconnected before the sockets finished
    /// opening, and tear down anything already registered — see
    /// [`Self::abandoned`]'s doc comment for the race this closes.
    pub(crate) fn abandon(&self) {
        self.abandoned.store(true, Ordering::Release);
        self.teardown();
    }
}

/// Begin opening a UDP association's pair of sockets. The outcome arrives
/// asynchronously via the returned [`UdpAssociateShared`] — same shape as
/// [`crate::connect::begin_connect`] and [`crate::bind::begin_bind`] —
/// because registering a UDP socket on a worker reactor blocks briefly
/// waiting for its assigned token, which would deadlock if attempted from
/// that same worker's own thread; the actual registration therefore
/// always happens on a dedicated, non-reactor thread.
pub(crate) fn begin_udp_associate(
    runtime: &Arc<Runtime>,
    dns: Arc<DnsResolver>,
    policy: Arc<dyn SocksPolicy>,
    metrics: Arc<SocksServerMetrics>,
    client: ConnHandle,
    expected_client_ip: IpAddr,
    local_ip: IpAddr,
) -> Arc<UdpAssociateShared> {
    let shared = Arc::new(UdpAssociateShared {
        outcome: Mutex::new(None),
        client,
        bound_addr: Mutex::new(None),
        reactor: Mutex::new(None),
        client_token: Mutex::new(None),
        upstream_token: Mutex::new(None),
        last_client_addr: Mutex::new(None),
        expected_client_ip,
        dns,
        policy,
        metrics,
        activity: AtomicBool::new(false),
        released: AtomicBool::new(false),
        abandoned: AtomicBool::new(false),
    });

    let shared2 = Arc::clone(&shared);
    let runtime2 = Arc::clone(runtime);
    // The upstream-facing socket's own address is never exposed to
    // anyone, so it just needs *an* outbound-capable interface of the
    // right family — unspecified is fine there. The client-facing
    // socket's address, by contrast, becomes the reply's `BND.ADDR` (the
    // address the client is told to send its datagrams to), so it must
    // bind the same concrete local interface the client already reached
    // this proxy on — binding it unspecified would report `0.0.0.0`
    // (or `::`), an address nothing can actually send a UDP datagram to.
    let upstream_bind_ip = match local_ip {
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    };
    let spawned = std::thread::Builder::new()
        .name("socks-udp-associate-setup".into())
        .spawn(move || match open_pair(&runtime2, local_ip, upstream_bind_ip, &shared2) {
            Ok(()) => {
                // `open_pair` itself already re-checks `abandoned` right
                // after registering (see its own doc comment) — this
                // check is the cheaper, purely-advisory early exit for
                // the common case where the client is already known gone
                // by the time setup finishes.
                if shared2.client.is_probably_open() {
                    shared2.set_outcome(UdpAssociateOutcome::Ready);
                }
            }
            Err(_) => shared2.fail(Socks5Reply::GeneralFailure),
        });
    if spawned.is_err() {
        shared.fail(Socks5Reply::GeneralFailure);
    }
    shared
}

/// Bind and register both UDP sockets on one worker reactor. Called only
/// from a plain (non-reactor) thread — see [`begin_udp_associate`]. Checks
/// [`UdpAssociateShared::abandoned`] once both sockets are registered and
/// tears them down immediately if the client disconnected while this was
/// in flight — see that field's doc comment for why both sides need to
/// check.
fn open_pair(
    runtime: &Runtime,
    client_bind_ip: IpAddr,
    upstream_bind_ip: IpAddr,
    shared: &Arc<UdpAssociateShared>,
) -> std::io::Result<()> {
    let worker = runtime.pick_worker().clone();

    let client_socket = bind_ephemeral_udp(client_bind_ip)?;
    let client_bound = client_socket.local_addr()?;
    let client_handler: Box<dyn UdpDatagramHandler> = Box::new(ClientFacingHandler {
        shared: Arc::clone(shared),
    });
    let client_token = worker.register_udp(client_socket, client_handler)?;

    let upstream_socket = bind_ephemeral_udp(upstream_bind_ip)?;
    let upstream_handler: Box<dyn UdpDatagramHandler> = Box::new(UpstreamHandler {
        shared: Arc::clone(shared),
    });
    let upstream_token = match worker.register_udp(upstream_socket, upstream_handler) {
        Ok(t) => t,
        Err(e) => {
            worker.deregister_udp(client_token);
            return Err(e);
        }
    };

    *shared.reactor.lock().unwrap() = Some(worker);
    *shared.client_token.lock().unwrap() = Some(client_token);
    *shared.upstream_token.lock().unwrap() = Some(upstream_token);
    *shared.bound_addr.lock().unwrap() = Some(client_bound);

    if shared.abandoned.load(Ordering::Acquire) {
        // The client disconnected (see `UdpAssociateShared::abandon`)
        // before this function reached the lines just above — its own
        // teardown call ran too early to find anything registered yet.
        // Finish the job now that there's something to tear down.
        shared.teardown();
    }
    Ok(())
}

fn bind_ephemeral_udp(ip: IpAddr) -> std::io::Result<mio::net::UdpSocket> {
    let std_sock = std::net::UdpSocket::bind(SocketAddr::new(ip, 0))?;
    std_sock.set_nonblocking(true)?;
    Ok(mio::net::UdpSocket::from_std(std_sock))
}

/// Datagram handler for the socket the client sends to and receives
/// replies from.
struct ClientFacingHandler {
    shared: Arc<UdpAssociateShared>,
}

impl UdpDatagramHandler for ClientFacingHandler {
    fn on_datagram(&mut self, peer: SocketAddr, data: &[u8]) {
        if peer.ip() != self.shared.expected_client_ip {
            return;
        }
        let Some(header) = udp_header::parse(data) else {
            return;
        };
        // RFC 1928 §7: only a standalone datagram is forwarded; anything
        // else (a fragment) is dropped. No reassembly is implemented.
        if header.frag != udp_header::FRAG_STANDALONE {
            return;
        }
        self.shared.mark_activity();
        *self.shared.last_client_addr.lock().unwrap() = Some(peer);

        let Some(upstream_token) = *self.shared.upstream_token.lock().unwrap() else {
            // The upstream socket hasn't finished registering yet — an
            // exceedingly narrow startup race. Nothing to forward to.
            return;
        };
        let reactor = self.shared.reactor.lock().unwrap().clone();
        let Some(reactor) = reactor else { return };

        match header.address {
            SocksAddress::Ip(ip) => {
                forward_to_target(&self.shared, &reactor, upstream_token, ip, header.port, header.payload.to_vec());
            }
            SocksAddress::Domain(host) => {
                let shared = Arc::clone(&self.shared);
                let reactor2 = reactor.clone();
                let payload = header.payload.to_vec();
                let port = header.port;
                self.shared.dns.resolve(
                    &host,
                    port,
                    Box::new(move |result| {
                        let Ok(addrs) = result else { return };
                        let Some(addr) = addrs.first().copied() else { return };
                        forward_to_target(&shared, &reactor2, upstream_token, addr.ip(), addr.port(), payload);
                    }),
                );
            }
        }
    }
}

/// Check the destination policy and, if allowed, send `payload` out the
/// upstream-facing socket to `(ip, port)`. Shared by the literal-IP and
/// resolved-hostname paths in [`ClientFacingHandler::on_datagram`].
fn forward_to_target(
    shared: &Arc<UdpAssociateShared>,
    reactor: &ReactorHandle,
    upstream_token: Token,
    ip: IpAddr,
    port: u16,
    payload: Vec<u8>,
) {
    if !shared.policy.is_target_allowed(ip, port) {
        SocksServerMetrics::add(&shared.metrics.destinations_blocked, 1);
        return;
    }
    SocksServerMetrics::add(&shared.metrics.bytes_upstream, payload.len() as u64);
    reactor.udp_send(upstream_token, SocketAddr::new(ip, port), payload);
}

/// Datagram handler for the socket used to send to (and receive replies
/// from) arbitrary resolved targets.
struct UpstreamHandler {
    shared: Arc<UdpAssociateShared>,
}

impl UdpDatagramHandler for UpstreamHandler {
    fn on_datagram(&mut self, peer: SocketAddr, data: &[u8]) {
        let Some(client_addr) = *self.shared.last_client_addr.lock().unwrap() else {
            // No client datagram has arrived yet, so there's nowhere to
            // send an unsolicited reply.
            return;
        };
        let Some(client_token) = *self.shared.client_token.lock().unwrap() else {
            return;
        };
        let reactor = self.shared.reactor.lock().unwrap().clone();
        let Some(reactor) = reactor else { return };

        self.shared.mark_activity();
        let encoded = udp_header::encode(peer, data);
        SocksServerMetrics::add(&self.shared.metrics.bytes_downstream, data.len() as u64);
        reactor.udp_send(client_token, client_addr, encoded);
    }
}

/// Arm (or re-arm) the association's self-rearming idle timer: fires
/// after `timeout`, and either finds activity since the last tick (clears
/// the flag and reschedules) or finds none — in which case both UDP
/// sockets are deregistered and the TCP control connection is closed,
/// per RFC 1928 §7 tying the association's lifetime to that connection.
pub(crate) fn arm_idle_timer(shared: Arc<UdpAssociateShared>, client: ConnHandle, timeout: Duration) {
    let shared2 = Arc::clone(&shared);
    let client2 = client.clone();
    let _ = client.schedule_timer(
        timeout,
        Box::new(move || {
            if shared2.activity.swap(false, Ordering::AcqRel) {
                arm_idle_timer(shared2, client2, timeout);
            } else {
                shared2.teardown();
                shared2.release_once();
                client2.close();
            }
        }),
    );
}
