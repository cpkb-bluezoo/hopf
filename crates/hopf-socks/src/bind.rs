// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! BIND command: an ephemeral, loopback-only, single-use listener; the
//! two-reply RFC 1928 §4 sequence; and handing off to the shared relay
//! ([`crate::relay`]) once a peer connects.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_core::{BindingId, ConnHandle, Endpoint, ProtocolHandler, Runtime, TcpListenerConfig};

use crate::metrics::SocksServerMetrics;
use crate::policy::SocksPolicy;
use crate::relay::RelayActivity;
use crate::wire::Socks5Reply;

/// How long a BIND request may wait for a peer to connect before it's
/// failed. RFC 1928 sets no lifetime bound itself.
pub const DEFAULT_BIND_ACCEPT_TIMEOUT: Duration = Duration::from_secs(2 * 60);

/// Outcome of waiting for a peer to connect to a BIND listener.
pub(crate) enum BindOutcome {
    /// A peer connected, passed the peer-address and destination-policy
    /// checks, and the listener has already been torn down (single-use).
    Accepted(ConnHandle, SocketAddr),
    /// The peer was rejected, the accept wait timed out, or the listener
    /// itself failed to open.
    Failed(Socks5Reply),
}

/// State shared between the client-facing connection and the ephemeral
/// listener's eventual accepted peer (which may land on a different
/// worker reactor) for one BIND request's lifetime — and, once accepted,
/// the relay's own activity tracking (see [`crate::relay`]).
pub(crate) struct BindShared {
    outcome: Mutex<Option<BindOutcome>>,
    client: ConnHandle,
    pub(crate) activity: Arc<RelayActivity>,
    /// Guards the `active_bind_waits` counter decrement — both the
    /// outcome being processed and the client disconnecting first (before
    /// any outcome arrives) can observe the end of the wait, but it must
    /// be counted exactly once. Mirrors [`RelayActivity::release_once`].
    wait_released: AtomicBool,
}

impl BindShared {
    fn new(client: ConnHandle) -> Arc<Self> {
        Arc::new(Self {
            outcome: Mutex::new(None),
            client,
            activity: RelayActivity::new(),
            wait_released: AtomicBool::new(false),
        })
    }

    /// First writer wins: whichever of {a peer connects, the accept-wait
    /// timeout fires} happens first sets the outcome: the other is a
    /// harmless no-op rather than overwriting an already-delivered result.
    fn set_outcome(&self, outcome: BindOutcome) {
        let mut guard = self.outcome.lock().unwrap();
        if guard.is_none() {
            *guard = Some(outcome);
            drop(guard);
            self.client.poke();
        }
    }

    fn fail(&self, reply: Socks5Reply) {
        self.set_outcome(BindOutcome::Failed(reply));
    }

    /// Take the outcome, if one has arrived — called from the client
    /// handler's `receive()` (including poke-triggered re-entry) while
    /// awaiting a peer.
    pub(crate) fn take_outcome(&self) -> Option<BindOutcome> {
        self.outcome.lock().unwrap().take()
    }

    /// Decrement `active_bind_waits` exactly once, whether that's because
    /// an outcome was just processed or because the client disconnected
    /// while still waiting for one.
    pub(crate) fn stop_waiting(&self, metrics: &SocksServerMetrics) {
        if !self.wait_released.swap(true, Ordering::AcqRel) {
            metrics.active_bind_waits.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Open an ephemeral, loopback-only listener for a BIND request and begin
/// waiting for one peer to connect. Returns the bound address (for the
/// caller's Reply 1) and the [`BindShared`] the eventual second-reply
/// outcome arrives on — same asynchronous-outcome shape as
/// [`crate::connect::begin_connect`].
///
/// `expected_peer`: the BIND request's own `DST.ADDR`, when it named a
/// specific (non-wildcard) address — the connecting peer must then match
/// it exactly (RFC 1928 §4 gives no ATYP for "any address", so a wildcard
/// request is ATYP-specific; callers pass `None` for that case). Also
/// picks which loopback family to bind: IPv6 if the expected peer is
/// IPv6, IPv4 otherwise (including "no expectation given").
pub(crate) fn begin_bind(
    runtime: &Arc<Runtime>,
    policy: Arc<dyn SocksPolicy>,
    metrics: Arc<SocksServerMetrics>,
    client: ConnHandle,
    expected_peer: Option<IpAddr>,
    accept_timeout: Duration,
) -> io::Result<(SocketAddr, Arc<BindShared>)> {
    let shared = BindShared::new(client.clone());

    let bind_ip = match expected_peer {
        Some(IpAddr::V6(_)) => IpAddr::V6(Ipv6Addr::LOCALHOST),
        _ => IpAddr::V4(Ipv4Addr::LOCALHOST),
    };

    // The listener must deregister itself after exactly one accept
    // (single-use, RFC 1928 §4) — but the binding id it needs for that is
    // only known *after* `add_tcp_listener` returns, which is after the
    // factory closure below is already constructed. A shared cell bridges
    // the two: whichever of {the first accept, the accept-wait timeout}
    // runs first claims and removes the binding; the other finds it
    // already gone and does nothing further.
    let binding_cell: Arc<Mutex<Option<BindingId>>> = Arc::new(Mutex::new(None));

    let binding_cell2 = Arc::clone(&binding_cell);
    let runtime2 = Arc::clone(runtime);
    let shared2 = Arc::clone(&shared);
    let policy2 = Arc::clone(&policy);
    let metrics2 = Arc::clone(&metrics);
    let cfg = TcpListenerConfig::new(SocketAddr::new(bind_ip, 0), move || {
        if let Some(id) = binding_cell2.lock().unwrap().take() {
            runtime2.remove_binding(id);
        }
        Box::new(BindAcceptHandler {
            shared: Arc::clone(&shared2),
            expected_peer,
            policy: Arc::clone(&policy2),
            metrics: Arc::clone(&metrics2),
        }) as Box<dyn ProtocolHandler>
    });
    let (addr, id) = runtime.add_tcp_listener(cfg)?;
    *binding_cell.lock().unwrap() = Some(id);

    let shared3 = Arc::clone(&shared);
    let runtime3 = Arc::clone(runtime);
    let binding_cell3 = Arc::clone(&binding_cell);
    let _ = client.schedule_timer(
        accept_timeout,
        Box::new(move || {
            if let Some(id) = binding_cell3.lock().unwrap().take() {
                runtime3.remove_binding(id);
            }
            // RFC 1928 §6 has no single obviously-correct code for "no
            // peer connected in time" — TTL expired is the closest
            // available semantic for an operation that ran out of time
            // without completing, so it's used here rather than the
            // generic server-failure code.
            shared3.fail(Socks5Reply::TtlExpired);
        }),
    );

    Ok((addr, shared))
}

/// Protocol handler for the one connection the BIND listener ever accepts.
struct BindAcceptHandler {
    shared: Arc<BindShared>,
    expected_peer: Option<IpAddr>,
    policy: Arc<dyn SocksPolicy>,
    metrics: Arc<SocksServerMetrics>,
}

impl ProtocolHandler for BindAcceptHandler {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        let Some(peer) = endpoint.remote_addr().ok().and_then(|a| a.as_socket_addr()) else {
            self.shared.fail(Socks5Reply::GeneralFailure);
            endpoint.close();
            return;
        };
        if let Some(expected) = self.expected_peer {
            if peer.ip() != expected {
                self.shared.fail(Socks5Reply::NotAllowed);
                endpoint.close();
                return;
            }
        }
        if !self.policy.is_target_allowed(peer.ip(), peer.port()) {
            self.shared.fail(Socks5Reply::NotAllowed);
            endpoint.close();
            return;
        }
        self.shared.set_outcome(BindOutcome::Accepted(endpoint.handle(), peer));
    }

    fn receive(&mut self, _endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        crate::relay::forward(&self.shared.activity, &self.shared.client, &self.metrics.bytes_downstream, data);
        *data = &[];
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
        self.shared.activity.release_once(&self.metrics);
        self.shared.client.close();
    }

    fn error(&mut self, endpoint: &mut dyn Endpoint, _err: &io::Error) {
        self.shared.fail(Socks5Reply::GeneralFailure);
        endpoint.close();
    }
}
