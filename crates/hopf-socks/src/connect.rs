// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! CONNECT command: target resolution, destination authorization, dial,
//! and the bidirectional relay once the upstream connection is up.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_core::{ConnHandle, Endpoint, ProtocolHandler, Runtime, TcpConnectorConfig};
use hopf_dns::DnsResolver;

use crate::metrics::SocksServerMetrics;
use crate::policy::SocksPolicy;
use crate::wire::Socks5Reply;

/// How long a CONNECT relay may sit with no traffic in either direction
/// before it's torn down. RFC 1928 sets no lifetime bound itself.
pub const DEFAULT_RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Outcome of resolving, authorizing, and dialing a CONNECT target.
pub(crate) enum ConnectOutcome {
    /// The upstream connection is up; relay through this handle.
    Connected(ConnHandle),
    /// Resolution, authorization, or the dial itself failed.
    Failed(Socks5Reply),
}

/// State shared between the client-facing connection (driven by its own
/// reactor) and the dialed upstream connection (which may land on a
/// different worker reactor) for one CONNECT request's lifetime.
pub(crate) struct ConnectShared {
    outcome: Mutex<Option<ConnectOutcome>>,
    client: ConnHandle,
    /// Set by traffic in either direction once the relay is established;
    /// cleared and checked by the self-rearming idle timer armed in
    /// [`arm_idle_timer`].
    activity: AtomicBool,
    /// Guards the active-relay counter decrement: both the client and
    /// upstream connections' `disconnected()` may observe the end of the
    /// same relay, but it must be counted exactly once.
    released: AtomicBool,
}

impl ConnectShared {
    fn new(client: ConnHandle) -> Arc<Self> {
        Arc::new(Self {
            outcome: Mutex::new(None),
            client,
            activity: AtomicBool::new(false),
            released: AtomicBool::new(false),
        })
    }

    fn set_outcome(&self, outcome: ConnectOutcome) {
        *self.outcome.lock().unwrap() = Some(outcome);
        self.client.poke();
    }

    fn fail(&self, reply: Socks5Reply) {
        self.set_outcome(ConnectOutcome::Failed(reply));
    }

    /// Take the outcome, if one has arrived — called from the client
    /// handler's `receive()` (including poke-triggered re-entry) while
    /// awaiting the dial.
    pub(crate) fn take_outcome(&self) -> Option<ConnectOutcome> {
        self.outcome.lock().unwrap().take()
    }

    fn mark_activity(&self) {
        self.activity.store(true, Ordering::Release);
    }

    /// Decrement the active-relay counter exactly once, however many of
    /// {client disconnect, upstream disconnect, idle timeout} end up
    /// observing this relay's end.
    fn release_once(&self, metrics: &SocksServerMetrics) {
        if !self.released.swap(true, Ordering::AcqRel) {
            metrics.active_relays.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Begin resolving, authorizing, and dialing `host`/`port` for a CONNECT
/// request from `client`. The outcome (and, later, all relay traffic) is
/// delivered asynchronously via the returned [`ConnectShared`] — the
/// caller must transition into an "awaiting outcome" state and re-check
/// [`ConnectShared::take_outcome`] on every subsequent `receive()`
/// (including poke-triggered re-entries with no new data).
pub(crate) fn begin_connect(
    dns: &DnsResolver,
    policy: Arc<dyn SocksPolicy>,
    runtime: Arc<Runtime>,
    metrics: Arc<SocksServerMetrics>,
    client: ConnHandle,
    host: &str,
    port: u16,
) -> Arc<ConnectShared> {
    let shared = ConnectShared::new(client.clone());
    let shared2 = Arc::clone(&shared);
    dns.resolve(
        host,
        port,
        Box::new(move |result| {
            resolve_and_dial(shared2, policy, runtime, metrics, client, result);
        }),
    );
    shared
}

/// Same as [`begin_connect`], but for a target that's already a literal IP
/// (no DNS round trip needed) — still asynchronous in shape, for a uniform
/// caller-side state machine, but resolves synchronously inline.
pub(crate) fn begin_connect_literal(
    policy: Arc<dyn SocksPolicy>,
    runtime: Arc<Runtime>,
    metrics: Arc<SocksServerMetrics>,
    client: ConnHandle,
    addr: SocketAddr,
) -> Arc<ConnectShared> {
    let shared = ConnectShared::new(client.clone());
    resolve_and_dial(Arc::clone(&shared), policy, runtime, metrics, client, Ok(vec![addr]));
    shared
}

fn resolve_and_dial(
    shared: Arc<ConnectShared>,
    policy: Arc<dyn SocksPolicy>,
    runtime: Arc<Runtime>,
    metrics: Arc<SocksServerMetrics>,
    client: ConnHandle,
    result: io::Result<Vec<SocketAddr>>,
) {
    let addrs = match result {
        Ok(a) if !a.is_empty() => a,
        _ => {
            shared.fail(Socks5Reply::HostUnreachable);
            return;
        }
    };
    // Checked against every resolved address, not just the first: a
    // multi-answer DNS response could otherwise bypass the destination
    // filter simply by having an allowed address ordered first.
    if !addrs.iter().all(|a| policy.is_target_allowed(a.ip(), a.port())) {
        SocksServerMetrics::add(&metrics.destinations_blocked, 1);
        shared.fail(Socks5Reply::NotAllowed);
        return;
    }
    let addr = addrs[0];
    let shared2 = Arc::clone(&shared);
    let client2 = client.clone();
    let cfg = TcpConnectorConfig::new(addr, move || {
        Box::new(SocksUpstreamHandler {
            shared: Arc::clone(&shared2),
            client: client2.clone(),
            metrics: Arc::clone(&metrics),
            connected: false,
        }) as Box<dyn ProtocolHandler>
    });
    if runtime.connect(cfg).is_err() {
        shared.fail(Socks5Reply::GeneralFailure);
    }
}

/// Map a dial failure to the closest RFC 1928 §6 reply code.
fn reply_for_dial_error(err: &io::Error) -> Socks5Reply {
    match err.kind() {
        io::ErrorKind::ConnectionRefused => Socks5Reply::ConnectionRefused,
        io::ErrorKind::HostUnreachable => Socks5Reply::HostUnreachable,
        io::ErrorKind::NetworkUnreachable => Socks5Reply::NetworkUnreachable,
        io::ErrorKind::TimedOut => Socks5Reply::TtlExpired,
        _ => Socks5Reply::GeneralFailure,
    }
}

/// Protocol handler for the dialed upstream (target) connection.
struct SocksUpstreamHandler {
    shared: Arc<ConnectShared>,
    client: ConnHandle,
    metrics: Arc<SocksServerMetrics>,
    connected: bool,
}

impl ProtocolHandler for SocksUpstreamHandler {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        self.connected = true;
        // The client may have disconnected while this dial was still in
        // flight — nothing will ever consume the outcome in that case, so
        // avoid leaving a dangling, fully-relayed-to-nowhere connection
        // open until its own idle timeout. `is_probably_open` is advisory,
        // not a correctness gate: worst case a since-closed client is
        // detected one round trip later here, which is harmless.
        if !self.client.is_probably_open() {
            endpoint.close();
            return;
        }
        self.shared.set_outcome(ConnectOutcome::Connected(endpoint.handle()));
    }

    fn receive(&mut self, _endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        if !data.is_empty() {
            self.shared.mark_activity();
            SocksServerMetrics::add(&self.metrics.bytes_downstream, data.len() as u64);
            self.client.send(data.to_vec());
            *data = &[];
        }
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
        self.shared.release_once(&self.metrics);
        self.client.close();
    }

    fn error(&mut self, endpoint: &mut dyn Endpoint, err: &io::Error) {
        if !self.connected {
            // Dial failed outright — `connected` never ran, so the client
            // is still waiting on `ConnectShared::take_outcome`.
            self.shared.fail(reply_for_dial_error(err));
        }
        endpoint.close();
    }
}

/// Forward one chunk of client-to-target traffic once the relay is
/// established. Called from the client-facing handler's `receive()`.
pub(crate) fn relay_upstream(shared: &ConnectShared, upstream: &ConnHandle, metrics: &SocksServerMetrics, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    shared.mark_activity();
    SocksServerMetrics::add(&metrics.bytes_upstream, data.len() as u64);
    upstream.send(data.to_vec());
}

/// Arm (or re-arm) the self-rearming relay idle timer: fires after
/// `timeout`, and either finds activity since the last tick (clears the
/// flag and reschedules) or finds none (closes both legs and stops).
pub(crate) fn arm_idle_timer(shared: Arc<ConnectShared>, client: ConnHandle, upstream: ConnHandle, timeout: Duration) {
    let shared2 = Arc::clone(&shared);
    let client2 = client.clone();
    let upstream2 = upstream.clone();
    // The returned `TimerHandle` is deliberately not retained: there is
    // nothing to cancel it for (a closed connection makes `close()` here a
    // harmless no-op, and letting one superseded tick fire is cheaper than
    // threading a handle through both legs' teardown paths).
    let _ = client.schedule_timer(
        timeout,
        Box::new(move || {
            if shared2.activity.swap(false, Ordering::AcqRel) {
                arm_idle_timer(shared2, client2, upstream2, timeout);
            } else {
                client2.close();
                upstream2.close();
            }
        }),
    );
}

/// Release the active-relay counter for a relay that never got past the
/// client-facing side alone (e.g. the client disconnected while the dial
/// was still pending) — exposed so [`crate::handler`] can call it without
/// reaching into [`ConnectShared`]'s private fields.
pub(crate) fn release_relay_slot(shared: &ConnectShared, metrics: &SocksServerMetrics) {
    shared.release_once(metrics);
}
