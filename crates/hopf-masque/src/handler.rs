// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! [`ServerHandlerFactory`] that accepts RFC 9298 CONNECT-UDP requests on
//! H1/H2/H3 and relays UDP traffic for their lifetime.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hopf_core::{ReactorHandle, Runtime};
use hopf_dns::DnsResolver;
use hopf_http::capsule::capsule_protocol_enabled;
use hopf_http::{Headers, ServerHandler, ServerHandlerFactory, ServerWriter};
use mio::Token;

use crate::accept::{accept_headers, is_extended_connect, is_h1_upgrade, send_error};
use crate::policy::ConnectUdpPolicy;
use crate::relay::ConnectUdpRelay;
use crate::target;

const PROTOCOL: &str = "connect-udp";

/// RFC 9298 sets no lifetime bound on a CONNECT-UDP session itself — this
/// is this crate's own default for how long a relay may sit with no
/// traffic in either direction before it's torn down.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Builds per-request [`ConnectUdpRequestHandler`]s.
///
/// Needs a [`Runtime`] (to open each relay's outbound UDP socket on one of
/// its workers) and a [`DnsResolver`] (to resolve each request's target
/// hostname) — construct these once at application setup and share them,
/// the same way [`hopf_smtp`](../hopf_smtp)'s relay support does.
pub struct ConnectUdpFactory {
    dns: Arc<DnsResolver>,
    runtime: Arc<Runtime>,
    policy: Arc<dyn ConnectUdpPolicy>,
    idle_timeout: Duration,
}

impl ConnectUdpFactory {
    /// `policy` has no permissive default anywhere in this crate — pass
    /// one that actually decides which targets to allow.
    pub fn new(dns: Arc<DnsResolver>, runtime: Arc<Runtime>, policy: Arc<dyn ConnectUdpPolicy>) -> Self {
        Self {
            dns,
            runtime,
            policy,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
        }
    }

    /// Override [`DEFAULT_IDLE_TIMEOUT`].
    pub fn with_idle_timeout(mut self, idle_timeout: Duration) -> Self {
        self.idle_timeout = idle_timeout;
        self
    }
}

impl ServerHandlerFactory for ConnectUdpFactory {
    fn create_handler(&self) -> Box<dyn ServerHandler> {
        Box::new(ConnectUdpRequestHandler {
            dns: Arc::clone(&self.dns),
            runtime: Arc::clone(&self.runtime),
            policy: Arc::clone(&self.policy),
            idle_timeout: self.idle_timeout,
        })
    }
}

struct ConnectUdpRequestHandler {
    dns: Arc<DnsResolver>,
    runtime: Arc<Runtime>,
    policy: Arc<dyn ConnectUdpPolicy>,
    idle_timeout: Duration,
}

impl ServerHandler for ConnectUdpRequestHandler {
    fn headers(&mut self, response: &mut dyn ServerWriter, headers: &Headers) {
        let extended_connect = is_extended_connect(headers, PROTOCOL);
        if !extended_connect && !is_h1_upgrade(headers, PROTOCOL) {
            send_error(response, 400, "CONNECT-UDP upgrade required");
            return;
        }
        if !capsule_protocol_enabled(headers) {
            send_error(response, 400, "Capsule-Protocol required");
            return;
        }
        let Some(target) = target::parse(headers.path().unwrap_or("")) else {
            send_error(response, 400, "malformed CONNECT-UDP target");
            return;
        };

        let rh = response.response_handle();
        let policy = Arc::clone(&self.policy);
        let runtime = Arc::clone(&self.runtime);
        let idle_timeout = self.idle_timeout;

        self.dns.resolve(
            &target.host,
            target.port,
            Box::new(move |result| {
                let addrs = match result {
                    Ok(a) => a,
                    Err(_) => {
                        rh.execute(move |w| send_error(w, 502, "DNS resolution failed"));
                        return;
                    }
                };
                let Some(addr) = addrs.into_iter().next() else {
                    rh.execute(move |w| send_error(w, 502, "no address for target"));
                    return;
                };
                if !policy.is_target_allowed(addr.ip(), addr.port()) {
                    rh.execute(move |w| send_error(w, 403, "target not allowed"));
                    return;
                }

                // Opening the relay socket (`ReactorHandle::register_udp`)
                // blocks briefly on a round trip to whichever worker it
                // lands on — safe from ordinary application code, but this
                // callback is itself already running on a reactor worker
                // thread, and `register_udp` targeting *that same* worker
                // would deadlock (it can't drain the registration command
                // it just blocked itself to wait for). Do it from a
                // plain, dedicated thread instead, exactly as `hopf-mdns`'s
                // own one-time-setup registration is expected to run
                // outside any reactor callback.
                let (shared, udp_handler) = ConnectUdpRelay::prepare();
                let rh2 = rh.clone();
                let spawned = std::thread::Builder::new()
                    .name("connect-udp-relay-setup".into())
                    .spawn(move || {
                        let outcome = open_relay_socket(&runtime, addr, udp_handler);
                        match outcome {
                            Err(_) => {
                                rh2.execute(move |w| {
                                    send_error(w, 502, "failed to open relay socket")
                                });
                            }
                            Ok((token, worker)) => {
                                rh2.execute(move |w| {
                                    let conn = w.conn_handle();
                                    let relay = ConnectUdpRelay::accept(
                                        shared,
                                        worker.clone(),
                                        token,
                                        addr,
                                        conn,
                                        idle_timeout,
                                    );
                                    if !w.upgrade(accept_headers(extended_connect, PROTOCOL), Box::new(relay)) {
                                        worker.deregister_udp(token);
                                        send_error(w, 500, "upgrade failed");
                                    }
                                });
                            }
                        }
                    });
                if spawned.is_err() {
                    rh.execute(move |w| send_error(w, 502, "failed to start relay setup"));
                }
            }),
        );
    }

    fn request_complete(&mut self, _response: &mut dyn ServerWriter) {}
}

/// Bind an ephemeral outbound UDP socket, register it with one of
/// `runtime`'s workers, and return the token to send/receive on it —
/// called only from a plain (non-reactor) thread, see the call site.
fn open_relay_socket(
    runtime: &Runtime,
    target: SocketAddr,
    udp_handler: Box<dyn hopf_core::UdpDatagramHandler>,
) -> io::Result<(Token, ReactorHandle)> {
    let bind_addr: SocketAddr = if target.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let std_sock = std::net::UdpSocket::bind(bind_addr)?;
    std_sock.set_nonblocking(true)?;
    let mio_sock = mio::net::UdpSocket::from_std(std_sock);
    let worker = runtime.pick_worker().clone();
    let token = worker.register_udp(mio_sock, udp_handler)?;
    Ok((token, worker))
}
