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

use crate::policy::ConnectUdpPolicy;
use crate::relay::ConnectUdpRelay;
use crate::target;

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

/// True for an RFC 8441/9220-shaped Extended CONNECT request naming this
/// protocol (H2/H3): `:method: CONNECT`, `:protocol: connect-udp`.
fn is_extended_connect_udp(headers: &Headers) -> bool {
    headers
        .get(":method")
        .is_some_and(|m| m.eq_ignore_ascii_case("CONNECT"))
        && headers
            .get(":protocol")
            .is_some_and(|p| p.eq_ignore_ascii_case("connect-udp"))
}

/// True for an HTTP/1.1 `Upgrade: connect-udp` request — H1 has no
/// `:protocol` pseudo-header (RFC 9110 §7.8 reserves Upgrade to H1), so
/// this is the only shape available there.
fn is_h1_connect_udp_upgrade(headers: &Headers) -> bool {
    if !headers.get(":method").is_some_and(|m| m.eq_ignore_ascii_case("GET")) {
        return false;
    }
    let upgrade = headers.get("upgrade").unwrap_or("");
    if !upgrade
        .split(',')
        .map(str::trim)
        .any(|p| p.eq_ignore_ascii_case("connect-udp"))
    {
        return false;
    }
    let connection = headers.get("connection").unwrap_or("");
    connection
        .split(',')
        .map(str::trim)
        .any(|p| p.eq_ignore_ascii_case("upgrade"))
}

fn accept_headers(is_extended_connect: bool) -> Headers {
    let mut h = Headers::new();
    if is_extended_connect {
        h.set(":status", "200");
    } else {
        h.set(":status", "101");
        h.set("Upgrade", "connect-udp");
        h.set("Connection", "Upgrade");
    }
    // Mandatory for this relay on every transport — RFC 9298's payload is
    // always Context-ID-prefixed and delivered via the DATAGRAM capsule
    // (see `relay.rs`), never a raw byte stream.
    h.set("Capsule-Protocol", "?1");
    h
}

fn send_error(w: &mut dyn ServerWriter, status: u16, message: &str) {
    let mut h = Headers::new();
    h.set(":status", status.to_string());
    h.set("Content-Type", "text/plain");
    w.headers(h);
    w.start_response_body();
    w.response_body_content(message.as_bytes());
    w.end_response_body();
    w.complete();
}

impl ServerHandler for ConnectUdpRequestHandler {
    fn headers(&mut self, response: &mut dyn ServerWriter, headers: &Headers) {
        let is_extended_connect = is_extended_connect_udp(headers);
        if !is_extended_connect && !is_h1_connect_udp_upgrade(headers) {
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
                                    if !w.upgrade(accept_headers(is_extended_connect), Box::new(relay)) {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn extended_connect_headers() -> Headers {
        let mut h = Headers::new();
        h.set(":method", "CONNECT");
        h.set(":protocol", "connect-udp");
        h.set(":path", "/.well-known/masque/udp/target.example/443/");
        h
    }

    fn h1_upgrade_headers() -> Headers {
        let mut h = Headers::new();
        h.set(":method", "GET");
        h.set("Upgrade", "connect-udp");
        h.set("Connection", "Upgrade");
        h.set(":path", "/.well-known/masque/udp/target.example/443/");
        h
    }

    #[test]
    fn recognizes_extended_connect() {
        assert!(is_extended_connect_udp(&extended_connect_headers()));
        assert!(!is_h1_connect_udp_upgrade(&extended_connect_headers()));
    }

    #[test]
    fn recognizes_h1_upgrade() {
        assert!(is_h1_connect_udp_upgrade(&h1_upgrade_headers()));
        assert!(!is_extended_connect_udp(&h1_upgrade_headers()));
    }

    #[test]
    fn extended_connect_requires_the_right_protocol_token() {
        let mut h = extended_connect_headers();
        h.set(":protocol", "websocket");
        assert!(!is_extended_connect_udp(&h));
    }

    #[test]
    fn h1_upgrade_requires_both_upgrade_and_connection_tokens() {
        let mut missing_connection = h1_upgrade_headers();
        missing_connection.set("Connection", "keep-alive");
        assert!(!is_h1_connect_udp_upgrade(&missing_connection));

        let mut wrong_upgrade = h1_upgrade_headers();
        wrong_upgrade.set("Upgrade", "websocket");
        assert!(!is_h1_connect_udp_upgrade(&wrong_upgrade));
    }

    #[test]
    fn h1_upgrade_token_list_is_comma_separated_and_case_insensitive() {
        let mut h = h1_upgrade_headers();
        h.set("Upgrade", "h2c, Connect-UDP");
        assert!(is_h1_connect_udp_upgrade(&h));
    }

    #[test]
    fn accept_headers_carry_capsule_protocol_and_the_right_status() {
        let extended = accept_headers(true);
        assert_eq!(extended.get(":status"), Some("200"));
        assert_eq!(extended.get("capsule-protocol"), Some("?1"));

        let h1 = accept_headers(false);
        assert_eq!(h1.get(":status"), Some("101"));
        assert_eq!(h1.get("upgrade"), Some("connect-udp"));
        assert_eq!(h1.get("capsule-protocol"), Some("?1"));
    }
}
