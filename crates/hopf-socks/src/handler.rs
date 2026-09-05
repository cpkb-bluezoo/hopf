// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The SOCKS4/4a/5 connection state machine: version detection, SOCKS5
//! method negotiation with RFC 1929 authentication, request parsing, and
//! dispatch into the CONNECT ([`crate::connect`]) and BIND
//! ([`crate::bind`]) commands.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hopf_core::{ConnHandle, Endpoint, ProtocolHandler, Runtime};
use hopf_dns::DnsResolver;

use crate::auth::SocksAuthenticator;
use crate::bind::{self, BindOutcome, BindShared, DEFAULT_BIND_ACCEPT_TIMEOUT};
use crate::connect::{self, ConnectOutcome, ConnectShared, DEFAULT_RELAY_IDLE_TIMEOUT};
use crate::metrics::SocksServerMetrics;
use crate::policy::SocksPolicy;
use crate::relay::RelayActivity;
use crate::wire::{self, ParseResult, Socks4Reply, Socks5Reply, SocksAddress, SocksCommand};

const ZERO_ADDR: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);

/// Which reply framing a pending outcome should be delivered with —
/// tracked separately from [`Phase`] so the SOCKS4-vs-5 distinction isn't
/// lost while awaiting an asynchronous DNS/dial/accept result.
#[derive(Clone, Copy)]
enum ReplyKind {
    Socks4,
    Socks5,
}

enum Phase {
    VersionDetect,
    Socks5Greeting,
    Socks5Auth,
    Socks5Request,
    Socks4Request,
    AwaitingUpstream(Arc<ConnectShared>, ReplyKind),
    AwaitingBindPeer(Arc<BindShared>, ReplyKind),
    Relay(ConnHandle, Arc<RelayActivity>),
}

/// Builds a `SocksConnectionHandler` for each accepted connection.
///
/// Needs a [`Runtime`] (to dial CONNECT targets and open BIND listeners)
/// and a [`DnsResolver`] (to resolve hostnames) — construct these once at
/// application setup and share them, the same way `hopf-masque`'s
/// CONNECT-UDP support does. `policy` has no permissive default anywhere
/// in this crate — pass one that actually decides which targets/peers to
/// allow.
pub struct SocksConnectionHandlerFactory {
    dns: Arc<DnsResolver>,
    runtime: Arc<Runtime>,
    policy: Arc<dyn SocksPolicy>,
    authenticator: Option<Arc<dyn SocksAuthenticator>>,
    metrics: Arc<SocksServerMetrics>,
    idle_timeout: Duration,
    bind_accept_timeout: Duration,
}

impl SocksConnectionHandlerFactory {
    /// Create a factory with no authentication (SOCKS5 offers no-auth
    /// only; SOCKS4/4a requests are accepted as-is).
    pub fn new(dns: Arc<DnsResolver>, runtime: Arc<Runtime>, policy: Arc<dyn SocksPolicy>) -> Self {
        Self {
            dns,
            runtime,
            policy,
            authenticator: None,
            metrics: SocksServerMetrics::shared(),
            idle_timeout: DEFAULT_RELAY_IDLE_TIMEOUT,
            bind_accept_timeout: DEFAULT_BIND_ACCEPT_TIMEOUT,
        }
    }

    /// Require RFC 1929 username/password authentication. SOCKS5 will no
    /// longer offer no-auth even if the client asks for it, and SOCKS4/4a
    /// requests (which carry no credential field) are rejected outright.
    pub fn with_authenticator(mut self, authenticator: Arc<dyn SocksAuthenticator>) -> Self {
        self.authenticator = Some(authenticator);
        self
    }

    /// Override [`crate::connect::DEFAULT_RELAY_IDLE_TIMEOUT`].
    pub fn with_idle_timeout(mut self, idle_timeout: Duration) -> Self {
        self.idle_timeout = idle_timeout;
        self
    }

    /// Override [`crate::bind::DEFAULT_BIND_ACCEPT_TIMEOUT`].
    pub fn with_bind_accept_timeout(mut self, bind_accept_timeout: Duration) -> Self {
        self.bind_accept_timeout = bind_accept_timeout;
        self
    }

    /// Shared metrics handle, for exposing counters to the application.
    pub fn metrics(&self) -> Arc<SocksServerMetrics> {
        Arc::clone(&self.metrics)
    }

    /// Build a handler for one accepted connection.
    pub fn create_handler(&self) -> Box<dyn ProtocolHandler> {
        Box::new(SocksConnectionHandler {
            phase: Phase::VersionDetect,
            dns: Arc::clone(&self.dns),
            runtime: Arc::clone(&self.runtime),
            policy: Arc::clone(&self.policy),
            authenticator: self.authenticator.clone(),
            metrics: Arc::clone(&self.metrics),
            idle_timeout: self.idle_timeout,
            bind_accept_timeout: self.bind_accept_timeout,
        })
    }
}

struct SocksConnectionHandler {
    phase: Phase,
    dns: Arc<DnsResolver>,
    runtime: Arc<Runtime>,
    policy: Arc<dyn SocksPolicy>,
    authenticator: Option<Arc<dyn SocksAuthenticator>>,
    metrics: Arc<SocksServerMetrics>,
    idle_timeout: Duration,
    bind_accept_timeout: Duration,
}

impl SocksConnectionHandler {
    fn dispatch_connect(
        &mut self,
        endpoint: &mut dyn Endpoint,
        address: SocksAddress,
        port: u16,
        reply_kind: ReplyKind,
    ) {
        SocksServerMetrics::add(&self.metrics.connect_requests, 1);
        let client = endpoint.handle();
        let shared = match address {
            SocksAddress::Ip(ip) => connect::begin_connect_literal(
                Arc::clone(&self.policy),
                Arc::clone(&self.runtime),
                Arc::clone(&self.metrics),
                client,
                SocketAddr::new(ip, port),
            ),
            SocksAddress::Domain(host) => connect::begin_connect(
                &self.dns,
                Arc::clone(&self.policy),
                Arc::clone(&self.runtime),
                Arc::clone(&self.metrics),
                client,
                &host,
                port,
            ),
        };
        self.phase = Phase::AwaitingUpstream(shared, reply_kind);
    }

    fn dispatch_bind(&mut self, endpoint: &mut dyn Endpoint, address: SocksAddress, reply_kind: ReplyKind) {
        SocksServerMetrics::add(&self.metrics.bind_requests, 1);
        // BIND's DST.ADDR is the peer address the client already knows
        // out-of-band (e.g. from a prior CONNECT or a PORT-style exchange)
        // — an unspecified address means "accept from anyone", a concrete
        // literal means "accept only from this address". A domain name has
        // no real-world precedent here worth an async DNS round trip for,
        // so it's rejected outright rather than silently treated as "any
        // peer allowed" (which would quietly drop the peer check).
        let expected_peer = match address {
            SocksAddress::Ip(ip) if ip.is_unspecified() => None,
            SocksAddress::Ip(ip) => Some(ip),
            SocksAddress::Domain(_) => {
                self.send_reply(endpoint, reply_kind, Socks5Reply::AddressTypeNotSupported, ZERO_ADDR);
                endpoint.close();
                return;
            }
        };
        let client = endpoint.handle();
        match bind::begin_bind(
            &self.runtime,
            Arc::clone(&self.policy),
            Arc::clone(&self.metrics),
            client,
            expected_peer,
            self.bind_accept_timeout,
        ) {
            Ok((bound, shared)) => {
                SocksServerMetrics::add(&self.metrics.active_bind_waits, 1);
                self.send_reply(endpoint, reply_kind, Socks5Reply::Succeeded, bound);
                self.phase = Phase::AwaitingBindPeer(shared, reply_kind);
            }
            Err(_) => {
                self.send_reply(endpoint, reply_kind, Socks5Reply::GeneralFailure, ZERO_ADDR);
                endpoint.close();
            }
        }
    }

    /// Encode and send a reply in whichever framing `reply_kind` calls
    /// for — SOCKS4/4a's coarser granted/rejected plus a real bound
    /// address (used for BIND; CONNECT always passes the zero address),
    /// or SOCKS5's full reply-code-plus-address form.
    fn send_reply(&self, endpoint: &mut dyn Endpoint, reply_kind: ReplyKind, reply: Socks5Reply, bound: SocketAddr) {
        match reply_kind {
            ReplyKind::Socks4 => {
                endpoint.send(&wire::encode_socks4_reply(Socks4Reply::from_socks5(reply), bound));
            }
            ReplyKind::Socks5 => {
                endpoint.send(&wire::encode_socks5_reply(reply, bound));
            }
        }
    }

    /// Check for (and act on) a CONNECT outcome that's arrived while in
    /// [`Phase::AwaitingUpstream`] — a no-op in any other phase, or if
    /// nothing has arrived yet.
    fn poll_connect_outcome(&mut self, endpoint: &mut dyn Endpoint) {
        let (shared, reply_kind) = match &self.phase {
            Phase::AwaitingUpstream(shared, reply_kind) => (Arc::clone(shared), *reply_kind),
            _ => return,
        };
        let Some(outcome) = shared.take_outcome() else {
            return;
        };
        match outcome {
            ConnectOutcome::Connected(upstream) => {
                let bound = local_bound_addr(endpoint);
                self.send_reply(endpoint, reply_kind, Socks5Reply::Succeeded, bound);
                shared.activity.mark_established(&self.metrics);
                crate::relay::arm_idle_timer(
                    Arc::clone(&shared.activity),
                    endpoint.handle(),
                    upstream.clone(),
                    self.idle_timeout,
                );
                self.phase = Phase::Relay(upstream, Arc::clone(&shared.activity));
            }
            ConnectOutcome::Failed(reply) => {
                self.send_reply(endpoint, reply_kind, reply, ZERO_ADDR);
                endpoint.close();
            }
        }
    }

    /// Same as [`Self::poll_connect_outcome`], for [`Phase::AwaitingBindPeer`].
    fn poll_bind_outcome(&mut self, endpoint: &mut dyn Endpoint) {
        let (shared, reply_kind) = match &self.phase {
            Phase::AwaitingBindPeer(shared, reply_kind) => (Arc::clone(shared), *reply_kind),
            _ => return,
        };
        let Some(outcome) = shared.take_outcome() else {
            return;
        };
        shared.stop_waiting(&self.metrics);
        match outcome {
            BindOutcome::Accepted(peer, peer_addr) => {
                self.send_reply(endpoint, reply_kind, Socks5Reply::Succeeded, peer_addr);
                shared.activity.mark_established(&self.metrics);
                crate::relay::arm_idle_timer(
                    Arc::clone(&shared.activity),
                    endpoint.handle(),
                    peer.clone(),
                    self.idle_timeout,
                );
                self.phase = Phase::Relay(peer, Arc::clone(&shared.activity));
            }
            BindOutcome::Failed(reply) => {
                self.send_reply(endpoint, reply_kind, reply, ZERO_ADDR);
                endpoint.close();
            }
        }
    }

    fn select_socks5_method(&self, offered: &[u8]) -> Option<u8> {
        if self.authenticator.is_some() {
            offered.contains(&0x02).then_some(0x02)
        } else {
            offered.contains(&0x00).then_some(0x00)
        }
    }
}

/// The endpoint's own local address, or the zero address if it can't be
/// determined — used as a CONNECT/BIND success reply's bound address.
fn local_bound_addr(endpoint: &dyn Endpoint) -> SocketAddr {
    endpoint
        .local_addr()
        .ok()
        .and_then(|a| a.as_socket_addr())
        .unwrap_or(ZERO_ADDR)
}

impl ProtocolHandler for SocksConnectionHandler {
    fn connected(&mut self, _endpoint: &mut dyn Endpoint) {
        SocksServerMetrics::add(&self.metrics.connections, 1);
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        match &self.phase {
            Phase::AwaitingUpstream(..) => self.poll_connect_outcome(endpoint),
            Phase::AwaitingBindPeer(..) => self.poll_bind_outcome(endpoint),
            _ => {}
        }

        loop {
            match &self.phase {
                Phase::VersionDetect => {
                    let Some(&first) = data.first() else {
                        return;
                    };
                    self.phase = match first {
                        wire::VERSION_4 => Phase::Socks4Request,
                        wire::VERSION_5 => Phase::Socks5Greeting,
                        _ => {
                            endpoint.close();
                            return;
                        }
                    };
                }
                Phase::Socks4Request => match wire::parse_socks4_request(data) {
                    ParseResult::Incomplete => return,
                    ParseResult::Invalid => {
                        endpoint.close();
                        return;
                    }
                    ParseResult::Complete(req, n) => {
                        *data = &data[n..];
                        if self.authenticator.is_some() {
                            // SOCKS4 carries no credential field, so a
                            // configured authenticator can never be
                            // honored for it — reject outright rather than
                            // silently treating USERID as an identity.
                            self.send_reply(endpoint, ReplyKind::Socks4, Socks5Reply::NotAllowed, ZERO_ADDR);
                            endpoint.close();
                            return;
                        }
                        match req.command {
                            SocksCommand::Connect => {
                                self.dispatch_connect(endpoint, req.address, req.port, ReplyKind::Socks4);
                            }
                            SocksCommand::Bind => {
                                self.dispatch_bind(endpoint, req.address, ReplyKind::Socks4);
                            }
                            SocksCommand::UdpAssociate => {
                                // No SOCKS4 equivalent; tracked separately
                                // for SOCKS5 only.
                                self.send_reply(endpoint, ReplyKind::Socks4, Socks5Reply::CommandNotSupported, ZERO_ADDR);
                                endpoint.close();
                            }
                        }
                        return;
                    }
                },
                Phase::Socks5Greeting => match wire::parse_socks5_greeting(data) {
                    ParseResult::Incomplete => return,
                    ParseResult::Invalid => {
                        endpoint.close();
                        return;
                    }
                    ParseResult::Complete(greeting, n) => {
                        *data = &data[n..];
                        match self.select_socks5_method(&greeting.methods) {
                            Some(0x02) => {
                                endpoint.send(&wire::encode_method_selection(0x02));
                                self.phase = Phase::Socks5Auth;
                            }
                            Some(_) => {
                                endpoint.send(&wire::encode_method_selection(0x00));
                                self.phase = Phase::Socks5Request;
                            }
                            None => {
                                endpoint.send(&wire::encode_method_selection(0xff));
                                endpoint.close();
                                return;
                            }
                        }
                    }
                },
                Phase::Socks5Auth => match wire::parse_user_password_request(data) {
                    ParseResult::Incomplete => return,
                    ParseResult::Invalid => {
                        endpoint.close();
                        return;
                    }
                    ParseResult::Complete(req, n) => {
                        *data = &data[n..];
                        // `authenticator` is always `Some` here: it's the
                        // only way `select_socks5_method` selects 0x02.
                        let ok = self
                            .authenticator
                            .as_ref()
                            .is_some_and(|a| a.verify(&req.username, &req.password));
                        endpoint.send(&wire::encode_user_password_reply(ok));
                        if ok {
                            SocksServerMetrics::add(&self.metrics.auth_ok, 1);
                            self.phase = Phase::Socks5Request;
                        } else {
                            SocksServerMetrics::add(&self.metrics.auth_fail, 1);
                            endpoint.close();
                            return;
                        }
                    }
                },
                Phase::Socks5Request => match wire::parse_socks5_request(data) {
                    ParseResult::Incomplete => return,
                    ParseResult::Invalid => {
                        // The dominant real-world cause is an ATYP outside
                        // {IPv4, domain name, IPv6} — send the specific
                        // RFC 1928 §6 reply for that rather than a bare
                        // close, matching how a malformed/unsupported
                        // request is reported once version and command
                        // framing are already known-good (both were
                        // already committed to by reaching this phase).
                        endpoint.send(&wire::encode_socks5_reply(Socks5Reply::AddressTypeNotSupported, ZERO_ADDR));
                        endpoint.close();
                        return;
                    }
                    ParseResult::Complete(req, n) => {
                        *data = &data[n..];
                        match req.command {
                            SocksCommand::Connect => {
                                self.dispatch_connect(endpoint, req.address, req.port, ReplyKind::Socks5);
                            }
                            SocksCommand::Bind => {
                                self.dispatch_bind(endpoint, req.address, ReplyKind::Socks5);
                            }
                            SocksCommand::UdpAssociate => {
                                // Not implemented yet (tracked separately).
                                endpoint.send(&wire::encode_socks5_reply(Socks5Reply::CommandNotSupported, ZERO_ADDR));
                                endpoint.close();
                            }
                        }
                        return;
                    }
                },
                Phase::AwaitingUpstream(..) | Phase::AwaitingBindPeer(..) => return,
                Phase::Relay(other, activity) => {
                    crate::relay::forward(activity, other, &self.metrics.bytes_upstream, data);
                    *data = &[];
                    return;
                }
            }
        }
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
        match &self.phase {
            Phase::Relay(other, activity) => {
                activity.release_once(&self.metrics);
                other.close();
            }
            Phase::AwaitingBindPeer(shared, _) => {
                // The client disconnected before a BIND outcome ever
                // arrived (or before this handler got a chance to process
                // one) — `stop_waiting` is idempotent, so this is safe
                // regardless of whether `poll_bind_outcome` already ran.
                shared.stop_waiting(&self.metrics);
            }
            _ => {}
        }
    }

    fn error(&mut self, endpoint: &mut dyn Endpoint, _err: &io::Error) {
        endpoint.close();
    }
}
