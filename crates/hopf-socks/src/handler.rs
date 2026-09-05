// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The SOCKS4/4a/5 connection state machine: version detection, SOCKS5
//! method negotiation with RFC 1929 authentication, request parsing, and
//! dispatch into the CONNECT relay ([`crate::connect`]).

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hopf_core::{ConnHandle, Endpoint, ProtocolHandler, Runtime};
use hopf_dns::DnsResolver;

use crate::auth::SocksAuthenticator;
use crate::connect::{self, ConnectOutcome, ConnectShared, DEFAULT_RELAY_IDLE_TIMEOUT};
use crate::metrics::SocksServerMetrics;
use crate::policy::SocksPolicy;
use crate::wire::{self, ParseResult, Socks4Reply, Socks5Reply, SocksAddress, SocksCommand};

/// Which reply framing a pending CONNECT outcome should be delivered with —
/// tracked separately from [`Phase`] so the SOCKS4-vs-5 distinction isn't
/// lost while awaiting an asynchronous DNS/dial result.
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
    Relay(ConnHandle, Arc<ConnectShared>),
}

/// Builds a `SocksConnectionHandler` for each accepted connection.
///
/// Needs a [`Runtime`] (to dial each CONNECT target) and a [`DnsResolver`]
/// (to resolve hostnames) — construct these once at application setup and
/// share them, the same way `hopf-masque`'s CONNECT-UDP support does.
/// `policy` has no permissive default anywhere in this crate — pass one
/// that actually decides which targets to allow.
pub struct SocksConnectionHandlerFactory {
    dns: Arc<DnsResolver>,
    runtime: Arc<Runtime>,
    policy: Arc<dyn SocksPolicy>,
    authenticator: Option<Arc<dyn SocksAuthenticator>>,
    metrics: Arc<SocksServerMetrics>,
    idle_timeout: Duration,
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
                let bound = endpoint
                    .local_addr()
                    .ok()
                    .and_then(|a| a.as_socket_addr())
                    .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
                match reply_kind {
                    ReplyKind::Socks4 => {
                        endpoint.send(&wire::encode_socks4_reply(Socks4Reply::Granted));
                    }
                    ReplyKind::Socks5 => {
                        endpoint.send(&wire::encode_socks5_reply(Socks5Reply::Succeeded, bound));
                    }
                }
                SocksServerMetrics::add(&self.metrics.active_relays, 1);
                connect::arm_idle_timer(
                    Arc::clone(&shared),
                    endpoint.handle(),
                    upstream.clone(),
                    self.idle_timeout,
                );
                self.phase = Phase::Relay(upstream, shared);
            }
            ConnectOutcome::Failed(reply) => {
                match reply_kind {
                    ReplyKind::Socks4 => {
                        endpoint.send(&wire::encode_socks4_reply(Socks4Reply::from_socks5(reply)));
                    }
                    ReplyKind::Socks5 => {
                        endpoint.send(&wire::encode_socks5_reply(
                            reply,
                            SocketAddr::from(([0, 0, 0, 0], 0)),
                        ));
                    }
                }
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

impl ProtocolHandler for SocksConnectionHandler {
    fn connected(&mut self, _endpoint: &mut dyn Endpoint) {
        SocksServerMetrics::add(&self.metrics.connections, 1);
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        if matches!(self.phase, Phase::AwaitingUpstream(..)) {
            self.poll_connect_outcome(endpoint);
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
                            endpoint.send(&wire::encode_socks4_reply(Socks4Reply::Rejected));
                            endpoint.close();
                            return;
                        }
                        if req.command != SocksCommand::Connect {
                            endpoint.send(&wire::encode_socks4_reply(Socks4Reply::Rejected));
                            endpoint.close();
                            return;
                        }
                        self.dispatch_connect(endpoint, req.address, req.port, ReplyKind::Socks4);
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
                        endpoint.send(&wire::encode_socks5_reply(
                            Socks5Reply::AddressTypeNotSupported,
                            SocketAddr::from(([0, 0, 0, 0], 0)),
                        ));
                        endpoint.close();
                        return;
                    }
                    ParseResult::Complete(req, n) => {
                        *data = &data[n..];
                        if req.command != SocksCommand::Connect {
                            // BIND and UDP ASSOCIATE are not implemented
                            // yet (tracked separately).
                            endpoint.send(&wire::encode_socks5_reply(
                                Socks5Reply::CommandNotSupported,
                                SocketAddr::from(([0, 0, 0, 0], 0)),
                            ));
                            endpoint.close();
                            return;
                        }
                        self.dispatch_connect(endpoint, req.address, req.port, ReplyKind::Socks5);
                        return;
                    }
                },
                Phase::AwaitingUpstream(..) => return,
                Phase::Relay(upstream, shared) => {
                    if !data.is_empty() {
                        connect::relay_upstream(shared, upstream, &self.metrics, data);
                        *data = &[];
                    }
                    return;
                }
            }
        }
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
        if let Phase::Relay(upstream, shared) = &self.phase {
            connect::release_relay_slot(shared, &self.metrics);
            upstream.close();
        }
    }

    fn error(&mut self, endpoint: &mut dyn Endpoint, _err: &io::Error) {
        endpoint.close();
    }
}
