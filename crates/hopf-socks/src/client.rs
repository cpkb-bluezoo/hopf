// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SOCKS4/4a/5 CONNECT client: a transport decorator that performs the
//! handshake over an already-dialed TCP connection to a SOCKS proxy, then
//! hands off to an arbitrary inner [`ProtocolHandler`] as if it were
//! talking to the target directly.
//!
//! This is deliberately not modeled on `hopf-http`'s protocol-upgrade
//! negotiation (WebSocket / CONNECT-UDP / CONNECT-IP), which operates
//! *above* an already-established HTTP connection. A SOCKS proxy sits
//! *below* the client protocol entirely — once CONNECT succeeds, the
//! tunnel is just the same raw TCP stream, so the inner handler talks to
//! the real [`Endpoint`] directly with no reframing at all.

use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hopf_core::{Endpoint, ProtocolHandler, SecurityInfo, TcpConnectorConfig};

use crate::wire::{self, ParseResult, SocksAddress, SocksCommand};

/// Default handshake timeout, matching the server side's own default.
pub const DEFAULT_CLIENT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Which SOCKS version the client speaks.
///
/// There is deliberately no "auto, prefer SOCKS5, fall back to SOCKS4"
/// mode: the target proxy's supported version is normally known
/// configuration, not something worth speculatively probing for, and
/// doing so properly would mean attempting one version, detecting
/// rejection, and retrying the whole handshake with the other — real
/// additional complexity for little practical payoff. Layer that on top
/// of this if a concrete need for it ever comes up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocksClientVersion {
    /// SOCKS4/4a (no formal RFC).
    Socks4,
    /// SOCKS5 (RFC 1928).
    Socks5,
}

/// Configuration for [`SocksConnectHandler`] / [`socks_connect_config`].
#[derive(Debug, Clone)]
pub struct SocksClientConfig {
    version: SocksClientVersion,
    credentials: Option<(String, String)>,
    handshake_timeout: Duration,
}

impl SocksClientConfig {
    /// Configuration for `version`, no authentication, the default
    /// handshake timeout.
    pub fn new(version: SocksClientVersion) -> Self {
        Self {
            version,
            credentials: None,
            handshake_timeout: DEFAULT_CLIENT_HANDSHAKE_TIMEOUT,
        }
    }

    /// Offer RFC 1929 username/password authentication. SOCKS4/4a has no
    /// credential field — this is silently unused when
    /// [`SocksClientVersion::Socks4`] is selected.
    pub fn with_credentials(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.credentials = Some((username.into(), password.into()));
        self
    }

    /// Override [`DEFAULT_CLIENT_HANDSHAKE_TIMEOUT`].
    pub fn with_handshake_timeout(mut self, handshake_timeout: Duration) -> Self {
        self.handshake_timeout = handshake_timeout;
        self
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ClientState {
    AwaitingMethodSelection,
    AwaitingAuthReply,
    AwaitingConnectReply,
    Established,
}

/// [`ProtocolHandler`] that performs a SOCKS4/4a/5 CONNECT handshake, then
/// forwards every callback straight through to `inner` as if `inner` were
/// talking to the target directly over a plain TCP connection.
///
/// Build via [`socks_connect_config`] for the common case of dialing a
/// proxy with [`hopf_core::Runtime::connect`]; construct directly only if
/// you already have some other way of producing the dialed connection.
pub struct SocksConnectHandler {
    config: SocksClientConfig,
    target_host: String,
    target_port: u16,
    inner: Box<dyn ProtocolHandler>,
    state: ClientState,
    /// Checked by the one-shot timer armed in `connected()` — see the
    /// server-side handler's identical pattern for why a plain `bool`
    /// field won't do (the timer callback has no reference to `self`).
    handshake_done: Arc<AtomicBool>,
}

impl SocksConnectHandler {
    /// `target_host`/`target_port` is the ultimate destination to CONNECT
    /// to through the proxy — not the proxy's own address, which the
    /// caller dials separately (see [`socks_connect_config`]). `inner`
    /// receives [`ProtocolHandler::connected`] once the tunnel is up, and
    /// every subsequent callback thereafter, as though it were connected
    /// to the target directly.
    pub fn new(
        config: SocksClientConfig,
        target_host: impl Into<String>,
        target_port: u16,
        inner: Box<dyn ProtocolHandler>,
    ) -> Self {
        Self {
            config,
            target_host: target_host.into(),
            target_port,
            inner,
            state: ClientState::AwaitingConnectReply,
            handshake_done: Arc::new(AtomicBool::new(false)),
        }
    }

    fn target_address(&self) -> SocksAddress {
        match self.target_host.parse::<IpAddr>() {
            Ok(ip) => SocksAddress::Ip(ip),
            Err(_) => SocksAddress::Domain(self.target_host.clone()),
        }
    }

    /// Report a handshake failure to `inner` (which never saw
    /// `connected()`, so `error()` is the only callback available to
    /// tell it anything went wrong) and close the connection.
    fn fail(&mut self, endpoint: &mut dyn Endpoint, message: impl Into<String>) {
        let err = io::Error::other(message.into());
        self.inner.error(endpoint, &err);
        endpoint.close();
    }

    fn establish(&mut self, endpoint: &mut dyn Endpoint) {
        self.handshake_done.store(true, Ordering::Release);
        self.state = ClientState::Established;
        self.inner.connected(endpoint);
    }

    fn send_connect_request(&mut self, endpoint: &mut dyn Endpoint) {
        let address = self.target_address();
        match wire::encode_socks5_request(SocksCommand::Connect, &address, self.target_port) {
            Some(req) => {
                endpoint.send(&req);
                self.state = ClientState::AwaitingConnectReply;
            }
            None => self.fail(endpoint, "target hostname too long to encode in a SOCKS5 request"),
        }
    }
}

impl ProtocolHandler for SocksConnectHandler {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        let flag = Arc::clone(&self.handshake_done);
        let conn = endpoint.handle();
        endpoint.schedule_timer(
            self.config.handshake_timeout,
            Box::new(move || {
                if !flag.load(Ordering::Acquire) {
                    // Unlike the CONNECT/BIND/UDP-ASSOCIATE server-side
                    // timers (which close two already-paired-up
                    // connections), `inner` here never saw `connected()`
                    // — a bare `close()` would only reach this handler's
                    // own `disconnected()`, which deliberately does not
                    // forward to `inner` for exactly this reason (see its
                    // doc comment). `Endpoint::fail` delivers to `error()`
                    // first, which does reach `inner`, then force-closes.
                    conn.with_endpoint(|ep| {
                        ep.fail(io::Error::new(io::ErrorKind::TimedOut, "SOCKS handshake timed out"));
                    });
                }
            }),
        );

        match self.config.version {
            SocksClientVersion::Socks4 => {
                let address = self.target_address();
                match wire::encode_socks4_request(SocksCommand::Connect, &address, self.target_port, None) {
                    Some(req) => {
                        endpoint.send(&req);
                        self.state = ClientState::AwaitingConnectReply;
                    }
                    None => self.fail(endpoint, "SOCKS4 does not support IPv6 targets"),
                }
            }
            SocksClientVersion::Socks5 => {
                let methods: &[u8] = if self.config.credentials.is_some() { &[0x00, 0x02] } else { &[0x00] };
                endpoint.send(&wire::encode_socks5_greeting(methods));
                self.state = ClientState::AwaitingMethodSelection;
            }
        }
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        loop {
            match self.state {
                ClientState::AwaitingMethodSelection => match wire::parse_method_selection(data) {
                    ParseResult::Incomplete => return,
                    ParseResult::Invalid => {
                        self.fail(endpoint, "malformed SOCKS5 method-selection reply");
                        return;
                    }
                    ParseResult::Complete(method, n) => {
                        *data = &data[n..];
                        match method {
                            0x00 => self.send_connect_request(endpoint),
                            0x02 if self.config.credentials.is_some() => {
                                let (username, password) = self.config.credentials.clone().unwrap();
                                match wire::encode_user_password_request(&username, &password) {
                                    Some(req) => {
                                        endpoint.send(&req);
                                        self.state = ClientState::AwaitingAuthReply;
                                    }
                                    None => self.fail(endpoint, "username/password too long to encode"),
                                }
                            }
                            0xff => {
                                self.fail(endpoint, "SOCKS5 proxy rejected every offered authentication method");
                                return;
                            }
                            other => {
                                self.fail(
                                    endpoint,
                                    format!("SOCKS5 proxy selected an unsupported authentication method (0x{other:02x})"),
                                );
                                return;
                            }
                        }
                    }
                },
                ClientState::AwaitingAuthReply => match wire::parse_user_password_reply(data) {
                    ParseResult::Incomplete => return,
                    ParseResult::Invalid => {
                        self.fail(endpoint, "malformed RFC 1929 authentication reply");
                        return;
                    }
                    ParseResult::Complete(ok, n) => {
                        *data = &data[n..];
                        if ok {
                            self.send_connect_request(endpoint);
                        } else {
                            self.fail(endpoint, "SOCKS5 proxy rejected the supplied credentials");
                            return;
                        }
                    }
                },
                ClientState::AwaitingConnectReply => match self.config.version {
                    SocksClientVersion::Socks4 => match wire::parse_socks4_reply(data) {
                        ParseResult::Incomplete => return,
                        ParseResult::Invalid => {
                            self.fail(endpoint, "malformed SOCKS4 reply");
                            return;
                        }
                        ParseResult::Complete(reply, n) => {
                            *data = &data[n..];
                            if reply.granted {
                                self.establish(endpoint);
                            } else {
                                self.fail(endpoint, "SOCKS4 CONNECT rejected");
                                return;
                            }
                        }
                    },
                    SocksClientVersion::Socks5 => match wire::parse_socks5_reply(data) {
                        ParseResult::Incomplete => return,
                        ParseResult::Invalid => {
                            self.fail(endpoint, "malformed SOCKS5 reply");
                            return;
                        }
                        ParseResult::Complete(reply, n) => {
                            *data = &data[n..];
                            if reply.reply == 0x00 {
                                self.establish(endpoint);
                            } else {
                                self.fail(endpoint, format!("SOCKS5 CONNECT rejected (reply code 0x{:02x})", reply.reply));
                                return;
                            }
                        }
                    },
                },
                ClientState::Established => {
                    self.inner.receive(endpoint, data);
                    return;
                }
            }
        }
    }

    fn disconnected(&mut self, endpoint: &mut dyn Endpoint) {
        if self.state == ClientState::Established {
            self.inner.disconnected(endpoint);
        }
        // Otherwise the handshake never completed: `inner` never saw
        // `connected()`, and any failure already reached it via
        // `fail()`'s call to `inner.error()` — forwarding `disconnected()`
        // too would be a spurious second notification for the same event.
    }

    fn security_established(&mut self, endpoint: &mut dyn Endpoint, info: &SecurityInfo) {
        self.inner.security_established(endpoint, info);
    }

    fn migrated(&mut self, endpoint: &mut dyn Endpoint) {
        self.inner.migrated(endpoint);
    }

    fn error(&mut self, endpoint: &mut dyn Endpoint, err: &io::Error) {
        self.inner.error(endpoint, err);
        endpoint.close();
    }

    fn datagram_received(&mut self, endpoint: &mut dyn Endpoint, data: &[u8]) {
        self.inner.datagram_received(endpoint, data);
    }
}

/// Build a [`TcpConnectorConfig`] that dials `proxy_addr`, performs the
/// SOCKS handshake per `config`, and hands off to a fresh
/// `inner_factory()`-built handler for `target_host`/`target_port`. The
/// common-case entry point — pass the result to
/// [`hopf_core::Runtime::connect`].
pub fn socks_connect_config<F>(
    proxy_addr: std::net::SocketAddr,
    config: SocksClientConfig,
    target_host: impl Into<String>,
    target_port: u16,
    inner_factory: F,
) -> TcpConnectorConfig
where
    F: Fn() -> Box<dyn ProtocolHandler> + Send + Sync + 'static,
{
    let target_host = target_host.into();
    TcpConnectorConfig::new(proxy_addr, move || {
        Box::new(SocksConnectHandler::new(
            config.clone(),
            target_host.clone(),
            target_port,
            inner_factory(),
        )) as Box<dyn ProtocolHandler>
    })
}
