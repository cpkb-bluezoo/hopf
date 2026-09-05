// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SOCKS4/4a/5 BIND client: the same transport-decorator shape as
//! [`crate::client`]'s CONNECT handler, adapted for BIND's two-reply
//! sequence (RFC 1928 §4) — a listening reply (whose bound address the
//! caller must relay to a remote peer out-of-band, e.g. embedded in an
//! FTP PORT command sent over a different connection this crate has no
//! part in) followed by a connected reply once that peer connects.
//!
//! This goes beyond the CONNECT-only client this crate's own reference
//! scope was drawn from — the server side already implements BIND, so a
//! CONNECT-only client would be asymmetric with what this crate's own
//! server can do.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use hopf_core::{Endpoint, ProtocolHandler, SecurityInfo, TcpConnectorConfig};

use crate::client::{SocksClientConfig, SocksClientVersion};
use crate::wire::{self, ParseResult, SocksAddress, SocksCommand};

#[derive(Clone, Copy, PartialEq, Eq)]
enum BindClientState {
    AwaitingMethodSelection,
    AwaitingAuthReply,
    AwaitingFirstReply,
    AwaitingSecondReply,
    Established,
}

/// [`ProtocolHandler`] that performs a SOCKS4/4a/5 BIND handshake, then
/// forwards every callback straight through to `inner` once a peer has
/// connected — see [`crate::client::SocksConnectHandler`] for the shape
/// this mirrors, and [`crate::socks_bind_config`] for the usual way to
/// build one.
pub struct SocksBindHandler {
    config: SocksClientConfig,
    expected_peer: SocksAddress,
    expected_peer_port: u16,
    /// Called exactly once, when the first reply arrives, with the
    /// listening address the caller must relay to a remote peer
    /// out-of-band. An `Arc<dyn Fn>` rather than an `FnOnce` so it can be
    /// cheaply cloned into the `Fn`-bound dial factory
    /// [`crate::socks_bind_config`] needs — in practice it only ever runs
    /// once, for the one real connection this handler is ever used on.
    on_bound: Arc<dyn Fn(SocketAddr) + Send + Sync>,
    inner: Box<dyn ProtocolHandler>,
    state: BindClientState,
    handshake_done: Arc<AtomicBool>,
}

impl SocksBindHandler {
    /// `expected_peer`/`expected_peer_port` is this BIND request's own
    /// `DST.ADDR`/`DST.PORT` — an unspecified address (`0.0.0.0`/`::`)
    /// means "accept a connection from anyone"; a concrete address
    /// restricts it, for a proxy that enforces the restriction (not every
    /// server does). `on_bound` receives the listening address from the
    /// first reply; `inner` receives [`ProtocolHandler::connected`] once
    /// a peer has actually connected (the second reply), and every
    /// subsequent callback thereafter.
    pub fn new(
        config: SocksClientConfig,
        expected_peer: SocksAddress,
        expected_peer_port: u16,
        on_bound: Arc<dyn Fn(SocketAddr) + Send + Sync>,
        inner: Box<dyn ProtocolHandler>,
    ) -> Self {
        Self {
            config,
            expected_peer,
            expected_peer_port,
            on_bound,
            inner,
            state: BindClientState::AwaitingFirstReply,
            handshake_done: Arc::new(AtomicBool::new(false)),
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
        self.state = BindClientState::Established;
        self.inner.connected(endpoint);
    }

    fn send_bind_request(&mut self, endpoint: &mut dyn Endpoint) {
        match wire::encode_socks5_request(SocksCommand::Bind, &self.expected_peer, self.expected_peer_port) {
            Some(req) => {
                endpoint.send(&req);
                self.state = BindClientState::AwaitingFirstReply;
            }
            None => self.fail(endpoint, "expected-peer hostname too long to encode in a SOCKS5 request"),
        }
    }
}

impl ProtocolHandler for SocksBindHandler {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        let flag = Arc::clone(&self.handshake_done);
        let conn = endpoint.handle();
        endpoint.schedule_timer(
            self.config.handshake_timeout(),
            Box::new(move || {
                if !flag.load(Ordering::Acquire) {
                    // See `SocksConnectHandler::connected`'s identical
                    // timer for why `Endpoint::fail` and not a bare
                    // `close()`.
                    conn.with_endpoint(|ep| {
                        ep.fail(io::Error::new(io::ErrorKind::TimedOut, "SOCKS BIND handshake timed out"));
                    });
                }
            }),
        );

        match self.config.version() {
            SocksClientVersion::Socks4 => {
                match wire::encode_socks4_request(SocksCommand::Bind, &self.expected_peer, self.expected_peer_port, None) {
                    Some(req) => {
                        endpoint.send(&req);
                        self.state = BindClientState::AwaitingFirstReply;
                    }
                    None => self.fail(endpoint, "SOCKS4 does not support an IPv6 expected-peer address"),
                }
            }
            SocksClientVersion::Socks5 => {
                let methods: &[u8] = if self.config.credentials().is_some() { &[0x00, 0x02] } else { &[0x00] };
                endpoint.send(&wire::encode_socks5_greeting(methods));
                self.state = BindClientState::AwaitingMethodSelection;
            }
        }
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        loop {
            match self.state {
                BindClientState::AwaitingMethodSelection => match wire::parse_method_selection(data) {
                    ParseResult::Incomplete => return,
                    ParseResult::Invalid => {
                        self.fail(endpoint, "malformed SOCKS5 method-selection reply");
                        return;
                    }
                    ParseResult::Complete(method, n) => {
                        *data = &data[n..];
                        match method {
                            0x00 => self.send_bind_request(endpoint),
                            0x02 if self.config.credentials().is_some() => {
                                let (username, password) = self.config.credentials().cloned().unwrap();
                                match wire::encode_user_password_request(&username, &password) {
                                    Some(req) => {
                                        endpoint.send(&req);
                                        self.state = BindClientState::AwaitingAuthReply;
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
                BindClientState::AwaitingAuthReply => match wire::parse_user_password_reply(data) {
                    ParseResult::Incomplete => return,
                    ParseResult::Invalid => {
                        self.fail(endpoint, "malformed RFC 1929 authentication reply");
                        return;
                    }
                    ParseResult::Complete(ok, n) => {
                        *data = &data[n..];
                        if ok {
                            self.send_bind_request(endpoint);
                        } else {
                            self.fail(endpoint, "SOCKS5 proxy rejected the supplied credentials");
                            return;
                        }
                    }
                },
                BindClientState::AwaitingFirstReply => match self.config.version() {
                    SocksClientVersion::Socks4 => match wire::parse_socks4_reply(data) {
                        ParseResult::Incomplete => return,
                        ParseResult::Invalid => {
                            self.fail(endpoint, "malformed SOCKS4 reply");
                            return;
                        }
                        ParseResult::Complete(reply, n) => {
                            *data = &data[n..];
                            if reply.granted {
                                (self.on_bound)(SocketAddr::new(reply.address.into(), reply.port));
                                self.state = BindClientState::AwaitingSecondReply;
                            } else {
                                self.fail(endpoint, "SOCKS4 BIND rejected");
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
                                let SocksAddress::Ip(ip) = reply.address else {
                                    self.fail(endpoint, "SOCKS5 BIND reply named a domain, not an address");
                                    return;
                                };
                                (self.on_bound)(SocketAddr::new(ip, reply.port));
                                self.state = BindClientState::AwaitingSecondReply;
                            } else {
                                self.fail(endpoint, format!("SOCKS5 BIND rejected (reply code 0x{:02x})", reply.reply));
                                return;
                            }
                        }
                    },
                },
                BindClientState::AwaitingSecondReply => match self.config.version() {
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
                                self.fail(endpoint, "SOCKS4 BIND: no peer connection accepted");
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
                                self.fail(
                                    endpoint,
                                    format!("SOCKS5 BIND: no peer connection accepted (reply code 0x{:02x})", reply.reply),
                                );
                                return;
                            }
                        }
                    },
                },
                BindClientState::Established => {
                    self.inner.receive(endpoint, data);
                    return;
                }
            }
        }
    }

    fn disconnected(&mut self, endpoint: &mut dyn Endpoint) {
        if self.state == BindClientState::Established {
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
/// SOCKS BIND handshake per `config`, calls `on_bound` with the listening
/// address once known, and hands off to a fresh `inner_factory()`-built
/// handler once a peer connects. The common-case entry point — pass the
/// result to [`hopf_core::Runtime::connect`].
pub fn socks_bind_config<F>(
    proxy_addr: SocketAddr,
    config: SocksClientConfig,
    expected_peer: SocksAddress,
    expected_peer_port: u16,
    on_bound: Arc<dyn Fn(SocketAddr) + Send + Sync>,
    inner_factory: F,
) -> TcpConnectorConfig
where
    F: Fn() -> Box<dyn ProtocolHandler> + Send + Sync + 'static,
{
    TcpConnectorConfig::new(proxy_addr, move || {
        Box::new(SocksBindHandler::new(
            config.clone(),
            expected_peer.clone(),
            expected_peer_port,
            Arc::clone(&on_bound),
            inner_factory(),
        )) as Box<dyn ProtocolHandler>
    })
}
