// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Connector and TCP dial configuration — peer of [`crate::listener`].

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::handler::ProtocolHandler;
use crate::listener::{HandlerFactory, DEFAULT_MAX_NET_IN, DEFAULT_MAX_NET_OUT};
use crate::tls::{SharedTlsAcceptor, SharedTlsConnector};

/// Shared buffer / TLS parameters for an accepted or dialed TCP Endpoint.
///
/// Listen and dial birth paths both reduce to registering a stream with these
/// params on a reactor (affinity).
#[derive(Clone)]
pub struct TcpConnParams {
    /// Max inbound buffer size before the connection is closed.
    pub max_net_in: usize,
    /// Max outbound buffer size before the connection is closed.
    pub max_net_out: usize,
    /// Idle timeout (no receive); `None` disables.
    pub idle_timeout: Option<Duration>,
    /// Wall-clock budget for the nonblocking TCP connect handshake; `None` disables.
    ///
    /// Only meaningful when registering a dial (`connecting = true`). Enforced by the
    /// reactor while [`crate::connection::TcpConnection::is_connecting`] is true.
    pub connect_timeout: Option<Duration>,
    /// When true, TLS begins from the first byte (TLS-from-accept / TLS-from-dial).
    pub secure: bool,
    /// Server TLS acceptor (listen / STARTTLS).
    pub tls_acceptor: Option<SharedTlsAcceptor>,
    /// Client TLS connector (dial).
    pub tls_connector: Option<SharedTlsConnector>,
    /// SNI / certificate name for client TLS.
    pub server_name: Option<String>,
    /// Expected peer address (used while dial connect is in progress).
    pub remote_hint: SocketAddr,
}

impl TcpConnParams {
    /// Plaintext params with default buffer caps.
    pub fn plaintext(remote_hint: SocketAddr) -> Self {
        Self {
            max_net_in: DEFAULT_MAX_NET_IN,
            max_net_out: DEFAULT_MAX_NET_OUT,
            idle_timeout: None,
            connect_timeout: None,
            secure: false,
            tls_acceptor: None,
            tls_connector: None,
            server_name: None,
            remote_hint,
        }
    }
}

/// TCP dial endpoint configuration — peer of [`crate::TcpListenerConfig`].
#[derive(Clone)]
pub struct TcpConnectorConfig {
    /// Peer address (Stage 0: already resolved [`SocketAddr`]).
    pub addr: SocketAddr,
    /// Creates the protocol handler for this dial.
    pub factory: HandlerFactory,
    /// Max inbound buffer size before the connection is closed.
    pub max_net_in: usize,
    /// Max outbound buffer size before the connection is closed.
    pub max_net_out: usize,
    /// Idle timeout (no receive); `None` disables.
    pub idle_timeout: Option<Duration>,
    /// Wall-clock budget for the TCP connect handshake; `None` disables.
    pub connect_timeout: Option<Duration>,
    /// When true, TLS handshake begins immediately after TCP connect.
    pub secure: bool,
    /// TLS connector (required when [`secure`](Self::secure) is true).
    pub tls: Option<SharedTlsConnector>,
    /// Server name for SNI / cert verification (defaults to addr display).
    pub server_name: Option<String>,
}

impl TcpConnectorConfig {
    /// Build a plaintext dial config with default buffer caps.
    pub fn new<F>(addr: SocketAddr, factory: F) -> Self
    where
        F: Fn() -> Box<dyn ProtocolHandler> + Send + Sync + 'static,
    {
        Self {
            addr,
            factory: Arc::new(factory),
            max_net_in: DEFAULT_MAX_NET_IN,
            max_net_out: DEFAULT_MAX_NET_OUT,
            idle_timeout: None,
            connect_timeout: None,
            secure: false,
            tls: None,
            server_name: None,
        }
    }

    /// Override inbound buffer cap.
    pub fn max_net_in(mut self, n: usize) -> Self {
        self.max_net_in = n;
        self
    }

    /// Override outbound buffer cap.
    pub fn max_net_out(mut self, n: usize) -> Self {
        self.max_net_out = n;
        self
    }

    /// Set idle timeout.
    pub fn idle_timeout(mut self, d: Option<Duration>) -> Self {
        self.idle_timeout = d;
        self
    }

    /// Set TCP connect handshake timeout (SYN → established).
    pub fn connect_timeout(mut self, d: Option<Duration>) -> Self {
        self.connect_timeout = d;
        self
    }

    /// Enable TLS-from-dial with the given connector and SNI name.
    pub fn with_tls(mut self, connector: SharedTlsConnector, server_name: impl Into<String>) -> Self {
        self.secure = true;
        self.tls = Some(connector);
        self.server_name = Some(server_name.into());
        self
    }

    /// Override SNI / certificate name without changing connector.
    pub fn server_name(mut self, name: impl Into<String>) -> Self {
        self.server_name = Some(name.into());
        self
    }

    /// Reduce to reactor registration params.
    pub fn conn_params(&self) -> TcpConnParams {
        TcpConnParams {
            max_net_in: self.max_net_in,
            max_net_out: self.max_net_out,
            idle_timeout: self.idle_timeout,
            connect_timeout: self.connect_timeout,
            secure: self.secure,
            tls_acceptor: None,
            tls_connector: self.tls.clone(),
            server_name: self.server_name.clone(),
            remote_hint: self.addr,
        }
    }

    /// Create the protocol handler for this dial.
    pub fn create_handler(&self) -> Box<dyn ProtocolHandler> {
        (self.factory)()
    }
}
