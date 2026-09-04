// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Listener and TCP listen configuration (Gumdrop `Listener` / `TCPListener`).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::acl::{AcceptRateLimit, PeerAcl};
use crate::handler::ProtocolHandler;
use crate::peer_cred::PeerCredAllowlist;
use crate::tls::SharedTlsAcceptor;

/// Default inbound buffer cap (1 MiB).
pub const DEFAULT_MAX_NET_IN: usize = 1024 * 1024;
/// Default outbound buffer cap (4 MiB).
pub const DEFAULT_MAX_NET_OUT: usize = 4 * 1024 * 1024;
/// Default socket read chunk / initial buffer (8 KiB).
pub const DEFAULT_BUFFER_SIZE: usize = 8 * 1024;

/// Factory for per-connection protocol handlers.
pub type HandlerFactory = Arc<dyn Fn() -> Box<dyn ProtocolHandler> + Send + Sync>;

/// TCP listen endpoint configuration — peer of [`crate::TcpConnectorConfig`].
#[derive(Clone)]
pub struct TcpListenerConfig {
    /// Bind address.
    pub addr: SocketAddr,
    /// Creates a handler for each accepted connection.
    pub factory: HandlerFactory,
    /// Max inbound buffer size before the connection is closed.
    pub max_net_in: usize,
    /// Max outbound buffer size before the connection is closed.
    pub max_net_out: usize,
    /// Idle timeout (no receive); `None` disables. Partially wired in Tranche 1.
    pub idle_timeout: Option<Duration>,
    /// When true, TLS handshake begins from the first byte (TLS-from-accept).
    pub secure: bool,
    /// TLS acceptor (PEM-backed via `hopf-tls`). Required when [`secure`](Self::secure)
    /// is true; also enables [`crate::Endpoint::start_tls`] when set.
    pub tls: Option<SharedTlsAcceptor>,
    /// Peer allow/deny CIDR lists.
    pub acl: PeerAcl,
    /// Optional accept rate limit.
    pub rate_limit: Option<AcceptRateLimit>,
}

impl TcpListenerConfig {
    /// Build a plaintext listener config with default buffer caps.
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
            secure: false,
            tls: None,
            acl: PeerAcl::open(),
            rate_limit: None,
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

    /// Enable TLS-from-accept with the given acceptor.
    pub fn with_tls(mut self, acceptor: SharedTlsAcceptor) -> Self {
        self.secure = true;
        self.tls = Some(acceptor);
        self
    }

    /// Attach an acceptor for STARTTLS without requiring TLS-from-accept.
    pub fn with_starttls_acceptor(mut self, acceptor: SharedTlsAcceptor) -> Self {
        self.tls = Some(acceptor);
        self
    }

    /// Set peer ACL.
    pub fn with_acl(mut self, acl: PeerAcl) -> Self {
        self.acl = acl;
        self
    }

    /// Set accept rate limit.
    pub fn with_rate_limit(mut self, limit: AcceptRateLimit) -> Self {
        self.rate_limit = Some(limit);
        self
    }

    /// Reduce to reactor registration params (peer address filled in after accept).
    pub fn conn_params(&self, remote: SocketAddr) -> crate::connector::TcpConnParams {
        crate::connector::TcpConnParams {
            max_net_in: self.max_net_in,
            max_net_out: self.max_net_out,
            idle_timeout: self.idle_timeout,
            connect_timeout: None,
            secure: self.secure,
            tls_acceptor: self.tls.clone(),
            tls_connector: None,
            server_name: None,
            remote_hint: remote.into(),
        }
    }
}

/// UNIX domain socket listen endpoint configuration — peer of
/// [`crate::UnixConnectorConfig`], mirrors [`TcpListenerConfig`]'s shape.
/// No [`PeerAcl`]/[`AcceptRateLimit`] fields: IP/CIDR matching doesn't apply
/// to a filesystem-path socket — see [`peer_allowlist`](Self::peer_allowlist)
/// for the UNIX-domain equivalent, checked via the kernel-reported peer
/// credentials (`SO_PEERCRED`/`getpeereid`) rather than anything
/// self-reported by the peer.
#[derive(Clone)]
pub struct UnixListenerConfig {
    /// Socket path to bind. Removed and recreated on bind if a stale
    /// socket file is already there (the standard UNIX daemon convention —
    /// a leftover path from an unclean previous shutdown must not block a
    /// fresh bind).
    pub path: PathBuf,
    /// Creates a handler for each accepted connection.
    pub factory: HandlerFactory,
    /// Max inbound buffer size before the connection is closed.
    pub max_net_in: usize,
    /// Max outbound buffer size before the connection is closed.
    pub max_net_out: usize,
    /// Idle timeout (no receive); `None` disables.
    pub idle_timeout: Option<Duration>,
    /// When true, TLS handshake begins from the first byte. Unusual for a
    /// local UNIX-domain listener, but not disallowed — some deployments
    /// run mTLS even over a local socket.
    pub secure: bool,
    /// TLS acceptor; required when [`secure`](Self::secure) is true.
    pub tls: Option<SharedTlsAcceptor>,
    /// Peer-credential allowlist, checked at accept time. Empty (the
    /// default) allows every peer that can reach the socket path at all —
    /// i.e. filesystem permissions on the path/directory are the only gate.
    pub peer_allowlist: PeerCredAllowlist,
}

impl UnixListenerConfig {
    /// Build a plaintext listener config with default buffer caps and an
    /// open (allow-all) peer-credential allowlist.
    pub fn new<F>(path: impl Into<PathBuf>, factory: F) -> Self
    where
        F: Fn() -> Box<dyn ProtocolHandler> + Send + Sync + 'static,
    {
        Self {
            path: path.into(),
            factory: Arc::new(factory),
            max_net_in: DEFAULT_MAX_NET_IN,
            max_net_out: DEFAULT_MAX_NET_OUT,
            idle_timeout: None,
            secure: false,
            tls: None,
            peer_allowlist: PeerCredAllowlist::open(),
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

    /// Enable TLS-from-accept with the given acceptor.
    pub fn with_tls(mut self, acceptor: SharedTlsAcceptor) -> Self {
        self.secure = true;
        self.tls = Some(acceptor);
        self
    }

    /// Attach an acceptor for STARTTLS without requiring TLS-from-accept.
    pub fn with_starttls_acceptor(mut self, acceptor: SharedTlsAcceptor) -> Self {
        self.tls = Some(acceptor);
        self
    }

    /// Set the peer-credential allowlist.
    pub fn with_peer_allowlist(mut self, allowlist: PeerCredAllowlist) -> Self {
        self.peer_allowlist = allowlist;
        self
    }

    /// Reduce to reactor registration params.
    pub fn conn_params(&self) -> crate::connector::TcpConnParams {
        crate::connector::TcpConnParams {
            max_net_in: self.max_net_in,
            max_net_out: self.max_net_out,
            idle_timeout: self.idle_timeout,
            connect_timeout: None,
            secure: self.secure,
            tls_acceptor: self.tls.clone(),
            tls_connector: None,
            server_name: None,
            remote_hint: crate::peer_addr::PeerAddr::Unix(None),
        }
    }
}

/// Service-owned listener seam (UDP/QUIC listeners will share this shape later).
pub trait Listener: Send {
    /// Create a protocol handler for a newly accepted connection.
    fn create_handler(&self) -> Box<dyn ProtocolHandler>;
}

impl Listener for TcpListenerConfig {
    fn create_handler(&self) -> Box<dyn ProtocolHandler> {
        (self.factory)()
    }
}

impl Listener for UnixListenerConfig {
    fn create_handler(&self) -> Box<dyn ProtocolHandler> {
        (self.factory)()
    }
}
