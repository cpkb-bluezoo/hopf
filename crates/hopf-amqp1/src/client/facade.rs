// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! High-level async AMQP 1.0 client facade.

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use hopf_core::{Runtime, SharedTlsConnector, TcpConnectorConfig, UnixConnectorConfig};
use hopf_dns::DnsResolver;

use super::endpoint::{Amqp1ClientEndpoint, Amqp1ClientParams};
use super::handlers::Amqp1ClientHandlerFactory;
use super::timeout::Amqp1ClientTimeouts;
use crate::codec::DEFAULT_MAX_FRAME_SIZE;

/// Async AMQP 1.0 client facade.
///
/// Build with [`Amqp1Client::new`] (or [`Amqp1Client::from_addr`] /
/// [`Amqp1Client::from_unix_path`]), configure credentials / TLS, then
/// [`Amqp1Client::connect`] with a handler factory.
#[derive(Clone)]
pub struct Amqp1Client {
    host: Option<String>,
    port: u16,
    addr: Option<SocketAddr>,
    unix_path: Option<PathBuf>,
    container_id: String,
    hostname: Option<String>,
    username: Option<String>,
    password: Option<String>,
    max_frame_size: u32,
    channel_max: u16,
    timeouts: Amqp1ClientTimeouts,
    tls_connector: Option<SharedTlsConnector>,
    tls_server_name: Option<String>,
    implicit_tls: bool,
    resolver: Option<Arc<DnsResolver>>,
}

impl Amqp1Client {
    /// Create a client that resolves `host` via DNS before connecting.
    /// Default AMQP 1.0 port is 5672; AMQPS (implicit TLS) is 5671.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: Some(host.into()),
            port,
            addr: None,
            unix_path: None,
            container_id: default_container_id(),
            hostname: None,
            username: None,
            password: None,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            channel_max: u16::MAX,
            timeouts: Amqp1ClientTimeouts::default(),
            tls_connector: None,
            tls_server_name: None,
            implicit_tls: false,
            resolver: None,
        }
    }

    /// Create a client with a pre-resolved [`SocketAddr`] (skips DNS).
    pub fn from_addr(addr: SocketAddr) -> Self {
        let mut c = Self::new(addr.ip().to_string(), addr.port());
        c.addr = Some(addr);
        c.host = None;
        c
    }

    /// Create a client that dials a UNIX domain socket instead of TCP/IP.
    pub fn from_unix_path(path: impl Into<PathBuf>) -> Self {
        let mut c = Self::new("localhost", 0);
        c.unix_path = Some(path.into());
        c.host = None;
        c
    }

    /// `open.container-id` (default a per-process generated identifier).
    pub fn container_id(mut self, container_id: impl Into<String>) -> Self {
        self.container_id = container_id.into();
        self
    }

    /// `open.hostname` / SASL `hostname`, for a multi-tenant broker.
    pub fn hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = Some(hostname.into());
        self
    }

    /// SASL PLAIN credentials. Without this, the client offers ANONYMOUS.
    pub fn credentials(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self.password = Some(password.into());
        self
    }

    /// Max frame size this side accepts (default 1 MiB).
    pub fn max_frame_size(mut self, max_frame_size: u32) -> Self {
        self.max_frame_size = max_frame_size;
        self
    }

    /// Override per-phase timeouts.
    pub fn timeouts(mut self, t: Amqp1ClientTimeouts) -> Self {
        self.timeouts = t;
        self
    }

    /// Configure implicit TLS (AMQPS — typically port 5671).
    pub fn implicit_tls(mut self, connector: SharedTlsConnector, server_name: impl Into<String>) -> Self {
        self.tls_connector = Some(connector);
        self.tls_server_name = Some(server_name.into());
        self.implicit_tls = true;
        self
    }

    /// Override the DNS resolver.
    pub fn resolver(mut self, resolver: Arc<DnsResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    fn params(&self) -> Amqp1ClientParams {
        Amqp1ClientParams {
            container_id: self.container_id.clone(),
            hostname: self.hostname.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
            max_frame_size: self.max_frame_size,
            channel_max: self.channel_max,
            handshake_timeout: self.timeouts.handshake,
        }
    }

    fn make_connector(&self, factory: Arc<dyn Amqp1ClientHandlerFactory>, addr: SocketAddr) -> TcpConnectorConfig {
        let params = self.params();
        let mut cfg = TcpConnectorConfig::new(addr, move || Box::new(Amqp1ClientEndpoint::new(factory.as_ref(), params.clone())))
            .connect_timeout(Some(self.timeouts.connect));
        if self.implicit_tls {
            if let (Some(c), Some(n)) = (self.tls_connector.clone(), self.tls_server_name.clone()) {
                cfg = cfg.with_tls(c, n);
            }
        }
        cfg
    }

    fn make_unix_connector(&self, factory: Arc<dyn Amqp1ClientHandlerFactory>, path: PathBuf) -> UnixConnectorConfig {
        let params = self.params();
        let mut cfg = UnixConnectorConfig::new(path, move || Box::new(Amqp1ClientEndpoint::new(factory.as_ref(), params.clone())))
            .connect_timeout(Some(self.timeouts.connect));
        if self.implicit_tls {
            if let (Some(c), Some(n)) = (self.tls_connector.clone(), self.tls_server_name.clone()) {
                cfg = cfg.with_tls(c, n);
            }
        }
        cfg
    }

    /// Schedule DNS (if needed) then [`Runtime::connect`]. Returns immediately.
    pub fn connect(&self, rt: &Arc<Runtime>, factory: Arc<dyn Amqp1ClientHandlerFactory>) -> io::Result<()> {
        if let Some(path) = &self.unix_path {
            return rt.connect_unix(self.make_unix_connector(factory, path.clone()));
        }
        if let Some(addr) = self.addr {
            return rt.connect(self.make_connector(factory, addr));
        }

        let host = self
            .host
            .as_deref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no host or addr set"))?;

        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            let addr = SocketAddr::new(ip, self.port);
            return rt.connect(self.make_connector(factory, addr));
        }

        let resolver = match &self.resolver {
            Some(r) => Arc::clone(r),
            None => Arc::new(DnsResolver::for_runtime(rt.as_ref())?),
        };
        resolver.set_timeout(self.timeouts.dns);

        let port = self.port;
        let params = self.params();
        let tls_for_dial = self.tls_connector.clone();
        let sn_for_dial = self.tls_server_name.clone();
        let implicit_tls = self.implicit_tls;
        let connect_timeout = self.timeouts.connect;
        let rt2 = Arc::clone(rt);
        let host_for_err = host.to_owned();

        resolver.resolve(
            host,
            port,
            Box::new(move |result| {
                let addrs = match result {
                    Ok(a) => a,
                    Err(e) => {
                        eprintln!("hopf-amqp1: DNS error for {host_for_err}: {e}");
                        return;
                    }
                };
                let Some(addr) = addrs.into_iter().next() else {
                    eprintln!("hopf-amqp1: DNS returned no addresses for {host_for_err}");
                    return;
                };
                let factory2 = Arc::clone(&factory);
                let params2 = params.clone();
                let mut cfg = TcpConnectorConfig::new(addr, move || Box::new(Amqp1ClientEndpoint::new(factory2.as_ref(), params2.clone())))
                    .connect_timeout(Some(connect_timeout));
                if implicit_tls {
                    if let (Some(c), Some(n)) = (tls_for_dial, sn_for_dial) {
                        cfg = cfg.with_tls(c, n);
                    }
                }
                if let Err(e) = rt2.connect(cfg) {
                    eprintln!("hopf-amqp1: connect error: {e}");
                }
            }),
        );
        Ok(())
    }
}

fn default_container_id() -> String {
    format!("hopf-amqp1-{}-{}", std::process::id(), env!("CARGO_PKG_VERSION"))
}
