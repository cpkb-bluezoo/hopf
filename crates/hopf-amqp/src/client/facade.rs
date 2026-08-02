// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! High-level async AMQP 0-9-1 client facade.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use hopf_core::{Runtime, SharedTlsConnector, TcpConnectorConfig};
use hopf_dns::DnsResolver;

use super::endpoint::{AmqpClientEndpoint, AmqpClientParams};
use super::handlers::AmqpClientHandlerFactory;
use super::timeout::AmqpClientTimeouts;

/// Async AMQP 0-9-1 client facade (RabbitMQ).
///
/// Build with [`AmqpClient::new`] or [`AmqpClient::from_addr`], configure
/// credentials / vhost / TLS, then [`AmqpClient::connect`] with a handler factory.
pub struct AmqpClient {
    host: Option<String>,
    port: u16,
    addr: Option<SocketAddr>,
    virtual_host: String,
    username: String,
    password: String,
    heartbeat: u16,
    frame_max: u32,
    channel_max: u16,
    timeouts: AmqpClientTimeouts,
    tls_connector: Option<SharedTlsConnector>,
    tls_server_name: Option<String>,
    implicit_tls: bool,
    resolver: Option<Arc<DnsResolver>>,
}

impl AmqpClient {
    /// Create a client that resolves `host` via DNS before connecting.
    /// Default port for AMQP is 5672; AMQPS is typically 5671.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: Some(host.into()),
            port,
            addr: None,
            virtual_host: "/".into(),
            username: "guest".into(),
            password: "guest".into(),
            heartbeat: 60,
            frame_max: 0,
            channel_max: 0,
            timeouts: AmqpClientTimeouts::default(),
            tls_connector: None,
            tls_server_name: None,
            implicit_tls: false,
            resolver: None,
        }
    }

    /// Create a client with a pre-resolved [`SocketAddr`] (skips DNS).
    pub fn from_addr(addr: SocketAddr) -> Self {
        Self {
            host: None,
            port: addr.port(),
            addr: Some(addr),
            virtual_host: "/".into(),
            username: "guest".into(),
            password: "guest".into(),
            heartbeat: 60,
            frame_max: 0,
            channel_max: 0,
            timeouts: AmqpClientTimeouts::default(),
            tls_connector: None,
            tls_server_name: None,
            implicit_tls: false,
            resolver: None,
        }
    }

    /// Virtual host (default `/`).
    pub fn virtual_host(mut self, vhost: impl Into<String>) -> Self {
        self.virtual_host = vhost.into();
        self
    }

    /// Username / password (default `guest` / `guest`).
    pub fn credentials(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.username = username.into();
        self.password = password.into();
        self
    }

    /// Preferred heartbeat interval in seconds (default 60; `0` disables).
    pub fn heartbeat(mut self, seconds: u16) -> Self {
        self.heartbeat = seconds;
        self
    }

    /// Cap on negotiated `frame_max` (`0` = accept broker).
    pub fn frame_max(mut self, frame_max: u32) -> Self {
        self.frame_max = frame_max;
        self
    }

    /// Cap on negotiated `channel_max` (`0` = accept broker).
    pub fn channel_max(mut self, channel_max: u16) -> Self {
        self.channel_max = channel_max;
        self
    }

    /// Override per-phase timeouts.
    pub fn timeouts(mut self, t: AmqpClientTimeouts) -> Self {
        self.timeouts = t;
        self
    }

    /// Configure implicit TLS (AMQPS — typically port 5671).
    pub fn implicit_tls(
        mut self,
        connector: SharedTlsConnector,
        server_name: impl Into<String>,
    ) -> Self {
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

    fn params(&self) -> AmqpClientParams {
        AmqpClientParams {
            virtual_host: self.virtual_host.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
            heartbeat: self.heartbeat,
            frame_max: self.frame_max,
            channel_max: self.channel_max,
            tls_connector: self.tls_connector.clone(),
            tls_server_name: self.tls_server_name.clone(),
            implicit_tls: self.implicit_tls,
            handshake_timeout: self.timeouts.handshake,
            heartbeat_timeout: self.timeouts.heartbeat,
        }
    }

    fn make_connector(
        &self,
        factory: Arc<dyn AmqpClientHandlerFactory>,
        addr: SocketAddr,
    ) -> TcpConnectorConfig {
        let params = self.params();
        let tls_for_dial = self.tls_connector.clone();
        let sn_for_dial = self.tls_server_name.clone();
        let implicit = self.implicit_tls;

        let mut cfg = TcpConnectorConfig::new(addr, move || {
            Box::new(AmqpClientEndpoint::new(factory.as_ref(), params.clone()))
        })
        .connect_timeout(Some(self.timeouts.connect));

        if implicit {
            if let (Some(c), Some(n)) = (tls_for_dial, sn_for_dial) {
                cfg = cfg.with_tls(c, n);
            }
        }
        cfg
    }

    /// Schedule DNS (if needed) then [`Runtime::connect`]. Returns immediately.
    pub fn connect(
        &self,
        rt: &Arc<Runtime>,
        factory: Arc<dyn AmqpClientHandlerFactory>,
    ) -> io::Result<()> {
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
                        eprintln!("hopf-amqp: DNS error for {host_for_err}: {e}");
                        return;
                    }
                };
                let Some(addr) = addrs.into_iter().next() else {
                    eprintln!("hopf-amqp: DNS returned no addresses for {host_for_err}");
                    return;
                };
                let factory2 = Arc::clone(&factory);
                let params2 = params.clone();
                let mut cfg = TcpConnectorConfig::new(addr, move || {
                    Box::new(AmqpClientEndpoint::new(factory2.as_ref(), params2.clone()))
                })
                .connect_timeout(Some(connect_timeout));
                if implicit_tls {
                    if let (Some(c), Some(n)) = (tls_for_dial, sn_for_dial) {
                        cfg = cfg.with_tls(c, n);
                    }
                }
                if let Err(e) = rt2.connect(cfg) {
                    eprintln!("hopf-amqp: connect error: {e}");
                }
            }),
        );
        Ok(())
    }
}
