// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! High-level async IMAP client facade.
//!
//! [`ImapClient`] resolves hostnames via hopf-dns then dials with
//! [`Runtime::connect`] and an [`ImapClientEndpoint`].

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use hopf_core::{Runtime, SharedTlsConnector, TcpConnectorConfig};
use hopf_dns::DnsResolver;

use super::endpoint::ImapClientEndpoint;
use super::handlers::ImapClientHandlerFactory;
use super::pending::DEFAULT_MAX_PIPELINE;
use super::timeout::ImapClientTimeouts;

/// Async IMAP client facade.
///
/// Build with [`ImapClient::new`] (hostname) or [`ImapClient::from_addr`].
/// Call [`ImapClient::connect`] with an [`ImapClientHandlerFactory`]
/// (e.g. [`super::pipeline::ImapFetch`]).
pub struct ImapClient {
    host: Option<String>,
    port: u16,
    addr: Option<SocketAddr>,
    timeouts: ImapClientTimeouts,
    tls_connector: Option<SharedTlsConnector>,
    tls_server_name: Option<String>,
    implicit_tls: bool,
    resolver: Option<Arc<DnsResolver>>,
    max_pipeline: usize,
}

impl ImapClient {
    /// Create a client that resolves `host` via DNS before connecting.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: Some(host.into()),
            port,
            addr: None,
            timeouts: ImapClientTimeouts::default(),
            tls_connector: None,
            tls_server_name: None,
            implicit_tls: false,
            resolver: None,
            max_pipeline: DEFAULT_MAX_PIPELINE,
        }
    }

    /// Create a client with a pre-resolved [`SocketAddr`] (skips DNS).
    pub fn from_addr(addr: SocketAddr) -> Self {
        Self {
            host: None,
            port: addr.port(),
            addr: Some(addr),
            timeouts: ImapClientTimeouts::default(),
            tls_connector: None,
            tls_server_name: None,
            implicit_tls: false,
            resolver: None,
            max_pipeline: DEFAULT_MAX_PIPELINE,
        }
    }

    /// Override per-phase timeouts.
    pub fn timeouts(mut self, t: ImapClientTimeouts) -> Self {
        self.timeouts = t;
        self
    }

    /// Cap outstanding tagged commands (default [`DEFAULT_MAX_PIPELINE`]).
    pub fn max_pipeline(mut self, n: usize) -> Self {
        self.max_pipeline = n.max(1);
        self
    }

    /// Configure STARTTLS (explicit TLS after greeting / CAPABILITY).
    pub fn starttls(
        mut self,
        connector: SharedTlsConnector,
        server_name: impl Into<String>,
    ) -> Self {
        self.tls_connector = Some(connector);
        self.tls_server_name = Some(server_name.into());
        self.implicit_tls = false;
        self
    }

    /// Configure implicit TLS (IMAPS — TLS from the first byte, typically 993).
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

    fn make_connector(
        &self,
        factory: Arc<dyn ImapClientHandlerFactory>,
        addr: SocketAddr,
    ) -> TcpConnectorConfig {
        let tls_connector = self.tls_connector.clone();
        let tls_server_name = self.tls_server_name.clone();
        let stage = self.timeouts.stage;
        let message = self.timeouts.message;
        let connect = self.timeouts.connect;
        let implicit = self.implicit_tls;
        let max_pipeline = self.max_pipeline;
        let tls_for_dial = self.tls_connector.clone();
        let sn_for_dial = self.tls_server_name.clone();

        let mut cfg = TcpConnectorConfig::new(addr, move || {
            Box::new(ImapClientEndpoint::new(
                factory.as_ref(),
                stage,
                message,
                connect,
                tls_connector.clone(),
                tls_server_name.clone(),
                implicit,
                max_pipeline,
            ))
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
        factory: Arc<dyn ImapClientHandlerFactory>,
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
        let timeouts = self.timeouts.clone();
        let tls_connector = self.tls_connector.clone();
        let tls_server_name = self.tls_server_name.clone();
        let implicit_tls = self.implicit_tls;
        let max_pipeline = self.max_pipeline;
        let rt2 = Arc::clone(rt);
        let host_for_err = host.to_owned();

        resolver.resolve(
            host,
            port,
            Box::new(move |result| {
                let addrs = match result {
                    Ok(a) => a,
                    Err(e) => {
                        eprintln!("hopf-imap: DNS error for {host_for_err}: {e}");
                        return;
                    }
                };
                let Some(addr) = addrs.into_iter().next() else {
                    eprintln!("hopf-imap: DNS returned no addresses for {host_for_err}");
                    return;
                };
                let tls_for_dial = tls_connector.clone();
                let sn_for_dial = tls_server_name.clone();
                let factory2 = Arc::clone(&factory);
                let mut cfg = TcpConnectorConfig::new(addr, move || {
                    Box::new(ImapClientEndpoint::new(
                        factory2.as_ref(),
                        timeouts.stage,
                        timeouts.message,
                        timeouts.connect,
                        tls_connector.clone(),
                        tls_server_name.clone(),
                        implicit_tls,
                        max_pipeline,
                    ))
                })
                .connect_timeout(Some(timeouts.connect));
                if implicit_tls {
                    if let (Some(c), Some(n)) = (tls_for_dial, sn_for_dial) {
                        cfg = cfg.with_tls(c, n);
                    }
                }
                if let Err(e) = rt2.connect(cfg) {
                    eprintln!("hopf-imap: connect error: {e}");
                }
            }),
        );
        Ok(())
    }
}
