// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! High-level async SMTP client facade.
//!
//! `SmtpClient` is a builder + connect method. It resolves hostnames via
//! the hopf-dns `DnsResolver` (or skips DNS for literal IPs), then calls
//! `Runtime::connect` with a `TcpConnectorConfig` that wraps an
//! `SmtpClientEndpoint` as the `ProtocolHandler`.

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use hopf_core::{Runtime, SharedTlsConnector, TcpConnectorConfig, UnixConnectorConfig};
use hopf_dns::DnsResolver;

use super::endpoint::SmtpClientEndpoint;
use super::handlers::SmtpClientHandlerFactory;

/// Per-phase timeout configuration for [`SmtpClient`].
#[derive(Debug, Clone)]
pub struct SmtpClientTimeouts {
    /// DNS resolution budget (default 5 s).
    pub dns: Duration,
    /// Connect budget: dial → greeting (default 30 s).
    pub connect: Duration,
    /// Per-reply idle budget after each command (default 60 s).
    pub stage: Duration,
    /// Post-DATA-end budget (default 600 s).
    pub message: Duration,
}

impl Default for SmtpClientTimeouts {
    fn default() -> Self {
        Self {
            dns: Duration::from_secs(5),
            connect: Duration::from_secs(30),
            stage: Duration::from_secs(60),
            message: Duration::from_secs(600),
        }
    }
}

/// Async SMTP client facade.
///
/// Build with [`SmtpClient::new`] (hostname) or [`SmtpClient::from_addr`]
/// (literal address). Call [`SmtpClient::connect`] with a
/// [`SmtpClientHandlerFactory`] to initiate the connection.
pub struct SmtpClient {
    host: Option<String>,
    port: u16,
    addr: Option<SocketAddr>,
    unix_path: Option<PathBuf>,
    timeouts: SmtpClientTimeouts,
    tls_connector: Option<SharedTlsConnector>,
    tls_server_name: Option<String>,
    implicit_tls: bool,
    resolver: Option<Arc<DnsResolver>>,
}

impl SmtpClient {
    /// Create a client that resolves `host` via DNS before connecting.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: Some(host.into()),
            port,
            addr: None,
            unix_path: None,
            timeouts: SmtpClientTimeouts::default(),
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
            unix_path: None,
            timeouts: SmtpClientTimeouts::default(),
            tls_connector: None,
            tls_server_name: None,
            implicit_tls: false,
            resolver: None,
        }
    }

    /// Create a client that dials a UNIX domain socket instead of TCP/IP —
    /// skips DNS and any TCP-specific setup entirely.
    pub fn from_unix_path(path: impl Into<PathBuf>) -> Self {
        Self {
            host: None,
            port: 0,
            addr: None,
            unix_path: Some(path.into()),
            timeouts: SmtpClientTimeouts::default(),
            tls_connector: None,
            tls_server_name: None,
            implicit_tls: false,
            resolver: None,
        }
    }

    /// Override the default timeouts.
    pub fn timeouts(mut self, t: SmtpClientTimeouts) -> Self {
        self.timeouts = t;
        self
    }

    /// Configure STARTTLS (explicit TLS after greeting).
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

    /// Configure implicit TLS (SMTPS — TLS from the first byte, port 465).
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

    /// Use the given DNS resolver for hostname → address lookup.
    pub fn resolver(mut self, resolver: Arc<DnsResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// Build a [`TcpConnectorConfig`] for a known [`SocketAddr`].
    pub fn connector(
        &self,
        factory: Arc<dyn SmtpClientHandlerFactory>,
        addr: SocketAddr,
        rt: &Arc<Runtime>,
    ) -> TcpConnectorConfig {
        let tls_connector = self.tls_connector.clone();
        let tls_server_name = self.tls_server_name.clone();
        let stage = self.timeouts.stage;
        let message = self.timeouts.message;
        let implicit = self.implicit_tls;
        let tls_for_dial = self.tls_connector.clone();
        let sn_for_dial = self.tls_server_name.clone();
        let rt = Arc::clone(rt);

        let mut cfg = TcpConnectorConfig::new(addr, move || {
            Box::new(SmtpClientEndpoint::new(
                factory.as_ref(),
                &rt,
                stage,
                message,
                tls_connector.clone(),
                tls_server_name.clone(),
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

    /// Build a [`UnixConnectorConfig`] for a known socket path — UNIX-domain
    /// counterpart of [`Self::connector`].
    pub fn unix_connector(
        &self,
        factory: Arc<dyn SmtpClientHandlerFactory>,
        path: PathBuf,
        rt: &Arc<Runtime>,
    ) -> UnixConnectorConfig {
        let tls_connector = self.tls_connector.clone();
        let tls_server_name = self.tls_server_name.clone();
        let stage = self.timeouts.stage;
        let message = self.timeouts.message;
        let implicit = self.implicit_tls;
        let tls_for_dial = self.tls_connector.clone();
        let sn_for_dial = self.tls_server_name.clone();
        let rt = Arc::clone(rt);

        let mut cfg = UnixConnectorConfig::new(path, move || {
            Box::new(SmtpClientEndpoint::new(
                factory.as_ref(),
                &rt,
                stage,
                message,
                tls_connector.clone(),
                tls_server_name.clone(),
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

    /// Schedule DNS (if needed) then `Runtime::connect`. Returns immediately.
    ///
    /// Takes [`Arc<Runtime>`] so hostname resolution can dial from the DNS
    /// callback without parking the caller. Literal IPs and `from_addr` skip DNS.
    /// [`Self::from_unix_path`] dials a UNIX domain socket instead — skips
    /// DNS and address resolution entirely.
    pub fn connect(
        &self,
        rt: &Arc<Runtime>,
        factory: Arc<dyn SmtpClientHandlerFactory>,
    ) -> io::Result<()> {
        if let Some(path) = &self.unix_path {
            return rt.connect_unix(self.unix_connector(factory, path.clone(), rt));
        }
        if let Some(addr) = self.addr {
            return rt.connect(self.connector(factory, addr, rt));
        }

        let host = self
            .host
            .as_deref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no host or addr set"))?;

        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            let addr = SocketAddr::new(ip, self.port);
            return rt.connect(self.connector(factory, addr, rt));
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
        let rt2 = Arc::clone(rt);
        let host_for_err = host.to_owned();

        resolver.resolve(
            host,
            port,
            Box::new(move |result| {
                let addrs = match result {
                    Ok(a) => a,
                    Err(e) => {
                        eprintln!("hopf-smtp: DNS error for {host_for_err}: {e}");
                        return;
                    }
                };
                let Some(addr) = addrs.into_iter().next() else {
                    eprintln!("hopf-smtp: DNS returned no addresses for {host_for_err}");
                    return;
                };
                let tls_for_dial = tls_connector.clone();
                let sn_for_dial = tls_server_name.clone();
                let factory2 = Arc::clone(&factory);
                let rt3 = Arc::clone(&rt2);
                let mut cfg = TcpConnectorConfig::new(addr, move || {
                    Box::new(SmtpClientEndpoint::new(
                        factory2.as_ref(),
                        &rt3,
                        timeouts.stage,
                        timeouts.message,
                        tls_connector.clone(),
                        tls_server_name.clone(),
                    ))
                })
                .connect_timeout(Some(timeouts.connect));
                if implicit_tls {
                    if let (Some(c), Some(n)) = (tls_for_dial, sn_for_dial) {
                        cfg = cfg.with_tls(c, n);
                    }
                }
                if let Err(e) = rt2.connect(cfg) {
                    eprintln!("hopf-smtp: connect error: {e}");
                }
            }),
        );
        Ok(())
    }
}
