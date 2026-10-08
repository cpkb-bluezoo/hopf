// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! [`NntpClient`]: configure and dial.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use hopf_core::{Runtime, SharedTlsConnector, TcpConnectorConfig};
use hopf_dns::DnsResolver;

use super::endpoint::{NntpClientEndpoint, TlsMode};
use super::handlers::{NntpClientHandler, NntpClientHandlerFactory, SingleHandler};
use super::timeout::NntpClientTimeouts;

/// Async NNTP client facade.
///
/// Build with [`NntpClient::new`] (hostname) or [`NntpClient::from_addr`],
/// choose TLS with [`Self::implicit_tls`], [`Self::starttls`] or
/// [`Self::opportunistic_starttls`], give [`Self::credentials`], then
/// [`Self::connect`] or [`Self::connect_with`].
pub struct NntpClient {
    host: Option<String>,
    port: u16,
    addr: Option<SocketAddr>,
    timeouts: NntpClientTimeouts,
    tls: Option<(SharedTlsConnector, String)>,
    tls_mode: TlsMode,
    credentials: Option<(String, String)>,
    resolver: Option<Arc<DnsResolver>>,
}

impl NntpClient {
    /// A client that resolves `host` via DNS before connecting.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: Some(host.into()),
            port,
            addr: None,
            timeouts: NntpClientTimeouts::default(),
            tls: None,
            tls_mode: TlsMode::None,
            credentials: None,
            resolver: None,
        }
    }

    /// A client with a pre-resolved address (skips DNS).
    pub fn from_addr(addr: SocketAddr) -> Self {
        let mut c = Self::new(addr.ip().to_string(), addr.port());
        c.host = None;
        c.addr = Some(addr);
        c
    }

    pub fn timeouts(mut self, t: NntpClientTimeouts) -> Self {
        self.timeouts = t;
        self
    }

    /// TLS from the first byte (NNTPS, port 563).
    pub fn implicit_tls(mut self, connector: SharedTlsConnector, server_name: impl Into<String>) -> Self {
        self.tls = Some((connector, server_name.into()));
        self.tls_mode = TlsMode::Implicit;
        self
    }

    /// `STARTTLS` after the greeting; the connection fails if the server
    /// does not offer it.
    pub fn starttls(mut self, connector: SharedTlsConnector, server_name: impl Into<String>) -> Self {
        self.tls = Some((connector, server_name.into()));
        self.tls_mode = TlsMode::StartTlsRequired;
        self
    }

    /// `STARTTLS` when offered, cleartext otherwise.
    pub fn opportunistic_starttls(mut self, connector: SharedTlsConnector, server_name: impl Into<String>) -> Self {
        self.tls = Some((connector, server_name.into()));
        self.tls_mode = TlsMode::StartTlsOpportunistic;
        self
    }

    /// `AUTHINFO` with these once the session is (as) secure (as asked).
    pub fn credentials(mut self, user: impl Into<String>, pass: impl Into<String>) -> Self {
        self.credentials = Some((user.into(), pass.into()));
        self
    }

    pub fn resolver(mut self, resolver: Arc<DnsResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    fn connector_for(&self, factory: &Arc<dyn NntpClientHandlerFactory>, addr: SocketAddr) -> TcpConnectorConfig {
        let factory = Arc::clone(factory);
        let credentials = self.credentials.clone();
        let tls = self.tls.clone();
        let tls_mode = self.tls_mode;
        let command = self.timeouts.command;
        let mut cfg = TcpConnectorConfig::new(addr, move || {
            Box::new(NntpClientEndpoint::new(factory.create(), credentials.clone(), tls.clone(), tls_mode, command))
        })
        .connect_timeout(Some(self.timeouts.connect));
        if tls_mode == TlsMode::Implicit {
            if let Some((c, n)) = self.tls.clone() {
                cfg = cfg.with_tls(c, n);
            }
        }
        cfg
    }

    /// Dial for one handler.
    pub fn connect_with(&self, rt: &Arc<Runtime>, handler: Box<dyn NntpClientHandler>) -> io::Result<()> {
        self.connect(rt, Arc::new(SingleHandler(Mutex::new(Some(handler)))))
    }

    /// DNS (if needed) then dial. Returns immediately; a dial that never
    /// starts reaches [`NntpClientHandlerFactory::connect_failed`].
    pub fn connect(&self, rt: &Arc<Runtime>, factory: Arc<dyn NntpClientHandlerFactory>) -> io::Result<()> {
        if let Some(addr) = self.addr {
            return rt.connect(self.connector_for(&factory, addr));
        }
        let host = self
            .host
            .as_deref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no host set"))?;
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            return rt.connect(self.connector_for(&factory, SocketAddr::new(ip, self.port)));
        }
        let resolver = match &self.resolver {
            Some(r) => Arc::clone(r),
            None => Arc::new(DnsResolver::for_runtime(rt.as_ref())?),
        };
        resolver.set_timeout(self.timeouts.dns);
        let me = Self {
            host: self.host.clone(),
            port: self.port,
            addr: None,
            timeouts: self.timeouts.clone(),
            tls: self.tls.clone(),
            tls_mode: self.tls_mode,
            credentials: self.credentials.clone(),
            resolver: None,
        };
        let rt2 = Arc::clone(rt);
        let host_for_err = host.to_owned();
        let port = self.port;
        resolver.resolve(
            host,
            port,
            Box::new(move |result| {
                let addrs = match result {
                    Ok(a) => a,
                    Err(e) => return factory.connect_failed(&host_for_err, &e),
                };
                let Some(addr) = addrs.into_iter().next() else {
                    return factory.connect_failed(&host_for_err, &io::Error::new(io::ErrorKind::NotFound, "DNS returned no addresses"));
                };
                if let Err(e) = rt2.connect(me.connector_for(&factory, addr)) {
                    factory.connect_failed(&host_for_err, &e);
                }
            }),
        );
        Ok(())
    }
}
