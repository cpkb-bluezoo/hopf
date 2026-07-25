// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! High-level async POP3 client facade.
//!
//! [`Pop3Client`] is a builder + connect method.  It resolves hostnames via
//! the hopf-dns [`DnsResolver`] (or skips DNS for literal IPs), then calls
//! [`Runtime::connect`] with a [`TcpConnectorConfig`] wrapping a
//! [`Pop3ClientEndpoint`].

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use hopf_core::{Runtime, SharedTlsConnector, TcpConnectorConfig};
use hopf_dns::DnsResolver;

use super::endpoint::Pop3ClientEndpoint;
use super::handlers::Pop3ClientHandlerFactory;
use super::timeout::Pop3ClientTimeouts;

// ── Pop3Client ────────────────────────────────────────────────────────────────

/// Async POP3 client facade.
///
/// Build with [`Pop3Client::new`] (hostname) or [`Pop3Client::from_addr`]
/// (literal address). Call [`Pop3Client::connect`] with a
/// [`Pop3ClientHandlerFactory`] (e.g. [`super::pipeline::Pop3Fetch`]) to
/// initiate the connection.
///
/// # Example
///
/// ```no_run
/// use std::sync::Arc;
/// use hopf_core::{Runtime, RuntimeConfig};
/// use hopf_pop3::{Pop3Client, Pop3Fetch};
///
/// let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
/// let fetch = Pop3Fetch::new()
///     .credentials("alice", "secret")
///     .on_complete(Box::new(|ok| println!("done: {ok}")));
/// Pop3Client::new("pop3.example.com", 110)
///     .connect(&rt, Arc::new(fetch))
///     .unwrap();
/// ```
pub struct Pop3Client {
    host: Option<String>,
    port: u16,
    addr: Option<SocketAddr>,
    timeouts: Pop3ClientTimeouts,
    tls_connector: Option<SharedTlsConnector>,
    tls_server_name: Option<String>,
    implicit_tls: bool,
    resolver: Option<Arc<DnsResolver>>,
}

impl Pop3Client {
    /// Create a client that resolves `host` via DNS before connecting.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: Some(host.into()),
            port,
            addr: None,
            timeouts: Pop3ClientTimeouts::default(),
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
            timeouts: Pop3ClientTimeouts::default(),
            tls_connector: None,
            tls_server_name: None,
            implicit_tls: false,
            resolver: None,
        }
    }

    /// Override per-phase timeouts.
    pub fn timeouts(mut self, t: Pop3ClientTimeouts) -> Self {
        self.timeouts = t;
        self
    }

    /// Configure STLS (explicit TLS after greeting).
    pub fn stls(
        mut self,
        connector: SharedTlsConnector,
        server_name: impl Into<String>,
    ) -> Self {
        self.tls_connector = Some(connector);
        self.tls_server_name = Some(server_name.into());
        self.implicit_tls = false;
        self
    }

    /// Configure implicit TLS (POP3S — TLS from the first byte, typically port 995).
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

    /// Build a [`TcpConnectorConfig`] for a known [`SocketAddr`].
    fn make_connector(
        &self,
        factory: Arc<dyn Pop3ClientHandlerFactory>,
        addr: SocketAddr,
    ) -> TcpConnectorConfig {
        let tls_connector = self.tls_connector.clone();
        let tls_server_name = self.tls_server_name.clone();
        let stage = self.timeouts.stage;
        let message = self.timeouts.message;
        let implicit = self.implicit_tls;
        let tls_for_dial = self.tls_connector.clone();
        let sn_for_dial = self.tls_server_name.clone();

        let mut cfg = TcpConnectorConfig::new(addr, move || {
            Box::new(Pop3ClientEndpoint::new(
                factory.as_ref(),
                stage,
                message,
                tls_connector.clone(),
                tls_server_name.clone(),
                implicit,
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
    ///
    /// Takes [`Arc<Runtime>`] so hostname resolution can dial from the DNS
    /// callback without blocking the caller.  Literal IPs and `from_addr`
    /// skip DNS.
    pub fn connect(
        &self,
        rt: &Arc<Runtime>,
        factory: Arc<dyn Pop3ClientHandlerFactory>,
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
        let rt2 = Arc::clone(rt);
        let host_for_err = host.to_owned();

        resolver.resolve(
            host,
            port,
            Box::new(move |result| {
                let addrs = match result {
                    Ok(a) => a,
                    Err(e) => {
                        eprintln!("hopf-pop3: DNS error for {host_for_err}: {e}");
                        return;
                    }
                };
                let Some(addr) = addrs.into_iter().next() else {
                    eprintln!("hopf-pop3: DNS returned no addresses for {host_for_err}");
                    return;
                };
                let tls_for_dial = tls_connector.clone();
                let sn_for_dial = tls_server_name.clone();
                let factory2 = Arc::clone(&factory);
                let mut cfg = TcpConnectorConfig::new(addr, move || {
                    Box::new(Pop3ClientEndpoint::new(
                        factory2.as_ref(),
                        timeouts.stage,
                        timeouts.message,
                        tls_connector.clone(),
                        tls_server_name.clone(),
                        implicit_tls,
                    ))
                })
                .connect_timeout(Some(timeouts.connect));
                if implicit_tls {
                    if let (Some(c), Some(n)) = (tls_for_dial, sn_for_dial) {
                        cfg = cfg.with_tls(c, n);
                    }
                }
                if let Err(e) = rt2.connect(cfg) {
                    eprintln!("hopf-pop3: connect error: {e}");
                }
            }),
        );
        Ok(())
    }
}
