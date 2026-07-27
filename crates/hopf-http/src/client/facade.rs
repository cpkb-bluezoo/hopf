// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Gumdrop-shaped [`HttpClient`] facade (connect + request factory after handshake).

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use hopf_core::{ProtocolHandler, Runtime, SharedTlsConnector, TcpConnectorConfig};
use hopf_dns::{parse_literal_ip, DnsResolver};

use crate::HttpLimits;

use super::api::HttpConnectionHandler;
use super::connection::HttpClientConnection;
use super::session_config::HttpClientSessionConfig;
use super::HttpClientTimeouts;

/// Async HTTP client with Gumdrop-style request objects.
///
/// Transport (HTTP/1.1, HTTP/2 via ALPN or prior-knowledge, later HTTP/3) is
/// negotiated by [`HttpClientConnection`]; applications use
/// [`HttpClientSessionHandle`](crate::HttpClientSessionHandle) and
/// [`crate::HttpRequest`] only.
///
/// Build with [`HttpClient::new`], optionally [`Self::tls`], then [`HttpClient::connect`].
pub struct HttpClient {
    host: String,
    port: u16,
    addr: Option<SocketAddr>,
    limits: HttpLimits,
    timeouts: HttpClientTimeouts,
    secure: bool,
    h2_prior_knowledge: bool,
    tls_connector: Option<SharedTlsConnector>,
    tls_server_name: Option<String>,
    resolver: Option<Arc<DnsResolver>>,
}

impl HttpClient {
    /// Client that resolves `host` before connecting.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            addr: None,
            limits: HttpLimits::default(),
            timeouts: HttpClientTimeouts::default(),
            secure: false,
            h2_prior_knowledge: false,
            tls_connector: None,
            tls_server_name: None,
            resolver: None,
        }
    }

    /// Client with a pre-resolved address (skips DNS).
    pub fn from_addr(addr: SocketAddr) -> Self {
        Self {
            host: addr.ip().to_string(),
            port: addr.port(),
            addr: Some(addr),
            limits: HttpLimits::default(),
            timeouts: HttpClientTimeouts::default(),
            secure: false,
            h2_prior_knowledge: false,
            tls_connector: None,
            tls_server_name: None,
            resolver: None,
        }
    }

    /// Override [`HttpLimits`].
    pub fn limits(mut self, limits: HttpLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Override dial timeouts.
    pub fn timeouts(mut self, t: HttpClientTimeouts) -> Self {
        self.timeouts = t;
        self
    }

    /// Cleartext HTTP/2 with prior knowledge (RFC 9113 §3.4); default is HTTP/1.1
    /// (with optional upgrade handled by the connection layer in a later tranche).
    pub fn h2_prior_knowledge(mut self, enabled: bool) -> Self {
        self.h2_prior_knowledge = enabled;
        self
    }

    /// TLS dial with ALPN (`h2`, `http/1.1`). Negotiated version is opaque to the app.
    pub fn tls(
        mut self,
        connector: SharedTlsConnector,
        server_name: impl Into<String>,
    ) -> Self {
        self.tls_connector = Some(connector);
        self.tls_server_name = Some(server_name.into());
        self.secure = true;
        self
    }

    /// Use a specific [`DnsResolver`] for hostname lookup.
    pub fn resolver(mut self, resolver: Arc<DnsResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    fn connector_for_addr(
        &self,
        addr: SocketAddr,
        handler: Box<dyn HttpConnectionHandler>,
    ) -> TcpConnectorConfig {
        let config = Arc::new(HttpClientSessionConfig {
            host: self.host.clone(),
            port: self.port,
            limits: self.limits,
            secure: self.secure,
            handler: Mutex::new(Some(handler)),
        });
        let limits = self.limits;
        let secure = self.secure;
        let h2_prior = self.h2_prior_knowledge;
        let connect_timeout = Some(self.timeouts.connect);

        let mut cfg = TcpConnectorConfig::new(addr, move || {
            Box::new(HttpClientConnection::new(
                Arc::clone(&config),
                limits,
                secure,
                h2_prior,
            )) as Box<dyn ProtocolHandler>
        })
        .connect_timeout(connect_timeout);

        if let (Some(tls), Some(name)) = (&self.tls_connector, &self.tls_server_name) {
            cfg = cfg.with_tls(Arc::clone(tls), name.clone());
        }
        cfg
    }

    /// DNS (if needed) then dial. Returns immediately.
    pub fn connect(
        &self,
        rt: &Arc<Runtime>,
        handler: Box<dyn HttpConnectionHandler>,
    ) -> io::Result<()> {
        if let Some(addr) = self.addr {
            return rt.connect(self.connector_for_addr(addr, handler));
        }
        if let Some(addr) = resolve_literal(&self.host, self.port) {
            return rt.connect(self.connector_for_addr(addr, handler));
        }

        let client = self.clone_for_dial();
        let resolver = match &self.resolver {
            Some(r) => Arc::clone(r),
            None => Arc::new(DnsResolver::for_runtime(rt)?),
        };
        let host = self.host.clone();
        let port = self.port;
        let rt2 = Arc::clone(rt);
        resolver.resolve(
            &host,
            port,
            Box::new(move |result| {
                let addrs = match result {
                    Ok(a) => a,
                    Err(e) => {
                        eprintln!("hopf-http: DNS error: {e}");
                        return;
                    }
                };
                if let Some(addr) = addrs.into_iter().next() {
                    let cfg = client.connector_for_addr(addr, handler);
                    if let Err(e) = rt2.connect(cfg) {
                        eprintln!("hopf-http: connect error: {e}");
                    }
                }
            }),
        );
        Ok(())
    }

    fn clone_for_dial(&self) -> Self {
        Self {
            host: self.host.clone(),
            port: self.port,
            addr: self.addr,
            limits: self.limits,
            timeouts: self.timeouts.clone(),
            secure: self.secure,
            h2_prior_knowledge: self.h2_prior_knowledge,
            tls_connector: self.tls_connector.clone(),
            tls_server_name: self.tls_server_name.clone(),
            resolver: self.resolver.clone(),
        }
    }
}

fn resolve_literal(host: &str, port: u16) -> Option<SocketAddr> {
    if let Ok(addr) = host.parse::<SocketAddr>() {
        return Some(addr);
    }
    parse_literal_ip(host).map(|ip| SocketAddr::new(ip, port))
}
