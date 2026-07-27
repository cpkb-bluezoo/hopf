// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Low-level HTTP dial helpers ([`connect_http`], timeouts).

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hopf_core::{ProtocolHandler, Runtime, TcpConnectorConfig};
use hopf_dns::{parse_literal_ip, DnsResolver};

use crate::{ClientHandlerFactory, H1Endpoint, H2Endpoint, H2cUpgradeClientEndpoint, HttpLimits};

#[cfg(feature = "h3")]
use crate::h3::connect_h3;
#[cfg(feature = "h3")]
use hopf_quic::{QuicClientConfig, QuicDriverHandle};

/// Timeouts applied at each phase of an outbound HTTP connection.
#[derive(Clone, Debug)]
pub struct HttpClientTimeouts {
    /// DNS resolution budget (ignored for literal IPs).
    pub dns: Duration,
    /// TCP connect handshake budget.
    pub connect: Duration,
    /// Time budget waiting for each HTTP response stage (headers, etc.).
    pub stage: Duration,
}

impl Default for HttpClientTimeouts {
    fn default() -> Self {
        Self {
            dns: Duration::from_secs(5),
            connect: Duration::from_secs(30),
            stage: Duration::from_secs(60),
        }
    }
}

/// Dial an HTTP/1.1 or HTTP/2 cleartext peer by hostname or socket-address.
pub fn connect_http(
    rt: &Arc<Runtime>,
    host_or_addr: &str,
    port: u16,
    factory: Arc<dyn ClientHandlerFactory>,
    limits: HttpLimits,
    http2: bool,
    timeouts: HttpClientTimeouts,
    resolver: Option<Arc<DnsResolver>>,
) -> io::Result<()> {
    let make_handler: Arc<dyn Fn() -> Box<dyn ProtocolHandler> + Send + Sync> =
        Arc::new(move || -> Box<dyn ProtocolHandler> {
            if http2 {
                Box::new(H2Endpoint::client(Arc::clone(&factory), limits, false))
            } else {
                Box::new(H1Endpoint::client(Arc::clone(&factory), limits, false))
            }
        });
    dial(rt, host_or_addr, port, &timeouts, resolver, make_handler)
}

/// Dial an HTTP/2 peer via HTTP/1.1 h2c Upgrade (RFC 7540 §3.2).
pub fn connect_http2_upgrade(
    rt: &Arc<Runtime>,
    host_or_addr: &str,
    port: u16,
    factory: Arc<dyn ClientHandlerFactory>,
    limits: HttpLimits,
    timeouts: HttpClientTimeouts,
    resolver: Option<Arc<DnsResolver>>,
) -> io::Result<()> {
    let make_handler: Arc<dyn Fn() -> Box<dyn ProtocolHandler> + Send + Sync> =
        Arc::new(move || -> Box<dyn ProtocolHandler> {
            Box::new(H2cUpgradeClientEndpoint::new(Arc::clone(&factory), limits))
        });
    dial(rt, host_or_addr, port, &timeouts, resolver, make_handler)
}

/// Shared DNS-resolve-then-connect plumbing.
pub(crate) fn dial(
    rt: &Arc<Runtime>,
    host_or_addr: &str,
    port: u16,
    timeouts: &HttpClientTimeouts,
    resolver: Option<Arc<DnsResolver>>,
    make_handler: Arc<dyn Fn() -> Box<dyn ProtocolHandler> + Send + Sync>,
) -> io::Result<()> {
    let connect_timeout = Some(timeouts.connect);

    if let Some(addr) = resolve_literal(host_or_addr, port) {
        let mh = Arc::clone(&make_handler);
        return rt.connect(
            TcpConnectorConfig::new(addr, move || mh()).connect_timeout(connect_timeout),
        );
    }

    let res = match resolver {
        Some(r) => r,
        None => Arc::new(DnsResolver::for_runtime(rt)?),
    };
    let rt2 = Arc::clone(rt);
    res.resolve(
        host_or_addr,
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
                let mh = Arc::clone(&make_handler);
                let cfg = TcpConnectorConfig::new(addr, move || mh())
                    .connect_timeout(connect_timeout);
                if let Err(e) = rt2.connect(cfg) {
                    eprintln!("hopf-http: connect error: {e}");
                }
            }
        }),
    );
    Ok(())
}

/// Dial an HTTP/3 peer by hostname or socket-address.
#[cfg(feature = "h3")]
pub fn connect_h3_by_name(
    _rt: &Arc<Runtime>,
    host_or_addr: &str,
    port: u16,
    client_config: Arc<QuicClientConfig>,
    server_name: Option<String>,
    factory: Arc<dyn ClientHandlerFactory>,
    limits: HttpLimits,
) -> io::Result<QuicDriverHandle> {
    let sni = server_name.unwrap_or_else(|| host_or_addr.to_string());
    let addr = if let Some(a) = resolve_literal(host_or_addr, port) {
        a
    } else {
        system_resolve(host_or_addr, port)?
    };
    connect_h3(addr, client_config, sni, factory, limits)
}

fn resolve_literal(host: &str, port: u16) -> Option<SocketAddr> {
    if let Ok(addr) = host.parse::<SocketAddr>() {
        return Some(addr);
    }
    parse_literal_ip(host).map(|ip| SocketAddr::new(ip, port))
}

#[cfg(feature = "h3")]
fn system_resolve(host: &str, port: u16) -> io::Result<SocketAddr> {
    use std::net::ToSocketAddrs;
    (host, port)
        .to_socket_addrs()
        .map_err(|e| io::Error::new(io::ErrorKind::NotFound, format!("DNS {host}: {e}")))?
        .next()
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("no address for {host}"))
        })
}
