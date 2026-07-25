// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP client connect helpers with DNS resolution and per-phase timeouts.
//!
//! High-level entry-points that resolve a hostname (or accept a literal IP /
//! socket-address string) and dial an H1/H2/H3 endpoint with configurable
//! timeouts.
//!
//! # Examples
//!
//! ```no_run
//! use std::sync::Arc;
//! use hopf_core::{Runtime, RuntimeConfig};
//! use hopf_http::{ClientHandlerFactory, HttpLimits};
//! use hopf_http::client::{connect_http, HttpClientTimeouts};
//!
//! # fn f(factory: Arc<dyn ClientHandlerFactory>) -> std::io::Result<()> {
//! let rt = Arc::new(Runtime::start(RuntimeConfig::default())?);
//! connect_http(&rt, "example.com", 80, factory, HttpLimits::default(),
//!              false, HttpClientTimeouts::default(), None)?;
//! # Ok(())
//! # }
//! ```

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hopf_core::{ProtocolHandler, Runtime, TcpConnectorConfig};
use hopf_dns::{parse_literal_ip, DnsResolver};

use crate::{ClientHandlerFactory, H1Endpoint, H2Endpoint, HttpLimits};

#[cfg(feature = "h3")]
use crate::h3::connect_h3;
#[cfg(feature = "h3")]
use hopf_quic::{QuicClientConfig, QuicDriverHandle};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Public functions
// ---------------------------------------------------------------------------

/// Dial an HTTP/1.1 or HTTP/2 cleartext peer by hostname or socket-address.
///
/// * If `host_or_addr` parses as a [`SocketAddr`] or bare IP, DNS is skipped.
/// * Otherwise a [`DnsResolver`] resolves the name asynchronously (system
///   resolvers are used when `resolver` is `None`).
/// * [`HttpClientTimeouts::connect`] is wired into
///   [`TcpConnectorConfig::connect_timeout`].
///
/// Returns immediately; the TCP connect and protocol handshake run
/// asynchronously on a worker reactor.
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
    let connect_timeout = Some(timeouts.connect);

    // Build a shared handler factory (Fn, not FnOnce, required by TcpConnectorConfig).
    let make_handler: Arc<dyn Fn() -> Box<dyn ProtocolHandler> + Send + Sync> =
        Arc::new(move || -> Box<dyn ProtocolHandler> {
            if http2 {
                Box::new(H2Endpoint::client(Arc::clone(&factory), limits, false))
            } else {
                Box::new(H1Endpoint::client(Arc::clone(&factory), limits, false))
            }
        });

    // Literal IP / full SocketAddr → skip DNS.
    if let Some(addr) = resolve_literal(host_or_addr, port) {
        let mh = Arc::clone(&make_handler);
        return rt.connect(
            TcpConnectorConfig::new(addr, move || mh()).connect_timeout(connect_timeout),
        );
    }

    // Hostname → async DNS lookup, then connect from callback.
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
///
/// Literal IPs bypass DNS. Hostnames are resolved via one blocking system-DNS
/// call (a future tranche will use the async [`DnsResolver`] once
/// `connect_quic_hooks` supports deferred dial).
///
/// `server_name` is the TLS SNI / certificate name; defaults to `host_or_addr`
/// when `None`.
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

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn resolve_literal(host: &str, port: u16) -> Option<SocketAddr> {
    // Full "ip:port" or "[::1]:port"
    if let Ok(addr) = host.parse::<SocketAddr>() {
        return Some(addr);
    }
    // Bare IP address
    parse_literal_ip(host).map(|ip| SocketAddr::new(ip, port))
}

/// Blocking one-shot system-DNS resolve used only for H3-by-name.
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
