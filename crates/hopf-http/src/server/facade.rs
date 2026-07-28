// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Gumdrop-shaped [`HttpServer`] facade (bind + handler factory), symmetric
//! to [`crate::HttpClient`].

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use hopf_core::{BindingId, ProtocolHandler, Runtime, SharedTlsAcceptor, TcpListenerConfig};

use crate::{AlpnHttpEndpoint, CleartextHttpEndpoint, HttpLimits, ServerHandlerFactory};

/// Async HTTP server: picks the cleartext (h2c prior-knowledge + Upgrade +
/// HTTP/1.1) or TLS (ALPN `h2`/`http/1.1`) endpoint per listener based on
/// whether [`Self::tls`] was configured. Applications implement only
/// [`ServerHandler`](crate::ServerHandler) / [`ServerHandlerFactory`];
/// version and transport negotiation stay below that line.
///
/// Build with [`HttpServer::new`], optionally [`Self::tls`], then
/// [`HttpServer::bind`] once per listen address.
#[derive(Default)]
pub struct HttpServer {
    limits: HttpLimits,
    tls_acceptor: Option<SharedTlsAcceptor>,
}

impl HttpServer {
    /// Server with default limits, no TLS.
    pub fn new() -> Self {
        Self::default()
    }

    /// Override [`HttpLimits`].
    pub fn limits(mut self, limits: HttpLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Terminate TLS at accept, negotiating `h2`/`http/1.1` via ALPN.
    /// `acceptor` must already advertise those protocols (see
    /// [`hopf_tls::acceptor_from_pem`] and friends).
    pub fn tls(mut self, acceptor: SharedTlsAcceptor) -> Self {
        self.tls_acceptor = Some(acceptor);
        self
    }

    /// Bind `addr` and register `factory` for every accepted connection.
    /// Returns the bound address (useful for `addr.port() == 0`) and the
    /// [`BindingId`] for [`Runtime::remove_binding`].
    pub fn bind(
        &self,
        rt: &Runtime,
        addr: SocketAddr,
        factory: Arc<dyn ServerHandlerFactory>,
    ) -> io::Result<(SocketAddr, BindingId)> {
        let limits = self.limits;
        let config = if let Some(acceptor) = &self.tls_acceptor {
            let acceptor = Arc::clone(acceptor);
            TcpListenerConfig::new(addr, move || {
                Box::new(AlpnHttpEndpoint::new(Arc::clone(&factory), limits)) as Box<dyn ProtocolHandler>
            })
            .with_tls(acceptor)
        } else {
            TcpListenerConfig::new(addr, move || {
                Box::new(CleartextHttpEndpoint::new(Arc::clone(&factory), limits)) as Box<dyn ProtocolHandler>
            })
        };
        rt.add_tcp_listener(config)
    }
}
