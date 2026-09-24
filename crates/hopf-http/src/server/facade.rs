// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Gumdrop-shaped [`HttpServer`] facade (bind + handler factory), symmetric
//! to [`crate::HttpClient`].

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use hopf_core::{BindingId, ProtocolHandler, Runtime, SharedTlsAcceptor, TcpListenerConfig};

use crate::{
    AlpnHttpEndpoint, CleartextHttpEndpoint, ConditionalServerFactory, ContentEncodingServerFactory,
    HttpLimits,
    ServerContentEncodingPolicy, ServerHandlerFactory,
};

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
    content_encoding: ContentEncodingSetting,
    conditional: ConditionalSetting,
}

/// Whether [`HttpServer`] answers conditional `GET`/`HEAD` requests itself.
#[derive(Default, PartialEq, Eq)]
enum ConditionalSetting {
    #[default]
    On,
    Off,
}

/// How [`HttpServer`] applies content coding.
#[derive(Default)]
enum ContentEncodingSetting {
    /// Compress eligible responses and decode request bodies, using
    /// [`ServerContentEncodingPolicy::new`] with this server's limits.
    #[default]
    Default,
    /// A caller-supplied policy.
    Custom(ServerContentEncodingPolicy),
    /// Leave every body exactly as the handler wrote / the peer sent it.
    Off,
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

    /// Replace the default content-coding policy (see
    /// [`Self::disable_content_encoding`] for what the default does).
    pub fn content_encoding(mut self, policy: ServerContentEncodingPolicy) -> Self {
        self.content_encoding = ContentEncodingSetting::Custom(policy);
        self
    }

    /// Turn content coding off entirely.
    ///
    /// By default every handler is wrapped in a [`ContentEncodingServerFactory`]:
    /// responses are compressed (`br`, then `gzip`, then `deflate`, whichever
    /// the client's `Accept-Encoding` allows) when that is safe, and
    /// `Content-Encoding` request bodies are decoded before the handler sees
    /// them. A handler opts a response out by setting `Content-Encoding`
    /// itself (`identity` will do) or `Cache-Control: no-transform`. See
    /// [`ContentEncodingServerFactory`] for the exact rules.
    pub fn disable_content_encoding(mut self) -> Self {
        self.content_encoding = ContentEncodingSetting::Off;
        self
    }

    /// Stop [`HttpServer`] answering conditional requests itself.
    ///
    /// By default every handler is wrapped in a [`ConditionalServerFactory`]:
    /// a `GET` or `HEAD` carrying `If-None-Match`, `If-Modified-Since`,
    /// `If-Match` or `If-Unmodified-Since` whose `200` response has an `ETag`
    /// and/or `Last-Modified` becomes a `304 Not Modified` or `412
    /// Precondition Failed` (RFC 9110 section 13). Requests without a
    /// precondition, other methods and other statuses are untouched; a
    /// handler that changes state evaluates preconditions itself with
    /// [`evaluate_preconditions`](crate::evaluate_preconditions).
    pub fn disable_conditional_requests(mut self) -> Self {
        self.conditional = ConditionalSetting::Off;
        self
    }

    /// Terminate TLS at accept, negotiating `h2`/`http/1.1` via ALPN.
    /// `acceptor` must already advertise those protocols (see
    /// [`hopf_core::acceptor_from_pem`] and friends).
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
        let factory: Arc<dyn ServerHandlerFactory> = match &self.content_encoding {
            ContentEncodingSetting::Off => factory,
            ContentEncodingSetting::Custom(p) => {
                Arc::new(ContentEncodingServerFactory::new(factory, p.clone()))
            }
            ContentEncodingSetting::Default => Arc::new(ContentEncodingServerFactory::new(
                factory,
                ServerContentEncodingPolicy::new(&limits),
            )),
        };
        let factory: Arc<dyn ServerHandlerFactory> = match self.conditional {
            // Outside content coding: a 304 must carry the `Vary` and weak
            // `ETag` the compressed 200 would have had, and only this layer
            // sees the final headers.
            ConditionalSetting::On => Arc::new(ConditionalServerFactory::new(factory)),
            ConditionalSetting::Off => factory,
        };
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
