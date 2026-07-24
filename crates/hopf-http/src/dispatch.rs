// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! ALPN-dispatching HTTP endpoint: routes `h2` connections to [`H2Endpoint`]
//! and everything else to [`H1Endpoint`].
//!
//! Register [`AlpnHttpEndpoint`] as the [`hopf_core::ProtocolHandler`]
//! when accepting TLS connections that advertise both `h2` and `http/1.1` in
//! their ALPN extension.

use std::sync::Arc;

use hopf_core::{Endpoint, ProtocolHandler, SecurityInfo};

use crate::h1::H1Endpoint;
use crate::h2::H2Endpoint;
use crate::limits::HttpLimits;
use crate::stream::{ServerHandlerFactory};

/// Dispatches an accepted TLS connection to H2 or H1 based on ALPN.
///
/// On `security_established`, inspects the negotiated ALPN protocol and
/// forwards all subsequent events to either [`H2Endpoint`] or
/// [`H1Endpoint`]. Before ALPN is known the endpoint buffers nothing and
/// simply waits.
pub struct AlpnHttpEndpoint {
    factory: Arc<dyn ServerHandlerFactory>,
    limits: HttpLimits,
    inner: Option<Box<dyn ProtocolHandler>>,
    pending_receive: Vec<u8>,
}

impl AlpnHttpEndpoint {
    /// Create an endpoint that uses `factory` for all incoming requests
    /// and `limits` for HTTP/1.x parsing bounds.
    pub fn new(factory: Arc<dyn ServerHandlerFactory>, limits: HttpLimits) -> Self {
        Self {
            factory,
            limits,
            inner: None,
            pending_receive: Vec::new(),
        }
    }
}

impl ProtocolHandler for AlpnHttpEndpoint {
    fn connected(&mut self, _endpoint: &mut dyn Endpoint) {
        // Nothing to do yet — wait for security_established to learn ALPN.
    }

    fn security_established(
        &mut self,
        endpoint: &mut dyn Endpoint,
        info: &SecurityInfo,
    ) {
        let is_h2 = info
            .alpn()
            .map(|a| a == b"h2")
            .unwrap_or(false);

        let mut inner: Box<dyn ProtocolHandler> = if is_h2 {
            Box::new(H2Endpoint::server(Arc::clone(&self.factory), self.limits, false))
        } else {
            Box::new(H1Endpoint::server(Arc::clone(&self.factory), self.limits, true))
        };

        inner.connected(endpoint);
        inner.security_established(endpoint, info);

        // Replay any data that arrived before security was established.
        if !self.pending_receive.is_empty() {
            let buf = std::mem::take(&mut self.pending_receive);
            let mut slice: &[u8] = &buf;
            inner.receive(endpoint, &mut slice);
        }

        self.inner = Some(inner);
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        if let Some(inner) = self.inner.as_mut() {
            inner.receive(endpoint, data);
        } else {
            // Buffer until ALPN is decided (should not normally happen for
            // TLS connections, but be defensive).
            self.pending_receive.extend_from_slice(data);
            *data = &[];
        }
    }

    fn disconnected(&mut self, endpoint: &mut dyn Endpoint) {
        if let Some(inner) = self.inner.as_mut() {
            inner.disconnected(endpoint);
        }
    }

    fn error(&mut self, endpoint: &mut dyn Endpoint, err: &std::io::Error) {
        if let Some(inner) = self.inner.as_mut() {
            inner.error(endpoint, err);
        } else {
            endpoint.close();
        }
    }
}
