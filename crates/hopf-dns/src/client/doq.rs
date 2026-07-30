// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! DNS-over-QUIC client (RFC 9250) — feature `doq`.
//!
//! Implements [`DnsClientTransport`]: each `send_query` dials via QUIC and
//! delivers the response via [`DnsClientTransportHandler`] — no caller-thread
//! wait, no channels. Driver handles are retained on the transport until it is
//! dropped (dropping a [`QuicDriverHandle`] shuts down the driver).

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use hopf_core::{Endpoint, HandlerFactory, ProtocolHandler};
use hopf_quic::{connect_quic, QuicClientConfig, QuicConnectConfig, QuicDriverHandle};

use super::{DnsClientTransport, DnsClientTransportHandler};

/// ALPN for DoQ.
pub const ALPN_DOQ: &[u8] = b"doq";

/// DoQ-specific QUIC application error codes (RFC 9250 §4.3), for use with
/// [`hopf_core::Endpoint::abort`]/`close_connection`.
pub const DOQ_NO_ERROR: u32 = 0x0;
/// The DoQ implementation encountered a local error and is incapable of
/// continuing the connection.
pub const DOQ_INTERNAL_ERROR: u32 = 0x1;
/// The DoQ implementation encountered a protocol error and is forcibly
/// aborting the connection (e.g. a malformed DNS message on a stream).
pub const DOQ_PROTOCOL_ERROR: u32 = 0x2;
/// A DoQ client uses this to signal that it wants to cancel an
/// outstanding request.
pub const DOQ_REQUEST_CANCELLED: u32 = 0x3;
/// A DoQ implementation uses this to signal when the excessive number of
/// concurrent streams/requests has caused it to terminate the connection.
pub const DOQ_EXCESSIVE_LOAD: u32 = 0x4;

/// DoQ client (one QUIC dial per query).
pub struct DoqClientTransport {
    client: Arc<QuicClientConfig>,
    server_name: String,
    /// Live driver handles (must outlive in-flight queries).
    drivers: Vec<QuicDriverHandle>,
}

impl DoqClientTransport {
    /// `client` TLS config should advertise ALPN `doq`.
    pub fn new(client: Arc<QuicClientConfig>, server_name: impl Into<String>) -> Self {
        Self {
            client,
            server_name: server_name.into(),
            drivers: Vec::new(),
        }
    }
}

impl DnsClientTransport for DoqClientTransport {
    fn send_query(
        &mut self,
        server: SocketAddr,
        message: &[u8],
        handler: Box<dyn DnsClientTransportHandler>,
    ) -> io::Result<()> {
        // RFC 9250 §4.2.1: the DNS message ID MUST be 0 over DoQ — the
        // QUIC stream itself provides the request/response correlation
        // the ID field exists for on UDP/TCP.
        let mut zeroed = message.to_vec();
        if zeroed.len() >= 2 {
            zeroed[0] = 0;
            zeroed[1] = 0;
        }
        let mut framed = Vec::with_capacity(2 + zeroed.len());
        framed.extend_from_slice(&(zeroed.len() as u16).to_be_bytes());
        framed.extend_from_slice(&zeroed);

        let slot: Arc<Mutex<Option<Box<dyn DnsClientTransportHandler>>>> =
            Arc::new(Mutex::new(Some(handler)));
        let factory: HandlerFactory = Arc::new({
            let slot = Arc::clone(&slot);
            let framed = framed.clone();
            move || {
                let h = slot.lock().unwrap().take();
                Box::new(DoqQueryHandler {
                    framed: framed.clone(),
                    sent: false,
                    buf: Vec::new(),
                    server,
                    handler: h,
                    delivered: false,
                }) as Box<dyn ProtocolHandler>
            }
        });
        let handle = connect_quic(QuicConnectConfig::new(
            server,
            Arc::clone(&self.client),
            self.server_name.clone(),
            factory,
        ))?;
        self.drivers.push(handle);
        Ok(())
    }
}

struct DoqQueryHandler {
    framed: Vec<u8>,
    sent: bool,
    buf: Vec<u8>,
    server: SocketAddr,
    handler: Option<Box<dyn DnsClientTransportHandler>>,
    delivered: bool,
}

impl DoqQueryHandler {
    fn deliver_ok(&mut self, raw: Vec<u8>) {
        if self.delivered {
            return;
        }
        self.delivered = true;
        if let Some(mut h) = self.handler.take() {
            h.on_response(self.server, &raw);
        }
    }

    fn deliver_err(&mut self, err: io::Error) {
        if self.delivered {
            return;
        }
        self.delivered = true;
        if let Some(mut h) = self.handler.take() {
            h.on_error(self.server, err);
        }
    }
}

impl ProtocolHandler for DoqQueryHandler {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        if !self.sent {
            endpoint.send(&self.framed);
            self.sent = true;
        }
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        self.buf.extend_from_slice(data);
        *data = &[];
        if self.buf.len() >= 2 {
            let len = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
            if self.buf.len() >= 2 + len {
                let raw = self.buf[2..2 + len].to_vec();
                self.deliver_ok(raw);
                endpoint.close();
            }
        }
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
        self.deliver_err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "DoQ closed before response",
        ));
    }

    fn error(&mut self, _endpoint: &mut dyn Endpoint, err: &io::Error) {
        self.deliver_err(io::Error::new(err.kind(), err.to_string()));
    }
}
