// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! DNS-over-QUIC client (RFC 9250) — feature `doq`.
//!
//! Implements [`DnsClientTransport`]: each `send_query` opens a client-
//! initiated bidirectional QUIC stream (RFC 9250 §4.2). Connections are
//! pooled per destination and reused across queries (RFC 9250 §5.5.1)
//! rather than dialled fresh every time — matching [`super::TcpDnsConnectionPool`]
//! for TCP/DoT.
//!
//! Driver handles are retained on the pool until it is dropped (dropping a
//! [`QuicDriverHandle`] shuts down the driver).
//!
//! **0-RTT / session resumption:** reusing a live connection avoids a full
//! handshake on subsequent queries. hopf-quic enables TLS early-data at the
//! config layer, but a fresh dial after the pooled connection is gone does
//! not yet perform ticket-based 0-RTT resume (no session-ticket cache is
//! wired through); that remains a config-only capability, same as H3.

use std::collections::HashMap;
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

struct DoqPoolEntry {
    handle: QuicDriverHandle,
    server_name: String,
    client: Arc<QuicClientConfig>,
}

/// Persistent DoQ connection pool (RFC 9250 §5.5.1): a live QUIC connection
/// per destination is kept and reused across queries; each query opens a
/// new client-initiated bidirectional stream (RFC 9250 §4.2). A reused
/// connection that turns out to be gone is transparently replaced with a
/// fresh dial.
pub struct DoqConnectionPool {
    entries: HashMap<SocketAddr, DoqPoolEntry>,
}

impl Default for DoqConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

impl DoqConnectionPool {
    /// New empty pool.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Number of live pooled drivers (test/introspection aid).
    pub fn pooled_connections(&self) -> usize {
        self.entries.len()
    }

    /// Length-prefixed DoQ query on a dedicated stream, reusing a pooled
    /// connection to `server` when one is available with matching identity.
    pub fn send_query(
        &mut self,
        server: SocketAddr,
        client: &Arc<QuicClientConfig>,
        server_name: &str,
        message: &[u8],
        handler: Box<dyn DnsClientTransportHandler>,
    ) -> io::Result<()> {
        let factory = make_query_factory(server, message, handler);

        let can_reuse = self.entries.get(&server).is_some_and(|e| {
            e.server_name == server_name
                && Arc::ptr_eq(&e.client, client)
                && e.handle.is_active()
        });

        if can_reuse {
            if let Some(entry) = self.entries.get(&server) {
                if entry.handle.open_bi(Arc::clone(&factory)).is_ok() {
                    return Ok(());
                }
            }
            // Stale (peer closed / idle timeout) — drop and fall through.
            self.entries.remove(&server);
        } else {
            self.entries.remove(&server);
        }

        let handle = connect_quic(QuicConnectConfig::new(
            server,
            Arc::clone(client),
            server_name.to_string(),
            factory,
        ))?;
        self.entries.insert(
            server,
            DoqPoolEntry {
                handle,
                server_name: server_name.to_string(),
                client: Arc::clone(client),
            },
        );
        Ok(())
    }
}

/// DoQ client transport — thin wrapper around [`DoqConnectionPool`] for a
/// fixed TLS identity (`client` + SNI). Prefer sharing one
/// [`DoqConnectionPool`] across identities via the resolver when possible.
pub struct DoqClientTransport {
    client: Arc<QuicClientConfig>,
    server_name: String,
    pool: DoqConnectionPool,
}

impl DoqClientTransport {
    /// `client` TLS config should advertise ALPN `doq`.
    pub fn new(client: Arc<QuicClientConfig>, server_name: impl Into<String>) -> Self {
        Self {
            client,
            server_name: server_name.into(),
            pool: DoqConnectionPool::new(),
        }
    }

    /// Number of live pooled drivers on this transport.
    pub fn pooled_connections(&self) -> usize {
        self.pool.pooled_connections()
    }
}

impl DnsClientTransport for DoqClientTransport {
    fn send_query(
        &mut self,
        server: SocketAddr,
        message: &[u8],
        handler: Box<dyn DnsClientTransportHandler>,
    ) -> io::Result<()> {
        self.pool
            .send_query(server, &self.client, &self.server_name, message, handler)
    }
}

fn make_query_factory(
    server: SocketAddr,
    message: &[u8],
    handler: Box<dyn DnsClientTransportHandler>,
) -> HandlerFactory {
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
    Arc::new({
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
    })
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
            // RFC 9250 §4.2: client MUST FIN the send side after the query;
            // the stream stays readable for the response.
            endpoint.close();
        }
    }

    fn receive(&mut self, _endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        self.buf.extend_from_slice(data);
        *data = &[];
        if self.buf.len() >= 2 {
            let len = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
            if self.buf.len() >= 2 + len {
                let raw = self.buf[2..2 + len].to_vec();
                self.deliver_ok(raw);
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
