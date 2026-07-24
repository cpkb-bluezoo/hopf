// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! DNS-over-QUIC client (RFC 9250) — feature `doq`.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hopf_core::{HandlerFactory, ProtocolHandler};
use hopf_quic::{connect_quic, QuicClientConfig, QuicConnectConfig};

use crate::wire::{DnsMessage, DnsQuestion};

/// ALPN for DoQ.
pub const ALPN_DOQ: &[u8] = b"doq";

/// DoQ client (one QUIC dial per query).
pub struct DoqClientTransport {
    client: Arc<QuicClientConfig>,
    server_name: String,
}

impl DoqClientTransport {
    /// `client` TLS config should advertise ALPN `doq`.
    pub fn new(client: Arc<QuicClientConfig>, server_name: impl Into<String>) -> Self {
        Self {
            client,
            server_name: server_name.into(),
        }
    }

    /// Blocking query (caller thread waits; I/O on QUIC driver).
    pub fn query(
        &self,
        addr: SocketAddr,
        question: &DnsQuestion,
        id: u16,
    ) -> io::Result<DnsMessage> {
        let msg = DnsMessage::query(id, question.clone(), true);
        let payload = msg
            .serialize()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let mut framed = Vec::with_capacity(2 + payload.len());
        framed.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        framed.extend_from_slice(&payload);

        let (tx, rx) = std::sync::mpsc::channel::<io::Result<DnsMessage>>();
        let framed2 = framed.clone();
        let tx2 = tx.clone();
        let factory: HandlerFactory = Arc::new(move || {
            Box::new(DoqQueryHandler {
                framed: framed2.clone(),
                sent: false,
                buf: Vec::new(),
                tx: Some(tx2.clone()),
            }) as Box<dyn ProtocolHandler>
        });
        let handle = connect_quic(QuicConnectConfig::new(
            addr,
            Arc::clone(&self.client),
            self.server_name.clone(),
            factory,
        ))?;
        let result = rx
            .recv_timeout(Duration::from_secs(10))
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DoQ timed out"))?;
        handle.shutdown();
        result
    }
}

struct DoqQueryHandler {
    framed: Vec<u8>,
    sent: bool,
    buf: Vec<u8>,
    tx: Option<std::sync::mpsc::Sender<io::Result<DnsMessage>>>,
}

impl ProtocolHandler for DoqQueryHandler {
    fn connected(&mut self, endpoint: &mut dyn hopf_core::Endpoint) {
        if !self.sent {
            endpoint.send(&self.framed);
            self.sent = true;
        }
    }

    fn receive(&mut self, endpoint: &mut dyn hopf_core::Endpoint, data: &mut &[u8]) {
        self.buf.extend_from_slice(data);
        *data = &[];
        if self.buf.len() >= 2 {
            let len = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
            if self.buf.len() >= 2 + len {
                let msg = DnsMessage::parse(&self.buf[2..2 + len])
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
                if let Some(tx) = self.tx.take() {
                    let _ = tx.send(msg);
                }
                endpoint.close();
            }
        }
    }

    fn disconnected(&mut self, _endpoint: &mut dyn hopf_core::Endpoint) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "DoQ closed",
            )));
        }
    }

    fn error(&mut self, _endpoint: &mut dyn hopf_core::Endpoint, err: &io::Error) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(Err(io::Error::new(err.kind(), err.to_string())));
        }
    }
}
