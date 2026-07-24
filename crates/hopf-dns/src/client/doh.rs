// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! DNS-over-HTTPS client (RFC 8484) — feature `doh`.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_core::{Endpoint, ProtocolHandler, Runtime, TcpConnectorConfig};

use crate::wire::{DnsMessage, DnsQuestion};

/// DoH client via HTTP/1.1 POST `application/dns-message`.
pub struct DohClientTransport {
    /// Host header / SNI.
    pub host: String,
    /// Path (default `/dns-query`).
    pub path: String,
    /// Optional TLS connector for HTTPS.
    pub tls: Option<hopf_core::SharedTlsConnector>,
}

impl DohClientTransport {
    /// HTTPS DoH to `host` (SNI) at `path`.
    pub fn https(
        host: impl Into<String>,
        path: impl Into<String>,
        tls: hopf_core::SharedTlsConnector,
    ) -> Self {
        Self {
            host: host.into(),
            path: path.into(),
            tls: Some(tls),
        }
    }

    /// Blocking query: dials `addr` on a temporary Runtime.
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
        let (tx, rx) = std::sync::mpsc::channel();
        let host = self.host.clone();
        let path = self.path.clone();
        let body = payload;
        let rt = Runtime::start(Default::default())?;
        let mut cfg = TcpConnectorConfig::new(addr, move || {
            Box::new(DohClientHandler {
                host: host.clone(),
                path: path.clone(),
                body: body.clone(),
                tx: Arc::new(Mutex::new(Some(tx.clone()))),
                started: false,
                buf: Vec::new(),
            }) as Box<dyn ProtocolHandler>
        });
        if let Some(ref tls) = self.tls {
            cfg = cfg.with_tls(Arc::clone(tls), self.host.clone());
        }
        rt.connect(cfg)?;
        let result = rx
            .recv_timeout(Duration::from_secs(15))
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DoH timed out"))?;
        rt.shutdown();
        result
    }
}

struct DohClientHandler {
    host: String,
    path: String,
    body: Vec<u8>,
    tx: Arc<Mutex<Option<std::sync::mpsc::Sender<io::Result<DnsMessage>>>>>,
    started: bool,
    buf: Vec<u8>,
}

impl ProtocolHandler for DohClientHandler {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        if self.started {
            return;
        }
        self.started = true;
        let mut req = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\nAccept: application/dns-message\r\n\r\n",
            self.path,
            self.host,
            self.body.len()
        )
        .into_bytes();
        req.extend_from_slice(&self.body);
        endpoint.send(&req);
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        self.buf.extend_from_slice(data);
        *data = &[];
        if let Some(pos) = find_header_end(&self.buf) {
            let body = &self.buf[pos..];
            let msg = DnsMessage::parse(body)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
            if let Some(tx) = self.tx.lock().unwrap().take() {
                let _ = tx.send(msg);
            }
            endpoint.close();
        }
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
        if let Some(tx) = self.tx.lock().unwrap().take() {
            let _ = tx.send(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "DoH closed before response",
            )));
        }
    }

    fn error(&mut self, _endpoint: &mut dyn Endpoint, err: &io::Error) {
        if let Some(tx) = self.tx.lock().unwrap().take() {
            let _ = tx.send(Err(io::Error::new(err.kind(), err.to_string())));
        }
    }
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
}
