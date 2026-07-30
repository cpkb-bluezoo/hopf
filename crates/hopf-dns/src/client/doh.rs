// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! DNS-over-HTTPS client (RFC 8484) — feature `doh`.
//!
//! Implements [`DnsClientTransport`]: each `send_query` dials on the shared
//! [`Runtime`] and delivers the response via [`DnsClientTransportHandler`]
//! callbacks — no caller-thread wait, no channels.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_core::{Endpoint, ProtocolHandler, Runtime, SharedTlsConnector, TcpConnectorConfig};

use super::{DnsClientTransport, DnsClientTransportHandler, DEFAULT_TIMEOUT};

/// DoH client via HTTP/1.1, `application/dns-message` (RFC 8484 §4.1).
pub struct DohClientTransport {
    /// Runtime used for dials.
    runtime: Arc<Runtime>,
    /// Host header / SNI.
    pub host: String,
    /// Path (default `/dns-query`).
    pub path: String,
    /// Optional TLS connector for HTTPS.
    pub tls: Option<SharedTlsConnector>,
    /// TCP connect timeout for DoH dials.
    pub connect_timeout: Option<Duration>,
    /// Use GET (base64url `dns` query parameter) instead of POST — both
    /// are RFC 8484-compliant; GET lets an intermediate cache identical
    /// queries by URL. `false` (POST) by default.
    pub use_get: bool,
}

impl DohClientTransport {
    /// HTTPS DoH to `host` (SNI) at `path`, dialing on `runtime`. Uses
    /// POST by default — see [`Self::use_get`] to switch to GET.
    pub fn https(
        runtime: Arc<Runtime>,
        host: impl Into<String>,
        path: impl Into<String>,
        tls: SharedTlsConnector,
    ) -> Self {
        Self {
            runtime,
            host: host.into(),
            path: path.into(),
            tls: Some(tls),
            connect_timeout: Some(DEFAULT_TIMEOUT),
            use_get: false,
        }
    }

    /// Use GET instead of POST for subsequent queries (RFC 8484 §4.1).
    pub fn with_get(mut self, use_get: bool) -> Self {
        self.use_get = use_get;
        self
    }
}

impl DnsClientTransport for DohClientTransport {
    fn send_query(
        &mut self,
        server: SocketAddr,
        message: &[u8],
        handler: Box<dyn DnsClientTransportHandler>,
    ) -> io::Result<()> {
        let host = self.host.clone();
        let path = self.path.clone();
        let body = message.to_vec();
        let use_get = self.use_get;
        let slot: Arc<Mutex<Option<Box<dyn DnsClientTransportHandler>>>> =
            Arc::new(Mutex::new(Some(handler)));
        let mut cfg = TcpConnectorConfig::new(server, {
            let slot = Arc::clone(&slot);
            move || {
                let h = slot.lock().unwrap().take();
                Box::new(DohClientHandler {
                    host: host.clone(),
                    path: path.clone(),
                    body: body.clone(),
                    use_get,
                    server,
                    handler: h,
                    started: false,
                    buf: Vec::new(),
                    delivered: false,
                }) as Box<dyn ProtocolHandler>
            }
        });
        if let Some(ref tls) = self.tls {
            cfg = cfg.with_tls(Arc::clone(tls), self.host.clone());
        }
        if let Some(t) = self.connect_timeout {
            cfg = cfg.connect_timeout(Some(t));
        }
        self.runtime.connect(cfg)
    }
}

struct DohClientHandler {
    host: String,
    path: String,
    body: Vec<u8>,
    use_get: bool,
    server: SocketAddr,
    handler: Option<Box<dyn DnsClientTransportHandler>>,
    started: bool,
    buf: Vec<u8>,
    delivered: bool,
}

impl DohClientHandler {
    fn deliver_ok(&mut self, body: Vec<u8>) {
        if self.delivered {
            return;
        }
        self.delivered = true;
        if let Some(mut h) = self.handler.take() {
            h.on_response(self.server, &body);
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

impl ProtocolHandler for DohClientHandler {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        if self.started {
            return;
        }
        self.started = true;
        let req = if self.use_get {
            // RFC 8484 §4.1: the DNS wire message base64url-encoded
            // (unpadded) into the `dns` query parameter; no body.
            let encoded = base64url_encode(&self.body);
            let sep = if self.path.contains('?') { '&' } else { '?' };
            format!(
                "GET {}{}dns={} HTTP/1.1\r\nHost: {}\r\nAccept: application/dns-message\r\nConnection: close\r\n\r\n",
                self.path, sep, encoded, self.host
            )
            .into_bytes()
        } else {
            let mut req = format!(
                "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\nAccept: application/dns-message\r\n\r\n",
                self.path, self.host, self.body.len()
            )
            .into_bytes();
            req.extend_from_slice(&self.body);
            req
        };
        endpoint.send(&req);
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        self.buf.extend_from_slice(data);
        *data = &[];
        if let Some(header_end) = find_header_end(&self.buf) {
            if let Some(content_length) = find_content_length(&self.buf[..header_end]) {
                let body_end = header_end + content_length;
                if self.buf.len() >= body_end {
                    let body = self.buf[header_end..body_end].to_vec();
                    self.deliver_ok(body);
                    endpoint.close();
                }
            }
        }
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
        if self.delivered {
            return;
        }
        if let Some(header_end) = find_header_end(&self.buf) {
            if !self.buf[header_end..].is_empty() {
                let body = self.buf[header_end..].to_vec();
                self.deliver_ok(body);
                return;
            }
        }
        self.deliver_err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "DoH closed before response",
        ));
    }

    fn error(&mut self, _endpoint: &mut dyn Endpoint, err: &io::Error) {
        self.deliver_err(io::Error::new(err.kind(), err.to_string()));
    }
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
}

fn find_content_length(headers: &[u8]) -> Option<usize> {
    let s = std::str::from_utf8(headers).ok()?;
    for line in s.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("content-length:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

const BASE64URL_ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Unpadded base64url (RFC 4648 §5) — the `dns` query parameter's encoding
/// for a GET request (RFC 8484 §4.1).
fn base64url_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied();
        let b2 = chunk.get(2).copied();
        out.push(BASE64URL_ALPHABET[(b0 >> 2) as usize] as char);
        out.push(BASE64URL_ALPHABET[(((b0 & 0x03) << 4) | (b1.unwrap_or(0) >> 4)) as usize] as char);
        if let Some(b1) = b1 {
            out.push(BASE64URL_ALPHABET[(((b1 & 0x0F) << 2) | (b2.unwrap_or(0) >> 6)) as usize] as char);
        }
        if let Some(b2) = b2 {
            out.push(BASE64URL_ALPHABET[(b2 & 0x3F) as usize] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_header_and_length() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nabcdefghijkl";
        let end = find_header_end(raw).unwrap();
        assert_eq!(find_content_length(&raw[..end]), Some(12));
        assert_eq!(&raw[end..], b"abcdefghijkl");
    }

    #[test]
    fn base64url_encode_matches_known_vectors() {
        // RFC 4648 §10 test vectors, re-expressed unpadded/URL-safe (none
        // of these particular inputs contain '+'/'/' chars anyway, but the
        // no-padding behavior is the thing under test).
        assert_eq!(base64url_encode(b""), "");
        assert_eq!(base64url_encode(b"f"), "Zg");
        assert_eq!(base64url_encode(b"fo"), "Zm8");
        assert_eq!(base64url_encode(b"foo"), "Zm9v");
        assert_eq!(base64url_encode(b"foob"), "Zm9vYg");
        assert_eq!(base64url_encode(b"fooba"), "Zm9vYmE");
        assert_eq!(base64url_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn base64url_encode_uses_url_safe_alphabet() {
        // Bytes that would produce '+' (0x3E) and '/' (0x3F) in standard
        // base64 must instead produce '-' and '_'.
        let encoded = base64url_encode(&[0xFB, 0xFF]);
        assert!(!encoded.contains('+') && !encoded.contains('/'));
        assert!(encoded.contains('-') || encoded.contains('_'));
    }
}
