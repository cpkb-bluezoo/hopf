// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Cleartext (non-TLS) HTTP dispatcher: sniffs for HTTP/2 prior-knowledge
//! and h2c Upgrade, falling back to HTTP/1.1.
//!
//! # Protocol selection
//!
//! ```text
//! first bytes == "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
//!   → H2 prior-knowledge (RFC 9113 §3.4)
//!
//! else first H1 request headers contain
//!     Connection: Upgrade, Upgrade: h2c, HTTP2-Settings: <base64url>
//!   → send 101 Switching Protocols
//!   → wait for H2 client preface
//!   → H2 via Upgrade (RFC 7540 §3.2 / RFC 9113)
//!
//! else
//!   → HTTP/1.1 (H1Endpoint::server)
//! ```
//!
//! Use [`CleartextHttpEndpoint`] as the [`ProtocolHandler`] factory for a
//! plaintext TCP listener when you want `curl --http2-prior-knowledge` support
//! as well as normal H1 and h2c Upgrade.

use std::sync::Arc;

use hopf_core::{Endpoint, ProtocolHandler, SecurityInfo};

use crate::h1::H1Endpoint;
use crate::h2::H2Endpoint;
use crate::headers::Headers;
use crate::limits::HttpLimits;
use crate::stream::ServerHandlerFactory;

use super::base64url;
use super::endpoint::CLIENT_PREFACE;

// ---------------------------------------------------------------------------
// Phase
// ---------------------------------------------------------------------------

enum Phase {
    /// Waiting for enough bytes to identify the protocol.
    Sniff,
    /// Identified as HTTP/1.1; inner handles everything.
    H1(H1Endpoint),
    /// H1 request identified as h2c Upgrade; 101 sent; awaiting client preface.
    WaitPreface(Headers),
    /// Full H2 connection (prior-knowledge or post-upgrade).
    H2(H2Endpoint),
}

// ---------------------------------------------------------------------------
// CleartextHttpEndpoint
// ---------------------------------------------------------------------------

/// Cleartext HTTP endpoint that auto-detects H2 prior-knowledge and h2c
/// Upgrade, falling back to HTTP/1.1.
///
/// Register one instance per accepted TCP connection:
/// ```no_run
/// use std::sync::Arc;
/// use hopf_http::{CleartextHttpEndpoint, HttpLimits, ServerHandlerFactory};
/// # use hopf_http::ServerHandler;
/// # struct F; impl ServerHandlerFactory for F { fn create_handler(&self) -> Box<dyn ServerHandler> { todo!() } }
/// let factory: Arc<dyn ServerHandlerFactory> = Arc::new(F);
/// let ep = CleartextHttpEndpoint::new(factory, HttpLimits::default());
/// ```
pub struct CleartextHttpEndpoint {
    factory: Arc<dyn ServerHandlerFactory>,
    limits: HttpLimits,
    buf: Vec<u8>,
    phase: Phase,
    was_connected: bool,
}

impl CleartextHttpEndpoint {
    /// Create a new cleartext endpoint using `factory` for application handlers.
    pub fn new(factory: Arc<dyn ServerHandlerFactory>, limits: HttpLimits) -> Self {
        Self {
            factory,
            limits,
            buf: Vec::new(),
            phase: Phase::Sniff,
            was_connected: false,
        }
    }

    // -----------------------------------------------------------------------
    // Internal protocol detection
    // -----------------------------------------------------------------------

    /// Try to advance out of `Sniff`. Returns `true` if the phase changed.
    fn try_sniff(&mut self, endpoint: &mut dyn Endpoint) -> bool {
        if self.buf.len() < 3 {
            return false;
        }

        if self.buf.starts_with(b"PRI") {
            // Likely HTTP/2 prior-knowledge preface.
            if self.buf.len() < CLIENT_PREFACE.len() {
                return false; // wait for more bytes
            }
            if &self.buf[..CLIENT_PREFACE.len()] == CLIENT_PREFACE {
                // Drain the preface; H2Endpoint will start in ExpectSettings.
                self.buf.drain(..CLIENT_PREFACE.len());
                let mut h2ep = H2Endpoint::server(
                    Arc::clone(&self.factory),
                    self.limits,
                    true, // send_settings_on_connected: triggers from connected()
                );
                if self.was_connected {
                    h2ep.connected(endpoint);
                }
                // Feed buffered remainder.
                if !self.buf.is_empty() {
                    let remainder = std::mem::take(&mut self.buf);
                    let mut slice: &[u8] = &remainder;
                    h2ep.receive(endpoint, &mut slice);
                }
                self.phase = Phase::H2(h2ep);
                return true;
            }
            // Not a valid preface (bytes happened to start with PRI but don't
            // match fully) — fall through to H1.
        }

        // Try to detect h2c Upgrade vs plain H1.
        // We need at least the end of headers (\r\n\r\n) before deciding.
        if let Some(end) = find_double_crlf(&self.buf) {
            let header_bytes = self.buf[..end].to_vec();
            if let Some((method, path, host, headers)) = parse_h1_request_head(&header_bytes) {
                if is_h2c_upgrade(&headers) {
                    let upgrade_headers = to_h2_request_headers(&method, &path, &host, &headers);
                    // Send 101 Switching Protocols directly on the transport.
                    endpoint.send(
                        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n",
                    );
                    self.phase = Phase::WaitPreface(upgrade_headers);
                    // Discard the H1 request bytes; body data (if any) is in
                    // the remainder after the header block, but h2c upgrade
                    // expects the request body to have been drained already.
                    self.buf.drain(..end);
                    return true;
                } else {
                    // Plain H1.
                    let buffered = std::mem::take(&mut self.buf);
                    let mut h1ep = H1Endpoint::server(
                        Arc::clone(&self.factory),
                        self.limits,
                        false,
                    );
                    if self.was_connected {
                        h1ep.connected(endpoint);
                    }
                    let mut slice: &[u8] = &buffered;
                    h1ep.receive(endpoint, &mut slice);
                    self.phase = Phase::H1(h1ep);
                    return true;
                }
            }
            // parse failed (malformed) — fall back to H1
            let buffered = std::mem::take(&mut self.buf);
            let mut h1ep = H1Endpoint::server(Arc::clone(&self.factory), self.limits, false);
            if self.was_connected {
                h1ep.connected(endpoint);
            }
            let mut slice: &[u8] = &buffered;
            h1ep.receive(endpoint, &mut slice);
            self.phase = Phase::H1(h1ep);
            return true;
        }

        // Not enough data yet.
        false
    }

    /// Try to advance out of `WaitPreface`. Returns `true` on success.
    fn try_wait_preface(&mut self, endpoint: &mut dyn Endpoint) -> bool {
        if self.buf.len() < CLIENT_PREFACE.len() {
            return false;
        }

        let upgrade_headers = match &self.phase {
            Phase::WaitPreface(h) => h.clone(),
            _ => return false,
        };

        if &self.buf[..CLIENT_PREFACE.len()] != CLIENT_PREFACE {
            // Client sent garbage instead of the preface — close.
            endpoint.close();
            return false;
        }

        self.buf.drain(..CLIENT_PREFACE.len());

        let mut h2ep = H2Endpoint::server_after_h2c_upgrade(
            Arc::clone(&self.factory),
            self.limits,
            upgrade_headers,
        );
        // Send our server SETTINGS now (preface consumed, state→ExpectSettings).
        h2ep.send_server_settings(endpoint);

        // Feed any data that arrived after the preface.
        if !self.buf.is_empty() {
            let remainder = std::mem::take(&mut self.buf);
            let mut slice: &[u8] = &remainder;
            h2ep.receive(endpoint, &mut slice);
        }

        self.phase = Phase::H2(h2ep);
        true
    }
}

// ---------------------------------------------------------------------------
// ProtocolHandler impl
// ---------------------------------------------------------------------------

impl ProtocolHandler for CleartextHttpEndpoint {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        self.was_connected = true;
        match &mut self.phase {
            Phase::H1(ep) => ep.connected(endpoint),
            Phase::H2(ep) => ep.connected(endpoint),
            _ => {}
        }
    }

    fn security_established(&mut self, endpoint: &mut dyn Endpoint, info: &SecurityInfo) {
        match &mut self.phase {
            Phase::H1(ep) => ep.security_established(endpoint, info),
            Phase::H2(ep) => ep.security_established(endpoint, info),
            _ => {}
        }
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        match &mut self.phase {
            Phase::H1(ep) => {
                ep.receive(endpoint, data);
                return;
            }
            Phase::H2(ep) => {
                ep.receive(endpoint, data);
                return;
            }
            Phase::Sniff => {
                self.buf.extend_from_slice(data);
                *data = &[];
                self.try_sniff(endpoint);
            }
            Phase::WaitPreface(_) => {
                self.buf.extend_from_slice(data);
                *data = &[];
                self.try_wait_preface(endpoint);
            }
        }
    }

    fn disconnected(&mut self, endpoint: &mut dyn Endpoint) {
        match &mut self.phase {
            Phase::H1(ep) => ep.disconnected(endpoint),
            Phase::H2(ep) => ep.disconnected(endpoint),
            _ => {}
        }
    }

    fn error(&mut self, endpoint: &mut dyn Endpoint, err: &std::io::Error) {
        match &mut self.phase {
            Phase::H1(ep) => ep.error(endpoint, err),
            Phase::H2(ep) => ep.error(endpoint, err),
            _ => endpoint.close(),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Find the end of HTTP/1.x headers (position after the first `\r\n\r\n`).
fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    for i in 0..buf.len().saturating_sub(3) {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' && buf[i + 2] == b'\r' && buf[i + 3] == b'\n' {
            return Some(i + 4);
        }
    }
    None
}

/// Check whether the parsed H1 headers indicate an h2c Upgrade request.
///
/// Requires all three of:
/// - `Connection: Upgrade` (token present in Connection list)
/// - `Upgrade: h2c` (token present in Upgrade list)
/// - `HTTP2-Settings` header that is valid base64url of a multiple-of-6 bytes
pub(crate) fn is_h2c_upgrade(headers: &Headers) -> bool {
    let connection_upgrade = headers
        .get("connection")
        .map(|v| {
            v.split(',')
                .any(|p| p.trim().eq_ignore_ascii_case("upgrade"))
        })
        .unwrap_or(false);

    let upgrade_h2c = headers
        .get("upgrade")
        .map(|v| v.split(',').any(|p| p.trim().eq_ignore_ascii_case("h2c")))
        .unwrap_or(false);

    let valid_settings = headers
        .get("http2-settings")
        .map(|v| {
            base64url::decode(v.trim())
                .map(|d| d.len() % 6 == 0)
                .unwrap_or(false)
        })
        .unwrap_or(false);

    connection_upgrade && upgrade_h2c && valid_settings
}

/// Convert H1 request components to H2 pseudo-headers.
///
/// Copies `method`, `path`, sets `:scheme = http`, maps `host` → `:authority`.
/// Excludes connection-specific and upgrade headers.
pub(crate) fn to_h2_request_headers(
    method: &str,
    path: &str,
    host: &str,
    headers: &Headers,
) -> Headers {
    let mut h = Headers::new();
    h.add(":method", method);
    h.add(":path", path);
    h.add(":scheme", "http");
    h.add(":authority", host);
    for header in headers.iter() {
        let name_lc = header.name.to_ascii_lowercase();
        if !matches!(
            name_lc.as_str(),
            "connection" | "upgrade" | "http2-settings" | "host" | "keep-alive"
                | "proxy-connection" | "transfer-encoding" | "te"
        ) {
            h.add(&header.name, &header.value);
        }
    }
    h
}

/// Minimally parse the request line + header fields from H1 header bytes.
///
/// Returns `(method, path, host, Headers)` or `None` on malformed input.
fn parse_h1_request_head(data: &[u8]) -> Option<(String, String, String, Headers)> {
    let text = std::str::from_utf8(data).ok()?;
    let mut lines = text.split("\r\n");

    let req_line = lines.next()?;
    let mut parts = req_line.splitn(3, ' ');
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    // version — present but we don't need it here

    let mut headers = Headers::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some(colon) = line.find(':') {
            let name = line[..colon].trim().to_string();
            let value = line[colon + 1..].trim().to_string();
            headers.add(name, value);
        }
    }

    let host = headers
        .get("host")
        .unwrap_or("localhost")
        .to_string();
    Some((method, path, host, headers))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h2c_upgrade_detection() {
        let mut h = Headers::new();
        h.add("connection", "Upgrade");
        h.add("upgrade", "h2c");
        h.add("http2-settings", "AAIAAAAA"); // ENABLE_PUSH=0, 6 bytes
        assert!(is_h2c_upgrade(&h));
    }

    #[test]
    fn h2c_upgrade_missing_settings() {
        let mut h = Headers::new();
        h.add("connection", "Upgrade");
        h.add("upgrade", "h2c");
        // no http2-settings
        assert!(!is_h2c_upgrade(&h));
    }

    #[test]
    fn h2c_upgrade_bad_settings_non_multiple_of_six() {
        let mut h = Headers::new();
        h.add("connection", "Upgrade");
        h.add("upgrade", "h2c");
        h.add("http2-settings", "AAIAA"); // 4 bytes — not multiple of 6
        assert!(!is_h2c_upgrade(&h));
    }
}
