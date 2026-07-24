// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! WebSocket opening handshake helpers (RFC 6455 §4, RFC 8441, RFC 9220).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use sha1::{Digest, Sha1};
use hopf_http::Headers;

/// RFC 6455 §1.3 GUID.
pub const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Required `Sec-WebSocket-Version`.
pub const WEBSOCKET_VERSION: &str = "13";

/// RFC 6455 §4.2.2 — `Sec-WebSocket-Accept` from client key.
pub fn calculate_accept(key: &str) -> String {
    let mut h = Sha1::new();
    h.update(key.as_bytes());
    h.update(WEBSOCKET_GUID.as_bytes());
    B64.encode(h.finalize())
}

/// Generate a random 16-byte client key (Base64).
pub fn generate_key() -> String {
    let mut raw = [0u8; 16];
    getrandom::getrandom(&mut raw).expect("getrandom");
    B64.encode(raw)
}

/// True if headers look like an HTTP/1.1 WebSocket upgrade (RFC 6455).
pub fn is_h1_websocket_upgrade(headers: &Headers) -> bool {
    let method = headers.get(":method").unwrap_or("");
    if !method.eq_ignore_ascii_case("GET") {
        return false;
    }
    let upgrade = headers.get("upgrade").unwrap_or("");
    if !upgrade.split(',').any(|p| p.trim().eq_ignore_ascii_case("websocket")) {
        return false;
    }
    let connection = headers.get("connection").unwrap_or("");
    if !connection
        .split(',')
        .any(|p| p.trim().eq_ignore_ascii_case("upgrade"))
    {
        return false;
    }
    let version = headers.get("sec-websocket-version").unwrap_or("");
    version.trim() == WEBSOCKET_VERSION
        && headers
            .get("sec-websocket-key")
            .map(|k| !k.trim().is_empty())
            .unwrap_or(false)
}

/// Validate H1 upgrade; returns the client key on success.
pub fn validate_h1_upgrade(headers: &Headers) -> Result<&str, &'static str> {
    if !is_h1_websocket_upgrade(headers) {
        return Err("not a websocket upgrade");
    }
    headers
        .get("sec-websocket-key")
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .ok_or("missing Sec-WebSocket-Key")
}

/// True if this is Extended CONNECT with `:protocol = websocket`.
pub fn is_extended_connect_websocket(headers: &Headers) -> bool {
    let method = headers.get(":method").unwrap_or("");
    if !method.eq_ignore_ascii_case("CONNECT") {
        return false;
    }
    headers
        .get(":protocol")
        .map(|p| p.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
}

/// Response headers for a successful H1 101 upgrade.
pub fn websocket_accept_headers(client_key: &str, subprotocol: Option<&str>) -> Headers {
    let mut h = Headers::new();
    h.set(":status", "101");
    h.set("Upgrade", "websocket");
    h.set("Connection", "Upgrade");
    h.set("Sec-WebSocket-Accept", calculate_accept(client_key));
    if let Some(sp) = subprotocol {
        h.set("Sec-WebSocket-Protocol", sp);
    }
    h
}

/// Response headers for successful Extended CONNECT (H2/H3) — `:status 200`.
pub fn websocket_connect_response_headers(subprotocol: Option<&str>) -> Headers {
    let mut h = Headers::new();
    h.set(":status", "200");
    if let Some(sp) = subprotocol {
        h.set("sec-websocket-protocol", sp);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_golden() {
        // RFC 6455 example
        let accept = calculate_accept("dGhlIHNhbXBsZSBub25jZQ==");
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn detects_h1_upgrade() {
        let mut h = Headers::new();
        h.set(":method", "GET");
        h.set("upgrade", "websocket");
        h.set("connection", "Upgrade");
        h.set("sec-websocket-version", "13");
        h.set("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");
        assert!(is_h1_websocket_upgrade(&h));
    }

    #[test]
    fn detects_ext_connect() {
        let mut h = Headers::new();
        h.set(":method", "CONNECT");
        h.set(":protocol", "websocket");
        h.set(":path", "/");
        assert!(is_extended_connect_websocket(&h));
    }
}
