// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! WebSocket opening handshake helpers (RFC 6455 §4, RFC 8441, RFC 9220).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hopf_http::Headers;
use sha1::{Digest, Sha1};

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
    if !upgrade
        .split(',')
        .any(|p| p.trim().eq_ignore_ascii_case("websocket"))
    {
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

/// Select a subprotocol from the client's `Sec-WebSocket-Protocol` offer.
///
/// Returns `Some(configured)` only when the client offered that token
/// (comma-separated list, case-sensitive token match per RFC 6455 §4.2.2 /
/// RFC 2616 token rules as used by browsers). Returns `None` when the
/// server has no preferred protocol, or the client did not offer it —
/// never echo a protocol the client did not request.
pub fn negotiate_subprotocol<'a>(
    headers: &Headers,
    configured: Option<&'a str>,
) -> Option<&'a str> {
    let configured = configured?;
    let offer = headers.get("sec-websocket-protocol").unwrap_or("");
    if offer
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .any(|t| t == configured)
    {
        Some(configured)
    } else {
        None
    }
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

/// Build client upgrade request headers (RFC 6455 §4.1), excluding `:method` /
/// `:path` / `Host` which the HTTP client sets separately.
pub fn create_upgrade_request(key: &str, subprotocol: Option<&str>) -> Headers {
    let mut h = Headers::new();
    h.set("Upgrade", "websocket");
    h.set("Connection", "Upgrade");
    h.set("Sec-WebSocket-Version", WEBSOCKET_VERSION);
    h.set("Sec-WebSocket-Key", key);
    if let Some(sp) = subprotocol {
        let sp = sp.trim();
        if !sp.is_empty() {
            h.set("Sec-WebSocket-Protocol", sp);
        }
    }
    h
}

fn header_token_list_contains(value: &str, needle: &str) -> bool {
    value
        .split(',')
        .map(str::trim)
        .any(|p| p.eq_ignore_ascii_case(needle))
}

/// RFC 6455 §4.1 step 5 — validate the server's `101 Switching Protocols`
/// response before entering the WebSocket session.
///
/// Checks status is 101, `Upgrade` contains `websocket`, `Connection`
/// contains `Upgrade`, and `Sec-WebSocket-Accept` matches
/// [`calculate_accept`] for `sent_key`.
///
/// When `offered_subprotocol` is `Some(p)`, a response
/// `Sec-WebSocket-Protocol` (if present) must equal `p`. Omitting the header
/// is allowed (no subprotocol selected). An unexpected token fails the
/// handshake (RFC 6455 §4.1).
///
/// Returns the negotiated subprotocol from the response (`None` if omitted).
pub fn validate_upgrade_response(
    sent_key: &str,
    response: &Headers,
    offered_subprotocol: Option<&str>,
) -> Result<Option<String>, &'static str> {
    let status = response.status_code();
    if status != 101 {
        return Err("expected 101 Switching Protocols");
    }

    let upgrade = response.get("upgrade").unwrap_or("");
    if !header_token_list_contains(upgrade, "websocket") {
        return Err("missing Upgrade: websocket");
    }

    let connection = response.get("connection").unwrap_or("");
    if !header_token_list_contains(connection, "upgrade") {
        return Err("missing Connection: Upgrade");
    }

    let accept = response
        .get("sec-websocket-accept")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or("missing Sec-WebSocket-Accept")?;
    let expected = calculate_accept(sent_key);
    if accept != expected {
        return Err("Sec-WebSocket-Accept mismatch");
    }

    let negotiated = response
        .get("sec-websocket-protocol")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    if let Some(ref got) = negotiated {
        match offered_subprotocol {
            Some(offered) if got == offered => {}
            Some(_) => return Err("Sec-WebSocket-Protocol mismatch"),
            None => return Err("unexpected Sec-WebSocket-Protocol"),
        }
    }

    Ok(negotiated)
}

/// Client-side state for one H1 WebSocket opening handshake.
///
/// Generate a key, write the upgrade request via [`Self::write_request`], then
/// call [`Self::validate_response`] from `ClientHandler::switching_protocols`
/// **before** installing [`crate::WsUpgradeHandler::client`]. On `Err`, do not
/// enter the WebSocket session.
#[derive(Debug, Clone)]
pub struct WebSocketOpening {
    key: String,
    subprotocol: Option<String>,
}

impl WebSocketOpening {
    /// New opening with a fresh random key and optional offered subprotocol.
    pub fn new(subprotocol: Option<String>) -> Self {
        Self {
            key: generate_key(),
            subprotocol,
        }
    }

    /// Opening with an explicit key (tests / golden vectors).
    pub fn with_key(key: impl Into<String>, subprotocol: Option<String>) -> Self {
        Self {
            key: key.into(),
            subprotocol,
        }
    }

    /// The `Sec-WebSocket-Key` sent on the wire.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Subprotocol offered to the server, if any.
    pub fn offered_subprotocol(&self) -> Option<&str> {
        self.subprotocol.as_deref()
    }

    /// Write `GET` upgrade request headers + empty body completion onto `request`.
    pub fn write_request(
        &self,
        request: &mut dyn hopf_http::ClientWriter,
        path: &str,
        host: &str,
    ) {
        let mut h = create_upgrade_request(&self.key, self.subprotocol.as_deref());
        h.set(":method", "GET");
        h.set(":path", path);
        h.set("host", host);
        request.headers(h);
        request.complete_request();
    }

    /// Validate a `101` response for this opening (see [`validate_upgrade_response`]).
    pub fn validate_response(&self, response: &Headers) -> Result<Option<String>, &'static str> {
        validate_upgrade_response(&self.key, response, self.subprotocol.as_deref())
    }
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

    #[test]
    fn negotiates_subprotocol_from_offer() {
        let mut h = Headers::new();
        h.set("sec-websocket-protocol", "chat, superchat");
        assert_eq!(
            negotiate_subprotocol(&h, Some("superchat")),
            Some("superchat")
        );
        assert_eq!(negotiate_subprotocol(&h, Some("other")), None);
        assert_eq!(negotiate_subprotocol(&h, None), None);
    }

    #[test]
    fn no_echo_when_client_omits_protocol() {
        let h = Headers::new();
        assert_eq!(negotiate_subprotocol(&h, Some("chat")), None);
    }

    #[test]
    fn validate_golden_101_response() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let response = websocket_accept_headers(key, None);
        assert_eq!(validate_upgrade_response(key, &response, None), Ok(None));
    }

    #[test]
    fn validate_rejects_non_101() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let mut response = websocket_accept_headers(key, None);
        response.set(":status", "200");
        assert_eq!(
            validate_upgrade_response(key, &response, None),
            Err("expected 101 Switching Protocols")
        );
    }

    #[test]
    fn validate_rejects_missing_upgrade() {
        let key = generate_key();
        let mut response = Headers::new();
        response.set(":status", "101");
        response.set("Connection", "Upgrade");
        response.set("Sec-WebSocket-Accept", calculate_accept(&key));
        assert_eq!(
            validate_upgrade_response(&key, &response, None),
            Err("missing Upgrade: websocket")
        );
    }

    #[test]
    fn validate_rejects_missing_connection() {
        let key = generate_key();
        let mut response = Headers::new();
        response.set(":status", "101");
        response.set("Upgrade", "websocket");
        response.set("Sec-WebSocket-Accept", calculate_accept(&key));
        assert_eq!(
            validate_upgrade_response(&key, &response, None),
            Err("missing Connection: Upgrade")
        );
    }

    #[test]
    fn validate_rejects_missing_accept() {
        let key = generate_key();
        let mut response = Headers::new();
        response.set(":status", "101");
        response.set("Upgrade", "websocket");
        response.set("Connection", "Upgrade");
        assert_eq!(
            validate_upgrade_response(&key, &response, None),
            Err("missing Sec-WebSocket-Accept")
        );
    }

    #[test]
    fn validate_rejects_wrong_accept() {
        let key = generate_key();
        let mut response = Headers::new();
        response.set(":status", "101");
        response.set("Upgrade", "websocket");
        response.set("Connection", "Upgrade");
        response.set("Sec-WebSocket-Accept", "wrongvalue");
        assert_eq!(
            validate_upgrade_response(&key, &response, None),
            Err("Sec-WebSocket-Accept mismatch")
        );
    }

    #[test]
    fn validate_rejects_accept_for_other_key() {
        let key1 = generate_key();
        let key2 = generate_key();
        let response = websocket_accept_headers(&key2, None);
        assert_eq!(
            validate_upgrade_response(&key1, &response, None),
            Err("Sec-WebSocket-Accept mismatch")
        );
    }

    #[test]
    fn validate_subprotocol_echo_rules() {
        let key = generate_key();
        let with_chat = websocket_accept_headers(&key, Some("chat"));
        assert_eq!(
            validate_upgrade_response(&key, &with_chat, Some("chat")),
            Ok(Some("chat".into()))
        );
        assert_eq!(
            validate_upgrade_response(&key, &with_chat, Some("other")),
            Err("Sec-WebSocket-Protocol mismatch")
        );
        assert_eq!(
            validate_upgrade_response(&key, &with_chat, None),
            Err("unexpected Sec-WebSocket-Protocol")
        );
        let bare = websocket_accept_headers(&key, None);
        // Server may omit protocol even when the client offered one.
        assert_eq!(
            validate_upgrade_response(&key, &bare, Some("chat")),
            Ok(None)
        );
    }

    #[test]
    fn opening_round_trip_with_protocol() {
        let opening = WebSocketOpening::with_key(generate_key(), Some("chat".into()));
        let request = create_upgrade_request(opening.key(), opening.offered_subprotocol());
        assert_eq!(request.get("sec-websocket-key"), Some(opening.key()));
        assert_eq!(request.get("sec-websocket-protocol"), Some("chat"));
        let response = websocket_accept_headers(opening.key(), opening.offered_subprotocol());
        assert_eq!(
            opening.validate_response(&response),
            Ok(Some("chat".into()))
        );
    }

    #[test]
    fn upgrade_token_list_is_case_insensitive() {
        let key = generate_key();
        let mut response = Headers::new();
        response.set(":status", "101");
        response.set("Upgrade", "WebSocket");
        response.set("Connection", "keep-alive, Upgrade");
        response.set("Sec-WebSocket-Accept", calculate_accept(&key));
        assert_eq!(validate_upgrade_response(&key, &response, None), Ok(None));
    }
}
