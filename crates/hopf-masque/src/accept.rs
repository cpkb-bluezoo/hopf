// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Shared Extended CONNECT (H2/H3) / HTTP-Upgrade (H1) acceptance logic —
//! identical between CONNECT-UDP (RFC 9298) and CONNECT-IP (RFC 9484)
//! other than which `:protocol`/`Upgrade` token is being matched.

use hopf_http::{Headers, ServerWriter};

/// True for an RFC 8441/9220-shaped Extended CONNECT request naming
/// `protocol` (H2/H3): `:method: CONNECT`, `:protocol: <protocol>`.
pub(crate) fn is_extended_connect(headers: &Headers, protocol: &str) -> bool {
    headers
        .get(":method")
        .is_some_and(|m| m.eq_ignore_ascii_case("CONNECT"))
        && headers
            .get(":protocol")
            .is_some_and(|p| p.eq_ignore_ascii_case(protocol))
}

/// True for an HTTP/1.1 `Upgrade: <protocol>` request — H1 has no
/// `:protocol` pseudo-header (RFC 9110 §7.8 reserves Upgrade to H1), so
/// this is the only shape available there.
pub(crate) fn is_h1_upgrade(headers: &Headers, protocol: &str) -> bool {
    if !headers.get(":method").is_some_and(|m| m.eq_ignore_ascii_case("GET")) {
        return false;
    }
    let upgrade = headers.get("upgrade").unwrap_or("");
    if !upgrade
        .split(',')
        .map(str::trim)
        .any(|p| p.eq_ignore_ascii_case(protocol))
    {
        return false;
    }
    let connection = headers.get("connection").unwrap_or("");
    connection
        .split(',')
        .map(str::trim)
        .any(|p| p.eq_ignore_ascii_case("upgrade"))
}

/// Build the accept response for `protocol` — `200` with the request
/// already-Extended-CONNECT-shaped, or `101 Switching Protocols` +
/// `Upgrade: <protocol>` on H1. Always carries `Capsule-Protocol: ?1`:
/// every protocol built on top of this helper uses Capsule Protocol
/// framing unconditionally, never a raw byte stream.
pub(crate) fn accept_headers(is_extended_connect: bool, protocol: &str) -> Headers {
    let mut h = Headers::new();
    if is_extended_connect {
        h.set(":status", "200");
    } else {
        h.set(":status", "101");
        h.set("Upgrade", protocol);
        h.set("Connection", "Upgrade");
    }
    h.set("Capsule-Protocol", "?1");
    h
}

/// Send a plain-text error response and end the request.
pub(crate) fn send_error(w: &mut dyn ServerWriter, status: u16, message: &str) {
    let mut h = Headers::new();
    h.set(":status", status.to_string());
    h.set("Content-Type", "text/plain");
    w.headers(h);
    w.start_response_body();
    w.response_body_content(message.as_bytes());
    w.end_response_body();
    w.complete();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extended_connect_headers(protocol: &str) -> Headers {
        let mut h = Headers::new();
        h.set(":method", "CONNECT");
        h.set(":protocol", protocol);
        h.set(":path", "/.well-known/masque/udp/target.example/443/");
        h
    }

    fn h1_upgrade_headers(protocol: &str) -> Headers {
        let mut h = Headers::new();
        h.set(":method", "GET");
        h.set("Upgrade", protocol);
        h.set("Connection", "Upgrade");
        h.set(":path", "/.well-known/masque/udp/target.example/443/");
        h
    }

    #[test]
    fn recognizes_extended_connect() {
        assert!(is_extended_connect(&extended_connect_headers("connect-udp"), "connect-udp"));
        assert!(!is_h1_upgrade(&extended_connect_headers("connect-udp"), "connect-udp"));
    }

    #[test]
    fn recognizes_h1_upgrade() {
        assert!(is_h1_upgrade(&h1_upgrade_headers("connect-ip"), "connect-ip"));
        assert!(!is_extended_connect(&h1_upgrade_headers("connect-ip"), "connect-ip"));
    }

    #[test]
    fn extended_connect_requires_the_right_protocol_token() {
        let h = extended_connect_headers("connect-udp");
        assert!(!is_extended_connect(&h, "connect-ip"));
    }

    #[test]
    fn h1_upgrade_requires_both_upgrade_and_connection_tokens() {
        let mut missing_connection = h1_upgrade_headers("connect-udp");
        missing_connection.set("Connection", "keep-alive");
        assert!(!is_h1_upgrade(&missing_connection, "connect-udp"));

        let mut wrong_upgrade = h1_upgrade_headers("connect-udp");
        wrong_upgrade.set("Upgrade", "websocket");
        assert!(!is_h1_upgrade(&wrong_upgrade, "connect-udp"));
    }

    #[test]
    fn h1_upgrade_token_list_is_comma_separated_and_case_insensitive() {
        let mut h = h1_upgrade_headers("connect-ip");
        h.set("Upgrade", "h2c, Connect-IP");
        assert!(is_h1_upgrade(&h, "connect-ip"));
    }

    #[test]
    fn accept_headers_carry_capsule_protocol_and_the_right_status() {
        let extended = accept_headers(true, "connect-ip");
        assert_eq!(extended.get(":status"), Some("200"));
        assert_eq!(extended.get("capsule-protocol"), Some("?1"));

        let h1 = accept_headers(false, "connect-ip");
        assert_eq!(h1.get(":status"), Some("101"));
        assert_eq!(h1.get("upgrade"), Some("connect-ip"));
        assert_eq!(h1.get("capsule-protocol"), Some("?1"));
    }
}
