// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! CONNECT-UDP target parsing (RFC 9298 §2).

/// A CONNECT-UDP request's decoded target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectUdpTarget {
    /// The proxied UDP target's hostname or IP literal.
    pub host: String,
    /// The proxied UDP target's port.
    pub port: u16,
}

const PREFIX: &str = "/.well-known/masque/udp/";

/// Parse a `:path` against the RFC 9298 §2 URI template
/// `/.well-known/masque/udp/{target_host}/{target_port}/`.
///
/// Both segments must be present, non-empty, and validly percent-encoded —
/// this feeds a DNS lookup, so a partial or best-effort decode would be
/// worse than an outright rejection (`None`).
pub fn parse(path: &str) -> Option<ConnectUdpTarget> {
    let rest = path.strip_prefix(PREFIX)?;
    let rest = rest.strip_suffix('/')?;
    let (host_enc, port_enc) = rest.split_once('/')?;
    if host_enc.is_empty() || port_enc.is_empty() {
        return None;
    }
    let host = crate::percent::decode(host_enc)?;
    if host.is_empty() {
        return None;
    }
    let port: u16 = crate::percent::decode(port_enc)?.parse().ok()?;
    Some(ConnectUdpTarget { host, port })
}

/// Build the RFC 9298 §2 URI template path for `host`:`port` — the inverse
/// of [`parse`], for the client side. Percent-encodes `host` (needed for
/// an IPv6 literal's colons, RFC 9298 §2's own example).
pub(crate) fn encode(host: &str, port: u16) -> String {
    format!("{PREFIX}{}/{port}/", crate::percent::encode(host))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_plain_hostname_and_port() {
        let t = parse("/.well-known/masque/udp/target.example/443/").unwrap();
        assert_eq!(t.host, "target.example");
        assert_eq!(t.port, 443);
    }

    #[test]
    fn encode_then_parse_round_trips_a_plain_hostname() {
        let path = encode("target.example", 443);
        let t = parse(&path).unwrap();
        assert_eq!(t.host, "target.example");
        assert_eq!(t.port, 443);
    }

    #[test]
    fn encode_then_parse_round_trips_an_ipv6_literal() {
        let path = encode("2001:db8::1", 53);
        let t = parse(&path).unwrap();
        assert_eq!(t.host, "2001:db8::1");
        assert_eq!(t.port, 53);
    }

    #[test]
    fn percent_decodes_both_segments() {
        // "203.0.113.5" needs no encoding in practice, but a colon in an
        // IPv6 literal (RFC 9298 §2's own example) does.
        let t = parse("/.well-known/masque/udp/2001%3Adb8%3A%3A1/53/").unwrap();
        assert_eq!(t.host, "2001:db8::1");
        assert_eq!(t.port, 53);
    }

    #[test]
    fn rejects_missing_trailing_slash() {
        assert!(parse("/.well-known/masque/udp/target.example/443").is_none());
    }

    #[test]
    fn rejects_wrong_prefix() {
        assert!(parse("/.well-known/masque/ip/target.example/443/").is_none());
    }

    #[test]
    fn rejects_empty_host_segment() {
        assert!(parse("/.well-known/masque/udp//443/").is_none());
    }

    #[test]
    fn rejects_empty_port_segment() {
        assert!(parse("/.well-known/masque/udp/target.example//").is_none());
    }

    #[test]
    fn rejects_non_numeric_port() {
        assert!(parse("/.well-known/masque/udp/target.example/https/").is_none());
    }

    #[test]
    fn rejects_port_out_of_u16_range() {
        assert!(parse("/.well-known/masque/udp/target.example/99999/").is_none());
    }

    #[test]
    fn rejects_truncated_percent_escape() {
        assert!(parse("/.well-known/masque/udp/target.example%2/443/").is_none());
    }

    #[test]
    fn rejects_non_hex_percent_escape() {
        assert!(parse("/.well-known/masque/udp/target.example%zz/443/").is_none());
    }

    #[test]
    fn rejects_percent_escape_that_decodes_to_invalid_utf8() {
        // %FF is not valid UTF-8 on its own.
        assert!(parse("/.well-known/masque/udp/%FF/443/").is_none());
    }
}
