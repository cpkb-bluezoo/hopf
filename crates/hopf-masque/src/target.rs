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
    let host = percent_decode(host_enc)?;
    if host.is_empty() {
        return None;
    }
    let port: u16 = percent_decode(port_enc)?.parse().ok()?;
    Some(ConnectUdpTarget { host, port })
}

/// Strict RFC 3986 `%XX` percent-decoding — `None` on a truncated or
/// non-hex escape, or invalid UTF-8 in the result, rather than silently
/// passing through whatever bytes happen to be there.
fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hi = from_hex(*bytes.get(i + 1)?)?;
            let lo = from_hex(*bytes.get(i + 2)?)?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
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
