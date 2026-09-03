// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 3986 `%XX` percent-encoding for one URI path segment — shared by
//! CONNECT-UDP's target parsing ([`crate::target`]) and CONNECT-IP's
//! ([`crate::ip_target`]), whose URI templates (RFC 9298 §2, RFC 9484 §3)
//! turn out to need the identical "percent-encode anything outside the
//! unreserved set" logic for their own path segments.

/// Percent-encode every byte of `s` outside RFC 3986's unreserved set
/// (`ALPHA / DIGIT / "-" / "." / "_" / "~"`).
pub(crate) fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Strict `%XX` percent-decoding — `None` on a truncated or non-hex escape,
/// or invalid UTF-8 in the result, rather than silently passing through
/// whatever bytes happen to be there.
pub(crate) fn decode(s: &str) -> Option<String> {
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
    fn round_trips_a_plain_hostname() {
        assert_eq!(decode(&encode("target.example")).unwrap(), "target.example");
    }

    #[test]
    fn round_trips_an_ipv6_literal() {
        assert_eq!(decode(&encode("2001:db8::1")).unwrap(), "2001:db8::1");
    }

    #[test]
    fn encodes_a_literal_slash() {
        // RFC 9484's own use: an IP prefix length is separated from the
        // address by a percent-encoded slash within one path segment.
        assert_eq!(encode("192.0.2.0/24"), "192.0.2.0%2F24");
        assert_eq!(decode("192.0.2.0%2F24").unwrap(), "192.0.2.0/24");
    }

    #[test]
    fn rejects_truncated_percent_escape() {
        assert!(decode("target.example%2").is_none());
    }

    #[test]
    fn rejects_non_hex_percent_escape() {
        assert!(decode("target.example%zz").is_none());
    }

    #[test]
    fn rejects_percent_escape_that_decodes_to_invalid_utf8() {
        assert!(decode("%FF").is_none());
    }
}
