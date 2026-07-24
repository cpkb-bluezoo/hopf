// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Token / host / Transfer-Encoding helpers.

/// RFC 9110 token characters for method names.
pub fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| {
            matches!(b,
                b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' |
                b'^' | b'_' | b'`' | b'|' | b'~' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z'
            )
        })
}

/// Basic request-target check (origin-form, absolute-form, authority-form, asterisk).
pub fn is_valid_request_target(target: &str) -> bool {
    if target.is_empty() {
        return false;
    }
    if target == "*" {
        return true;
    }
    // Reject CTLs and spaces.
    target.bytes().all(|b| b >= 0x21 && b != 0x7f)
}

/// Host / :authority: non-empty, no spaces/CTLs (simplified Gumdrop check).
pub fn is_valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 255 {
        return false;
    }
    host.bytes().all(|b| b >= 0x21 && b != 0x7f)
}

/// Whether `Transfer-Encoding` is exactly one coding: `chunked` (Gumdrop).
///
/// Multi-coding TE or non-chunked coding is rejected by the connection
/// (400); this helper is the positive check only.
pub fn is_chunked_te(value: &str) -> bool {
    let mut tokens = value
        .split(',')
        .map(|p| p.trim())
        .filter(|p| !p.is_empty());
    match (tokens.next(), tokens.next()) {
        (Some(only), None) => only.eq_ignore_ascii_case("chunked"),
        _ => false,
    }
}

/// True when TE is present but not a single `chunked` coding.
pub fn is_invalid_te(value: &str) -> bool {
    !value.trim().is_empty() && !is_chunked_te(value)
}

/// Header field-name: token, optional leading `:` for pseudo-headers.
pub fn is_valid_header_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let start = if bytes[0] == b':' {
        if bytes.len() == 1 {
            return false;
        }
        1
    } else {
        0
    };
    bytes[start..]
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Default methods Hopf accepts without a custom factory set.
///
/// Includes RFC 4918 WebDAV methods so H1 does not 501 them.
pub fn is_default_method(method: &str) -> bool {
    matches!(
        method,
        "GET"
            | "HEAD"
            | "POST"
            | "PUT"
            | "DELETE"
            | "OPTIONS"
            | "TRACE"
            | "CONNECT"
            | "PATCH"
            | "PROPFIND"
            | "PROPPATCH"
            | "MKCOL"
            | "COPY"
            | "MOVE"
            | "LOCK"
            | "UNLOCK"
    )
}

/// Parse `Content-Length` (single decimal, no `+`).
pub fn parse_content_length(value: &str) -> Option<u64> {
    let v = value.trim();
    if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    v.parse().ok()
}

/// Methods that never have a request body in practice for H1 framing.
pub fn method_implies_no_body(method: &str) -> bool {
    matches!(
        method,
        "GET" | "HEAD" | "DELETE" | "OPTIONS" | "TRACE" | "CONNECT"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_and_targets() {
        assert!(is_token("GET"));
        assert!(is_token("X-Custom"));
        assert!(!is_token(""));
        assert!(!is_token("bad method"));
        assert!(is_valid_request_target("/"));
        assert!(is_valid_request_target("*"));
        assert!(!is_valid_request_target(""));
        assert!(!is_valid_request_target("a b"));
        assert!(is_valid_host("example.com"));
        assert!(!is_valid_host(""));
        assert!(!is_valid_host("bad host"));
    }

    #[test]
    fn transfer_encoding_helpers() {
        assert!(is_chunked_te("chunked"));
        assert!(is_chunked_te(" Chunked "));
        assert!(!is_chunked_te("gzip"));
        assert!(!is_chunked_te("chunked, gzip"));
        assert!(is_invalid_te("gzip"));
        assert!(!is_invalid_te("chunked"));
        assert!(!is_invalid_te("  "));
    }

    #[test]
    fn header_name_cl_methods() {
        assert!(is_valid_header_name("Content-Type"));
        assert!(is_valid_header_name(":status"));
        assert!(!is_valid_header_name(""));
        assert!(!is_valid_header_name(":"));
        assert!(!is_valid_header_name("Bad Name"));
        assert_eq!(parse_content_length("42"), Some(42));
        assert_eq!(parse_content_length("+42"), None);
        assert_eq!(parse_content_length(""), None);
        assert!(is_default_method("GET"));
        assert!(is_default_method("PROPFIND"));
        assert!(is_default_method("LOCK"));
        assert!(!is_default_method("FOO"));
        assert!(method_implies_no_body("GET"));
        assert!(!method_implies_no_body("POST"));
    }
}

