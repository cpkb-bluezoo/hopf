// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Token / host / Transfer-Encoding helpers.

/// Whether `b` is an RFC 9110 §5.6.2 `tchar`.
fn is_tchar(b: u8) -> bool {
    matches!(b,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' |
        b'^' | b'_' | b'`' | b'|' | b'~' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z'
    )
}

/// RFC 9110 token characters for method names.
pub fn is_token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(is_tchar)
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

/// Header field-name: token (full RFC 9110 `tchar` set), optional leading
/// `:` for pseudo-headers.
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
    bytes[start..].iter().all(|&b| is_tchar(b))
}

/// Header field-value: reject CTL bytes (RFC 9112 §5.5 `field-content`
/// grammar) — HTAB is the only permitted control character; SP, VCHAR
/// (0x21-0x7E), and obs-text (0x80-0xFF) are otherwise allowed.
pub fn is_valid_header_value(value: &[u8]) -> bool {
    value
        .iter()
        .all(|&b| b == 0x09 || (0x20..=0x7e).contains(&b) || b >= 0x80)
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

/// Current time as a `Date` response header value: IMF-fixdate, always GMT
/// (RFC 9110 §5.6.7, §6.6.1).
pub fn http_date_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    format_http_date(secs)
}

fn format_http_date(secs: i64) -> String {
    const DAYS: &[&str] = &["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const MONTHS: &[&str] = &[
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = secs.div_euclid(86400);
    let time = secs.rem_euclid(86400);
    let hour = (time / 3600) as u32;
    let min = ((time % 3600) / 60) as u32;
    let sec = (time % 60) as u32;
    // 1970-01-01 was a Thursday.
    let wday = (days + 3).rem_euclid(7) as usize;
    let mut y = 1970i64;
    let mut day = days;
    loop {
        let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
        let year_days = if leap { 366 } else { 365 };
        if day >= 0 && day < year_days {
            break;
        }
        if day < 0 {
            y -= 1;
            let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
            day += if leap { 366 } else { 365 };
        } else {
            day -= year_days;
            y += 1;
        }
    }
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let mdays = [
        31,
        if leap { 29 } else { 28 },
        31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
    ];
    let mut m = 0usize;
    while m < 12 && day >= mdays[m] as i64 {
        day -= mdays[m] as i64;
        m += 1;
    }
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        DAYS[wday],
        day + 1,
        MONTHS[m],
        y,
        hour,
        min,
        sec
    )
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

    #[test]
    fn header_name_accepts_full_tchar_set() {
        // RFC 9110 tchar beyond alphanumeric/-/_: "!#$%&'*+.^`|~"
        assert!(is_valid_header_name("X-A!B#C$D%E&F'G*H+I.J^K_L`M|N~O"));
        assert!(!is_valid_header_name("Bad Name"));
        assert!(!is_valid_header_name("Bad/Name"));
        assert!(!is_valid_header_name("Bad:Name"));
    }

    #[test]
    fn header_value_rejects_ctl_allows_obs_text() {
        assert!(is_valid_header_value(b"plain value"));
        assert!(is_valid_header_value(b"tab\tseparated"));
        assert!(is_valid_header_value(&[0xC3, 0xA9])); // obs-text (UTF-8 'é' bytes)
        assert!(!is_valid_header_value(b"line\rinjection"));
        assert!(!is_valid_header_value(b"line\ninjection"));
        assert!(!is_valid_header_value(b"null\0byte"));
        assert!(!is_valid_header_value(&[0x7f])); // DEL
    }

    #[test]
    fn http_date_format() {
        // 2024-01-01T00:00:00Z was a Monday.
        assert_eq!(format_http_date(1704067200), "Mon, 01 Jan 2024 00:00:00 GMT");
        // Epoch itself was a Thursday.
        assert_eq!(format_http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        // A leap-day date, exercised for the Feb-29 branch.
        assert_eq!(format_http_date(1582934400), "Sat, 29 Feb 2020 00:00:00 GMT");
    }
}

