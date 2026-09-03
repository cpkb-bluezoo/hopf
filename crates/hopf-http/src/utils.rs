// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Token / host / Transfer-Encoding helpers.

use crate::headers::Headers;

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

/// RFC 9113 §8.2 / RFC 9114 §4.2: HTTP/2 and HTTP/3 field names MUST be
/// lowercase. A request or response containing an uppercase letter in any
/// field name is malformed.
pub fn http_binary_field_names_are_lowercase(pairs: &[(String, String)]) -> bool {
    pairs
        .iter()
        .all(|(name, _)| name.bytes().all(|b| !b.is_ascii_uppercase()))
}

/// Header fields whose framing role HTTP/2 and HTTP/3 carry out-of-band, so
/// the field itself is forbidden on the wire (RFC 9113 §8.2.2 / RFC 9114 §4.2).
const CONNECTION_SPECIFIC_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
];

/// RFC 9113 §8.2.2 / RFC 9114 §4.2: a message containing a connection-specific
/// field, or a `TE` field whose value is not `"trailers"`, is malformed.
/// Pseudo-header fields are skipped (validated separately).
pub fn http_connection_specific_fields_are_valid(pairs: &[(String, String)]) -> bool {
    for (name, value) in pairs {
        if name.starts_with(':') {
            continue;
        }
        if CONNECTION_SPECIFIC_HEADERS.iter().any(|h| name == *h) {
            return false;
        }
        if name == "te" && !value.eq_ignore_ascii_case("trailers") {
            return false;
        }
    }
    true
}

/// Strip request headers that are meaningless or outright forbidden on
/// H2/H3 (RFC 9113 §8.2.2 / RFC 9114 §4.2) before they ever reach the wire
/// — a caller building a request has no reason to know which transport it
/// lands on, so the framework is what has to make a connection-specific
/// header make sense (or safely disappear) rather than the app.
///
/// Returns whether a `Connection: close` token was present, so H2 — which
/// has a real, if degenerate, way to act on the app's intent locally
/// (close the connection once its current streams finish, rather than
/// forward a header the peer would reject as malformed) — can still honor
/// it. H3 has no equivalent notion of a graceful pre-close warning, so its
/// caller has nothing to do with the return value.
pub(crate) fn strip_connection_specific_request_headers(headers: &mut Headers) -> bool {
    let wants_close = headers
        .get("connection")
        .is_some_and(|v| v.split(',').map(str::trim).any(|t| t.eq_ignore_ascii_case("close")));
    for name in CONNECTION_SPECIFIC_HEADERS {
        headers.remove(name);
    }
    wants_close
}

/// RFC 9114 §4.1: trailer field sections MUST NOT contain pseudo-headers.
pub fn field_section_contains_pseudo_headers(pairs: &[(String, String)]) -> bool {
    pairs.iter().any(|(name, _)| name.starts_with(':'))
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
/// `TRACE` is intentionally omitted (XST / cross-site tracing); H1 answers
/// `501` like any other unimplemented method.
pub fn is_default_method(method: &str) -> bool {
    matches!(
        method,
        "GET"
            | "HEAD"
            | "POST"
            | "PUT"
            | "DELETE"
            | "OPTIONS"
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

/// RFC 9110 §6.3: a single consistent `Content-Length` from a field section.
/// `None` when absent; `Err(())` when invalid or conflicting.
pub fn parse_content_length_from_pairs(pairs: &[(String, String)]) -> Result<Option<u64>, ()> {
    let mut seen = None;
    for (name, value) in pairs {
        if name.eq_ignore_ascii_case("content-length") {
            let n = parse_content_length(value).ok_or(())?;
            if let Some(prev) = seen {
                if prev != n {
                    return Err(());
                }
            } else {
                seen = Some(n);
            }
        }
    }
    Ok(seen)
}

/// RFC 9110 §15.2 / §6.4: interim (1xx), 204, and 304 responses MUST NOT
/// contain content.
pub fn http_response_status_must_not_have_content(status: u16) -> bool {
    (100..200).contains(&status) || status == 204 || status == 304
}

/// RFC 9110 §9.3.2: a HEAD request MUST NOT include a content body.
pub fn http_request_method_must_not_have_content(method: &str) -> bool {
    method.eq_ignore_ascii_case("HEAD")
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

/// Format a Unix timestamp as IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`).
pub fn format_http_date(secs: i64) -> String {
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

/// Parse an HTTP-date (RFC 9110 §5.6.7) into a [`std::time::SystemTime`].
///
/// Accepts IMF-fixdate and the two obsolete forms recipients must still
/// understand: RFC 850 and ANSI C's `asctime()`.
pub fn parse_http_date(s: &str) -> Option<std::time::SystemTime> {
    let s = s.trim();
    let secs = parse_imf_fixdate(s)
        .or_else(|| parse_rfc850_date(s))
        .or_else(|| parse_asctime_date(s))?;
    if secs < 0 {
        return None;
    }
    Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs as u64))
}

fn parse_imf_fixdate(s: &str) -> Option<i64> {
    // Sun, 06 Nov 1994 08:49:37 GMT
    let rest = s.split_once(", ")?.1;
    let mut parts = rest.split_whitespace();
    let day: u32 = parts.next()?.parse().ok()?;
    let month = month_num(parts.next()?)?;
    let year: i64 = parts.next()?.parse().ok()?;
    let (hour, min, sec) = parse_hms(parts.next()?)?;
    let _gmt = parts.next()?; // GMT
    civil_to_unix(year, month, day, hour, min, sec)
}

fn parse_rfc850_date(s: &str) -> Option<i64> {
    // Sunday, 06-Nov-94 08:49:37 GMT
    let rest = s.split_once(", ")?.1;
    let mut parts = rest.split_whitespace();
    let date = parts.next()?;
    let mut dmy = date.split('-');
    let day: u32 = dmy.next()?.parse().ok()?;
    let month = month_num(dmy.next()?)?;
    let yy: i64 = dmy.next()?.parse().ok()?;
    // RFC 850 two-digit year: 0–69 → 2000–2069, 70–99 → 1970–1999 (common convention).
    let year = if yy < 70 { 2000 + yy } else { 1900 + yy };
    let (hour, min, sec) = parse_hms(parts.next()?)?;
    let _gmt = parts.next()?;
    civil_to_unix(year, month, day, hour, min, sec)
}

fn parse_asctime_date(s: &str) -> Option<i64> {
    // Sun Nov  6 08:49:37 1994
    let mut parts = s.split_whitespace();
    let _wday = parts.next()?;
    let month = month_num(parts.next()?)?;
    let day: u32 = parts.next()?.parse().ok()?;
    let (hour, min, sec) = parse_hms(parts.next()?)?;
    let year: i64 = parts.next()?.parse().ok()?;
    civil_to_unix(year, month, day, hour, min, sec)
}

fn parse_hms(s: &str) -> Option<(u32, u32, u32)> {
    let mut p = s.split(':');
    let hour: u32 = p.next()?.parse().ok()?;
    let min: u32 = p.next()?.parse().ok()?;
    let sec: u32 = p.next()?.parse().ok()?;
    if hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    Some((hour, min, sec))
}

fn month_num(m: &str) -> Option<u32> {
    Some(match m {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    })
}

fn civil_to_unix(year: i64, month: u32, day: u32, hour: u32, min: u32, sec: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || day == 0 || day > 31 {
        return None;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let mdays = [
        31,
        if leap { 29 } else { 28 },
        31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
    ];
    if day > mdays[(month - 1) as usize] {
        return None;
    }
    let mut days: i64 = 0;
    if year >= 1970 {
        for y in 1970..year {
            let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
            days += if leap { 366 } else { 365 };
        }
    } else {
        for y in (year..1970).rev() {
            let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
            days -= if leap { 366 } else { 365 };
        }
    }
    for m in 1..month {
        days += mdays[(m - 1) as usize] as i64;
    }
    days += (day - 1) as i64;
    Some(days * 86400 + (hour as i64) * 3600 + (min as i64) * 60 + sec as i64)
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
        assert!(!is_default_method("TRACE"));
        assert!(method_implies_no_body("GET"));
        assert!(method_implies_no_body("TRACE"));
        assert!(!method_implies_no_body("POST"));
    }

    #[test]
    fn binary_http_rejects_uppercase_field_names() {
        assert!(http_binary_field_names_are_lowercase(&[
            (":method".into(), "GET".into()),
            ("content-type".into(), "text/plain".into()),
        ]));
        assert!(!http_binary_field_names_are_lowercase(&[
            (":method".into(), "GET".into()),
            ("Content-Type".into(), "text/plain".into()),
        ]));
    }

    #[test]
    fn connection_specific_fields_and_te() {
        let ok = &[
            (":method".into(), "GET".into()),
            ("te".into(), "trailers".into()),
        ];
        assert!(http_connection_specific_fields_are_valid(ok));

        for (name, value) in [
            ("connection", "keep-alive"),
            ("keep-alive", "timeout=5"),
            ("proxy-connection", "keep-alive"),
            ("transfer-encoding", "chunked"),
            ("upgrade", "h2c"),
            ("te", "gzip"),
        ] {
            assert!(
                !http_connection_specific_fields_are_valid(&[
                    (":method".into(), "GET".into()),
                    (name.into(), value.into()),
                ]),
                "expected {name} to be rejected"
            );
        }
    }

    #[test]
    fn content_length_from_pairs_rejects_conflicting_values() {
        assert_eq!(
            parse_content_length_from_pairs(&[
                ("content-length".into(), "5".into()),
            ])
            .unwrap(),
            Some(5)
        );
        assert!(parse_content_length_from_pairs(&[
            ("content-length".into(), "5".into()),
            ("content-length".into(), "6".into()),
        ])
        .is_err());
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

    #[test]
    fn http_date_parse_round_trips_imf() {
        let s = "Mon, 01 Jan 2024 00:00:00 GMT";
        let t = parse_http_date(s).unwrap();
        let secs = t.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        assert_eq!(secs, 1704067200);
        assert_eq!(format_http_date(secs), s);
    }

    #[test]
    fn http_date_parse_obsolete_forms() {
        // RFC 850 (two-digit year 94 → 1994).
        let t = parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT").unwrap();
        assert_eq!(
            t.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            784111777
        );
        // asctime — note the double space before single-digit day.
        let t = parse_http_date("Sun Nov  6 08:49:37 1994").unwrap();
        assert_eq!(
            t.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            784111777
        );
    }
}

