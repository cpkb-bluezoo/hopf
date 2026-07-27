// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Serialize an HTTP/1.1 request line and header block into a byte buffer.

use crate::headers::Headers;
use crate::utils::method_implies_no_body;
use crate::version::HttpVersion;

/// Write `method path HTTP/1.1`, mandatory `Host`, user headers, and optional
/// framing hints into `out`.
///
/// When `has_body` is true and the caller did not set `Content-Length` or
/// `Transfer-Encoding`, `Transfer-Encoding: chunked` is added (RFC 9112 §7.1).
pub(crate) fn write_request_headers(
    out: &mut Vec<u8>,
    method: &str,
    path: &str,
    host_header: &str,
    headers: &Headers,
    has_body: bool,
    version: HttpVersion,
) {
    let ver = version.as_str();
    let mut msg = format!("{method} {path} {ver}\r\n");
    msg.push_str(&format!("Host: {host_header}\r\n"));

    let mut saw_connection = false;
    for h in headers.iter() {
        if h.name.starts_with(':') {
            continue;
        }
        if h.name.eq_ignore_ascii_case("host") {
            continue;
        }
        if h.name.eq_ignore_ascii_case("connection") {
            saw_connection = true;
        }
        msg.push_str(&format!("{}: {}\r\n", h.name, h.value));
    }

    if !saw_connection {
        msg.push_str("Connection: keep-alive\r\n");
    }

    let has_cl = headers.contains("content-length");
    let has_te = headers.contains("transfer-encoding");
    if has_body && !has_cl && !has_te {
        msg.push_str("Transfer-Encoding: chunked\r\n");
    } else if !has_cl && !has_te && !method_implies_no_body(method) {
        if matches!(method, "POST" | "PUT" | "PATCH") && !has_body {
            msg.push_str("Content-Length: 0\r\n");
        }
    }

    msg.push_str("\r\n");
    out.extend_from_slice(msg.as_bytes());
}
