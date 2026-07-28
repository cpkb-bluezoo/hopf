// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! FTP reply formatting helpers.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::server::utf8::encode_text;

/// Format `code desc\r\n` as UTF-8 (default when charset is not negotiated).
pub fn reply(code: u16, desc: &str) -> Vec<u8> {
    reply_charset(code, desc, true)
}

/// Format a reply using the RFC 2640 control charset.
pub fn reply_charset(code: u16, desc: &str, utf8: bool) -> Vec<u8> {
    encode_text(&format!("{code} {desc}\r\n"), utf8)
}

/// RFC 959 multiline: `code-line\r\n` … final `code last\r\n` (UTF-8).
pub fn reply_multiline(code: u16, lines: &[&str]) -> Vec<u8> {
    reply_multiline_charset(code, lines, true)
}

/// Multiline reply under the active control charset.
pub fn reply_multiline_charset(code: u16, lines: &[&str], utf8: bool) -> Vec<u8> {
    let mut out = Vec::new();
    if lines.is_empty() {
        return reply_charset(code, "", utf8);
    }
    for (i, line) in lines.iter().enumerate() {
        let text = if i + 1 == lines.len() {
            format!("{code} {line}\r\n")
        } else {
            format!("{code}-{line}\r\n")
        };
        out.extend_from_slice(&encode_text(&text, utf8));
    }
    out
}

/// `227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)`.
pub fn format_pasv_reply(addr: SocketAddr) -> Vec<u8> {
    let ip = match addr.ip() {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => Ipv4Addr::new(127, 0, 0, 1), // EPSV preferred for v6
    };
    let o = ip.octets();
    let port = addr.port();
    let p1 = port / 256;
    let p2 = port % 256;
    reply(
        227,
        &format!(
            "Entering Passive Mode ({},{},{},{},{},{})",
            o[0], o[1], o[2], o[3], p1, p2
        ),
    )
}

/// `229 Entering Extended Passive Mode (|||port|)`.
pub fn format_epsv_reply(port: u16) -> Vec<u8> {
    reply(229, &format!("Entering Extended Passive Mode (|||{port}|)"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddrV4;

    #[test]
    fn pasv_format() {
        let a = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 2), 256 * 4 + 5));
        let s = String::from_utf8(format_pasv_reply(a)).unwrap();
        assert!(s.contains("192,168,1,2,4,5"));
    }
}
