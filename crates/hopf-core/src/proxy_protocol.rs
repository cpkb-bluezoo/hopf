// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! PROXY protocol v1/v2 header parsing (issue #342).
//!
//! A listener with [`crate::listener::TcpListenerConfig::with_proxy_protocol`]
//! (or the UNIX-domain equivalent) enabled expects every accepted connection
//! to begin with a PROXY protocol header — the preamble an L4 relay (nginx,
//! haproxy, a cloud load balancer) prepends to a forwarded connection so the
//! backend can recover the original client address instead of seeing the
//! relay's own. [`try_parse_proxy_header`] parses either wire format
//! ([v1 text][v1] or [v2 binary][v2]) from the front of a connection's
//! inbound buffer.
//!
//! [v1]: https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
//! [v2]: https://www.haproxy.org/download/2.0/doc/proxy-protocol.txt

use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;

use crate::peer_addr::PeerAddr;

/// Result of attempting to parse a PROXY protocol header from the front of
/// a buffer.
pub(crate) enum ProxyHeaderOutcome {
    /// Not enough bytes buffered yet to tell one way or the other — wait
    /// for more to arrive and try again.
    Incomplete,
    /// A complete header was parsed. `consumed` bytes (the header itself)
    /// should be dropped from the front of the buffer; `peer` is the
    /// address the header reports, or `None` for a `LOCAL`/health-check
    /// header (v1 `UNKNOWN`, v2 command `LOCAL`) that carries no address
    /// at all — the connection's actual socket peer should be kept as-is
    /// in that case.
    Parsed {
        consumed: usize,
        peer: Option<PeerAddr>,
    },
}

fn malformed(msg: &str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, format!("PROXY protocol: {msg}"))
}

/// The fixed 12-byte v2 signature every v2 header starts with.
const V2_SIG: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// v1 headers are a single line, always starting with this literal.
const V1_PREFIX: &[u8] = b"PROXY ";

/// Per the v1 spec, a receiver only needs to accept lines up to this many
/// bytes (including the trailing CRLF) before treating an unterminated
/// line as malformed rather than still-arriving.
const V1_MAX_LEN: usize = 107;

/// Try to parse a PROXY protocol v1 or v2 header from the front of `buf`.
///
/// `buf` holds bytes not yet consumed by anything else; this never looks
/// past `buf`'s end, and never consumes bytes belonging to the connection's
/// real application/TLS traffic that happens to follow the header in the
/// same read.
pub(crate) fn try_parse_proxy_header(buf: &[u8]) -> io::Result<ProxyHeaderOutcome> {
    let v2_prefix_len = buf.len().min(V2_SIG.len());
    if buf[..v2_prefix_len] == V2_SIG[..v2_prefix_len] {
        if buf.len() < V2_SIG.len() {
            return Ok(ProxyHeaderOutcome::Incomplete);
        }
        return parse_v2(buf);
    }
    parse_v1(buf)
}

fn parse_v1(buf: &[u8]) -> io::Result<ProxyHeaderOutcome> {
    let prefix_len = buf.len().min(V1_PREFIX.len());
    if buf[..prefix_len] != V1_PREFIX[..prefix_len] {
        return Err(malformed("missing PROXY protocol header"));
    }
    if buf.len() < V1_PREFIX.len() {
        return Ok(ProxyHeaderOutcome::Incomplete);
    }
    let search = &buf[..buf.len().min(V1_MAX_LEN)];
    let Some(pos) = find_crlf(search) else {
        if buf.len() >= V1_MAX_LEN {
            return Err(malformed("v1 header exceeds max line length without CRLF"));
        }
        return Ok(ProxyHeaderOutcome::Incomplete);
    };
    let consumed = pos + 2;
    let line =
        std::str::from_utf8(&buf[..pos]).map_err(|_| malformed("v1 header is not valid UTF-8"))?;
    let mut parts = line.split(' ');
    parts.next(); // "PROXY"
    let peer = match parts.next() {
        Some("UNKNOWN") => None,
        Some(family @ ("TCP4" | "TCP6")) => {
            let src_ip = parts
                .next()
                .ok_or_else(|| malformed("v1 header missing source address"))?;
            let _dst_ip = parts
                .next()
                .ok_or_else(|| malformed("v1 header missing destination address"))?;
            let src_port = parts
                .next()
                .ok_or_else(|| malformed("v1 header missing source port"))?;
            let ip: IpAddr = src_ip
                .parse()
                .map_err(|_| malformed("v1 header has an invalid source address"))?;
            if (family == "TCP4") != ip.is_ipv4() {
                return Err(malformed("v1 header address family doesn't match its address"));
            }
            let port: u16 = src_port
                .parse()
                .map_err(|_| malformed("v1 header has an invalid source port"))?;
            Some(PeerAddr::Inet(SocketAddr::new(ip, port)))
        }
        _ => return Err(malformed("v1 header has an unsupported protocol family")),
    };
    Ok(ProxyHeaderOutcome::Parsed { consumed, peer })
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

fn parse_v2(buf: &[u8]) -> io::Result<ProxyHeaderOutcome> {
    debug_assert!(buf.len() >= V2_SIG.len());
    if buf.len() < 16 {
        return Ok(ProxyHeaderOutcome::Incomplete);
    }
    let ver_cmd = buf[12];
    let version = ver_cmd >> 4;
    let command = ver_cmd & 0x0F;
    if version != 2 {
        return Err(malformed("unsupported v2 version"));
    }
    let fam_proto = buf[13];
    let family = fam_proto >> 4;
    let len = u16::from_be_bytes([buf[14], buf[15]]) as usize;
    let total = 16 + len;
    if buf.len() < total {
        return Ok(ProxyHeaderOutcome::Incomplete);
    }
    // Command 0x0 is LOCAL (e.g. a relay health check) — no address info,
    // real socket peer stays as-is. Command 0x1 is PROXY, the only other
    // defined value.
    if command == 0x0 {
        return Ok(ProxyHeaderOutcome::Parsed {
            consumed: total,
            peer: None,
        });
    }
    if command != 0x1 {
        return Err(malformed("unsupported v2 command"));
    }
    let addr_block = &buf[16..total];
    let peer = match family {
        // AF_UNSPEC: PROXY command with no address family — no address info.
        0x0 => None,
        0x1 => {
            if addr_block.len() < 12 {
                return Err(malformed("truncated v2 IPv4 address block"));
            }
            let src = Ipv4Addr::new(addr_block[0], addr_block[1], addr_block[2], addr_block[3]);
            let port = u16::from_be_bytes([addr_block[8], addr_block[9]]);
            Some(PeerAddr::Inet(SocketAddr::new(IpAddr::V4(src), port)))
        }
        0x2 => {
            if addr_block.len() < 36 {
                return Err(malformed("truncated v2 IPv6 address block"));
            }
            let mut src = [0u8; 16];
            src.copy_from_slice(&addr_block[0..16]);
            let port = u16::from_be_bytes([addr_block[32], addr_block[33]]);
            Some(PeerAddr::Inet(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(src)),
                port,
            )))
        }
        0x3 => {
            if addr_block.len() < 216 {
                return Err(malformed("truncated v2 UNIX address block"));
            }
            let src_path = &addr_block[0..108];
            let end = src_path.iter().position(|&b| b == 0).unwrap_or(108);
            if end == 0 {
                None
            } else {
                let path = String::from_utf8_lossy(&src_path[..end]).into_owned();
                Some(PeerAddr::Unix(Some(PathBuf::from(path))))
            }
        }
        _ => return Err(malformed("unsupported v2 address family")),
    };
    Ok(ProxyHeaderOutcome::Parsed {
        consumed: total,
        peer,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(buf: &[u8]) -> (usize, Option<PeerAddr>) {
        match try_parse_proxy_header(buf).expect("expected a parsed header, got an error") {
            ProxyHeaderOutcome::Parsed { consumed, peer } => (consumed, peer),
            ProxyHeaderOutcome::Incomplete => panic!("expected Parsed, got Incomplete"),
        }
    }

    #[test]
    fn v1_tcp4_parses_source_address_and_consumes_exactly_the_line() {
        let mut buf = b"PROXY TCP4 203.0.113.7 198.51.100.1 56324 443\r\n".to_vec();
        buf.extend_from_slice(b"trailing app data");
        let (consumed, peer) = parsed(&buf);
        assert_eq!(consumed, 47);
        assert_eq!(
            peer,
            Some(PeerAddr::Inet(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
                56324
            )))
        );
        assert_eq!(&buf[consumed..], b"trailing app data");
    }

    #[test]
    fn v1_tcp6_parses_source_address() {
        let buf = b"PROXY TCP6 ::1 ::1 56324 443\r\nGET / HTTP/1.1\r\n".to_vec();
        let (_, peer) = parsed(&buf);
        assert_eq!(
            peer,
            Some(PeerAddr::Inet(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                56324
            )))
        );
    }

    #[test]
    fn v1_unknown_has_no_address_and_keeps_actual_peer() {
        let buf = b"PROXY UNKNOWN\r\nafterwards".to_vec();
        let (consumed, peer) = parsed(&buf);
        assert_eq!(consumed, 15);
        assert_eq!(peer, None);
    }

    #[test]
    fn v1_incomplete_line_waits_for_more_bytes() {
        let buf = b"PROXY TCP4 203.0.113.7 198.51".to_vec();
        match try_parse_proxy_header(&buf).unwrap() {
            ProxyHeaderOutcome::Incomplete => {}
            ProxyHeaderOutcome::Parsed { .. } => panic!("expected Incomplete"),
        }
    }

    #[test]
    fn v1_partial_prefix_waits_for_more_bytes() {
        let buf = b"PROX".to_vec();
        match try_parse_proxy_header(&buf).unwrap() {
            ProxyHeaderOutcome::Incomplete => {}
            ProxyHeaderOutcome::Parsed { .. } => panic!("expected Incomplete"),
        }
    }

    #[test]
    fn garbage_that_cannot_be_either_signature_is_rejected() {
        let buf = b"GET / HTTP/1.1\r\n".to_vec();
        assert!(try_parse_proxy_header(&buf).is_err());
    }

    #[test]
    fn v1_line_without_crlf_within_max_length_is_rejected() {
        let mut buf = b"PROXY TCP4 ".to_vec();
        buf.extend(std::iter::repeat(b'1').take(200));
        assert!(try_parse_proxy_header(&buf).is_err());
    }

    /// v2 binary header, AF_INET/STREAM ("PROXY" command), no TLVs.
    fn v2_header_ipv4(src: [u8; 4], src_port: u16, dst: [u8; 4], dst_port: u16) -> Vec<u8> {
        let mut h = vec![
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
        ];
        h.push(0x21); // version 2, command PROXY
        h.push(0x11); // AF_INET, STREAM
        h.extend_from_slice(&12u16.to_be_bytes());
        h.extend_from_slice(&src);
        h.extend_from_slice(&dst);
        h.extend_from_slice(&src_port.to_be_bytes());
        h.extend_from_slice(&dst_port.to_be_bytes());
        h
    }

    #[test]
    fn v2_ipv4_parses_source_address_and_consumes_exactly_the_header() {
        let mut buf = v2_header_ipv4([203, 0, 113, 7], 56324, [198, 51, 100, 1], 443);
        let header_len = buf.len();
        buf.extend_from_slice(b"trailing app data");
        let (consumed, peer) = parsed(&buf);
        assert_eq!(consumed, header_len);
        assert_eq!(
            peer,
            Some(PeerAddr::Inet(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
                56324
            )))
        );
        assert_eq!(&buf[consumed..], b"trailing app data");
    }

    #[test]
    fn v2_ipv6_parses_source_address() {
        let mut h = vec![
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
        ];
        h.push(0x21);
        h.push(0x21); // AF_INET6, STREAM
        h.extend_from_slice(&36u16.to_be_bytes());
        h.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        h.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        h.extend_from_slice(&56324u16.to_be_bytes());
        h.extend_from_slice(&443u16.to_be_bytes());
        let (_, peer) = parsed(&h);
        assert_eq!(
            peer,
            Some(PeerAddr::Inet(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                56324
            )))
        );
    }

    #[test]
    fn v2_unix_parses_source_path() {
        let mut h = vec![
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
        ];
        h.push(0x21);
        h.push(0x31); // AF_UNIX, STREAM
        h.extend_from_slice(&216u16.to_be_bytes());
        let mut src = [0u8; 108];
        src[..12].copy_from_slice(b"/run/relay.s");
        h.extend_from_slice(&src);
        h.extend_from_slice(&[0u8; 108]);
        let (_, peer) = parsed(&h);
        assert_eq!(peer, Some(PeerAddr::Unix(Some(PathBuf::from("/run/relay.s")))));
    }

    #[test]
    fn v2_local_command_has_no_address_and_keeps_actual_peer() {
        let mut h = vec![
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
        ];
        h.push(0x20); // version 2, command LOCAL
        h.push(0x00);
        h.extend_from_slice(&0u16.to_be_bytes());
        let (consumed, peer) = parsed(&h);
        assert_eq!(consumed, 16);
        assert_eq!(peer, None);
    }

    #[test]
    fn v2_unknown_tlvs_after_the_address_block_are_skipped_not_rejected() {
        let mut buf = v2_header_ipv4([203, 0, 113, 7], 56324, [198, 51, 100, 1], 443);
        // Rewrite the length field to include 4 extra TLV bytes, and append them.
        let extra: &[u8] = &[0x01, 0x00, 0x01, 0xFF]; // fake 1-byte TLV
        let new_len = 12u16 + extra.len() as u16;
        buf[14..16].copy_from_slice(&new_len.to_be_bytes());
        buf.extend_from_slice(extra);
        buf.extend_from_slice(b"app data");
        let header_len = 16 + 12 + extra.len();
        let (consumed, peer) = parsed(&buf);
        assert_eq!(consumed, header_len);
        assert!(peer.is_some());
        assert_eq!(&buf[consumed..], b"app data");
    }

    #[test]
    fn v2_incomplete_address_block_waits_for_more_bytes() {
        let full = v2_header_ipv4([203, 0, 113, 7], 56324, [198, 51, 100, 1], 443);
        let partial = &full[..full.len() - 3];
        match try_parse_proxy_header(partial).unwrap() {
            ProxyHeaderOutcome::Incomplete => {}
            ProxyHeaderOutcome::Parsed { .. } => panic!("expected Incomplete"),
        }
    }

    #[test]
    fn v2_incomplete_fixed_header_waits_for_more_bytes() {
        let full = v2_header_ipv4([203, 0, 113, 7], 56324, [198, 51, 100, 1], 443);
        let partial = &full[..14];
        match try_parse_proxy_header(partial).unwrap() {
            ProxyHeaderOutcome::Incomplete => {}
            ProxyHeaderOutcome::Parsed { .. } => panic!("expected Incomplete"),
        }
    }

    #[test]
    fn v2_wrong_version_is_rejected() {
        let mut h = vec![
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
        ];
        h.push(0x11); // version 1 (invalid — only version 2 exists)
        h.push(0x11);
        h.extend_from_slice(&12u16.to_be_bytes());
        h.extend_from_slice(&[0u8; 12]);
        assert!(try_parse_proxy_header(&h).is_err());
    }
}
