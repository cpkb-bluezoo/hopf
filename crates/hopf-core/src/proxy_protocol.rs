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
    /// in that case. `local` is the destination address the header
    /// reports (the relay/load-balancer address the client connected to),
    /// or `None` when the header carries none. `tlvs` are the v2 TLVs in
    /// wire order (always empty for v1).
    Parsed {
        consumed: usize,
        peer: Option<PeerAddr>,
        local: Option<PeerAddr>,
        tlvs: Vec<ProxyTlv>,
    },
}

/// One type-length-value vector from the trailing area of a PROXY protocol
/// v2 header.
///
/// A PROXY listener exposes these through
/// [`Endpoint::proxy_tlvs`](crate::Endpoint::proxy_tlvs). The value bytes
/// are left uninterpreted (an `SSL` TLV's sub-TLVs, for instance, stay
/// packed) except where a helper such as [`ProxyTlv::aws_vpce_id`] says
/// otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyTlv {
    /// The TLV type byte; see the associated constants.
    pub kind: u8,
    /// The raw value bytes.
    pub value: Vec<u8>,
}

impl ProxyTlv {
    /// `PP2_TYPE_ALPN`: the negotiated ALPN protocol, if the relay
    /// terminated TLS.
    pub const ALPN: u8 = 0x01;
    /// `PP2_TYPE_AUTHORITY`: the host name from the client's SNI.
    pub const AUTHORITY: u8 = 0x02;
    /// `PP2_TYPE_CRC32C`: a CRC-32C checksum of the whole header.
    pub const CRC32C: u8 = 0x03;
    /// `PP2_TYPE_NOOP`: padding to be ignored.
    pub const NOOP: u8 = 0x04;
    /// `PP2_TYPE_UNIQUE_ID`: an opaque connection identifier.
    pub const UNIQUE_ID: u8 = 0x05;
    /// `PP2_TYPE_SSL`: details of the client's TLS session at the relay.
    pub const SSL: u8 = 0x20;
    /// `PP2_TYPE_NETNS`: the name of the network namespace.
    pub const NETNS: u8 = 0x30;
    /// AWS-specific TLV (`0xEA`), sent by Network Load Balancer. The first
    /// value byte is a subtype.
    pub const AWS: u8 = 0xEA;
    /// Subtype of the [`AWS`](Self::AWS) TLV whose payload is the VPC
    /// endpoint ID (`vpce-...`) the client came through.
    pub const AWS_SUBTYPE_VPCE_ID: u8 = 0x01;

    /// The first TLV of type `kind`, if any.
    pub fn find(tlvs: &[ProxyTlv], kind: u8) -> Option<&ProxyTlv> {
        tlvs.iter().find(|t| t.kind == kind)
    }

    /// The AWS VPC endpoint ID carried in an [`AWS`](Self::AWS) TLV with
    /// subtype [`AWS_SUBTYPE_VPCE_ID`](Self::AWS_SUBTYPE_VPCE_ID), if one is
    /// present and its payload is valid UTF-8.
    pub fn aws_vpce_id(tlvs: &[ProxyTlv]) -> Option<&str> {
        tlvs.iter()
            .filter(|t| t.kind == Self::AWS)
            .find_map(|t| match t.value.split_first() {
                Some((&Self::AWS_SUBTYPE_VPCE_ID, id)) => std::str::from_utf8(id).ok(),
                _ => None,
            })
    }
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
    let (peer, local) = match parts.next() {
        Some("UNKNOWN") => (None, None),
        Some(family @ ("TCP4" | "TCP6")) => {
            let src_ip = parts
                .next()
                .ok_or_else(|| malformed("v1 header missing source address"))?;
            let dst_ip = parts
                .next()
                .ok_or_else(|| malformed("v1 header missing destination address"))?;
            let src_port = parts
                .next()
                .ok_or_else(|| malformed("v1 header missing source port"))?;
            let dst_port = parts
                .next()
                .ok_or_else(|| malformed("v1 header missing destination port"))?;
            let src: IpAddr = src_ip
                .parse()
                .map_err(|_| malformed("v1 header has an invalid source address"))?;
            let dst: IpAddr = dst_ip
                .parse()
                .map_err(|_| malformed("v1 header has an invalid destination address"))?;
            if (family == "TCP4") != src.is_ipv4() || (family == "TCP4") != dst.is_ipv4() {
                return Err(malformed("v1 header address family doesn't match its address"));
            }
            let src_port: u16 = src_port
                .parse()
                .map_err(|_| malformed("v1 header has an invalid source port"))?;
            let dst_port: u16 = dst_port
                .parse()
                .map_err(|_| malformed("v1 header has an invalid destination port"))?;
            (
                Some(PeerAddr::Inet(SocketAddr::new(src, src_port))),
                Some(PeerAddr::Inet(SocketAddr::new(dst, dst_port))),
            )
        }
        _ => return Err(malformed("v1 header has an unsupported protocol family")),
    };
    Ok(ProxyHeaderOutcome::Parsed {
        consumed,
        peer,
        local,
        tlvs: Vec::new(),
    })
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
            local: None,
            tlvs: Vec::new(),
        });
    }
    if command != 0x1 {
        return Err(malformed("unsupported v2 command"));
    }
    let block = &buf[16..total];
    let (addr_len, peer, local) = match family {
        // AF_UNSPEC: PROXY command with no address family. The spec has
        // receivers ignore whatever follows, so there are no TLVs to read.
        0x0 => {
            return Ok(ProxyHeaderOutcome::Parsed {
                consumed: total,
                peer: None,
                local: None,
                tlvs: Vec::new(),
            });
        }
        0x1 => {
            if block.len() < 12 {
                return Err(malformed("truncated v2 IPv4 address block"));
            }
            let ip = |b: &[u8]| IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]));
            let port = |b: &[u8]| u16::from_be_bytes([b[0], b[1]]);
            (
                12,
                Some(PeerAddr::Inet(SocketAddr::new(ip(&block[0..4]), port(&block[8..10])))),
                Some(PeerAddr::Inet(SocketAddr::new(ip(&block[4..8]), port(&block[10..12])))),
            )
        }
        0x2 => {
            if block.len() < 36 {
                return Err(malformed("truncated v2 IPv6 address block"));
            }
            let ip = |b: &[u8]| {
                let mut o = [0u8; 16];
                o.copy_from_slice(b);
                IpAddr::V6(Ipv6Addr::from(o))
            };
            let port = |b: &[u8]| u16::from_be_bytes([b[0], b[1]]);
            (
                36,
                Some(PeerAddr::Inet(SocketAddr::new(ip(&block[0..16]), port(&block[32..34])))),
                Some(PeerAddr::Inet(SocketAddr::new(ip(&block[16..32]), port(&block[34..36])))),
            )
        }
        0x3 => {
            if block.len() < 216 {
                return Err(malformed("truncated v2 UNIX address block"));
            }
            let path = |b: &[u8]| {
                let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
                if end == 0 {
                    None
                } else {
                    let path = String::from_utf8_lossy(&b[..end]).into_owned();
                    Some(PeerAddr::Unix(Some(PathBuf::from(path))))
                }
            };
            (216, path(&block[0..108]), path(&block[108..216]))
        }
        _ => return Err(malformed("unsupported v2 address family")),
    };
    let tlvs = parse_v2_tlvs(&block[addr_len..])?;
    Ok(ProxyHeaderOutcome::Parsed {
        consumed: total,
        peer,
        local,
        tlvs,
    })
}

/// Parse the TLV area that follows a v2 address block. Every TLV must lie
/// wholly within `area`; a truncated one makes the whole header malformed.
fn parse_v2_tlvs(mut area: &[u8]) -> io::Result<Vec<ProxyTlv>> {
    let mut tlvs = Vec::new();
    while !area.is_empty() {
        if area.len() < 3 {
            return Err(malformed("truncated v2 TLV header"));
        }
        let kind = area[0];
        let len = u16::from_be_bytes([area[1], area[2]]) as usize;
        let rest = &area[3..];
        if rest.len() < len {
            return Err(malformed("v2 TLV value overruns the header"));
        }
        tlvs.push(ProxyTlv {
            kind,
            value: rest[..len].to_vec(),
        });
        area = &rest[len..];
    }
    Ok(tlvs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed_full(buf: &[u8]) -> (usize, Option<PeerAddr>, Option<PeerAddr>, Vec<ProxyTlv>) {
        match try_parse_proxy_header(buf).expect("expected a parsed header, got an error") {
            ProxyHeaderOutcome::Parsed {
                consumed,
                peer,
                local,
                tlvs,
            } => (consumed, peer, local, tlvs),
            ProxyHeaderOutcome::Incomplete => panic!("expected Parsed, got Incomplete"),
        }
    }

    fn parsed(buf: &[u8]) -> (usize, Option<PeerAddr>) {
        let (consumed, peer, _, _) = parsed_full(buf);
        (consumed, peer)
    }

    fn inet(ip: IpAddr, port: u16) -> Option<PeerAddr> {
        Some(PeerAddr::Inet(SocketAddr::new(ip, port)))
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
        buf.extend(std::iter::repeat_n(b'1', 200));
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
    fn v2_tlvs_after_the_address_block_are_consumed_with_the_header() {
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
    fn v1_tcp4_keeps_destination_address() {
        let buf = b"PROXY TCP4 203.0.113.7 198.51.100.1 56324 443\r\n".to_vec();
        let (_, peer, local, tlvs) = parsed_full(&buf);
        assert_eq!(peer, inet(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 56324));
        assert_eq!(local, inet(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 443));
        assert!(tlvs.is_empty());
    }

    #[test]
    fn v1_tcp6_keeps_destination_address() {
        let buf = b"PROXY TCP6 2001:db8::1 2001:db8::2 56324 25\r\n".to_vec();
        let (_, _, local, _) = parsed_full(&buf);
        assert_eq!(local, inet("2001:db8::2".parse().unwrap(), 25));
    }

    #[test]
    fn v1_unknown_has_no_destination() {
        let buf = b"PROXY UNKNOWN\r\n".to_vec();
        let (_, peer, local, tlvs) = parsed_full(&buf);
        assert_eq!(peer, None);
        assert_eq!(local, None);
        assert!(tlvs.is_empty());
    }

    #[test]
    fn v1_invalid_destination_is_rejected() {
        for line in [
            &b"PROXY TCP4 203.0.113.7 not-an-ip 56324 443\r\n"[..],
            b"PROXY TCP4 203.0.113.7 2001:db8::2 56324 443\r\n",
            b"PROXY TCP4 203.0.113.7 198.51.100.1 56324 99999\r\n",
            b"PROXY TCP4 203.0.113.7 198.51.100.1 56324\r\n",
        ] {
            assert!(
                try_parse_proxy_header(line).is_err(),
                "expected {:?} to be rejected",
                String::from_utf8_lossy(line)
            );
        }
    }

    #[test]
    fn v2_ipv4_keeps_destination_address() {
        let buf = v2_header_ipv4([203, 0, 113, 7], 56324, [198, 51, 100, 1], 443);
        let (_, peer, local, tlvs) = parsed_full(&buf);
        assert_eq!(peer, inet(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 56324));
        assert_eq!(local, inet(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 443));
        assert!(tlvs.is_empty());
    }

    #[test]
    fn v2_ipv6_keeps_destination_address() {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let mut h = V2_SIG.to_vec();
        h.push(0x21);
        h.push(0x21); // AF_INET6, STREAM
        h.extend_from_slice(&36u16.to_be_bytes());
        h.extend_from_slice(&src.octets());
        h.extend_from_slice(&dst.octets());
        h.extend_from_slice(&56324u16.to_be_bytes());
        h.extend_from_slice(&25u16.to_be_bytes());
        let (_, peer, local, _) = parsed_full(&h);
        assert_eq!(peer, inet(IpAddr::V6(src), 56324));
        assert_eq!(local, inet(IpAddr::V6(dst), 25));
    }

    #[test]
    fn v2_unix_keeps_destination_path() {
        let mut h = V2_SIG.to_vec();
        h.push(0x21);
        h.push(0x31); // AF_UNIX, STREAM
        h.extend_from_slice(&216u16.to_be_bytes());
        let mut src = [0u8; 108];
        src[..12].copy_from_slice(b"/run/relay.s");
        let mut dst = [0u8; 108];
        dst[..13].copy_from_slice(b"/run/mailer.s");
        h.extend_from_slice(&src);
        h.extend_from_slice(&dst);
        let (_, _, local, _) = parsed_full(&h);
        assert_eq!(local, Some(PeerAddr::Unix(Some(PathBuf::from("/run/mailer.s")))));
    }

    #[test]
    fn v2_tlvs_are_exposed_including_aws_vpce_id() {
        let mut buf = v2_header_ipv4([203, 0, 113, 7], 56324, [198, 51, 100, 1], 443);
        let mut tlvs: Vec<u8> = Vec::new();
        // PP2_TYPE_AUTHORITY "mx.example.org"
        tlvs.push(ProxyTlv::AUTHORITY);
        tlvs.extend_from_slice(&14u16.to_be_bytes());
        tlvs.extend_from_slice(b"mx.example.org");
        // AWS VPC endpoint ID: subtype 0x01 then the ASCII ID
        let vpce = b"vpce-0123456789abcdef0";
        tlvs.push(ProxyTlv::AWS);
        tlvs.extend_from_slice(&((vpce.len() + 1) as u16).to_be_bytes());
        tlvs.push(ProxyTlv::AWS_SUBTYPE_VPCE_ID);
        tlvs.extend_from_slice(vpce);
        let new_len = 12u16 + tlvs.len() as u16;
        buf[14..16].copy_from_slice(&new_len.to_be_bytes());
        buf.extend_from_slice(&tlvs);
        buf.extend_from_slice(b"app data");

        let (consumed, _, _, parsed_tlvs) = parsed_full(&buf);
        assert_eq!(&buf[consumed..], b"app data");
        assert_eq!(parsed_tlvs.len(), 2);
        assert_eq!(
            ProxyTlv::find(&parsed_tlvs, ProxyTlv::AUTHORITY).map(|t| t.value.as_slice()),
            Some(&b"mx.example.org"[..])
        );
        assert!(ProxyTlv::find(&parsed_tlvs, ProxyTlv::ALPN).is_none());
        assert_eq!(
            ProxyTlv::aws_vpce_id(&parsed_tlvs),
            Some("vpce-0123456789abcdef0")
        );
    }

    #[test]
    fn aws_vpce_id_ignores_other_aws_subtypes() {
        let tlvs = vec![ProxyTlv {
            kind: ProxyTlv::AWS,
            value: vec![0x02, b'x'],
        }];
        assert_eq!(ProxyTlv::aws_vpce_id(&tlvs), None);
    }

    #[test]
    fn v2_truncated_tlv_is_rejected() {
        // TLV header says 10 value bytes but only 2 remain in the header.
        let mut buf = v2_header_ipv4([203, 0, 113, 7], 56324, [198, 51, 100, 1], 443);
        let tlv: &[u8] = &[ProxyTlv::AUTHORITY, 0x00, 0x0A, b'a', b'b'];
        let new_len = 12u16 + tlv.len() as u16;
        buf[14..16].copy_from_slice(&new_len.to_be_bytes());
        buf.extend_from_slice(tlv);
        assert!(try_parse_proxy_header(&buf).is_err());

        // A TLV area too short to hold even a 3-byte TLV header.
        let mut buf = v2_header_ipv4([203, 0, 113, 7], 56324, [198, 51, 100, 1], 443);
        let new_len = 12u16 + 2;
        buf[14..16].copy_from_slice(&new_len.to_be_bytes());
        buf.extend_from_slice(&[ProxyTlv::NOOP, 0x00]);
        assert!(try_parse_proxy_header(&buf).is_err());
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
