// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 1928 §7 SOCKS5 UDP request header codec:
//!
//! ```text
//! +----+------+------+----------+----------+----------+
//! |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//! +----+------+------+----------+----------+----------+
//! | 2  |  1   |  1   | Variable |    2     | Variable |
//! +----+------+------+----------+----------+----------+
//! ```
//!
//! Unlike the TCP handshake/request codecs in [`crate::wire`], a UDP
//! datagram always arrives whole — there is no "wait for more bytes"
//! case, so parsing here is a plain `Option`, not the incremental
//! `ParseResult` those use.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::wire::SocksAddress;

/// The only `FRAG` value ever forwarded: a standalone (non-fragmented)
/// datagram. RFC 1928 §7 says non-standalone fragments (out-of-order or
/// duplicate) "MUST" be dropped — this crate implements no fragment
/// reassembly at all, matching near-universal real-world SOCKS5 practice.
pub(crate) const FRAG_STANDALONE: u8 = 0x00;

/// A parsed RFC 1928 §7 header, with the payload borrowed from the same
/// input the header itself was parsed from.
pub(crate) struct UdpHeader<'a> {
    pub(crate) frag: u8,
    pub(crate) address: SocksAddress,
    pub(crate) port: u16,
    pub(crate) payload: &'a [u8],
}

/// Parse one datagram's RFC 1928 §7 header. `RSV` is parsed-but-ignored.
/// Returns `None` for a truncated header or an unrecognized `ATYP` —
/// there is no reply channel for a malformed UDP datagram (RFC 1928 §7),
/// so the only correct response is to drop it, not to report an error.
pub(crate) fn parse(data: &[u8]) -> Option<UdpHeader<'_>> {
    if data.len() < 4 {
        return None;
    }
    let frag = data[2];
    let atyp = data[3];
    let (address, addr_len) = match atyp {
        0x01 => {
            if data.len() < 4 + 4 {
                return None;
            }
            let ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            (SocksAddress::Ip(IpAddr::V4(ip)), 4)
        }
        0x04 => {
            if data.len() < 4 + 16 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[4..20]);
            (SocksAddress::Ip(IpAddr::V6(Ipv6Addr::from(octets))), 16)
        }
        0x03 => {
            if data.len() < 5 {
                return None;
            }
            let len = data[4] as usize;
            if data.len() < 5 + len {
                return None;
            }
            let host = std::str::from_utf8(&data[5..5 + len]).ok()?;
            (SocksAddress::Domain(host.to_string()), 1 + len)
        }
        _ => return None,
    };
    let port_offset = 4 + addr_len;
    if data.len() < port_offset + 2 {
        return None;
    }
    let port = u16::from_be_bytes([data[port_offset], data[port_offset + 1]]);
    let payload = &data[port_offset + 2..];
    Some(UdpHeader { frag, address, port, payload })
}

/// Encode a reply header carrying `from` (the actual source of the
/// datagram being relayed back to the client) as `DST.ADDR`/`DST.PORT`,
/// followed by `payload`. Always standalone (`FRAG = 0`); domain names
/// never appear in an encoded header — replies always carry a resolved
/// socket address.
pub(crate) fn encode(from: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 18 + payload.len());
    out.extend_from_slice(&[0, 0]); // RSV
    out.push(FRAG_STANDALONE);
    match from.ip() {
        IpAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(0x04);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&from.port().to_be_bytes());
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_an_ipv4_header() {
        let addr: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let encoded = encode(addr, b"payload");
        let parsed = parse(&encoded).unwrap();
        assert_eq!(parsed.frag, FRAG_STANDALONE);
        assert_eq!(parsed.address, SocksAddress::Ip(addr.ip()));
        assert_eq!(parsed.port, addr.port());
        assert_eq!(parsed.payload, b"payload");
    }

    #[test]
    fn round_trips_an_ipv6_header() {
        let addr: SocketAddr = "[2001:db8::1]:8080".parse().unwrap();
        let encoded = encode(addr, b"hi");
        let parsed = parse(&encoded).unwrap();
        assert_eq!(parsed.address, SocksAddress::Ip(addr.ip()));
        assert_eq!(parsed.port, 8080);
        assert_eq!(parsed.payload, b"hi");
    }

    #[test]
    fn parses_a_domain_name_target() {
        let mut data = vec![0, 0, 0x00, 0x03, 11];
        data.extend_from_slice(b"example.com");
        data.extend_from_slice(&443u16.to_be_bytes());
        data.extend_from_slice(b"payload");
        let parsed = parse(&data).unwrap();
        assert_eq!(parsed.address, SocksAddress::Domain("example.com".to_string()));
        assert_eq!(parsed.payload, b"payload");
    }

    #[test]
    fn preserves_a_nonstandard_frag_value_for_the_caller_to_drop() {
        // Parsing itself doesn't enforce the "standalone only" rule —
        // that's the relay's job (see `crate::udp_associate`) — but the
        // parsed value must be reported accurately so the caller can.
        let mut data = vec![0, 0, 0x01, 0x01];
        data.extend_from_slice(&[1, 2, 3, 4]);
        data.extend_from_slice(&0u16.to_be_bytes());
        let parsed = parse(&data).unwrap();
        assert_eq!(parsed.frag, 0x01);
    }

    #[test]
    fn empty_payload_is_valid() {
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let encoded = encode(addr, b"");
        let parsed = parse(&encoded).unwrap();
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn truncated_header_returns_none() {
        assert!(parse(&[0, 0, 0]).is_none());
        assert!(parse(&[0, 0, 0x00, 0x01, 1, 2, 3]).is_none());
    }

    #[test]
    fn unknown_atyp_returns_none() {
        let data = vec![0, 0, 0x00, 0x7f];
        assert!(parse(&data).is_none());
    }

    #[test]
    fn domain_name_waits_for_full_length() {
        let data = vec![0, 0, 0x00, 0x03, 11, b'e', b'x'];
        assert!(parse(&data).is_none());
    }
}
