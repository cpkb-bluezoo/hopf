// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 9484 §4 capsules layered on top of [`hopf_http::capsule`]'s generic
//! Capsule Protocol (RFC 9297 §3) machinery: `ADDRESS_ASSIGN`,
//! `ADDRESS_REQUEST` (identically shaped, one entry per assigned/requested
//! address), and `ROUTE_ADVERTISEMENT` (one entry per advertised range).
//! `DATAGRAM` (RFC 9297's own, for IP packets) needs no codec of its own
//! here — see [`crate::ip_relay`], which uses [`hopf_http::capsule::Capsule::datagram`]
//! directly, same as CONNECT-UDP's relay.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// `ADDRESS_ASSIGN` capsule type (RFC 9484 §4.2).
pub(crate) const CAPSULE_ADDRESS_ASSIGN: u64 = 0x01;
/// `ADDRESS_REQUEST` capsule type (RFC 9484 §4.2).
pub(crate) const CAPSULE_ADDRESS_REQUEST: u64 = 0x02;
/// `ROUTE_ADVERTISEMENT` capsule type (RFC 9484 §4.3).
pub(crate) const CAPSULE_ROUTE_ADVERTISEMENT: u64 = 0x03;

/// One `Assigned Address` / `Requested Address` entry (RFC 9484 §4.2) —
/// the two capsules share this exact shape, differing only in which
/// direction they travel and what the Request ID means (server-chosen
/// correlation vs. client-chosen, per RFC 9484 §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AddressEntry {
    pub(crate) request_id: u64,
    pub(crate) address: IpAddr,
    pub(crate) prefix_length: u8,
}

/// One `IP Address Range` entry (RFC 9484 §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RouteEntry {
    pub(crate) start: IpAddr,
    pub(crate) end: IpAddr,
    /// `0` means all protocols (RFC 9484 §4.3).
    pub(crate) ip_protocol: u8,
}

impl RouteEntry {
    /// `None` if `start`/`end` are different IP versions, or `start` sorts
    /// after `end` — RFC 9484 §4.3: "The Start IP Address MUST be less
    /// than or equal to the End IP Address."
    pub(crate) fn new(start: IpAddr, end: IpAddr, ip_protocol: u8) -> Option<Self> {
        let same_family = matches!((start, end), (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)));
        if !same_family || start > end {
            return None;
        }
        Some(Self { start, end, ip_protocol })
    }
}

fn encode_varint(out: &mut Vec<u8>, value: u64) {
    // RFC 9000 §16 QUIC variable-length integer — the same encoding
    // `hopf_http::context_id` uses for its Context ID field, reimplemented
    // here since that crate's `varint` module is private to it.
    let (len, tag): (usize, u8) = if value < (1 << 6) {
        (1, 0)
    } else if value < (1 << 14) {
        (2, 0x40)
    } else if value < (1 << 30) {
        (4, 0x80)
    } else {
        (8, 0xc0)
    };
    let encoded = value | (u64::from(tag) << ((len - 1) * 8));
    for shift in (0..len).rev().map(|n| n * 8) {
        out.push((encoded >> shift) as u8);
    }
}

fn decode_varint(input: &[u8]) -> Option<(u64, usize)> {
    let first = *input.first()?;
    let len = 1usize << (first >> 6);
    if input.len() < len {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &input[1..len] {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, len))
}

fn encode_ip_address(out: &mut Vec<u8>, addr: IpAddr) {
    match addr {
        IpAddr::V4(v4) => {
            out.push(4);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(6);
            out.extend_from_slice(&v6.octets());
        }
    }
}

/// Decode an `IP Version` byte plus the address bytes it introduces.
/// Returns the address and the total bytes consumed (1 + 4, or 1 + 16).
fn decode_ip_address(buf: &[u8]) -> Option<(IpAddr, usize)> {
    match *buf.first()? {
        4 => {
            let b = buf.get(1..5)?;
            Some((IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])), 5))
        }
        6 => {
            let b: [u8; 16] = buf.get(1..17)?.try_into().ok()?;
            Some((IpAddr::V6(Ipv6Addr::from(b)), 17))
        }
        _ => None,
    }
}

fn encode_address_entry(out: &mut Vec<u8>, entry: &AddressEntry) {
    encode_varint(out, entry.request_id);
    encode_ip_address(out, entry.address);
    out.push(entry.prefix_length);
}

fn decode_address_entry(buf: &[u8]) -> Option<(AddressEntry, usize)> {
    let (request_id, n1) = decode_varint(buf)?;
    let (address, n2) = decode_ip_address(&buf[n1..])?;
    let prefix_length = *buf.get(n1 + n2)?;
    let max_prefix = if address.is_ipv4() { 32 } else { 128 };
    if prefix_length > max_prefix {
        return None;
    }
    Some((AddressEntry { request_id, address, prefix_length }, n1 + n2 + 1))
}

/// Encode one or more entries as an `ADDRESS_ASSIGN`/`ADDRESS_REQUEST`
/// capsule value (RFC 9484 §4.2: repeated `Assigned Address`/`Requested
/// Address` structures fill the capsule).
pub(crate) fn encode_address_entries(entries: &[AddressEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    for e in entries {
        encode_address_entry(&mut out, e);
    }
    out
}

/// Decode a full `ADDRESS_ASSIGN`/`ADDRESS_REQUEST` capsule value into its
/// entries. `None` on any malformed or trailing-partial entry.
pub(crate) fn decode_address_entries(value: &[u8]) -> Option<Vec<AddressEntry>> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < value.len() {
        let (entry, consumed) = decode_address_entry(&value[pos..])?;
        out.push(entry);
        pos += consumed;
    }
    Some(out)
}

fn encode_route_entry(out: &mut Vec<u8>, entry: &RouteEntry) {
    // `RouteEntry::new` already established `start`/`end` share a family —
    // one `IP Version` byte covers both (RFC 9484 §4.3's `IP Address
    // Range`), so only `start`'s tag is written; `end`'s address bytes
    // follow at the same width without repeating it.
    encode_ip_address(out, entry.start);
    match entry.end {
        IpAddr::V4(v4) => out.extend_from_slice(&v4.octets()),
        IpAddr::V6(v6) => out.extend_from_slice(&v6.octets()),
    }
    out.push(entry.ip_protocol);
}

fn decode_route_entry(buf: &[u8]) -> Option<(RouteEntry, usize)> {
    let (start, n1) = decode_ip_address(buf)?;
    let addr_len = if start.is_ipv4() { 4 } else { 16 };
    // `start`'s IP Version tag (already consumed as part of `n1`) applies
    // to both addresses — `end` is that same width with no tag of its own.
    let end_bytes = buf.get(n1..n1 + addr_len)?;
    let end = match start {
        IpAddr::V4(_) => {
            IpAddr::V4(Ipv4Addr::new(end_bytes[0], end_bytes[1], end_bytes[2], end_bytes[3]))
        }
        IpAddr::V6(_) => {
            let b: [u8; 16] = end_bytes.try_into().ok()?;
            IpAddr::V6(Ipv6Addr::from(b))
        }
    };
    let ip_protocol = *buf.get(n1 + addr_len)?;
    let entry = RouteEntry::new(start, end, ip_protocol)?;
    Some((entry, n1 + addr_len + 1))
}

/// Encode one or more entries as a `ROUTE_ADVERTISEMENT` capsule value.
pub(crate) fn encode_route_entries(entries: &[RouteEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    for e in entries {
        encode_route_entry(&mut out, e);
    }
    out
}

/// Decode a full `ROUTE_ADVERTISEMENT` capsule value into its entries —
/// the relay (server) side only ever encodes one of these (RFC 9484 §4.3
/// is server-to-client only); decoding is the client's job (see
/// [`crate::ip_client`]).
pub(crate) fn decode_route_entries(value: &[u8]) -> Option<Vec<RouteEntry>> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < value.len() {
        let (entry, consumed) = decode_route_entry(&value[pos..])?;
        out.push(entry);
        pos += consumed;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_entry_round_trips_ipv4() {
        let e = AddressEntry { request_id: 7, address: "192.0.2.1".parse().unwrap(), prefix_length: 32 };
        let bytes = encode_address_entries(&[e]);
        assert_eq!(decode_address_entries(&bytes).unwrap(), vec![e]);
    }

    #[test]
    fn address_entry_round_trips_ipv6() {
        let e = AddressEntry {
            request_id: 300, // needs a multi-byte varint
            address: "2001:db8::1".parse().unwrap(),
            prefix_length: 128,
        };
        let bytes = encode_address_entries(&[e]);
        assert_eq!(decode_address_entries(&bytes).unwrap(), vec![e]);
    }

    #[test]
    fn address_entries_round_trip_multiple_packed_into_one_capsule() {
        let a = AddressEntry { request_id: 1, address: "192.0.2.1".parse().unwrap(), prefix_length: 32 };
        let b = AddressEntry { request_id: 2, address: "2001:db8::2".parse().unwrap(), prefix_length: 64 };
        let bytes = encode_address_entries(&[a, b]);
        assert_eq!(decode_address_entries(&bytes).unwrap(), vec![a, b]);
    }

    #[test]
    fn address_entry_rejects_prefix_length_past_the_address_width() {
        let e = AddressEntry { request_id: 1, address: "192.0.2.1".parse().unwrap(), prefix_length: 33 };
        let bytes = encode_address_entries(&[e]);
        assert!(decode_address_entries(&bytes).is_none());
    }

    #[test]
    fn address_entries_reject_a_truncated_trailing_entry() {
        let e = AddressEntry { request_id: 1, address: "192.0.2.1".parse().unwrap(), prefix_length: 32 };
        let mut bytes = encode_address_entries(&[e]);
        bytes.pop();
        assert!(decode_address_entries(&bytes).is_none());
    }

    #[test]
    fn route_entry_rejects_mismatched_address_families() {
        let v4: IpAddr = "192.0.2.1".parse().unwrap();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(RouteEntry::new(v4, v6, 0).is_none());
    }

    #[test]
    fn route_entry_rejects_start_after_end() {
        let start: IpAddr = "192.0.2.10".parse().unwrap();
        let end: IpAddr = "192.0.2.1".parse().unwrap();
        assert!(RouteEntry::new(start, end, 0).is_none());
    }

    #[test]
    fn route_entry_round_trips_ipv4() {
        let e = RouteEntry::new("192.0.2.0".parse().unwrap(), "192.0.2.255".parse().unwrap(), 17).unwrap();
        let bytes = encode_route_entries(&[e]);
        assert_eq!(decode_route_entries(&bytes).unwrap(), vec![e]);
    }

    #[test]
    fn route_entry_round_trips_ipv6_with_wildcard_protocol() {
        let e = RouteEntry::new("2001:db8::".parse().unwrap(), "2001:db8::ffff".parse().unwrap(), 0).unwrap();
        let bytes = encode_route_entries(&[e]);
        assert_eq!(decode_route_entries(&bytes).unwrap(), vec![e]);
    }

    #[test]
    fn route_entries_round_trip_multiple_packed_into_one_capsule() {
        let a = RouteEntry::new("192.0.2.0".parse().unwrap(), "192.0.2.255".parse().unwrap(), 6).unwrap();
        let b = RouteEntry::new("2001:db8::".parse().unwrap(), "2001:db8::ffff".parse().unwrap(), 17).unwrap();
        let bytes = encode_route_entries(&[a, b]);
        assert_eq!(decode_route_entries(&bytes).unwrap(), vec![a, b]);
    }

    #[test]
    fn route_entries_reject_a_truncated_trailing_entry() {
        let e = RouteEntry::new("192.0.2.0".parse().unwrap(), "192.0.2.255".parse().unwrap(), 6).unwrap();
        let mut bytes = encode_route_entries(&[e]);
        bytes.pop();
        assert!(decode_route_entries(&bytes).is_none());
    }
}
