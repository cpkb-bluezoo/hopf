// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Long-header packet codecs (RFC 9000 §17.2).

use crate::transport::packet::pn;
use crate::transport::types::ConnectionId;
use crate::transport::version::QuicVersion;
use crate::transport::varint;

// Packet types as version-independent values. Version 1 puts these on the
// wire as they are; version 2 permutes them (RFC 9369 section 3.2) - see
// `QuicVersion::wire_type` / `logical_type`.

/// Initial.
pub const TYPE_INITIAL: u8 = 0;
/// 0-RTT.
pub const TYPE_0RTT: u8 = 1;
/// Handshake.
pub const TYPE_HANDSHAKE: u8 = 2;
/// Retry.
pub const TYPE_RETRY: u8 = 3;

pub(crate) const HEADER_FORM_LONG: u8 = 0x80;
pub(crate) const FIXED_BIT: u8 = 0x40;

/// Unprotected long-header prefix (through Length; PN still protected).
#[derive(Debug, Clone)]
pub struct LongHeaderPrefix {
    /// Packet type as a version-independent `TYPE_*` value.
    pub packet_type: u8,
    /// QUIC version.
    pub version: QuicVersion,
    /// Destination Connection ID.
    pub dst_cid: ConnectionId,
    /// Source Connection ID.
    pub src_cid: ConnectionId,
    /// Token (Initial only).
    pub token: Vec<u8>,
    /// Length field (PN + payload ciphertext).
    pub length: u64,
    /// Byte offset of the (still protected) packet number.
    pub pn_offset: usize,
    /// Total header bytes through Length (exclusive of PN).
    pub prefix_len: usize,
}

/// Build unprotected long header (through PN, before header protection).
pub fn build(
    packet_type: u8,
    version: QuicVersion,
    dst_cid: &ConnectionId,
    src_cid: &ConnectionId,
    token: &[u8],
    packet_number: u64,
    pn_length: usize,
    protected_payload_len: usize,
) -> Vec<u8> {
    let remaining = (pn_length + protected_payload_len) as u64;
    let mut out = Vec::with_capacity(64);
    let first = HEADER_FORM_LONG
        | FIXED_BIT
        | (version.wire_type(packet_type) << 4)
        | ((pn_length as u8 - 1) & 0x03);
    out.push(first);
    out.extend_from_slice(&version.wire().to_be_bytes());
    out.push(dst_cid.len() as u8);
    out.extend_from_slice(dst_cid.as_slice());
    out.push(src_cid.len() as u8);
    out.extend_from_slice(src_cid.as_slice());
    if packet_type == TYPE_INITIAL {
        varint::encode(token.len() as u64, &mut out);
        out.extend_from_slice(token);
    }
    varint::encode(remaining, &mut out);
    let pn_off = out.len();
    out.resize(pn_off + pn_length, 0);
    pn::encode(packet_number, pn_length, &mut out[pn_off..]);
    out
}

/// Whether `packet` is a Retry (RFC 9000 section 17.2.5) in a version we speak.
/// The type bits are version-specific, so the version is read first.
pub fn is_retry(packet: &[u8]) -> bool {
    if packet.len() < 5 || packet[0] & HEADER_FORM_LONG == 0 {
        return false;
    }
    match QuicVersion::from_wire(u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]])) {
        Some(v) => v.logical_type((packet[0] >> 4) & 0x03) == TYPE_RETRY,
        None => false,
    }
}

/// Parse unprotected long-header prefix through Length.
pub fn parse_prefix(packet: &[u8]) -> Option<LongHeaderPrefix> {
    if packet.len() < 7 {
        return None;
    }
    let first = packet[0];
    if first & HEADER_FORM_LONG == 0 {
        return None;
    }
    // Only versions we speak can be read past the invariants; the type bits
    // mean different things in each.
    let version = QuicVersion::from_wire(u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]))?;
    let packet_type = version.logical_type((first >> 4) & 0x03);
    let mut rest = &packet[5..];
    let dcid_len = *rest.first()? as usize;
    rest = &rest[1..];
    if rest.len() < dcid_len {
        return None;
    }
    let dst_cid = ConnectionId::from_slice(&rest[..dcid_len]);
    rest = &rest[dcid_len..];
    let scid_len = *rest.first()? as usize;
    rest = &rest[1..];
    if rest.len() < scid_len {
        return None;
    }
    let src_cid = ConnectionId::from_slice(&rest[..scid_len]);
    rest = &rest[scid_len..];
    let token = if packet_type == TYPE_INITIAL {
        let token_len = varint::decode(&mut rest)? as usize;
        if rest.len() < token_len {
            return None;
        }
        let t = rest[..token_len].to_vec();
        rest = &rest[token_len..];
        t
    } else {
        Vec::new()
    };
    let length = varint::decode(&mut rest)?;
    let prefix_len = packet.len() - rest.len();
    Some(LongHeaderPrefix {
        packet_type,
        version,
        dst_cid,
        src_cid,
        token,
        length,
        pn_offset: prefix_len,
        prefix_len,
    })
}

/// Convenience: Initial packet.
pub fn build_initial(
    version: QuicVersion,
    dst_cid: &ConnectionId,
    src_cid: &ConnectionId,
    token: &[u8],
    packet_number: u64,
    pn_length: usize,
    protected_payload_len: usize,
) -> Vec<u8> {
    build(
        TYPE_INITIAL,
        version,
        dst_cid,
        src_cid,
        token,
        packet_number,
        pn_length,
        protected_payload_len,
    )
}

/// Convenience: Handshake packet.
pub fn build_handshake(
    version: QuicVersion,
    dst_cid: &ConnectionId,
    src_cid: &ConnectionId,
    packet_number: u64,
    pn_length: usize,
    protected_payload_len: usize,
) -> Vec<u8> {
    build(
        TYPE_HANDSHAKE,
        version,
        dst_cid,
        src_cid,
        &[],
        packet_number,
        pn_length,
        protected_payload_len,
    )
}

/// Convenience: 0-RTT packet.
pub fn build_0rtt(
    version: QuicVersion,
    dst_cid: &ConnectionId,
    src_cid: &ConnectionId,
    packet_number: u64,
    pn_length: usize,
    protected_payload_len: usize,
) -> Vec<u8> {
    build(
        TYPE_0RTT,
        version,
        dst_cid,
        src_cid,
        &[],
        packet_number,
        pn_length,
        protected_payload_len,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_parse_initial_prefix() {
        let dst = ConnectionId::from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let src = ConnectionId::from_slice(&[9, 10, 11, 12]);
        let header = build_initial(QuicVersion::V1, &dst, &src, &[], 0, 1, 32);
        let prefix = parse_prefix(&header).unwrap();
        assert_eq!(prefix.packet_type, TYPE_INITIAL);
        assert_eq!(prefix.version, QuicVersion::V1);
        assert_eq!(prefix.dst_cid.as_slice(), dst.as_slice());
        assert_eq!(prefix.src_cid.as_slice(), src.as_slice());
        assert_eq!(prefix.length, 1 + 32);
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
    }

    /// The unprotected headers of the RFC 9001 (v1) and RFC 9369 (v2)
    /// sample client and server Initials, built from their parameters.
    #[test]
    fn builds_the_rfc_sample_initial_headers() {
        use crate::transport::packet::{rfc9001_vectors as v1, rfc9369_vectors as v2};
        let dcid = ConnectionId::from_slice(&hex(v1::DCID));
        let none = ConnectionId::empty();
        let scid = ConnectionId::from_slice(&hex("f067a5502a4262b5"));
        // Length = 4-octet PN + 1162 frames + 16-octet tag = 1182; server 2 + 99 + 16.
        assert_eq!(build_initial(QuicVersion::V1, &dcid, &none, &[], 2, 4, 1178), hex(v1::CLIENT_INITIAL_HEADER));
        assert_eq!(build_initial(QuicVersion::V2, &dcid, &none, &[], 2, 4, 1178), hex(v2::CLIENT_INITIAL_HEADER));
        assert_eq!(build_initial(QuicVersion::V1, &none, &scid, &[], 1, 2, 115), hex(v1::SERVER_INITIAL_HEADER));
        assert_eq!(build_initial(QuicVersion::V2, &none, &scid, &[], 1, 2, 115), hex(v2::SERVER_INITIAL_HEADER));
    }

    /// Version 2 permutes the type bits (RFC 9369 section 3.2): the same
    /// logical packet type reads back through either version, and a v2
    /// Initial is *not* a v1 Initial on the wire.
    #[test]
    fn packet_types_round_trip_per_version_and_differ_on_the_wire() {
        let d = ConnectionId::from_slice(&[1; 8]);
        let s = ConnectionId::from_slice(&[2; 4]);
        for version in [QuicVersion::V1, QuicVersion::V2] {
            for (ty, header) in [
                (TYPE_INITIAL, build_initial(version, &d, &s, &[], 0, 1, 20)),
                (TYPE_HANDSHAKE, build_handshake(version, &d, &s, 0, 1, 20)),
                (TYPE_0RTT, build_0rtt(version, &d, &s, 0, 1, 20)),
            ] {
                let p = parse_prefix(&header).unwrap();
                assert_eq!((p.packet_type, p.version), (ty, version));
            }
        }
        let v1 = build_initial(QuicVersion::V1, &d, &s, &[], 0, 1, 20);
        let v2 = build_initial(QuicVersion::V2, &d, &s, &[], 0, 1, 20);
        assert_eq!((v1[0] >> 4) & 3, 0b00);
        assert_eq!((v2[0] >> 4) & 3, 0b01);
    }

    #[test]
    fn unsupported_versions_have_no_readable_prefix() {
        let mut header = build_initial(QuicVersion::V1, &ConnectionId::from_slice(&[1; 8]), &ConnectionId::empty(), &[], 0, 1, 20);
        header[1..5].copy_from_slice(&0x1a2a_3a4au32.to_be_bytes());
        assert!(parse_prefix(&header).is_none());
        assert!(!is_retry(&header));
    }
}
