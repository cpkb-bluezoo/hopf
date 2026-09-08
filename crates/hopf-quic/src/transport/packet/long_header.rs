// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Long-header packet codecs (RFC 9000 §17.2).

use crate::transport::packet::pn;
use crate::transport::types::{ConnectionId, VERSION_V1};
use crate::transport::varint;

/// Initial packet type bits.
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
    /// Packet type (0–3).
    pub packet_type: u8,
    /// QUIC version.
    pub version: u32,
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
    version: u32,
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
        | ((packet_type & 0x03) << 4)
        | ((pn_length as u8 - 1) & 0x03);
    out.push(first);
    out.extend_from_slice(&version.to_be_bytes());
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

/// Parse unprotected long-header prefix through Length.
pub fn parse_prefix(packet: &[u8]) -> Option<LongHeaderPrefix> {
    if packet.len() < 7 {
        return None;
    }
    let first = packet[0];
    if first & HEADER_FORM_LONG == 0 {
        return None;
    }
    let packet_type = (first >> 4) & 0x03;
    let version = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]);
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

/// Convenience: Initial packet for QUIC v1.
pub fn build_initial(
    dst_cid: &ConnectionId,
    src_cid: &ConnectionId,
    token: &[u8],
    packet_number: u64,
    pn_length: usize,
    protected_payload_len: usize,
) -> Vec<u8> {
    build(
        TYPE_INITIAL,
        VERSION_V1,
        dst_cid,
        src_cid,
        token,
        packet_number,
        pn_length,
        protected_payload_len,
    )
}

/// Convenience: Handshake packet for QUIC v1.
pub fn build_handshake(
    dst_cid: &ConnectionId,
    src_cid: &ConnectionId,
    packet_number: u64,
    pn_length: usize,
    protected_payload_len: usize,
) -> Vec<u8> {
    build(
        TYPE_HANDSHAKE,
        VERSION_V1,
        dst_cid,
        src_cid,
        &[],
        packet_number,
        pn_length,
        protected_payload_len,
    )
}

/// Convenience: 0-RTT packet for QUIC v1.
pub fn build_0rtt(
    dst_cid: &ConnectionId,
    src_cid: &ConnectionId,
    packet_number: u64,
    pn_length: usize,
    protected_payload_len: usize,
) -> Vec<u8> {
    build(
        TYPE_0RTT,
        VERSION_V1,
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
        let header = build_initial(&dst, &src, &[], 0, 1, 32);
        let prefix = parse_prefix(&header).unwrap();
        assert_eq!(prefix.packet_type, TYPE_INITIAL);
        assert_eq!(prefix.version, VERSION_V1);
        assert_eq!(prefix.dst_cid.as_slice(), dst.as_slice());
        assert_eq!(prefix.src_cid.as_slice(), src.as_slice());
        assert_eq!(prefix.length, 1 + 32);
    }
}
