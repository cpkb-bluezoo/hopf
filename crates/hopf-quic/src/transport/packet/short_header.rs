// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Short-header (1-RTT) packet codec (RFC 9000 §17.3).

use crate::transport::packet::pn;
use crate::transport::types::ConnectionId;

const HEADER_FORM_SHORT: u8 = 0x00;
const FIXED_BIT: u8 = 0x40;

/// Unprotected short-header prefix (through DCID; PN still protected).
#[derive(Debug, Clone)]
pub struct ShortHeaderPrefix {
    /// Destination Connection ID.
    pub dst_cid: ConnectionId,
    /// Byte offset of the (still protected) packet number.
    pub pn_offset: usize,
    /// Spin bit.
    pub spin: bool,
    /// Key phase bit (still protected until header protection removed).
    pub key_phase: bool,
}

/// Build unprotected short header through PN.
pub fn build(
    dst_cid: &ConnectionId,
    spin: bool,
    key_phase: bool,
    packet_number: u64,
    pn_length: usize,
) -> Vec<u8> {
    let mut first = HEADER_FORM_SHORT | FIXED_BIT | ((pn_length as u8 - 1) & 0x03);
    if spin {
        first |= 0x20;
    }
    if key_phase {
        first |= 0x04;
    }
    let mut out = Vec::with_capacity(1 + dst_cid.len() + pn_length);
    out.push(first);
    out.extend_from_slice(dst_cid.as_slice());
    let pn_off = out.len();
    out.resize(pn_off + pn_length, 0);
    pn::encode(packet_number, pn_length, &mut out[pn_off..]);
    out
}

/// Parse short-header prefix through DCID (requires known CID length).
pub fn parse_prefix(packet: &[u8], cid_len: usize) -> Option<ShortHeaderPrefix> {
    if packet.is_empty() || packet[0] & 0x80 != 0 {
        return None;
    }
    if packet.len() < 1 + cid_len {
        return None;
    }
    let first = packet[0];
    let dst_cid = ConnectionId::from_slice(&packet[1..1 + cid_len]);
    Some(ShortHeaderPrefix {
        dst_cid,
        pn_offset: 1 + cid_len,
        spin: first & 0x20 != 0,
        key_phase: first & 0x04 != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_parse_short() {
        let dst = ConnectionId::from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let header = build(&dst, false, false, 5, 1);
        let prefix = parse_prefix(&header, 8).unwrap();
        assert_eq!(prefix.dst_cid.as_slice(), dst.as_slice());
        assert_eq!(prefix.pn_offset, 9);
    }
}
