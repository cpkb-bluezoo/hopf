// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Version Negotiation packets (RFC 9000 section 17.2.1, RFC 8999).
//!
//! Only the version-independent long-header invariants (first-byte form bit,
//! version, DCID, SCID) can be read from a packet of a version we don't
//! speak, so this module deals in raw byte slices: connection IDs of an
//! unknown version may be up to 255 bytes, unlike QUIC v1's 20.

use aws_lc_rs::rand::{SecureRandom, SystemRandom};

#[cfg(test)]
use crate::transport::types::VERSION_V1;

/// Smallest UDP payload that could carry a client Initial in any supported
/// version (RFC 9000 section 14.1): a server only answers unsupported
/// versions in datagrams at least this big, and never in smaller ones.
pub const MIN_INITIAL_DATAGRAM_LEN: usize = 1200;

/// The long-header invariants (RFC 8999 section 5.1) of `packet`: version,
/// DCID and SCID, or `None` for a short header or a truncated one.
pub fn parse_invariants(packet: &[u8]) -> Option<(u32, &[u8], &[u8])> {
    if packet.len() < 7 || packet[0] & 0x80 == 0 {
        return None;
    }
    let version = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]);
    let dcid_len = usize::from(packet[5]);
    let dcid = packet.get(6..6 + dcid_len)?;
    let scid_len = usize::from(*packet.get(6 + dcid_len)?);
    let scid = packet.get(7 + dcid_len..7 + dcid_len + scid_len)?;
    Some((version, dcid, scid))
}

/// A parsed Version Negotiation packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionNegotiation<'a> {
    /// Destination CID: the client's own SCID, echoed.
    pub dst_cid: &'a [u8],
    /// Source CID: the DCID the client used in its first Initial, echoed.
    pub src_cid: &'a [u8],
    /// Versions the server offers.
    pub versions: Vec<u32>,
}

/// Parse a Version Negotiation packet: long form, version 0, and a
/// non-empty list of whole 32-bit versions. `None` for anything else.
pub fn parse(packet: &[u8]) -> Option<VersionNegotiation<'_>> {
    let (version, dst_cid, src_cid) = parse_invariants(packet)?;
    if version != 0 {
        return None;
    }
    let list = &packet[7 + dst_cid.len() + src_cid.len()..];
    if list.is_empty() || list.len() % 4 != 0 {
        return None;
    }
    let versions = list.chunks_exact(4).map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]])).collect();
    Some(VersionNegotiation { dst_cid, src_cid, versions })
}

/// A reserved "greasing" version (RFC 9000 section 15: `0x?a?a?a?a`), so
/// peers that mishandle unknown values are caught by our own replies.
fn grease_version() -> u32 {
    let mut r = [0u8; 4];
    let _ = SystemRandom::new().fill(&mut r);
    (u32::from_be_bytes(r) & 0xf0f0_f0f0) | 0x0a0a_0a0a
}

/// Build the Version Negotiation reply to a client packet whose SCID was
/// `client_scid` and DCID `client_dcid`, offering `supported` versions: the
/// IDs are swapped so the client can recognise it (RFC 9000 section 17.2.1).
pub fn build(client_scid: &[u8], client_dcid: &[u8], supported: &[u32]) -> Vec<u8> {
    let mut first = [0u8; 1];
    let _ = SystemRandom::new().fill(&mut first);
    let mut out = Vec::with_capacity(7 + client_scid.len() + client_dcid.len() + 4 * (supported.len() + 1));
    out.push(0x80 | (first[0] & 0x7f)); // unused bits are arbitrary
    out.extend_from_slice(&0u32.to_be_bytes());
    out.push(client_scid.len() as u8);
    out.extend_from_slice(client_scid);
    out.push(client_dcid.len() as u8);
    out.extend_from_slice(client_dcid);
    for v in supported {
        out.extend_from_slice(&v.to_be_bytes());
    }
    out.extend_from_slice(&grease_version().to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_then_parse_round_trips_with_swapped_ids() {
        let client_scid = [1u8, 2, 3, 4, 5];
        let client_dcid: Vec<u8> = (0..30u8).collect();
        let pkt = build(&client_scid, &client_dcid, &[VERSION_V1]);
        let vn = parse(&pkt).expect("parses");
        assert_eq!(vn.dst_cid, client_scid);
        assert_eq!(vn.src_cid, client_dcid.as_slice());
        assert!(vn.versions.contains(&VERSION_V1));
        // Exactly one greased entry, of the reserved 0x?a?a?a?a shape.
        let greased: Vec<_> = vn.versions.iter().filter(|v| **v & 0x0f0f_0f0f == 0x0a0a_0a0a).collect();
        assert_eq!(greased.len(), 1, "{:x?}", vn.versions);
    }

    #[test]
    fn version_field_is_zero_and_form_bit_set_whatever_the_random_bits() {
        for _ in 0..64 {
            let pkt = build(&[1], &[2], &[VERSION_V1]);
            assert_eq!(pkt[0] & 0x80, 0x80);
            assert_eq!(&pkt[1..5], &[0, 0, 0, 0]);
        }
    }

    #[test]
    fn parse_rejects_non_vn_and_malformed_packets() {
        let good = build(&[1, 2], &[3, 4], &[VERSION_V1]);
        // Short header, non-zero version, empty / ragged version list, truncated CIDs.
        let mut short = good.clone();
        short[0] &= 0x7f;
        assert!(parse(&short).is_none());
        let mut v1 = good.clone();
        v1[1..5].copy_from_slice(&VERSION_V1.to_be_bytes());
        assert!(parse(&v1).is_none());
        assert!(parse(&good[..7 + 2 + 2]).is_none(), "no versions");
        assert!(parse(&good[..good.len() - 1]).is_none(), "ragged list");
        assert!(parse(&good[..8]).is_none(), "truncated CID");
        assert!(parse(&[]).is_none());
    }

    #[test]
    fn invariants_read_long_cids_that_a_v1_id_type_would_truncate() {
        let mut d = vec![0xc0, 0xba, 0xba, 0xba, 0xba, 40];
        d.extend((0..40u8).collect::<Vec<_>>());
        d.push(33);
        d.extend((0..33u8).collect::<Vec<_>>());
        let (v, dcid, scid) = parse_invariants(&d).unwrap();
        assert_eq!(v, 0xbabababa);
        assert_eq!(dcid.len(), 40);
        assert_eq!(scid.len(), 33);
    }
}
