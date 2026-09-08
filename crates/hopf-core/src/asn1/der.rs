// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Zero-copy DER sequential-TLV reader for one-shot, already-complete
//! buffers — X.509 certificates, PKCS#8 keys, SPKI, DER signatures. No
//! incremental feeding, no allocation: every accessor borrows straight out
//! of the caller's original slice.
//!
//! This is deliberately a *different* API shape from [`super::BerDecoder`]/
//! [`super::Asn1Element`] (which materializes an owned tree, built for
//! LDAP's genuinely-streamed messages) rather than one forced-universal
//! representation — walking a handful of fields out of a complete
//! certificate with zero allocation is a different job from decoding a
//! network stream, and conflating them would make one or the other worse
//! at what it actually needs to do. They do share the wire-level length
//! grammar via [`read_length`], since DER's length encoding is exactly
//! BER's; nothing about it is X.509-specific.
//!
//! Was previously copy-pasted (byte-for-byte identical in three places,
//! plus a fourth incompatible variant) across `crypto::x509`,
//! `crypto::cert`, `tls::handshake::verify`, and `tls::tls12::engine`.

/// Sequential reader over one constructed DER element's content (its tag
/// and length already consumed) — call [`parse_sequence`] to get one.
pub struct DerReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> DerReader<'a> {
    /// The next unread byte's tag, without consuming it.
    pub fn peek_tag(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    /// Read and return the next complete TLV (tag byte through content,
    /// inclusive), advancing past it.
    pub fn next(&mut self) -> Option<&'a [u8]> {
        let start = self.pos;
        let _tag = *self.bytes.get(self.pos)?;
        self.pos += 1;
        let (len, hdr) = read_length(&self.bytes[self.pos..])?;
        self.pos += hdr;
        let end = self.pos.checked_add(len)?;
        if end > self.bytes.len() {
            return None;
        }
        self.pos = end;
        Some(&self.bytes[start..end])
    }

    /// Read and discard the next TLV.
    pub fn skip_element(&mut self) -> Option<()> {
        self.next()?;
        Some(())
    }
}

/// Read a `SEQUENCE`'s tag and length, returning a reader over its content.
pub fn parse_sequence(bytes: &[u8]) -> Option<DerReader<'_>> {
    read_tlv_content(bytes, 0x30).map(|content| DerReader { bytes: content, pos: 0 })
}

/// Read one DER/BER length field (the bytes starting *at* the length
/// octet, i.e. right after the tag byte) — short form (`< 0x80`, the value
/// itself) or long form (`0x80 | count`, `count` big-endian length bytes
/// following, `count` capped at 4 since nothing this codebase parses is
/// anywhere near 4GB). Returns `(content length, bytes consumed by the
/// length field itself)`. Rejects indefinite length (`0x80` alone) by
/// simply not matching either form.
pub fn read_length(bytes: &[u8]) -> Option<(usize, usize)> {
    let first = *bytes.first()?;
    if first & 0x80 == 0 {
        return Some((first as usize, 1));
    }
    let count = (first & 0x7f) as usize;
    if count == 0 || count > 4 || bytes.len() < 1 + count {
        return None;
    }
    let mut len = 0usize;
    for i in 0..count {
        len = (len << 8) | bytes[1 + i] as usize;
    }
    Some((len, 1 + count))
}

/// Read one complete TLV's content, given its expected tag byte — e.g.
/// `read_tlv_content(elem, 0x04)` for an `OCTET STRING`, or a context tag
/// like `0xa3` for `[3] EXPLICIT`. `None` if `elem`'s tag doesn't match or
/// the declared length runs past the end of `elem`.
pub fn read_tlv_content(elem: &[u8], expected_tag: u8) -> Option<&[u8]> {
    if *elem.first()? != expected_tag {
        return None;
    }
    let (len, hdr) = read_length(&elem[1..])?;
    let start = 1 + hdr;
    let end = start.checked_add(len)?;
    if end > elem.len() {
        return None;
    }
    Some(&elem[start..end])
}

/// Read an `OBJECT IDENTIFIER` TLV's raw (still BER-encoded) content bytes.
pub fn read_oid(elem: &[u8]) -> Option<&[u8]> {
    read_tlv_content(elem, 0x06)
}

/// Read a `BIT STRING` TLV's content, stripping the leading unused-bits
/// count byte (0 for every key/signature encoding this crate handles —
/// callers that need to check it for non-zero can inspect `elem` directly
/// instead). `None` for a zero-length `BIT STRING` (no unused-bits byte to
/// strip) or a tag/length mismatch.
pub fn read_bit_string_content(elem: &[u8]) -> Option<&[u8]> {
    let content = read_tlv_content(elem, 0x03)?;
    if content.is_empty() {
        return None;
    }
    Some(&content[1..])
}

/// Strip a DER `INTEGER`'s content down to its minimal unsigned big-endian
/// representation — undoes the leading `0x00` pad DER adds when the
/// top-content-byte's high bit is set (to keep two's-complement values
/// non-negative). Symmetric with [`super::BerEncoder::write_integer_bytes`].
pub fn strip_integer_padding(der_integer_content: &[u8]) -> &[u8] {
    if der_integer_content.len() > 1 && der_integer_content[0] == 0 {
        &der_integer_content[1..]
    } else {
        der_integer_content
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::encoder::BerEncoder;

    #[test]
    fn parse_sequence_walks_top_level_elements() {
        let mut enc = BerEncoder::new();
        enc.begin_sequence();
        enc.write_integer_i32(1);
        enc.write_octet_string(b"hi");
        enc.end_sequence();
        let der = enc.to_bytes();

        let mut seq = parse_sequence(&der).unwrap();
        assert_eq!(seq.peek_tag(), Some(0x02));
        let a = seq.next().unwrap();
        assert_eq!(a, &[0x02, 0x01, 0x01]);
        let b = seq.next().unwrap();
        assert_eq!(b, &[0x04, 0x02, b'h', b'i']);
        assert!(seq.next().is_none());
    }

    #[test]
    fn parse_sequence_rejects_non_sequence_tag() {
        assert!(parse_sequence(&[0x02, 0x01, 0x01]).is_none());
    }

    #[test]
    fn skip_element_advances_without_returning() {
        let mut enc = BerEncoder::new();
        enc.begin_sequence();
        enc.write_boolean(true);
        enc.write_integer_i32(42);
        enc.end_sequence();
        let der = enc.to_bytes();
        let mut seq = parse_sequence(&der).unwrap();
        seq.skip_element().unwrap();
        assert_eq!(seq.next().unwrap(), &[0x02, 0x01, 42]);
    }

    #[test]
    fn read_length_short_and_long_form() {
        assert_eq!(read_length(&[0x05]), Some((5, 1)));
        assert_eq!(read_length(&[0x81, 0xC8]), Some((200, 2)));
        assert_eq!(read_length(&[0x82, 0x03, 0xE8]), Some((1000, 3)));
    }

    #[test]
    fn read_length_rejects_indefinite() {
        assert_eq!(read_length(&[0x80]), None);
    }

    #[test]
    fn read_tlv_content_matches_expected_tag() {
        let elem = [0x04, 0x03, b'a', b'b', b'c'];
        assert_eq!(read_tlv_content(&elem, 0x04), Some(&b"abc"[..]));
        assert_eq!(read_tlv_content(&elem, 0x06), None);
    }

    #[test]
    fn read_oid_extracts_raw_content() {
        // 1.2.840.113549.1.1.1 (rsaEncryption)
        let elem = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
        assert_eq!(read_oid(&elem), Some(&elem[2..]));
    }

    #[test]
    fn read_bit_string_content_strips_unused_bits_byte() {
        let elem = [0x03, 0x03, 0x00, 0xAB, 0xCD]; // 0 unused bits, content AB CD
        assert_eq!(read_bit_string_content(&elem), Some(&[0xAB, 0xCD][..]));
    }

    #[test]
    fn read_bit_string_content_rejects_empty_content() {
        let elem = [0x03, 0x00];
        assert_eq!(read_bit_string_content(&elem), None);
    }

    #[test]
    fn strip_integer_padding_removes_single_leading_zero() {
        assert_eq!(strip_integer_padding(&[0x00, 0xFF, 0x01]), &[0xFF, 0x01]);
    }

    #[test]
    fn strip_integer_padding_keeps_lone_zero_byte() {
        assert_eq!(strip_integer_padding(&[0x00]), &[0x00]);
    }

    #[test]
    fn strip_integer_padding_no_op_without_leading_zero() {
        assert_eq!(strip_integer_padding(&[0x7F, 0x01]), &[0x7F, 0x01]);
    }

    #[test]
    fn round_trips_through_encoder_for_nested_sequences() {
        let mut enc = BerEncoder::new();
        enc.begin_sequence();
        enc.begin_sequence();
        enc.write_integer_i32(7);
        enc.end_sequence();
        enc.write_octet_string(b"x");
        enc.end_sequence();
        let der = enc.to_bytes();

        let mut outer = parse_sequence(&der).unwrap();
        let inner_tlv = outer.next().unwrap();
        let mut inner = parse_sequence(inner_tlv).unwrap();
        assert_eq!(inner.next().unwrap(), &[0x02, 0x01, 0x07]);
        assert_eq!(outer.next().unwrap(), &[0x04, 0x01, b'x']);
    }
}
