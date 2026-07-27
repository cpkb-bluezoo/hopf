// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! NSEC/NSEC3 type bitmap encode/decode (RFC 4034 §4.1.2).

/// Encode a set of RR type values as consecutive 256-type windows.
pub(crate) fn encode_type_bitmap(mut types: Vec<u16>) -> Vec<u8> {
    types.sort_unstable();
    types.dedup();
    let mut out = Vec::new();
    let mut i = 0;
    while i < types.len() {
        let window = (types[i] >> 8) as u8;
        let mut bitmap = [0u8; 32];
        let mut max_octet = 0usize;
        while i < types.len() && (types[i] >> 8) as u8 == window {
            let lo = (types[i] & 0xFF) as usize;
            let octet = lo / 8;
            bitmap[octet] |= 0x80 >> (lo % 8);
            max_octet = max_octet.max(octet);
            i += 1;
        }
        let len = max_octet + 1;
        out.push(window);
        out.push(len as u8);
        out.extend_from_slice(&bitmap[..len]);
    }
    out
}

/// Decode a type bitmap into the set of RR type values present.
pub(crate) fn decode_type_bitmap(data: &[u8]) -> Option<Vec<u16>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        if i + 2 > data.len() {
            return None;
        }
        let window = data[i] as u16;
        let len = data[i + 1] as usize;
        i += 2;
        if len == 0 || len > 32 || i + len > data.len() {
            return None;
        }
        for (octet, &byte) in data[i..i + len].iter().enumerate() {
            for bit in 0..8 {
                if byte & (0x80 >> bit) != 0 {
                    out.push((window << 8) | ((octet * 8 + bit) as u16));
                }
            }
        }
        i += len;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitmap_roundtrip_across_multiple_windows() {
        let types = vec![1u16, 15, 16, 46, 47, 48, 258, 65280];
        let encoded = encode_type_bitmap(types.clone());
        let mut decoded = decode_type_bitmap(&encoded).unwrap();
        decoded.sort_unstable();
        let mut expected = types;
        expected.sort_unstable();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn empty_bitmap_roundtrips() {
        assert_eq!(encode_type_bitmap(vec![]), Vec::<u8>::new());
        assert_eq!(decode_type_bitmap(&[]), Some(Vec::new()));
    }

    #[test]
    fn truncated_window_length_is_rejected() {
        // window 0, claimed length 5, but only 2 bytes follow.
        assert_eq!(decode_type_bitmap(&[0, 5, 0xFF, 0xFF]), None);
    }
}
