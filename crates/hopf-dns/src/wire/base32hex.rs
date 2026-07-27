// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! base32hex codec (RFC 4648 §7), unpadded — the presentation format NSEC3
//! uses for owner-name / next-hashed-owner labels (RFC 5155 §1).

const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";

/// Encode to uppercase, unpadded base32hex.
pub fn encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut bits: u32 = 0;
    let mut bit_count: u32 = 0;
    for &byte in data {
        bits = (bits << 8) | byte as u32;
        bit_count += 8;
        while bit_count >= 5 {
            bit_count -= 5;
            out.push(ALPHABET[((bits >> bit_count) & 0x1F) as usize] as char);
        }
    }
    if bit_count > 0 {
        out.push(ALPHABET[((bits << (5 - bit_count)) & 0x1F) as usize] as char);
    }
    out
}

/// Decode unpadded (or `=`-padded) base32hex; case-insensitive.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut bits: u32 = 0;
    let mut bit_count: u32 = 0;
    for c in s.chars() {
        if c == '=' {
            break;
        }
        let val = ALPHABET
            .iter()
            .position(|&b| b.eq_ignore_ascii_case(&(c as u8)))? as u32;
        bits = (bits << 5) | val;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            out.push(((bits >> bit_count) & 0xFF) as u8);
        }
    }
    Some(out)
}

/// Decode an NSEC3 owner name's leading (hash) label back to raw bytes.
pub fn decode_owner_label(name: &str) -> Option<Vec<u8>> {
    decode(name.split('.').next()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_lengths() {
        let samples: &[&[u8]] = &[b"", b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar", &[0xDE, 0xAD, 0xBE, 0xEF]];
        for data in samples {
            let enc = encode(data);
            let dec = decode(&enc).unwrap();
            assert_eq!(&dec, data, "roundtrip failed for {data:?} -> {enc}");
        }
    }

    #[test]
    fn decode_is_case_insensitive() {
        assert_eq!(decode("q04"), decode("Q04"));
    }

    #[test]
    fn owner_label_decodes_only_the_leading_label() {
        let hash = [1u8, 2, 3, 4, 5];
        let encoded = encode(&hash);
        let name = format!("{encoded}.example.com");
        assert_eq!(decode_owner_label(&name), Some(hash.to_vec()));
    }
}
