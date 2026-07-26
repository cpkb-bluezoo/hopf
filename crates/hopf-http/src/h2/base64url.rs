// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Base64url decode (RFC 4648 §5, no-padding variant).
//!
//! Used to parse the `HTTP2-Settings` header in h2c Upgrade requests.
//! No external crates; alphabet is `A-Za-z0-9-_`.

fn char_value(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encode `input` as base64url (RFC 4648 §5, no padding) — used to build the
/// `HTTP2-Settings` header value for a client-side h2c Upgrade request.
pub fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity((input.len() * 4).div_ceil(3));
    let mut chunks = input.chunks_exact(3);
    for c in &mut chunks {
        let block = ((c[0] as u32) << 16) | ((c[1] as u32) << 8) | c[2] as u32;
        out.push(ALPHABET[(block >> 18 & 0x3f) as usize] as char);
        out.push(ALPHABET[(block >> 12 & 0x3f) as usize] as char);
        out.push(ALPHABET[(block >> 6 & 0x3f) as usize] as char);
        out.push(ALPHABET[(block & 0x3f) as usize] as char);
    }
    let rem = chunks.remainder();
    match rem.len() {
        1 => {
            let block = (rem[0] as u32) << 16;
            out.push(ALPHABET[(block >> 18 & 0x3f) as usize] as char);
            out.push(ALPHABET[(block >> 12 & 0x3f) as usize] as char);
        }
        2 => {
            let block = ((rem[0] as u32) << 16) | ((rem[1] as u32) << 8);
            out.push(ALPHABET[(block >> 18 & 0x3f) as usize] as char);
            out.push(ALPHABET[(block >> 12 & 0x3f) as usize] as char);
            out.push(ALPHABET[(block >> 6 & 0x3f) as usize] as char);
        }
        _ => {}
    }
    out
}

/// Decode a base64url-encoded string without requiring padding characters.
///
/// Returns `None` if the input contains characters outside the base64url
/// alphabet (`A-Za-z0-9-_`).
pub fn decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity((bytes.len() * 3) / 4 + 1);
    let mut i = 0;
    while i < bytes.len() {
        let remaining = bytes.len() - i;
        if remaining >= 4 {
            let v0 = char_value(bytes[i])? as u32;
            let v1 = char_value(bytes[i + 1])? as u32;
            let v2 = char_value(bytes[i + 2])? as u32;
            let v3 = char_value(bytes[i + 3])? as u32;
            let block = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;
            out.push((block >> 16) as u8);
            out.push((block >> 8) as u8);
            out.push(block as u8);
            i += 4;
        } else if remaining == 3 {
            let v0 = char_value(bytes[i])? as u32;
            let v1 = char_value(bytes[i + 1])? as u32;
            let v2 = char_value(bytes[i + 2])? as u32;
            let block = (v0 << 18) | (v1 << 12) | (v2 << 6);
            out.push((block >> 16) as u8);
            out.push((block >> 8) as u8);
            i += 3;
        } else if remaining == 2 {
            let v0 = char_value(bytes[i])? as u32;
            let v1 = char_value(bytes[i + 1])? as u32;
            let block = (v0 << 18) | (v1 << 12);
            out.push((block >> 16) as u8);
            i += 2;
        } else {
            // 1 char: 6 bits — not enough for a full byte; skip
            let _ = char_value(bytes[i])?; // validate the char
            i += 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_enable_push_zero() {
        // SETTINGS_ENABLE_PUSH=0 encoded as AAIAAAAA
        // bytes: 00 02 00 00 00 00
        let decoded = decode("AAIAAAAA").expect("valid base64url");
        assert_eq!(decoded.len() % 6, 0, "must be multiple of 6 bytes");
        assert_eq!(decoded, &[0x00, 0x02, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn decode_empty() {
        assert_eq!(decode("").unwrap(), &[] as &[u8]);
    }

    #[test]
    fn encode_enable_push_zero_matches_decode_fixture() {
        assert_eq!(encode(&[0x00, 0x02, 0x00, 0x00, 0x00, 0x00]), "AAIAAAAA");
    }

    #[test]
    fn encode_decode_roundtrip_all_remainder_lengths() {
        for input in [
            &b""[..],
            &b"f"[..],
            &b"fo"[..],
            &b"foo"[..],
            &b"foob"[..],
            &b"fooba"[..],
            &b"foobar"[..],
            &[0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05][..],
        ] {
            let encoded = encode(input);
            assert!(
                encoded.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
                "output must be padding-free base64url: {encoded:?}"
            );
            assert_eq!(decode(&encoded).unwrap(), input, "roundtrip failed for {input:?}");
        }
    }

    #[test]
    fn decode_invalid_char() {
        assert!(decode("AA==").is_none());
        assert!(decode("AA+A").is_none());
        assert!(decode("AA/A").is_none());
    }

    #[test]
    fn preface_constant_length() {
        // RFC 9113 §3.4: client preface is exactly 24 bytes
        let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        assert_eq!(preface.len(), 24);
    }
}
