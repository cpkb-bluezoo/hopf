// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Standard Base64 (RFC 4648) for proto3 JSON `bytes` fields.

const ENC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode `data` as standard Base64 with padding.
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        out.push(ENC[((n >> 18) & 0x3f) as usize] as char);
        out.push(ENC[((n >> 12) & 0x3f) as usize] as char);
        out.push(ENC[((n >> 6) & 0x3f) as usize] as char);
        out.push(ENC[(n & 0x3f) as usize] as char);
        i += 3;
    }
    let rem = data.len() - i;
    if rem == 1 {
        let n = (data[i] as u32) << 16;
        out.push(ENC[((n >> 18) & 0x3f) as usize] as char);
        out.push(ENC[((n >> 12) & 0x3f) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
        out.push(ENC[((n >> 18) & 0x3f) as usize] as char);
        out.push(ENC[((n >> 12) & 0x3f) as usize] as char);
        out.push(ENC[((n >> 6) & 0x3f) as usize] as char);
        out.push('=');
    }
    out
}

fn decode_char(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        // The standard alphabet and the URL-safe one: proto3 JSON parsers
        // accept either for `bytes`.
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

/// Decode Base64, standard or URL-safe alphabet, padding optional. Returns
/// `None` on invalid input: a character outside the alphabets, `=` anywhere
/// but the end, padding that does not complete a group, or a length no
/// whole number of bytes encodes.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    let bytes: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let pad = bytes.iter().rev().take_while(|&&b| b == b'=').count();
    if pad > 2 {
        return None;
    }
    let body = &bytes[..bytes.len() - pad];
    if body.contains(&b'=') {
        return None;
    }
    // With padding the group must be completed; without it any length but
    // 1 mod 4 (a single sextet carries no whole byte) is fine.
    if pad > 0 && bytes.len() % 4 != 0 {
        return None;
    }
    if body.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(body.len() / 4 * 3 + 2);
    for chunk in body.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= u32::from(decode_char(c)?) << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        for data in [
            &b""[..],
            b"f",
            b"fo",
            b"foo",
            b"foob",
            b"fooba",
            b"foobar",
            &[0u8, 1, 2, 255, 128],
        ] {
            let enc = encode(data);
            assert_eq!(decode(&enc).as_deref(), Some(data));
        }
    }
}
