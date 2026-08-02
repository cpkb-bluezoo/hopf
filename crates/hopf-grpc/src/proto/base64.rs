// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Standard Base64 (RFC 4648) for proto3 JSON `bytes` fields.

const ENC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode `data` as standard Base64 with padding.
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
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
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decode standard Base64 (padding optional). Returns `None` on invalid input.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    let bytes: Vec<u8> = s
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if bytes.is_empty() {
        return Some(Vec::new());
    }
    let pad = bytes.iter().rev().take_while(|&&b| b == b'=').count();
    if pad > 2 {
        return None;
    }
    let len = bytes.len();
    if len % 4 != 0 {
        // Allow unpadded input by synthetically padding.
        let need = (4 - (len % 4)) % 4;
        let mut padded = bytes;
        padded.extend(std::iter::repeat(b'=').take(need));
        return decode_padded(&padded);
    }
    decode_padded(&bytes)
}

fn decode_padded(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut i = 0;
    while i < bytes.len() {
        let a = if bytes[i] == b'=' {
            0
        } else {
            decode_char(bytes[i])?
        };
        let b = if bytes[i + 1] == b'=' {
            0
        } else {
            decode_char(bytes[i + 1])?
        };
        let c = if bytes[i + 2] == b'=' {
            0
        } else {
            decode_char(bytes[i + 2])?
        };
        let d = if bytes[i + 3] == b'=' {
            0
        } else {
            decode_char(bytes[i + 3])?
        };
        let n = ((a as u32) << 18) | ((b as u32) << 12) | ((c as u32) << 6) | (d as u32);
        out.push(((n >> 16) & 0xff) as u8);
        if bytes[i + 2] != b'=' {
            out.push(((n >> 8) & 0xff) as u8);
        }
        if bytes[i + 3] != b'=' {
            out.push((n & 0xff) as u8);
        }
        i += 4;
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
