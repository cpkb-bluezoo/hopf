// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Shared crypto helpers for SASL and HTTP Digest (Gumdrop `SASLUtils` parity).

use hmac::{Hmac, Mac};
use md5::{Digest as _, Md5};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacMd5 = Hmac<Md5>;
type HmacSha256 = Hmac<Sha256>;

/// Lowercase hex encode.
pub fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

/// Decode lowercase/uppercase hex; `None` on bad input.
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Constant-time equality for equal-length slices.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    bool::from(a.ct_eq(b))
}

/// Constant-time compare of ASCII hex digests (case-insensitive).
pub fn ct_eq_hex(a: &str, b: &str) -> bool {
    let al = a.to_ascii_lowercase();
    let bl = b.to_ascii_lowercase();
    ct_eq(al.as_bytes(), bl.as_bytes())
}

/// RFC 1321 MD5.
pub fn md5(data: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(data);
    h.finalize().into()
}

/// MD5 as lowercase hex.
pub fn md5_hex(data: &[u8]) -> String {
    to_hex(&md5(data))
}

/// SHA-256.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// HMAC-MD5.
pub fn hmac_md5(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacMd5::new_from_slice(key).expect("HMAC-MD5 accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// HMAC-SHA-256.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// PBKDF2-HMAC-SHA256 → 32-byte key (SCRAM-SHA-256).
pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut out);
    out
}

/// RFC 4648 §4 Base64 encode (standard alphabet, with padding).
pub fn encode_base64(data: &[u8]) -> String {
    const T: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | data[i + 2] as u32;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(T[((n >> 6) & 63) as usize] as char);
        out.push(T[(n & 63) as usize] as char);
        i += 3;
    }
    let rem = data.len() - i;
    if rem == 1 {
        let n = (data[i] as u32) << 16;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(T[((n >> 6) & 63) as usize] as char);
        out.push('=');
    }
    out
}

/// RFC 4648 §4 Base64 decode.
pub fn decode_base64(input: &str) -> Option<Vec<u8>> {
    fn val(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            b'=' => Some(0),
            _ => None,
        }
    }
    let bytes: Vec<u8> = input
        .as_bytes()
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if bytes.is_empty() {
        return Some(Vec::new());
    }
    if bytes.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut i = 0;
    while i + 4 <= bytes.len() {
        let pad = (bytes[i + 2] == b'=') as usize + (bytes[i + 3] == b'=') as usize;
        let v0 = val(bytes[i])? as u32;
        let v1 = val(bytes[i + 1])? as u32;
        let v2 = val(bytes[i + 2])? as u32;
        let v3 = val(bytes[i + 3])? as u32;
        let block = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;
        out.push((block >> 16) as u8);
        if pad < 2 {
            out.push((block >> 8) as u8);
        }
        if pad < 1 {
            out.push(block as u8);
        }
        i += 4;
    }
    Some(out)
}

/// Cryptographically strong hex nonce (`nbytes` random bytes → 2× hex chars).
pub fn generate_nonce_hex(nbytes: usize) -> String {
    let mut buf = vec![0u8; nbytes];
    getrandom::getrandom(&mut buf).expect("OS RNG");
    to_hex(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip() {
        let s = b"alice:s3cret";
        let e = encode_base64(s);
        assert_eq!(e, "YWxpY2U6czNjcmV0");
        assert_eq!(decode_base64(&e).unwrap(), s);
    }

    #[test]
    fn md5_empty() {
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
    }
}
