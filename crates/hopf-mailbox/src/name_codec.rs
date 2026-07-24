// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Filesystem-safe mailbox name encoding.

/// Encode / decode mailbox path segments for the filesystem.
///
/// Safe characters `A–Z a–z 0–9 . _ -` are left as-is; all other bytes
/// (including `/` and non-ASCII UTF-8) become `=XX` uppercase hex.
pub struct MailboxNameCodec;

impl MailboxNameCodec {
    /// Encode a UTF-8 mailbox name for use as a path component.
    pub fn encode(name: &str) -> String {
        let mut out = String::with_capacity(name.len());
        for b in name.as_bytes() {
            if is_safe(*b) {
                out.push(*b as char);
            } else {
                out.push('=');
                out.push_str(&format!("{:02X}", b));
            }
        }
        out
    }

    /// Decode a filesystem name produced by [`encode`](Self::encode).
    pub fn decode(encoded: &str) -> String {
        let bytes = encoded.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'=' && i + 2 < bytes.len() {
                if let (Some(hi), Some(lo)) = (from_hex(bytes[i + 1]), from_hex(bytes[i + 2])) {
                    out.push((hi << 4) | lo);
                    i += 3;
                    continue;
                }
            }
            out.push(bytes[i]);
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }
}

fn is_safe(b: u8) -> bool {
    matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-')
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_unicode() {
        let name = "Données/été";
        let enc = MailboxNameCodec::encode(name);
        assert!(enc.contains('='));
        assert_eq!(MailboxNameCodec::decode(&enc), name);
    }
}
