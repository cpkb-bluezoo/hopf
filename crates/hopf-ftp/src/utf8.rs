// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 2640 control-channel charset (`OPTS UTF8`).

/// Error decoding a command argument under the active charset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathnameCharsetError {
    /// Bytes are not valid UTF-8 (`OPTS UTF8 ON`).
    InvalidUtf8,
    /// High bytes present without `OPTS UTF8 ON`.
    NonAscii,
}

/// Decode a control-command argument / pathname.
///
/// * `utf8 == true` — strict UTF-8 (RFC 2640 after `OPTS UTF8 ON`).
/// * `utf8 == false` — 7-bit US-ASCII only; reject any byte ≥ 0x80.
pub fn decode_arg(bytes: &[u8], utf8: bool) -> Result<String, PathnameCharsetError> {
    if utf8 {
        std::str::from_utf8(bytes)
            .map(|s| s.to_string())
            .map_err(|_| PathnameCharsetError::InvalidUtf8)
    } else if bytes.iter().any(|b| !b.is_ascii()) {
        Err(PathnameCharsetError::NonAscii)
    } else {
        // ASCII is valid UTF-8.
        Ok(String::from_utf8(bytes.to_vec()).expect("ascii"))
    }
}

/// Encode control-reply or listing text for the wire.
///
/// With UTF-8 off, non-ASCII codepoints become `?` (US-ASCII substitution,
/// matching typical `Charset.encode` replacement behaviour).
pub fn encode_text(text: &str, utf8: bool) -> Vec<u8> {
    if utf8 || text.is_ascii() {
        text.as_bytes().to_vec()
    } else {
        text.chars()
            .map(|c| if c.is_ascii() { c as u8 } else { b'?' })
            .collect()
    }
}

/// Encode a single filename for LIST/NLST/MLSx when UTF-8 is off.
pub fn encode_name(name: &str, utf8: bool) -> String {
    if utf8 || name.is_ascii() {
        name.to_string()
    } else {
        name.chars()
            .map(|c| if c.is_ascii() { c } else { '?' })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_ok_either_mode() {
        assert_eq!(decode_arg(b"hello", false).unwrap(), "hello");
        assert_eq!(decode_arg(b"hello", true).unwrap(), "hello");
    }

    #[test]
    fn non_ascii_requires_utf8() {
        let cafe = "café".as_bytes();
        assert_eq!(decode_arg(cafe, false), Err(PathnameCharsetError::NonAscii));
        assert_eq!(decode_arg(cafe, true).unwrap(), "café");
    }

    #[test]
    fn invalid_utf8_rejected_when_on() {
        assert_eq!(
            decode_arg(&[0xff, 0xfe], true),
            Err(PathnameCharsetError::InvalidUtf8)
        );
    }

    #[test]
    fn encode_substitutes_when_off() {
        assert_eq!(encode_text("café", true), "café".as_bytes());
        assert_eq!(encode_text("café", false), b"caf?");
        assert_eq!(encode_name("näme", false), "n?me");
    }
}
