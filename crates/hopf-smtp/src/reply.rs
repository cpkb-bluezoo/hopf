// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SMTP reply formatting helpers (RFC 5321 / RFC 2034).

/// Format `code text\r\n`.
pub fn reply(code: u16, text: &str) -> Vec<u8> {
    format!("{code} {text}\r\n").into_bytes()
}

/// Format an enhanced-status reply: `code ecode text\r\n` (RFC 2034).
pub fn reply_enhanced(code: u16, ecode: &str, text: &str) -> Vec<u8> {
    format!("{code} {ecode} {text}\r\n").into_bytes()
}

/// RFC 5321 multiline: `code-line\r\n` … final `code last\r\n`.
pub fn reply_multiline(code: u16, lines: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    if lines.is_empty() {
        return reply(code, "");
    }
    for (i, line) in lines.iter().enumerate() {
        if i + 1 == lines.len() {
            out.extend_from_slice(&format!("{code} {line}\r\n").into_bytes());
        } else {
            out.extend_from_slice(&format!("{code}-{line}\r\n").into_bytes());
        }
    }
    out
}

/// EHLO capability advertisement helper.
pub fn reply_ehlo(hostname: &str, hello_name: &str, capabilities: &[&str]) -> Vec<u8> {
    let mut lines: Vec<String> = Vec::with_capacity(1 + capabilities.len());
    lines.push(format!("{hostname} Hello {hello_name}"));
    for c in capabilities {
        lines.push((*c).to_string());
    }
    let refs: Vec<&str> = lines.iter().map(|s| s.as_str()).collect();
    reply_multiline(250, &refs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_reply() {
        assert_eq!(reply(250, "OK"), b"250 OK\r\n");
    }

    #[test]
    fn enhanced() {
        assert_eq!(
            reply_enhanced(250, "2.0.0", "OK"),
            b"250 2.0.0 OK\r\n"
        );
    }

    #[test]
    fn multiline() {
        let s = String::from_utf8(reply_multiline(250, &["a", "b"])).unwrap();
        assert_eq!(s, "250-a\r\n250 b\r\n");
    }
}
