// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! POP3 wire replies (`+OK` / `-ERR` / `+` continuation).

/// Strip CR/LF from a reply text line to avoid response smuggling.
fn sanitize(msg: &str) -> String {
    msg.chars().filter(|&c| c != '\r' && c != '\n').collect()
}

/// `+OK <msg>\r\n`
pub fn ok(msg: &str) -> Vec<u8> {
    let msg = sanitize(msg);
    let mut out = Vec::with_capacity(6 + msg.len());
    out.extend_from_slice(b"+OK ");
    out.extend_from_slice(msg.as_bytes());
    out.extend_from_slice(b"\r\n");
    out
}

/// `+OK\r\n` with no trailing text.
pub fn ok_bare() -> Vec<u8> {
    b"+OK\r\n".to_vec()
}

/// `-ERR <msg>\r\n`
pub fn err(msg: &str) -> Vec<u8> {
    let msg = sanitize(msg);
    let mut out = Vec::with_capacity(6 + msg.len());
    out.extend_from_slice(b"-ERR ");
    out.extend_from_slice(msg.as_bytes());
    out.extend_from_slice(b"\r\n");
    out
}

/// SASL continuation `+ <data>\r\n` (data usually base64).
pub fn continuation(data: &str) -> Vec<u8> {
    let data = sanitize(data);
    let mut out = Vec::with_capacity(4 + data.len());
    out.extend_from_slice(b"+ ");
    out.extend_from_slice(data.as_bytes());
    out.extend_from_slice(b"\r\n");
    out
}

/// Bare `+ \r\n` continuation (empty challenge).
#[allow(dead_code)]
pub fn continuation_empty() -> Vec<u8> {
    b"+ \r\n".to_vec()
}

/// Multiline terminator.
pub fn multiline_end() -> Vec<u8> {
    b".\r\n".to_vec()
}

/// One capa / listing line terminated with CRLF.
pub fn line(text: &str) -> Vec<u8> {
    let text = sanitize(text);
    let mut out = Vec::with_capacity(text.len() + 2);
    out.extend_from_slice(text.as_bytes());
    out.extend_from_slice(b"\r\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok_err_shapes() {
        assert_eq!(ok("hi"), b"+OK hi\r\n");
        assert_eq!(err("[AUTH] no"), b"-ERR [AUTH] no\r\n");
        assert_eq!(continuation("YQ=="), b"+ YQ==\r\n");
    }

    #[test]
    fn strips_crlf_from_text() {
        assert_eq!(ok("hi\r\nsmuggle"), b"+OK hismuggle\r\n");
    }
}
