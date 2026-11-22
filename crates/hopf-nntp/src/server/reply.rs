// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! NNTP response lines (RFC 3977 section 3.2).

/// Strips CR and LF from reply text, so that nothing a client or a store
/// supplied can end the line early and begin another.
fn sanitize(text: &str) -> String {
    text.chars().filter(|&c| c != '\r' && c != '\n').collect()
}

/// `<code> <text>\r\n`.
pub(crate) fn status(code: u16, text: &str) -> Vec<u8> {
    let text = sanitize(text);
    let mut out = Vec::with_capacity(text.len() + 7);
    out.extend_from_slice(code.to_string().as_bytes());
    if !text.is_empty() {
        out.push(b' ');
        out.extend_from_slice(text.as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// A line of a multi-line data block, dot-stuffed and terminated.
pub(crate) fn data_line(text: &str, out: &mut Vec<u8>) {
    let text = sanitize(text);
    if text.starts_with('.') {
        out.push(b'.');
    }
    out.extend_from_slice(text.as_bytes());
    out.extend_from_slice(b"\r\n");
}

/// The line that ends a multi-line data block.
pub(crate) const END: &[u8] = b".\r\n";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_status_line_is_code_text_crlf() {
        assert_eq!(status(200, "ready"), b"200 ready\r\n");
        assert_eq!(status(205, ""), b"205\r\n");
    }

    #[test]
    fn text_cannot_end_the_line_early() {
        assert_eq!(status(501, "bad\r\n200 ok"), b"501 bad200 ok\r\n");
    }

    #[test]
    fn a_data_line_is_stuffed_when_it_begins_with_a_dot() {
        let mut out = Vec::new();
        data_line(".hidden", &mut out);
        data_line("plain", &mut out);
        assert_eq!(out, b"..hidden\r\nplain\r\n");
    }
}
