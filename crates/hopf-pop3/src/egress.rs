// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RETR / TOP message formatting (dot-stuffing, TOP truncation).

/// Truncate an RFC 822 message to headers + the first `lines` body lines (TOP).
pub fn truncate_top(message: &[u8], lines: u32) -> Vec<u8> {
    let mut out = Vec::new();
    let mut body_lines_left = lines;
    let mut in_body = false;
    for raw in message.split_inclusive(|&b| b == b'\n') {
        let line = strip_line_ending(raw);
        if !in_body {
            out.extend_from_slice(line);
            out.extend_from_slice(b"\r\n");
            if line.is_empty() {
                in_body = true;
            }
            continue;
        }
        if body_lines_left == 0 {
            break;
        }
        out.extend_from_slice(line);
        out.extend_from_slice(b"\r\n");
        body_lines_left -= 1;
    }
    out
}

/// Dot-stuff a message body and append the terminating `.\r\n`.
///
/// Strips bare CR from each content line to prevent response smuggling.
pub fn dot_stuff_message(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len() + 16);
    if message.is_empty() {
        out.extend_from_slice(b".\r\n");
        return out;
    }
    for raw in message.split_inclusive(|&b| b == b'\n') {
        let line = strip_line_ending(raw);
        let cleaned = strip_cr(line);
        if cleaned.first() == Some(&b'.') {
            out.push(b'.');
        }
        out.extend_from_slice(&cleaned);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b".\r\n");
    out
}

fn strip_line_ending(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    if end > 0 && line[end - 1] == b'\n' {
        end -= 1;
    }
    if end > 0 && line[end - 1] == b'\r' {
        end -= 1;
    }
    &line[..end]
}

fn strip_cr(line: &[u8]) -> Vec<u8> {
    line.iter().copied().filter(|&b| b != b'\r').collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn top_zero_body_lines() {
        let msg = b"From: a@b\r\nSubject: x\r\n\r\nbody1\r\nbody2\r\n";
        let top = truncate_top(msg, 0);
        assert_eq!(top, b"From: a@b\r\nSubject: x\r\n\r\n");
    }

    #[test]
    fn top_one_body_line() {
        let msg = b"Subject: x\r\n\r\nbody1\r\nbody2\r\n";
        let top = truncate_top(msg, 1);
        assert_eq!(top, b"Subject: x\r\n\r\nbody1\r\n");
    }

    #[test]
    fn dot_stuff_leading_dot() {
        let msg = b"hello\r\n.hidden\r\n";
        let out = dot_stuff_message(msg);
        assert_eq!(out, b"hello\r\n..hidden\r\n.\r\n");
    }
}
