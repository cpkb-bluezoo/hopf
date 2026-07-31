// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RETR / TOP message formatting: streaming dot-stuffing.

/// Streaming dot-stuffer for RETR/TOP message bodies — fed one chunk at a
/// time (chunk boundaries may fall anywhere, including mid-line), never
/// buffers more than the current, not-yet-terminated line.
///
/// Per line: strips a trailing CRLF's `\r` (if present) and any other bare
/// `\r` bytes within the line (prevents response smuggling), normalizes
/// the terminator to `\r\n`, and doubles a leading `.` (RFC 1939 §3). Call
/// [`Self::finish`] once the message is exhausted to flush any trailing
/// unterminated line and append the terminating `.\r\n`.
pub struct Pop3DotStuffer {
    line_buf: Vec<u8>,
}

impl Pop3DotStuffer {
    /// New stuffer, positioned at the start of the message.
    pub fn new() -> Self {
        Self {
            line_buf: Vec::new(),
        }
    }

    /// Dot-stuff one chunk, appending the result to `out`.
    pub fn feed(&mut self, chunk: &[u8], out: &mut Vec<u8>) {
        for &b in chunk {
            if b == b'\n' {
                self.emit_line(out);
            } else {
                self.line_buf.push(b);
            }
        }
    }

    fn emit_line(&mut self, out: &mut Vec<u8>) {
        let mut line = std::mem::take(&mut self.line_buf);
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        line.retain(|&b| b != b'\r');
        if line.first() == Some(&b'.') {
            out.push(b'.');
        }
        out.extend_from_slice(&line);
        out.extend_from_slice(b"\r\n");
    }

    /// Flush any trailing unterminated line, then the dot-stuff terminator.
    pub fn finish(&mut self, out: &mut Vec<u8>) {
        if !self.line_buf.is_empty() {
            self.emit_line(out);
        }
        out.extend_from_slice(b".\r\n");
    }
}

impl Default for Pop3DotStuffer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whole-buffer reference implementation, used only by these tests to
    /// check the streaming version against varying chunk sizes.
    fn dot_stuff_whole(message: &[u8]) -> Vec<u8> {
        let mut stuffer = Pop3DotStuffer::new();
        let mut out = Vec::new();
        stuffer.feed(message, &mut out);
        stuffer.finish(&mut out);
        out
    }

    #[test]
    fn dot_stuff_leading_dot() {
        let msg = b"hello\r\n.hidden\r\n";
        let out = dot_stuff_whole(msg);
        assert_eq!(out, b"hello\r\n..hidden\r\n.\r\n");
    }

    #[test]
    fn dot_stuff_empty_message_is_just_terminator() {
        assert_eq!(dot_stuff_whole(b""), b".\r\n");
    }

    #[test]
    fn dot_stuff_strips_bare_cr_mid_line() {
        let out = dot_stuff_whole(b"foo\rbar\r\n");
        assert_eq!(out, b"foobar\r\n.\r\n");
    }

    #[test]
    fn dot_stuff_normalizes_bare_lf_terminator() {
        let out = dot_stuff_whole(b"one\ntwo\n");
        assert_eq!(out, b"one\r\ntwo\r\n.\r\n");
    }

    #[test]
    fn streaming_matches_whole_buffer_regardless_of_chunk_size() {
        let msg = b"From: a@b\r\nSubject: x\r\n\r\n.leading dot\r\nplain\r\nfoo\rbar\r\nlast-no-nl";
        let whole = dot_stuff_whole(msg);
        for chunk_size in [1usize, 2, 3, 7, 64, 4096] {
            let mut stuffer = Pop3DotStuffer::new();
            let mut out = Vec::new();
            for chunk in msg.chunks(chunk_size) {
                stuffer.feed(chunk, &mut out);
            }
            stuffer.finish(&mut out);
            assert_eq!(out, whole, "chunk_size={chunk_size}");
        }
    }
}
