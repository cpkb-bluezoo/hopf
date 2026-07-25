// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 1939 §3 dot-unstuffing for POP3 RETR / TOP bodies.
//!
//! After a `+OK` response to RETR or TOP, the message body arrives
//! dot-stuffed: lines starting with `..` are unstuffed to `.`, and
//! the sole-dot line `.\r\n` terminates the body.
//!
//! Feed inbound bytes to [`Pop3DotUnstuffer::feed`]; it returns content
//! chunks and signals completion via `Some(offset)` in the second return
//! value, where `offset` is the number of input bytes consumed (including
//! the terminator). Bytes at `input[offset..]` belong to the next reply.

/// Internal state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum DotState {
    /// At the start of a new line (saw CRLF, or at the very start).
    #[default]
    SawCrlf,
    /// Inside a content line (no pending special characters).
    Normal,
    /// Saw `\r` (possible start of CRLF).
    SawCr,
    /// Saw `.` at the beginning of a line (possible stuffed dot or terminator).
    SawDot,
    /// Saw `.\r` at the beginning of a line (possible `.\r\n` terminator).
    SawDotCr,
}

/// POP3 message-body dot-unstuffer.
///
/// Starts in [`DotState::SawCrlf`] so a leading `.\r\n` correctly terminates
/// an empty message.
#[derive(Debug, Default)]
pub struct Pop3DotUnstuffer {
    state: DotState,
}

impl Pop3DotUnstuffer {
    /// Create a new unstuffer ready for the start of a message body.
    pub fn new() -> Self {
        Self { state: DotState::SawCrlf }
    }

    /// Reset for a new transfer.
    pub fn reset(&mut self) {
        self.state = DotState::SawCrlf;
    }

    /// Feed `input` bytes.
    ///
    /// Returns `(chunks, complete)`:
    /// - `chunks`: zero or more content byte slices (unstuffed, without the
    ///   terminator).
    /// - `complete`: `Some(n)` when `.\r\n` was found at `input[..n]` (bytes
    ///   at `input[n..]` belong to the next reply); `None` if the terminator
    ///   has not yet been seen and all of `input` is consumed.
    pub fn feed(&mut self, input: &[u8]) -> (Vec<Vec<u8>>, Option<usize>) {
        let mut chunks: Vec<Vec<u8>> = Vec::new();
        let mut chunk_start = 0usize;
        let mut i = 0usize;

        macro_rules! flush {
            ($end:expr) => {
                if $end > chunk_start {
                    chunks.push(input[chunk_start..$end].to_vec());
                }
            };
        }

        while i < input.len() {
            let b = input[i];
            match self.state {
                DotState::Normal => {
                    if b == b'\r' {
                        self.state = DotState::SawCr;
                    }
                    i += 1;
                }
                DotState::SawCr => {
                    if b == b'\n' {
                        self.state = DotState::SawCrlf;
                    } else if b != b'\r' {
                        self.state = DotState::Normal;
                    }
                    // If b == '\r', stay in SawCr.
                    i += 1;
                }
                DotState::SawCrlf => {
                    if b == b'.' {
                        // Flush content up to (not including) the dot.
                        flush!(i);
                        self.state = DotState::SawDot;
                        i += 1;
                        chunk_start = i; // exclude the dot from output
                    } else {
                        self.state = if b == b'\r' { DotState::SawCr } else { DotState::Normal };
                        i += 1;
                    }
                }
                DotState::SawDot => {
                    if b == b'\r' {
                        self.state = DotState::SawDotCr;
                        i += 1;
                    } else if b == b'\n' {
                        // Lenient: bare LF terminates (some servers do this).
                        flush!(chunk_start);
                        return (chunks, Some(i + 1));
                    } else {
                        // Stuffed dot: the leading dot was already excluded from
                        // chunk_start; `b` is content, continue.
                        self.state = if b == b'\r' { DotState::SawCr } else { DotState::Normal };
                        i += 1;
                    }
                }
                DotState::SawDotCr => {
                    if b == b'\n' {
                        // Terminator `.\r\n` found.
                        flush!(chunk_start);
                        return (chunks, Some(i + 1));
                    } else {
                        // Not a terminator — the `.\r` was content.
                        // Emit the dot and CR explicitly (they were excluded).
                        chunks.push(b".\r".to_vec());
                        chunk_start = i;
                        self.state = if b == b'\r' { DotState::SawCr } else { DotState::Normal };
                        i += 1;
                    }
                }
            }
        }

        // Exhausted input without finding the terminator.
        flush!(i);
        (chunks, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect(chunks: Vec<Vec<u8>>) -> Vec<u8> {
        chunks.into_iter().flatten().collect()
    }

    #[test]
    fn simple_body() {
        let mut u = Pop3DotUnstuffer::new();
        let (chunks, done) = u.feed(b"Hello\r\nworld\r\n.\r\n");
        assert!(done.is_some(), "should complete");
        assert_eq!(collect(chunks), b"Hello\r\nworld\r\n");
    }

    #[test]
    fn empty_body() {
        let mut u = Pop3DotUnstuffer::new();
        let (chunks, done) = u.feed(b".\r\n");
        assert!(done.is_some());
        assert!(collect(chunks).is_empty());
    }

    #[test]
    fn stuffed_dot() {
        let mut u = Pop3DotUnstuffer::new();
        let (chunks, done) = u.feed(b"..dotted\r\n.\r\n");
        assert!(done.is_some());
        // Leading dot removed → ".dotted\r\n"
        assert_eq!(collect(chunks), b".dotted\r\n");
    }

    #[test]
    fn split_terminator() {
        let mut u = Pop3DotUnstuffer::new();
        let (c1, d1) = u.feed(b"body\r\n.");
        assert!(d1.is_none());
        let (c2, d2) = u.feed(b"\r\n");
        assert!(d2.is_some());
        assert_eq!(collect(c1.into_iter().chain(c2).collect()), b"body\r\n");
    }

    #[test]
    fn split_mid_content() {
        let mut u = Pop3DotUnstuffer::new();
        let (c1, d1) = u.feed(b"hel");
        assert!(d1.is_none());
        let (c2, d2) = u.feed(b"lo\r\n.\r\n");
        assert!(d2.is_some());
        assert_eq!(collect(c1.into_iter().chain(c2).collect()), b"hello\r\n");
    }

    #[test]
    fn trailing_bytes_after_terminator() {
        let mut u = Pop3DotUnstuffer::new();
        let (chunks, done) = u.feed(b"hi\r\n.\r\n+OK next reply\r\n");
        let consumed = done.expect("should complete");
        // Bytes before the consumed offset are the body; the rest is the next reply.
        let body = collect(chunks);
        assert_eq!(body, b"hi\r\n");
        // consumed = index just past ".\r\n"
        let leftover = &b"hi\r\n.\r\n+OK next reply\r\n"[consumed..];
        assert_eq!(leftover, b"+OK next reply\r\n");
    }

    #[test]
    fn reset_reuses_unstuffer() {
        let mut u = Pop3DotUnstuffer::new();
        let (_, d1) = u.feed(b"msg1\r\n.\r\n");
        assert!(d1.is_some());
        u.reset();
        let (chunks, d2) = u.feed(b"msg2\r\n.\r\n");
        assert!(d2.is_some());
        assert_eq!(collect(chunks), b"msg2\r\n");
    }
}
