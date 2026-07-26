// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SMTP reply type and incremental parser.

use super::error::{SmtpError, SmtpResult};

/// One complete SMTP reply (possibly multiline).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpReply {
    /// Three-digit reply code.
    pub code: u16,
    /// Lines of text without the code prefix.
    pub lines: Vec<String>,
}

impl SmtpReply {
    /// Primary text — first line of the reply.
    pub fn text(&self) -> String {
        self.lines.first().cloned().unwrap_or_default()
    }

    /// All lines joined with newlines.
    pub fn full_text(&self) -> String {
        self.lines.join("\n")
    }
}

/// Incremental SMTP reply lexer.
///
/// Self-contained streaming parser: [`SmtpReplyLexer::feed`] consumes every
/// byte it is given — `*data` is always left empty — and keeps a line in
/// progress in its own `line_buf` scratch buffer, never in a buffer the
/// caller has to retain and re-supply.
#[derive(Default)]
pub struct SmtpReplyLexer {
    /// Current line accumulation buffer.
    line_buf: Vec<u8>,
    /// Code of the current (possibly multiline) reply in progress.
    current_code: Option<u16>,
    /// Accumulated text lines of the current reply.
    accumulated: Vec<String>,
}

impl SmtpReplyLexer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed bytes from the wire. Returns completed replies. Consumes
    /// everything given — `*data` is always left empty. Returns an error on
    /// malformed input.
    pub fn feed(&mut self, data: &mut &[u8]) -> SmtpResult<Vec<SmtpReply>> {
        let mut ready = Vec::new();

        'outer: for &b in data.iter() {
            self.line_buf.push(b);

            // Line cap to avoid unbounded growth on bad servers.
            if self.line_buf.len() > 16 * 1024 {
                return Err(SmtpError::Parse("SMTP reply line too long".into()));
            }

            // Wait for CRLF.
            let n = self.line_buf.len();
            if n < 2 || self.line_buf[n - 2] != b'\r' || self.line_buf[n - 1] != b'\n' {
                continue 'outer;
            }

            // We have a complete line: parse it.
            let line = std::mem::take(&mut self.line_buf);

            // A line must be at least "XYZ\r\n" (5 bytes).
            if line.len() < 5 {
                return Err(SmtpError::Parse(format!(
                    "SMTP reply line too short: {line:?}"
                )));
            }

            // Parse 3-digit code.
            let code_bytes = &line[..3];
            if !code_bytes.iter().all(|b| b.is_ascii_digit()) {
                return Err(SmtpError::Parse(format!(
                    "SMTP reply: non-digit code in {:?}",
                    String::from_utf8_lossy(&line)
                )));
            }
            let code: u16 = std::str::from_utf8(code_bytes)
                .unwrap()
                .parse()
                .map_err(|_| SmtpError::Parse("reply code overflow".into()))?;

            // 4th byte: '-' = continuation, ' ' (or anything else) = final.
            let sep = line[3];
            let text_bytes = &line[4..line.len() - 2]; // strip code+sep and CRLF
            let text = String::from_utf8_lossy(text_bytes).into_owned();

            if sep == b'-' {
                // Continuation line.
                match self.current_code {
                    None => {
                        self.current_code = Some(code);
                        self.accumulated.push(text);
                    }
                    Some(c) if c == code => {
                        self.accumulated.push(text);
                    }
                    Some(c) => {
                        return Err(SmtpError::Parse(format!(
                            "SMTP multiline code mismatch: expected {c}, got {code}"
                        )));
                    }
                }
            } else {
                // Final line.
                match self.current_code {
                    None => {
                        // Single-line reply.
                        ready.push(SmtpReply {
                            code,
                            lines: vec![text],
                        });
                    }
                    Some(c) if c == code => {
                        // Last line of a multiline reply.
                        let mut lines = std::mem::take(&mut self.accumulated);
                        lines.push(text);
                        self.current_code = None;
                        ready.push(SmtpReply { code, lines });
                    }
                    Some(c) => {
                        return Err(SmtpError::Parse(format!(
                            "SMTP multiline final code mismatch: expected {c}, got {code}"
                        )));
                    }
                }
            }
        }

        *data = &[];
        Ok(ready)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_line_reply() {
        let mut lex = SmtpReplyLexer::new();
        let mut data: &[u8] = b"250 OK\r\n";
        let replies = lex.feed(&mut data).unwrap();
        assert!(data.is_empty());
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].code, 250);
        assert_eq!(replies[0].lines, vec!["OK".to_string()]);
    }

    #[test]
    fn multiline_reply() {
        let mut lex = SmtpReplyLexer::new();
        let mut data: &[u8] = b"250-Hello\r\n250-SIZE 1000\r\n250 OK\r\n";
        let replies = lex.feed(&mut data).unwrap();
        assert!(data.is_empty());
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].code, 250);
        assert_eq!(
            replies[0].lines,
            vec!["Hello".to_string(), "SIZE 1000".to_string(), "OK".to_string()]
        );
    }

    #[test]
    fn pipelined_replies() {
        let mut lex = SmtpReplyLexer::new();
        let mut data: &[u8] = b"220 ready\r\n250 OK\r\n";
        let replies = lex.feed(&mut data).unwrap();
        assert!(data.is_empty());
        assert_eq!(replies.len(), 2);
        assert_eq!(replies[0].code, 220);
        assert_eq!(replies[1].code, 250);
    }

    /// A reply split mid-line across two `feed()` calls (as `connection.rs`
    /// does: re-presenting whatever wasn't consumed, combined with newly
    /// read bytes) must not duplicate the already-buffered prefix.
    #[test]
    fn feed_across_calls_does_not_duplicate_partial_line() {
        let mut lex = SmtpReplyLexer::new();
        let full: &[u8] = b"250-Hello\r\n250 OK\r\n";

        let mut buf: Vec<u8> = full[..7].to_vec(); // "250-Hel", no CRLF yet
        let mut slice: &[u8] = &buf;
        let replies = lex.feed(&mut slice).unwrap();
        assert!(slice.is_empty());
        assert!(replies.is_empty());
        buf.clear(); // *data is always fully consumed — nothing to retain

        buf.extend_from_slice(&full[7..]); // rest of the reply arrives
        let mut slice2: &[u8] = &buf;
        let replies2 = lex.feed(&mut slice2).unwrap();
        assert!(slice2.is_empty());

        assert_eq!(replies2.len(), 1);
        assert_eq!(replies2[0].code, 250);
        assert_eq!(
            replies2[0].lines,
            vec!["Hello".to_string(), "OK".to_string()]
        );
    }

    /// One byte per `feed()` call must produce identical replies to a
    /// single bulk feed, and never leave anything unconsumed.
    #[test]
    fn one_byte_at_a_time_matches_bulk_feed() {
        let msg: &[u8] = b"250-Hello\r\n250-SIZE 1000\r\n250 OK\r\n220 next\r\n";

        let mut bulk = SmtpReplyLexer::new();
        let mut bulk_data = msg;
        let bulk_replies = bulk.feed(&mut bulk_data).unwrap();

        let mut drip = SmtpReplyLexer::new();
        let mut drip_replies = Vec::new();
        for &b in msg {
            let mut one: &[u8] = &[b];
            drip_replies.extend(drip.feed(&mut one).unwrap());
            assert!(one.is_empty());
        }

        assert_eq!(bulk_replies, drip_replies);
        assert_eq!(bulk_replies.len(), 2);
    }

    /// Every split point of a full reply stream must be equivalent.
    #[test]
    fn all_split_points_are_equivalent() {
        let msg: &[u8] = b"250-Hello\r\n250-SIZE 1000\r\n250 OK\r\n220 next\r\n";
        let mut base = SmtpReplyLexer::new();
        let mut base_data = msg;
        let base_replies = base.feed(&mut base_data).unwrap();

        for split in 1..msg.len() {
            let mut lex = SmtpReplyLexer::new();
            let mut a: &[u8] = &msg[..split];
            let mut replies = lex.feed(&mut a).unwrap();
            assert!(a.is_empty(), "split {split} retained bytes");
            let mut b: &[u8] = &msg[split..];
            replies.extend(lex.feed(&mut b).unwrap());
            assert!(b.is_empty(), "split {split} retained bytes");
            assert_eq!(replies, base_replies, "split {split} diverged");
        }
    }
}
