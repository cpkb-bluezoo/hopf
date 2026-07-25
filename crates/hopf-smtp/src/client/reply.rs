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
/// Feed bytes from the wire; complete [`SmtpReply`] values are returned from
/// [`SmtpReplyLexer::feed`]. Any unconsumed bytes remain at the start of the
/// next [`feed`] call's `data` slice (NIO compact semantics via `data` advance).
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

    /// Feed bytes from the wire. Returns completed replies and advances `data`
    /// past the consumed bytes. Returns an error on malformed input.
    pub fn feed(&mut self, data: &mut &[u8]) -> SmtpResult<Vec<SmtpReply>> {
        let mut ready = Vec::new();
        let mut consumed = 0usize;

        'outer: for (i, &b) in data.iter().enumerate() {
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
            consumed = i + 1;
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

        *data = &data[consumed..];
        Ok(ready)
    }
}
