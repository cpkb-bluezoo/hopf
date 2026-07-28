// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Incremental IMAP server-reply lexer.
//!
//! Handles untagged `*`, continuation `+`, tagged `OK`/`NO`/`BAD`, bracketed
//! response codes, quoted values (so literal markers inside quotes are not
//! mistaken for `{n}`), and literals split across arbitrary buffer boundaries.

use super::error::ImapError;

/// Cap on one buffered reply line, so a server that never sends CRLF can't
/// grow [`ImapReplyLexer`]'s buffer without bound. Counterpart to the
/// server-side [`crate::server::MAX_COMMAND_LINE`] (which bounds a client's
/// command line instead) — this lexer allows a larger margin since IMAP
/// tagged/untagged reply lines (e.g. long FETCH attribute lists) run longer
/// than commands.
pub const MAX_REPLY_LINE: usize = 64 * 1024;

/// Tagged / untagged completion status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImapStatus {
    /// `OK`
    Ok,
    /// `NO`
    No,
    /// `BAD`
    Bad,
}

/// Parsed wire event emitted by [`ImapReplyLexer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImapWireEvent {
    /// Untagged response line (`* …`), without the leading `* `.
    Untagged {
        /// `OK` / `NO` / `BAD` when the untagged line is a status response.
        status: Option<ImapStatus>,
        /// Bracketed response code without the surrounding `[]`, if present.
        response_code: Option<String>,
        /// Text after status/code (or the full remaining payload for data
        /// responses such as `EXISTS` / `FETCH`).
        text: String,
        /// Full line after `* ` (useful for routing FETCH / LIST / SEARCH).
        raw: String,
    },
    /// Continuation request (`+ [text]`).
    Continuation {
        /// Text after `+ ` (may be empty).
        text: String,
    },
    /// Tagged completion (`tag OK|NO|BAD …`).
    Tagged {
        /// Command tag (e.g. `A001`).
        tag: String,
        /// Completion status.
        status: ImapStatus,
        /// Bracketed response code without `[]`.
        response_code: Option<String>,
        /// Human-readable text after the status/code.
        message: String,
    },
    /// Octets belonging to a response literal that followed a `{n}` marker.
    LiteralData(Vec<u8>),
    /// The outstanding response literal has been fully consumed.
    LiteralComplete,
    /// Residual text after a literal mid-response (e.g. closing `)` of FETCH).
    Residual(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LexMode {
    Line,
    Literal,
}

/// Incremental IMAP server-reply lexer.
///
/// Call [`ImapReplyLexer::feed`] with inbound bytes; it advances the slice
/// past consumed bytes and returns zero or more [`ImapWireEvent`]s.
pub struct ImapReplyLexer {
    mode: LexMode,
    line_buf: Vec<u8>,
    literal_remaining: u64,
    max_line: usize,
}

impl Default for ImapReplyLexer {
    fn default() -> Self {
        Self::new()
    }
}

impl ImapReplyLexer {
    /// Create a new lexer in line mode.
    pub fn new() -> Self {
        Self {
            mode: LexMode::Line,
            line_buf: Vec::with_capacity(256),
            literal_remaining: 0,
            max_line: MAX_REPLY_LINE,
        }
    }

    /// Whether the lexer is currently consuming a response literal.
    pub fn in_literal(&self) -> bool {
        self.mode == LexMode::Literal
    }

    /// Feed inbound bytes. Advances `data` past consumed octets.
    pub fn feed(&mut self, data: &mut &[u8]) -> Result<Vec<ImapWireEvent>, ImapError> {
        let mut events = Vec::new();
        loop {
            if data.is_empty() {
                break;
            }
            match self.mode {
                LexMode::Literal => {
                    let take = (*data).len().min(self.literal_remaining as usize);
                    if take == 0 {
                        break;
                    }
                    let chunk = data[..take].to_vec();
                    *data = &data[take..];
                    self.literal_remaining -= take as u64;
                    events.push(ImapWireEvent::LiteralData(chunk));
                    if self.literal_remaining == 0 {
                        self.mode = LexMode::Line;
                        events.push(ImapWireEvent::LiteralComplete);
                    }
                }
                LexMode::Line => {
                    let available = *data;
                    let mut found_crlf = false;
                    let mut line_end = 0usize;
                    for (i, &b) in available.iter().enumerate() {
                        self.line_buf.push(b);
                        if self.line_buf.len() > self.max_line {
                            return Err(ImapError::Parse("IMAP reply line too long".into()));
                        }
                        let n = self.line_buf.len();
                        if n >= 2 && self.line_buf[n - 2] == b'\r' && self.line_buf[n - 1] == b'\n'
                        {
                            line_end = i + 1;
                            found_crlf = true;
                            break;
                        }
                    }
                    if !found_crlf {
                        *data = &available[available.len()..];
                        break;
                    }
                    let line = std::mem::take(&mut self.line_buf);
                    *data = &available[line_end..];
                    let text_bytes = &line[..line.len() - 2];
                    let text = String::from_utf8_lossy(text_bytes).into_owned();
                    let literal = trailing_literal_size(&text);
                    let event = parse_response_line(&text)?;
                    events.push(event);
                    if let Some(n) = literal {
                        self.mode = LexMode::Literal;
                        self.literal_remaining = n;
                        // Continue so remaining bytes in this buffer feed the literal.
                        continue;
                    }
                }
            }
        }
        Ok(events)
    }
}

fn parse_response_line(line: &str) -> Result<ImapWireEvent, ImapError> {
    if line == "+" {
        return Ok(ImapWireEvent::Continuation {
            text: String::new(),
        });
    }
    if let Some(rest) = line.strip_prefix("+ ") {
        return Ok(ImapWireEvent::Continuation {
            text: rest.to_string(),
        });
    }
    if let Some(rest) = line.strip_prefix("* ") {
        return Ok(parse_untagged(rest));
    }
    if line == "*" {
        return Ok(ImapWireEvent::Untagged {
            status: None,
            response_code: None,
            text: String::new(),
            raw: String::new(),
        });
    }
    let Some(sp) = line.find(' ') else {
        // Trailing fragment after a response literal (e.g. `)`).
        return Ok(ImapWireEvent::Residual(line.to_string()));
    };
    let tag = line[..sp].to_string();
    let rest = &line[sp + 1..];
    let Some(status) = parse_status(rest) else {
        // Not a tagged completion — treat as residual / continuation text.
        return Ok(ImapWireEvent::Residual(line.to_string()));
    };
    let after = after_status(rest, status);
    let (code, message) = split_response_code(after);
    Ok(ImapWireEvent::Tagged {
        tag,
        status,
        response_code: code,
        message,
    })
}

fn parse_untagged(rest: &str) -> ImapWireEvent {
    if let Some(status) = parse_status(rest) {
        let after = after_status(rest, status);
        let (code, message) = split_response_code(after);
        ImapWireEvent::Untagged {
            status: Some(status),
            response_code: code,
            text: message,
            raw: rest.to_string(),
        }
    } else {
        ImapWireEvent::Untagged {
            status: None,
            response_code: None,
            text: rest.to_string(),
            raw: rest.to_string(),
        }
    }
}

fn parse_status(text: &str) -> Option<ImapStatus> {
    if text.starts_with("OK") && (text.len() == 2 || text.as_bytes().get(2) == Some(&b' ')) {
        Some(ImapStatus::Ok)
    } else if text.starts_with("NO") && (text.len() == 2 || text.as_bytes().get(2) == Some(&b' ')) {
        Some(ImapStatus::No)
    } else if text.starts_with("BAD") && (text.len() == 3 || text.as_bytes().get(3) == Some(&b' '))
    {
        Some(ImapStatus::Bad)
    } else {
        None
    }
}

fn after_status(text: &str, status: ImapStatus) -> &str {
    let n = match status {
        ImapStatus::Ok | ImapStatus::No => 2,
        ImapStatus::Bad => 3,
    };
    text[n..].trim_start()
}

/// Quote-aware split of an optional `[response-code]` prefix.
fn split_response_code(text: &str) -> (Option<String>, String) {
    let text = text.trim_start();
    if !text.starts_with('[') {
        return (None, text.to_string());
    }
    let bytes = text.as_bytes();
    let mut i = 1;
    let mut in_quote = false;
    let mut depth = 1i32;
    while i < bytes.len() {
        let b = bytes[i];
        if in_quote {
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == b'"' {
                in_quote = false;
            }
            i += 1;
            continue;
        }
        match b {
            b'"' => in_quote = true,
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    let code = text[1..i].to_string();
                    let after = text[i + 1..].trim_start().to_string();
                    return (Some(code), after);
                }
            }
            _ => {}
        }
        i += 1;
    }
    (None, text.to_string())
}

/// Detect a trailing unquoted `{n}` or `{n+}` literal size marker.
pub fn trailing_literal_size(line: &str) -> Option<u64> {
    let bytes = line.as_bytes();
    if bytes.last() != Some(&b'}') {
        return None;
    }
    let mut in_quote = false;
    let mut last_open = None;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if in_quote {
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == b'"' {
                in_quote = false;
            }
            i += 1;
            continue;
        }
        match b {
            b'"' => in_quote = true,
            b'{' => last_open = Some(i),
            _ => {}
        }
        i += 1;
    }
    let open = last_open?;
    // Marker must be at the end of the line (only digits / optional + before `}`).
    let inner = &line[open + 1..line.len() - 1];
    let (num, plus) = if let Some(n) = inner.strip_suffix('+') {
        (n, true)
    } else {
        (inner, false)
    };
    if num.is_empty() || !num.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // Reject if anything after a prior `}` — require the `{…}` to be a suffix.
    if open > 0 {
        // ok — text before marker is fine
    }
    let _ = plus;
    num.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untagged_ok_with_code() {
        let mut lex = ImapReplyLexer::new();
        let mut data: &[u8] = b"* OK [CAPABILITY IMAP4rev2 STARTTLS] ready\r\n";
        let ev = lex.feed(&mut data).unwrap();
        assert_eq!(ev.len(), 1);
        match &ev[0] {
            ImapWireEvent::Untagged {
                status: Some(ImapStatus::Ok),
                response_code: Some(code),
                text,
                ..
            } => {
                assert_eq!(code, "CAPABILITY IMAP4rev2 STARTTLS");
                assert_eq!(text, "ready");
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(data.is_empty());
    }

    #[test]
    fn continuation_and_tagged() {
        let mut lex = ImapReplyLexer::new();
        let mut data: &[u8] = b"+ go ahead\r\nA001 OK done\r\n";
        let ev = lex.feed(&mut data).unwrap();
        assert_eq!(ev.len(), 2);
        assert_eq!(
            ev[0],
            ImapWireEvent::Continuation {
                text: "go ahead".into()
            }
        );
        assert!(matches!(
            &ev[1],
            ImapWireEvent::Tagged {
                tag,
                status: ImapStatus::Ok,
                ..
            } if tag == "A001"
        ));
    }

    #[test]
    fn quoted_value_not_literal() {
        assert_eq!(trailing_literal_size(r#"* 1 FETCH (BODY "hi {3}")"#), None);
        // Literal marker must be the line suffix (before CRLF); a closing
        // `)` after `{n}` means it is not a response literal.
        assert_eq!(trailing_literal_size("* 1 FETCH (BODY {5})"), None);
        assert_eq!(trailing_literal_size("* 1 FETCH (BODY {5}"), Some(5));
        assert_eq!(trailing_literal_size("* 1 FETCH (BODY {5+}"), Some(5));
    }

    #[test]
    fn literal_split_across_buffers() {
        let mut lex = ImapReplyLexer::new();
        let mut p1: &[u8] = b"* 1 FETCH (BODY[] {5}\r\nhe";
        let e1 = lex.feed(&mut p1).unwrap();
        assert!(matches!(e1[0], ImapWireEvent::Untagged { .. }));
        assert!(matches!(&e1[1], ImapWireEvent::LiteralData(d) if d == b"he"));
        assert!(lex.in_literal());
        let mut p2: &[u8] = b"llo)\r\n";
        let e2 = lex.feed(&mut p2).unwrap();
        assert!(matches!(&e2[0], ImapWireEvent::LiteralData(d) if d == b"llo"));
        assert_eq!(e2[1], ImapWireEvent::LiteralComplete);
        assert_eq!(e2[2], ImapWireEvent::Residual(")".into()));
    }

    #[test]
    fn literal_then_tagged_ok() {
        let mut lex = ImapReplyLexer::new();
        let mut data: &[u8] = b"* 1 FETCH (RFC822 {3}\r\nabc)\r\nA001 OK FETCH completed\r\n";
        let ev = lex.feed(&mut data).unwrap();
        assert!(matches!(ev[0], ImapWireEvent::Untagged { .. }));
        assert!(matches!(&ev[1], ImapWireEvent::LiteralData(d) if d == b"abc"));
        assert_eq!(ev[2], ImapWireEvent::LiteralComplete);
        assert_eq!(ev[3], ImapWireEvent::Residual(")".into()));
        assert!(matches!(
            &ev[4],
            ImapWireEvent::Tagged {
                tag,
                status: ImapStatus::Ok,
                ..
            } if tag == "A001"
        ));
    }

    #[test]
    fn split_crlf_across_feeds() {
        let mut lex = ImapReplyLexer::new();
        let mut a: &[u8] = b"* OK ready\r";
        assert!(lex.feed(&mut a).unwrap().is_empty());
        let mut b: &[u8] = b"\n";
        let ev = lex.feed(&mut b).unwrap();
        assert_eq!(ev.len(), 1);
        assert!(matches!(
            &ev[0],
            ImapWireEvent::Untagged {
                status: Some(ImapStatus::Ok),
                ..
            }
        ));
    }

    #[test]
    fn tagged_no_and_bad() {
        let mut lex = ImapReplyLexer::new();
        let mut data: &[u8] = b"A002 NO [ALERT] denied\r\nA003 BAD command\r\n";
        let ev = lex.feed(&mut data).unwrap();
        assert!(matches!(
            &ev[0],
            ImapWireEvent::Tagged {
                status: ImapStatus::No,
                response_code: Some(c),
                message,
                ..
            } if c == "ALERT" && message == "denied"
        ));
        assert!(matches!(
            &ev[1],
            ImapWireEvent::Tagged {
                status: ImapStatus::Bad,
                message,
                ..
            } if message == "command"
        ));
    }

    #[test]
    fn exists_vs_fetch_raw() {
        let mut lex = ImapReplyLexer::new();
        let mut data: &[u8] = b"* 3 EXISTS\r\n* 1 FETCH (FLAGS (\\Seen))\r\n";
        let ev = lex.feed(&mut data).unwrap();
        match &ev[0] {
            ImapWireEvent::Untagged { raw, .. } => assert_eq!(raw, "3 EXISTS"),
            _ => panic!(),
        }
        match &ev[1] {
            ImapWireEvent::Untagged { raw, .. } => {
                assert!(raw.contains("FETCH"));
            }
            _ => panic!(),
        }
    }
}
