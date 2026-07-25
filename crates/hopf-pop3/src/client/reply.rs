// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! POP3 wire-reply incremental lexer.
//!
//! Two-mode incremental lexer:
//! - [`Pop3LexMode::Status`]: parses `+OK`, `-ERR`, or `+` continuation lines.
//! - [`Pop3LexMode::Listing`]: collects lines until the `.\r\n` terminator,
//!   dot-unstuffing each line (leading `..` → `.`).
//!
//! Body data (after RETR/TOP +OK) is handled by
//! [`super::unstuff::Pop3DotUnstuffer`] and not this lexer.
//!
//! ## Mode switching
//!
//! Call [`Pop3ReplyLexer::expect_multiline`] **before** the response bytes
//! arrive (i.e. right after sending CAPA/LIST/UIDL).  The lexer then
//! automatically transitions from Status → Listing mode after it emits the
//! `+OK` event, so listing lines in the same TCP segment are parsed correctly.

use super::error::Pop3Error;

/// Lexer operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pop3LexMode {
    /// Parse a status line (+OK / -ERR / +).
    Status,
    /// Collect multiline listing lines until `.\r\n`.
    Listing,
}

/// Parsed wire event emitted by [`Pop3ReplyLexer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pop3WireEvent {
    /// `+OK [text]` — success reply.
    Ok {
        /// Reply text after `+OK `.
        text: String,
    },
    /// `-ERR [text]` — error reply.
    Err {
        /// Error description after `-ERR `.
        text: String,
    },
    /// `+ [data]` — SASL continuation (RFC 2449 §8).
    Continue {
        /// Base64 challenge data (may be empty).
        text: String,
    },
    /// One line from a multiline listing (CAPA / LIST / UIDL body).
    ListingLine {
        /// Dot-unstuffed line text (without CRLF).
        text: String,
    },
    /// `.\r\n` — end of a multiline listing.
    ListingEnd,
}

/// Incremental POP3 server-reply lexer.
///
/// Call [`Pop3ReplyLexer::feed`] with inbound bytes; it advances the slice
/// past consumed bytes and returns zero or more [`Pop3WireEvent`]s.
///
/// `*data` is updated **after each complete line**, so the caller can break
/// out of the event loop on body-mode transitions (RETR / TOP) and route the
/// remaining bytes to [`super::unstuff::Pop3DotUnstuffer`] rather than the
/// lexer.
pub struct Pop3ReplyLexer {
    mode: Pop3LexMode,
    line_buf: Vec<u8>,
    /// When `true`, the next `+OK` event automatically switches mode to
    /// [`Pop3LexMode::Listing`]. Set with [`Pop3ReplyLexer::expect_multiline`].
    after_ok_enter_listing: bool,
    /// When `true`, stop after emitting the next `+OK` event and return
    /// immediately, leaving remaining bytes (the message body) in `data`.
    /// Used for RETR / TOP.
    pub(crate) stop_after_ok: bool,
}

impl Default for Pop3ReplyLexer {
    fn default() -> Self {
        Self::new()
    }
}

impl Pop3ReplyLexer {
    /// Create a new lexer in Status mode.
    pub fn new() -> Self {
        Self {
            mode: Pop3LexMode::Status,
            line_buf: Vec::new(),
            after_ok_enter_listing: false,
            stop_after_ok: false,
        }
    }

    /// Signal that the next server response will be a multiline listing.
    ///
    /// Must be called before the response bytes arrive (e.g. right after the
    /// CAPA/LIST/UIDL command is queued). The lexer will automatically enter
    /// [`Pop3LexMode::Listing`] after emitting the +OK status event.
    pub fn expect_multiline(&mut self) {
        self.after_ok_enter_listing = true;
    }

    /// Current lexer mode.
    pub fn current_mode(&self) -> Pop3LexMode {
        self.mode
    }

    /// Feed inbound bytes. Returns parsed events; advances `data` past consumed
    /// bytes **after each complete line** so that transitions to body mode
    /// (RETR / TOP) leave remaining bytes accessible for the dot-unstuffer.
    ///
    /// Returns an error on malformed input.
    pub fn feed(&mut self, data: &mut &[u8]) -> Result<Vec<Pop3WireEvent>, Pop3Error> {
        let mut events = Vec::new();

        loop {
            if (*data).is_empty() {
                break;
            }

            // Scan forward to find the next CRLF, accumulating bytes into line_buf.
            let available = *data;
            let mut found_crlf = false;
            let mut line_end = 0usize; // index in `available` just past the CRLF

            for (i, &b) in available.iter().enumerate() {
                self.line_buf.push(b);

                if self.line_buf.len() > 32 * 1024 {
                    return Err(Pop3Error::Parse("POP3 reply line too long".into()));
                }

                let n = self.line_buf.len();
                if n >= 2 && self.line_buf[n - 2] == b'\r' && self.line_buf[n - 1] == b'\n' {
                    line_end = i + 1;
                    found_crlf = true;
                    break;
                }
            }

            if !found_crlf {
                // No complete line in the remaining input; line_buf accumulates.
                // All of `available` has been pushed into line_buf.
                *data = &available[available.len()..];
                break;
            }

            // We have a complete line in line_buf.
            let line = std::mem::take(&mut self.line_buf);
            let text_bytes = &line[..line.len() - 2]; // strip CRLF
            let text = String::from_utf8_lossy(text_bytes).into_owned();

            // Build the event (may fail for bad status lines).
            let event = match self.mode {
                Pop3LexMode::Listing => {
                    if text == "." {
                        self.mode = Pop3LexMode::Status;
                        Pop3WireEvent::ListingEnd
                    } else {
                        let unstuffed = if text.starts_with("..") {
                            text[1..].to_string()
                        } else {
                            text
                        };
                        Pop3WireEvent::ListingLine { text: unstuffed }
                    }
                }
                Pop3LexMode::Status => {
                    if text.starts_with("+OK") {
                        let body = if text.len() > 3 && text.as_bytes()[3] == b' ' {
                            text[4..].to_string()
                        } else {
                            String::new()
                        };
                        if self.after_ok_enter_listing {
                            self.after_ok_enter_listing = false;
                            self.mode = Pop3LexMode::Listing;
                        }
                        Pop3WireEvent::Ok { text: body }
                    } else if text.starts_with("-ERR") {
                        self.after_ok_enter_listing = false;
                        let body = if text.len() > 4 && text.as_bytes()[4] == b' ' {
                            text[5..].to_string()
                        } else {
                            String::new()
                        };
                        Pop3WireEvent::Err { text: body }
                    } else if let Some(rest) = text.strip_prefix("+ ") {
                        Pop3WireEvent::Continue { text: rest.to_string() }
                    } else if text == "+" {
                        Pop3WireEvent::Continue { text: String::new() }
                    } else if text.is_empty() {
                        // Tolerate blank lines — advance past them and continue.
                        *data = &available[line_end..];
                        continue;
                    } else {
                        // Bad status line — do NOT advance *data; return error.
                        // (The erroneous line bytes are discarded from line_buf.)
                        return Err(Pop3Error::Parse(format!(
                            "unexpected POP3 reply: {text:?}"
                        )));
                    }
                }
            };

            // SUCCESS: advance *data past this line.
            *data = &available[line_end..];
            let stop = self.stop_after_ok && matches!(event, Pop3WireEvent::Ok { .. });
            if stop {
                self.stop_after_ok = false;
            }
            events.push(event);
            if stop {
                // Stop here and leave remaining bytes (body) for the unstuffer.
                break;
            }
        }

        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok_single_line() {
        let mut lex = Pop3ReplyLexer::new();
        let mut data: &[u8] = b"+OK POP3 server ready\r\n";
        let events = lex.feed(&mut data).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], Pop3WireEvent::Ok { text: "POP3 server ready".into() });
        assert!(data.is_empty());
    }

    #[test]
    fn err_single_line() {
        let mut lex = Pop3ReplyLexer::new();
        let mut data: &[u8] = b"-ERR [AUTH] bad credentials\r\n";
        let events = lex.feed(&mut data).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], Pop3WireEvent::Err { text: "[AUTH] bad credentials".into() });
    }

    #[test]
    fn continuation_line() {
        let mut lex = Pop3ReplyLexer::new();
        let mut data: &[u8] = b"+ YWJj\r\n";
        let events = lex.feed(&mut data).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], Pop3WireEvent::Continue { text: "YWJj".into() });
    }

    #[test]
    fn multiline_capa() {
        let mut lex = Pop3ReplyLexer::new();
        lex.expect_multiline();
        let mut data: &[u8] = b"+OK Capability list follows\r\nUSER\r\nTOP\r\nUIDL\r\nSTLS\r\n.\r\n";
        let events = lex.feed(&mut data).unwrap();
        assert_eq!(events.len(), 6, "{events:?}");
        assert!(matches!(&events[0], Pop3WireEvent::Ok { .. }));
        assert_eq!(events[1], Pop3WireEvent::ListingLine { text: "USER".into() });
        assert_eq!(events[4], Pop3WireEvent::ListingLine { text: "STLS".into() });
        assert_eq!(events[5], Pop3WireEvent::ListingEnd);
    }

    #[test]
    fn multiline_err_clears_listing_flag() {
        let mut lex = Pop3ReplyLexer::new();
        lex.expect_multiline();
        let mut data: &[u8] = b"-ERR no capa\r\n";
        let events = lex.feed(&mut data).unwrap();
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], Pop3WireEvent::Err { .. }));
        // Should be back in Status mode — next line is a normal status.
        let mut data2: &[u8] = b"+OK ok\r\n";
        let events2 = lex.feed(&mut data2).unwrap();
        assert!(matches!(&events2[0], Pop3WireEvent::Ok { .. }));
        assert_eq!(lex.current_mode(), Pop3LexMode::Status);
    }

    #[test]
    fn listing_dot_unstuff() {
        let mut lex = Pop3ReplyLexer::new();
        lex.expect_multiline();
        let mut data: &[u8] = b"+OK\r\n..dotted\r\n.\r\n";
        let events = lex.feed(&mut data).unwrap();
        // Ok, ListingLine(".dotted"), ListingEnd
        assert_eq!(events[1], Pop3WireEvent::ListingLine { text: ".dotted".into() });
    }

    #[test]
    fn split_across_feeds() {
        let mut lex = Pop3ReplyLexer::new();
        let mut part1: &[u8] = b"+OK POP3 ready\r";
        let e1 = lex.feed(&mut part1).unwrap();
        assert!(e1.is_empty());
        let mut part2: &[u8] = b"\n";
        let e2 = lex.feed(&mut part2).unwrap();
        assert_eq!(e2.len(), 1);
        assert!(matches!(&e2[0], Pop3WireEvent::Ok { .. }));
    }
}
