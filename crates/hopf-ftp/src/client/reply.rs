// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Incremental, semantic FTP client reply parser.
//!
//! [`FtpReplyLexer`] never buffers a whole reply block and re-scans it for
//! `CRLF`. The 3-digit code is accumulated one digit at a time; RFC 959
//! §4.2's multi-line replies ("`nnn-`text ... `nnn `text") are handled by
//! matching each subsequent line's leading digits against the code already
//! established by the first line — only the *terminating* line (the one
//! whose code matches and whose separator is a space, not a dash) carries
//! meaning for the FTP client. Every other line's text is decorative and is
//! scanned-and-discarded without ever being buffered — matching the
//! precedent set by the POP3/SMTP client rewrites (`hopf-pop3`,
//! `hopf-smtp`). The terminating line's text is captured, bounded, only
//! when the shape in flight actually needs it (a `PASV`/`EPSV` address to
//! parse, or diagnostic text on failure).
//!
//! The caller tells the lexer what shape of reply to expect via
//! [`FtpReplyLexer::expect`], right after sending the corresponding
//! command — mirroring `SmtpReplyLexer`/`Pop3ReplyLexer`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use super::error::FtpError;

/// Cap on the terminating line's captured text (a PASV/EPSV address or a
/// diagnostic message), so a server that never sends a CRLF can't grow the
/// lexer's scratch buffer without bound.
pub const MAX_REPLY_LINE: usize = 4 * 1024;

/// What shape of reply to expect, set via [`FtpReplyLexer::expect`] right
/// after sending the corresponding command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FtpReplyShape {
    /// The initial `220` welcome banner.
    Welcome,
    /// `USER`.
    User,
    /// `PASS`.
    Pass,
    /// `PASV` or `EPSV` — the reply's code (227 vs 229) says which.
    PassiveMode,
    /// Start of a data transfer (`RETR`/`STOR`/`LIST` sent).
    XferStart,
    /// End of a data transfer.
    XferEnd,
    /// An arbitrary command; `expect` is the required reply code, or `0`
    /// for "any `2xx`".
    Cmd {
        /// Required reply code, or `0` for any `2xx`.
        expect: u16,
    },
    /// `QUIT` — any reply ends the session.
    Quit,
}

/// Semantic events. Every variant carries already-parsed, ready-to-use
/// data — never a raw code+text pair for the caller to re-interpret,
/// except [`FtpEvent::Error`], whose whole purpose *is* to carry
/// diagnostic text back to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FtpEvent {
    /// `220` welcome banner.
    Welcome,
    /// `331` — login needs a password.
    UserNeedsPassword,
    /// `230` on `USER` — no password needed.
    UserLoggedIn,
    /// `230` on `PASS`.
    PassOk,
    /// `227` PASV reply, address already parsed (RFC 959 §4.1.2).
    PasvAddr(SocketAddr),
    /// `229` EPSV reply, port already parsed (RFC 2428).
    EpsvPort(u16),
    /// `125`/`150` — server ready to begin the data transfer. `text` is
    /// the reply line's text — for `STOU`, servers conventionally return
    /// the assigned filename here (RFC 959 §4.1.3 doesn't standardize the
    /// exact wording, so callers parse it themselves).
    XferStartOk {
        /// The reply's text.
        text: String,
    },
    /// `226`/`250` — data transfer complete.
    XferEndOk,
    /// The expected code for an arbitrary command was received. `text` is
    /// the reply line's text (e.g. `PWD`'s quoted path, `SIZE`'s byte
    /// count, `SYST`'s system string) — previously discarded.
    CmdOk {
        /// The success reply's text.
        text: String,
    },
    /// `QUIT` acknowledged (any reply code — RFC 959 §4.1.1).
    QuitDone,
    /// Any shape's failure path: unexpected code, malformed PASV/EPSV
    /// text, or a plain rejection.
    Error {
        /// The server's 3-digit reply code.
        code: u16,
        /// The terminating line's diagnostic text.
        message: String,
    },
}

// ── Internal FSM ─────────────────────────────────────────────────────────────

/// What to do with the terminating line's text, decided once its code is
/// known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    /// Decorative text: scan for CRLF, never store.
    SkipToEol,
    /// Bounded text, kept (a PASV/EPSV address, or diagnostic text).
    KeepText,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Accumulating a line's leading 3 digits (0..3 seen so far).
    LineCode { digits: u8, value: u16 },
    /// 3 digits seen for this line; next byte decides SP (final line) /
    /// `-` (continuation) / anything else (bare code, immediate CRLF).
    LineSep { value: u16 },
    /// Reading (or discarding) the terminating line's text field.
    Reading(Field),
    /// Saw the text field's own CR; expect LF to complete it.
    FieldCr(Field),
    /// A non-terminating line: scan for CRLF, discard everything.
    DiscardLine,
    /// Saw CR while discarding a non-terminating line; expect LF.
    DiscardLineCr,
}

/// Incremental FTP client-reply parser. See the module docs.
pub struct FtpReplyLexer {
    shape: FtpReplyShape,
    state: State,
    /// The code established by the reply's first line. `None` before the
    /// first line of a reply has been read.
    reply_code: Option<u16>,
    /// `true` until the first line of the current reply has been read.
    at_first_line: bool,
    /// Scratch buffer for the terminating line's text (bounded).
    text: String,
}

impl Default for FtpReplyLexer {
    fn default() -> Self {
        Self::new()
    }
}

impl FtpReplyLexer {
    /// Create a lexer with no shape expectation set yet.
    pub fn new() -> Self {
        Self {
            shape: FtpReplyShape::Welcome,
            state: State::LineCode { digits: 0, value: 0 },
            reply_code: None,
            at_first_line: true,
            text: String::new(),
        }
    }

    /// Tell the lexer what shape of reply to expect next. Call this right
    /// after sending the command this reply answers.
    pub fn expect(&mut self, shape: FtpReplyShape) {
        self.shape = shape;
    }

    /// Feed newly-arrived bytes, returning every reply completed so far.
    /// `data` is advanced past every byte consumed (i.e. all of it, on
    /// success).
    pub fn feed(&mut self, data: &mut &[u8]) -> Result<Vec<FtpEvent>, FtpError> {
        let mut events = Vec::new();
        let mut rest = *data;
        while let Some((&b, tail)) = rest.split_first() {
            rest = tail;
            if let Some(event) = self.feed_byte(b)? {
                events.push(event);
            }
        }
        *data = rest;
        Ok(events)
    }

    fn feed_byte(&mut self, b: u8) -> Result<Option<FtpEvent>, FtpError> {
        match self.state {
            State::LineCode { digits, value } => self.push_line_code_byte(digits, value, b),
            State::LineSep { value } => self.push_line_sep_byte(value, b),
            State::Reading(field) => self.push_field_byte(field, b),
            State::FieldCr(field) => {
                if b == b'\n' {
                    self.finish_field(field)
                } else {
                    Err(FtpError::Parse("malformed FTP reply: expected LF after CR".into()))
                }
            }
            State::DiscardLine => {
                if b == b'\r' {
                    self.state = State::DiscardLineCr;
                }
                Ok(None)
            }
            State::DiscardLineCr => {
                if b == b'\n' {
                    self.state = State::LineCode { digits: 0, value: 0 };
                } else {
                    self.state = State::DiscardLine;
                }
                Ok(None)
            }
        }
    }

    fn push_line_code_byte(
        &mut self,
        digits: u8,
        value: u16,
        b: u8,
    ) -> Result<Option<FtpEvent>, FtpError> {
        if b.is_ascii_digit() {
            let value = value * 10 + u16::from(b - b'0');
            let digits = digits + 1;
            self.state = if digits == 3 {
                State::LineSep { value }
            } else {
                State::LineCode { digits, value }
            };
            return Ok(None);
        }
        if self.at_first_line {
            return Err(FtpError::Parse(format!(
                "malformed FTP reply: expected 3-digit code, got {b:#04x}"
            )));
        }
        // Non-digit-prefixed continuation line: free text, discard.
        if b == b'\r' {
            self.state = State::DiscardLineCr;
        } else {
            self.state = State::DiscardLine;
        }
        Ok(None)
    }

    fn push_line_sep_byte(&mut self, value: u16, b: u8) -> Result<Option<FtpEvent>, FtpError> {
        match b {
            b' ' => {
                self.begin_line(value, true);
                Ok(None)
            }
            b'\r' => {
                // Bare "NNN" line with no separator at all — RFC 959
                // allows a text-less final line. Treat as if a space had
                // terminated it, then feed this already-consumed CR to
                // whatever state that established.
                self.begin_line(value, true);
                match self.state {
                    State::Reading(field) => self.push_field_byte(field, b'\r'),
                    _ => {
                        self.state = State::DiscardLineCr;
                        Ok(None)
                    }
                }
            }
            _ => {
                // '-' (continuation) or any other byte: not a terminator.
                self.begin_line(value, false);
                Ok(None)
            }
        }
    }

    /// Establish whether the line whose code is `value` is the reply's
    /// terminating line, and set `self.state` accordingly. `is_space`:
    /// the separator byte actually seen was a space (candidate
    /// terminator) as opposed to `-`/anything else (definitely not).
    fn begin_line(&mut self, value: u16, is_space: bool) {
        let is_terminator = if self.at_first_line {
            self.reply_code = Some(value);
            is_space
        } else {
            is_space && self.reply_code == Some(value)
        };
        self.at_first_line = false;
        self.state = if is_terminator {
            self.text.clear();
            State::Reading(self.select_field(value))
        } else {
            State::DiscardLine
        };
    }

    /// Decide how to handle the terminating line's text, based on the
    /// shape and the code just established.
    fn select_field(&self, code: u16) -> Field {
        match self.shape {
            FtpReplyShape::Welcome => {
                if code == 220 {
                    Field::SkipToEol
                } else {
                    Field::KeepText
                }
            }
            FtpReplyShape::User => {
                if matches!(code, 331 | 230) {
                    Field::SkipToEol
                } else {
                    Field::KeepText
                }
            }
            FtpReplyShape::Pass => {
                if code == 230 {
                    Field::SkipToEol
                } else {
                    Field::KeepText
                }
            }
            // Always kept: 227/229 need the address text parsed; any
            // other code needs the diagnostic text.
            FtpReplyShape::PassiveMode => Field::KeepText,
            // Kept either way: STOU's assigned filename rides the success
            // text (RFC 959 §4.1.3); other transfers ignore it, but there's
            // no way to tell which without knowing the verb, which this
            // shape doesn't carry — see FtpReplyShape::Cmd for the same
            // reasoning applied to arbitrary commands.
            FtpReplyShape::XferStart => Field::KeepText,
            FtpReplyShape::XferEnd => {
                if matches!(code, 226 | 250) {
                    Field::SkipToEol
                } else {
                    Field::KeepText
                }
            }
            // Kept either way: success text carries real values (PWD's
            // path, SIZE's byte count, SYST's system string, …) just as
            // much as failure text carries diagnostics.
            FtpReplyShape::Cmd { .. } => Field::KeepText,
            FtpReplyShape::Quit => Field::SkipToEol, // any code ends the session
        }
    }

    fn push_field_byte(&mut self, field: Field, b: u8) -> Result<Option<FtpEvent>, FtpError> {
        if b == b'\r' {
            self.state = State::FieldCr(field);
            return Ok(None);
        }
        if field == Field::KeepText {
            if self.text.len() >= MAX_REPLY_LINE {
                return Err(FtpError::Parse("FTP reply line too long".into()));
            }
            self.text.push(b as char);
        }
        Ok(None)
    }

    fn finish_field(&mut self, field: Field) -> Result<Option<FtpEvent>, FtpError> {
        let code = self.reply_code.take().unwrap_or(0);
        self.at_first_line = true;
        self.state = State::LineCode { digits: 0, value: 0 };
        let text = std::mem::take(&mut self.text);

        if field == Field::SkipToEol {
            return Ok(Some(self.success_event(code)));
        }

        // KeepText: either a PASV/EPSV address to parse, an arbitrary
        // command's success/failure text, or diagnostics.
        match self.shape {
            FtpReplyShape::PassiveMode if code == 227 => match parse_pasv_addr(&text) {
                Ok(addr) => Ok(Some(FtpEvent::PasvAddr(addr))),
                Err(_) => Ok(Some(FtpEvent::Error { code, message: text })),
            },
            FtpReplyShape::PassiveMode if code == 229 => match parse_epsv_port(&text) {
                Ok(port) => Ok(Some(FtpEvent::EpsvPort(port))),
                Err(_) => Ok(Some(FtpEvent::Error { code, message: text })),
            },
            FtpReplyShape::Cmd { expect } => {
                let ok = if expect == 0 { code / 100 == 2 } else { code == expect };
                if ok {
                    Ok(Some(FtpEvent::CmdOk { text }))
                } else {
                    Ok(Some(FtpEvent::Error { code, message: text }))
                }
            }
            FtpReplyShape::XferStart if matches!(code, 125 | 150) => {
                Ok(Some(FtpEvent::XferStartOk { text }))
            }
            _ => Ok(Some(FtpEvent::Error { code, message: text })),
        }
    }

    fn success_event(&self, code: u16) -> FtpEvent {
        match self.shape {
            FtpReplyShape::Welcome => FtpEvent::Welcome,
            FtpReplyShape::User => {
                if code == 331 {
                    FtpEvent::UserNeedsPassword
                } else {
                    FtpEvent::UserLoggedIn
                }
            }
            FtpReplyShape::Pass => FtpEvent::PassOk,
            FtpReplyShape::PassiveMode => {
                // select_field always returns KeepText for this shape, so
                // finish_field never reaches success_event for it.
                unreachable!("PassiveMode's field is always KeepText")
            }
            FtpReplyShape::XferStart => {
                // select_field always returns KeepText for this shape, so
                // finish_field never reaches success_event for it.
                unreachable!("XferStart's field is always KeepText")
            }
            FtpReplyShape::XferEnd => FtpEvent::XferEndOk,
            FtpReplyShape::Cmd { .. } => {
                // select_field always returns KeepText for this shape, so
                // finish_field never reaches success_event for it.
                unreachable!("Cmd's field is always KeepText")
            }
            FtpReplyShape::Quit => FtpEvent::QuitDone,
        }
    }
}

// ---------------------------------------------------------------------------
// Address-parsing helpers
// ---------------------------------------------------------------------------

/// Parse a `227` PASV reply text into a [`SocketAddr`].
///
/// Expects the canonical form `(h1,h2,h3,h4,p1,p2)` anywhere in `text`.
pub fn parse_pasv_addr(text: &str) -> Result<SocketAddr, FtpError> {
    let start = text
        .find('(')
        .ok_or_else(|| FtpError::Parse(format!("PASV: no '(' in {text:?}")))?
        + 1;
    let end = text[start..]
        .find(')')
        .ok_or_else(|| FtpError::Parse(format!("PASV: no ')' in {text:?}")))?
        + start;
    let parts: Vec<&str> = text[start..end].split(',').collect();
    if parts.len() != 6 {
        return Err(FtpError::Parse(format!("PASV: expected 6 fields, got {}", parts.len())));
    }
    let mut nums = [0u16; 6];
    for (i, p) in parts.iter().enumerate() {
        nums[i] = p
            .trim()
            .parse()
            .map_err(|_| FtpError::Parse(format!("PASV: bad number {:?}", p)))?;
    }
    let ip = Ipv4Addr::new(nums[0] as u8, nums[1] as u8, nums[2] as u8, nums[3] as u8);
    let port = nums[4] * 256 + nums[5];
    Ok(SocketAddr::from((ip, port)))
}

/// Parse a `229` EPSV reply text into the data port number.
///
/// Expects `(|||port|)` or `(|af|addr|port|)` anywhere in `text`.
pub fn parse_epsv_port(text: &str) -> Result<u16, FtpError> {
    let start = text
        .find('(')
        .ok_or_else(|| FtpError::Parse(format!("EPSV: no '(' in {text:?}")))?
        + 1;
    let end = text[start..]
        .find(')')
        .ok_or_else(|| FtpError::Parse(format!("EPSV: no ')' in {text:?}")))?
        + start;
    let inner = &text[start..end];
    // Format: `|||port|` or `|af|addr|port|`
    let parts: Vec<&str> = inner.split('|').collect();
    let port_str = parts
        .iter()
        .rev()
        .find(|p| !p.is_empty())
        .copied()
        .ok_or_else(|| FtpError::Parse(format!("EPSV: no port in {text:?}")))?;
    port_str
        .parse()
        .map_err(|_| FtpError::Parse(format!("EPSV: bad port {port_str:?}")))
}

/// Parse a `257` PWD reply and extract the quoted path.
///
/// Returns `None` when no double-quoted string is found.
pub fn parse_pwd_path(text: &str) -> Option<String> {
    let start = text.find('"')?;
    let end = text[start + 1..].find('"')? + start + 1;
    Some(text[start + 1..end].replace("\"\"", "\""))
}

/// Format a `PORT` command argument for an IPv4 `addr` (`h1,h2,h3,h4,p1,p2`).
///
/// Returns `None` for IPv6 — use [`format_eprt_arg`] instead (RFC 2428).
pub fn format_port_arg(addr: SocketAddr) -> Option<String> {
    let IpAddr::V4(ip) = addr.ip() else {
        return None;
    };
    let o = ip.octets();
    let p = addr.port();
    Some(format!(
        "{},{},{},{},{},{}",
        o[0],
        o[1],
        o[2],
        o[3],
        p / 256,
        p % 256
    ))
}

/// Format an `EPRT` command argument (`|af|addr|port|`, RFC 2428 §2).
pub fn format_eprt_arg(addr: SocketAddr) -> String {
    let af = match addr.ip() {
        IpAddr::V4(_) => 1,
        IpAddr::V6(_) => 2,
    };
    format!("|{af}|{}|{}|", addr.ip(), addr.port())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed_all(lex: &mut FtpReplyLexer, s: &str) -> Vec<FtpEvent> {
        let mut data: &[u8] = s.as_bytes();
        lex.feed(&mut data).unwrap()
    }

    #[test]
    fn welcome_single_line() {
        let mut lex = FtpReplyLexer::new();
        lex.expect(FtpReplyShape::Welcome);
        assert_eq!(feed_all(&mut lex, "220 Welcome\r\n"), vec![FtpEvent::Welcome]);
    }

    #[test]
    fn welcome_multiline_banner_discarded() {
        let mut lex = FtpReplyLexer::new();
        lex.expect(FtpReplyShape::Welcome);
        let events = feed_all(
            &mut lex,
            "220-Server ready\r\nSecond banner line\r\n220 Welcome\r\n",
        );
        assert_eq!(events, vec![FtpEvent::Welcome]);
    }

    #[test]
    fn welcome_rejected_service_unavailable() {
        let mut lex = FtpReplyLexer::new();
        lex.expect(FtpReplyShape::Welcome);
        assert_eq!(
            feed_all(&mut lex, "421 Too many connections\r\n"),
            vec![FtpEvent::Error { code: 421, message: "Too many connections".into() }]
        );
    }

    #[test]
    fn user_needs_password_and_logged_in() {
        let mut lex = FtpReplyLexer::new();
        lex.expect(FtpReplyShape::User);
        assert_eq!(feed_all(&mut lex, "331 Password required\r\n"), vec![FtpEvent::UserNeedsPassword]);

        lex.expect(FtpReplyShape::User);
        assert_eq!(feed_all(&mut lex, "230 Logged in\r\n"), vec![FtpEvent::UserLoggedIn]);
    }

    #[test]
    fn user_rejected() {
        let mut lex = FtpReplyLexer::new();
        lex.expect(FtpReplyShape::User);
        assert_eq!(
            feed_all(&mut lex, "530 Not logged in\r\n"),
            vec![FtpEvent::Error { code: 530, message: "Not logged in".into() }]
        );
    }

    #[test]
    fn pass_ok_and_rejected() {
        let mut lex = FtpReplyLexer::new();
        lex.expect(FtpReplyShape::Pass);
        assert_eq!(feed_all(&mut lex, "230 Logged in\r\n"), vec![FtpEvent::PassOk]);

        lex.expect(FtpReplyShape::Pass);
        assert_eq!(
            feed_all(&mut lex, "530 Login incorrect\r\n"),
            vec![FtpEvent::Error { code: 530, message: "Login incorrect".into() }]
        );
    }

    #[test]
    fn pasv_address_parsed() {
        let mut lex = FtpReplyLexer::new();
        lex.expect(FtpReplyShape::PassiveMode);
        assert_eq!(
            feed_all(&mut lex, "227 Entering Passive Mode (192,168,1,2,4,5)\r\n"),
            vec![FtpEvent::PasvAddr("192.168.1.2:1029".parse().unwrap())]
        );
    }

    #[test]
    fn epsv_port_parsed() {
        let mut lex = FtpReplyLexer::new();
        lex.expect(FtpReplyShape::PassiveMode);
        assert_eq!(
            feed_all(&mut lex, "229 Entering Extended Passive Mode (|||2121|)\r\n"),
            vec![FtpEvent::EpsvPort(2121)]
        );
    }

    #[test]
    fn pasv_rejected() {
        let mut lex = FtpReplyLexer::new();
        lex.expect(FtpReplyShape::PassiveMode);
        assert_eq!(
            feed_all(&mut lex, "502 Command not implemented\r\n"),
            vec![FtpEvent::Error { code: 502, message: "Command not implemented".into() }]
        );
    }

    #[test]
    fn xfer_start_and_end() {
        let mut lex = FtpReplyLexer::new();
        lex.expect(FtpReplyShape::XferStart);
        assert_eq!(
            feed_all(&mut lex, "150 Opening data connection\r\n"),
            vec![FtpEvent::XferStartOk { text: "Opening data connection".into() }]
        );

        lex.expect(FtpReplyShape::XferEnd);
        assert_eq!(feed_all(&mut lex, "226 Transfer complete\r\n"), vec![FtpEvent::XferEndOk]);
    }

    #[test]
    fn xfer_start_stou_filename_text_kept() {
        // STOU's assigned filename rides the 125/150 reply text.
        let mut lex = FtpReplyLexer::new();
        lex.expect(FtpReplyShape::XferStart);
        assert_eq!(
            feed_all(&mut lex, "150 FILE: unique-name-123.txt\r\n"),
            vec![FtpEvent::XferStartOk { text: "FILE: unique-name-123.txt".into() }]
        );
    }

    #[test]
    fn xfer_start_rejected() {
        let mut lex = FtpReplyLexer::new();
        lex.expect(FtpReplyShape::XferStart);
        assert_eq!(
            feed_all(&mut lex, "550 File not found\r\n"),
            vec![FtpEvent::Error { code: 550, message: "File not found".into() }]
        );
    }

    #[test]
    fn cmd_exact_code_and_any_2xx() {
        let mut lex = FtpReplyLexer::new();
        lex.expect(FtpReplyShape::Cmd { expect: 200 });
        assert_eq!(
            feed_all(&mut lex, "200 Command OK\r\n"),
            vec![FtpEvent::CmdOk { text: "Command OK".into() }]
        );

        lex.expect(FtpReplyShape::Cmd { expect: 0 });
        assert_eq!(
            feed_all(&mut lex, "250 OK\r\n"),
            vec![FtpEvent::CmdOk { text: "OK".into() }]
        );

        lex.expect(FtpReplyShape::Cmd { expect: 200 });
        assert_eq!(
            feed_all(&mut lex, "500 Syntax error\r\n"),
            vec![FtpEvent::Error { code: 500, message: "Syntax error".into() }]
        );
    }

    #[test]
    fn quit_always_done() {
        let mut lex = FtpReplyLexer::new();
        lex.expect(FtpReplyShape::Quit);
        assert_eq!(feed_all(&mut lex, "221 Goodbye\r\n"), vec![FtpEvent::QuitDone]);

        lex.expect(FtpReplyShape::Quit);
        assert_eq!(feed_all(&mut lex, "500 Huh\r\n"), vec![FtpEvent::QuitDone]);
    }

    #[test]
    fn bare_code_no_text_no_crlf_separator() {
        // RFC 959 allows a final line with no text at all: "NNN\r\n".
        let mut lex = FtpReplyLexer::new();
        lex.expect(FtpReplyShape::XferEnd);
        assert_eq!(feed_all(&mut lex, "226\r\n"), vec![FtpEvent::XferEndOk]);
    }

    #[test]
    fn cmd_bare_code_no_text_is_empty_string() {
        let mut lex = FtpReplyLexer::new();
        lex.expect(FtpReplyShape::Cmd { expect: 200 });
        assert_eq!(feed_all(&mut lex, "200\r\n"), vec![FtpEvent::CmdOk { text: String::new() }]);
    }

    #[test]
    fn cmd_success_text_reaches_pwd_parser() {
        // Previously unreachable: PWD's success text was discarded before
        // parse_pwd_path could ever see it.
        let mut lex = FtpReplyLexer::new();
        lex.expect(FtpReplyShape::Cmd { expect: 257 });
        let events = feed_all(&mut lex, "257 \"/tmp\" is current directory\r\n");
        match &events[0] {
            FtpEvent::CmdOk { text } => {
                assert_eq!(parse_pwd_path(text).as_deref(), Some("/tmp"));
            }
            other => panic!("expected CmdOk, got {other:?}"),
        }
    }

    #[test]
    fn multiline_error_only_terminator_text_kept() {
        let mut lex = FtpReplyLexer::new();
        lex.expect(FtpReplyShape::Cmd { expect: 200 });
        let events = feed_all(
            &mut lex,
            "550-First diagnostic line\r\nSecond diagnostic line\r\n550 Final line text\r\n",
        );
        assert_eq!(
            events,
            vec![FtpEvent::Error { code: 550, message: "Final line text".into() }]
        );
    }

    #[test]
    fn expect_updated_between_replies() {
        // Realistic driving: one reply per feed() call, `expect` updated
        // (by the command that was sent in response to the first) before
        // the next reply's bytes arrive.
        let mut lex = FtpReplyLexer::new();
        lex.expect(FtpReplyShape::User);
        let mut data: &[u8] = b"331 Password required\r\n";
        assert_eq!(lex.feed(&mut data).unwrap(), vec![FtpEvent::UserNeedsPassword]);

        lex.expect(FtpReplyShape::Pass);
        let mut data2: &[u8] = b"230 Logged in\r\n";
        assert_eq!(lex.feed(&mut data2).unwrap(), vec![FtpEvent::PassOk]);
    }

    #[test]
    fn two_replies_in_one_feed_same_shape() {
        // A single feed() call can legitimately contain more than one
        // complete reply (e.g. a burst read) — every reply in that burst
        // shares the shape active when feed() was called.
        let mut lex = FtpReplyLexer::new();
        lex.expect(FtpReplyShape::Cmd { expect: 200 });
        let mut data: &[u8] = b"200 First OK\r\n200 Second OK\r\n";
        assert_eq!(
            lex.feed(&mut data).unwrap(),
            vec![
                FtpEvent::CmdOk { text: "First OK".into() },
                FtpEvent::CmdOk { text: "Second OK".into() },
            ]
        );
    }

    #[test]
    fn split_one_byte_at_a_time_matches_bulk_feed() {
        let input = b"227 Entering Passive Mode (10,0,0,1,200,10)\r\n";
        let mut bulk_lex = FtpReplyLexer::new();
        bulk_lex.expect(FtpReplyShape::PassiveMode);
        let mut bulk_data: &[u8] = input;
        let bulk_events = bulk_lex.feed(&mut bulk_data).unwrap();

        let mut split_lex = FtpReplyLexer::new();
        split_lex.expect(FtpReplyShape::PassiveMode);
        let mut split_events = Vec::new();
        for &b in input {
            let mut one = [b];
            let mut slice: &[u8] = &one[..];
            split_events.extend(split_lex.feed(&mut slice).unwrap());
            let _ = &mut one;
        }
        assert_eq!(bulk_events, split_events);
    }

    #[test]
    fn oversized_diagnostic_errors_out() {
        let mut lex = FtpReplyLexer::new();
        lex.expect(FtpReplyShape::Cmd { expect: 200 });
        let mut data = Vec::new();
        data.extend_from_slice(b"500 ");
        data.extend(std::iter::repeat(b'x').take(MAX_REPLY_LINE + 1));
        data.extend_from_slice(b"\r\n");
        let mut slice: &[u8] = &data;
        let err = lex.feed(&mut slice).unwrap_err();
        assert!(matches!(err, FtpError::Parse(_)));
    }

    #[test]
    fn malformed_first_line_errors() {
        let mut lex = FtpReplyLexer::new();
        lex.expect(FtpReplyShape::Welcome);
        let mut data: &[u8] = b"abc Not a code\r\n";
        assert!(lex.feed(&mut data).is_err());
    }
}
