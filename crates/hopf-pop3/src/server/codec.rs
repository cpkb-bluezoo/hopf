// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Incremental, semantic POP3 command parser: `KEYWORD [SP TEXT] CRLF`.
//!
//! Self-contained streaming parser: [`Pop3ServerLexer::feed`] consumes every
//! byte it is given and keeps a command-in-progress in its own bounded
//! `verb`/`arg` scratch buffers — never in a buffer the caller has to retain
//! and re-supply.
//!
//! Beyond tokenizing the line, the lexer also builds the semantic
//! [`Pop3Command`] directly: `RETR`/`DELE`/`TOP`'s message numbers are
//! already-parsed `u32`s, `APOP`'s name/digest are already split, and
//! `AUTH`'s initial response is already base64-decoded — the caller never
//! re-parses a raw argument string. A command whose arguments don't match
//! its verb's expected shape becomes [`Pop3Command::Malformed`] rather than
//! a parse error: unlike a malformed *reply* on the client side, a
//! malformed *command* here is just something to reply `-ERR` to and move
//! on from, not a reason to tear down the connection.
//!
//! `AUTH`'s SASL continuation lines (bare base64, no verb) are handled by
//! the same lexer via [`Pop3ServerLexer::expect_sasl_response`] — call it
//! right after sending a `+ challenge` reply, mirroring the `expect()`
//! pattern used by the client-side reply lexers in `hopf-pop3`/`hopf-smtp`/
//! `hopf-imap`. This replaces an ad-hoc `data.windows(2).position(CRLF)`
//! scan that used to live in `control.rs` — that scan silently dropped a
//! continuation line's bytes if the CRLF hadn't arrived yet in the current
//! `feed()` call, since it had no persistent scratch buffer to resume from
//! on the next call.

use rmimeparser::charset::base64;

/// Default RFC 1939 command-line length limit (octets), applied
/// independently to the verb and to the argument.
pub const MAX_COMMAND_LINE: usize = 512;

/// A fully parsed, semantic POP3 command (or a syntactically/lexically
/// invalid line, reported so the caller can reply `-ERR` without erroring
/// the connection).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pop3Command {
    /// `USER name`
    User(String),
    /// `PASS string`
    Pass(String),
    /// `APOP name digest`
    Apop {
        /// Mailbox name.
        name: String,
        /// MD5 digest (hex text, as sent).
        digest: String,
    },
    /// Bare `AUTH` — list supported SASL mechanisms (RFC 1734 style).
    AuthList,
    /// `AUTH mechanism [initial-response]` (RFC 5034).
    Auth {
        /// SASL mechanism name, as sent (not yet uppercased).
        mechanism: String,
        /// Already base64-decoded initial response, if present. `Some("=")`
        /// on the wire (an explicit empty response) decodes to `Some(vec![])`.
        initial_response: Option<Vec<u8>>,
    },
    /// A bare-line SASL continuation response, already base64-decoded (see
    /// [`Pop3ServerLexer::expect_sasl_response`]).
    SaslResponse(Vec<u8>),
    /// A bare-line SASL continuation that failed to base64-decode.
    SaslResponseInvalid,
    /// A bare `*` SASL continuation line — client cancels the exchange.
    SaslAbort,
    /// `STLS` (RFC 2595).
    Stls,
    /// `UTF8` (RFC 6856).
    Utf8,
    /// `CAPA` (RFC 2449).
    Capa,
    /// `NOOP`
    Noop,
    /// `QUIT`
    Quit,
    /// `STAT`
    Stat,
    /// `LIST [msg]`
    List(Option<u32>),
    /// `RETR msg`
    Retr(u32),
    /// `DELE msg`
    Dele(u32),
    /// `RSET`
    Rset,
    /// `TOP msg n`
    Top(u32, u32),
    /// `UIDL [msg]`
    Uidl(Option<u32>),
    /// A recognised verb whose argument didn't match its expected shape
    /// (e.g. `RETR` with no number, `TOP` with only one number).
    Malformed {
        /// The verb, for an error reply.
        verb: String,
    },
    /// A verb the lexer doesn't recognise at all.
    Unknown {
        /// The unrecognised verb.
        verb: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Accumulating the verb, up to SP or CR.
    Verb,
    /// Accumulating the argument (post-SP), up to CR.
    Arg,
    /// Saw CR; a following LF completes the command. Any other byte means
    /// the CR was literal content, not a terminator.
    Cr,
    /// A token exceeded the cap: discard bytes up to the next CRLF (no
    /// command is produced for the discarded line), then resume normally.
    Resync,
    /// Saw CR while resyncing; a following LF ends the discarded line.
    ResyncCr,
    /// Accumulating a bare SASL continuation line (no verb/arg split).
    RawLine,
    /// Saw CR while accumulating a raw line; a following LF completes it.
    RawLineCr,
}

/// Incremental, semantic POP3 command-line parser. See the module docs.
pub struct Pop3ServerLexer {
    max_line: usize,
    state: State,
    verb: Vec<u8>,
    arg: Vec<u8>,
    have_arg: bool,
    raw: Vec<u8>,
    ready: Vec<Pop3Command>,
    line_too_long: bool,
}

impl Pop3ServerLexer {
    /// Create with a max token length (bytes), applied to the verb, the
    /// argument, and a raw SASL continuation line independently.
    pub fn new(max_line: usize) -> Self {
        Self {
            max_line,
            state: State::Verb,
            verb: Vec::new(),
            arg: Vec::new(),
            have_arg: false,
            raw: Vec::new(),
            ready: Vec::new(),
            line_too_long: false,
        }
    }

    /// Tell the lexer the next line is a bare SASL continuation response
    /// (RFC 5034 §4), not a command. Call this right after sending a `+
    /// challenge` reply. The lexer reverts to normal command parsing as
    /// soon as that one line completes.
    pub fn expect_sasl_response(&mut self) {
        self.state = State::RawLine;
        self.raw.clear();
    }

    /// Feed inbound control bytes; returns newly completed commands.
    ///
    /// Consumes everything given — `*data` is always left empty. When a
    /// token exceeds the length cap, that line produces no command;
    /// [`took_line_too_long`](Self::took_line_too_long) reports it.
    pub fn feed(&mut self, data: &mut &[u8]) -> Vec<Pop3Command> {
        for &b in data.iter() {
            self.push_byte(b);
        }
        *data = &[];
        std::mem::take(&mut self.ready)
    }

    /// Whether the last feed hit the token-length cap (clears the flag).
    pub fn took_line_too_long(&mut self) -> bool {
        std::mem::take(&mut self.line_too_long)
    }

    fn push_byte(&mut self, b: u8) {
        loop {
            match self.state {
                State::Resync => {
                    if b == b'\r' {
                        self.state = State::ResyncCr;
                    }
                    return;
                }
                State::ResyncCr => {
                    if b == b'\n' {
                        self.state = State::Verb;
                    } else if b != b'\r' {
                        self.state = State::Resync;
                    }
                    return;
                }
                State::Cr => {
                    if b == b'\n' {
                        self.finish_command();
                        self.state = State::Verb;
                        return;
                    }
                    // Literal CR, not a terminator — keep it as content and
                    // re-dispatch this byte under the token that was active.
                    self.push_content(b'\r');
                    self.state = if self.have_arg { State::Arg } else { State::Verb };
                    continue;
                }
                State::Verb => {
                    if b == b'\r' {
                        self.state = State::Cr;
                    } else if b == b' ' {
                        self.have_arg = true;
                        self.state = State::Arg;
                    } else {
                        self.push_content(b);
                    }
                    return;
                }
                State::Arg => {
                    if b == b'\r' {
                        self.state = State::Cr;
                    } else {
                        self.push_content(b);
                    }
                    return;
                }
                State::RawLine => {
                    if b == b'\r' {
                        self.state = State::RawLineCr;
                    } else if self.raw.len() >= self.max_line {
                        self.raw.clear();
                        self.line_too_long = true;
                        self.state = State::Resync;
                    } else {
                        self.raw.push(b);
                    }
                    return;
                }
                State::RawLineCr => {
                    if b == b'\n' {
                        self.finish_raw_line();
                        self.state = State::Verb;
                        return;
                    }
                    // Literal CR mid-line — keep it as content.
                    let byte = b'\r';
                    if self.raw.len() >= self.max_line {
                        self.raw.clear();
                        self.line_too_long = true;
                        self.state = State::Resync;
                        return;
                    }
                    self.raw.push(byte);
                    self.state = State::RawLine;
                    continue;
                }
            }
        }
    }

    fn push_content(&mut self, b: u8) {
        let buf = if self.have_arg { &mut self.arg } else { &mut self.verb };
        if buf.len() >= self.max_line {
            self.verb.clear();
            self.arg.clear();
            self.have_arg = false;
            self.line_too_long = true;
            self.state = State::Resync;
            return;
        }
        buf.push(b);
    }

    fn finish_raw_line(&mut self) {
        let line = std::mem::take(&mut self.raw);
        let cmd = if line == b"*" {
            Pop3Command::SaslAbort
        } else if line.is_empty() {
            Pop3Command::SaslResponse(Vec::new())
        } else {
            match std::str::from_utf8(&line).ok().and_then(|s| base64::decode(s).ok()) {
                Some(decoded) => Pop3Command::SaslResponse(decoded),
                None => Pop3Command::SaslResponseInvalid,
            }
        };
        self.ready.push(cmd);
    }

    fn finish_command(&mut self) {
        let verb = String::from_utf8_lossy(&self.verb).to_ascii_uppercase();
        let arg = std::mem::take(&mut self.arg);
        self.verb.clear();
        self.have_arg = false;
        if verb.is_empty() {
            // Blank line — RFC 1939 has no notion of an empty command;
            // silently ignored, matching a bare CRLF keepalive.
            return;
        }
        self.ready.push(build_command(&verb, &arg));
    }
}

fn build_command(verb: &str, arg: &[u8]) -> Pop3Command {
    let text = String::from_utf8_lossy(arg).into_owned();
    let trimmed = text.trim();
    match verb {
        "USER" => Pop3Command::User(trimmed.to_string()),
        "PASS" => Pop3Command::Pass(trimmed.to_string()),
        "APOP" => match split_two(trimmed) {
            Some((name, digest)) => {
                Pop3Command::Apop { name: name.to_string(), digest: digest.to_string() }
            }
            None => Pop3Command::Malformed { verb: verb.to_string() },
        },
        "AUTH" => {
            if trimmed.is_empty() {
                return Pop3Command::AuthList;
            }
            let mut parts = trimmed.splitn(2, char::is_whitespace);
            let mechanism = parts.next().unwrap_or("").to_string();
            let ir_text = parts.next().map(str::trim).filter(|s| !s.is_empty());
            let initial_response = match ir_text {
                None => None,
                Some("=") => Some(Vec::new()),
                Some(ir) => match base64::decode(ir) {
                    Ok(b) => Some(b),
                    Err(_) => return Pop3Command::Malformed { verb: verb.to_string() },
                },
            };
            Pop3Command::Auth { mechanism, initial_response }
        }
        "STLS" => Pop3Command::Stls,
        "UTF8" => Pop3Command::Utf8,
        "CAPA" => Pop3Command::Capa,
        "NOOP" => Pop3Command::Noop,
        "QUIT" => Pop3Command::Quit,
        "STAT" => Pop3Command::Stat,
        "LIST" => Pop3Command::List(parse_optional_msg(trimmed)),
        "RETR" => match parse_msg(trimmed) {
            Some(n) => Pop3Command::Retr(n),
            None => Pop3Command::Malformed { verb: verb.to_string() },
        },
        "DELE" => match parse_msg(trimmed) {
            Some(n) => Pop3Command::Dele(n),
            None => Pop3Command::Malformed { verb: verb.to_string() },
        },
        "RSET" => Pop3Command::Rset,
        "TOP" => match split_two(trimmed) {
            Some((n, lines)) => match (n.parse::<u32>(), lines.parse::<u32>()) {
                (Ok(n), Ok(lines)) => Pop3Command::Top(n, lines),
                _ => Pop3Command::Malformed { verb: verb.to_string() },
            },
            None => Pop3Command::Malformed { verb: verb.to_string() },
        },
        "UIDL" => Pop3Command::Uidl(parse_optional_msg(trimmed)),
        _ => Pop3Command::Unknown { verb: verb.to_string() },
    }
}

/// A positive message number (`RETR`/`DELE`/`TOP`'s required argument, or
/// `LIST`/`UIDL`'s optional one).
fn parse_msg(s: &str) -> Option<u32> {
    if s.is_empty() {
        return None;
    }
    s.parse().ok().filter(|&n| n > 0)
}

/// Same shape as [`parse_msg`], named separately for call-site clarity where
/// `None` means "apply to the whole mailbox" rather than "syntax error".
fn parse_optional_msg(s: &str) -> Option<u32> {
    parse_msg(s)
}

/// Split on the first run of whitespace into exactly two non-empty tokens
/// (`APOP name digest`, `TOP msg lines`).
fn split_two(s: &str) -> Option<(&str, &str)> {
    let mut parts = s.splitn(2, char::is_whitespace);
    let first = parts.next().filter(|s| !s.is_empty())?;
    let second = parts.next().map(str::trim).filter(|s| !s.is_empty())?;
    Some((first, second))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_user_pass() {
        let mut lex = Pop3ServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"USER alice\r\nPASS secret\r\n";
        let cmds = lex.feed(&mut data);
        assert!(data.is_empty());
        assert_eq!(
            cmds,
            vec![
                Pop3Command::User("alice".into()),
                Pop3Command::Pass("secret".into()),
            ]
        );
    }

    #[test]
    fn parse_split_buffers() {
        let mut lex = Pop3ServerLexer::new(MAX_COMMAND_LINE);
        let mut a: &[u8] = b"STA";
        assert!(lex.feed(&mut a).is_empty());
        assert!(a.is_empty());
        let mut b: &[u8] = b"T\r\n";
        let cmds = lex.feed(&mut b);
        assert!(b.is_empty());
        assert_eq!(cmds, vec![Pop3Command::Stat]);
    }

    #[test]
    fn parse_apop() {
        let mut lex = Pop3ServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"APOP user deadbeefcafe\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(
            cmds,
            vec![Pop3Command::Apop { name: "user".into(), digest: "deadbeefcafe".into() }]
        );
    }

    #[test]
    fn apop_missing_digest_is_malformed() {
        let mut lex = Pop3ServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"APOP user\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(cmds, vec![Pop3Command::Malformed { verb: "APOP".into() }]);
    }

    #[test]
    fn retr_dele_top() {
        let mut lex = Pop3ServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"RETR 5\r\nDELE 3\r\nTOP 2 10\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(
            cmds,
            vec![Pop3Command::Retr(5), Pop3Command::Dele(3), Pop3Command::Top(2, 10)]
        );
    }

    #[test]
    fn retr_missing_arg_is_malformed() {
        let mut lex = Pop3ServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"RETR\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(cmds, vec![Pop3Command::Malformed { verb: "RETR".into() }]);
    }

    #[test]
    fn retr_non_numeric_is_malformed() {
        let mut lex = Pop3ServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"RETR abc\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(cmds, vec![Pop3Command::Malformed { verb: "RETR".into() }]);
    }

    #[test]
    fn top_one_number_is_malformed() {
        let mut lex = Pop3ServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"TOP 5\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(cmds, vec![Pop3Command::Malformed { verb: "TOP".into() }]);
    }

    #[test]
    fn list_and_uidl_optional_arg() {
        let mut lex = Pop3ServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"LIST\r\nLIST 3\r\nUIDL\r\nUIDL 7\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(
            cmds,
            vec![
                Pop3Command::List(None),
                Pop3Command::List(Some(3)),
                Pop3Command::Uidl(None),
                Pop3Command::Uidl(Some(7)),
            ]
        );
    }

    #[test]
    fn list_garbled_arg_treated_as_none() {
        // Matches historical leniency: an optional numeric arg that fails
        // to parse is treated the same as no arg at all, not an error.
        let mut lex = Pop3ServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"LIST garbage\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(cmds, vec![Pop3Command::List(None)]);
    }

    #[test]
    fn no_arg_commands() {
        let mut lex = Pop3ServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"STAT\r\nRSET\r\nNOOP\r\nQUIT\r\nCAPA\r\nSTLS\r\nUTF8\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(
            cmds,
            vec![
                Pop3Command::Stat,
                Pop3Command::Rset,
                Pop3Command::Noop,
                Pop3Command::Quit,
                Pop3Command::Capa,
                Pop3Command::Stls,
                Pop3Command::Utf8,
            ]
        );
    }

    #[test]
    fn auth_list_and_mechanism_with_initial_response() {
        let mut lex = Pop3ServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"AUTH\r\n";
        assert_eq!(lex.feed(&mut data), vec![Pop3Command::AuthList]);

        let mut lex2 = Pop3ServerLexer::new(MAX_COMMAND_LINE);
        // base64("hello") == "aGVsbG8="
        let mut data2: &[u8] = b"AUTH PLAIN aGVsbG8=\r\n";
        assert_eq!(
            lex2.feed(&mut data2),
            vec![Pop3Command::Auth {
                mechanism: "PLAIN".into(),
                initial_response: Some(b"hello".to_vec()),
            }]
        );
    }

    #[test]
    fn auth_bare_equals_is_empty_initial_response() {
        let mut lex = Pop3ServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"AUTH PLAIN =\r\n";
        assert_eq!(
            lex.feed(&mut data),
            vec![Pop3Command::Auth { mechanism: "PLAIN".into(), initial_response: Some(vec![]) }]
        );
    }

    #[test]
    fn auth_bad_base64_initial_response_is_malformed() {
        let mut lex = Pop3ServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"AUTH PLAIN not-base64!!\r\n";
        assert_eq!(lex.feed(&mut data), vec![Pop3Command::Malformed { verb: "AUTH".into() }]);
    }

    #[test]
    fn sasl_response_round_trip() {
        let mut lex = Pop3ServerLexer::new(MAX_COMMAND_LINE);
        lex.expect_sasl_response();
        // base64("world") == "d29ybGQ="
        let mut data: &[u8] = b"d29ybGQ=\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(cmds, vec![Pop3Command::SaslResponse(b"world".to_vec())]);
        // Lexer reverts to normal command parsing after one raw line.
        let mut data2: &[u8] = b"NOOP\r\n";
        assert_eq!(lex.feed(&mut data2), vec![Pop3Command::Noop]);
    }

    #[test]
    fn sasl_response_split_across_feeds() {
        let mut lex = Pop3ServerLexer::new(MAX_COMMAND_LINE);
        lex.expect_sasl_response();
        let mut a: &[u8] = b"d29y";
        assert!(lex.feed(&mut a).is_empty());
        let mut b: &[u8] = b"bGQ=\r\n";
        assert_eq!(lex.feed(&mut b), vec![Pop3Command::SaslResponse(b"world".to_vec())]);
    }

    #[test]
    fn sasl_abort_and_empty_response() {
        let mut lex = Pop3ServerLexer::new(MAX_COMMAND_LINE);
        lex.expect_sasl_response();
        let mut data: &[u8] = b"*\r\n";
        assert_eq!(lex.feed(&mut data), vec![Pop3Command::SaslAbort]);

        let mut lex2 = Pop3ServerLexer::new(MAX_COMMAND_LINE);
        lex2.expect_sasl_response();
        let mut data2: &[u8] = b"\r\n";
        assert_eq!(lex2.feed(&mut data2), vec![Pop3Command::SaslResponse(Vec::new())]);
    }

    #[test]
    fn sasl_response_bad_base64() {
        let mut lex = Pop3ServerLexer::new(MAX_COMMAND_LINE);
        lex.expect_sasl_response();
        let mut data: &[u8] = b"not valid base64!!\r\n";
        assert_eq!(lex.feed(&mut data), vec![Pop3Command::SaslResponseInvalid]);
    }

    #[test]
    fn pipelined_commands() {
        let mut lex = Pop3ServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"STAT\r\nLIST\r\nNOOP\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(cmds, vec![Pop3Command::Stat, Pop3Command::List(None), Pop3Command::Noop]);
    }

    #[test]
    fn blank_line_produces_no_command() {
        let mut lex = Pop3ServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"\r\nSTAT\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(cmds, vec![Pop3Command::Stat]);
    }

    #[test]
    fn unknown_verb() {
        let mut lex = Pop3ServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"FROBNICATE arg\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(cmds, vec![Pop3Command::Unknown { verb: "FROBNICATE".into() }]);
    }

    #[test]
    fn oversized_token_discards_and_resyncs() {
        let mut lex = Pop3ServerLexer::new(4);
        let mut data: &[u8] = b"TOOLONG arg\r\nNOOP\r\n";
        let cmds = lex.feed(&mut data);
        assert!(lex.took_line_too_long());
        // Only the well-formed line after the overflow survives.
        assert_eq!(cmds, vec![Pop3Command::Noop]);
    }

    #[test]
    fn literal_cr_not_followed_by_lf_is_content() {
        let mut lex = Pop3ServerLexer::new(MAX_COMMAND_LINE);
        // A bare CR mid-argument is not a terminator; only CRLF is.
        let mut data: &[u8] = b"PASS a\rb\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(cmds, vec![Pop3Command::Pass("a\rb".into())]);
    }

    /// One byte per `feed()` call must produce identical commands to a
    /// single bulk feed, and never leave anything unconsumed.
    #[test]
    fn one_byte_at_a_time_matches_bulk_feed() {
        let msg: &[u8] = b"USER alice\r\nPASS secret\r\nQUIT\r\n";

        let mut bulk = Pop3ServerLexer::new(MAX_COMMAND_LINE);
        let mut bulk_data = msg;
        let bulk_cmds = bulk.feed(&mut bulk_data);

        let mut drip = Pop3ServerLexer::new(MAX_COMMAND_LINE);
        let mut drip_cmds = Vec::new();
        for &b in msg {
            let mut one: &[u8] = &[b];
            drip_cmds.extend(drip.feed(&mut one));
            assert!(one.is_empty());
        }

        assert_eq!(bulk_cmds, drip_cmds);
        assert_eq!(bulk_cmds.len(), 3);
    }

    /// Every split point of a full command stream must be equivalent.
    #[test]
    fn all_split_points_are_equivalent() {
        let msg: &[u8] = b"USER alice\r\nPASS s3cret\r\nSTAT\r\nQUIT\r\n";
        let mut base = Pop3ServerLexer::new(MAX_COMMAND_LINE);
        let mut base_data = msg;
        let base_cmds = base.feed(&mut base_data);

        for split in 1..msg.len() {
            let mut lex = Pop3ServerLexer::new(MAX_COMMAND_LINE);
            let mut a: &[u8] = &msg[..split];
            let mut cmds = lex.feed(&mut a);
            assert!(a.is_empty(), "split {split} retained bytes");
            let mut b: &[u8] = &msg[split..];
            cmds.extend(lex.feed(&mut b));
            assert!(b.is_empty(), "split {split} retained bytes");
            assert_eq!(cmds, base_cmds, "split {split} diverged");
        }
    }

    /// Every split point of the SASL continuation line itself must be
    /// equivalent, once the lexer is in `expect_sasl_response` mode —
    /// parameterizes `sasl_response_split_across_feeds` over every split
    /// point rather than just one.
    #[test]
    fn sasl_response_all_split_points_are_equivalent() {
        let line: &[u8] = b"AGFsaWNlAHNlY3JldA==\r\n"; // base64("\0alice\0secret")

        let mut base = Pop3ServerLexer::new(MAX_COMMAND_LINE);
        base.expect_sasl_response();
        let mut d = line;
        let base_cmds = base.feed(&mut d);

        for split in 1..line.len() {
            let mut lex = Pop3ServerLexer::new(MAX_COMMAND_LINE);
            lex.expect_sasl_response();
            let mut a: &[u8] = &line[..split];
            let mut cmds = lex.feed(&mut a);
            assert!(a.is_empty(), "split {split} retained bytes");
            let mut b: &[u8] = &line[split..];
            cmds.extend(lex.feed(&mut b));
            assert!(b.is_empty(), "split {split} retained bytes");
            assert_eq!(cmds, base_cmds, "split {split} diverged");
        }
    }

    /// A full realistic exchange — command line, then a mode switch, then
    /// the continuation line, each in its own `feed()` call (matching how
    /// `control.rs` actually drives the lexer: dispatch the AUTH command,
    /// send the challenge, call `expect_sasl_response`, then keep reading).
    #[test]
    fn auth_then_sasl_response_end_to_end() {
        let mut lex = Pop3ServerLexer::new(MAX_COMMAND_LINE);
        let mut cmd_data: &[u8] = b"AUTH PLAIN\r\n";
        assert_eq!(
            lex.feed(&mut cmd_data),
            vec![Pop3Command::Auth { mechanism: "PLAIN".into(), initial_response: None }]
        );
        lex.expect_sasl_response();
        let mut sasl_data: &[u8] = b"AGFsaWNlAHNlY3JldA==\r\n";
        assert_eq!(
            lex.feed(&mut sasl_data),
            vec![Pop3Command::SaslResponse(b"\0alice\0secret".to_vec())]
        );
    }
}
