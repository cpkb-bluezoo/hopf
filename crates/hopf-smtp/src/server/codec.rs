// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Incremental, semantic SMTP command parser: `KEYWORD [SP TEXT] CRLF`.
//!
//! Self-contained streaming parser: [`SmtpServerLexer::feed`] consumes every
//! byte it is given and keeps a command-in-progress in its own bounded
//! `verb`/`arg` scratch buffers — never in a buffer the caller has to retain
//! and re-supply. See `hopf_http::h1::parse` for the design this follows.
//!
//! Most verbs are built directly into a typed [`SmtpCommand`] variant here
//! (`RSET`/`QUIT`/`NOOP`/`STARTTLS`/… take no argument at all; `AUTH`'s
//! mechanism/initial-response are already split and the initial response is
//! already base64-decoded). `MAIL`/`RCPT`/`BDAT` keep their raw argument
//! text — their ESMTP-parameter grammar is already parsed by dedicated,
//! well-tested functions in `server::delivery` with rich per-field error
//! messages, and duplicating that here would only relocate complexity, not
//! reduce it.
//!
//! `AUTH`'s SASL continuation lines (bare base64, no verb) are handled by
//! the same lexer via [`SmtpServerLexer::expect_sasl_response`] — call it
//! right after sending a `334` challenge, mirroring the `expect()` pattern
//! used by the client-side reply lexers and by `hopf-pop3`'s server codec.
//! This replaces two dead/broken code paths that used to live in
//! `control.rs`: a `cmd_auth_continuation` stub that was provably
//! unreachable (its own comment said so — the *real* logic lived
//! elsewhere), and a `receive_inner` branch that scanned for a `CRLF` via
//! `data.windows(2).position(...)` — which had two bugs, not one: (1) it
//! silently dropped a continuation line's bytes with no scratch buffer to
//! resume from if the CRLF hadn't arrived yet in the current `feed()` call,
//! and (2) when a continuation line *did* arrive whole, path (1) was
//! actually correct, but the *other*, unreachable path — if it had ever
//! run — would have fed the raw base64 through the normal command lexer,
//! which uppercases whatever it treats as the "verb", corrupting
//! case-sensitive base64.

use rmimeparser::charset::base64;

/// Command-line length limit (octets), applied independently to the verb
/// and to the argument. RFC 5321 §4.5.3.1.4 sets the minimum a server must
/// accept at 512; this crate allows a larger practical margin.
pub const MAX_COMMAND_LINE: usize = 8192;

/// A fully parsed, semantic SMTP command (or a syntactically/lexically
/// invalid line, reported so the caller can reply `5xx` without erroring
/// the connection).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmtpCommand {
    /// `HELO hostname`
    Helo(String),
    /// `EHLO hostname`
    Ehlo(String),
    /// `MAIL <arg>` — raw text after `MAIL `, parsed by
    /// `server::delivery::parse_mail_from_arg`.
    Mail(String),
    /// `RCPT <arg>` — raw text after `RCPT `, parsed by
    /// `server::delivery::parse_rcpt_to_arg`.
    Rcpt(String),
    /// `DATA`
    Data,
    /// `BDAT size [LAST]` — raw text after `BDAT `.
    Bdat(String),
    /// `RSET`
    Rset,
    /// `QUIT`
    Quit,
    /// `NOOP`
    Noop,
    /// `HELP`
    Help,
    /// `VRFY` (argument intentionally ignored — RFC 5321 §3.5.1 permits a
    /// canned response to avoid user enumeration).
    Vrfy,
    /// `EXPN` (not implemented; argument ignored).
    Expn,
    /// `ETRN` (argument ignored — only whether EHLO was used matters).
    Etrn,
    /// `STARTTLS`
    Starttls,
    /// `AUTH mechanism [initial-response]` (RFC 4954).
    Auth {
        /// SASL mechanism name, as sent (not yet uppercased).
        mechanism: String,
        /// Already base64-decoded initial response, if present. `Some("=")`
        /// on the wire (an explicit empty response) decodes to `Some(vec![])`.
        initial_response: Option<Vec<u8>>,
    },
    /// A bare-line SASL continuation response, already base64-decoded (see
    /// [`SmtpServerLexer::expect_sasl_response`]).
    SaslResponse(Vec<u8>),
    /// A bare-line SASL continuation that failed to base64-decode.
    SaslResponseInvalid,
    /// A bare `*` SASL continuation line — client cancels the exchange.
    SaslAbort,
    /// `XCLIENT attr=value …` (Postfix extension; ACL-gated).
    Xclient(String),
    /// A recognised verb whose argument didn't match its expected shape
    /// (currently only `AUTH` with unparseable base64).
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

/// Incremental, semantic SMTP command-line parser. See the module docs.
pub struct SmtpServerLexer {
    max_line: usize,
    state: State,
    verb: Vec<u8>,
    arg: Vec<u8>,
    have_arg: bool,
    raw: Vec<u8>,
    ready: Vec<SmtpCommand>,
}

impl SmtpServerLexer {
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
        }
    }

    /// Tell the lexer the next line is a bare SASL continuation response
    /// (RFC 4954 §4), not a command. Call this right after sending a `334`
    /// challenge reply. The lexer reverts to normal command parsing as
    /// soon as that one line completes.
    pub fn expect_sasl_response(&mut self) {
        self.state = State::RawLine;
        self.raw.clear();
    }

    /// Feed inbound control bytes; returns newly completed commands.
    ///
    /// Consumes everything given — `*data` is always left empty. A line
    /// whose verb or argument exceeds the cap is silently discarded (no
    /// command produced), matching the prior lexer's behavior.
    pub fn feed(&mut self, data: &mut &[u8]) -> Vec<SmtpCommand> {
        for &b in data.iter() {
            self.push_byte(b);
        }
        *data = &[];
        std::mem::take(&mut self.ready)
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
                    if self.raw.len() >= self.max_line {
                        self.raw.clear();
                        self.state = State::Resync;
                        return;
                    }
                    self.raw.push(b'\r');
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
            self.state = State::Resync;
            return;
        }
        buf.push(b);
    }

    fn finish_raw_line(&mut self) {
        let line = std::mem::take(&mut self.raw);
        let cmd = if line == b"*" {
            SmtpCommand::SaslAbort
        } else if line.is_empty() {
            SmtpCommand::SaslResponse(Vec::new())
        } else {
            match std::str::from_utf8(&line).ok().and_then(|s| base64::decode(s).ok()) {
                Some(decoded) => SmtpCommand::SaslResponse(decoded),
                None => SmtpCommand::SaslResponseInvalid,
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
            return;
        }
        self.ready.push(build_command(&verb, &arg));
    }
}

fn build_command(verb: &str, arg: &[u8]) -> SmtpCommand {
    let text = String::from_utf8_lossy(arg).into_owned();
    let trimmed = text.trim();
    match verb {
        "HELO" => SmtpCommand::Helo(trimmed.to_string()),
        "EHLO" => SmtpCommand::Ehlo(trimmed.to_string()),
        "MAIL" => SmtpCommand::Mail(text),
        "RCPT" => SmtpCommand::Rcpt(text),
        "DATA" => SmtpCommand::Data,
        "BDAT" => SmtpCommand::Bdat(trimmed.to_string()),
        "RSET" => SmtpCommand::Rset,
        "QUIT" => SmtpCommand::Quit,
        "NOOP" => SmtpCommand::Noop,
        "HELP" => SmtpCommand::Help,
        "VRFY" => SmtpCommand::Vrfy,
        "EXPN" => SmtpCommand::Expn,
        "ETRN" => SmtpCommand::Etrn,
        "STARTTLS" => SmtpCommand::Starttls,
        "XCLIENT" => SmtpCommand::Xclient(trimmed.to_string()),
        "AUTH" => {
            let mut parts = trimmed.splitn(2, char::is_whitespace);
            let mechanism = parts.next().unwrap_or("").to_string();
            let ir_text = parts.next().map(str::trim).filter(|s| !s.is_empty());
            let initial_response = match ir_text {
                None => None,
                Some("=") => Some(Vec::new()),
                Some(ir) => match base64::decode(ir) {
                    Ok(b) => Some(b),
                    Err(_) => return SmtpCommand::Malformed { verb: verb.to_string() },
                },
            };
            SmtpCommand::Auth { mechanism, initial_response }
        }
        _ => SmtpCommand::Unknown { verb: verb.to_string() },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mail_from() {
        let mut lex = SmtpServerLexer::new(4096);
        let mut data: &[u8] = b"MAIL FROM:<a@b.com>\r\n";
        let cmds = lex.feed(&mut data);
        assert!(data.is_empty());
        assert_eq!(cmds, vec![SmtpCommand::Mail("FROM:<a@b.com>".into())]);
    }

    #[test]
    fn parse_noop() {
        let mut lex = SmtpServerLexer::new(4096);
        let mut data: &[u8] = b"NOOP\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(cmds, vec![SmtpCommand::Noop]);
    }

    #[test]
    fn parse_split_buffers() {
        let mut lex = SmtpServerLexer::new(4096);
        let mut a: &[u8] = b"EHL";
        assert!(lex.feed(&mut a).is_empty());
        assert!(a.is_empty());
        let mut b: &[u8] = b"O client.example\r\n";
        let cmds = lex.feed(&mut b);
        assert!(b.is_empty());
        assert_eq!(cmds, vec![SmtpCommand::Ehlo("client.example".into())]);
    }

    #[test]
    fn pipelined_commands() {
        let mut lex = SmtpServerLexer::new(4096);
        let mut data: &[u8] = b"MAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\nDATA\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(
            cmds,
            vec![
                SmtpCommand::Mail("FROM:<a@b>".into()),
                SmtpCommand::Rcpt("TO:<c@d>".into()),
                SmtpCommand::Data,
            ]
        );
    }

    #[test]
    fn no_arg_commands() {
        let mut lex = SmtpServerLexer::new(4096);
        let mut data: &[u8] =
            b"RSET\r\nQUIT\r\nNOOP\r\nHELP\r\nVRFY\r\nEXPN\r\nETRN\r\nSTARTTLS\r\nXCLIENT\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(
            cmds,
            vec![
                SmtpCommand::Rset,
                SmtpCommand::Quit,
                SmtpCommand::Noop,
                SmtpCommand::Help,
                SmtpCommand::Vrfy,
                SmtpCommand::Expn,
                SmtpCommand::Etrn,
                SmtpCommand::Starttls,
                SmtpCommand::Xclient(String::new()),
            ]
        );
    }

    #[test]
    fn parse_xclient_keeps_args() {
        let mut lex = SmtpServerLexer::new(4096);
        let mut data: &[u8] = b"XCLIENT NAME=a.example ADDR=1.2.3.4\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(
            cmds,
            vec![SmtpCommand::Xclient("NAME=a.example ADDR=1.2.3.4".into())]
        );
    }

    #[test]
    fn bdat_size_and_last() {
        let mut lex = SmtpServerLexer::new(4096);
        let mut data: &[u8] = b"BDAT 100\r\nBDAT 0 LAST\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(cmds, vec![SmtpCommand::Bdat("100".into()), SmtpCommand::Bdat("0 LAST".into())]);
    }

    #[test]
    fn auth_mechanism_with_initial_response() {
        let mut lex = SmtpServerLexer::new(4096);
        // base64("hello") == "aGVsbG8="
        let mut data: &[u8] = b"AUTH PLAIN aGVsbG8=\r\n";
        assert_eq!(
            lex.feed(&mut data),
            vec![SmtpCommand::Auth {
                mechanism: "PLAIN".into(),
                initial_response: Some(b"hello".to_vec()),
            }]
        );
    }

    #[test]
    fn auth_no_initial_response() {
        let mut lex = SmtpServerLexer::new(4096);
        let mut data: &[u8] = b"AUTH PLAIN\r\n";
        assert_eq!(
            lex.feed(&mut data),
            vec![SmtpCommand::Auth { mechanism: "PLAIN".into(), initial_response: None }]
        );
    }

    #[test]
    fn auth_bare_equals_is_empty_initial_response() {
        let mut lex = SmtpServerLexer::new(4096);
        let mut data: &[u8] = b"AUTH PLAIN =\r\n";
        assert_eq!(
            lex.feed(&mut data),
            vec![SmtpCommand::Auth { mechanism: "PLAIN".into(), initial_response: Some(vec![]) }]
        );
    }

    #[test]
    fn auth_bad_base64_initial_response_is_malformed() {
        let mut lex = SmtpServerLexer::new(4096);
        let mut data: &[u8] = b"AUTH PLAIN not-base64!!\r\n";
        assert_eq!(lex.feed(&mut data), vec![SmtpCommand::Malformed { verb: "AUTH".into() }]);
    }

    #[test]
    fn sasl_response_round_trip() {
        let mut lex = SmtpServerLexer::new(4096);
        lex.expect_sasl_response();
        // base64("world") == "d29ybGQ="
        let mut data: &[u8] = b"d29ybGQ=\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(cmds, vec![SmtpCommand::SaslResponse(b"world".to_vec())]);
        // Lexer reverts to normal command parsing after one raw line.
        let mut data2: &[u8] = b"NOOP\r\n";
        assert_eq!(lex.feed(&mut data2), vec![SmtpCommand::Noop]);
    }

    #[test]
    fn sasl_response_split_across_feeds() {
        let mut lex = SmtpServerLexer::new(4096);
        lex.expect_sasl_response();
        let mut a: &[u8] = b"d29y";
        assert!(lex.feed(&mut a).is_empty());
        let mut b: &[u8] = b"bGQ=\r\n";
        assert_eq!(lex.feed(&mut b), vec![SmtpCommand::SaslResponse(b"world".to_vec())]);
    }

    #[test]
    fn sasl_abort_and_empty_response() {
        let mut lex = SmtpServerLexer::new(4096);
        lex.expect_sasl_response();
        let mut data: &[u8] = b"*\r\n";
        assert_eq!(lex.feed(&mut data), vec![SmtpCommand::SaslAbort]);

        let mut lex2 = SmtpServerLexer::new(4096);
        lex2.expect_sasl_response();
        let mut data2: &[u8] = b"\r\n";
        assert_eq!(lex2.feed(&mut data2), vec![SmtpCommand::SaslResponse(Vec::new())]);
    }

    #[test]
    fn sasl_response_bad_base64() {
        let mut lex = SmtpServerLexer::new(4096);
        lex.expect_sasl_response();
        let mut data: &[u8] = b"not valid base64!!\r\n";
        assert_eq!(lex.feed(&mut data), vec![SmtpCommand::SaslResponseInvalid]);
    }

    #[test]
    fn sasl_response_all_split_points_are_equivalent() {
        let line: &[u8] = b"AGFsaWNlAHNlY3JldA==\r\n"; // base64("\0alice\0secret")

        let mut base = SmtpServerLexer::new(4096);
        base.expect_sasl_response();
        let mut d = line;
        let base_cmds = base.feed(&mut d);

        for split in 1..line.len() {
            let mut lex = SmtpServerLexer::new(4096);
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

    #[test]
    fn auth_then_sasl_response_end_to_end() {
        let mut lex = SmtpServerLexer::new(4096);
        let mut cmd_data: &[u8] = b"AUTH PLAIN\r\n";
        assert_eq!(
            lex.feed(&mut cmd_data),
            vec![SmtpCommand::Auth { mechanism: "PLAIN".into(), initial_response: None }]
        );
        lex.expect_sasl_response();
        let mut sasl_data: &[u8] = b"AGFsaWNlAHNlY3JldA==\r\n";
        assert_eq!(
            lex.feed(&mut sasl_data),
            vec![SmtpCommand::SaslResponse(b"\0alice\0secret".to_vec())]
        );
    }

    #[test]
    fn unknown_verb() {
        let mut lex = SmtpServerLexer::new(4096);
        let mut data: &[u8] = b"FROBNICATE arg\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(cmds, vec![SmtpCommand::Unknown { verb: "FROBNICATE".into() }]);
    }

    #[test]
    fn oversized_token_discards_and_resyncs() {
        let mut lex = SmtpServerLexer::new(4);
        let mut data: &[u8] = b"TOOLONG arg\r\nNOOP\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(cmds, vec![SmtpCommand::Noop]);
    }

    #[test]
    fn literal_cr_not_followed_by_lf_is_content() {
        let mut lex = SmtpServerLexer::new(4096);
        let mut data: &[u8] = b"RCPT a\rb\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(cmds, vec![SmtpCommand::Rcpt("a\rb".into())]);
    }

    /// One byte per `feed()` call must produce identical commands to a
    /// single bulk feed, and never leave anything unconsumed.
    #[test]
    fn one_byte_at_a_time_matches_bulk_feed() {
        let msg: &[u8] = b"MAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\nQUIT\r\n";

        let mut bulk = SmtpServerLexer::new(4096);
        let mut bulk_data = msg;
        let bulk_cmds = bulk.feed(&mut bulk_data);

        let mut drip = SmtpServerLexer::new(4096);
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
        let msg: &[u8] = b"MAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\nDATA\r\nQUIT\r\n";
        let mut base = SmtpServerLexer::new(4096);
        let mut base_data = msg;
        let base_cmds = base.feed(&mut base_data);

        for split in 1..msg.len() {
            let mut lex = SmtpServerLexer::new(4096);
            let mut a: &[u8] = &msg[..split];
            let mut cmds = lex.feed(&mut a);
            assert!(a.is_empty(), "split {split} retained bytes");
            let mut b: &[u8] = &msg[split..];
            cmds.extend(lex.feed(&mut b));
            assert!(b.is_empty(), "split {split} retained bytes");
            assert_eq!(cmds, base_cmds, "split {split} diverged");
        }
    }
}
