// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Incremental IMAP server command tokenizer (tag, verb, argument tokens,
//! literals).
//!
//! Self-contained streaming lexer: [`ImapServerLexer::feed`] consumes every
//! byte it is given. The tag is read as it arrives, then the verb, then each
//! argument as a typed token - an atom, a quoted string (unescaped), a
//! literal, or a parenthesis - the moment it is complete. The line is never
//! accumulated as text to be searched again afterwards.
//!
//! A literal (`{n}` / `{n+}`, CRLF, `n` raw octets) may stand wherever a
//! string may, and is *one token* however many spaces or quotes its octets
//! contain: it is not spliced into the line as text, so its contents can
//! never change how the rest of the line is read. Its octets are copied in
//! bulk slices as they arrive (never byte-by-byte). The message literal of an
//! `APPEND` is not collected at all: it is delivered as it arrives, as
//! [`LexEvent::AppendChunk`]s.
//!
//! An [`ImapCommand`] carries the tokens; `args` is the same arguments
//! rendered canonically as text (quoted and escaped), for the command
//! handlers that have not yet been moved to read tokens.

use hopf_mailbox::{Flag, MessageSet};

use crate::server::grammar::{grammar_for, Grammar, Reject, Request};
use crate::server::handler::StoreAction;

/// Default max command-line length (octets), matching common IMAP practice.
pub const MAX_COMMAND_LINE: usize = 8192;

/// Maximum synchronizing / non-synchronizing literal size accepted (32 MiB).
pub const MAX_LITERAL_SIZE: u64 = 32 * 1024 * 1024;

/// LITERAL- non-synchronizing literal cap (RFC 7888).
pub const LITERAL_MINUS_LIMIT: u64 = 4096;

/// One argument token of a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgToken {
    /// A word written bare: `INBOX`, `1:*`, `\Seen`, `NIL`, or a fetch item
    /// with its section and partial, `BODY[HEADER.FIELDS (From To)]<0.100>`.
    Atom(String),
    /// A quoted string, with its escapes removed.
    Quoted(String),
    /// A literal's octets.
    Literal(Vec<u8>),
    /// `(`
    Open,
    /// `)`
    Close,
}

/// A completed IMAP command ready for dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImapCommand {
    /// Client tag.
    pub tag: String,
    /// Uppercased command verb.
    pub verb: String,
    /// The arguments, as the lexer tokenized them.
    pub tokens: Vec<ArgToken>,
    /// The same arguments rendered as text: see [`render_args`].
    pub args: String,
    /// The command with its arguments read, for a verb whose grammar the
    /// lexer already runs (see `server::grammar`); then `tokens` and `args`
    /// are empty.
    pub request: Option<Request>,
}

impl ImapCommand {
    /// A command from its tokens.
    pub fn new(tag: impl Into<String>, verb: impl Into<String>, tokens: Vec<ArgToken>) -> Self {
        let args = render_args(&tokens);
        Self { tag: tag.into(), verb: verb.into(), tokens, args, request: None }
    }

    /// A command whose arguments the lexer has read.
    pub fn typed(tag: impl Into<String>, verb: impl Into<String>, request: Request) -> Self {
        Self { tag: tag.into(), verb: verb.into(), tokens: Vec::new(), args: String::new(), request: Some(request) }
    }

    /// The command that the first argument of this one names, with the rest
    /// as its arguments (`UID FETCH ...` is a `FETCH`).
    pub fn sub_command(&self) -> Option<ImapCommand> {
        let (ArgToken::Atom(verb), rest) = self.tokens.split_first()? else {
            return None;
        };
        Some(ImapCommand::new(self.tag.clone(), verb.to_ascii_uppercase(), rest.to_vec()))
    }
}

/// The arguments as text for the handlers that read text: atoms as they are,
/// quoted strings quoted and escaped, a literal bare if it is a plain word
/// and quoted otherwise, a list's parentheses without spaces inside them.
pub fn render_args(tokens: &[ArgToken]) -> String {
    let mut out = String::new();
    let mut after_open = true;
    for token in tokens {
        match token {
            ArgToken::Close => {
                out.push(')');
                after_open = false;
                continue;
            }
            _ if !after_open => out.push(' '),
            _ => {}
        }
        after_open = false;
        match token {
            ArgToken::Atom(a) => out.push_str(a),
            ArgToken::Quoted(q) => push_quoted(&mut out, q),
            ArgToken::Literal(bytes) => {
                let text = String::from_utf8_lossy(bytes);
                if !text.is_empty() && text.bytes().all(|b| b.is_ascii_graphic() && !b"(){\"\\%*]".contains(&b)) {
                    out.push_str(&text);
                } else {
                    push_quoted(&mut out, &text);
                }
            }
            ArgToken::Open => {
                out.push('(');
                after_open = true;
            }
            ArgToken::Close => unreachable!("handled above"),
        }
    }
    out
}

fn push_quoted(out: &mut String, text: &str) {
    out.push('"');
    for c in text.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
}

/// Events produced while feeding the lexer (commands and sync-literal prompts).
#[derive(Debug)]
pub enum LexEvent {
    /// A complete command (literals incorporated).
    Command(ImapCommand),
    /// Synchronizing literal — send `+` then continue feeding.
    NeedContinuation,
    /// A raw line received while [`ImapServerLexer::expect_sasl_response`] is
    /// in effect (a SASL continuation response to `AUTHENTICATE`). Bytes are
    /// exactly the line's content, minus the CRLF terminator — undecoded,
    /// since interpretation (base64, `*` abort) is mechanism-specific.
    SaslLine(Vec<u8>),
    /// One chunk of an in-progress APPEND literal's raw octets, delivered as
    /// soon as it's readable off the wire — the lexer never buffers an
    /// APPEND literal whole; the caller decides what to do with each chunk
    /// (e.g. spool it to a temp file) as it arrives. The literal is complete
    /// once the following [`LexEvent::Command`] arrives.
    AppendChunk(Vec<u8>),
    /// Protocol error (line too long, bad literal, …).
    Error {
        /// Tag if known, else `"*"`.
        tag: String,
        /// Human-readable reason.
        message: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LiteralPhase {
    None,
    /// Waiting for raw bytes of a general-purpose (arg) literal.
    General {
        remaining: u64,
    },
    /// Waiting for APPEND message-body literal.
    Append {
        remaining: u64,
    },
    /// A literal the grammar refused, which the client sends anyway (a
    /// non-synchronizing one): its octets are skipped.
    Skip {
        remaining: u64,
    },
}

/// How the end of a line being skipped reads: whether it is a literal the
/// client will send whatever was said of the command (`{n+}`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SkipSpec {
    /// Not (yet) the start of one.
    None,
    /// `{`
    Open,
    /// `{` and the digits so far.
    Digits(u64),
    /// `{n+`
    Plus(u64),
    /// `{n+}`: a literal of `n` octets if the line ends here.
    Close(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Reading the tag, up to SP or CR.
    Tag,
    /// Between the tokens of the verb and arguments.
    Between,
    /// Inside a bare word.
    Atom,
    /// Inside a quoted string.
    Quoted,
    /// Inside a quoted string, after a backslash.
    QuotedEscape,
    /// Inside a quoted string, after a CR.
    QuotedCr,
    /// Reading `{n}` or `{n+}`.
    LiteralSpec,
    /// After `}`: the CR of the line the octets follow.
    LiteralCr,
    /// After that CR: the LF.
    LiteralLf,
    /// Saw CR; a following LF ends the line. Any other byte means the CR was
    /// content of the token that was being read.
    Cr,
    /// Streaming a literal's raw octets (`LiteralPhase` says which).
    Literal,
    /// An error: discard bytes up to the next CRLF (no command is produced
    /// for the discarded line), then resume normally.
    Resync,
    /// Saw CR while resyncing; a following LF ends the discarded line.
    ResyncCr,
    /// Accumulating a raw SASL continuation line (see
    /// [`ImapServerLexer::expect_sasl_response`]), up to CR.
    RawLine,
    /// Saw CR while accumulating a raw line; a following LF completes it.
    RawLineCr,
}

/// Incremental IMAP command lexer with literal support.
pub struct ImapServerLexer {
    max_line: usize,
    state: State,
    /// The state a CR was seen in, to carry on in if no LF follows.
    cr_from: State,
    tag: Vec<u8>,
    /// The verb, once read.
    verb: Option<String>,
    /// The arguments so far, for a verb with no grammar yet.
    tokens: Vec<ArgToken>,
    /// The machine reading the arguments of this verb, if it has one.
    grammar: Option<Box<dyn Grammar>>,
    /// The verb is `UID`: the next token names the command it is for.
    uid_pending: bool,
    /// The line's CRLF has been read, so a refusal has nothing left to skip.
    line_ended: bool,
    /// The end of the line being skipped (`Resync`), as far as it is read.
    skip_spec: SkipSpec,
    /// The atom or quoted string being read.
    word: Vec<u8>,
    /// Unclosed `[` in the atom being read: inside brackets, white space and
    /// parentheses are part of the atom (`BODY[HEADER.FIELDS (From To)]`).
    brackets: u32,
    /// The literal being announced: its size so far, digits, and `+`.
    literal_size: u64,
    literal_digits: u32,
    literal_plus: bool,
    /// Bytes of the line read so far since the tag or the last literal, for
    /// the `max_line` cap.
    typed_bytes: usize,
    /// Octets of literals taken into this command, for their total cap.
    literal_total: u64,
    literal: LiteralPhase,
    literal_buf: Vec<u8>,
    /// Scratch buffer for a SASL continuation line (see `State::RawLine`).
    raw: Vec<u8>,
    ready: Vec<LexEvent>,
}

impl ImapServerLexer {
    /// Create with a max command-line length.
    pub fn new(max_line: usize) -> Self {
        Self {
            max_line,
            state: State::Tag,
            cr_from: State::Tag,
            tag: Vec::new(),
            verb: None,
            tokens: Vec::new(),
            grammar: None,
            uid_pending: false,
            line_ended: false,
            word: Vec::new(),
            brackets: 0,
            skip_spec: SkipSpec::None,
            literal_size: 0,
            literal_digits: 0,
            literal_plus: false,
            typed_bytes: 0,
            literal_total: 0,
            literal: LiteralPhase::None,
            literal_buf: Vec::new(),
            raw: Vec::new(),
            ready: Vec::new(),
        }
    }

    /// Switch to raw-line mode for one SASL continuation response: the next
    /// complete line fed in is delivered verbatim as [`LexEvent::SaslLine`]
    /// instead of being parsed as a tagged command. Resumable across `feed`
    /// calls like everything else here - the partial line lives in `self.raw`,
    /// never in a buffer the caller must retain.
    pub fn expect_sasl_response(&mut self) {
        self.state = State::RawLine;
        self.raw.clear();
    }

    /// Feed inbound bytes; returns newly completed lex events (commands,
    /// continuations, errors). Consumes everything given - `*data` is
    /// always left empty.
    pub fn feed(&mut self, data: &mut &[u8]) -> Vec<LexEvent> {
        while !data.is_empty() {
            if self.state == State::Literal {
                self.feed_literal(data);
            } else {
                let b = data[0];
                *data = &data[1..];
                self.push_byte(b);
            }
        }
        std::mem::take(&mut self.ready)
    }

    /// Whether currently reading a literal.
    pub fn in_literal(&self) -> bool {
        !matches!(self.literal, LiteralPhase::None)
    }

    /// Consume as much of a literal's raw octets from `data` as are
    /// available, in one bulk slice - never byte-by-byte.
    fn feed_literal(&mut self, data: &mut &[u8]) {
        let remaining = match self.literal {
            LiteralPhase::General { remaining } => remaining,
            LiteralPhase::Append { remaining } => remaining,
            LiteralPhase::Skip { remaining } => remaining,
            LiteralPhase::None => unreachable!("feed_literal only called in State::Literal"),
        };
        let take = (remaining as usize).min(data.len());
        let (chunk, rest_data) = data.split_at(take);
        *data = rest_data;
        match &mut self.literal {
            LiteralPhase::General { remaining } => {
                self.literal_buf.extend_from_slice(chunk);
                *remaining -= take as u64;
                if *remaining == 0 {
                    let octets = std::mem::take(&mut self.literal_buf);
                    self.literal = LiteralPhase::None;
                    // (The line goes on after a literal.)
                    self.state = State::Between;
                    self.push_token(ArgToken::Literal(octets));
                }
            }
            LiteralPhase::Skip { remaining } => {
                *remaining -= take as u64;
                if *remaining == 0 {
                    self.literal = LiteralPhase::None;
                    // The line goes on after the literal, and is skipped too.
                    self.resync();
                }
            }
            LiteralPhase::Append { remaining } => {
                *remaining -= take as u64;
                let done = *remaining == 0;
                // Emitted even when empty on completion (a valid `{0}`
                // literal) - the control layer uses this to tell "a
                // zero-length literal was provided" apart from "no literal
                // was provided at all", which it can't distinguish from
                // silence alone.
                if !chunk.is_empty() || done {
                    self.ready.push(LexEvent::AppendChunk(chunk.to_vec()));
                }
                if done {
                    self.literal = LiteralPhase::None;
                    self.finish_command();
                    self.state = State::Tag;
                }
            }
            LiteralPhase::None => unreachable!(),
        }
    }

    fn push_byte(&mut self, b: u8) {
        // The cap is on what the client typed of the line, not on literal
        // octets, and not on the line ending or the raw SASL line (which has
        // its own).
        if !matches!(
            self.state,
            State::Resync | State::ResyncCr | State::RawLine | State::RawLineCr | State::Cr | State::LiteralLf
        ) && b != b'\r'
        {
            self.typed_bytes += 1;
            if self.typed_bytes > self.max_line {
                self.fail("Line too long");
                return;
            }
        }
        loop {
            match self.state {
                State::Resync => {
                    if b == b'\r' {
                        self.state = State::ResyncCr;
                    } else {
                        self.skip_spec = match (self.skip_spec, b) {
                            (_, b'{') => SkipSpec::Open,
                            (SkipSpec::Open, b'0'..=b'9') => SkipSpec::Digits(u64::from(b - b'0')),
                            (SkipSpec::Digits(n), b'0'..=b'9') => {
                                SkipSpec::Digits(n.saturating_mul(10).saturating_add(u64::from(b - b'0')))
                            }
                            (SkipSpec::Digits(n), b'+') => SkipSpec::Plus(n),
                            (SkipSpec::Plus(n), b'}') => SkipSpec::Close(n),
                            _ => SkipSpec::None,
                        };
                    }
                    return;
                }
                State::ResyncCr => {
                    if b == b'\n' {
                        // A literal the client sends without waiting is part of
                        // this line: skip its octets, and the rest of the line.
                        match std::mem::replace(&mut self.skip_spec, SkipSpec::None) {
                            SkipSpec::Close(n) if n > 0 => {
                                self.literal = LiteralPhase::Skip { remaining: n };
                                self.state = State::Literal;
                            }
                            SkipSpec::Close(_) => self.state = State::Resync,
                            _ => self.state = State::Tag,
                        }
                    } else if b != b'\r' {
                        self.skip_spec = SkipSpec::None;
                        self.state = State::Resync;
                    }
                    return;
                }
                State::Cr => {
                    if b == b'\n' {
                        self.on_crlf();
                        return;
                    }
                    // A CR that is not the end of the line is content of what
                    // was being read: carry on with this byte as it.
                    let from = self.cr_from;
                    self.state = from;
                    match from {
                        State::Tag => self.tag.push(b'\r'),
                        State::Between => {
                            self.word.clear();
                            self.word.push(b'\r');
                            self.state = State::Atom;
                        }
                        _ => self.word.push(b'\r'),
                    }
                    continue;
                }
                State::Tag => {
                    if b == b'\r' {
                        self.cr_from = State::Tag;
                        self.state = State::Cr;
                    } else if b == b' ' {
                        self.typed_bytes = 0;
                        self.state = State::Between;
                    } else {
                        self.tag.push(b);
                    }
                    return;
                }
                State::Between => {
                    match b {
                        b' ' => {}
                        b'\r' => {
                            self.cr_from = State::Between;
                            self.state = State::Cr;
                        }
                        b'(' => self.push_token(ArgToken::Open),
                        b')' => self.push_token(ArgToken::Close),
                        b'"' => {
                            self.word.clear();
                            self.state = State::Quoted;
                        }
                        b'{' => {
                            self.literal_size = 0;
                            self.literal_digits = 0;
                            self.literal_plus = false;
                            self.state = State::LiteralSpec;
                        }
                        _ => {
                            self.word.clear();
                            self.brackets = 0;
                            self.state = State::Atom;
                            self.atom_byte(b);
                        }
                    }
                    return;
                }
                State::Atom => {
                    if self.brackets > 0 {
                        if b == b'\r' {
                            self.cr_from = State::Atom;
                            self.state = State::Cr;
                        } else {
                            self.atom_byte(b);
                        }
                        return;
                    }
                    match b {
                        b' ' => {
                            self.state = State::Between;
                            self.end_atom();
                        }
                        b'\r' => {
                            self.cr_from = State::Atom;
                            self.state = State::Cr;
                        }
                        b'(' | b')' | b'"' => {
                            self.state = State::Between;
                            self.end_atom();
                            if self.state != State::Between {
                                return; // refused: the rest of the line is skipped
                            }
                            continue;
                        }
                        _ => self.atom_byte(b),
                    }
                    return;
                }
                State::Quoted => {
                    match b {
                        b'"' => {
                            let text = String::from_utf8_lossy(&self.word).into_owned();
                            self.word.clear();
                            self.state = State::Between;
                            self.push_token(ArgToken::Quoted(text));
                        }
                        b'\\' => self.state = State::QuotedEscape,
                        b'\r' => self.state = State::QuotedCr,
                        _ => self.word.push(b),
                    }
                    return;
                }
                State::QuotedEscape => {
                    self.word.push(b);
                    self.state = State::Quoted;
                    return;
                }
                State::QuotedCr => {
                    if b == b'\n' {
                        // The line has ended inside the string: nothing more
                        // of it to skip.
                        self.emit_error("Unterminated quoted string");
                        self.reset_command();
                        self.state = State::Tag;
                        return;
                    }
                    // A CR inside the string, not a line ending.
                    self.word.push(b'\r');
                    self.state = State::Quoted;
                    continue;
                }
                State::LiteralSpec => {
                    match b {
                        b'0'..=b'9' if !self.literal_plus => {
                            self.literal_digits += 1;
                            // (Saturates: anything this large is too large.)
                            self.literal_size = self
                                .literal_size
                                .saturating_mul(10)
                                .saturating_add(u64::from(b - b'0'));
                        }
                        b'+' if self.literal_digits > 0 && !self.literal_plus => self.literal_plus = true,
                        b'}' if self.literal_digits > 0 => self.state = State::LiteralCr,
                        _ => self.fail_at("Bad literal", b),
                    }
                    return;
                }
                State::LiteralCr => {
                    if b == b'\r' {
                        self.state = State::LiteralLf;
                    } else {
                        self.fail_at("Bad literal", b);
                    }
                    return;
                }
                State::LiteralLf => {
                    if b == b'\n' {
                        self.begin_literal();
                    } else {
                        self.fail_at("Bad literal", b);
                    }
                    return;
                }
                State::Literal => unreachable!("feed() never calls push_byte in State::Literal"),
                State::RawLine => {
                    if b == b'\r' {
                        self.state = State::RawLineCr;
                    } else if self.raw.len() >= self.max_line {
                        self.emit_error("Line too long");
                        self.raw.clear();
                        self.resync();
                    } else {
                        self.raw.push(b);
                    }
                    return;
                }
                State::RawLineCr => {
                    if b == b'\n' {
                        let line = std::mem::take(&mut self.raw);
                        self.ready.push(LexEvent::SaslLine(line));
                        self.state = State::Tag;
                    } else if b == b'\r' {
                        self.raw.push(b'\r');
                    } else {
                        self.raw.push(b'\r');
                        self.raw.push(b);
                        self.state = State::RawLine;
                    }
                    return;
                }
            }
        }
    }

    /// A byte of an atom: tracks the `[` ... `]` of a fetch section.
    fn atom_byte(&mut self, b: u8) {
        match b {
            b'[' => self.brackets += 1,
            b']' => self.brackets = self.brackets.saturating_sub(1),
            _ => {}
        }
        self.word.push(b);
    }

    fn end_atom(&mut self) {
        let text = String::from_utf8_lossy(&self.word).into_owned();
        self.word.clear();
        self.brackets = 0;
        self.push_token(ArgToken::Atom(text));
    }

    /// The next token of the command: the first, if it is a word, is the
    /// verb; after that each goes to the verb's grammar, which may refuse it.
    fn push_token(&mut self, token: ArgToken) {
        if self.verb.is_none() {
            match token {
                ArgToken::Atom(word) => {
                    let verb = word.to_ascii_uppercase();
                    self.grammar = grammar_for(&verb, false);
                    self.uid_pending = verb == "UID";
                    self.verb = Some(verb);
                }
                _ => self.fail("Missing command"),
            }
            return;
        }
        if self.uid_pending {
            // `UID` names the command that follows it.
            self.uid_pending = false;
            if let ArgToken::Atom(sub) = &token {
                if let Some(grammar) = grammar_for(&sub.to_ascii_uppercase(), true) {
                    self.grammar = Some(grammar);
                    return;
                }
            }
            self.tokens.push(token);
            return;
        }
        if let Some(grammar) = self.grammar.as_mut() {
            if let Err(reject) = grammar.token(token.as_tok()) {
                self.refuse(reject);
            }
            return;
        }
        self.tokens.push(token);
    }

    /// A grammar refused the command: reply, and skip what is left of the
    /// line (nothing, if it has been read).
    fn refuse(&mut self, reject: Reject) {
        self.emit_error(&reject.0);
        self.reset_command();
        if self.line_ended {
            self.state = State::Tag;
        } else {
            self.resync();
        }
    }

    /// `{n}` and the line it ends have been read: take the octets.
    fn begin_literal(&mut self) {
        let n = self.literal_size;
        let non_sync = self.literal_plus;
        if self.verb.is_none() {
            return self.fail("Missing command");
        }
        // May a literal stand here, and of this size? Asked before the client
        // is told to send it.
        if let Some(grammar) = self.grammar.as_mut() {
            if let Err(reject) = grammar.literal(n) {
                self.emit_error(&reject.0);
                self.reset_command();
                if non_sync && n > 0 {
                    // It will be sent anyway: its octets are skipped.
                    self.literal = LiteralPhase::Skip { remaining: n };
                    self.state = State::Literal;
                } else {
                    self.state = State::Tag;
                }
                return;
            }
        }
        // The body of an APPEND is its message: streamed, not collected.
        let append_body = self.grammar.as_ref().is_some_and(|g| g.streams_literal());
        if n > MAX_LITERAL_SIZE || (!append_body && self.literal_total.saturating_add(n) > MAX_LITERAL_SIZE) {
            self.emit_error("Literal too large");
            self.reset_command();
            self.state = State::Tag;
            return;
        }
        // LITERAL- (RFC 7888): non-synchronizing literals larger than 4 KiB
        // are rejected; clients must use a synchronizing literal instead for
        // anything bigger.
        if non_sync && n > LITERAL_MINUS_LIMIT {
            self.emit_error("Non-synchronizing literal too large (LITERAL-)");
            self.reset_command();
            self.state = State::Tag;
            return;
        }
        if append_body {
            self.literal = LiteralPhase::Append { remaining: n };
        } else {
            self.literal_total += n;
            self.literal_buf.clear();
            self.literal = LiteralPhase::General { remaining: n };
        }
        if !non_sync {
            self.ready.push(LexEvent::NeedContinuation);
        }
        self.typed_bytes = 0;
        self.state = State::Literal;
        if n == 0 {
            // Nothing to wait for.
            let mut none: &[u8] = &[];
            self.feed_literal(&mut none);
        }
    }

    /// Something is wrong with the line: report it and skip to its end.
    fn fail(&mut self, message: &str) {
        self.emit_error(message);
        self.reset_command();
        self.resync();
    }

    /// Skip the rest of the line.
    fn resync(&mut self) {
        self.skip_spec = SkipSpec::None;
        self.state = State::Resync;
    }

    /// As [`Self::fail`], when the byte that showed it is `b`: if that was
    /// the CR of the line ending, the LF is all that is left to skip.
    fn fail_at(&mut self, message: &str, b: u8) {
        self.fail(message);
        if b == b'\r' {
            self.state = State::ResyncCr;
        }
    }

    fn emit_error(&mut self, message: &str) {
        let tag = if self.tag.is_empty() {
            "*".to_string()
        } else {
            String::from_utf8_lossy(&self.tag).into_owned()
        };
        self.ready.push(LexEvent::Error {
            tag,
            message: message.to_string(),
        });
    }

    fn reset_command(&mut self) {
        self.tag.clear();
        self.verb = None;
        self.tokens.clear();
        self.grammar = None;
        self.uid_pending = false;
        self.word.clear();
        self.brackets = 0;
        self.typed_bytes = 0;
        self.literal_total = 0;
        self.literal = LiteralPhase::None;
        self.literal_buf.clear();
    }

    /// CRLF confirmed: the line ends here.
    fn on_crlf(&mut self) {
        self.line_ended = true;
        self.on_crlf_inner();
        self.line_ended = false;
    }

    fn on_crlf_inner(&mut self) {
        match self.cr_from {
            // A line that is only a tag: IDLE's "DONE", sent without a tag.
            State::Tag => {
                if !self.tag.is_empty() {
                    let verb = String::from_utf8_lossy(&self.tag).to_ascii_uppercase();
                    self.tag.clear();
                    self.typed_bytes = 0;
                    self.ready.push(LexEvent::Command(ImapCommand::new("*", verb, Vec::new())));
                }
                self.state = State::Tag;
            }
            State::Atom => {
                self.end_atom();
                self.finish_command();
                self.state = State::Tag;
            }
            _ => {
                self.finish_command();
                self.state = State::Tag;
            }
        }
    }

    fn finish_command(&mut self) {
        let tag = std::mem::take(&mut self.tag);
        let verb = self.verb.take();
        let tokens = std::mem::take(&mut self.tokens);
        let grammar = self.grammar.take();
        self.uid_pending = false;
        self.typed_bytes = 0;
        self.literal_total = 0;
        if tag.is_empty() {
            return;
        }
        if let Some(grammar) = grammar {
            let tag = String::from_utf8_lossy(&tag).into_owned();
            match grammar.finish() {
                Ok(request) => {
                    self.ready.push(LexEvent::Command(ImapCommand::typed(tag, verb.unwrap_or_default(), request)));
                }
                Err(reject) => self.ready.push(LexEvent::Error { tag, message: reject.0.into_owned() }),
            }
            return;
        }
        self.ready.push(LexEvent::Command(ImapCommand::new(
            String::from_utf8_lossy(&tag).into_owned(),
            verb.unwrap_or_default(),
            tokens,
        )));
    }
}

/// Parse an IMAP astring (atom / quoted) from the start of `s`.
pub fn parse_astring(s: &str) -> Result<(String, &str), String> {
    let s = s.trim_start();
    if s.is_empty() {
        return Err("expected astring".into());
    }
    if s.as_bytes()[0] == b'"' {
        return parse_quoted(s);
    }
    // Atom
    let mut end = 0;
    for (i, b) in s.bytes().enumerate() {
        if matches!(
            b,
            b'(' | b')' | b'{' | b' ' | b'"' | b'\\' | b']' | b'%' | b'*'
        ) || !b.is_ascii_graphic()
        {
            break;
        }
        end = i + 1;
    }
    if end == 0 {
        return Err("expected astring".into());
    }
    Ok((s[..end].to_string(), s[end..].trim_start()))
}

fn parse_quoted(s: &str) -> Result<(String, &str), String> {
    let bytes = s.as_bytes();
    if bytes.first() != Some(&b'"') {
        return Err("expected quoted".into());
    }
    // Accumulate raw bytes and decode once at the end (matching the
    // client-side reply parser) — pushing `bytes[i] as char` byte-by-byte
    // corrupts any non-ASCII content, since a multi-byte UTF-8 sequence's
    // bytes each get reinterpreted as an independent Latin-1 codepoint.
    let mut out = Vec::new();
    let mut i = 1;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            let text =
                String::from_utf8(out).map_err(|_| "invalid utf-8 in quoted string".to_string())?;
            return Ok((text, s[i + 1..].trim_start()));
        }
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            out.push(bytes[i + 1]);
            i += 2;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    Err("unterminated quoted string".into())
}

/// Parse a parenthesized flag list `(...)`.
pub fn parse_flag_list(s: &str) -> Result<(BTreeSetFlags, &str), String> {
    let s = s.trim_start();
    if !s.starts_with('(') {
        return Err("expected flag list".into());
    }
    let end = s.find(')').ok_or("unclosed flag list")?;
    let inner = &s[1..end];
    let mut flags = std::collections::BTreeSet::new();
    let mut keywords = std::collections::BTreeSet::new();
    for tok in inner.split_whitespace() {
        if let Some(f) = Flag::parse(tok) {
            if f != Flag::Recent {
                flags.insert(f);
            }
        } else {
            keywords.insert(tok.trim_start_matches('\\').to_string());
        }
    }
    Ok((BTreeSetFlags { flags, keywords }, s[end + 1..].trim_start()))
}

/// Parsed system flags + keywords.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BTreeSetFlags {
    /// System flags.
    pub flags: std::collections::BTreeSet<Flag>,
    /// User keywords.
    pub keywords: std::collections::BTreeSet<String>,
}

impl BTreeSetFlags {
    /// Adds a flag or keyword by name (`\Seen`, `$label`); `\Recent` is the
    /// server's to set, and is ignored.
    pub fn add(&mut self, name: &str) {
        if let Some(f) = Flag::parse(name) {
            if f != Flag::Recent {
                self.flags.insert(f);
            }
        } else {
            self.keywords.insert(name.trim_start_matches('\\').to_string());
        }
    }
}

/// Parse STORE data item name into action + silent.
pub fn parse_store_item(name: &str) -> Result<(StoreAction, bool), String> {
    let u = name.to_ascii_uppercase();
    Ok(match u.as_str() {
        "FLAGS" => (StoreAction::Replace, false),
        "FLAGS.SILENT" => (StoreAction::Replace, true),
        "+FLAGS" => (StoreAction::Add, false),
        "+FLAGS.SILENT" => (StoreAction::Add, true),
        "-FLAGS" => (StoreAction::Remove, false),
        "-FLAGS.SILENT" => (StoreAction::Remove, true),
        _ => return Err(format!("bad STORE item: {name}")),
    })
}

/// Parse a sequence-set token.
pub fn parse_sequence_set(s: &str) -> Result<(MessageSet, &str), String> {
    let s = s.trim_start();
    let mut end = 0;
    for (i, b) in s.bytes().enumerate() {
        if b.is_ascii_digit() || b == b'*' || b == b':' || b == b',' {
            end = i + 1;
        } else {
            break;
        }
    }
    if end == 0 {
        return Err("expected sequence set".into());
    }
    let set = MessageSet::parse(&s[..end]).map_err(|e| e.to_string())?;
    Ok((set, s[end..].trim_start()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_command() {
        let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"a1 NOOP\r\n";
        let ev = lex.feed(&mut data);
        assert!(data.is_empty());
        assert_eq!(ev.len(), 1);
        match &ev[0] {
            LexEvent::Command(c) => {
                assert_eq!(c.tag, "a1");
                assert_eq!(c.verb, "NOOP");
                assert!(c.args.is_empty());
            }
            _ => panic!("expected command"),
        }
    }

    #[test]
    fn parse_login() {
        let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"a1 LOGIN alice secret\r\n";
        let ev = lex.feed(&mut data);
        match &ev[0] {
            LexEvent::Command(c) => {
                assert_eq!(c.verb, "LOGIN");
                assert_eq!(c.request, Some(login("alice", "secret")));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn non_sync_literal() {
        let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"a1 LOGIN {5+}\r\nalice secret\r\n";
        let ev = lex.feed(&mut data);
        assert!(data.is_empty());
        let cmds: Vec<_> = ev
            .into_iter()
            .filter_map(|e| match e {
                LexEvent::Command(c) => Some(c),
                _ => None,
            })
            .collect();
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].verb, "LOGIN");
        assert_eq!(cmds[0].request, Some(login("alice", "secret")));
        let mut data2: &[u8] = b"a2 CAPABILITY\r\n";
        let ev2 = lex.feed(&mut data2);
        assert!(matches!(ev2[0], LexEvent::Command(_)));
    }

    #[test]
    fn sync_literal_needs_continuation() {
        let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"a1 LOGIN {5}\r\n";
        let ev = lex.feed(&mut data);
        assert!(matches!(ev[0], LexEvent::NeedContinuation));
        let mut lit: &[u8] = b"alice secret\r\n";
        let ev2 = lex.feed(&mut lit);
        let cmds: Vec<_> = ev2
            .into_iter()
            .filter_map(|e| match e {
                LexEvent::Command(c) => Some(c),
                LexEvent::NeedContinuation => None,
                LexEvent::SaslLine(_) => None,
                LexEvent::Error { .. } => None,
                LexEvent::AppendChunk(_) => None,
            })
            .collect();
        assert!(!cmds.is_empty());
        assert_eq!(cmds[0].verb, "LOGIN");
        assert_eq!(cmds[0].request, Some(login("alice", "secret")));
    }

    #[test]
    fn literal_split_across_many_feeds() {
        // The literal's bytes arrive one at a time across many feed() calls,
        // proving bulk-vs-dribbled delivery is equivalent and nothing is
        // ever retained by the caller.
        let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
        let msg: &[u8] = b"a1 LOGIN {5}\r\nalice secret\r\n";
        let mut events = Vec::new();
        for &b in msg {
            let mut one: &[u8] = &[b];
            events.extend(lex.feed(&mut one));
            assert!(one.is_empty());
        }
        let cmds: Vec<_> = events
            .into_iter()
            .filter_map(|e| match e {
                LexEvent::Command(c) => Some(c),
                _ => None,
            })
            .collect();
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].verb, "LOGIN");
        assert_eq!(cmds[0].request, Some(login("alice", "secret")));
    }

    #[test]
    fn append_literal_streams_and_finishes_command() {
        let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"a1 APPEND INBOX {5}\r\nhello\r\n";
        let ev = lex.feed(&mut data);
        assert!(data.is_empty());
        assert!(matches!(ev[0], LexEvent::NeedContinuation));
        let mut body = Vec::new();
        let mut cmds = Vec::new();
        for e in ev {
            match e {
                LexEvent::AppendChunk(chunk) => body.extend_from_slice(&chunk),
                LexEvent::Command(c) => cmds.push(c),
                _ => {}
            }
        }
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].verb, "APPEND");
        assert_eq!(body, b"hello");
    }

    #[test]
    fn append_literal_chunk_delivered_as_soon_as_bytes_arrive_even_before_command_completes() {
        let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"a1 APPEND INBOX {11}\r\nhel";
        let ev = lex.feed(&mut data);
        assert!(lex.in_literal());
        let chunk: Vec<u8> = ev
            .into_iter()
            .filter_map(|e| match e {
                LexEvent::AppendChunk(c) => Some(c),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(chunk, b"hel", "partial literal bytes must be delivered immediately, not buffered until the literal completes");

        let mut rest: &[u8] = b"lo world\r\n";
        let ev2 = lex.feed(&mut rest);
        assert!(!lex.in_literal());
        let mut tail = Vec::new();
        let mut saw_command = false;
        for e in ev2 {
            match e {
                LexEvent::AppendChunk(c) => tail.extend_from_slice(&c),
                LexEvent::Command(c) => {
                    assert_eq!(c.verb, "APPEND");
                    saw_command = true;
                }
                _ => {}
            }
        }
        assert_eq!(tail, b"lo world");
        assert!(saw_command);
    }

    #[test]
    fn in_literal_reports_mid_literal_state() {
        let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"a1 LOGIN {5+}\r\nal";
        let _ = lex.feed(&mut data);
        assert!(lex.in_literal());
        let mut rest: &[u8] = b"ice secret\r\n";
        let _ = lex.feed(&mut rest);
        assert!(!lex.in_literal());
    }

    #[test]
    fn oversized_literal_rejected() {
        let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
        let line = format!("a1 LOGIN {{{}}}\r\n", MAX_LITERAL_SIZE + 1);
        let mut data: &[u8] = line.as_bytes();
        let ev = lex.feed(&mut data);
        assert!(matches!(
            &ev[0],
            LexEvent::Error { tag, message } if tag == "a1" && message == "Literal too large"
        ));
    }

    #[test]
    fn sync_literal_over_literal_minus_limit_accepted() {
        // Synchronizing literals (`{n}`) have no LITERAL- cap of their own -
        // they're only bounded by MAX_LITERAL_SIZE - so a size above
        // LITERAL_MINUS_LIMIT must still be accepted, prompting a
        // continuation request rather than an error.
        let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
        let n = LITERAL_MINUS_LIMIT + 1;
        assert!(n < MAX_LITERAL_SIZE);
        let line = format!("a1 LOGIN {{{n}}}\r\n");
        let mut data: &[u8] = line.as_bytes();
        let ev = lex.feed(&mut data);
        assert!(matches!(ev[0], LexEvent::NeedContinuation));
    }

    #[test]
    fn oversized_non_sync_literal_over_literal_minus_limit_rejected() {
        // Non-synchronizing literals (`{n+}`) above LITERAL_MINUS_LIMIT are
        // exactly what RFC 7888 forbids: the client would send the bytes
        // without giving the server a chance to reject first.
        let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
        let n = LITERAL_MINUS_LIMIT + 1;
        let line = format!("a1 LOGIN {{{n}+}}\r\n");
        let mut data: &[u8] = line.as_bytes();
        let ev = lex.feed(&mut data);
        assert!(matches!(
            &ev[0],
            LexEvent::Error { tag, message } if tag == "a1" && message == "Non-synchronizing literal too large (LITERAL-)"
        ));
    }

    #[test]
    fn pipelined_commands() {
        let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"a1 NOOP\r\na2 CAPABILITY\r\n";
        let ev = lex.feed(&mut data);
        assert_eq!(ev.len(), 2);
    }

    #[test]
    fn sasl_response_split_across_feeds() {
        // The line following `expect_sasl_response` must resume correctly
        // even when its bytes (and CRLF) arrive across separate `feed`
        // calls — this is the exact class of bug the raw-line scratch
        // buffer replaces a windows(2)-CRLF-scan with.
        let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
        let mut a: &[u8] = b"a1 AUTHENTICATE PLAIN\r\n";
        let ev = lex.feed(&mut a);
        assert_eq!(ev.len(), 1);
        lex.expect_sasl_response();

        let mut part1: &[u8] = b"AGFsaWNl";
        assert!(lex.feed(&mut part1).is_empty());
        let mut part2: &[u8] = b"AHNlY3JldA==\r\n";
        let ev2 = lex.feed(&mut part2);
        assert_eq!(ev2.len(), 1);
        match &ev2[0] {
            LexEvent::SaslLine(line) => assert_eq!(line, b"AGFsaWNlAHNlY3JldA=="),
            _ => panic!("expected SaslLine"),
        }
    }

    #[test]
    fn sasl_response_all_split_points_are_equivalent() {
        let msg: &[u8] = b"AGFsaWNlAHNlY3JldA==\r\n";
        for split in 1..msg.len() {
            let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
            lex.expect_sasl_response();
            let mut a: &[u8] = &msg[..split];
            let mut ev = lex.feed(&mut a);
            assert!(a.is_empty(), "split {split} retained bytes");
            let mut b: &[u8] = &msg[split..];
            ev.extend(lex.feed(&mut b));
            assert!(b.is_empty(), "split {split} retained bytes");
            assert_eq!(ev.len(), 1, "split {split}");
            match &ev[0] {
                LexEvent::SaslLine(line) => assert_eq!(line, b"AGFsaWNlAHNlY3JldA=="),
                _ => panic!("split {split}: expected SaslLine"),
            }
        }
    }

    #[test]
    fn sasl_response_abort_line_passed_through_raw() {
        // `*` (RFC 3501 continuation abort) isn't interpreted by the lexer —
        // that's the caller's job, same as base64 decoding.
        let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
        lex.expect_sasl_response();
        let mut data: &[u8] = b"*\r\n";
        let ev = lex.feed(&mut data);
        match &ev[0] {
            LexEvent::SaslLine(line) => assert_eq!(line, b"*"),
            _ => panic!("expected SaslLine"),
        }
    }

    #[test]
    fn sasl_response_resumes_normal_commands_afterward() {
        let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
        lex.expect_sasl_response();
        let mut data: &[u8] = b"AGFsaWNlAHNlY3JldA==\r\na2 NOOP\r\n";
        let ev = lex.feed(&mut data);
        assert_eq!(ev.len(), 2);
        assert!(matches!(&ev[0], LexEvent::SaslLine(_)));
        match &ev[1] {
            LexEvent::Command(c) => assert_eq!(c.verb, "NOOP"),
            _ => panic!("expected command"),
        }
    }

    #[test]
    fn split_buffers() {
        let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
        let mut a: &[u8] = b"a1 NO";
        assert!(lex.feed(&mut a).is_empty());
        let mut b: &[u8] = b"OP\r\n";
        let ev = lex.feed(&mut b);
        match &ev[0] {
            LexEvent::Command(c) => assert_eq!(c.verb, "NOOP"),
            _ => panic!(),
        }
    }

    #[test]
    fn bare_tag_only_line_is_idle_done() {
        let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"DONE\r\n";
        let ev = lex.feed(&mut data);
        match &ev[0] {
            LexEvent::Command(c) => {
                assert_eq!(c.tag, "*");
                assert_eq!(c.verb, "DONE");
                assert!(c.args.is_empty());
            }
            _ => panic!("expected command"),
        }
    }

    #[test]
    fn blank_line_produces_no_command() {
        let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"\r\na1 NOOP\r\n";
        let ev = lex.feed(&mut data);
        assert_eq!(ev.len(), 1);
        assert!(matches!(&ev[0], LexEvent::Command(c) if c.verb == "NOOP"));
    }

    #[test]
    fn oversized_tag_discards_and_resyncs() {
        let mut lex = ImapServerLexer::new(4);
        let mut data: &[u8] = b"toolongtag NOOP\r\na2 NOOP\r\n";
        let ev = lex.feed(&mut data);
        let cmds: Vec<_> = ev
            .into_iter()
            .filter_map(|e| match e {
                LexEvent::Command(c) => Some(c),
                _ => None,
            })
            .collect();
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].tag, "a2");
    }

    #[test]
    fn literal_cr_not_followed_by_lf_is_content() {
        let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"a1 SEARCH a\rb\r\n";
        let ev = lex.feed(&mut data);
        match &ev[0] {
            LexEvent::Command(c) => {
                assert_eq!(c.verb, "SEARCH");
                assert_eq!(c.args, "a\rb");
            }
            _ => panic!(),
        }
    }

    /// One byte per `feed()` call must produce identical commands to a
    /// single bulk feed, and never leave anything unconsumed.
    #[test]
    fn one_byte_at_a_time_matches_bulk_feed() {
        let msg: &[u8] = b"a1 LOGIN alice secret\r\na2 CAPABILITY\r\na3 LOGOUT\r\n";

        let mut bulk = ImapServerLexer::new(MAX_COMMAND_LINE);
        let mut bulk_data = msg;
        let bulk_ev = bulk.feed(&mut bulk_data);
        let bulk_cmds: Vec<_> = bulk_ev
            .into_iter()
            .filter_map(|e| match e {
                LexEvent::Command(c) => Some(c),
                _ => None,
            })
            .collect();

        let mut drip = ImapServerLexer::new(MAX_COMMAND_LINE);
        let mut drip_cmds = Vec::new();
        for &b in msg {
            let mut one: &[u8] = &[b];
            let ev = drip.feed(&mut one);
            assert!(one.is_empty());
            drip_cmds.extend(ev.into_iter().filter_map(|e| match e {
                LexEvent::Command(c) => Some(c),
                _ => None,
            }));
        }

        assert_eq!(bulk_cmds, drip_cmds);
        assert_eq!(bulk_cmds.len(), 3);
    }

    /// Every split point of a full command stream (including one with a
    /// literal) must be equivalent.
    #[test]
    fn all_split_points_are_equivalent() {
        let msg: &[u8] = b"a1 LOGIN {5}\r\nalice secret\r\na2 CAPABILITY\r\na3 LOGOUT\r\n";
        let mut base = ImapServerLexer::new(MAX_COMMAND_LINE);
        let mut base_data = msg;
        let base_ev = base.feed(&mut base_data);
        let base_cmds: Vec<_> = base_ev
            .into_iter()
            .filter_map(|e| match e {
                LexEvent::Command(c) => Some(c),
                _ => None,
            })
            .collect();

        for split in 1..msg.len() {
            let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
            let mut a: &[u8] = &msg[..split];
            let mut ev = lex.feed(&mut a);
            assert!(a.is_empty(), "split {split} retained bytes");
            let mut b: &[u8] = &msg[split..];
            ev.extend(lex.feed(&mut b));
            assert!(b.is_empty(), "split {split} retained bytes");
            let cmds: Vec<_> = ev
                .into_iter()
                .filter_map(|e| match e {
                    LexEvent::Command(c) => Some(c),
                    _ => None,
                })
                .collect();
            assert_eq!(cmds, base_cmds, "split {split} diverged");
        }
    }

    #[test]
    fn sequence_set_parse() {
        let (set, rest) = parse_sequence_set("1:5,7 UID").unwrap();
        assert!(set.contains(3, 20));
        assert_eq!(rest, "UID");
    }

    #[test]
    fn store_item() {
        assert_eq!(
            parse_store_item("+FLAGS.SILENT").unwrap(),
            (StoreAction::Add, true)
        );
    }

    /// Issue #195: a quoted string containing non-ASCII UTF-8 content must
    /// decode intact, not get mangled by treating each byte of a
    /// multi-byte sequence as an independent Latin-1 codepoint.
    #[test]
    fn parse_quoted_preserves_non_ascii_utf8() {
        let (s, rest) = parse_astring("\"café\" REST").unwrap();
        assert_eq!(s, "café");
        assert_eq!(rest, "REST");
    }

    #[test]
    fn parse_quoted_preserves_multibyte_and_emoji() {
        let (s, rest) = parse_astring("\"日本語 🎉\" REST").unwrap();
        assert_eq!(s, "日本語 🎉");
        assert_eq!(rest, "REST");
    }

    #[test]
    fn parse_quoted_still_handles_escapes_with_non_ascii() {
        let (s, _) = parse_astring("\"caf\\\"é\\\\\"").unwrap();
        assert_eq!(s, "caf\"é\\");
    }

    // ── tokens ──────────────────────────────────────────────────────────

    fn login(user: &str, pass: &str) -> Request {
        Request::Login { user: user.into(), pass: pass.into() }
    }

    fn a(text: &str) -> ArgToken {
        ArgToken::Atom(text.into())
    }

    fn q(text: &str) -> ArgToken {
        ArgToken::Quoted(text.into())
    }

    fn lit(bytes: &[u8]) -> ArgToken {
        ArgToken::Literal(bytes.to_vec())
    }

    /// Lexes `wire` in chunks of `chunk` bytes, returning every event.
    fn lex(wire: &[u8], chunk: usize) -> Vec<LexEvent> {
        let mut lexer = ImapServerLexer::new(MAX_COMMAND_LINE);
        let mut out = Vec::new();
        for piece in wire.chunks(chunk) {
            let mut data: &[u8] = piece;
            out.extend(lexer.feed(&mut data));
            assert!(data.is_empty());
        }
        out
    }

    fn commands(events: Vec<LexEvent>) -> Vec<(String, String, Vec<ArgToken>)> {
        events
            .into_iter()
            .filter_map(|e| match e {
                LexEvent::Command(c) => Some((c.tag, c.verb, c.tokens)),
                _ => None,
            })
            .collect()
    }

    fn cmd(tag: &str, verb: &str, tokens: Vec<ArgToken>) -> (String, String, Vec<ArgToken>) {
        (tag.into(), verb.into(), tokens)
    }

    #[test]
    fn arguments_are_typed_tokens() {
        let wire = b"t1 XFETCH 1:* (FLAGS BODY.PEEK[HEADER.FIELDS (From \"To\")]<0.100>)\r\n\
                     t2 XLIST \"\" \"INBOX/%\"\r\n\
                     t3 SEARCH 1,3:5 KEYWORD (\\Seen \\Deleted)\r\n\
                     t4 METADATA \"My \\\"box\\\" \\\\ x\"\r\n";
        let want = vec![
            cmd(
                "t1",
                "XFETCH",
                vec![
                    a("1:*"),
                    ArgToken::Open,
                    a("FLAGS"),
                    a("BODY.PEEK[HEADER.FIELDS (From \"To\")]<0.100>"),
                    ArgToken::Close,
                ],
            ),
            cmd("t2", "XLIST", vec![q(""), q("INBOX/%")]),
            cmd(
                "t3",
                "SEARCH",
                vec![a("1,3:5"), a("KEYWORD"), ArgToken::Open, a("\\Seen"), a("\\Deleted"), ArgToken::Close],
            ),
            cmd("t4", "METADATA", vec![q("My \"box\" \\ x")]),
        ];
        for chunk in [1, 2, 3, 5, 13, 1000] {
            assert_eq!(commands(lex(wire, chunk)), want, "chunk={chunk}");
        }
    }

    /// A literal is one token: whatever its octets contain, it cannot change
    /// how the rest of the line is read. (Spliced into the line as text, the
    /// first of these would have been a user, a password and a stray word.)
    #[test]
    fn a_literal_is_one_token_whatever_it_contains() {
        let wire = b"a1 SEARCH TEXT {7}\r\nal ice\" secret\r\n\
                     a2 METADATA {4}\r\n(x)\" \r\n\
                     a3 SETQUOTA {3+}\r\na b {2+}\r\ncd\r\n";
        let want = vec![
            cmd("a1", "SEARCH", vec![a("TEXT"), lit(b"al ice\""), a("secret")]),
            cmd("a2", "METADATA", vec![lit(b"(x)\"")]),
            cmd("a3", "SETQUOTA", vec![lit(b"a b"), lit(b"cd")]),
        ];
        for chunk in [1, 2, 3, 7, 1000] {
            let events = lex(wire, chunk);
            let continuations = events.iter().filter(|e| matches!(e, LexEvent::NeedContinuation)).count();
            assert_eq!(continuations, 2, "chunk={chunk}: {{7}} and {{4}} are synchronizing");
            assert_eq!(commands(events), want, "chunk={chunk}");
        }
    }

    #[test]
    fn args_render_tokens_as_text_for_handlers_that_read_text() {
        let tokens = vec![
            lit(b"alice"),
            lit(b"two words"),
            q("say \"hi\""),
            ArgToken::Open,
            a("\\Seen"),
            a("\\Flagged"),
            ArgToken::Close,
            lit(b""),
            lit(b"1:*"),
        ];
        assert_eq!(
            render_args(&tokens),
            "alice \"two words\" \"say \\\"hi\\\"\" (\\Seen \\Flagged) \"\" \"1:*\""
        );
    }

    #[test]
    fn uid_names_the_command_after_it() {
        let c = ImapCommand::new("t", "UID", vec![a("fetch"), a("1:*"), a("FLAGS")]);
        let sub = c.sub_command().unwrap();
        assert_eq!((sub.verb.as_str(), sub.args.as_str()), ("FETCH", "1:* FLAGS"));
        assert!(ImapCommand::new("t", "UID", vec![]).sub_command().is_none());
    }

    #[test]
    fn append_body_is_the_literal_after_the_mailbox() {
        // The mailbox may itself be a literal; only the message after it is
        // the body, delivered as chunks and not collected.
        let wire = b"a1 APPEND {5+}\r\nINBOX (\\Seen) {5+}\r\nhello\r\n";
        for chunk in [1, 4, 1000] {
            let events = lex(wire, chunk);
            let body: Vec<u8> = events
                .iter()
                .filter_map(|e| match e {
                    LexEvent::AppendChunk(c) => Some(c.clone()),
                    _ => None,
                })
                .flatten()
                .collect();
            assert_eq!(body, b"hello", "chunk={chunk}");
            let mut seen = BTreeSetFlags::default();
            seen.add("\\Seen");
            let requests: Vec<_> = events
                .into_iter()
                .filter_map(|e| match e {
                    LexEvent::Command(c) => c.request,
                    _ => None,
                })
                .collect();
            assert_eq!(requests, vec![Request::Append { mailbox: "INBOX".to_string(), flags: seen }], "chunk={chunk}");
        }
    }

    #[test]
    fn literals_in_one_command_are_capped_together() {
        let mut lexer = ImapServerLexer::new(MAX_COMMAND_LINE);
        let one = MAX_LITERAL_SIZE / 2 + 1;
        // Each is under the cap; both together are not.
        let mut first: &[u8] = format!("a1 SEARCH TEXT {{{one}}}\r\n").as_bytes().to_vec().leak();
        let events = lexer.feed(&mut first);
        assert!(matches!(events[0], LexEvent::NeedContinuation));
        let octets = vec![b'x'; one as usize];
        let mut data: &[u8] = &octets;
        lexer.feed(&mut data);
        let mut second: &[u8] = format!(" TEXT {{{one}}}\r\n").as_bytes().to_vec().leak();
        let events = lexer.feed(&mut second);
        assert!(
            events.iter().any(|e| matches!(e, LexEvent::Error { message, .. } if message == "Literal too large")),
            "{events:?}"
        );
    }

    #[test]
    fn syntax_errors_are_reported_and_the_next_command_still_runs() {
        for bad in [
            &b"a1 SELECT \"unterminated\r\na2 NOOP\r\n"[..],
            b"a1 SELECT {x}\r\na2 NOOP\r\n",
            b"a1 SELECT {5\r\na2 NOOP\r\n",
            b"a1 SELECT {}\r\na2 NOOP\r\n",
            b"a1 (SELECT\r\na2 NOOP\r\n",
        ] {
            for chunk in [1, 5, 1000] {
                let events = lex(bad, chunk);
                assert!(events.iter().any(|e| matches!(e, LexEvent::Error { .. })), "{bad:?} chunk={chunk}");
                let cmds = commands(events);
                assert_eq!(cmds.last(), Some(&cmd("a2", "NOOP", vec![])), "{bad:?} chunk={chunk}");
            }
        }
    }

    #[test]
    fn a_zero_length_literal_is_an_empty_token() {
        let events = lex(b"a1 SETQUOTA {0+}\r\n\r\n", 3);
        assert_eq!(commands(events), vec![cmd("a1", "SETQUOTA", vec![lit(b"")])]);
    }

    #[test]
    fn a_line_over_the_limit_is_an_error_but_literals_do_not_count() {
        let mut lexer = ImapServerLexer::new(40);
        let mut wire = b"a1 LOGIN {200+}\r\n".to_vec();
        wire.extend(vec![b'x'; 200]);
        wire.extend_from_slice(b" ok\r\n");
        let mut data: &[u8] = &wire;
        let events = lexer.feed(&mut data);
        assert_eq!(commands(events).len(), 1);
        let mut long = format!("a2 SELECT {}\r\na3 NOOP\r\n", "y".repeat(100)).into_bytes();
        let mut data: &[u8] = &long;
        let events = lexer.feed(&mut data);
        assert!(events.iter().any(|e| matches!(e, LexEvent::Error { message, .. } if message == "Line too long")));
        assert_eq!(commands(events), vec![cmd("a3", "NOOP", vec![])]);
        long.clear();
    }
}
