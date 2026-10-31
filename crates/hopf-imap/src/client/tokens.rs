// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The token layer under the client's structured response payloads.
//!
//! A [`Tokenizer`] reads the bytes of IMAP response syntax - atoms, quoted
//! strings, literals (`{n}` CRLF `n` octets), parentheses - and hands each
//! token to a [`Sink`] the moment it is complete. The sink is a small state
//! machine for one payload (an `ENVELOPE`, a `NAMESPACE`, a `THREAD` tree
//! ...) that builds the typed value as the tokens arrive. Nothing is kept
//! as text to be parsed again afterwards, and a literal is just another
//! string token wherever a string may stand.
//!
//! A payload is either the rest of the line ([`Tokenizer::line`]), ending at
//! its CRLF, or one value ([`Tokenizer::value`]): a single token or a
//! balanced parenthesized list, ending with it.

use super::error::ImapError;
use super::reply::ImapEvent;
use super::structure::{ImapBodyStructure, ImapEnvelope};

/// The most one payload may keep (atoms, strings and literal octets added
/// together): a hostile server cannot make the client buffer without limit.
pub const MAX_PAYLOAD: usize = 1024 * 1024;

/// One token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tok<'a> {
    /// A word written bare: `NIL`, `12`, `INBOX`, `\Seen`.
    Atom(&'a [u8]),
    /// A quoted string (unescaped) or a literal's octets.
    Str(&'a [u8]),
    /// `(`
    Open,
    /// `)`
    Close,
}

/// The sink refuses what it was given: the payload is dropped, and the rest
/// of it is read and discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Bad;

/// What a payload amounts to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Output {
    /// An event to report.
    Event(ImapEvent),
    /// A FETCH `ENVELOPE`.
    Envelope(ImapEnvelope),
    /// A FETCH `BODYSTRUCTURE` (or `BODY`).
    Body(ImapBodyStructure),
    /// A FETCH `INTERNALDATE`, without its quotes.
    Date(String),
}

/// A machine for one payload.
pub(crate) trait Sink: Send {
    /// The next token.
    fn token(&mut self, tok: Tok<'_>) -> Result<(), Bad>;

    /// Does the payload want the octets of literals? (A discarding sink does
    /// not: they are skipped as they arrive.)
    fn keeps_literals(&self) -> bool {
        true
    }

    /// The end of the payload.
    fn finish(self: Box<Self>) -> Result<Output, Bad>;
}

/// What a byte did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Out {
    /// Nothing complete yet.
    More,
    /// The line ended (in [`Tokenizer::line`] mode).
    Eol,
    /// The value is complete (in [`Tokenizer::value`] mode). When
    /// `reprocess`, the byte that showed it (the delimiter after a bare
    /// word) was not used and belongs to whatever follows.
    Done { reprocess: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum St {
    Between,
    Atom,
    Quoted,
    QuotedEscape,
    LiteralSize,
    LiteralCr,
    LiteralLf,
    LiteralOctets,
    Cr,
}

/// Reads tokens from bytes.
pub(crate) struct Tokenizer {
    st: St,
    value_mode: bool,
    /// Parenthesis depth.
    depth: usize,
    /// The word, quoted string or literal being read.
    buf: Vec<u8>,
    size: u64,
    digits: u32,
    remaining: u64,
    /// The current literal's octets are skipped.
    skip_literal: bool,
    /// A sink refused something, or the payload outgrew [`MAX_PAYLOAD`]: what
    /// is left of it is only read through.
    bad: bool,
    used: usize,
}

fn protocol(message: &str) -> ImapError {
    ImapError::Parse(message.into())
}

/// Ends a bare word.
fn ends_word(b: u8) -> bool {
    matches!(b, b' ' | b'\r' | b'\n' | b'(' | b')' | b'"')
}

impl Tokenizer {
    fn new(value_mode: bool) -> Self {
        Self {
            st: St::Between,
            value_mode,
            depth: 0,
            buf: Vec::new(),
            size: 0,
            digits: 0,
            remaining: 0,
            skip_literal: false,
            bad: false,
            used: 0,
        }
    }

    /// For a payload that is the rest of the line.
    pub(crate) fn line() -> Self {
        Self::new(false)
    }

    /// For a payload that is one value: a word, a string, or a balanced list.
    pub(crate) fn value() -> Self {
        Self::new(true)
    }

    /// Did the payload go wrong (and is it being read through only)?
    pub(crate) fn is_bad(&self) -> bool {
        self.bad
    }

    /// Are literal octets next, to be given to [`Self::literal_octets`]?
    pub(crate) fn in_literal(&self) -> bool {
        self.st == St::LiteralOctets
    }

    fn keep(&mut self, b: u8) {
        if self.bad {
            return;
        }
        if self.used >= MAX_PAYLOAD {
            self.bad = true;
            self.buf.clear();
            return;
        }
        self.used += 1;
        self.buf.push(b);
    }

    fn emit(&mut self, sink: &mut dyn Sink, tok: Tok<'_>) {
        if !self.bad && sink.token(tok).is_err() {
            self.bad = true;
        }
    }

    /// A token has been given to the sink: is the value complete?
    fn complete(&self, reprocess: bool) -> Out {
        if self.value_mode && self.depth == 0 {
            Out::Done { reprocess }
        } else {
            Out::More
        }
    }

    /// Feed one byte.
    pub(crate) fn byte(&mut self, b: u8, sink: &mut dyn Sink) -> Result<Out, ImapError> {
        loop {
            match self.st {
                St::Between => {
                    return match b {
                        b' ' => Ok(Out::More),
                        b'\r' => {
                            self.st = St::Cr;
                            Ok(Out::More)
                        }
                        b'\n' => Err(protocol("expected CRLF")),
                        b'(' => {
                            self.depth += 1;
                            self.emit(sink, Tok::Open);
                            Ok(Out::More)
                        }
                        b')' => {
                            if self.depth == 0 {
                                if self.value_mode {
                                    return Err(protocol("unexpected ')'"));
                                }
                                self.bad = true;
                                return Ok(Out::More);
                            }
                            self.depth -= 1;
                            self.emit(sink, Tok::Close);
                            Ok(self.complete(false))
                        }
                        b'"' => {
                            self.buf.clear();
                            self.st = St::Quoted;
                            Ok(Out::More)
                        }
                        b'{' => {
                            self.size = 0;
                            self.digits = 0;
                            self.st = St::LiteralSize;
                            Ok(Out::More)
                        }
                        _ => {
                            self.buf.clear();
                            self.st = St::Atom;
                            self.keep(b);
                            Ok(Out::More)
                        }
                    };
                }
                St::Atom => {
                    if !ends_word(b) {
                        self.keep(b);
                        return Ok(Out::More);
                    }
                    self.st = St::Between;
                    let word = std::mem::take(&mut self.buf);
                    self.emit(sink, Tok::Atom(&word));
                    self.buf = word;
                    if self.complete(true) != Out::More {
                        return Ok(Out::Done { reprocess: true });
                    }
                    // The delimiter is read again, between tokens.
                }
                St::Quoted => {
                    return match b {
                        b'"' => {
                            self.st = St::Between;
                            let text = std::mem::take(&mut self.buf);
                            self.emit(sink, Tok::Str(&text));
                            self.buf = text;
                            Ok(self.complete(false))
                        }
                        b'\\' => {
                            self.st = St::QuotedEscape;
                            Ok(Out::More)
                        }
                        b'\r' | b'\n' => Err(protocol("line ended inside a quoted string")),
                        _ => {
                            self.keep(b);
                            Ok(Out::More)
                        }
                    };
                }
                St::QuotedEscape => {
                    self.keep(b);
                    self.st = St::Quoted;
                    return Ok(Out::More);
                }
                St::LiteralSize => {
                    match b {
                        b'0'..=b'9' => {
                            self.digits += 1;
                            self.size = self.size.saturating_mul(10).saturating_add(u64::from(b - b'0'));
                        }
                        b'+' if self.digits > 0 => {}
                        b'}' if self.digits > 0 => self.st = St::LiteralCr,
                        _ => return Err(protocol("bad literal marker")),
                    }
                    return Ok(Out::More);
                }
                St::LiteralCr => {
                    if b != b'\r' {
                        return Err(protocol("bad literal marker"));
                    }
                    self.st = St::LiteralLf;
                    return Ok(Out::More);
                }
                St::LiteralLf => {
                    if b != b'\n' {
                        return Err(protocol("bad literal marker"));
                    }
                    self.begin_literal(sink);
                    if self.size == 0 {
                        self.st = St::Between;
                        self.emit(sink, Tok::Str(&[]));
                        return Ok(self.complete(false));
                    }
                    return Ok(Out::More);
                }
                St::LiteralOctets => return Ok(self.literal_octets(&[b], sink).1),
                St::Cr => {
                    if b != b'\n' {
                        return Err(protocol("expected LF after CR"));
                    }
                    self.st = St::Between;
                    if self.value_mode {
                        return Err(protocol("line ended inside a value"));
                    }
                    return Ok(Out::Eol);
                }
            }
        }
    }

    fn begin_literal(&mut self, sink: &mut dyn Sink) {
        self.remaining = self.size;
        self.buf.clear();
        let wanted = sink.keeps_literals() && !self.bad;
        let fits = (self.used as u64).saturating_add(self.size) <= MAX_PAYLOAD as u64;
        if wanted && !fits {
            self.bad = true;
        }
        self.skip_literal = !wanted || !fits;
        self.st = St::LiteralOctets;
    }

    /// Literal octets: takes as many of `data` as belong to the literal, and
    /// returns how many that was.
    pub(crate) fn literal_octets(&mut self, data: &[u8], sink: &mut dyn Sink) -> (usize, Out) {
        debug_assert_eq!(self.st, St::LiteralOctets);
        let take = data.len().min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        if !self.skip_literal {
            self.used += take;
            self.buf.extend_from_slice(&data[..take]);
        }
        self.remaining -= take as u64;
        if self.remaining > 0 {
            return (take, Out::More);
        }
        self.st = St::Between;
        let octets = std::mem::take(&mut self.buf);
        if !self.skip_literal {
            self.emit(sink, Tok::Str(&octets));
        }
        self.buf = octets;
        self.buf.clear();
        (take, self.complete(false))
    }
}
