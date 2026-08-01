// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Incremental, semantic POP3 client reply parser.
//!
//! [`Pop3ReplyLexer`] never buffers a whole reply line and re-parses it.
//! Bytes are consumed one at a time; numeric fields accumulate in a small
//! fixed-size scratch value (not a growing buffer), and a [`Pop3Event`] is
//! emitted the instant each protocol-meaningful field completes — already
//! parsed, never a raw token for the caller to re-interpret. Decorative
//! text after `+OK` (banners, "N messages" summaries, per-command status
//! prose) is scanned for its terminator and discarded without ever being
//! stored, even temporarily; only structurally meaningful text (an `-ERR`
//! diagnostic, a UIDL unique-id, a CAPA entry, the bracketed APOP
//! challenge token) is captured, bounded by [`MAX_REPLY_LINE`].
//!
//! The caller tells the lexer what shape of reply to expect via
//! [`Pop3ReplyLexer::expect`], right after sending the corresponding
//! command — POP3's grammar is command-dependent: the same `+OK` line
//! means a different field layout after `STAT` than after `USER`.

use rmimeparser::charset::base64;
use rmimeparser::ContentIdParser;

use super::error::Pop3Error;
use super::state::Pop3Capabilities;

pub use rmimeparser::ContentId;

/// Cap on one buffered field (an `-ERR`/SASL-continuation line, a UIDL
/// unique-id, a CAPA entry line), so a server that never sends a
/// delimiter can't grow the lexer's scratch buffer without bound.
/// Decorative `+OK` text is never buffered at all — this bound only
/// applies to fields the parser actually keeps.
pub const MAX_REPLY_LINE: usize = 32 * 1024;

/// Cap on the bracketed APOP challenge token specifically (RFC 1939 §7
/// challenges are always short; this just prevents pathological input from
/// growing the scratch buffer while capture is in progress).
const MAX_CHALLENGE_LEN: usize = 256;

/// What shape of reply to expect, set via [`Pop3ReplyLexer::expect`] right
/// after sending the corresponding command. POP3's `+OK`/`-ERR` grammar is
/// command-dependent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pop3ReplyShape {
    /// The initial greeting.
    Greeting,
    /// `CAPA`.
    Capa,
    /// `USER`.
    User,
    /// `PASS`.
    Pass,
    /// `APOP`.
    Apop,
    /// `AUTH` (initial send, and every subsequent challenge response).
    Auth,
    /// `STLS`.
    Stls,
    /// `STAT`.
    Stat,
    /// `LIST` (all messages).
    ListAll,
    /// `LIST n`.
    ListSingle,
    /// `UIDL` (all messages).
    UidlAll,
    /// `UIDL n`.
    UidlSingle,
    /// `RETR n`.
    Retr,
    /// `TOP n lines`.
    Top,
    /// `DELE n`.
    Dele,
    /// `RSET`.
    Rset,
    /// `NOOP`.
    Noop,
    /// `QUIT`.
    Quit,
}

/// Semantic events. Every success variant carries already-parsed,
/// ready-to-use data — never a raw line for the caller to split or
/// re-parse. `Err` is the one shared failure event: POP3 `-ERR` text has
/// no further protocol-defined structure to extract, so there's nothing
/// more "semantic" to pull out of it than the message itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pop3Event {
    /// Server greeting — the surrounding banner prose is discarded, never
    /// stored (RFC 1939 §7).
    ServerGreeting {
        /// The `<...>` APOP challenge token, already parsed, if present.
        apop_challenge: Option<ContentId>,
    },
    /// CAPA response, fully parsed (RFC 2449).
    Capa(Pop3Capabilities),
    /// `USER` accepted; not yet authenticated.
    UserOk,
    /// Authenticated (via PASS, APOP, or AUTH).
    Authenticated,
    /// AUTH SASL challenge (`+` continuation), already base64-decoded.
    AuthChallenge {
        /// Decoded challenge bytes.
        data: Vec<u8>,
    },
    /// STAT: `count` messages totalling `octets` bytes.
    Stat {
        /// Number of messages in the maildrop.
        count: u32,
        /// Total size in bytes.
        octets: u64,
    },
    /// LIST (all) intro accepted; entries follow.
    ListStart,
    /// One LIST entry.
    ListEntry {
        /// Message number.
        message: u32,
        /// Message size in bytes.
        octets: u64,
    },
    /// End of the LIST listing.
    ListEnd,
    /// Response to `LIST n`.
    ListSingle {
        /// Message number.
        message: u32,
        /// Message size in bytes.
        octets: u64,
    },
    /// UIDL (all) intro accepted; entries follow.
    UidlStart,
    /// One UIDL entry.
    UidlEntry {
        /// Message number.
        message: u32,
        /// Unique-id string.
        uid: String,
    },
    /// End of the UIDL listing.
    UidlEnd,
    /// Response to `UIDL n`.
    UidlSingle {
        /// Message number.
        message: u32,
        /// Unique-id string.
        uid: String,
    },
    /// RETR accepted; body follows (streamed separately via
    /// [`super::unstuff::Pop3DotUnstuffer`], not through this lexer).
    RetrStart,
    /// TOP accepted; body follows.
    TopStart,
    /// STLS accepted; the endpoint drives the TLS handshake next.
    StlsOk,
    /// DELE accepted.
    DeleOk,
    /// RSET accepted.
    RsetOk,
    /// NOOP accepted.
    NoopOk,
    /// QUIT accepted.
    QuitOk,
    /// `-ERR` for the shape that was expected. There's no protocol-defined
    /// structure to further parse the diagnostic text into (unlike
    /// decorative `+OK` text, which is never stored at all), so it's kept
    /// as-is — bounded, and genuinely useful to the caller.
    Err {
        /// The server's diagnostic text.
        message: String,
    },
}

// ── Internal FSM ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Prefix {
    Start,
    Plus,
    PlusO,
    PlusOk,
    Minus,
    MinusE,
    MinusEr,
    MinusErr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NumberSlot {
    StatCount,
    StatOctets,
    ListSingleMessage,
    ListSingleOctets,
    ListEntryMessage,
    ListEntryOctets,
    UidlSingleMessage,
    UidlEntryMessage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Delim {
    Space,
    Cr,
}

/// What the current field is, and what happens once its delimiter arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    /// Decorative text: scan for CRLF, never store (greeting also watches
    /// for a `<...>` challenge token via `self.in_challenge`).
    SkipToEol,
    /// A numeric field ending at `end` (SP or CR) — no other byte
    /// (including the "wrong" delimiter) is accepted, so a reply that
    /// doesn't match the expected grammar errors immediately rather than
    /// silently reinterpreting later bytes as this field's content.
    Number { which: NumberSlot, end: Delim },
    /// A UIDL unique-id (bounded text) ending at CR.
    UniqueId { message: u32 },
    /// An `-ERR` diagnostic (bounded text) ending at CR.
    ErrorText,
    /// A `+` SASL continuation's base64 text (bounded) ending at CR.
    ContinuationText,
    /// One CAPA entry line (bounded text) ending at CR.
    CapaLine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Matching `+OK` / `-ERR` / `+` at the start of a reply line.
    Prefix(Prefix),
    /// Reading one field (see [`Field`]).
    Reading(Field),
    /// Saw the field's own CR terminator; expect LF next to complete it.
    /// Also used directly (with no field bytes read) for a bare `+OK\r\n` /
    /// `-ERR\r\n` / `+\r\n` with no argument at all.
    FieldCr(Field),
    /// At the start of a multiline-listing line: first byte decides
    /// whether this is the `.` terminator or a content line.
    ListingLineStart,
    /// Saw `.` as the first byte of a listing line; a following CR
    /// continues toward the terminator, anything else means this was a
    /// dot-stuffed content line (RFC 1939 §3) whose real first byte
    /// follows.
    ListingDotSeen,
    /// Saw `.` CR while confirming the terminator; expect LF.
    ListingDotCr,
}

/// Incremental POP3 client-reply parser. See the module docs.
pub struct Pop3ReplyLexer {
    shape: Pop3ReplyShape,
    state: State,
    /// Numeric field accumulator (reset per field).
    number: u64,
    /// Bounded scratch for the field kinds that keep text (`-ERR` text,
    /// AUTH continuation text, UIDL unique-id, CAPA line).
    text: String,
    /// Greeting only: currently inside a `<...>` APOP challenge token.
    in_challenge: bool,
    /// Greeting only: a challenge token has already been captured this
    /// line (ignore any further `<...>` rather than overwriting it).
    challenge_captured: bool,
    /// Bounded scratch for the in-progress challenge token.
    challenge: String,
    /// Staged value for entries with two fields (message number, waiting
    /// for its paired octets/uid).
    pending_message: Option<u32>,
    /// CAPA entries accumulated across the listing (small, bounded by a
    /// real server's capability count, not message count).
    capa_lines: Vec<String>,
}

impl Default for Pop3ReplyLexer {
    fn default() -> Self {
        Self::new()
    }
}

impl Pop3ReplyLexer {
    /// Create a new lexer. Call [`Self::expect`] before feeding the bytes
    /// of each reply.
    pub fn new() -> Self {
        Self {
            shape: Pop3ReplyShape::Greeting,
            state: State::Prefix(Prefix::Start),
            number: 0,
            text: String::new(),
            in_challenge: false,
            challenge_captured: false,
            challenge: String::new(),
            pending_message: None,
            capa_lines: Vec::new(),
        }
    }

    /// Tell the lexer what shape the next reply takes. Call this right
    /// after sending the corresponding command.
    pub fn expect(&mut self, shape: Pop3ReplyShape) {
        self.shape = shape;
        self.state = State::Prefix(Prefix::Start);
        self.pending_message = None;
        self.in_challenge = false;
        self.challenge_captured = false;
        self.challenge.clear();
    }

    /// Feed inbound bytes. Returns parsed events; advances `data` past
    /// consumed bytes. On `RetrStart`/`TopStart`, remaining bytes in `data`
    /// belong to the message body (route them to
    /// [`super::unstuff::Pop3DotUnstuffer`], not back into this lexer).
    pub fn feed(&mut self, data: &mut &[u8]) -> Result<Vec<Pop3Event>, Pop3Error> {
        let mut events = Vec::new();
        let mut i = 0usize;
        let bytes = *data;

        while i < bytes.len() {
            let b = bytes[i];
            i += 1;

            if let Some(event) = self.push_byte(b)? {
                let is_body_start = matches!(event, Pop3Event::RetrStart | Pop3Event::TopStart);
                events.push(event);
                if is_body_start {
                    *data = &bytes[i..];
                    return Ok(events);
                }
            }
        }

        *data = &bytes[i..];
        Ok(events)
    }

    fn push_byte(&mut self, b: u8) -> Result<Option<Pop3Event>, Pop3Error> {
        match self.state {
            State::Prefix(p) => self.push_prefix_byte(p, b),
            State::Reading(field) => self.push_field_byte(field, b),
            State::FieldCr(field) => {
                if b == b'\n' {
                    self.finish_field(field)
                } else {
                    Err(Pop3Error::Parse("malformed POP3 reply: expected LF after CR".into()))
                }
            }
            State::ListingLineStart => {
                if b == b'.' {
                    self.state = State::ListingDotSeen;
                    Ok(None)
                } else {
                    self.begin_listing_content_line()?;
                    self.push_byte(b)
                }
            }
            State::ListingDotSeen => {
                if b == b'\r' {
                    self.state = State::ListingDotCr;
                    Ok(None)
                } else {
                    // Dot-stuffing (RFC 1939 §3): a line whose real content
                    // starts with '.' arrives with the leading dot doubled.
                    // The stuffing dot is already consumed; `b` is the
                    // first genuine content byte.
                    self.begin_listing_content_line()?;
                    self.push_byte(b)
                }
            }
            State::ListingDotCr => {
                if b == b'\n' {
                    self.finish_listing()
                } else {
                    Err(Pop3Error::Parse("malformed POP3 reply: expected LF after CR".into()))
                }
            }
        }
    }

    // ── Prefix matching ───────────────────────────────────────────────

    fn push_prefix_byte(&mut self, p: Prefix, b: u8) -> Result<Option<Pop3Event>, Pop3Error> {
        match (p, b) {
            (Prefix::Start, b'+') => {
                self.state = State::Prefix(Prefix::Plus);
                Ok(None)
            }
            (Prefix::Start, b'-') => {
                self.state = State::Prefix(Prefix::Minus);
                Ok(None)
            }
            (Prefix::Plus, b'O') => {
                self.state = State::Prefix(Prefix::PlusO);
                Ok(None)
            }
            (Prefix::Plus, b' ') | (Prefix::Plus, b'\r') => {
                self.begin_continuation(b == b'\r');
                Ok(None)
            }
            (Prefix::PlusO, b'K') => {
                self.state = State::Prefix(Prefix::PlusOk);
                Ok(None)
            }
            (Prefix::PlusOk, b' ') | (Prefix::PlusOk, b'\r') => self.begin_ok(b == b'\r'),
            (Prefix::Minus, b'E') => {
                self.state = State::Prefix(Prefix::MinusE);
                Ok(None)
            }
            (Prefix::MinusE, b'R') => {
                self.state = State::Prefix(Prefix::MinusEr);
                Ok(None)
            }
            (Prefix::MinusEr, b'R') => {
                self.state = State::Prefix(Prefix::MinusErr);
                Ok(None)
            }
            (Prefix::MinusErr, b' ') | (Prefix::MinusErr, b'\r') => {
                self.text.clear();
                self.state = if b == b'\r' {
                    State::FieldCr(Field::ErrorText)
                } else {
                    State::Reading(Field::ErrorText)
                };
                Ok(None)
            }
            _ => Err(Pop3Error::Parse(format!(
                "unexpected POP3 reply prefix byte {b:#04x} in state {p:?}"
            ))),
        }
    }

    /// Bare `+` continuation prefix fully matched. `at_cr` is `true` if
    /// the delimiter was CR (empty continuation) rather than SP.
    fn begin_continuation(&mut self, at_cr: bool) {
        self.text.clear();
        self.state = if at_cr {
            State::FieldCr(Field::ContinuationText)
        } else {
            State::Reading(Field::ContinuationText)
        };
    }

    /// `+OK` prefix fully matched. `at_cr` is `true` if the delimiter was
    /// CR (no argument at all) rather than SP.
    fn begin_ok(&mut self, at_cr: bool) -> Result<Option<Pop3Event>, Pop3Error> {
        let field = match self.shape {
            Pop3ReplyShape::Greeting
            | Pop3ReplyShape::Capa
            | Pop3ReplyShape::User
            | Pop3ReplyShape::Pass
            | Pop3ReplyShape::Apop
            | Pop3ReplyShape::Auth
            | Pop3ReplyShape::Stls
            | Pop3ReplyShape::Dele
            | Pop3ReplyShape::Rset
            | Pop3ReplyShape::Noop
            | Pop3ReplyShape::Quit
            | Pop3ReplyShape::Retr
            | Pop3ReplyShape::Top
            | Pop3ReplyShape::ListAll
            | Pop3ReplyShape::UidlAll => Field::SkipToEol,
            Pop3ReplyShape::Stat => Field::Number { which: NumberSlot::StatCount, end: Delim::Space },
            Pop3ReplyShape::ListSingle => {
                Field::Number { which: NumberSlot::ListSingleMessage, end: Delim::Space }
            }
            Pop3ReplyShape::UidlSingle => {
                Field::Number { which: NumberSlot::UidlSingleMessage, end: Delim::Space }
            }
        };

        if at_cr {
            // "+OK\r\n" with no argument at all.
            match field {
                Field::SkipToEol => {
                    // Valid: an empty argument. Wait for LF like any other
                    // field whose own CR terminator just arrived.
                    self.state = State::FieldCr(field);
                    Ok(None)
                }
                Field::Number { which, .. } => Err(Pop3Error::Parse(format!(
                    "POP3 reply missing required numeric field ({which:?})"
                ))),
                _ => unreachable!("begin_ok only ever selects SkipToEol or Number"),
            }
        } else {
            // SP consumed by the prefix match above; now read the field's
            // actual content starting at the next byte.
            self.number = 0;
            self.state = State::Reading(field);
            Ok(None)
        }
    }

    // ── Field accumulation ────────────────────────────────────────────

    fn push_field_byte(&mut self, field: Field, b: u8) -> Result<Option<Pop3Event>, Pop3Error> {
        match field {
            Field::SkipToEol => {
                if self.shape == Pop3ReplyShape::Greeting && !self.challenge_captured {
                    if self.in_challenge {
                        if b == b'>' {
                            self.challenge.push('>');
                            self.in_challenge = false;
                            self.challenge_captured = true;
                            return Ok(None);
                        } else if b != b'\r' {
                            // Captured with its delimiting brackets, ready
                            // to hand to ContentIdParser::parse_str as-is.
                            if self.challenge.len() < MAX_CHALLENGE_LEN {
                                self.challenge.push(b as char);
                            } else {
                                // Runaway token: abandon capture, keep skipping.
                                self.in_challenge = false;
                                self.challenge.clear();
                            }
                            return Ok(None);
                        } else {
                            // Unterminated challenge; abandon it and fall
                            // through to normal CR handling below.
                            self.in_challenge = false;
                            self.challenge.clear();
                        }
                    } else if b == b'<' {
                        self.in_challenge = true;
                        self.challenge.clear();
                        self.challenge.push('<');
                        return Ok(None);
                    }
                }
                if b == b'\r' {
                    self.state = State::FieldCr(field);
                }
                Ok(None)
            }
            Field::Number { which, end } => {
                match (b, end) {
                    (b' ', Delim::Space) => self.finish_field(field),
                    (b'\r', Delim::Cr) => {
                        self.state = State::FieldCr(field);
                        Ok(None)
                    }
                    (d, _) if d.is_ascii_digit() => {
                        self.push_digit(d)?;
                        Ok(None)
                    }
                    _ => Err(Pop3Error::Parse(format!(
                        "unexpected byte {b:#04x} in POP3 numeric field ({which:?})"
                    ))),
                }
            }
            Field::UniqueId { .. } | Field::ErrorText | Field::ContinuationText | Field::CapaLine => {
                if b == b'\r' {
                    self.state = State::FieldCr(field);
                    return Ok(None);
                }
                if self.text.len() >= MAX_REPLY_LINE {
                    return Err(Pop3Error::Parse("POP3 reply field too long".into()));
                }
                self.text.push(b as char);
                Ok(None)
            }
        }
    }

    fn push_digit(&mut self, b: u8) -> Result<(), Pop3Error> {
        let d = u64::from(b - b'0');
        self.number = self
            .number
            .checked_mul(10)
            .and_then(|n| n.checked_add(d))
            .ok_or_else(|| Pop3Error::Parse("POP3 numeric field overflow".into()))?;
        Ok(())
    }

    /// Called once a field's terminator has been fully consumed (its own
    /// CR *and* the following LF, or — for a space-delimited field — just
    /// the space). Every arm must explicitly set `self.state`: either
    /// [`State::Prefix`] (this reply is complete) or a continuation state
    /// (more of this reply follows on the same or a subsequent line).
    fn finish_field(&mut self, field: Field) -> Result<Option<Pop3Event>, Pop3Error> {
        match field {
            Field::SkipToEol => {
                let event = match self.shape {
                    Pop3ReplyShape::Greeting => {
                        let challenge = if self.challenge_captured {
                            // Already captured with its `<...>` brackets.
                            ContentIdParser::parse_str(&self.challenge)
                        } else {
                            None
                        };
                        self.challenge.clear();
                        self.state = State::Prefix(Prefix::Start);
                        Some(Pop3Event::ServerGreeting { apop_challenge: challenge })
                    }
                    Pop3ReplyShape::User => {
                        self.state = State::Prefix(Prefix::Start);
                        Some(Pop3Event::UserOk)
                    }
                    Pop3ReplyShape::Pass | Pop3ReplyShape::Apop | Pop3ReplyShape::Auth => {
                        self.state = State::Prefix(Prefix::Start);
                        Some(Pop3Event::Authenticated)
                    }
                    Pop3ReplyShape::Stls => {
                        self.state = State::Prefix(Prefix::Start);
                        Some(Pop3Event::StlsOk)
                    }
                    Pop3ReplyShape::Dele => {
                        self.state = State::Prefix(Prefix::Start);
                        Some(Pop3Event::DeleOk)
                    }
                    Pop3ReplyShape::Rset => {
                        self.state = State::Prefix(Prefix::Start);
                        Some(Pop3Event::RsetOk)
                    }
                    Pop3ReplyShape::Noop => {
                        self.state = State::Prefix(Prefix::Start);
                        Some(Pop3Event::NoopOk)
                    }
                    Pop3ReplyShape::Quit => {
                        self.state = State::Prefix(Prefix::Start);
                        Some(Pop3Event::QuitOk)
                    }
                    Pop3ReplyShape::Retr => {
                        self.state = State::Prefix(Prefix::Start);
                        Some(Pop3Event::RetrStart)
                    }
                    Pop3ReplyShape::Top => {
                        self.state = State::Prefix(Prefix::Start);
                        Some(Pop3Event::TopStart)
                    }
                    Pop3ReplyShape::ListAll => {
                        self.state = State::ListingLineStart;
                        Some(Pop3Event::ListStart)
                    }
                    Pop3ReplyShape::UidlAll => {
                        self.state = State::ListingLineStart;
                        Some(Pop3Event::UidlStart)
                    }
                    Pop3ReplyShape::Capa => {
                        self.capa_lines.clear();
                        self.state = State::ListingLineStart;
                        None
                    }
                    Pop3ReplyShape::Stat
                    | Pop3ReplyShape::ListSingle
                    | Pop3ReplyShape::UidlSingle => {
                        unreachable!("numeric shapes never select Field::SkipToEol")
                    }
                };
                Ok(event)
            }
            Field::Number { which, .. } => self.finish_number(which),
            Field::UniqueId { message } => {
                let uid = std::mem::take(&mut self.text);
                let event = if matches!(self.shape, Pop3ReplyShape::UidlSingle) {
                    Pop3Event::UidlSingle { message, uid }
                } else {
                    Pop3Event::UidlEntry { message, uid }
                };
                self.state = if matches!(self.shape, Pop3ReplyShape::UidlAll) {
                    State::ListingLineStart
                } else {
                    State::Prefix(Prefix::Start)
                };
                Ok(Some(event))
            }
            Field::ErrorText => {
                let message = std::mem::take(&mut self.text);
                self.state = State::Prefix(Prefix::Start);
                Ok(Some(Pop3Event::Err { message }))
            }
            Field::ContinuationText => {
                let text = std::mem::take(&mut self.text);
                let data = base64::decode(&text).map_err(|()| {
                    Pop3Error::Parse("bad base64 in SASL continuation".into())
                })?;
                self.state = State::Prefix(Prefix::Start);
                Ok(Some(Pop3Event::AuthChallenge { data }))
            }
            Field::CapaLine => {
                let line = std::mem::take(&mut self.text);
                self.capa_lines.push(line);
                self.state = State::ListingLineStart;
                Ok(None)
            }
        }
    }

    fn finish_number(&mut self, which: NumberSlot) -> Result<Option<Pop3Event>, Pop3Error> {
        let n = self.number;
        self.number = 0;
        match which {
            NumberSlot::StatCount => {
                self.pending_message = Some(n as u32);
                self.state =
                    State::Reading(Field::Number { which: NumberSlot::StatOctets, end: Delim::Cr });
                Ok(None)
            }
            NumberSlot::StatOctets => {
                let count = self.pending_message.take().unwrap_or(0);
                self.state = State::Prefix(Prefix::Start);
                Ok(Some(Pop3Event::Stat { count, octets: n }))
            }
            NumberSlot::ListSingleMessage => {
                self.pending_message = Some(n as u32);
                self.state = State::Reading(Field::Number {
                    which: NumberSlot::ListSingleOctets,
                    end: Delim::Cr,
                });
                Ok(None)
            }
            NumberSlot::ListSingleOctets => {
                let message = self.pending_message.take().unwrap_or(0);
                self.state = State::Prefix(Prefix::Start);
                Ok(Some(Pop3Event::ListSingle { message, octets: n }))
            }
            NumberSlot::ListEntryMessage => {
                self.pending_message = Some(n as u32);
                self.state = State::Reading(Field::Number {
                    which: NumberSlot::ListEntryOctets,
                    end: Delim::Cr,
                });
                Ok(None)
            }
            NumberSlot::ListEntryOctets => {
                let message = self.pending_message.take().unwrap_or(0);
                self.state = State::ListingLineStart;
                Ok(Some(Pop3Event::ListEntry { message, octets: n }))
            }
            NumberSlot::UidlSingleMessage | NumberSlot::UidlEntryMessage => {
                let message = n as u32;
                self.text.clear();
                self.state = State::Reading(Field::UniqueId { message });
                Ok(None)
            }
        }
    }

    // ── Multiline listing (LIST / UIDL / CAPA) ────────────────────────

    fn begin_listing_content_line(&mut self) -> Result<(), Pop3Error> {
        match self.shape {
            Pop3ReplyShape::ListAll => {
                self.number = 0;
                self.state =
                    State::Reading(Field::Number { which: NumberSlot::ListEntryMessage, end: Delim::Space });
            }
            Pop3ReplyShape::UidlAll => {
                self.number = 0;
                self.state =
                    State::Reading(Field::Number { which: NumberSlot::UidlEntryMessage, end: Delim::Space });
            }
            Pop3ReplyShape::Capa => {
                self.text.clear();
                self.state = State::Reading(Field::CapaLine);
            }
            _ => return Err(Pop3Error::Parse("unexpected listing line outside LIST/UIDL/CAPA".into())),
        }
        Ok(())
    }

    fn finish_listing(&mut self) -> Result<Option<Pop3Event>, Pop3Error> {
        self.state = State::Prefix(Prefix::Start);
        match self.shape {
            Pop3ReplyShape::ListAll => Ok(Some(Pop3Event::ListEnd)),
            Pop3ReplyShape::UidlAll => Ok(Some(Pop3Event::UidlEnd)),
            Pop3ReplyShape::Capa => {
                let caps = parse_capa(&self.capa_lines);
                self.capa_lines.clear();
                Ok(Some(Pop3Event::Capa(caps)))
            }
            _ => Err(Pop3Error::Parse("unexpected listing terminator".into())),
        }
    }
}

/// Parse RFC 2449 CAPA entries into structured [`Pop3Capabilities`].
fn parse_capa(lines: &[String]) -> Pop3Capabilities {
    let mut caps = Pop3Capabilities::default();
    for line in lines {
        let upper = line.to_ascii_uppercase();
        match upper.as_str() {
            "USER" => caps.user = true,
            "TOP" => caps.top = true,
            "UIDL" => caps.uidl = true,
            "STLS" => caps.stls = true,
            "PIPELINING" => caps.pipelining = true,
            "UTF8" => caps.utf8 = true,
            _ => {
                if upper.starts_with("SASL") {
                    for mech in line.get(4..).unwrap_or("").split_whitespace() {
                        caps.sasl_mechs.push(mech.to_ascii_uppercase());
                    }
                } else if upper.starts_with("IMPLEMENTATION") && line.len() > 14 {
                    caps.implementation = Some(line[14..].trim().to_string());
                }
            }
        }
    }
    caps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greeting_no_challenge() {
        let mut lex = Pop3ReplyLexer::new();
        lex.expect(Pop3ReplyShape::Greeting);
        let mut data: &[u8] = b"+OK POP3 server ready\r\n";
        let events = lex.feed(&mut data).unwrap();
        assert_eq!(events, vec![Pop3Event::ServerGreeting { apop_challenge: None }]);
        assert!(data.is_empty());
    }

    #[test]
    fn greeting_with_apop_challenge() {
        let mut lex = Pop3ReplyLexer::new();
        lex.expect(Pop3ReplyShape::Greeting);
        let mut data: &[u8] =
            b"+OK POP3 server ready <1829.1714285714@mail.example.com>\r\n";
        let events = lex.feed(&mut data).unwrap();
        assert_eq!(events.len(), 1);
        match &events[0] {
            Pop3Event::ServerGreeting { apop_challenge: Some(id) } => {
                assert_eq!(id.local_part(), "1829.1714285714");
                assert_eq!(id.domain(), "mail.example.com");
                assert_eq!(id.to_string(), "<1829.1714285714@mail.example.com>");
            }
            other => panic!("expected ServerGreeting with challenge, got {other:?}"),
        }
    }

    #[test]
    fn greeting_err() {
        let mut lex = Pop3ReplyLexer::new();
        lex.expect(Pop3ReplyShape::Greeting);
        let mut data: &[u8] = b"-ERR too many connections\r\n";
        let events = lex.feed(&mut data).unwrap();
        assert_eq!(events, vec![Pop3Event::Err { message: "too many connections".into() }]);
    }

    #[test]
    fn user_ok_and_err() {
        let mut lex = Pop3ReplyLexer::new();
        lex.expect(Pop3ReplyShape::User);
        let mut data: &[u8] = b"+OK send PASS\r\n";
        assert_eq!(lex.feed(&mut data).unwrap(), vec![Pop3Event::UserOk]);

        lex.expect(Pop3ReplyShape::User);
        let mut data2: &[u8] = b"-ERR no such user\r\n";
        assert_eq!(
            lex.feed(&mut data2).unwrap(),
            vec![Pop3Event::Err { message: "no such user".into() }]
        );
    }

    #[test]
    fn pass_apop_auth_all_produce_authenticated() {
        for shape in [Pop3ReplyShape::Pass, Pop3ReplyShape::Apop, Pop3ReplyShape::Auth] {
            let mut lex = Pop3ReplyLexer::new();
            lex.expect(shape);
            let mut data: &[u8] = b"+OK Mailbox open, 2 messages\r\n";
            assert_eq!(lex.feed(&mut data).unwrap(), vec![Pop3Event::Authenticated]);
        }
    }

    #[test]
    fn auth_continuation_decodes_base64() {
        let mut lex = Pop3ReplyLexer::new();
        lex.expect(Pop3ReplyShape::Auth);
        let mut data: &[u8] = b"+ YWJj\r\n";
        let events = lex.feed(&mut data).unwrap();
        assert_eq!(events, vec![Pop3Event::AuthChallenge { data: b"abc".to_vec() }]);
    }

    #[test]
    fn auth_bad_base64_errors() {
        let mut lex = Pop3ReplyLexer::new();
        lex.expect(Pop3ReplyShape::Auth);
        let mut data: &[u8] = b"+ not base64!!\r\n";
        assert!(lex.feed(&mut data).is_err());
    }

    #[test]
    fn stls_ok_and_unavailable() {
        let mut lex = Pop3ReplyLexer::new();
        lex.expect(Pop3ReplyShape::Stls);
        let mut data: &[u8] = b"+OK Begin TLS negotiation\r\n";
        assert_eq!(lex.feed(&mut data).unwrap(), vec![Pop3Event::StlsOk]);

        lex.expect(Pop3ReplyShape::Stls);
        let mut data2: &[u8] = b"-ERR TLS not available\r\n";
        assert_eq!(
            lex.feed(&mut data2).unwrap(),
            vec![Pop3Event::Err { message: "TLS not available".into() }]
        );
    }

    /// The user's exact walkthrough: "+OK 2" arrives, then " 3200\r\n" in a
    /// second chunk. Feeding a partial field must not error and must not
    /// require the whole line to be buffered-then-batch-parsed — the
    /// count digit(s) already accumulated in `self.number` (a bounded
    /// scratch value, not a growing line buffer) survive across the
    /// `feed()` call boundary.
    #[test]
    fn stat_split_across_chunks_like_the_walkthrough() {
        let mut lex = Pop3ReplyLexer::new();
        lex.expect(Pop3ReplyShape::Stat);

        let mut part1: &[u8] = b"+OK 2";
        let e1 = lex.feed(&mut part1).unwrap();
        assert!(e1.is_empty(), "no complete field yet: {e1:?}");
        assert!(part1.is_empty());

        let mut part2: &[u8] = b" 3200\r\n";
        let e2 = lex.feed(&mut part2).unwrap();
        assert_eq!(e2, vec![Pop3Event::Stat { count: 2, octets: 3200 }]);
    }

    #[test]
    fn stat_split_one_byte_at_a_time_matches_bulk_feed() {
        let mut bulk_lex = Pop3ReplyLexer::new();
        bulk_lex.expect(Pop3ReplyShape::Stat);
        let mut bulk: &[u8] = b"+OK 2 3200\r\n";
        let bulk_events = bulk_lex.feed(&mut bulk).unwrap();

        let mut drip_lex = Pop3ReplyLexer::new();
        drip_lex.expect(Pop3ReplyShape::Stat);
        let mut drip_events = Vec::new();
        for &b in b"+OK 2 3200\r\n" {
            let mut one: &[u8] = std::slice::from_ref(&b);
            drip_events.extend(drip_lex.feed(&mut one).unwrap());
        }
        assert_eq!(bulk_events, drip_events);
        assert_eq!(drip_events, vec![Pop3Event::Stat { count: 2, octets: 3200 }]);
    }

    #[test]
    fn stat_err() {
        let mut lex = Pop3ReplyLexer::new();
        lex.expect(Pop3ReplyShape::Stat);
        let mut data: &[u8] = b"-ERR mailbox locked\r\n";
        assert_eq!(
            lex.feed(&mut data).unwrap(),
            vec![Pop3Event::Err { message: "mailbox locked".into() }]
        );
    }

    #[test]
    fn stat_missing_fields_errors() {
        let mut lex = Pop3ReplyLexer::new();
        lex.expect(Pop3ReplyShape::Stat);
        let mut data: &[u8] = b"+OK\r\n";
        assert!(lex.feed(&mut data).is_err());
    }

    #[test]
    fn list_all_full_sequence() {
        let mut lex = Pop3ReplyLexer::new();
        lex.expect(Pop3ReplyShape::ListAll);
        let mut data: &[u8] = b"+OK 2 messages (3200 octets)\r\n1 1200\r\n2 2000\r\n.\r\n";
        let events = lex.feed(&mut data).unwrap();
        assert_eq!(
            events,
            vec![
                Pop3Event::ListStart,
                Pop3Event::ListEntry { message: 1, octets: 1200 },
                Pop3Event::ListEntry { message: 2, octets: 2000 },
                Pop3Event::ListEnd,
            ]
        );
        assert!(data.is_empty());
    }

    #[test]
    fn list_all_split_mid_entry() {
        let mut lex = Pop3ReplyLexer::new();
        lex.expect(Pop3ReplyShape::ListAll);
        let mut part1: &[u8] = b"+OK\r\n1 12";
        let e1 = lex.feed(&mut part1).unwrap();
        assert_eq!(e1, vec![Pop3Event::ListStart]);
        let mut part2: &[u8] = b"00\r\n.\r\n";
        let e2 = lex.feed(&mut part2).unwrap();
        assert_eq!(
            e2,
            vec![Pop3Event::ListEntry { message: 1, octets: 1200 }, Pop3Event::ListEnd]
        );
    }

    #[test]
    fn list_single() {
        let mut lex = Pop3ReplyLexer::new();
        lex.expect(Pop3ReplyShape::ListSingle);
        let mut data: &[u8] = b"+OK 2 200\r\n";
        assert_eq!(
            lex.feed(&mut data).unwrap(),
            vec![Pop3Event::ListSingle { message: 2, octets: 200 }]
        );

        lex.expect(Pop3ReplyShape::ListSingle);
        let mut data2: &[u8] = b"-ERR no such message\r\n";
        assert_eq!(
            lex.feed(&mut data2).unwrap(),
            vec![Pop3Event::Err { message: "no such message".into() }]
        );
    }

    #[test]
    fn uidl_all_and_single() {
        let mut lex = Pop3ReplyLexer::new();
        lex.expect(Pop3ReplyShape::UidlAll);
        let mut data: &[u8] = b"+OK\r\n1 whqtswO00WBw418f9t5JxYwZ\r\n2 QhdPYR:00WBw1Ph7x7\r\n.\r\n";
        let events = lex.feed(&mut data).unwrap();
        assert_eq!(
            events,
            vec![
                Pop3Event::UidlStart,
                Pop3Event::UidlEntry { message: 1, uid: "whqtswO00WBw418f9t5JxYwZ".into() },
                Pop3Event::UidlEntry { message: 2, uid: "QhdPYR:00WBw1Ph7x7".into() },
                Pop3Event::UidlEnd,
            ]
        );

        let mut lex2 = Pop3ReplyLexer::new();
        lex2.expect(Pop3ReplyShape::UidlSingle);
        let mut data2: &[u8] = b"+OK 2 QhdPYR:00WBw1Ph7x7\r\n";
        assert_eq!(
            lex2.feed(&mut data2).unwrap(),
            vec![Pop3Event::UidlSingle { message: 2, uid: "QhdPYR:00WBw1Ph7x7".into() }]
        );
    }

    #[test]
    fn capa_parses_into_capabilities() {
        let mut lex = Pop3ReplyLexer::new();
        lex.expect(Pop3ReplyShape::Capa);
        let mut data: &[u8] =
            b"+OK Capability list follows\r\nUSER\r\nTOP\r\nUIDL\r\nSTLS\r\nSASL PLAIN LOGIN\r\nIMPLEMENTATION Foo/1.0\r\n.\r\n";
        let events = lex.feed(&mut data).unwrap();
        assert_eq!(events.len(), 1);
        match &events[0] {
            Pop3Event::Capa(caps) => {
                assert!(caps.user);
                assert!(caps.top);
                assert!(caps.uidl);
                assert!(caps.stls);
                assert_eq!(caps.sasl_mechs, vec!["PLAIN", "LOGIN"]);
                assert_eq!(caps.implementation.as_deref(), Some("Foo/1.0"));
            }
            other => panic!("expected Capa, got {other:?}"),
        }
    }

    #[test]
    fn capa_dot_stuffed_entry() {
        // A (hypothetical) capability name starting with '.' must survive
        // RFC 1939 §3 dot-stuffing (doubled leading dot).
        let mut lex = Pop3ReplyLexer::new();
        lex.expect(Pop3ReplyShape::Capa);
        let mut data: &[u8] = b"+OK\r\n..FOO\r\n.\r\n";
        let events = lex.feed(&mut data).unwrap();
        match &events[0] {
            Pop3Event::Capa(caps) => {
                let _ = caps; // parse_capa doesn't recognize ".FOO"; just confirm no crash/error.
            }
            other => panic!("expected Capa, got {other:?}"),
        }
    }

    #[test]
    fn retr_and_top_start_leave_body_bytes_unconsumed() {
        let mut lex = Pop3ReplyLexer::new();
        lex.expect(Pop3ReplyShape::Retr);
        let mut data: &[u8] = b"+OK 1200 octets\r\nFrom: bob@example.com\r\n.\r\n";
        let events = lex.feed(&mut data).unwrap();
        assert_eq!(events, vec![Pop3Event::RetrStart]);
        assert_eq!(data, b"From: bob@example.com\r\n.\r\n");

        let mut lex2 = Pop3ReplyLexer::new();
        lex2.expect(Pop3ReplyShape::Top);
        let mut data2: &[u8] = b"+OK\r\nbody\r\n.\r\n";
        let events2 = lex2.feed(&mut data2).unwrap();
        assert_eq!(events2, vec![Pop3Event::TopStart]);
        assert_eq!(data2, b"body\r\n.\r\n");
    }

    #[test]
    fn retr_no_such_message() {
        let mut lex = Pop3ReplyLexer::new();
        lex.expect(Pop3ReplyShape::Retr);
        let mut data: &[u8] = b"-ERR no such message\r\n";
        assert_eq!(
            lex.feed(&mut data).unwrap(),
            vec![Pop3Event::Err { message: "no such message".into() }]
        );
    }

    #[test]
    fn dele_rset_noop_quit() {
        let cases: &[(Pop3ReplyShape, Pop3Event)] = &[
            (Pop3ReplyShape::Dele, Pop3Event::DeleOk),
            (Pop3ReplyShape::Rset, Pop3Event::RsetOk),
            (Pop3ReplyShape::Noop, Pop3Event::NoopOk),
            (Pop3ReplyShape::Quit, Pop3Event::QuitOk),
        ];
        for (shape, expected) in cases {
            let mut lex = Pop3ReplyLexer::new();
            lex.expect(*shape);
            let mut data: &[u8] = b"+OK done\r\n";
            assert_eq!(&lex.feed(&mut data).unwrap(), &vec![expected.clone()]);
        }
    }

    #[test]
    fn bare_ok_no_argument_is_valid_for_text_shapes() {
        let mut lex = Pop3ReplyLexer::new();
        lex.expect(Pop3ReplyShape::Noop);
        let mut data: &[u8] = b"+OK\r\n";
        assert_eq!(lex.feed(&mut data).unwrap(), vec![Pop3Event::NoopOk]);
    }

    #[test]
    fn overlong_error_text_errors_out() {
        let mut lex = Pop3ReplyLexer::new();
        lex.expect(Pop3ReplyShape::Noop);
        let mut junk = Vec::new();
        junk.extend_from_slice(b"-ERR ");
        junk.extend(std::iter::repeat(b'x').take(MAX_REPLY_LINE + 1));
        let mut data: &[u8] = &junk;
        assert!(lex.feed(&mut data).is_err());
    }

    #[test]
    fn decorative_text_after_ok_is_never_stored() {
        // A very long banner after +OK must not error even though
        // MAX_REPLY_LINE would reject that many bytes if it were being
        // buffered — because SkipToEol never buffers it.
        let mut lex = Pop3ReplyLexer::new();
        lex.expect(Pop3ReplyShape::Noop);
        let mut junk = Vec::new();
        junk.extend_from_slice(b"+OK ");
        junk.extend(std::iter::repeat(b'x').take(MAX_REPLY_LINE * 4));
        junk.extend_from_slice(b"\r\n");
        let mut data: &[u8] = &junk;
        assert_eq!(lex.feed(&mut data).unwrap(), vec![Pop3Event::NoopOk]);
    }
}
