// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Incremental, semantic IMAP client reply parser.
//!
//! [`ImapReplyLexer`] never buffers a whole response line into a growing
//! `Vec<u8>` and hands it to a string-based parser afterward — bytes are
//! recognised into structure (tag/sigil, status word, response-data type,
//! atoms, numbers, quoted strings) as they arrive, and the corresponding
//! [`ImapEvent`] is built up directly from that recognition.
//!
//! This goes a step further than Gumdrop's own IMAP client (which tokenises
//! only down to whole-line granularity and hands each line to a
//! string-based `IMAPResponse.parse`): here, `CAPABILITY`/`ENABLED`/`SEARCH`
//! token-and-number lists, `LIST`/`LSUB` entries, and `STATUS` item lists
//! are built token-by-token with no intermediate raw-line buffer, and
//! `FETCH` responses are walked attribute-by-attribute — recognised
//! attributes (`FLAGS`, `UID`, `RFC822.SIZE`, `MODSEQ`, literal-bearing
//! `BODY[...]`/`RFC822`/`RFC822.TEXT`/`RFC822.HEADER`) are parsed directly
//! into [`super::state::ImapFetchData`], while unrecognised substructure
//! (`ENVELOPE`, `BODYSTRUCTURE`, `INTERNALDATE`, bare `BODY`, …) is
//! skip-scanned by paren/bracket/quote depth rather than buffered, since
//! hopf doesn't expose that structurally today.
//!
//! A few naturally small, bounded, literal-free substructures — response
//! codes (`[COPYUID …]` etc.) and the rarely-used `NAMESPACE`/`QUOTA`/
//! `QUOTAROOT`/`ID` payloads — are captured into a bounded scratch buffer
//! and parsed once complete, the same convention SMTP uses for its
//! AUTH-challenge/queue-id text: never a growing whole-line buffer, but not
//! worth a bespoke incremental grammar either. (Truly unrecognised untagged
//! response types — future/vendor extensions hopf doesn't know about — are
//! scanned to the next CRLF without literal-marker detection; only the
//! response types hopf actually understands are guaranteed literal-safe.)
//!
//! IMAP's own grammar is self-describing (the leading word after `* `/tag
//! says what kind of response this is), so unlike POP3/SMTP/FTP there is no
//! `expect()` — the lexer doesn't need the caller to say what shape is in
//! flight.
//!
//! Literal octets (`{n}CRLF` followed by `n` raw bytes, RFC 9051 §4.3) are
//! streamed directly as [`ImapEvent::FetchLiteralData`] chunks — this was
//! already correct before this rewrite and is unchanged in spirit.

use super::error::ImapError;
use super::state::{ImapCapabilities, ImapFetchData, ImapListEntry, ImapStatusData};

/// Cap on one bounded scratch field (an atom, tag, quoted string, message
/// text, or response-code/NAMESPACE/QUOTA/ID payload) — large enough for
/// any legitimate token, small enough that a hostile/broken server can't
/// grow the lexer's memory without bound. Never applies to literal octets,
/// which stream directly.
pub const MAX_TOKEN: usize = 8 * 1024;

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

/// Semantic events emitted by [`ImapReplyLexer`]. Every variant carries
/// already-parsed data; the only "raw-ish" fields left are bounded,
/// naturally free-form text (response-code bodies, human-readable
/// messages) that hopf doesn't interpret further at the lexer level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImapEvent {
    /// `+ [text]`
    Continuation {
        /// Text after `+ ` (may be empty).
        text: String,
    },
    /// `tag OK|NO|BAD [code] text`
    Tagged {
        /// Command tag (e.g. `A001`).
        tag: String,
        /// Completion status.
        status: ImapStatus,
        /// Bracketed response code without `[]`, if present.
        code: Option<String>,
        /// Human-readable completion text.
        message: String,
    },
    /// Untagged `OK` (greeting, or a mid-session status update).
    UntaggedOk {
        /// Bracketed response code without `[]`, if present.
        code: Option<String>,
        /// Text after the code.
        text: String,
    },
    /// Untagged `NO`.
    UntaggedNo {
        /// Bracketed response code without `[]`, if present.
        code: Option<String>,
        /// Text after the code.
        text: String,
    },
    /// Untagged `BAD`.
    UntaggedBad {
        /// Bracketed response code without `[]`, if present.
        code: Option<String>,
        /// Text after the code.
        text: String,
    },
    /// `* BYE …` — server is closing the connection.
    Bye {
        /// Bracketed response code without `[]`, if present.
        code: Option<String>,
        /// Text after the code.
        text: String,
    },
    /// `* PREAUTH …` — greeting only, already-authenticated session.
    Preauth {
        /// Bracketed response code without `[]`, if present.
        code: Option<String>,
        /// Text after the code.
        text: String,
    },
    /// `* CAPABILITY …`, fully parsed.
    Capability(ImapCapabilities),
    /// One `* LIST`/`* LSUB` line, fully parsed.
    ListEntry(ImapListEntry),
    /// `* STATUS mailbox (…)`, fully parsed.
    StatusData(ImapStatusData),
    /// `* SEARCH n1 n2 …`.
    SearchNumbers(Vec<u32>),
    /// `* n EXISTS`.
    Exists(u32),
    /// `* n RECENT`.
    Recent(u32),
    /// `* n EXPUNGE`.
    Expunge(u32),
    /// `* FLAGS (…)` (SELECT/EXAMINE's mailbox-wide flags list).
    FlagsList(Vec<String>),
    /// A FETCH response's non-literal attributes, emitted once the
    /// top-level attribute list closes. Whether this is a genuine FETCH
    /// data response, an unsolicited flags update, or a STORE response is
    /// for the caller to decide (e.g. by checking whether only `flags` is
    /// populated) — mirroring how pending-command routing already worked.
    Fetch(ImapFetchData),
    /// A FETCH literal (`BODY[section]`/`RFC822`/`RFC822.TEXT`/
    /// `RFC822.HEADER`) is about to stream, bracketing the
    /// [`ImapEvent::FetchLiteralData`] chunks that follow.
    FetchLiteralBegin {
        /// The FETCH response's message sequence number.
        seq: u32,
        /// Section identifier: a `BODY[...]`'s bracket contents (e.g.
        /// `"HEADER"`, `"1.TEXT"`, `""` for the whole message), or the
        /// bare attribute name for `RFC822`/`RFC822.TEXT`/`RFC822.HEADER`.
        section: String,
        /// Total literal size in octets.
        size: u64,
    },
    /// FETCH literal octets (a `BODY[...]`/`RFC822`/… value), streamed as
    /// they arrive — never buffered.
    FetchLiteralData(Vec<u8>),
    /// The literal started by [`ImapEvent::FetchLiteralBegin`] is complete.
    FetchLiteralEnd {
        /// The FETCH response's message sequence number.
        seq: u32,
    },
    /// `* ENABLED …`.
    Enabled(Vec<String>),
    /// `* NAMESPACE …` (bounded-captured; caller parses with
    /// [`super::state::ImapNamespaceData::parse`]).
    Namespace(String),
    /// `* QUOTA …` (bounded-captured; caller parses with
    /// [`super::state::ImapQuotaData::parse`]).
    Quota(String),
    /// `* QUOTAROOT …` (bounded-captured; caller parses with
    /// [`super::state::ImapQuotaRootData::parse`]).
    QuotaRoot(String),
    /// `* ID …` (bounded-captured; caller parses with the `ID` params
    /// helper).
    IdParams(String),
    /// Unrecognised untagged response — a server extension hopf doesn't
    /// know about. The line has already been consumed.
    Other,
}

// ── Internal FSM ─────────────────────────────────────────────────────────────

/// What a response-text tail (`[code] text`) belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RespCtx {
    TaggedOk,
    TaggedNo,
    TaggedBad,
    UntaggedOk,
    UntaggedNo,
    UntaggedBad,
    Bye,
    Preauth,
}

/// Which space-separated list we're reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenListUse {
    Capability,
    Enabled,
}

/// Which bounded-capture payload we're accumulating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BoundedKind {
    Namespace,
    Quota,
    QuotaRoot,
    Id,
}

/// A recognised STATUS item name, or `Other` for one we skip the value of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StatusItem {
    Messages,
    Recent,
    UidNext,
    UidValidity,
    Unseen,
    Deleted,
    Size,
    HighestModseq,
    Other,
}

/// A recognised numeric FETCH attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FetchNumField {
    Uid,
    Size,
}

/// What kind of bracketed list `FetchListCloseCr` (a shared "expect CRLF
/// after the closing `)`" state) is closing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListCloseKind {
    Fetch,
    StatusData,
    ListEntry,
}

/// What to emit once the LF completing a CRLF just seen arrives.
#[derive(Debug, Clone, PartialEq, Eq)]
enum AwaitLfKind {
    Continuation,
    Tagged { status: ImapStatus, code: Option<String> },
    UntaggedOk { code: Option<String> },
    UntaggedNo { code: Option<String> },
    UntaggedBad { code: Option<String> },
    Bye { code: Option<String> },
    Preauth { code: Option<String> },
    Capability,
    Enabled,
    SearchNumbers,
    Other,
    Exists(u32),
    Recent(u32),
    Expunge(u32),
    Flags,
    ListEntry,
    Fetch,
    StatusData,
    Bounded(BoundedKind),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum State {
    /// Reading the first word: a tag, `*`, or `+`.
    Word1,
    /// Consumed `* `; reading the second word.
    UntaggedAfterSigil,
    /// Second word was numeric; consumed the following SP; reading the
    /// third word (`EXISTS`/`RECENT`/`EXPUNGE`/`FETCH`).
    UntaggedNumSeen { n: u32 },
    /// Consumed `tag `; reading the status word.
    TaggedAfterTag,
    /// `+`; reading continuation text (bounded) to CRLF.
    Continuation,
    /// About to see an optional `[code]` then text.
    RespTextStart { ctx: RespCtx },
    /// Inside `[...]`, quote/depth aware; content kept in `text`.
    RespCode { ctx: RespCtx, depth: i32, in_quote: bool, escape: bool },
    /// Consumed the closing `]`; expect SP then message, or CRLF directly.
    RespCodeGap { ctx: RespCtx },
    /// Free text to CRLF.
    RespMessage { ctx: RespCtx },
    /// Space-separated atom list to CRLF (`CAPABILITY` / `ENABLED`).
    TokenList { use_: TokenListUse },
    /// Space-separated numbers to CRLF (`SEARCH`).
    SearchNums,
    /// Optional `(MODSEQ n)`-style trailer after SEARCH numbers, or the
    /// remainder of an unrecognised line — quote/depth aware skip.
    SearchTrailerSkip { depth: i32, in_quote: bool, escape: bool },
    /// Discard remaining bytes of an unrecognised untagged line to CRLF.
    SkipToCrlf,
    /// `(` expected (`LIST`/`LSUB` attribute list).
    ListAttrsOpen,
    /// Inside the attribute list, quote/depth aware.
    ListAttrsBody { depth: i32, in_quote: bool, escape: bool },
    /// Expect SP after the attribute list.
    ListPostAttrs,
    /// Reading the delimiter: quoted char, or `NIL`.
    ListDelimStart,
    /// Reading the one delimiter char inside quotes (escape pending).
    ListDelimQuotedChar { escape: bool },
    /// Expect the closing `"` after the delimiter char.
    ListDelimQuotedClose,
    /// Matching literal `NIL` for the delimiter (chars matched so far).
    ListDelimNil { matched: u8 },
    /// Expect SP between delimiter and mailbox name.
    ListPreName,
    /// Deciding quoted-vs-atom for the mailbox name.
    ListNameStart,
    /// Inside a quoted mailbox name.
    ListNameQuoted { escape: bool },
    /// Reading an unquoted mailbox name atom.
    ListNameAtom,
    /// Deciding quoted-vs-atom for STATUS's mailbox name.
    StatusMailboxStart,
    /// Inside a quoted STATUS mailbox name.
    StatusMailboxQuoted { escape: bool },
    /// Reading an unquoted STATUS mailbox name atom.
    StatusMailboxAtom,
    /// After a quoted STATUS mailbox name: expect SP.
    StatusPostMailbox,
    /// `(` expected (STATUS item list).
    StatusItemsOpen,
    /// Reading a STATUS item name.
    StatusItemName,
    /// Reading a STATUS item's numeric value.
    StatusItemValue { item: StatusItem },
    /// `(` expected after `n FETCH`.
    FetchOpenParen,
    /// At the top of the attribute list: expect `)` (done) or an attribute
    /// name.
    FetchAttrNameStart,
    /// Reading an attribute name atom.
    FetchAttrName,
    /// Reading a numeric attribute's value (`UID` / `RFC822.SIZE`).
    FetchNumberValue { field: FetchNumField },
    /// `(` expected (`MODSEQ`'s value is `(n)`).
    FetchModseqOpen,
    /// Reading `MODSEQ`'s numeric value.
    FetchModseqValue,
    /// `)` expected to close `MODSEQ (n)`.
    FetchModseqClose,
    /// `(` expected (`FLAGS`'s value).
    FetchFlagsOpen,
    /// Reading `FLAGS`'s value (depth 1 = inside the list).
    FetchFlagsBody { depth: i32 },
    /// Reading a `BODY[section]`-style bracketed section spec into
    /// `fetch_section` (used to attribute the literal that follows).
    FetchBodySection,
    /// After the section spec closes: expect `<partial>` or the value.
    FetchAfterSection,
    /// Reading (and discarding) `<origin>` digits.
    FetchPartialOrigin,
    /// Expect SP after the closing `>` of `<origin>`.
    FetchAfterPartial,
    /// Expect the body value: `NIL`, a quoted string, or a literal marker.
    FetchBodyValueStart,
    /// Matching literal `NIL` for a body value (chars matched so far).
    FetchBodyNilTail { matched: u8 },
    /// Skipping a quoted body value (rare, but grammar allows it).
    FetchBodyQuotedSkip { escape: bool },
    /// Reading a literal size marker's digits (`{n` or `{n+`).
    FetchLiteralMarker,
    /// Consumed `}`; expect the CR of the marker's terminating CRLF.
    FetchLiteralCr,
    /// Consumed the marker's CR; expect its LF, then literal bytes begin.
    FetchLiteralLf,
    /// Streaming literal octets (count in `literal_remaining`); handled by
    /// [`ImapReplyLexer::feed`] directly, not `feed_byte`.
    FetchLiteral,
    /// An unrecognised attribute's value — skip-scanned by depth.
    FetchSkipValue { depth: i32, in_quote: bool, escape: bool },
    /// Just closed a value: expect SP (next attribute) or `)` (list done).
    FetchAfterValue,
    /// `)` closed the FETCH list: expect CRLF.
    FetchListCloseCr,
    /// `)` closed the top-level `* FLAGS (…)` list: expect CRLF.
    FlagsListCloseCr,
    /// Bounded whole-payload capture (`NAMESPACE`/`QUOTA`/`QUOTAROOT`/`ID`).
    BoundedPayload { kind: BoundedKind },
    /// Saw CR; waiting for the completing LF, then emit `kind`'s event.
    AwaitLf(AwaitLfKind),
}

/// Incremental IMAP client-reply parser. See the module docs.
pub struct ImapReplyLexer {
    state: State,
    /// Bounded scratch for the current atom/number/tag.
    word: Vec<u8>,
    /// Bounded scratch for the current quoted-string/message/code text.
    text: Vec<u8>,
    /// The tag of the response currently being parsed (tagged completions
    /// only).
    tag: String,
    /// A just-completed response code, held while the message text after
    /// it is read into `text`.
    code: Option<String>,
    literal_remaining: u64,
    caps: ImapCapabilities,
    list_entry: ImapListEntry,
    status_data: ImapStatusData,
    fetch_data: ImapFetchData,
    search_nums: Vec<u32>,
    tokens: Vec<String>,
    /// Which event `FetchListCloseCr` should emit once CRLF completes.
    list_close_kind: Option<ListCloseKind>,
    /// Whether the `FLAGS` value currently being read via
    /// `FetchFlagsOpen`/`FetchFlagsBody` is a FETCH attribute (goes into
    /// `fetch_data.flags`) or the top-level SELECT/EXAMINE `* FLAGS (…)`
    /// response (emits `ImapEvent::FlagsList`) — both reuse the same
    /// states since the grammar is identical.
    flags_is_fetch_attr: bool,
    /// Bounded scratch for the section identifier of the value about to be
    /// read: a `BODY[section]`'s bracket contents (e.g. `"HEADER"`,
    /// `"1.TEXT"`, `""` for the whole message), or the bare attribute name
    /// for `RFC822`/`RFC822.TEXT`/`RFC822.HEADER`. Read by
    /// `FetchLiteralBegin` once a literal marker for this value is seen.
    fetch_section: Vec<u8>,
}

impl Default for ImapReplyLexer {
    fn default() -> Self {
        Self::new()
    }
}

impl ImapReplyLexer {
    /// Create a new lexer, ready for the first response line.
    pub fn new() -> Self {
        Self {
            state: State::Word1,
            word: Vec::with_capacity(32),
            text: Vec::with_capacity(64),
            tag: String::new(),
            code: None,
            literal_remaining: 0,
            caps: ImapCapabilities::default(),
            list_entry: ImapListEntry::default(),
            status_data: ImapStatusData::default(),
            fetch_data: ImapFetchData::default(),
            search_nums: Vec::new(),
            tokens: Vec::new(),
            list_close_kind: None,
            flags_is_fetch_attr: false,
            fetch_section: Vec::with_capacity(16),
        }
    }

    /// Whether the lexer is currently streaming a FETCH literal's octets.
    pub fn in_literal(&self) -> bool {
        matches!(self.state, State::FetchLiteral)
    }

    /// Feed inbound bytes, returning every event completed so far.
    /// Advances `data` past every byte consumed.
    pub fn feed(&mut self, data: &mut &[u8]) -> Result<Vec<ImapEvent>, ImapError> {
        let mut events = Vec::new();
        let mut rest = *data;
        while let Some(&b) = rest.first() {
            // Literal streaming consumes as many bytes as possible in one
            // shot rather than one byte at a time.
            if let State::FetchLiteral = self.state {
                let take = rest.len().min(self.literal_remaining as usize);
                let chunk = rest[..take].to_vec();
                rest = &rest[take..];
                self.literal_remaining -= take as u64;
                if !chunk.is_empty() {
                    self.fetch_data.body.extend_from_slice(&chunk);
                    events.push(ImapEvent::FetchLiteralData(chunk));
                }
                if self.literal_remaining == 0 {
                    self.state = State::FetchAfterValue;
                    events.push(ImapEvent::FetchLiteralEnd { seq: self.fetch_data.seq });
                }
                continue;
            }
            rest = &rest[1..];
            if let Some(event) = self.feed_byte(b)? {
                events.push(event);
            }
        }
        *data = rest;
        Ok(events)
    }

    // ── bounded scratch helpers ─────────────────────────────────────────

    fn push_word(&mut self, b: u8) -> Result<(), ImapError> {
        if self.word.len() >= MAX_TOKEN {
            return Err(ImapError::Parse("IMAP token too long".into()));
        }
        self.word.push(b);
        Ok(())
    }

    fn push_text(&mut self, b: u8) -> Result<(), ImapError> {
        if self.text.len() >= MAX_TOKEN {
            return Err(ImapError::Parse("IMAP text field too long".into()));
        }
        self.text.push(b);
        Ok(())
    }

    fn take_word(&mut self) -> String {
        String::from_utf8_lossy(&std::mem::take(&mut self.word)).into_owned()
    }

    fn take_text(&mut self) -> String {
        String::from_utf8_lossy(&std::mem::take(&mut self.text)).into_owned()
    }

    // ── top-level dispatch ──────────────────────────────────────────────

    fn feed_byte(&mut self, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        // Clone rather than `mem::replace` with a placeholder: a handler
        // that doesn't explicitly transition `self.state` (still
        // accumulating a token) must leave it exactly as it was, not
        // silently revert to `Word1`.
        let state = self.state.clone();
        match state {
            State::Word1 => self.on_word1(b),
            State::UntaggedAfterSigil => self.on_untagged_after_sigil(b),
            State::UntaggedNumSeen { n } => self.on_untagged_num_seen(n, b),
            State::TaggedAfterTag => self.on_tagged_after_tag(b),
            State::Continuation => self.on_continuation(b),
            State::RespTextStart { ctx } => self.on_resp_text_start(ctx, b),
            State::RespCode { ctx, depth, in_quote, escape } => {
                self.on_resp_code(ctx, depth, in_quote, escape, b)
            }
            State::RespCodeGap { ctx } => self.on_resp_code_gap(ctx, b),
            State::RespMessage { ctx } => self.on_resp_message(ctx, b),
            State::TokenList { use_ } => self.on_token_list(use_, b),
            State::SearchNums => self.on_search_nums(b),
            State::SearchTrailerSkip { depth, in_quote, escape } => {
                self.on_search_trailer_skip(depth, in_quote, escape, b)
            }
            State::SkipToCrlf => self.on_skip_to_crlf(b),
            State::ListAttrsOpen => self.on_list_attrs_open(b),
            State::ListAttrsBody { depth, in_quote, escape } => {
                self.on_list_attrs_body(depth, in_quote, escape, b)
            }
            State::ListPostAttrs => self.on_list_post_attrs(b),
            State::ListDelimStart => self.on_list_delim_start(b),
            State::ListDelimQuotedChar { escape } => self.on_list_delim_quoted_char(escape, b),
            State::ListDelimQuotedClose => self.on_list_delim_quoted_close(b),
            State::ListDelimNil { matched } => self.on_list_delim_nil(matched, b),
            State::ListPreName => self.on_list_pre_name(b),
            State::ListNameStart => self.on_list_name_start(b),
            State::ListNameQuoted { escape } => self.on_list_name_quoted(escape, b),
            State::ListNameAtom => self.on_list_name_atom(b),
            State::StatusMailboxStart => self.on_status_mailbox_start(b),
            State::StatusMailboxQuoted { escape } => self.on_status_mailbox_quoted(escape, b),
            State::StatusMailboxAtom => self.on_status_mailbox_atom(b),
            State::StatusPostMailbox => self.on_status_post_mailbox(b),
            State::StatusItemsOpen => self.on_status_items_open(b),
            State::StatusItemName => self.on_status_item_name(b),
            State::StatusItemValue { item } => self.on_status_item_value(item, b),
            State::FetchOpenParen => self.on_fetch_open_paren(b),
            State::FetchAttrNameStart => self.on_fetch_attr_name_start(b),
            State::FetchAttrName => self.on_fetch_attr_name(b),
            State::FetchNumberValue { field } => self.on_fetch_number_value(field, b),
            State::FetchModseqOpen => self.on_fetch_modseq_open(b),
            State::FetchModseqValue => self.on_fetch_modseq_value(b),
            State::FetchModseqClose => self.on_fetch_modseq_close(b),
            State::FetchFlagsOpen => self.on_fetch_flags_open(b),
            State::FetchFlagsBody { depth } => self.on_fetch_flags_body(depth, b),
            State::FetchBodySection => self.on_fetch_body_section(b),
            State::FetchAfterSection => self.on_fetch_after_section(b),
            State::FetchPartialOrigin => self.on_fetch_partial_origin(b),
            State::FetchAfterPartial => self.on_fetch_after_partial(b),
            State::FetchBodyValueStart => self.on_fetch_body_value_start(b),
            State::FetchBodyNilTail { matched } => self.on_fetch_body_nil_tail(matched, b),
            State::FetchBodyQuotedSkip { escape } => self.on_fetch_body_quoted_skip(escape, b),
            State::FetchLiteralMarker => self.on_fetch_literal_marker(b),
            State::FetchLiteralCr => self.on_fetch_literal_cr(b),
            State::FetchLiteralLf => self.on_fetch_literal_lf(b),
            State::FetchLiteral => unreachable!("handled in feed()"),
            State::FetchSkipValue { depth, in_quote, escape } => {
                self.on_fetch_skip_value(depth, in_quote, escape, b)
            }
            State::FetchAfterValue => self.on_fetch_after_value(b),
            State::FetchListCloseCr => self.on_fetch_list_close_cr(b),
            State::FlagsListCloseCr => self.on_flags_list_close_cr(b),
            State::BoundedPayload { kind } => self.on_bounded_payload(kind, b),
            State::AwaitLf(kind) => self.on_await_lf(kind, b),
        }
    }

    // ── word1: tag / `*` / `+` ───────────────────────────────────────────

    fn on_word1(&mut self, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        match b {
            b' ' => {
                let w = self.take_word();
                if w == "*" {
                    self.state = State::UntaggedAfterSigil;
                } else if w == "+" {
                    self.state = State::Continuation;
                } else if w.is_empty() {
                    return Err(ImapError::Parse("empty IMAP response tag".into()));
                } else {
                    self.tag = w;
                    self.state = State::TaggedAfterTag;
                }
                Ok(None)
            }
            b'\r' if self.word == b"+" => {
                self.word.clear();
                self.state = State::Continuation;
                self.on_continuation(b'\r')
            }
            b'\r' => {
                let w = self.take_word();
                Err(ImapError::Parse(format!("unexpected bare IMAP word: {w:?}")))
            }
            _ => {
                self.push_word(b)?;
                Ok(None)
            }
        }
    }

    // ── untagged: word2 ──────────────────────────────────────────────────

    fn on_untagged_after_sigil(&mut self, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        match b {
            b' ' | b'\r' => {
                let w = self.take_word();
                let by_cr = b == b'\r';
                if let Ok(n) = w.parse::<u32>() {
                    if by_cr {
                        return Err(ImapError::Parse("bare numeric untagged response".into()));
                    }
                    self.state = State::UntaggedNumSeen { n };
                    return Ok(None);
                }
                let upper = w.to_ascii_uppercase();
                match upper.as_str() {
                    "OK" => self.begin_resp_text(RespCtx::UntaggedOk, by_cr),
                    "NO" => self.begin_resp_text(RespCtx::UntaggedNo, by_cr),
                    "BAD" => self.begin_resp_text(RespCtx::UntaggedBad, by_cr),
                    "BYE" => self.begin_resp_text(RespCtx::Bye, by_cr),
                    "PREAUTH" => self.begin_resp_text(RespCtx::Preauth, by_cr),
                    "CAPABILITY" => {
                        self.caps = ImapCapabilities::default();
                        if by_cr {
                            self.state = State::AwaitLf(AwaitLfKind::Capability);
                            return Ok(None);
                        }
                        self.state = State::TokenList { use_: TokenListUse::Capability };
                        Ok(None)
                    }
                    "ENABLED" => {
                        self.tokens.clear();
                        if by_cr {
                            self.state = State::AwaitLf(AwaitLfKind::Enabled);
                            return Ok(None);
                        }
                        self.state = State::TokenList { use_: TokenListUse::Enabled };
                        Ok(None)
                    }
                    "SEARCH" | "ESEARCH" => {
                        self.search_nums.clear();
                        if by_cr {
                            self.state = State::AwaitLf(AwaitLfKind::SearchNumbers);
                            return Ok(None);
                        }
                        self.state = State::SearchNums;
                        Ok(None)
                    }
                    "LIST" | "LSUB" => {
                        if by_cr {
                            return Err(ImapError::Parse("truncated LIST response".into()));
                        }
                        self.list_entry = ImapListEntry::default();
                        self.state = State::ListAttrsOpen;
                        Ok(None)
                    }
                    "STATUS" => {
                        if by_cr {
                            return Err(ImapError::Parse("truncated STATUS response".into()));
                        }
                        self.status_data = ImapStatusData::default();
                        self.state = State::StatusMailboxStart;
                        Ok(None)
                    }
                    "FLAGS" => {
                        if by_cr {
                            return Err(ImapError::Parse("truncated FLAGS response".into()));
                        }
                        self.state = State::FetchFlagsOpen;
                        Ok(None)
                    }
                    "NAMESPACE" => self.begin_bounded(BoundedKind::Namespace, by_cr),
                    "QUOTA" => self.begin_bounded(BoundedKind::Quota, by_cr),
                    "QUOTAROOT" => self.begin_bounded(BoundedKind::QuotaRoot, by_cr),
                    "ID" => self.begin_bounded(BoundedKind::Id, by_cr),
                    _ => {
                        if by_cr {
                            self.state = State::AwaitLf(AwaitLfKind::Other);
                        } else {
                            self.state = State::SkipToCrlf;
                        }
                        Ok(None)
                    }
                }
            }
            _ => {
                self.push_word(b)?;
                Ok(None)
            }
        }
    }

    fn on_untagged_num_seen(&mut self, n: u32, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        match b {
            b' ' | b'\r' => {
                let w = self.take_word().to_ascii_uppercase();
                let by_cr = b == b'\r';
                match w.as_str() {
                    "EXISTS" if by_cr => {
                        self.state = State::AwaitLf(AwaitLfKind::Exists(n));
                        Ok(None)
                    }
                    "RECENT" if by_cr => {
                        self.state = State::AwaitLf(AwaitLfKind::Recent(n));
                        Ok(None)
                    }
                    "EXPUNGE" if by_cr => {
                        self.state = State::AwaitLf(AwaitLfKind::Expunge(n));
                        Ok(None)
                    }
                    "FETCH" if !by_cr => {
                        self.fetch_data = ImapFetchData { seq: n, ..Default::default() };
                        self.state = State::FetchOpenParen;
                        Ok(None)
                    }
                    _ => Err(ImapError::Parse(format!(
                        "unexpected IMAP message-data keyword: {w:?}"
                    ))),
                }
            }
            _ => {
                self.push_word(b)?;
                Ok(None)
            }
        }
    }

    // ── tagged: status word ─────────────────────────────────────────────

    fn on_tagged_after_tag(&mut self, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        match b {
            b' ' | b'\r' => {
                let w = self.take_word().to_ascii_uppercase();
                let by_cr = b == b'\r';
                match w.as_str() {
                    "OK" => self.begin_resp_text(RespCtx::TaggedOk, by_cr),
                    "NO" => self.begin_resp_text(RespCtx::TaggedNo, by_cr),
                    "BAD" => self.begin_resp_text(RespCtx::TaggedBad, by_cr),
                    _ => Err(ImapError::Parse(format!("unexpected IMAP tagged status: {w:?}"))),
                }
            }
            _ => {
                self.push_word(b)?;
                Ok(None)
            }
        }
    }

    // ── continuation ─────────────────────────────────────────────────────

    fn on_continuation(&mut self, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        if b == b'\r' {
            self.state = State::AwaitLf(AwaitLfKind::Continuation);
            return Ok(None);
        }
        // The single space separating "+" from text (if any) was already
        // consumed as the state-transition terminator in `on_word1`.
        self.push_text(b)?;
        Ok(None)
    }

    // ── shared response-text tail: [code] message ───────────────────────

    fn begin_resp_text(&mut self, ctx: RespCtx, by_cr: bool) -> Result<Option<ImapEvent>, ImapError> {
        if by_cr {
            self.state = State::AwaitLf(resp_text_await(ctx, None));
            return Ok(None);
        }
        self.state = State::RespTextStart { ctx };
        Ok(None)
    }

    fn on_resp_text_start(&mut self, ctx: RespCtx, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        match b {
            b'[' => {
                self.state = State::RespCode { ctx, depth: 1, in_quote: false, escape: false };
                Ok(None)
            }
            b'\r' => {
                self.state = State::AwaitLf(resp_text_await(ctx, None));
                Ok(None)
            }
            b' ' => Ok(None), // tolerate an extra leading space
            _ => {
                self.state = State::RespMessage { ctx };
                self.push_text(b)?;
                Ok(None)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn on_resp_code(
        &mut self,
        ctx: RespCtx,
        depth: i32,
        in_quote: bool,
        escape: bool,
        b: u8,
    ) -> Result<Option<ImapEvent>, ImapError> {
        if escape {
            self.push_text(b)?;
            self.state = State::RespCode { ctx, depth, in_quote, escape: false };
            return Ok(None);
        }
        if in_quote {
            match b {
                b'\\' => self.state = State::RespCode { ctx, depth, in_quote, escape: true },
                b'"' => {
                    self.push_text(b)?;
                    self.state = State::RespCode { ctx, depth, in_quote: false, escape: false };
                }
                _ => {
                    self.push_text(b)?;
                    self.state = State::RespCode { ctx, depth, in_quote, escape: false };
                }
            }
            return Ok(None);
        }
        match b {
            b'"' => {
                self.push_text(b)?;
                self.state = State::RespCode { ctx, depth, in_quote: true, escape: false };
            }
            b'[' => {
                self.push_text(b)?;
                self.state = State::RespCode { ctx, depth: depth + 1, in_quote: false, escape: false };
            }
            b']' if depth > 1 => {
                self.push_text(b)?;
                self.state = State::RespCode { ctx, depth: depth - 1, in_quote: false, escape: false };
            }
            b']' => {
                self.code = Some(self.take_text());
                self.state = State::RespCodeGap { ctx };
            }
            _ => {
                self.push_text(b)?;
                self.state = State::RespCode { ctx, depth, in_quote: false, escape: false };
            }
        }
        Ok(None)
    }

    fn on_resp_code_gap(&mut self, ctx: RespCtx, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        match b {
            b' ' => {
                self.state = State::RespMessage { ctx };
                Ok(None)
            }
            b'\r' => {
                let code = self.code.take();
                self.state = State::AwaitLf(resp_text_await(ctx, code));
                Ok(None)
            }
            _ => Err(ImapError::Parse("expected SP or CRLF after response code".into())),
        }
    }

    fn on_resp_message(&mut self, ctx: RespCtx, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        if b == b'\r' {
            let code = self.code.take();
            self.state = State::AwaitLf(resp_text_await(ctx, code));
            return Ok(None);
        }
        self.push_text(b)?;
        self.state = State::RespMessage { ctx };
        Ok(None)
    }

    // ── token lists (CAPABILITY / ENABLED) ──────────────────────────────

    fn on_token_list(&mut self, use_: TokenListUse, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        match b {
            b' ' => {
                let w = self.take_word();
                if !w.is_empty() {
                    self.apply_token(use_, &w);
                }
                self.state = State::TokenList { use_ };
                Ok(None)
            }
            b'\r' => {
                let w = self.take_word();
                if !w.is_empty() {
                    self.apply_token(use_, &w);
                }
                self.state = State::AwaitLf(match use_ {
                    TokenListUse::Capability => AwaitLfKind::Capability,
                    TokenListUse::Enabled => AwaitLfKind::Enabled,
                });
                Ok(None)
            }
            _ => {
                self.push_word(b)?;
                self.state = State::TokenList { use_ };
                Ok(None)
            }
        }
    }

    fn apply_token(&mut self, use_: TokenListUse, tok: &str) {
        let upper = tok.to_ascii_uppercase();
        match use_ {
            TokenListUse::Capability => apply_capability_token(&mut self.caps, &upper),
            TokenListUse::Enabled => self.tokens.push(upper),
        }
    }

    // ── SEARCH numbers ───────────────────────────────────────────────────

    fn on_search_nums(&mut self, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        match b {
            b' ' => {
                let w = self.take_word();
                if w.is_empty() {
                    self.state = State::SearchNums;
                    return Ok(None);
                }
                if let Ok(n) = w.parse::<u32>() {
                    self.search_nums.push(n);
                    self.state = State::SearchNums;
                    Ok(None)
                } else if w.starts_with('(') {
                    self.state =
                        State::SearchTrailerSkip { depth: 1, in_quote: false, escape: false };
                    Ok(None)
                } else {
                    Err(ImapError::Parse(format!("unexpected SEARCH token: {w:?}")))
                }
            }
            b'\r' => {
                let w = self.take_word();
                if !w.is_empty() {
                    let n: u32 = w
                        .parse()
                        .map_err(|_| ImapError::Parse(format!("unexpected SEARCH token: {w:?}")))?;
                    self.search_nums.push(n);
                }
                self.state = State::AwaitLf(AwaitLfKind::SearchNumbers);
                Ok(None)
            }
            b'(' if self.word.is_empty() => {
                self.state = State::SearchTrailerSkip { depth: 1, in_quote: false, escape: false };
                Ok(None)
            }
            _ => {
                self.push_word(b)?;
                self.state = State::SearchNums;
                Ok(None)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn on_search_trailer_skip(
        &mut self,
        depth: i32,
        in_quote: bool,
        escape: bool,
        b: u8,
    ) -> Result<Option<ImapEvent>, ImapError> {
        if escape {
            self.state = State::SearchTrailerSkip { depth, in_quote, escape: false };
            return Ok(None);
        }
        if in_quote {
            match b {
                b'\\' => self.state = State::SearchTrailerSkip { depth, in_quote, escape: true },
                b'"' => {
                    self.state = State::SearchTrailerSkip { depth, in_quote: false, escape: false }
                }
                _ => self.state = State::SearchTrailerSkip { depth, in_quote, escape: false },
            }
            return Ok(None);
        }
        match b {
            b'"' => {
                self.state = State::SearchTrailerSkip { depth, in_quote: true, escape: false };
                Ok(None)
            }
            b'(' => {
                self.state =
                    State::SearchTrailerSkip { depth: depth + 1, in_quote: false, escape: false };
                Ok(None)
            }
            b')' if depth > 1 => {
                self.state =
                    State::SearchTrailerSkip { depth: depth - 1, in_quote: false, escape: false };
                Ok(None)
            }
            b')' => {
                self.state = State::SearchTrailerSkip { depth: 0, in_quote: false, escape: false };
                Ok(None)
            }
            b'\r' if depth <= 0 => {
                self.state = State::AwaitLf(AwaitLfKind::SearchNumbers);
                Ok(None)
            }
            _ => {
                self.state = State::SearchTrailerSkip { depth, in_quote: false, escape: false };
                Ok(None)
            }
        }
    }

    fn on_skip_to_crlf(&mut self, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        if b == b'\r' {
            self.state = State::AwaitLf(AwaitLfKind::Other);
            return Ok(None);
        }
        self.state = State::SkipToCrlf;
        Ok(None)
    }

    // ── LIST / LSUB ───────────────────────────────────────────────────────

    fn on_list_attrs_open(&mut self, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        if b == b'(' {
            self.state = State::ListAttrsBody { depth: 1, in_quote: false, escape: false };
            self.word.clear();
            return Ok(None);
        }
        Err(ImapError::Parse("expected '(' opening LIST attribute list".into()))
    }

    #[allow(clippy::too_many_arguments)]
    fn on_list_attrs_body(
        &mut self,
        depth: i32,
        in_quote: bool,
        escape: bool,
        b: u8,
    ) -> Result<Option<ImapEvent>, ImapError> {
        if escape {
            self.state = State::ListAttrsBody { depth, in_quote, escape: false };
            return Ok(None);
        }
        if in_quote {
            match b {
                b'\\' => self.state = State::ListAttrsBody { depth, in_quote, escape: true },
                b'"' => self.state = State::ListAttrsBody { depth, in_quote: false, escape: false },
                _ => self.state = State::ListAttrsBody { depth, in_quote, escape: false },
            }
            return Ok(None);
        }
        match b {
            b'"' => {
                self.state = State::ListAttrsBody { depth, in_quote: true, escape: false };
                Ok(None)
            }
            b'(' => {
                self.state = State::ListAttrsBody { depth: depth + 1, in_quote: false, escape: false };
                Ok(None)
            }
            b')' if depth > 1 => {
                self.state = State::ListAttrsBody { depth: depth - 1, in_quote: false, escape: false };
                Ok(None)
            }
            b')' => {
                let w = self.take_word();
                if !w.is_empty() {
                    self.list_entry.attributes.push(w);
                }
                self.state = State::ListPostAttrs;
                Ok(None)
            }
            b' ' => {
                let w = self.take_word();
                if !w.is_empty() {
                    self.list_entry.attributes.push(w);
                }
                self.state = State::ListAttrsBody { depth, in_quote: false, escape: false };
                Ok(None)
            }
            _ => {
                self.push_word(b)?;
                self.state = State::ListAttrsBody { depth, in_quote: false, escape: false };
                Ok(None)
            }
        }
    }

    fn on_list_post_attrs(&mut self, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        if b == b' ' {
            self.state = State::ListDelimStart;
            return Ok(None);
        }
        Err(ImapError::Parse("expected SP after LIST attribute list".into()))
    }

    fn on_list_delim_start(&mut self, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        match b {
            b'"' => {
                self.state = State::ListDelimQuotedChar { escape: false };
                Ok(None)
            }
            b'N' | b'n' => {
                self.state = State::ListDelimNil { matched: 1 };
                Ok(None)
            }
            _ => Err(ImapError::Parse("expected quoted delimiter or NIL in LIST".into())),
        }
    }

    fn on_list_delim_quoted_char(&mut self, escape: bool, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        if !escape && b == b'\\' {
            self.state = State::ListDelimQuotedChar { escape: true };
            return Ok(None);
        }
        self.list_entry.delimiter = Some((b as char).to_string());
        self.state = State::ListDelimQuotedClose;
        Ok(None)
    }

    fn on_list_delim_quoted_close(&mut self, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        if b == b'"' {
            self.state = State::ListPreName;
            return Ok(None);
        }
        Err(ImapError::Parse("expected closing '\"' after LIST delimiter".into()))
    }

    fn on_list_delim_nil(&mut self, matched: u8, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        const NIL: &[u8] = b"NIL";
        if b.to_ascii_uppercase() != NIL[matched as usize] {
            return Err(ImapError::Parse("expected NIL delimiter in LIST".into()));
        }
        let matched = matched + 1;
        if matched as usize == NIL.len() {
            self.list_entry.delimiter = None;
            self.state = State::ListPreName;
        } else {
            self.state = State::ListDelimNil { matched };
        }
        Ok(None)
    }

    fn on_list_pre_name(&mut self, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        if b == b' ' {
            self.state = State::ListNameStart;
            return Ok(None);
        }
        Err(ImapError::Parse("expected SP before LIST mailbox name".into()))
    }

    fn on_list_name_start(&mut self, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        if b == b'"' {
            self.state = State::ListNameQuoted { escape: false };
            return Ok(None);
        }
        self.state = State::ListNameAtom;
        self.push_text(b)?;
        Ok(None)
    }

    fn on_list_name_quoted(&mut self, escape: bool, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        if escape {
            self.push_text(b)?;
            self.state = State::ListNameQuoted { escape: false };
            return Ok(None);
        }
        match b {
            b'\\' => {
                self.state = State::ListNameQuoted { escape: true };
                Ok(None)
            }
            b'"' => {
                self.list_entry.name = self.take_text();
                self.state = State::FetchListCloseCr; // reused: "expect CRLF"
                self.pending_list_entry();
                Ok(None)
            }
            _ => {
                self.push_text(b)?;
                self.state = State::ListNameQuoted { escape: false };
                Ok(None)
            }
        }
    }

    fn on_list_name_atom(&mut self, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        if b == b'\r' {
            self.list_entry.name = self.take_text();
            self.state = State::AwaitLf(AwaitLfKind::ListEntry);
            return Ok(None);
        }
        self.push_text(b)?;
        self.state = State::ListNameAtom;
        Ok(None)
    }

    fn pending_list_entry(&mut self) {
        // FetchListCloseCr is a generic "expect CRLF" state shared with
        // FETCH/STATUS; on_fetch_list_close_cr checks which of these
        // flags produced the wait and emits the right event.
        self.list_close_kind = Some(ListCloseKind::ListEntry);
    }

    // ── STATUS ────────────────────────────────────────────────────────────

    fn on_status_mailbox_start(&mut self, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        if b == b'"' {
            self.state = State::StatusMailboxQuoted { escape: false };
            return Ok(None);
        }
        self.state = State::StatusMailboxAtom;
        self.push_text(b)?;
        Ok(None)
    }

    fn on_status_mailbox_quoted(&mut self, escape: bool, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        if escape {
            self.push_text(b)?;
            self.state = State::StatusMailboxQuoted { escape: false };
            return Ok(None);
        }
        match b {
            b'\\' => {
                self.state = State::StatusMailboxQuoted { escape: true };
                Ok(None)
            }
            b'"' => {
                self.status_data.mailbox = self.take_text();
                self.state = State::StatusPostMailbox;
                Ok(None)
            }
            _ => {
                self.push_text(b)?;
                self.state = State::StatusMailboxQuoted { escape: false };
                Ok(None)
            }
        }
    }

    fn on_status_mailbox_atom(&mut self, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        if b == b' ' {
            self.status_data.mailbox = self.take_text();
            self.state = State::StatusItemsOpen;
            return Ok(None);
        }
        self.push_text(b)?;
        self.state = State::StatusMailboxAtom;
        Ok(None)
    }

    fn on_status_post_mailbox(&mut self, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        if b == b' ' {
            self.state = State::StatusItemsOpen;
            return Ok(None);
        }
        Err(ImapError::Parse("expected SP after STATUS mailbox".into()))
    }

    fn on_status_items_open(&mut self, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        if b == b'(' {
            self.state = State::StatusItemName;
            self.word.clear();
            return Ok(None);
        }
        Err(ImapError::Parse("expected '(' opening STATUS item list".into()))
    }

    fn on_status_item_name(&mut self, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        match b {
            b' ' => {
                let w = self.take_word().to_ascii_uppercase();
                let item = status_item_from_name(&w);
                self.state = State::StatusItemValue { item };
                Ok(None)
            }
            b')' if self.word.is_empty() => {
                self.state = State::FetchListCloseCr;
                self.list_close_kind = Some(ListCloseKind::StatusData);
                Ok(None)
            }
            _ => {
                self.push_word(b)?;
                self.state = State::StatusItemName;
                Ok(None)
            }
        }
    }

    fn on_status_item_value(&mut self, item: StatusItem, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        match b {
            b' ' | b')' => {
                let w = self.take_word();
                let val = w.parse::<i64>().ok();
                apply_status_item(&mut self.status_data, item, val);
                if b == b')' {
                    self.state = State::FetchListCloseCr;
                    self.list_close_kind = Some(ListCloseKind::StatusData);
                    return Ok(None);
                }
                self.state = State::StatusItemName;
                Ok(None)
            }
            _ => {
                self.push_word(b)?;
                self.state = State::StatusItemValue { item };
                Ok(None)
            }
        }
    }

    // ── FETCH ─────────────────────────────────────────────────────────────

    fn on_fetch_open_paren(&mut self, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        if b == b'(' {
            self.state = State::FetchAttrNameStart;
            return Ok(None);
        }
        Err(ImapError::Parse("expected '(' opening FETCH attribute list".into()))
    }

    fn on_fetch_attr_name_start(&mut self, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        if b == b')' {
            self.state = State::FetchListCloseCr;
            self.list_close_kind = Some(ListCloseKind::Fetch);
            return Ok(None);
        }
        self.state = State::FetchAttrName;
        self.push_word(b)?;
        Ok(None)
    }

    fn on_fetch_attr_name(&mut self, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        match b {
            b' ' | b'(' | b'[' | b')' => {
                let name = self.take_word().to_ascii_uppercase();
                self.dispatch_fetch_attr(&name, b)
            }
            _ => {
                self.push_word(b)?;
                self.state = State::FetchAttrName;
                Ok(None)
            }
        }
    }

    fn dispatch_fetch_attr(&mut self, name: &str, sep: u8) -> Result<Option<ImapEvent>, ImapError> {
        match (name, sep) {
            ("UID", b' ') => {
                self.state = State::FetchNumberValue { field: FetchNumField::Uid };
                Ok(None)
            }
            ("RFC822.SIZE", b' ') => {
                self.state = State::FetchNumberValue { field: FetchNumField::Size };
                Ok(None)
            }
            ("MODSEQ", b' ') => {
                self.state = State::FetchModseqOpen;
                Ok(None)
            }
            ("FLAGS", b' ') => {
                self.flags_is_fetch_attr = true;
                self.state = State::FetchFlagsOpen;
                Ok(None)
            }
            (_, b'[') => {
                // BODY[section]<partial> — capture the bracketed section
                // spec (attributes the literal that may follow), then read
                // the literal/quoted/NIL value.
                self.fetch_section.clear();
                self.state = State::FetchBodySection;
                Ok(None)
            }
            ("RFC822" | "RFC822.TEXT" | "RFC822.HEADER", b' ') => {
                self.fetch_section.clear();
                self.fetch_section.extend_from_slice(name.as_bytes());
                self.state = State::FetchBodyValueStart;
                Ok(None)
            }
            (_, b' ') => {
                // ENVELOPE / BODYSTRUCTURE / INTERNALDATE / bare BODY /
                // any unrecognised atom: skip the value (quoted string,
                // atom, or parenthesized structure).
                self.state = State::FetchSkipValue { depth: 0, in_quote: false, escape: false };
                Ok(None)
            }
            (_, b')') => {
                // A flag-like attribute with no value — stay resilient.
                self.state = State::FetchListCloseCr;
                self.list_close_kind = Some(ListCloseKind::Fetch);
                Ok(None)
            }
            _ => Err(ImapError::Parse(format!(
                "unexpected FETCH attribute separator after {name:?}"
            ))),
        }
    }

    fn on_fetch_number_value(
        &mut self,
        field: FetchNumField,
        b: u8,
    ) -> Result<Option<ImapEvent>, ImapError> {
        match b {
            b' ' | b')' => {
                let w = self.take_word();
                let n: u64 = w
                    .parse()
                    .map_err(|_| ImapError::Parse(format!("bad FETCH numeric value: {w:?}")))?;
                match field {
                    FetchNumField::Uid => self.fetch_data.uid = Some(n as u32),
                    FetchNumField::Size => self.fetch_data.size = Some(n),
                }
                if b == b')' {
                    self.state = State::FetchListCloseCr;
                    self.list_close_kind = Some(ListCloseKind::Fetch);
                    return Ok(None);
                }
                self.state = State::FetchAttrNameStart;
                Ok(None)
            }
            _ => {
                self.push_word(b)?;
                self.state = State::FetchNumberValue { field };
                Ok(None)
            }
        }
    }

    fn on_fetch_modseq_open(&mut self, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        if b == b'(' {
            self.state = State::FetchModseqValue;
            return Ok(None);
        }
        Err(ImapError::Parse("expected '(' opening MODSEQ value".into()))
    }

    fn on_fetch_modseq_value(&mut self, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        if b == b')' {
            let w = self.take_word();
            let n: u64 = w
                .parse()
                .map_err(|_| ImapError::Parse(format!("bad MODSEQ value: {w:?}")))?;
            self.fetch_data.modseq = Some(n);
            self.state = State::FetchModseqClose;
            return Ok(None);
        }
        self.push_word(b)?;
        self.state = State::FetchModseqValue;
        Ok(None)
    }

    fn on_fetch_modseq_close(&mut self, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        match b {
            b' ' => {
                self.state = State::FetchAttrNameStart;
                Ok(None)
            }
            b')' => {
                self.state = State::FetchListCloseCr;
                self.list_close_kind = Some(ListCloseKind::Fetch);
                Ok(None)
            }
            _ => Err(ImapError::Parse("expected SP or ')' after MODSEQ value".into())),
        }
    }

    fn on_fetch_flags_open(&mut self, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        if b == b'(' {
            self.state = State::FetchFlagsBody { depth: 1 };
            self.tokens.clear();
            self.word.clear();
            return Ok(None);
        }
        Err(ImapError::Parse("expected '(' opening FLAGS value".into()))
    }

    fn on_fetch_flags_body(&mut self, depth: i32, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        let _ = depth;
        match b {
            b' ' => {
                let w = self.take_word();
                if !w.is_empty() {
                    self.tokens.push(w);
                }
                self.state = State::FetchFlagsBody { depth: 1 };
                Ok(None)
            }
            b')' => {
                let w = self.take_word();
                if !w.is_empty() {
                    self.tokens.push(w);
                }
                let flags = std::mem::take(&mut self.tokens);
                // `FLAGS` reached at the untagged top level (SELECT's
                // mailbox-wide flags) vs. as a FETCH attribute are
                // distinguished by whether `fetch_data` is mid-flight;
                // both paths reuse this state, so the caller (dispatch
                // site) decides which — see `on_untagged_after_sigil`'s
                // "FLAGS" arm (top-level) vs `dispatch_fetch_attr`'s
                // ("FLAGS", ' ') arm (FETCH attribute), tracked via
                // `flags_is_fetch_attr`.
                if self.flags_is_fetch_attr {
                    self.flags_is_fetch_attr = false;
                    self.fetch_data.flags = flags;
                    self.state = State::FetchAfterValue;
                } else {
                    self.tokens = flags;
                    self.state = State::FlagsListCloseCr;
                }
                Ok(None)
            }
            _ => {
                self.push_word(b)?;
                self.state = State::FetchFlagsBody { depth: 1 };
                Ok(None)
            }
        }
    }

    fn on_fetch_body_section(&mut self, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        if b == b']' {
            self.state = State::FetchAfterSection;
            return Ok(None);
        }
        if self.fetch_section.len() >= MAX_TOKEN {
            return Err(ImapError::Parse("FETCH section spec too long".into()));
        }
        self.fetch_section.push(b);
        self.state = State::FetchBodySection;
        Ok(None)
    }

    fn on_fetch_after_section(&mut self, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        match b {
            b'<' => {
                self.state = State::FetchPartialOrigin;
                Ok(None)
            }
            b' ' => {
                self.state = State::FetchBodyValueStart;
                Ok(None)
            }
            _ => Err(ImapError::Parse("expected '<' or SP after FETCH section spec".into())),
        }
    }

    fn on_fetch_partial_origin(&mut self, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        if b == b'>' {
            self.state = State::FetchAfterPartial;
            return Ok(None);
        }
        self.state = State::FetchPartialOrigin;
        Ok(None)
    }

    fn on_fetch_after_partial(&mut self, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        if b == b' ' {
            self.state = State::FetchBodyValueStart;
            return Ok(None);
        }
        Err(ImapError::Parse("expected SP after FETCH partial origin".into()))
    }

    fn on_fetch_body_value_start(&mut self, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        match b {
            b'{' => {
                self.word.clear();
                self.state = State::FetchLiteralMarker;
                Ok(None)
            }
            b'N' | b'n' => {
                self.state = State::FetchBodyNilTail { matched: 1 };
                Ok(None)
            }
            b'"' => {
                self.state = State::FetchBodyQuotedSkip { escape: false };
                Ok(None)
            }
            _ => Err(ImapError::Parse("expected literal, NIL, or quoted FETCH body value".into())),
        }
    }

    fn on_fetch_body_nil_tail(&mut self, matched: u8, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        const NIL: &[u8] = b"NIL";
        if b.to_ascii_uppercase() != NIL[matched as usize] {
            return Err(ImapError::Parse("expected NIL FETCH body value".into()));
        }
        let matched = matched + 1;
        if matched as usize == NIL.len() {
            self.state = State::FetchAfterValue;
        } else {
            self.state = State::FetchBodyNilTail { matched };
        }
        Ok(None)
    }

    fn on_fetch_body_quoted_skip(&mut self, escape: bool, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        if escape {
            self.state = State::FetchBodyQuotedSkip { escape: false };
            return Ok(None);
        }
        match b {
            b'\\' => {
                self.state = State::FetchBodyQuotedSkip { escape: true };
                Ok(None)
            }
            b'"' => {
                self.state = State::FetchAfterValue;
                Ok(None)
            }
            _ => {
                self.state = State::FetchBodyQuotedSkip { escape: false };
                Ok(None)
            }
        }
    }

    fn on_fetch_literal_marker(&mut self, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        match b {
            b'+' => Ok(None), // non-synchronizing marker; irrelevant to a reply reader
            b'}' => {
                let w = self.take_word();
                let n: u64 = w
                    .parse()
                    .map_err(|_| ImapError::Parse(format!("bad literal size: {w:?}")))?;
                self.literal_remaining = n;
                self.state = State::FetchLiteralCr;
                Ok(None)
            }
            _ if b.is_ascii_digit() => {
                self.push_word(b)?;
                self.state = State::FetchLiteralMarker;
                Ok(None)
            }
            _ => Err(ImapError::Parse("malformed literal size marker".into())),
        }
    }

    fn on_fetch_literal_cr(&mut self, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        if b == b'\r' {
            self.state = State::FetchLiteralLf;
            return Ok(None);
        }
        Err(ImapError::Parse("expected CR after literal size marker".into()))
    }

    fn on_fetch_literal_lf(&mut self, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        if b == b'\n' {
            if self.literal_remaining == 0 {
                // Nothing will stream — no Begin/End pair for an empty value.
                self.state = State::FetchAfterValue;
                return Ok(None);
            }
            self.state = State::FetchLiteral;
            let section = String::from_utf8_lossy(&std::mem::take(&mut self.fetch_section))
                .into_owned();
            return Ok(Some(ImapEvent::FetchLiteralBegin {
                seq: self.fetch_data.seq,
                section,
                size: self.literal_remaining,
            }));
        }
        Err(ImapError::Parse("expected LF after literal size marker's CR".into()))
    }

    #[allow(clippy::too_many_arguments)]
    fn on_fetch_skip_value(
        &mut self,
        depth: i32,
        in_quote: bool,
        escape: bool,
        b: u8,
    ) -> Result<Option<ImapEvent>, ImapError> {
        if escape {
            self.state = State::FetchSkipValue { depth, in_quote, escape: false };
            return Ok(None);
        }
        if in_quote {
            match b {
                b'\\' => self.state = State::FetchSkipValue { depth, in_quote, escape: true },
                b'"' => self.state = State::FetchSkipValue { depth, in_quote: false, escape: false },
                _ => self.state = State::FetchSkipValue { depth, in_quote, escape: false },
            }
            return Ok(None);
        }
        match b {
            b'"' => {
                self.state = State::FetchSkipValue { depth, in_quote: true, escape: false };
                Ok(None)
            }
            b'(' | b'[' => {
                self.state = State::FetchSkipValue { depth: depth + 1, in_quote: false, escape: false };
                Ok(None)
            }
            b')' | b']' if depth > 1 => {
                self.state = State::FetchSkipValue { depth: depth - 1, in_quote: false, escape: false };
                Ok(None)
            }
            b')' | b']' if depth == 1 => {
                self.state = State::FetchAfterValue;
                Ok(None)
            }
            b' ' if depth == 0 => {
                self.state = State::FetchAttrNameStart;
                Ok(None)
            }
            b')' if depth == 0 => {
                self.state = State::FetchListCloseCr;
                self.list_close_kind = Some(ListCloseKind::Fetch);
                Ok(None)
            }
            _ => {
                self.state = State::FetchSkipValue { depth, in_quote: false, escape: false };
                Ok(None)
            }
        }
    }

    fn on_fetch_after_value(&mut self, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        match b {
            b' ' => {
                self.state = State::FetchAttrNameStart;
                Ok(None)
            }
            b')' => {
                self.state = State::FetchListCloseCr;
                self.list_close_kind = Some(ListCloseKind::Fetch);
                Ok(None)
            }
            _ => Err(ImapError::Parse("expected SP or ')' after FETCH attribute value".into())),
        }
    }

    fn on_fetch_list_close_cr(&mut self, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        if b != b'\r' {
            return Err(ImapError::Parse("expected CRLF after ')'".into()));
        }
        let kind = self.list_close_kind.take();
        self.state = State::AwaitLf(match kind {
            Some(ListCloseKind::Fetch) => AwaitLfKind::Fetch,
            Some(ListCloseKind::StatusData) => AwaitLfKind::StatusData,
            Some(ListCloseKind::ListEntry) => AwaitLfKind::ListEntry,
            None => return Err(ImapError::Parse("internal: missing list-close kind".into())),
        });
        Ok(None)
    }

    fn on_flags_list_close_cr(&mut self, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        if b != b'\r' {
            return Err(ImapError::Parse("expected CRLF after ')'".into()));
        }
        self.state = State::AwaitLf(AwaitLfKind::Flags);
        Ok(None)
    }

    // ── bounded-capture payloads (NAMESPACE / QUOTA / QUOTAROOT / ID) ────

    fn begin_bounded(&mut self, kind: BoundedKind, by_cr: bool) -> Result<Option<ImapEvent>, ImapError> {
        self.text.clear();
        if by_cr {
            self.state = State::AwaitLf(AwaitLfKind::Bounded(kind));
            return Ok(None);
        }
        self.state = State::BoundedPayload { kind };
        Ok(None)
    }

    fn on_bounded_payload(&mut self, kind: BoundedKind, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        if b == b'\r' {
            self.state = State::AwaitLf(AwaitLfKind::Bounded(kind));
            return Ok(None);
        }
        self.push_text(b)?;
        self.state = State::BoundedPayload { kind };
        Ok(None)
    }

    fn finish_bounded(&mut self, kind: BoundedKind) -> ImapEvent {
        let payload = self.take_text();
        match kind {
            BoundedKind::Namespace => ImapEvent::Namespace(payload),
            BoundedKind::Quota => ImapEvent::Quota(payload),
            BoundedKind::QuotaRoot => ImapEvent::QuotaRoot(payload),
            BoundedKind::Id => ImapEvent::IdParams(payload),
        }
    }

    // ── CRLF completion ──────────────────────────────────────────────────

    fn on_await_lf(&mut self, kind: AwaitLfKind, b: u8) -> Result<Option<ImapEvent>, ImapError> {
        if b != b'\n' {
            return Err(ImapError::Parse("expected LF after CR".into()));
        }
        self.state = State::Word1;
        let event = match kind {
            AwaitLfKind::Continuation => ImapEvent::Continuation { text: self.take_text() },
            AwaitLfKind::Tagged { status, code } => ImapEvent::Tagged {
                tag: std::mem::take(&mut self.tag),
                status,
                code,
                message: self.take_text(),
            },
            AwaitLfKind::UntaggedOk { code } => {
                ImapEvent::UntaggedOk { code, text: self.take_text() }
            }
            AwaitLfKind::UntaggedNo { code } => {
                ImapEvent::UntaggedNo { code, text: self.take_text() }
            }
            AwaitLfKind::UntaggedBad { code } => {
                ImapEvent::UntaggedBad { code, text: self.take_text() }
            }
            AwaitLfKind::Bye { code } => ImapEvent::Bye { code, text: self.take_text() },
            AwaitLfKind::Preauth { code } => ImapEvent::Preauth { code, text: self.take_text() },
            AwaitLfKind::Capability => ImapEvent::Capability(std::mem::take(&mut self.caps)),
            AwaitLfKind::Enabled => ImapEvent::Enabled(std::mem::take(&mut self.tokens)),
            AwaitLfKind::SearchNumbers => {
                ImapEvent::SearchNumbers(std::mem::take(&mut self.search_nums))
            }
            AwaitLfKind::Other => ImapEvent::Other,
            AwaitLfKind::Exists(n) => ImapEvent::Exists(n),
            AwaitLfKind::Recent(n) => ImapEvent::Recent(n),
            AwaitLfKind::Expunge(n) => ImapEvent::Expunge(n),
            AwaitLfKind::Flags => ImapEvent::FlagsList(std::mem::take(&mut self.tokens)),
            AwaitLfKind::ListEntry => ImapEvent::ListEntry(std::mem::take(&mut self.list_entry)),
            AwaitLfKind::Fetch => ImapEvent::Fetch(std::mem::take(&mut self.fetch_data)),
            AwaitLfKind::StatusData => ImapEvent::StatusData(std::mem::take(&mut self.status_data)),
            AwaitLfKind::Bounded(k) => self.finish_bounded(k),
        };
        Ok(Some(event))
    }
}

fn resp_text_await(ctx: RespCtx, code: Option<String>) -> AwaitLfKind {
    match ctx {
        RespCtx::TaggedOk => AwaitLfKind::Tagged { status: ImapStatus::Ok, code },
        RespCtx::TaggedNo => AwaitLfKind::Tagged { status: ImapStatus::No, code },
        RespCtx::TaggedBad => AwaitLfKind::Tagged { status: ImapStatus::Bad, code },
        RespCtx::UntaggedOk => AwaitLfKind::UntaggedOk { code },
        RespCtx::UntaggedNo => AwaitLfKind::UntaggedNo { code },
        RespCtx::UntaggedBad => AwaitLfKind::UntaggedBad { code },
        RespCtx::Bye => AwaitLfKind::Bye { code },
        RespCtx::Preauth => AwaitLfKind::Preauth { code },
    }
}

fn apply_capability_token(caps: &mut ImapCapabilities, upper: &str) {
    match upper {
        "STARTTLS" => caps.starttls = true,
        "LITERAL-" => caps.literal_minus = true,
        "IDLE" => caps.idle = true,
        "LOGINDISABLED" => caps.login_disabled = true,
        "MOVE" => caps.move_ = true,
        "UIDPLUS" => caps.uidplus = true,
        "NAMESPACE" => caps.namespace = true,
        "ENABLE" => caps.enable = true,
        "CONDSTORE" => caps.condstore = true,
        "QRESYNC" => caps.qresync = true,
        "UNSELECT" => caps.unselect = true,
        "ID" => caps.id = true,
        "QUOTA" => caps.quota = true,
        _ => {
            if let Some(mech) = upper.strip_prefix("AUTH=") {
                if mech == "PLAIN" {
                    caps.auth_plain = true;
                }
            }
        }
    }
    caps.tokens.push(upper.to_string());
}

fn status_item_from_name(name: &str) -> StatusItem {
    match name {
        "MESSAGES" => StatusItem::Messages,
        "RECENT" => StatusItem::Recent,
        "UIDNEXT" => StatusItem::UidNext,
        "UIDVALIDITY" => StatusItem::UidValidity,
        "UNSEEN" => StatusItem::Unseen,
        "DELETED" => StatusItem::Deleted,
        "SIZE" => StatusItem::Size,
        "HIGHESTMODSEQ" => StatusItem::HighestModseq,
        _ => StatusItem::Other,
    }
}

fn apply_status_item(data: &mut ImapStatusData, item: StatusItem, val: Option<i64>) {
    let u32v = val.and_then(|v| u32::try_from(v).ok());
    let u64v = val.and_then(|v| u64::try_from(v).ok());
    match item {
        StatusItem::Messages => data.messages = u32v,
        StatusItem::Recent => data.recent = u32v,
        StatusItem::UidNext => data.uid_next = u32v,
        StatusItem::UidValidity => data.uid_validity = u32v,
        StatusItem::Unseen => data.unseen = u32v,
        StatusItem::Deleted => data.deleted = u32v,
        StatusItem::Size => data.size = u64v,
        StatusItem::HighestModseq => data.highest_modseq = u64v,
        StatusItem::Other => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed_all(lex: &mut ImapReplyLexer, s: &str) -> Vec<ImapEvent> {
        let mut data: &[u8] = s.as_bytes();
        lex.feed(&mut data).unwrap()
    }

    /// Feed one byte at a time and assert the result matches feeding the
    /// whole buffer at once — the core incremental-parsing guarantee.
    fn assert_split_matches_bulk(input: &[u8]) -> Vec<ImapEvent> {
        let mut bulk = ImapReplyLexer::new();
        let mut bulk_data = input;
        let bulk_events = bulk.feed(&mut bulk_data).unwrap();

        let mut split = ImapReplyLexer::new();
        let mut split_events = Vec::new();
        for &b in input {
            let mut one = [b];
            let mut slice: &[u8] = &one[..];
            split_events.extend(split.feed(&mut slice).unwrap());
            let _ = &mut one;
        }
        assert_eq!(bulk_events, split_events, "split vs bulk mismatch");
        bulk_events
    }

    #[test]
    fn greeting_ok_with_capability_code() {
        let mut lex = ImapReplyLexer::new();
        let ev = feed_all(&mut lex, "* OK [CAPABILITY IMAP4rev2 STARTTLS] ready\r\n");
        assert_eq!(
            ev,
            vec![ImapEvent::UntaggedOk {
                code: Some("CAPABILITY IMAP4rev2 STARTTLS".into()),
                text: "ready".into(),
            }]
        );
    }

    #[test]
    fn greeting_bye_and_preauth() {
        let mut lex = ImapReplyLexer::new();
        assert_eq!(
            feed_all(&mut lex, "* BYE too many connections\r\n"),
            vec![ImapEvent::Bye { code: None, text: "too many connections".into() }]
        );

        let mut lex2 = ImapReplyLexer::new();
        assert_eq!(
            feed_all(&mut lex2, "* PREAUTH already authenticated\r\n"),
            vec![ImapEvent::Preauth { code: None, text: "already authenticated".into() }]
        );
    }

    #[test]
    fn continuation_bare_and_with_text() {
        let mut lex = ImapReplyLexer::new();
        assert_eq!(
            feed_all(&mut lex, "+ \r\n"),
            vec![ImapEvent::Continuation { text: "".into() }]
        );

        let mut lex2 = ImapReplyLexer::new();
        assert_eq!(
            feed_all(&mut lex2, "+ go ahead\r\n"),
            vec![ImapEvent::Continuation { text: "go ahead".into() }]
        );

        let mut lex3 = ImapReplyLexer::new();
        assert_eq!(
            feed_all(&mut lex3, "+\r\n"),
            vec![ImapEvent::Continuation { text: "".into() }]
        );
    }

    #[test]
    fn tagged_ok_no_bad_with_code() {
        let mut lex = ImapReplyLexer::new();
        assert_eq!(
            feed_all(&mut lex, "A001 OK LOGIN completed\r\n"),
            vec![ImapEvent::Tagged {
                tag: "A001".into(),
                status: ImapStatus::Ok,
                code: None,
                message: "LOGIN completed".into(),
            }]
        );

        let mut lex2 = ImapReplyLexer::new();
        assert_eq!(
            feed_all(&mut lex2, "A002 NO [ALERT] denied\r\n"),
            vec![ImapEvent::Tagged {
                tag: "A002".into(),
                status: ImapStatus::No,
                code: Some("ALERT".into()),
                message: "denied".into(),
            }]
        );

        let mut lex3 = ImapReplyLexer::new();
        assert_eq!(
            feed_all(&mut lex3, "A003 BAD command unknown\r\n"),
            vec![ImapEvent::Tagged {
                tag: "A003".into(),
                status: ImapStatus::Bad,
                code: None,
                message: "command unknown".into(),
            }]
        );
    }

    #[test]
    fn tagged_ok_bare_code_no_message() {
        let mut lex = ImapReplyLexer::new();
        assert_eq!(
            feed_all(&mut lex, "A000 OK [READ-WRITE]\r\n"),
            vec![ImapEvent::Tagged {
                tag: "A000".into(),
                status: ImapStatus::Ok,
                code: Some("READ-WRITE".into()),
                message: "".into(),
            }]
        );
    }

    #[test]
    fn capability_tokens_parsed() {
        let mut lex = ImapReplyLexer::new();
        let ev = feed_all(
            &mut lex,
            "* CAPABILITY IMAP4rev2 STARTTLS AUTH=PLAIN IDLE\r\n",
        );
        assert_eq!(ev.len(), 1);
        match &ev[0] {
            ImapEvent::Capability(caps) => {
                assert!(caps.starttls);
                assert!(caps.auth_plain);
                assert!(caps.idle);
                assert_eq!(caps.tokens.len(), 4);
            }
            other => panic!("expected Capability, got {other:?}"),
        }
    }

    #[test]
    fn list_entry_quoted_and_atom_name() {
        let mut lex = ImapReplyLexer::new();
        let ev = feed_all(&mut lex, "* LIST (\\HasNoChildren) \"/\" INBOX\r\n");
        assert_eq!(
            ev,
            vec![ImapEvent::ListEntry(ImapListEntry {
                attributes: vec!["\\HasNoChildren".into()],
                delimiter: Some("/".into()),
                name: "INBOX".into(),
            })]
        );

        let mut lex2 = ImapReplyLexer::new();
        let ev2 = feed_all(&mut lex2, "* LIST () \"/\" \"My Folder\"\r\n");
        assert_eq!(
            ev2,
            vec![ImapEvent::ListEntry(ImapListEntry {
                attributes: vec![],
                delimiter: Some("/".into()),
                name: "My Folder".into(),
            })]
        );
    }

    #[test]
    fn list_entry_nil_delimiter() {
        let mut lex = ImapReplyLexer::new();
        let ev = feed_all(&mut lex, "* LSUB () NIL Everything\r\n");
        assert_eq!(
            ev,
            vec![ImapEvent::ListEntry(ImapListEntry {
                attributes: vec![],
                delimiter: None,
                name: "Everything".into(),
            })]
        );
    }

    #[test]
    fn status_data_parsed() {
        let mut lex = ImapReplyLexer::new();
        let ev = feed_all(
            &mut lex,
            "* STATUS INBOX (MESSAGES 17 UIDNEXT 18 UNSEEN 3)\r\n",
        );
        match &ev[0] {
            ImapEvent::StatusData(data) => {
                assert_eq!(data.mailbox, "INBOX");
                assert_eq!(data.messages, Some(17));
                assert_eq!(data.uid_next, Some(18));
                assert_eq!(data.unseen, Some(3));
            }
            other => panic!("expected StatusData, got {other:?}"),
        }
    }

    #[test]
    fn status_data_quoted_mailbox() {
        let mut lex = ImapReplyLexer::new();
        let ev = feed_all(&mut lex, "* STATUS \"My Box\" (MESSAGES 1)\r\n");
        match &ev[0] {
            ImapEvent::StatusData(data) => {
                assert_eq!(data.mailbox, "My Box");
                assert_eq!(data.messages, Some(1));
            }
            other => panic!("expected StatusData, got {other:?}"),
        }
    }

    #[test]
    fn search_numbers_and_empty() {
        let mut lex = ImapReplyLexer::new();
        assert_eq!(
            feed_all(&mut lex, "* SEARCH 1 2 9\r\n"),
            vec![ImapEvent::SearchNumbers(vec![1, 2, 9])]
        );

        let mut lex2 = ImapReplyLexer::new();
        assert_eq!(
            feed_all(&mut lex2, "* SEARCH\r\n"),
            vec![ImapEvent::SearchNumbers(vec![])]
        );
    }

    #[test]
    fn search_numbers_with_modseq_trailer() {
        let mut lex = ImapReplyLexer::new();
        assert_eq!(
            feed_all(&mut lex, "* SEARCH 2 5 (MODSEQ 12345)\r\n"),
            vec![ImapEvent::SearchNumbers(vec![2, 5])]
        );
    }

    #[test]
    fn exists_recent_expunge() {
        let mut lex = ImapReplyLexer::new();
        assert_eq!(feed_all(&mut lex, "* 5 EXISTS\r\n"), vec![ImapEvent::Exists(5)]);

        let mut lex2 = ImapReplyLexer::new();
        assert_eq!(feed_all(&mut lex2, "* 0 RECENT\r\n"), vec![ImapEvent::Recent(0)]);

        let mut lex3 = ImapReplyLexer::new();
        assert_eq!(feed_all(&mut lex3, "* 2 EXPUNGE\r\n"), vec![ImapEvent::Expunge(2)]);
    }

    #[test]
    fn top_level_flags_list() {
        // Regression test: the top-level `* FLAGS (...)` response must wait
        // for the terminating CRLF before completing — a prior bug jumped
        // straight from the closing `)` to expecting LF, skipping CR.
        let mut lex = ImapReplyLexer::new();
        let ev = feed_all(
            &mut lex,
            "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n",
        );
        assert_eq!(
            ev,
            vec![ImapEvent::FlagsList(vec![
                "\\Answered".into(),
                "\\Flagged".into(),
                "\\Deleted".into(),
                "\\Seen".into(),
                "\\Draft".into(),
            ])]
        );
    }

    #[test]
    fn fetch_simple_attrs_no_literal() {
        let mut lex = ImapReplyLexer::new();
        let ev = feed_all(&mut lex, "* 1 FETCH (FLAGS (\\Seen) UID 5 RFC822.SIZE 44)\r\n");
        match &ev[0] {
            ImapEvent::Fetch(data) => {
                assert_eq!(data.seq, 1);
                assert_eq!(data.flags, vec!["\\Seen".to_string()]);
                assert_eq!(data.uid, Some(5));
                assert_eq!(data.size, Some(44));
                assert!(data.body.is_empty());
            }
            other => panic!("expected Fetch, got {other:?}"),
        }
    }

    #[test]
    fn fetch_modseq_attr() {
        let mut lex = ImapReplyLexer::new();
        let ev = feed_all(&mut lex, "* 3 FETCH (MODSEQ (123456) FLAGS (\\Seen))\r\n");
        match &ev[0] {
            ImapEvent::Fetch(data) => {
                assert_eq!(data.modseq, Some(123456));
                assert_eq!(data.flags, vec!["\\Seen".to_string()]);
            }
            other => panic!("expected Fetch, got {other:?}"),
        }
    }

    #[test]
    fn fetch_with_literal_body() {
        let mut lex = ImapReplyLexer::new();
        let mut data: &[u8] =
            b"* 1 FETCH (UID 5 BODY[] {11}\r\nhello world)\r\nA000 OK done\r\n";
        let ev = lex.feed(&mut data).unwrap();
        // Events: FetchLiteralBegin, FetchLiteralData chunk(s),
        // FetchLiteralEnd, then Fetch, then Tagged.
        assert!(ev.iter().any(|e| matches!(
            e,
            ImapEvent::FetchLiteralBegin { seq: 1, section, size: 11 } if section.is_empty()
        )));
        assert!(ev.iter().any(|e| matches!(e, ImapEvent::FetchLiteralData(d) if d == b"hello world")));
        assert!(ev.iter().any(|e| *e == ImapEvent::FetchLiteralEnd { seq: 1 }));
        let fetch = ev
            .iter()
            .find_map(|e| match e {
                ImapEvent::Fetch(d) => Some(d),
                _ => None,
            })
            .expect("Fetch event");
        assert_eq!(fetch.uid, Some(5));
        assert_eq!(fetch.body, b"hello world");
        assert!(ev.iter().any(|e| matches!(
            e,
            ImapEvent::Tagged { status: ImapStatus::Ok, .. }
        )));
    }

    #[test]
    fn fetch_literal_split_across_feeds() {
        let mut lex = ImapReplyLexer::new();
        let mut p1: &[u8] = b"* 1 FETCH (BODY[] {5}\r\nhe";
        let e1 = lex.feed(&mut p1).unwrap();
        assert!(e1.iter().any(|e| matches!(
            e,
            ImapEvent::FetchLiteralBegin { seq: 1, section, size: 5 } if section.is_empty()
        )));
        assert!(e1.iter().any(|e| matches!(e, ImapEvent::FetchLiteralData(d) if d == b"he")));
        assert!(lex.in_literal());

        let mut p2: &[u8] = b"llo)\r\n";
        let e2 = lex.feed(&mut p2).unwrap();
        assert!(e2.iter().any(|e| matches!(e, ImapEvent::FetchLiteralData(d) if d == b"llo")));
        assert!(e2.iter().any(|e| *e == ImapEvent::FetchLiteralEnd { seq: 1 }));
        let fetch = e2
            .iter()
            .find_map(|e| match e {
                ImapEvent::Fetch(d) => Some(d),
                _ => None,
            })
            .expect("Fetch event");
        assert_eq!(fetch.body, b"hello");
    }

    #[test]
    fn fetch_literal_section_attributed_for_body_bracket() {
        let mut lex = ImapReplyLexer::new();
        let mut data: &[u8] = b"* 4 FETCH (UID 9 BODY[HEADER] {7}\r\nHeader!)\r\n";
        let ev = lex.feed(&mut data).unwrap();
        assert!(ev.iter().any(|e| matches!(
            e,
            ImapEvent::FetchLiteralBegin { seq: 4, section, size: 7 } if section == "HEADER"
        )));
        assert!(ev.iter().any(|e| *e == ImapEvent::FetchLiteralEnd { seq: 4 }));
    }

    #[test]
    fn fetch_literal_section_attributed_for_rfc822_variants() {
        for (attr, section) in [
            ("RFC822", "RFC822"),
            ("RFC822.TEXT", "RFC822.TEXT"),
            ("RFC822.HEADER", "RFC822.HEADER"),
        ] {
            let mut lex = ImapReplyLexer::new();
            let line = format!("* 2 FETCH ({attr} {{3}}\r\nabc)\r\n");
            let mut data: &[u8] = line.as_bytes();
            let ev = lex.feed(&mut data).unwrap();
            assert!(
                ev.iter().any(|e| matches!(
                    e,
                    ImapEvent::FetchLiteralBegin { seq: 2, section: s, size: 3 } if s == section
                )),
                "attr {attr}: {ev:?}"
            );
        }
    }

    #[test]
    fn fetch_skips_unrecognised_structure() {
        // ENVELOPE (with a parenthesized value and a quoted string that
        // itself contains parens) is skip-scanned, never buffered, but
        // FLAGS after it still parses correctly.
        let mut lex = ImapReplyLexer::new();
        let mut data: &[u8] =
            b"* 1 FETCH (ENVELOPE (\"date\" \"subj (with parens)\" NIL NIL) FLAGS (\\Seen))\r\n";
        let ev = lex.feed(&mut data).unwrap();
        match &ev[0] {
            ImapEvent::Fetch(d) => {
                assert_eq!(d.flags, vec!["\\Seen".to_string()]);
            }
            other => panic!("expected Fetch, got {other:?}"),
        }
    }

    #[test]
    fn fetch_flags_only_distinguishable_from_full() {
        let mut lex = ImapReplyLexer::new();
        let ev = feed_all(&mut lex, "* 1 FETCH (FLAGS (\\Seen))\r\n");
        match &ev[0] {
            ImapEvent::Fetch(d) => {
                assert_eq!(d.flags, vec!["\\Seen".to_string()]);
                assert!(d.uid.is_none());
                assert!(d.size.is_none());
                assert!(d.body.is_empty());
            }
            other => panic!("expected Fetch, got {other:?}"),
        }
    }

    #[test]
    fn enabled_tokens() {
        let mut lex = ImapReplyLexer::new();
        assert_eq!(
            feed_all(&mut lex, "* ENABLED CONDSTORE QRESYNC\r\n"),
            vec![ImapEvent::Enabled(vec!["CONDSTORE".into(), "QRESYNC".into()])]
        );
    }

    #[test]
    fn namespace_bounded_capture() {
        let mut lex = ImapReplyLexer::new();
        let ev = feed_all(&mut lex, "* NAMESPACE ((\"\" \"/\")) NIL NIL\r\n");
        assert_eq!(ev, vec![ImapEvent::Namespace("((\"\" \"/\")) NIL NIL".into())]);
    }

    #[test]
    fn quota_bounded_capture() {
        let mut lex = ImapReplyLexer::new();
        let ev = feed_all(&mut lex, "* QUOTA \"\" (STORAGE 10 512)\r\n");
        assert_eq!(ev, vec![ImapEvent::Quota("\"\" (STORAGE 10 512)".into())]);
    }

    #[test]
    fn quotaroot_and_id_bounded_capture() {
        let mut lex = ImapReplyLexer::new();
        assert_eq!(
            feed_all(&mut lex, "* QUOTAROOT INBOX \"\"\r\n"),
            vec![ImapEvent::QuotaRoot("INBOX \"\"".into())]
        );

        let mut lex2 = ImapReplyLexer::new();
        assert_eq!(
            feed_all(&mut lex2, "* ID (\"name\" \"hopf\")\r\n"),
            vec![ImapEvent::IdParams("(\"name\" \"hopf\")".into())]
        );
    }

    #[test]
    fn unrecognised_untagged_response_is_other() {
        let mut lex = ImapReplyLexer::new();
        assert_eq!(
            feed_all(&mut lex, "* VENDOR-EXTENSION foo bar\r\n"),
            vec![ImapEvent::Other]
        );
    }

    #[test]
    fn two_tagged_replies_in_one_feed() {
        let mut lex = ImapReplyLexer::new();
        let ev = feed_all(&mut lex, "A000 OK first\r\nA001 OK second\r\n");
        assert_eq!(ev.len(), 2);
        assert!(matches!(&ev[0], ImapEvent::Tagged { tag, .. } if tag == "A000"));
        assert!(matches!(&ev[1], ImapEvent::Tagged { tag, .. } if tag == "A001"));
    }

    #[test]
    fn split_one_byte_at_a_time_matches_bulk_for_tagged() {
        assert_split_matches_bulk(b"A001 OK [READ-WRITE] SELECT completed\r\n");
    }

    #[test]
    fn split_one_byte_at_a_time_matches_bulk_for_list() {
        assert_split_matches_bulk(b"* LIST (\\HasNoChildren) \"/\" INBOX\r\n");
    }

    #[test]
    fn split_one_byte_at_a_time_matches_bulk_for_fetch_with_literal() {
        // Literal chunk boundaries legitimately differ by split point (a
        // bulk feed can deliver the whole literal in one chunk; per-byte
        // feeding always yields one chunk per byte) — merge consecutive
        // `FetchLiteralData` chunks before comparing so this only asserts
        // on the reconstructed content and every other event.
        fn normalize(events: Vec<ImapEvent>) -> Vec<ImapEvent> {
            let mut out: Vec<ImapEvent> = Vec::new();
            for e in events {
                if let (Some(ImapEvent::FetchLiteralData(prev)), ImapEvent::FetchLiteralData(cur)) =
                    (out.last_mut(), &e)
                {
                    prev.extend_from_slice(cur);
                    continue;
                }
                out.push(e);
            }
            out
        }

        let input: &[u8] = b"* 1 FETCH (UID 5 BODY[] {5}\r\nhello)\r\nA000 OK done\r\n";
        let mut bulk = ImapReplyLexer::new();
        let mut bulk_data = input;
        let bulk_events = normalize(bulk.feed(&mut bulk_data).unwrap());

        let mut split = ImapReplyLexer::new();
        let mut split_events = Vec::new();
        for &b in input {
            let mut one = [b];
            let mut slice: &[u8] = &one[..];
            split_events.extend(split.feed(&mut slice).unwrap());
            let _ = &mut one;
        }
        assert_eq!(bulk_events, normalize(split_events));
    }

    #[test]
    fn split_one_byte_at_a_time_matches_bulk_for_flags_list() {
        assert_split_matches_bulk(b"* FLAGS (\\Answered \\Seen)\r\n");
    }

    #[test]
    fn oversized_token_errors_out() {
        let mut lex = ImapReplyLexer::new();
        let mut data = Vec::new();
        data.extend_from_slice(b"A000 OK ");
        data.extend(std::iter::repeat(b'x').take(MAX_TOKEN + 1));
        data.extend_from_slice(b"\r\n");
        let mut slice: &[u8] = &data;
        let err = lex.feed(&mut slice).unwrap_err();
        assert!(matches!(err, ImapError::Parse(_)));
    }

    #[test]
    fn malformed_first_word_before_status_errors() {
        let mut lex = ImapReplyLexer::new();
        let mut data: &[u8] = b"A001 HUH what\r\n";
        assert!(lex.feed(&mut data).is_err());
    }
}
