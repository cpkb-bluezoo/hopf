// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The grammar of each command's arguments, as a state machine the lexer feeds
//! token by token.
//!
//! When the lexer has read the verb of a command, it asks [`grammar_for`] for
//! that verb's machine and hands it every argument token the moment the token
//! is complete. The machine knows what may stand at that point in the command:
//! a string, a sequence set, a list of flags. It refuses the first token that
//! is wrong ([`Reject`]), without waiting for the rest of the line, and it is
//! asked before a literal is allowed ([`Grammar::literal`]) whether one may
//! stand there and how large it may be, so a synchronizing literal that is not
//! acceptable is refused before the client is told to send it. At the end of
//! the line it yields a typed [`Request`].
//!
//! Nothing is searched for: a machine only ever sees the next token, and what
//! lies inside one (the digits and separators of a sequence set) is read a
//! byte at a time by a builder, not split out of the text afterwards.

use std::borrow::Cow;
use std::collections::BTreeSet;

use hopf_mailbox::{MessageRange, MessageSet, WILDCARD};

use super::codec::{ArgToken, BTreeSetFlags};
use super::handler::StoreAction;
use super::status_items::StatusItem;

/// The largest literal that may stand for a name (a mailbox, a user, a
/// password, a quota root).
pub const MAX_NAME_LITERAL: u64 = 64 * 1024;

/// Why a command was refused: the text of the `BAD` reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reject(pub Cow<'static, str>);

impl Reject {
    fn new(message: &'static str) -> Self {
        Self(Cow::Borrowed(message))
    }
}

/// One argument token, as the machine sees it.
#[derive(Debug, Clone, Copy)]
pub enum Tok<'a> {
    /// A word written bare.
    Atom(&'a str),
    /// A quoted string, unescaped.
    Quoted(&'a str),
    /// A literal's octets.
    Literal(&'a [u8]),
    /// `(`
    Open,
    /// `)`
    Close,
}

impl ArgToken {
    /// This token as a machine sees it.
    pub fn as_tok(&self) -> Tok<'_> {
        match self {
            ArgToken::Atom(a) => Tok::Atom(a),
            ArgToken::Quoted(q) => Tok::Quoted(q),
            ArgToken::Literal(l) => Tok::Literal(l),
            ArgToken::Open => Tok::Open,
            ArgToken::Close => Tok::Close,
        }
    }
}

/// A command whose arguments have been read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// `LOGIN user password`
    Login { user: String, pass: String },
    /// `AUTHENTICATE mechanism [initial-response]`
    Authenticate { mechanism: String, initial_response: Option<String> },
    /// `SELECT` / `EXAMINE mailbox [(CONDSTORE) | (QRESYNC (...))]`
    Select { mailbox: String, examine: bool, condstore: bool, qresync: Option<(u64, u64)> },
    /// `CREATE mailbox [parameters]`
    Create { mailbox: String },
    /// `DELETE mailbox`
    Delete { mailbox: String },
    /// `SUBSCRIBE mailbox`
    Subscribe { mailbox: String },
    /// `UNSUBSCRIBE mailbox`
    Unsubscribe { mailbox: String },
    /// `RENAME from to`
    Rename { from: String, to: String },
    /// `[UID] COPY set mailbox`
    Copy { set: MessageSet, mailbox: String, by_uid: bool },
    /// `[UID] MOVE set mailbox`
    Move { set: MessageSet, mailbox: String, by_uid: bool },
    /// `ENABLE capability...`
    Enable { capabilities: Vec<String> },
    /// `COMPRESS mechanism`
    Compress { mechanism: String },
    /// `GETQUOTA root`
    GetQuota { root: String },
    /// `GETQUOTAROOT mailbox`
    GetQuotaRoot { mailbox: String },
    /// `[UID] STORE set item flags`
    Store { set: MessageSet, action: StoreAction, silent: bool, flags: BTreeSetFlags, by_uid: bool },
    /// `STATUS mailbox (items)`
    Status { mailbox: String, items: BTreeSet<StatusItem> },
}

/// The machine for one command's arguments.
pub trait Grammar: Send {
    /// The next argument token. An error refuses the command at once.
    fn token(&mut self, tok: Tok<'_>) -> Result<(), Reject>;

    /// A literal of `size` octets is announced where the next token would
    /// stand: may one be, of that size?
    fn literal(&mut self, size: u64) -> Result<(), Reject>;

    /// The end of the line.
    fn finish(self: Box<Self>) -> Result<Request, Reject>;
}

/// The machine for `verb` (upper case), if its arguments are read by one yet.
/// `by_uid` when the command was written `UID verb ...`.
pub fn grammar_for(verb: &str, by_uid: bool) -> Option<Box<dyn Grammar>> {
    let pattern = |slots: &'static [(Slot, &'static str)], extra: &'static str, build: Build| -> Option<Box<dyn Grammar>> {
        Some(Box::new(Pattern::new(slots, extra, build, by_uid)))
    };
    const NAME: &str = "Invalid mailbox name";
    if by_uid {
        return match verb {
            "STORE" => pattern(STORE, "Invalid flag list", build_store),
            "COPY" => pattern(COPY, "Invalid destination", build_copy),
            "MOVE" => pattern(COPY, "Invalid destination", build_move),
            _ => None,
        };
    }
    match verb {
        "LOGIN" => pattern(LOGIN, "Invalid LOGIN arguments", build_login),
        "AUTHENTICATE" => pattern(AUTHENTICATE, "Invalid AUTHENTICATE arguments", build_authenticate),
        "SELECT" => Some(Box::new(Select::new(false))),
        "EXAMINE" => Some(Box::new(Select::new(true))),
        "CREATE" => pattern(CREATE, NAME, build_create),
        "DELETE" => pattern(ONE_NAME, NAME, build_delete),
        "SUBSCRIBE" => pattern(ONE_NAME, NAME, build_subscribe),
        "UNSUBSCRIBE" => pattern(ONE_NAME, NAME, build_unsubscribe),
        "RENAME" => pattern(RENAME, "Invalid RENAME", build_rename),
        "COPY" => pattern(COPY, "Invalid destination", build_copy),
        "MOVE" => pattern(COPY, "Invalid destination", build_move),
        "ENABLE" => pattern(ENABLE, "Invalid ENABLE arguments", build_enable),
        "COMPRESS" => pattern(COMPRESS, "Unsupported compression mechanism", build_compress),
        "GETQUOTA" => pattern(ONE_ROOT, "Invalid quota root", build_getquota),
        "GETQUOTAROOT" => pattern(ONE_MAILBOX, "Invalid mailbox", build_getquotaroot),
        "STORE" => pattern(STORE, "Invalid flag list", build_store),
        "STATUS" => pattern(STATUS, "Invalid STATUS arguments", build_status),
        _ => None,
    }
}

// ── sequence sets ──────────────────────────────────────────────────────────

/// Reads a sequence set (`1`, `2:4`, `1,3:*`) a byte at a time.
#[derive(Debug, Default)]
pub struct SeqSetBuilder {
    ranges: Vec<MessageRange>,
    /// The value before the `:`, once it has been read.
    first: Option<u64>,
    /// The value being read.
    value: Option<u64>,
    /// Whether the value being read is `*`.
    star: bool,
    colon: bool,
    bad: bool,
}

impl SeqSetBuilder {
    /// The next byte.
    pub fn feed(&mut self, b: u8) {
        match b {
            b'0'..=b'9' if !self.star => {
                let digit = u64::from(b - b'0');
                match self.value.unwrap_or(0).checked_mul(10).and_then(|v| v.checked_add(digit)) {
                    Some(v) => self.value = Some(v),
                    None => self.bad = true,
                }
            }
            b'*' if self.value.is_none() && !self.star => self.star = true,
            b':' if !self.colon => {
                self.first = self.take_value();
                self.colon = true;
                if self.first.is_none() {
                    self.bad = true;
                }
            }
            b',' => self.end_part(),
            _ => self.bad = true,
        }
    }

    /// The value just read: `*` is the wildcard, a number must be 1 or more.
    fn take_value(&mut self) -> Option<u64> {
        let v = if self.star {
            Some(WILDCARD)
        } else {
            self.value.filter(|&v| v >= 1)
        };
        self.star = false;
        self.value = None;
        v
    }

    fn end_part(&mut self) {
        let empty = self.value.is_none() && !self.star && !self.colon;
        if empty {
            return; // an empty part between commas is skipped
        }
        let last = self.take_value();
        match (self.colon, self.first.take(), last) {
            (true, Some(a), Some(b)) => self.ranges.push(MessageRange::range(a, b)),
            (false, None, Some(n)) => self.ranges.push(MessageRange::single(n)),
            _ => self.bad = true,
        }
        self.colon = false;
    }

    /// The set, if what was read was one.
    pub fn finish(mut self) -> Option<MessageSet> {
        self.end_part();
        if self.bad {
            return None;
        }
        MessageSet::from_ranges(self.ranges)
    }
}

// ── slot patterns ──────────────────────────────────────────────────────────

/// What may stand in one place of a fixed-shape command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    /// An atom (of astring characters), a quoted string, or a literal.
    Astring,
    /// A bare word.
    Keyword,
    /// A bare word or a quoted string; may be missing.
    OptionalString,
    /// A sequence set.
    SeqSet,
    /// `(item item ...)` of STATUS items.
    StatusItems,
    /// A STORE's flags: `(flag ...)`, or the flags bare, to the end.
    StoreFlags,
    /// One or more bare words, to the end.
    Keywords,
    /// Whatever follows, to the end.
    IgnoreRest,
}

#[derive(Debug)]
enum Value {
    Text(String),
    Set(MessageSet),
    Flags(BTreeSetFlags),
    Status(BTreeSet<StatusItem>),
    Words(Vec<String>),
    None,
}

impl Value {
    fn text(self) -> String {
        match self {
            Value::Text(t) => t,
            _ => String::new(),
        }
    }

    fn optional_text(self) -> Option<String> {
        match self {
            Value::Text(t) => Some(t),
            _ => None,
        }
    }
}

/// A list being read across tokens.
#[derive(Debug)]
enum Partial {
    None,
    Flags(BTreeSetFlags),
    BareFlags(BTreeSetFlags),
    Status(BTreeSet<StatusItem>),
    Words(Vec<String>),
}

type Build = fn(Vec<Value>, bool) -> Result<Request, Reject>;

/// A command of a fixed shape: a run of slots, each with the reply to give if
/// what stands there is wrong.
struct Pattern {
    slots: &'static [(Slot, &'static str)],
    /// The reply for a token after the last slot.
    extra: &'static str,
    build: Build,
    by_uid: bool,
    at: usize,
    values: Vec<Value>,
    partial: Partial,
}

impl Pattern {
    fn new(slots: &'static [(Slot, &'static str)], extra: &'static str, build: Build, by_uid: bool) -> Self {
        Self { slots, extra, build, by_uid, at: 0, values: Vec::new(), partial: Partial::None }
    }

    fn done(&mut self, value: Value) {
        self.values.push(value);
        self.at += 1;
    }
}

/// A character an atom that is to be an astring may be made of
/// (RFC 3501 §9: ATOM-CHAR and `]`; 8-bit characters are UTF8=ACCEPT's).
fn is_astring_char(b: u8) -> bool {
    b >= 0x80 || (b.is_ascii_graphic() && !b"(){\"\\%*".contains(&b))
}

impl Grammar for Pattern {
    fn token(&mut self, tok: Tok<'_>) -> Result<(), Reject> {
        // In the middle of a list.
        match &mut self.partial {
            Partial::Flags(flags) => {
                let msg = self.slots[self.at].1;
                return match tok {
                    Tok::Atom(a) => {
                        flags.add(a);
                        Ok(())
                    }
                    Tok::Close => {
                        let flags = std::mem::take(flags);
                        self.partial = Partial::None;
                        self.done(Value::Flags(flags));
                        Ok(())
                    }
                    _ => Err(Reject::new(msg)),
                };
            }
            Partial::BareFlags(flags) => {
                return match tok {
                    Tok::Atom(a) => {
                        flags.add(a);
                        Ok(())
                    }
                    _ => Err(Reject::new(self.slots[self.at].1)),
                };
            }
            Partial::Status(items) => {
                return match tok {
                    Tok::Atom(a) => match StatusItem::parse(a) {
                        Some(item) => {
                            items.insert(item);
                            Ok(())
                        }
                        None => Err(Reject(Cow::Owned(format!("unknown STATUS item {a}")))),
                    },
                    Tok::Close if items.is_empty() => Err(Reject::new("empty STATUS list")),
                    Tok::Close => {
                        let items = std::mem::take(items);
                        self.partial = Partial::None;
                        self.done(Value::Status(items));
                        Ok(())
                    }
                    _ => Err(Reject::new("unclosed STATUS list")),
                };
            }
            Partial::Words(words) => {
                return match tok {
                    Tok::Atom(a) => {
                        words.push(a.to_ascii_uppercase());
                        Ok(())
                    }
                    _ => Err(Reject::new(self.slots[self.at].1)),
                };
            }
            Partial::None => {}
        }

        let Some(&(slot, msg)) = self.slots.get(self.at) else {
            return Err(Reject::new(self.extra));
        };
        match (slot, tok) {
            (Slot::Astring, Tok::Atom(a)) if !a.is_empty() && a.bytes().all(is_astring_char) => {
                self.done(Value::Text(a.to_string()));
            }
            (Slot::Astring, Tok::Quoted(q)) => self.done(Value::Text(q.to_string())),
            (Slot::Astring, Tok::Literal(l)) => self.done(Value::Text(String::from_utf8_lossy(l).into_owned())),
            (Slot::Keyword, Tok::Atom(a)) | (Slot::OptionalString, Tok::Atom(a)) | (Slot::OptionalString, Tok::Quoted(a)) => {
                self.done(Value::Text(a.to_string()));
            }
            (Slot::SeqSet, Tok::Atom(a)) => {
                let mut builder = SeqSetBuilder::default();
                for b in a.bytes() {
                    builder.feed(b);
                }
                match builder.finish() {
                    Some(set) => self.done(Value::Set(set)),
                    None => return Err(Reject::new(msg)),
                }
            }
            (Slot::StatusItems, Tok::Open) => self.partial = Partial::Status(BTreeSet::new()),
            (Slot::StatusItems, _) => return Err(Reject::new("STATUS requires parenthesized items")),
            (Slot::StoreFlags, Tok::Open) => self.partial = Partial::Flags(BTreeSetFlags::default()),
            (Slot::StoreFlags, Tok::Atom(a)) => {
                let mut flags = BTreeSetFlags::default();
                flags.add(a);
                self.partial = Partial::BareFlags(flags);
            }
            (Slot::Keywords, Tok::Atom(a)) => self.partial = Partial::Words(vec![a.to_ascii_uppercase()]),
            (Slot::IgnoreRest, _) => {}
            _ => return Err(Reject::new(msg)),
        }
        Ok(())
    }

    fn literal(&mut self, size: u64) -> Result<(), Reject> {
        if !matches!(self.partial, Partial::None) {
            return Err(Reject::new("Literal not allowed here"));
        }
        match self.slots.get(self.at).map(|&(slot, _)| slot) {
            Some(Slot::Astring) if size > MAX_NAME_LITERAL => Err(Reject::new("Literal too large")),
            Some(Slot::Astring | Slot::IgnoreRest) => Ok(()),
            _ => Err(Reject::new("Literal not allowed here")),
        }
    }

    fn finish(mut self: Box<Self>) -> Result<Request, Reject> {
        // A list that runs to the end of the line ends with it.
        match std::mem::replace(&mut self.partial, Partial::None) {
            Partial::BareFlags(flags) => self.done(Value::Flags(flags)),
            Partial::Words(words) => self.done(Value::Words(words)),
            Partial::None => {}
            Partial::Flags(_) => return Err(Reject::new(self.slots[self.at].1)),
            Partial::Status(_) => return Err(Reject::new("unclosed STATUS list")),
        }
        // What is left of the pattern must be able to be absent.
        while let Some(&(slot, msg)) = self.slots.get(self.at) {
            match slot {
                Slot::OptionalString => self.done(Value::None),
                Slot::IgnoreRest => self.done(Value::None),
                _ => return Err(Reject::new(msg)),
            }
        }
        let by_uid = self.by_uid;
        (self.build)(std::mem::take(&mut self.values), by_uid)
    }
}

// ── the commands ───────────────────────────────────────────────────────────

const LOGIN: &[(Slot, &str)] = &[
    (Slot::Astring, "Invalid LOGIN arguments"),
    (Slot::Astring, "Invalid LOGIN arguments"),
];
const AUTHENTICATE: &[(Slot, &str)] = &[
    (Slot::Keyword, "Missing mechanism"),
    (Slot::OptionalString, "Invalid AUTHENTICATE arguments"),
];
const ONE_NAME: &[(Slot, &str)] = &[(Slot::Astring, "Invalid mailbox name")];
const CREATE: &[(Slot, &str)] = &[(Slot::Astring, "Invalid mailbox name"), (Slot::IgnoreRest, "")];
const RENAME: &[(Slot, &str)] = &[(Slot::Astring, "Invalid RENAME"), (Slot::Astring, "Invalid RENAME")];
const COPY: &[(Slot, &str)] = &[(Slot::SeqSet, "Invalid sequence set"), (Slot::Astring, "Invalid destination")];
const ENABLE: &[(Slot, &str)] = &[(Slot::Keywords, "Invalid ENABLE arguments")];
const COMPRESS: &[(Slot, &str)] = &[(Slot::Keyword, "Unsupported compression mechanism")];
const ONE_ROOT: &[(Slot, &str)] = &[(Slot::Astring, "Invalid quota root")];
const ONE_MAILBOX: &[(Slot, &str)] = &[(Slot::Astring, "Invalid mailbox")];
const STORE: &[(Slot, &str)] = &[
    (Slot::SeqSet, "Invalid sequence set"),
    (Slot::Keyword, "Missing STORE item"),
    (Slot::StoreFlags, "Invalid flag list"),
];
const STATUS: &[(Slot, &str)] = &[(Slot::Astring, "missing mailbox name"), (Slot::StatusItems, "STATUS requires parenthesized items")];

fn take(values: &mut Vec<Value>) -> Value {
    if values.is_empty() {
        Value::None
    } else {
        values.remove(0)
    }
}

fn build_login(mut v: Vec<Value>, _: bool) -> Result<Request, Reject> {
    Ok(Request::Login { user: take(&mut v).text(), pass: take(&mut v).text() })
}

fn build_authenticate(mut v: Vec<Value>, _: bool) -> Result<Request, Reject> {
    Ok(Request::Authenticate { mechanism: take(&mut v).text(), initial_response: take(&mut v).optional_text() })
}

fn build_create(mut v: Vec<Value>, _: bool) -> Result<Request, Reject> {
    Ok(Request::Create { mailbox: take(&mut v).text() })
}

fn build_delete(mut v: Vec<Value>, _: bool) -> Result<Request, Reject> {
    Ok(Request::Delete { mailbox: take(&mut v).text() })
}

fn build_subscribe(mut v: Vec<Value>, _: bool) -> Result<Request, Reject> {
    Ok(Request::Subscribe { mailbox: take(&mut v).text() })
}

fn build_unsubscribe(mut v: Vec<Value>, _: bool) -> Result<Request, Reject> {
    Ok(Request::Unsubscribe { mailbox: take(&mut v).text() })
}

fn build_rename(mut v: Vec<Value>, _: bool) -> Result<Request, Reject> {
    Ok(Request::Rename { from: take(&mut v).text(), to: take(&mut v).text() })
}

fn take_set(v: &mut Vec<Value>) -> MessageSet {
    match take(v) {
        Value::Set(s) => s,
        _ => MessageSet::empty(),
    }
}

fn build_copy(mut v: Vec<Value>, by_uid: bool) -> Result<Request, Reject> {
    Ok(Request::Copy { set: take_set(&mut v), mailbox: take(&mut v).text(), by_uid })
}

fn build_move(mut v: Vec<Value>, by_uid: bool) -> Result<Request, Reject> {
    Ok(Request::Move { set: take_set(&mut v), mailbox: take(&mut v).text(), by_uid })
}

fn build_enable(mut v: Vec<Value>, _: bool) -> Result<Request, Reject> {
    match take(&mut v) {
        Value::Words(capabilities) => Ok(Request::Enable { capabilities }),
        _ => Err(Reject::new("Invalid ENABLE arguments")),
    }
}

fn build_compress(mut v: Vec<Value>, _: bool) -> Result<Request, Reject> {
    Ok(Request::Compress { mechanism: take(&mut v).text() })
}

fn build_getquota(mut v: Vec<Value>, _: bool) -> Result<Request, Reject> {
    Ok(Request::GetQuota { root: take(&mut v).text() })
}

fn build_getquotaroot(mut v: Vec<Value>, _: bool) -> Result<Request, Reject> {
    Ok(Request::GetQuotaRoot { mailbox: take(&mut v).text() })
}

fn build_store(mut v: Vec<Value>, by_uid: bool) -> Result<Request, Reject> {
    let set = take_set(&mut v);
    let item = take(&mut v).text();
    let (action, silent) = super::codec::parse_store_item(&item).map_err(|_| Reject::new("Invalid STORE item"))?;
    let flags = match take(&mut v) {
        Value::Flags(f) => f,
        _ => BTreeSetFlags::default(),
    };
    Ok(Request::Store { set, action, silent, flags, by_uid })
}

fn build_status(mut v: Vec<Value>, _: bool) -> Result<Request, Reject> {
    let mailbox = take(&mut v).text();
    match take(&mut v) {
        Value::Status(items) => Ok(Request::Status { mailbox, items }),
        _ => Err(Reject::new("STATUS requires parenthesized items")),
    }
}

// ── SELECT ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SelectAt {
    /// The mailbox.
    Mailbox,
    /// After it: the end, or `(`.
    Options,
    /// After `(`: the option's name.
    OptionName,
    /// `(CONDSTORE` ... `)`.
    CondstoreClose,
    /// `(QRESYNC` ... `(`.
    QresyncOpen,
    /// The UIDVALIDITY.
    QresyncUidValidity,
    /// The modification sequence.
    QresyncModSeq,
    /// The optional rest of the inner list, up to its `)`.
    QresyncInnerRest,
    /// The `)` that closes the QRESYNC option.
    QresyncClose,
    /// An option not known: skipped to its `)`.
    SkipOption,
    /// After the option's `)`: nothing more.
    Done,
}

/// `SELECT` / `EXAMINE mailbox [(CONDSTORE) | (QRESYNC (uidvalidity modseq [known-uids [seq-match]]))]`
struct Select {
    examine: bool,
    at: SelectAt,
    mailbox: String,
    condstore: bool,
    uid_validity: Option<u64>,
    mod_seq: Option<u64>,
    /// Depth inside a list being skipped.
    depth: usize,
}

impl Select {
    fn new(examine: bool) -> Self {
        Self {
            examine,
            at: SelectAt::Mailbox,
            mailbox: String::new(),
            condstore: false,
            uid_validity: None,
            mod_seq: None,
            depth: 0,
        }
    }
}

fn number(atom: &str) -> Option<u64> {
    (!atom.is_empty() && atom.bytes().all(|b| b.is_ascii_digit())).then(|| atom.parse().ok()).flatten()
}

impl Grammar for Select {
    fn token(&mut self, tok: Tok<'_>) -> Result<(), Reject> {
        let bad = || Reject::new("Invalid SELECT arguments");
        match (self.at, tok) {
            (SelectAt::Mailbox, Tok::Atom(a)) if !a.is_empty() && a.bytes().all(is_astring_char) => {
                self.mailbox = a.to_string();
                self.at = SelectAt::Options;
            }
            (SelectAt::Mailbox, Tok::Quoted(q)) => {
                self.mailbox = q.to_string();
                self.at = SelectAt::Options;
            }
            (SelectAt::Mailbox, Tok::Literal(l)) => {
                self.mailbox = String::from_utf8_lossy(l).into_owned();
                self.at = SelectAt::Options;
            }
            (SelectAt::Mailbox, _) => return Err(Reject::new("Invalid mailbox name")),
            (SelectAt::Options, Tok::Open) => self.at = SelectAt::OptionName,
            (SelectAt::OptionName, Tok::Atom(name)) => {
                if name.eq_ignore_ascii_case("CONDSTORE") {
                    self.condstore = true;
                    self.at = SelectAt::CondstoreClose;
                } else if name.eq_ignore_ascii_case("QRESYNC") {
                    self.at = SelectAt::QresyncOpen;
                } else {
                    self.depth = 1;
                    self.at = SelectAt::SkipOption;
                }
            }
            (SelectAt::CondstoreClose, Tok::Close) => self.at = SelectAt::Done,
            (SelectAt::QresyncOpen, Tok::Open) => self.at = SelectAt::QresyncUidValidity,
            (SelectAt::QresyncUidValidity, Tok::Atom(a)) => {
                self.uid_validity = Some(number(a).ok_or_else(bad)?);
                self.at = SelectAt::QresyncModSeq;
            }
            (SelectAt::QresyncModSeq, Tok::Atom(a)) => {
                self.mod_seq = Some(number(a).ok_or_else(bad)?);
                self.depth = 1;
                self.at = SelectAt::QresyncInnerRest;
            }
            (SelectAt::QresyncInnerRest, Tok::Open) => self.depth += 1,
            (SelectAt::QresyncInnerRest, Tok::Close) => {
                self.depth -= 1;
                if self.depth == 0 {
                    self.at = SelectAt::QresyncClose;
                }
            }
            (SelectAt::QresyncInnerRest, _) => {}
            (SelectAt::QresyncClose, Tok::Close) => self.at = SelectAt::Done,
            (SelectAt::SkipOption, Tok::Open) => self.depth += 1,
            (SelectAt::SkipOption, Tok::Close) => {
                self.depth -= 1;
                if self.depth == 0 {
                    self.at = SelectAt::Done;
                }
            }
            (SelectAt::SkipOption, _) => {}
            _ => return Err(bad()),
        }
        Ok(())
    }

    fn literal(&mut self, size: u64) -> Result<(), Reject> {
        match self.at {
            SelectAt::Mailbox if size > MAX_NAME_LITERAL => Err(Reject::new("Literal too large")),
            SelectAt::Mailbox | SelectAt::QresyncInnerRest | SelectAt::SkipOption => Ok(()),
            _ => Err(Reject::new("Literal not allowed here")),
        }
    }

    fn finish(self: Box<Self>) -> Result<Request, Reject> {
        match self.at {
            SelectAt::Mailbox => Err(Reject::new("Invalid mailbox name")),
            SelectAt::Options | SelectAt::Done => Ok(Request::Select {
                mailbox: self.mailbox,
                examine: self.examine,
                condstore: self.condstore,
                qresync: self.uid_validity.zip(self.mod_seq),
            }),
            _ => Err(Reject::new("Invalid SELECT arguments")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::codec::{ImapServerLexer, LexEvent};
    use hopf_mailbox::Flag;

    /// Lexes `wire` in chunks of `chunk` bytes.
    fn lex(wire: &[u8], chunk: usize) -> Vec<LexEvent> {
        let mut lexer = ImapServerLexer::new(8192);
        let mut out = Vec::new();
        for piece in wire.chunks(chunk) {
            let mut data: &[u8] = piece;
            out.extend(lexer.feed(&mut data));
            assert!(data.is_empty());
        }
        out
    }

    /// The requests, and the refusals, the lexer made of `wire`.
    fn outcomes(wire: &str, chunk: usize) -> Vec<Result<Request, String>> {
        lex(wire.as_bytes(), chunk)
            .into_iter()
            .filter_map(|e| match e {
                LexEvent::Command(c) => Some(Ok(c.request.expect("a typed request"))),
                LexEvent::Error { message, .. } => Some(Err(message)),
                _ => None,
            })
            .collect()
    }

    fn one(wire: &str) -> Result<Request, String> {
        let mut all = Vec::new();
        for chunk in [1, 2, 3, 7, 1000] {
            let got = outcomes(wire, chunk);
            assert_eq!(got.len(), 1, "{wire:?} chunk={chunk}: {got:?}");
            all.push(got.into_iter().next().unwrap());
        }
        assert!(all.windows(2).all(|w| w[0] == w[1]), "{wire:?}: chunking changed the outcome: {all:?}");
        all.pop().unwrap()
    }

    fn set(s: &str) -> MessageSet {
        MessageSet::parse(s).unwrap()
    }

    #[test]
    fn login_authenticate_and_names() {
        assert_eq!(one("a LOGIN alice secret\r\n"), Ok(Request::Login { user: "alice".into(), pass: "secret".into() }));
        assert_eq!(
            one("a LOGIN \"al ice\" {7}\r\nse cret\r\n"),
            Ok(Request::Login { user: "al ice".into(), pass: "se cret".into() })
        );
        assert_eq!(
            one("a AUTHENTICATE PLAIN AGZvbwBiYXI=\r\n"),
            Ok(Request::Authenticate { mechanism: "PLAIN".into(), initial_response: Some("AGZvbwBiYXI=".into()) })
        );
        assert_eq!(
            one("a AUTHENTICATE CRAM-MD5\r\n"),
            Ok(Request::Authenticate { mechanism: "CRAM-MD5".into(), initial_response: None })
        );
        assert_eq!(one("a CREATE Work\r\n"), Ok(Request::Create { mailbox: "Work".into() }));
        assert_eq!(one("a CREATE Work (USE (\\Sent))\r\n"), Ok(Request::Create { mailbox: "Work".into() }));
        assert_eq!(one("a DELETE \"A (b)\"\r\n"), Ok(Request::Delete { mailbox: "A (b)".into() }));
        assert_eq!(one("a RENAME one two\r\n"), Ok(Request::Rename { from: "one".into(), to: "two".into() }));
        assert_eq!(one("a COMPRESS DEFLATE\r\n"), Ok(Request::Compress { mechanism: "DEFLATE".into() }));
        assert_eq!(one("a GETQUOTA \"\"\r\n"), Ok(Request::GetQuota { root: String::new() }));
        assert_eq!(one("a GETQUOTAROOT INBOX\r\n"), Ok(Request::GetQuotaRoot { mailbox: "INBOX".into() }));
        assert_eq!(
            one("a ENABLE condstore QRESYNC\r\n"),
            Ok(Request::Enable { capabilities: vec!["CONDSTORE".into(), "QRESYNC".into()] })
        );
    }

    #[test]
    fn select_and_its_options() {
        let select = |examine, condstore, qresync| Ok(Request::Select { mailbox: "INBOX".into(), examine, condstore, qresync });
        assert_eq!(one("a SELECT INBOX\r\n"), select(false, false, None));
        assert_eq!(one("a EXAMINE INBOX\r\n"), select(true, false, None));
        assert_eq!(one("a SELECT INBOX (CONDSTORE)\r\n"), select(false, true, None));
        assert_eq!(one("a SELECT INBOX (QRESYNC (67890007 20050715194045000))\r\n"), select(false, false, Some((67890007, 20050715194045000))));
        assert_eq!(
            one("a SELECT INBOX (QRESYNC (1 2 41,43:211 (1,3:5 8,11:14)))\r\n"),
            select(false, false, Some((1, 2)))
        );
        // An option that is not known is skipped.
        assert_eq!(one("a SELECT INBOX (X-FUTURE (a (b)) )\r\n"), select(false, false, None));
        for bad in ["a SELECT\r\n", "a SELECT INBOX (CONDSTORE\r\n", "a SELECT INBOX extra\r\n", "a SELECT INBOX (QRESYNC (x 2))\r\n", "a SELECT INBOX (QRESYNC 1 2)\r\n"] {
            assert!(one(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn copy_move_store_and_uid() {
        let copy = |s: &str, by_uid| Ok(Request::Copy { set: set(s), mailbox: "Archive".into(), by_uid });
        assert_eq!(one("a COPY 1:3,5 Archive\r\n"), copy("1:3,5", false));
        assert_eq!(one("a UID COPY 100:* Archive\r\n"), copy("100:*", true));
        assert_eq!(
            one("a UID MOVE 7 \"Sent Items\"\r\n"),
            Ok(Request::Move { set: set("7"), mailbox: "Sent Items".into(), by_uid: true })
        );
        let flags = |names: &[&str]| {
            let mut f = BTreeSetFlags::default();
            for n in names {
                f.add(n);
            }
            f
        };
        let store = |action, silent, f, by_uid| Ok(Request::Store { set: set("1:*"), action, silent, flags: f, by_uid });
        assert_eq!(
            one("a STORE 1:* +FLAGS.SILENT (\\Seen $x)\r\n"),
            store(StoreAction::Add, true, flags(&["\\Seen", "$x"]), false)
        );
        // RFC 3501 §6.4.6 allows the flags bare.
        assert_eq!(one("a UID STORE 1:* -FLAGS \\Seen \\Deleted\r\n"), store(StoreAction::Remove, false, flags(&["\\Seen", "\\Deleted"]), true));
        assert_eq!(one("a STORE 1:* FLAGS ()\r\n"), store(StoreAction::Replace, false, flags(&[]), false));
        assert!(flags(&["\\Recent"]).flags.is_empty(), "\\Recent is the server's");
        assert!(flags(&["\\Seen"]).flags.contains(&Flag::Seen));
    }

    #[test]
    fn status_names_may_contain_parentheses() {
        let status = |name: &str, n| Ok(Request::Status { mailbox: name.into(), items: [StatusItem::Messages, StatusItem::Unseen].into_iter().take(n).collect() });
        assert_eq!(one("a STATUS \"Old (2023) mail\" (MESSAGES UNSEEN)\r\n"), status("Old (2023) mail", 2));
        assert_eq!(one("a STATUS {10}\r\nWork (new) (MESSAGES)\r\n"), status("Work (new)", 1));
        assert_eq!(one("a STATUS INBOX (MESSAGES)\r\n"), status("INBOX", 1));
    }

    /// The first wrong token ends the command, with the reply for that place,
    /// and the next command is read as if nothing had happened.
    #[test]
    fn a_wrong_token_refuses_at_once_and_the_next_command_is_unharmed() {
        let cases = [
            ("a LOGIN\r\n", "Invalid LOGIN arguments"),
            ("a LOGIN alice\r\n", "Invalid LOGIN arguments"),
            ("a LOGIN alice p%ss\r\n", "Invalid LOGIN arguments"),
            ("a LOGIN alice secret extra\r\n", "Invalid LOGIN arguments"),
            ("a LOGIN (alice) secret\r\n", "Invalid LOGIN arguments"),
            ("a AUTHENTICATE\r\n", "Missing mechanism"),
            ("a AUTHENTICATE \"PLAIN\"\r\n", "Missing mechanism"),
            ("a RENAME one\r\n", "Invalid RENAME"),
            ("a COPY x:y Archive\r\n", "Invalid sequence set"),
            ("a COPY 0 Archive\r\n", "Invalid sequence set"),
            ("a COPY 1:2\r\n", "Invalid destination"),
            ("a COPY 1:2 Archive more\r\n", "Invalid destination"),
            ("a STORE 1 +FLAGS\r\n", "Invalid flag list"),
            ("a STORE 1 BOGUS (\\Seen)\r\n", "Invalid STORE item"),
            ("a STORE 1\r\n", "Missing STORE item"),
            ("a STATUS INBOX MESSAGES\r\n", "STATUS requires parenthesized items"),
            ("a STATUS INBOX (BOGUS)\r\n", "unknown STATUS item BOGUS"),
            ("a STATUS INBOX ()\r\n", "empty STATUS list"),
            ("a ENABLE\r\n", "Invalid ENABLE arguments"),
            ("a ENABLE (CONDSTORE)\r\n", "Invalid ENABLE arguments"),
        ];
        for (wire, reply) in cases {
            for chunk in [1, 5, 1000] {
                let full = format!("{wire}b NOOP\r\n");
                let events = lex(full.as_bytes(), chunk);
                let errors: Vec<_> = events
                    .iter()
                    .filter_map(|e| match e {
                        LexEvent::Error { tag, message } => Some((tag.as_str(), message.as_str())),
                        _ => None,
                    })
                    .collect();
                assert_eq!(errors, vec![("a", reply)], "{wire:?} chunk={chunk}");
                let after = events.iter().filter(|e| matches!(e, LexEvent::Command(c) if c.verb == "NOOP")).count();
                assert_eq!(after, 1, "{wire:?} chunk={chunk}: the next command must run");
            }
        }
    }

    /// A literal is refused where it cannot stand, or is too big, before the
    /// client is told to send it; one it sends regardless is skipped.
    #[test]
    fn a_literal_is_refused_before_the_continuation() {
        // A synchronizing literal: no "+" is sent, the reply is BAD.
        for (wire, reply) in [
            ("a AUTHENTICATE {5}\r\n", "Literal not allowed here"),
            ("a COPY {3}\r\n", "Literal not allowed here"),
            ("a LOGIN {65537}\r\n", "Literal too large"),
            ("a SELECT INBOX ({4}\r\n", "Literal not allowed here"),
        ] {
            let events = lex(format!("{wire}b NOOP\r\n").as_bytes(), 1000);
            assert!(!events.iter().any(|e| matches!(e, LexEvent::NeedContinuation)), "{wire:?}: no continuation");
            assert!(
                events.iter().any(|e| matches!(e, LexEvent::Error { message, .. } if message == reply)),
                "{wire:?}: {events:?}"
            );
            assert!(events.iter().any(|e| matches!(e, LexEvent::Command(c) if c.verb == "NOOP")));
        }
        // A non-synchronizing one is sent anyway: its octets are skipped, not
        // read as commands.
        let events = lex(b"a COPY {6+}\r\nb NOOP\r\nc NOOP\r\n", 1000);
        let noops: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                LexEvent::Command(c) => Some(c.tag.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(noops, vec!["c".to_string()], "the six octets are not a command: {events:?}");
    }

    #[test]
    fn sequence_set_builder_agrees_with_the_set_parser() {
        let corpus = [
            "1", "1:5", "5:1", "*", "1:*", "*:1", "1,3,5", "1,3:5,7:*", "", ",", "1,,2", "1,", ",1", "0", "0:5", "1:0", "1:", ":1", "1:2:3",
            "1::2", "**", "*1", "1*", "18446744073709551615", "18446744073709551616", "99999999999999999999", "1,2,3,4,5,6,7,8,9,10,11,12", "a", "1a", "-1",
        ];
        for text in corpus {
            let mut builder = SeqSetBuilder::default();
            for b in text.bytes() {
                builder.feed(b);
            }
            assert_eq!(builder.finish(), MessageSet::parse(text).ok(), "{text:?}");
        }
    }
}
