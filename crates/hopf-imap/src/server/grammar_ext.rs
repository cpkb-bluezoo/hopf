// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The machines for the extension commands: `GETMETADATA`, `SETMETADATA`,
//! `NOTIFY`, `SETQUOTA` and `ID`.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use super::grammar::{is_astring_char, Grammar, Reject, Request, Tok, MAX_NAME_LITERAL};
use super::metadata::{GetMetadataCommand, GetMetadataOptions, SetMetadataCommand};
use super::notify::{NotifyEvent, NotifyState};

/// An astring (an atom, a quoted string, or a literal) a token stands for.
fn astring(tok: Tok<'_>) -> Option<String> {
    match tok {
        Tok::Atom(a) if !a.is_empty() && a.bytes().all(is_astring_char) => Some(a.to_string()),
        Tok::Quoted(q) => Some(q.to_string()),
        Tok::Literal(l) => Some(String::from_utf8_lossy(l).into_owned()),
        _ => None,
    }
}

fn owned(message: String) -> Reject {
    Reject(Cow::Owned(message))
}

// ── GETMETADATA ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GetAt {
    /// The options' `(`, or the mailbox.
    Start,
    /// An option's name, or the `)`.
    Option,
    /// `DEPTH`'s value.
    Depth,
    /// `MAXSIZE`'s value.
    MaxSize,
    /// The mailbox.
    Mailbox,
    /// The entry, or the `(` of the entries.
    Entries,
    /// An entry, or the `)`.
    EntryList,
    /// Nothing more.
    Done,
}

/// `GETMETADATA [(DEPTH 0|1|infinity MAXSIZE n)] mailbox entry | (entry ...)`
pub(super) struct GetMetadata {
    at: GetAt,
    options: GetMetadataOptions,
    mailbox: String,
    entries: Vec<String>,
}

impl GetMetadata {
    pub(super) fn new() -> Self {
        Self { at: GetAt::Start, options: GetMetadataOptions::default(), mailbox: String::new(), entries: Vec::new() }
    }
}

impl Grammar for GetMetadata {
    fn token(&mut self, tok: Tok<'_>) -> Result<(), Reject> {
        match (self.at, tok) {
            (GetAt::Start, Tok::Open) => self.at = GetAt::Option,
            (GetAt::Start | GetAt::Mailbox, tok) => {
                self.mailbox = astring(tok).ok_or_else(|| Reject::new("expected astring"))?;
                self.at = GetAt::Entries;
            }
            (GetAt::Option, Tok::Atom(a)) if a.eq_ignore_ascii_case("DEPTH") => self.at = GetAt::Depth,
            (GetAt::Option, Tok::Atom(a)) if a.eq_ignore_ascii_case("MAXSIZE") => self.at = GetAt::MaxSize,
            (GetAt::Option, Tok::Atom(a)) => return Err(owned(format!("unknown GETMETADATA option: {}", a.to_ascii_uppercase()))),
            (GetAt::Option, Tok::Close) => self.at = GetAt::Mailbox,
            (GetAt::Depth, Tok::Atom(a)) => {
                self.options.depth = match a {
                    "0" => Some(0),
                    "1" => Some(1),
                    _ if a.eq_ignore_ascii_case("infinity") => None,
                    other => return Err(owned(format!("invalid DEPTH value: {other}"))),
                };
                self.at = GetAt::Option;
            }
            (GetAt::MaxSize, Tok::Atom(a)) => {
                self.options.max_size = Some(a.parse().map_err(|_| owned(format!("invalid MAXSIZE value: {a}")))?);
                self.at = GetAt::Option;
            }
            (GetAt::Entries, Tok::Open) => self.at = GetAt::EntryList,
            (GetAt::Entries, tok) => {
                self.entries.push(astring(tok).ok_or_else(|| Reject::new("expected astring"))?);
                self.at = GetAt::Done;
            }
            (GetAt::EntryList, Tok::Close) => {
                if self.entries.is_empty() {
                    return Err(Reject::new("empty entry list"));
                }
                self.at = GetAt::Done;
            }
            (GetAt::EntryList, tok) => self.entries.push(astring(tok).ok_or_else(|| Reject::new("expected astring"))?),
            (GetAt::Depth | GetAt::MaxSize, _) => return Err(Reject::new("expected atom")),
            (GetAt::Option, _) => return Err(Reject::new("expected atom")),
            (GetAt::Done, _) => return Err(Reject::new("unexpected input after entry list")),
        }
        Ok(())
    }

    fn literal(&mut self, size: u64) -> Result<(), Reject> {
        match self.at {
            GetAt::Start | GetAt::Mailbox | GetAt::Entries | GetAt::EntryList if size > MAX_NAME_LITERAL => {
                Err(Reject::new("Literal too large"))
            }
            GetAt::Start | GetAt::Mailbox | GetAt::Entries | GetAt::EntryList => Ok(()),
            _ => Err(Reject::new("Literal not allowed here")),
        }
    }

    fn finish(self: Box<Self>) -> Result<Request, Reject> {
        match self.at {
            GetAt::Done => Ok(Request::GetMetadata {
                command: GetMetadataCommand { mailbox: self.mailbox, entries: self.entries, options: self.options },
            }),
            GetAt::Entries => Err(Reject::new("GETMETADATA requires an entry list")),
            GetAt::Option | GetAt::EntryList | GetAt::Depth | GetAt::MaxSize => Err(Reject::new("unclosed parenthesized list")),
            GetAt::Start | GetAt::Mailbox => Err(Reject::new("expected astring")),
        }
    }
}

// ── SETMETADATA ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SetAt {
    Mailbox,
    Open,
    /// An entry name, or the `)`.
    Entry,
    /// The entry's value.
    Value,
    Done,
}

/// `SETMETADATA mailbox (entry value ...)`; a value of `NIL` deletes the entry.
pub(super) struct SetMetadata {
    at: SetAt,
    mailbox: String,
    entry: String,
    entries: Vec<(String, Option<String>)>,
}

impl SetMetadata {
    pub(super) fn new() -> Self {
        Self { at: SetAt::Mailbox, mailbox: String::new(), entry: String::new(), entries: Vec::new() }
    }
}

impl Grammar for SetMetadata {
    fn token(&mut self, tok: Tok<'_>) -> Result<(), Reject> {
        match (self.at, tok) {
            (SetAt::Mailbox, tok) => {
                self.mailbox = astring(tok).ok_or_else(|| Reject::new("expected astring"))?;
                self.at = SetAt::Open;
            }
            (SetAt::Open, Tok::Open) => self.at = SetAt::Entry,
            (SetAt::Open, _) => return Err(Reject::new("SETMETADATA requires a parenthesized entry-value list")),
            (SetAt::Entry, Tok::Close) => {
                if self.entries.is_empty() {
                    return Err(Reject::new("SETMETADATA requires at least one entry"));
                }
                self.at = SetAt::Done;
            }
            (SetAt::Entry, tok) => {
                self.entry = astring(tok).ok_or_else(|| Reject::new("expected astring"))?;
                self.at = SetAt::Value;
            }
            (SetAt::Value, Tok::Atom(a)) if a.eq_ignore_ascii_case("NIL") => {
                self.entries.push((std::mem::take(&mut self.entry), None));
                self.at = SetAt::Entry;
            }
            (SetAt::Value, tok) => {
                let value = astring(tok).ok_or_else(|| Reject::new("expected astring"))?;
                self.entries.push((std::mem::take(&mut self.entry), Some(value)));
                self.at = SetAt::Entry;
            }
            (SetAt::Done, _) => return Err(Reject::new("unexpected input after SETMETADATA entry list")),
        }
        Ok(())
    }

    fn literal(&mut self, size: u64) -> Result<(), Reject> {
        match self.at {
            // A value may be as large as the lexer allows literals to be.
            SetAt::Value => Ok(()),
            SetAt::Mailbox | SetAt::Entry if size > MAX_NAME_LITERAL => Err(Reject::new("Literal too large")),
            SetAt::Mailbox | SetAt::Entry => Ok(()),
            SetAt::Open | SetAt::Done => Err(Reject::new("Literal not allowed here")),
        }
    }

    fn finish(self: Box<Self>) -> Result<Request, Reject> {
        match self.at {
            SetAt::Done => Ok(Request::SetMetadata { command: SetMetadataCommand { mailbox: self.mailbox, entries: self.entries } }),
            SetAt::Mailbox => Err(Reject::new("expected astring")),
            SetAt::Open => Err(Reject::new("SETMETADATA requires a parenthesized entry-value list")),
            SetAt::Entry | SetAt::Value => Err(Reject::new("unclosed parenthesized list")),
        }
    }
}

// ── NOTIFY ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotifyAt {
    /// `NONE` or `SET`.
    Start,
    /// `STATUS`, or the `(`.
    AfterSet,
    /// The `(`.
    Open,
    /// The mailbox selector.
    Selector,
    /// An event group, or the `)`.
    Events,
    Done,
}

/// `NOTIFY NONE` | `NOTIFY SET [STATUS] (SELECTED event ...)`
pub(super) struct Notify {
    at: NotifyAt,
    state: NotifyState,
    events: BTreeSet<NotifyEvent>,
}

impl Notify {
    pub(super) fn new() -> Self {
        Self { at: NotifyAt::Start, state: NotifyState::None, events: BTreeSet::new() }
    }
}

impl Grammar for Notify {
    fn token(&mut self, tok: Tok<'_>) -> Result<(), Reject> {
        let nested = || Reject::new("nested selector groups and per-event status-item lists are not supported");
        match (self.at, tok) {
            (NotifyAt::Start, Tok::Atom(a)) if a.eq_ignore_ascii_case("NONE") => self.at = NotifyAt::Done,
            (NotifyAt::Start, Tok::Atom(a)) if a.eq_ignore_ascii_case("SET") => self.at = NotifyAt::AfterSet,
            (NotifyAt::Start, Tok::Atom(a)) => return Err(owned(format!("expected NONE or SET, got: {a}"))),
            (NotifyAt::Start, _) => return Err(Reject::new("expected NONE or SET")),
            // (The status keyword has no effect beyond being accepted.)
            (NotifyAt::AfterSet, Tok::Atom(a)) if a.eq_ignore_ascii_case("STATUS") => self.at = NotifyAt::Open,
            (NotifyAt::AfterSet | NotifyAt::Open, Tok::Open) => self.at = NotifyAt::Selector,
            (NotifyAt::AfterSet | NotifyAt::Open, _) => {
                return Err(Reject::new("expected a single parenthesized mailbox-selector group"))
            }
            (NotifyAt::Selector, Tok::Atom(a)) if a.eq_ignore_ascii_case("SELECTED") => self.at = NotifyAt::Events,
            (NotifyAt::Selector, Tok::Atom(a)) => {
                return Err(owned(format!("unsupported NOTIFY mailbox-selector: {a} (only SELECTED is implemented)")))
            }
            (NotifyAt::Selector, Tok::Close) => return Err(Reject::new("expected a mailbox-selector")),
            (NotifyAt::Selector, _) => return Err(nested()),
            (NotifyAt::Events, Tok::Atom(a)) => match a.to_ascii_uppercase().as_str() {
                "MESSAGENEW" => {
                    self.events.insert(NotifyEvent::MessageNew);
                }
                "MESSAGEEXPUNGE" => {
                    self.events.insert(NotifyEvent::MessageExpunge);
                }
                "FLAGCHANGE" => {
                    self.events.insert(NotifyEvent::FlagChange);
                }
                "NONE" => {}
                other => {
                    return Err(owned(format!(
                        "unsupported NOTIFY event-group: {other} (only MessageNew, MessageExpunge, FlagChange are implemented)"
                    )))
                }
            },
            (NotifyAt::Events, Tok::Close) => {
                self.state = NotifyState::Selected(std::mem::take(&mut self.events));
                self.at = NotifyAt::Done;
            }
            (NotifyAt::Events, _) => return Err(nested()),
            (NotifyAt::Done, Tok::Open) if matches!(self.state, NotifyState::Selected(_)) => {
                return Err(Reject::new("expected a single parenthesized mailbox-selector group"))
            }
            (NotifyAt::Done, _) => return Err(Reject::new("Invalid NOTIFY arguments")),
        }
        Ok(())
    }

    fn literal(&mut self, _size: u64) -> Result<(), Reject> {
        Err(Reject::new("Literal not allowed here"))
    }

    fn finish(self: Box<Self>) -> Result<Request, Reject> {
        match self.at {
            NotifyAt::Done => Ok(Request::Notify { state: self.state }),
            NotifyAt::Start => Err(Reject::new("expected NONE or SET")),
            NotifyAt::AfterSet | NotifyAt::Open => Err(Reject::new("expected a single parenthesized mailbox-selector group")),
            NotifyAt::Selector => Err(Reject::new("expected a mailbox-selector")),
            NotifyAt::Events => Err(Reject::new("expected a single parenthesized mailbox-selector group")),
        }
    }
}

// ── SETQUOTA ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuotaAt {
    Root,
    Open,
    /// A resource name, or the `)`.
    Name,
    /// The resource's limit.
    Limit,
    Done,
}

/// `SETQUOTA root (resource limit ...)`
pub(super) struct SetQuota {
    at: QuotaAt,
    root: String,
    name: String,
    resources: BTreeMap<String, i64>,
}

impl SetQuota {
    pub(super) fn new() -> Self {
        Self { at: QuotaAt::Root, root: String::new(), name: String::new(), resources: BTreeMap::new() }
    }
}

impl Grammar for SetQuota {
    fn token(&mut self, tok: Tok<'_>) -> Result<(), Reject> {
        match (self.at, tok) {
            (QuotaAt::Root, tok) => {
                self.root = astring(tok).ok_or_else(|| Reject::new("Invalid quota root"))?;
                self.at = QuotaAt::Open;
            }
            (QuotaAt::Open, Tok::Open) => self.at = QuotaAt::Name,
            (QuotaAt::Open, _) => return Err(Reject::new("SETQUOTA requires a parenthesized resource list")),
            (QuotaAt::Name, Tok::Atom(a)) => {
                self.name = a.to_ascii_uppercase();
                self.at = QuotaAt::Limit;
            }
            (QuotaAt::Name, Tok::Close) => self.at = QuotaAt::Done,
            (QuotaAt::Limit, Tok::Atom(a)) => {
                let limit = a.parse().map_err(|_| owned(format!("bad quota limit {a}")))?;
                self.resources.insert(std::mem::take(&mut self.name), limit);
                self.at = QuotaAt::Name;
            }
            (QuotaAt::Limit, _) => return Err(owned(format!("missing limit for {}", self.name))),
            (QuotaAt::Done, _) => return Err(Reject::new("Invalid SETQUOTA arguments")),
            _ => return Err(Reject::new("Invalid SETQUOTA arguments")),
        }
        Ok(())
    }

    fn literal(&mut self, size: u64) -> Result<(), Reject> {
        match self.at {
            QuotaAt::Root if size > MAX_NAME_LITERAL => Err(Reject::new("Literal too large")),
            QuotaAt::Root => Ok(()),
            _ => Err(Reject::new("Literal not allowed here")),
        }
    }

    fn finish(self: Box<Self>) -> Result<Request, Reject> {
        match self.at {
            QuotaAt::Done => Ok(Request::SetQuota { root: self.root, resources: self.resources }),
            QuotaAt::Root => Err(Reject::new("Invalid quota root")),
            QuotaAt::Open => Err(Reject::new("SETQUOTA requires a parenthesized resource list")),
            QuotaAt::Name => Err(Reject::new("unclosed quota resource list")),
            QuotaAt::Limit => Err(owned(format!("missing limit for {}", self.name))),
        }
    }
}

// ── ID ─────────────────────────────────────────────────────────────────────

/// RFC 2971's limits on what a client says of itself.
const MAX_ID_FIELDS: usize = 30;
const MAX_ID_FIELD_NAME: usize = 30;
const MAX_ID_VALUE: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdAt {
    /// `NIL`, or `(`.
    Start,
    /// A field name, or the `)`.
    Field,
    /// The field's value.
    Value,
    Done,
}

/// `ID NIL` | `ID ("field" "value"|NIL ...)`
pub(super) struct Id {
    at: IdAt,
    field: String,
    fields: Vec<(String, Option<String>)>,
}

impl Id {
    pub(super) fn new() -> Self {
        Self { at: IdAt::Start, field: String::new(), fields: Vec::new() }
    }
}

impl Grammar for Id {
    fn token(&mut self, tok: Tok<'_>) -> Result<(), Reject> {
        let bad = || Reject::new("Invalid ID arguments");
        match (self.at, tok) {
            (IdAt::Start, Tok::Atom(a)) if a.eq_ignore_ascii_case("NIL") => self.at = IdAt::Done,
            (IdAt::Start, Tok::Open) => self.at = IdAt::Field,
            (IdAt::Field, Tok::Close) => self.at = IdAt::Done,
            (IdAt::Field, Tok::Quoted(name)) => self.name(name.to_string())?,
            (IdAt::Field, Tok::Literal(name)) => self.name(String::from_utf8_lossy(name).into_owned())?,
            (IdAt::Value, Tok::Atom(a)) if a.eq_ignore_ascii_case("NIL") => {
                self.fields.push((std::mem::take(&mut self.field), None));
                self.at = IdAt::Field;
            }
            (IdAt::Value, Tok::Quoted(v)) => self.value(v.to_string())?,
            (IdAt::Value, Tok::Literal(v)) => self.value(String::from_utf8_lossy(v).into_owned())?,
            _ => return Err(bad()),
        }
        Ok(())
    }

    fn literal(&mut self, size: u64) -> Result<(), Reject> {
        let limit = match self.at {
            IdAt::Field => MAX_ID_FIELD_NAME,
            IdAt::Value => MAX_ID_VALUE,
            _ => return Err(Reject::new("Literal not allowed here")),
        };
        if size > limit as u64 {
            return Err(Reject::new("ID field too long"));
        }
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Request, Reject> {
        match self.at {
            IdAt::Done => Ok(Request::Id { fields: self.fields }),
            _ => Err(Reject::new("Invalid ID arguments")),
        }
    }
}

impl Id {
    fn name(&mut self, name: String) -> Result<(), Reject> {
        if self.fields.len() >= MAX_ID_FIELDS {
            return Err(Reject::new("Too many ID fields"));
        }
        if name.len() > MAX_ID_FIELD_NAME {
            return Err(Reject::new("ID field too long"));
        }
        self.field = name;
        self.at = IdAt::Value;
        Ok(())
    }

    fn value(&mut self, value: String) -> Result<(), Reject> {
        if value.len() > MAX_ID_VALUE {
            return Err(Reject::new("ID value too long"));
        }
        self.fields.push((std::mem::take(&mut self.field), Some(value)));
        self.at = IdAt::Field;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::codec::{ImapServerLexer, LexEvent};
    use crate::server::metadata::{parse_getmetadata, parse_setmetadata};
    use crate::server::notify::parse_notify;
    use crate::server::quota::parse_quota_resource_list;

    fn outcomes(wire: &str, chunk: usize) -> Vec<Result<Request, String>> {
        let mut lexer = ImapServerLexer::new(65536);
        let mut out = Vec::new();
        for piece in wire.as_bytes().chunks(chunk) {
            let mut data: &[u8] = piece;
            for e in lexer.feed(&mut data) {
                match e {
                    LexEvent::Command(c) => out.push(Ok(c.request.expect("a typed request"))),
                    LexEvent::Error { message, .. } => out.push(Err(message)),
                    _ => {}
                }
            }
        }
        out
    }

    fn one(wire: &str) -> Result<Request, String> {
        let all: Vec<_> = [1, 3, 1000].into_iter().map(|c| outcomes(wire, c)).collect();
        assert!(all.iter().all(|a| a.len() == 1), "{wire:?}: {all:?}");
        assert!(all.windows(2).all(|w| w[0] == w[1]), "{wire:?}: chunking changed the outcome: {all:?}");
        all.into_iter().next().unwrap().pop().unwrap()
    }

    #[test]
    fn getmetadata_agrees_with_the_text_parser() {
        for args in [
            "INBOX /private/comment",
            "INBOX (/private/comment)",
            "\"\" (/private/comment /shared/comment)",
            "\"Sent Items\" \"/private/a b\"",
            "(DEPTH 1) INBOX /private",
            "(DEPTH 0 MAXSIZE 1024) INBOX /private",
            "(MAXSIZE 5 DEPTH infinity) INBOX (/a /b)",
            "() INBOX /a",
            "(DEPTH 2) INBOX /a",
            "(DEPTH) INBOX /a",
            "(MAXSIZE x) INBOX /a",
            "(MAXSIZE 99999999999) INBOX /a",
            "(NOPE 1) INBOX /a",
            "(DEPTH 1 INBOX /a",
            "INBOX",
            "INBOX ()",
            "INBOX (/a",
            "INBOX (/a) /b",
            "INBOX /a /b",
            "",
            "(",
        ] {
            let mine = one(&format!("a GETMETADATA {args}\r\n"));
            let old = parse_getmetadata(args);
            match (&mine, &old) {
                (Ok(Request::GetMetadata { command }), Ok(o)) => assert_eq!(command, o, "{args:?}"),
                (Err(_), Err(_)) => {}
                _ => panic!("{args:?}: new {mine:?}, old {old:?}"),
            }
        }
    }

    #[test]
    fn setmetadata_agrees_with_the_text_parser() {
        for args in [
            "INBOX (/private/comment \"hello\")",
            "INBOX (/private/comment NIL)",
            "INBOX (/a \"1\" /b NIL /c value)",
            "\"\" (/shared/x \"y z\")",
            "INBOX (/a \"1\")  ",
            "INBOX",
            "INBOX ()",
            "INBOX /a",
            "INBOX (/a)",
            "INBOX (/a \"1\"",
            "INBOX (/a \"1\") extra",
            "",
        ] {
            let wire = format!("a SETMETADATA {args}\r\n");
            let mine = one(&wire);
            // The text parser reads literals spliced into the line.
            let old = parse_setmetadata(args);
            match (&mine, &old) {
                (Ok(Request::SetMetadata { command }), Ok(o)) => assert_eq!(command, o, "{args:?}"),
                (Err(_), Err(_)) => {}
                _ => panic!("{args:?}: new {mine:?}, old {old:?}"),
            }
        }
    }

    #[test]
    fn setmetadata_values_may_be_literals() {
        assert_eq!(
            one("a SETMETADATA INBOX (/a {3}\r\nabc /b {0}\r\n)\r\n"),
            Ok(Request::SetMetadata {
                command: SetMetadataCommand {
                    mailbox: "INBOX".to_string(),
                    entries: vec![("/a".to_string(), Some("abc".to_string())), ("/b".to_string(), Some(String::new()))]
                }
            })
        );
        // A literal is refused before the continuation where none may stand.
        assert_eq!(one("a SETMETADATA INBOX {3}\r\n"), Err("Literal not allowed here".to_string()));
    }

    #[test]
    fn notify_agrees_with_the_text_parser() {
        for args in [
            "NONE",
            "none",
            "SET (SELECTED MessageNew MessageExpunge FlagChange)",
            "set status (selected flagchange)",
            "SET (SELECTED)",
            "SET (SELECTED NONE)",
            "SET (PERSONAL MessageNew)",
            "SET (SELECTED MailboxName)",
            "SET (SELECTED MessageNew) (PERSONAL MessageNew)",
            "SET (SELECTED (UIDNEXT))",
            "SET (SELECTED MessageNew (UIDNEXT))",
            "SET ()",
            "SET",
            "SET SELECTED",
            "NONE extra",
            "WHAT",
            "",
        ] {
            let mine = one(&format!("a NOTIFY {args}\r\n"));
            let old = parse_notify(args);
            match (&mine, &old) {
                (Ok(Request::Notify { state }), Ok(o)) => assert_eq!(state, o, "{args:?}"),
                (Err(_), Err(_)) => {}
                _ => panic!("{args:?}: new {mine:?}, old {old:?}"),
            }
        }
    }

    #[test]
    fn setquota_agrees_with_the_text_parser() {
        for list in [
            "(STORAGE 1024 MESSAGE -1)",
            "(storage 5)",
            "()",
            "(STORAGE)",
            "(STORAGE x)",
            "(STORAGE 1",
            "(STORAGE 99999999999999999999)",
        ] {
            let mine = one(&format!("a SETQUOTA \"\" {list}\r\n"));
            let old = parse_quota_resource_list(list);
            match (&mine, &old) {
                (Ok(Request::SetQuota { root, resources }), Ok(o)) => {
                    assert_eq!((root.as_str(), resources), ("", o), "{list:?}")
                }
                (Err(_), Err(_)) => {}
                _ => panic!("{list:?}: new {mine:?}, old {old:?}"),
            }
        }
        assert_eq!(one("a SETQUOTA\r\n"), Err("Invalid quota root".to_string()));
        assert_eq!(one("a SETQUOTA root\r\n"), Err("SETQUOTA requires a parenthesized resource list".to_string()));
        assert_eq!(one("a SETQUOTA root STORAGE 5\r\n"), Err("SETQUOTA requires a parenthesized resource list".to_string()));
    }

    #[test]
    fn id_reads_what_the_client_says_of_itself() {
        assert_eq!(one("a ID NIL\r\n"), Ok(Request::Id { fields: vec![] }));
        assert_eq!(one("a ID ()\r\n"), Ok(Request::Id { fields: vec![] }));
        assert_eq!(
            one("a ID (\"name\" \"Mail\" \"os\" NIL \"v\" {3}\r\n1.0)\r\n"),
            Ok(Request::Id {
                fields: vec![
                    ("name".to_string(), Some("Mail".to_string())),
                    ("os".to_string(), None),
                    ("v".to_string(), Some("1.0".to_string()))
                ]
            })
        );
        for wire in ["a ID\r\n", "a ID (\"name\")\r\n", "a ID (name \"x\")\r\n", "a ID (\"a\" x)\r\n", "a ID NIL x\r\n", "a ID (\"a\" \"b\"\r\n"] {
            assert_eq!(one(wire), Err("Invalid ID arguments".to_string()), "{wire:?}");
        }
        let long = "x".repeat(31);
        assert_eq!(one(&format!("a ID (\"{long}\" \"v\")\r\n")), Err("ID field too long".to_string()));
        let value = "y".repeat(1025);
        assert_eq!(one(&format!("a ID (\"k\" \"{value}\")\r\n")), Err("ID value too long".to_string()));
        // Refused before the continuation.
        assert_eq!(one("a ID (\"k\" {2000}\r\n"), Err("ID field too long".to_string()));
        let many: String = (0..31).map(|i| format!("\"k{i}\" \"v\" ")).collect();
        assert_eq!(one(&format!("a ID ({many})\r\n")), Err("Too many ID fields".to_string()));
    }

    #[test]
    fn expunge_and_uid_expunge() {
        assert_eq!(one("a EXPUNGE\r\n"), Ok(Request::Expunge { uids: None }));
        assert_eq!(one("a EXPUNGE 1\r\n"), Err("Invalid EXPUNGE arguments".to_string()));
        let Ok(Request::Expunge { uids: Some(set) }) = one("a UID EXPUNGE 1:3,7\r\n") else { panic!() };
        assert_eq!(set, hopf_mailbox::MessageSet::parse("1:3,7").unwrap());
        assert_eq!(one("a UID EXPUNGE\r\n"), Err("Invalid UID set".to_string()));
        assert_eq!(one("a UID EXPUNGE x\r\n"), Err("Invalid UID set".to_string()));
    }
}
