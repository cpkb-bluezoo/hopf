// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The machines for `SEARCH`, `SORT` and `THREAD`.
//!
//! Search keys nest (`NOT`, `OR`, parentheses), so the keys read so far are
//! kept on a stack of what is waiting for its next key; a key that is
//! complete goes to the frame on top, which may complete in turn. Nothing
//! recurses, and the depth is capped.

use std::borrow::Cow;

use hopf_mailbox::{Flag, MessageSet, SearchCriteria};

use super::grammar::{is_astring_char, Grammar, Reject, Request, SeqSetBuilder, Tok, MAX_NAME_LITERAL};
use super::search_parse::parse_imap_date;
use super::sort::{validate_charset, SortCriterion, SortKey};
use super::thread::ThreadAlgorithm;

/// The deepest nesting of `(`, `NOT` and `OR` allowed.
const MAX_DEPTH: usize = 64;

/// A key waiting for the keys that complete it.
enum Frame {
    /// Keys read so far, to be ANDed: the whole criteria, or one `( ... )`.
    Group(Vec<SearchCriteria>),
    /// `NOT`, waiting for its key.
    Not,
    /// `OR`, waiting for its first key (`None`) or its second.
    Or(Option<SearchCriteria>),
}

/// What the next token must be.
enum Want {
    /// A key.
    Key,
    /// A string, for the key it ends.
    Str(fn(String) -> SearchCriteria),
    /// `HEADER`'s field name.
    HeaderName,
    /// `HEADER`'s pattern, for the field named.
    HeaderPattern(String),
    /// A date.
    Date(fn(i32, u32, u32) -> SearchCriteria),
    /// A number.
    Number(fn(u64) -> SearchCriteria),
    /// A flag or keyword name.
    Word(fn(String) -> SearchCriteria),
    /// `UID`'s message set.
    UidSet,
    /// `MODSEQ`'s entry name, or its value.
    ModSeq,
    /// `MODSEQ "entry"`'s type.
    ModSeqType,
    /// `MODSEQ "entry" type`'s value.
    ModSeqValue,
}

/// A key written as one word.
const WORD_KEYS: &[(&str, fn() -> SearchCriteria)] = &[
    ("ALL", || SearchCriteria::All),
    ("ANSWERED", SearchCriteria::answered),
    ("DELETED", SearchCriteria::deleted),
    ("DRAFT", SearchCriteria::draft),
    ("FLAGGED", SearchCriteria::flagged),
    ("NEW", || SearchCriteria::New),
    ("OLD", || SearchCriteria::Old),
    ("RECENT", SearchCriteria::recent),
    ("SEEN", SearchCriteria::seen),
    ("UNANSWERED", || SearchCriteria::NotFlag(Flag::Answered)),
    ("UNDELETED", || SearchCriteria::NotFlag(Flag::Deleted)),
    ("UNDRAFT", || SearchCriteria::NotFlag(Flag::Draft)),
    ("UNFLAGGED", || SearchCriteria::NotFlag(Flag::Flagged)),
    ("UNSEEN", SearchCriteria::unseen),
];

fn header(name: &'static str) -> impl Fn(String) -> SearchCriteria {
    move |pattern| SearchCriteria::Header { name: name.into(), pattern }
}

/// A string a token stands for.
fn string(tok: Tok<'_>) -> Result<String, Reject> {
    match tok {
        Tok::Atom(a) if !a.is_empty() && a.bytes().all(is_astring_char) => Ok(a.to_string()),
        Tok::Quoted(q) => Ok(q.to_string()),
        Tok::Literal(l) => Ok(String::from_utf8_lossy(l).into_owned()),
        _ => Err(Reject::new("expected string")),
    }
}

fn number(atom: &str) -> Option<u64> {
    (!atom.is_empty() && atom.bytes().all(|b| b.is_ascii_digit())).then(|| atom.parse().ok()).flatten()
}

fn message_set(atom: &str) -> Option<MessageSet> {
    let mut builder = SeqSetBuilder::default();
    for b in atom.bytes() {
        builder.feed(b);
    }
    builder.finish()
}

/// Reads search keys from tokens.
pub(super) struct SearchReader {
    stack: Vec<Frame>,
    want: Want,
}

impl SearchReader {
    pub(super) fn new() -> Self {
        Self { stack: vec![Frame::Group(Vec::new())], want: Want::Key }
    }

    pub(super) fn token(&mut self, tok: Tok<'_>) -> Result<(), Reject> {
        match std::mem::replace(&mut self.want, Want::Key) {
            Want::Key => self.key(tok),
            Want::Str(make) => self.deliver(make(string(tok)?)),
            Want::HeaderName => match tok {
                Tok::Atom(a) if !a.is_empty() && a.bytes().all(is_astring_char) => {
                    self.want = Want::HeaderPattern(a.to_string());
                    Ok(())
                }
                _ => Err(Reject::new("expected header name")),
            },
            Want::HeaderPattern(name) => {
                let pattern = string(tok)?;
                self.deliver(SearchCriteria::Header { name, pattern })
            }
            Want::Date(make) => {
                let (Tok::Atom(text) | Tok::Quoted(text)) = tok else {
                    return Err(Reject::new("expected date"));
                };
                let (y, m, d) = parse_imap_date(text).ok_or_else(|| Reject(Cow::Owned(format!("invalid date: {text}"))))?;
                self.deliver(make(y, m, d))
            }
            Want::Number(make) => match tok {
                Tok::Atom(a) => self.deliver(make(number(a).ok_or_else(|| Reject::new("expected number"))?)),
                _ => Err(Reject::new("expected number")),
            },
            Want::Word(make) => match tok {
                Tok::Atom(a) if !a.is_empty() && a.bytes().all(is_astring_char) => self.deliver(make(a.to_string())),
                _ => Err(Reject::new("expected keyword")),
            },
            Want::UidSet => match tok {
                Tok::Atom(a) => self.deliver(SearchCriteria::Uid(message_set(a).ok_or_else(|| Reject::new("expected message set"))?)),
                _ => Err(Reject::new("expected message set")),
            },
            Want::ModSeq => match tok {
                Tok::Quoted(_) => {
                    self.want = Want::ModSeqType;
                    Ok(())
                }
                Tok::Atom(a) => self.deliver(SearchCriteria::ModSeq(number(a).ok_or_else(|| Reject::new("expected number"))?)),
                _ => Err(Reject::new("expected number")),
            },
            Want::ModSeqType => match tok {
                Tok::Atom(_) => {
                    self.want = Want::ModSeqValue;
                    Ok(())
                }
                _ => Err(Reject::new("expected number")),
            },
            Want::ModSeqValue => match tok {
                Tok::Atom(a) => self.deliver(SearchCriteria::ModSeq(number(a).ok_or_else(|| Reject::new("expected number"))?)),
                _ => Err(Reject::new("expected number")),
            },
        }
    }

    /// A key, or the start or end of a group.
    fn key(&mut self, tok: Tok<'_>) -> Result<(), Reject> {
        match tok {
            Tok::Open => self.push(Frame::Group(Vec::new())),
            Tok::Close => {
                if self.stack.len() == 1 {
                    return Err(Reject::new("unexpected input after search expression"));
                }
                match self.stack.pop() {
                    Some(Frame::Group(keys)) => self.deliver(collapse(keys)),
                    _ => Err(Reject::new("expected search key")),
                }
            }
            Tok::Atom(a) if a.starts_with(|c: char| c.is_ascii_digit() || c == '*') => {
                let set = message_set(a).ok_or_else(|| Reject::new("expected message set"))?;
                self.deliver(SearchCriteria::Sequence(set))
            }
            Tok::Atom(a) => self.keyword(a),
            _ => Err(Reject::new("expected search key")),
        }
    }

    fn keyword(&mut self, word: &str) -> Result<(), Reject> {
        let upper = word.to_ascii_uppercase();
        if let Some((_, make)) = WORD_KEYS.iter().find(|(name, _)| *name == upper) {
            return self.deliver(make());
        }
        self.want = match upper.as_str() {
            "BCC" => Want::Str(|p| header("Bcc")(p)),
            "CC" => Want::Str(|p| header("Cc")(p)),
            "FROM" => Want::Str(SearchCriteria::from),
            "SUBJECT" => Want::Str(SearchCriteria::subject),
            "TO" => Want::Str(|p| header("To")(p)),
            "HEADER" => Want::HeaderName,
            "BODY" => Want::Str(SearchCriteria::body),
            "TEXT" => Want::Str(SearchCriteria::text),
            "BEFORE" => Want::Date(SearchCriteria::Before),
            "ON" => Want::Date(SearchCriteria::On),
            "SINCE" => Want::Date(SearchCriteria::Since),
            "SENTBEFORE" => Want::Date(SearchCriteria::SentBefore),
            "SENTON" => Want::Date(SearchCriteria::SentOn),
            "SENTSINCE" => Want::Date(SearchCriteria::SentSince),
            "LARGER" => Want::Number(SearchCriteria::Larger),
            "SMALLER" => Want::Number(SearchCriteria::Smaller),
            "KEYWORD" => Want::Word(SearchCriteria::Keyword),
            "UNKEYWORD" => Want::Word(SearchCriteria::Unkeyword),
            "UID" => Want::UidSet,
            "EMAILID" => Want::Str(SearchCriteria::EmailId),
            "MODSEQ" => Want::ModSeq,
            "NOT" => return self.push(Frame::Not),
            "OR" => return self.push(Frame::Or(None)),
            _ => return Err(Reject(Cow::Owned(format!("unknown search key: {word}")))),
        };
        Ok(())
    }

    fn push(&mut self, frame: Frame) -> Result<(), Reject> {
        if self.stack.len() >= MAX_DEPTH {
            return Err(Reject::new("search keys nested too deeply"));
        }
        self.stack.push(frame);
        Ok(())
    }

    /// A key is complete: it goes to the frame waiting for one.
    fn deliver(&mut self, mut key: SearchCriteria) -> Result<(), Reject> {
        loop {
            match self.stack.last_mut() {
                Some(Frame::Group(keys)) => {
                    keys.push(key);
                    return Ok(());
                }
                Some(Frame::Or(first @ None)) => {
                    *first = Some(key);
                    return Ok(());
                }
                Some(Frame::Or(Some(_))) => {
                    let Some(Frame::Or(Some(a))) = self.stack.pop() else { unreachable!() };
                    key = SearchCriteria::or(a, key);
                }
                Some(Frame::Not) => {
                    self.stack.pop();
                    key = SearchCriteria::negate(key);
                }
                None => unreachable!("the base group is never popped"),
            }
        }
    }

    /// May a literal stand where the next token does, and of this size?
    pub(super) fn literal(&self, size: u64) -> Result<(), Reject> {
        match self.want {
            Want::Str(_) | Want::HeaderPattern(_) if size > MAX_NAME_LITERAL => Err(Reject::new("Literal too large")),
            Want::Str(_) | Want::HeaderPattern(_) => Ok(()),
            _ => Err(Reject::new("Literal not allowed here")),
        }
    }

    /// The end of the line.
    pub(super) fn finish(mut self) -> Result<SearchCriteria, Reject> {
        match self.want {
            Want::Key => {}
            Want::Str(_) | Want::HeaderPattern(_) => return Err(Reject::new("expected string")),
            Want::HeaderName => return Err(Reject::new("expected header name")),
            Want::Date(_) => return Err(Reject::new("expected date")),
            Want::Number(_) | Want::ModSeq | Want::ModSeqType | Want::ModSeqValue => return Err(Reject::new("expected number")),
            Want::Word(_) => return Err(Reject::new("expected keyword")),
            Want::UidSet => return Err(Reject::new("expected message set")),
        }
        match self.stack.last() {
            Some(Frame::Not | Frame::Or(_)) => return Err(Reject::new("expected search key")),
            _ if self.stack.len() > 1 => return Err(Reject::new("missing closing parenthesis")),
            _ => {}
        }
        match self.stack.pop() {
            Some(Frame::Group(keys)) => Ok(collapse(keys)),
            _ => unreachable!("the base is a group"),
        }
    }
}

/// The keys of a group, ANDed.
fn collapse(mut keys: Vec<SearchCriteria>) -> SearchCriteria {
    match keys.len() {
        0 => SearchCriteria::All,
        1 => keys.pop().unwrap(),
        _ => SearchCriteria::And(keys),
    }
}

// ── SEARCH ─────────────────────────────────────────────────────────────────

/// `[UID] SEARCH key ...`
pub(super) struct Search {
    by_uid: bool,
    reader: SearchReader,
}

impl Search {
    pub(super) fn new(by_uid: bool) -> Self {
        Self { by_uid, reader: SearchReader::new() }
    }
}

impl Grammar for Search {
    fn token(&mut self, tok: Tok<'_>) -> Result<(), Reject> {
        self.reader.token(tok)
    }

    fn literal(&mut self, size: u64) -> Result<(), Reject> {
        self.reader.literal(size)
    }

    fn finish(self: Box<Self>) -> Result<Request, Reject> {
        Ok(Request::Search { criteria: self.reader.finish()?, by_uid: self.by_uid })
    }
}

/// The charset of a SORT or THREAD: only what is understood is accepted.
fn charset(tok: Tok<'_>) -> Result<(), Reject> {
    let name = match tok {
        Tok::Atom(a) if !a.is_empty() && a.bytes().all(is_astring_char) => a.to_string(),
        Tok::Quoted(q) => q.to_string(),
        Tok::Literal(l) => String::from_utf8_lossy(l).into_owned(),
        _ => return Err(Reject::new("expected astring")),
    };
    validate_charset(&name).map_err(|message| Reject(Cow::Owned(message)))
}

// ── SORT ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortAt {
    /// The `(` of the keys.
    Open,
    /// A key, or the `)`.
    Keys,
    /// The charset.
    Charset,
    /// The search keys.
    Search,
}

/// `[UID] SORT (key ...) charset search-key ...`
pub(super) struct Sort {
    by_uid: bool,
    at: SortAt,
    reverse: bool,
    keys: Vec<SortCriterion>,
    reader: SearchReader,
}

impl Sort {
    pub(super) fn new(by_uid: bool) -> Self {
        Self { by_uid, at: SortAt::Open, reverse: false, keys: Vec::new(), reader: SearchReader::new() }
    }
}

impl Grammar for Sort {
    fn token(&mut self, tok: Tok<'_>) -> Result<(), Reject> {
        match (self.at, tok) {
            (SortAt::Open, Tok::Open) => self.at = SortAt::Keys,
            (SortAt::Open, _) => return Err(Reject::new("SORT requires a parenthesized key list")),
            (SortAt::Keys, Tok::Atom(a)) => {
                let key = match a.to_ascii_uppercase().as_str() {
                    "REVERSE" => {
                        self.reverse = true;
                        return Ok(());
                    }
                    "ARRIVAL" => SortKey::Arrival,
                    "CC" => SortKey::Cc,
                    "DATE" => SortKey::Date,
                    "FROM" => SortKey::From,
                    "SIZE" => SortKey::Size,
                    "SUBJECT" => SortKey::Subject,
                    "TO" => SortKey::To,
                    other => return Err(Reject(Cow::Owned(format!("unknown SORT key {other}")))),
                };
                self.keys.push(SortCriterion { key, reverse: std::mem::take(&mut self.reverse) });
            }
            (SortAt::Keys, Tok::Close) => {
                if self.keys.is_empty() {
                    return Err(Reject::new("empty SORT key list"));
                }
                self.at = SortAt::Charset;
            }
            (SortAt::Keys, _) => return Err(Reject::new("unclosed SORT key list")),
            (SortAt::Charset, tok) => {
                charset(tok)?;
                self.at = SortAt::Search;
            }
            (SortAt::Search, tok) => return self.reader.token(tok),
        }
        Ok(())
    }

    fn literal(&mut self, size: u64) -> Result<(), Reject> {
        match self.at {
            SortAt::Charset if size > MAX_NAME_LITERAL => Err(Reject::new("Literal too large")),
            SortAt::Charset => Ok(()),
            SortAt::Search => self.reader.literal(size),
            _ => Err(Reject::new("Literal not allowed here")),
        }
    }

    fn finish(self: Box<Self>) -> Result<Request, Reject> {
        match self.at {
            SortAt::Open => Err(Reject::new("SORT requires a parenthesized key list")),
            SortAt::Keys => Err(Reject::new("unclosed SORT key list")),
            SortAt::Charset => Err(Reject::new("expected astring")),
            SortAt::Search => Ok(Request::Sort { keys: self.keys, criteria: self.reader.finish()?, by_uid: self.by_uid }),
        }
    }
}

// ── THREAD ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ThreadAt {
    /// The algorithm.
    Algorithm,
    /// The charset.
    Charset,
    /// The search keys.
    Search,
}

/// `[UID] THREAD algorithm charset search-key ...`
pub(super) struct Thread {
    by_uid: bool,
    at: ThreadAt,
    algorithm: Option<ThreadAlgorithm>,
    reader: SearchReader,
}

impl Thread {
    pub(super) fn new(by_uid: bool) -> Self {
        Self { by_uid, at: ThreadAt::Algorithm, algorithm: None, reader: SearchReader::new() }
    }
}

impl Grammar for Thread {
    fn token(&mut self, tok: Tok<'_>) -> Result<(), Reject> {
        match (self.at, tok) {
            (ThreadAt::Algorithm, Tok::Atom(a)) => {
                self.algorithm = Some(
                    ThreadAlgorithm::parse(a).ok_or_else(|| Reject(Cow::Owned(format!("unsupported THREAD algorithm {a}"))))?,
                );
                self.at = ThreadAt::Charset;
            }
            (ThreadAt::Algorithm, _) => return Err(Reject::new("THREAD requires an algorithm and charset")),
            (ThreadAt::Charset, tok) => {
                charset(tok)?;
                self.at = ThreadAt::Search;
            }
            (ThreadAt::Search, tok) => return self.reader.token(tok),
        }
        Ok(())
    }

    fn literal(&mut self, size: u64) -> Result<(), Reject> {
        match self.at {
            ThreadAt::Charset if size > MAX_NAME_LITERAL => Err(Reject::new("Literal too large")),
            ThreadAt::Charset => Ok(()),
            ThreadAt::Search => self.reader.literal(size),
            ThreadAt::Algorithm => Err(Reject::new("Literal not allowed here")),
        }
    }

    fn finish(self: Box<Self>) -> Result<Request, Reject> {
        match (self.at, self.algorithm) {
            (ThreadAt::Search, Some(algorithm)) => {
                Ok(Request::Thread { algorithm, criteria: self.reader.finish()?, by_uid: self.by_uid })
            }
            _ => Err(Reject::new("THREAD requires an algorithm and charset")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::codec::{ImapServerLexer, LexEvent};
    use crate::server::search_parse::parse_search;
    use crate::server::sort::parse_sort_command;
    use crate::server::thread::parse_thread_command;

    fn outcomes(wire: &str, chunk: usize) -> Vec<Result<Request, String>> {
        let mut lexer = ImapServerLexer::new(65536);
        let mut out = Vec::new();
        for piece in wire.as_bytes().chunks(chunk) {
            let mut data: &[u8] = piece;
            for e in lexer.feed(&mut data) {
                match e {
                    LexEvent::Command(c) => out.push(Ok(c.request)),
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

    const KEYS: &[&str] = &[
        "",
        "ALL",
        "unseen",
        "UNSEEN FROM \"alice\"",
        "FROM alice SUBJECT \"hello world\"",
        "NOT SEEN",
        "NOT NOT SEEN",
        "NOT (SEEN FLAGGED)",
        "OR SEEN FLAGGED",
        "OR SEEN OR FLAGGED DRAFT",
        "OR (SEEN DRAFT) NOT DELETED UNSEEN",
        "(SEEN) (FLAGGED)",
        "(SEEN (DRAFT (NEW)))",
        "()",
        "(())",
        "1",
        "1:5",
        "1,3:5,*",
        "*",
        "SEEN 1:5 UID 10:20",
        "UID 1",
        "UID *:5",
        "HEADER X-Foo bar",
        "HEADER X-Foo \"a b\"",
        "BODY foo TEXT \"bar baz\" BCC a CC b TO c",
        "BEFORE 1-Jan-2020",
        "SINCE \"01-Feb-2021\"",
        "ON 15-mar-2022 SENTBEFORE 1-Dec-1999 SENTON 2-Jan-2000 SENTSINCE 3-Feb-2001",
        "LARGER 100 SMALLER 5",
        "KEYWORD $x UNKEYWORD \\Foo",
        "EMAILID abc123",
        "MODSEQ 5",
        "MODSEQ \"/flags/\\\\Seen\" priv 7",
        "SUBJECT \"caf\u{e9}\"",
        "SUBJECT \"a \\\"quoted\\\" word\"",
        // Refused.
        "NOPE",
        "FROM",
        "NOT",
        "OR SEEN",
        "OR",
        "(SEEN",
        "SEEN)",
        ")",
        "(SEEN))",
        "NOT )",
        "OR SEEN )",
        "BEFORE",
        "BEFORE notadate",
        "BEFORE 32-Jan-2020",
        "BEFORE 1-Foo-2020",
        "LARGER x",
        "LARGER",
        "LARGER -1",
        "LARGER 99999999999999999999",
        "UID",
        "UID x",
        "HEADER",
        "HEADER X-Foo",
        "KEYWORD",
        "MODSEQ",
        "MODSEQ x",
        "MODSEQ \"/flags/\\\\Seen\" priv",
        "1:",
        "1a",
        "FROM \"unterminated",
    ];

    #[test]
    fn search_agrees_with_the_text_parser() {
        for keys in KEYS {
            let mine = one(&format!("a SEARCH {keys}\r\n"));
            let old = parse_search(keys);
            match (&mine, &old) {
                (Ok(Request::Search { criteria, by_uid: false }), Ok(o)) => assert_eq!(criteria, o, "{keys:?}"),
                (Err(_), Err(_)) => {}
                _ => panic!("{keys:?}: new {mine:?}, old {old:?}"),
            }
            let uid = one(&format!("a UID SEARCH {keys}\r\n"));
            match (&uid, &mine) {
                (Ok(Request::Search { criteria: u, by_uid: true }), Ok(Request::Search { criteria: m, .. })) => assert_eq!(u, m),
                (Err(a), Err(b)) => assert_eq!(a, b),
                _ => panic!("{keys:?}: {uid:?} vs {mine:?}"),
            }
        }
    }

    #[test]
    fn sort_and_thread_agree_with_the_text_parsers() {
        for keys in KEYS {
            for (head, charset) in [("(DATE)", "UTF-8"), ("(REVERSE ARRIVAL SUBJECT)", "us-ascii"), ("(DATE)", "KOI8-R")] {
                let args = format!("{head} {charset} {keys}");
                let mine = one(&format!("a SORT {args}\r\n"));
                let old = parse_sort_command(&args).and_then(|(k, rest)| parse_search(&rest).map(|c| (k, c)).map_err(|e| e.to_string()));
                match (&mine, &old) {
                    (Ok(Request::Sort { keys: k, criteria, .. }), Ok((ok, oc))) => assert_eq!((k, criteria), (ok, oc), "{args:?}"),
                    (Err(_), Err(_)) => {}
                    _ => panic!("{args:?}: new {mine:?}, old {old:?}"),
                }
            }
            for alg in ["REFERENCES", "orderedsubject", "WHATEVER"] {
                let args = format!("{alg} UTF-8 {keys}");
                let mine = one(&format!("a THREAD {args}\r\n"));
                let old = parse_thread_command(&args).and_then(|(a, rest)| parse_search(&rest).map(|c| (a, c)).map_err(|e| e.to_string()));
                match (&mine, &old) {
                    (Ok(Request::Thread { algorithm, criteria, .. }), Ok((oa, oc))) => assert_eq!((algorithm, criteria), (oa, oc), "{args:?}"),
                    (Err(_), Err(_)) => {}
                    _ => panic!("{args:?}: new {mine:?}, old {old:?}"),
                }
            }
        }
    }

    #[test]
    fn sort_and_thread_prefix_errors() {
        for (wire, message) in [
            ("a SORT\r\n", "SORT requires a parenthesized key list"),
            ("a SORT DATE UTF-8 ALL\r\n", "SORT requires a parenthesized key list"),
            ("a SORT () UTF-8 ALL\r\n", "empty SORT key list"),
            ("a SORT (DATE\r\n", "unclosed SORT key list"),
            ("a SORT (NOPE) UTF-8 ALL\r\n", "unknown SORT key NOPE"),
            ("a SORT (DATE)\r\n", "expected astring"),
            ("a SORT (DATE) KOI8-R ALL\r\n", "[BADCHARSET (UTF-8 US-ASCII)] unsupported charset KOI8-R"),
            ("a THREAD\r\n", "THREAD requires an algorithm and charset"),
            ("a THREAD REFERENCES\r\n", "THREAD requires an algorithm and charset"),
            ("a THREAD NOPE UTF-8 ALL\r\n", "unsupported THREAD algorithm NOPE"),
        ] {
            assert_eq!(one(wire), Err(message.to_string()), "{wire:?}");
        }
    }

    #[test]
    fn nesting_builds_the_tree_without_recursion_and_is_capped() {
        let r = one("a SEARCH OR SEEN NOT (FLAGGED DRAFT)\r\n").unwrap();
        let Request::Search { criteria, .. } = r else { panic!() };
        assert_eq!(
            criteria,
            SearchCriteria::or(
                SearchCriteria::seen(),
                SearchCriteria::negate(SearchCriteria::And(vec![SearchCriteria::flagged(), SearchCriteria::draft()]))
            )
        );
        let deep = |n: usize| format!("a SEARCH {}SEEN{}\r\n", "(".repeat(n), ")".repeat(n));
        assert!(one(&deep(MAX_DEPTH - 1)).is_ok());
        assert_eq!(one(&deep(MAX_DEPTH + 1)), Err("search keys nested too deeply".to_string()));
        let nots = format!("a SEARCH {}SEEN\r\n", "NOT ".repeat(MAX_DEPTH + 1));
        assert_eq!(one(&nots), Err("search keys nested too deeply".to_string()));
    }

    #[test]
    fn strings_may_be_literals_and_are_refused_early_elsewhere() {
        let r = one("a SEARCH FROM {5}\r\nal ce SUBJECT {2+}\r\nhi\r\n").unwrap();
        assert_eq!(
            r,
            Request::Search {
                criteria: SearchCriteria::And(vec![SearchCriteria::from("al ce"), SearchCriteria::subject("hi")]),
                by_uid: false
            }
        );
        // Where no string stands, a literal is refused before the continuation.
        assert_eq!(one("a SEARCH LARGER {3}\r\n"), Err("Literal not allowed here".to_string()));
        assert_eq!(one("a SEARCH {3}\r\n"), Err("Literal not allowed here".to_string()));
        assert_eq!(one("a SEARCH TEXT {70000}\r\n"), Err("Literal too large".to_string()));
        // A bad key refuses the command at once; the next command is unharmed.
        let got = outcomes("a SEARCH NOPE SEEN\r\nb SEARCH SEEN\r\n", 1);
        assert_eq!(got.len(), 2, "{got:?}");
        assert_eq!(got[0], Err("unknown search key: NOPE".to_string()));
        assert!(got[1].is_ok());
    }
}
