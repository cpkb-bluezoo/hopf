// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The machines that build the client's structured response payloads from
//! tokens (see [`super::tokens`]): `NAMESPACE`, `QUOTA`, `QUOTAROOT`, `ID`,
//! `THREAD` and `METADATA`.

use super::reply::ImapEvent;
use super::state::{
    ImapMetadataData, ImapMetadataEntry, ImapNamespace, ImapNamespaceData, ImapQuotaData, ImapQuotaResource,
    ImapQuotaRootData, ImapThreadNode,
};
use super::tokens::{Bad, Output, Sink, Tok};

/// The text a word or string stands for.
fn text(tok: Tok<'_>) -> Option<String> {
    match tok {
        Tok::Atom(a) | Tok::Str(a) => Some(String::from_utf8_lossy(a).into_owned()),
        _ => None,
    }
}

fn is_nil(tok: Tok<'_>) -> bool {
    matches!(tok, Tok::Atom(a) if a.eq_ignore_ascii_case(b"NIL"))
}

fn number<T: std::str::FromStr>(tok: Tok<'_>) -> Option<T> {
    match tok {
        Tok::Atom(a) => std::str::from_utf8(a).ok()?.parse().ok(),
        _ => None,
    }
}

/// A sink that reads everything and keeps nothing.
pub(crate) struct Discard;

impl Sink for Discard {
    fn token(&mut self, _tok: Tok<'_>) -> Result<(), Bad> {
        Ok(())
    }

    fn keeps_literals(&self) -> bool {
        false
    }

    fn finish(self: Box<Self>) -> Result<Output, Bad> {
        Ok(Output::Event(ImapEvent::Other))
    }
}

// ── NAMESPACE ──────────────────────────────────────────────────────────────

/// `personal other shared`, each `NIL` or `((prefix delimiter extension...) ...)`.
#[derive(Default)]
pub(crate) struct NamespaceSink {
    data: ImapNamespaceData,
    /// Which of the three descriptions is being read.
    group: usize,
    depth: usize,
    /// The place in the entry: 0 prefix, 1 delimiter, 2 extension data.
    field: usize,
    prefix: String,
    delimiter: Option<String>,
}

impl NamespaceSink {
    fn group_mut(&mut self) -> &mut Vec<ImapNamespace> {
        match self.group {
            0 => &mut self.data.personal,
            1 => &mut self.data.other,
            _ => &mut self.data.shared,
        }
    }
}

impl Sink for NamespaceSink {
    fn token(&mut self, tok: Tok<'_>) -> Result<(), Bad> {
        match (self.depth, tok) {
            (0, _) if self.group > 2 => return Err(Bad),
            (0, tok) if is_nil(tok) => self.group += 1,
            (0, Tok::Open) => self.depth = 1,
            (1, Tok::Open) => {
                self.depth = 2;
                self.field = 0;
                self.prefix.clear();
                self.delimiter = None;
            }
            (1, Tok::Close) => {
                self.depth = 0;
                self.group += 1;
            }
            (2, Tok::Close) => {
                if self.field < 2 {
                    return Err(Bad);
                }
                let namespace = ImapNamespace { prefix: std::mem::take(&mut self.prefix), delimiter: self.delimiter.take() };
                self.group_mut().push(namespace);
                self.depth = 1;
            }
            (2, tok) if self.field == 0 => {
                self.prefix = text(tok).ok_or(Bad)?;
                self.field = 1;
            }
            (2, tok) if self.field == 1 => {
                self.delimiter = if is_nil(tok) { None } else { Some(text(tok).ok_or(Bad)?) };
                self.field = 2;
            }
            // Extension data after the delimiter ("TRANSLATION" ("..."), RFC 2342
            // §5): read, not kept.
            (2, Tok::Open) => self.depth = 3,
            (2, _) => {}
            (d, Tok::Open) if d >= 3 => self.depth += 1,
            (d, Tok::Close) if d >= 3 => self.depth -= 1,
            (d, _) if d >= 3 => {}
            _ => return Err(Bad),
        }
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Output, Bad> {
        if self.depth != 0 {
            return Err(Bad);
        }
        Ok(Output::Event(ImapEvent::Namespace(self.data)))
    }
}

// ── QUOTA ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum QuotaAt {
    #[default]
    Root,
    Open,
    Name,
    Usage,
    Limit,
    Done,
}

/// `root (resource usage limit ...)`
#[derive(Default)]
pub(crate) struct QuotaSink {
    at: QuotaAt,
    data: ImapQuotaData,
    name: String,
    usage: i64,
}

impl Sink for QuotaSink {
    fn token(&mut self, tok: Tok<'_>) -> Result<(), Bad> {
        match (self.at, tok) {
            (QuotaAt::Root, tok) => {
                self.data.root = text(tok).ok_or(Bad)?;
                self.at = QuotaAt::Open;
            }
            (QuotaAt::Open, Tok::Open) => self.at = QuotaAt::Name,
            (QuotaAt::Name, Tok::Close) => self.at = QuotaAt::Done,
            (QuotaAt::Name, Tok::Atom(a)) => {
                self.name = String::from_utf8_lossy(a).into_owned();
                self.at = QuotaAt::Usage;
            }
            (QuotaAt::Usage, tok) => {
                self.usage = number(tok).ok_or(Bad)?;
                self.at = QuotaAt::Limit;
            }
            (QuotaAt::Limit, tok) => {
                let limit = number(tok).ok_or(Bad)?;
                self.data.resources.push(ImapQuotaResource { name: std::mem::take(&mut self.name), usage: self.usage, limit });
                self.at = QuotaAt::Name;
            }
            (QuotaAt::Done, _) => {}
            _ => return Err(Bad),
        }
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Output, Bad> {
        match self.at {
            QuotaAt::Done => Ok(Output::Event(ImapEvent::Quota(self.data))),
            _ => Err(Bad),
        }
    }
}

// ── QUOTAROOT ──────────────────────────────────────────────────────────────

/// `mailbox root ...`
#[derive(Default)]
pub(crate) struct QuotaRootSink {
    named: bool,
    data: ImapQuotaRootData,
}

impl Sink for QuotaRootSink {
    fn token(&mut self, tok: Tok<'_>) -> Result<(), Bad> {
        let name = text(tok).ok_or(Bad)?;
        if self.named {
            self.data.roots.push(name);
        } else {
            self.data.mailbox = name;
            self.named = true;
        }
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Output, Bad> {
        if !self.named {
            return Err(Bad);
        }
        Ok(Output::Event(ImapEvent::QuotaRoot(self.data)))
    }
}

// ── ID ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum IdAt {
    #[default]
    Start,
    Field,
    Value,
    Done,
}

/// `NIL` or `("field" "value" ...)`
#[derive(Default)]
pub(crate) struct IdSink {
    at: IdAt,
    field: String,
    params: Vec<(String, String)>,
}

impl Sink for IdSink {
    fn token(&mut self, tok: Tok<'_>) -> Result<(), Bad> {
        match (self.at, tok) {
            (IdAt::Start, tok) if is_nil(tok) => self.at = IdAt::Done,
            (IdAt::Start, Tok::Open) => self.at = IdAt::Field,
            // (A field with no value at the end is dropped, as it always was.)
            (IdAt::Field | IdAt::Value, Tok::Close) => self.at = IdAt::Done,
            (IdAt::Field, tok) => {
                self.field = text(tok).ok_or(Bad)?;
                self.at = IdAt::Value;
            }
            // (A value of NIL is passed on as the word, as it always was.)
            (IdAt::Value, tok) => {
                let value = text(tok).ok_or(Bad)?;
                self.params.push((std::mem::take(&mut self.field), value));
                self.at = IdAt::Field;
            }
            (IdAt::Done, _) => {}
            _ => return Err(Bad),
        }
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Output, Bad> {
        match self.at {
            IdAt::Done => Ok(Output::Event(ImapEvent::IdParams(self.params))),
            _ => Err(Bad),
        }
    }
}

// ── THREAD ─────────────────────────────────────────────────────────────────

/// One `( ... )` of a THREAD response, as far as it has been read.
#[derive(Default)]
struct Chain {
    /// The messages of the chain, each the single reply to the one before,
    /// except that the last may have groups of replies.
    nodes: Vec<ImapThreadNode>,
    /// Groups have been given to the last node: nothing may follow them.
    closed: bool,
}

impl Chain {
    /// The chain as one tree.
    fn fold(mut self) -> Option<ImapThreadNode> {
        let mut tree = self.nodes.pop()?;
        while let Some(mut parent) = self.nodes.pop() {
            parent.children.push(tree);
            tree = parent;
        }
        Some(tree)
    }
}

/// `(3)(1 2 (4)(5))`: a forest of threads.
#[derive(Default)]
pub(crate) struct ThreadSink {
    threads: Vec<ImapThreadNode>,
    open: Vec<Chain>,
}

impl Sink for ThreadSink {
    fn token(&mut self, tok: Tok<'_>) -> Result<(), Bad> {
        match tok {
            Tok::Open => {
                // A group of replies may follow a message, but not another group's end.
                if let Some(parent) = self.open.last() {
                    if parent.nodes.is_empty() {
                        return Err(Bad);
                    }
                }
                self.open.push(Chain::default());
            }
            Tok::Atom(_) => {
                let n = number(tok).ok_or(Bad)?;
                let chain = self.open.last_mut().ok_or(Bad)?;
                if chain.closed {
                    return Err(Bad);
                }
                chain.nodes.push(ImapThreadNode { result_number: n, children: Vec::new() });
            }
            Tok::Close => {
                let tree = self.open.pop().ok_or(Bad)?.fold().ok_or(Bad)?;
                match self.open.last_mut() {
                    Some(parent) => {
                        parent.nodes.last_mut().ok_or(Bad)?.children.push(tree);
                        parent.closed = true;
                    }
                    None => self.threads.push(tree),
                }
            }
            Tok::Str(_) => return Err(Bad),
        }
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Output, Bad> {
        if !self.open.is_empty() {
            return Err(Bad);
        }
        Ok(Output::Event(ImapEvent::ThreadData(self.threads)))
    }
}

// ── METADATA ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum MetadataAt {
    #[default]
    Mailbox,
    Open,
    Entry,
    Value,
    Done,
}

/// `mailbox (entry value ...)`; a value may be `NIL`, a string or a literal.
#[derive(Default)]
pub(crate) struct MetadataSink {
    at: MetadataAt,
    data: ImapMetadataData,
    entry: String,
}

impl Sink for MetadataSink {
    fn token(&mut self, tok: Tok<'_>) -> Result<(), Bad> {
        match (self.at, tok) {
            (MetadataAt::Mailbox, tok) => {
                self.data.mailbox = text(tok).ok_or(Bad)?;
                self.at = MetadataAt::Open;
            }
            (MetadataAt::Open, Tok::Open) => self.at = MetadataAt::Entry,
            (MetadataAt::Entry, Tok::Close) => self.at = MetadataAt::Done,
            (MetadataAt::Entry, tok) => {
                self.entry = text(tok).ok_or(Bad)?;
                self.at = MetadataAt::Value;
            }
            (MetadataAt::Value, tok) => {
                let value = if is_nil(tok) { None } else { Some(text(tok).ok_or(Bad)?) };
                self.data.entries.push(ImapMetadataEntry { entry: std::mem::take(&mut self.entry), value });
                self.at = MetadataAt::Entry;
            }
            (MetadataAt::Done, _) => {}
            _ => return Err(Bad),
        }
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Output, Bad> {
        match self.at {
            MetadataAt::Done => Ok(Output::Event(ImapEvent::Metadata(self.data))),
            _ => Err(Bad),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::endpoint::parse_id_params;
    use crate::client::reply::ImapEvent as E;
    use crate::client::reply::ImapReplyLexer;
    use crate::client::state::{parse_thread_response, ImapNamespaceData as Ns};

    const CHUNKS: [usize; 5] = [1, 2, 3, 7, 4096];

    /// The one event `* line` makes, however the bytes arrive.
    fn event(line: &str) -> ImapEvent {
        let mut all = Vec::new();
        for chunk in CHUNKS {
            let mut lexer = ImapReplyLexer::new();
            let mut events = Vec::new();
            for piece in line.as_bytes().chunks(chunk) {
                let mut data: &[u8] = piece;
                events.extend(lexer.feed(&mut data).expect("no protocol error"));
                assert!(data.is_empty());
            }
            assert_eq!(events.len(), 1, "{line:?} chunk={chunk}: {events:?}");
            all.push(events.pop().unwrap());
        }
        assert!(all.windows(2).all(|w| w[0] == w[1]), "{line:?}: chunking changed the outcome: {all:?}");
        all.pop().unwrap()
    }

    #[test]
    fn namespace_agrees_with_the_text_parser() {
        for payload in [
            "((\"\" \"/\")) NIL NIL",
            "((\"INBOX.\" \".\")) ((\"user.\" \".\")) ((\"#shared.\" \".\"))",
            "NIL NIL NIL",
            "((\"\" NIL))",
            "((\"\" \"/\") (\"Other\" \"/\")) NIL NIL",
            "(( \"\" \"/\" )) nil NIL",
        ] {
            let want = Ns::parse(payload).expect("the oracle reads it");
            assert_eq!(event(&format!("* NAMESPACE {payload}\r\n")), E::Namespace(want), "{payload:?}");
        }
        for payload in ["((\"\" \"/\")", "(", "x", "((\"\"))", "((\"\" \"/\")) ((", ")"] {
            assert_eq!(event(&format!("* NAMESPACE {payload}\r\n")), E::Other, "{payload:?}");
        }
    }

    #[test]
    fn namespace_extension_data_and_literals_are_read() {
        let want = Ns {
            personal: vec![ImapNamespace { prefix: "abc".into(), delimiter: Some("/".into()) }],
            other: vec![],
            shared: vec![],
        };
        // RFC 2342 extension data after the delimiter is read and not kept.
        assert_eq!(
            event("* NAMESPACE ((\"abc\" \"/\" \"TRANSLATION\" (\"x\" (\"y\")))) NIL NIL\r\n"),
            E::Namespace(want.clone())
        );
        // A literal stands for any string.
        assert_eq!(event("* NAMESPACE (({3}\r\nabc \"/\")) NIL NIL\r\n"), E::Namespace(want));
    }

    #[test]
    fn quota_and_quotaroot_agree_with_the_text_parsers() {
        for payload in [
            "\"\" (STORAGE 10 512)",
            "\"user/x\" (STORAGE 10 512 MESSAGE 5 100)",
            "\"\" ()",
            "root (STORAGE -1 -1)",
        ] {
            let want = ImapQuotaData::parse(payload).expect("the oracle reads it");
            assert_eq!(event(&format!("* QUOTA {payload}\r\n")), E::Quota(want), "{payload:?}");
        }
        for payload in ["\"\" (STORAGE 10)", "\"\" (STORAGE x 5)", "\"\"", "\"\" (STORAGE 10 512"] {
            assert_eq!(event(&format!("* QUOTA {payload}\r\n")), E::Other, "{payload:?}");
        }
        for payload in ["INBOX \"\"", "INBOX", "\"Sent\" root1 root2", "INBOX r1"] {
            let want = ImapQuotaRootData::parse(payload).expect("the oracle reads it");
            assert_eq!(event(&format!("* QUOTAROOT {payload}\r\n")), E::QuotaRoot(want), "{payload:?}");
        }
        assert_eq!(event("* QUOTAROOT \r\n"), E::Other);
        // A name with a space is one name.
        assert_eq!(
            event("* QUOTAROOT \"Sent Items\" \"a b\"\r\n"),
            E::QuotaRoot(ImapQuotaRootData { mailbox: "Sent Items".into(), roots: vec!["a b".into()] })
        );
    }

    #[test]
    fn id_agrees_with_the_text_parser() {
        for payload in [
            "(\"name\" \"hopf\" \"version\" \"1.0\")",
            "NIL",
            "nil",
            "()",
            "(\"a\" NIL)",
            "(\"a\")",
            "(\"a\" \"b\" \"c\")",
        ] {
            assert_eq!(event(&format!("* ID {payload}\r\n")), E::IdParams(parse_id_params(payload)), "{payload:?}");
        }
        assert_eq!(event("* ID (\"a\" {2}\r\nxy)\r\n"), E::IdParams(vec![("a".into(), "xy".into())]));
        assert_eq!(event("* ID (\"a\" \"b\"\r\n"), E::Other);
    }

    #[test]
    fn thread_agrees_with_the_text_parser() {
        for payload in [
            "(3)(1 2)",
            "(2)(3 6)(6 (4 23)(44 7))",
            "",
            "(1 (2)(3))",
            "(1 2 3)",
            "(1 2 (3)(4))",
            "(1 (2 3)(4 5))",
            " (1) (2) ",
        ] {
            let want = parse_thread_response(payload).expect("the oracle reads it");
            assert_eq!(event(&format!("* THREAD {payload}\r\n")), E::ThreadData(want), "{payload:?}");
        }
        for payload in ["(1", "()", "1", "(1 (2) 3)", "((1))", "(1))", "(x)"] {
            assert!(parse_thread_response(payload).is_none(), "oracle {payload:?}");
            assert_eq!(event(&format!("* THREAD {payload}\r\n")), E::Other, "{payload:?}");
        }
    }

    #[test]
    fn metadata_agrees_with_the_text_parser_and_reads_literals() {
        for payload in [
            "INBOX (/private/comment \"hello\")",
            "\"\" (/a NIL /b \"x y\")",
            "INBOX (/a v)",
            "INBOX ()",
        ] {
            let want = ImapMetadataData::parse(payload).expect("the oracle reads it");
            assert_eq!(event(&format!("* METADATA {payload}\r\n")), E::Metadata(want), "{payload:?}");
        }
        // The old single-line capture could not read a literal value.
        assert_eq!(
            event("* METADATA INBOX (/a {6}\r\nl1\r\nl2 /b NIL)\r\n"),
            E::Metadata(ImapMetadataData {
                mailbox: "INBOX".into(),
                entries: vec![
                    ImapMetadataEntry { entry: "/a".into(), value: Some("l1\r\nl2".into()) },
                    ImapMetadataEntry { entry: "/b".into(), value: None },
                ],
            })
        );
        for payload in ["INBOX", "INBOX (/a", "INBOX (/a \"x\") extra)"] {
            let got = event(&format!("* METADATA {payload}\r\n"));
            assert!(matches!(got, E::Other | E::Metadata(_)), "{payload:?}: {got:?}");
        }
        assert_eq!(event("* METADATA INBOX\r\n"), E::Other);
        assert_eq!(event("* METADATA INBOX (/a\r\n"), E::Other);
    }

    #[test]
    fn a_payload_that_is_refused_is_read_through_and_the_next_response_is_unharmed() {
        // The refused one has a literal whose octets look like the end of the line.
        let wire = "* QUOTA \"\" (STORAGE {6}\r\n1\r\n* 2 x 3)\r\n* 3 EXISTS\r\n";
        for chunk in CHUNKS {
            let mut lexer = ImapReplyLexer::new();
            let mut events = Vec::new();
            for piece in wire.as_bytes().chunks(chunk) {
                let mut data: &[u8] = piece;
                events.extend(lexer.feed(&mut data).expect("no protocol error"));
            }
            assert_eq!(events, vec![E::Other, E::Exists(3)], "chunk={chunk}");
        }
    }

    #[test]
    fn a_payload_larger_than_the_cap_is_refused_without_being_kept() {
        let big = "x".repeat(2 * 1024 * 1024);
        let line = format!("* ID (\"a\" {{{}}}\r\n{big})\r\n* 1 EXISTS\r\n", big.len());
        let mut lexer = ImapReplyLexer::new();
        let mut events = Vec::new();
        for piece in line.as_bytes().chunks(65536) {
            let mut data: &[u8] = piece;
            events.extend(lexer.feed(&mut data).expect("no protocol error"));
        }
        assert_eq!(events, vec![E::Other, E::Exists(1)]);
    }
}
