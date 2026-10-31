// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The machines that build `ENVELOPE`, `BODYSTRUCTURE` and `INTERNALDATE`
//! from tokens (see [`super::tokens`]) as the FETCH response arrives.
//!
//! Both structures are positional lists of slots, some of them lists in
//! turn. A stack of frames keeps the lists that are open, each knowing what
//! its next slot may be; a token that is a word or a string fills the slot,
//! `(` opens the frame the slot calls for (an address list, a nested body,
//! parameters, or one to be read and dropped), and `)` closes the top frame
//! and hands its value to the one below. The shapes and the leniency are
//! those of the text readers in [`super::structure`].

use super::structure::{ImapAddress, ImapBodyPart, ImapBodyStructure, ImapDisposition, ImapEnvelope, ImapMultipart};
use super::tokens::{Bad, Output, Sink, Tok};

/// The deepest nesting of lists allowed.
const MAX_DEPTH: usize = 64;

/// A word or string, as a slot sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Scalar {
    Nil,
    Number(u64),
    Str(String),
}

impl Scalar {
    fn of(tok: Tok<'_>) -> Option<Self> {
        Some(match tok {
            Tok::Str(s) => Scalar::Str(String::from_utf8_lossy(s).into_owned()),
            Tok::Atom(a) if a.eq_ignore_ascii_case(b"NIL") => Scalar::Nil,
            Tok::Atom(a) => {
                let text = String::from_utf8_lossy(a).into_owned();
                match (a.iter().all(u8::is_ascii_digit), text.parse::<u64>()) {
                    (true, Ok(n)) => Scalar::Number(n),
                    _ => Scalar::Str(text),
                }
            }
            _ => return None,
        })
    }

    /// The text of a string or number.
    fn text(&self) -> Option<String> {
        match self {
            Scalar::Str(s) => Some(s.clone()),
            Scalar::Number(n) => Some(n.to_string()),
            Scalar::Nil => None,
        }
    }

    fn number(&self) -> Option<u64> {
        match self {
            Scalar::Number(n) => Some(*n),
            Scalar::Str(s) => s.parse().ok(),
            Scalar::Nil => None,
        }
    }
}

/// The frame a `(` opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Want {
    /// A list that is read and dropped.
    Skip,
    Envelope,
    Addrs,
    Addr,
    Body,
    Params,
    Disposition,
    Language,
}

/// What a closed frame was.
enum Value {
    Nothing,
    Envelope(ImapEnvelope),
    Addrs(Vec<ImapAddress>),
    Addr(ImapAddress),
    Body(ImapBodyStructure),
    Params(Vec<(String, String)>),
    Disposition(Option<ImapDisposition>),
    Language(Vec<String>),
}

// ── frames ─────────────────────────────────────────────────────────────────

#[derive(Default)]
struct EnvelopeFrame {
    idx: usize,
    env: ImapEnvelope,
}

#[derive(Default)]
struct AddrFrame {
    idx: usize,
    addr: ImapAddress,
}

/// `(media subtype params id description encoding size ...)`, or a multipart.
enum BodyFrame {
    /// Nothing read yet: the first slot says which it is.
    Start,
    Multi(MultiFrame),
    Part(PartFrame),
}

#[derive(Default)]
struct MultiFrame {
    parts: Vec<ImapBodyStructure>,
    subtype: Option<String>,
    /// Extension data slot: 0 params, 1 disposition, 2 language, 3 location.
    ext: usize,
    params: Vec<(String, String)>,
    disposition: Option<ImapDisposition>,
    language: Vec<String>,
    location: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PartAt {
    /// `type subtype params id description encoding size`.
    Basic(usize),
    /// A `text/*` part's line count.
    Lines,
    /// A `message/rfc822` part's envelope, or (for a server that could not
    /// parse the inner message) the extension data.
    EnvelopeOrExt,
    /// The encapsulated message's body.
    NestedBody,
    /// The encapsulated message's line count.
    NestedLines,
    /// Extension data: 0 md5, 1 disposition, 2 language, 3 location.
    Ext(usize),
}

struct PartFrame {
    at: PartAt,
    part: ImapBodyPart,
    envelope: Option<ImapEnvelope>,
}

enum Frame {
    Skip,
    Envelope(EnvelopeFrame),
    Addrs(Vec<ImapAddress>),
    Addr(AddrFrame),
    Body(BodyFrame),
    /// Alternating names and values (a list in either place counts as none).
    Params(Vec<Option<String>>),
    Disposition { kind: Option<Option<String>>, params: Vec<(String, String)> },
    Language(Vec<String>),
}

impl Frame {
    fn open(want: Want) -> Self {
        match want {
            Want::Skip => Frame::Skip,
            Want::Envelope => Frame::Envelope(EnvelopeFrame::default()),
            Want::Addrs => Frame::Addrs(Vec::new()),
            Want::Addr => Frame::Addr(AddrFrame::default()),
            Want::Body => Frame::Body(BodyFrame::Start),
            Want::Params => Frame::Params(Vec::new()),
            Want::Disposition => Frame::Disposition { kind: None, params: Vec::new() },
            Want::Language => Frame::Language(Vec::new()),
        }
    }

    /// What a `(` in the next slot opens.
    fn wants(&self) -> Want {
        match self {
            Frame::Skip | Frame::Addr(_) | Frame::Params(_) | Frame::Language(_) => Want::Skip,
            Frame::Envelope(f) => match f.idx {
                2..=7 => Want::Addrs,
                _ => Want::Skip,
            },
            Frame::Addrs(_) => Want::Addr,
            Frame::Disposition { kind, .. } => {
                if kind.is_some() {
                    Want::Params
                } else {
                    Want::Skip
                }
            }
            Frame::Body(BodyFrame::Start) => Want::Body,
            Frame::Body(BodyFrame::Multi(m)) => {
                if m.subtype.is_none() {
                    Want::Body
                } else {
                    match m.ext {
                        0 => Want::Params,
                        1 => Want::Disposition,
                        2 => Want::Language,
                        _ => Want::Skip,
                    }
                }
            }
            Frame::Body(BodyFrame::Part(p)) => match p.at {
                PartAt::Basic(2) => Want::Params,
                PartAt::EnvelopeOrExt => Want::Envelope,
                PartAt::NestedBody => Want::Body,
                PartAt::Ext(1) => Want::Disposition,
                PartAt::Ext(2) => Want::Language,
                _ => Want::Skip,
            },
        }
    }

    /// A word or string fills the next slot.
    fn scalar(&mut self, s: Scalar) -> Result<(), Bad> {
        match self {
            Frame::Skip | Frame::Addrs(_) => {}
            Frame::Envelope(f) => {
                let env = &mut f.env;
                match f.idx {
                    0 => env.date = s.text(),
                    1 => env.subject = s.text(),
                    8 => env.in_reply_to = s.text(),
                    9 => env.message_id = s.text(),
                    _ => {}
                }
                f.idx += 1;
            }
            Frame::Addr(f) => {
                match f.idx {
                    0 => f.addr.name = s.text(),
                    1 => f.addr.adl = s.text(),
                    2 => f.addr.mailbox = s.text(),
                    3 => f.addr.host = s.text(),
                    _ => {}
                }
                f.idx += 1;
            }
            Frame::Params(items) => items.push(s.text()),
            Frame::Language(tags) => tags.extend(s.text()),
            Frame::Disposition { kind, .. } => {
                if kind.is_none() {
                    *kind = Some(s.text().map(|k| k.to_ascii_lowercase()));
                }
            }
            Frame::Body(body) => body.scalar(s)?,
        }
        Ok(())
    }

    /// A closed list fills the next slot.
    fn child(&mut self, value: Value) -> Result<(), Bad> {
        match (self, value) {
            (Frame::Skip, _) => {}
            (Frame::Envelope(f), value) => {
                if let (2..=7, Value::Addrs(addrs)) = (f.idx, value) {
                    match f.idx {
                        2 => f.env.from = addrs,
                        3 => f.env.sender = addrs,
                        4 => f.env.reply_to = addrs,
                        5 => f.env.to = addrs,
                        6 => f.env.cc = addrs,
                        _ => f.env.bcc = addrs,
                    }
                }
                f.idx += 1;
            }
            (Frame::Addrs(addrs), Value::Addr(addr)) => addrs.push(addr),
            (Frame::Addrs(_), _) => {}
            (Frame::Addr(f), _) => f.idx += 1,
            (Frame::Params(items), _) => items.push(None),
            (Frame::Language(_), _) => {}
            (Frame::Disposition { kind, params }, value) => match kind {
                None => *kind = Some(None),
                Some(_) => {
                    if let Value::Params(p) = value {
                        *params = p;
                    }
                }
            },
            (Frame::Body(body), value) => body.child(value)?,
        }
        Ok(())
    }

    /// `)`: the frame's value.
    fn close(self) -> Result<Value, Bad> {
        Ok(match self {
            Frame::Skip => Value::Nothing,
            Frame::Envelope(f) => {
                if f.idx < 10 {
                    return Err(Bad);
                }
                Value::Envelope(f.env)
            }
            Frame::Addrs(addrs) => Value::Addrs(addrs),
            Frame::Addr(f) => Value::Addr(f.addr),
            Frame::Params(items) => Value::Params(
                items
                    .chunks(2)
                    .filter_map(|pair| {
                        let name = pair.first()?.clone()?.to_ascii_lowercase();
                        Some((name, pair.get(1).cloned().flatten().unwrap_or_default()))
                    })
                    .collect(),
            ),
            Frame::Disposition { kind, params } => {
                Value::Disposition(kind.flatten().map(|kind| ImapDisposition { kind, params }))
            }
            Frame::Language(tags) => Value::Language(tags),
            Frame::Body(body) => Value::Body(body.close()?),
        })
    }
}

impl BodyFrame {
    fn scalar(&mut self, s: Scalar) -> Result<(), Bad> {
        match self {
            BodyFrame::Start => {
                let mut part = PartFrame { at: PartAt::Basic(0), part: ImapBodyPart::default(), envelope: None };
                part.scalar(s)?;
                *self = BodyFrame::Part(part);
            }
            BodyFrame::Multi(m) => m.scalar(s)?,
            BodyFrame::Part(p) => p.scalar(s)?,
        }
        Ok(())
    }

    fn child(&mut self, value: Value) -> Result<(), Bad> {
        match self {
            BodyFrame::Start => match value {
                Value::Body(first) => {
                    *self = BodyFrame::Multi(MultiFrame { parts: vec![first], ..MultiFrame::default() });
                }
                _ => return Err(Bad),
            },
            BodyFrame::Multi(m) => m.child(value)?,
            BodyFrame::Part(p) => p.child(value)?,
        }
        Ok(())
    }

    fn close(self) -> Result<ImapBodyStructure, Bad> {
        match self {
            BodyFrame::Start => Err(Bad),
            BodyFrame::Multi(m) => {
                Ok(ImapBodyStructure::Multipart(ImapMultipart {
                    media_subtype: m.subtype.ok_or(Bad)?,
                    parts: m.parts,
                    params: m.params,
                    disposition: m.disposition,
                    language: m.language,
                    location: m.location,
                }))
            }
            BodyFrame::Part(p) => {
                if matches!(p.at, PartAt::Basic(i) if i < 7) {
                    return Err(Bad);
                }
                if p.envelope.is_some() || p.at == PartAt::NestedBody {
                    return Err(Bad);
                }
                Ok(ImapBodyStructure::Part(p.part))
            }
        }
    }
}

impl MultiFrame {
    fn scalar(&mut self, s: Scalar) -> Result<(), Bad> {
        if self.subtype.is_none() {
            // The first word after the parts is the subtype.
            self.subtype = Some(s.text().ok_or(Bad)?.to_ascii_lowercase());
            return Ok(());
        }
        match self.ext {
            2 => {
                self.language = match &s {
                    Scalar::Str(text) => vec![text.clone()],
                    _ => Vec::new(),
                }
            }
            3 => self.location = s.text(),
            _ => {}
        }
        self.ext += 1;
        Ok(())
    }

    fn child(&mut self, value: Value) -> Result<(), Bad> {
        if self.subtype.is_none() {
            match value {
                Value::Body(body) => self.parts.push(body),
                _ => return Err(Bad),
            }
            return Ok(());
        }
        match (self.ext, value) {
            (0, Value::Params(p)) => self.params = p,
            (1, Value::Disposition(d)) => self.disposition = d,
            (2, Value::Language(l)) => self.language = l,
            _ => {}
        }
        self.ext += 1;
        Ok(())
    }
}

impl PartFrame {
    fn scalar(&mut self, s: Scalar) -> Result<(), Bad> {
        match self.at {
            PartAt::Basic(i) => {
                let part = &mut self.part;
                match i {
                    0 => part.media_type = s.text().ok_or(Bad)?.to_ascii_lowercase(),
                    1 => part.media_subtype = s.text().ok_or(Bad)?.to_ascii_lowercase(),
                    3 => part.content_id = s.text(),
                    4 => part.description = s.text(),
                    5 => part.encoding = s.text().unwrap_or_else(|| "7BIT".to_string()).to_ascii_uppercase(),
                    6 => part.size = s.number().unwrap_or(0),
                    _ => {}
                }
                self.at = if i < 6 { PartAt::Basic(i + 1) } else { self.after_basic() };
            }
            PartAt::Lines => {
                self.part.lines = s.number();
                self.at = PartAt::Ext(0);
            }
            PartAt::EnvelopeOrExt => {
                // No envelope: the extension data starts here.
                self.at = PartAt::Ext(0);
                return self.scalar(s);
            }
            PartAt::NestedBody => return Err(Bad),
            PartAt::NestedLines => {
                self.part.lines = s.number();
                self.at = PartAt::Ext(0);
            }
            PartAt::Ext(i) => {
                let part = &mut self.part;
                match i {
                    0 => part.md5 = s.text(),
                    2 => {
                        part.language = match &s {
                            Scalar::Str(text) => vec![text.clone()],
                            _ => Vec::new(),
                        }
                    }
                    3 => part.location = s.text(),
                    _ => {}
                }
                self.at = PartAt::Ext(i + 1);
            }
        }
        Ok(())
    }

    fn child(&mut self, value: Value) -> Result<(), Bad> {
        match self.at {
            PartAt::Basic(i) => {
                // (The media type and subtype must be words.)
                if i < 2 {
                    return Err(Bad);
                }
                if let (2, Value::Params(p)) = (i, value) {
                    self.part.params = p;
                }
                self.at = if i < 6 { PartAt::Basic(i + 1) } else { self.after_basic() };
            }
            PartAt::Lines | PartAt::NestedLines => self.at = PartAt::Ext(0),
            PartAt::EnvelopeOrExt => match value {
                Value::Envelope(envelope) => {
                    self.envelope = Some(envelope);
                    self.at = PartAt::NestedBody;
                }
                _ => return Err(Bad),
            },
            PartAt::NestedBody => match (value, self.envelope.take()) {
                (Value::Body(body), Some(envelope)) => {
                    self.part.nested = Some(Box::new((envelope, body)));
                    self.at = PartAt::NestedLines;
                }
                _ => return Err(Bad),
            },
            PartAt::Ext(i) => {
                let part = &mut self.part;
                match (i, value) {
                    (1, Value::Disposition(d)) => part.disposition = d,
                    (2, Value::Language(l)) => part.language = l,
                    _ => {}
                }
                self.at = PartAt::Ext(i + 1);
            }
        }
        Ok(())
    }

    /// The seven basic fields are read: what follows depends on the type.
    fn after_basic(&self) -> PartAt {
        let part = &self.part;
        if part.media_type == "message" && part.media_subtype == "rfc822" {
            PartAt::EnvelopeOrExt
        } else if part.media_type == "text" {
            PartAt::Lines
        } else {
            PartAt::Ext(0)
        }
    }
}

// ── the sinks ──────────────────────────────────────────────────────────────

/// What the sink is building.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    Envelope,
    Body,
}

/// `ENVELOPE (...)` or `BODYSTRUCTURE (...)`.
pub(crate) struct StructureSink {
    target: Target,
    stack: Vec<Frame>,
    done: Option<Value>,
}

impl StructureSink {
    pub(crate) fn envelope() -> Self {
        Self { target: Target::Envelope, stack: Vec::new(), done: None }
    }

    pub(crate) fn body() -> Self {
        Self { target: Target::Body, stack: Vec::new(), done: None }
    }
}

impl Sink for StructureSink {
    fn token(&mut self, tok: Tok<'_>) -> Result<(), Bad> {
        if self.done.is_some() {
            return Err(Bad);
        }
        match tok {
            Tok::Open => {
                if self.stack.len() >= MAX_DEPTH {
                    return Err(Bad);
                }
                let want = match self.stack.last() {
                    None => match self.target {
                        Target::Envelope => Want::Envelope,
                        Target::Body => Want::Body,
                    },
                    Some(top) => top.wants(),
                };
                self.stack.push(Frame::open(want));
            }
            Tok::Close => {
                let frame = self.stack.pop().ok_or(Bad)?;
                let value = frame.close()?;
                match self.stack.last_mut() {
                    Some(parent) => parent.child(value)?,
                    None => self.done = Some(value),
                }
            }
            tok => {
                let scalar = Scalar::of(tok).ok_or(Bad)?;
                match self.stack.last_mut() {
                    Some(top) => top.scalar(scalar)?,
                    // (A bare word where the structure's list should be.)
                    None => return Err(Bad),
                }
            }
        }
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Output, Bad> {
        match (self.target, self.done) {
            (Target::Envelope, Some(Value::Envelope(env))) => Ok(Output::Envelope(env)),
            (Target::Body, Some(Value::Body(body))) => Ok(Output::Body(body)),
            _ => Err(Bad),
        }
    }
}

/// `INTERNALDATE "17-Jul-1996 02:44:25 -0700"`
#[derive(Default)]
pub(crate) struct DateSink {
    date: Option<String>,
}

impl Sink for DateSink {
    fn token(&mut self, tok: Tok<'_>) -> Result<(), Bad> {
        if self.date.is_some() {
            return Err(Bad);
        }
        self.date = Some(Scalar::of(tok).ok_or(Bad)?.text().ok_or(Bad)?);
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Output, Bad> {
        Ok(Output::Date(self.date.ok_or(Bad)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::reply::{ImapEvent, ImapReplyLexer};

    const CHUNKS: [usize; 5] = [1, 2, 3, 7, 4096];

    /// The FETCH attributes the lexer makes of `* 1 FETCH (attrs UID 1)`, however the bytes arrive.
    fn fetch(attrs: &str) -> crate::client::state::ImapFetchData {
        let line = format!("* 1 FETCH ({attrs} UID 1)\r\n");
        let mut all = Vec::new();
        for chunk in CHUNKS {
            let mut lexer = ImapReplyLexer::new();
            let mut events = Vec::new();
            for piece in line.as_bytes().chunks(chunk) {
                let mut data: &[u8] = piece;
                events.extend(lexer.feed(&mut data).expect("no protocol error"));
            }
            assert_eq!(events.len(), 1, "{attrs:?} chunk={chunk}: {events:?}");
            match events.pop().unwrap() {
                ImapEvent::Fetch(d) => all.push(d),
                other => panic!("expected Fetch, got {other:?}"),
            }
        }
        assert!(all.windows(2).all(|w| w[0] == w[1]), "{attrs:?}: chunking changed the outcome");
        let data = all.pop().unwrap();
        assert_eq!(data.uid, Some(1), "{attrs:?}: the rest of the response is intact");
        data
    }

    const BODIES: &[&str] = &[
        r#"("TEXT" "PLAIN" ("CHARSET" "UTF-8") NIL NIL "QUOTED-PRINTABLE" 42 3)"#,
        r#"(("TEXT" "PLAIN" ("CHARSET" "UTF-8") NIL NIL "7BIT" 10 1)("TEXT" "HTML" ("CHARSET" "UTF-8") NIL NIL "QUOTED-PRINTABLE" 20 1) "ALTERNATIVE" ("BOUNDARY" "x"))"#,
        r#"(("TEXT" "plain" ("charset" "UTF-8") NIL NIL "QUOTED-PRINTABLE" 12279 158 NIL NIL NIL NIL)("TEXT" "html" ("charset" "UTF-8") NIL NIL "QUOTED-PRINTABLE" 64748 832 NIL NIL NIL NIL) "alternative" ("boundary" "_----/hALBbAWiPaRTdEKOe/0Uw===_D5/F2-17034-7AF5DC96") NIL NIL NIL)"#,
        concat!(
            r#"(("TEXT" "PLAIN" ("CHARSET" "US-ASCII") NIL NIL "7BIT" 1152 23)"#,
            r#"(("TEXT" "PLAIN" ("CHARSET" "US-ASCII") NIL NIL "7BIT" 10 1)("TEXT" "HTML" NIL NIL NIL "8BIT" 20 1) "ALTERNATIVE" ("BOUNDARY" "inner"))"#,
            r#"("APPLICATION" "PDF" ("NAME" "report.pdf") NIL NIL "BASE64" 4554 NIL ("attachment" ("filename" "report.pdf")) NIL NIL)"#,
            r#"("IMAGE" "PNG" ("NAME" "logo.png") "<logo@x>" NIL "BASE64" 300 NIL ("inline" ("filename" "logo.png")) NIL NIL)"#,
            r#" "MIXED" ("BOUNDARY" "outer") NIL ("en" "fr") NIL)"#,
        ),
        concat!(
            r#"(("TEXT" "PLAIN" NIL NIL NIL "7BIT" 5 1)"#,
            r#"("MESSAGE" "RFC822" NIL NIL NIL "7BIT" 999 "#,
            r#"("Thu, 1 Jan 2026 00:00:00 +0000" "Fwd" (("A" NIL "a" "x.org")) NIL NIL NIL NIL NIL NIL "<m1@x.org>") "#,
            r#"(("TEXT" "PLAIN" NIL NIL NIL "7BIT" 7 1)("APPLICATION" "OCTET-STREAM" NIL NIL NIL "BASE64" 8 NIL ("attachment" ("filename" "f.bin")) NIL NIL) "MIXED" ("BOUNDARY" "in")) 40)"#,
            r#"("MESSAGE" "RFC822" NIL NIL NIL "7BIT" 50 "#,
            r#"("Thu, 1 Jan 2026 00:00:00 +0000" "Single" NIL NIL NIL NIL NIL NIL NIL NIL) "#,
            r#"("TEXT" "PLAIN" NIL NIL NIL "7BIT" 9 1) 3)"#,
            r#" "MIXED")"#,
        ),
        r#"("MESSAGE" "RFC822" NIL NIL NIL "7BIT" 999 NIL ("attachment" ("filename" "old.eml")) NIL NIL)"#,
        r#"(text plain (charset utf-8) nil nil 7bit 12 1)"#,
        r#"("TEXT" "PLAIN" NIL NIL NIL "7BIT" 5)"#,
        r#"("IMAGE" "GIF" NIL NIL NIL "BASE64" 5 "md5" ("inline" NIL) "en" "http://x/y")"#,
        r#"("APPLICATION" "X" ("a" "b" ("nested") "c") NIL NIL NIL x NIL "attachment" 7 ("x"))"#,
        r#"(("TEXT" "PLAIN" NIL NIL NIL "7BIT" 5 1) "MIXED" NIL ("inline" ("filename" "a.txt" "x")) "de" "loc" EXTRA ("more" (deep)))"#,
        // Refused by the text reader too.
        r#"("TEXT" "PLAIN")"#,
        r#"(("TEXT" "PLAIN" NIL NIL NIL "7BIT" 1 1))"#,
        r#"(("TEXT" "PLAIN" NIL NIL NIL "7BIT" 1 1) NIL)"#,
        r#"((1 2 NIL NIL NIL "7BIT" 1 1) "MIXED")"#,
        r#"()"#,
    ];

    #[test]
    fn bodystructure_agrees_with_the_text_reader() {
        for text in BODIES {
            let want = ImapBodyStructure::parse(text).ok();
            let got = fetch(&format!("BODYSTRUCTURE {text}")).bodystructure;
            assert_eq!(got, want, "{text}");
            assert_eq!(fetch(&format!("BODY {text}")).bodystructure, want, "BODY {text}");
        }
    }

    const ENVELOPES: &[&str] = &[
        concat!(
            r#"("Wed, 17 Jul 1996 02:23:25 -0700 (PDT)" "IMAP4rev2 WG mtg summary \"and\" minutes" "#,
            r#"(("Terry Gray" NIL "gray" "cac.washington.edu")) "#,
            r#"(("Terry Gray" NIL "gray" "cac.washington.edu")) "#,
            r#"(("Terry Gray" NIL "gray" "cac.washington.edu")) "#,
            r#"((NIL NIL "imap" "cac.washington.edu")) "#,
            r#"((NIL NIL "minutes" "CNRI.Reston.VA.US")(NIL NIL "undisclosed" NIL)("John Klensin" NIL "KLENSIN" "MIT.EDU")(NIL NIL NIL NIL)) "#,
            r#"NIL NIL "<B27397-0100000@cac.washington.edu>")"#,
        ),
        r#"("date" "Say \"hi\" \\ café" NIL NIL NIL NIL NIL NIL NIL NIL)"#,
        r#"(NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)"#,
        r#"("d" "s" ((NIL NIL "a")) NIL NIL NIL NIL NIL 12 "id" "extra" (x))"#,
        r#"("d" "s" (("n" "adl" "m" "h" "extra")) (junk) NIL NIL NIL NIL "irt" "mid")"#,
        r#"("d" "s" ("notalist" ("x" NIL "y" "z")) NIL NIL NIL NIL NIL NIL NIL)"#,
        r#"(d s NIL NIL NIL NIL NIL NIL nil nil)"#,
        // Refused by the text reader too.
        r#"("date" "subj")"#,
        r#"(("date") "subj" NIL NIL NIL NIL NIL NIL NIL NIL)"#,
    ];

    #[test]
    fn envelope_agrees_with_the_text_reader() {
        for text in ENVELOPES {
            let want = ImapEnvelope::parse(text).ok();
            assert_eq!(fetch(&format!("ENVELOPE {text}")).envelope, want, "{text}");
        }
    }

    #[test]
    fn literals_stand_for_strings_anywhere_in_a_structure() {
        let got = fetch("BODYSTRUCTURE ({4}\r\nTEXT {5}\r\nPLAIN ({7}\r\nCHARSET {5}\r\nUTF-8) NIL NIL \"7BIT\" 3 1)");
        let want = ImapBodyStructure::parse(r#"("TEXT" "PLAIN" ("CHARSET" "UTF-8") NIL NIL "7BIT" 3 1)"#).unwrap();
        assert_eq!(got.bodystructure, Some(want));
    }

    #[test]
    fn internaldate_is_a_string_without_its_quotes() {
        assert_eq!(fetch("INTERNALDATE \"17-Jul-1996 02:44:25 -0700\"").internaldate.as_deref(), Some("17-Jul-1996 02:44:25 -0700"));
        assert_eq!(fetch("INTERNALDATE {26}\r\n17-Jul-1996 02:44:25 -0700").internaldate.as_deref(), Some("17-Jul-1996 02:44:25 -0700"));
    }

    #[test]
    fn nesting_is_capped() {
        let deep = format!("{}{}", "(".repeat(MAX_DEPTH + 2), ")".repeat(MAX_DEPTH + 2));
        assert!(fetch(&format!("BODYSTRUCTURE {deep}")).bodystructure.is_none());
    }
}
