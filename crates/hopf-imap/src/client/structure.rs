// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Client-side parsers for the structured FETCH items the reply lexer
//! captures verbatim: `ENVELOPE` (RFC 9051 §7.5.2) and `BODYSTRUCTURE` /
//! `BODY` (RFC 9051 §7.5.2, RFC 3501 §7.4.2).
//!
//! The lexer hands these over as one line of IMAP syntax — parenthesized
//! lists of quoted strings, atoms, numbers and `NIL` — with any literal the
//! server sent already re-encoded as a quoted string, so a small
//! S-expression reader is all that is needed here. Nothing in this module
//! is incremental: a structure is parsed once the lexer has it whole.
//!
//! [`ImapBodyStructure::parts`] numbers the leaf parts the way
//! `BODY[section]` refers to them (RFC 3501 §6.4.5), which is what a mail
//! client needs to fetch exactly the text part it wants to display, or
//! one attachment, instead of the whole message.

use std::fmt;

use super::error::{ImapError, ImapResult};

/// One address in an `ENVELOPE` address list.
///
/// RFC 5322 group syntax is encoded the way the server sends it: a group
/// start has `mailbox` set to the group name and `host` `None`; a group end
/// has both `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImapAddress {
    /// Display name (`addr-name`), if any.
    pub name: Option<String>,
    /// Source route (`addr-adl`); obsolete, almost always `None`.
    pub adl: Option<String>,
    /// Local part (`addr-mailbox`), or the group name at a group start.
    pub mailbox: Option<String>,
    /// Domain (`addr-host`); `None` at a group start or end.
    pub host: Option<String>,
}

impl ImapAddress {
    /// `mailbox@host` when both are present.
    pub fn address(&self) -> Option<String> {
        match (&self.mailbox, &self.host) {
            (Some(m), Some(h)) => Some(format!("{m}@{h}")),
            _ => None,
        }
    }
}

/// Parsed `ENVELOPE`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImapEnvelope {
    /// `Date:` header value as sent (not parsed).
    pub date: Option<String>,
    /// `Subject:` as sent (RFC 2047 encoded words are not decoded here).
    pub subject: Option<String>,
    /// `From:`.
    pub from: Vec<ImapAddress>,
    /// `Sender:` (the server copies `From:` when absent).
    pub sender: Vec<ImapAddress>,
    /// `Reply-To:` (the server copies `From:` when absent).
    pub reply_to: Vec<ImapAddress>,
    /// `To:`.
    pub to: Vec<ImapAddress>,
    /// `Cc:`.
    pub cc: Vec<ImapAddress>,
    /// `Bcc:`.
    pub bcc: Vec<ImapAddress>,
    /// `In-Reply-To:` as sent.
    pub in_reply_to: Option<String>,
    /// `Message-ID:` as sent.
    pub message_id: Option<String>,
}

impl ImapEnvelope {
    /// Parse the captured text of an `ENVELOPE` item
    /// ([`ImapFetchData::envelope`](super::state::ImapFetchData::envelope)).
    pub fn parse(text: &str) -> ImapResult<Self> {
        let expr = parse_sexpr(text)?;
        envelope_from(&expr)
    }
}

/// `Content-Disposition` as reported in BODYSTRUCTURE extension data.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImapDisposition {
    /// Disposition type, lower-cased (`inline`, `attachment`, …).
    pub kind: String,
    /// Parameters as sent, names lower-cased (`filename`, …).
    pub params: Vec<(String, String)>,
}

impl ImapDisposition {
    /// The `filename` parameter, if any.
    pub fn filename(&self) -> Option<&str> {
        param(&self.params, "filename")
    }
}

/// A non-multipart body part.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImapBodyPart {
    /// Media type, lower-cased (`text`, `image`, `message`, …).
    pub media_type: String,
    /// Media subtype, lower-cased (`plain`, `html`, `rfc822`, …).
    pub media_subtype: String,
    /// `Content-Type` parameters as sent, names lower-cased.
    pub params: Vec<(String, String)>,
    /// `Content-ID`, angle brackets included if the server sent them.
    pub content_id: Option<String>,
    /// `Content-Description`.
    pub description: Option<String>,
    /// `Content-Transfer-Encoding`, upper-cased (`7BIT`, `BASE64`, …).
    pub encoding: String,
    /// Body size in octets, as encoded on the wire.
    pub size: u64,
    /// Line count; sent for `text/*` and `message/rfc822` only.
    pub lines: Option<u64>,
    /// For `message/rfc822`: the encapsulated message's envelope and body
    /// structure.
    pub nested: Option<Box<(ImapEnvelope, ImapBodyStructure)>>,
    /// Extension data: `Content-MD5`.
    pub md5: Option<String>,
    /// Extension data: `Content-Disposition`.
    pub disposition: Option<ImapDisposition>,
    /// Extension data: `Content-Language` tags.
    pub language: Vec<String>,
    /// Extension data: `Content-Location`.
    pub location: Option<String>,
}

impl ImapBodyPart {
    /// `type/subtype`, lower-cased.
    pub fn media(&self) -> String {
        format!("{}/{}", self.media_type, self.media_subtype)
    }

    /// The `charset` parameter, if any.
    pub fn charset(&self) -> Option<&str> {
        param(&self.params, "charset")
    }

    /// Whether this part is `text/*`.
    pub fn is_text(&self) -> bool {
        self.media_type == "text"
    }

    /// Whether this part is an attachment by disposition, or has a filename
    /// without being declared inline.
    pub fn is_attachment(&self) -> bool {
        match &self.disposition {
            Some(d) if d.kind == "attachment" => true,
            Some(d) if d.kind == "inline" => false,
            Some(d) => d.filename().is_some(),
            None => param(&self.params, "name").is_some() && !self.is_text(),
        }
    }

    /// The best filename for this part: the disposition's `filename`,
    /// else the content type's `name`.
    pub fn filename(&self) -> Option<&str> {
        self.disposition
            .as_ref()
            .and_then(ImapDisposition::filename)
            .or_else(|| param(&self.params, "name"))
    }
}

/// A `multipart/*` body.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImapMultipart {
    /// Multipart subtype, lower-cased (`mixed`, `alternative`, `related`, …).
    pub media_subtype: String,
    /// The parts, in order.
    pub parts: Vec<ImapBodyStructure>,
    /// Extension data: `Content-Type` parameters (`boundary`, `type`, …).
    pub params: Vec<(String, String)>,
    /// Extension data: `Content-Disposition`.
    pub disposition: Option<ImapDisposition>,
    /// Extension data: `Content-Language` tags.
    pub language: Vec<String>,
    /// Extension data: `Content-Location`.
    pub location: Option<String>,
}

/// A leaf part together with the section number `BODY[section]` uses for it.
pub type ImapSectionPart<'a> = (String, &'a ImapBodyPart);

/// Parsed `BODYSTRUCTURE` (or `BODY`) tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImapBodyStructure {
    /// A single part.
    Part(ImapBodyPart),
    /// A multipart container.
    Multipart(ImapMultipart),
}

impl ImapBodyStructure {
    /// Parse the captured text of a `BODYSTRUCTURE` or `BODY` item
    /// ([`ImapFetchData::bodystructure`](super::state::ImapFetchData::bodystructure)).
    pub fn parse(text: &str) -> ImapResult<Self> {
        let expr = parse_sexpr(text)?;
        body_from(&expr)
    }

    /// Every leaf part with the section number `BODY[section]` would use
    /// for it (RFC 3501 §6.4.5), depth first in wire order.
    ///
    /// A non-multipart message has the single section `1`. A multipart
    /// message's parts are `1`, `2`, …, and nested multiparts extend the
    /// number with a dot (`2.1`). A `message/rfc822` part is listed
    /// itself, and the encapsulated message's parts follow it under its
    /// number: `3.1`, `3.2` for a multipart inner message, `3.1` for a
    /// single-part one.
    pub fn parts(&self) -> Vec<ImapSectionPart<'_>> {
        let mut out = Vec::new();
        match self {
            ImapBodyStructure::Part(part) => {
                out.push(("1".to_string(), part));
                collect_nested(part, "1", &mut out);
            }
            ImapBodyStructure::Multipart(mp) => collect_multipart(mp, "", &mut out),
        }
        out
    }

    /// The first `text/plain` and first `text/html` parts that are not
    /// attachments, with their section numbers — the usual candidates for
    /// displaying a message.
    pub fn display_candidates(&self) -> (Option<ImapSectionPart<'_>>, Option<ImapSectionPart<'_>>) {
        let mut plain = None;
        let mut html = None;
        for (section, part) in self.parts() {
            if !part.is_text() || part.is_attachment() {
                continue;
            }
            match part.media_subtype.as_str() {
                "plain" if plain.is_none() => plain = Some((section, part)),
                "html" if html.is_none() => html = Some((section, part)),
                _ => {}
            }
        }
        (plain, html)
    }
}

fn collect_multipart<'a>(mp: &'a ImapMultipart, prefix: &str, out: &mut Vec<ImapSectionPart<'a>>) {
    for (i, child) in mp.parts.iter().enumerate() {
        let section = if prefix.is_empty() { format!("{}", i + 1) } else { format!("{prefix}.{}", i + 1) };
        match child {
            ImapBodyStructure::Part(part) => {
                out.push((section.clone(), part));
                collect_nested(part, &section, out);
            }
            ImapBodyStructure::Multipart(inner) => collect_multipart(inner, &section, out),
        }
    }
}

fn collect_nested<'a>(part: &'a ImapBodyPart, section: &str, out: &mut Vec<ImapSectionPart<'a>>) {
    let Some(nested) = &part.nested else {
        return;
    };
    match &nested.1 {
        ImapBodyStructure::Multipart(inner) => collect_multipart(inner, section, out),
        ImapBodyStructure::Part(inner) => {
            let s = format!("{section}.1");
            out.push((s.clone(), inner));
            collect_nested(inner, &s, out);
        }
    }
}

fn param<'a>(params: &'a [(String, String)], name: &str) -> Option<&'a str> {
    params.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

// ── S-expression reader ──────────────────────────────────────────────────────

/// One value of IMAP response syntax.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SExpr {
    Nil,
    Number(u64),
    /// Quoted string or atom — IMAP servers use them interchangeably for
    /// most of these fields, so no distinction is kept.
    Str(String),
    List(Vec<SExpr>),
}

impl fmt::Display for SExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SExpr::Nil => f.write_str("NIL"),
            SExpr::Number(n) => write!(f, "{n}"),
            SExpr::Str(s) => write!(f, "{s:?}"),
            SExpr::List(items) => {
                f.write_str("(")?;
                for (i, it) in items.iter().enumerate() {
                    if i > 0 {
                        f.write_str(" ")?;
                    }
                    write!(f, "{it}")?;
                }
                f.write_str(")")
            }
        }
    }
}

fn parse_error(msg: impl Into<String>) -> ImapError {
    ImapError::Parse(msg.into())
}

/// Read one complete value from `text`, which must contain nothing else.
fn parse_sexpr(text: &str) -> ImapResult<SExpr> {
    let bytes = text.as_bytes();
    let mut i = 0usize;
    skip_ws(bytes, &mut i);
    let expr = read_value(text, &mut i, 0)?;
    skip_ws(bytes, &mut i);
    if i != bytes.len() {
        return Err(parse_error(format!("trailing data after structure at offset {i}")));
    }
    Ok(expr)
}

const MAX_DEPTH: usize = 64;

fn skip_ws(bytes: &[u8], i: &mut usize) {
    while *i < bytes.len() && matches!(bytes[*i], b' ' | b'\t' | b'\r' | b'\n') {
        *i += 1;
    }
}

fn read_value(text: &str, i: &mut usize, depth: usize) -> ImapResult<SExpr> {
    let bytes = text.as_bytes();
    let Some(&b) = bytes.get(*i) else {
        return Err(parse_error("unexpected end of structure"));
    };
    match b {
        b'(' => {
            if depth >= MAX_DEPTH {
                return Err(parse_error("structure nested too deeply"));
            }
            *i += 1;
            let mut items = Vec::new();
            loop {
                skip_ws(bytes, i);
                match bytes.get(*i) {
                    None => return Err(parse_error("unterminated list in structure")),
                    Some(b')') => {
                        *i += 1;
                        return Ok(SExpr::List(items));
                    }
                    Some(_) => items.push(read_value(text, i, depth + 1)?),
                }
            }
        }
        b')' => Err(parse_error(format!("unexpected ')' at offset {i}"))),
        b'"' => {
            *i += 1;
            let mut s = String::new();
            loop {
                match bytes.get(*i) {
                    None => return Err(parse_error("unterminated quoted string in structure")),
                    Some(b'"') => {
                        *i += 1;
                        return Ok(SExpr::Str(s));
                    }
                    Some(b'\\') => {
                        let Some(&next) = bytes.get(*i + 1) else {
                            return Err(parse_error("dangling escape in quoted string"));
                        };
                        push_char(&mut s, text, *i + 1, next);
                        *i += 1 + char_len(next);
                    }
                    Some(&c) => {
                        push_char(&mut s, text, *i, c);
                        *i += char_len(c);
                    }
                }
            }
        }
        _ => {
            let start = *i;
            while *i < bytes.len() && !matches!(bytes[*i], b' ' | b'\t' | b'\r' | b'\n' | b'(' | b')') {
                *i += 1;
            }
            let atom = &text[start..*i];
            if atom.is_empty() {
                return Err(parse_error(format!("unexpected byte at offset {start}")));
            }
            if atom.eq_ignore_ascii_case("NIL") {
                return Ok(SExpr::Nil);
            }
            if atom.bytes().all(|c| c.is_ascii_digit()) {
                if let Ok(n) = atom.parse::<u64>() {
                    return Ok(SExpr::Number(n));
                }
            }
            Ok(SExpr::Str(atom.to_string()))
        }
    }
}

/// Byte length of the UTF-8 sequence starting with `first`.
fn char_len(first: u8) -> usize {
    match first {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    }
}

fn push_char(s: &mut String, text: &str, at: usize, first: u8) {
    let len = char_len(first);
    match text.get(at..at + len) {
        Some(ch) => s.push_str(ch),
        None => s.push(char::REPLACEMENT_CHARACTER),
    }
}

// ── Semantic mapping ─────────────────────────────────────────────────────────

fn opt_string(e: Option<&SExpr>) -> Option<String> {
    match e {
        Some(SExpr::Str(s)) => Some(s.clone()),
        Some(SExpr::Number(n)) => Some(n.to_string()),
        _ => None,
    }
}

fn req_string(e: Option<&SExpr>, what: &str) -> ImapResult<String> {
    opt_string(e).ok_or_else(|| parse_error(format!("{what}: expected a string")))
}

fn number(e: Option<&SExpr>) -> Option<u64> {
    match e {
        Some(SExpr::Number(n)) => Some(*n),
        Some(SExpr::Str(s)) => s.parse().ok(),
        _ => None,
    }
}

/// `("name" "value" …)` → pairs, names lower-cased; `NIL` → empty.
fn params_from(e: Option<&SExpr>) -> Vec<(String, String)> {
    let Some(SExpr::List(items)) = e else {
        return Vec::new();
    };
    items
        .chunks(2)
        .filter_map(|pair| {
            let k = opt_string(pair.first())?.to_ascii_lowercase();
            let v = opt_string(pair.get(1)).unwrap_or_default();
            Some((k, v))
        })
        .collect()
}

/// `("type" (params))` → disposition; `NIL` → `None`.
fn disposition_from(e: Option<&SExpr>) -> Option<ImapDisposition> {
    let SExpr::List(items) = e? else {
        return None;
    };
    let kind = opt_string(items.first())?.to_ascii_lowercase();
    Some(ImapDisposition { kind, params: params_from(items.get(1)) })
}

/// `"lang"` or `("lang" …)` → tags; `NIL` → empty.
fn language_from(e: Option<&SExpr>) -> Vec<String> {
    match e {
        Some(SExpr::Str(s)) => vec![s.clone()],
        Some(SExpr::List(items)) => items.iter().filter_map(|it| opt_string(Some(it))).collect(),
        _ => Vec::new(),
    }
}

fn addresses_from(e: Option<&SExpr>) -> Vec<ImapAddress> {
    let Some(SExpr::List(items)) = e else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|it| match it {
            SExpr::List(f) => Some(ImapAddress {
                name: opt_string(f.first()),
                adl: opt_string(f.get(1)),
                mailbox: opt_string(f.get(2)),
                host: opt_string(f.get(3)),
            }),
            _ => None,
        })
        .collect()
}

fn envelope_from(expr: &SExpr) -> ImapResult<ImapEnvelope> {
    let SExpr::List(f) = expr else {
        return Err(parse_error("ENVELOPE: expected a parenthesized list"));
    };
    if f.len() < 10 {
        return Err(parse_error(format!("ENVELOPE: expected 10 fields, got {}", f.len())));
    }
    Ok(ImapEnvelope {
        date: opt_string(f.first()),
        subject: opt_string(f.get(1)),
        from: addresses_from(f.get(2)),
        sender: addresses_from(f.get(3)),
        reply_to: addresses_from(f.get(4)),
        to: addresses_from(f.get(5)),
        cc: addresses_from(f.get(6)),
        bcc: addresses_from(f.get(7)),
        in_reply_to: opt_string(f.get(8)),
        message_id: opt_string(f.get(9)),
    })
}

fn body_from(expr: &SExpr) -> ImapResult<ImapBodyStructure> {
    let SExpr::List(items) = expr else {
        return Err(parse_error("BODYSTRUCTURE: expected a parenthesized list"));
    };
    if items.is_empty() {
        return Err(parse_error("BODYSTRUCTURE: empty list"));
    }
    if matches!(items[0], SExpr::List(_)) {
        multipart_from(items)
    } else {
        part_from(items).map(ImapBodyStructure::Part)
    }
}

/// `body-type-mpart`: one or more bodies, the subtype, then optional
/// extension data `params disposition language location`.
fn multipart_from(items: &[SExpr]) -> ImapResult<ImapBodyStructure> {
    let mut i = 0;
    let mut parts = Vec::new();
    while let Some(SExpr::List(_)) = items.get(i) {
        parts.push(body_from(&items[i])?);
        i += 1;
    }
    let media_subtype = req_string(items.get(i), "multipart subtype")?.to_ascii_lowercase();
    let ext = &items[i + 1..];
    Ok(ImapBodyStructure::Multipart(ImapMultipart {
        media_subtype,
        parts,
        params: params_from(ext.first()),
        disposition: disposition_from(ext.get(1)),
        language: language_from(ext.get(2)),
        location: opt_string(ext.get(3)),
    }))
}

/// `body-type-1part`: `type subtype params id description encoding size`,
/// then for `text/*` the line count, for `message/rfc822` the nested
/// envelope, body and line count; then optional extension data
/// `md5 disposition language location`.
fn part_from(items: &[SExpr]) -> ImapResult<ImapBodyPart> {
    if items.len() < 7 {
        return Err(parse_error(format!("BODYSTRUCTURE part: expected at least 7 fields, got {}", items.len())));
    }
    let media_type = req_string(items.first(), "media type")?.to_ascii_lowercase();
    let media_subtype = req_string(items.get(1), "media subtype")?.to_ascii_lowercase();
    let mut part = ImapBodyPart {
        media_type,
        media_subtype,
        params: params_from(items.get(2)),
        content_id: opt_string(items.get(3)),
        description: opt_string(items.get(4)),
        encoding: opt_string(items.get(5)).unwrap_or_else(|| "7BIT".to_string()).to_ascii_uppercase(),
        size: number(items.get(6)).unwrap_or(0),
        ..Default::default()
    };
    let mut i = 7;
    if part.media_type == "message" && part.media_subtype == "rfc822" {
        // Servers that cannot parse the inner message fall back to the
        // basic shape (RFC 9051 §7.5.2 allows it); tolerate both.
        if let (Some(env @ SExpr::List(_)), Some(body @ SExpr::List(_))) = (items.get(7), items.get(8)) {
            let envelope = envelope_from(env)?;
            let body = body_from(body)?;
            part.nested = Some(Box::new((envelope, body)));
            part.lines = number(items.get(9));
            i = 10;
        }
    } else if part.media_type == "text" {
        part.lines = number(items.get(7));
        i = 8;
    }
    let ext = items.get(i..).unwrap_or(&[]);
    part.md5 = opt_string(ext.first());
    part.disposition = disposition_from(ext.get(1));
    part.language = language_from(ext.get(2));
    part.location = opt_string(ext.get(3));
    Ok(part)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn part<'a>(parts: &'a [ImapSectionPart<'a>], section: &str) -> &'a ImapBodyPart {
        parts.iter().find(|(s, _)| s == section).map(|(_, p)| *p).unwrap_or_else(|| panic!("no section {section}"))
    }

    #[test]
    fn single_text_part() {
        let bs = ImapBodyStructure::parse(r#"("TEXT" "PLAIN" ("CHARSET" "UTF-8") NIL NIL "QUOTED-PRINTABLE" 42 3)"#).unwrap();
        let parts = bs.parts();
        assert_eq!(parts.len(), 1);
        let p = part(&parts, "1");
        assert_eq!(p.media(), "text/plain");
        assert_eq!(p.charset(), Some("UTF-8"));
        assert_eq!(p.encoding, "QUOTED-PRINTABLE");
        assert_eq!(p.size, 42);
        assert_eq!(p.lines, Some(3));
        assert!(!p.is_attachment());
    }

    #[test]
    fn alternative_numbers_its_parts() {
        let bs = ImapBodyStructure::parse(
            r#"(("TEXT" "PLAIN" ("CHARSET" "UTF-8") NIL NIL "7BIT" 10 1)("TEXT" "HTML" ("CHARSET" "UTF-8") NIL NIL "QUOTED-PRINTABLE" 20 1) "ALTERNATIVE" ("BOUNDARY" "x"))"#,
        )
        .unwrap();
        let ImapBodyStructure::Multipart(mp) = &bs else { panic!("expected multipart") };
        assert_eq!(mp.media_subtype, "alternative");
        assert_eq!(mp.params, vec![("boundary".to_string(), "x".to_string())]);
        let parts = bs.parts();
        assert_eq!(parts.iter().map(|(s, _)| s.as_str()).collect::<Vec<_>>(), vec!["1", "2"]);
        assert_eq!(part(&parts, "2").media(), "text/html");
        let (plain, html) = bs.display_candidates();
        assert_eq!(plain.map(|(s, _)| s).as_deref(), Some("1"));
        assert_eq!(html.map(|(s, _)| s).as_deref(), Some("2"));
    }

    /// Extended multipart data (extra NILs after the boundary) is what real
    /// servers send; it used to break tagliacarte's planner.
    #[test]
    fn extended_multipart_data_is_tolerated() {
        let bs = ImapBodyStructure::parse(
            r#"(("TEXT" "plain" ("charset" "UTF-8") NIL NIL "QUOTED-PRINTABLE" 12279 158 NIL NIL NIL NIL)("TEXT" "html" ("charset" "UTF-8") NIL NIL "QUOTED-PRINTABLE" 64748 832 NIL NIL NIL NIL) "alternative" ("boundary" "_----/hALBbAWiPaRTdEKOe/0Uw===_D5/F2-17034-7AF5DC96") NIL NIL NIL)"#,
        )
        .unwrap();
        let (plain, html) = bs.display_candidates();
        assert_eq!(plain.unwrap().0, "1");
        assert_eq!(html.unwrap().0, "2");
    }

    #[test]
    fn mixed_with_attachment_and_nested_multipart() {
        let bs = ImapBodyStructure::parse(concat!(
            r#"(("TEXT" "PLAIN" ("CHARSET" "US-ASCII") NIL NIL "7BIT" 1152 23)"#,
            r#"(("TEXT" "PLAIN" ("CHARSET" "US-ASCII") NIL NIL "7BIT" 10 1)("TEXT" "HTML" NIL NIL NIL "8BIT" 20 1) "ALTERNATIVE" ("BOUNDARY" "inner"))"#,
            r#"("APPLICATION" "PDF" ("NAME" "report.pdf") NIL NIL "BASE64" 4554 NIL ("attachment" ("filename" "report.pdf")) NIL NIL)"#,
            r#"("IMAGE" "PNG" ("NAME" "logo.png") "<logo@x>" NIL "BASE64" 300 NIL ("inline" ("filename" "logo.png")) NIL NIL)"#,
            r#" "MIXED" ("BOUNDARY" "outer") NIL ("en" "fr") NIL)"#,
        ))
        .unwrap();
        let parts = bs.parts();
        assert_eq!(
            parts.iter().map(|(s, _)| s.as_str()).collect::<Vec<_>>(),
            vec!["1", "2.1", "2.2", "3", "4"]
        );
        let pdf = part(&parts, "3");
        assert!(pdf.is_attachment());
        assert_eq!(pdf.filename(), Some("report.pdf"));
        assert_eq!(pdf.lines, None);
        let logo = part(&parts, "4");
        assert!(!logo.is_attachment(), "inline by disposition");
        assert_eq!(logo.content_id.as_deref(), Some("<logo@x>"));
        let ImapBodyStructure::Multipart(mp) = &bs else { panic!() };
        assert_eq!(mp.language, vec!["en", "fr"]);
        let (plain, html) = bs.display_candidates();
        assert_eq!(plain.unwrap().0, "1", "first text/plain wins");
        assert_eq!(html.unwrap().0, "2.2");
    }

    /// RFC 3501 §6.4.5's numbering for an encapsulated message: the
    /// message/rfc822 part itself, then its inner parts under its number.
    #[test]
    fn message_rfc822_parts_are_numbered_under_their_container() {
        let bs = ImapBodyStructure::parse(concat!(
            r#"(("TEXT" "PLAIN" NIL NIL NIL "7BIT" 5 1)"#,
            r#"("MESSAGE" "RFC822" NIL NIL NIL "7BIT" 999 "#,
            r#"("Thu, 1 Jan 2026 00:00:00 +0000" "Fwd" (("A" NIL "a" "x.org")) NIL NIL NIL NIL NIL NIL "<m1@x.org>") "#,
            r#"(("TEXT" "PLAIN" NIL NIL NIL "7BIT" 7 1)("APPLICATION" "OCTET-STREAM" NIL NIL NIL "BASE64" 8 NIL ("attachment" ("filename" "f.bin")) NIL NIL) "MIXED" ("BOUNDARY" "in")) 40)"#,
            r#"("MESSAGE" "RFC822" NIL NIL NIL "7BIT" 50 "#,
            r#"("Thu, 1 Jan 2026 00:00:00 +0000" "Single" NIL NIL NIL NIL NIL NIL NIL NIL) "#,
            r#"("TEXT" "PLAIN" NIL NIL NIL "7BIT" 9 1) 3)"#,
            r#" "MIXED")"#,
        ))
        .unwrap();
        let parts = bs.parts();
        assert_eq!(
            parts.iter().map(|(s, _)| s.as_str()).collect::<Vec<_>>(),
            vec!["1", "2", "2.1", "2.2", "3", "3.1"]
        );
        let fwd = part(&parts, "2");
        assert_eq!(fwd.media(), "message/rfc822");
        assert_eq!(fwd.lines, Some(40));
        let nested = fwd.nested.as_ref().unwrap();
        assert_eq!(nested.0.subject.as_deref(), Some("Fwd"));
        assert_eq!(nested.0.from[0].address().as_deref(), Some("a@x.org"));
        assert_eq!(part(&parts, "2.2").filename(), Some("f.bin"));
        assert_eq!(part(&parts, "3.1").size, 9);
    }

    /// A server that could not parse the inner message sends message/rfc822
    /// in the basic shape; that must still parse as a leaf.
    #[test]
    fn message_rfc822_without_nested_structure() {
        let bs = ImapBodyStructure::parse(r#"("MESSAGE" "RFC822" NIL NIL NIL "7BIT" 999 NIL ("attachment" ("filename" "old.eml")) NIL NIL)"#).unwrap();
        let parts = bs.parts();
        assert_eq!(parts.len(), 1);
        let p = part(&parts, "1");
        assert!(p.nested.is_none());
        assert_eq!(p.filename(), Some("old.eml"));
    }

    #[test]
    fn atoms_and_lowercase_nil_are_accepted() {
        let bs = ImapBodyStructure::parse(r#"(text plain (charset utf-8) nil nil 7bit 12 1)"#).unwrap();
        let parts = bs.parts();
        let p = part(&parts, "1");
        assert_eq!(p.media(), "text/plain");
        assert_eq!(p.charset(), Some("utf-8"));
        assert_eq!(p.encoding, "7BIT");
        assert!(p.content_id.is_none());
    }

    #[test]
    fn malformed_structures_are_errors_not_panics() {
        for bad in [
            "",
            "(",
            ")",
            r#"("TEXT" "PLAIN")"#,
            r#"(("TEXT" "PLAIN" NIL NIL NIL "7BIT" 1 1))"#,
            r#"("TEXT" "PLAIN" NIL NIL NIL "7BIT" 1 1) extra"#,
            r#"("TEXT" "unterminated"#,
            "(((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((",
        ] {
            assert!(ImapBodyStructure::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn envelope_fields_and_groups() {
        let env = ImapEnvelope::parse(concat!(
            r#"("Wed, 17 Jul 1996 02:23:25 -0700 (PDT)" "IMAP4rev2 WG mtg summary \"and\" minutes" "#,
            r#"(("Terry Gray" NIL "gray" "cac.washington.edu")) "#,
            r#"(("Terry Gray" NIL "gray" "cac.washington.edu")) "#,
            r#"(("Terry Gray" NIL "gray" "cac.washington.edu")) "#,
            r#"((NIL NIL "imap" "cac.washington.edu")) "#,
            r#"((NIL NIL "minutes" "CNRI.Reston.VA.US")(NIL NIL "undisclosed" NIL)("John Klensin" NIL "KLENSIN" "MIT.EDU")(NIL NIL NIL NIL)) "#,
            r#"NIL NIL "<B27397-0100000@cac.washington.edu>")"#,
        ))
        .unwrap();
        assert_eq!(env.date.as_deref(), Some("Wed, 17 Jul 1996 02:23:25 -0700 (PDT)"));
        assert_eq!(env.subject.as_deref(), Some(r#"IMAP4rev2 WG mtg summary "and" minutes"#));
        assert_eq!(env.from[0].name.as_deref(), Some("Terry Gray"));
        assert_eq!(env.from[0].address().as_deref(), Some("gray@cac.washington.edu"));
        assert_eq!(env.to[0].address().as_deref(), Some("imap@cac.washington.edu"));
        assert_eq!(env.cc.len(), 4);
        assert_eq!(env.cc[1].mailbox.as_deref(), Some("undisclosed"), "group start");
        assert!(env.cc[1].host.is_none() && env.cc[1].address().is_none());
        assert!(env.cc[3].mailbox.is_none() && env.cc[3].host.is_none(), "group end");
        assert!(env.bcc.is_empty());
        assert!(env.in_reply_to.is_none());
        assert_eq!(env.message_id.as_deref(), Some("<B27397-0100000@cac.washington.edu>"));
    }

    #[test]
    fn envelope_with_escaped_and_non_ascii_subject_from_a_captured_literal() {
        // What the lexer produces for a `{n}` literal subject.
        let env = ImapEnvelope::parse(r#"("date" "Say \"hi\" \\ café" NIL NIL NIL NIL NIL NIL NIL NIL)"#).unwrap();
        assert_eq!(env.subject.as_deref(), Some(r#"Say "hi" \ café"#));
        assert!(ImapEnvelope::parse(r#"("date" "subj")"#).is_err(), "too few fields");
    }
}
