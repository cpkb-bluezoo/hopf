// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! IMAP FETCH response formatting helpers.

use std::collections::BTreeSet;

use hopf_mailbox::Flag;

/// One FETCH data item requested by the client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FetchItem {
    /// `FLAGS`
    Flags,
    /// `UID`
    Uid,
    /// `RFC822.SIZE`
    Rfc822Size,
    /// `RFC822` (full message)
    Rfc822,
    /// `RFC822.HEADER`
    Rfc822Header,
    /// `RFC822.TEXT`
    Rfc822Text,
    /// `BODY[]` or `BODY.PEEK[]` — full body; `peek` skips `\Seen`.
    Body {
        /// `true` for `BODY.PEEK`.
        peek: bool,
        /// Header field filter (`BODY[HEADER.FIELDS (...)]`), if any.
        header_fields: Option<Vec<String>>,
        /// `BODY[HEADER]` / `BODY[TEXT]` section.
        section: BodySection,
    },
    /// `MODSEQ` (CONDSTORE).
    ModSeq,
    /// Unknown / passthrough atom (echoed as NIL).
    Other(String),
}

/// BODY section selector for basic header/text fetches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BodySection {
    /// Full message (`BODY[]`).
    Full,
    /// Header block only.
    Header,
    /// Body text after the header blank line.
    Text,
    /// Specific header fields.
    HeaderFields,
}

/// Parse a FETCH items list such as `(FLAGS UID BODY.PEEK[])` or a single atom.
pub fn parse_fetch_items(s: &str) -> Result<Vec<FetchItem>, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty FETCH items".into());
    }
    let inner = if s.starts_with('(') {
        if !s.ends_with(')') {
            return Err("unclosed FETCH list".into());
        }
        &s[1..s.len() - 1]
    } else {
        s
    };
    let mut items = Vec::new();
    let mut i = 0;
    let bytes = inner.as_bytes();
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let start = i;
        // Consume atom / BODY[...] token.
        while i < bytes.len() {
            let c = bytes[i];
            if c == b'[' {
                // Include bracketed section.
                i += 1;
                let mut depth = 1i32;
                while i < bytes.len() && depth > 0 {
                    if bytes[i] == b'[' {
                        depth += 1;
                    } else if bytes[i] == b']' {
                        depth -= 1;
                    } else if bytes[i] == b'(' {
                        // nested list inside HEADER.FIELDS
                        i += 1;
                        let mut pdepth = 1i32;
                        while i < bytes.len() && pdepth > 0 {
                            if bytes[i] == b'(' {
                                pdepth += 1;
                            } else if bytes[i] == b')' {
                                pdepth -= 1;
                            }
                            i += 1;
                        }
                        continue;
                    }
                    i += 1;
                }
                break;
            }
            if c.is_ascii_whitespace() || c == b')' {
                break;
            }
            i += 1;
        }
        let tok = inner[start..i].trim();
        if !tok.is_empty() {
            items.push(parse_one_item(tok)?);
        }
    }
    if items.is_empty() {
        return Err("empty FETCH items".into());
    }
    Ok(items)
}

fn parse_one_item(tok: &str) -> Result<FetchItem, String> {
    let upper = tok.to_ascii_uppercase();
    Ok(match upper.as_str() {
        "FLAGS" => FetchItem::Flags,
        "UID" => FetchItem::Uid,
        "RFC822.SIZE" => FetchItem::Rfc822Size,
        "RFC822" => FetchItem::Rfc822,
        "RFC822.HEADER" => FetchItem::Rfc822Header,
        "RFC822.TEXT" => FetchItem::Rfc822Text,
        "MODSEQ" => FetchItem::ModSeq,
        _ if upper.starts_with("BODY.PEEK[") || upper.starts_with("BODY[") => {
            let peek = upper.starts_with("BODY.PEEK[");
            let section_start = tok.find('[').ok_or("bad BODY item")?;
            let section_end = tok.rfind(']').ok_or("bad BODY item")?;
            let section = &tok[section_start + 1..section_end];
            parse_body_section(peek, section)
        }
        _ => FetchItem::Other(tok.to_string()),
    })
}

fn parse_body_section(peek: bool, section: &str) -> FetchItem {
    let s = section.trim();
    if s.is_empty() {
        return FetchItem::Body {
            peek,
            header_fields: None,
            section: BodySection::Full,
        };
    }
    let upper = s.to_ascii_uppercase();
    if upper == "HEADER" {
        return FetchItem::Body {
            peek,
            header_fields: None,
            section: BodySection::Header,
        };
    }
    if upper == "TEXT" {
        return FetchItem::Body {
            peek,
            header_fields: None,
            section: BodySection::Text,
        };
    }
    if upper.starts_with("HEADER.FIELDS") {
        let fields = extract_header_fields(s);
        return FetchItem::Body {
            peek,
            header_fields: Some(fields),
            section: BodySection::HeaderFields,
        };
    }
    FetchItem::Body {
        peek,
        header_fields: None,
        section: BodySection::Full,
    }
}

fn extract_header_fields(section: &str) -> Vec<String> {
    let Some(start) = section.find('(') else {
        return Vec::new();
    };
    let Some(end) = section.rfind(')') else {
        return Vec::new();
    };
    section[start + 1..end]
        .split_whitespace()
        .map(|s| s.trim_matches('"').to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Whether any item requires loading full message bytes.
pub fn fetch_needs_bytes(items: &[FetchItem]) -> bool {
    items.iter().any(|i| {
        matches!(
            i,
            FetchItem::Rfc822
                | FetchItem::Rfc822Header
                | FetchItem::Rfc822Text
                | FetchItem::Body { .. }
        )
    })
}

/// Whether FETCH should set `\Seen` (non-peek body / RFC822).
pub fn fetch_sets_seen(items: &[FetchItem]) -> bool {
    items.iter().any(|i| match i {
        FetchItem::Rfc822 | FetchItem::Rfc822Header | FetchItem::Rfc822Text => true,
        FetchItem::Body { peek, .. } => !peek,
        _ => false,
    })
}

/// Format FLAGS parenthesized list.
pub fn format_flags(flags: &BTreeSet<Flag>, keywords: &BTreeSet<String>) -> String {
    let mut parts: Vec<String> = flags.iter().map(|f| f.atom().to_string()).collect();
    for k in keywords {
        parts.push(k.clone());
    }
    format!("({})", parts.join(" "))
}

/// Quote or literal-encode an IMAP string for responses.
pub fn format_nstring(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return b"\"\"".to_vec();
    }
    // Prefer quoted when ASCII-safe; otherwise synchronizing literal.
    if data
        .iter()
        .all(|&b| (b.is_ascii_graphic() || b == b' ') && b != b'\\' && b != b'"')
        && !data.contains(&b'\r')
        && !data.contains(&b'\n')
        && data.len() < 1024
    {
        let mut out = Vec::with_capacity(data.len() + 2);
        out.push(b'"');
        for &b in data {
            if b == b'\\' || b == b'"' {
                out.push(b'\\');
            }
            out.push(b);
        }
        out.push(b'"');
        return out;
    }
    let mut out = format!("{{{}}}\r\n", data.len()).into_bytes();
    out.extend_from_slice(data);
    out
}

/// Extract header block (including trailing blank line) from an RFC822 message.
pub fn message_header(msg: &[u8]) -> &[u8] {
    if let Some(i) = find_header_end(msg) {
        &msg[..i]
    } else {
        msg
    }
}

/// Extract body text after the header blank line.
pub fn message_text(msg: &[u8]) -> &[u8] {
    if let Some(i) = find_header_end(msg) {
        &msg[i..]
    } else {
        &[]
    }
}

/// Select listed header fields (case-insensitive names) into a header block.
pub fn select_header_fields(msg: &[u8], fields: &[String]) -> Vec<u8> {
    let header = message_header(msg);
    let mut out = Vec::new();
    let wanted: Vec<String> = fields.iter().map(|f| f.to_ascii_lowercase()).collect();
    let mut i = 0;
    while i < header.len() {
        let line_end = header[i..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|p| i + p + 1)
            .unwrap_or(header.len());
        let line = &header[i..line_end];
        // Folded continuation lines start with SP/HTAB — attach to previous.
        if line
            .first()
            .map(|b| *b == b' ' || *b == b'\t')
            .unwrap_or(false)
        {
            if !out.is_empty() {
                out.extend_from_slice(line);
            }
            i = line_end;
            continue;
        }
        if line == b"\r\n" || line == b"\n" {
            break;
        }
        let name_end = line.iter().position(|&b| b == b':').unwrap_or(0);
        let name = String::from_utf8_lossy(&line[..name_end]).to_ascii_lowercase();
        if wanted.iter().any(|w| w == &name) {
            out.extend_from_slice(line);
            // Include subsequent folded lines.
            i = line_end;
            while i < header.len() {
                let le = header[i..]
                    .iter()
                    .position(|&b| b == b'\n')
                    .map(|p| i + p + 1)
                    .unwrap_or(header.len());
                let cont = &header[i..le];
                if cont
                    .first()
                    .map(|b| *b == b' ' || *b == b'\t')
                    .unwrap_or(false)
                {
                    out.extend_from_slice(cont);
                    i = le;
                } else {
                    break;
                }
            }
            continue;
        }
        i = line_end;
    }
    out.extend_from_slice(b"\r\n");
    out
}

fn find_header_end(msg: &[u8]) -> Option<usize> {
    msg.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .or_else(|| msg.windows(2).position(|w| w == b"\n\n").map(|i| i + 2))
}

/// Optional FETCH modifiers after the items list (`(CHANGEDSINCE n)`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FetchModifiers {
    /// CHANGEDSINCE modseq (exclusive); `None` if absent.
    pub changed_since: Option<u64>,
}

/// Split FETCH args into `(sequence-set already parsed) items [modifiers]`.
///
/// `rest` is everything after the sequence set.
pub fn parse_fetch_args(rest: &str) -> Result<(Vec<FetchItem>, FetchModifiers), String> {
    let rest = rest.trim_start();
    if rest.is_empty() {
        return Err("empty FETCH items".into());
    }
    // Items may be a parenthesized list or a single atom; optional trailing
    // `(CHANGEDSINCE n)` modifier list.
    let (items_part, mods_part) = split_fetch_items_and_mods(rest)?;
    let items = parse_fetch_items(items_part)?;
    let modifiers = parse_fetch_modifiers(mods_part)?;
    Ok((items, modifiers))
}

fn split_fetch_items_and_mods(s: &str) -> Result<(&str, &str), String> {
    let s = s.trim();
    if !s.starts_with('(') {
        // Single atom — no modifiers supported without parens on items.
        return Ok((s, ""));
    }
    let mut depth = 0i32;
    for (i, b) in s.bytes().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    let items = &s[..=i];
                    let rest = s[i + 1..].trim_start();
                    return Ok((items, rest));
                }
            }
            _ => {}
        }
    }
    Err("unclosed FETCH items".into())
}

fn parse_fetch_modifiers(s: &str) -> Result<FetchModifiers, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(FetchModifiers::default());
    }
    if !s.starts_with('(') || !s.ends_with(')') {
        return Err("FETCH modifiers must be parenthesized".into());
    }
    let inner = &s[1..s.len() - 1];
    let mut mods = FetchModifiers::default();
    let upper = inner.to_ascii_uppercase();
    if let Some(rest) = upper.strip_prefix("CHANGEDSINCE") {
        let n: u64 = rest
            .trim()
            .parse()
            .map_err(|_| "bad CHANGEDSINCE value".to_string())?;
        mods.changed_since = Some(n);
    } else if !inner.trim().is_empty() {
        // Ignore unknown modifiers rather than failing hard.
    }
    Ok(mods)
}

/// Build one untagged FETCH body (without the `* N FETCH` prefix / CRLF).
///
/// Returns the parenthesized attribute list bytes, e.g. `(FLAGS (\\Seen) UID 1)`.
pub fn format_fetch_attrs(
    items: &[FetchItem],
    seq: u32,
    uid: u64,
    size: u64,
    flags: &BTreeSet<Flag>,
    keywords: &BTreeSet<String>,
    msg: Option<&[u8]>,
    by_uid: bool,
    modseq: Option<u64>,
) -> Vec<u8> {
    let _ = seq;
    let mut out = Vec::from(b"(".as_slice());
    let mut first = true;
    let mut wrote_uid = false;
    let mut wrote_modseq = false;

    let emit = |name: &str, value: &[u8], buf: &mut Vec<u8>, first: &mut bool| {
        if !*first {
            buf.push(b' ');
        }
        *first = false;
        buf.extend_from_slice(name.as_bytes());
        buf.push(b' ');
        buf.extend_from_slice(value);
    };

    for item in items {
        match item {
            FetchItem::Flags => {
                let f = format_flags(flags, keywords);
                emit("FLAGS", f.as_bytes(), &mut out, &mut first);
            }
            FetchItem::Uid => {
                emit("UID", uid.to_string().as_bytes(), &mut out, &mut first);
                wrote_uid = true;
            }
            FetchItem::ModSeq => {
                if let Some(m) = modseq {
                    // RFC 7162: MODSEQ value is parenthesized.
                    let v = format!("({m})");
                    emit("MODSEQ", v.as_bytes(), &mut out, &mut first);
                    wrote_modseq = true;
                }
            }
            FetchItem::Rfc822Size => {
                emit(
                    "RFC822.SIZE",
                    size.to_string().as_bytes(),
                    &mut out,
                    &mut first,
                );
            }
            FetchItem::Rfc822 => {
                let data = msg.unwrap_or(&[]);
                let lit = format_nstring(data);
                emit("RFC822", &lit, &mut out, &mut first);
            }
            FetchItem::Rfc822Header => {
                let data = msg.map(message_header).unwrap_or(&[]);
                let lit = format_nstring(data);
                emit("RFC822.HEADER", &lit, &mut out, &mut first);
            }
            FetchItem::Rfc822Text => {
                let data = msg.map(message_text).unwrap_or(&[]);
                let lit = format_nstring(data);
                emit("RFC822.TEXT", &lit, &mut out, &mut first);
            }
            FetchItem::Body {
                peek,
                header_fields,
                section,
            } => {
                let name = body_item_name(*peek, section, header_fields.as_deref());
                let data: Vec<u8> = match (section, msg) {
                    (BodySection::Full, Some(m)) => m.to_vec(),
                    (BodySection::Header, Some(m)) => message_header(m).to_vec(),
                    (BodySection::Text, Some(m)) => message_text(m).to_vec(),
                    (BodySection::HeaderFields, Some(m)) => {
                        select_header_fields(m, header_fields.as_deref().unwrap_or(&[]))
                    }
                    _ => Vec::new(),
                };
                let lit = format_nstring(&data);
                emit(&name, &lit, &mut out, &mut first);
            }
            FetchItem::Other(name) => {
                emit(name, b"NIL", &mut out, &mut first);
            }
        }
    }

    if by_uid && !wrote_uid {
        emit("UID", uid.to_string().as_bytes(), &mut out, &mut first);
    }
    if let Some(m) = modseq {
        if !wrote_modseq {
            let v = format!("({m})");
            emit("MODSEQ", v.as_bytes(), &mut out, &mut first);
        }
    }
    out.push(b')');
    out
}

fn body_item_name(peek: bool, section: &BodySection, fields: Option<&[String]>) -> String {
    let prefix = if peek { "BODY.PEEK" } else { "BODY" };
    match section {
        BodySection::Full => format!("{prefix}[]"),
        BodySection::Header => format!("{prefix}[HEADER]"),
        BodySection::Text => format!("{prefix}[TEXT]"),
        BodySection::HeaderFields => {
            let list = fields
                .unwrap_or(&[])
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(" ");
            format!("{prefix}[HEADER.FIELDS ({list})]")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_list() {
        let items = parse_fetch_items("(FLAGS UID RFC822.SIZE)").unwrap();
        assert_eq!(
            items,
            vec![FetchItem::Flags, FetchItem::Uid, FetchItem::Rfc822Size]
        );
    }

    #[test]
    fn parse_body_peek() {
        let items = parse_fetch_items("BODY.PEEK[]").unwrap();
        assert!(matches!(
            items[0],
            FetchItem::Body {
                peek: true,
                section: BodySection::Full,
                ..
            }
        ));
    }

    #[test]
    fn parse_header_fields() {
        let items = parse_fetch_items("(BODY[HEADER.FIELDS (From Subject)])").unwrap();
        match &items[0] {
            FetchItem::Body {
                section: BodySection::HeaderFields,
                header_fields: Some(f),
                ..
            } => {
                assert_eq!(f, &["From".to_string(), "Subject".to_string()]);
            }
            _ => panic!("expected HEADER.FIELDS"),
        }
    }

    #[test]
    fn format_flags_and_nstring() {
        let mut flags = BTreeSet::new();
        flags.insert(Flag::Seen);
        assert_eq!(format_flags(&flags, &BTreeSet::new()), "(\\Seen)");
        assert_eq!(format_nstring(b"hi"), b"\"hi\"");
        let lit = format_nstring(b"a\nb");
        assert!(lit.starts_with(b"{3}\r\n"));
    }

    #[test]
    fn header_text_split() {
        let msg = b"From: a\r\nSubject: b\r\n\r\nHello\r\n";
        assert_eq!(message_header(msg), b"From: a\r\nSubject: b\r\n\r\n");
        assert_eq!(message_text(msg), b"Hello\r\n");
        let sel = select_header_fields(msg, &["Subject".into()]);
        assert!(sel.starts_with(b"Subject: b\r\n"));
    }
}
