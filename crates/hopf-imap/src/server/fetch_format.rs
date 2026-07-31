// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! IMAP FETCH response formatting helpers.

use std::collections::BTreeSet;

use hopf_mailbox::{Flag, Mailbox, MailboxResult, MessageReadCallback};

use crate::server::bodystructure::{build_structure, build_structure_for_whole_message, format_bodystructure};
use crate::server::envelope::{format_envelope, parse_envelope};

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
        /// Trailing `<start.count>` octet range, if any.
        partial: Option<(u64, u64)>,
    },
    /// `MODSEQ` (CONDSTORE).
    ModSeq,
    /// `ENVELOPE` (RFC 9051 §7.5.2).
    Envelope,
    /// `BODYSTRUCTURE` (RFC 9051 §7.5.2, recursive MIME structure).
    BodyStructure,
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
                // Optional trailing partial-fetch range, e.g. `<0.1024>`
                // (RFC 9051 §7.5) — without this, the `<...>` is left for
                // the outer loop to mis-tokenize as a bogus following item.
                if i < bytes.len() && bytes[i] == b'<' {
                    if let Some(end) = bytes[i..].iter().position(|&b| b == b'>') {
                        i += end + 1;
                    }
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
        "ENVELOPE" => FetchItem::Envelope,
        "BODYSTRUCTURE" => FetchItem::BodyStructure,
        _ if upper.starts_with("BODY.PEEK[") || upper.starts_with("BODY[") => {
            let peek = upper.starts_with("BODY.PEEK[");
            let section_start = tok.find('[').ok_or("bad BODY item")?;
            let section_end = tok.rfind(']').ok_or("bad BODY item")?;
            let section = &tok[section_start + 1..section_end];
            let partial = parse_partial_range(&tok[section_end + 1..])?;
            parse_body_section(peek, section, partial)
        }
        _ => FetchItem::Other(tok.to_string()),
    })
}

/// Parse a trailing `<start.count>` octet range (RFC 9051 §7.5) following a
/// `BODY[section]`/`BODY.PEEK[section]` item's closing `]`. `s` is either
/// empty (no partial range) or the exact `<...>` span.
fn parse_partial_range(s: &str) -> Result<Option<(u64, u64)>, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    if !s.starts_with('<') || !s.ends_with('>') {
        return Err("bad partial fetch range".into());
    }
    let inner = &s[1..s.len() - 1];
    let (start_s, count_s) = inner.split_once('.').ok_or("bad partial fetch range")?;
    let start: u64 = start_s
        .parse()
        .map_err(|_| "bad partial fetch start".to_string())?;
    let count: u64 = count_s
        .parse()
        .map_err(|_| "bad partial fetch count".to_string())?;
    if count == 0 {
        return Err("partial fetch count must be nonzero".into());
    }
    Ok(Some((start, count)))
}

fn parse_body_section(peek: bool, section: &str, partial: Option<(u64, u64)>) -> FetchItem {
    let s = section.trim();
    if s.is_empty() {
        return FetchItem::Body {
            peek,
            header_fields: None,
            section: BodySection::Full,
            partial,
        };
    }
    let upper = s.to_ascii_uppercase();
    if upper == "HEADER" {
        return FetchItem::Body {
            peek,
            header_fields: None,
            section: BodySection::Header,
            partial,
        };
    }
    if upper == "TEXT" {
        return FetchItem::Body {
            peek,
            header_fields: None,
            section: BodySection::Text,
            partial,
        };
    }
    if upper.starts_with("HEADER.FIELDS") {
        let fields = extract_header_fields(s);
        return FetchItem::Body {
            peek,
            header_fields: Some(fields),
            section: BodySection::HeaderFields,
            partial,
        };
    }
    FetchItem::Body {
        peek,
        header_fields: None,
        section: BodySection::Full,
        partial,
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
                | FetchItem::Envelope
                | FetchItem::BodyStructure
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
    select_header_fields_from_header(message_header(msg), fields)
}

/// Same as [`select_header_fields`], but takes the header block directly
/// (already isolated) instead of a whole message — used by the streaming
/// FETCH path, which never assembles a whole message in the first place.
pub fn select_header_fields_from_header(header: &[u8], fields: &[String]) -> Vec<u8> {
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

pub(crate) fn find_header_end(msg: &[u8]) -> Option<usize> {
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
                partial,
            } => {
                let name = body_item_name(*peek, section, header_fields.as_deref(), *partial);
                let data: Vec<u8> = match (section, msg) {
                    (BodySection::Full, Some(m)) => m.to_vec(),
                    (BodySection::Header, Some(m)) => message_header(m).to_vec(),
                    (BodySection::Text, Some(m)) => message_text(m).to_vec(),
                    (BodySection::HeaderFields, Some(m)) => {
                        select_header_fields(m, header_fields.as_deref().unwrap_or(&[]))
                    }
                    _ => Vec::new(),
                };
                let data = slice_partial(&data, *partial);
                let lit = format_nstring(&data);
                emit(&name, &lit, &mut out, &mut first);
            }
            FetchItem::Envelope => {
                let env = msg.map(|m| parse_envelope(message_header(m))).unwrap_or_default();
                emit("ENVELOPE", &format_envelope(&env), &mut out, &mut first);
            }
            FetchItem::BodyStructure => {
                let bytes = match msg {
                    Some(m) => format_bodystructure(&build_structure_for_whole_message(m)),
                    None => b"NIL".to_vec(),
                };
                emit("BODYSTRUCTURE", &bytes, &mut out, &mut first);
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

/// How much of a message's header block a single content-scanning pass will
/// capture before giving up — headers are inherently small (a few KB, even
/// pathologically), so this is generous, not a proxy for "whole message".
const MAX_HEADER_CAP: usize = 1 << 20;

struct HeaderScan {
    buf: Vec<u8>,
    boundary: Option<usize>,
}

impl MessageReadCallback for HeaderScan {
    fn message_content(&mut self, chunk: &[u8]) -> bool {
        if self.buf.len() < MAX_HEADER_CAP {
            let take = chunk.len().min(MAX_HEADER_CAP - self.buf.len());
            self.buf.extend_from_slice(&chunk[..take]);
        }
        if let Some(b) = find_header_end(&self.buf) {
            self.boundary = Some(b);
            return false;
        }
        self.buf.len() < MAX_HEADER_CAP
    }
}

/// One read pass that finds the header/body boundary, capturing the header
/// bytes themselves (capped — see [`MAX_HEADER_CAP`]) along the way. The
/// returned length is exact and needed up front for any header- or
/// text-derived FETCH literal, regardless of whether the header content
/// itself ends up being used.
fn scan_header(mb: &mut dyn Mailbox, seq: u32) -> MailboxResult<(Vec<u8>, u64)> {
    let mut cb = HeaderScan {
        buf: Vec::new(),
        boundary: None,
    };
    mb.read_message(seq, &mut cb)?;
    let boundary = cb.boundary.unwrap_or(cb.buf.len());
    cb.buf.truncate(boundary);
    Ok((cb.buf, boundary as u64))
}

struct SkipCapPush<'a> {
    skip: u64,
    remaining: u64,
    push: &'a mut dyn FnMut(&[u8]),
}

impl MessageReadCallback for SkipCapPush<'_> {
    fn message_content(&mut self, chunk: &[u8]) -> bool {
        let mut chunk = chunk;
        if self.skip > 0 {
            let n = (self.skip as usize).min(chunk.len());
            chunk = &chunk[n..];
            self.skip -= n as u64;
        }
        if !chunk.is_empty() && self.remaining > 0 {
            let take = (chunk.len() as u64).min(self.remaining) as usize;
            (self.push)(&chunk[..take]);
            self.remaining -= take as u64;
        }
        self.skip > 0 || self.remaining > 0
    }
}

/// Stream everything from `mb.read_message` after the first `skip_len`
/// bytes straight to `push`, capped at `limit` pushed bytes (`u64::MAX` for
/// unbounded) — used for RFC822.TEXT/BODY[TEXT] (unbounded) and partial
/// `BODY[section]<start.count>` fetches (capped), so the (potentially
/// large) body content is never buffered, only skipped/capped in flight.
fn stream_window(
    mb: &mut dyn Mailbox,
    seq: u32,
    skip_len: u64,
    limit: u64,
    push: &mut dyn FnMut(&[u8]),
) -> MailboxResult<()> {
    let mut cb = SkipCapPush {
        skip: skip_len,
        remaining: limit,
        push,
    };
    mb.read_message(seq, &mut cb)
}

/// Clamp a `<start.count>` partial-fetch range against the actual
/// available length, returning `(effective_start, declared_len)` — RFC
/// 9051 §7.5: a start beyond the end of the content yields an empty
/// string, never an error.
fn clamp_partial(partial: Option<(u64, u64)>, available: u64) -> (u64, u64) {
    match partial {
        None => (0, available),
        Some((start, count)) => {
            let start = start.min(available);
            let len = count.min(available - start);
            (start, len)
        }
    }
}

/// Slice an already-in-memory buffer to a `<start.count>` partial-fetch
/// range (or return it unchanged when `partial` is `None`).
fn slice_partial(data: &[u8], partial: Option<(u64, u64)>) -> Vec<u8> {
    let (start, len) = clamp_partial(partial, data.len() as u64);
    data[start as usize..(start + len) as usize].to_vec()
}

struct JustPush<'a>(&'a mut dyn FnMut(&[u8]));

impl MessageReadCallback for JustPush<'_> {
    fn message_content(&mut self, chunk: &[u8]) -> bool {
        (self.0)(chunk);
        true
    }
}

/// Streaming counterpart to [`format_fetch_attrs`] — same wire shape
/// (`(NAME value NAME value ...)`), but pushes it to `push` piece by piece
/// instead of returning it as one `Vec<u8>`, and never buffers message
/// content beyond what's structurally required:
///
/// - `RFC822` / `BODY[]` (whole message): the exact length is already
///   known from mailbox metadata (`size`), so the literal header and
///   content stream straight from [`Mailbox::read_message`] with zero
///   buffering.
/// - `RFC822.HEADER` / `BODY[HEADER]` / `BODY[HEADER.FIELDS...]`: one read
///   pass captures just the header block, capped (see [`MAX_HEADER_CAP`])
///   — headers are inherently small, this is the one place a real (if
///   generous) internal buffer remains.
/// - `RFC822.TEXT` / `BODY[TEXT]`: the header length from the same scan
///   gives an exact text length (`size - header_len`) without needing the
///   header *content*; the text itself streams via a second read pass that
///   skips those bytes rather than buffering them.
#[allow(clippy::too_many_arguments)]
pub fn push_fetch_attrs(
    mb: &mut dyn Mailbox,
    items: &[FetchItem],
    seq: u32,
    uid: u64,
    size: u64,
    flags: &BTreeSet<Flag>,
    keywords: &BTreeSet<String>,
    by_uid: bool,
    modseq: Option<u64>,
    push: &mut dyn FnMut(&[u8]),
) -> MailboxResult<()> {
    let needs_header_scan = items.iter().any(|it| {
        matches!(
            it,
            FetchItem::Rfc822Header
                | FetchItem::Rfc822Text
                | FetchItem::Envelope
                | FetchItem::Body {
                    section: BodySection::Header,
                    ..
                }
                | FetchItem::Body {
                    section: BodySection::Text,
                    ..
                }
                | FetchItem::Body {
                    section: BodySection::HeaderFields,
                    ..
                }
        )
    });
    let header_scan = if needs_header_scan {
        Some(scan_header(mb, seq)?)
    } else {
        None
    };
    let needs_structure = items
        .iter()
        .any(|it| matches!(it, FetchItem::BodyStructure));
    let structure = if needs_structure {
        Some(build_structure(mb, seq)?)
    } else {
        None
    };

    push(b"(");
    let mut first = true;
    let mut wrote_uid = false;
    let mut wrote_modseq = false;

    for item in items {
        if !first {
            push(b" ");
        }
        first = false;
        match item {
            FetchItem::Flags => {
                push(b"FLAGS ");
                push(format_flags(flags, keywords).as_bytes());
            }
            FetchItem::Uid => {
                push(b"UID ");
                push(uid.to_string().as_bytes());
                wrote_uid = true;
            }
            FetchItem::ModSeq => {
                if let Some(m) = modseq {
                    push(b"MODSEQ ");
                    push(format!("({m})").as_bytes());
                    wrote_modseq = true;
                } else {
                    // Nothing written for this item — undo the separator
                    // we just pushed so we don't leave a dangling space.
                    first = true;
                }
            }
            FetchItem::Rfc822Size => {
                push(b"RFC822.SIZE ");
                push(size.to_string().as_bytes());
            }
            FetchItem::Rfc822 => {
                push(b"RFC822 ");
                push(format!("{{{size}}}\r\n").as_bytes());
                let mut cb = JustPush(push);
                mb.read_message(seq, &mut cb)?;
            }
            FetchItem::Rfc822Header => {
                let (header, _) = header_scan.as_ref().expect("scanned above");
                push(b"RFC822.HEADER ");
                push(format!("{{{}}}\r\n", header.len()).as_bytes());
                push(header);
            }
            FetchItem::Rfc822Text => {
                let (_, header_len) = *header_scan.as_ref().expect("scanned above");
                let text_len = size.saturating_sub(header_len);
                push(b"RFC822.TEXT ");
                push(format!("{{{text_len}}}\r\n").as_bytes());
                stream_window(mb, seq, header_len, u64::MAX, push)?;
            }
            FetchItem::Body {
                peek,
                header_fields,
                section,
                partial,
            } => {
                let name = body_item_name(*peek, section, header_fields.as_deref(), *partial);
                push(name.as_bytes());
                push(b" ");
                match section {
                    BodySection::Full => {
                        let (skip, len) = clamp_partial(*partial, size);
                        push(format!("{{{len}}}\r\n").as_bytes());
                        if len > 0 {
                            stream_window(mb, seq, skip, len, push)?;
                        }
                    }
                    BodySection::Header => {
                        let (header, _) = header_scan.as_ref().expect("scanned above");
                        let sliced = slice_partial(header, *partial);
                        push(format!("{{{}}}\r\n", sliced.len()).as_bytes());
                        push(&sliced);
                    }
                    BodySection::Text => {
                        let (_, header_len) = *header_scan.as_ref().expect("scanned above");
                        let text_len = size.saturating_sub(header_len);
                        let (extra_skip, len) = clamp_partial(*partial, text_len);
                        push(format!("{{{len}}}\r\n").as_bytes());
                        if len > 0 {
                            stream_window(mb, seq, header_len + extra_skip, len, push)?;
                        }
                    }
                    BodySection::HeaderFields => {
                        let (header, _) = header_scan.as_ref().expect("scanned above");
                        let selected = select_header_fields_from_header(
                            header,
                            header_fields.as_deref().unwrap_or(&[]),
                        );
                        let sliced = slice_partial(&selected, *partial);
                        push(format!("{{{}}}\r\n", sliced.len()).as_bytes());
                        push(&sliced);
                    }
                }
            }
            FetchItem::Envelope => {
                let (header, _) = header_scan.as_ref().expect("scanned above");
                let env = parse_envelope(header);
                push(b"ENVELOPE ");
                push(&format_envelope(&env));
            }
            FetchItem::BodyStructure => {
                let (_, node) = structure.as_ref().expect("scanned above");
                push(b"BODYSTRUCTURE ");
                push(&format_bodystructure(node));
            }
            FetchItem::Other(name) => {
                push(name.as_bytes());
                push(b" NIL");
            }
        }
    }

    if by_uid && !wrote_uid {
        if !first {
            push(b" ");
        }
        first = false;
        push(b"UID ");
        push(uid.to_string().as_bytes());
    }
    if let Some(m) = modseq {
        if !wrote_modseq {
            if !first {
                push(b" ");
            }
            push(b"MODSEQ ");
            push(format!("({m})").as_bytes());
        }
    }
    push(b")");
    Ok(())
}

fn body_item_name(
    peek: bool,
    section: &BodySection,
    fields: Option<&[String]>,
    partial: Option<(u64, u64)>,
) -> String {
    let prefix = if peek { "BODY.PEEK" } else { "BODY" };
    let base = match section {
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
    };
    match partial {
        // RFC 9051 §7.5: the FETCH response echoes only the actual start
        // offset, never the requested count.
        Some((start, _)) => format!("{base}<{start}>"),
        None => base,
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

    fn mailbox_with(msg: &[u8]) -> (tempfile::TempDir, Box<dyn Mailbox>) {
        use hopf_mailbox::{AppendGuard, MailboxFactory};
        let dir = tempfile::tempdir().unwrap();
        let factory = hopf_mailbox::MaildirFactory::new(dir.path());
        let mut store = factory.create_store();
        store.open("fetchuser").unwrap();
        let mut mb = store.open_mailbox("INBOX", false).unwrap();
        let mut guard = AppendGuard::start(mb.as_mut(), &BTreeSet::new(), None).unwrap();
        guard.append_content(msg).unwrap();
        guard.commit().unwrap();
        (dir, mb)
    }

    fn push_collect(mb: &mut dyn Mailbox, items: &[FetchItem], size: u64) -> Vec<u8> {
        let flags = BTreeSet::new();
        let keywords = BTreeSet::new();
        let mut out = Vec::new();
        push_fetch_attrs(mb, items, 1, 1, size, &flags, &keywords, false, None, &mut |c| {
            out.extend_from_slice(c);
        })
        .unwrap();
        out
    }

    /// A body long enough that `format_nstring`'s quoted-vs-literal
    /// heuristic always picks literal syntax (its threshold is 1024 bytes)
    /// — so the streaming and whole-buffer paths are byte-for-byte
    /// comparable here, not just semantically equivalent.
    fn large_message() -> Vec<u8> {
        let mut msg = b"From: a@b\r\nTo: c@d\r\nSubject: streaming fetch\r\n\r\n".to_vec();
        for i in 0..100 {
            msg.extend_from_slice(format!("body line {i}\r\n").as_bytes());
        }
        msg
    }

    #[test]
    fn push_fetch_attrs_matches_format_fetch_attrs_for_rfc822_and_body_full() {
        let msg = large_message();
        let (_dir, mut mb) = mailbox_with(&msg);
        let size = msg.len() as u64;
        let items = vec![
            FetchItem::Flags,
            FetchItem::Rfc822,
            FetchItem::Body {
                peek: true,
                header_fields: None,
                section: BodySection::Full,
                partial: None,
            },
        ];
        let streamed = push_collect(mb.as_mut(), &items, size);
        let whole = format_fetch_attrs(
            &items,
            1,
            1,
            size,
            &BTreeSet::new(),
            &BTreeSet::new(),
            Some(&msg),
            false,
            None,
        );
        assert_eq!(streamed, whole);
    }

    #[test]
    fn push_fetch_attrs_matches_format_fetch_attrs_for_header_and_text() {
        let msg = large_message();
        let (_dir, mut mb) = mailbox_with(&msg);
        let size = msg.len() as u64;
        let items = vec![
            FetchItem::Rfc822Header,
            FetchItem::Rfc822Text,
            FetchItem::Body {
                peek: true,
                header_fields: None,
                section: BodySection::Header,
                partial: None,
            },
            FetchItem::Body {
                peek: true,
                header_fields: None,
                section: BodySection::Text,
                partial: None,
            },
        ];
        let streamed = push_collect(mb.as_mut(), &items, size);
        let whole = format_fetch_attrs(
            &items,
            1,
            1,
            size,
            &BTreeSet::new(),
            &BTreeSet::new(),
            Some(&msg),
            false,
            None,
        );
        assert_eq!(streamed, whole);
    }

    #[test]
    fn push_fetch_attrs_matches_format_fetch_attrs_for_header_fields() {
        let msg = large_message();
        let (_dir, mut mb) = mailbox_with(&msg);
        let size = msg.len() as u64;
        let items = vec![FetchItem::Body {
            peek: true,
            header_fields: Some(vec!["Subject".to_string(), "To".to_string()]),
            section: BodySection::HeaderFields,
            partial: None,
        }];
        let streamed = push_collect(mb.as_mut(), &items, size);
        let whole = format_fetch_attrs(
            &items,
            1,
            1,
            size,
            &BTreeSet::new(),
            &BTreeSet::new(),
            Some(&msg),
            false,
            None,
        );
        assert_eq!(streamed, whole);
    }

    #[test]
    fn push_fetch_attrs_declared_literal_length_matches_pushed_byte_count() {
        // Verifies the {n}\r\n length prefix for a content item is exactly
        // right regardless of message size — not just "some length was
        // written", which byte-equality against the reference alone
        // wouldn't catch if both sides were wrong the same way.
        let msg = large_message();
        let (_dir, mut mb) = mailbox_with(&msg);
        let size = msg.len() as u64;
        let out = push_collect(mb.as_mut(), &[FetchItem::Rfc822Text], size);
        let s = String::from_utf8_lossy(&out);
        let start = s.find('{').unwrap();
        let end = s.find('}').unwrap();
        let declared_len: usize = s[start + 1..end].parse().unwrap();
        let literal_start = s.find("\r\n").unwrap() + 2;
        // The literal runs from literal_start to the closing ')' just
        // before the end of the response.
        let content = &out[literal_start..literal_start + declared_len];
        assert_eq!(content, message_text(&msg));
    }

    #[test]
    fn push_fetch_attrs_uses_the_real_streaming_mailbox_read_regardless_of_chunk_size() {
        // The maildir backend already reads in 8KB chunks; use a message
        // that spans several to exercise the header/text split logic
        // across real chunk boundaries, not just in-memory slicing.
        let mut msg = b"From: a@b\r\nSubject: big\r\n\r\n".to_vec();
        for i in 0..2000 {
            msg.extend_from_slice(format!("line {i} of a large body\r\n").as_bytes());
        }
        let (_dir, mut mb) = mailbox_with(&msg);
        let size = msg.len() as u64;
        let items = vec![FetchItem::Rfc822Text];
        let streamed = push_collect(mb.as_mut(), &items, size);
        let whole = format_fetch_attrs(
            &items,
            1,
            1,
            size,
            &BTreeSet::new(),
            &BTreeSet::new(),
            Some(&msg),
            false,
            None,
        );
        assert_eq!(streamed, whole);
    }

    #[test]
    fn parse_envelope_and_bodystructure_items() {
        let items = parse_fetch_items("(ENVELOPE BODYSTRUCTURE)").unwrap();
        assert_eq!(items, vec![FetchItem::Envelope, FetchItem::BodyStructure]);
    }

    #[test]
    fn parse_body_partial_range() {
        let items = parse_fetch_items("BODY[]<0.1024>").unwrap();
        match &items[0] {
            FetchItem::Body {
                section: BodySection::Full,
                partial: Some((0, 1024)),
                ..
            } => {}
            other => panic!("expected BODY[]<0.1024>, got {other:?}"),
        }
    }

    #[test]
    fn parse_body_partial_range_does_not_leak_into_a_bogus_following_item() {
        // Before the lexer fix, the `<0.1024>` suffix was left for the
        // outer loop to mis-tokenize as its own bogus FETCH item.
        let items = parse_fetch_items("(BODY[]<0.1024> FLAGS)").unwrap();
        assert_eq!(items.len(), 2);
        assert!(matches!(items[1], FetchItem::Flags));
    }

    #[test]
    fn parse_body_peek_header_fields_with_partial_range() {
        let items =
            parse_fetch_items("BODY.PEEK[HEADER.FIELDS (Subject)]<10.5>").unwrap();
        match &items[0] {
            FetchItem::Body {
                peek: true,
                section: BodySection::HeaderFields,
                header_fields: Some(f),
                partial: Some((10, 5)),
            } => assert_eq!(f, &["Subject".to_string()]),
            other => panic!("unexpected item: {other:?}"),
        }
    }

    #[test]
    fn parse_body_partial_range_rejects_zero_count() {
        assert!(parse_fetch_items("BODY[]<0.0>").is_err());
    }

    #[test]
    fn push_fetch_attrs_partial_body_matches_format_fetch_attrs() {
        let msg = large_message();
        let (_dir, mut mb) = mailbox_with(&msg);
        let size = msg.len() as u64;
        let items = vec![FetchItem::Body {
            peek: false,
            header_fields: None,
            section: BodySection::Full,
            partial: Some((10, 20)),
        }];
        let streamed = push_collect(mb.as_mut(), &items, size);
        let whole = format_fetch_attrs(
            &items,
            1,
            1,
            size,
            &BTreeSet::new(),
            &BTreeSet::new(),
            Some(&msg),
            false,
            None,
        );
        assert_eq!(streamed, whole);
        let s = String::from_utf8_lossy(&streamed);
        assert!(s.contains("BODY[]<10> {20}\r\n"), "got: {s}");
        assert_eq!(
            &streamed[s.find("{20}\r\n").unwrap() + 6..][..20],
            &msg[10..30]
        );
    }

    #[test]
    fn push_fetch_attrs_partial_body_start_beyond_end_is_empty_not_error() {
        let msg = b"From: a@b\r\n\r\nshort\r\n".to_vec();
        let (_dir, mut mb) = mailbox_with(&msg);
        let size = msg.len() as u64;
        let items = vec![FetchItem::Body {
            peek: true,
            header_fields: None,
            section: BodySection::Full,
            partial: Some((size + 1000, 10)),
        }];
        let streamed = push_collect(mb.as_mut(), &items, size);
        let s = String::from_utf8_lossy(&streamed);
        assert!(s.contains("{0}\r\n"), "got: {s}");
    }

    #[test]
    fn push_fetch_attrs_partial_text_matches_format_fetch_attrs() {
        let msg = large_message();
        let (_dir, mut mb) = mailbox_with(&msg);
        let size = msg.len() as u64;
        let items = vec![FetchItem::Body {
            peek: true,
            header_fields: None,
            section: BodySection::Text,
            partial: Some((5, 15)),
        }];
        let streamed = push_collect(mb.as_mut(), &items, size);
        let whole = format_fetch_attrs(
            &items,
            1,
            1,
            size,
            &BTreeSet::new(),
            &BTreeSet::new(),
            Some(&msg),
            false,
            None,
        );
        assert_eq!(streamed, whole);
    }

    #[test]
    fn push_fetch_attrs_envelope_matches_format_fetch_attrs() {
        let msg = b"From: Alice <alice@example.com>\r\nTo: Bob <bob@example.com>\r\nSubject: Hi\r\n\r\nbody\r\n".to_vec();
        let (_dir, mut mb) = mailbox_with(&msg);
        let size = msg.len() as u64;
        let items = vec![FetchItem::Envelope];
        let streamed = push_collect(mb.as_mut(), &items, size);
        let whole = format_fetch_attrs(
            &items,
            1,
            1,
            size,
            &BTreeSet::new(),
            &BTreeSet::new(),
            Some(&msg),
            false,
            None,
        );
        assert_eq!(streamed, whole);
        let s = String::from_utf8_lossy(&streamed);
        assert!(s.contains("ENVELOPE ("), "got: {s}");
        assert!(s.contains("\"Hi\""), "got: {s}");
    }

    #[test]
    fn push_fetch_attrs_bodystructure_matches_format_fetch_attrs() {
        let msg = b"Content-Type: multipart/mixed; boundary=X\r\n\r\n\
--X\r\nContent-Type: text/plain\r\n\r\nplain body\r\n--X\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=a.pdf\r\n\r\nPDFDATA\r\n--X--\r\n"
            .to_vec();
        let (_dir, mut mb) = mailbox_with(&msg);
        let size = msg.len() as u64;
        let items = vec![FetchItem::BodyStructure];
        let streamed = push_collect(mb.as_mut(), &items, size);
        let whole = format_fetch_attrs(
            &items,
            1,
            1,
            size,
            &BTreeSet::new(),
            &BTreeSet::new(),
            Some(&msg),
            false,
            None,
        );
        assert_eq!(streamed, whole);
        let s = String::from_utf8_lossy(&streamed);
        assert!(s.contains("BODYSTRUCTURE (("), "got: {s}");
        assert!(s.contains("\"MIXED\""), "got: {s}");
        assert!(s.contains("\"attachment\""), "got: {s}");
        assert!(s.contains("\"a.pdf\""), "got: {s}");
    }

    #[test]
    fn push_fetch_attrs_envelope_and_bodystructure_together_match_whole_buffer() {
        // Both items in the same FETCH — exercises the header_scan +
        // structure-walk paths running side by side without interfering.
        let msg = large_message();
        let (_dir, mut mb) = mailbox_with(&msg);
        let size = msg.len() as u64;
        let items = vec![FetchItem::Envelope, FetchItem::BodyStructure, FetchItem::Flags];
        let streamed = push_collect(mb.as_mut(), &items, size);
        let whole = format_fetch_attrs(
            &items,
            1,
            1,
            size,
            &BTreeSet::new(),
            &BTreeSet::new(),
            Some(&msg),
            false,
            None,
        );
        assert_eq!(streamed, whole);
    }
}
