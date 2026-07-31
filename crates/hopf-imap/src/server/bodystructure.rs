// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! IMAP `BODYSTRUCTURE` (RFC 9051 §7.5.2) — built by streaming a message
//! through `rmimeparser`'s push-based MIME/RFC 5322 parser.
//!
//! Two known, deliberate scope limits (both documented in
//! `docs/conformance.html`):
//!
//! - `rmimeparser`'s public `MimeHandler::body_content` delivers *decoded*
//!   bytes for `base64`/`quoted-printable` entities (its raw-wire capture
//!   hook exists only for its own internal DKIM use, `pub(crate)`). Body
//!   `size`/`lines` are computed from what it delivers, so for
//!   base64/quoted-printable parts they reflect the decoded octet count,
//!   not the RFC-mandated wire-encoded count. `7bit`/`8bit`/`binary` parts
//!   (identity encoding — the common case, and the only encodings valid
//!   for `message/rfc822` bodies) are unaffected: decoded and wire bytes
//!   are the same.
//! - Content-Language/Content-Location aren't part of `rmimeparser`'s
//!   `MimeHandler` trait, so the corresponding BODYSTRUCTURE extension
//!   fields are always `NIL`. Content-Disposition parameters other than
//!   `filename` are also always omitted: `ContentDisposition` only exposes
//!   named lookup (`get_parameter`), not enumeration, in the installed
//!   `rmimeparser` version.

use hopf_mailbox::{Mailbox, MailboxResult, MessageReadCallback};
use rmimeparser::{
    ContentDisposition, ContentId, ContentType, EmailAddress, MessageHandler, MessageParser,
    MimeHandler, OffsetDateTime, ParseResult,
};

use crate::server::envelope::{apply_address_header, apply_message_id_header, Envelope};
use crate::server::fetch_format::format_nstring;

/// A message/rfc822 part's encapsulated message is parsed recursively, but
/// only up to this many bytes of its own (undecoded-identity) content —
/// generous for realistic forwarded messages, and bounded rather than
/// buffering an unlimited nested message. Mirrors the same
/// bounded-buffer-with-documented-cap precedent as
/// `fetch_format::MAX_HEADER_CAP`.
const MAX_NESTED_MESSAGE_CAP: usize = 8 << 20;

/// One MIME body part in a BODYSTRUCTURE tree.
#[derive(Clone, Debug)]
pub enum BodyStructureNode {
    /// A non-multipart leaf (`text/plain`, `application/pdf`,
    /// `message/rfc822`, ...).
    Leaf {
        primary_type: String,
        sub_type: String,
        params: Vec<(String, String)>,
        content_id: Option<String>,
        description: Option<String>,
        encoding: String,
        size: u64,
        /// Line count — only meaningful (`Some`) for `text/*` and
        /// `message/rfc822`; `None` for everything else.
        lines: Option<u64>,
        disposition: Option<(String, Vec<(String, String)>)>,
        /// Only for `message/rfc822`: the encapsulated message's own
        /// envelope and body structure.
        nested: Option<(Envelope, Box<BodyStructureNode>)>,
    },
    /// A `multipart/*` entity.
    Multipart {
        sub_type: String,
        children: Vec<BodyStructureNode>,
        params: Vec<(String, String)>,
        disposition: Option<(String, Vec<(String, String)>)>,
    },
}

fn empty_leaf() -> BodyStructureNode {
    BodyStructureNode::Leaf {
        primary_type: "text".to_string(),
        sub_type: "plain".to_string(),
        params: Vec::new(),
        content_id: None,
        description: None,
        encoding: "7BIT".to_string(),
        size: 0,
        lines: Some(0),
        disposition: None,
        nested: None,
    }
}

/// Only `filename` is exposed: `ContentDisposition` (installed
/// `rmimeparser` version) only supports named parameter lookup, not
/// enumeration — see module docs.
fn disposition_params(cd: &ContentDisposition) -> Vec<(String, String)> {
    match cd.get_parameter("filename") {
        Some(name) => vec![("filename".to_string(), name.to_string())],
        None => Vec::new(),
    }
}

struct PartInProgress {
    primary_type: String,
    sub_type: String,
    params: Vec<(String, String)>,
    content_id: Option<String>,
    description: Option<String>,
    encoding: String,
    disposition: Option<(String, Vec<(String, String)>)>,
    size: u64,
    lines: u64,
    is_multipart: bool,
    children: Vec<BodyStructureNode>,
    nested_buf: Option<Vec<u8>>,
    nested_capped: bool,
}

impl PartInProgress {
    fn new() -> Self {
        // RFC 2045 §5.2 default when Content-Type is absent.
        Self {
            primary_type: "text".to_string(),
            sub_type: "plain".to_string(),
            params: Vec::new(),
            content_id: None,
            description: None,
            encoding: "7BIT".to_string(),
            disposition: None,
            size: 0,
            lines: 0,
            is_multipart: false,
            children: Vec::new(),
            nested_buf: None,
            nested_capped: false,
        }
    }

    fn is_rfc822(&self) -> bool {
        self.primary_type.eq_ignore_ascii_case("message")
            && self.sub_type.eq_ignore_ascii_case("rfc822")
    }

    fn finish(self) -> BodyStructureNode {
        if self.is_multipart {
            return BodyStructureNode::Multipart {
                sub_type: self.sub_type,
                children: self.children,
                params: self.params,
                disposition: self.disposition,
            };
        }
        let is_text = self.primary_type.eq_ignore_ascii_case("text");
        let is_rfc822 = self.is_rfc822();
        let nested = if is_rfc822 {
            self.nested_buf
                .as_deref()
                .map(build_structure_from_slice)
                .map(|(env, node)| (env, Box::new(node)))
        } else {
            None
        };
        let lines = if is_text || is_rfc822 {
            Some(self.lines)
        } else {
            None
        };
        BodyStructureNode::Leaf {
            primary_type: self.primary_type,
            sub_type: self.sub_type,
            params: self.params,
            content_id: self.content_id,
            description: self.description,
            encoding: self.encoding,
            size: self.size,
            lines,
            disposition: self.disposition,
            nested,
        }
    }
}

/// Walks a whole message (top-level RFC 5322 headers, then MIME entities —
/// possibly nested `multipart/*`) building both its [`Envelope`] and its
/// [`BodyStructureNode`] tree in one streaming pass.
///
/// Reused, recursively, to parse a buffered `message/rfc822` part's own
/// encapsulated message (a fresh `StructureBuilder` with its own empty
/// stack) — RFC 5322 header events are only applied to `envelope` while
/// `stack.len() == 1` (the outermost entity currently being parsed), so a
/// stray header-like line inside a nested MIME part's own headers can
/// never overwrite the real envelope.
struct StructureBuilder {
    stack: Vec<PartInProgress>,
    root: Option<BodyStructureNode>,
    envelope: Envelope,
}

impl StructureBuilder {
    fn new() -> Self {
        Self {
            stack: Vec::new(),
            root: None,
            envelope: Envelope::default(),
        }
    }
}

impl MimeHandler for StructureBuilder {
    fn start_entity(&mut self, _boundary: Option<&str>) -> ParseResult<()> {
        self.stack.push(PartInProgress::new());
        Ok(())
    }

    fn content_type(&mut self, ct: &ContentType) -> ParseResult<()> {
        if let Some(top) = self.stack.last_mut() {
            top.primary_type = ct.primary_type().to_string();
            top.sub_type = ct.sub_type().to_string();
            top.is_multipart = ct.is_primary_type("multipart");
            top.params = ct
                .parameters()
                .unwrap_or(&[])
                .iter()
                .map(|p| (p.name().to_string(), p.value().to_string()))
                .collect();
        }
        Ok(())
    }

    fn content_disposition(&mut self, cd: &ContentDisposition) -> ParseResult<()> {
        if let Some(top) = self.stack.last_mut() {
            top.disposition = Some((cd.disposition_type().to_string(), disposition_params(cd)));
        }
        Ok(())
    }

    fn content_transfer_encoding(&mut self, encoding: &str) -> ParseResult<()> {
        if let Some(top) = self.stack.last_mut() {
            top.encoding = encoding.to_ascii_uppercase();
        }
        Ok(())
    }

    fn content_id(&mut self, id: &ContentId) -> ParseResult<()> {
        if let Some(top) = self.stack.last_mut() {
            top.content_id = Some(id.to_string());
        }
        Ok(())
    }

    fn content_description(&mut self, description: &str) -> ParseResult<()> {
        if let Some(top) = self.stack.last_mut() {
            top.description = Some(description.to_string());
        }
        Ok(())
    }

    fn body_content(&mut self, data: &[u8]) -> ParseResult<()> {
        if let Some(top) = self.stack.last_mut() {
            top.size += data.len() as u64;
            top.lines += data.iter().filter(|&&b| b == b'\n').count() as u64;
            if top.is_rfc822() && !top.nested_capped {
                let buf = top.nested_buf.get_or_insert_with(Vec::new);
                let room = MAX_NESTED_MESSAGE_CAP.saturating_sub(buf.len());
                let take = data.len().min(room);
                buf.extend_from_slice(&data[..take]);
                if take < data.len() {
                    top.nested_capped = true;
                }
            }
        }
        Ok(())
    }

    fn end_entity(&mut self, _boundary: Option<&str>) -> ParseResult<()> {
        if let Some(part) = self.stack.pop() {
            let node = part.finish();
            if let Some(parent) = self.stack.last_mut() {
                parent.children.push(node);
            } else {
                self.root = Some(node);
            }
        }
        Ok(())
    }
}

impl MessageHandler for StructureBuilder {
    fn header(&mut self, name: &str, value: &str) -> ParseResult<()> {
        if self.stack.len() == 1 && name.eq_ignore_ascii_case("Subject") {
            self.envelope.subject = Some(value.to_string());
        }
        Ok(())
    }

    fn date_header(&mut self, name: &str, date: OffsetDateTime) -> ParseResult<()> {
        if self.stack.len() == 1 && name.eq_ignore_ascii_case("Date") {
            self.envelope.date = Some(date.to_string());
        }
        Ok(())
    }

    fn address_header(&mut self, name: &str, addrs: &[EmailAddress]) -> ParseResult<()> {
        if self.stack.len() == 1 {
            apply_address_header(&mut self.envelope, name, addrs);
        }
        Ok(())
    }

    fn message_id_header(&mut self, name: &str, ids: &[ContentId]) -> ParseResult<()> {
        if self.stack.len() == 1 {
            apply_message_id_header(&mut self.envelope, name, ids);
        }
        Ok(())
    }
}

/// Parse a complete, already-in-memory message (used for a buffered
/// `message/rfc822` nested part, and as the whole-buffer reference path in
/// tests).
fn build_structure_from_slice(msg: &[u8]) -> (Envelope, BodyStructureNode) {
    let mut builder = StructureBuilder::new();
    {
        let mut parser = MessageParser::new(&mut builder);
        let mut data = msg;
        let _ = parser.receive(&mut data);
        let _ = parser.close();
    }
    let node = builder.root.take().unwrap_or_else(empty_leaf);
    (builder.envelope, node)
}

struct FeedParser<'a> {
    parser: MessageParser<'a, StructureBuilder>,
}

impl MessageReadCallback for FeedParser<'_> {
    fn message_content(&mut self, chunk: &[u8]) -> bool {
        let mut data = chunk;
        let _ = self.parser.receive(&mut data);
        true
    }
}

/// Stream a mailbox message through a [`StructureBuilder`], returning its
/// envelope and body-structure tree without ever buffering the whole
/// message.
pub fn build_structure(mb: &mut dyn Mailbox, seq: u32) -> MailboxResult<(Envelope, BodyStructureNode)> {
    let mut builder = StructureBuilder::new();
    {
        let parser = MessageParser::new(&mut builder);
        let mut cb = FeedParser { parser };
        mb.read_message(seq, &mut cb)?;
        let _ = cb.parser.close();
    }
    let node = builder.root.take().unwrap_or_else(empty_leaf);
    Ok((builder.envelope, node))
}

/// Parse a complete in-memory message — used by the `format_fetch_attrs`
/// whole-buffer reference path in tests.
pub fn build_structure_for_whole_message(msg: &[u8]) -> BodyStructureNode {
    build_structure_from_slice(msg).1
}

fn push_nstring_opt(out: &mut Vec<u8>, s: Option<&str>) {
    match s {
        Some(s) => out.extend_from_slice(&format_nstring(s.as_bytes())),
        None => out.extend_from_slice(b"NIL"),
    }
}

fn write_params(out: &mut Vec<u8>, params: &[(String, String)]) {
    if params.is_empty() {
        out.extend_from_slice(b"NIL");
        return;
    }
    out.push(b'(');
    for (i, (k, v)) in params.iter().enumerate() {
        if i > 0 {
            out.push(b' ');
        }
        out.extend_from_slice(&format_nstring(k.to_ascii_uppercase().as_bytes()));
        out.push(b' ');
        out.extend_from_slice(&format_nstring(v.as_bytes()));
    }
    out.push(b')');
}

fn write_disposition(out: &mut Vec<u8>, disp: Option<&(String, Vec<(String, String)>)>) {
    match disp {
        None => out.extend_from_slice(b"NIL"),
        Some((ty, params)) => {
            out.push(b'(');
            out.extend_from_slice(&format_nstring(ty.as_bytes()));
            out.push(b' ');
            write_params(out, params);
            out.push(b')');
        }
    }
}

fn write_node(out: &mut Vec<u8>, node: &BodyStructureNode) {
    out.push(b'(');
    match node {
        BodyStructureNode::Multipart {
            sub_type,
            children,
            params,
            disposition,
        } => {
            for child in children {
                write_node(out, child);
            }
            out.push(b' ');
            out.extend_from_slice(&format_nstring(sub_type.to_ascii_uppercase().as_bytes()));
            out.push(b' ');
            write_params(out, params);
            out.push(b' ');
            write_disposition(out, disposition.as_ref());
            out.push(b' ');
            out.extend_from_slice(b"NIL"); // language — not tracked, see module docs.
            out.push(b' ');
            out.extend_from_slice(b"NIL"); // location — not tracked.
        }
        BodyStructureNode::Leaf {
            primary_type,
            sub_type,
            params,
            content_id,
            description,
            encoding,
            size,
            lines,
            disposition,
            nested,
        } => {
            out.extend_from_slice(&format_nstring(primary_type.to_ascii_uppercase().as_bytes()));
            out.push(b' ');
            out.extend_from_slice(&format_nstring(sub_type.to_ascii_uppercase().as_bytes()));
            out.push(b' ');
            write_params(out, params);
            out.push(b' ');
            push_nstring_opt(out, content_id.as_deref());
            out.push(b' ');
            push_nstring_opt(out, description.as_deref());
            out.push(b' ');
            out.extend_from_slice(&format_nstring(encoding.as_bytes()));
            out.push(b' ');
            out.extend_from_slice(size.to_string().as_bytes());
            if let Some((env, sub)) = nested {
                out.push(b' ');
                out.extend_from_slice(&crate::server::envelope::format_envelope(env));
                out.push(b' ');
                write_node(out, sub);
                out.push(b' ');
                out.extend_from_slice(lines.unwrap_or(0).to_string().as_bytes());
            } else if let Some(l) = lines {
                out.push(b' ');
                out.extend_from_slice(l.to_string().as_bytes());
            }
            out.push(b' ');
            out.extend_from_slice(b"NIL"); // body MD5 — not computed.
            out.push(b' ');
            write_disposition(out, disposition.as_ref());
            out.push(b' ');
            out.extend_from_slice(b"NIL"); // language — not tracked.
            out.push(b' ');
            out.extend_from_slice(b"NIL"); // location — not tracked.
        }
    }
    out.push(b')');
}

/// Format per RFC 9051 §7.5.2 (no trailing CRLF — caller supplies one).
pub fn format_bodystructure(node: &BodyStructureNode) -> Vec<u8> {
    let mut out = Vec::new();
    write_node(&mut out, node);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_text_leaf() {
        let msg = b"Content-Type: text/plain; charset=us-ascii\r\n\r\nhello\r\nworld\r\n";
        let node = build_structure_for_whole_message(msg);
        match &node {
            BodyStructureNode::Leaf {
                primary_type,
                sub_type,
                size,
                lines,
                ..
            } => {
                assert_eq!(primary_type, "text");
                assert_eq!(sub_type, "plain");
                assert_eq!(*size, 14); // "hello\r\nworld\r\n"
                assert_eq!(*lines, Some(2));
            }
            _ => panic!("expected leaf"),
        }
        let formatted = format_bodystructure(&node);
        let s = String::from_utf8_lossy(&formatted);
        assert!(s.starts_with("(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"us-ascii\") NIL NIL \"7BIT\" 14 2 NIL NIL NIL NIL)"), "got: {s}");
    }

    #[test]
    fn default_content_type_is_text_plain() {
        let msg = b"Subject: no content-type\r\n\r\nbody\r\n";
        let node = build_structure_for_whole_message(msg);
        match &node {
            BodyStructureNode::Leaf {
                primary_type,
                sub_type,
                ..
            } => {
                assert_eq!(primary_type, "text");
                assert_eq!(sub_type, "plain");
            }
            _ => panic!("expected leaf"),
        }
    }

    #[test]
    fn multipart_alternative_two_children() {
        let msg = b"Content-Type: multipart/alternative; boundary=X\r\n\r\n\
--X\r\nContent-Type: text/plain\r\n\r\nplain body\r\n--X\r\nContent-Type: text/html\r\n\r\n<p>html</p>\r\n--X--\r\n";
        let node = build_structure_for_whole_message(msg);
        match &node {
            BodyStructureNode::Multipart {
                sub_type, children, ..
            } => {
                assert_eq!(sub_type, "alternative");
                assert_eq!(children.len(), 2);
                match &children[0] {
                    BodyStructureNode::Leaf { sub_type, .. } => assert_eq!(sub_type, "plain"),
                    _ => panic!("expected leaf"),
                }
                match &children[1] {
                    BodyStructureNode::Leaf { sub_type, .. } => assert_eq!(sub_type, "html"),
                    _ => panic!("expected leaf"),
                }
            }
            _ => panic!("expected multipart"),
        }
        let formatted = format_bodystructure(&node);
        let s = String::from_utf8_lossy(&formatted);
        assert!(s.starts_with("((\"TEXT\" \"PLAIN\""), "got: {s}");
        assert!(s.contains(")(\"TEXT\" \"HTML\""), "got: {s}");
        // The multipart's own Content-Type carried `boundary=X`, so its
        // parameter list is non-NIL (unlike disposition/language/location).
        assert!(
            s.ends_with(" \"ALTERNATIVE\" (\"BOUNDARY\" \"X\") NIL NIL NIL)"),
            "got: {s}"
        );
    }

    #[test]
    fn content_disposition_attachment_with_filename() {
        let msg = b"Content-Type: application/pdf\r\nContent-Disposition: attachment; filename=report.pdf\r\n\r\nPDFDATA\r\n";
        let node = build_structure_for_whole_message(msg);
        match &node {
            BodyStructureNode::Leaf { disposition, .. } => {
                let (ty, params) = disposition.as_ref().expect("disposition present");
                assert_eq!(ty, "attachment");
                assert_eq!(params, &[("filename".to_string(), "report.pdf".to_string())]);
            }
            _ => panic!("expected leaf"),
        }
    }

    #[test]
    fn nested_message_rfc822_has_its_own_envelope_and_structure() {
        let inner = b"From: inner@example.com\r\nSubject: inner subject\r\n\r\ninner body\r\n";
        let mut msg = b"Content-Type: message/rfc822\r\n\r\n".to_vec();
        msg.extend_from_slice(inner);
        let node = build_structure_for_whole_message(&msg);
        match &node {
            BodyStructureNode::Leaf {
                primary_type,
                sub_type,
                nested,
                lines,
                ..
            } => {
                assert_eq!(primary_type, "message");
                assert_eq!(sub_type, "rfc822");
                let (env, inner_node) = nested.as_ref().expect("nested message");
                assert_eq!(env.subject.as_deref(), Some("inner subject"));
                assert_eq!(env.from[0].mailbox, "inner");
                match inner_node.as_ref() {
                    BodyStructureNode::Leaf { sub_type, .. } => assert_eq!(sub_type, "plain"),
                    _ => panic!("expected leaf"),
                }
                assert!(lines.is_some());
            }
            _ => panic!("expected leaf"),
        }
    }

    #[test]
    fn outer_envelope_unaffected_by_stray_header_like_lines_in_nested_parts() {
        // A malformed/adversarial nested part header block that happens to
        // include a "Subject:" line must never overwrite the real,
        // outermost envelope subject.
        let msg = b"Subject: real subject\r\nContent-Type: multipart/mixed; boundary=X\r\n\r\n\
--X\r\nContent-Type: text/plain\r\nSubject: fake nested subject\r\n\r\nbody\r\n--X--\r\n";
        let (env, _) = build_structure_from_slice(msg);
        assert_eq!(env.subject.as_deref(), Some("real subject"));
    }
}
