// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! IMAP `ENVELOPE` (RFC 9051 §7.5.2) — parsed from a message's RFC 5322
//! headers via `rmimeparser`.

use rmimeparser::{
    ContentId, MessageHandler, MessageIdListCollector, MessageParser, MimeHandler, OffsetDateTime,
    ParseResult,
};

use crate::server::fetch_format::format_nstring;

/// One address in an ENVELOPE address list — `(name adl mailbox host)`.
///
/// `adl` (source route) is always emitted `NIL`: RFC 5321/5322 source
/// routes are obsolete and [`EmailAddress`] has no field for one.
#[derive(Clone, Debug, Default)]
pub struct EnvelopeAddress {
    pub name: Option<String>,
    pub mailbox: String,
    pub host: String,
}

/// Parsed RFC 9051 §7.5.2 ENVELOPE fields.
#[derive(Clone, Debug, Default)]
pub struct Envelope {
    pub date: Option<String>,
    pub subject: Option<String>,
    pub from: Vec<EnvelopeAddress>,
    pub sender: Vec<EnvelopeAddress>,
    pub reply_to: Vec<EnvelopeAddress>,
    pub to: Vec<EnvelopeAddress>,
    pub cc: Vec<EnvelopeAddress>,
    pub bcc: Vec<EnvelopeAddress>,
    pub in_reply_to: Option<String>,
    pub message_id: Option<String>,
}

/// Shared by [`EnvelopeCollector`] and `bodystructure::StructureBuilder`
/// (which also collects the top-level message's envelope while it walks
/// the MIME structure) so both apply RFC 5322 address headers identically.
fn apply_address_header(env: &mut Envelope, name: &str, list: Vec<EnvelopeAddress>) {
    match name.to_ascii_lowercase().as_str() {
        "from" => env.from = list,
        "sender" => env.sender = list,
        "reply-to" => env.reply_to = list,
        "to" => env.to = list,
        "cc" => env.cc = list,
        "bcc" => env.bcc = list,
        _ => {}
    }
}

/// Shared by [`EnvelopeCollector`] and `bodystructure::StructureBuilder` —
/// see [`apply_address_header`].
fn apply_message_id_header(env: &mut Envelope, name: &str, ids: &[ContentId]) {
    let joined = ids
        .iter()
        .map(|id| id.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    match name.to_ascii_lowercase().as_str() {
        "message-id" => env.message_id = Some(joined),
        "in-reply-to" => env.in_reply_to = Some(joined),
        _ => {}
    }
}

/// Builds an [`Envelope`] from the parser's header events, which arrive a
/// piece at a time: the subject and each address list are held only until
/// their header ends. The handler methods of the same names forward here.
#[derive(Default)]
pub(crate) struct EnvelopeBuilder {
    pub(crate) env: Envelope,
    in_subject: bool,
    subject: String,
    address_header: String,
    addresses: Vec<EnvelopeAddress>,
    id_header: String,
    ids: MessageIdListCollector,
}

impl EnvelopeBuilder {
    pub(crate) fn start_header(&mut self, name: &str) {
        self.in_subject = name.eq_ignore_ascii_case("Subject");
        self.subject.clear();
    }

    pub(crate) fn header_content(&mut self, text: &str) {
        if self.in_subject {
            self.subject.push_str(text);
        }
    }

    pub(crate) fn end_header(&mut self) {
        if self.in_subject {
            self.in_subject = false;
            self.env.subject = Some(std::mem::take(&mut self.subject));
        }
    }

    pub(crate) fn date_header(&mut self, name: &str, date: OffsetDateTime) {
        if name.eq_ignore_ascii_case("Date") {
            self.env.date = Some(date.to_string());
        }
    }

    pub(crate) fn start_address_header(&mut self, name: &str) {
        self.address_header.clear();
        self.address_header.push_str(name);
        self.addresses.clear();
    }

    /// A mailbox of the address header, of a group's members too: an
    /// ENVELOPE has no groups.
    pub(crate) fn mailbox(&mut self, display_name: Option<&str>, local_part: &str, domain: &str) {
        self.addresses.push(EnvelopeAddress {
            name: display_name.map(str::to_string),
            mailbox: local_part.to_string(),
            host: domain.to_string(),
        });
    }

    pub(crate) fn end_address_header(&mut self) {
        let list = std::mem::take(&mut self.addresses);
        apply_address_header(&mut self.env, &self.address_header, list);
    }

    pub(crate) fn start_message_id_header(&mut self, name: &str) {
        self.id_header.clear();
        self.id_header.push_str(name);
        self.ids.clear();
    }

    pub(crate) fn message_id(&mut self, local_part: &str, domain: &str) {
        self.ids.message_id(local_part, domain);
    }

    pub(crate) fn end_message_id_header(&mut self) {
        let ids = self.ids.take();
        apply_message_id_header(&mut self.env, &self.id_header, &ids);
    }
}

#[derive(Default)]
struct EnvelopeCollector {
    builder: EnvelopeBuilder,
}

impl MimeHandler for EnvelopeCollector {
    fn start_header(&mut self, name: &str) -> ParseResult<()> {
        self.builder.start_header(name);
        Ok(())
    }

    fn header_content(&mut self, text: &str) -> ParseResult<()> {
        self.builder.header_content(text);
        Ok(())
    }

    fn end_header(&mut self) -> ParseResult<()> {
        self.builder.end_header();
        Ok(())
    }
}

impl MessageHandler for EnvelopeCollector {
    fn date_header(&mut self, name: &str, date: OffsetDateTime) -> ParseResult<()> {
        self.builder.date_header(name, date);
        Ok(())
    }

    fn start_address_header(&mut self, name: &str) -> ParseResult<()> {
        self.builder.start_address_header(name);
        Ok(())
    }

    fn mailbox(
        &mut self,
        display_name: Option<&str>,
        local_part: &str,
        domain: &str,
    ) -> ParseResult<()> {
        self.builder.mailbox(display_name, local_part, domain);
        Ok(())
    }

    fn end_address_header(&mut self) -> ParseResult<()> {
        self.builder.end_address_header();
        Ok(())
    }

    fn start_message_id_header(&mut self, name: &str) -> ParseResult<()> {
        self.builder.start_message_id_header(name);
        Ok(())
    }

    fn message_id(&mut self, local_part: &str, domain: &str) -> ParseResult<()> {
        self.builder.message_id(local_part, domain);
        Ok(())
    }

    fn end_message_id_header(&mut self) -> ParseResult<()> {
        self.builder.end_message_id_header();
        Ok(())
    }
}

/// Parse ENVELOPE fields from a message's header block (e.g.
/// [`crate::server::fetch_format::message_header`], or an equivalent
/// bounded header scan) — never the whole message, so this is cheap
/// regardless of message size.
///
/// `header` is expected to end at (and include) the header/body blank
/// line, matching what a header-only scan naturally produces. Parsing may
/// report an error at the end if the header claims a multipart
/// `Content-Type` (since no body/boundary lines follow) — that error is
/// intentionally ignored: every header field is dispatched to this
/// collector as it completes, well before the end, so the ignored error
/// never loses data.
pub fn parse_envelope(header: &[u8]) -> Envelope {
    let mut collector = EnvelopeCollector::default();
    let mut parser = MessageParser::new(&mut collector);
    let _ = parser.parse(header);
    collector.builder.env
}

fn push_nstring_opt(out: &mut Vec<u8>, s: Option<&str>) {
    match s {
        Some(s) => out.extend_from_slice(&format_nstring(s.as_bytes())),
        None => out.extend_from_slice(b"NIL"),
    }
}

fn push_address_list(out: &mut Vec<u8>, addrs: &[EnvelopeAddress]) {
    if addrs.is_empty() {
        out.extend_from_slice(b"NIL");
        return;
    }
    out.push(b'(');
    for (i, a) in addrs.iter().enumerate() {
        if i > 0 {
            out.push(b' ');
        }
        out.push(b'(');
        push_nstring_opt(out, a.name.as_deref());
        out.push(b' ');
        out.extend_from_slice(b"NIL"); // adl (source route) — always NIL.
        out.push(b' ');
        let mailbox = (!a.mailbox.is_empty()).then_some(a.mailbox.as_str());
        push_nstring_opt(out, mailbox);
        out.push(b' ');
        let host = (!a.host.is_empty()).then_some(a.host.as_str());
        push_nstring_opt(out, host);
        out.push(b')');
    }
    out.push(b')');
}

/// Format per RFC 9051 §7.5.2 (no trailing CRLF — caller supplies one).
pub fn format_envelope(env: &Envelope) -> Vec<u8> {
    let mut out = Vec::from(b"(".as_slice());
    push_nstring_opt(&mut out, env.date.as_deref());
    out.push(b' ');
    push_nstring_opt(&mut out, env.subject.as_deref());
    out.push(b' ');
    push_address_list(&mut out, &env.from);
    out.push(b' ');
    // RFC 9051 §7.5.2: sender/reply-to default to from when the message
    // has no Sender/Reply-To header of its own.
    if env.sender.is_empty() {
        push_address_list(&mut out, &env.from);
    } else {
        push_address_list(&mut out, &env.sender);
    }
    out.push(b' ');
    if env.reply_to.is_empty() {
        push_address_list(&mut out, &env.from);
    } else {
        push_address_list(&mut out, &env.reply_to);
    }
    out.push(b' ');
    push_address_list(&mut out, &env.to);
    out.push(b' ');
    push_address_list(&mut out, &env.cc);
    out.push(b' ');
    push_address_list(&mut out, &env.bcc);
    out.push(b' ');
    push_nstring_opt(&mut out, env.in_reply_to.as_deref());
    out.push(b' ');
    push_nstring_opt(&mut out, env.message_id.as_deref());
    out.push(b')');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_fields() {
        let header = b"From: Alice <alice@example.com>\r\n\
To: Bob <bob@example.com>\r\n\
Subject: Hello\r\n\
Date: Mon, 1 Jan 2024 12:00:00 +0000\r\n\
Message-ID: <abc@example.com>\r\n\
\r\n";
        let env = parse_envelope(header);
        assert_eq!(env.subject.as_deref(), Some("Hello"));
        assert_eq!(env.from[0].mailbox, "alice");
        assert_eq!(env.from[0].host, "example.com");
        assert_eq!(env.from[0].name.as_deref(), Some("Alice"));
        assert_eq!(env.to[0].mailbox, "bob");
        assert_eq!(env.message_id.as_deref(), Some("<abc@example.com>"));
        assert!(env.date.is_some());
    }

    #[test]
    fn sender_and_reply_to_default_to_from() {
        let header = b"From: Alice <alice@example.com>\r\nTo: Bob <bob@example.com>\r\n\r\n";
        let env = parse_envelope(header);
        let formatted = format_envelope(&env);
        let s = String::from_utf8_lossy(&formatted);
        // Sender and Reply-To fields (2nd and 3rd address lists) should
        // both echo the From address rather than being NIL.
        let from_addr = "(\"Alice\" NIL \"alice\" \"example.com\")";
        assert_eq!(s.matches(from_addr).count(), 3, "envelope: {s}");
    }

    #[test]
    fn missing_headers_format_as_nil() {
        let env = parse_envelope(b"\r\n");
        let formatted = format_envelope(&env);
        assert_eq!(
            formatted,
            b"(NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)".to_vec()
        );
    }
}
