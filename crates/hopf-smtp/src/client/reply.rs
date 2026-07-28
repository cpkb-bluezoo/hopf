// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Incremental, semantic SMTP client reply parser.
//!
//! [`SmtpReplyLexer`] never buffers a whole reply line and re-parses it.
//! The 3-digit code is accumulated one digit at a time; once known, the
//! text that follows is either scanned-and-discarded (decorative — most
//! success replies, where the driver call it feeds takes no message text
//! today) or kept in a bounded scratch buffer (diagnostics on rejection,
//! and the handful of replies whose text carries real structure: EHLO's
//! per-line capabilities, AUTH's base64 challenge, the queue-id embedded
//! in a post-DATA 250). [`SmtpEvent`] is emitted once each reply
//! completes, already parsed — never a raw code+text pair for the caller
//! to re-interpret.
//!
//! The caller tells the lexer what shape of reply to expect via
//! [`SmtpReplyLexer::expect`], right after sending the corresponding
//! command — SMTP's *codes* mean the same thing everywhere (2xx/3xx
//! success, 4xx/5xx failure), but what the client does with the
//! accompanying text depends on which command is in flight.
//!
//! RFC 5321 §4.2.1's `421 <service closing>` can arrive under any shape
//! (the server can drop the connection at any point in the exchange) and
//! is handled uniformly regardless of what was expected.

use base64::Engine;

use super::error::SmtpError;
use super::state::SmtpCapabilities;

/// Cap on one buffered field (rejection/error diagnostics, an EHLO line,
/// an AUTH challenge, the text scanned for a queue-id), so a server that
/// never sends a delimiter can't grow the lexer's scratch buffer without
/// bound. Decorative success text is never buffered at all — this bound
/// only applies to fields the parser actually keeps.
pub const MAX_REPLY_LINE: usize = 16 * 1024;

/// What shape of reply to expect, set via [`SmtpReplyLexer::expect`] right
/// after sending the corresponding command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpReplyShape {
    /// The initial greeting.
    Greeting,
    /// `EHLO`.
    Ehlo,
    /// `HELO`.
    Helo,
    /// `STARTTLS`.
    Starttls,
    /// `AUTH` (initial send, and every subsequent challenge response).
    Auth,
    /// `MAIL FROM`.
    MailFrom,
    /// `RCPT TO`.
    RcptTo,
    /// `DATA` (the command itself, before content).
    DataCommand,
    /// End-of-data (`CRLF.CRLF`).
    DataEnd,
    /// `RSET`.
    Rset,
    /// `QUIT`.
    Quit,
    /// `VRFY`.
    Vrfy,
    /// `EXPN`.
    Expn,
}

/// Semantic events. Every variant carries already-parsed, ready-to-use
/// data — never a raw code+text pair for the caller to re-interpret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmtpEvent {
    /// 220 greeting.
    Greeting {
        /// `true` if "ESMTP" appeared in the banner text — the text
        /// itself is scanned for that and then discarded.
        esmtp: bool,
    },
    /// Non-220, non-421 greeting.
    ServiceUnavailable {
        /// The server's diagnostic text.
        message: String,
    },
    /// 250 (multiline) EHLO response, fully parsed (RFC 5321 §4.1.1.1).
    Ehlo(SmtpCapabilities),
    /// 502 — EHLO not supported.
    EhloNotSupported,
    /// EHLO permanent failure (5xx other than 502).
    EhloError {
        /// The server's diagnostic text.
        message: String,
    },
    /// 250 HELO response (no message text — matches the driver call it
    /// feeds, which takes none).
    Helo,
    /// HELO failure.
    HeloError {
        /// The server's diagnostic text.
        message: String,
    },
    /// 220 to STARTTLS — the endpoint drives the TLS handshake next.
    StarttlsAccepted,
    /// 454/502 to STARTTLS — recoverable, session continues without TLS.
    TlsUnavailable,
    /// STARTTLS permanently rejected (5xx other than 502, e.g. 554) —
    /// connection is closed, matching Gumdrop's `handlePermanentFailure`.
    TlsError {
        /// The server's diagnostic text.
        message: String,
    },
    /// 235 — AUTH succeeded.
    AuthOk,
    /// 334 — AUTH challenge, already base64-decoded.
    AuthChallenge {
        /// Decoded challenge bytes.
        data: Vec<u8>,
    },
    /// 535/504/454 — AUTH failed. `code` lets the driver distinguish bad
    /// credentials (535) from an unsupported mechanism (504) or a
    /// temporary failure (454) worth retrying.
    AuthFailed {
        /// The server's 3-digit reply code.
        code: u16,
    },
    /// 250 MAIL FROM accepted.
    MailOk,
    /// MAIL FROM rejected.
    MailRejected {
        /// The server's 3-digit reply code.
        code: u16,
        /// The server's diagnostic text.
        message: String,
    },
    /// 250/251/252 RCPT TO accepted.
    RcptOk,
    /// RCPT TO rejected.
    RcptRejected {
        /// The server's 3-digit reply code.
        code: u16,
        /// The server's diagnostic text.
        message: String,
    },
    /// 354 — ready for DATA.
    ReadyForData,
    /// DATA command rejected, or the message rejected after end-of-data.
    MessageRejected {
        /// The server's 3-digit reply code.
        code: u16,
        /// The server's diagnostic text.
        message: String,
    },
    /// 250 after end-of-data. `queue_id` is scanned from the reply text
    /// ("queued as X" / "message accepted for delivery X") if present.
    MessageAccepted {
        /// The server's queue identifier, if present in the reply text.
        queue_id: Option<String>,
    },
    /// RSET accepted (RFC 5321: RSET has no failure path).
    RsetOk,
    /// 250/251/252 — VRFY succeeded. `code` distinguishes a fully verified
    /// mailbox (250) from one that will be forwarded (251) or merely
    /// accepted without verification (252); `text` is the resolved-mailbox
    /// text the server returned.
    VrfyOk {
        /// The server's 3-digit reply code.
        code: u16,
        /// The server's resolved-mailbox text.
        text: String,
    },
    /// VRFY failed (5xx, or 502/504 if VRFY itself isn't implemented).
    VrfyFailed {
        /// The server's 3-digit reply code.
        code: u16,
        /// The server's diagnostic text.
        message: String,
    },
    /// 250 — EXPN succeeded; one entry per expanded mailing-list member.
    ExpnOk {
        /// Each member's text, one per reply line.
        members: Vec<String>,
    },
    /// EXPN failed (5xx, or 502/504 if EXPN itself isn't implemented).
    ExpnFailed {
        /// The server's 3-digit reply code.
        code: u16,
        /// The server's diagnostic text.
        message: String,
    },
    /// 421 — service closing. Can arrive under any shape.
    ServiceClosing {
        /// The server's diagnostic text.
        message: String,
    },
}

// ── Internal FSM ─────────────────────────────────────────────────────────────

/// What the current line's text field is, decided once the 3-digit code
/// and separator are known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    /// Decorative text: scan for CRLF, never store.
    SkipToEol,
    /// Bounded diagnostic text, kept.
    KeepText,
    /// Greeting banner: scanned for "ESMTP" (case-insensitive), discarded.
    GreetingText,
    /// One EHLO capability line, bounded, parsed into `caps` on CR.
    EhloLine,
    /// AUTH challenge text, bounded, base64-decoded on CR.
    AuthChallengeText,
    /// First line of a post-DATA 250, bounded, scanned for a queue-id.
    QueueIdText,
    /// One EXPN member line, bounded, pushed onto `expn_members` on CR.
    ExpnLine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Accumulating the 3-digit reply code (0, 1, or 2 digits seen).
    Code { digits: u8, value: u16 },
    /// 3 digits seen; next byte is `-` (continuation), SP (final, text
    /// follows), or CR (final, no text at all — RFC 5321 §4.2 allows a
    /// bare `code CRLF` final line).
    Sep { code: u16 },
    /// Reading a text field.
    Reading(Field),
    /// Saw the field's own CR; expect LF next to complete it.
    FieldCr(Field),
}

/// Incremental SMTP client-reply parser. See the module docs.
pub struct SmtpReplyLexer {
    shape: SmtpReplyShape,
    state: State,
    /// The 3-digit code of the line most recently completed — read back
    /// by `finish_reply` once the text field (if any) has also finished,
    /// since `Sep` (where the code is first known) may have transitioned
    /// straight into a multi-byte text field read over several `feed()`
    /// calls before the code is needed again.
    last_code: u16,
    /// Code of the multiline reply in progress, if any continuation line
    /// has been seen (`None` before the first line, or once complete).
    pending_code: Option<u16>,
    /// `true` once at least one line of the current reply has completed —
    /// only the first line gets shape-specific field treatment (kept
    /// text, ESMTP scan, queue-id scan); continuation lines after it are
    /// always discarded (matches today's `reply.text()` == first line
    /// only). EHLO is the one exception: every line matters.
    seen_first_line: bool,
    /// Bounded scratch for `KeepText`/`EhloLine`/`AuthChallengeText`/`QueueIdText`.
    text: String,
    /// Greeting-only: how many bytes of "ESMTP" have matched so far.
    esmtp_matched: u8,
    /// Greeting-only: whether "ESMTP" has been found in the banner.
    esmtp_found: bool,
    /// EHLO-only: capabilities accumulated across lines.
    caps: SmtpCapabilities,
    /// EXPN-only: members accumulated across lines.
    expn_members: Vec<String>,
}

const ESMTP: &[u8] = b"ESMTP";

impl Default for SmtpReplyLexer {
    fn default() -> Self {
        Self::new()
    }
}

impl SmtpReplyLexer {
    /// Create a new lexer. Call [`Self::expect`] before feeding the bytes
    /// of each reply.
    pub fn new() -> Self {
        Self {
            shape: SmtpReplyShape::Greeting,
            state: State::Code { digits: 0, value: 0 },
            last_code: 0,
            pending_code: None,
            seen_first_line: false,
            text: String::new(),
            esmtp_matched: 0,
            esmtp_found: false,
            caps: SmtpCapabilities::default(),
            expn_members: Vec::new(),
        }
    }

    /// Tell the lexer what shape the next reply takes. Call this right
    /// after sending the corresponding command.
    pub fn expect(&mut self, shape: SmtpReplyShape) {
        self.shape = shape;
        self.state = State::Code { digits: 0, value: 0 };
        self.pending_code = None;
        self.seen_first_line = false;
        self.caps = SmtpCapabilities::default();
        self.expn_members.clear();
    }

    /// Feed inbound bytes. Returns parsed events; consumes everything
    /// given (`*data` is always left empty).
    pub fn feed(&mut self, data: &mut &[u8]) -> Result<Vec<SmtpEvent>, SmtpError> {
        let mut events = Vec::new();
        for &b in data.iter() {
            if let Some(event) = self.push_byte(b)? {
                events.push(event);
            }
        }
        *data = &[];
        Ok(events)
    }

    fn push_byte(&mut self, b: u8) -> Result<Option<SmtpEvent>, SmtpError> {
        match self.state {
            State::Code { digits, value } => self.push_code_byte(digits, value, b),
            State::Sep { code } => self.push_sep_byte(code, b),
            State::Reading(field) => self.push_field_byte(field, b),
            State::FieldCr(field) => {
                if b == b'\n' {
                    self.finish_field(field)
                } else {
                    Err(SmtpError::Parse("malformed SMTP reply: expected LF after CR".into()))
                }
            }
        }
    }

    // ── Code + separator ──────────────────────────────────────────────

    fn push_code_byte(
        &mut self,
        digits: u8,
        value: u16,
        b: u8,
    ) -> Result<Option<SmtpEvent>, SmtpError> {
        if !b.is_ascii_digit() {
            return Err(SmtpError::Parse(format!(
                "unexpected byte {b:#04x} in SMTP reply code (digit {digits})"
            )));
        }
        let value = value * 10 + u16::from(b - b'0');
        if digits + 1 == 3 {
            self.state = State::Sep { code: value };
        } else {
            self.state = State::Code { digits: digits + 1, value };
        }
        Ok(None)
    }

    fn push_sep_byte(&mut self, code: u16, b: u8) -> Result<Option<SmtpEvent>, SmtpError> {
        let is_continuation = match b {
            b'-' => true,
            b' ' | b'\r' => false,
            _ => {
                return Err(SmtpError::Parse(format!(
                    "unexpected byte {b:#04x} after SMTP reply code {code}"
                )))
            }
        };

        // Multiline code consistency (RFC 5321 §4.2.1).
        match self.pending_code {
            Some(c) if c != code => {
                return Err(SmtpError::Parse(format!(
                    "SMTP multiline code mismatch: expected {c}, got {code}"
                )))
            }
            _ => {}
        }
        let first_line = !self.seen_first_line;
        self.pending_code = if is_continuation { Some(code) } else { None };
        self.last_code = code;

        let field = self.select_field(code, first_line);
        self.text.clear();
        if field == Field::GreetingText {
            self.esmtp_matched = 0;
        }

        if b == b'\r' {
            // Bare "code CRLF" — no text at all on this line.
            self.state = State::FieldCr(field);
        } else {
            self.state = State::Reading(field);
        }
        Ok(None)
    }

    /// Decide how to handle this line's text, based on the shape, the
    /// code just seen, and whether this is the first line of the reply
    /// (only the first line gets shape-specific treatment for every shape
    /// except EHLO, where every line carries a capability).
    fn select_field(&self, code: u16, first_line: bool) -> Field {
        if code == 421 {
            return if first_line { Field::KeepText } else { Field::SkipToEol };
        }
        if self.shape == SmtpReplyShape::Ehlo && code == 250 {
            return Field::EhloLine;
        }
        if self.shape == SmtpReplyShape::Expn && code == 250 {
            return Field::ExpnLine;
        }
        if !first_line {
            return Field::SkipToEol;
        }
        match self.shape {
            SmtpReplyShape::Greeting => {
                if code == 220 {
                    Field::GreetingText
                } else {
                    Field::KeepText
                }
            }
            SmtpReplyShape::Ehlo => {
                // Non-250 (EHLO failed): 502 needs no text, other 5xx does.
                if code == 502 {
                    Field::SkipToEol
                } else {
                    Field::KeepText
                }
            }
            SmtpReplyShape::Helo => {
                if code == 250 {
                    Field::SkipToEol
                } else {
                    Field::KeepText
                }
            }
            SmtpReplyShape::Starttls => {
                if code == 220 || code == 454 || code == 502 {
                    Field::SkipToEol // accepted or recoverably unavailable
                } else {
                    Field::KeepText // permanent failure — text goes to TlsError
                }
            }
            SmtpReplyShape::Auth => match code {
                235 => Field::SkipToEol,
                334 => Field::AuthChallengeText,
                _ => Field::SkipToEol, // on_auth_failed takes a code, not text
            },
            SmtpReplyShape::MailFrom => {
                if code == 250 {
                    Field::SkipToEol
                } else {
                    Field::KeepText
                }
            }
            SmtpReplyShape::RcptTo => {
                if matches!(code, 250 | 251 | 252) {
                    Field::SkipToEol
                } else {
                    Field::KeepText
                }
            }
            SmtpReplyShape::DataCommand => {
                if code == 354 {
                    Field::SkipToEol
                } else {
                    Field::KeepText
                }
            }
            SmtpReplyShape::DataEnd => {
                if code == 250 {
                    Field::QueueIdText
                } else {
                    Field::KeepText
                }
            }
            SmtpReplyShape::Rset => Field::SkipToEol, // RSET has no failure path
            SmtpReplyShape::Quit => Field::SkipToEol, // no reply text is used
            // Success/failure text both matter for VRFY (the resolved
            // mailbox *is* the success text); EXPN's success path never
            // reaches here (handled by the ExpnLine check above), so this
            // arm is failure-only for EXPN.
            SmtpReplyShape::Vrfy | SmtpReplyShape::Expn => Field::KeepText,
        }
    }

    // ── Field accumulation ────────────────────────────────────────────

    fn push_field_byte(&mut self, field: Field, b: u8) -> Result<Option<SmtpEvent>, SmtpError> {
        if b == b'\r' {
            self.state = State::FieldCr(field);
            return Ok(None);
        }
        match field {
            Field::SkipToEol => {}
            Field::GreetingText => self.push_esmtp_byte(b),
            Field::KeepText
            | Field::EhloLine
            | Field::AuthChallengeText
            | Field::QueueIdText
            | Field::ExpnLine => {
                if self.text.len() >= MAX_REPLY_LINE {
                    return Err(SmtpError::Parse("SMTP reply field too long".into()));
                }
                self.text.push(b as char);
            }
        }
        Ok(None)
    }

    /// Case-insensitive streaming match for the fixed pattern "ESMTP". All
    /// characters in the pattern are distinct, so on a mismatch the only
    /// possible restart point is "does this byte start a fresh match" —
    /// no KMP failure-function bookkeeping needed beyond that.
    fn push_esmtp_byte(&mut self, b: u8) {
        if self.esmtp_found {
            return;
        }
        let upper = b.to_ascii_uppercase();
        if upper == ESMTP[self.esmtp_matched as usize] {
            self.esmtp_matched += 1;
            if self.esmtp_matched as usize == ESMTP.len() {
                self.esmtp_found = true;
            }
        } else {
            self.esmtp_matched = u8::from(upper == ESMTP[0]);
        }
    }

    fn finish_field(&mut self, field: Field) -> Result<Option<SmtpEvent>, SmtpError> {
        let was_first_line = !self.seen_first_line;
        self.seen_first_line = true;
        let reply_complete = self.pending_code.is_none();

        match field {
            Field::EhloLine => {
                if was_first_line {
                    // First line of EHLO's reply is the greeting-domain
                    // echo, not a capability — matches today's
                    // `lines.iter().skip(1)`.
                } else {
                    let line = std::mem::take(&mut self.text);
                    apply_ehlo_line(&mut self.caps, &line);
                }
                self.state = State::Code { digits: 0, value: 0 };
                if reply_complete {
                    let caps = std::mem::take(&mut self.caps);
                    Ok(Some(SmtpEvent::Ehlo(caps)))
                } else {
                    Ok(None)
                }
            }
            Field::ExpnLine => {
                let line = std::mem::take(&mut self.text);
                self.expn_members.push(line);
                self.state = State::Code { digits: 0, value: 0 };
                if reply_complete {
                    let members = std::mem::take(&mut self.expn_members);
                    Ok(Some(SmtpEvent::ExpnOk { members }))
                } else {
                    Ok(None)
                }
            }
            _ if !reply_complete => {
                // Continuation line of a non-EHLO/EXPN multiline reply:
                // nothing to emit yet, keep reading lines.
                self.state = State::Code { digits: 0, value: 0 };
                Ok(None)
            }
            Field::SkipToEol => {
                self.state = State::Code { digits: 0, value: 0 };
                Ok(self.finish_reply(None))
            }
            Field::KeepText => {
                let text = std::mem::take(&mut self.text);
                self.state = State::Code { digits: 0, value: 0 };
                Ok(self.finish_reply(Some(text)))
            }
            Field::GreetingText => {
                self.state = State::Code { digits: 0, value: 0 };
                Ok(self.finish_reply(None))
            }
            Field::AuthChallengeText => {
                let text = std::mem::take(&mut self.text);
                self.state = State::Code { digits: 0, value: 0 };
                let data = base64::engine::general_purpose::STANDARD
                    .decode(text.trim().as_bytes())
                    .unwrap_or_default();
                Ok(Some(SmtpEvent::AuthChallenge { data }))
            }
            Field::QueueIdText => {
                let text = std::mem::take(&mut self.text);
                self.state = State::Code { digits: 0, value: 0 };
                Ok(Some(SmtpEvent::MessageAccepted { queue_id: parse_queue_id(&text) }))
            }
        }
    }

    /// Build the final event for shapes whose outcome only needs the
    /// code (and, for kept-text fields, the accumulated diagnostic text).
    fn finish_reply(&mut self, message: Option<String>) -> Option<SmtpEvent> {
        let code = self.last_code;
        let esmtp = self.esmtp_found;
        self.esmtp_matched = 0;
        self.esmtp_found = false;

        if code == 421 {
            return Some(SmtpEvent::ServiceClosing { message: message.unwrap_or_default() });
        }

        Some(match self.shape {
            SmtpReplyShape::Greeting => {
                if code == 220 {
                    SmtpEvent::Greeting { esmtp }
                } else {
                    SmtpEvent::ServiceUnavailable { message: message.unwrap_or_default() }
                }
            }
            SmtpReplyShape::Ehlo => {
                if code == 502 {
                    SmtpEvent::EhloNotSupported
                } else {
                    SmtpEvent::EhloError { message: message.unwrap_or_default() }
                }
            }
            SmtpReplyShape::Helo => {
                if code == 250 {
                    SmtpEvent::Helo
                } else {
                    SmtpEvent::HeloError { message: message.unwrap_or_default() }
                }
            }
            SmtpReplyShape::Starttls => {
                if code == 220 {
                    SmtpEvent::StarttlsAccepted
                } else if code == 454 || code == 502 {
                    SmtpEvent::TlsUnavailable
                } else {
                    SmtpEvent::TlsError { message: message.unwrap_or_default() }
                }
            }
            SmtpReplyShape::Auth => match code {
                235 => SmtpEvent::AuthOk,
                _ => SmtpEvent::AuthFailed { code },
            },
            SmtpReplyShape::MailFrom => {
                if code == 250 {
                    SmtpEvent::MailOk
                } else {
                    SmtpEvent::MailRejected { code, message: message.unwrap_or_default() }
                }
            }
            SmtpReplyShape::RcptTo => {
                if matches!(code, 250 | 251 | 252) {
                    SmtpEvent::RcptOk
                } else {
                    SmtpEvent::RcptRejected { code, message: message.unwrap_or_default() }
                }
            }
            SmtpReplyShape::DataCommand => {
                if code == 354 {
                    SmtpEvent::ReadyForData
                } else {
                    SmtpEvent::MessageRejected { code, message: message.unwrap_or_default() }
                }
            }
            SmtpReplyShape::DataEnd => {
                // 250 goes through Field::QueueIdText, not finish_reply.
                SmtpEvent::MessageRejected { code, message: message.unwrap_or_default() }
            }
            SmtpReplyShape::Rset => SmtpEvent::RsetOk,
            SmtpReplyShape::Quit => return None, // no driver callback exists for QUIT
            SmtpReplyShape::Vrfy => {
                if matches!(code, 250 | 251 | 252) {
                    SmtpEvent::VrfyOk { code, text: message.unwrap_or_default() }
                } else {
                    SmtpEvent::VrfyFailed { code, message: message.unwrap_or_default() }
                }
            }
            // 250 goes through Field::ExpnLine, not finish_reply.
            SmtpReplyShape::Expn => {
                SmtpEvent::ExpnFailed { code, message: message.unwrap_or_default() }
            }
        })
    }
}

/// Apply one EHLO continuation line to `caps` (RFC 5321 §4.1.1.1).
fn apply_ehlo_line(caps: &mut SmtpCapabilities, line: &str) {
    let upper = line.to_ascii_uppercase();
    if upper == "STARTTLS" {
        caps.starttls = true;
    } else if upper.starts_with("SIZE") {
        if upper.len() > 5 {
            if let Ok(n) = line[5..].trim().parse::<u64>() {
                caps.max_size = n;
            }
        }
    } else if upper.starts_with("AUTH") {
        for token in line.get(4..).unwrap_or("").split_whitespace() {
            caps.auth_methods.push(token.to_ascii_uppercase());
        }
    } else if upper == "PIPELINING" {
        caps.pipelining = true;
    } else if upper == "CHUNKING" {
        caps.chunking = true;
    } else if upper == "8BITMIME" {
        caps.eight_bit_mime = true;
    } else if upper == "SMTPUTF8" {
        caps.smtp_utf8 = true;
    } else if upper == "DSN" {
        caps.dsn = true;
    } else if upper == "ENHANCEDSTATUSCODES" {
        caps.enhanced_status_codes = true;
    } else if upper == "REQUIRETLS" {
        caps.require_tls = true;
    } else if upper == "BINARYMIME" {
        caps.binary_mime = true;
    } else if upper.starts_with("MT-PRIORITY") {
        caps.mt_priority = true;
    } else if upper.starts_with("FUTURERELEASE") {
        caps.future_release = true;
    } else if upper.starts_with("DELIVERBY") {
        caps.deliver_by = true;
    } else if upper.starts_with("LIMITS") {
        apply_limits_line(caps, line);
    }
}

/// RFC 9422 — parse `LIMITS` keyword parameters (`RCPTMAX=`/`MAILMAX=`).
fn apply_limits_line(caps: &mut SmtpCapabilities, line: &str) {
    for token in line.split_whitespace().skip(1) {
        let upper = token.to_ascii_uppercase();
        if let Some(v) = upper.strip_prefix("RCPTMAX=") {
            if let Ok(n) = v.parse() {
                caps.limits_rcpt_max = n;
            }
        } else if let Some(v) = upper.strip_prefix("MAILMAX=") {
            if let Ok(n) = v.parse() {
                caps.limits_mail_max = n;
            }
        }
    }
}

/// Extract a queue identifier from a 250 message-accepted text.
fn parse_queue_id(message: &str) -> Option<String> {
    let lower = message.to_ascii_lowercase();
    for prefix in &["queued as ", "message accepted for delivery "] {
        if let Some(idx) = lower.find(prefix) {
            let rest = message[idx + prefix.len()..].trim();
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            if end > 0 {
                return Some(rest[..end].to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greeting_esmtp() {
        let mut lex = SmtpReplyLexer::new();
        lex.expect(SmtpReplyShape::Greeting);
        let mut data: &[u8] = b"220 mail.example.com ESMTP Postfix\r\n";
        let events = lex.feed(&mut data).unwrap();
        assert_eq!(events, vec![SmtpEvent::Greeting { esmtp: true }]);
        assert!(data.is_empty());
    }

    #[test]
    fn greeting_plain_smtp() {
        let mut lex = SmtpReplyLexer::new();
        lex.expect(SmtpReplyShape::Greeting);
        let mut data: &[u8] = b"220 mail.example.com Simple Mail Transfer Service Ready\r\n";
        let events = lex.feed(&mut data).unwrap();
        assert_eq!(events, vec![SmtpEvent::Greeting { esmtp: false }]);
    }

    #[test]
    fn greeting_esmtp_case_insensitive() {
        let mut lex = SmtpReplyLexer::new();
        lex.expect(SmtpReplyShape::Greeting);
        let mut data: &[u8] = b"220 host esmtp ready\r\n";
        let events = lex.feed(&mut data).unwrap();
        assert_eq!(events, vec![SmtpEvent::Greeting { esmtp: true }]);
    }

    #[test]
    fn greeting_service_unavailable() {
        let mut lex = SmtpReplyLexer::new();
        lex.expect(SmtpReplyShape::Greeting);
        let mut data: &[u8] = b"554 No SMTP service here\r\n";
        let events = lex.feed(&mut data).unwrap();
        assert_eq!(
            events,
            vec![SmtpEvent::ServiceUnavailable { message: "No SMTP service here".into() }]
        );
    }

    #[test]
    fn service_closing_421_overrides_any_shape() {
        for shape in [
            SmtpReplyShape::Greeting,
            SmtpReplyShape::Ehlo,
            SmtpReplyShape::MailFrom,
            SmtpReplyShape::RcptTo,
            SmtpReplyShape::DataEnd,
        ] {
            let mut lex = SmtpReplyLexer::new();
            lex.expect(shape);
            let mut data: &[u8] = b"421 mail.example.com Service not available, closing\r\n";
            let events = lex.feed(&mut data).unwrap();
            assert_eq!(
                events,
                vec![SmtpEvent::ServiceClosing {
                    message: "mail.example.com Service not available, closing".into()
                }],
                "shape {shape:?}"
            );
        }
    }

    #[test]
    fn ehlo_full_capabilities() {
        let mut lex = SmtpReplyLexer::new();
        lex.expect(SmtpReplyShape::Ehlo);
        let mut data: &[u8] = b"250-mail.example.com Hello\r\n250-SIZE 35882577\r\n250-PIPELINING\r\n250-AUTH PLAIN LOGIN\r\n250-STARTTLS\r\n250 8BITMIME\r\n";
        let events = lex.feed(&mut data).unwrap();
        assert_eq!(events.len(), 1);
        match &events[0] {
            SmtpEvent::Ehlo(caps) => {
                assert_eq!(caps.max_size, 35882577);
                assert!(caps.pipelining);
                assert_eq!(caps.auth_methods, vec!["PLAIN", "LOGIN"]);
                assert!(caps.starttls);
                assert!(caps.eight_bit_mime);
            }
            other => panic!("expected Ehlo, got {other:?}"),
        }
        assert!(data.is_empty());
    }

    #[test]
    fn ehlo_extension_capabilities() {
        let mut lex = SmtpReplyLexer::new();
        lex.expect(SmtpReplyShape::Ehlo);
        let mut data: &[u8] = b"250-mail.example.com Hello\r\n250-BINARYMIME\r\n250-MT-PRIORITY\r\n250-FUTURERELEASE 1234567 2023-12-31T23:59:59Z\r\n250-DELIVERBY 100\r\n250 LIMITS RCPTMAX=100 MAILMAX=50\r\n";
        let events = lex.feed(&mut data).unwrap();
        assert_eq!(events.len(), 1);
        match &events[0] {
            SmtpEvent::Ehlo(caps) => {
                assert!(caps.binary_mime);
                assert!(caps.mt_priority);
                assert!(caps.future_release);
                assert!(caps.deliver_by);
                assert_eq!(caps.limits_rcpt_max, 100);
                assert_eq!(caps.limits_mail_max, 50);
            }
            other => panic!("expected Ehlo, got {other:?}"),
        }
    }

    #[test]
    fn ehlo_split_mid_capability_line() {
        let mut lex = SmtpReplyLexer::new();
        lex.expect(SmtpReplyShape::Ehlo);
        let mut part1: &[u8] = b"250-mail.example.com\r\n250-STARTT";
        let e1 = lex.feed(&mut part1).unwrap();
        assert!(e1.is_empty());
        let mut part2: &[u8] = b"LS\r\n250 PIPELINING\r\n";
        let e2 = lex.feed(&mut part2).unwrap();
        assert_eq!(e2.len(), 1);
        match &e2[0] {
            SmtpEvent::Ehlo(caps) => {
                assert!(caps.starttls);
                assert!(caps.pipelining);
            }
            other => panic!("expected Ehlo, got {other:?}"),
        }
    }

    #[test]
    fn ehlo_not_supported() {
        let mut lex = SmtpReplyLexer::new();
        lex.expect(SmtpReplyShape::Ehlo);
        let mut data: &[u8] = b"502 Command not implemented\r\n";
        let events = lex.feed(&mut data).unwrap();
        assert_eq!(events, vec![SmtpEvent::EhloNotSupported]);
    }

    #[test]
    fn ehlo_error() {
        let mut lex = SmtpReplyLexer::new();
        lex.expect(SmtpReplyShape::Ehlo);
        let mut data: &[u8] = b"500 Syntax error\r\n";
        let events = lex.feed(&mut data).unwrap();
        assert_eq!(events, vec![SmtpEvent::EhloError { message: "Syntax error".into() }]);
    }

    #[test]
    fn helo_ok_and_error() {
        let mut lex = SmtpReplyLexer::new();
        lex.expect(SmtpReplyShape::Helo);
        let mut data: &[u8] = b"250 mail.example.com\r\n";
        assert_eq!(lex.feed(&mut data).unwrap(), vec![SmtpEvent::Helo]);

        lex.expect(SmtpReplyShape::Helo);
        let mut data2: &[u8] = b"501 Syntax error in parameters\r\n";
        assert_eq!(
            lex.feed(&mut data2).unwrap(),
            vec![SmtpEvent::HeloError { message: "Syntax error in parameters".into() }]
        );
    }

    #[test]
    fn starttls_accepted_and_unavailable() {
        let mut lex = SmtpReplyLexer::new();
        lex.expect(SmtpReplyShape::Starttls);
        let mut data: &[u8] = b"220 Ready to start TLS\r\n";
        assert_eq!(lex.feed(&mut data).unwrap(), vec![SmtpEvent::StarttlsAccepted]);

        lex.expect(SmtpReplyShape::Starttls);
        let mut data2: &[u8] = b"454 TLS not available due to temporary reason\r\n";
        assert_eq!(lex.feed(&mut data2).unwrap(), vec![SmtpEvent::TlsUnavailable]);

        lex.expect(SmtpReplyShape::Starttls);
        let mut data3: &[u8] = b"502 Command not implemented\r\n";
        assert_eq!(lex.feed(&mut data3).unwrap(), vec![SmtpEvent::TlsUnavailable]);
    }

    #[test]
    fn starttls_permanent_failure() {
        let mut lex = SmtpReplyLexer::new();
        lex.expect(SmtpReplyShape::Starttls);
        let mut data: &[u8] = b"554 TLS not available\r\n";
        assert_eq!(
            lex.feed(&mut data).unwrap(),
            vec![SmtpEvent::TlsError { message: "TLS not available".into() }]
        );
    }

    #[test]
    fn auth_ok_challenge_failed() {
        let mut lex = SmtpReplyLexer::new();
        lex.expect(SmtpReplyShape::Auth);
        let mut data: &[u8] = b"235 Authentication successful\r\n";
        assert_eq!(lex.feed(&mut data).unwrap(), vec![SmtpEvent::AuthOk]);

        lex.expect(SmtpReplyShape::Auth);
        let mut data2: &[u8] = b"334 VXNlcm5hbWU6\r\n";
        assert_eq!(
            lex.feed(&mut data2).unwrap(),
            vec![SmtpEvent::AuthChallenge { data: b"Username:".to_vec() }]
        );

        lex.expect(SmtpReplyShape::Auth);
        let mut data3: &[u8] = b"535 Authentication failed\r\n";
        assert_eq!(lex.feed(&mut data3).unwrap(), vec![SmtpEvent::AuthFailed { code: 535 }]);

        lex.expect(SmtpReplyShape::Auth);
        let mut data4: &[u8] = b"504 Mechanism not supported\r\n";
        assert_eq!(lex.feed(&mut data4).unwrap(), vec![SmtpEvent::AuthFailed { code: 504 }]);

        lex.expect(SmtpReplyShape::Auth);
        let mut data5: &[u8] = b"454 Temporary auth failure\r\n";
        assert_eq!(lex.feed(&mut data5).unwrap(), vec![SmtpEvent::AuthFailed { code: 454 }]);
    }

    #[test]
    fn mail_from_ok_and_rejected() {
        let mut lex = SmtpReplyLexer::new();
        lex.expect(SmtpReplyShape::MailFrom);
        let mut data: &[u8] = b"250 OK\r\n";
        assert_eq!(lex.feed(&mut data).unwrap(), vec![SmtpEvent::MailOk]);

        lex.expect(SmtpReplyShape::MailFrom);
        let mut data2: &[u8] = b"552 Message size exceeds fixed limit\r\n";
        assert_eq!(
            lex.feed(&mut data2).unwrap(),
            vec![SmtpEvent::MailRejected {
                code: 552,
                message: "Message size exceeds fixed limit".into()
            }]
        );
    }

    #[test]
    fn rcpt_to_ok_and_rejected() {
        for code in [250u16, 251, 252] {
            let mut lex = SmtpReplyLexer::new();
            lex.expect(SmtpReplyShape::RcptTo);
            let mut data: Vec<u8> = format!("{code} OK\r\n").into_bytes();
            let mut slice: &[u8] = &data;
            assert_eq!(lex.feed(&mut slice).unwrap(), vec![SmtpEvent::RcptOk]);
            data.clear();
        }

        let mut lex = SmtpReplyLexer::new();
        lex.expect(SmtpReplyShape::RcptTo);
        let mut data: &[u8] = b"550 No such user here\r\n";
        assert_eq!(
            lex.feed(&mut data).unwrap(),
            vec![SmtpEvent::RcptRejected { code: 550, message: "No such user here".into() }]
        );
    }

    #[test]
    fn data_command_ready_and_rejected() {
        let mut lex = SmtpReplyLexer::new();
        lex.expect(SmtpReplyShape::DataCommand);
        let mut data: &[u8] = b"354 Start mail input; end with <CRLF>.<CRLF>\r\n";
        assert_eq!(lex.feed(&mut data).unwrap(), vec![SmtpEvent::ReadyForData]);

        lex.expect(SmtpReplyShape::DataCommand);
        let mut data2: &[u8] = b"503 Bad sequence of commands\r\n";
        assert_eq!(
            lex.feed(&mut data2).unwrap(),
            vec![SmtpEvent::MessageRejected {
                code: 503,
                message: "Bad sequence of commands".into()
            }]
        );
    }

    #[test]
    fn data_end_accepted_with_queue_id() {
        let mut lex = SmtpReplyLexer::new();
        lex.expect(SmtpReplyShape::DataEnd);
        let mut data: &[u8] = b"250 2.0.0 OK queued as 4Y2ZzR6q5vzJ\r\n";
        let events = lex.feed(&mut data).unwrap();
        assert_eq!(
            events,
            vec![SmtpEvent::MessageAccepted { queue_id: Some("4Y2ZzR6q5vzJ".into()) }]
        );
    }

    #[test]
    fn data_end_accepted_no_queue_id() {
        let mut lex = SmtpReplyLexer::new();
        lex.expect(SmtpReplyShape::DataEnd);
        let mut data: &[u8] = b"250 Message accepted\r\n";
        let events = lex.feed(&mut data).unwrap();
        assert_eq!(events, vec![SmtpEvent::MessageAccepted { queue_id: None }]);
    }

    #[test]
    fn data_end_rejected() {
        let mut lex = SmtpReplyLexer::new();
        lex.expect(SmtpReplyShape::DataEnd);
        let mut data: &[u8] = b"552 Message exceeds storage allocation\r\n";
        assert_eq!(
            lex.feed(&mut data).unwrap(),
            vec![SmtpEvent::MessageRejected {
                code: 552,
                message: "Message exceeds storage allocation".into()
            }]
        );
    }

    #[test]
    fn vrfy_ok_variants() {
        for code in [250u16, 251, 252] {
            let mut lex = SmtpReplyLexer::new();
            lex.expect(SmtpReplyShape::Vrfy);
            let mut data: Vec<u8> =
                format!("{code} Fred Bloggs <fred@example.com>\r\n").into_bytes();
            let mut slice: &[u8] = &data;
            assert_eq!(
                lex.feed(&mut slice).unwrap(),
                vec![SmtpEvent::VrfyOk { code, text: "Fred Bloggs <fred@example.com>".into() }]
            );
            data.clear();
        }
    }

    #[test]
    fn vrfy_failed() {
        let mut lex = SmtpReplyLexer::new();
        lex.expect(SmtpReplyShape::Vrfy);
        let mut data: &[u8] = b"550 String does not match anything\r\n";
        assert_eq!(
            lex.feed(&mut data).unwrap(),
            vec![SmtpEvent::VrfyFailed {
                code: 550,
                message: "String does not match anything".into()
            }]
        );
    }

    #[test]
    fn expn_ok_multiline() {
        let mut lex = SmtpReplyLexer::new();
        lex.expect(SmtpReplyShape::Expn);
        let mut data: &[u8] =
            b"250-Zaphod Beeblebrox <zb@example.com>\r\n250 Ford Prefect <ford@example.com>\r\n";
        let events = lex.feed(&mut data).unwrap();
        assert_eq!(
            events,
            vec![SmtpEvent::ExpnOk {
                members: vec![
                    "Zaphod Beeblebrox <zb@example.com>".into(),
                    "Ford Prefect <ford@example.com>".into(),
                ]
            }]
        );
    }

    #[test]
    fn expn_ok_single_line() {
        let mut lex = SmtpReplyLexer::new();
        lex.expect(SmtpReplyShape::Expn);
        let mut data: &[u8] = b"250 Solo Member <solo@example.com>\r\n";
        assert_eq!(
            lex.feed(&mut data).unwrap(),
            vec![SmtpEvent::ExpnOk { members: vec!["Solo Member <solo@example.com>".into()] }]
        );
    }

    #[test]
    fn expn_failed() {
        let mut lex = SmtpReplyLexer::new();
        lex.expect(SmtpReplyShape::Expn);
        let mut data: &[u8] = b"550 Access denied\r\n";
        assert_eq!(
            lex.feed(&mut data).unwrap(),
            vec![SmtpEvent::ExpnFailed { code: 550, message: "Access denied".into() }]
        );
    }

    #[test]
    fn rset_always_ok_regardless_of_code() {
        for line in [&b"250 OK\r\n"[..], &b"500 whatever\r\n"[..]] {
            let mut lex = SmtpReplyLexer::new();
            lex.expect(SmtpReplyShape::Rset);
            let mut data: &[u8] = line;
            assert_eq!(lex.feed(&mut data).unwrap(), vec![SmtpEvent::RsetOk]);
        }
    }

    #[test]
    fn quit_produces_no_event() {
        let mut lex = SmtpReplyLexer::new();
        lex.expect(SmtpReplyShape::Quit);
        let mut data: &[u8] = b"221 Bye\r\n";
        assert_eq!(lex.feed(&mut data).unwrap(), Vec::<SmtpEvent>::new());
    }

    #[test]
    fn bare_code_no_separator_no_text() {
        // RFC 5321 §4.2 allows a final line with no SP/text at all.
        let mut lex = SmtpReplyLexer::new();
        lex.expect(SmtpReplyShape::Rset);
        let mut data: &[u8] = b"250\r\n";
        assert_eq!(lex.feed(&mut data).unwrap(), vec![SmtpEvent::RsetOk]);
    }

    #[test]
    fn decorative_text_after_success_is_never_stored() {
        // A very long success message must not error even though
        // MAX_REPLY_LINE would reject that many bytes if it were being
        // buffered — because SkipToEol never buffers it.
        let mut lex = SmtpReplyLexer::new();
        lex.expect(SmtpReplyShape::MailFrom);
        let mut junk = Vec::new();
        junk.extend_from_slice(b"250 ");
        junk.extend(std::iter::repeat(b'x').take(MAX_REPLY_LINE * 4));
        junk.extend_from_slice(b"\r\n");
        let mut data: &[u8] = &junk;
        assert_eq!(lex.feed(&mut data).unwrap(), vec![SmtpEvent::MailOk]);
    }

    #[test]
    fn overlong_error_text_errors_out() {
        let mut lex = SmtpReplyLexer::new();
        lex.expect(SmtpReplyShape::MailFrom);
        let mut junk = Vec::new();
        junk.extend_from_slice(b"550 ");
        junk.extend(std::iter::repeat(b'x').take(MAX_REPLY_LINE + 1));
        let mut data: &[u8] = &junk;
        assert!(lex.feed(&mut data).is_err());
    }

    #[test]
    fn split_one_byte_at_a_time_matches_bulk_feed() {
        let msg: &[u8] = b"250-mail.example.com Hello\r\n250-SIZE 1000\r\n250-STARTTLS\r\n250 PIPELINING\r\n";

        let mut bulk = SmtpReplyLexer::new();
        bulk.expect(SmtpReplyShape::Ehlo);
        let mut bulk_data = msg;
        let bulk_events = bulk.feed(&mut bulk_data).unwrap();

        let mut drip = SmtpReplyLexer::new();
        drip.expect(SmtpReplyShape::Ehlo);
        let mut drip_events = Vec::new();
        for &b in msg {
            let mut one: &[u8] = std::slice::from_ref(&b);
            drip_events.extend(drip.feed(&mut one).unwrap());
        }
        assert_eq!(bulk_events, drip_events);
        assert_eq!(bulk_events.len(), 1);
    }

    #[test]
    fn multiline_code_mismatch_errors() {
        let mut lex = SmtpReplyLexer::new();
        lex.expect(SmtpReplyShape::Ehlo);
        let mut data: &[u8] = b"250-Hello\r\n251-oops\r\n";
        assert!(lex.feed(&mut data).is_err());
    }

    #[test]
    fn pipelined_replies_in_one_feed() {
        // Greeting immediately followed by an EHLO reply in one segment —
        // exercised via two lexers since shape differs per reply in
        // practice (the endpoint re-`expect()`s between them), but this
        // confirms multiple *same-shape* replies in one feed still work.
        let mut lex = SmtpReplyLexer::new();
        lex.expect(SmtpReplyShape::Rset);
        let mut data: &[u8] = b"250 OK\r\n250 OK\r\n";
        let events = lex.feed(&mut data).unwrap();
        assert_eq!(events, vec![SmtpEvent::RsetOk, SmtpEvent::RsetOk]);
    }
}
