// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Incremental IMAP server command parser (tag + args + literals).
//!
//! Self-contained streaming parser: [`ImapServerLexer::feed`] consumes every
//! byte it is given and keeps a command-in-progress in its own bounded
//! `tag`/`rest` scratch buffers — never in a buffer the caller has to retain
//! and re-supply. See `hopf_http::h1::parse` for the design this follows.
//!
//! IMAP's line grammar is the same `TAG SP REST CRLF` shape as POP3/SMTP/FTP
//! (`REST` here is simply accumulated verbatim, spaces and all — it gets
//! split into verb + args only once the line is complete), plus one wrinkle:
//! a trailing `{n}` / `{n+}` on `REST` announces `n` raw octets that follow
//! immediately after the line's CRLF, before the command continues. Those
//! octets are copied in bulk slices as they arrive (never byte-by-byte) and
//! spliced onto `REST` once complete, so a multi-megabyte literal streams
//! through in whatever chunk sizes the transport delivers.

use hopf_mailbox::{Flag, MessageSet};

use crate::server::handler::StoreAction;

/// Default max command-line length (octets), matching common IMAP practice.
pub const MAX_COMMAND_LINE: usize = 8192;

/// Maximum synchronizing / non-synchronizing literal size accepted (32 MiB).
pub const MAX_LITERAL_SIZE: u64 = 32 * 1024 * 1024;

/// LITERAL- non-synchronizing literal cap (RFC 7888).
pub const LITERAL_MINUS_LIMIT: u64 = 4096;

/// A completed IMAP command ready for dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImapCommand {
    /// Client tag.
    pub tag: String,
    /// Uppercased command verb.
    pub verb: String,
    /// Remaining arguments (literals already spliced as raw octets in UTF-8 lossy form
    /// via replacement of literal spans with their decoded content as binary-safe Vec).
    pub args: String,
    /// Raw argument bytes (preserves literal binary content).
    pub arg_bytes: Vec<u8>,
}

/// Events produced while feeding the lexer (commands and sync-literal prompts).
#[derive(Debug)]
pub enum LexEvent {
    /// A complete command (literals incorporated).
    Command(ImapCommand),
    /// Synchronizing literal — send `+` then continue feeding.
    NeedContinuation,
    /// Protocol error (line too long, bad literal, …).
    Error {
        /// Tag if known, else `"*"`.
        tag: String,
        /// Human-readable reason.
        message: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LiteralPhase {
    None,
    /// Waiting for raw bytes of a general-purpose (arg) literal.
    General { remaining: u64 },
    /// Waiting for APPEND message-body literal.
    Append { remaining: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Accumulating the tag, up to SP or CR.
    Tag,
    /// Accumulating the rest of the line (verb + args, literal splices
    /// included), up to CR.
    Rest,
    /// Saw CR; a following LF completes the line. Any other byte means the
    /// CR was literal content, not a terminator.
    Cr,
    /// Streaming a literal's raw octets (`LiteralPhase` says which).
    Literal,
    /// A token exceeded the cap: discard bytes up to the next CRLF (no
    /// command is produced for the discarded line), then resume normally.
    Resync,
    /// Saw CR while resyncing; a following LF ends the discarded line.
    ResyncCr,
}

/// Incremental IMAP command-line parser with literal support.
pub struct ImapServerLexer {
    max_line: usize,
    state: State,
    tag: Vec<u8>,
    /// True while accumulating the tag (before the first SP of a fresh
    /// command line); false once accumulating `rest`.
    fresh_command: bool,
    rest: Vec<u8>,
    /// Length of the current typed (non-literal) run, for the `max_line` cap.
    typed_bytes: usize,
    literal: LiteralPhase,
    literal_buf: Vec<u8>,
    /// APPEND body bytes (exposed to the control handler).
    append_body: Vec<u8>,
    /// When set, an APPEND literal just finished.
    append_complete: bool,
    ready: Vec<LexEvent>,
}

impl ImapServerLexer {
    /// Create with a max command-line length.
    pub fn new(max_line: usize) -> Self {
        Self {
            max_line,
            state: State::Tag,
            tag: Vec::new(),
            fresh_command: true,
            rest: Vec::new(),
            typed_bytes: 0,
            literal: LiteralPhase::None,
            literal_buf: Vec::new(),
            append_body: Vec::new(),
            append_complete: false,
            ready: Vec::new(),
        }
    }

    /// Feed inbound bytes; returns newly completed lex events (commands,
    /// continuations, errors). Consumes everything given — `*data` is
    /// always left empty.
    pub fn feed(&mut self, data: &mut &[u8]) -> Vec<LexEvent> {
        while !data.is_empty() {
            if self.state == State::Literal {
                self.feed_literal(data);
            } else {
                let b = data[0];
                *data = &data[1..];
                self.push_byte(b);
            }
        }
        std::mem::take(&mut self.ready)
    }

    /// Take APPEND body if a literal just completed.
    pub fn take_append_body(&mut self) -> Option<Vec<u8>> {
        if self.append_complete {
            self.append_complete = false;
            Some(std::mem::take(&mut self.append_body))
        } else {
            None
        }
    }

    /// Whether currently reading a literal.
    pub fn in_literal(&self) -> bool {
        !matches!(self.literal, LiteralPhase::None)
    }

    /// Consume as much of a literal's raw octets from `data` as are
    /// available, in one bulk slice — never byte-by-byte.
    fn feed_literal(&mut self, data: &mut &[u8]) {
        let remaining = match self.literal {
            LiteralPhase::General { remaining } => remaining,
            LiteralPhase::Append { remaining } => remaining,
            LiteralPhase::None => unreachable!("feed_literal only called in State::Literal"),
        };
        let take = (remaining as usize).min(data.len());
        let (chunk, rest_data) = data.split_at(take);
        *data = rest_data;
        match &mut self.literal {
            LiteralPhase::General { remaining } => {
                self.literal_buf.extend_from_slice(chunk);
                *remaining -= take as u64;
                if *remaining == 0 {
                    self.rest.append(&mut self.literal_buf);
                    self.literal = LiteralPhase::None;
                    self.fresh_command = false;
                    self.state = State::Rest;
                }
            }
            LiteralPhase::Append { remaining } => {
                self.append_body.extend_from_slice(chunk);
                *remaining -= take as u64;
                if *remaining == 0 {
                    self.literal = LiteralPhase::None;
                    self.append_complete = true;
                    self.finish_command();
                    self.state = State::Tag;
                }
            }
            LiteralPhase::None => unreachable!(),
        }
    }

    fn push_byte(&mut self, b: u8) {
        loop {
            match self.state {
                State::Resync => {
                    if b == b'\r' {
                        self.state = State::ResyncCr;
                    }
                    return;
                }
                State::ResyncCr => {
                    if b == b'\n' {
                        self.state = State::Tag;
                    } else if b != b'\r' {
                        self.state = State::Resync;
                    }
                    return;
                }
                State::Cr => {
                    if b == b'\n' {
                        self.on_crlf();
                        return;
                    }
                    // Literal CR, not a terminator — keep it as content and
                    // re-dispatch this byte under the run that was active.
                    self.push_content(b'\r');
                    self.state = if self.fresh_command {
                        State::Tag
                    } else {
                        State::Rest
                    };
                    continue;
                }
                State::Tag => {
                    if b == b'\r' {
                        self.state = State::Cr;
                    } else if b == b' ' {
                        self.fresh_command = false;
                        self.typed_bytes = 0;
                        self.state = State::Rest;
                    } else {
                        self.push_content(b);
                    }
                    return;
                }
                State::Rest => {
                    if b == b'\r' {
                        self.state = State::Cr;
                    } else {
                        self.push_content(b);
                    }
                    return;
                }
                State::Literal => unreachable!("feed() never calls push_byte in State::Literal"),
            }
        }
    }

    fn push_content(&mut self, b: u8) {
        if self.typed_bytes >= self.max_line {
            self.emit_error("Line too long");
            self.reset_command();
            self.state = State::Resync;
            return;
        }
        let buf = if self.fresh_command {
            &mut self.tag
        } else {
            &mut self.rest
        };
        buf.push(b);
        self.typed_bytes += 1;
    }

    /// CRLF confirmed while in `Tag` or `Rest` — decide whether the line is
    /// a bare tag-only command, opens a literal, or completes a command.
    fn on_crlf(&mut self) {
        // Bare tag-only line (e.g. IDLE's "DONE", sent without a tag).
        if self.fresh_command && !self.tag.is_empty() {
            let verb = String::from_utf8_lossy(&self.tag).to_ascii_uppercase();
            self.tag.clear();
            self.rest.clear();
            self.typed_bytes = 0;
            self.ready.push(LexEvent::Command(ImapCommand {
                tag: "*".to_string(),
                verb,
                args: String::new(),
                arg_bytes: Vec::new(),
            }));
            self.state = State::Tag;
            return;
        }

        if let Some((n, non_sync)) = trailing_literal(&self.rest) {
            if n > MAX_LITERAL_SIZE {
                self.emit_error("Literal too large");
                self.reset_command();
                self.state = State::Tag;
                return;
            }
            // LITERAL- (RFC 7888): non-synchronizing literals larger than 4 KiB are rejected;
            // clients must use a synchronizing literal instead for anything bigger.
            if non_sync && n > LITERAL_MINUS_LIMIT {
                self.emit_error("Non-synchronizing literal too large (LITERAL-)");
                self.reset_command();
                self.state = State::Tag;
                return;
            }
            // Strip `{n[+]}` from rest; the literal's bytes are spliced back
            // on once complete.
            if let Some(open) = self.rest.iter().rposition(|&b| b == b'{') {
                self.rest.truncate(open);
            }
            // APPEND body literal: verb APPEND and this is the final arg literal.
            if is_append_body_literal(&self.rest) {
                self.append_body.clear();
                self.append_complete = false;
                self.literal = LiteralPhase::Append { remaining: n };
            } else {
                self.literal_buf.clear();
                self.literal = LiteralPhase::General { remaining: n };
            }
            if !non_sync {
                self.ready.push(LexEvent::NeedContinuation);
            }
            self.typed_bytes = 0;
            self.state = State::Literal;
            return;
        }

        self.finish_command();
        self.state = State::Tag;
    }

    fn emit_error(&mut self, message: &str) {
        let tag = if self.tag.is_empty() {
            "*".to_string()
        } else {
            String::from_utf8_lossy(&self.tag).into_owned()
        };
        self.ready.push(LexEvent::Error {
            tag,
            message: message.to_string(),
        });
    }

    fn reset_command(&mut self) {
        self.tag.clear();
        self.rest.clear();
        self.fresh_command = true;
        self.typed_bytes = 0;
        self.literal = LiteralPhase::None;
        self.literal_buf.clear();
    }

    fn finish_command(&mut self) {
        let tag = std::mem::take(&mut self.tag);
        let rest = std::mem::take(&mut self.rest);
        self.fresh_command = true;
        self.typed_bytes = 0;
        if tag.is_empty() {
            return;
        }
        let (verb, arg_bytes) = split_verb(&rest);
        self.ready.push(LexEvent::Command(ImapCommand {
            tag: String::from_utf8_lossy(&tag).into_owned(),
            verb,
            args: String::from_utf8_lossy(&arg_bytes).into_owned(),
            arg_bytes,
        }));
    }
}

/// Detect trailing `{n}` / `{n+}` on the current rest buffer; return size + non_sync.
fn trailing_literal(rest: &[u8]) -> Option<(u64, bool)> {
    if rest.last() != Some(&b'}') {
        return None;
    }
    let open = rest.iter().rposition(|&b| b == b'{')?;
    let inner = &rest[open + 1..rest.len() - 1];
    if inner.is_empty() {
        return None;
    }
    let non_sync = inner.last() == Some(&b'+');
    let digits = if non_sync {
        &inner[..inner.len() - 1]
    } else {
        inner
    };
    if digits.is_empty() || !digits.iter().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u64 = std::str::from_utf8(digits).ok()?.parse().ok()?;
    Some((n, non_sync))
}

fn split_verb(args: &[u8]) -> (String, Vec<u8>) {
    let s = String::from_utf8_lossy(args);
    let s = s.trim_start();
    if s.is_empty() {
        return (String::new(), Vec::new());
    }
    let mut end = 0;
    for (i, b) in s.bytes().enumerate() {
        if b == b' ' {
            end = i;
            break;
        }
        end = i + 1;
    }
    let verb = s[..end].to_ascii_uppercase();
    let rest = s[end..].trim_start().as_bytes().to_vec();
    // Prefer original bytes for rest when ASCII.
    let rest = if args.is_empty() {
        rest
    } else {
        // Re-derive from original arg_bytes for binary fidelity after verb.
        let raw = String::from_utf8_lossy(args);
        let trimmed = raw.trim_start();
        let vlen = verb.len();
        let after = if trimmed.len() >= vlen {
            trimmed[vlen..].trim_start()
        } else {
            ""
        };
        after.as_bytes().to_vec()
    };
    (verb, rest)
}

fn is_append_body_literal(args_without_literal: &[u8]) -> bool {
    let s = String::from_utf8_lossy(args_without_literal);
    let t = s.trim_start();
    t.len() >= 6 && t[..6].eq_ignore_ascii_case("APPEND")
}

/// Parse an IMAP astring (atom / quoted) from the start of `s`.
pub fn parse_astring(s: &str) -> Result<(String, &str), String> {
    let s = s.trim_start();
    if s.is_empty() {
        return Err("expected astring".into());
    }
    if s.as_bytes()[0] == b'"' {
        return parse_quoted(s);
    }
    // Atom
    let mut end = 0;
    for (i, b) in s.bytes().enumerate() {
        if matches!(
            b,
            b'(' | b')' | b'{' | b' ' | b'"' | b'\\' | b']' | b'%' | b'*'
        ) || !b.is_ascii_graphic()
        {
            break;
        }
        end = i + 1;
    }
    if end == 0 {
        return Err("expected astring".into());
    }
    Ok((s[..end].to_string(), s[end..].trim_start()))
}

fn parse_quoted(s: &str) -> Result<(String, &str), String> {
    let bytes = s.as_bytes();
    if bytes.first() != Some(&b'"') {
        return Err("expected quoted".into());
    }
    let mut out = String::new();
    let mut i = 1;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            return Ok((out, s[i + 1..].trim_start()));
        }
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            out.push(bytes[i + 1] as char);
            i += 2;
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    Err("unterminated quoted string".into())
}

/// Parse a parenthesized flag list `(...)`.
pub fn parse_flag_list(s: &str) -> Result<(BTreeSetFlags, &str), String> {
    let s = s.trim_start();
    if !s.starts_with('(') {
        return Err("expected flag list".into());
    }
    let end = s.find(')').ok_or("unclosed flag list")?;
    let inner = &s[1..end];
    let mut flags = std::collections::BTreeSet::new();
    let mut keywords = std::collections::BTreeSet::new();
    for tok in inner.split_whitespace() {
        if let Some(f) = Flag::parse(tok) {
            if f != Flag::Recent {
                flags.insert(f);
            }
        } else {
            keywords.insert(tok.trim_start_matches('\\').to_string());
        }
    }
    Ok((BTreeSetFlags { flags, keywords }, s[end + 1..].trim_start()))
}

/// Parsed system flags + keywords.
#[derive(Clone, Debug, Default)]
pub struct BTreeSetFlags {
    /// System flags.
    pub flags: std::collections::BTreeSet<Flag>,
    /// User keywords.
    pub keywords: std::collections::BTreeSet<String>,
}

/// Parse STORE data item name into action + silent.
pub fn parse_store_item(name: &str) -> Result<(StoreAction, bool), String> {
    let u = name.to_ascii_uppercase();
    Ok(match u.as_str() {
        "FLAGS" => (StoreAction::Replace, false),
        "FLAGS.SILENT" => (StoreAction::Replace, true),
        "+FLAGS" => (StoreAction::Add, false),
        "+FLAGS.SILENT" => (StoreAction::Add, true),
        "-FLAGS" => (StoreAction::Remove, false),
        "-FLAGS.SILENT" => (StoreAction::Remove, true),
        _ => return Err(format!("bad STORE item: {name}")),
    })
}

/// Parse a sequence-set token.
pub fn parse_sequence_set(s: &str) -> Result<(MessageSet, &str), String> {
    let s = s.trim_start();
    let mut end = 0;
    for (i, b) in s.bytes().enumerate() {
        if b.is_ascii_digit() || b == b'*' || b == b':' || b == b',' {
            end = i + 1;
        } else {
            break;
        }
    }
    if end == 0 {
        return Err("expected sequence set".into());
    }
    let set = MessageSet::parse(&s[..end]).map_err(|e| e.to_string())?;
    Ok((set, s[end..].trim_start()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_command() {
        let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"a1 NOOP\r\n";
        let ev = lex.feed(&mut data);
        assert!(data.is_empty());
        assert_eq!(ev.len(), 1);
        match &ev[0] {
            LexEvent::Command(c) => {
                assert_eq!(c.tag, "a1");
                assert_eq!(c.verb, "NOOP");
                assert!(c.args.is_empty());
            }
            _ => panic!("expected command"),
        }
    }

    #[test]
    fn parse_login() {
        let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"a1 LOGIN alice secret\r\n";
        let ev = lex.feed(&mut data);
        match &ev[0] {
            LexEvent::Command(c) => {
                assert_eq!(c.verb, "LOGIN");
                assert_eq!(c.args, "alice secret");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn non_sync_literal() {
        let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"a1 LOGIN {5+}\r\nalice secret\r\n";
        let ev = lex.feed(&mut data);
        assert!(data.is_empty());
        let cmds: Vec<_> = ev
            .into_iter()
            .filter_map(|e| match e {
                LexEvent::Command(c) => Some(c),
                _ => None,
            })
            .collect();
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].verb, "LOGIN");
        assert_eq!(cmds[0].args, "alice secret");
        let mut data2: &[u8] = b"a2 CAPABILITY\r\n";
        let ev2 = lex.feed(&mut data2);
        assert!(matches!(ev2[0], LexEvent::Command(_)));
    }

    #[test]
    fn sync_literal_needs_continuation() {
        let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"a1 LOGIN {5}\r\n";
        let ev = lex.feed(&mut data);
        assert!(matches!(ev[0], LexEvent::NeedContinuation));
        let mut lit: &[u8] = b"alice secret\r\n";
        let ev2 = lex.feed(&mut lit);
        let cmds: Vec<_> = ev2
            .into_iter()
            .filter_map(|e| match e {
                LexEvent::Command(c) => Some(c),
                LexEvent::NeedContinuation => None,
                LexEvent::Error { .. } => None,
            })
            .collect();
        assert!(!cmds.is_empty());
        assert_eq!(cmds[0].verb, "LOGIN");
        assert_eq!(cmds[0].args, "alice secret");
    }

    #[test]
    fn literal_split_across_many_feeds() {
        // The literal's bytes arrive one at a time across many feed() calls,
        // proving bulk-vs-dribbled delivery is equivalent and nothing is
        // ever retained by the caller.
        let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
        let msg: &[u8] = b"a1 LOGIN {5}\r\nalice secret\r\n";
        let mut events = Vec::new();
        for &b in msg {
            let mut one: &[u8] = &[b];
            events.extend(lex.feed(&mut one));
            assert!(one.is_empty());
        }
        let cmds: Vec<_> = events
            .into_iter()
            .filter_map(|e| match e {
                LexEvent::Command(c) => Some(c),
                _ => None,
            })
            .collect();
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].verb, "LOGIN");
        assert_eq!(cmds[0].args, "alice secret");
    }

    #[test]
    fn append_literal_streams_and_finishes_command() {
        let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"a1 APPEND INBOX {5}\r\nhello\r\n";
        let ev = lex.feed(&mut data);
        assert!(data.is_empty());
        assert!(matches!(ev[0], LexEvent::NeedContinuation));
        let cmds: Vec<_> = ev
            .into_iter()
            .filter_map(|e| match e {
                LexEvent::Command(c) => Some(c),
                _ => None,
            })
            .collect();
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].verb, "APPEND");
        let body = lex.take_append_body().expect("append body");
        assert_eq!(body, b"hello");
    }

    #[test]
    fn in_literal_reports_mid_literal_state() {
        let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"a1 LOGIN {5+}\r\nal";
        let _ = lex.feed(&mut data);
        assert!(lex.in_literal());
        let mut rest: &[u8] = b"ice secret\r\n";
        let _ = lex.feed(&mut rest);
        assert!(!lex.in_literal());
    }

    #[test]
    fn oversized_literal_rejected() {
        let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
        let line = format!("a1 LOGIN {{{}}}\r\n", MAX_LITERAL_SIZE + 1);
        let mut data: &[u8] = line.as_bytes();
        let ev = lex.feed(&mut data);
        assert!(matches!(
            &ev[0],
            LexEvent::Error { tag, message } if tag == "a1" && message == "Literal too large"
        ));
    }

    #[test]
    fn sync_literal_over_literal_minus_limit_accepted() {
        // Synchronizing literals (`{n}`) have no LITERAL- cap of their own -
        // they're only bounded by MAX_LITERAL_SIZE - so a size above
        // LITERAL_MINUS_LIMIT must still be accepted, prompting a
        // continuation request rather than an error.
        let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
        let n = LITERAL_MINUS_LIMIT + 1;
        assert!(n < MAX_LITERAL_SIZE);
        let line = format!("a1 LOGIN {{{n}}}\r\n");
        let mut data: &[u8] = line.as_bytes();
        let ev = lex.feed(&mut data);
        assert!(matches!(ev[0], LexEvent::NeedContinuation));
    }

    #[test]
    fn oversized_non_sync_literal_over_literal_minus_limit_rejected() {
        // Non-synchronizing literals (`{n+}`) above LITERAL_MINUS_LIMIT are
        // exactly what RFC 7888 forbids: the client would send the bytes
        // without giving the server a chance to reject first.
        let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
        let n = LITERAL_MINUS_LIMIT + 1;
        let line = format!("a1 LOGIN {{{n}+}}\r\n");
        let mut data: &[u8] = line.as_bytes();
        let ev = lex.feed(&mut data);
        assert!(matches!(
            &ev[0],
            LexEvent::Error { tag, message } if tag == "a1" && message == "Non-synchronizing literal too large (LITERAL-)"
        ));
    }

    #[test]
    fn pipelined_commands() {
        let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"a1 NOOP\r\na2 CAPABILITY\r\n";
        let ev = lex.feed(&mut data);
        assert_eq!(ev.len(), 2);
    }

    #[test]
    fn split_buffers() {
        let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
        let mut a: &[u8] = b"a1 NO";
        assert!(lex.feed(&mut a).is_empty());
        let mut b: &[u8] = b"OP\r\n";
        let ev = lex.feed(&mut b);
        match &ev[0] {
            LexEvent::Command(c) => assert_eq!(c.verb, "NOOP"),
            _ => panic!(),
        }
    }

    #[test]
    fn bare_tag_only_line_is_idle_done() {
        let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"DONE\r\n";
        let ev = lex.feed(&mut data);
        match &ev[0] {
            LexEvent::Command(c) => {
                assert_eq!(c.tag, "*");
                assert_eq!(c.verb, "DONE");
                assert!(c.args.is_empty());
            }
            _ => panic!("expected command"),
        }
    }

    #[test]
    fn blank_line_produces_no_command() {
        let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"\r\na1 NOOP\r\n";
        let ev = lex.feed(&mut data);
        assert_eq!(ev.len(), 1);
        assert!(matches!(&ev[0], LexEvent::Command(c) if c.verb == "NOOP"));
    }

    #[test]
    fn oversized_tag_discards_and_resyncs() {
        let mut lex = ImapServerLexer::new(4);
        let mut data: &[u8] = b"toolongtag NOOP\r\na2 NOOP\r\n";
        let ev = lex.feed(&mut data);
        let cmds: Vec<_> = ev
            .into_iter()
            .filter_map(|e| match e {
                LexEvent::Command(c) => Some(c),
                _ => None,
            })
            .collect();
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].tag, "a2");
    }

    #[test]
    fn literal_cr_not_followed_by_lf_is_content() {
        let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"a1 LOGIN a\rb\r\n";
        let ev = lex.feed(&mut data);
        match &ev[0] {
            LexEvent::Command(c) => {
                assert_eq!(c.verb, "LOGIN");
                assert_eq!(c.args, "a\rb");
            }
            _ => panic!(),
        }
    }

    /// One byte per `feed()` call must produce identical commands to a
    /// single bulk feed, and never leave anything unconsumed.
    #[test]
    fn one_byte_at_a_time_matches_bulk_feed() {
        let msg: &[u8] = b"a1 LOGIN alice secret\r\na2 CAPABILITY\r\na3 LOGOUT\r\n";

        let mut bulk = ImapServerLexer::new(MAX_COMMAND_LINE);
        let mut bulk_data = msg;
        let bulk_ev = bulk.feed(&mut bulk_data);
        let bulk_cmds: Vec<_> = bulk_ev
            .into_iter()
            .filter_map(|e| match e {
                LexEvent::Command(c) => Some(c),
                _ => None,
            })
            .collect();

        let mut drip = ImapServerLexer::new(MAX_COMMAND_LINE);
        let mut drip_cmds = Vec::new();
        for &b in msg {
            let mut one: &[u8] = &[b];
            let ev = drip.feed(&mut one);
            assert!(one.is_empty());
            drip_cmds.extend(ev.into_iter().filter_map(|e| match e {
                LexEvent::Command(c) => Some(c),
                _ => None,
            }));
        }

        assert_eq!(bulk_cmds, drip_cmds);
        assert_eq!(bulk_cmds.len(), 3);
    }

    /// Every split point of a full command stream (including one with a
    /// literal) must be equivalent.
    #[test]
    fn all_split_points_are_equivalent() {
        let msg: &[u8] = b"a1 LOGIN {5}\r\nalice secret\r\na2 CAPABILITY\r\na3 LOGOUT\r\n";
        let mut base = ImapServerLexer::new(MAX_COMMAND_LINE);
        let mut base_data = msg;
        let base_ev = base.feed(&mut base_data);
        let base_cmds: Vec<_> = base_ev
            .into_iter()
            .filter_map(|e| match e {
                LexEvent::Command(c) => Some(c),
                _ => None,
            })
            .collect();

        for split in 1..msg.len() {
            let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
            let mut a: &[u8] = &msg[..split];
            let mut ev = lex.feed(&mut a);
            assert!(a.is_empty(), "split {split} retained bytes");
            let mut b: &[u8] = &msg[split..];
            ev.extend(lex.feed(&mut b));
            assert!(b.is_empty(), "split {split} retained bytes");
            let cmds: Vec<_> = ev
                .into_iter()
                .filter_map(|e| match e {
                    LexEvent::Command(c) => Some(c),
                    _ => None,
                })
                .collect();
            assert_eq!(cmds, base_cmds, "split {split} diverged");
        }
    }

    #[test]
    fn sequence_set_parse() {
        let (set, rest) = parse_sequence_set("1:5,7 UID").unwrap();
        assert!(set.contains(3, 20));
        assert_eq!(rest, "UID");
    }

    #[test]
    fn store_item() {
        assert_eq!(
            parse_store_item("+FLAGS.SILENT").unwrap(),
            (StoreAction::Add, true)
        );
    }

    #[test]
    fn state_gating_helpers() {
        // Verb extraction
        let (v, r) = split_verb(b"SELECT INBOX");
        assert_eq!(v, "SELECT");
        assert_eq!(String::from_utf8_lossy(&r), "INBOX");
    }
}
