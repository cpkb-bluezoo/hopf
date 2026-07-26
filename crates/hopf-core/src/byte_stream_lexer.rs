// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Shared streaming byte-to-token lexer (Gumdrop `ByteStreamLexer`).
//!
//! Used by line-oriented protocols (HTTP, SMTP, IMAP, POP3, FTP, …). Protocol
//! crates implement [`ByteStreamScanner`] (`consume`) and
//! [`ByteStreamHandler`] (token / raw callbacks). This module owns modes
//! (structured / text / raw), the token-length cap, CRLF text latching, and
//! the compact/rewind buffer contract.
//!
//! # Buffer contract
//!
//! [`ByteStreamLexer::feed`] takes `&mut &[u8]`. Token and raw windows are
//! zero-copy views valid **only for the duration of the handler callback**.
//! After `feed` returns, `*data` is the unconsumed suffix (start of an
//! incomplete structured token, or empty). The transport must compact /
//! await more bytes — same NIO contract as Gumdrop.
//!
//! Do **not** put protocol-specific line buffering here. Incomplete tokens
//! stay in the caller's slice via rewind; handlers that need retention must
//! copy during the callback.

use std::cmp::min;

/// Control returned from handler callbacks (Gumdrop post-token / post-raw hooks).
///
/// Lets protocol parsers request [`ByteStreamLexer::enter_raw`] or a handoff
/// stop without holding a mutable borrow of the lexer during the callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandlerControl {
    /// Keep scanning under the current mode rules.
    Continue,
    /// Latch text mode until the next CRLF token (structured tokens only).
    LatchText,
    /// Deliver the next `n` bytes via [`ByteStreamHandler::raw_bytes`].
    EnterRaw(u64),
    /// Stop this `feed`; outer receive takes over (until-close body, H2, …).
    Stop,
}

/// Receives lexed tokens and raw escapes.
pub trait ByteStreamHandler {
    /// Protocol-specific token discriminant.
    type Token: Copy + PartialEq;

    /// A complete structured token or text chunk.
    fn token(&mut self, ty: Self::Token, window: &[u8]) -> HandlerControl;

    /// Raw bytes during [`ByteStreamLexer::enter_raw`].
    ///
    /// Default: [`HandlerControl::Continue`]. Override when a raw phase
    /// completion must immediately start another raw phase or stop.
    fn raw_bytes(&mut self, slice: &[u8]) -> HandlerControl {
        let _ = slice;
        HandlerControl::Continue
    }

    /// Structured token exceeded `max_token_length` before completing.
    fn token_too_long(&mut self);
}

/// Result of one [`ByteStreamScanner::consume`] call.
#[derive(Debug)]
pub enum ScanAction<T: Copy> {
    /// Keep scanning structured tokens.
    Continue,
    /// Abort `feed` (not a token-cap violation).
    Abort,
    /// Emit token over `[start, end)` of the current `feed` base buffer.
    Emit {
        /// Token type.
        token: T,
        /// Inclusive start index into the `feed` base slice.
        start: usize,
        /// Exclusive end index (typically [`ByteStreamLexer::current_position`]).
        end: usize,
    },
}

/// Per-byte structured scanning (Gumdrop subclass `consume`).
pub trait ByteStreamScanner {
    /// Protocol token type.
    type Token: Copy + PartialEq;

    /// One byte of structured input.
    ///
    /// `position` is one past this byte within the current `feed` base.
    /// `region_start` is the start of the in-progress token (replay-safe).
    fn consume(&mut self, b: u8, position: usize, region_start: usize) -> ScanAction<Self::Token>;

    /// Reset scanner state when the lexer resets / after a completed token
    /// if needed. Default no-op.
    fn reset(&mut self) {}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Token,
    RawFixed,
    Text,
    Stopped,
}

/// Shared lexer used by all line-oriented protocol scanners.
pub struct ByteStreamLexer<S, H>
where
    S: ByteStreamScanner,
    H: ByteStreamHandler<Token = S::Token>,
{
    scanner: S,
    handler: H,
    max_token_length: usize,
    crlf_token: S::Token,
    text_token: S::Token,
    mode: Mode,
    region_start: usize,
    /// One past last consumed byte within the current `feed` base.
    position: usize,
    raw_remaining: u64,
    /// Bytes of the in-progress `Mode::Token` token already fed through
    /// `scanner.consume()` in a previous `feed` call. Callers always retain
    /// an incomplete token's bytes at the front of the buffer they pass in
    /// (see the buffer contract above), so on the next call those bytes are
    /// at `base[0..resume_len]` again — resuming here instead of
    /// re-scanning from 0 keeps `feed` from re-visiting the same byte once
    /// per call as a token accumulates across many small reads.
    resume_len: usize,
}

impl<S, H> ByteStreamLexer<S, H>
where
    S: ByteStreamScanner,
    H: ByteStreamHandler<Token = S::Token>,
{
    /// Create a lexer.
    ///
    /// `crlf_token` / `text_token` match Gumdrop's constructor: CRLF ends
    /// text mode; `text_token` is used for free-form chunks.
    pub fn new(
        scanner: S,
        handler: H,
        max_token_length: usize,
        crlf_token: S::Token,
        text_token: S::Token,
    ) -> Self {
        assert!(max_token_length > 0);
        Self {
            scanner,
            handler,
            max_token_length,
            crlf_token,
            text_token,
            mode: Mode::Token,
            region_start: 0,
            position: 0,
            raw_remaining: 0,
            resume_len: 0,
        }
    }

    /// Assert the token cap can fit under the transport receive ceiling.
    pub fn check_token_cap(max_token_length: usize, max_net_in_size: usize) {
        assert!(
            max_token_length <= max_net_in_size,
            "max_token_length ({max_token_length}) exceeds max_net_in_size ({max_net_in_size})"
        );
    }

    /// Immutable access to the handler.
    pub fn handler(&self) -> &H {
        &self.handler
    }

    /// Handler (protocol parser / connection sink).
    pub fn handler_mut(&mut self) -> &mut H {
        &mut self.handler
    }

    /// Scanner (protocol-specific `consume` state).
    pub fn scanner_mut(&mut self) -> &mut S {
        &mut self.scanner
    }

    /// Start of the in-progress structured token.
    pub fn region_start(&self) -> usize {
        self.region_start
    }

    /// One past the byte most recently consumed.
    pub fn current_position(&self) -> usize {
        self.position
    }

    /// Deliver exactly `n` bytes to [`ByteStreamHandler::raw_bytes`] without
    /// tokenising; then resume structured scanning (same `feed` if data remains).
    pub fn enter_raw(&mut self, n: u64) {
        self.raw_remaining = n;
        self.mode = Mode::RawFixed;
    }

    /// Stop after the current callback; next `feed` resumes TOKEN mode.
    pub fn request_stop(&mut self) {
        self.mode = Mode::Stopped;
    }

    /// Reset modes and scanner (new connection / message unit).
    pub fn reset(&mut self) {
        self.mode = Mode::Token;
        self.region_start = 0;
        self.position = 0;
        self.raw_remaining = 0;
        self.resume_len = 0;
        self.scanner.reset();
    }

    /// Feed bytes. Advances `data` past consumed input; rewinds incomplete tokens.
    pub fn feed(&mut self, data: &mut &[u8]) {
        let base = *data;
        let mut idx = 0usize;
        if self.mode == Mode::Token {
            // Resume an in-progress token at the point we left off, rather
            // than re-running `consume()` over bytes already scanned in an
            // earlier `feed` call — see `resume_len`'s doc comment.
            debug_assert!(self.resume_len <= base.len());
            idx = self.resume_len.min(base.len());
            self.region_start = 0;
            self.position = idx;
        }
        self.resume_len = 0;
        let mut cont = true;
        while cont && idx < base.len() {
            match self.mode {
                Mode::Stopped => {
                    self.mode = Mode::Token;
                    *data = &base[idx..];
                    return;
                }
                Mode::RawFixed => cont = self.continue_raw_fixed(base, &mut idx),
                Mode::Text => cont = self.continue_text(base, &mut idx),
                Mode::Token => {
                    cont = self.scan_tokens(base, &mut idx);
                }
            }
        }
        if self.mode == Mode::Stopped {
            self.mode = Mode::Token;
        }
        if self.mode == Mode::Token && idx == self.region_start && idx < base.len() {
            // scan_tokens rewound idx to region_start for incomplete token
            *data = &base[self.region_start..];
        } else {
            *data = &base[idx..];
        }
    }

    fn scan_tokens(&mut self, base: &[u8], idx: &mut usize) -> bool {
        while *idx < base.len() {
            let b = base[*idx];
            *idx += 1;
            self.position = *idx;
            let action = self
                .scanner
                .consume(b, self.position, self.region_start);
            match action {
                ScanAction::Abort => return false,
                ScanAction::Continue => {
                    if self.mode != Mode::Token {
                        return true;
                    }
                    if self.position - self.region_start > self.max_token_length {
                        self.handler.token_too_long();
                        return false;
                    }
                }
                ScanAction::Emit { token, start, end } => {
                    let ctrl = self.dispatch_token(base, token, start, end);
                    self.region_start = end;
                    *idx = end;
                    self.position = end;
                    if self.apply_control(ctrl, token) {
                        return true;
                    }
                }
            }
        }
        // Not enough data for the next token boundary yet (or we just
        // finished one exactly at the end of `base`, in which case this is
        // 0). Remember how far into it we've scanned so the next `feed`
        // call resumes here instead of re-scanning, then rewind `idx` for
        // the caller-facing "unconsumed" slice below — that part of the
        // contract is unchanged.
        self.resume_len = *idx - self.region_start;
        *idx = self.region_start;
        false
    }

    /// Apply handler control. Returns true if the outer feed loop should
    /// continue with a (possibly new) mode.
    fn apply_control(&mut self, ctrl: HandlerControl, token: S::Token) -> bool {
        match ctrl {
            HandlerControl::Continue => {
                if token == self.crlf_token {
                    self.mode = Mode::Token;
                }
                self.mode != Mode::Token
            }
            HandlerControl::LatchText => {
                if token == self.crlf_token {
                    // CRLF never latches text.
                    self.mode = Mode::Token;
                    false
                } else {
                    self.mode = Mode::Text;
                    true
                }
            }
            HandlerControl::EnterRaw(n) => {
                self.enter_raw(n);
                true
            }
            HandlerControl::Stop => {
                self.mode = Mode::Stopped;
                true
            }
        }
    }

    fn dispatch_token(&mut self, base: &[u8], ty: S::Token, start: usize, end: usize) -> HandlerControl {
        debug_assert!(start <= end && end <= base.len());
        self.handler.token(ty, &base[start..end])
    }

    fn continue_text(&mut self, base: &[u8], idx: &mut usize) -> bool {
        let start = *idx;
        let mut last = 0u8;
        while *idx < base.len() {
            let c = base[*idx];
            *idx += 1;
            if c == b'\n' && last == b'\r' {
                let cr_start = *idx - 2;
                if cr_start > start {
                    let ctrl = self.dispatch_token(base, self.text_token, start, cr_start);
                    if matches!(ctrl, HandlerControl::EnterRaw(_) | HandlerControl::Stop) {
                        self.region_start = cr_start;
                        *idx = cr_start;
                        return self.apply_control(ctrl, self.text_token);
                    }
                }
                let ctrl = self.dispatch_token(base, self.crlf_token, cr_start, *idx);
                self.region_start = *idx;
                self.mode = Mode::Token;
                // Fresh token boundary — any resume position from earlier
                // in this same `feed` call (before Text mode) is stale now.
                self.resume_len = 0;
                // Always continue the outer feed loop after leaving text mode.
                let _ = self.apply_control(ctrl, self.crlf_token);
                return true;
            }
            last = c;
        }
        let mut flush_end = *idx;
        if last == b'\r' {
            flush_end -= 1;
            *idx = flush_end;
        }
        if flush_end > start {
            let ctrl = self.dispatch_token(base, self.text_token, start, flush_end);
            if matches!(ctrl, HandlerControl::EnterRaw(_) | HandlerControl::Stop) {
                return self.apply_control(ctrl, self.text_token);
            }
        }
        false
    }

    fn continue_raw_fixed(&mut self, base: &[u8], idx: &mut usize) -> bool {
        while self.raw_remaining > 0 && *idx < base.len() {
            let available = min(self.raw_remaining as usize, base.len() - *idx);
            let end = *idx + available;
            let ctrl = self.handler.raw_bytes(&base[*idx..end]);
            *idx = end;
            self.raw_remaining -= available as u64;
            match ctrl {
                HandlerControl::Continue | HandlerControl::LatchText => {}
                HandlerControl::EnterRaw(n) => {
                    // Replace or chain raw phase from mid-delivery.
                    self.raw_remaining = n;
                    self.mode = Mode::RawFixed;
                    return true;
                }
                HandlerControl::Stop => {
                    self.mode = Mode::Stopped;
                    return true;
                }
            }
        }
        if self.raw_remaining > 0 {
            return false;
        }
        self.mode = Mode::Token;
        self.region_start = *idx;
        // Fresh token boundary — see the matching comment in `continue_text`.
        self.resume_len = 0;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Tok {
        Line,
        Text,
    }

    struct LineScan {
        last_was_cr: bool,
    }

    impl ByteStreamScanner for LineScan {
        type Token = Tok;

        fn consume(&mut self, b: u8, position: usize, region_start: usize) -> ScanAction<Tok> {
            if b == b'\n' && self.last_was_cr {
                self.last_was_cr = false;
                return ScanAction::Emit {
                    token: Tok::Line,
                    start: region_start,
                    end: position,
                };
            }
            self.last_was_cr = b == b'\r';
            ScanAction::Continue
        }

        fn reset(&mut self) {
            self.last_was_cr = false;
        }
    }

    struct Collect {
        lines: Vec<Vec<u8>>,
        raw: Vec<u8>,
        too_long: bool,
    }

    impl ByteStreamHandler for Collect {
        type Token = Tok;

        fn token(&mut self, ty: Tok, window: &[u8]) -> HandlerControl {
            if ty == Tok::Line {
                self.lines.push(window.to_vec());
            }
            HandlerControl::Continue
        }

        fn raw_bytes(&mut self, slice: &[u8]) -> HandlerControl {
            self.raw.extend_from_slice(slice);
            HandlerControl::Continue
        }

        fn token_too_long(&mut self) {
            self.too_long = true;
        }
    }

    fn new_lex() -> ByteStreamLexer<LineScan, Collect> {
        ByteStreamLexer::new(
            LineScan { last_was_cr: false },
            Collect {
                lines: Vec::new(),
                raw: Vec::new(),
                too_long: false,
            },
            8192,
            Tok::Line,
            Tok::Text,
        )
    }

    /// Simulate transport compact: keep unconsumed, append more, feed again.
    fn feed_chunk(lex: &mut ByteStreamLexer<LineScan, Collect>, pending: &mut Vec<u8>, chunk: &[u8]) {
        pending.extend_from_slice(chunk);
        let mut slice = pending.as_slice();
        let before = slice.len();
        lex.feed(&mut slice);
        let consumed = before - slice.len();
        pending.drain(..consumed);
    }

    /// Same grammar as [`LineScan`], but counts `consume()` invocations —
    /// used to prove `feed` doesn't re-scan bytes across calls.
    struct CountingScan {
        last_was_cr: bool,
        calls: usize,
    }

    impl ByteStreamScanner for CountingScan {
        type Token = Tok;

        fn consume(&mut self, b: u8, position: usize, region_start: usize) -> ScanAction<Tok> {
            self.calls += 1;
            if b == b'\n' && self.last_was_cr {
                self.last_was_cr = false;
                return ScanAction::Emit {
                    token: Tok::Line,
                    start: region_start,
                    end: position,
                };
            }
            self.last_was_cr = b == b'\r';
            ScanAction::Continue
        }

        fn reset(&mut self) {
            self.last_was_cr = false;
            self.calls = 0;
        }
    }

    #[test]
    fn feeding_one_byte_at_a_time_scans_each_byte_exactly_once() {
        let mut lex = ByteStreamLexer::new(
            CountingScan {
                last_was_cr: false,
                calls: 0,
            },
            Collect {
                lines: Vec::new(),
                raw: Vec::new(),
                too_long: false,
            },
            8192,
            Tok::Line,
            Tok::Text,
        );
        let mut pending = Vec::new();
        let line: &[u8] = b"a fairly long line that arrives one byte at a time\r\n";
        for &b in line {
            pending.extend_from_slice(&[b]);
            let mut slice = pending.as_slice();
            lex.feed(&mut slice);
            let consumed = pending.len() - slice.len();
            pending.drain(..consumed);
        }
        // Regression guard: before the resume-position fix, an incomplete
        // Token-mode scan restarted from byte 0 on every `feed` call, so
        // this would take O(n^2) `consume()` calls for a line of length n
        // (1,431 for this 53-byte line). Fixed, each byte is scanned
        // exactly once no matter how many separate `feed` calls it
        // straddles.
        assert_eq!(lex.scanner_mut().calls, line.len());
        assert_eq!(lex.handler_mut().lines, vec![line.to_vec()]);
    }

    #[test]
    fn split_crlf_across_feeds() {
        let mut lex = new_lex();
        let mut pending = Vec::new();
        feed_chunk(&mut lex, &mut pending, b"GET / HTTP/1.1\r");
        assert!(lex.handler_mut().lines.is_empty());
        assert_eq!(pending, b"GET / HTTP/1.1\r");

        feed_chunk(&mut lex, &mut pending, b"\nHost: x\r\n");
        assert!(pending.is_empty());
        assert_eq!(lex.handler_mut().lines.len(), 2);
        assert_eq!(lex.handler_mut().lines[0], b"GET / HTTP/1.1\r\n");
        assert_eq!(lex.handler_mut().lines[1], b"Host: x\r\n");
    }

    #[test]
    fn enter_raw_delivers_bytes() {
        let mut lex = new_lex();
        let mut data: &[u8] = b"abcdREST";
        lex.enter_raw(4);
        lex.feed(&mut data);
        assert_eq!(lex.handler_mut().raw, b"abcd");
        assert_eq!(data, b"REST");
    }

    #[test]
    fn one_byte_feeds_emit_line() {
        let mut lex = new_lex();
        let mut pending = Vec::new();
        for &b in b"OK\r\n" {
            feed_chunk(&mut lex, &mut pending, &[b]);
        }
        assert!(pending.is_empty());
        assert_eq!(lex.handler_mut().lines.len(), 1);
        assert_eq!(lex.handler_mut().lines[0], b"OK\r\n");
    }
}
