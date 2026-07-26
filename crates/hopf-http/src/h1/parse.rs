// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Incremental HTTP/1.x line scanner emitting HTTP's own token vocabulary.
//!
//! # Contract
//!
//! [`H1Scanner::push`] **consumes every byte it is given** and returns
//! nothing to retain. A token split across chunk boundaries is accumulated
//! in the scanner's own bounded scratch buffer, and the corresponding event
//! fires the moment the token is complete — not when the line is complete,
//! and never by asking the caller to re-supply earlier bytes.
//!
//! ```text
//! "GET /this_is_my/resource.ht"   -> method("GET")
//! "ml HTTP/1"                     -> request_target("/this_is_my/resource.html")
//! ".1\r\nUser-Agent: blogho"      -> http_version("HTTP/1.1"), request_line_end(),
//!                                    header_name("User-Agent")
//! "ti 1.1\r"                      -> (value still accumulating)
//! "\n\r\n"                        -> header_value("bloghoti 1.1"), headers_end()
//! ```
//!
//! Body bytes are never buffered at all — [`H1Events::body_data`] receives
//! borrowed slices straight out of the caller's buffer, however the chunk
//! boundaries happen to fall.

use crate::version::HttpVersion;

/// Longest header value assembled from obs-fold continuation lines.
///
/// Each individual line is already bounded by the caller's `max_token`; this
/// caps the total after folding so a long run of continuations can't grow
/// without limit.
const MAX_FOLDED_VALUE: usize = 64 * 1024;

/// What the scanner should do with the bytes that follow an event.
///
/// Returned by every [`H1Events`] callback, so the protocol driver steers
/// the scanner as each production completes (a header block can be followed
/// by a counted body, a chunked body, or the next message — only the driver
/// knows which).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    /// Keep scanning under the current mode.
    Continue,
    /// Scan the first line of a new message.
    FirstLine,
    /// Scan field-lines (headers or trailers).
    Fields,
    /// Scan a chunk-size line.
    ChunkSize,
    /// Deliver exactly `n` bytes via [`H1Events::body_data`], then
    /// [`H1Events::body_end`].
    Body(u64),
    /// Deliver exactly `n` bytes of chunk data, consume the mandatory CRLF
    /// that follows it, then [`H1Events::chunk_end`].
    ChunkBody(u64),
    /// Deliver everything that arrives via [`H1Events::body_data`] until the
    /// connection closes (HTTP/1.0 response-until-close).
    UntilClose,
    /// Stop scanning. Remaining bytes in this push are left for the caller
    /// (protocol upgrade), and the scanner does nothing further.
    Stop,
}

/// Which grammar the first line of a message follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirstLineKind {
    /// `method SP request-target SP HTTP-version CRLF`
    Request,
    /// `HTTP-version SP status-code SP [reason-phrase] CRLF`
    Status,
}

/// Semantic events emitted by [`H1Scanner`].
///
/// Every `&[u8]` is valid only for the duration of the call. Implementations
/// that need to retain a value must copy it.
pub trait H1Events {
    /// Request-line method (`Request` mode only).
    fn method(&mut self, value: &[u8]) -> Next;
    /// Request-line target (`Request` mode only).
    fn request_target(&mut self, value: &[u8]) -> Next;
    /// HTTP-version token from either first-line form.
    fn http_version(&mut self, value: &[u8]) -> Next;
    /// Status-line 3-digit code (`Status` mode only).
    fn status_code(&mut self, value: &[u8]) -> Next;
    /// Status-line reason phrase, possibly empty (`Status` mode only).
    fn reason_phrase(&mut self, value: &[u8]) -> Next;
    /// CRLF ending the first line.
    fn first_line_end(&mut self) -> Next;
    /// Field name, with the `:` seen but not included.
    fn header_name(&mut self, value: &[u8]) -> Next;
    /// Complete field value, obs-fold continuations already joined, outer
    /// whitespace already trimmed.
    fn header_value(&mut self, value: &[u8]) -> Next;
    /// Empty line ending the field block.
    fn headers_end(&mut self) -> Next;
    /// Complete chunk-size line including any `;ext` (CRLF not included).
    fn chunk_size_line(&mut self, value: &[u8]) -> Next;
    /// Body bytes, borrowed from the caller's buffer.
    fn body_data(&mut self, value: &[u8]) -> Next;
    /// A counted body has delivered its final byte.
    fn body_end(&mut self) -> Next;
    /// A chunk's data and its trailing CRLF have been consumed.
    fn chunk_end(&mut self) -> Next;
    /// A token exceeded `max_token` (or a folded value exceeded the internal cap).
    fn too_long(&mut self) -> Next;
    /// Malformed input; `what` is a short static description.
    fn bad_syntax(&mut self, what: &'static str) -> Next;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// First token of the first line (method, or version for a status line).
    FirstTok,
    /// Second token (request-target, or status code).
    SecondTok,
    /// Third token: version (request) — ends at CR.
    ThirdTokWord,
    /// Third token: reason phrase (status) — free text to CR.
    ThirdTokText,
    /// Saw CR ending the first line; expect LF.
    FirstLineLf,
    /// Start of a field-line: field-name, obs-fold whitespace, or empty line.
    FieldStart,
    /// Accumulating a field value up to CR.
    FieldValue,
    /// Saw CR in a field value; expect LF.
    FieldValueLf,
    /// Value line ended; one byte of lookahead decides obs-fold vs commit.
    FieldFoldPeek,
    /// Inside an obs-fold: a single SP has been substituted, so skip any
    /// further leading whitespace on the continuation line (RFC 9112 §5.2).
    FieldFoldSkipWs,
    /// Saw CR on an empty field-line; expect LF then the block ends.
    FieldsEndLf,
    /// Accumulating a chunk-size line up to CR.
    ChunkSizeLine,
    /// Saw CR in a chunk-size line; expect LF.
    ChunkSizeLf,
    /// Counted body bytes remaining.
    Body,
    /// Chunk data bytes remaining.
    ChunkBody,
    /// Consuming the CR of a chunk's trailing CRLF.
    ChunkTrailCr,
    /// Consuming the LF of a chunk's trailing CRLF.
    ChunkTrailLf,
    /// Everything through to EOF is body.
    UntilClose,
    /// Scanning halted (upgrade or fatal error).
    Halted,
}

/// Incremental HTTP/1.x scanner.
///
/// Owns all partial-token state; see the module docs for the contract.
pub struct H1Scanner {
    kind: FirstLineKind,
    mode: Mode,
    /// Partial token spanning chunk boundaries. Empty whenever the current
    /// token happens to be fully contained in the chunk being scanned, which
    /// lets the common case emit a borrowed slice with no copy.
    scratch: Vec<u8>,
    /// Field value under construction, including joined obs-fold lines.
    value: Vec<u8>,
    /// Bytes still to deliver for the current counted/chunk body.
    remaining: u64,
    max_token: usize,
}

impl H1Scanner {
    /// Create a scanner. `max_token` caps any single line/token.
    pub fn new(kind: FirstLineKind, max_token: usize) -> Self {
        Self {
            kind,
            mode: Mode::FirstTok,
            scratch: Vec::new(),
            value: Vec::new(),
            remaining: 0,
            max_token,
        }
    }

    /// Reset to the start of a new message, keeping configuration.
    pub fn reset(&mut self) {
        self.mode = Mode::FirstTok;
        self.scratch.clear();
        self.value.clear();
        self.remaining = 0;
    }

    /// True once scanning has halted (upgrade or fatal error).
    pub fn is_halted(&self) -> bool {
        self.mode == Mode::Halted
    }

    /// True when positioned at the very start of a message with nothing
    /// buffered — i.e. a clean point at which EOF is not a truncation.
    pub fn at_message_start(&self) -> bool {
        self.mode == Mode::FirstTok && self.scratch.is_empty()
    }

    /// True when the scanner is delivering an until-close body.
    pub fn is_until_close(&self) -> bool {
        self.mode == Mode::UntilClose
    }

    /// Apply a driver-requested mode change.
    fn apply(&mut self, next: Next) {
        match next {
            Next::Continue => {}
            Next::FirstLine => {
                self.mode = Mode::FirstTok;
                self.scratch.clear();
                self.value.clear();
            }
            Next::Fields => {
                self.mode = Mode::FieldStart;
                self.scratch.clear();
                self.value.clear();
            }
            Next::ChunkSize => {
                self.mode = Mode::ChunkSizeLine;
                self.scratch.clear();
            }
            Next::Body(n) => {
                if n == 0 {
                    // Caller asked for an empty body; nothing to deliver.
                    self.mode = Mode::Body;
                    self.remaining = 0;
                } else {
                    self.mode = Mode::Body;
                    self.remaining = n;
                }
            }
            Next::ChunkBody(n) => {
                self.remaining = n;
                self.mode = if n == 0 { Mode::ChunkTrailCr } else { Mode::ChunkBody };
            }
            Next::UntilClose => self.mode = Mode::UntilClose,
            Next::Stop => self.mode = Mode::Halted,
        }
    }

    /// Push `data` through the scanner.
    ///
    /// Returns the number of bytes consumed. That is always `data.len()`
    /// unless scanning halted partway (protocol upgrade), in which case the
    /// remainder belongs to whatever takes the connection over.
    pub fn push<E: H1Events + ?Sized>(&mut self, data: &[u8], ev: &mut E) -> usize {
        let mut i = 0usize;
        loop {
            if self.mode == Mode::Halted {
                break;
            }
            // A zero-length counted body completes with no further input, so
            // it must be drained even once the buffer is exhausted.
            let zero_body = self.mode == Mode::Body && self.remaining == 0;
            if i >= data.len() && !zero_body {
                break;
            }
            // A step may legitimately consume nothing when it changes mode in
            // order to re-dispatch the current byte under new rules (ending a
            // header value, leaving an obs-fold). Only a step that consumes
            // nothing *and* leaves the mode unchanged has stalled.
            let before = self.mode;
            let consumed = if zero_body {
                let n = ev.body_end();
                self.apply(n);
                0
            } else {
                self.step(&data[i..], ev)
            };
            i += consumed;
            if consumed == 0 && self.mode == before {
                break;
            }
        }
        i
    }

    /// Scan from the front of `data`, returning bytes consumed.
    fn step<E: H1Events + ?Sized>(&mut self, data: &[u8], ev: &mut E) -> usize {
        match self.mode {
            Mode::Body | Mode::ChunkBody | Mode::UntilClose => self.step_body(data, ev),
            Mode::Halted => 0,
            _ => self.step_line(data, ev),
        }
    }

    /// Bulk body passthrough — never copies, never buffers.
    fn step_body<E: H1Events + ?Sized>(&mut self, data: &[u8], ev: &mut E) -> usize {
        let take = if self.mode == Mode::UntilClose {
            data.len()
        } else {
            (self.remaining as usize).min(data.len())
        };
        if take == 0 {
            // Zero-length body: fire completion without consuming anything.
            // The caller's stall check tolerates this because the mode changes.
            match self.mode {
                Mode::Body => {
                    let n = ev.body_end();
                    self.apply(n);
                }
                Mode::ChunkBody => self.mode = Mode::ChunkTrailCr,
                _ => {}
            }
            return 0;
        }
        let next = ev.body_data(&data[..take]);
        if self.mode != Mode::UntilClose {
            self.remaining -= take as u64;
        }
        // A driver-requested mode change during body delivery wins.
        if next != Next::Continue {
            self.apply(next);
            return take;
        }
        if self.remaining == 0 {
            match self.mode {
                Mode::Body => {
                    let n = ev.body_end();
                    self.apply(n);
                }
                Mode::ChunkBody => self.mode = Mode::ChunkTrailCr,
                _ => {}
            }
        }
        take
    }

    /// Scan one line-oriented step. Consumes at least one byte unless halted.
    fn step_line<E: H1Events + ?Sized>(&mut self, data: &[u8], ev: &mut E) -> usize {
        debug_assert!(!data.is_empty());

        // Modes that examine exactly one byte.
        match self.mode {
            Mode::FirstLineLf | Mode::FieldValueLf | Mode::FieldsEndLf | Mode::ChunkSizeLf => {
                let b = data[0];
                if b != b'\n' {
                    let n = ev.bad_syntax("expected LF after CR");
                    self.apply(n);
                    self.mode = Mode::Halted;
                    return 1;
                }
                let next = match self.mode {
                    Mode::FirstLineLf => {
                        let n = ev.first_line_end();
                        // Default to reading field-lines unless told otherwise.
                        if n == Next::Continue {
                            self.mode = Mode::FieldStart;
                            self.scratch.clear();
                            self.value.clear();
                            return 1;
                        }
                        n
                    }
                    Mode::FieldValueLf => {
                        // Defer committing the value: an obs-fold continuation
                        // may extend it, and we can't know until the next byte.
                        self.mode = Mode::FieldFoldPeek;
                        return 1;
                    }
                    Mode::FieldsEndLf => ev.headers_end(),
                    Mode::ChunkSizeLf => {
                        let line = std::mem::take(&mut self.scratch);
                        let n = ev.chunk_size_line(&line);
                        self.scratch = line;
                        self.scratch.clear();
                        n
                    }
                    _ => unreachable!(),
                };
                self.apply(next);
                return 1;
            }
            Mode::FieldFoldSkipWs => {
                if data[0] == b' ' || data[0] == b'\t' {
                    return 1;
                }
                // First non-whitespace byte of the continuation: resume
                // accumulating the value, re-dispatching this byte.
                self.mode = Mode::FieldValue;
                return 0;
            }
            Mode::FieldFoldPeek => {
                let b = data[0];
                if b == b' ' || b == b'\t' {
                    // obs-fold: the value continues. The whole fold (CRLF plus
                    // all leading whitespace) is replaced by a single SP per
                    // RFC 9112 §5.2, so substitute it here and skip the rest.
                    if self.value.len() + 1 > MAX_FOLDED_VALUE {
                        let n = ev.too_long();
                        self.apply(n);
                        self.mode = Mode::Halted;
                        return 1;
                    }
                    self.value.push(b' ');
                    self.mode = Mode::FieldFoldSkipWs;
                    return 1;
                }
                // Not folded — commit the completed value, then re-dispatch
                // this byte as the start of the next field-line.
                let value = std::mem::take(&mut self.value);
                let next = ev.header_value(trim(&value));
                self.value = value;
                self.value.clear();
                if next != Next::Continue {
                    self.apply(next);
                    return 0;
                }
                self.mode = Mode::FieldStart;
                self.scratch.clear();
                return 0;
            }
            Mode::ChunkTrailCr => {
                if data[0] != b'\r' {
                    let n = ev.bad_syntax("bad chunk CRLF");
                    self.apply(n);
                    self.mode = Mode::Halted;
                    return 1;
                }
                self.mode = Mode::ChunkTrailLf;
                return 1;
            }
            Mode::ChunkTrailLf => {
                if data[0] != b'\n' {
                    let n = ev.bad_syntax("bad chunk CRLF");
                    self.apply(n);
                    self.mode = Mode::Halted;
                    return 1;
                }
                let next = ev.chunk_end();
                self.apply(next);
                return 1;
            }
            _ => {}
        }

        // Accumulating modes: find this token's terminator within `data`.
        let (delims, mode) = (self.delimiters(), self.mode);
        let stop = data.iter().position(|b| delims.contains(b));

        let end = stop.unwrap_or(data.len());
        if end > 0 && !self.push_scratch(&data[..end], ev) {
            return end;
        }
        let Some(stop) = stop else {
            // Token continues into the next chunk; everything consumed.
            return end;
        };

        let b = data[stop];
        // `take`/restore keeps the borrow checker happy while handing the
        // accumulated token to the driver.
        let tok = std::mem::take(&mut self.scratch);
        let next = self.emit(mode, b, &tok, ev);
        self.scratch = tok;

        match next {
            EmitOutcome::Consumed(n) => {
                self.scratch.clear();
                self.apply(n);
                stop + 1
            }
            EmitOutcome::Continue => {
                self.scratch.clear();
                stop + 1
            }
            // Token not emitted yet — a later state still needs it.
            EmitOutcome::KeepScratch => stop + 1,
        }
    }

    /// Delimiters that end the token in the current mode.
    fn delimiters(&self) -> &'static [u8] {
        match self.mode {
            Mode::FirstTok | Mode::SecondTok => b" \r",
            Mode::ThirdTokWord | Mode::ThirdTokText => b"\r",
            Mode::FieldStart => b": \t\r",
            Mode::FieldValue => b"\r",
            Mode::ChunkSizeLine => b"\r",
            _ => b"\r",
        }
    }

    /// Append to the current token, enforcing `max_token`.
    fn push_scratch<E: H1Events + ?Sized>(&mut self, bytes: &[u8], ev: &mut E) -> bool {
        let target_len = if self.mode == Mode::FieldValue {
            self.value.len() + bytes.len()
        } else {
            self.scratch.len() + bytes.len()
        };
        let cap = if self.mode == Mode::FieldValue {
            MAX_FOLDED_VALUE.min(self.max_token.max(MAX_FOLDED_VALUE))
        } else {
            self.max_token
        };
        if target_len > cap {
            let n = ev.too_long();
            self.apply(n);
            self.mode = Mode::Halted;
            return false;
        }
        if self.mode == Mode::FieldValue {
            self.value.extend_from_slice(bytes);
        } else {
            self.scratch.extend_from_slice(bytes);
        }
        true
    }

    /// Dispatch the completed token `tok`, terminated by `b`, in `mode`.
    fn emit<E: H1Events + ?Sized>(
        &mut self,
        mode: Mode,
        b: u8,
        tok: &[u8],
        ev: &mut E,
    ) -> EmitOutcome {
        match (mode, b) {
            // ---- first line ----
            (Mode::FirstTok, b' ') => {
                let n = match self.kind {
                    FirstLineKind::Request => ev.method(tok),
                    FirstLineKind::Status => ev.http_version(tok),
                };
                self.mode = Mode::SecondTok;
                EmitOutcome::from(n, EmitOutcome::Continue)
            }
            (Mode::SecondTok, b' ') => {
                let n = match self.kind {
                    FirstLineKind::Request => ev.request_target(tok),
                    FirstLineKind::Status => ev.status_code(tok),
                };
                self.mode = match self.kind {
                    FirstLineKind::Request => Mode::ThirdTokWord,
                    FirstLineKind::Status => Mode::ThirdTokText,
                };
                EmitOutcome::from(n, EmitOutcome::Continue)
            }
            // Status lines may omit the reason phrase entirely.
            (Mode::SecondTok, b'\r') => {
                let n = match self.kind {
                    FirstLineKind::Request => ev.bad_syntax("truncated request-line"),
                    FirstLineKind::Status => ev.status_code(tok),
                };
                if self.kind == FirstLineKind::Request {
                    self.mode = Mode::Halted;
                    return EmitOutcome::Consumed(n);
                }
                let n2 = ev.reason_phrase(b"");
                self.mode = Mode::FirstLineLf;
                EmitOutcome::from(if n == Next::Continue { n2 } else { n }, EmitOutcome::Continue)
            }
            (Mode::FirstTok, b'\r') => {
                let n = ev.bad_syntax("truncated first line");
                self.mode = Mode::Halted;
                EmitOutcome::Consumed(n)
            }
            (Mode::ThirdTokWord, b'\r') => {
                let n = ev.http_version(tok);
                self.mode = Mode::FirstLineLf;
                EmitOutcome::from(n, EmitOutcome::Continue)
            }
            (Mode::ThirdTokText, b'\r') => {
                let n = ev.reason_phrase(trim(tok));
                self.mode = Mode::FirstLineLf;
                EmitOutcome::from(n, EmitOutcome::Continue)
            }

            // ---- field lines ----
            (Mode::FieldStart, b'\r') if tok.is_empty() => {
                self.mode = Mode::FieldsEndLf;
                EmitOutcome::Continue
            }
            // obs-fold at the very start of a line with no preceding field.
            (Mode::FieldStart, b' ' | b'\t') if tok.is_empty() => {
                let n = ev.bad_syntax("obs-fold without field");
                self.mode = Mode::Halted;
                EmitOutcome::Consumed(n)
            }
            (Mode::FieldStart, b':') => {
                let n = ev.header_name(tok);
                self.mode = Mode::FieldValue;
                self.value.clear();
                EmitOutcome::from(n, EmitOutcome::Continue)
            }
            // Whitespace inside a field name is illegal (request smuggling).
            (Mode::FieldStart, b' ' | b'\t') => {
                let n = ev.bad_syntax("whitespace in field name");
                self.mode = Mode::Halted;
                EmitOutcome::Consumed(n)
            }
            (Mode::FieldStart, b'\r') => {
                let n = ev.bad_syntax("field line without colon");
                self.mode = Mode::Halted;
                EmitOutcome::Consumed(n)
            }
            (Mode::FieldValue, b'\r') => {
                self.mode = Mode::FieldValueLf;
                EmitOutcome::Continue
            }

            // ---- chunk size ----
            (Mode::ChunkSizeLine, b'\r') => {
                // The line is emitted only once its LF is validated, so the
                // driver never sees a size it might act on before the CRLF is
                // known-good — keep the accumulated token until then.
                self.mode = Mode::ChunkSizeLf;
                EmitOutcome::KeepScratch
            }

            _ => {
                let n = ev.bad_syntax("unexpected byte");
                self.mode = Mode::Halted;
                EmitOutcome::Consumed(n)
            }
        }
    }
}

/// How `emit` wants the terminator byte handled.
enum EmitOutcome {
    /// Terminator consumed; apply this `Next`.
    Consumed(Next),
    /// Terminator consumed; no mode change beyond what `emit` already did.
    Continue,
    /// Terminator consumed, but the accumulated token is deliberately kept —
    /// a later state (e.g. the LF after a chunk-size CR) still has to emit it.
    KeepScratch,
}

impl EmitOutcome {
    fn from(n: Next, default: EmitOutcome) -> EmitOutcome {
        if n == Next::Continue {
            default
        } else {
            EmitOutcome::Consumed(n)
        }
    }
}

/// Trim leading/trailing SP and HTAB (RFC 9112 §5 OWS).
fn trim(v: &[u8]) -> &[u8] {
    let start = v.iter().position(|b| *b != b' ' && *b != b'\t').unwrap_or(v.len());
    let end = v
        .iter()
        .rposition(|b| *b != b' ' && *b != b'\t')
        .map(|i| i + 1)
        .unwrap_or(start);
    &v[start..end]
}

/// Parse an HTTP-version token, for drivers that want it typed.
pub fn parse_version(v: &[u8]) -> Option<HttpVersion> {
    std::str::from_utf8(v).ok().and_then(HttpVersion::parse)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    enum Ev {
        Method(String),
        Target(String),
        Version(String),
        Status(String),
        Reason(String),
        FirstLineEnd,
        Name(String),
        Value(String),
        HeadersEnd,
        ChunkSize(String),
        Body(Vec<u8>),
        BodyEnd,
        ChunkEnd,
        TooLong,
        Bad(&'static str),
    }

    #[derive(Default)]
    struct Rec {
        evs: Vec<Ev>,
        /// Queued driver responses, consumed in order by matching events.
        after_headers: Option<Next>,
        after_chunk_size: Option<Next>,
    }

    fn s(v: &[u8]) -> String {
        String::from_utf8_lossy(v).into_owned()
    }

    impl H1Events for Rec {
        fn method(&mut self, v: &[u8]) -> Next {
            self.evs.push(Ev::Method(s(v)));
            Next::Continue
        }
        fn request_target(&mut self, v: &[u8]) -> Next {
            self.evs.push(Ev::Target(s(v)));
            Next::Continue
        }
        fn http_version(&mut self, v: &[u8]) -> Next {
            self.evs.push(Ev::Version(s(v)));
            Next::Continue
        }
        fn status_code(&mut self, v: &[u8]) -> Next {
            self.evs.push(Ev::Status(s(v)));
            Next::Continue
        }
        fn reason_phrase(&mut self, v: &[u8]) -> Next {
            self.evs.push(Ev::Reason(s(v)));
            Next::Continue
        }
        fn first_line_end(&mut self) -> Next {
            self.evs.push(Ev::FirstLineEnd);
            Next::Continue
        }
        fn header_name(&mut self, v: &[u8]) -> Next {
            self.evs.push(Ev::Name(s(v)));
            Next::Continue
        }
        fn header_value(&mut self, v: &[u8]) -> Next {
            self.evs.push(Ev::Value(s(v)));
            Next::Continue
        }
        fn headers_end(&mut self) -> Next {
            self.evs.push(Ev::HeadersEnd);
            self.after_headers.take().unwrap_or(Next::FirstLine)
        }
        fn chunk_size_line(&mut self, v: &[u8]) -> Next {
            self.evs.push(Ev::ChunkSize(s(v)));
            self.after_chunk_size.take().unwrap_or(Next::FirstLine)
        }
        fn body_data(&mut self, v: &[u8]) -> Next {
            self.evs.push(Ev::Body(v.to_vec()));
            Next::Continue
        }
        fn body_end(&mut self) -> Next {
            self.evs.push(Ev::BodyEnd);
            Next::FirstLine
        }
        fn chunk_end(&mut self) -> Next {
            self.evs.push(Ev::ChunkEnd);
            Next::ChunkSize
        }
        fn too_long(&mut self) -> Next {
            self.evs.push(Ev::TooLong);
            Next::Stop
        }
        fn bad_syntax(&mut self, what: &'static str) -> Next {
            self.evs.push(Ev::Bad(what));
            Next::Stop
        }
    }

    fn req_scanner() -> H1Scanner {
        H1Scanner::new(FirstLineKind::Request, 8192)
    }

    /// The exact scenario from the design brief: events must fire as soon as
    /// each token completes, and no bytes may be left for the caller.
    #[test]
    fn emits_events_as_tokens_complete_across_chunks() {
        let mut sc = req_scanner();
        let mut r = Rec::default();

        let n = sc.push(b"GET /this_is_my/resource.ht", &mut r);
        assert_eq!(n, 27, "every byte consumed");
        assert_eq!(r.evs, vec![Ev::Method("GET".into())]);
        r.evs.clear();

        let n = sc.push(b"ml HTTP/1", &mut r);
        assert_eq!(n, 9);
        assert_eq!(r.evs, vec![Ev::Target("/this_is_my/resource.html".into())]);
        r.evs.clear();

        let n = sc.push(b".1\r\nUser-Agent: blogho", &mut r);
        assert_eq!(n, 22);
        assert_eq!(
            r.evs,
            vec![
                Ev::Version("HTTP/1.1".into()),
                Ev::FirstLineEnd,
                Ev::Name("User-Agent".into()),
            ]
        );
        r.evs.clear();

        let n = sc.push(b"ti 1.1\r", &mut r);
        assert_eq!(n, 7);
        assert_eq!(r.evs, vec![], "value not complete until fold is ruled out");

        let n = sc.push(b"\n\r\n", &mut r);
        assert_eq!(n, 3);
        assert_eq!(
            r.evs,
            vec![Ev::Value("bloghoti 1.1".into()), Ev::HeadersEnd]
        );
    }

    #[test]
    fn one_byte_at_a_time_gives_identical_events() {
        let msg: &[u8] = b"POST /x HTTP/1.1\r\nHost: h\r\nX: y\r\n\r\n";

        let mut bulk = req_scanner();
        let mut rb = Rec::default();
        assert_eq!(bulk.push(msg, &mut rb), msg.len());

        let mut drip = req_scanner();
        let mut rd = Rec::default();
        for b in msg {
            assert_eq!(drip.push(&[*b], &mut rd), 1, "always consumes its byte");
        }

        assert_eq!(rb.evs, rd.evs);
        assert_eq!(
            rb.evs,
            vec![
                Ev::Method("POST".into()),
                Ev::Target("/x".into()),
                Ev::Version("HTTP/1.1".into()),
                Ev::FirstLineEnd,
                Ev::Name("Host".into()),
                Ev::Value("h".into()),
                Ev::Name("X".into()),
                Ev::Value("y".into()),
                Ev::HeadersEnd,
            ]
        );
    }

    #[test]
    fn obs_fold_joins_continuation_lines() {
        let mut sc = req_scanner();
        let mut r = Rec::default();
        sc.push(b"GET / HTTP/1.1\r\nX: a\r\n  b\r\n\tc\r\n\r\n", &mut r);
        assert!(r.evs.contains(&Ev::Value("a b c".into())), "{:?}", r.evs);
    }

    #[test]
    fn counted_body_streams_without_buffering() {
        let mut sc = req_scanner();
        let mut r = Rec::default();
        r.after_headers = Some(Next::Body(11));
        sc.push(b"POST / HTTP/1.1\r\nHost: h\r\n\r\nhello ", &mut r);
        sc.push(b"world", &mut r);
        let bodies: Vec<Vec<u8>> = r
            .evs
            .iter()
            .filter_map(|e| match e {
                Ev::Body(b) => Some(b.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(bodies, vec![b"hello ".to_vec(), b"world".to_vec()]);
        assert!(r.evs.contains(&Ev::BodyEnd));
    }

    #[test]
    fn chunked_body_size_data_crlf_cycle() {
        let mut sc = req_scanner();
        let mut r = Rec::default();
        r.after_headers = Some(Next::ChunkSize);
        r.after_chunk_size = Some(Next::ChunkBody(5));
        sc.push(b"POST / HTTP/1.1\r\nHost: h\r\n\r\n5\r\nhello\r\n", &mut r);
        assert!(r.evs.contains(&Ev::ChunkSize("5".into())), "{:?}", r.evs);
        assert!(r.evs.contains(&Ev::Body(b"hello".to_vec())), "{:?}", r.evs);
        assert!(r.evs.contains(&Ev::ChunkEnd), "{:?}", r.evs);
    }

    #[test]
    fn status_line_with_and_without_reason() {
        let mut sc = H1Scanner::new(FirstLineKind::Status, 8192);
        let mut r = Rec::default();
        sc.push(b"HTTP/1.1 404 Not Found\r\n\r\n", &mut r);
        assert_eq!(
            r.evs,
            vec![
                Ev::Version("HTTP/1.1".into()),
                Ev::Status("404".into()),
                Ev::Reason("Not Found".into()),
                Ev::FirstLineEnd,
                Ev::HeadersEnd,
            ]
        );

        let mut sc = H1Scanner::new(FirstLineKind::Status, 8192);
        let mut r = Rec::default();
        sc.push(b"HTTP/1.1 204\r\n\r\n", &mut r);
        assert_eq!(
            r.evs,
            vec![
                Ev::Version("HTTP/1.1".into()),
                Ev::Status("204".into()),
                Ev::Reason("".into()),
                Ev::FirstLineEnd,
                Ev::HeadersEnd,
            ]
        );
    }

    #[test]
    fn oversized_token_reports_too_long() {
        let mut sc = H1Scanner::new(FirstLineKind::Request, 16);
        let mut r = Rec::default();
        sc.push(b"GET /aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa HTTP/1.1\r\n", &mut r);
        assert!(r.evs.contains(&Ev::TooLong), "{:?}", r.evs);
        assert!(sc.is_halted());
    }

    #[test]
    fn whitespace_in_field_name_is_rejected() {
        let mut sc = req_scanner();
        let mut r = Rec::default();
        sc.push(b"GET / HTTP/1.1\r\nBad Name: v\r\n\r\n", &mut r);
        assert!(
            r.evs.iter().any(|e| matches!(e, Ev::Bad(_))),
            "{:?}",
            r.evs
        );
    }

    #[test]
    fn pipelined_requests_scan_back_to_back() {
        let mut sc = req_scanner();
        let mut r = Rec::default();
        sc.push(b"GET /a HTTP/1.1\r\nHost: h\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\n\r\n", &mut r);
        let targets: Vec<&Ev> = r
            .evs
            .iter()
            .filter(|e| matches!(e, Ev::Target(_)))
            .collect();
        assert_eq!(
            targets,
            vec![&Ev::Target("/a".into()), &Ev::Target("/b".into())]
        );
    }

    /// Every split point of a full message must produce identical events.
    #[test]
    fn all_split_points_are_equivalent() {
        let msg: &[u8] = b"GET /p?q=1 HTTP/1.1\r\nHost: e.com\r\nA: 1\r\nB: 2\r\n\r\n";
        let mut base = req_scanner();
        let mut rb = Rec::default();
        base.push(msg, &mut rb);

        for split in 1..msg.len() {
            let mut sc = req_scanner();
            let mut r = Rec::default();
            let a = sc.push(&msg[..split], &mut r);
            let b = sc.push(&msg[split..], &mut r);
            assert_eq!(a + b, msg.len(), "split {split} left bytes behind");
            assert_eq!(r.evs, rb.evs, "split {split} diverged");
        }
    }
}
