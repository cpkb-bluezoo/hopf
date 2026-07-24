// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Grammar-driven HTTP/1.x scanner over [`hopf_core::ByteStreamLexer`].
//!
//! Issue [#3](https://github.com/cpkb-bluezoo/hopf/issues/3): emit fine
//! tokens so the parse FSM advances as each production completes — not one
//! opaque `LINE` that is re-scanned later.
//!
//! Request-line shape: `Word` `Sp` `Word` `Sp` `Word` `Crlf`  
//! Header shape: `Word` `Colon` + latched `Text`* `Crlf` (obs-fold: leading
//! `Sp`/`Ht` then more `Text`)  
//! Chunk-size: `Word` `Crlf` (`;` extensions stay inside `Word`)
//!
//! Phase is shared with the parser (`Arc<AtomicU8>`) so `:` is only a `Colon`
//! in header/trailer phases — absolute-form request-targets may contain `:`.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use hopf_core::{ByteStreamScanner, ScanAction};

/// Tokens emitted by [`HttpScanner`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpToken {
    /// Non-space / non-delimiter run (method, target, version, field-name, chunk-size).
    Word,
    /// Single SP (or HTAB when signalling obs-fold at the start of a header line).
    Sp,
    /// `:` after a header field-name.
    Colon,
    /// Field-value chunk (latched text mode until [`HttpToken::Crlf`]).
    Text,
    /// CRLF (`\r\n`).
    Crlf,
}

/// Lexical phase — controls whether `:` ends a word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HttpScanPhase {
    /// Request-line: `Word` / `Sp` / `Crlf` only (`:` is word content).
    RequestLine = 0,
    /// Header block (and trailers): `Word` / `Colon` / `Sp` / `Crlf`.
    Header = 1,
    /// Chunk-size line: `Word` until `Crlf`.
    ChunkSize = 2,
}

impl HttpScanPhase {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Header,
            2 => Self::ChunkSize,
            _ => Self::RequestLine,
        }
    }
}

/// Shared scan phase (Send — required by `ProtocolHandler`).
#[derive(Debug, Clone)]
pub struct HttpScanPhaseGate {
    inner: Arc<AtomicU8>,
}

impl HttpScanPhaseGate {
    /// Start in [`HttpScanPhase::RequestLine`].
    pub fn new() -> Self {
        Self {
            inner: Arc::new(AtomicU8::new(HttpScanPhase::RequestLine as u8)),
        }
    }

    /// Current phase.
    pub fn get(&self) -> HttpScanPhase {
        HttpScanPhase::from_u8(self.inner.load(Ordering::Relaxed))
    }

    /// Update phase (parser calls this on state transitions).
    pub fn set(&self, phase: HttpScanPhase) {
        self.inner.store(phase as u8, Ordering::Relaxed);
    }
}

impl Default for HttpScanPhaseGate {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-byte HTTP/1.x structured scanner.
pub struct HttpScanner {
    phase: HttpScanPhaseGate,
    last_was_cr: bool,
}

impl HttpScanner {
    /// Create a scanner sharing `phase` with the parser.
    pub fn new(phase: HttpScanPhaseGate) -> Self {
        Self {
            phase,
            last_was_cr: false,
        }
    }

    /// Phase gate (same `Arc` the parser holds).
    pub fn phase_gate(&self) -> HttpScanPhaseGate {
        self.phase.clone()
    }
}

impl ByteStreamScanner for HttpScanner {
    type Token = HttpToken;

    fn consume(
        &mut self,
        b: u8,
        position: usize,
        region_start: usize,
    ) -> ScanAction<HttpToken> {
        if b == b'\n' && self.last_was_cr {
            let crlf_start = position - 2;
            self.last_was_cr = false;
            if crlf_start > region_start {
                // Emit Word first; rewind so CRLF is consumed on the next pass.
                return ScanAction::Emit {
                    token: HttpToken::Word,
                    start: region_start,
                    end: crlf_start,
                };
            }
            return ScanAction::Emit {
                token: HttpToken::Crlf,
                start: crlf_start,
                end: position,
            };
        }
        if b == b'\r' {
            self.last_was_cr = true;
            return ScanAction::Continue;
        }
        self.last_was_cr = false;

        let phase = self.phase.get();

        if b == b' ' {
            if position - 1 > region_start {
                return ScanAction::Emit {
                    token: HttpToken::Word,
                    start: region_start,
                    end: position - 1,
                };
            }
            return ScanAction::Emit {
                token: HttpToken::Sp,
                start: position - 1,
                end: position,
            };
        }

        // Obs-fold: HTAB at the start of a header production.
        if phase == HttpScanPhase::Header && b == b'\t' && position - 1 == region_start {
            return ScanAction::Emit {
                token: HttpToken::Sp,
                start: position - 1,
                end: position,
            };
        }

        if phase == HttpScanPhase::Header && b == b':' {
            if position - 1 > region_start {
                return ScanAction::Emit {
                    token: HttpToken::Word,
                    start: region_start,
                    end: position - 1,
                };
            }
            return ScanAction::Emit {
                token: HttpToken::Colon,
                start: position - 1,
                end: position,
            };
        }

        ScanAction::Continue
    }

    fn reset(&mut self) {
        self.last_was_cr = false;
        self.phase.set(HttpScanPhase::RequestLine);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hopf_core::{ByteStreamHandler, ByteStreamLexer, HandlerControl};

    struct Collect {
        tokens: Vec<(HttpToken, Vec<u8>)>,
    }

    impl ByteStreamHandler for Collect {
        type Token = HttpToken;

        fn token(&mut self, ty: HttpToken, window: &[u8]) -> HandlerControl {
            self.tokens.push((ty, window.to_vec()));
            if ty == HttpToken::Colon {
                HandlerControl::LatchText
            } else {
                HandlerControl::Continue
            }
        }

        fn token_too_long(&mut self) {}
    }

    fn feed(lex: &mut ByteStreamLexer<HttpScanner, Collect>, pending: &mut Vec<u8>, chunk: &[u8]) {
        pending.extend_from_slice(chunk);
        let mut slice = pending.as_slice();
        let before = slice.len();
        lex.feed(&mut slice);
        let consumed = before - slice.len();
        pending.drain(..consumed);
    }

    #[test]
    fn request_line_words_before_crlf() {
        let phase = HttpScanPhaseGate::new();
        let mut lex = ByteStreamLexer::new(
            HttpScanner::new(phase.clone()),
            Collect { tokens: Vec::new() },
            8192,
            HttpToken::Crlf,
            HttpToken::Text,
        );
        let mut pending = Vec::new();
        feed(&mut lex, &mut pending, b"GET /x H");
        let toks = &lex.handler_mut().tokens;
        assert_eq!(toks[0], (HttpToken::Word, b"GET".to_vec()));
        assert_eq!(toks[1], (HttpToken::Sp, b" ".to_vec()));
        assert_eq!(toks[2], (HttpToken::Word, b"/x".to_vec()));
        assert_eq!(toks[3], (HttpToken::Sp, b" ".to_vec()));
        assert_eq!(pending, b"H");

        feed(&mut lex, &mut pending, b"TTP/1.1\r\n");
        let toks = &lex.handler_mut().tokens;
        assert!(toks.iter().any(|(t, w)| *t == HttpToken::Word && w == b"HTTP/1.1"));
        assert_eq!(toks.last().unwrap().0, HttpToken::Crlf);
    }

    #[test]
    fn header_colon_latches_text() {
        let phase = HttpScanPhaseGate::new();
        phase.set(HttpScanPhase::Header);
        let mut lex = ByteStreamLexer::new(
            HttpScanner::new(phase),
            Collect { tokens: Vec::new() },
            8192,
            HttpToken::Crlf,
            HttpToken::Text,
        );
        let mut data: &[u8] = b"Host: example\r\n";
        lex.feed(&mut data);
        assert!(data.is_empty());
        let toks = &lex.handler_mut().tokens;
        assert_eq!(toks[0], (HttpToken::Word, b"Host".to_vec()));
        assert_eq!(toks[1], (HttpToken::Colon, b":".to_vec()));
        assert!(toks.iter().any(|(t, w)| *t == HttpToken::Text && w == b" example"));
        assert_eq!(toks.last().unwrap().0, HttpToken::Crlf);
    }
}
