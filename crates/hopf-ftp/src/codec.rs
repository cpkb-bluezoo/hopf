// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Incremental FTP control lexer: `KEYWORD [SP TEXT] CRLF`.

use hopf_core::{
    ByteStreamHandler, ByteStreamLexer, ByteStreamScanner, HandlerControl, ScanAction,
};

/// Lexer token kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FtpToken {
    /// Command verb.
    Keyword,
    /// Single space after the verb.
    Sp,
    /// Argument text (may contain spaces); zero-copy chunks.
    Text,
    /// End of command line.
    Crlf,
}

/// Parsed control command.
///
/// The argument is kept as raw bytes so [`crate::utf8::decode_arg`] can apply
/// RFC 2640 charset rules (`OPTS UTF8`) at dispatch time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtpCommand {
    /// Uppercased verb (ASCII).
    pub verb: String,
    /// Raw argument bytes after the first SP (may be empty).
    pub arg_bytes: Vec<u8>,
}

impl FtpCommand {
    /// Lossy UTF-8 view of the argument (tests / debugging).
    pub fn arg_lossy(&self) -> String {
        String::from_utf8_lossy(&self.arg_bytes).into_owned()
    }
}

/// Scanner for FTP control grammar.
pub struct FtpScanner {
    last_was_cr: bool,
}

impl Default for FtpScanner {
    fn default() -> Self {
        Self { last_was_cr: false }
    }
}

impl ByteStreamScanner for FtpScanner {
    type Token = FtpToken;

    fn consume(&mut self, b: u8, pos: usize, region_start: usize) -> ScanAction<FtpToken> {
        if b == b'\n' && self.last_was_cr {
            let crlf_start = pos.saturating_sub(2);
            self.last_was_cr = false;
            if crlf_start > region_start {
                return ScanAction::Emit {
                    token: FtpToken::Keyword,
                    start: region_start,
                    end: crlf_start,
                };
            }
            return ScanAction::Emit {
                token: FtpToken::Crlf,
                start: crlf_start,
                end: pos,
            };
        }
        if b == b'\r' {
            self.last_was_cr = true;
            return ScanAction::Continue;
        }
        self.last_was_cr = false;
        if b == b' ' {
            let sp_start = pos.saturating_sub(1);
            if sp_start > region_start {
                return ScanAction::Emit {
                    token: FtpToken::Keyword,
                    start: region_start,
                    end: sp_start,
                };
            }
            return ScanAction::Emit {
                token: FtpToken::Sp,
                start: sp_start,
                end: pos,
            };
        }
        ScanAction::Continue
    }

    fn reset(&mut self) {
        self.last_was_cr = false;
    }
}

/// Accumulates tokens into complete [`FtpCommand`]s.
pub struct FtpCommandBuilder {
    verb: Option<String>,
    arg: Vec<u8>,
    after_sp: bool,
    /// Completed commands ready for dispatch.
    pub ready: Vec<FtpCommand>,
}

impl Default for FtpCommandBuilder {
    fn default() -> Self {
        Self {
            verb: None,
            arg: Vec::new(),
            after_sp: false,
            ready: Vec::new(),
        }
    }
}

impl ByteStreamHandler for FtpCommandBuilder {
    type Token = FtpToken;

    fn token(&mut self, ty: FtpToken, window: &[u8]) -> HandlerControl {
        match ty {
            FtpToken::Keyword => {
                if self.verb.is_none() {
                    // Verbs are ASCII; lossy uppercase is fine.
                    self.verb = Some(String::from_utf8_lossy(window).to_ascii_uppercase());
                }
                HandlerControl::Continue
            }
            FtpToken::Sp => {
                self.after_sp = true;
                HandlerControl::LatchText
            }
            FtpToken::Text => {
                self.arg.extend_from_slice(window);
                HandlerControl::Continue
            }
            FtpToken::Crlf => {
                let verb = self.verb.take().unwrap_or_default();
                let arg_bytes = std::mem::take(&mut self.arg);
                self.after_sp = false;
                if !verb.is_empty() {
                    self.ready.push(FtpCommand { verb, arg_bytes });
                }
                HandlerControl::Continue
            }
        }
    }

    fn token_too_long(&mut self) {
        self.verb = None;
        self.arg.clear();
        self.after_sp = false;
    }
}

/// Push lexer wrapping scanner + command builder.
pub struct FtpServerLexer {
    lexer: ByteStreamLexer<FtpScanner, FtpCommandBuilder>,
    pending: Vec<u8>,
}

impl FtpServerLexer {
    /// Create with a max command-line length (bytes).
    pub fn new(max_line: usize) -> Self {
        Self {
            lexer: ByteStreamLexer::new(
                FtpScanner::default(),
                FtpCommandBuilder::default(),
                max_line,
                FtpToken::Crlf,
                FtpToken::Text,
            ),
            pending: Vec::new(),
        }
    }

    /// Feed inbound control bytes; returns newly completed commands.
    pub fn feed(&mut self, data: &mut &[u8]) -> Vec<FtpCommand> {
        self.pending.extend_from_slice(data);
        *data = &[];
        let mut slice = self.pending.as_slice();
        self.lexer.feed(&mut slice);
        let consumed = self.pending.len() - slice.len();
        self.pending.drain(..consumed);
        std::mem::take(&mut self.lexer.handler_mut().ready)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cwd_with_spaces() {
        let mut lex = FtpServerLexer::new(4096);
        let mut data: &[u8] = b"CWD my dir\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].verb, "CWD");
        assert_eq!(cmds[0].arg_bytes, b"my dir");
    }

    #[test]
    fn parse_noop() {
        let mut lex = FtpServerLexer::new(4096);
        let mut data: &[u8] = b"NOOP\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].verb, "NOOP");
        assert!(cmds[0].arg_bytes.is_empty());
    }

    #[test]
    fn parse_split_buffers() {
        let mut lex = FtpServerLexer::new(4096);
        let mut a: &[u8] = b"USE";
        assert!(lex.feed(&mut a).is_empty());
        let mut b: &[u8] = b"R anonymous\r\n";
        let cmds = lex.feed(&mut b);
        assert_eq!(cmds[0].verb, "USER");
        assert_eq!(cmds[0].arg_bytes, b"anonymous");
    }

    #[test]
    fn preserves_utf8_arg_bytes() {
        let mut lex = FtpServerLexer::new(4096);
        let mut line = Vec::from(&b"CWD "[..]);
        line.extend_from_slice("café".as_bytes());
        line.extend_from_slice(b"\r\n");
        let mut data = line.as_slice();
        let cmds = lex.feed(&mut data);
        assert_eq!(cmds[0].arg_bytes, "café".as_bytes());
    }
}
