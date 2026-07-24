// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Incremental SMTP control lexer: `KEYWORD [SP TEXT] CRLF`.

use hopf_core::{
    ByteStreamHandler, ByteStreamLexer, ByteStreamScanner, HandlerControl, ScanAction,
};

/// Lexer token kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpToken {
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpCommand {
    /// Uppercased verb (ASCII).
    pub verb: String,
    /// Raw argument bytes after the first SP (may be empty).
    pub arg_bytes: Vec<u8>,
}

impl SmtpCommand {
    /// Lossy UTF-8 view of the argument (tests / debugging).
    pub fn arg_lossy(&self) -> String {
        String::from_utf8_lossy(&self.arg_bytes).into_owned()
    }
}

/// Scanner for SMTP control grammar.
pub struct SmtpScanner {
    last_was_cr: bool,
}

impl Default for SmtpScanner {
    fn default() -> Self {
        Self { last_was_cr: false }
    }
}

impl ByteStreamScanner for SmtpScanner {
    type Token = SmtpToken;

    fn consume(&mut self, b: u8, pos: usize, region_start: usize) -> ScanAction<SmtpToken> {
        if b == b'\n' && self.last_was_cr {
            let crlf_start = pos.saturating_sub(2);
            self.last_was_cr = false;
            if crlf_start > region_start {
                return ScanAction::Emit {
                    token: SmtpToken::Keyword,
                    start: region_start,
                    end: crlf_start,
                };
            }
            return ScanAction::Emit {
                token: SmtpToken::Crlf,
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
                    token: SmtpToken::Keyword,
                    start: region_start,
                    end: sp_start,
                };
            }
            return ScanAction::Emit {
                token: SmtpToken::Sp,
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

/// Accumulates tokens into complete [`SmtpCommand`]s.
pub struct SmtpCommandBuilder {
    verb: Option<String>,
    arg: Vec<u8>,
    after_sp: bool,
    /// Completed commands ready for dispatch.
    pub ready: Vec<SmtpCommand>,
}

impl Default for SmtpCommandBuilder {
    fn default() -> Self {
        Self {
            verb: None,
            arg: Vec::new(),
            after_sp: false,
            ready: Vec::new(),
        }
    }
}

impl ByteStreamHandler for SmtpCommandBuilder {
    type Token = SmtpToken;

    fn token(&mut self, ty: SmtpToken, window: &[u8]) -> HandlerControl {
        match ty {
            SmtpToken::Keyword => {
                if self.verb.is_none() {
                    self.verb = Some(String::from_utf8_lossy(window).to_ascii_uppercase());
                }
                HandlerControl::Continue
            }
            SmtpToken::Sp => {
                self.after_sp = true;
                HandlerControl::LatchText
            }
            SmtpToken::Text => {
                self.arg.extend_from_slice(window);
                HandlerControl::Continue
            }
            SmtpToken::Crlf => {
                let verb = self.verb.take().unwrap_or_default();
                let arg_bytes = std::mem::take(&mut self.arg);
                self.after_sp = false;
                if !verb.is_empty() {
                    self.ready.push(SmtpCommand { verb, arg_bytes });
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
pub struct SmtpServerLexer {
    lexer: ByteStreamLexer<SmtpScanner, SmtpCommandBuilder>,
    pending: Vec<u8>,
}

impl SmtpServerLexer {
    /// Create with a max command-line length (bytes).
    pub fn new(max_line: usize) -> Self {
        Self {
            lexer: ByteStreamLexer::new(
                SmtpScanner::default(),
                SmtpCommandBuilder::default(),
                max_line,
                SmtpToken::Crlf,
                SmtpToken::Text,
            ),
            pending: Vec::new(),
        }
    }

    /// Feed inbound control bytes; returns newly completed commands.
    pub fn feed(&mut self, data: &mut &[u8]) -> Vec<SmtpCommand> {
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
    fn parse_mail_from() {
        let mut lex = SmtpServerLexer::new(4096);
        let mut data: &[u8] = b"MAIL FROM:<a@b.com>\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].verb, "MAIL");
        assert_eq!(cmds[0].arg_bytes, b"FROM:<a@b.com>");
    }

    #[test]
    fn parse_noop() {
        let mut lex = SmtpServerLexer::new(4096);
        let mut data: &[u8] = b"NOOP\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(cmds[0].verb, "NOOP");
        assert!(cmds[0].arg_bytes.is_empty());
    }

    #[test]
    fn parse_split_buffers() {
        let mut lex = SmtpServerLexer::new(4096);
        let mut a: &[u8] = b"EHL";
        assert!(lex.feed(&mut a).is_empty());
        let mut b: &[u8] = b"O client.example\r\n";
        let cmds = lex.feed(&mut b);
        assert_eq!(cmds[0].verb, "EHLO");
        assert_eq!(cmds[0].arg_bytes, b"client.example");
    }
}
