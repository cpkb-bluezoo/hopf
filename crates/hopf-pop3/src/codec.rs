// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Incremental POP3 command lexer: `KEYWORD [SP TEXT] CRLF`.

use hopf_core::{
    ByteStreamHandler, ByteStreamLexer, ByteStreamScanner, HandlerControl, ScanAction,
};

/// Default RFC 1939 command-line length limit (octets).
pub const MAX_COMMAND_LINE: usize = 512;

/// Lexer token kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pop3Token {
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
pub struct Pop3Command {
    /// Uppercased verb (ASCII).
    pub verb: String,
    /// Raw argument bytes after the first SP (may be empty).
    pub arg_bytes: Vec<u8>,
}

impl Pop3Command {
    /// Lossy UTF-8 view of the argument.
    pub fn arg_lossy(&self) -> String {
        String::from_utf8_lossy(&self.arg_bytes).into_owned()
    }
}

/// Scanner for POP3 control grammar.
pub struct Pop3Scanner {
    last_was_cr: bool,
}

impl Default for Pop3Scanner {
    fn default() -> Self {
        Self { last_was_cr: false }
    }
}

impl ByteStreamScanner for Pop3Scanner {
    type Token = Pop3Token;

    fn consume(&mut self, b: u8, pos: usize, region_start: usize) -> ScanAction<Pop3Token> {
        if b == b'\n' && self.last_was_cr {
            let crlf_start = pos.saturating_sub(2);
            self.last_was_cr = false;
            if crlf_start > region_start {
                return ScanAction::Emit {
                    token: Pop3Token::Keyword,
                    start: region_start,
                    end: crlf_start,
                };
            }
            return ScanAction::Emit {
                token: Pop3Token::Crlf,
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
                    token: Pop3Token::Keyword,
                    start: region_start,
                    end: sp_start,
                };
            }
            return ScanAction::Emit {
                token: Pop3Token::Sp,
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

/// Accumulates tokens into complete [`Pop3Command`]s.
pub struct Pop3CommandBuilder {
    verb: Option<String>,
    arg: Vec<u8>,
    after_sp: bool,
    /// Completed commands ready for dispatch.
    pub ready: Vec<Pop3Command>,
    /// Set when a token exceeded the line length cap.
    pub line_too_long: bool,
}

impl Default for Pop3CommandBuilder {
    fn default() -> Self {
        Self {
            verb: None,
            arg: Vec::new(),
            after_sp: false,
            ready: Vec::new(),
            line_too_long: false,
        }
    }
}

impl ByteStreamHandler for Pop3CommandBuilder {
    type Token = Pop3Token;

    fn token(&mut self, ty: Pop3Token, window: &[u8]) -> HandlerControl {
        match ty {
            Pop3Token::Keyword => {
                if self.verb.is_none() {
                    self.verb = Some(String::from_utf8_lossy(window).to_ascii_uppercase());
                }
                HandlerControl::Continue
            }
            Pop3Token::Sp => {
                self.after_sp = true;
                HandlerControl::LatchText
            }
            Pop3Token::Text => {
                self.arg.extend_from_slice(window);
                HandlerControl::Continue
            }
            Pop3Token::Crlf => {
                let verb = self.verb.take().unwrap_or_default();
                let arg_bytes = std::mem::take(&mut self.arg);
                self.after_sp = false;
                if !verb.is_empty() {
                    self.ready.push(Pop3Command { verb, arg_bytes });
                }
                HandlerControl::Continue
            }
        }
    }

    fn token_too_long(&mut self) {
        self.verb = None;
        self.arg.clear();
        self.after_sp = false;
        self.line_too_long = true;
    }
}

/// Push lexer wrapping scanner + command builder.
pub struct Pop3ServerLexer {
    lexer: ByteStreamLexer<Pop3Scanner, Pop3CommandBuilder>,
    pending: Vec<u8>,
}

impl Pop3ServerLexer {
    /// Create with a max command-line length (bytes).
    pub fn new(max_line: usize) -> Self {
        Self {
            lexer: ByteStreamLexer::new(
                Pop3Scanner::default(),
                Pop3CommandBuilder::default(),
                max_line,
                Pop3Token::Crlf,
                Pop3Token::Text,
            ),
            pending: Vec::new(),
        }
    }

    /// Feed inbound control bytes; returns newly completed commands.
    ///
    /// When the line-length cap is exceeded, returns an empty vec and sets
    /// [`took_line_too_long`](Self::took_line_too_long).
    pub fn feed(&mut self, data: &mut &[u8]) -> Vec<Pop3Command> {
        self.pending.extend_from_slice(data);
        *data = &[];
        let mut slice = self.pending.as_slice();
        self.lexer.feed(&mut slice);
        let consumed = self.pending.len() - slice.len();
        self.pending.drain(..consumed);
        std::mem::take(&mut self.lexer.handler_mut().ready)
    }

    /// Whether the last feed hit the token-length cap (clears the flag).
    pub fn took_line_too_long(&mut self) -> bool {
        let h = self.lexer.handler_mut();
        let v = h.line_too_long;
        h.line_too_long = false;
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_user_pass() {
        let mut lex = Pop3ServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"USER alice\r\nPASS secret\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0].verb, "USER");
        assert_eq!(cmds[0].arg_bytes, b"alice");
        assert_eq!(cmds[1].verb, "PASS");
        assert_eq!(cmds[1].arg_bytes, b"secret");
    }

    #[test]
    fn parse_split_buffers() {
        let mut lex = Pop3ServerLexer::new(MAX_COMMAND_LINE);
        let mut a: &[u8] = b"STA";
        assert!(lex.feed(&mut a).is_empty());
        let mut b: &[u8] = b"T\r\n";
        let cmds = lex.feed(&mut b);
        assert_eq!(cmds[0].verb, "STAT");
        assert!(cmds[0].arg_bytes.is_empty());
    }

    #[test]
    fn parse_arg_with_spaces() {
        let mut lex = Pop3ServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"APOP user deadbeef cafe\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(cmds[0].verb, "APOP");
        assert_eq!(cmds[0].arg_bytes, b"user deadbeef cafe");
    }

    #[test]
    fn pipelined_commands() {
        let mut lex = Pop3ServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"STAT\r\nLIST\r\nNOOP\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(cmds.len(), 3);
        assert_eq!(cmds[0].verb, "STAT");
        assert_eq!(cmds[1].verb, "LIST");
        assert_eq!(cmds[2].verb, "NOOP");
    }
}
