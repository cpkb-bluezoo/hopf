// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Streaming lexer for BIND-style zone files (RFC 1035 §5.1): words, quoted
//! strings, `(...)` grouping and `;` comments.
//!
//! Bytes are fed in arbitrary chunks and scanned once; a token split across
//! chunks is carried in a small scratch buffer. A newline is reported only
//! at parenthesis depth zero, so a multi-line `(...)` group is one logical
//! line.

use super::error::ZoneError;

/// Longest single token (an escaped TXT string is the longest legitimate one).
const MAX_TOKEN: usize = 4096;

/// One lexical token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Token {
    /// A word. Backslash escapes are kept verbatim.
    Word {
        /// The text (without the enclosing quotes when `quoted`).
        text: String,
        /// Whether it was a `"quoted string"`.
        quoted: bool,
        /// True only for the first word of a logical line that began with
        /// whitespace: the owner name is omitted and the previous one is
        /// reused (RFC 1035 §5.1).
        blank_owner: bool,
        /// 1-based line the word is on.
        line: usize,
    },
    /// End of a logical line.
    Eol,
}

pub(crate) struct ZoneLexer {
    word: Vec<u8>,
    in_word: bool,
    in_quote: bool,
    escaped: bool,
    in_comment: bool,
    depth: u32,
    line: usize,
    /// No word has been emitted yet on this logical line.
    entry_start: bool,
    /// The physical line this logical line began on started with whitespace.
    leading_blank: bool,
    /// At the very first byte of a physical line.
    line_begin: bool,
}

impl ZoneLexer {
    pub(crate) fn new() -> Self {
        Self {
            word: Vec::new(),
            in_word: false,
            in_quote: false,
            escaped: false,
            in_comment: false,
            depth: 0,
            line: 1,
            entry_start: true,
            leading_blank: false,
            line_begin: true,
        }
    }

    /// Feed a chunk; `sink` receives each completed token.
    pub(crate) fn push<F>(&mut self, data: &[u8], sink: &mut F) -> Result<(), ZoneError>
    where
        F: FnMut(Token) -> Result<(), ZoneError>,
    {
        for &b in data {
            self.byte(b, sink)?;
        }
        Ok(())
    }

    /// End of input: flush a final word and line.
    pub(crate) fn finish<F>(&mut self, sink: &mut F) -> Result<(), ZoneError>
    where
        F: FnMut(Token) -> Result<(), ZoneError>,
    {
        if self.in_quote {
            return Err(ZoneError::at(self.line, "unterminated quoted string"));
        }
        if self.depth != 0 {
            return Err(ZoneError::at(self.line, "unbalanced '(' at end of file"));
        }
        self.flush_word(sink)?;
        sink(Token::Eol)
    }

    fn byte<F>(&mut self, b: u8, sink: &mut F) -> Result<(), ZoneError>
    where
        F: FnMut(Token) -> Result<(), ZoneError>,
    {
        if self.line_begin {
            self.line_begin = false;
            if self.entry_start && self.depth == 0 {
                self.leading_blank = b == b' ' || b == b'\t';
            }
        }
        if self.in_quote {
            if b == b'\n' {
                // A quoted string may not span lines.
                return Err(ZoneError::at(self.line, "unterminated quoted string"));
            }
            if self.escaped {
                self.escaped = false;
            } else if b == b'\\' {
                self.escaped = true;
            } else if b == b'"' {
                self.in_quote = false;
                self.in_word = false;
                let bytes = std::mem::take(&mut self.word);
                return self.emit_word(bytes, true, sink);
            }
            return self.append(b);
        }
        if self.in_comment {
            if b == b'\n' {
                self.in_comment = false;
                return self.newline(sink);
            }
            return Ok(());
        }
        if self.escaped {
            self.escaped = false;
            return self.append(b);
        }
        match b {
            b'\\' => {
                self.escaped = true;
                self.in_word = true;
                self.append(b)
            }
            b'\n' => self.newline(sink),
            b'\r' | b' ' | b'\t' => self.flush_word(sink),
            b';' => {
                self.flush_word(sink)?;
                self.in_comment = true;
                Ok(())
            }
            b'(' => {
                self.flush_word(sink)?;
                self.depth += 1;
                Ok(())
            }
            b')' => {
                self.flush_word(sink)?;
                if self.depth == 0 {
                    return Err(ZoneError::at(self.line, "unbalanced ')'"));
                }
                self.depth -= 1;
                Ok(())
            }
            b'"' => {
                self.flush_word(sink)?;
                self.in_quote = true;
                self.in_word = true;
                Ok(())
            }
            _ => {
                self.in_word = true;
                self.append(b)
            }
        }
    }

    fn append(&mut self, b: u8) -> Result<(), ZoneError> {
        if self.word.len() >= MAX_TOKEN {
            return Err(ZoneError::at(
                self.line,
                format!("token longer than {MAX_TOKEN} bytes"),
            ));
        }
        self.word.push(b);
        Ok(())
    }

    fn newline<F>(&mut self, sink: &mut F) -> Result<(), ZoneError>
    where
        F: FnMut(Token) -> Result<(), ZoneError>,
    {
        self.flush_word(sink)?;
        self.line += 1;
        self.line_begin = true;
        if self.depth == 0 {
            self.entry_start = true;
            sink(Token::Eol)?;
        }
        Ok(())
    }

    fn flush_word<F>(&mut self, sink: &mut F) -> Result<(), ZoneError>
    where
        F: FnMut(Token) -> Result<(), ZoneError>,
    {
        if !self.in_word {
            return Ok(());
        }
        self.in_word = false;
        let bytes = std::mem::take(&mut self.word);
        self.emit_word(bytes, false, sink)
    }

    fn emit_word<F>(&mut self, bytes: Vec<u8>, quoted: bool, sink: &mut F) -> Result<(), ZoneError>
    where
        F: FnMut(Token) -> Result<(), ZoneError>,
    {
        let text = String::from_utf8(bytes)
            .map_err(|_| ZoneError::at(self.line, "zone file is not valid UTF-8"))?;
        let blank_owner = self.entry_start && self.leading_blank;
        self.entry_start = false;
        sink(Token::Word {
            text,
            quoted,
            blank_owner,
            line: self.line,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lex(chunks: &[&[u8]]) -> Result<Vec<Token>, ZoneError> {
        let mut lexer = ZoneLexer::new();
        let mut out = Vec::new();
        let mut sink = |t| {
            out.push(t);
            Ok(())
        };
        for c in chunks {
            lexer.push(c, &mut sink)?;
        }
        lexer.finish(&mut sink)?;
        // Line numbers have their own test; drop them from comparisons.
        for t in &mut out {
            if let Token::Word { line, .. } = t {
                *line = 0;
            }
        }
        Ok(out)
    }

    fn word(t: &str) -> Token {
        Token::Word {
            text: t.into(),
            quoted: false,
            blank_owner: false,
            line: 0,
        }
    }

    #[test]
    fn words_comments_and_parens() {
        let toks = lex(&[b"@ IN SOA ns. host. ( 1 ; serial\n 2 3 )\nwww A 1.2.3.4 ; c\n"]).unwrap();
        let words: Vec<_> = toks
            .iter()
            .filter_map(|t| match t {
                Token::Word { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            words,
            ["@", "IN", "SOA", "ns.", "host.", "1", "2", "3", "www", "A", "1.2.3.4"]
        );
        // The parenthesised group is one logical line: exactly one Eol
        // between the SOA and the A record.
        let eols = toks.iter().filter(|t| **t == Token::Eol).count();
        assert_eq!(eols, 3, "SOA line, A line, and the final flush");
    }

    #[test]
    fn quoted_strings_keep_spaces_semicolons_and_escaped_quotes() {
        let toks = lex(&[br#"t TXT "a b; (c)" "q\"r""#]).unwrap();
        assert_eq!(
            toks[2],
            Token::Word {
                text: "a b; (c)".into(),
                quoted: true,
                blank_owner: false,
                line: 0
            }
        );
        assert_eq!(
            toks[3],
            Token::Word {
                text: "q\\\"r".into(),
                quoted: true,
                blank_owner: false,
                line: 0
            }
        );
    }

    #[test]
    fn leading_whitespace_marks_a_blank_owner_only_on_the_first_word() {
        let toks = lex(&[b"a A 1.1.1.1\n  MX 10 m.\n"]).unwrap();
        assert_eq!(
            toks[4],
            Token::Word {
                text: "MX".into(),
                quoted: false,
                blank_owner: true,
                line: 0
            }
        );
        assert_eq!(toks[5], word("10"));
    }

    #[test]
    fn every_split_point_gives_identical_tokens() {
        let src = b"$ORIGIN example.com.\n@ IN SOA ns hm ( 1 2\n 3 4 5 )\n  NS ns\nt TXT \"a b\" c\r\n";
        let whole = lex(&[src]).unwrap();
        for i in 0..=src.len() {
            assert_eq!(lex(&[&src[..i], &src[i..]]).unwrap(), whole, "split at {i}");
        }
        let bytes: Vec<&[u8]> = src.chunks(1).collect();
        assert_eq!(lex(&bytes).unwrap(), whole, "one byte at a time");
    }

    #[test]
    fn words_carry_their_line_number() {
        let mut lexer = ZoneLexer::new();
        let mut lines = Vec::new();
        let mut sink = |t| {
            if let Token::Word { line, .. } = t {
                lines.push(line);
            }
            Ok(())
        };
        lexer.push(b"a
b (
c
) d
", &mut sink).unwrap();
        assert_eq!(lines, [1, 2, 3, 4]);
    }

    #[test]
    fn malformed_input_is_an_error_with_a_line_number() {
        assert!(lex(&[b"a ( b"]).is_err());
        assert!(lex(&[b"a )"]).is_err());
        let e = lex(&[b"ok\n\"open\n"]).unwrap_err();
        assert_eq!(e.line, Some(2));
        let long = vec![b'a'; MAX_TOKEN + 1];
        assert!(lex(&[&long]).is_err());
    }
}
