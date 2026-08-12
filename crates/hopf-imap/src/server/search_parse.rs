// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! IMAP SEARCH syntax to [`hopf_mailbox::SearchCriteria`] parsing.

use hopf_mailbox::{Flag, MessageSet, SearchCriteria};

/// Error from SEARCH argument parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchParseError {
    /// Human-readable description.
    pub message: String,
    /// Byte offset into the input (best-effort).
    pub position: usize,
}

impl std::fmt::Display for SearchParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} at {}", self.message, self.position)
    }
}

impl std::error::Error for SearchParseError {}

/// Parse IMAP SEARCH keys into a [`SearchCriteria`] tree.
///
/// Empty input yields [`SearchCriteria::All`]. Multiple keys are ANDed.
pub fn parse_search(input: &str) -> Result<SearchCriteria, SearchParseError> {
    let mut p = Parser {
        input,
        pos: 0,
        len: input.len(),
    };
    p.skip_ws();
    if p.pos >= p.len {
        return Ok(SearchCriteria::All);
    }
    let result = p.parse_keys()?;
    p.skip_ws();
    if p.pos < p.len {
        return Err(p.err("unexpected input after search expression"));
    }
    Ok(result)
}

struct Parser<'a> {
    input: &'a str,
    pos: usize,
    len: usize,
}

impl<'a> Parser<'a> {
    fn err(&self, message: impl Into<String>) -> SearchParseError {
        SearchParseError {
            message: message.into(),
            position: self.pos,
        }
    }

    fn skip_ws(&mut self) {
        while self.pos < self.len && self.input.as_bytes()[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.as_bytes().get(self.pos).copied()
    }

    fn parse_keys(&mut self) -> Result<SearchCriteria, SearchParseError> {
        let mut parts = Vec::new();
        loop {
            self.skip_ws();
            if self.pos >= self.len {
                break;
            }
            if self.peek() == Some(b')') {
                break;
            }
            parts.push(self.parse_key()?);
        }
        Ok(match parts.len() {
            0 => SearchCriteria::All,
            1 => parts.pop().unwrap(),
            _ => SearchCriteria::And(parts),
        })
    }

    fn parse_key(&mut self) -> Result<SearchCriteria, SearchParseError> {
        self.skip_ws();
        match self.peek() {
            Some(b'(') => {
                self.pos += 1;
                let inner = self.parse_keys()?;
                self.skip_ws();
                if self.peek() != Some(b')') {
                    return Err(self.err("missing closing parenthesis"));
                }
                self.pos += 1;
                Ok(inner)
            }
            Some(b) if b.is_ascii_digit() || b == b'*' => self.parse_sequence_set(),
            Some(_) => {
                let keyword = self
                    .parse_atom()?
                    .ok_or_else(|| self.err("expected search key"))?;
                self.parse_keyword(&keyword.to_ascii_uppercase())
            }
            None => Err(self.err("expected search key")),
        }
    }

    fn parse_keyword(&mut self, keyword: &str) -> Result<SearchCriteria, SearchParseError> {
        Ok(match keyword {
            "ALL" => SearchCriteria::All,
            "ANSWERED" => SearchCriteria::answered(),
            "DELETED" => SearchCriteria::deleted(),
            "DRAFT" => SearchCriteria::draft(),
            "FLAGGED" => SearchCriteria::flagged(),
            "NEW" => SearchCriteria::New,
            "OLD" => SearchCriteria::Old,
            "RECENT" => SearchCriteria::recent(),
            "SEEN" => SearchCriteria::seen(),
            "UNANSWERED" => SearchCriteria::NotFlag(Flag::Answered),
            "UNDELETED" => SearchCriteria::NotFlag(Flag::Deleted),
            "UNDRAFT" => SearchCriteria::NotFlag(Flag::Draft),
            "UNFLAGGED" => SearchCriteria::NotFlag(Flag::Flagged),
            "UNSEEN" => SearchCriteria::unseen(),
            "BCC" => SearchCriteria::Header {
                name: "Bcc".into(),
                pattern: self.parse_string()?,
            },
            "CC" => SearchCriteria::Header {
                name: "Cc".into(),
                pattern: self.parse_string()?,
            },
            "FROM" => SearchCriteria::from(self.parse_string()?),
            "SUBJECT" => SearchCriteria::subject(self.parse_string()?),
            "TO" => SearchCriteria::Header {
                name: "To".into(),
                pattern: self.parse_string()?,
            },
            "HEADER" => {
                let name = self
                    .parse_atom()?
                    .ok_or_else(|| self.err("expected header name"))?;
                let pattern = self.parse_string()?;
                SearchCriteria::Header { name, pattern }
            }
            "BODY" => SearchCriteria::body(self.parse_string()?),
            "TEXT" => SearchCriteria::text(self.parse_string()?),
            "BEFORE" => {
                let (y, m, d) = self.parse_date()?;
                SearchCriteria::Before(y, m, d)
            }
            "ON" => {
                let (y, m, d) = self.parse_date()?;
                SearchCriteria::On(y, m, d)
            }
            "SINCE" => {
                let (y, m, d) = self.parse_date()?;
                SearchCriteria::Since(y, m, d)
            }
            "SENTBEFORE" => {
                let (y, m, d) = self.parse_date()?;
                SearchCriteria::SentBefore(y, m, d)
            }
            "SENTON" => {
                let (y, m, d) = self.parse_date()?;
                SearchCriteria::SentOn(y, m, d)
            }
            "SENTSINCE" => {
                let (y, m, d) = self.parse_date()?;
                SearchCriteria::SentSince(y, m, d)
            }
            "LARGER" => SearchCriteria::Larger(self.parse_number()?),
            "SMALLER" => SearchCriteria::Smaller(self.parse_number()?),
            "KEYWORD" => SearchCriteria::Keyword(
                self.parse_atom()?
                    .ok_or_else(|| self.err("expected keyword"))?,
            ),
            "UNKEYWORD" => SearchCriteria::Unkeyword(
                self.parse_atom()?
                    .ok_or_else(|| self.err("expected keyword"))?,
            ),
            "UID" => SearchCriteria::Uid(self.parse_message_set()?),
            "MODSEQ" => {
                // Simplified: MODSEQ value (skip optional entry-name/type).
                self.skip_ws();
                if self.peek() == Some(b'"') {
                    let _ = self.parse_quoted()?;
                    self.skip_ws();
                    let _ = self.parse_atom()?;
                    self.skip_ws();
                }
                SearchCriteria::ModSeq(self.parse_number()?)
            }
            "NOT" => SearchCriteria::negate(self.parse_key()?),
            "OR" => {
                let a = self.parse_key()?;
                let b = self.parse_key()?;
                SearchCriteria::or(a, b)
            }
            _ => return Err(self.err(format!("unknown search key: {keyword}"))),
        })
    }

    fn parse_sequence_set(&mut self) -> Result<SearchCriteria, SearchParseError> {
        let set = self.parse_message_set()?;
        Ok(SearchCriteria::Sequence(set))
    }

    fn parse_message_set(&mut self) -> Result<MessageSet, SearchParseError> {
        self.skip_ws();
        let start = self.pos;
        while self.pos < self.len {
            let c = self.input.as_bytes()[self.pos];
            if c.is_ascii_digit() || c == b'*' || c == b':' || c == b',' {
                self.pos += 1;
            } else {
                break;
            }
        }
        if start == self.pos {
            return Err(self.err("expected message set"));
        }
        MessageSet::parse(&self.input[start..self.pos]).map_err(|e| self.err(e.to_string()))
    }

    fn parse_number(&mut self) -> Result<u64, SearchParseError> {
        self.skip_ws();
        let start = self.pos;
        while self.pos < self.len && self.input.as_bytes()[self.pos].is_ascii_digit() {
            self.pos += 1;
        }
        if start == self.pos {
            return Err(self.err("expected number"));
        }
        self.input[start..self.pos]
            .parse()
            .map_err(|_| self.err("invalid number"))
    }

    fn parse_date(&mut self) -> Result<(i32, u32, u32), SearchParseError> {
        self.skip_ws();
        let s = if self.peek() == Some(b'"') {
            self.parse_quoted()?
        } else {
            self.parse_atom()?
                .ok_or_else(|| self.err("expected date"))?
        };
        parse_imap_date(&s).ok_or_else(|| self.err(format!("invalid date: {s}")))
    }

    fn parse_string(&mut self) -> Result<String, SearchParseError> {
        self.skip_ws();
        match self.peek() {
            Some(b'"') => self.parse_quoted(),
            Some(b'{') => self.parse_inline_literal(),
            _ => self
                .parse_atom()?
                .ok_or_else(|| self.err("expected string")),
        }
    }

    fn parse_quoted(&mut self) -> Result<String, SearchParseError> {
        if self.peek() != Some(b'"') {
            return Err(self.err("expected quoted string"));
        }
        self.pos += 1;
        // Accumulate raw bytes and decode once at the end — pushing
        // `c as char` byte-by-byte corrupts any non-ASCII content, since a
        // multi-byte UTF-8 sequence's bytes each get reinterpreted as an
        // independent Latin-1 codepoint.
        let mut out = Vec::new();
        while self.pos < self.len {
            let c = self.input.as_bytes()[self.pos];
            if c == b'"' {
                self.pos += 1;
                return String::from_utf8(out).map_err(|_| self.err("invalid utf-8 in quoted string"));
            }
            if c == b'\\' && self.pos + 1 < self.len {
                self.pos += 1;
                out.push(self.input.as_bytes()[self.pos]);
                self.pos += 1;
                continue;
            }
            out.push(c);
            self.pos += 1;
        }
        Err(self.err("unterminated quoted string"))
    }

    fn parse_inline_literal(&mut self) -> Result<String, SearchParseError> {
        // Literals are normally consumed by the wire lexer; this handles
        // already-spliced `{n}CRLF<data>` forms in the args string.
        if self.peek() != Some(b'{') {
            return Err(self.err("expected literal"));
        }
        self.pos += 1;
        let digits_start = self.pos;
        while self.pos < self.len && self.input.as_bytes()[self.pos].is_ascii_digit() {
            self.pos += 1;
        }
        let digits_end = self.pos;
        if self.peek() == Some(b'+') {
            self.pos += 1;
        }
        if self.peek() != Some(b'}') {
            return Err(self.err("invalid literal syntax"));
        }
        let n: usize = self.input[digits_start..digits_end]
            .parse()
            .map_err(|_| self.err("invalid literal length"))?;
        self.pos += 1; // }
        if self.peek() == Some(b'\r') {
            self.pos += 1;
        }
        if self.peek() == Some(b'\n') {
            self.pos += 1;
        }
        if self.pos + n > self.len {
            return Err(self.err("literal extends beyond input"));
        }
        let s = self.input[self.pos..self.pos + n].to_string();
        self.pos += n;
        Ok(s)
    }

    fn parse_atom(&mut self) -> Result<Option<String>, SearchParseError> {
        self.skip_ws();
        let start = self.pos;
        while self.pos < self.len {
            let c = self.input.as_bytes()[self.pos];
            if matches!(
                c,
                b'(' | b')' | b'{' | b' ' | b'"' | b'\\' | b']' | b'%' | b'*'
            ) || !c.is_ascii_graphic()
            {
                break;
            }
            self.pos += 1;
        }
        if start == self.pos {
            Ok(None)
        } else {
            Ok(Some(self.input[start..self.pos].to_string()))
        }
    }
}

fn parse_imap_date(s: &str) -> Option<(i32, u32, u32)> {
    // d-MMM-yyyy or dd-MMM-yyyy
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 {
        return None;
    }
    let d: u32 = parts[0].parse().ok()?;
    let m = match parts[1].to_ascii_lowercase().as_str() {
        "jan" => 1,
        "feb" => 2,
        "mar" => 3,
        "apr" => 4,
        "may" => 5,
        "jun" => 6,
        "jul" => 7,
        "aug" => 8,
        "sep" => 9,
        "oct" => 10,
        "nov" => 11,
        "dec" => 12,
        _ => return None,
    };
    let y: i32 = parts[2].parse().ok()?;
    if d < 1 || d > 31 {
        return None;
    }
    Some((y, m, d))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_all() {
        assert!(matches!(parse_search("").unwrap(), SearchCriteria::All));
    }

    #[test]
    fn unseen() {
        assert!(matches!(
            parse_search("UNSEEN").unwrap(),
            SearchCriteria::NotFlag(Flag::Seen)
        ));
    }

    #[test]
    fn and_keys() {
        let c = parse_search("UNSEEN FROM \"alice\"").unwrap();
        match c {
            SearchCriteria::And(v) => assert_eq!(v.len(), 2),
            _ => panic!("expected AND"),
        }
    }

    #[test]
    fn or_not() {
        let c = parse_search("OR SEEN FLAGGED").unwrap();
        assert!(matches!(c, SearchCriteria::Or(_, _)));
        let c = parse_search("NOT DELETED").unwrap();
        assert!(matches!(c, SearchCriteria::Not(_)));
    }

    #[test]
    fn sequence_and_uid() {
        let c = parse_search("1:5,7").unwrap();
        assert!(matches!(c, SearchCriteria::Sequence(_)));
        let c = parse_search("UID 10:*").unwrap();
        assert!(matches!(c, SearchCriteria::Uid(_)));
    }

    #[test]
    fn larger_smaller() {
        assert!(matches!(
            parse_search("LARGER 100").unwrap(),
            SearchCriteria::Larger(100)
        ));
        assert!(matches!(
            parse_search("SMALLER 50").unwrap(),
            SearchCriteria::Smaller(50)
        ));
    }

    #[test]
    fn date_quoted() {
        let c = parse_search("SINCE \"1-Jan-2024\"").unwrap();
        assert!(matches!(c, SearchCriteria::Since(2024, 1, 1)));
    }

    #[test]
    fn paren_group() {
        let c = parse_search("(UNSEEN FLAGGED)").unwrap();
        assert!(matches!(c, SearchCriteria::And(_)));
    }

    #[test]
    fn unknown_key_errors() {
        assert!(parse_search("XYZ").is_err());
    }

    /// Issue #195: a quoted SEARCH string argument containing non-ASCII
    /// UTF-8 content must decode intact, not get mangled by treating each
    /// byte of a multi-byte sequence as an independent Latin-1 codepoint.
    #[test]
    fn quoted_string_preserves_non_ascii_utf8() {
        let c = parse_search("FROM \"café\"").unwrap();
        match c {
            SearchCriteria::Header { name, pattern } => {
                assert_eq!(name, "From");
                assert_eq!(pattern, "café");
            }
            _ => panic!("expected Header"),
        }
    }

    #[test]
    fn quoted_string_preserves_multibyte_and_emoji() {
        let c = parse_search("SUBJECT \"日本語 🎉\"").unwrap();
        match c {
            SearchCriteria::Header { pattern, .. } => assert_eq!(pattern, "日本語 🎉"),
            _ => panic!("expected Header"),
        }
    }
}
