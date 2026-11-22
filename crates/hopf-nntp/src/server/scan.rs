// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! One pass over an article's octets for the facts the overview commands
//! report: chosen header fields, the size, and the number of lines in the
//! body (RFC 3977 section 8).

/// The longest value of a field the scanner keeps.
const MAX_VALUE: usize = 8 * 1024;

/// What a scan found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArticleSummary {
    /// The first value of each field asked for, in the order asked, or `None`
    /// for a field the article does not have. A value has its folds undone
    /// and its tabs made spaces, as RFC 3977 section 8.3.2 has it.
    pub fields: Vec<Option<String>>,
    /// The article's size in octets, counting each line end as CRLF.
    pub bytes: u64,
    /// The number of lines in the body.
    pub lines: u64,
}

/// A push scanner: give it the article in chunks of any size, then ask for
/// the summary. It holds one header line at most, and a value of each field
/// asked for, however large the article is.
#[derive(Debug)]
pub struct ArticleScanner {
    names: Vec<String>,
    values: Vec<Option<Vec<u8>>>,
    /// The field the current header line belongs to, for a fold to add to.
    collecting: Option<usize>,
    line: Vec<u8>,
    line_overflow: bool,
    in_body: bool,
    body_line_open: bool,
    bytes: u64,
    lines: u64,
    /// The last byte seen, to tell a CR that ends a line from one that does
    /// not.
    pending_cr: bool,
    line_has_bytes: bool,
}

impl ArticleScanner {
    /// A scanner for the header fields in `names`, without the colon, in any
    /// case.
    pub fn new(names: &[&str]) -> Self {
        Self {
            names: names.iter().map(|n| n.to_ascii_lowercase()).collect(),
            values: vec![None; names.len()],
            collecting: None,
            line: Vec::new(),
            line_overflow: false,
            in_body: false,
            body_line_open: false,
            bytes: 0,
            lines: 0,
            pending_cr: false,
            line_has_bytes: false,
        }
    }

    /// Reads a chunk of the article. The scanner reads to the end, for the
    /// size and the lines of the body.
    pub fn feed(&mut self, chunk: &[u8]) {
        for &b in chunk {
            match b {
                b'\r' => {
                    self.pending_cr = true;
                }
                b'\n' => {
                    self.pending_cr = false;
                    self.bytes += 2;
                    self.end_line();
                }
                _ => {
                    // A CR that does not end a line is dropped.
                    self.pending_cr = false;
                    self.bytes += 1;
                    self.line_has_bytes = true;
                    if self.in_body {
                        self.body_line_open = true;
                    } else if self.line.len() < MAX_VALUE + 128 {
                        self.line.push(b);
                    } else {
                        self.line_overflow = true;
                    }
                }
            }
        }
    }

    fn end_line(&mut self) {
        if self.in_body {
            self.lines += 1;
            self.body_line_open = false;
            self.line_has_bytes = false;
            return;
        }
        let line = std::mem::take(&mut self.line);
        self.line_overflow = false;
        let empty = !self.line_has_bytes;
        self.line_has_bytes = false;
        if empty {
            self.in_body = true;
            self.collecting = None;
            return;
        }
        if matches!(line.first(), Some(b' ') | Some(b'\t')) {
            // A fold: part of the field before it.
            if let Some(i) = self.collecting {
                if let Some(v) = &mut self.values[i] {
                    if v.len() < MAX_VALUE {
                        v.extend_from_slice(&line);
                    }
                }
            }
            return;
        }
        self.collecting = None;
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            return;
        };
        let name = line[..colon].to_ascii_lowercase();
        let Some(i) = self.names.iter().position(|n| n.as_bytes() == name.as_slice()) else {
            return;
        };
        if self.values[i].is_some() {
            // Only the first occurrence counts.
            return;
        }
        let mut value = &line[colon + 1..];
        if value.first() == Some(&b' ') {
            value = &value[1..];
        }
        let mut v = value.to_vec();
        v.truncate(MAX_VALUE);
        self.values[i] = Some(v);
        self.collecting = Some(i);
    }

    /// Has the header block ended? A caller that wants only headers may stop
    /// reading then.
    pub fn headers_done(&self) -> bool {
        self.in_body
    }

    /// Ends the article and returns what was found.
    pub fn finish(mut self) -> ArticleSummary {
        // An unterminated last line is ended the way the stuffer ends it.
        if self.line_has_bytes {
            self.bytes += 2;
            self.end_line();
        }
        let fields = self
            .values
            .into_iter()
            .map(|v| {
                v.map(|bytes| {
                    String::from_utf8_lossy(&bytes)
                        .chars()
                        .map(|c| if c == '\t' { ' ' } else { c })
                        .collect()
                })
            })
            .collect();
        ArticleSummary {
            fields,
            bytes: self.bytes,
            lines: self.lines,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(names: &[&str], chunks: &[&[u8]]) -> ArticleSummary {
        let mut s = ArticleScanner::new(names);
        for c in chunks {
            s.feed(c);
        }
        s.finish()
    }

    const ARTICLE: &[u8] = b"From: a@b\r\nSubject: hello\r\n\tworld\r\nsubject: ignored\r\nX-Tab: a\tb\r\nEmpty:\r\n\r\nline one\r\nline two\r\n";

    #[test]
    fn it_finds_the_first_value_of_each_field_asked_for() {
        let s = scan(&["Subject", "from", "message-id", "empty"], &[ARTICLE]);
        assert_eq!(s.fields[0].as_deref(), Some("hello world"));
        assert_eq!(s.fields[1].as_deref(), Some("a@b"));
        assert_eq!(s.fields[2], None);
        assert_eq!(s.fields[3].as_deref(), Some(""));
    }

    #[test]
    fn a_fold_keeps_its_white_space_and_a_tab_becomes_a_space() {
        let s = scan(&["subject", "x-tab"], &[ARTICLE]);
        assert_eq!(s.fields[0].as_deref(), Some("hello\tworld".replace('\t', " ").as_str()));
        assert_eq!(s.fields[1].as_deref(), Some("a b"));
    }

    #[test]
    fn it_counts_the_octets_and_the_lines_of_the_body() {
        let s = scan(&[], &[ARTICLE]);
        assert_eq!(s.bytes, ARTICLE.len() as u64);
        assert_eq!(s.lines, 2);
    }

    #[test]
    fn an_unterminated_last_line_counts_as_a_line_with_its_line_end() {
        let s = scan(&[], &[b"A: b\r\n\r\nx\r\nlast"]);
        assert_eq!(s.lines, 2);
        assert_eq!(s.bytes, b"A: b\r\n\r\nx\r\nlast\r\n".len() as u64);
    }

    #[test]
    fn an_article_with_no_body_has_no_lines() {
        assert_eq!(scan(&[], &[b"A: b\r\n"]).lines, 0);
        assert_eq!(scan(&[], &[b"A: b\r\n\r\n"]).lines, 0);
        assert_eq!(scan(&[], &[b""]).lines, 0);
    }

    #[test]
    fn a_blank_body_line_is_a_line() {
        assert_eq!(scan(&[], &[b"A: b\r\n\r\n\r\n\r\n"]).lines, 2);
    }

    #[test]
    fn bare_line_feeds_count_as_crlf_and_stray_carriage_returns_are_nothing() {
        let s = scan(&[], &[b"A: b\n\nx\ny\rz\n"]);
        assert_eq!(s.lines, 2);
        // "A: b\r\n" "\r\n" "x\r\n" "yz\r\n"
        assert_eq!(s.bytes, 6 + 2 + 3 + 4);
    }

    #[test]
    fn however_the_article_is_split_the_summary_is_the_same() {
        let whole = scan(&["subject", "from"], &[ARTICLE]);
        for size in 1..ARTICLE.len() {
            let chunks: Vec<&[u8]> = ARTICLE.chunks(size).collect();
            assert_eq!(scan(&["subject", "from"], &chunks), whole, "chunks of {size}");
        }
    }

    #[test]
    fn a_huge_header_is_held_to_a_bound() {
        let mut s = ArticleScanner::new(&["subject"]);
        s.feed(b"Subject: ");
        for _ in 0..1000 {
            s.feed(&[b'x'; 1024]);
        }
        s.feed(b"\r\n\r\nbody\r\n");
        let r = s.finish();
        assert!(r.fields[0].as_ref().unwrap().len() <= MAX_VALUE);
        assert_eq!(r.lines, 1);
    }
}
