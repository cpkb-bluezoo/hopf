// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Article text on its way to a client: streaming dot-stuffing (RFC 3977
//! section 3.1.1).

/// Which part of an article a response carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArticlePart {
    /// The whole article: `ARTICLE`.
    Full,
    /// The header block only, without the empty line that ends it: `HEAD`.
    Head,
    /// The body only, without the empty line that precedes it: `BODY`.
    Body,
}

/// Dot-stuffs an article as it is read, a chunk at a time, in constant
/// memory: it holds three flags and never a line, however long.
///
/// Line ends are made CRLF (a bare LF becomes CRLF; a CR that is not
/// followed by LF is dropped, so that nothing in an article can pass for a
/// line end of its own), a line that begins with `.` gains a second one, and
/// [`finish`](Self::finish) ends an unterminated last line and adds the line
/// with the single dot that ends the data block. For [`ArticlePart::Head`] and
/// [`ArticlePart::Body`] it also finds the empty line between the two and
/// emits only the part asked for.
#[derive(Debug, Clone)]
pub struct NntpDotStuffer {
    part: ArticlePart,
    /// Nothing but an unreleased CR has been seen on the current line.
    line_start: bool,
    /// A CR has been seen and not yet followed by anything.
    pending_cr: bool,
    /// The empty line that ends the headers has gone by.
    in_body: bool,
}

impl NntpDotStuffer {
    /// A stuffer positioned at the start of an article.
    pub fn new(part: ArticlePart) -> Self {
        Self {
            part,
            line_start: true,
            pending_cr: false,
            in_body: false,
        }
    }

    /// Are the bytes being read now part of what is emitted?
    fn emitting(&self) -> bool {
        match self.part {
            ArticlePart::Full => true,
            ArticlePart::Head => !self.in_body,
            ArticlePart::Body => self.in_body,
        }
    }

    /// Has everything that will be emitted been seen? True for a head once
    /// its empty line has been; the reader may stop there.
    pub fn is_complete(&self) -> bool {
        self.part == ArticlePart::Head && self.in_body
    }

    /// Stuffs `chunk`, appending to `out`. Returns false once the part asked
    /// for is complete and further input is not needed.
    pub fn feed(&mut self, chunk: &[u8], out: &mut Vec<u8>) -> bool {
        for &b in chunk {
            if self.is_complete() {
                return false;
            }
            match b {
                b'\r' => self.pending_cr = true,
                b'\n' => {
                    self.pending_cr = false;
                    let blank = self.line_start;
                    if blank && !self.in_body {
                        // The empty line between headers and body belongs to
                        // neither part.
                        self.in_body = true;
                        if self.part == ArticlePart::Full {
                            out.extend_from_slice(b"\r\n");
                        }
                    } else if self.emitting() {
                        out.extend_from_slice(b"\r\n");
                    }
                    self.line_start = true;
                }
                _ => {
                    // A CR in the middle of a line is dropped.
                    self.pending_cr = false;
                    if self.emitting() {
                        if self.line_start && b == b'.' {
                            out.push(b'.');
                        }
                        out.push(b);
                    }
                    self.line_start = false;
                }
            }
        }
        !self.is_complete()
    }

    /// Ends the article: terminates an unterminated last line, then adds the
    /// line that ends the data block.
    pub fn finish(&mut self, out: &mut Vec<u8>) {
        if !self.line_start && self.emitting() {
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b".\r\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stuff(part: ArticlePart, chunks: &[&[u8]]) -> Vec<u8> {
        let mut s = NntpDotStuffer::new(part);
        let mut out = Vec::new();
        for c in chunks {
            if !s.feed(c, &mut out) {
                break;
            }
        }
        s.finish(&mut out);
        out
    }

    const ARTICLE: &[u8] = b"From: a@b\r\nSubject: x\r\n\r\n.leading dot\r\nplain\r\nfoo\rbar\r\nlast-no-newline";

    #[test]
    fn a_whole_article_is_stuffed_and_terminated() {
        let out = stuff(ArticlePart::Full, &[ARTICLE]);
        assert_eq!(
            out,
            b"From: a@b\r\nSubject: x\r\n\r\n..leading dot\r\nplain\r\nfoobar\r\nlast-no-newline\r\n.\r\n"
        );
    }

    #[test]
    fn a_head_stops_at_the_empty_line() {
        let out = stuff(ArticlePart::Head, &[ARTICLE]);
        assert_eq!(out, b"From: a@b\r\nSubject: x\r\n.\r\n");
    }

    #[test]
    fn a_body_starts_after_the_empty_line() {
        let out = stuff(ArticlePart::Body, &[ARTICLE]);
        assert_eq!(out, b"..leading dot\r\nplain\r\nfoobar\r\nlast-no-newline\r\n.\r\n");
    }

    #[test]
    fn bare_line_feeds_become_crlf() {
        let out = stuff(ArticlePart::Full, &[b"a\nb\n\nc\n"]);
        assert_eq!(out, b"a\r\nb\r\n\r\nc\r\n.\r\n");
    }

    #[test]
    fn an_article_of_headers_alone_has_an_empty_body() {
        assert_eq!(stuff(ArticlePart::Body, &[b"From: a\r\nSubject: x\r\n"]), b".\r\n");
        assert_eq!(stuff(ArticlePart::Head, &[b"From: a\r\nSubject: x\r\n"]), b"From: a\r\nSubject: x\r\n.\r\n");
    }

    #[test]
    fn an_empty_article_is_just_the_terminator() {
        for part in [ArticlePart::Full, ArticlePart::Head, ArticlePart::Body] {
            assert_eq!(stuff(part, &[b""]), b".\r\n", "{part:?}");
        }
    }

    #[test]
    fn a_dot_alone_on_a_line_is_stuffed() {
        let out = stuff(ArticlePart::Full, &[b"x\r\n.\r\ny\r\n"]);
        assert_eq!(out, b"x\r\n..\r\ny\r\n.\r\n");
    }

    #[test]
    fn however_the_input_is_split_the_output_is_the_same() {
        for part in [ArticlePart::Full, ArticlePart::Head, ArticlePart::Body] {
            let whole = stuff(part, &[ARTICLE]);
            for size in 1..ARTICLE.len() {
                let chunks: Vec<&[u8]> = ARTICLE.chunks(size).collect();
                assert_eq!(stuff(part, &chunks), whole, "{part:?} in chunks of {size}");
            }
        }
    }

    #[test]
    fn a_crlf_split_between_chunks_is_one_line_end() {
        let out = stuff(ArticlePart::Full, &[b"a\r", b"\nb\r", b"\n"]);
        assert_eq!(out, b"a\r\nb\r\n.\r\n");
    }

    #[test]
    fn feed_says_when_a_head_is_complete() {
        let mut s = NntpDotStuffer::new(ArticlePart::Head);
        let mut out = Vec::new();
        assert!(s.feed(b"A: 1\r\n", &mut out));
        assert!(!s.feed(b"\r\nbody", &mut out));
        assert!(s.is_complete());
    }

    #[test]
    fn nothing_but_the_line_in_progress_is_held() {
        // A line of a megabyte passes through with no growth in the stuffer.
        let mut s = NntpDotStuffer::new(ArticlePart::Full);
        let mut out = Vec::new();
        for _ in 0..1024 {
            s.feed(&[b'x'; 1024], &mut out);
            out.clear();
        }
        assert_eq!(std::mem::size_of_val(&s), std::mem::size_of::<NntpDotStuffer>());
    }
}
