// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! An article on its way in: streaming dot-unstuffing (RFC 3977 section
//! 3.1.1).

/// Removes dot-stuffing from an article as it arrives, a chunk at a time, and
/// finds the line with the single dot that ends it.
///
/// It holds a state and nothing else, however long the lines are. Bytes are
/// passed on as they are (the line ends of the client are kept) except that a
/// line that begins with two dots loses one. When the end of the article is
/// found, [`feed`](Self::feed) stops there and says how much it used, so that
/// what follows (the client's next command) is left for the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NntpDotUnstuffer {
    state: State,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// At the start of a line.
    LineStart,
    /// In a line.
    Mid,
    /// A dot at the start of a line has been seen.
    Dot,
    /// A dot and a CR at the start of a line have been seen.
    DotCr,
    /// The end of the article has been seen.
    Done,
}

impl Default for NntpDotUnstuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl NntpDotUnstuffer {
    /// An unstuffer positioned at the start of an article.
    pub fn new() -> Self {
        Self { state: State::LineStart }
    }

    /// Has the end of the article been seen?
    pub fn is_done(&self) -> bool {
        self.state == State::Done
    }

    /// Unstuffs `data`, appending the article's bytes to `out`. Returns how
    /// many bytes of `data` were used, which is all of them unless the end of
    /// the article was found among them.
    pub fn feed(&mut self, data: &[u8], out: &mut Vec<u8>) -> usize {
        for (i, &b) in data.iter().enumerate() {
            match self.state {
                State::Done => return i,
                State::LineStart => match b {
                    b'.' => self.state = State::Dot,
                    b'\n' => out.push(b),
                    _ => {
                        out.push(b);
                        self.state = State::Mid;
                    }
                },
                State::Mid => {
                    out.push(b);
                    if b == b'\n' {
                        self.state = State::LineStart;
                    }
                }
                State::Dot => match b {
                    b'\r' => self.state = State::DotCr,
                    // A bare LF ends the article as CRLF does.
                    b'\n' => self.state = State::Done,
                    b'.' => {
                        out.push(b'.');
                        self.state = State::Mid;
                    }
                    _ => {
                        // A dot that was not stuffed: keep it.
                        out.push(b'.');
                        out.push(b);
                        self.state = State::Mid;
                    }
                },
                State::DotCr => {
                    if b == b'\n' {
                        self.state = State::Done;
                    } else {
                        out.extend_from_slice(b".\r");
                        out.push(b);
                        self.state = State::Mid;
                    }
                }
            }
            if self.state == State::Done {
                return i + 1;
            }
        }
        data.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unstuff(chunks: &[&[u8]]) -> (Vec<u8>, bool, usize) {
        let mut u = NntpDotUnstuffer::new();
        let mut out = Vec::new();
        let mut used = 0;
        for c in chunks {
            used += u.feed(c, &mut out);
            if u.is_done() {
                break;
            }
        }
        (out, u.is_done(), used)
    }

    #[test]
    fn an_article_ends_at_the_line_with_one_dot() {
        let (out, done, used) = unstuff(&[b"Subject: x\r\n\r\nbody\r\n.\r\nGROUP a\r\n"]);
        assert_eq!(out, b"Subject: x\r\n\r\nbody\r\n");
        assert!(done);
        assert_eq!(used, b"Subject: x\r\n\r\nbody\r\n.\r\n".len(), "what follows is left alone");
    }

    #[test]
    fn a_stuffed_line_loses_one_dot() {
        let (out, done, _) = unstuff(&[b"..hidden\r\n...two\r\nplain.\r\n.\r\n"]);
        assert_eq!(out, b".hidden\r\n..two\r\nplain.\r\n");
        assert!(done);
    }

    #[test]
    fn an_empty_article_is_just_the_end() {
        let (out, done, used) = unstuff(&[b".\r\n"]);
        assert!(out.is_empty() && done);
        assert_eq!(used, 3);
    }

    #[test]
    fn a_dot_in_the_middle_of_a_line_is_nothing_special() {
        let (out, done, _) = unstuff(&[b"a.b\r\nc.\r\n.\r\n"]);
        assert_eq!(out, b"a.b\r\nc.\r\n");
        assert!(done);
    }

    #[test]
    fn a_bare_line_feed_after_the_dot_ends_the_article_too() {
        let (out, done, _) = unstuff(&[b"x\n.\n"]);
        assert_eq!(out, b"x\n");
        assert!(done);
    }

    #[test]
    fn a_dot_that_was_not_stuffed_is_kept() {
        let (out, done, _) = unstuff(&[b".oops\r\n.\r\n"]);
        assert_eq!(out, b".oops\r\n");
        assert!(done);
    }

    #[test]
    fn however_the_input_is_split_the_result_is_the_same() {
        let wire: &[u8] = b"A: b\r\n\r\n..one\r\n.two\r\n...\r\nlast\r\n.\r\nNEXT\r\n";
        let (whole, _, used) = unstuff(&[wire]);
        for size in 1..wire.len() {
            let chunks: Vec<&[u8]> = wire.chunks(size).collect();
            let (out, done, got) = unstuff(&chunks);
            assert_eq!((&out, done), (&whole, true), "chunks of {size}");
            // The split at the end of the article may stop early in a chunk;
            // what matters is that the same bytes were used overall.
            assert_eq!(got, used, "chunks of {size}");
        }
    }

    #[test]
    fn nothing_after_the_end_is_taken() {
        let mut u = NntpDotUnstuffer::new();
        let mut out = Vec::new();
        assert_eq!(u.feed(b".\r\nabc", &mut out), 3);
        assert_eq!(u.feed(b"abc", &mut out), 0);
        assert!(out.is_empty());
    }
}
