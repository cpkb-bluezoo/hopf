// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Incremental FTP command parser: `KEYWORD [SP TEXT] CRLF`.
//!
//! Self-contained streaming parser: [`FtpServerLexer::feed`] consumes every
//! byte it is given and keeps a command-in-progress in its own bounded
//! `verb`/`arg` scratch buffers — never in a buffer the caller has to retain
//! and re-supply. See `hopf_http::h1::parse` for the design this follows.

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Accumulating the verb, up to SP or CR.
    Verb,
    /// Accumulating the argument (post-SP), up to CR.
    Arg,
    /// Saw CR; a following LF completes the command. Any other byte means
    /// the CR was literal content, not a terminator.
    Cr,
    /// A token exceeded the cap: discard bytes up to the next CRLF (no
    /// command is produced for the discarded line), then resume normally.
    Resync,
    /// Saw CR while resyncing; a following LF ends the discarded line.
    ResyncCr,
}

/// Incremental FTP command-line parser.
pub struct FtpServerLexer {
    max_line: usize,
    state: State,
    verb: Vec<u8>,
    arg: Vec<u8>,
    have_arg: bool,
    ready: Vec<FtpCommand>,
}

impl FtpServerLexer {
    /// Create with a max token length (bytes), applied to the verb and to
    /// the argument independently.
    pub fn new(max_line: usize) -> Self {
        Self {
            max_line,
            state: State::Verb,
            verb: Vec::new(),
            arg: Vec::new(),
            have_arg: false,
            ready: Vec::new(),
        }
    }

    /// Feed inbound control bytes; returns newly completed commands.
    ///
    /// Consumes everything given — `*data` is always left empty. A line
    /// whose verb or argument exceeds the cap is silently discarded (no
    /// command produced), matching the prior lexer's behavior.
    pub fn feed(&mut self, data: &mut &[u8]) -> Vec<FtpCommand> {
        for &b in data.iter() {
            self.push_byte(b);
        }
        *data = &[];
        std::mem::take(&mut self.ready)
    }

    fn push_byte(&mut self, b: u8) {
        loop {
            match self.state {
                State::Resync => {
                    if b == b'\r' {
                        self.state = State::ResyncCr;
                    }
                    return;
                }
                State::ResyncCr => {
                    if b == b'\n' {
                        self.state = State::Verb;
                    } else if b != b'\r' {
                        self.state = State::Resync;
                    }
                    return;
                }
                State::Cr => {
                    if b == b'\n' {
                        self.finish_command();
                        self.state = State::Verb;
                        return;
                    }
                    // Literal CR, not a terminator — keep it as content and
                    // re-dispatch this byte under the token that was active.
                    self.push_content(b'\r');
                    self.state = if self.have_arg { State::Arg } else { State::Verb };
                    continue;
                }
                State::Verb => {
                    if b == b'\r' {
                        self.state = State::Cr;
                    } else if b == b' ' {
                        self.have_arg = true;
                        self.state = State::Arg;
                    } else {
                        self.push_content(b);
                    }
                    return;
                }
                State::Arg => {
                    if b == b'\r' {
                        self.state = State::Cr;
                    } else {
                        self.push_content(b);
                    }
                    return;
                }
            }
        }
    }

    fn push_content(&mut self, b: u8) {
        let buf = if self.have_arg { &mut self.arg } else { &mut self.verb };
        if buf.len() >= self.max_line {
            self.verb.clear();
            self.arg.clear();
            self.have_arg = false;
            self.state = State::Resync;
            return;
        }
        buf.push(b);
    }

    fn finish_command(&mut self) {
        let verb = String::from_utf8_lossy(&self.verb).to_ascii_uppercase();
        let arg_bytes = std::mem::take(&mut self.arg);
        self.verb.clear();
        self.have_arg = false;
        if !verb.is_empty() {
            self.ready.push(FtpCommand { verb, arg_bytes });
        }
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
        assert!(data.is_empty());
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
        assert!(a.is_empty());
        let mut b: &[u8] = b"R anonymous\r\n";
        let cmds = lex.feed(&mut b);
        assert!(b.is_empty());
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

    #[test]
    fn pipelined_commands() {
        let mut lex = FtpServerLexer::new(4096);
        let mut data: &[u8] = b"TYPE I\r\nPASV\r\nNOOP\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(cmds.len(), 3);
        assert_eq!(cmds[0].verb, "TYPE");
        assert_eq!(cmds[1].verb, "PASV");
        assert_eq!(cmds[2].verb, "NOOP");
    }

    #[test]
    fn oversized_token_discards_and_resyncs() {
        let mut lex = FtpServerLexer::new(4);
        let mut data: &[u8] = b"TOOLONG arg\r\nNOOP\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(cmds.iter().map(|c| c.verb.as_str()).collect::<Vec<_>>(), vec!["NOOP"]);
    }

    #[test]
    fn literal_cr_not_followed_by_lf_is_content() {
        let mut lex = FtpServerLexer::new(4096);
        let mut data: &[u8] = b"CWD a\rb\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(cmds[0].verb, "CWD");
        assert_eq!(cmds[0].arg_bytes, b"a\rb");
    }

    /// One byte per `feed()` call must produce identical commands to a
    /// single bulk feed, and never leave anything unconsumed.
    #[test]
    fn one_byte_at_a_time_matches_bulk_feed() {
        let msg: &[u8] = b"USER anonymous\r\nPASS x\r\nQUIT\r\n";

        let mut bulk = FtpServerLexer::new(4096);
        let mut bulk_data = msg;
        let bulk_cmds = bulk.feed(&mut bulk_data);

        let mut drip = FtpServerLexer::new(4096);
        let mut drip_cmds = Vec::new();
        for &b in msg {
            let mut one: &[u8] = &[b];
            drip_cmds.extend(drip.feed(&mut one));
            assert!(one.is_empty());
        }

        assert_eq!(bulk_cmds, drip_cmds);
        assert_eq!(bulk_cmds.len(), 3);
    }

    /// Every split point of a full command stream must be equivalent.
    #[test]
    fn all_split_points_are_equivalent() {
        let msg: &[u8] = b"USER anonymous\r\nPASS x\r\nTYPE I\r\nQUIT\r\n";
        let mut base = FtpServerLexer::new(4096);
        let mut base_data = msg;
        let base_cmds = base.feed(&mut base_data);

        for split in 1..msg.len() {
            let mut lex = FtpServerLexer::new(4096);
            let mut a: &[u8] = &msg[..split];
            let mut cmds = lex.feed(&mut a);
            assert!(a.is_empty(), "split {split} retained bytes");
            let mut b: &[u8] = &msg[split..];
            cmds.extend(lex.feed(&mut b));
            assert!(b.is_empty(), "split {split} retained bytes");
            assert_eq!(cmds, base_cmds, "split {split} diverged");
        }
    }
}
