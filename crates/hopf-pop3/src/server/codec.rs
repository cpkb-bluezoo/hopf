// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Incremental POP3 command parser: `KEYWORD [SP TEXT] CRLF`.
//!
//! Self-contained streaming parser: [`Pop3ServerLexer::feed`] consumes every
//! byte it is given and keeps a command-in-progress in its own bounded
//! `verb`/`arg` scratch buffers — never in a buffer the caller has to retain
//! and re-supply.

/// Default RFC 1939 command-line length limit (octets), applied
/// independently to the verb and to the argument.
pub const MAX_COMMAND_LINE: usize = 512;

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

/// Incremental POP3 command-line parser.
pub struct Pop3ServerLexer {
    max_line: usize,
    state: State,
    verb: Vec<u8>,
    arg: Vec<u8>,
    have_arg: bool,
    ready: Vec<Pop3Command>,
    line_too_long: bool,
}

impl Pop3ServerLexer {
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
            line_too_long: false,
        }
    }

    /// Feed inbound control bytes; returns newly completed commands.
    ///
    /// Consumes everything given — `*data` is always left empty. When a
    /// token exceeds the length cap, that line produces no command;
    /// [`took_line_too_long`](Self::took_line_too_long) reports it.
    pub fn feed(&mut self, data: &mut &[u8]) -> Vec<Pop3Command> {
        for &b in data.iter() {
            self.push_byte(b);
        }
        *data = &[];
        std::mem::take(&mut self.ready)
    }

    /// Whether the last feed hit the token-length cap (clears the flag).
    pub fn took_line_too_long(&mut self) -> bool {
        std::mem::take(&mut self.line_too_long)
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
            self.line_too_long = true;
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
            self.ready.push(Pop3Command { verb, arg_bytes });
        }
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
        assert!(data.is_empty());
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
        assert!(a.is_empty());
        let mut b: &[u8] = b"T\r\n";
        let cmds = lex.feed(&mut b);
        assert!(b.is_empty());
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

    #[test]
    fn blank_line_produces_no_command() {
        let mut lex = Pop3ServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"\r\nSTAT\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].verb, "STAT");
    }

    #[test]
    fn oversized_token_discards_and_resyncs() {
        let mut lex = Pop3ServerLexer::new(4);
        let mut data: &[u8] = b"TOOLONG arg\r\nOK\r\n";
        let cmds = lex.feed(&mut data);
        assert!(lex.took_line_too_long());
        // Only the well-formed line after the overflow survives.
        assert_eq!(cmds.iter().map(|c| c.verb.as_str()).collect::<Vec<_>>(), vec!["OK"]);
    }

    #[test]
    fn literal_cr_not_followed_by_lf_is_content() {
        let mut lex = Pop3ServerLexer::new(MAX_COMMAND_LINE);
        // A bare CR mid-argument is not a terminator; only CRLF is.
        let mut data: &[u8] = b"PASS a\rb\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(cmds[0].verb, "PASS");
        assert_eq!(cmds[0].arg_bytes, b"a\rb");
    }

    /// One byte per `feed()` call must produce identical commands to a
    /// single bulk feed, and never leave anything unconsumed.
    #[test]
    fn one_byte_at_a_time_matches_bulk_feed() {
        let msg: &[u8] = b"USER alice\r\nPASS secret\r\nQUIT\r\n";

        let mut bulk = Pop3ServerLexer::new(MAX_COMMAND_LINE);
        let mut bulk_data = msg;
        let bulk_cmds = bulk.feed(&mut bulk_data);

        let mut drip = Pop3ServerLexer::new(MAX_COMMAND_LINE);
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
        let msg: &[u8] = b"USER alice\r\nPASS s3cret\r\nSTAT\r\nQUIT\r\n";
        let mut base = Pop3ServerLexer::new(MAX_COMMAND_LINE);
        let mut base_data = msg;
        let base_cmds = base.feed(&mut base_data);

        for split in 1..msg.len() {
            let mut lex = Pop3ServerLexer::new(MAX_COMMAND_LINE);
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
