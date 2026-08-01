// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Incremental, semantic FTP command parser: `KEYWORD [SP TEXT] CRLF`.
//!
//! Self-contained streaming parser: [`FtpServerLexer::feed`] consumes every
//! byte it is given and keeps a command-in-progress in its own bounded
//! `verb`/`arg` scratch buffers — never in a buffer the caller has to retain
//! and re-supply. See `hopf_http::h1::parse` for the design this follows.
//!
//! Unlike POP3/SMTP's server codecs, [`FtpCommand`]'s path/text arguments
//! stay as raw bytes rather than being decoded into a `String` here: RFC
//! 2640 (`OPTS UTF8`) charset decoding depends on a per-connection runtime
//! toggle (`FtpControlHandler::utf8`) the lexer has no access to, so that
//! step has to stay at the dispatch layer — see
//! [`crate::server::utf8::decode_arg`]. What the lexer *does* own is verb
//! identity: `CWD`/`XCWD`, `CDUP`/`XCUP`, `PWD`/`XPWD`, `RMD`/`XRMD`, and
//! `MKD`/`XMKD` are consolidated into one variant each here, instead of
//! dispatch needing an alias-aware `|` pattern per pair.

/// Command-line length limit (octets), applied independently to the verb
/// and to the argument.
pub const MAX_COMMAND_LINE: usize = 4096;

/// A fully parsed FTP command. Path/text arguments are raw bytes — see the
/// module docs for why charset decoding stays at the dispatch layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FtpCommand {
    /// `USER name`
    User(Vec<u8>),
    /// `PASS string`
    Pass(Vec<u8>),
    /// `ACCT` (not implemented; argument ignored)
    Acct,
    /// `CWD` / `XCWD`
    Cwd(Vec<u8>),
    /// `CDUP` / `XCUP`
    Cdup,
    /// `PWD` / `XPWD`
    Pwd,
    /// `QUIT`
    Quit,
    /// `REIN`
    Rein,
    /// `NOOP`
    Noop,
    /// `SYST`
    Syst,
    /// `TYPE`
    Type(Vec<u8>),
    /// `STRU`
    Stru(Vec<u8>),
    /// `MODE`
    Mode(Vec<u8>),
    /// `PASV`
    Pasv,
    /// `EPSV`
    Epsv(Vec<u8>),
    /// `PORT`
    Port(Vec<u8>),
    /// `EPRT`
    Eprt(Vec<u8>),
    /// `RETR`
    Retr(Vec<u8>),
    /// `STOR`
    Stor(Vec<u8>),
    /// `APPE`
    Appe(Vec<u8>),
    /// `STOU` (argument ignored — server assigns the unique name)
    Stou,
    /// `LIST`
    List(Vec<u8>),
    /// `NLST`
    Nlst(Vec<u8>),
    /// `MLSD`
    Mlsd(Vec<u8>),
    /// `MLST`
    Mlst(Vec<u8>),
    /// `SIZE`
    Size(Vec<u8>),
    /// `MDTM`
    Mdtm(Vec<u8>),
    /// `DELE`
    Dele(Vec<u8>),
    /// `RMD` / `XRMD`
    Rmd(Vec<u8>),
    /// `MKD` / `XMKD`
    Mkd(Vec<u8>),
    /// `RNFR`
    Rnfr(Vec<u8>),
    /// `RNTO`
    Rnto(Vec<u8>),
    /// `REST`
    Rest(Vec<u8>),
    /// `ABOR`
    Abor,
    /// `STAT` (argument, if any, is a path to list)
    Stat(Vec<u8>),
    /// `HELP` / `FEAT`
    Feat,
    /// `OPTS`
    Opts(Vec<u8>),
    /// `AUTH` (RFC 2228 — TLS negotiation, not a SASL exchange)
    Auth(Vec<u8>),
    /// `PBSZ`
    Pbsz(Vec<u8>),
    /// `PROT`
    Prot(Vec<u8>),
    /// `CCC` (not supported; argument ignored)
    Ccc,
    /// `ALLO` (declared byte count; dispatched to
    /// [`crate::server::fs::FtpFileSystem::allocate_space`])
    Allo(Vec<u8>),
    /// `SITE` (application-defined subcommand; dispatched to
    /// [`crate::server::handler::FtpConnectionHandler::handle_site_command`])
    Site(Vec<u8>),
    /// `SMNT` (not implemented; argument ignored)
    Smnt,
    /// A verb the lexer doesn't recognise at all.
    Unknown {
        /// The unrecognised verb.
        verb: String,
    },
}

impl FtpCommand {
    /// The raw argument bytes for commands that carry one, `None` for
    /// argless commands (or commands whose argument is always ignored).
    pub fn arg_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::User(b)
            | Self::Pass(b)
            | Self::Cwd(b)
            | Self::Type(b)
            | Self::Stru(b)
            | Self::Mode(b)
            | Self::Epsv(b)
            | Self::Port(b)
            | Self::Eprt(b)
            | Self::Retr(b)
            | Self::Stor(b)
            | Self::Appe(b)
            | Self::List(b)
            | Self::Nlst(b)
            | Self::Mlsd(b)
            | Self::Mlst(b)
            | Self::Size(b)
            | Self::Mdtm(b)
            | Self::Dele(b)
            | Self::Rmd(b)
            | Self::Mkd(b)
            | Self::Rnfr(b)
            | Self::Rnto(b)
            | Self::Rest(b)
            | Self::Stat(b)
            | Self::Opts(b)
            | Self::Auth(b)
            | Self::Pbsz(b)
            | Self::Prot(b)
            | Self::Site(b)
            | Self::Allo(b) => Some(b),
            _ => None,
        }
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

/// Incremental, semantic FTP command-line parser. See the module docs.
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
        if verb.is_empty() {
            return;
        }
        self.ready.push(build_command(&verb, arg_bytes));
    }
}

fn build_command(verb: &str, arg: Vec<u8>) -> FtpCommand {
    match verb {
        "USER" => FtpCommand::User(arg),
        "PASS" => FtpCommand::Pass(arg),
        "ACCT" => FtpCommand::Acct,
        "CWD" | "XCWD" => FtpCommand::Cwd(arg),
        "CDUP" | "XCUP" => FtpCommand::Cdup,
        "PWD" | "XPWD" => FtpCommand::Pwd,
        "QUIT" => FtpCommand::Quit,
        "REIN" => FtpCommand::Rein,
        "NOOP" => FtpCommand::Noop,
        "SYST" => FtpCommand::Syst,
        "TYPE" => FtpCommand::Type(arg),
        "STRU" => FtpCommand::Stru(arg),
        "MODE" => FtpCommand::Mode(arg),
        "PASV" => FtpCommand::Pasv,
        "EPSV" => FtpCommand::Epsv(arg),
        "PORT" => FtpCommand::Port(arg),
        "EPRT" => FtpCommand::Eprt(arg),
        "RETR" => FtpCommand::Retr(arg),
        "STOR" => FtpCommand::Stor(arg),
        "APPE" => FtpCommand::Appe(arg),
        "STOU" => FtpCommand::Stou,
        "LIST" => FtpCommand::List(arg),
        "NLST" => FtpCommand::Nlst(arg),
        "MLSD" => FtpCommand::Mlsd(arg),
        "MLST" => FtpCommand::Mlst(arg),
        "SIZE" => FtpCommand::Size(arg),
        "MDTM" => FtpCommand::Mdtm(arg),
        "DELE" => FtpCommand::Dele(arg),
        "RMD" | "XRMD" => FtpCommand::Rmd(arg),
        "MKD" | "XMKD" => FtpCommand::Mkd(arg),
        "RNFR" => FtpCommand::Rnfr(arg),
        "RNTO" => FtpCommand::Rnto(arg),
        "REST" => FtpCommand::Rest(arg),
        "ABOR" => FtpCommand::Abor,
        "STAT" => FtpCommand::Stat(arg),
        "HELP" | "FEAT" => FtpCommand::Feat,
        "OPTS" => FtpCommand::Opts(arg),
        "AUTH" => FtpCommand::Auth(arg),
        "PBSZ" => FtpCommand::Pbsz(arg),
        "PROT" => FtpCommand::Prot(arg),
        "CCC" => FtpCommand::Ccc,
        "ALLO" => FtpCommand::Allo(arg),
        "SITE" => FtpCommand::Site(arg),
        "SMNT" => FtpCommand::Smnt,
        _ => FtpCommand::Unknown { verb: verb.to_string() },
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
        assert_eq!(cmds, vec![FtpCommand::Cwd(b"my dir".to_vec())]);
    }

    #[test]
    fn cwd_alias_xcwd_same_variant() {
        let mut lex = FtpServerLexer::new(4096);
        let mut data: &[u8] = b"XCWD /tmp\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(cmds, vec![FtpCommand::Cwd(b"/tmp".to_vec())]);
    }

    #[test]
    fn parse_noop() {
        let mut lex = FtpServerLexer::new(4096);
        let mut data: &[u8] = b"NOOP\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(cmds, vec![FtpCommand::Noop]);
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
        assert_eq!(cmds, vec![FtpCommand::User(b"anonymous".to_vec())]);
    }

    #[test]
    fn preserves_utf8_arg_bytes() {
        let mut lex = FtpServerLexer::new(4096);
        let mut line = Vec::from(&b"CWD "[..]);
        line.extend_from_slice("café".as_bytes());
        line.extend_from_slice(b"\r\n");
        let mut data = line.as_slice();
        let cmds = lex.feed(&mut data);
        assert_eq!(cmds, vec![FtpCommand::Cwd("café".as_bytes().to_vec())]);
    }

    #[test]
    fn pipelined_commands() {
        let mut lex = FtpServerLexer::new(4096);
        let mut data: &[u8] = b"TYPE I\r\nPASV\r\nNOOP\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(
            cmds,
            vec![FtpCommand::Type(b"I".to_vec()), FtpCommand::Pasv, FtpCommand::Noop]
        );
    }

    #[test]
    fn argless_commands() {
        let mut lex = FtpServerLexer::new(4096);
        let mut data: &[u8] =
            b"CDUP\r\nPWD\r\nQUIT\r\nREIN\r\nSYST\r\nPASV\r\nSTOU\r\nABOR\r\nCCC\r\nALLO\r\nSITE\r\nSMNT\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(
            cmds,
            vec![
                FtpCommand::Cdup,
                FtpCommand::Pwd,
                FtpCommand::Quit,
                FtpCommand::Rein,
                FtpCommand::Syst,
                FtpCommand::Pasv,
                FtpCommand::Stou,
                FtpCommand::Abor,
                FtpCommand::Ccc,
                FtpCommand::Allo(Vec::new()),
                FtpCommand::Site(Vec::new()),
                FtpCommand::Smnt,
            ]
        );
    }

    #[test]
    fn help_and_feat_are_the_same_variant() {
        let mut lex = FtpServerLexer::new(4096);
        let mut data: &[u8] = b"HELP\r\nFEAT\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(cmds, vec![FtpCommand::Feat, FtpCommand::Feat]);
    }

    #[test]
    fn unknown_verb() {
        let mut lex = FtpServerLexer::new(4096);
        let mut data: &[u8] = b"FROBNICATE arg\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(cmds, vec![FtpCommand::Unknown { verb: "FROBNICATE".into() }]);
    }

    #[test]
    fn oversized_token_discards_and_resyncs() {
        let mut lex = FtpServerLexer::new(4);
        let mut data: &[u8] = b"TOOLONG arg\r\nNOOP\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(cmds, vec![FtpCommand::Noop]);
    }

    #[test]
    fn literal_cr_not_followed_by_lf_is_content() {
        let mut lex = FtpServerLexer::new(4096);
        let mut data: &[u8] = b"CWD a\rb\r\n";
        let cmds = lex.feed(&mut data);
        assert_eq!(cmds, vec![FtpCommand::Cwd(b"a\rb".to_vec())]);
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
