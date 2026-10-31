// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Incremental, semantic FTP command parser: `KEYWORD [SP TEXT] CRLF`.
//!
//! Self-contained streaming parser: [`FtpServerLexer::feed`] consumes every
//! byte it is given and keeps a command-in-progress in its own bounded
//! `verb`/`arg` scratch buffers — never in a buffer the caller has to retain
//! and re-supply. See `hopf_http::h1::parse` for the design this follows.
//!
//! The argument is read according to its verb as its bytes arrive. `PORT`,
//! `EPRT` and `REST` are split into fields as they arrive and delivered as a
//! typed address or offset (a malformed one is `None`/`Err`, to be answered
//! `501`); the argument of a verb that takes none is skipped; only a path or
//! other text is kept, bounded.
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

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

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
    Port(Option<SocketAddr>),
    /// `EPRT`
    Eprt(Result<SocketAddr, EprtError>),
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
    Rest(Option<u64>),
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

/// Why an `EPRT` argument was refused (RFC 2428 §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EprtError {
    /// Not `|net-prt|net-addr|tcp-port|`.
    Syntax,
    /// A protocol (or address family) that is not supported.
    ProtocolNotSupported {
        /// What is, for the `522` reply.
        supported: &'static str,
    },
}

/// What the argument of the verb just read is made of, which decides what
/// the lexer does with each byte of it as it arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArgKind {
    /// A path or other text, kept (bounded): the string is the thing.
    Text,
    /// Fields split on a delimiter as they arrive (`PORT`, `EPRT`, `REST`).
    Fields(u8),
    /// Takes no argument, or an unknown verb: whatever follows is skipped.
    Ignored,
}

/// Splits an argument into fields as the bytes arrive: leading white space
/// and (optionally) leading delimiters skipped, each field a bounded token,
/// trailing white space and (optionally) trailing empty fields dropped at the
/// end. The argument is never held whole.
#[derive(Debug, Default)]
struct Fields {
    delim: Option<u8>,
    skip_leading_delims: bool,
    drop_trailing_empty: bool,
    started: bool,
    fields: Vec<Vec<u8>>,
    cur: Vec<u8>,
}

impl Fields {
    fn new(delim: Option<u8>, skip_leading_delims: bool, drop_trailing_empty: bool) -> Self {
        Self { delim, skip_leading_delims, drop_trailing_empty, ..Self::default() }
    }

    fn feed(&mut self, b: u8) {
        if !self.started {
            if b.is_ascii_whitespace() || b == 0x0b {
                return;
            }
            if self.skip_leading_delims && Some(b) == self.delim {
                return;
            }
            self.started = true;
        }
        if Some(b) == self.delim {
            self.fields.push(std::mem::take(&mut self.cur));
        } else {
            self.cur.push(b);
        }
    }

    fn finish(mut self) -> Vec<Vec<u8>> {
        if self.started {
            while self.cur.last().is_some_and(|b| b.is_ascii_whitespace() || *b == 0x0b) {
                self.cur.pop();
            }
            self.fields.push(self.cur);
        }
        if self.drop_trailing_empty {
            while self.fields.last().is_some_and(Vec::is_empty) {
                self.fields.pop();
            }
        }
        self.fields
    }
}

fn field_str(field: &[u8]) -> Option<&str> {
    std::str::from_utf8(field).ok()
}

/// `PORT h1,h2,h3,h4,p1,p2` (RFC 959 §4.1.2): six bytes.
fn port_from_fields(fields: &[Vec<u8>]) -> Option<SocketAddr> {
    if fields.len() != 6 {
        return None;
    }
    let mut n = [0u8; 6];
    for (slot, field) in n.iter_mut().zip(fields) {
        *slot = field_str(field)?.parse().ok()?;
    }
    let port = u16::from(n[4]) << 8 | u16::from(n[5]);
    Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(n[0], n[1], n[2], n[3])), port))
}

/// `EPRT |net-prt|net-addr|tcp-port|` (RFC 2428 §2), `|1|127.0.0.1|65000|`
/// or `|2|::1|65000|`.
fn eprt_from_fields(fields: &[Vec<u8>]) -> Result<SocketAddr, EprtError> {
    if fields.len() < 3 {
        return Err(EprtError::Syntax);
    }
    let host: IpAddr = field_str(&fields[1]).and_then(|s| s.parse().ok()).ok_or(EprtError::Syntax)?;
    let port: u16 = field_str(&fields[2]).and_then(|s| s.parse().ok()).ok_or(EprtError::Syntax)?;
    match (field_str(&fields[0]), host) {
        (Some("1"), IpAddr::V4(_)) => Ok(SocketAddr::new(host, port)),
        (Some("2"), IpAddr::V6(_)) => Ok(SocketAddr::new(host, port)),
        (Some("1"), IpAddr::V6(_)) | (Some("2"), IpAddr::V4(_)) => Err(EprtError::ProtocolNotSupported {
            supported: if host.is_ipv4() { "1" } else { "2" },
        }),
        _ => Err(EprtError::ProtocolNotSupported { supported: "1,2" }),
    }
}

/// `REST marker`: a byte offset.
fn rest_from_fields(fields: &[Vec<u8>]) -> Option<u64> {
    match fields {
        [one] => field_str(one)?.parse().ok(),
        _ => None,
    }
}

/// Incremental, semantic FTP command-line parser. See the module docs.
pub struct FtpServerLexer {
    max_line: usize,
    state: State,
    verb: Vec<u8>,
    arg: Vec<u8>,
    /// Bytes of argument so far, kept or not, for the length cap.
    arg_len: usize,
    kind: ArgKind,
    fields: Fields,
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
            arg_len: 0,
            kind: ArgKind::Ignored,
            fields: Fields::default(),
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
                        self.start_arg();
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

    /// The verb is complete and an argument follows: decide what it is made
    /// of from the verb.
    fn start_arg(&mut self) {
        self.have_arg = true;
        self.arg_len = 0;
        self.arg.clear();
        let verb = String::from_utf8_lossy(&self.verb).to_ascii_uppercase();
        self.kind = match verb.as_str() {
            "PORT" => {
                self.fields = Fields::new(Some(b','), false, false);
                ArgKind::Fields(b',')
            }
            "EPRT" => {
                self.fields = Fields::new(Some(b'|'), true, true);
                ArgKind::Fields(b'|')
            }
            "REST" => {
                self.fields = Fields::new(None, false, false);
                ArgKind::Fields(0)
            }
            "ACCT" | "CDUP" | "XCUP" | "PWD" | "XPWD" | "QUIT" | "REIN" | "NOOP" | "SYST" | "PASV" | "STOU"
            | "ABOR" | "HELP" | "FEAT" | "CCC" | "SMNT" => ArgKind::Ignored,
            v if is_text_verb(v) => ArgKind::Text,
            _ => ArgKind::Ignored,
        };
    }

    fn push_content(&mut self, b: u8) {
        let len = if self.have_arg { self.arg_len } else { self.verb.len() };
        if len >= self.max_line {
            self.verb.clear();
            self.arg.clear();
            self.have_arg = false;
            self.state = State::Resync;
            return;
        }
        if !self.have_arg {
            self.verb.push(b);
            return;
        }
        self.arg_len += 1;
        match self.kind {
            ArgKind::Text => self.arg.push(b),
            ArgKind::Fields(_) => self.fields.feed(b),
            ArgKind::Ignored => {}
        }
    }

    fn finish_command(&mut self) {
        let verb = String::from_utf8_lossy(&self.verb).to_ascii_uppercase();
        let arg_bytes = std::mem::take(&mut self.arg);
        let fields = std::mem::take(&mut self.fields).finish();
        self.verb.clear();
        self.have_arg = false;
        if verb.is_empty() {
            return;
        }
        let command = match verb.as_str() {
            "PORT" => FtpCommand::Port(port_from_fields(&fields)),
            "EPRT" => FtpCommand::Eprt(eprt_from_fields(&fields)),
            "REST" => FtpCommand::Rest(rest_from_fields(&fields)),
            _ => build_command(&verb, arg_bytes),
        };
        self.ready.push(command);
    }
}

/// The verbs whose argument is a string kept as it came (a path, a name, a
/// keyword).
fn is_text_verb(verb: &str) -> bool {
    matches!(
        verb,
        "USER" | "PASS" | "CWD" | "XCWD" | "TYPE" | "STRU" | "MODE" | "EPSV" | "RETR" | "STOR" | "APPE" | "LIST"
            | "NLST" | "MLSD" | "MLST" | "SIZE" | "MDTM" | "DELE" | "RMD" | "XRMD" | "MKD" | "XMKD" | "RNFR"
            | "RNTO" | "STAT" | "OPTS" | "AUTH" | "PBSZ" | "PROT" | "ALLO" | "SITE"
    )
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

    /// Runs one line through a lexer in chunks of `chunk` bytes.
    fn lex_line(line: &str, chunk: usize) -> Vec<FtpCommand> {
        let mut lex = FtpServerLexer::new(4096);
        let mut out = Vec::new();
        for piece in line.as_bytes().chunks(chunk) {
            let mut data: &[u8] = piece;
            out.extend(lex.feed(&mut data));
        }
        out
    }

    fn sock(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// Each of the last two PORT numbers is a byte (RFC 959 §4.1.2); larger
    /// ones are a syntax error, not an overflow of `p1 * 256 + p2` (which
    /// the code that parsed the argument after the line had panicked on).
    #[test]
    fn port_numbers_are_bytes() {
        for chunk in [1, 3, 100] {
            assert_eq!(lex_line("PORT 1,2,3,4,300,300\r\n", chunk), vec![FtpCommand::Port(None)]);
            assert_eq!(lex_line("PORT 1,2,3,4,0,256\r\n", chunk), vec![FtpCommand::Port(None)]);
            assert_eq!(lex_line("PORT 1,2,3,4,255,255\r\n", chunk), vec![FtpCommand::Port(Some(sock("1.2.3.4:65535")))]);
            assert_eq!(lex_line("PORT 127,0,0,1,4,1\r\n", chunk), vec![FtpCommand::Port(Some(sock("127.0.0.1:1025")))]);
            assert_eq!(lex_line("PORT  127,0,0,1,4,1 \r\n", chunk), vec![FtpCommand::Port(Some(sock("127.0.0.1:1025")))]);
            for bad in ["PORT\r\n", "PORT 1,2,3,4,5\r\n", "PORT 1,2,3,4,5,6,7\r\n", "PORT 1,2,3,256,5,6\r\n", "PORT 1, 2,3,4,5,6\r\n", "PORT a,b,c,d,e,f\r\n"] {
                assert_eq!(lex_line(bad, chunk), vec![FtpCommand::Port(None)], "{bad:?}");
            }
        }
    }

    #[test]
    fn eprt_checks_the_protocol_against_the_address() {
        for chunk in [1, 4, 100] {
            assert_eq!(lex_line("EPRT |1|127.0.0.1|65000|\r\n", chunk), vec![FtpCommand::Eprt(Ok(sock("127.0.0.1:65000")))]);
            assert_eq!(lex_line("EPRT |2|::1|65000|\r\n", chunk), vec![FtpCommand::Eprt(Ok(sock("[::1]:65000")))]);
            assert_eq!(lex_line("EPRT |1|::1|65000|\r\n", chunk), vec![FtpCommand::Eprt(Err(EprtError::ProtocolNotSupported { supported: "2" }))]);
            assert_eq!(lex_line("EPRT |2|127.0.0.1|65000|\r\n", chunk), vec![FtpCommand::Eprt(Err(EprtError::ProtocolNotSupported { supported: "1" }))]);
            assert_eq!(lex_line("EPRT |3|127.0.0.1|65000|\r\n", chunk), vec![FtpCommand::Eprt(Err(EprtError::ProtocolNotSupported { supported: "1,2" }))]);
            for bad in ["EPRT\r\n", "EPRT |1|127.0.0.1|\r\n", "EPRT |1|nope|65000|\r\n", "EPRT |1|127.0.0.1|99999|\r\n", "EPRT ||||\r\n"] {
                assert_eq!(lex_line(bad, chunk), vec![FtpCommand::Eprt(Err(EprtError::Syntax))], "{bad:?}");
            }
        }
    }

    #[test]
    fn rest_is_a_byte_offset() {
        assert_eq!(lex_line("REST 1024\r\n", 2), vec![FtpCommand::Rest(Some(1024))]);
        assert_eq!(lex_line("REST  7 \r\n", 1), vec![FtpCommand::Rest(Some(7))]);
        for bad in ["REST\r\n", "REST x\r\n", "REST -1\r\n", "REST 1 2\r\n", "REST 99999999999999999999999\r\n"] {
            assert_eq!(lex_line(bad, 3), vec![FtpCommand::Rest(None)], "{bad:?}");
        }
    }

    /// An argument to a verb that takes none is skipped, not kept, and a
    /// too-long one is still caught.
    #[test]
    fn an_argument_to_a_verb_that_takes_none_is_skipped_and_still_bounded() {
        let mut lex = FtpServerLexer::new(32);
        let mut data: &[u8] = b"QUIT now please\r\nNOOP\r\n";
        assert_eq!(lex.feed(&mut data), vec![FtpCommand::Quit, FtpCommand::Noop]);
        let mut long = b"QUIT ".to_vec();
        long.extend(vec![b'x'; 64]);
        long.extend_from_slice(b"\r\nNOOP\r\n");
        let mut data: &[u8] = &long;
        assert_eq!(lex.feed(&mut data), vec![FtpCommand::Noop]);
    }
}
