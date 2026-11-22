// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Incremental NNTP command parser (RFC 3977 section 3.1).
//!
//! [`NntpServerLexer::next_command`] takes the bytes the connection has and
//! returns the next command, consuming exactly the line that held it and
//! nothing after: the rest stays with the caller, who may have a reason not
//! to read on (a command in progress, a data block that follows `POST`). A
//! line in progress is kept in the lexer, bounded, so a command may arrive
//! in pieces of any size.
//!
//! Arguments are read into the shape their command takes: article numbers
//! are numbers, a message-id is checked, a range is a range. A line that does
//! not fit its command becomes [`NntpCommand::Malformed`], and one that is
//! too long [`NntpCommand::TooLong`]; the connection carries on after either.

/// The longest command line the lexer will hold, line end included. RFC
/// 3977 allows 512 octets; the extra room is for the initial response of
/// `AUTHINFO SASL`, which RFC 4643 allows to be longer.
pub const MAX_COMMAND_LINE: usize = 4096;

/// The largest article number (RFC 3977 section 6).
pub const MAX_ARTICLE_NUMBER: u32 = 2_147_483_647;

/// What an article command or a range command names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// Nothing: the current article.
    Current,
    /// An article number in the current group.
    Number(u32),
    /// `n-` (to the end of the group, when the second is `None`) or `n-m`.
    Range(u32, Option<u32>),
    /// An article by message-id, with the angle brackets.
    MessageId(String),
}

/// The date and time of `NEWGROUPS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewGroupsSince {
    /// The year as sent: two or four digits.
    pub year: u32,
    /// Was the year sent with four digits?
    pub four_digit_year: bool,
    /// 1 to 12.
    pub month: u32,
    /// 1 to 31.
    pub day: u32,
    /// 0 to 23.
    pub hour: u32,
    /// 0 to 59.
    pub minute: u32,
    /// 0 to 60.
    pub second: u32,
    /// Was `GMT` given? Without it the time is the server's local time.
    pub gmt: bool,
}

/// Which listing `LIST` asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListKind {
    /// `LIST ACTIVE [wildmat]`, and `LIST` alone.
    Active(Option<String>),
    /// `LIST NEWSGROUPS [wildmat]`.
    Newsgroups(Option<String>),
    /// `LIST OVERVIEW.FMT`.
    OverviewFmt,
}

/// A parsed command, or the reason a line is not one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NntpCommand {
    /// `CAPABILITIES`
    Capabilities,
    /// `MODE READER`
    ModeReader,
    /// `QUIT`
    Quit,
    /// `HELP`
    Help,
    /// `DATE`
    Date,
    /// `GROUP group`
    Group(String),
    /// `LISTGROUP [group [range]]`
    ListGroup(Option<String>, Option<Target>),
    /// `LAST`
    Last,
    /// `NEXT`
    Next,
    /// `ARTICLE [number|message-id]`
    Article(Target),
    /// `HEAD [number|message-id]`
    Head(Target),
    /// `BODY [number|message-id]`
    Body(Target),
    /// `STAT [number|message-id]`
    Stat(Target),
    /// `LIST [keyword [argument]]`
    List(ListKind),
    /// `NEWGROUPS date time [GMT]`
    NewGroups(NewGroupsSince),
    /// `OVER [range|message-id]` (and `XOVER`)
    Over(Target),
    /// `HDR field [range|message-id]` (and `XHDR`)
    Hdr(String, Target),
    /// `POST`
    Post,
    /// `STARTTLS`
    StartTls,
    /// `AUTHINFO USER name`
    AuthinfoUser(String),
    /// `AUTHINFO PASS password`
    AuthinfoPass(String),
    /// `AUTHINFO SASL mechanism [initial-response]`, the response base64
    /// decoded, and `Some(vec![])` for the `=` that stands for an empty one.
    AuthinfoSasl {
        /// The mechanism, as sent.
        mechanism: String,
        /// The initial response, decoded.
        initial_response: Option<Vec<u8>>,
    },
    /// A line of a SASL exchange: the client's response, decoded.
    SaslResponse(Vec<u8>),
    /// `*`: the client cancels the exchange.
    SaslAbort,
    /// A line of a SASL exchange that is not valid base64.
    SaslInvalid,
    /// A command this server does not have (response 500).
    Unknown(String),
    /// A command of this server, with arguments that do not fit it
    /// (response 501). Carries the command name.
    Malformed(String),
    /// A line longer than [`MAX_COMMAND_LINE`] (response 501). It was
    /// discarded to its end.
    TooLong,
}

/// The incremental parser. See the module documentation.
#[derive(Debug)]
pub struct NntpServerLexer {
    max_line: usize,
    line: Vec<u8>,
    too_long: bool,
    sasl: bool,
}

impl Default for NntpServerLexer {
    fn default() -> Self {
        Self::new(MAX_COMMAND_LINE)
    }
}

impl NntpServerLexer {
    /// A lexer that holds at most `max_line` bytes of a line.
    pub fn new(max_line: usize) -> Self {
        Self {
            max_line,
            line: Vec::new(),
            too_long: false,
            sasl: false,
        }
    }

    /// The next line is a response in a SASL exchange, not a command. Call
    /// it after sending the `383` that asks for one.
    pub fn expect_sasl_response(&mut self) {
        self.sasl = true;
    }

    /// Returns the next command in `data`, advancing `data` past its line, or
    /// `None` when `data` ends before the line does (what there is of it is
    /// kept, and `data` is left empty).
    pub fn next_command(&mut self, data: &mut &[u8]) -> Option<NntpCommand> {
        loop {
            let Some(end) = data.iter().position(|&b| b == b'\n') else {
                self.keep(data);
                *data = &[];
                return None;
            };
            let (head, rest) = data.split_at(end);
            self.keep(head);
            *data = &rest[1..];
            let overlong = std::mem::take(&mut self.too_long);
            let mut line = std::mem::take(&mut self.line);
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if overlong {
                self.sasl = false;
                return Some(NntpCommand::TooLong);
            }
            if self.sasl {
                self.sasl = false;
                return Some(parse_sasl_response(&line));
            }
            if line.is_empty() {
                // An empty line is not a command; there is nothing to say
                // to it either, so it is skipped as a blank line between
                // commands is by other servers.
                continue;
            }
            return Some(parse_line(&line));
        }
    }

    fn keep(&mut self, bytes: &[u8]) {
        if self.too_long {
            return;
        }
        if self.line.len() + bytes.len() > self.max_line {
            self.line.clear();
            self.too_long = true;
        } else {
            self.line.extend_from_slice(bytes);
        }
    }
}

fn parse_sasl_response(line: &[u8]) -> NntpCommand {
    if line == b"*" {
        return NntpCommand::SaslAbort;
    }
    match decode_base64(line) {
        Some(bytes) => NntpCommand::SaslResponse(bytes),
        None => NntpCommand::SaslInvalid,
    }
}

/// Decodes standard base64; `=` alone is the empty string.
fn decode_base64(text: &[u8]) -> Option<Vec<u8>> {
    if text == b"=" {
        return Some(Vec::new());
    }
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(text).ok()
}

fn parse_line(line: &[u8]) -> NntpCommand {
    let Ok(text) = std::str::from_utf8(line) else {
        return NntpCommand::Malformed(String::new());
    };
    let mut words = text.split([' ', '\t']).filter(|w| !w.is_empty());
    let Some(verb) = words.next() else {
        return NntpCommand::Unknown(String::new());
    };
    let name = verb.to_ascii_uppercase();
    let args: Vec<&str> = words.collect();
    let bad = || NntpCommand::Malformed(name.clone());
    match name.as_str() {
        "CAPABILITIES" => NntpCommand::Capabilities,
        "MODE" => match args.as_slice() {
            [m] if m.eq_ignore_ascii_case("READER") => NntpCommand::ModeReader,
            _ => bad(),
        },
        "QUIT" => none(&args, NntpCommand::Quit, bad),
        "HELP" => none(&args, NntpCommand::Help, bad),
        "DATE" => none(&args, NntpCommand::Date, bad),
        "LAST" => none(&args, NntpCommand::Last, bad),
        "NEXT" => none(&args, NntpCommand::Next, bad),
        "POST" => none(&args, NntpCommand::Post, bad),
        "STARTTLS" => none(&args, NntpCommand::StartTls, bad),
        "GROUP" => match args.as_slice() {
            [g] => NntpCommand::Group((*g).to_string()),
            _ => bad(),
        },
        "LISTGROUP" => match args.as_slice() {
            [] => NntpCommand::ListGroup(None, None),
            [g] => NntpCommand::ListGroup(Some((*g).to_string()), None),
            [g, r] => match parse_range(r) {
                Some(t) => NntpCommand::ListGroup(Some((*g).to_string()), Some(t)),
                None => bad(),
            },
            _ => bad(),
        },
        "ARTICLE" | "HEAD" | "BODY" | "STAT" => {
            let target = match args.as_slice() {
                [] => Target::Current,
                [a] => match parse_article_target(a) {
                    Some(t) => t,
                    None => return bad(),
                },
                _ => return bad(),
            };
            match name.as_str() {
                "ARTICLE" => NntpCommand::Article(target),
                "HEAD" => NntpCommand::Head(target),
                "BODY" => NntpCommand::Body(target),
                _ => NntpCommand::Stat(target),
            }
        }
        "LIST" => match args.as_slice() {
            [] => NntpCommand::List(ListKind::Active(None)),
            [k] | [k, _] if k.eq_ignore_ascii_case("ACTIVE") => {
                NntpCommand::List(ListKind::Active(args.get(1).map(|w| (*w).to_string())))
            }
            [k] | [k, _] if k.eq_ignore_ascii_case("NEWSGROUPS") => {
                NntpCommand::List(ListKind::Newsgroups(args.get(1).map(|w| (*w).to_string())))
            }
            [k] if k.eq_ignore_ascii_case("OVERVIEW.FMT") => NntpCommand::List(ListKind::OverviewFmt),
            _ => bad(),
        },
        "NEWGROUPS" => match parse_new_groups(&args) {
            Some(n) => NntpCommand::NewGroups(n),
            None => bad(),
        },
        "OVER" | "XOVER" => match args.as_slice() {
            [] => NntpCommand::Over(Target::Current),
            [a] => match parse_range_or_id(a) {
                Some(t) => NntpCommand::Over(t),
                None => bad(),
            },
            _ => bad(),
        },
        "HDR" | "XHDR" => match args.as_slice() {
            [f] => NntpCommand::Hdr((*f).to_string(), Target::Current),
            [f, a] => match parse_range_or_id(a) {
                Some(t) => NntpCommand::Hdr((*f).to_string(), t),
                None => bad(),
            },
            _ => bad(),
        },
        "AUTHINFO" => parse_authinfo(&args, &name),
        _ => NntpCommand::Unknown(name),
    }
}

fn none(args: &[&str], command: NntpCommand, bad: impl Fn() -> NntpCommand) -> NntpCommand {
    if args.is_empty() {
        command
    } else {
        bad()
    }
}

fn parse_authinfo(args: &[&str], name: &str) -> NntpCommand {
    let bad = || NntpCommand::Malformed(name.to_string());
    let Some((sub, rest)) = args.split_first() else {
        return bad();
    };
    match (sub.to_ascii_uppercase().as_str(), rest) {
        ("USER", [u]) => NntpCommand::AuthinfoUser((*u).to_string()),
        ("PASS", [p]) => NntpCommand::AuthinfoPass((*p).to_string()),
        ("SASL", [m]) => NntpCommand::AuthinfoSasl {
            mechanism: (*m).to_string(),
            initial_response: None,
        },
        ("SASL", [m, r]) => match decode_base64(r.as_bytes()) {
            Some(bytes) => NntpCommand::AuthinfoSasl {
                mechanism: (*m).to_string(),
                initial_response: Some(bytes),
            },
            None => bad(),
        },
        _ => bad(),
    }
}

/// `number`, or a message-id.
fn parse_article_target(arg: &str) -> Option<Target> {
    if arg.starts_with('<') {
        return is_message_id(arg).then(|| Target::MessageId(arg.to_string()));
    }
    parse_number(arg).map(Target::Number)
}

/// `number`, `number-`, `number-number`, or a message-id.
fn parse_range_or_id(arg: &str) -> Option<Target> {
    if arg.starts_with('<') {
        return is_message_id(arg).then(|| Target::MessageId(arg.to_string()));
    }
    parse_range(arg)
}

fn parse_range(arg: &str) -> Option<Target> {
    match arg.split_once('-') {
        None => parse_number(arg).map(Target::Number),
        Some((lo, "")) => parse_number(lo).map(|lo| Target::Range(lo, None)),
        Some((lo, hi)) => {
            let (lo, hi) = (parse_number(lo)?, parse_number(hi)?);
            Some(Target::Range(lo, Some(hi)))
        }
    }
}

fn parse_number(text: &str) -> Option<u32> {
    if text.is_empty() || text.len() > 10 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u64 = text.parse().ok()?;
    (n <= u64::from(MAX_ARTICLE_NUMBER)).then_some(n as u32)
}

/// A message-id as RFC 3977 section 3.6 has it: `<` and `>` around 1 to 248
/// visible ASCII characters, none of them a angle bracket.
pub fn is_message_id(text: &str) -> bool {
    let b = text.as_bytes();
    b.len() >= 3
        && b.len() <= 250
        && b[0] == b'<'
        && b[b.len() - 1] == b'>'
        && b[1..b.len() - 1]
            .iter()
            .all(|&c| (0x21..=0x7e).contains(&c) && c != b'<' && c != b'>')
}

fn parse_new_groups(args: &[&str]) -> Option<NewGroupsSince> {
    let (date, time, gmt) = match args {
        [d, t] => (*d, *t, false),
        [d, t, g] if g.eq_ignore_ascii_case("GMT") => (*d, *t, true),
        // A distributions argument is accepted and ignored (RFC 3977
        // section 7.3 deprecates it).
        [d, t, g, _] if g.eq_ignore_ascii_case("GMT") => (*d, *t, true),
        [d, t, _] => (*d, *t, false),
        _ => return None,
    };
    if !date.bytes().all(|b| b.is_ascii_digit()) || !time.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let (four, year_len) = match date.len() {
        6 => (false, 2),
        8 => (true, 4),
        _ => return None,
    };
    if time.len() != 6 {
        return None;
    }
    let n = |s: &str| s.parse::<u32>().ok();
    let since = NewGroupsSince {
        year: n(&date[..year_len])?,
        four_digit_year: four,
        month: n(&date[year_len..year_len + 2])?,
        day: n(&date[year_len + 2..])?,
        hour: n(&time[..2])?,
        minute: n(&time[2..4])?,
        second: n(&time[4..])?,
        gmt,
    };
    let valid = (1..=12).contains(&since.month)
        && (1..=31).contains(&since.day)
        && since.hour < 24
        && since.minute < 60
        && since.second <= 60;
    valid.then_some(since)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lex(text: &str) -> Vec<NntpCommand> {
        let mut lexer = NntpServerLexer::default();
        let mut data = text.as_bytes();
        let mut out = Vec::new();
        while let Some(c) = lexer.next_command(&mut data) {
            out.push(c);
        }
        out
    }

    fn one(text: &str) -> NntpCommand {
        let mut v = lex(&format!("{text}\r\n"));
        assert_eq!(v.len(), 1, "{text}: {v:?}");
        v.remove(0)
    }

    #[test]
    fn simple_commands_are_case_insensitive() {
        assert_eq!(one("quit"), NntpCommand::Quit);
        assert_eq!(one("Capabilities"), NntpCommand::Capabilities);
        assert_eq!(one("MODE reader"), NntpCommand::ModeReader);
        assert_eq!(one("date"), NntpCommand::Date);
        assert_eq!(one("POST"), NntpCommand::Post);
        assert_eq!(one("starttls"), NntpCommand::StartTls);
    }

    #[test]
    fn a_command_that_takes_no_arguments_refuses_them() {
        for line in ["QUIT now", "LAST 1", "DATE x", "POST x", "MODE", "MODE STREAM", "GROUP", "GROUP a b"] {
            assert!(matches!(one(line), NntpCommand::Malformed(_)), "{line}");
        }
    }

    #[test]
    fn article_commands_take_a_number_a_message_id_or_nothing() {
        assert_eq!(one("ARTICLE"), NntpCommand::Article(Target::Current));
        assert_eq!(one("HEAD 17"), NntpCommand::Head(Target::Number(17)));
        assert_eq!(one("body <a@b>"), NntpCommand::Body(Target::MessageId("<a@b>".into())));
        assert_eq!(one("STAT 2147483647"), NntpCommand::Stat(Target::Number(2147483647)));
        for line in ["STAT 2147483648", "STAT x", "STAT 1-2", "STAT <a b>", "STAT <>", "ARTICLE 1 2", "STAT -1"] {
            assert!(matches!(one(line), NntpCommand::Malformed(_)), "{line}");
        }
    }

    #[test]
    fn ranges_are_numbers_or_open_or_closed_ranges() {
        assert_eq!(one("OVER"), NntpCommand::Over(Target::Current));
        assert_eq!(one("OVER 5"), NntpCommand::Over(Target::Number(5)));
        assert_eq!(one("XOVER 5-"), NntpCommand::Over(Target::Range(5, None)));
        assert_eq!(one("OVER 5-9"), NntpCommand::Over(Target::Range(5, Some(9))));
        assert_eq!(one("OVER <m@x>"), NntpCommand::Over(Target::MessageId("<m@x>".into())));
        assert_eq!(one("LISTGROUP g 3-4"), NntpCommand::ListGroup(Some("g".into()), Some(Target::Range(3, Some(4)))));
        assert_eq!(one("LISTGROUP"), NntpCommand::ListGroup(None, None));
        assert!(matches!(one("OVER -5"), NntpCommand::Malformed(_)));
        assert!(matches!(one("OVER 1-2-3"), NntpCommand::Malformed(_)));
    }

    #[test]
    fn hdr_takes_a_field_and_an_optional_range() {
        assert_eq!(one("HDR Subject"), NntpCommand::Hdr("Subject".into(), Target::Current));
        assert_eq!(one("xhdr :bytes 1-9"), NntpCommand::Hdr(":bytes".into(), Target::Range(1, Some(9))));
        assert!(matches!(one("HDR"), NntpCommand::Malformed(_)));
    }

    #[test]
    fn list_has_three_keywords_and_an_optional_wildmat() {
        assert_eq!(one("LIST"), NntpCommand::List(ListKind::Active(None)));
        assert_eq!(one("LIST ACTIVE comp.*"), NntpCommand::List(ListKind::Active(Some("comp.*".into()))));
        assert_eq!(one("list newsgroups"), NntpCommand::List(ListKind::Newsgroups(None)));
        assert_eq!(one("LIST OVERVIEW.FMT"), NntpCommand::List(ListKind::OverviewFmt));
        assert!(matches!(one("LIST DISTRIB.PATS"), NntpCommand::Malformed(_)));
        assert!(matches!(one("LIST OVERVIEW.FMT x"), NntpCommand::Malformed(_)));
    }

    #[test]
    fn newgroups_reads_a_date_and_a_time() {
        let NntpCommand::NewGroups(n) = one("NEWGROUPS 20260102 030405 GMT") else { panic!() };
        assert_eq!((n.year, n.four_digit_year, n.month, n.day, n.hour, n.minute, n.second, n.gmt), (2026, true, 1, 2, 3, 4, 5, true));
        let NntpCommand::NewGroups(n) = one("NEWGROUPS 260102 030405") else { panic!() };
        assert_eq!((n.year, n.four_digit_year, n.gmt), (26, false, false));
        for bad in ["NEWGROUPS", "NEWGROUPS 20261301 000000", "NEWGROUPS 20260102 250000", "NEWGROUPS 2026010 000000", "NEWGROUPS 20260102 0000"] {
            assert!(matches!(one(bad), NntpCommand::Malformed(_)), "{bad}");
        }
    }

    #[test]
    fn authinfo_commands() {
        assert_eq!(one("AUTHINFO USER fred"), NntpCommand::AuthinfoUser("fred".into()));
        assert_eq!(one("authinfo pass sesame"), NntpCommand::AuthinfoPass("sesame".into()));
        assert_eq!(
            one("AUTHINFO SASL PLAIN AGZyZWQAeA=="),
            NntpCommand::AuthinfoSasl { mechanism: "PLAIN".into(), initial_response: Some(b"\0fred\0x".to_vec()) }
        );
        assert_eq!(
            one("AUTHINFO SASL EXTERNAL ="),
            NntpCommand::AuthinfoSasl { mechanism: "EXTERNAL".into(), initial_response: Some(Vec::new()) }
        );
        assert_eq!(
            one("AUTHINFO SASL SCRAM-SHA-256"),
            NntpCommand::AuthinfoSasl { mechanism: "SCRAM-SHA-256".into(), initial_response: None }
        );
        for bad in ["AUTHINFO", "AUTHINFO USER", "AUTHINFO PASS a b", "AUTHINFO FOO x", "AUTHINFO SASL PLAIN !!!"] {
            assert!(matches!(one(bad), NntpCommand::Malformed(_)), "{bad}");
        }
    }

    #[test]
    fn an_unknown_command_is_named_in_upper_case() {
        assert_eq!(one("ihave <a@b>"), NntpCommand::Unknown("IHAVE".into()));
        assert_eq!(one("NEWNEWS * 20260101 000000"), NntpCommand::Unknown("NEWNEWS".into()));
    }

    #[test]
    fn consumes_one_line_and_leaves_the_rest() {
        let mut lexer = NntpServerLexer::default();
        let mut data: &[u8] = b"POST\r\nFrom: a\r\n";
        assert_eq!(lexer.next_command(&mut data), Some(NntpCommand::Post));
        assert_eq!(data, b"From: a\r\n");
    }

    #[test]
    fn a_line_may_arrive_in_pieces_of_any_size() {
        let wire = b"GROUP comp.lang.rust\r\nARTICLE 12\r\nQUIT\r\n";
        for size in 1..wire.len() {
            let mut lexer = NntpServerLexer::default();
            let mut out = Vec::new();
            for chunk in wire.chunks(size) {
                let mut data = chunk;
                while let Some(c) = lexer.next_command(&mut data) {
                    out.push(c);
                }
            }
            assert_eq!(
                out,
                vec![
                    NntpCommand::Group("comp.lang.rust".into()),
                    NntpCommand::Article(Target::Number(12)),
                    NntpCommand::Quit
                ],
                "chunks of {size}"
            );
        }
    }

    #[test]
    fn a_bare_line_feed_ends_a_line_and_an_empty_line_is_skipped() {
        assert_eq!(lex("QUIT\n\r\n\nDATE\r\n"), vec![NntpCommand::Quit, NntpCommand::Date]);
    }

    #[test]
    fn a_line_that_is_too_long_is_discarded_and_the_next_is_read() {
        let mut lexer = NntpServerLexer::new(32);
        let long = format!("GROUP {}\r\nDATE\r\n", "x".repeat(100));
        let mut data = long.as_bytes();
        assert_eq!(lexer.next_command(&mut data), Some(NntpCommand::TooLong));
        assert_eq!(lexer.next_command(&mut data), Some(NntpCommand::Date));
    }

    #[test]
    fn a_long_line_arriving_in_pieces_holds_nothing_past_the_bound() {
        let mut lexer = NntpServerLexer::new(32);
        let mut data: &[u8] = &[b'x'; 10_000];
        assert_eq!(lexer.next_command(&mut data), None);
        assert!(lexer.line.capacity() < 10_000);
        let mut rest: &[u8] = b"\r\nQUIT\r\n";
        assert_eq!(lexer.next_command(&mut rest), Some(NntpCommand::TooLong));
        assert_eq!(lexer.next_command(&mut rest), Some(NntpCommand::Quit));
    }

    #[test]
    fn sasl_responses_are_read_as_lines_of_base64() {
        let mut lexer = NntpServerLexer::default();
        lexer.expect_sasl_response();
        let mut data: &[u8] = b"Zm9v\r\n*\r\n";
        assert_eq!(lexer.next_command(&mut data), Some(NntpCommand::SaslResponse(b"foo".to_vec())));
        // Only the one line was a response; the next is a command again.
        assert_eq!(lexer.next_command(&mut data), Some(NntpCommand::Unknown("*".into())));
    }

    #[test]
    fn sasl_abort_and_invalid_base64() {
        let mut lexer = NntpServerLexer::default();
        lexer.expect_sasl_response();
        let mut data: &[u8] = b"*\r\n";
        assert_eq!(lexer.next_command(&mut data), Some(NntpCommand::SaslAbort));
        lexer.expect_sasl_response();
        let mut data: &[u8] = b"!!!\r\n";
        assert_eq!(lexer.next_command(&mut data), Some(NntpCommand::SaslInvalid));
    }

    #[test]
    fn message_id_syntax() {
        assert!(is_message_id("<a@b>"));
        assert!(is_message_id("<1>"));
        assert!(!is_message_id("<>"));
        assert!(!is_message_id("a@b"));
        assert!(!is_message_id("<a b>"));
        assert!(!is_message_id("<a<b>"));
        assert!(!is_message_id(&format!("<{}>", "x".repeat(249))));
        assert!(is_message_id(&format!("<{}>", "x".repeat(248))));
    }
}
