// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Response codes: the `[...]` that can open the text of a status response
//! (RFC 9051 §7.1), built as they arrive.
//!
//! The reply lexer reads the code with its tokenizer (see
//! [`super::tokens`]) into [`CodeSink`], which keeps the code's name and the
//! structure of its arguments - words, strings and parenthesized lists -
//! and turns the codes hopf acts on into typed values. A code it does not
//! know is kept as [`ImapResponseCode::Other`]: its name and its argument
//! structure, nothing re-rendered as text.

use super::reply::apply_capability_token;
use super::state::{ImapAppendUid, ImapCapabilities, ImapCopyUid};
use super::tokens::{Bad, Output, Sink, Tok};

/// The deepest nesting of lists in a code's arguments.
const MAX_DEPTH: usize = 16;

/// One argument of a response code that hopf does not interpret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImapCodeArg {
    /// A word written bare: an atom, a number, a set (`1:3,7`), a flag.
    Atom(String),
    /// A quoted string or a literal.
    Str(String),
    /// A parenthesized list.
    List(Vec<ImapCodeArg>),
}

impl ImapCodeArg {
    /// The text of an atom or string.
    pub fn text(&self) -> Option<&str> {
        match self {
            ImapCodeArg::Atom(s) | ImapCodeArg::Str(s) => Some(s),
            ImapCodeArg::List(_) => None,
        }
    }
}

/// A response code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImapResponseCode {
    /// `[ALERT]`: the text is to be shown to the user.
    Alert,
    /// `[READ-ONLY]`
    ReadOnly,
    /// `[READ-WRITE]`
    ReadWrite,
    /// `[CAPABILITY ...]`
    Capability(ImapCapabilities),
    /// `[PERMANENTFLAGS (...)]`
    PermanentFlags(Vec<String>),
    /// `[UIDVALIDITY n]`
    UidValidity(u32),
    /// `[UIDNEXT n]`
    UidNext(u32),
    /// `[UNSEEN n]`
    Unseen(u32),
    /// `[HIGHESTMODSEQ n]` (RFC 7162)
    HighestModSeq(u64),
    /// `[MAILBOXID (objectid)]` (RFC 8474)
    MailboxId(String),
    /// `[COPYUID uidvalidity source destination]` (RFC 4315)
    CopyUid(ImapCopyUid),
    /// `[APPENDUID uidvalidity uid]` (RFC 4315)
    AppendUid(ImapAppendUid),
    /// Any other code, or one of the above in a form hopf does not read:
    /// its name (upper case) and arguments.
    Other {
        /// The code's name, upper-cased (`TRYCREATE`, `BADCHARSET`, ...).
        name: String,
        /// The arguments after the name.
        args: Vec<ImapCodeArg>,
    },
}

impl ImapResponseCode {
    /// The code made of `name` and `args`.
    fn of(name: String, args: Vec<ImapCodeArg>) -> Self {
        let number = |args: &[ImapCodeArg]| match args {
            [ImapCodeArg::Atom(n)] => n.parse::<u32>().ok(),
            _ => None,
        };
        let known = match (name.as_str(), args.as_slice()) {
            ("ALERT", []) => Some(Self::Alert),
            ("READ-ONLY", []) => Some(Self::ReadOnly),
            ("READ-WRITE", []) => Some(Self::ReadWrite),
            ("CAPABILITY", words) if words.iter().all(|w| matches!(w, ImapCodeArg::Atom(_))) => {
                let mut caps = ImapCapabilities::default();
                for word in words.iter().filter_map(ImapCodeArg::text) {
                    apply_capability_token(&mut caps, &word.to_ascii_uppercase());
                }
                Some(Self::Capability(caps))
            }
            ("PERMANENTFLAGS", [ImapCodeArg::List(flags)]) => {
                flags.iter().map(|f| f.text().map(str::to_string)).collect::<Option<Vec<_>>>().map(Self::PermanentFlags)
            }
            ("UIDVALIDITY", a) => number(a).map(Self::UidValidity),
            ("UIDNEXT", a) => number(a).map(Self::UidNext),
            ("UNSEEN", a) => number(a).map(Self::Unseen),
            ("HIGHESTMODSEQ", [ImapCodeArg::Atom(n)]) => n.parse().ok().map(Self::HighestModSeq),
            ("MAILBOXID", [ImapCodeArg::List(id)]) => match id.as_slice() {
                [one] => one.text().map(|id| Self::MailboxId(id.to_string())),
                _ => None,
            },
            ("COPYUID", [ImapCodeArg::Atom(validity), ImapCodeArg::Atom(from), ImapCodeArg::Atom(to)]) => {
                validity.parse().ok().map(|uid_validity| {
                    Self::CopyUid(ImapCopyUid { uid_validity, source_uids: from.clone(), dest_uids: to.clone() })
                })
            }
            ("APPENDUID", [ImapCodeArg::Atom(validity), ImapCodeArg::Atom(uid)]) => {
                validity.parse().ok().zip(uid.parse().ok()).map(|(uid_validity, uid)| {
                    Self::AppendUid(ImapAppendUid { uid_validity, uid })
                })
            }
            _ => None,
        };
        known.unwrap_or(Self::Other { name, args })
    }
}

/// Builds a response code from the tokens between `[` and `]`.
#[derive(Default)]
pub(crate) struct CodeSink {
    /// The lists open; the first is the code itself, name first.
    stack: Vec<Vec<ImapCodeArg>>,
    /// Lists opened, for those closing the first.
    started: bool,
}

impl Sink for CodeSink {
    fn token(&mut self, tok: Tok<'_>) -> Result<(), Bad> {
        if !self.started {
            self.started = true;
            self.stack.push(Vec::new());
        }
        match tok {
            Tok::Open => {
                if self.stack.len() > MAX_DEPTH {
                    return Err(Bad);
                }
                self.stack.push(Vec::new());
            }
            Tok::Close => {
                if self.stack.len() < 2 {
                    return Err(Bad);
                }
                let list = self.stack.pop().unwrap_or_default();
                self.stack.last_mut().ok_or(Bad)?.push(ImapCodeArg::List(list));
            }
            Tok::Atom(a) => self.stack.last_mut().ok_or(Bad)?.push(ImapCodeArg::Atom(String::from_utf8_lossy(a).into_owned())),
            Tok::Str(s) => self.stack.last_mut().ok_or(Bad)?.push(ImapCodeArg::Str(String::from_utf8_lossy(s).into_owned())),
        }
        Ok(())
    }

    fn finish(mut self: Box<Self>) -> Result<Output, Bad> {
        if self.stack.len() != 1 {
            return Err(Bad);
        }
        let mut args = self.stack.pop().unwrap_or_default();
        if args.is_empty() {
            return Err(Bad);
        }
        let ImapCodeArg::Atom(name) = args.remove(0) else {
            return Err(Bad);
        };
        Ok(Output::Code(ImapResponseCode::of(name.to_ascii_uppercase(), args)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::endpoint::parse_flag_list;
    use crate::client::reply::{ImapEvent, ImapReplyLexer, ImapStatus};

    const CHUNKS: [usize; 5] = [1, 2, 3, 7, 4096];

    /// The one event `line` makes, however the bytes arrive.
    fn event(line: &str) -> ImapEvent {
        let mut all = Vec::new();
        for chunk in CHUNKS {
            let mut lexer = ImapReplyLexer::new();
            let mut events = Vec::new();
            for piece in line.as_bytes().chunks(chunk) {
                let mut data: &[u8] = piece;
                events.extend(lexer.feed(&mut data).expect("no protocol error"));
                assert!(data.is_empty());
            }
            assert_eq!(events.len(), 1, "{line:?} chunk={chunk}: {events:?}");
            all.push(events.pop().unwrap());
        }
        assert!(all.windows(2).all(|w| w[0] == w[1]), "{line:?}: chunking changed the outcome: {all:?}");
        all.pop().unwrap()
    }

    /// The code of `* OK [code] text`, and its text.
    fn code(code: &str) -> Option<ImapResponseCode> {
        match event(&format!("* OK [{code}] some text\r\n")) {
            ImapEvent::UntaggedOk { code, text } => {
                assert_eq!(text, "some text", "{code:?}");
                code
            }
            other => panic!("expected UntaggedOk, got {other:?}"),
        }
    }

    fn other(name: &str, args: Vec<ImapCodeArg>) -> Option<ImapResponseCode> {
        Some(ImapResponseCode::Other { name: name.into(), args })
    }

    fn atom(s: &str) -> ImapCodeArg {
        ImapCodeArg::Atom(s.into())
    }

    #[test]
    fn the_codes_hopf_acts_on_are_typed() {
        assert_eq!(code("ALERT"), Some(ImapResponseCode::Alert));
        assert_eq!(code("alert"), Some(ImapResponseCode::Alert));
        assert_eq!(code("READ-ONLY"), Some(ImapResponseCode::ReadOnly));
        assert_eq!(code("READ-WRITE"), Some(ImapResponseCode::ReadWrite));
        assert_eq!(code("UIDVALIDITY 3857529045"), Some(ImapResponseCode::UidValidity(3857529045)));
        assert_eq!(code("UIDNEXT 4392"), Some(ImapResponseCode::UidNext(4392)));
        assert_eq!(code("UNSEEN 12"), Some(ImapResponseCode::Unseen(12)));
        assert_eq!(code("HIGHESTMODSEQ 715194045007"), Some(ImapResponseCode::HighestModSeq(715194045007)));
        assert_eq!(code("MAILBOXID (F2212ea87-6097-4256-9d51-71338625)"), Some(ImapResponseCode::MailboxId("F2212ea87-6097-4256-9d51-71338625".into())));
    }

    #[test]
    fn a_capability_code_carries_every_capability_a_server_lists() {
        // What the hopf server sends with a successful LOGIN.
        let words = "IMAP4rev2 IDLE NAMESPACE QUOTA MOVE CONDSTORE QRESYNC COMPRESS=DEFLATE UTF8=ACCEPT \
                     SORT THREAD=ORDEREDSUBJECT THREAD=REFERENCES STATUS=SIZE OBJECTID METADATA NOTIFY \
                     UNSELECT UIDPLUS CHILDREN LIST-EXTENDED LIST-STATUS LITERAL- ID ENABLE";
        match code(&format!("CAPABILITY {words}")) {
            Some(ImapResponseCode::Capability(caps)) => {
                assert_eq!(caps, ImapCapabilities::parse(words));
                assert!(caps.compress_deflate && caps.idle);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn capability_and_permanentflags_agree_with_the_text_parsers() {
        for words in ["IMAP4rev2 STARTTLS", "imap4rev1 IDLE AUTH=PLAIN LOGINDISABLED", "IMAP4rev2"] {
            assert_eq!(code(&format!("CAPABILITY {words}")), Some(ImapResponseCode::Capability(ImapCapabilities::parse(words))), "{words}");
        }
        for flags in ["(\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)", "()", "(\\Seen $Forwarded)"] {
            assert_eq!(code(&format!("PERMANENTFLAGS {flags}")), Some(ImapResponseCode::PermanentFlags(parse_flag_list(flags))), "{flags}");
        }
    }

    #[test]
    fn copyuid_and_appenduid_agree_with_the_text_parsers() {
        for text in ["COPYUID 38505 304,319:320 3956:3958", "COPYUID 1 1 1", "copyuid 7 1:3 4:6"] {
            let want = ImapCopyUid::parse(text).expect("the oracle reads it");
            assert_eq!(code(text), Some(ImapResponseCode::CopyUid(want)), "{text}");
        }
        for text in ["APPENDUID 38505 3955", "appenduid 9 1"] {
            let want = ImapAppendUid::parse(text).expect("the oracle reads it");
            assert_eq!(code(text), Some(ImapResponseCode::AppendUid(want)), "{text}");
        }
    }

    #[test]
    fn a_code_hopf_does_not_read_keeps_its_name_and_argument_structure() {
        assert_eq!(code("TRYCREATE"), other("TRYCREATE", vec![]));
        assert_eq!(code("trycreate"), other("TRYCREATE", vec![]));
        assert_eq!(
            code("BADCHARSET (UTF-8 \"us ascii\")"),
            other("BADCHARSET", vec![ImapCodeArg::List(vec![atom("UTF-8"), ImapCodeArg::Str("us ascii".into())])])
        );
        assert_eq!(code("REFERRAL IMAP://user@host/INBOX"), other("REFERRAL", vec![atom("IMAP://user@host/INBOX")]));
        assert_eq!(
            code("X-VENDOR 1 (a (b c)) \"d\""),
            other("X-VENDOR", vec![atom("1"), ImapCodeArg::List(vec![atom("a"), ImapCodeArg::List(vec![atom("b"), atom("c")])]), ImapCodeArg::Str("d".into())])
        );
        // APPENDUID with a UID set (MULTIAPPEND) is not the single-UID form hopf reads.
        assert_eq!(code("APPENDUID 5 3955:3957"), other("APPENDUID", vec![atom("5"), atom("3955:3957")]));
        // A number that is not one.
        assert_eq!(code("UIDNEXT x"), other("UIDNEXT", vec![atom("x")]));
        assert_eq!(code("UIDNEXT"), other("UIDNEXT", vec![]));
    }

    #[test]
    fn a_literal_is_a_string_in_a_code() {
        assert_eq!(
            event("* OK [X-NOTE {5}\r\na]b c] text\r\n"),
            ImapEvent::UntaggedOk {
                code: other("X-NOTE", vec![ImapCodeArg::Str("a]b c".into())]),
                text: "text".into()
            }
        );
    }

    #[test]
    fn a_code_that_is_malformed_is_dropped_and_the_text_kept() {
        for bad in ["", "(a b)", "\"quoted\" x", "A )"] {
            assert_eq!(
                event(&format!("* OK [{bad}] still here\r\n")),
                ImapEvent::UntaggedOk { code: None, text: "still here".into() },
                "{bad:?}"
            );
        }
    }

    #[test]
    fn the_code_of_a_tagged_response_and_the_text_after_it() {
        assert_eq!(
            event("a1 OK [APPENDUID 38505 3955] APPEND completed\r\n"),
            ImapEvent::Tagged {
                tag: "a1".into(),
                status: ImapStatus::Ok,
                code: Some(ImapResponseCode::AppendUid(ImapAppendUid { uid_validity: 38505, uid: 3955 })),
                message: "APPEND completed".into(),
            }
        );
        assert_eq!(
            event("a2 NO [TRYCREATE]\r\n"),
            ImapEvent::Tagged { tag: "a2".into(), status: ImapStatus::No, code: other("TRYCREATE", vec![]), message: String::new() }
        );
        // Square brackets in the text after the code mean nothing.
        assert_eq!(
            event("a3 OK [READ-ONLY] [not a code] (EXAMINE) done\r\n"),
            ImapEvent::Tagged {
                tag: "a3".into(),
                status: ImapStatus::Ok,
                code: Some(ImapResponseCode::ReadOnly),
                message: "[not a code] (EXAMINE) done".into(),
            }
        );
    }
}
