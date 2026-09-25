// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Push parser for zone file entries: lexes once, then a small explicit
//! state machine turns tokens into [`ZoneEvents`]. Nothing here builds a
//! zone; the events carry just one logical line's fields at a time.

use super::error::ZoneError;
use super::lexer::{Token, ZoneLexer};

/// One field of an entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Field {
    pub(crate) text: String,
    pub(crate) quoted: bool,
}

/// Semantic callbacks for [`ZoneParser`].
pub(crate) trait ZoneEvents {
    /// `$ORIGIN name`.
    fn origin(&mut self, line: usize, name: &str) -> Result<(), ZoneError>;
    /// `$TTL value` (raw text; may carry BIND units such as `1h`).
    fn default_ttl(&mut self, line: usize, value: &str) -> Result<(), ZoneError>;
    /// `$INCLUDE file [origin]`.
    fn include(&mut self, line: usize, file: &str, origin: Option<&str>) -> Result<(), ZoneError>;
    /// `$GENERATE range lhs [ttl] [class] type rhs...` (fields after the keyword).
    fn generate(&mut self, line: usize, fields: &[Field]) -> Result<(), ZoneError>;
    /// A resource record entry. With `blank_owner` the owner name was omitted
    /// and `fields` starts at the TTL/class/type.
    fn record(&mut self, line: usize, blank_owner: bool, fields: &[Field]) -> Result<(), ZoneError>;
}

impl<T: ZoneEvents> ZoneEvents for &mut T {
    fn origin(&mut self, line: usize, name: &str) -> Result<(), ZoneError> {
        (**self).origin(line, name)
    }
    fn default_ttl(&mut self, line: usize, value: &str) -> Result<(), ZoneError> {
        (**self).default_ttl(line, value)
    }
    fn include(&mut self, line: usize, file: &str, origin: Option<&str>) -> Result<(), ZoneError> {
        (**self).include(line, file, origin)
    }
    fn generate(&mut self, line: usize, fields: &[Field]) -> Result<(), ZoneError> {
        (**self).generate(line, fields)
    }
    fn record(&mut self, line: usize, blank_owner: bool, fields: &[Field]) -> Result<(), ZoneError> {
        (**self).record(line, blank_owner, fields)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Between,
    Directive(Directive),
    Record { blank_owner: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Directive {
    Origin,
    Ttl,
    Include,
    Generate,
}

pub(crate) struct ZoneParser<E: ZoneEvents> {
    events: E,
    lexer: ZoneLexer,
    state: State,
    fields: Vec<Field>,
    /// Line the current entry started on.
    entry_line: usize,
}

impl<E: ZoneEvents> ZoneParser<E> {
    pub(crate) fn new(events: E) -> Self {
        Self {
            events,
            lexer: ZoneLexer::new(),
            state: State::Between,
            fields: Vec::new(),
            entry_line: 1,
        }
    }

    /// Feed a chunk of the zone file.
    pub(crate) fn push(&mut self, data: &[u8]) -> Result<(), ZoneError> {
        let Self {
            events,
            lexer,
            state,
            fields,
            entry_line,
        } = self;
        lexer.push(data, &mut |t| step(events, state, fields, entry_line, t))
    }

    /// End of input.
    pub(crate) fn finish(&mut self) -> Result<(), ZoneError> {
        let Self {
            events,
            lexer,
            state,
            fields,
            entry_line,
        } = self;
        lexer.finish(&mut |t| step(events, state, fields, entry_line, t))
    }
}

fn step<E: ZoneEvents>(
    events: &mut E,
    state: &mut State,
    fields: &mut Vec<Field>,
    entry_line: &mut usize,
    token: Token,
) -> Result<(), ZoneError> {
    match token {
        Token::Eol => end_entry(events, state, fields, *entry_line),
        Token::Word {
            text,
            quoted,
            blank_owner,
            line,
        } => match *state {
            State::Between => {
                *entry_line = line;
                if !blank_owner && !quoted && text.starts_with('$') {
                    *state = match text.to_ascii_uppercase().as_str() {
                        "$ORIGIN" => State::Directive(Directive::Origin),
                        "$TTL" => State::Directive(Directive::Ttl),
                        "$INCLUDE" => State::Directive(Directive::Include),
                        "$GENERATE" => State::Directive(Directive::Generate),
                        _ => {
                            return Err(ZoneError::at(
                                line,
                                format!("unsupported directive {text}"),
                            ))
                        }
                    };
                } else {
                    *state = State::Record { blank_owner };
                    fields.push(Field { text, quoted });
                }
                Ok(())
            }
            State::Directive(_) | State::Record { .. } => {
                fields.push(Field { text, quoted });
                Ok(())
            }
        },
    }
}

fn end_entry<E: ZoneEvents>(
    events: &mut E,
    state: &mut State,
    fields: &mut Vec<Field>,
    line: usize,
) -> Result<(), ZoneError> {
    let taken = std::mem::take(fields);
    let s = std::mem::replace(state, State::Between);
    match s {
        State::Between => Ok(()),
        State::Record { blank_owner } => events.record(line, blank_owner, &taken),
        State::Directive(Directive::Origin) => match taken.as_slice() {
            [f] => events.origin(line, &f.text),
            _ => Err(ZoneError::at(line, "$ORIGIN takes exactly one name")),
        },
        State::Directive(Directive::Ttl) => match taken.as_slice() {
            [f] => events.default_ttl(line, &f.text),
            _ => Err(ZoneError::at(line, "$TTL takes exactly one value")),
        },
        State::Directive(Directive::Include) => match taken.as_slice() {
            [f] => events.include(line, &f.text, None),
            [f, o] => events.include(line, &f.text, Some(&o.text)),
            _ => Err(ZoneError::at(line, "$INCLUDE takes a file and an optional origin")),
        },
        State::Directive(Directive::Generate) => {
            if taken.len() < 4 {
                return Err(ZoneError::at(line, "$GENERATE needs range, owner, type and data"));
            }
            events.generate(line, &taken)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default, Debug, PartialEq)]
    struct Log(Vec<String>);

    impl ZoneEvents for Log {
        fn origin(&mut self, _l: usize, n: &str) -> Result<(), ZoneError> {
            self.0.push(format!("origin {n}"));
            Ok(())
        }
        fn default_ttl(&mut self, _l: usize, v: &str) -> Result<(), ZoneError> {
            self.0.push(format!("ttl {v}"));
            Ok(())
        }
        fn include(&mut self, _l: usize, f: &str, o: Option<&str>) -> Result<(), ZoneError> {
            self.0.push(format!("include {f} {o:?}"));
            Ok(())
        }
        fn generate(&mut self, _l: usize, f: &[Field]) -> Result<(), ZoneError> {
            self.0.push(format!("generate {}", f.len()));
            Ok(())
        }
        fn record(&mut self, l: usize, b: bool, f: &[Field]) -> Result<(), ZoneError> {
            let t: Vec<_> = f.iter().map(|f| f.text.as_str()).collect();
            self.0.push(format!("record@{l} blank={b} {}", t.join("|")));
            Ok(())
        }
    }

    fn run(chunks: &[&[u8]]) -> Result<Vec<String>, ZoneError> {
        let mut log = Log::default();
        {
            let mut p = ZoneParser::new(&mut log);
            for c in chunks {
                p.push(c)?;
            }
            p.finish()?;
        }
        Ok(log.0)
    }

    const SRC: &[u8] = b"$ORIGIN example.com.\n$TTL 1h\n$INCLUDE more.zone sub\n\
@ IN SOA ns hm (\n 1 2 3 4 5 )\n  NS ns\nwww 300 IN A 192.0.2.1\n$GENERATE 1-3 h$ A 10.0.0.$\n";

    #[test]
    fn directives_and_records_become_events() {
        let got = run(&[SRC]).unwrap();
        assert_eq!(
            got,
            [
                "origin example.com.",
                "ttl 1h",
                "include more.zone Some(\"sub\")",
                "record@4 blank=false @|IN|SOA|ns|hm|1|2|3|4|5",
                "record@6 blank=true NS|ns",
                "record@7 blank=false www|300|IN|A|192.0.2.1",
                "generate 4",
            ]
        );
    }

    #[test]
    fn chunking_never_changes_the_events() {
        let whole = run(&[SRC]).unwrap();
        for i in 0..=SRC.len() {
            assert_eq!(run(&[&SRC[..i], &SRC[i..]]).unwrap(), whole, "split at {i}");
        }
        let ones: Vec<&[u8]> = SRC.chunks(1).collect();
        assert_eq!(run(&ones).unwrap(), whole);
    }

    #[test]
    fn malformed_directives_are_errors() {
        assert!(run(&[b"$ORIGIN\n"]).is_err());
        assert!(run(&[b"$TTL 1 2\n"]).is_err());
        assert!(run(&[b"$GENERATE 1-2\n"]).is_err());
        assert!(run(&[b"$WAT x\n"]).is_err());
    }
}
