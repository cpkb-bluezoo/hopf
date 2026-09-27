// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! IMAP GETMETADATA / SETMETADATA argument parsing (RFC 5464).

use crate::server::codec::parse_astring;

/// GETMETADATA options (RFC 5464 §4.2.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetMetadataOptions {
    /// `DEPTH` — `None` means `infinity` (every descendant); `Some(0)`
    /// (the default when the option is absent — see [`Default`] below)
    /// means the named entries only, no children.
    pub depth: Option<u32>,
    /// `MAXSIZE` — entries whose value exceeds this are omitted from the
    /// response, and the server reports the largest skipped size via the
    /// `METADATA LONGENTRIES` response code.
    pub max_size: Option<u32>,
}

impl Default for GetMetadataOptions {
    /// RFC 5464 §4.2.2: `DEPTH` defaults to `0` (no children) when the
    /// option is absent — deriving `Default` would wrongly give `None`
    /// (this type's spelling of `infinity`) instead.
    fn default() -> Self {
        Self {
            depth: Some(0),
            max_size: None,
        }
    }
}

/// Parsed `GETMETADATA` command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetMetadataCommand {
    /// Target mailbox, or `""` for server annotations (RFC 5464's own
    /// convention).
    pub mailbox: String,
    /// Requested entries, in command order.
    pub entries: Vec<String>,
    /// `DEPTH` / `MAXSIZE` options.
    pub options: GetMetadataOptions,
}

/// Parsed `SETMETADATA` command. A `None` value means the client sent
/// literal `NIL` — delete that entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetMetadataCommand {
    /// Target mailbox, or `""` for server annotations.
    pub mailbox: String,
    /// `(entry, value)` pairs, in command order.
    pub entries: Vec<(String, Option<String>)>,
}

/// Parse `GETMETADATA` args, i.e. everything after the command verb:
/// `[(options)] mailbox (entry ...)` or `[(options)] mailbox entry`.
pub fn parse_getmetadata(args: &str) -> Result<GetMetadataCommand, String> {
    let mut rest = args.trim_start();
    let mut options = GetMetadataOptions::default();
    if rest.starts_with('(') {
        let (opts_str, after) = take_parenthesized(rest)?;
        options = parse_getmetadata_options(opts_str)?;
        rest = after.trim_start();
    }
    let (mailbox, rest) = parse_astring(rest)?;
    let rest = rest.trim_start();
    if rest.is_empty() {
        return Err("GETMETADATA requires an entry list".into());
    }
    let entries = parse_entry_list(rest)?;
    Ok(GetMetadataCommand {
        mailbox,
        entries,
        options,
    })
}

/// Parse `SETMETADATA` args: `mailbox (entry value entry value ...)`.
pub fn parse_setmetadata(args: &str) -> Result<SetMetadataCommand, String> {
    let rest = args.trim_start();
    let (mailbox, rest) = parse_astring(rest)?;
    let rest = rest.trim_start();
    if !rest.starts_with('(') {
        return Err("SETMETADATA requires a parenthesized entry-value list".into());
    }
    let (inner, trailing) = take_parenthesized(rest)?;
    if !trailing.trim().is_empty() {
        return Err("unexpected input after SETMETADATA entry list".into());
    }
    let mut entries = Vec::new();
    let mut cursor = inner;
    loop {
        cursor = cursor.trim_start();
        if cursor.is_empty() {
            break;
        }
        let (entry, after_entry) = parse_astring(cursor)?;
        let after_entry = after_entry.trim_start();
        let (value, after_value) = parse_metadata_value(after_entry)?;
        entries.push((entry, value));
        cursor = after_value;
    }
    if entries.is_empty() {
        return Err("SETMETADATA requires at least one entry".into());
    }
    Ok(SetMetadataCommand { mailbox, entries })
}

fn parse_getmetadata_options(s: &str) -> Result<GetMetadataOptions, String> {
    let mut opts = GetMetadataOptions::default();
    let mut cursor = s.trim();
    while !cursor.is_empty() {
        let (tok, after) = take_atom(cursor)?;
        match tok.to_ascii_uppercase().as_str() {
            "DEPTH" => {
                let after = after.trim_start();
                let (val, after) = take_atom(after)?;
                opts.depth = match val.as_str() {
                    "0" => Some(0),
                    "1" => Some(1),
                    "infinity" => None,
                    other => return Err(format!("invalid DEPTH value: {other}")),
                };
                cursor = after;
            }
            "MAXSIZE" => {
                let after = after.trim_start();
                let (val, after) = take_atom(after)?;
                let n: u32 = val
                    .parse()
                    .map_err(|_| format!("invalid MAXSIZE value: {val}"))?;
                opts.max_size = Some(n);
                cursor = after;
            }
            other => return Err(format!("unknown GETMETADATA option: {other}")),
        }
        cursor = cursor.trim_start();
    }
    Ok(opts)
}

fn parse_entry_list(s: &str) -> Result<Vec<String>, String> {
    let s = s.trim();
    if s.starts_with('(') {
        let (inner, trailing) = take_parenthesized(s)?;
        if !trailing.trim().is_empty() {
            return Err("unexpected input after entry list".into());
        }
        let mut entries = Vec::new();
        let mut cursor = inner;
        loop {
            cursor = cursor.trim_start();
            if cursor.is_empty() {
                break;
            }
            let (entry, after) = parse_astring(cursor)?;
            entries.push(entry);
            cursor = after;
        }
        if entries.is_empty() {
            return Err("empty entry list".into());
        }
        Ok(entries)
    } else {
        let (entry, trailing) = parse_astring(s)?;
        if !trailing.trim().is_empty() {
            return Err("unexpected input after entry".into());
        }
        Ok(vec![entry])
    }
}

/// One `SETMETADATA` value: `NIL` (deletion) or an astring/literal.
fn parse_metadata_value(s: &str) -> Result<(Option<String>, &str), String> {
    if let Some(after) = s.strip_prefix("NIL") {
        let boundary = after
            .as_bytes()
            .first()
            .map(|b| !b.is_ascii_alphanumeric())
            .unwrap_or(true);
        if boundary {
            return Ok((None, after.trim_start()));
        }
    }
    let (v, after) = parse_astring(s)?;
    Ok((Some(v), after))
}

/// Consume a balanced `(...)` group starting at `s`, returning its interior
/// (without the parens) and whatever trails it.
fn take_parenthesized(s: &str) -> Result<(&str, &str), String> {
    if !s.starts_with('(') {
        return Err("expected '('".into());
    }
    let mut depth = 0i32;
    for (i, b) in s.bytes().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Ok((&s[1..i], &s[i + 1..]));
                }
            }
            _ => {}
        }
    }
    Err("unclosed parenthesized list".into())
}

fn take_atom(s: &str) -> Result<(String, &str), String> {
    let s = s.trim_start();
    let end = s
        .find(|c: char| c.is_whitespace() || c == '(' || c == ')')
        .unwrap_or(s.len());
    if end == 0 {
        return Err("expected atom".into());
    }
    Ok((s[..end].to_string(), &s[end..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn getmetadata_single_bare_entry() {
        let c = parse_getmetadata("INBOX /private/comment").unwrap();
        assert_eq!(c.mailbox, "INBOX");
        assert_eq!(c.entries, vec!["/private/comment".to_string()]);
        assert_eq!(c.options, GetMetadataOptions::default());
    }

    #[test]
    fn depth_absent_defaults_to_zero_not_infinity() {
        // RFC 5464 §4.2.2: DEPTH defaults to 0 (no children) when the
        // option is absent, not `infinity`.
        assert_eq!(GetMetadataOptions::default().depth, Some(0));
        let c = parse_getmetadata("INBOX /private/comment").unwrap();
        assert_eq!(c.options.depth, Some(0));
    }

    #[test]
    fn getmetadata_entry_list_and_server_mailbox() {
        let c = parse_getmetadata("\"\" (/private/comment /shared/comment)").unwrap();
        assert_eq!(c.mailbox, "");
        assert_eq!(
            c.entries,
            vec![
                "/private/comment".to_string(),
                "/shared/comment".to_string()
            ]
        );
    }

    #[test]
    fn getmetadata_depth_and_maxsize_options() {
        let c = parse_getmetadata("(DEPTH infinity MAXSIZE 1024) INBOX /private/comment").unwrap();
        assert_eq!(c.options.depth, None);
        assert_eq!(c.options.max_size, Some(1024));

        let c = parse_getmetadata("(DEPTH 1) INBOX /private/comment").unwrap();
        assert_eq!(c.options.depth, Some(1));
    }

    #[test]
    fn getmetadata_rejects_bad_depth() {
        assert!(parse_getmetadata("(DEPTH 7) INBOX /private/comment").is_err());
    }

    #[test]
    fn setmetadata_sets_and_deletes() {
        let c = parse_setmetadata("INBOX (/private/comment \"hello\" /private/other NIL)").unwrap();
        assert_eq!(c.mailbox, "INBOX");
        assert_eq!(
            c.entries,
            vec![
                ("/private/comment".to_string(), Some("hello".to_string())),
                ("/private/other".to_string(), None),
            ]
        );
    }

    #[test]
    fn setmetadata_server_mailbox_is_empty_string() {
        let c = parse_setmetadata("\"\" (/private/comment \"x\")").unwrap();
        assert_eq!(c.mailbox, "");
    }

    #[test]
    fn setmetadata_requires_parenthesized_list() {
        assert!(parse_setmetadata("INBOX /private/comment \"x\"").is_err());
    }
}
