// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! LIST-EXTENDED selection and return options (RFC 5258 / RFC 5819).

use std::collections::BTreeSet;

use crate::server::status_items::{parse_status_items, StatusItem};

/// LIST selection options (before the reference/mailbox).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ListSelectOption {
    /// SUBSCRIBED
    Subscribed,
    /// REMOTE (ignored — no remote namespaces)
    Remote,
    /// RECURSIVEMATCH
    RecursiveMatch,
    /// SPECIAL-USE (pass-through; no filtering without SPECIAL-USE attrs)
    SpecialUse,
}

/// LIST return options.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ListReturnOptions {
    /// RETURN (CHILDREN) — request \HasChildren / \HasNoChildren.
    pub children: bool,
    /// RETURN (SUBSCRIBED)
    pub subscribed: bool,
    /// RETURN (STATUS (…))
    pub status: BTreeSet<StatusItem>,
}

/// Parsed LIST / LIST-EXTENDED command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListCommand {
    /// Selection options (may be empty).
    pub select: BTreeSet<ListSelectOption>,
    /// Reference name.
    pub reference: String,
    /// Mailbox pattern.
    pub pattern: String,
    /// Return options.
    pub ret: ListReturnOptions,
}

impl ListSelectOption {
    fn parse(name: &str) -> Option<Self> {
        Some(match name.to_ascii_uppercase().as_str() {
            "SUBSCRIBED" => Self::Subscribed,
            "REMOTE" => Self::Remote,
            "RECURSIVEMATCH" => Self::RecursiveMatch,
            "SPECIAL-USE" => Self::SpecialUse,
            _ => return None,
        })
    }
}

/// Parse LIST arguments, supporting both classic and extended forms.
///
/// Classic: `reference pattern`  
/// Extended: `(select…) reference pattern [RETURN (…)]`
pub fn parse_list_command(args: &str) -> Result<ListCommand, String> {
    let mut s = args.trim_start();
    let mut select = BTreeSet::new();

    if s.starts_with('(') {
        let end = find_matching_paren(s)?;
        let inner = &s[1..end];
        for tok in inner.split_whitespace() {
            let Some(opt) = ListSelectOption::parse(tok) else {
                return Err(format!("unknown LIST selection option {tok}"));
            };
            select.insert(opt);
        }
        s = s[end + 1..].trim_start();
    }

    let (reference, rest) = parse_list_mailbox(s)?;
    let (pattern, rest) = parse_list_mailbox(rest)?;
    let mut ret = ListReturnOptions::default();
    let rest = rest.trim_start();
    if !rest.is_empty() {
        if !rest.to_ascii_uppercase().starts_with("RETURN") {
            return Err("unexpected trailing LIST arguments".into());
        }
        let after = rest[6..].trim_start();
        if !after.starts_with('(') {
            return Err("RETURN requires a parenthesized list".into());
        }
        let end = find_matching_paren(after)?;
        let inner = after[1..end].trim();
        parse_return_options(inner, &mut ret)?;
        let trailing = after[end + 1..].trim();
        if !trailing.is_empty() {
            return Err("trailing junk after LIST RETURN".into());
        }
    }

    Ok(ListCommand {
        select,
        reference,
        pattern,
        ret,
    })
}

/// Parse a list-mailbox / astring, allowing `%` and `*` wildcards in atoms.
fn parse_list_mailbox(s: &str) -> Result<(String, &str), String> {
    let s = s.trim_start();
    if s.is_empty() {
        return Err("expected astring".into());
    }
    if s.as_bytes()[0] == b'"' {
        return crate::parse_astring(s);
    }
    let mut end = 0;
    for (i, b) in s.bytes().enumerate() {
        if matches!(b, b'(' | b')' | b'{' | b' ' | b'"' | b'\\' | b']') || !b.is_ascii_graphic() {
            break;
        }
        end = i + 1;
    }
    if end == 0 {
        return Err("expected astring".into());
    }
    Ok((s[..end].to_string(), s[end..].trim_start()))
}

fn parse_return_options(inner: &str, ret: &mut ListReturnOptions) -> Result<(), String> {
    let mut i = 0;
    let bytes = inner.as_bytes();
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        if bytes[i] == b'(' {
            return Err("unexpected nested list in RETURN".into());
        }
        let start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'(' {
            i += 1;
        }
        let atom = inner[start..i].to_ascii_uppercase();
        match atom.as_str() {
            "CHILDREN" => ret.children = true,
            "SUBSCRIBED" => ret.subscribed = true,
            "STATUS" => {
                let rest = inner[i..].trim_start();
                if !rest.starts_with('(') {
                    return Err("STATUS return option requires (items)".into());
                }
                let end = find_matching_paren(rest)?;
                ret.status = parse_status_items(&rest[..=end])?;
                i = (inner.len() - rest.len()) + end + 1;
            }
            _ => return Err(format!("unknown LIST RETURN option {atom}")),
        }
    }
    Ok(())
}

fn find_matching_paren(s: &str) -> Result<usize, String> {
    let bytes = s.as_bytes();
    if bytes.first() != Some(&b'(') {
        return Err("expected '('".into());
    }
    let mut depth = 0i32;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(i);
                }
            }
            _ => {}
        }
    }
    Err("unclosed parenthesis".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classic_list() {
        let cmd = parse_list_command("\"\" INBOX").unwrap();
        assert!(cmd.select.is_empty());
        assert_eq!(cmd.reference, "");
        assert_eq!(cmd.pattern, "INBOX");
        assert!(!cmd.ret.children);
    }

    #[test]
    fn extended_subscribed_children() {
        let cmd = parse_list_command("(SUBSCRIBED) \"\" * RETURN (CHILDREN)").unwrap();
        assert!(cmd.select.contains(&ListSelectOption::Subscribed));
        assert!(cmd.ret.children);
    }

    #[test]
    fn list_return_status() {
        let cmd = parse_list_command("() \"\" % RETURN (STATUS (MESSAGES UIDNEXT))").unwrap();
        assert!(cmd.ret.status.contains(&StatusItem::Messages));
        assert!(cmd.ret.status.contains(&StatusItem::UidNext));
    }

    #[test]
    fn empty_selection_parens() {
        let cmd = parse_list_command("() \"\" *").unwrap();
        assert!(cmd.select.is_empty());
        assert_eq!(cmd.pattern, "*");
    }
}
