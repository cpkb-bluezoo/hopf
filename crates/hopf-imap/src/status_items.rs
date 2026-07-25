// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! IMAP STATUS data items (RFC 9051 §6.3.11).

use std::collections::BTreeSet;

/// STATUS / LIST-STATUS data item.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StatusItem {
    /// MESSAGES
    Messages,
    /// RECENT (legacy)
    Recent,
    /// UIDNEXT
    UidNext,
    /// UIDVALIDITY
    UidValidity,
    /// UNSEEN (first unseen sequence, or 0)
    Unseen,
    /// DELETED count
    Deleted,
    /// SIZE in octets
    Size,
    /// HIGHESTMODSEQ (CONDSTORE)
    HighestModseq,
}

impl StatusItem {
    /// Parse a single atom (case-insensitive).
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name.to_ascii_uppercase().as_str() {
            "MESSAGES" => Self::Messages,
            "RECENT" => Self::Recent,
            "UIDNEXT" => Self::UidNext,
            "UIDVALIDITY" => Self::UidValidity,
            "UNSEEN" => Self::Unseen,
            "DELETED" => Self::Deleted,
            "SIZE" => Self::Size,
            "HIGHESTMODSEQ" => Self::HighestModseq,
            _ => return None,
        })
    }

    /// Wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Messages => "MESSAGES",
            Self::Recent => "RECENT",
            Self::UidNext => "UIDNEXT",
            Self::UidValidity => "UIDVALIDITY",
            Self::Unseen => "UNSEEN",
            Self::Deleted => "DELETED",
            Self::Size => "SIZE",
            Self::HighestModseq => "HIGHESTMODSEQ",
        }
    }
}

/// Parse `(MESSAGES UIDNEXT …)` after the mailbox name.
pub fn parse_status_items(s: &str) -> Result<BTreeSet<StatusItem>, String> {
    let s = s.trim();
    let inner = if s.starts_with('(') {
        if !s.ends_with(')') {
            return Err("unclosed STATUS list".into());
        }
        &s[1..s.len() - 1]
    } else {
        s
    };
    let mut items = BTreeSet::new();
    for tok in inner.split_whitespace() {
        let Some(item) = StatusItem::parse(tok) else {
            return Err(format!("unknown STATUS item {tok}"));
        };
        items.insert(item);
    }
    if items.is_empty() {
        return Err("empty STATUS list".into());
    }
    Ok(items)
}

/// Parse `mailbox (ITEMS…)` for STATUS.
pub fn parse_status_command(args: &str) -> Result<(String, BTreeSet<StatusItem>), String> {
    let args = args.trim();
    let paren = args
        .find('(')
        .ok_or_else(|| "STATUS requires parenthesized items".to_string())?;
    let name_part = args[..paren].trim();
    let items_part = args[paren..].trim();
    let name = if name_part.starts_with('"') {
        crate::parse_astring(name_part)?.0
    } else if name_part.is_empty() {
        return Err("missing mailbox name".into());
    } else {
        // Atom or empty string — allow unquoted.
        name_part
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string()
    };
    let items = parse_status_items(items_part)?;
    Ok((name, items))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_status_items_basic() {
        let items = parse_status_items("(MESSAGES UIDNEXT UNSEEN)").unwrap();
        assert!(items.contains(&StatusItem::Messages));
        assert!(items.contains(&StatusItem::UidNext));
        assert!(items.contains(&StatusItem::Unseen));
        assert_eq!(items.len(), 3);
    }

    #[test]
    fn parse_status_command_quoted() {
        let (name, items) = parse_status_command("\"INBOX\" (MESSAGES RECENT)").unwrap();
        assert_eq!(name, "INBOX");
        assert!(items.contains(&StatusItem::Recent));
    }

    #[test]
    fn parse_status_rejects_unknown() {
        assert!(parse_status_items("(BOGUS)").is_err());
    }
}
