// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The rows of a `LIST` (RFC 9051 §6.3.9), shared by the stores: matching a
//! pattern against names, and saying which have children.

use std::collections::{BTreeMap, BTreeSet};

use crate::traits::{MailboxAttribute, MailboxInfo};

/// Does `name` match `pattern`? `*` matches any run of characters, `%` any
/// run that does not contain `delimiter`. Names are case-sensitive except
/// `INBOX`, which is not.
pub(crate) fn matches(pattern: &str, name: &str, delimiter: char) -> bool {
    let pattern: Vec<char> = if name == "INBOX" { pattern.to_lowercase().chars().collect() } else { pattern.chars().collect() };
    let name: Vec<char> = if name == "INBOX" { "inbox".chars().collect() } else { name.chars().collect() };
    // reach[j]: the pattern so far can have consumed the first j characters of the name.
    let mut reach = vec![false; name.len() + 1];
    reach[0] = true;
    for &p in &pattern {
        let mut next = vec![false; name.len() + 1];
        for j in 0..=name.len() {
            next[j] = match p {
                '*' => reach[j] || (j > 0 && next[j - 1]),
                '%' => reach[j] || (j > 0 && next[j - 1] && name[j - 1] != delimiter),
                c => j > 0 && reach[j - 1] && name[j - 1] == c,
            };
        }
        reach = next;
    }
    reach[name.len()]
}

/// The rows of a `LIST` of `reference` and `pattern` over the mailboxes
/// `real` (each with the attributes it has of its own).
///
/// A name that is the way to a mailbox but no mailbox itself (`Deep` and
/// `Deep/Down`, when only `Deep/Down/Here` exists) is a row too, `\Noselect`:
/// without it a client that lists one level at a time could not find its way
/// down. An empty pattern asks for the delimiter and the root, and is
/// answered with one `\Noselect` row for the root, which has no name.
pub(crate) fn rows(real: Vec<MailboxInfo>, reference: &str, pattern: &str, delimiter: char) -> Vec<MailboxInfo> {
    let full = format!("{reference}{pattern}");
    if full.is_empty() {
        return vec![MailboxInfo { name: String::new(), attributes: BTreeSet::from([MailboxAttribute::NoSelect]) }];
    }
    let mut all: BTreeMap<String, BTreeSet<MailboxAttribute>> = BTreeMap::new();
    let mut parents: BTreeSet<String> = BTreeSet::new();
    for info in &real {
        // The names above it: "a/b/c" is below "a" and "a/b".
        for (i, _) in info.name.match_indices(delimiter) {
            parents.insert(info.name[..i].to_string());
        }
    }
    for info in real {
        all.insert(info.name, info.attributes);
    }
    for parent in &parents {
        all.entry(parent.clone()).or_insert_with(|| BTreeSet::from([MailboxAttribute::NoSelect]));
    }
    let mut out: Vec<MailboxInfo> = all
        .into_iter()
        .filter(|(name, _)| matches(&full, name, delimiter))
        .map(|(name, mut attributes)| {
            attributes.insert(if parents.contains(&name) { MailboxAttribute::HasChildren } else { MailboxAttribute::HasNoChildren });
            MailboxInfo { name, attributes }
        })
        .collect();
    out.sort_by(|a, b| (a.name != "INBOX", &a.name).cmp(&(b.name != "INBOX", &b.name)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards() {
        assert!(matches("*", "a/b", '/') && matches("%", "ab", '/') && !matches("%", "a/b", '/'));
        assert!(matches("a/%", "a/b", '/') && !matches("a/%", "a/b/c", '/') && matches("a/*", "a/b/c", '/'));
        assert!(matches("%/%", "a/b", '/') && !matches("%/%", "a", '/'));
        assert!(matches("a%c", "abc", '/') && matches("a*c", "a/b/c", '/') && !matches("a%c", "a/c", '/'));
        assert!(matches("", "", '/') && !matches("", "a", '/'));
        assert!(matches("inbox", "INBOX", '/') && matches("INB*", "INBOX", '/') && !matches("inbox", "Inbox", '/'));
        assert!(!matches("work", "Work", '/'));
        // Many wildcards do not make it slow.
        assert!(!matches(&format!("{}x", "*%".repeat(40)), &"a".repeat(3000), '/'));
    }
}
