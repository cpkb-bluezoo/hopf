// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Public Suffix List — organizational-domain resolution for DMARC (RFC 7489 §3.2).
//!
//! Bundles the ICANN + PRIVATE sections of the Mozilla Public Suffix List
//! (<https://publicsuffix.org/list/>, MPL-2.0 — see `public_suffix_list.dat`)
//! and implements the "Formal Algorithm" from <https://publicsuffix.org/list/>:
//! longest matching rule wins, exception rules beat wildcards beat plain rules,
//! and an unmatched domain falls back to its last label (`*`).

use std::collections::HashSet;
use std::sync::OnceLock;

const RAW_LIST: &str = include_str!("public_suffix_list.dat");

/// Parsed Public Suffix List rule set.
pub struct PublicSuffixList {
    exact: HashSet<String>,
    wildcard: HashSet<String>,
    exception: HashSet<String>,
}

fn global() -> &'static PublicSuffixList {
    static LIST: OnceLock<PublicSuffixList> = OnceLock::new();
    LIST.get_or_init(|| PublicSuffixList::parse(RAW_LIST))
}

impl PublicSuffixList {
    /// The bundled list (ICANN + PRIVATE sections).
    pub fn bundled() -> &'static PublicSuffixList {
        global()
    }

    /// Parse a `public_suffix_list.dat`-format document.
    pub fn parse(data: &str) -> Self {
        let mut exact = HashSet::new();
        let mut wildcard = HashSet::new();
        let mut exception = HashSet::new();
        for line in data.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("//") {
                continue;
            }
            // Rules are the first whitespace-delimited token on the line.
            let rule = match line.split_whitespace().next() {
                Some(r) => r,
                None => continue,
            };
            if let Some(rest) = rule.strip_prefix('!') {
                exception.insert(rest.to_ascii_lowercase());
            } else if let Some(rest) = rule.strip_prefix("*.") {
                wildcard.insert(rest.to_ascii_lowercase());
            } else {
                exact.insert(rule.to_ascii_lowercase());
            }
        }
        Self {
            exact,
            wildcard,
            exception,
        }
    }

    /// Public suffix of `domain` (e.g. `"example.co.uk"` -> `"co.uk"`).
    ///
    /// Returns `None` only for the empty string.
    pub fn public_suffix(&self, domain: &str) -> Option<String> {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        if domain.is_empty() {
            return None;
        }
        let labels: Vec<&str> = domain.split('.').collect();

        // Exception rules take priority: the exact candidate suffix is listed
        // (without its leading `!`) in `exception`.
        for start in 0..labels.len() {
            let candidate = labels[start..].join(".");
            if self.exception.contains(&candidate) {
                // Public suffix = matched labels minus the leftmost one.
                return Some(labels[start + 1..].join("."));
            }
        }

        let mut best: Option<usize> = None; // best = start index into `labels`
        for start in 0..labels.len() {
            let candidate = labels[start..].join(".");
            if self.exact.contains(&candidate) {
                best = Some(best.map_or(start, |b| b.min(start)));
            }
            // Wildcard "*.rest" matches when `candidate` minus its first label
            // equals a wildcard entry, i.e. `candidate` has >= 2 labels.
            if labels.len() - start >= 2 {
                let rest = labels[start + 1..].join(".");
                if self.wildcard.contains(&rest) {
                    best = Some(best.map_or(start, |b| b.min(start)));
                }
            }
        }

        match best {
            Some(start) => Some(labels[start..].join(".")),
            // No rule matched: the implicit `*` rule applies — last label only.
            None => Some(labels[labels.len() - 1].to_string()),
        }
    }

    /// Organizational (registrable) domain per RFC 7489 §3.2: the public
    /// suffix plus the one label immediately to its left. Returns `None` if
    /// `domain` is itself at or above its own public suffix (no such label).
    pub fn organizational_domain(&self, domain: &str) -> Option<String> {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        let suffix = self.public_suffix(&domain)?;
        if domain == suffix {
            return None;
        }
        let suffix_labels = suffix.split('.').count();
        let labels: Vec<&str> = domain.split('.').collect();
        if labels.len() <= suffix_labels {
            return None;
        }
        let start = labels.len() - suffix_labels - 1;
        Some(labels[start..].join("."))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_com() {
        let psl = PublicSuffixList::bundled();
        assert_eq!(psl.public_suffix("example.com").as_deref(), Some("com"));
        assert_eq!(
            psl.organizational_domain("mail.example.com").as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn multi_label_suffix() {
        let psl = PublicSuffixList::bundled();
        assert_eq!(
            psl.public_suffix("www.example.co.uk").as_deref(),
            Some("co.uk")
        );
        assert_eq!(
            psl.organizational_domain("www.example.co.uk").as_deref(),
            Some("example.co.uk")
        );
    }

    #[test]
    fn wildcard_rule() {
        // *.ck with exception !www.ck
        let psl = PublicSuffixList::bundled();
        assert_eq!(psl.public_suffix("foo.ck").as_deref(), Some("foo.ck"));
        assert_eq!(
            psl.organizational_domain("bar.foo.ck").as_deref(),
            Some("bar.foo.ck")
        );
        // www.ck is an exception carve-out: public suffix becomes "ck".
        assert_eq!(psl.public_suffix("www.ck").as_deref(), Some("ck"));
        assert_eq!(
            psl.organizational_domain("www.ck").as_deref(),
            Some("www.ck")
        );
    }

    #[test]
    fn unknown_tld_falls_back_to_last_label() {
        let psl = PublicSuffixList::bundled();
        assert_eq!(
            psl.public_suffix("example.invalidtld").as_deref(),
            Some("invalidtld")
        );
        assert_eq!(
            psl.organizational_domain("mail.example.invalidtld")
                .as_deref(),
            Some("example.invalidtld")
        );
    }

    #[test]
    fn domain_is_its_own_suffix() {
        let psl = PublicSuffixList::bundled();
        assert_eq!(psl.organizational_domain("co.uk"), None);
    }
}
