// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Bailiwick filtering (cache-poisoning defence).

use crate::wire::{normalize_name, DnsResourceRecord};

/// Case-insensitive domain equality.
pub fn names_equal(a: &str, b: &str) -> bool {
    normalize_name(a) == normalize_name(b)
}

/// `record_owner` is `qname` or a subdomain of it.
pub fn is_within_bailiwick(record_owner: &str, qname: &str) -> bool {
    let owner = normalize_name(record_owner);
    let query = normalize_name(qname);
    if owner.is_empty() || query.is_empty() {
        return false;
    }
    if owner == query {
        return true;
    }
    owner.ends_with(&format!(".{query}"))
}

/// Filter answers to bailiwick of `qname`.
pub fn filter_answers_in_bailiwick(
    qname: &str,
    answers: &[DnsResourceRecord],
) -> Vec<DnsResourceRecord> {
    answers
        .iter()
        .filter(|rr| is_within_bailiwick(&rr.name, qname))
        .cloned()
        .collect()
}

/// Filter authority section similarly.
pub fn filter_authorities_in_bailiwick(
    qname: &str,
    authorities: &[DnsResourceRecord],
) -> Vec<DnsResourceRecord> {
    filter_answers_in_bailiwick(qname, authorities)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subdomain_in_bailiwick() {
        assert!(is_within_bailiwick("www.example.com", "example.com"));
        assert!(!is_within_bailiwick("evil.com", "example.com"));
    }
}
