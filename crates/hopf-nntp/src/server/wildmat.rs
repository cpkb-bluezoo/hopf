// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Wildmat matching (RFC 3977 section 4.2).
//!
//! A wildmat is a comma-separated list of patterns, each optionally preceded
//! by `!`. The rightmost pattern that matches a name decides: the name is
//! accepted unless that pattern is negated, and a name no pattern matches is
//! rejected. Within a pattern `*` matches any run of characters (possibly
//! none) and `?` exactly one; every other character matches itself. Matching
//! is by character, so neither wildcard can split a UTF-8 sequence, and it is
//! case sensitive.

/// A parsed wildmat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wildmat {
    patterns: Vec<Pattern>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Pattern {
    negated: bool,
    items: Vec<Item>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Item {
    Star,
    Any,
    Exact(char),
}

impl Wildmat {
    /// Parses `text`, or `None` if it is not a wildmat: empty, or with an
    /// empty pattern (a leading, trailing or doubled comma, or a lone `!`).
    pub fn parse(text: &str) -> Option<Wildmat> {
        if text.is_empty() {
            return None;
        }
        let mut patterns = Vec::new();
        for part in text.split(',') {
            let (negated, body) = match part.strip_prefix('!') {
                Some(rest) => (true, rest),
                None => (false, part),
            };
            if body.is_empty() {
                return None;
            }
            let mut items: Vec<Item> = Vec::with_capacity(body.len());
            for c in body.chars() {
                let item = match c {
                    '*' => Item::Star,
                    '?' => Item::Any,
                    other => Item::Exact(other),
                };
                // Runs of stars match what one star does.
                if item == Item::Star && items.last() == Some(&Item::Star) {
                    continue;
                }
                items.push(item);
            }
            patterns.push(Pattern { negated, items });
        }
        Some(Wildmat { patterns })
    }

    /// The wildmat that matches every name.
    pub fn all() -> Wildmat {
        Wildmat {
            patterns: vec![Pattern {
                negated: false,
                items: vec![Item::Star],
            }],
        }
    }

    /// Does the wildmat accept `name`?
    pub fn matches(&self, name: &str) -> bool {
        for pattern in self.patterns.iter().rev() {
            if pattern.matches(name) {
                return !pattern.negated;
            }
        }
        false
    }
}

impl Pattern {
    /// Greedy matching with a single backtrack point (the last star), which
    /// is linear in the length of the name for each star in the pattern.
    fn matches(&self, name: &str) -> bool {
        let name: Vec<char> = name.chars().collect();
        let items = &self.items;
        let (mut n, mut p) = (0usize, 0usize);
        let mut star: Option<(usize, usize)> = None;
        while n < name.len() {
            match items.get(p) {
                Some(Item::Star) => {
                    star = Some((p, n));
                    p += 1;
                }
                Some(Item::Any) => {
                    n += 1;
                    p += 1;
                }
                Some(Item::Exact(c)) if *c == name[n] => {
                    n += 1;
                    p += 1;
                }
                _ => match star {
                    Some((sp, sn)) => {
                        // Let the star take one more character.
                        p = sp + 1;
                        n = sn + 1;
                        star = Some((sp, sn + 1));
                    }
                    None => return false,
                },
            }
        }
        while items.get(p) == Some(&Item::Star) {
            p += 1;
        }
        p == items.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(w: &str, name: &str) -> bool {
        Wildmat::parse(w).unwrap().matches(name)
    }

    #[test]
    fn the_rfc_example_decides_by_the_rightmost_match() {
        let w = "a*,!*b,*c*";
        assert!(m(w, "aaa"));
        assert!(!m(w, "abb"));
        assert!(m(w, "ccb"));
        assert!(!m(w, "xxx"));
    }

    #[test]
    fn star_and_question_mark() {
        assert!(m("comp.*", "comp.lang.rust"));
        assert!(m("comp.*", "comp."));
        assert!(!m("comp.*", "comp"));
        assert!(m("*.rust", "comp.lang.rust"));
        assert!(m("c?mp", "comp"));
        assert!(!m("c?mp", "cmp"));
        assert!(m("*", ""));
        assert!(m("a*b*c", "a--b--c"));
        assert!(!m("a*b*c", "a--b--d"));
        assert!(m("a**b", "ab"));
    }

    #[test]
    fn matching_is_by_character_not_octet() {
        assert!(m("caf?", "caf\u{e9}"));
        assert!(!m("caf??", "caf\u{e9}"));
        assert!(m("*\u{e9}", "caf\u{e9}"));
    }

    #[test]
    fn matching_is_case_sensitive_and_anchored() {
        assert!(!m("Comp.*", "comp.x"));
        assert!(!m("comp", "comp.x"));
        assert!(!m("omp.x", "comp.x"));
    }

    #[test]
    fn a_star_does_not_take_exponential_time() {
        let name = "a".repeat(5000);
        let pattern = "a*a*a*a*a*a*a*a*b";
        assert!(!m(pattern, &name));
    }

    #[test]
    fn malformed_wildmats_are_refused() {
        for bad in ["", ",", "a,", ",a", "a,,b", "!", "a,!"] {
            assert!(Wildmat::parse(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn all_matches_everything() {
        assert!(Wildmat::all().matches("anything.at.all"));
        assert!(Wildmat::all().matches(""));
    }
}
