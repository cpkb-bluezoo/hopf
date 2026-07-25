// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! ENABLE command support (RFC 5161 / RFC 7162).

use std::collections::BTreeSet;

/// Per-session enabled extension set.
#[derive(Clone, Debug, Default)]
pub struct EnabledExtensions {
    /// CONDSTORE enabled (explicitly or via QRESYNC).
    pub condstore: bool,
    /// QRESYNC enabled.
    pub qresync: bool,
}

impl EnabledExtensions {
    /// Apply ENABLE tokens; returns the subset newly enabled this round.
    pub fn enable(
        &mut self,
        tokens: &[&str],
        allow_condstore: bool,
        allow_qresync: bool,
    ) -> Vec<&'static str> {
        let mut newly = Vec::new();
        for tok in tokens {
            let u = tok.to_ascii_uppercase();
            match u.as_str() {
                "CONDSTORE" if allow_condstore && !self.condstore => {
                    self.condstore = true;
                    newly.push("CONDSTORE");
                }
                "QRESYNC" if allow_qresync && !self.qresync => {
                    self.qresync = true;
                    self.condstore = true;
                    newly.push("QRESYNC");
                }
                _ => {}
            }
        }
        newly
    }

    /// Names currently enabled (for tests / diagnostics).
    pub fn names(&self) -> BTreeSet<&'static str> {
        let mut s = BTreeSet::new();
        if self.condstore {
            s.insert("CONDSTORE");
        }
        if self.qresync {
            s.insert("QRESYNC");
        }
        s
    }
}

/// Split ENABLE arguments into extension names.
pub fn parse_enable_args(args: &str) -> Vec<String> {
    args.split_whitespace()
        .map(|s| s.to_ascii_uppercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enable_condstore_then_qresync() {
        let mut e = EnabledExtensions::default();
        let n = e.enable(&["CONDSTORE"], true, true);
        assert_eq!(n, vec!["CONDSTORE"]);
        assert!(e.condstore);
        let n2 = e.enable(&["QRESYNC"], true, true);
        assert_eq!(n2, vec!["QRESYNC"]);
        assert!(e.qresync);
        // Re-enable is a no-op for ENABLED list.
        let n3 = e.enable(&["CONDSTORE", "QRESYNC"], true, true);
        assert!(n3.is_empty());
    }

    #[test]
    fn enable_respects_config() {
        let mut e = EnabledExtensions::default();
        let n = e.enable(&["CONDSTORE", "QRESYNC"], false, false);
        assert!(n.is_empty());
        assert!(!e.condstore);
    }

    #[test]
    fn parse_enable_args_uppercases() {
        assert_eq!(
            parse_enable_args("condstore QRESYNC"),
            vec!["CONDSTORE".to_string(), "QRESYNC".to_string()]
        );
    }
}
