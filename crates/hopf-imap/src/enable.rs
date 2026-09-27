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
    /// UTF8=ACCEPT enabled (RFC 6855) — sticky for the session; RFC 6855
    /// forbids un-enabling it once set.
    pub utf8_accept: bool,
}

impl EnabledExtensions {
    /// Apply ENABLE tokens; returns the subset newly enabled this round.
    pub fn enable(
        &mut self,
        tokens: &[&str],
        allow_condstore: bool,
        allow_qresync: bool,
        allow_utf8_accept: bool,
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
                "UTF8=ACCEPT" if allow_utf8_accept && !self.utf8_accept => {
                    self.utf8_accept = true;
                    newly.push("UTF8=ACCEPT");
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
        if self.utf8_accept {
            s.insert("UTF8=ACCEPT");
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
        let n = e.enable(&["CONDSTORE"], true, true, true);
        assert_eq!(n, vec!["CONDSTORE"]);
        assert!(e.condstore);
        let n2 = e.enable(&["QRESYNC"], true, true, true);
        assert_eq!(n2, vec!["QRESYNC"]);
        assert!(e.qresync);
        // Re-enable is a no-op for ENABLED list.
        let n3 = e.enable(&["CONDSTORE", "QRESYNC"], true, true, true);
        assert!(n3.is_empty());
    }

    #[test]
    fn enable_respects_config() {
        let mut e = EnabledExtensions::default();
        let n = e.enable(&["CONDSTORE", "QRESYNC"], false, false, false);
        assert!(n.is_empty());
        assert!(!e.condstore);
    }

    #[test]
    fn enable_utf8_accept_is_sticky() {
        let mut e = EnabledExtensions::default();
        let n = e.enable(&["UTF8=ACCEPT"], true, true, true);
        assert_eq!(n, vec!["UTF8=ACCEPT"]);
        assert!(e.utf8_accept);
        assert!(e.names().contains("UTF8=ACCEPT"));
        // Re-enable is a no-op for ENABLED list.
        let n2 = e.enable(&["UTF8=ACCEPT"], true, true, true);
        assert!(n2.is_empty());
    }

    #[test]
    fn enable_utf8_accept_respects_config() {
        let mut e = EnabledExtensions::default();
        let n = e.enable(&["UTF8=ACCEPT"], true, true, false);
        assert!(n.is_empty());
        assert!(!e.utf8_accept);
    }

    #[test]
    fn parse_enable_args_uppercases() {
        assert_eq!(
            parse_enable_args("condstore QRESYNC"),
            vec!["CONDSTORE".to_string(), "QRESYNC".to_string()]
        );
    }
}
