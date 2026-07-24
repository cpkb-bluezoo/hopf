// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! IMAP system flags.

use std::collections::BTreeSet;
use std::fmt;

/// IMAP system flag (RFC 9051).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Flag {
    /// `\Seen`
    Seen = 0,
    /// `\Answered`
    Answered = 1,
    /// `\Flagged`
    Flagged = 2,
    /// `\Deleted`
    Deleted = 3,
    /// `\Draft`
    Draft = 4,
    /// `\Recent` — session-only; not permanent.
    Recent = 5,
}

impl Flag {
    /// IMAP atom including leading backslash.
    pub fn atom(self) -> &'static str {
        match self {
            Self::Seen => "\\Seen",
            Self::Answered => "\\Answered",
            Self::Flagged => "\\Flagged",
            Self::Deleted => "\\Deleted",
            Self::Draft => "\\Draft",
            Self::Recent => "\\Recent",
        }
    }

    /// Name without backslash (for sidecars).
    pub fn name(self) -> &'static str {
        match self {
            Self::Seen => "Seen",
            Self::Answered => "Answered",
            Self::Flagged => "Flagged",
            Self::Deleted => "Deleted",
            Self::Draft => "Draft",
            Self::Recent => "Recent",
        }
    }

    /// Maildir info letter, if any (`Recent` has none).
    pub fn maildir_letter(self) -> Option<char> {
        match self {
            Self::Draft => Some('D'),
            Self::Flagged => Some('F'),
            Self::Answered => Some('R'),
            Self::Seen => Some('S'),
            Self::Deleted => Some('T'),
            Self::Recent => None,
        }
    }

    /// Parse Maildir info letter.
    pub fn from_maildir_letter(c: char) -> Option<Self> {
        match c {
            'D' => Some(Self::Draft),
            'F' => Some(Self::Flagged),
            'R' => Some(Self::Answered),
            'S' => Some(Self::Seen),
            'T' => Some(Self::Deleted),
            _ => None,
        }
    }

    /// Parse IMAP atom or bare name (case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        let t = s.trim().trim_start_matches('\\');
        match t.to_ascii_lowercase().as_str() {
            "seen" => Some(Self::Seen),
            "answered" => Some(Self::Answered),
            "flagged" => Some(Self::Flagged),
            "deleted" => Some(Self::Deleted),
            "draft" => Some(Self::Draft),
            "recent" => Some(Self::Recent),
            _ => None,
        }
    }

    /// Permanent flags (excludes `Recent`).
    pub fn permanent() -> [Flag; 5] {
        [
            Self::Seen,
            Self::Answered,
            Self::Flagged,
            Self::Deleted,
            Self::Draft,
        ]
    }

    /// Index bit for `.gidx` flags byte.
    pub fn index_bit(self) -> u8 {
        1u8 << (self as u8)
    }
}

impl fmt::Display for Flag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.atom())
    }
}

/// Encode system flags into a single index byte.
pub fn flags_to_byte(flags: &BTreeSet<Flag>) -> u8 {
    flags.iter().fold(0u8, |acc, f| acc | f.index_bit())
}

/// Decode system flags from an index byte.
pub fn flags_from_byte(b: u8) -> BTreeSet<Flag> {
    let mut out = BTreeSet::new();
    for f in [
        Flag::Seen,
        Flag::Answered,
        Flag::Flagged,
        Flag::Deleted,
        Flag::Draft,
        Flag::Recent,
    ] {
        if b & f.index_bit() != 0 {
            out.insert(f);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_byte() {
        let mut s = BTreeSet::new();
        s.insert(Flag::Seen);
        s.insert(Flag::Flagged);
        let b = flags_to_byte(&s);
        assert_eq!(flags_from_byte(b), s);
    }
}
