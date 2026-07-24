// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! IMAP message set (`1:5,7,*`).

use crate::error::{MailboxError, MailboxResult};

/// Wildcard sequence / UID (`*`).
pub const WILDCARD: u64 = u64::MAX;

/// Inclusive range; endpoints may be [`WILDCARD`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessageRange {
    /// Start (1-based, or [`WILDCARD`]).
    pub start: u64,
    /// End (1-based, or [`WILDCARD`]).
    pub end: u64,
}

impl MessageRange {
    /// Single message number.
    pub fn single(n: u64) -> Self {
        Self { start: n, end: n }
    }

    /// Inclusive range (normalized ascending when both ends are concrete).
    pub fn range(start: u64, end: u64) -> Self {
        if start != WILDCARD && end != WILDCARD && start > end {
            Self {
                start: end,
                end: start,
            }
        } else {
            Self { start, end }
        }
    }

    /// Whether `number` is in this range given the mailbox's last number.
    pub fn contains(self, number: u64, last_number: u64) -> bool {
        let start = if self.start == WILDCARD {
            last_number
        } else {
            self.start
        };
        let end = if self.end == WILDCARD {
            last_number
        } else {
            self.end
        };
        let (lo, hi) = if start <= end {
            (start, end)
        } else {
            (end, start)
        };
        number >= lo && number <= hi
    }
}

/// Parsed IMAP message set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MessageSet {
    ranges: Vec<MessageRange>,
}

impl MessageSet {
    /// Empty set.
    pub fn empty() -> Self {
        Self { ranges: Vec::new() }
    }

    /// `1:*`
    pub fn all() -> Self {
        Self {
            ranges: vec![MessageRange::range(1, WILDCARD)],
        }
    }

    /// Single number.
    pub fn single(n: u64) -> Self {
        Self {
            ranges: vec![MessageRange::single(n)],
        }
    }

    /// Inclusive range.
    pub fn range(start: u64, end: u64) -> Self {
        Self {
            ranges: vec![MessageRange::range(start, end)],
        }
    }

    /// Last message (`*`).
    pub fn last() -> Self {
        Self {
            ranges: vec![MessageRange::single(WILDCARD)],
        }
    }

    /// Parse IMAP set syntax (`1:5,7,10:*`).
    pub fn parse(s: &str) -> MailboxResult<Self> {
        let mut ranges = Vec::new();
        for part in s.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some((a, b)) = part.split_once(':') {
                let start = parse_value(a.trim())?;
                let end = parse_value(b.trim())?;
                ranges.push(MessageRange::range(start, end));
            } else {
                ranges.push(MessageRange::single(parse_value(part)?));
            }
        }
        if ranges.is_empty() {
            return Err(MailboxError::Invalid(
                "empty message set".to_string(),
            ));
        }
        Ok(Self { ranges })
    }

    /// Ranges in this set.
    pub fn ranges(&self) -> &[MessageRange] {
        &self.ranges
    }

    /// Whether `number` is included.
    pub fn contains(&self, number: u64, last_number: u64) -> bool {
        self.ranges
            .iter()
            .any(|r| r.contains(number, last_number))
    }
}

fn parse_value(s: &str) -> MailboxResult<u64> {
    if s == "*" {
        return Ok(WILDCARD);
    }
    let n: u64 = s
        .parse()
        .map_err(|_| MailboxError::Invalid(format!("bad message set value: {s}")))?;
    if n < 1 {
        return Err(MailboxError::Invalid(
            "message numbers must be >= 1".to_string(),
        ));
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mixed() {
        let s = MessageSet::parse("1:5,7,10:*").unwrap();
        assert!(s.contains(3, 20));
        assert!(s.contains(7, 20));
        assert!(s.contains(15, 20));
        assert!(!s.contains(6, 20));
        assert!(!s.contains(9, 20));
    }
}
