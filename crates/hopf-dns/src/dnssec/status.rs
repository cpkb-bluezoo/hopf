// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

/// DNSSEC validation outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecStatus {
    /// Chain of trust validated.
    Secure,
    /// Insecure (no DS / unsigned zone).
    Insecure,
    /// Bogus (validation failed).
    Bogus,
    /// Not enough data to decide.
    Indeterminate,
}
