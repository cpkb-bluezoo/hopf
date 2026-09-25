// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 8482 minimal `ANY` policy.

use crate::wire::DnsQuestion;

/// Decides whether a query for `ANY` is answered with the single synthesised
/// `HINFO "RFC8482" ""` record instead of everything at the name (RFC 8482
/// §4.2).
///
/// It is consulted only for `ANY` questions, and a name that does not exist
/// is `NXDOMAIN` whatever the policy says. Any `Fn(&DnsQuestion) -> bool`
/// is a policy, so per-name rules are a closure:
///
/// ```ignore
/// builder.minimal_any_policy(|q: &DnsQuestion| !q.name.ends_with("internal.example"))
/// ```
pub trait MinimalAnyPolicy: Send + Sync {
    /// `true` to answer with the minimal record.
    fn should_return_minimal_any(&self, question: &DnsQuestion) -> bool;
}

/// Always answer `ANY` minimally (the default).
#[derive(Debug, Clone, Copy, Default)]
pub struct MinimalAnyEnabled;

/// Never: answer `ANY` with everything at the name.
#[derive(Debug, Clone, Copy, Default)]
pub struct MinimalAnyDisabled;

impl MinimalAnyPolicy for MinimalAnyEnabled {
    fn should_return_minimal_any(&self, _question: &DnsQuestion) -> bool {
        true
    }
}

impl MinimalAnyPolicy for MinimalAnyDisabled {
    fn should_return_minimal_any(&self, _question: &DnsQuestion) -> bool {
        false
    }
}

impl<F> MinimalAnyPolicy for F
where
    F: Fn(&DnsQuestion) -> bool + Send + Sync,
{
    fn should_return_minimal_any(&self, question: &DnsQuestion) -> bool {
        self(question)
    }
}
