// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Quota tracking skeleton (bytes / messages per connection).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Quota decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaVerdict {
    /// Under limit.
    Ok,
    /// Exceeded.
    Exceeded,
}

/// Per-connection (or shared) quota tracker.
pub trait QuotaTracker: Send + Sync {
    /// Record `n` inbound bytes.
    fn add_inbound(&self, n: u64) -> QuotaVerdict;
    /// Record `n` outbound bytes.
    fn add_outbound(&self, n: u64) -> QuotaVerdict;
    /// Record one application message / frame.
    fn add_message(&self) -> QuotaVerdict;
}

/// Unlimited no-op tracker.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnlimitedQuota;

impl QuotaTracker for UnlimitedQuota {
    fn add_inbound(&self, _n: u64) -> QuotaVerdict {
        QuotaVerdict::Ok
    }
    fn add_outbound(&self, _n: u64) -> QuotaVerdict {
        QuotaVerdict::Ok
    }
    fn add_message(&self) -> QuotaVerdict {
        QuotaVerdict::Ok
    }
}

/// Simple counter with independent caps (`0` = unlimited for that axis).
#[derive(Debug)]
pub struct CounterQuota {
    max_in: u64,
    max_out: u64,
    max_messages: u64,
    in_bytes: AtomicU64,
    out_bytes: AtomicU64,
    messages: AtomicU64,
}

impl CounterQuota {
    /// Create caps (`0` disables that limit).
    pub fn new(max_in: u64, max_out: u64, max_messages: u64) -> Arc<Self> {
        Arc::new(Self {
            max_in,
            max_out,
            max_messages,
            in_bytes: AtomicU64::new(0),
            out_bytes: AtomicU64::new(0),
            messages: AtomicU64::new(0),
        })
    }
}

impl QuotaTracker for CounterQuota {
    fn add_inbound(&self, n: u64) -> QuotaVerdict {
        let v = self.in_bytes.fetch_add(n, Ordering::Relaxed) + n;
        if self.max_in > 0 && v > self.max_in {
            QuotaVerdict::Exceeded
        } else {
            QuotaVerdict::Ok
        }
    }

    fn add_outbound(&self, n: u64) -> QuotaVerdict {
        let v = self.out_bytes.fetch_add(n, Ordering::Relaxed) + n;
        if self.max_out > 0 && v > self.max_out {
            QuotaVerdict::Exceeded
        } else {
            QuotaVerdict::Ok
        }
    }

    fn add_message(&self) -> QuotaVerdict {
        let v = self.messages.fetch_add(1, Ordering::Relaxed) + 1;
        if self.max_messages > 0 && v > self.max_messages {
            QuotaVerdict::Exceeded
        } else {
            QuotaVerdict::Ok
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlimited_always_ok() {
        let q = UnlimitedQuota;
        assert_eq!(q.add_inbound(1 << 40), QuotaVerdict::Ok);
        assert_eq!(q.add_outbound(1 << 40), QuotaVerdict::Ok);
        assert_eq!(q.add_message(), QuotaVerdict::Ok);
    }

    #[test]
    fn counter_caps_and_zero_unlimited() {
        let q = CounterQuota::new(10, 5, 2);
        assert_eq!(q.add_inbound(10), QuotaVerdict::Ok);
        assert_eq!(q.add_inbound(1), QuotaVerdict::Exceeded);
        assert_eq!(q.add_outbound(5), QuotaVerdict::Ok);
        assert_eq!(q.add_outbound(1), QuotaVerdict::Exceeded);
        assert_eq!(q.add_message(), QuotaVerdict::Ok);
        assert_eq!(q.add_message(), QuotaVerdict::Ok);
        assert_eq!(q.add_message(), QuotaVerdict::Exceeded);

        let open = CounterQuota::new(0, 0, 0);
        assert_eq!(open.add_inbound(u64::MAX / 2), QuotaVerdict::Ok);
        assert_eq!(open.add_message(), QuotaVerdict::Ok);
    }
}

