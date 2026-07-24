// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

use std::sync::atomic::{AtomicU16, Ordering};

/// Allocates 16-bit DNS query IDs.
#[derive(Debug, Default)]
pub struct DnsQueryIdGenerator {
    next: AtomicU16,
}

impl DnsQueryIdGenerator {
    /// New generator.
    pub fn new() -> Self {
        Self {
            next: AtomicU16::new(1),
        }
    }

    /// Next ID (skips 0).
    pub fn next_id(&self) -> u16 {
        loop {
            let id = self.next.fetch_add(1, Ordering::Relaxed);
            if id != 0 {
                return id;
            }
        }
    }
}
