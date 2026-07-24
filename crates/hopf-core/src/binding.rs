// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Opaque binding identifiers for dynamic listen/dial registration.

use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_BINDING_ID: AtomicU64 = AtomicU64::new(1);

/// Identifies a Runtime-registered binding (TCP listener today).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BindingId(u64);

impl BindingId {
    /// Allocate a new unique id.
    pub fn next() -> Self {
        Self(NEXT_BINDING_ID.fetch_add(1, Ordering::Relaxed))
    }

    /// Raw numeric value (diagnostics).
    pub fn as_u64(self) -> u64 {
        self.0
    }
}
