// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Closed registry of named [`HandlerFactory`](crate::HandlerFactory) values.
//!
//! Composition XML resolves `handler="…"` here — never by reflective type load.

use std::collections::HashMap;

use crate::listener::HandlerFactory;

/// Maps short names to connection-level handler factories.
#[derive(Clone, Default)]
pub struct CompositionRegistry {
    handlers: HashMap<String, HandlerFactory>,
}

impl CompositionRegistry {
    /// Empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `name` → `factory`. Replaces any previous entry for `name`.
    pub fn register(&mut self, name: impl Into<String>, factory: HandlerFactory) -> &mut Self {
        self.handlers.insert(name.into(), factory);
        self
    }

    /// Look up a registered factory.
    pub fn get(&self, name: &str) -> Option<&HandlerFactory> {
        self.handlers.get(name)
    }

    /// Whether `name` is registered.
    pub fn contains(&self, name: &str) -> bool {
        self.handlers.contains_key(name)
    }
}
