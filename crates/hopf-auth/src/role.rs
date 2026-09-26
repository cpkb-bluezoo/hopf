// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Role membership for authorization after authentication (HTTP Digest/Basic
//! identity, SASL authcid, certificate mapping, …).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Check whether `username` holds `role`.
///
/// Role names are application-defined strings (e.g. `webdav:read` for RFC 3744
/// WebDAV privileges). This is separate from [`crate::TrustPolicy`], which only
/// decides whether presented credentials are accepted.
pub trait RolePolicy: Send + Sync {
    /// Whether `username` is a member of `role`.
    fn is_user_in_role(&self, username: &str, role: &str) -> bool;
}

impl RolePolicy for Arc<dyn RolePolicy> {
    fn is_user_in_role(&self, username: &str, role: &str) -> bool {
        (**self).is_user_in_role(username, role)
    }
}

/// In-memory username → role set (demos and tests).
#[derive(Debug, Default, Clone)]
pub struct RoleMembership {
    roles: HashMap<String, HashSet<String>>,
}

impl RoleMembership {
    /// Empty membership (every [`is_user_in_role`](RolePolicy::is_user_in_role) is false).
    pub fn new() -> Self {
        Self::default()
    }

    /// Grant `role` to `username` (builder).
    pub fn with_role(mut self, username: impl Into<String>, role: impl Into<String>) -> Self {
        self.add_role(username, role);
        self
    }

    /// Grant `role` to `username`.
    pub fn add_role(&mut self, username: impl Into<String>, role: impl Into<String>) {
        self.roles
            .entry(username.into())
            .or_default()
            .insert(role.into());
    }

    /// Shared trait object.
    pub fn shared(self) -> Arc<dyn RolePolicy> {
        Arc::new(self)
    }
}

impl RolePolicy for RoleMembership {
    fn is_user_in_role(&self, username: &str, role: &str) -> bool {
        self.roles
            .get(username)
            .map(|r| r.contains(role))
            .unwrap_or(false)
    }
}
