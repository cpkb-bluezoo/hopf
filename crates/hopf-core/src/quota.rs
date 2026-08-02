// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Quota tracking: connection traffic limits and per-user storage accounting.
//!
//! # Connection-level (DoS / rate)
//!
//! [`QuotaTracker`] / [`CounterQuota`] / [`UnlimitedQuota`] count bytes in/out
//! and messages **per connection** — closer to traffic limiting than storage
//! policy.
//!
//! # Per-user storage (Gumdrop `org.bluezoo.gumdrop.quota` parity)
//!
//! [`QuotaManager`] / [`Quota`] track how much storage (and, optionally, how
//! many messages) a *user* has accumulated — across however many connections
//! or protocols touch their data. The same manager can back an FTP file store
//! and an IMAP mailbox at once.
//!
//! Resolution priority for [`QuotaManager::get_quota`]: user-specific quota
//! (highest), then role-based, then the system default, then unlimited.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

// ── Connection-level traffic tracker ──────────────────────────────────────────

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

// ── Per-user storage quota ────────────────────────────────────────────────────

/// Sentinel meaning "no limit" for [`Quota`] fields.
pub const UNLIMITED: i64 = -1;

/// Where a [`Quota`]'s limits came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaSource {
    /// Defined specifically for this user (highest priority).
    User,
    /// Derived from a role the user belongs to.
    Role,
    /// The system-wide default policy.
    Default,
    /// No quota configured (unlimited).
    None,
}

/// A user's storage quota limits and current usage. Either limit may be
/// [`UNLIMITED`] (`-1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quota {
    storage_limit: i64,
    message_limit: i64,
    storage_used: i64,
    message_count: i64,
    source: QuotaSource,
    source_detail: Option<String>,
}

impl Quota {
    /// New quota with the given limits and zero usage.
    pub fn new(storage_limit: i64, message_limit: i64) -> Self {
        Self {
            storage_limit,
            message_limit,
            storage_used: 0,
            message_count: 0,
            source: QuotaSource::None,
            source_detail: None,
        }
    }

    /// No limits on either axis.
    pub fn unlimited() -> Self {
        Self::new(UNLIMITED, UNLIMITED)
    }

    /// Attach where this quota's limits came from.
    pub fn with_source(mut self, source: QuotaSource, detail: Option<String>) -> Self {
        self.source = source;
        self.source_detail = detail;
        self
    }

    /// Storage limit in bytes, or [`UNLIMITED`].
    pub fn storage_limit(&self) -> i64 {
        self.storage_limit
    }
    /// Message count limit, or [`UNLIMITED`].
    pub fn message_limit(&self) -> i64 {
        self.message_limit
    }
    /// Bytes currently used.
    pub fn storage_used(&self) -> i64 {
        self.storage_used
    }
    /// Messages currently stored.
    pub fn message_count(&self) -> i64 {
        self.message_count
    }
    /// Where the limits came from.
    pub fn source(&self) -> QuotaSource {
        self.source
    }
    /// Extra detail about the source (e.g. the role name), if any.
    pub fn source_detail(&self) -> Option<&str> {
        self.source_detail.as_deref()
    }

    /// Storage limit in KiB (IMAP QUOTA response units), or [`UNLIMITED`].
    pub fn storage_limit_kib(&self) -> i64 {
        if self.storage_limit < 0 {
            UNLIMITED
        } else {
            self.storage_limit / 1024
        }
    }
    /// Storage used in KiB.
    pub fn storage_used_kib(&self) -> i64 {
        self.storage_used / 1024
    }

    /// Set current usage directly (e.g. after
    /// [`QuotaManager::recalculate_usage`] rescans storage).
    pub fn set_storage_used(&mut self, used: i64) {
        self.storage_used = used;
    }
    /// Set current message count directly.
    pub fn set_message_count(&mut self, count: i64) {
        self.message_count = count;
    }

    /// Storage limit reached or exceeded.
    pub fn is_storage_exceeded(&self) -> bool {
        self.storage_limit >= 0 && self.storage_used >= self.storage_limit
    }
    /// Message limit reached or exceeded.
    pub fn is_message_limit_exceeded(&self) -> bool {
        self.message_limit >= 0 && self.message_count >= self.message_limit
    }
    /// No storage limit set.
    pub fn is_storage_unlimited(&self) -> bool {
        self.storage_limit < 0
    }
    /// No message limit set.
    pub fn is_message_unlimited(&self) -> bool {
        self.message_limit < 0
    }

    /// Bytes remaining before the limit, or `i64::MAX` if unlimited.
    pub fn storage_remaining(&self) -> i64 {
        if self.storage_limit < 0 {
            i64::MAX
        } else {
            (self.storage_limit - self.storage_used).max(0)
        }
    }
    /// Messages remaining before the limit, or `i64::MAX` if unlimited.
    pub fn messages_remaining(&self) -> i64 {
        if self.message_limit < 0 {
            i64::MAX
        } else {
            (self.message_limit - self.message_count).max(0)
        }
    }

    /// Storage used, 0-100 (0 if unlimited).
    pub fn storage_percent_used(&self) -> u32 {
        if self.storage_limit <= 0 {
            0
        } else {
            (((self.storage_used.max(0) as i128 * 100) / self.storage_limit as i128).min(100)) as u32
        }
    }
    /// Messages used, 0-100 (0 if unlimited).
    pub fn message_percent_used(&self) -> u32 {
        if self.message_limit <= 0 {
            0
        } else {
            (((self.message_count.max(0) as i128 * 100) / self.message_limit as i128).min(100)) as u32
        }
    }

    /// Whether `additional_bytes` more can be stored without exceeding the
    /// limit.
    pub fn can_add_storage(&self, additional_bytes: i64) -> bool {
        self.storage_limit < 0 || self.storage_used + additional_bytes <= self.storage_limit
    }
    /// Whether one more message can be stored without exceeding the limit.
    pub fn can_add_message(&self) -> bool {
        self.message_limit < 0 || self.message_count + 1 <= self.message_limit
    }

    /// Record bytes added.
    pub fn add_storage_used(&mut self, bytes: i64) {
        self.storage_used += bytes;
    }
    /// Record bytes removed (never below zero).
    pub fn subtract_storage_used(&mut self, bytes: i64) {
        self.storage_used = (self.storage_used - bytes).max(0);
    }
    /// Record one message added.
    pub fn increment_message_count(&mut self) {
        self.message_count += 1;
    }
    /// Record one message removed (never below zero).
    pub fn decrement_message_count(&mut self) {
        self.message_count = (self.message_count - 1).max(0);
    }
}

/// Manages storage quotas for users (Gumdrop `QuotaManager`).
///
/// Resolution priority for [`get_quota`](Self::get_quota): user-specific
/// quota, then role-based, then the system default, then unlimited.
pub trait QuotaManager: Send + Sync {
    /// The user's effective quota (limits + current usage). Never fails —
    /// an unconfigured user gets [`Quota::unlimited`].
    fn get_quota(&self, username: &str) -> Quota;

    /// Force a full recalculation of usage (e.g. by rescanning storage).
    /// Default is a no-op — implementations that track usage incrementally
    /// via [`record_bytes_added`](Self::record_bytes_added) don't need it.
    fn recalculate_usage(&self, _username: &str) {}

    /// Whether `additional_bytes` more can be stored for `username`.
    fn can_store(&self, username: &str, additional_bytes: u64) -> bool {
        self.get_quota(username).can_add_storage(additional_bytes as i64)
    }

    /// Whether one more message can be stored for `username`.
    fn can_store_message(&self, username: &str) -> bool {
        self.get_quota(username).can_add_message()
    }

    /// Record bytes added after a successful store operation.
    fn record_bytes_added(&self, username: &str, bytes_added: u64);
    /// Record bytes removed after a successful delete operation.
    fn record_bytes_removed(&self, username: &str, bytes_removed: u64);
    /// Record a message added (mail systems) — `message_size` also counts
    /// toward the storage total.
    fn record_message_added(&self, username: &str, message_size: u64);
    /// Record a message removed (mail systems).
    fn record_message_removed(&self, username: &str, message_size: u64);

    /// Set a user-specific quota, overriding any role-based/default quota.
    fn set_user_quota(&self, username: &str, storage_limit: i64, message_limit: i64);
    /// Clear a user-specific quota, reverting to role-based/default.
    fn clear_user_quota(&self, username: &str);
    /// Whether a user-specific quota is defined for `username`.
    fn has_user_quota(&self, username: &str) -> bool;

    /// Persist current usage data. Default is a no-op — only relevant to
    /// implementations that don't already write through to persistent
    /// storage on every update.
    fn save_usage_data(&self) {}
    /// Load usage data from persistent storage (called on startup).
    /// Default is a no-op.
    fn load_usage_data(&self) {}
}

/// Named storage/message limits (e.g. for a role or the system default).
#[derive(Debug, Clone)]
pub struct QuotaPolicy {
    name: String,
    storage_limit: i64,
    message_limit: i64,
}

impl QuotaPolicy {
    /// New policy with both limits.
    pub fn new(name: impl Into<String>, storage_limit: i64, message_limit: i64) -> Self {
        Self {
            name: name.into(),
            storage_limit,
            message_limit,
        }
    }

    /// New policy with a storage limit only (unlimited messages).
    pub fn with_storage(name: impl Into<String>, storage_limit: i64) -> Self {
        Self::new(name, storage_limit, UNLIMITED)
    }

    /// Policy name (typically a role name, or `"default"`).
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Storage limit in bytes, or [`UNLIMITED`].
    pub fn storage_limit(&self) -> i64 {
        self.storage_limit
    }
    /// Message limit, or [`UNLIMITED`].
    pub fn message_limit(&self) -> i64 {
        self.message_limit
    }

    /// Build a fresh [`Quota`] (zero usage) from this policy.
    pub fn to_quota(&self, source: QuotaSource) -> Quota {
        Quota::new(self.storage_limit, self.message_limit).with_source(source, Some(self.name.clone()))
    }

    /// Parse a human-readable size: `"100MB"`, `"10GB"`, `"1TB"`, a bare
    /// byte count, or `"unlimited"` / `"-1"`.
    pub fn parse_size(s: &str) -> Result<i64, String> {
        let s = s.trim();
        if s.eq_ignore_ascii_case("unlimited") || s == "-1" {
            return Ok(UNLIMITED);
        }
        const KB: i64 = 1024;
        const MB: i64 = KB * 1024;
        const GB: i64 = MB * 1024;
        const TB: i64 = GB * 1024;
        let lower = s.to_ascii_lowercase();
        let (num, mult) = if let Some(n) = lower.strip_suffix("tb") {
            (n, TB)
        } else if let Some(n) = lower.strip_suffix("gb") {
            (n, GB)
        } else if let Some(n) = lower.strip_suffix("mb") {
            (n, MB)
        } else if let Some(n) = lower.strip_suffix("kb") {
            (n, KB)
        } else {
            (lower.as_str(), 1)
        };
        num.trim()
            .parse::<i64>()
            .map(|n| n * mult)
            .map_err(|_| format!("invalid quota size: {s:?}"))
    }
}

/// Always-unlimited manager: no limits, usage tracking is a no-op.
#[derive(Debug, Default)]
pub struct UnlimitedQuotaManager;

impl QuotaManager for UnlimitedQuotaManager {
    fn get_quota(&self, _username: &str) -> Quota {
        Quota::unlimited()
    }
    fn can_store(&self, _username: &str, _additional_bytes: u64) -> bool {
        true
    }
    fn can_store_message(&self, _username: &str) -> bool {
        true
    }
    fn record_bytes_added(&self, _username: &str, _bytes_added: u64) {}
    fn record_bytes_removed(&self, _username: &str, _bytes_removed: u64) {}
    fn record_message_added(&self, _username: &str, _message_size: u64) {}
    fn record_message_removed(&self, _username: &str, _message_size: u64) {}
    fn set_user_quota(&self, _username: &str, _storage_limit: i64, _message_limit: i64) {}
    fn clear_user_quota(&self, _username: &str) {}
    fn has_user_quota(&self, _username: &str) -> bool {
        false
    }
}

/// In-memory [`QuotaManager`]: usage tracked in the process, limits
/// resolved user-specific → role-based → default → unlimited. When a user
/// matches more than one role policy, the most generous storage limit
/// applies (Gumdrop semantics).
///
/// Usage isn't persisted across restarts — for that, call
/// [`QuotaManager::set_user_quota`] again on startup after loading limits
/// from wherever you store them, or subclass around
/// [`QuotaManager::save_usage_data`]/[`QuotaManager::load_usage_data`].
pub struct MemoryQuotaManager {
    users: Mutex<BTreeMap<String, Quota>>,
    roles: Vec<QuotaPolicy>,
    role_lookup: Option<Box<dyn Fn(&str) -> Vec<String> + Send + Sync>>,
    default_policy: Option<QuotaPolicy>,
}

impl std::fmt::Debug for MemoryQuotaManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryQuotaManager")
            .field("roles", &self.roles)
            .field("has_role_lookup", &self.role_lookup.is_some())
            .field("default_policy", &self.default_policy)
            .finish()
    }
}

impl Default for MemoryQuotaManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryQuotaManager {
    /// Empty manager: every user gets [`Quota::unlimited`] until a
    /// user-specific quota is set, or [`Self::with_roles`]/[`Self::with_default`]
    /// attach role/default policies.
    pub fn new() -> Self {
        Self {
            users: Mutex::new(BTreeMap::new()),
            roles: Vec::new(),
            role_lookup: None,
            default_policy: None,
        }
    }

    /// Attach role policies plus a role-membership lookup (returns the
    /// role names a user belongs to).
    pub fn with_roles(
        mut self,
        roles: Vec<QuotaPolicy>,
        lookup: impl Fn(&str) -> Vec<String> + Send + Sync + 'static,
    ) -> Self {
        self.roles = roles;
        self.role_lookup = Some(Box::new(lookup));
        self
    }

    /// System-wide default policy, applied when no user- or role-based
    /// quota matches.
    pub fn with_default(mut self, policy: QuotaPolicy) -> Self {
        self.default_policy = Some(policy);
        self
    }

    fn resolve_fresh(&self, username: &str) -> Quota {
        if let Some(lookup) = &self.role_lookup {
            let user_roles = lookup(username);
            let best = self
                .roles
                .iter()
                .filter(|p| user_roles.iter().any(|r| r == p.name()))
                .max_by_key(|p| if p.storage_limit() < 0 { i64::MAX } else { p.storage_limit() });
            if let Some(policy) = best {
                return policy.to_quota(QuotaSource::Role);
            }
        }
        if let Some(policy) = &self.default_policy {
            return policy.to_quota(QuotaSource::Default);
        }
        Quota::unlimited()
    }
}

impl QuotaManager for MemoryQuotaManager {
    fn get_quota(&self, username: &str) -> Quota {
        let mut g = self.users.lock().unwrap();
        if let Some(q) = g.get(username) {
            return q.clone();
        }
        let fresh = self.resolve_fresh(username);
        g.insert(username.to_string(), fresh.clone());
        fresh
    }

    fn record_bytes_added(&self, username: &str, bytes_added: u64) {
        let mut g = self.users.lock().unwrap();
        let fresh = self.resolve_fresh(username);
        g.entry(username.to_string())
            .or_insert(fresh)
            .add_storage_used(bytes_added as i64);
    }

    fn record_bytes_removed(&self, username: &str, bytes_removed: u64) {
        let mut g = self.users.lock().unwrap();
        let fresh = self.resolve_fresh(username);
        g.entry(username.to_string())
            .or_insert(fresh)
            .subtract_storage_used(bytes_removed as i64);
    }

    fn record_message_added(&self, username: &str, message_size: u64) {
        let mut g = self.users.lock().unwrap();
        let fresh = self.resolve_fresh(username);
        let q = g.entry(username.to_string()).or_insert(fresh);
        q.add_storage_used(message_size as i64);
        q.increment_message_count();
    }

    fn record_message_removed(&self, username: &str, message_size: u64) {
        let mut g = self.users.lock().unwrap();
        let fresh = self.resolve_fresh(username);
        let q = g.entry(username.to_string()).or_insert(fresh);
        q.subtract_storage_used(message_size as i64);
        q.decrement_message_count();
    }

    fn set_user_quota(&self, username: &str, storage_limit: i64, message_limit: i64) {
        let mut g = self.users.lock().unwrap();
        let mut q = Quota::new(storage_limit, message_limit).with_source(QuotaSource::User, None);
        if let Some(existing) = g.get(username) {
            q.set_storage_used(existing.storage_used());
            q.set_message_count(existing.message_count());
        }
        g.insert(username.to_string(), q);
    }

    fn clear_user_quota(&self, username: &str) {
        let mut g = self.users.lock().unwrap();
        if let Some(existing) = g.get(username) {
            let (used, count) = (existing.storage_used(), existing.message_count());
            let mut fresh = self.resolve_fresh(username);
            fresh.set_storage_used(used);
            fresh.set_message_count(count);
            g.insert(username.to_string(), fresh);
        }
    }

    fn has_user_quota(&self, username: &str) -> bool {
        self.users
            .lock()
            .unwrap()
            .get(username)
            .map(|q| q.source() == QuotaSource::User)
            .unwrap_or(false)
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

    #[test]
    fn quota_arithmetic() {
        let mut q = Quota::new(1000, 10);
        assert!(!q.is_storage_exceeded());
        q.add_storage_used(999);
        assert!(!q.is_storage_exceeded());
        assert!(q.can_add_storage(1));
        assert!(!q.can_add_storage(2));
        q.add_storage_used(1);
        assert!(q.is_storage_exceeded());
        assert_eq!(q.storage_remaining(), 0);
        assert_eq!(q.storage_percent_used(), 100);

        for _ in 0..10 {
            q.increment_message_count();
        }
        assert!(q.is_message_limit_exceeded());
        q.decrement_message_count();
        assert!(!q.is_message_limit_exceeded());
    }

    #[test]
    fn unlimited_quota_never_exceeded() {
        let q = Quota::unlimited();
        assert!(q.can_add_storage(i64::MAX / 2));
        assert!(q.can_add_message());
        assert_eq!(q.storage_remaining(), i64::MAX);
        assert_eq!(q.storage_percent_used(), 0);
    }

    #[test]
    fn parse_size_variants() {
        assert_eq!(QuotaPolicy::parse_size("100MB").unwrap(), 100 * 1024 * 1024);
        assert_eq!(QuotaPolicy::parse_size("10GB").unwrap(), 10 * 1024 * 1024 * 1024);
        assert_eq!(QuotaPolicy::parse_size("1TB").unwrap(), 1024i64.pow(4));
        assert_eq!(QuotaPolicy::parse_size("512").unwrap(), 512);
        assert_eq!(QuotaPolicy::parse_size("unlimited").unwrap(), UNLIMITED);
        assert_eq!(QuotaPolicy::parse_size("-1").unwrap(), UNLIMITED);
        assert!(QuotaPolicy::parse_size("not-a-size").is_err());
    }

    #[test]
    fn unlimited_manager_always_allows() {
        let m = UnlimitedQuotaManager;
        assert!(m.can_store("alice", u64::MAX / 2));
        assert!(m.can_store_message("alice"));
        m.record_bytes_added("alice", 1 << 40); // must not panic / track anything
        assert_eq!(m.get_quota("alice"), Quota::unlimited());
    }

    #[test]
    fn memory_manager_user_override_takes_priority_over_role_and_default() {
        let m = MemoryQuotaManager::new()
            .with_roles(
                vec![QuotaPolicy::with_storage("admin", 1_000_000)],
                |user| if user == "alice" { vec!["admin".into()] } else { vec![] },
            )
            .with_default(QuotaPolicy::with_storage("default", 1000));

        assert_eq!(m.get_quota("bob").storage_limit(), 1000); // default
        assert_eq!(m.get_quota("bob").source(), QuotaSource::Default);
        assert_eq!(m.get_quota("alice").storage_limit(), 1_000_000); // role
        assert_eq!(m.get_quota("alice").source(), QuotaSource::Role);

        m.set_user_quota("alice", 50, -1);
        assert_eq!(m.get_quota("alice").storage_limit(), 50); // user override wins
        assert_eq!(m.get_quota("alice").source(), QuotaSource::User);
        assert!(m.has_user_quota("alice"));

        m.clear_user_quota("alice");
        assert_eq!(m.get_quota("alice").storage_limit(), 1_000_000); // back to role
        assert!(!m.has_user_quota("alice"));
    }

    #[test]
    fn memory_manager_most_generous_role_wins() {
        let m = MemoryQuotaManager::new().with_roles(
            vec![
                QuotaPolicy::with_storage("basic", 1_000),
                QuotaPolicy::with_storage("premium", 1_000_000),
            ],
            |_user| vec!["basic".into(), "premium".into()],
        );
        assert_eq!(m.get_quota("carol").storage_limit(), 1_000_000);
    }

    #[test]
    fn memory_manager_tracks_usage_and_denies_over_limit() {
        let m = MemoryQuotaManager::new();
        m.set_user_quota("dave", 100, -1);
        assert!(m.can_store("dave", 100));
        assert!(!m.can_store("dave", 101));

        m.record_bytes_added("dave", 60);
        assert_eq!(m.get_quota("dave").storage_used(), 60);
        assert!(m.can_store("dave", 40));
        assert!(!m.can_store("dave", 41));

        m.record_bytes_removed("dave", 30);
        assert_eq!(m.get_quota("dave").storage_used(), 30);
    }

    #[test]
    fn memory_manager_message_accounting_tracks_both_bytes_and_count() {
        let m = MemoryQuotaManager::new();
        m.set_user_quota("erin", -1, 2);
        m.record_message_added("erin", 500);
        m.record_message_added("erin", 500);
        let q = m.get_quota("erin");
        assert_eq!(q.message_count(), 2);
        assert_eq!(q.storage_used(), 1000);
        assert!(q.is_message_limit_exceeded());

        m.record_message_removed("erin", 500);
        let q = m.get_quota("erin");
        assert_eq!(q.message_count(), 1);
        assert_eq!(q.storage_used(), 500);
    }
}
