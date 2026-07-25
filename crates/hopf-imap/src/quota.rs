// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Minimal IMAP QUOTA manager (RFC 9208).

use std::collections::BTreeMap;
use std::sync::Mutex;

/// One quota resource limit. Negative limit means unlimited.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuotaResource {
    /// Current usage.
    pub usage: i64,
    /// Limit (`-1` = unlimited).
    pub limit: i64,
}

impl QuotaResource {
    /// Unlimited resource with the given usage.
    pub fn unlimited(usage: i64) -> Self {
        Self { usage, limit: -1 }
    }

    /// Limited resource.
    pub fn limited(usage: i64, limit: i64) -> Self {
        Self { usage, limit }
    }

    /// Whether the limit is unlimited.
    pub fn is_unlimited(&self) -> bool {
        self.limit < 0
    }
}

/// Quota for one root: resource name → usage/limit.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Quota {
    /// Resources (`STORAGE` in KiB, `MESSAGE` count, …).
    pub resources: BTreeMap<String, QuotaResource>,
}

impl Quota {
    /// Unlimited STORAGE and MESSAGE.
    pub fn unlimited() -> Self {
        let mut resources = BTreeMap::new();
        resources.insert("STORAGE".into(), QuotaResource::unlimited(0));
        resources.insert("MESSAGE".into(), QuotaResource::unlimited(0));
        Self { resources }
    }

    /// Format an untagged `QUOTA` response line (without the `* ` prefix).
    pub fn format_response(&self, quota_root: &str) -> String {
        let mut parts = Vec::new();
        for (name, res) in &self.resources {
            if res.is_unlimited() {
                continue;
            }
            parts.push(format!("{name} {} {}", res.usage, res.limit));
        }
        format!(
            "QUOTA {} ({})",
            crate::quote_astring(quota_root),
            parts.join(" ")
        )
    }
}

/// Pluggable quota backend for GETQUOTA / SETQUOTA.
pub trait QuotaManager: Send + Sync {
    /// Quota for `username` (personal root).
    fn get_quota(&self, username: &str) -> Quota;
    /// Replace limits for `username`. Usage is preserved when possible.
    fn set_quota(&self, username: &str, resources: BTreeMap<String, i64>) -> Result<Quota, String>;
}

/// Always-unlimited default (advertises empty resource list).
#[derive(Debug, Default)]
pub struct UnlimitedQuotaManager;

impl QuotaManager for UnlimitedQuotaManager {
    fn get_quota(&self, _username: &str) -> Quota {
        Quota::unlimited()
    }

    fn set_quota(
        &self,
        _username: &str,
        _resources: BTreeMap<String, i64>,
    ) -> Result<Quota, String> {
        Err("quota is unlimited and not configurable".into())
    }
}

/// In-memory per-user limits (usage stays at 0 unless updated externally).
#[derive(Debug, Default)]
pub struct MemoryQuotaManager {
    inner: Mutex<BTreeMap<String, Quota>>,
}

impl MemoryQuotaManager {
    /// Empty manager (missing users → unlimited).
    pub fn new() -> Self {
        Self::default()
    }
}

impl QuotaManager for MemoryQuotaManager {
    fn get_quota(&self, username: &str) -> Quota {
        self.inner
            .lock()
            .unwrap()
            .get(username)
            .cloned()
            .unwrap_or_else(Quota::unlimited)
    }

    fn set_quota(&self, username: &str, resources: BTreeMap<String, i64>) -> Result<Quota, String> {
        let mut g = self.inner.lock().unwrap();
        let entry = g
            .entry(username.to_string())
            .or_insert_with(Quota::unlimited);
        for (name, limit) in resources {
            let usage = entry.resources.get(&name).map(|r| r.usage).unwrap_or(0);
            entry.resources.insert(name, QuotaResource { usage, limit });
        }
        Ok(entry.clone())
    }
}

/// Parse SETQUOTA resource list `(STORAGE 1024 MESSAGE 100)`.
pub fn parse_quota_resource_list(s: &str) -> Result<BTreeMap<String, i64>, String> {
    let s = s.trim();
    let inner = if s.starts_with('(') {
        if !s.ends_with(')') {
            return Err("unclosed quota resource list".into());
        }
        &s[1..s.len() - 1]
    } else {
        s
    };
    let mut out = BTreeMap::new();
    let mut toks = inner.split_whitespace();
    while let Some(name) = toks.next() {
        let Some(limit_s) = toks.next() else {
            return Err(format!("missing limit for {name}"));
        };
        let limit: i64 = limit_s
            .parse()
            .map_err(|_| format!("bad quota limit {limit_s}"))?;
        out.insert(name.to_ascii_uppercase(), limit);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota_parser() {
        let m = parse_quota_resource_list("(STORAGE 1024 MESSAGE -1)").unwrap();
        assert_eq!(m.get("STORAGE"), Some(&1024));
        assert_eq!(m.get("MESSAGE"), Some(&-1));
    }

    #[test]
    fn unlimited_formats_empty_resources() {
        let q = Quota::unlimited();
        assert_eq!(q.format_response(""), "QUOTA \"\" ()");
    }

    #[test]
    fn memory_set_get() {
        let mgr = MemoryQuotaManager::new();
        let mut limits = BTreeMap::new();
        limits.insert("STORAGE".into(), 100);
        mgr.set_quota("alice", limits).unwrap();
        let q = mgr.get_quota("alice");
        assert_eq!(q.resources["STORAGE"].limit, 100);
        assert!(!q.resources["STORAGE"].is_unlimited());
    }
}
