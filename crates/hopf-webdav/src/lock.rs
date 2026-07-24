// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! In-memory WebDAV lock manager (RFC 4918 §6).

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use crate::constants::{self, DEPTH_1, DEPTH_INFINITY, LOCK_TOKEN_SCHEME};

/// Lock scope (RFC 4918 §14.13 / §14.26).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockScope {
    Exclusive,
    Shared,
}

/// Lock type (RFC 4918 §14.29).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockType {
    Write,
}

/// A WebDAV lock on a resource.
#[derive(Debug, Clone)]
pub struct WebDavLock {
    token: String,
    path: PathBuf,
    scope: LockScope,
    #[allow(dead_code)]
    ty: LockType,
    depth: i32,
    owner: String,
    #[allow(dead_code)]
    created_at: SystemTime,
    expires_at: Option<SystemTime>,
}

impl WebDavLock {
    pub fn new(
        path: PathBuf,
        scope: LockScope,
        ty: LockType,
        depth: i32,
        owner: String,
        timeout_seconds: i64,
    ) -> Self {
        let token = format!("{}{}", LOCK_TOKEN_SCHEME, new_opaque_token());
        let created_at = SystemTime::now();
        let expires_at = if timeout_seconds < 0 {
            None
        } else {
            Some(created_at + Duration::from_secs(timeout_seconds as u64))
        };
        Self {
            token,
            path,
            scope,
            ty,
            depth,
            owner,
            created_at,
            expires_at,
        }
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn scope(&self) -> LockScope {
        self.scope
    }

    pub fn depth(&self) -> i32 {
        self.depth
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }

    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            None => false,
            Some(t) => SystemTime::now() > t,
        }
    }

    pub fn remaining_timeout_seconds(&self) -> i64 {
        match self.expires_at {
            None => -1,
            Some(t) => t
                .duration_since(SystemTime::now())
                .unwrap_or(Duration::ZERO)
                .as_secs() as i64,
        }
    }

    pub fn refresh(&mut self, timeout_seconds: i64) {
        if timeout_seconds < 0 {
            self.expires_at = None;
        } else {
            self.expires_at = Some(SystemTime::now() + Duration::from_secs(timeout_seconds as u64));
        }
    }

    /// Whether this lock covers `target_path` (RFC 4918 §14.4 depth).
    pub fn covers(&self, target_path: &Path) -> bool {
        if self.path == target_path {
            return true;
        }
        if self.depth == DEPTH_INFINITY {
            return target_path.starts_with(&self.path);
        }
        if self.depth == DEPTH_1 {
            if let Some(parent) = target_path.parent() {
                return parent == self.path.as_path();
            }
        }
        false
    }

    pub fn timeout_header_value(&self) -> String {
        let rem = self.remaining_timeout_seconds();
        if rem < 0 {
            constants::TIMEOUT_INFINITE.to_string()
        } else {
            format!("{}{}", constants::TIMEOUT_SECOND_PREFIX, rem)
        }
    }
}

fn new_opaque_token() -> String {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).expect("getrandom");
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i == 8 || i == 12 || i == 16 || i == 20 {
                format!("-{c}")
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// Manages WebDAV locks for resources.
pub struct WebDavLockManager {
    inner: Mutex<LockTable>,
}

struct LockTable {
    by_token: std::collections::HashMap<String, WebDavLock>,
    by_path: std::collections::HashMap<PathBuf, Vec<String>>,
}

impl Default for WebDavLockManager {
    fn default() -> Self {
        Self::new()
    }
}

impl WebDavLockManager {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(LockTable {
                by_token: std::collections::HashMap::new(),
                by_path: std::collections::HashMap::new(),
            }),
        }
    }

    pub fn lock(
        &self,
        path: PathBuf,
        scope: LockScope,
        ty: LockType,
        depth: i32,
        owner: String,
        timeout_seconds: i64,
    ) -> Option<WebDavLock> {
        let mut table = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        table.clean_expired();
        if table.has_conflicting_lock(&path, scope) {
            return None;
        }
        let lock = WebDavLock::new(path.clone(), scope, ty, depth, owner, timeout_seconds);
        let token = lock.token().to_string();
        table.by_token.insert(token.clone(), lock.clone());
        table.by_path.entry(path).or_default().push(token);
        Some(lock)
    }

    pub fn unlock(&self, token: &str) -> bool {
        let mut table = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(lock) = table.by_token.remove(token) else {
            return false;
        };
        if let Some(list) = table.by_path.get_mut(lock.path()) {
            list.retain(|t| t != token);
            if list.is_empty() {
                table.by_path.remove(lock.path());
            }
        }
        true
    }

    pub fn refresh(&self, token: &str, timeout_seconds: i64) -> Option<WebDavLock> {
        let mut table = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let lock = table.by_token.get_mut(token)?;
        if lock.is_expired() {
            table.remove_token(token);
            return None;
        }
        lock.refresh(timeout_seconds);
        Some(lock.clone())
    }

    pub fn get_lock(&self, token: &str) -> Option<WebDavLock> {
        let mut table = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let expired = table
            .by_token
            .get(token)
            .map(|l| l.is_expired())
            .unwrap_or(false);
        if expired {
            table.remove_token(token);
            return None;
        }
        table.by_token.get(token).cloned()
    }

    pub fn get_locks(&self, path: &Path) -> Vec<WebDavLock> {
        let table = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(tokens) = table.by_path.get(path) else {
            return Vec::new();
        };
        tokens
            .iter()
            .filter_map(|t| table.by_token.get(t).filter(|l| !l.is_expired()).cloned())
            .collect()
    }

    pub fn get_covering_locks(&self, path: &Path) -> Vec<WebDavLock> {
        let table = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        table
            .by_token
            .values()
            .filter(|l| !l.is_expired() && l.covers(path))
            .cloned()
            .collect()
    }

    pub fn is_locked(&self, path: &Path) -> bool {
        !self.get_covering_locks(path).is_empty()
    }

    pub fn validate_token(&self, path: &Path, token: &str) -> bool {
        self.get_lock(token)
            .map(|l| l.covers(path))
            .unwrap_or(false)
    }
}

impl LockTable {
    fn remove_token(&mut self, token: &str) {
        if let Some(lock) = self.by_token.remove(token) {
            if let Some(list) = self.by_path.get_mut(lock.path()) {
                list.retain(|t| t != token);
                if list.is_empty() {
                    self.by_path.remove(lock.path());
                }
            }
        }
    }

    fn clean_expired(&mut self) {
        let expired: Vec<String> = self
            .by_token
            .iter()
            .filter(|(_, l)| l.is_expired())
            .map(|(t, _)| t.clone())
            .collect();
        for t in expired {
            self.remove_token(&t);
        }
    }

    fn has_conflicting_lock(&self, path: &Path, requested_scope: LockScope) -> bool {
        for existing in self.by_token.values() {
            if existing.is_expired() {
                continue;
            }
            if existing.covers(path) {
                if existing.scope == LockScope::Exclusive || requested_scope == LockScope::Exclusive
                {
                    return true;
                }
            }
            if path == existing.path() || existing.path().starts_with(path) {
                if existing.scope == LockScope::Exclusive || requested_scope == LockScope::Exclusive
                {
                    return true;
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::DEPTH_0;
    use std::path::PathBuf;

    #[test]
    fn lock_covers_depth_infinity() {
        let root = PathBuf::from("/data/collection");
        let lock = WebDavLock::new(
            root.clone(),
            LockScope::Exclusive,
            LockType::Write,
            DEPTH_INFINITY,
            String::new(),
            3600,
        );
        assert!(lock.covers(&PathBuf::from("/data/collection/a/b")));
        assert!(!lock.covers(&PathBuf::from("/data/other")));
    }

    #[test]
    fn lock_manager_conflict() {
        let mgr = WebDavLockManager::new();
        let p = PathBuf::from("/x");
        assert!(mgr
            .lock(
                p.clone(),
                LockScope::Exclusive,
                LockType::Write,
                DEPTH_0,
                String::new(),
                60
            )
            .is_some());
        assert!(mgr
            .lock(
                p.clone(),
                LockScope::Shared,
                LockType::Write,
                DEPTH_0,
                String::new(),
                60
            )
            .is_none());
    }

    #[test]
    fn lock_manager_covers_validate() {
        let mgr = WebDavLockManager::new();
        let root = PathBuf::from("/dav");
        let lock = mgr
            .lock(
                root,
                LockScope::Exclusive,
                LockType::Write,
                DEPTH_INFINITY,
                String::new(),
                3600,
            )
            .unwrap();
        assert!(mgr.validate_token(
            &PathBuf::from("/dav/sub/file"),
            lock.token()
        ));
        assert!(mgr.unlock(lock.token()));
        assert!(!mgr.validate_token(&PathBuf::from("/dav/sub/file"), lock.token()));
    }
}
