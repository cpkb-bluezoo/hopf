// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! File-backed WebDAV lock records shared across handler instances (issue #415).
//!
//! Each lock is a file under the configured lock root, at the resource's
//! path relative to the content root, so handlers that mount the same tree
//! at different absolute paths agree on where a lock is. A resource's
//! record directory holds `exclusive` (the exclusive lock, if any) and
//! `shared/<token>` (one file per shared lock). Each relative-path
//! component is prefixed with `_` in the record tree so a resource literally
//! named `exclusive` or `shared` can never be confused with a record.
//!
//! A lock is granted by creating its record with a create-new (exclusive
//! create) open, then checking the ancestors' records for a lock that
//! covers the path and the descendants' records for one this lock would
//! cover. Any conflict — including a record another handler created at the
//! same moment — removes the new record and refuses the lock; if two
//! handlers each see the other, both refuse and the client retries.
//!
//! This needs a filesystem where a create-new open is atomic and a record
//! one handler writes is visible to the others before they finish their
//! conflict walk: a local disk or a typical `ReadWriteOnce` volume. Where
//! that does not hold (NFS attribute caching, for one) two grants can both
//! succeed — use a coherent filesystem, or run one lock-root replica.
//!
//! All methods here do blocking file I/O and must only be called from a
//! storage thread.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::lock::{LockScope, LockType, WebDavLock};

const EXCLUSIVE: &str = "exclusive";
const SHARED: &str = "shared";
const TEMP_PREFIX: &str = ".tmp-";
const COMPONENT_PREFIX: &str = "_";

/// A record that cannot be read for this long was abandoned mid-write.
const ABANDONED_RECORD: Duration = Duration::from_secs(10);

pub(crate) struct FileLockStore {
    /// The content root as configured (possibly relative, pre-symlink).
    configured_root: PathBuf,
    /// The content root with symlinks resolved: the form resolved request
    /// paths take once a resource already exists on disk.
    content_root: PathBuf,
    lock_root: PathBuf,
}

impl FileLockStore {
    pub(crate) fn new(configured_root: PathBuf, content_root: PathBuf, lock_root: PathBuf) -> Self {
        Self {
            configured_root,
            content_root,
            lock_root,
        }
    }

    /// Grants a lock, or returns `None` if it conflicts with another.
    pub(crate) fn lock(
        &self,
        resource: &Path,
        scope: LockScope,
        ty: LockType,
        depth: i32,
        owner: String,
        timeout_seconds: i64,
    ) -> Option<WebDavLock> {
        let relative = self.relative(resource);
        let lock = WebDavLock::new(
            self.resolve(&relative),
            scope,
            ty,
            depth,
            owner,
            timeout_seconds,
        );
        let dir = self.record_directory(&relative);
        let record = if scope == LockScope::Exclusive {
            if fs::create_dir_all(&dir).is_err() {
                return None;
            }
            dir.join(EXCLUSIVE)
        } else {
            let shared_dir = dir.join(SHARED);
            if fs::create_dir_all(&shared_dir).is_err() {
                return None;
            }
            shared_dir.join(token_file_name(lock.token()))
        };
        if !self.create_record(&record, &lock, &relative) {
            return None;
        }
        if self.conflicts(&relative, scope, &record) {
            let _ = fs::remove_file(&record);
            return None;
        }
        Some(lock)
    }

    /// Removes the lock with this token that covers `resource`.
    pub(crate) fn unlock(&self, resource: &Path, token: &str) -> bool {
        let relative = self.relative(resource);
        match self.find(&relative, token) {
            Some((record, lock)) if !lock.is_expired() => fs::remove_file(&record).is_ok(),
            _ => false,
        }
    }

    /// Extends the lock with this token, or returns `None` if there is no
    /// live lock of that token covering `resource`.
    pub(crate) fn refresh(
        &self,
        resource: &Path,
        token: &str,
        timeout_seconds: i64,
    ) -> Option<WebDavLock> {
        let relative = self.relative(resource);
        let (record, mut lock) = self.find(&relative, token)?;
        if lock.is_expired() {
            return None;
        }
        lock.refresh(timeout_seconds);
        let temp = record.with_file_name(format!(
            "{TEMP_PREFIX}{}",
            token_file_name(&new_temp_suffix())
        ));
        if write_record(&temp, &lock, &relative).is_err() {
            let _ = fs::remove_file(&temp);
            return None;
        }
        if fs::rename(&temp, &record).is_err() {
            let _ = fs::remove_file(&temp);
            return None;
        }
        Some(lock)
    }

    /// Returns the live lock with this token covering `resource`, or `None`.
    pub(crate) fn get_lock(&self, resource: &Path, token: &str) -> Option<WebDavLock> {
        let relative = self.relative(resource);
        let (_, lock) = self.find(&relative, token)?;
        if lock.is_expired() {
            None
        } else {
            Some(lock)
        }
    }

    /// Returns the live locks placed on `resource` itself.
    pub(crate) fn get_locks_at(&self, resource: &Path) -> Vec<WebDavLock> {
        let relative = self.relative(resource);
        let resolved = self.resolve(&relative);
        self.get_covering_locks(resource)
            .into_iter()
            .filter(|l| l.path() == resolved)
            .collect()
    }

    /// Returns the live locks that cover `resource`.
    pub(crate) fn get_covering_locks(&self, resource: &Path) -> Vec<WebDavLock> {
        let relative = self.relative(resource);
        let mut result = Vec::new();
        for ancestor in self.ancestors(&relative) {
            for record in self.records(&self.record_directory(&ancestor)) {
                if let Some(lock) = self.read_record(&record) {
                    if !lock.is_expired() && lock.covers(&self.resolve(&relative)) {
                        result.push(lock);
                    }
                }
            }
        }
        result
    }

    // -- Records --

    /// Creates `record` for `lock`; false if it is already held by a live
    /// lock. An expired or abandoned record is replaced.
    fn create_record(&self, record: &Path, lock: &WebDavLock, relative: &Path) -> bool {
        for _ in 0..3 {
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(record)
            {
                Ok(mut f) => {
                    return write_lock(&mut f, lock, relative).is_ok();
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    match self.read_record(record) {
                        Some(existing) if !existing.is_expired() => return false,
                        Some(_) => {
                            let _ = fs::remove_file(record);
                        }
                        None => {
                            if record.exists() {
                                if abandoned(record) {
                                    let _ = fs::remove_file(record);
                                } else {
                                    // Another handler is still writing it.
                                    return false;
                                }
                            } else {
                                // Removed since the create attempt started.
                                continue;
                            }
                        }
                    }
                }
                Err(_) => return false,
            }
        }
        false
    }

    fn conflicts(&self, relative: &Path, scope: LockScope, own: &Path) -> bool {
        let resolved = self.resolve(relative);
        for ancestor in self.ancestors(relative) {
            for record in self.records(&self.record_directory(&ancestor)) {
                if record == own {
                    continue;
                }
                match self.read_record(&record) {
                    Some(existing) => {
                        if existing.is_expired() {
                            let _ = fs::remove_file(&record);
                            continue;
                        }
                        if existing.covers(&resolved) && clash(existing.scope(), scope) {
                            return true;
                        }
                    }
                    None => {
                        if !record.exists() {
                            continue; // removed since it was listed
                        }
                        if abandoned(&record) {
                            let _ = fs::remove_file(&record);
                            continue;
                        }
                        return true;
                    }
                }
            }
        }
        self.descendant_conflict(relative, scope, own)
    }

    /// Whether any lock below `relative` would clash with a lock on it.
    fn descendant_conflict(&self, relative: &Path, scope: LockScope, own: &Path) -> bool {
        let base = self.record_directory(relative);
        if !base.is_dir() {
            return false;
        }
        let mut found = false;
        walk_files(&base, &mut |file| {
            if found {
                return;
            }
            if !is_record_name(&file) || file == own || is_at_or_below_own(&file, &base) {
                return;
            }
            match self.read_record(&file) {
                Some(existing) => {
                    if existing.is_expired() {
                        let _ = fs::remove_file(&file);
                    } else if clash(existing.scope(), scope) {
                        found = true;
                    }
                }
                None => {
                    if !file.exists() {
                        // another handler removed it (a refused grant rolling back)
                    } else if abandoned(&file) {
                        let _ = fs::remove_file(&file);
                    } else {
                        found = true;
                    }
                }
            }
        });
        found
    }

    /// Finds the record of the lock with this token that covers `relative`.
    fn find(&self, relative: &Path, token: &str) -> Option<(PathBuf, WebDavLock)> {
        let name = token_file_name(token);
        for ancestor in self.ancestors(relative) {
            let dir = self.record_directory(&ancestor);
            let shared = dir.join(SHARED).join(&name);
            if let Some(lock) = self.read_record(&shared) {
                if lock.token() == token && lock.covers(&self.resolve(relative)) {
                    return Some((shared, lock));
                }
            }
            let exclusive = dir.join(EXCLUSIVE);
            if let Some(lock) = self.read_record(&exclusive) {
                if lock.token() == token && lock.covers(&self.resolve(relative)) {
                    return Some((exclusive, lock));
                }
            }
        }
        None
    }

    /// The records (exclusive and shared) of one resource.
    fn records(&self, dir: &Path) -> Vec<PathBuf> {
        let mut result = Vec::new();
        let exclusive = dir.join(EXCLUSIVE);
        if exclusive.is_file() {
            result.push(exclusive);
        }
        let shared = dir.join(SHARED);
        if shared.is_dir() {
            if let Ok(entries) = fs::read_dir(&shared) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if !name.starts_with(TEMP_PREFIX) {
                        result.push(entry.path());
                    }
                }
            }
        }
        result
    }

    // -- Keys --

    /// `relative` and each of its ancestors up to the content root, nearest
    /// first (including `relative` itself).
    fn ancestors(&self, relative: &Path) -> Vec<PathBuf> {
        let mut result = Vec::new();
        let mut current = Some(relative.to_path_buf());
        while let Some(cur) = current {
            let is_root = cur.as_os_str().is_empty();
            result.push(cur.clone());
            if is_root {
                break;
            }
            current = cur.parent().map(|p| p.to_path_buf());
        }
        result
    }

    fn record_directory(&self, relative: &Path) -> PathBuf {
        let mut dir = self.lock_root.clone();
        for component in relative.components() {
            let name = component.as_os_str().to_string_lossy();
            if !name.is_empty() {
                dir.push(format!("{COMPONENT_PREFIX}{name}"));
            }
        }
        dir
    }

    /// `resource`'s path relative to the content root, whether given as
    /// already-resolved (under [`Self::content_root`]) or as the
    /// pre-resolution form under [`Self::configured_root`] (a resource that
    /// does not exist yet takes this form — see
    /// [`crate::path::canonicalize_path`]).
    fn relative(&self, resource: &Path) -> PathBuf {
        if let Ok(rel) = resource.strip_prefix(&self.content_root) {
            return rel.to_path_buf();
        }
        if let Ok(rel) = resource.strip_prefix(&self.configured_root) {
            return rel.to_path_buf();
        }
        // Not under either root: nothing sensible to key this by, but a
        // caller only reaches here through paths this handler resolved
        // itself, so fall back to the given path rather than panicking.
        resource.to_path_buf()
    }

    fn resolve(&self, relative: &Path) -> PathBuf {
        if relative.as_os_str().is_empty() {
            self.content_root.clone()
        } else {
            self.content_root.join(relative)
        }
    }

    fn read_record(&self, record: &Path) -> Option<WebDavLock> {
        let data = fs::read_to_string(record).ok()?;
        parse_record(&data, self)
    }
}

fn clash(existing: LockScope, requested: LockScope) -> bool {
    existing == LockScope::Exclusive || requested == LockScope::Exclusive
}

/// Whether `file` is one of the records of the resource whose record
/// directory is `base` (as opposed to a genuine descendant's record).
fn is_at_or_below_own(file: &Path, base: &Path) -> bool {
    let Some(parent) = file.parent() else {
        return false;
    };
    if parent == base {
        return true;
    }
    let Some(grand) = parent.parent() else {
        return false;
    };
    grand == base && parent.file_name().map(|n| n == SHARED).unwrap_or(false)
}

fn is_record_name(file: &Path) -> bool {
    let Some(name) = file.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if name.starts_with(TEMP_PREFIX) {
        return false;
    }
    if name == EXCLUSIVE {
        return true;
    }
    file.parent()
        .and_then(|p| p.file_name())
        .map(|n| n == SHARED)
        .unwrap_or(false)
}

fn abandoned(record: &Path) -> bool {
    match fs::metadata(record).and_then(|m| m.modified()) {
        Ok(modified) => SystemTime::now()
            .duration_since(modified)
            .map(|age| age > ABANDONED_RECORD)
            .unwrap_or(false),
        Err(_) => true,
    }
}

/// Recursively visits every file under `dir`, depth-first; tolerant of
/// entries removed by another handler mid-walk.
fn walk_files(dir: &Path, visit: &mut impl FnMut(PathBuf)) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        match entry.file_type() {
            Ok(ty) if ty.is_dir() => walk_files(&path, visit),
            Ok(ty) if ty.is_file() => visit(path),
            _ => {}
        }
    }
}

fn token_file_name(token: &str) -> String {
    let name = token.rsplit(':').next().unwrap_or(token);
    name.replace('/', "_").replace('\\', "_")
}

fn new_temp_suffix() -> String {
    let mut bytes = [0u8; 8];
    let _ = getrandom::getrandom(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// -- Serialisation --
//
// A record is a small `key=value` text file; the only field that can carry
// arbitrary client-supplied text (the lock owner, from the request body) is
// escaped so an embedded newline cannot inject another field.

fn write_lock(f: &mut fs::File, lock: &WebDavLock, relative: &Path) -> io::Result<()> {
    let body = record_body(lock, relative);
    f.write_all(body.as_bytes())
}

fn write_record(path: &Path, lock: &WebDavLock, relative: &Path) -> io::Result<()> {
    fs::write(path, record_body(lock, relative))
}

fn record_body(lock: &WebDavLock, relative: &Path) -> String {
    let expires = match lock.expires_at_millis() {
        Some(ms) => ms.to_string(),
        None => "-1".to_string(),
    };
    format!(
        "token={}\npath={}\nscope={}\ntype={}\ndepth={}\nowner={}\ncreated={}\nexpires={}\n",
        lock.token(),
        escape(&relative_string(relative)),
        lock.scope().as_str(),
        lock.lock_type().as_str(),
        lock.depth(),
        escape(lock.owner()),
        lock.created_at_millis(),
        expires,
    )
}

fn relative_string(relative: &Path) -> String {
    relative
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\n', "\\n")
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('\\') => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn parse_record(data: &str, store: &FileLockStore) -> Option<WebDavLock> {
    let mut token = None;
    let mut path = None;
    let mut scope = None;
    let mut ty = None;
    let mut depth = None;
    let mut owner = None;
    let mut created = None;
    let mut expires = None;
    for line in data.lines() {
        let (key, value) = line.split_once('=')?;
        match key {
            "token" => token = Some(value.to_string()),
            "path" => path = Some(unescape(value)),
            "scope" => scope = LockScope::parse(value),
            "type" => ty = LockType::parse(value),
            "depth" => depth = value.parse::<i32>().ok(),
            "owner" => owner = Some(unescape(value)),
            "created" => created = value.parse::<i64>().ok(),
            "expires" => expires = value.parse::<i64>().ok(),
            _ => {}
        }
    }
    let relative = PathBuf::from(path?);
    let resolved = store.resolve(&relative);
    let expires_at = match expires? {
        -1 => None,
        ms => Some(UNIX_EPOCH + Duration::from_millis(ms.max(0) as u64)),
    };
    let created_at = UNIX_EPOCH + Duration::from_millis(created?.max(0) as u64);
    Some(WebDavLock::from_record(
        token?,
        resolved,
        scope?,
        ty?,
        depth?,
        owner.unwrap_or_default(),
        created_at,
        expires_at,
    ))
}

/// Issue #415: with a lock root, locks are files keyed by each resource's
/// path relative to the content root, so handlers that share the lock root
/// agree about them wherever they mount the content tree — exercised here
/// through the public [`WebDavLockManager`] API, exactly as
/// `crate::factory::WebDavFactory` wires it up.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{DEPTH_0, DEPTH_INFINITY};
    use crate::lock::WebDavLockManager;
    use std::sync::Arc;
    use std::thread;

    const WRITE: LockType = LockType::Write;
    const EXCLUSIVE: LockScope = LockScope::Exclusive;
    const SHARED: LockScope = LockScope::Shared;

    /// One logical tree, mounted at two different absolute paths (as two
    /// pods sharing a content volume would), plus a common lock root.
    struct TwoPods {
        _base: tempfile::TempDir,
        content_a: PathBuf,
        content_b: PathBuf,
        lock_root: PathBuf,
        pod_a: WebDavLockManager,
        pod_b: WebDavLockManager,
    }

    fn two_pods() -> TwoPods {
        let base = tempfile::tempdir().unwrap();
        let content_a = base.path().join("podA/data");
        let content_b = base.path().join("podB/mnt/data");
        let lock_root = base.path().join("locks");
        fs::create_dir_all(&content_a).unwrap();
        fs::create_dir_all(&content_b).unwrap();
        fs::create_dir_all(&lock_root).unwrap();
        let pod_a = WebDavLockManager::with_lock_root(content_a.clone(), content_a.clone(), lock_root.clone());
        let pod_b = WebDavLockManager::with_lock_root(content_b.clone(), content_b.clone(), lock_root.clone());
        TwoPods {
            _base: base,
            content_a,
            content_b,
            lock_root,
            pod_a,
            pod_b,
        }
    }

    fn in_a(pods: &TwoPods, relative: &str) -> PathBuf {
        pods.content_a.join(relative)
    }

    fn in_b(pods: &TwoPods, relative: &str) -> PathBuf {
        pods.content_b.join(relative)
    }

    fn file_count(dir: &Path) -> usize {
        fn walk(dir: &Path, count: &mut usize) {
            let Ok(entries) = fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    walk(&entry.path(), count);
                } else {
                    *count += 1;
                }
            }
        }
        let mut count = 0;
        walk(dir, &mut count);
        count
    }

    #[test]
    fn with_no_lock_root_locks_stay_in_memory_and_write_nothing() {
        let pods = two_pods();
        let memory = WebDavLockManager::new();
        assert!(memory
            .lock(in_a(&pods, "doc.txt"), EXCLUSIVE, WRITE, DEPTH_0, "me".into(), 3600)
            .is_some());
        assert_eq!(file_count(&pods.lock_root), 0);
        // another in-memory manager knows nothing of it
        assert!(WebDavLockManager::new()
            .lock(in_a(&pods, "doc.txt"), EXCLUSIVE, WRITE, DEPTH_0, "you".into(), 3600)
            .is_some());
    }

    #[test]
    fn second_exclusive_lock_on_same_relative_path_is_refused_across_pods() {
        let pods = two_pods();
        assert!(pods
            .pod_a
            .lock(in_a(&pods, "docs/a.txt"), EXCLUSIVE, WRITE, DEPTH_0, "a".into(), 3600)
            .is_some());
        assert!(pods
            .pod_b
            .lock(in_b(&pods, "docs/a.txt"), EXCLUSIVE, WRITE, DEPTH_0, "b".into(), 3600)
            .is_none());
        assert!(
            pods.pod_b
                .lock(in_b(&pods, "docs/a.txt"), SHARED, WRITE, DEPTH_0, "b".into(), 3600)
                .is_none(),
            "a shared lock also conflicts with an exclusive one"
        );
    }

    #[test]
    fn shared_locks_coexist_and_block_an_exclusive_one() {
        let pods = two_pods();
        assert!(pods
            .pod_a
            .lock(in_a(&pods, "a.txt"), SHARED, WRITE, DEPTH_0, "a".into(), 3600)
            .is_some());
        assert!(pods
            .pod_b
            .lock(in_b(&pods, "a.txt"), SHARED, WRITE, DEPTH_0, "b".into(), 3600)
            .is_some());
        assert!(pods
            .pod_b
            .lock(in_b(&pods, "a.txt"), EXCLUSIVE, WRITE, DEPTH_0, "b".into(), 3600)
            .is_none());
        assert_eq!(pods.pod_a.get_covering_locks(&in_a(&pods, "a.txt")).len(), 2);
    }

    #[test]
    fn parent_infinity_lock_conflicts_with_a_child_lock_on_another_pod() {
        let pods = two_pods();
        assert!(pods
            .pod_a
            .lock(in_a(&pods, "docs"), EXCLUSIVE, WRITE, DEPTH_INFINITY, "a".into(), 3600)
            .is_some());
        assert!(pods
            .pod_b
            .lock(in_b(&pods, "docs/sub/child.txt"), EXCLUSIVE, WRITE, DEPTH_0, "b".into(), 3600)
            .is_none());
        assert!(
            pods.pod_b
                .lock(in_b(&pods, "other/child.txt"), EXCLUSIVE, WRITE, DEPTH_0, "b".into(), 3600)
                .is_some(),
            "an unrelated path is unaffected"
        );
    }

    #[test]
    fn unlock_on_one_pod_makes_the_path_lockable_on_the_other() {
        let pods = two_pods();
        let lock = pods
            .pod_a
            .lock(in_a(&pods, "a.txt"), EXCLUSIVE, WRITE, DEPTH_0, "a".into(), 3600)
            .unwrap();
        assert!(pods.pod_a.unlock(&in_a(&pods, "a.txt"), lock.token()));
        assert!(pods
            .pod_b
            .lock(in_b(&pods, "a.txt"), EXCLUSIVE, WRITE, DEPTH_0, "b".into(), 3600)
            .is_some());
    }

    #[test]
    fn another_pod_can_unlock_and_validate_a_token_it_did_not_issue() {
        let pods = two_pods();
        let lock = pods
            .pod_a
            .lock(in_a(&pods, "docs/a.txt"), EXCLUSIVE, WRITE, DEPTH_0, "a".into(), 3600)
            .unwrap();
        assert!(pods.pod_b.validate_token(&in_b(&pods, "docs/a.txt"), lock.token()));
        assert!(!pods.pod_b.validate_token(&in_b(&pods, "docs/other.txt"), lock.token()));
        assert!(
            !pods.pod_b.unlock(&in_b(&pods, "docs/a.txt"), "opaquelocktoken:unknown"),
            "an unknown token unlocks nothing"
        );
        assert!(pods.pod_b.unlock(&in_b(&pods, "docs/a.txt"), lock.token()));
        assert!(!pods.pod_a.validate_token(&in_a(&pods, "docs/a.txt"), lock.token()));
    }

    #[test]
    fn a_token_of_a_depth_infinity_lock_unlocks_through_a_descendant() {
        let pods = two_pods();
        let lock = pods
            .pod_a
            .lock(in_a(&pods, "docs"), EXCLUSIVE, WRITE, DEPTH_INFINITY, "a".into(), 3600)
            .unwrap();
        assert!(pods
            .pod_b
            .validate_token(&in_b(&pods, "docs/sub/x.txt"), lock.token()));
        assert!(pods.pod_b.unlock(&in_b(&pods, "docs/sub/x.txt"), lock.token()));
        assert!(pods.pod_a.get_covering_locks(&in_a(&pods, "docs")).is_empty());
    }

    #[test]
    fn refresh_on_one_pod_is_seen_by_the_other() {
        let pods = two_pods();
        let lock = pods
            .pod_a
            .lock(in_a(&pods, "a.txt"), EXCLUSIVE, WRITE, DEPTH_0, "a".into(), 60)
            .unwrap();
        let refreshed = pods
            .pod_b
            .refresh(&in_b(&pods, "a.txt"), lock.token(), 7200)
            .unwrap();
        assert!(refreshed.remaining_timeout_seconds() > 3600);
        let seen = pods.pod_a.get_lock(&in_a(&pods, "a.txt"), lock.token()).unwrap();
        assert!(seen.remaining_timeout_seconds() > 3600);
        assert!(pods
            .pod_a
            .refresh(&in_a(&pods, "a.txt"), "opaquelocktoken:unknown", 60)
            .is_none());
    }

    #[test]
    fn an_expired_record_does_not_block_a_new_grant() {
        let pods = two_pods();
        let lock = pods
            .pod_a
            .lock(in_a(&pods, "a.txt"), EXCLUSIVE, WRITE, DEPTH_0, "a".into(), 0)
            .unwrap();
        while !lock.is_expired() {
            thread::yield_now();
        }
        assert!(pods.pod_b.get_covering_locks(&in_b(&pods, "a.txt")).is_empty());
        assert!(pods
            .pod_b
            .lock(in_b(&pods, "a.txt"), EXCLUSIVE, WRITE, DEPTH_0, "b".into(), 3600)
            .is_some());
    }

    #[test]
    fn records_are_keyed_by_relative_path() {
        let pods = two_pods();
        pods.pod_a
            .lock(in_a(&pods, "docs/a.txt"), EXCLUSIVE, WRITE, DEPTH_0, "a".into(), 3600)
            .unwrap();
        assert!(pods
            .lock_root
            .join("_docs")
            .join("_a.txt")
            .join("exclusive")
            .is_file());
    }

    #[test]
    fn refused_grant_leaves_no_record_behind() {
        let pods = two_pods();
        assert!(pods
            .pod_a
            .lock(in_a(&pods, "a.txt"), EXCLUSIVE, WRITE, DEPTH_0, "a".into(), 3600)
            .is_some());
        assert!(pods
            .pod_b
            .lock(in_b(&pods, "a.txt"), EXCLUSIVE, WRITE, DEPTH_0, "b".into(), 3600)
            .is_none());
        assert_eq!(file_count(&pods.lock_root), 1);
    }

    #[test]
    fn concurrent_exclusive_grants_leave_one_winner() {
        for round in 0..30 {
            let pods = Arc::new(two_pods());
            let name = format!("race{round}.txt");
            let (p1, n1) = (Arc::clone(&pods), name.clone());
            let t1 = thread::spawn(move || {
                p1.pod_a
                    .lock(in_a(&p1, &n1), EXCLUSIVE, WRITE, DEPTH_0, "a".into(), 3600)
            });
            let (p2, n2) = (Arc::clone(&pods), name.clone());
            let t2 = thread::spawn(move || {
                p2.pod_b
                    .lock(in_b(&p2, &n2), EXCLUSIVE, WRITE, DEPTH_0, "b".into(), 3600)
            });
            let got_a = t1.join().unwrap();
            let got_b = t2.join().unwrap();
            let winners = got_a.is_some() as u32 + got_b.is_some() as u32;
            assert_eq!(winners, 1, "round {round}");
        }
    }
}
