// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Maildir++ store.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::config::IndexConfig;
use crate::error::{MailboxError, MailboxResult};
use crate::name_codec::MailboxNameCodec;
use crate::traits::{Mailbox, MailboxAttribute, MailboxFactory, MailboxInfo, MailboxStore};

use super::mailbox::{ensure_maildir_layout, resolve_mailbox_dir, MaildirMailbox, MaildirPaths};

/// Factory for Maildir++ stores under `{root}/{user}/`.
#[derive(Clone, Debug)]
pub struct MaildirFactory {
    root: PathBuf,
    index_config: IndexConfig,
}

impl MaildirFactory {
    /// Create factory.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            index_config: IndexConfig::default(),
        }
    }

    /// Index configuration (body indexing off by default).
    pub fn with_index_config(mut self, config: IndexConfig) -> Self {
        self.index_config = config;
        self
    }
}

impl MailboxFactory for MaildirFactory {
    fn create_store(&self) -> Box<dyn MailboxStore> {
        Box::new(MaildirStore {
            root: self.root.clone(),
            index_config: self.index_config.clone(),
            user_root: None,
            paths: None,
            open_lock: Arc::new(Mutex::new(())),
        })
    }
}

/// Per-session Maildir++ store.
pub struct MaildirStore {
    root: PathBuf,
    index_config: IndexConfig,
    user_root: Option<PathBuf>,
    paths: Option<Arc<MaildirPaths>>,
    open_lock: Arc<Mutex<()>>,
}

impl MaildirStore {
    fn user_root(&self) -> MailboxResult<&Path> {
        self.user_root
            .as_deref()
            .ok_or_else(|| MailboxError::Invalid("store not open".into()))
    }

    fn subscriptions_path(&self) -> MailboxResult<PathBuf> {
        Ok(self.user_root()?.join(".subscriptions"))
    }

    fn load_subscriptions(&self) -> MailboxResult<BTreeSet<String>> {
        let path = self.subscriptions_path()?;
        let mut set = BTreeSet::new();
        if path.exists() {
            for line in fs::read_to_string(&path)?.lines() {
                let line = line.trim();
                if !line.is_empty() && !line.starts_with('#') {
                    set.insert(line.to_string());
                }
            }
        }
        Ok(set)
    }

    fn save_subscriptions(&self, set: &BTreeSet<String>) -> MailboxResult<()> {
        let path = self.subscriptions_path()?;
        let mut body = String::from("# hopf-subscriptions v1\n");
        for s in set {
            body.push_str(s);
            body.push('\n');
        }
        fs::write(path, body)?;
        Ok(())
    }

    /// RFC 5464 METADATA storage root for `mailbox` — `.metadata/` under
    /// the mailbox's own directory (so it moves with RENAME, same as
    /// `.uidlist`), or `.server-metadata/` under the user root for server
    /// annotations (`mailbox == ""`, the RFC's own convention for "the
    /// server itself"). This can't just be `.metadata` under the user
    /// root: `resolve_mailbox_dir` resolves INBOX to the user root itself
    /// (Maildir++ convention), so INBOX's own `.metadata` would otherwise
    /// collide with the server-level store, silently merging the two
    /// namespaces.
    fn metadata_base_dir(&self, mailbox: &str) -> MailboxResult<PathBuf> {
        let root = self.user_root()?;
        if mailbox.is_empty() {
            Ok(root.join(".server-metadata"))
        } else {
            Ok(resolve_mailbox_dir(root, mailbox)?.join(".metadata"))
        }
    }
}

/// Validate and resolve a METADATA `entry` path (e.g. `/private/comment`)
/// to a file under `base` — entries nest via `/`, exactly like a
/// filesystem path, so a leaf entry's value and a deeper entry sharing its
/// prefix can't coexist (the prefix would need to be both a file and a
/// directory); this implementation accepts that as the cost of needing no
/// separate index.
fn metadata_entry_path(base: &Path, entry: &str) -> MailboxResult<PathBuf> {
    let trimmed = entry.strip_prefix('/').unwrap_or(entry);
    if trimmed.is_empty()
        || trimmed
            .split('/')
            .any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        return Err(MailboxError::Invalid(format!(
            "invalid metadata entry {entry}"
        )));
    }
    Ok(base.join(trimmed))
}

/// Collect value-bearing entries strictly beneath `dir` (already resolved
/// from the queried entry), as full `/`-rooted entry strings relative to
/// `base`, stopping recursion once `depth` would exceed `max_depth`
/// (`None` = unbounded — GETMETADATA `DEPTH infinity`).
fn walk_metadata_dir(
    base: &Path,
    dir: &Path,
    max_depth: Option<u32>,
    depth: u32,
    out: &mut Vec<String>,
) -> MailboxResult<()> {
    for ent in fs::read_dir(dir)? {
        let ent = ent?;
        let path = ent.path();
        if path.is_file() {
            let rel = path.strip_prefix(base).unwrap_or(&path);
            let entry = rel.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
            out.push(format!("/{entry}"));
        } else if path.is_dir() && max_depth.is_none_or(|m| depth < m) {
            walk_metadata_dir(base, &path, max_depth, depth + 1, out)?;
        }
    }
    Ok(())
}

impl MailboxStore for MaildirStore {
    fn open(&mut self, username: &str) -> MailboxResult<()> {
        if username.is_empty() || username.contains("..") || username.contains('/') {
            return Err(MailboxError::Invalid("bad username".into()));
        }
        let user_root = self.root.join(username);
        ensure_maildir_layout(&user_root)?;
        self.paths = Some(Arc::new(MaildirPaths {
            user_root: user_root.clone(),
        }));
        self.user_root = Some(user_root);
        Ok(())
    }

    fn close(&mut self) -> MailboxResult<()> {
        self.user_root = None;
        self.paths = None;
        Ok(())
    }

    fn hierarchy_delimiter(&self) -> char {
        '/'
    }

    fn list(&self, _reference: &str, pattern: &str) -> MailboxResult<Vec<MailboxInfo>> {
        let root = self.user_root()?;
        let mut out = Vec::new();
        // INBOX
        if glob_match(pattern, "INBOX") {
            let mut attrs = BTreeSet::new();
            attrs.insert(MailboxAttribute::HasNoChildren);
            out.push(MailboxInfo {
                name: "INBOX".into(),
                attributes: attrs,
            });
        }
        for ent in fs::read_dir(root)? {
            let ent = ent?;
            let name = ent.file_name().to_string_lossy().into_owned();
            if !name.starts_with('.')
                || name == ".subscriptions"
                || name == ".uidlist"
                || name == ".keywords"
                || name == ".gidx"
                || name == ".metadata"
                || name == ".server-metadata"
            {
                continue;
            }
            if !ent.path().join("cur").is_dir() {
                continue;
            }
            let imap = maildir_dir_to_imap(&name);
            if glob_match(pattern, &imap) {
                let mut attrs = BTreeSet::new();
                attrs.insert(MailboxAttribute::HasNoChildren);
                out.push(MailboxInfo {
                    name: imap,
                    attributes: attrs,
                });
            }
        }
        Ok(out)
    }

    fn list_subscribed(&self, reference: &str, pattern: &str) -> MailboxResult<Vec<MailboxInfo>> {
        let all = self.list(reference, pattern)?;
        let subs = self.load_subscriptions()?;
        Ok(all
            .into_iter()
            .filter(|info| subs.iter().any(|s| s.eq_ignore_ascii_case(&info.name)))
            .collect())
    }

    fn create_mailbox(&mut self, name: &str) -> MailboxResult<()> {
        let root = self.user_root()?;
        if name.eq_ignore_ascii_case("INBOX") {
            return Err(MailboxError::Invalid("cannot create INBOX".into()));
        }
        let dir = resolve_mailbox_dir(root, name)?;
        if dir.exists() {
            return Err(MailboxError::Invalid("mailbox exists".into()));
        }
        ensure_maildir_layout(&dir)?;
        Ok(())
    }

    fn delete_mailbox(&mut self, name: &str) -> MailboxResult<()> {
        let root = self.user_root()?;
        if name.eq_ignore_ascii_case("INBOX") {
            return Err(MailboxError::Invalid("cannot delete INBOX".into()));
        }
        let dir = resolve_mailbox_dir(root, name)?;
        if !dir.exists() {
            return Err(MailboxError::NotFound(name.into()));
        }
        fs::remove_dir_all(dir)?;
        let mut subs = self.load_subscriptions()?;
        subs.remove(name);
        self.save_subscriptions(&subs)?;
        Ok(())
    }

    fn rename_mailbox(&mut self, old: &str, new: &str) -> MailboxResult<()> {
        let root = self.user_root()?;
        if old.eq_ignore_ascii_case("INBOX") || new.eq_ignore_ascii_case("INBOX") {
            return Err(MailboxError::Invalid("cannot rename INBOX".into()));
        }
        let src = resolve_mailbox_dir(root, old)?;
        let dst = resolve_mailbox_dir(root, new)?;
        if !src.exists() {
            return Err(MailboxError::NotFound(old.into()));
        }
        if dst.exists() {
            return Err(MailboxError::Invalid("destination exists".into()));
        }
        fs::rename(src, dst)?;
        let mut subs = self.load_subscriptions()?;
        if subs.remove(old) {
            subs.insert(new.to_string());
            self.save_subscriptions(&subs)?;
        }
        Ok(())
    }

    fn subscribe(&mut self, name: &str) -> MailboxResult<()> {
        let mut subs = self.load_subscriptions()?;
        subs.insert(name.to_string());
        self.save_subscriptions(&subs)
    }

    fn unsubscribe(&mut self, name: &str) -> MailboxResult<()> {
        let mut subs = self.load_subscriptions()?;
        subs.remove(name);
        self.save_subscriptions(&subs)
    }

    fn get_metadata_entry(&self, mailbox: &str, entry: &str) -> MailboxResult<Option<String>> {
        let base = self.metadata_base_dir(mailbox)?;
        let path = metadata_entry_path(&base, entry)?;
        if !path.is_file() {
            return Ok(None);
        }
        // Lossy: annotation values are treated as text throughout this
        // implementation (like header/body content elsewhere in this
        // crate), not preserved as arbitrary binary octets.
        Ok(Some(String::from_utf8_lossy(&fs::read(&path)?).into_owned()))
    }

    fn set_metadata_entry(
        &mut self,
        mailbox: &str,
        entry: &str,
        value: Option<&str>,
    ) -> MailboxResult<()> {
        if !mailbox.is_empty() {
            let root = self.user_root()?;
            let dir = resolve_mailbox_dir(root, mailbox)?;
            if !dir.join("cur").is_dir() {
                return Err(MailboxError::NotFound(mailbox.into()));
            }
        }
        let base = self.metadata_base_dir(mailbox)?;
        let path = metadata_entry_path(&base, entry)?;
        match value {
            None => {
                match fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
                // Best-effort cleanup of now-empty intermediate directories
                // an entry like `/private/vendor/x` created for its
                // hierarchy — never removes `base` itself.
                let mut dir = path.parent();
                while let Some(d) = dir {
                    if d == base || fs::remove_dir(d).is_err() {
                        break;
                    }
                    dir = d.parent();
                }
            }
            Some(v) => {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&path, v.as_bytes())?;
            }
        }
        Ok(())
    }

    fn list_metadata_children(
        &self,
        mailbox: &str,
        entry: &str,
        max_depth: Option<u32>,
    ) -> MailboxResult<Vec<String>> {
        if max_depth == Some(0) {
            return Ok(Vec::new());
        }
        let base = self.metadata_base_dir(mailbox)?;
        let path = metadata_entry_path(&base, entry)?;
        if !path.is_dir() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        walk_metadata_dir(&base, &path, max_depth, 1, &mut out)?;
        Ok(out)
    }

    fn open_mailbox(&mut self, name: &str, read_only: bool) -> MailboxResult<Box<dyn Mailbox>> {
        let root = self.user_root()?;
        let paths = self
            .paths
            .clone()
            .ok_or_else(|| MailboxError::Invalid("store not open".into()))?;
        let dir = resolve_mailbox_dir(root, name)?;
        if !dir.exists() && name.eq_ignore_ascii_case("INBOX") {
            ensure_maildir_layout(&dir)?;
        }
        if !dir.join("cur").is_dir() {
            return Err(MailboxError::NotFound(name.into()));
        }
        let mb = MaildirMailbox::open(
            dir,
            if name.eq_ignore_ascii_case("INBOX") {
                "INBOX".into()
            } else {
                name.to_string()
            },
            read_only,
            paths,
            self.index_config.clone(),
            Some(Arc::clone(&self.open_lock)),
        )?;
        Ok(Box::new(mb))
    }
}

fn maildir_dir_to_imap(dot_name: &str) -> String {
    let rest = dot_name.trim_start_matches('.');
    rest.split('.')
        .map(MailboxNameCodec::decode)
        .collect::<Vec<_>>()
        .join("/")
}

fn glob_match(pattern: &str, name: &str) -> bool {
    if pattern == "*" || pattern == "%" {
        return true;
    }
    if pattern.eq_ignore_ascii_case(name) {
        return true;
    }
    // simple * suffix
    if let Some(prefix) = pattern.strip_suffix('*') {
        return name.starts_with(prefix);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn list_subscribed_filters_by_subscriptions_file() {
        let dir = tempdir().unwrap();
        let factory = MaildirFactory::new(dir.path());
        let mut store = factory.create_store();
        store.open("subuser").unwrap();
        store.create_mailbox("Archive").unwrap();
        store.create_mailbox("Sent").unwrap();

        let listed = store.list("", "*").unwrap();
        assert!(listed.iter().any(|m| m.name == "INBOX"));
        assert!(listed.iter().any(|m| m.name == "Archive"));
        assert!(listed.iter().any(|m| m.name == "Sent"));

        assert!(store.list_subscribed("", "*").unwrap().is_empty());

        store.subscribe("Archive").unwrap();
        store.subscribe("INBOX").unwrap();
        let sub = store.list_subscribed("", "*").unwrap();
        let names: BTreeSet<_> = sub.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, BTreeSet::from(["Archive", "INBOX"]));
        assert!(!names.contains("Sent"));
    }

    #[test]
    fn mailbox_metadata_set_get_and_delete() {
        let dir = tempdir().unwrap();
        let factory = MaildirFactory::new(dir.path());
        let mut store = factory.create_store();
        store.open("metadatauser").unwrap();
        store.create_mailbox("Archive").unwrap();

        assert_eq!(
            store.get_metadata_entry("Archive", "/private/comment").unwrap(),
            None
        );
        store
            .set_metadata_entry("Archive", "/private/comment", Some("hello"))
            .unwrap();
        assert_eq!(
            store.get_metadata_entry("Archive", "/private/comment").unwrap(),
            Some("hello".to_string())
        );
        store
            .set_metadata_entry("Archive", "/private/comment", None)
            .unwrap();
        assert_eq!(
            store.get_metadata_entry("Archive", "/private/comment").unwrap(),
            None
        );
    }

    #[test]
    fn server_metadata_uses_empty_mailbox_name_and_is_separate_from_mailbox_metadata() {
        let dir = tempdir().unwrap();
        let factory = MaildirFactory::new(dir.path());
        let mut store = factory.create_store();
        store.open("servermetadatauser").unwrap();
        store.create_mailbox("Archive").unwrap();

        store
            .set_metadata_entry("", "/private/comment", Some("server-level"))
            .unwrap();
        store
            .set_metadata_entry("Archive", "/private/comment", Some("mailbox-level"))
            .unwrap();
        assert_eq!(
            store.get_metadata_entry("", "/private/comment").unwrap(),
            Some("server-level".to_string())
        );
        assert_eq!(
            store.get_metadata_entry("Archive", "/private/comment").unwrap(),
            Some("mailbox-level".to_string())
        );
    }

    #[test]
    fn server_metadata_does_not_collide_with_inbox_metadata() {
        // INBOX's mailbox directory *is* the user root (Maildir++
        // convention — see `resolve_mailbox_dir`), so server-level
        // annotations must live somewhere INBOX's own `.metadata` can
        // never reach, or the two namespaces silently merge.
        let dir = tempdir().unwrap();
        let factory = MaildirFactory::new(dir.path());
        let mut store = factory.create_store();
        store.open("inboxmetadatauser").unwrap();
        // INBOX must exist as an open-able mailbox before SETMETADATA
        // will accept it (mirrors the nonexistent-mailbox rejection test).
        store.open_mailbox("INBOX", false).unwrap().close(false).unwrap();

        store
            .set_metadata_entry("", "/private/comment", Some("server-wide"))
            .unwrap();
        store
            .set_metadata_entry("INBOX", "/private/comment", Some("inbox-only"))
            .unwrap();
        assert_eq!(
            store.get_metadata_entry("", "/private/comment").unwrap(),
            Some("server-wide".to_string()),
            "server-level value must be unaffected by INBOX's own SETMETADATA"
        );
        assert_eq!(
            store.get_metadata_entry("INBOX", "/private/comment").unwrap(),
            Some("inbox-only".to_string()),
            "INBOX's value must be unaffected by the server-level SETMETADATA"
        );
    }

    #[test]
    fn metadata_directories_are_not_listed_as_mailboxes() {
        let dir = tempdir().unwrap();
        let factory = MaildirFactory::new(dir.path());
        let mut store = factory.create_store();
        store.open("listmetadatauser").unwrap();
        store.open_mailbox("INBOX", false).unwrap().close(false).unwrap();
        store
            .set_metadata_entry("", "/private/comment", Some("x"))
            .unwrap();
        store
            .set_metadata_entry("INBOX", "/private/comment", Some("y"))
            .unwrap();

        let names: BTreeSet<_> = store
            .list("", "*")
            .unwrap()
            .into_iter()
            .map(|m| m.name)
            .collect();
        assert_eq!(names, BTreeSet::from(["INBOX".to_string()]));
    }

    #[test]
    fn setting_metadata_on_a_nonexistent_mailbox_is_an_error() {
        let dir = tempdir().unwrap();
        let factory = MaildirFactory::new(dir.path());
        let mut store = factory.create_store();
        store.open("nometadatauser").unwrap();
        assert!(store
            .set_metadata_entry("NoSuchBox", "/private/comment", Some("x"))
            .is_err());
    }

    #[test]
    fn metadata_entry_rejects_path_traversal() {
        let dir = tempdir().unwrap();
        let factory = MaildirFactory::new(dir.path());
        let mut store = factory.create_store();
        store.open("traversaluser").unwrap();
        assert!(store
            .set_metadata_entry("", "/private/../../etc/passwd", Some("x"))
            .is_err());
    }

    #[test]
    fn list_metadata_children_respects_depth() {
        let dir = tempdir().unwrap();
        let factory = MaildirFactory::new(dir.path());
        let mut store = factory.create_store();
        store.open("depthuser").unwrap();
        store
            .set_metadata_entry("", "/private/vendor/a", Some("1"))
            .unwrap();
        store
            .set_metadata_entry("", "/private/vendor/nested/b", Some("2"))
            .unwrap();

        let depth1 = store
            .list_metadata_children("", "/private/vendor", Some(1))
            .unwrap();
        assert_eq!(depth1, vec!["/private/vendor/a".to_string()]);

        let mut depth_inf = store
            .list_metadata_children("", "/private/vendor", None)
            .unwrap();
        depth_inf.sort();
        assert_eq!(
            depth_inf,
            vec![
                "/private/vendor/a".to_string(),
                "/private/vendor/nested/b".to_string(),
            ]
        );

        let depth0 = store
            .list_metadata_children("", "/private/vendor", Some(0))
            .unwrap();
        assert!(depth0.is_empty());
    }
}
