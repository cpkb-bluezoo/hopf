// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Maildir++ store.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::config::IndexConfig;
use crate::error::{MailboxError, MailboxResult};
use crate::name_codec::MailboxNameCodec;
use crate::traits::{
    Mailbox, MailboxAttribute, MailboxFactory, MailboxInfo, MailboxStore,
};

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
            if !name.starts_with('.') || name == ".subscriptions" || name == ".uidlist"
                || name == ".keywords" || name == ".gidx"
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
