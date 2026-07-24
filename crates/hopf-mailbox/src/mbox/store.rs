// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! mbox store (single INBOX per user).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::config::IndexConfig;
use crate::error::{MailboxError, MailboxResult};
use crate::traits::{
    Mailbox, MailboxAttribute, MailboxFactory, MailboxInfo, MailboxStore,
};

use super::mailbox::MboxMailbox;

/// Factory for mbox stores rooted at a directory (`{root}/{user}` file or dir).
#[derive(Clone, Debug)]
pub struct MboxFactory {
    root: PathBuf,
    index_config: IndexConfig,
}

impl MboxFactory {
    /// `{root}/{username}` is the mbox file (created on open if missing).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            index_config: IndexConfig::default(),
        }
    }

    /// Set index configuration (body indexing off by default).
    pub fn with_index_config(mut self, config: IndexConfig) -> Self {
        self.index_config = config;
        self
    }
}

impl MailboxFactory for MboxFactory {
    fn create_store(&self) -> Box<dyn MailboxStore> {
        Box::new(MboxStore {
            root: self.root.clone(),
            index_config: self.index_config.clone(),
            user_path: None,
        })
    }
}

/// One-user mbox store — only `INBOX`.
pub struct MboxStore {
    root: PathBuf,
    index_config: IndexConfig,
    user_path: Option<PathBuf>,
}

impl MboxStore {
    fn inbox_path(&self) -> MailboxResult<&Path> {
        self.user_path
            .as_deref()
            .ok_or_else(|| MailboxError::Invalid("store not open".into()))
    }
}

impl MailboxStore for MboxStore {
    fn open(&mut self, username: &str) -> MailboxResult<()> {
        if username.is_empty() || username.contains("..") || username.contains('/') {
            return Err(MailboxError::Invalid("bad username".into()));
        }
        let path = self.root.join(username);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        self.user_path = Some(path);
        Ok(())
    }

    fn close(&mut self) -> MailboxResult<()> {
        self.user_path = None;
        Ok(())
    }

    fn hierarchy_delimiter(&self) -> char {
        '/'
    }

    fn list(&self, _reference: &str, pattern: &str) -> MailboxResult<Vec<MailboxInfo>> {
        let _ = self.inbox_path()?;
        if pattern_matches(pattern, "INBOX") {
            let mut attrs = BTreeSet::new();
            attrs.insert(MailboxAttribute::NoInferiors);
            attrs.insert(MailboxAttribute::HasNoChildren);
            Ok(vec![MailboxInfo {
                name: "INBOX".into(),
                attributes: attrs,
            }])
        } else {
            Ok(vec![])
        }
    }

    fn create_mailbox(&mut self, _name: &str) -> MailboxResult<()> {
        Err(MailboxError::Unsupported("CREATE on mbox store"))
    }

    fn delete_mailbox(&mut self, _name: &str) -> MailboxResult<()> {
        Err(MailboxError::Unsupported("DELETE on mbox store"))
    }

    fn rename_mailbox(&mut self, _old: &str, _new: &str) -> MailboxResult<()> {
        Err(MailboxError::Unsupported("RENAME on mbox store"))
    }

    fn subscribe(&mut self, _name: &str) -> MailboxResult<()> {
        Ok(())
    }

    fn unsubscribe(&mut self, _name: &str) -> MailboxResult<()> {
        Ok(())
    }

    fn open_mailbox(&mut self, name: &str, read_only: bool) -> MailboxResult<Box<dyn Mailbox>> {
        if !name.eq_ignore_ascii_case("INBOX") {
            return Err(MailboxError::NotFound(name.into()));
        }
        let path = self.inbox_path()?.to_path_buf();
        Ok(Box::new(MboxMailbox::open(
            path,
            "INBOX",
            read_only,
            self.index_config.clone(),
        )?))
    }
}

fn pattern_matches(pattern: &str, name: &str) -> bool {
    if pattern == "*" || pattern == "%" || pattern.eq_ignore_ascii_case("INBOX") {
        return name.eq_ignore_ascii_case("INBOX");
    }
    pattern.eq_ignore_ascii_case(name)
}
