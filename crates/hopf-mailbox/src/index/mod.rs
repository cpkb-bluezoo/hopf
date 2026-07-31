// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Message search index (`.gidx`).

mod builder;
mod entry;
mod gidx;

pub use builder::IndexBuilder;
pub use entry::IndexEntry;
pub use gidx::{IndexFile, INDEX_MAGIC, INDEX_VERSION_BODY, INDEX_VERSION_HEADERS};

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use crate::config::IndexConfig;
use crate::error::{MailboxError, MailboxResult};
use crate::flag::Flag;
use crate::search::{MessageContext, SearchCriteria};

/// In-memory search index for one mailbox session.
#[derive(Debug)]
pub struct MessageIndex {
    path: PathBuf,
    config: IndexConfig,
    uid_validity: u64,
    uid_next: u64,
    /// UID → entry
    entries: BTreeMap<u64, IndexEntry>,
    dirty: bool,
}

impl MessageIndex {
    /// Create an empty index.
    pub fn new(
        path: impl Into<PathBuf>,
        uid_validity: u64,
        uid_next: u64,
        config: IndexConfig,
    ) -> Self {
        Self {
            path: path.into(),
            config,
            uid_validity,
            uid_next,
            entries: BTreeMap::new(),
            dirty: true,
        }
    }

    /// Load from disk, or `None` if missing.
    pub fn load(path: impl AsRef<Path>, config: IndexConfig) -> MailboxResult<Option<Self>> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(None);
        }
        let file = IndexFile::load(path)?;
        let mut entries = BTreeMap::new();
        for e in file.entries {
            entries.insert(e.uid, e);
        }
        Ok(Some(Self {
            path: path.to_path_buf(),
            config,
            uid_validity: file.uid_validity,
            uid_next: file.uid_next,
            entries,
            dirty: false,
        }))
    }

    /// Persist if dirty.
    pub fn save(&mut self) -> MailboxResult<()> {
        if !self.dirty {
            return Ok(());
        }
        let version = if self.config.body_indexing {
            INDEX_VERSION_BODY
        } else {
            INDEX_VERSION_HEADERS
        };
        let file = IndexFile {
            version,
            uid_validity: self.uid_validity,
            uid_next: self.uid_next,
            entries: self.entries.values().cloned().collect(),
            body_indexing: self.config.body_indexing,
        };
        file.save(&self.path)?;
        self.dirty = false;
        Ok(())
    }

    /// Path to `.gidx`.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Index config.
    pub fn config(&self) -> &IndexConfig {
        &self.config
    }

    /// UIDVALIDITY.
    pub fn uid_validity(&self) -> u64 {
        self.uid_validity
    }

    /// UIDNEXT.
    pub fn uid_next(&self) -> u64 {
        self.uid_next
    }

    /// Set UIDNEXT.
    pub fn set_uid_next(&mut self, n: u64) {
        self.uid_next = n;
        self.dirty = true;
    }

    /// Entry count.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Insert / replace entry.
    pub fn put(&mut self, entry: IndexEntry) {
        self.entries.insert(entry.uid, entry);
        self.dirty = true;
    }

    /// Remove by UID.
    pub fn remove(&mut self, uid: u64) {
        if self.entries.remove(&uid).is_some() {
            self.dirty = true;
        }
    }

    /// Get entry.
    pub fn get(&self, uid: u64) -> Option<&IndexEntry> {
        self.entries.get(&uid)
    }

    /// All entries in UID order.
    pub fn entries(&self) -> impl Iterator<Item = &IndexEntry> {
        self.entries.values()
    }

    /// Update flags on an entry.
    pub fn set_flags(&mut self, uid: u64, flags: &std::collections::BTreeSet<Flag>) {
        if let Some(e) = self.entries.get_mut(&uid) {
            e.set_flags(flags);
            self.dirty = true;
        }
    }

    /// Update keywords on an entry.
    pub fn set_keywords(&mut self, uid: u64, keywords: &std::collections::BTreeSet<String>) {
        if let Some(e) = self.entries.get_mut(&uid) {
            e.set_keywords(keywords);
            self.dirty = true;
        }
    }

    /// Search using index; for BODY/TEXT without body index, `body_loader`
    /// streams a case-insensitive substring check for a given uid + needle
    /// (already lowercased) rather than materializing the body — see
    /// [`crate::search::body_contains_streaming`] for backends implementing
    /// it as a real stream.
    pub fn search<F>(&self, criteria: &SearchCriteria, body_loader: F) -> MailboxResult<Vec<u32>>
    where
        F: Fn(u64, &str) -> MailboxResult<bool>,
    {
        let need_body = criteria.needs_body() && !self.config.body_indexing;
        let mut out = Vec::new();
        for e in self.entries.values() {
            let ctx = IndexedContext {
                entry: e,
                need_body,
                body_loader: &body_loader,
            };
            if criteria.matches(&ctx).map_err(MailboxError::Io)? {
                out.push(e.message_number);
            }
        }
        out.sort_unstable();
        Ok(out)
    }
}

struct IndexedContext<'a> {
    entry: &'a IndexEntry,
    need_body: bool,
    body_loader: &'a dyn Fn(u64, &str) -> MailboxResult<bool>,
}

impl MessageContext for IndexedContext<'_> {
    fn message_number(&self) -> u32 {
        self.entry.message_number
    }
    fn uid(&self) -> u64 {
        self.entry.uid
    }
    fn size(&self) -> u64 {
        self.entry.size
    }
    fn flags(&self) -> std::collections::BTreeSet<Flag> {
        self.entry.flags()
    }
    fn keywords(&self) -> std::collections::BTreeSet<String> {
        self.entry.keywords_set()
    }
    fn internal_date_millis(&self) -> Option<i64> {
        if self.entry.internal_date == 0 {
            None
        } else {
            Some(self.entry.internal_date)
        }
    }
    fn sent_date_millis(&self) -> Option<i64> {
        if self.entry.sent_date == 0 {
            None
        } else {
            Some(self.entry.sent_date)
        }
    }
    fn header(&self, name: &str) -> io::Result<String> {
        Ok(self.entry.header_value(name).unwrap_or("").to_string())
    }
    fn body_contains(&self, needle_lower: &str) -> io::Result<bool> {
        if self.need_body {
            return (self.body_loader)(self.entry.uid, needle_lower)
                .map_err(|e| io::Error::other(e.to_string()));
        }
        Ok(self
            .entry
            .body()
            .unwrap_or("")
            .to_ascii_lowercase()
            .contains(needle_lower))
    }
}
