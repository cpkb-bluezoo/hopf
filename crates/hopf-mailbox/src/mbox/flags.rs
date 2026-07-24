// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! mbox `.flags` sidecar.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use crate::error::{MailboxError, MailboxResult};
use crate::flag::Flag;

const HEADER: &str = "# hopf-mbox-flags v1";

/// Flags keyed by stable content id (MD5 hex of RFC 822 bytes).
#[derive(Debug, Default)]
pub struct MboxFlagsFile {
    path: PathBuf,
    uid_validity: u64,
    /// unique_id → (system flags, keywords)
    map: BTreeMap<String, (BTreeSet<Flag>, BTreeSet<String>)>,
    dirty: bool,
}

impl MboxFlagsFile {
    /// Path next to the mbox: `{mbox}.flags`.
    pub fn path_for_mbox(mbox: &Path) -> PathBuf {
        let mut s = mbox.as_os_str().to_os_string();
        s.push(".flags");
        PathBuf::from(s)
    }

    /// Load or create empty.
    pub fn load_or_empty(path: impl Into<PathBuf>, uid_validity: u64) -> MailboxResult<Self> {
        let path = path.into();
        if !path.exists() {
            return Ok(Self {
                path,
                uid_validity,
                map: BTreeMap::new(),
                dirty: false,
            });
        }
        let f = File::open(&path)?;
        let reader = BufReader::new(f);
        let mut map = BTreeMap::new();
        let mut uv = uid_validity;
        for (i, line) in reader.lines().enumerate() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                if i == 0 && line.starts_with("# ") {
                    continue;
                }
                continue;
            }
            if let Some(rest) = line.strip_prefix("uidvalidity ") {
                uv = rest
                    .trim()
                    .parse()
                    .map_err(|_| MailboxError::Corrupt("flags uidvalidity".into()))?;
                continue;
            }
            let mut parts = line.splitn(2, char::is_whitespace);
            let id = parts
                .next()
                .ok_or_else(|| MailboxError::Corrupt("flags line".into()))?
                .to_string();
            let rest = parts.next().unwrap_or("").trim();
            let mut flags = BTreeSet::new();
            let mut keywords = BTreeSet::new();
            if !rest.is_empty() {
                for tok in rest.split(',') {
                    let tok = tok.trim();
                    if tok.is_empty() {
                        continue;
                    }
                    if let Some(f) = Flag::parse(tok) {
                        if f != Flag::Recent {
                            flags.insert(f);
                        }
                    } else {
                        keywords.insert(tok.to_string());
                    }
                }
            }
            map.insert(id, (flags, keywords));
        }
        Ok(Self {
            path,
            uid_validity: uv,
            map,
            dirty: false,
        })
    }

    /// UIDVALIDITY recorded in file.
    pub fn uid_validity(&self) -> u64 {
        self.uid_validity
    }

    /// Get flags + keywords for unique id.
    pub fn get(&self, unique_id: &str) -> (BTreeSet<Flag>, BTreeSet<String>) {
        self.map
            .get(unique_id)
            .cloned()
            .unwrap_or_else(|| (BTreeSet::new(), BTreeSet::new()))
    }

    /// Set flags (merges keywords unless `keywords` provided).
    pub fn set(
        &mut self,
        unique_id: &str,
        flags: BTreeSet<Flag>,
        keywords: BTreeSet<String>,
    ) {
        let mut flags = flags;
        flags.remove(&Flag::Recent);
        self.map.insert(unique_id.to_string(), (flags, keywords));
        self.dirty = true;
    }

    /// Remove entry.
    pub fn remove(&mut self, unique_id: &str) {
        if self.map.remove(unique_id).is_some() {
            self.dirty = true;
        }
    }

    /// Persist atomically.
    pub fn save(&mut self) -> MailboxResult<()> {
        if !self.dirty {
            return Ok(());
        }
        let tmp = self.path.with_file_name(format!(
            "{}.tmp",
            self.path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("mbox.flags")
        ));
        {
            let mut f = File::create(&tmp)?;
            writeln!(f, "{HEADER}")?;
            writeln!(f, "uidvalidity {}", self.uid_validity)?;
            for (id, (flags, keywords)) in &self.map {
                let mut parts: Vec<String> = flags.iter().map(|f| f.name().to_string()).collect();
                parts.extend(keywords.iter().cloned());
                if parts.is_empty() {
                    writeln!(f, "{id}")?;
                } else {
                    writeln!(f, "{id} {}", parts.join(","))?;
                }
            }
            f.sync_all()?;
        }
        fs::rename(&tmp, &self.path)?;
        self.dirty = false;
        Ok(())
    }
}
