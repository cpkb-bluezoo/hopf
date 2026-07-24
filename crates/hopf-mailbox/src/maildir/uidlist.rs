// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! `.uidlist` sidecar.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use crate::error::{MailboxError, MailboxResult};

const HEADER: &str = "# gumdrop-uidlist v1";

/// Maps base filename → UID.
#[derive(Debug)]
pub struct UidList {
    path: PathBuf,
    pub uid_validity: u64,
    pub uid_next: u64,
    /// base → uid
    map: BTreeMap<String, u64>,
    dirty: bool,
}

impl UidList {
    pub fn path_in(dir: &Path) -> PathBuf {
        dir.join(".uidlist")
    }

    pub fn load_or_new(dir: &Path, default_uv: u64) -> MailboxResult<Self> {
        let path = Self::path_in(dir);
        if !path.exists() {
            return Ok(Self {
                path,
                uid_validity: default_uv,
                uid_next: 1,
                map: BTreeMap::new(),
                dirty: true,
            });
        }
        let f = File::open(&path)?;
        let mut uid_validity = default_uv;
        let mut uid_next = 1u64;
        let mut map = BTreeMap::new();
        for line in BufReader::new(f).lines() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(rest) = line.strip_prefix("uidvalidity ") {
                uid_validity = rest.trim().parse().map_err(|_| {
                    MailboxError::Corrupt("uidlist uidvalidity".into())
                })?;
            } else if let Some(rest) = line.strip_prefix("uidnext ") {
                uid_next = rest
                    .trim()
                    .parse()
                    .map_err(|_| MailboxError::Corrupt("uidlist uidnext".into()))?;
            } else {
                let mut parts = line.splitn(2, char::is_whitespace);
                let uid: u64 = parts
                    .next()
                    .unwrap_or("")
                    .parse()
                    .map_err(|_| MailboxError::Corrupt("uidlist entry".into()))?;
                let base = parts.next().unwrap_or("").trim().to_string();
                if !base.is_empty() {
                    map.insert(base, uid);
                }
            }
        }
        Ok(Self {
            path,
            uid_validity,
            uid_next,
            map,
            dirty: false,
        })
    }

    #[allow(dead_code)]
    pub fn get(&self, base: &str) -> Option<u64> {
        self.map.get(base).copied()
    }

    pub fn assign(&mut self, base: &str) -> u64 {
        if let Some(u) = self.map.get(base) {
            return *u;
        }
        let u = self.uid_next;
        self.uid_next += 1;
        self.map.insert(base.to_string(), u);
        self.dirty = true;
        u
    }

    pub fn remove_base(&mut self, base: &str) {
        if self.map.remove(base).is_some() {
            self.dirty = true;
        }
    }

    pub fn save(&mut self) -> MailboxResult<()> {
        if !self.dirty {
            return Ok(());
        }
        let tmp = self.path.with_file_name(".uidlist.tmp");
        {
            let mut f = File::create(&tmp)?;
            writeln!(f, "{HEADER}")?;
            writeln!(f, "uidvalidity {}", self.uid_validity)?;
            writeln!(f, "uidnext {}", self.uid_next)?;
            let mut by_uid: Vec<_> = self.map.iter().collect();
            by_uid.sort_by_key(|(_, u)| *u);
            for (base, uid) in by_uid {
                writeln!(f, "{uid} {base}")?;
            }
            f.sync_all()?;
        }
        fs::rename(&tmp, &self.path)?;
        self.dirty = false;
        Ok(())
    }
}
