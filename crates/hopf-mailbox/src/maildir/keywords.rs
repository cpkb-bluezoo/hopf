// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! `.keywords` sidecar (max 26).

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use crate::error::{MailboxError, MailboxResult};

const HEADER: &str = "# gumdrop-keywords v1";

/// Keyword registry: index 0..25 ↔ letter a..z.
#[derive(Debug, Default)]
pub struct KeywordsFile {
    path: PathBuf,
    /// index → keyword
    by_index: BTreeMap<u8, String>,
    dirty: bool,
}

impl KeywordsFile {
    pub fn path_in(dir: &Path) -> PathBuf {
        dir.join(".keywords")
    }

    pub fn load_or_empty(dir: &Path) -> MailboxResult<Self> {
        let path = Self::path_in(dir);
        let mut by_index = BTreeMap::new();
        if path.exists() {
            for line in BufReader::new(File::open(&path)?).lines() {
                let line = line?;
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let mut parts = line.splitn(2, char::is_whitespace);
                let idx: u8 = parts
                    .next()
                    .unwrap_or("")
                    .parse()
                    .map_err(|_| MailboxError::Corrupt("keywords index".into()))?;
                let name = parts.next().unwrap_or("").trim().to_string();
                if idx < 26 && !name.is_empty() {
                    by_index.insert(idx, name);
                }
            }
        }
        Ok(Self {
            path,
            by_index,
            dirty: false,
        })
    }

    /// Allocate or reuse a letter (`a`–`z`) for `keyword`.
    pub fn letter_for(&mut self, keyword: &str) -> MailboxResult<char> {
        for (i, name) in &self.by_index {
            if name.eq_ignore_ascii_case(keyword) {
                return Ok(char::from(b'a' + i));
            }
        }
        if self.by_index.len() >= 26 {
            return Err(MailboxError::Invalid("too many keywords".into()));
        }
        let mut idx = 0u8;
        while self.by_index.contains_key(&idx) {
            idx += 1;
        }
        self.by_index.insert(idx, keyword.to_string());
        self.dirty = true;
        Ok(char::from(b'a' + idx))
    }

    pub fn keyword_for_letter(&self, c: char) -> Option<&str> {
        if !c.is_ascii_lowercase() {
            return None;
        }
        let idx = (c as u8) - b'a';
        self.by_index.get(&idx).map(|s| s.as_str())
    }

    pub fn save(&mut self) -> MailboxResult<()> {
        if !self.dirty {
            return Ok(());
        }
        let tmp = self.path.with_file_name(".keywords.tmp");
        {
            let mut f = File::create(&tmp)?;
            writeln!(f, "{HEADER}")?;
            for (i, name) in &self.by_index {
                writeln!(f, "{i} {name}")?;
            }
            f.sync_all()?;
        }
        fs::rename(&tmp, &self.path)?;
        self.dirty = false;
        Ok(())
    }
}
