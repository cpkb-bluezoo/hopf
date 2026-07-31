// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! mbox `.flags` sidecar.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use crate::error::{MailboxError, MailboxResult};
use crate::flag::Flag;

const HEADER: &str = "# hopf-mbox-flags v2";

/// Flags (+ CONDSTORE mod-sequence) keyed by stable content id (SHA-256
/// hex of RFC 822 bytes).
#[derive(Debug, Default)]
pub struct MboxFlagsFile {
    path: PathBuf,
    uid_validity: u64,
    /// RFC 7162 HIGHESTMODSEQ — monotonic, never decreases. 0 means no
    /// CONDSTORE data yet (no flag/keyword change or append recorded
    /// since this field was added).
    pub highest_modseq: u64,
    /// unique_id → (system flags, keywords, modseq)
    map: BTreeMap<String, (BTreeSet<Flag>, BTreeSet<String>, u64)>,
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
                highest_modseq: 0,
                map: BTreeMap::new(),
                dirty: false,
            });
        }
        let f = File::open(&path)?;
        let reader = BufReader::new(f);
        let mut map = BTreeMap::new();
        let mut uv = uid_validity;
        let mut highest_modseq = 0u64;
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
            if let Some(rest) = line.strip_prefix("highestmodseq ") {
                highest_modseq = rest
                    .trim()
                    .parse()
                    .map_err(|_| MailboxError::Corrupt("flags highestmodseq".into()))?;
                continue;
            }
            let mut parts = line.splitn(2, char::is_whitespace);
            let id = parts
                .next()
                .ok_or_else(|| MailboxError::Corrupt("flags line".into()))?
                .to_string();
            let rest = parts.next().unwrap_or("").trim();
            let (modseq, csv) = parse_modseq_and_rest(rest);
            let mut flags = BTreeSet::new();
            let mut keywords = BTreeSet::new();
            if !csv.is_empty() {
                for tok in csv.split(',') {
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
            map.insert(id, (flags, keywords, modseq));
        }
        Ok(Self {
            path,
            uid_validity: uv,
            highest_modseq,
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
            .map(|(f, k, _)| (f.clone(), k.clone()))
            .unwrap_or_else(|| (BTreeSet::new(), BTreeSet::new()))
    }

    /// Mod-sequence for `unique_id` (0 if never recorded — matches
    /// [`crate::traits::Mailbox::modseq`]'s "0 = unsupported/unset"
    /// convention).
    pub fn modseq_for(&self, unique_id: &str) -> u64 {
        self.map.get(unique_id).map(|(_, _, ms)| *ms).unwrap_or(0)
    }

    /// Set flags (replaces keywords) and bump the mod-sequence. Called
    /// both for a brand-new message becoming visible (`end_append`) and
    /// for an actual flag/keyword change (`set_flags` et al.) — both are
    /// genuine CONDSTORE-visible changes, so an unconditional bump is
    /// correct in both cases; unlike `.uidlist`'s `assign`, this is never
    /// called during a mailbox *scan* of already-tracked messages, so
    /// there's no idempotency concern to guard against here.
    pub fn set(&mut self, unique_id: &str, flags: BTreeSet<Flag>, keywords: BTreeSet<String>) {
        let mut flags = flags;
        flags.remove(&Flag::Recent);
        self.highest_modseq += 1;
        let ms = self.highest_modseq;
        self.map.insert(unique_id.to_string(), (flags, keywords, ms));
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
            writeln!(f, "highestmodseq {}", self.highest_modseq)?;
            for (id, (flags, keywords, modseq)) in &self.map {
                let mut parts: Vec<String> = flags.iter().map(|f| f.name().to_string()).collect();
                parts.extend(keywords.iter().cloned());
                if parts.is_empty() {
                    writeln!(f, "{id} {modseq}")?;
                } else {
                    writeln!(f, "{id} {modseq} {}", parts.join(","))?;
                }
            }
            f.sync_all()?;
        }
        fs::rename(&tmp, &self.path)?;
        self.dirty = false;
        Ok(())
    }
}

/// Splits a v2 `"<modseq> <csv>"` entry tail into its parts, tolerating v1
/// files (`"<csv>"` only, no modseq token — falls back to modseq 0) the
/// same way `maildir::uidlist::parse_modseq_and_base` does. The one
/// accepted ambiguity: a v1 entry whose *only* keyword happens to be all
/// ASCII digits would be misparsed as a bare v2 modseq with no
/// flags/keywords — astronomically unlikely for a real IMAP keyword.
fn parse_modseq_and_rest(rest: &str) -> (u64, &str) {
    let mut it = rest.splitn(2, char::is_whitespace);
    let first = it.next().unwrap_or("");
    let Ok(ms) = first.parse::<u64>() else {
        return (0, rest);
    };
    match it.next() {
        Some(remainder) => (ms, remainder.trim()),
        None => (ms, ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_bumps_highest_modseq_and_records_it_per_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mbox.flags");
        let mut f = MboxFlagsFile::load_or_empty(&path, 1).unwrap();
        assert_eq!(f.highest_modseq, 0);

        let mut seen = BTreeSet::new();
        seen.insert(Flag::Seen);
        f.set("id1", seen.clone(), BTreeSet::new());
        assert_eq!(f.highest_modseq, 1);
        assert_eq!(f.modseq_for("id1"), 1);

        f.set("id2", BTreeSet::new(), BTreeSet::new());
        assert_eq!(f.highest_modseq, 2);
        assert_eq!(f.modseq_for("id2"), 2);
        assert_eq!(f.modseq_for("id1"), 1, "unrelated entry untouched");
    }

    #[test]
    fn unknown_id_has_modseq_zero() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mbox.flags");
        let f = MboxFlagsFile::load_or_empty(&path, 1).unwrap();
        assert_eq!(f.modseq_for("nope"), 0);
    }

    #[test]
    fn save_and_reload_round_trips_modseq_and_flags() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mbox.flags");
        {
            let mut f = MboxFlagsFile::load_or_empty(&path, 7).unwrap();
            let mut seen = BTreeSet::new();
            seen.insert(Flag::Seen);
            let mut kw = BTreeSet::new();
            kw.insert("custom".to_string());
            f.set("id1", seen, kw);
            f.set("id2", BTreeSet::new(), BTreeSet::new());
            f.save().unwrap();
        }
        let f2 = MboxFlagsFile::load_or_empty(&path, 0).unwrap();
        assert_eq!(f2.uid_validity(), 7);
        assert_eq!(f2.highest_modseq, 2);
        assert_eq!(f2.modseq_for("id1"), 1);
        assert_eq!(f2.modseq_for("id2"), 2);
        let (flags, kw) = f2.get("id1");
        assert!(flags.contains(&Flag::Seen));
        assert!(kw.contains("custom"));
    }

    #[test]
    fn loading_a_v1_file_with_no_modseq_column_defaults_to_zero() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mbox.flags");
        std::fs::write(
            &path,
            "# hopf-mbox-flags v1\nuidvalidity 3\nabc123 Seen,Flagged\ndef456\n",
        )
        .unwrap();
        let f = MboxFlagsFile::load_or_empty(&path, 0).unwrap();
        assert_eq!(f.uid_validity(), 3);
        assert_eq!(f.highest_modseq, 0);
        assert_eq!(f.modseq_for("abc123"), 0);
        let (flags, _) = f.get("abc123");
        assert!(flags.contains(&Flag::Seen));
        assert!(flags.contains(&Flag::Flagged));
    }
}
