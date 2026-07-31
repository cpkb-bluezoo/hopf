// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! `.uidlist` sidecar.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use crate::error::{MailboxError, MailboxResult};

const HEADER: &str = "# gumdrop-uidlist v2";

/// Maps base filename → (UID, CONDSTORE mod-sequence).
#[derive(Debug)]
pub struct UidList {
    path: PathBuf,
    pub uid_validity: u64,
    pub uid_next: u64,
    /// RFC 7162 HIGHESTMODSEQ — a monotonic counter that never decreases,
    /// even across expunges of messages that held higher values than
    /// whatever survives. 0 means "no CONDSTORE data yet" (e.g. a mailbox
    /// with no flag/keyword change or append since this field was added).
    pub highest_modseq: u64,
    /// base → (uid, modseq)
    map: BTreeMap<String, (u64, u64)>,
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
                highest_modseq: 0,
                map: BTreeMap::new(),
                dirty: true,
            });
        }
        let f = File::open(&path)?;
        let mut uid_validity = default_uv;
        let mut uid_next = 1u64;
        let mut highest_modseq = 0u64;
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
            } else if let Some(rest) = line.strip_prefix("highestmodseq ") {
                highest_modseq = rest
                    .trim()
                    .parse()
                    .map_err(|_| MailboxError::Corrupt("uidlist highestmodseq".into()))?;
            } else {
                let mut parts = line.splitn(2, char::is_whitespace);
                let uid: u64 = parts
                    .next()
                    .unwrap_or("")
                    .parse()
                    .map_err(|_| MailboxError::Corrupt("uidlist entry".into()))?;
                let rest = parts.next().unwrap_or("").trim();
                let (modseq, base) = parse_modseq_and_base(rest);
                if !base.is_empty() {
                    map.insert(base, (uid, modseq));
                }
            }
        }
        Ok(Self {
            path,
            uid_validity,
            uid_next,
            highest_modseq,
            map,
            dirty: false,
        })
    }

    #[allow(dead_code)]
    pub fn get(&self, base: &str) -> Option<u64> {
        self.map.get(base).map(|(uid, _)| *uid)
    }

    /// Mod-sequence for a tracked base (0 if this uidlist has never seen
    /// `base` — matches [`crate::traits::Mailbox::modseq`]'s "0 =
    /// unsupported/unset" convention).
    pub fn modseq_for(&self, base: &str) -> u64 {
        self.map.get(base).map(|(_, ms)| *ms).unwrap_or(0)
    }

    /// Assign (or return the existing) UID for `base`. A genuinely new
    /// base also gets a fresh mod-sequence — RFC 7162 §3.6 requires a
    /// message's mod-sequence to be assigned no later than when it
    /// becomes visible to the client, so a newly-appended (or
    /// newly-discovered-on-scan) message counts as a change too.
    pub fn assign(&mut self, base: &str) -> u64 {
        if let Some((u, _)) = self.map.get(base) {
            return *u;
        }
        let u = self.uid_next;
        self.uid_next += 1;
        self.highest_modseq += 1;
        let ms = self.highest_modseq;
        self.map.insert(base.to_string(), (u, ms));
        self.dirty = true;
        u
    }

    /// Bump `base`'s mod-sequence to a new, strictly higher value (a
    /// flag/keyword change) and advance [`Self::highest_modseq`] to
    /// match. Returns the new value, or 0 if `base` isn't tracked (a
    /// no-op — nothing to bump).
    pub fn bump_modseq(&mut self, base: &str) -> u64 {
        let Some(entry) = self.map.get_mut(base) else {
            return 0;
        };
        self.highest_modseq += 1;
        entry.1 = self.highest_modseq;
        self.dirty = true;
        self.highest_modseq
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
            writeln!(f, "highestmodseq {}", self.highest_modseq)?;
            let mut by_uid: Vec<_> = self.map.iter().collect();
            by_uid.sort_by_key(|(_, (u, _))| *u);
            for (base, (uid, modseq)) in by_uid {
                writeln!(f, "{uid} {modseq} {base}")?;
            }
            f.sync_all()?;
        }
        fs::rename(&tmp, &self.path)?;
        self.dirty = false;
        Ok(())
    }
}

/// Splits a v2 `"<modseq> <base>"` entry tail into its parts. Tolerates v1
/// files (`"<base>"` only, no modseq token) by falling back to modseq 0 —
/// `base` names always contain a `.` (see `MaildirFilename::generate`), so
/// they never parse as a bare `u64`, letting the two formats be told apart
/// without a version bump gate.
fn parse_modseq_and_base(rest: &str) -> (u64, String) {
    let mut it = rest.splitn(2, char::is_whitespace);
    let first = it.next().unwrap_or("");
    if let (Ok(ms), Some(base)) = (first.parse::<u64>(), it.next()) {
        (ms, base.trim().to_string())
    } else {
        (0, rest.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assign_gives_fresh_uid_and_modseq_for_a_new_base() {
        let dir = tempfile::tempdir().unwrap();
        let mut ul = UidList::load_or_new(dir.path(), 1).unwrap();
        assert_eq!(ul.highest_modseq, 0);
        let uid = ul.assign("base1");
        assert_eq!(uid, 1);
        assert_eq!(ul.highest_modseq, 1);
        assert_eq!(ul.modseq_for("base1"), 1);
    }

    #[test]
    fn assign_is_idempotent_and_does_not_rebump_modseq() {
        let dir = tempfile::tempdir().unwrap();
        let mut ul = UidList::load_or_new(dir.path(), 1).unwrap();
        let uid1 = ul.assign("base1");
        let ms1 = ul.modseq_for("base1");
        let uid2 = ul.assign("base1");
        assert_eq!(uid1, uid2);
        assert_eq!(ul.modseq_for("base1"), ms1);
        assert_eq!(ul.highest_modseq, 1, "second assign must not bump again");
    }

    #[test]
    fn bump_modseq_advances_highest_and_the_entry_together() {
        let dir = tempfile::tempdir().unwrap();
        let mut ul = UidList::load_or_new(dir.path(), 1).unwrap();
        ul.assign("base1");
        ul.assign("base2");
        assert_eq!(ul.highest_modseq, 2);
        let new_ms = ul.bump_modseq("base1");
        assert_eq!(new_ms, 3);
        assert_eq!(ul.modseq_for("base1"), 3);
        assert_eq!(ul.modseq_for("base2"), 2, "unrelated entry untouched");
        assert_eq!(ul.highest_modseq, 3);
    }

    #[test]
    fn bump_modseq_on_unknown_base_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let mut ul = UidList::load_or_new(dir.path(), 1).unwrap();
        assert_eq!(ul.bump_modseq("nonexistent"), 0);
        assert_eq!(ul.highest_modseq, 0);
    }

    #[test]
    fn highest_modseq_never_decreases_across_expunge() {
        let dir = tempfile::tempdir().unwrap();
        let mut ul = UidList::load_or_new(dir.path(), 1).unwrap();
        ul.assign("base1");
        ul.bump_modseq("base1");
        ul.bump_modseq("base1");
        assert_eq!(ul.highest_modseq, 3);
        ul.remove_base("base1");
        assert_eq!(
            ul.highest_modseq, 3,
            "removing the message that held the high modseq must not roll HIGHESTMODSEQ back"
        );
    }

    #[test]
    fn save_and_reload_round_trips_uid_and_modseq() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut ul = UidList::load_or_new(dir.path(), 42).unwrap();
            ul.assign("base1");
            ul.assign("base2");
            ul.bump_modseq("base1");
            ul.save().unwrap();
        }
        let ul2 = UidList::load_or_new(dir.path(), 0).unwrap();
        assert_eq!(ul2.uid_validity, 42);
        assert_eq!(ul2.get("base1"), Some(1));
        assert_eq!(ul2.get("base2"), Some(2));
        assert_eq!(ul2.modseq_for("base1"), 3);
        assert_eq!(ul2.modseq_for("base2"), 2);
        assert_eq!(ul2.highest_modseq, 3);
    }

    #[test]
    fn loading_a_v1_file_with_no_modseq_column_defaults_to_zero() {
        let dir = tempfile::tempdir().unwrap();
        let path = UidList::path_in(dir.path());
        std::fs::write(
            &path,
            "# gumdrop-uidlist v1\nuidvalidity 7\nuidnext 3\n1 1234567890.1.1.host\n2 1234567890.2.1.host\n",
        )
        .unwrap();
        let ul = UidList::load_or_new(dir.path(), 0).unwrap();
        assert_eq!(ul.uid_validity, 7);
        assert_eq!(ul.uid_next, 3);
        assert_eq!(ul.highest_modseq, 0);
        assert_eq!(ul.get("1234567890.1.1.host"), Some(1));
        assert_eq!(ul.modseq_for("1234567890.1.1.host"), 0);
    }
}
