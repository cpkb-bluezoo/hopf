// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Maildir filename encoding (`:2,` flags).

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::flag::Flag;

static COUNTER: AtomicU64 = AtomicU64::new(1);

/// Parse / build Maildir filenames.
#[derive(Clone, Debug)]
pub struct MaildirFilename {
    /// Identity without `:2,...`
    pub base: String,
    /// System flags from info.
    pub flags: BTreeSet<Flag>,
    /// Keyword letters `a`–`z`.
    pub keyword_letters: BTreeSet<char>,
}

impl MaildirFilename {
    /// Split base / info.
    pub fn parse(name: &str) -> Self {
        if let Some((base, info)) = name.split_once(":2,") {
            let mut flags = BTreeSet::new();
            let mut keyword_letters = BTreeSet::new();
            for c in info.chars() {
                if let Some(f) = Flag::from_maildir_letter(c) {
                    flags.insert(f);
                } else if c.is_ascii_lowercase() {
                    keyword_letters.insert(c);
                }
            }
            Self {
                base: base.to_string(),
                flags,
                keyword_letters,
            }
        } else {
            Self {
                base: name.to_string(),
                flags: BTreeSet::new(),
                keyword_letters: BTreeSet::new(),
            }
        }
    }

    /// Full filename with `:2,` info.
    pub fn to_string_name(&self) -> String {
        let mut letters: Vec<char> = self
            .flags
            .iter()
            .filter_map(|f| f.maildir_letter())
            .collect();
        letters.sort_unstable();
        let mut kw: Vec<char> = self.keyword_letters.iter().copied().collect();
        kw.sort_unstable();
        letters.extend(kw);
        format!("{}:2,{}", self.base, letters.iter().collect::<String>())
    }

    /// Generate a unique base name with optional size.
    pub fn generate(size: Option<u64>) -> String {
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        match size {
            Some(s) => format!("{ms}.{pid}.{n},S={s}"),
            None => format!("{ms}.{pid}.{n}"),
        }
    }
}
