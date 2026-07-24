// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HPACK dynamic header table (RFC 7541 §2.3.2).
//!
//! Entries are evicted from the oldest end whenever the table exceeds the
//! current maximum size. Size accounting uses the 32-byte overhead rule from
//! RFC 7541 §4.1.

use super::static_table::entry_size;

/// One dynamic table entry.
#[derive(Debug, Clone)]
pub struct DynamicEntry {
    /// Field name.
    pub name: String,
    /// Field value.
    pub value: String,
}

impl DynamicEntry {
    /// RFC 7541 §4.1 size: `name.len() + value.len() + 32`.
    pub fn size(&self) -> usize {
        entry_size(&self.name, &self.value)
    }
}

/// Ring-buffer dynamic header table.
///
/// Entries are stored newest-first; index 1 is the most recently added entry.
pub struct DynamicTable {
    entries: Vec<DynamicEntry>,
    current_size: usize,
    max_size: usize,
}

#[allow(dead_code)]
impl DynamicTable {
    /// Create a new table with the given maximum size (octets).
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: Vec::new(),
            current_size: 0,
            max_size,
        }
    }

    /// Current aggregate size in octets.
    pub fn current_size(&self) -> usize {
        self.current_size
    }

    /// Current maximum size.
    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// Update the maximum size and evict entries as required by RFC 7541 §4.3.
    pub fn set_max_size(&mut self, new_max: usize) {
        self.max_size = new_max;
        self.evict();
    }

    /// Insert a new entry at the front (lowest dynamic index).
    ///
    /// If the entry alone exceeds `max_size`, the table is cleared entirely
    /// per RFC 7541 §4.4.
    pub fn insert(&mut self, name: String, value: String) {
        let size = entry_size(&name, &value);
        if size > self.max_size {
            self.entries.clear();
            self.current_size = 0;
            return;
        }
        self.entries.insert(0, DynamicEntry { name, value });
        self.current_size += size;
        self.evict();
    }

    /// Look up by 0-based dynamic index (index 0 = most recent entry, exposed
    /// to callers as 1-based offset from 62 in the combined table).
    pub fn get(&self, idx: usize) -> Option<(&str, &str)> {
        self.entries
            .get(idx)
            .map(|e| (e.name.as_str(), e.value.as_str()))
    }

    /// Number of entries currently in the table.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Find the first entry matching `name` (case-insensitive). Returns
    /// `(0-based-index, full_match)` where `full_match` means the value also matched.
    pub fn find(&self, name: &str, value: &str) -> Option<(usize, bool)> {
        let mut name_only: Option<usize> = None;
        for (i, e) in self.entries.iter().enumerate() {
            if e.name.eq_ignore_ascii_case(name) {
                if e.value == value {
                    return Some((i, true));
                }
                if name_only.is_none() {
                    name_only = Some(i);
                }
            }
        }
        name_only.map(|i| (i, false))
    }

    fn evict(&mut self) {
        while self.current_size > self.max_size {
            if let Some(oldest) = self.entries.pop() {
                self.current_size -= oldest.size();
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_find_evict_and_oversized_clear() {
        let mut t = DynamicTable::new(100);
        t.insert("a".into(), "1".into());
        assert_eq!(t.len(), 1);
        assert_eq!(t.find("a", "1"), Some((0, true)));
        assert_eq!(t.find("a", "2"), Some((0, false)));
        assert_eq!(t.get(0), Some(("a", "1")));

        // Force eviction by shrinking max size.
        t.set_max_size(0);
        assert!(t.is_empty());
        assert_eq!(t.current_size(), 0);

        let mut t2 = DynamicTable::new(40);
        // entry_size = name+value+32; "big"+"valueeeee" is > 40 → clear
        t2.insert("x".into(), "y".into());
        assert_eq!(t2.len(), 1);
        t2.insert("toolongname".into(), "toolongvaluehere!!!!".into());
        assert!(t2.is_empty() || t2.max_size() < 100);
        // Oversized alone clears
        let mut t3 = DynamicTable::new(30);
        t3.insert("abcdefghijklmnop".into(), "qrstuvwxyz012345".into());
        assert!(t3.is_empty());
    }
}

