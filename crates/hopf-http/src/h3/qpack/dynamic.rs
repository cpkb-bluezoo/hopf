// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! QPACK dynamic table (RFC 9204 §3.2), absolute indexing.
//!
//! Entries are addressed by an ever-increasing "absolute index" assigned at
//! insertion time (0, 1, 2, ...) — unlike HPACK's relative indexing, QPACK
//! indices never shift as new entries arrive; only the *window* of which
//! indices are still live shrinks as entries are evicted from the oldest
//! end.
//!
//! The same struct backs both roles: the encoder's `insert()` refuses to
//! evict a still-referenced, unacknowledged entry (RFC 9204 §3.2.2) and
//! reports failure so the caller falls back to a literal; the decoder's
//! `insert_mirrored()` unconditionally mirrors whatever the peer encoder
//! already decided, since the decoder does its own eviction-safety
//! accounting by definition (it never originates an insert).

use std::collections::VecDeque;

use super::static_table::entry_size;

struct DynamicEntry {
    name: String,
    value: String,
    /// Outstanding (not yet acknowledged) field sections referencing this
    /// entry — while nonzero, it must not be evicted (RFC 9204 §3.2.2).
    ref_count: u32,
}

impl DynamicEntry {
    fn size(&self) -> usize {
        entry_size(&self.name, &self.value)
    }
}

pub(crate) struct DynamicTable {
    /// Live entries, oldest first; `entries[0]`'s absolute index is `base_index`.
    entries: VecDeque<DynamicEntry>,
    /// Absolute index of `entries[0]`. Total ever inserted = `base_index +
    /// entries.len()` (== [`Self::insert_count`]).
    base_index: u64,
    current_size: usize,
    capacity: usize,
}

impl DynamicTable {
    /// Create an empty table with the given capacity in bytes (RFC 9204
    /// §3.2.1 accounting: `entry_size` per entry).
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            base_index: 0,
            current_size: 0,
            capacity,
        }
    }

    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }

    /// Total number of entries ever inserted — the table's "Insert Count"
    /// (RFC 9204 §2.1.1).
    pub(crate) fn insert_count(&self) -> u64 {
        self.base_index + self.entries.len() as u64
    }

    /// Absolute index of the oldest still-live entry (entries below this
    /// have been evicted).
    pub(crate) fn base_index(&self) -> u64 {
        self.base_index
    }

    /// Encoder-side insert: evicts unreferenced entries from the oldest end
    /// as needed, but refuses (returns `None`) rather than evict a
    /// still-referenced entry or exceed capacity with a single oversized
    /// entry. On success, returns the new entry's absolute index.
    pub(crate) fn insert(&mut self, name: String, value: String) -> Option<u64> {
        let size = entry_size(&name, &value);
        if size > self.capacity {
            return None;
        }
        while self.current_size + size > self.capacity {
            match self.entries.front() {
                Some(e) if e.ref_count == 0 => {
                    let evicted = self.entries.pop_front().expect("front just checked Some");
                    self.current_size -= evicted.size();
                    self.base_index += 1;
                }
                _ => return None,
            }
        }
        let idx = self.insert_count();
        self.current_size += size;
        self.entries.push_back(DynamicEntry { name, value, ref_count: 0 });
        Some(idx)
    }

    /// Decoder-side insert: unconditionally mirrors an insert instruction
    /// already accepted by the peer's encoder, evicting oldest entries as
    /// needed regardless of any local reference count (the decoder never
    /// originates evictions).
    pub(crate) fn insert_mirrored(&mut self, name: String, value: String) {
        let size = entry_size(&name, &value);
        if size > self.capacity {
            return; // peer's own accounting should prevent this; defensively ignore
        }
        while self.current_size + size > self.capacity {
            let Some(evicted) = self.entries.pop_front() else {
                break;
            };
            self.current_size -= evicted.size();
            self.base_index += 1;
        }
        self.current_size += size;
        self.entries.push_back(DynamicEntry { name, value, ref_count: 0 });
    }

    /// Update the working capacity (Set Dynamic Table Capacity, RFC 9204
    /// §4.3.1), evicting oldest entries if the table must shrink.
    pub(crate) fn set_capacity(&mut self, capacity: usize) {
        self.capacity = capacity;
        while self.current_size > self.capacity {
            let Some(evicted) = self.entries.pop_front() else {
                break;
            };
            self.current_size -= evicted.size();
            self.base_index += 1;
        }
    }

    /// Look up a live entry by absolute index.
    pub(crate) fn get(&self, absolute_index: u64) -> Option<(&str, &str)> {
        if absolute_index < self.base_index {
            return None;
        }
        let pos = usize::try_from(absolute_index - self.base_index).ok()?;
        self.entries.get(pos).map(|e| (e.name.as_str(), e.value.as_str()))
    }

    /// Find a match visible to a reference with absolute index strictly
    /// less than `visible_before` (e.g. the encoder's Known Received Count,
    /// for a non-blocking encoding policy). Returns `(absolute_index,
    /// full_match)`, preferring a full name+value match over a name-only one.
    pub(crate) fn find(&self, name: &str, value: &str, visible_before: u64) -> Option<(u64, bool)> {
        let mut name_only: Option<u64> = None;
        for (i, e) in self.entries.iter().enumerate() {
            let abs = self.base_index + i as u64;
            if abs >= visible_before {
                break; // entries are insertion-ordered; later ones are even less visible
            }
            if e.name == name {
                if e.value == value {
                    return Some((abs, true));
                }
                if name_only.is_none() {
                    name_only = Some(abs);
                }
            }
        }
        name_only.map(|abs| (abs, false))
    }

    /// Mark `absolute_index` as referenced by an outstanding field section
    /// (encoder side — protects it from eviction until released).
    pub(crate) fn add_ref(&mut self, absolute_index: u64) {
        if let Some(pos) = self.pos_of(absolute_index) {
            self.entries[pos].ref_count += 1;
        }
    }

    /// Release a reference previously taken via [`Self::add_ref`] (the
    /// field section that held it has been acknowledged or cancelled).
    pub(crate) fn release_ref(&mut self, absolute_index: u64) {
        if let Some(pos) = self.pos_of(absolute_index) {
            self.entries[pos].ref_count = self.entries[pos].ref_count.saturating_sub(1);
        }
    }

    fn pos_of(&self, absolute_index: u64) -> Option<usize> {
        if absolute_index < self.base_index {
            return None;
        }
        let pos = usize::try_from(absolute_index - self.base_index).ok()?;
        (pos < self.entries.len()).then_some(pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_get_and_absolute_indices_never_shift() {
        let mut t = DynamicTable::new(1000);
        let i0 = t.insert("a".into(), "1".into()).unwrap();
        let i1 = t.insert("b".into(), "2".into()).unwrap();
        assert_eq!((i0, i1), (0, 1));
        assert_eq!(t.get(0), Some(("a", "1")));
        assert_eq!(t.get(1), Some(("b", "2")));
        assert_eq!(t.insert_count(), 2);
    }

    #[test]
    fn eviction_advances_base_index_but_not_absolute_indices() {
        // Each entry costs 1+1+32 = 34 bytes; capacity for ~2 entries.
        let mut t = DynamicTable::new(70);
        let i0 = t.insert("a".into(), "1".into()).unwrap();
        let i1 = t.insert("b".into(), "2".into()).unwrap();
        let i2 = t.insert("c".into(), "3".into()).unwrap(); // evicts i0
        assert_eq!((i0, i1, i2), (0, 1, 2));
        assert_eq!(t.get(0), None, "evicted");
        assert_eq!(t.get(1), Some(("b", "2")));
        assert_eq!(t.get(2), Some(("c", "3")));
        assert_eq!(t.base_index(), 1);
    }

    #[test]
    fn referenced_entry_blocks_eviction_and_insert_fails() {
        let mut t = DynamicTable::new(70);
        let i0 = t.insert("a".into(), "1".into()).unwrap();
        t.add_ref(i0);
        let _i1 = t.insert("b".into(), "2".into()).unwrap();
        // A third insert would need to evict i0, but it's still referenced.
        assert_eq!(t.insert("c".into(), "3".into()), None);

        t.release_ref(i0);
        assert!(t.insert("c".into(), "3".into()).is_some(), "now evictable");
    }

    #[test]
    fn oversized_entry_alone_is_refused() {
        let mut t = DynamicTable::new(40);
        assert_eq!(t.insert("toolongname".into(), "toolongvaluehere!!!!".into()), None);
        assert_eq!(t.insert_count(), 0);
    }

    #[test]
    fn find_respects_visibility_cutoff() {
        let mut t = DynamicTable::new(1000);
        t.insert("a".into(), "1".into()); // index 0
        t.insert("b".into(), "2".into()); // index 1
        // Only index 0 is "visible" (acknowledged so far).
        assert_eq!(t.find("a", "1", 1), Some((0, true)));
        assert_eq!(t.find("b", "2", 1), None, "index 1 not yet visible");
        assert_eq!(t.find("b", "2", 2), Some((1, true)), "now visible");
    }

    #[test]
    fn set_capacity_shrink_evicts_oldest() {
        let mut t = DynamicTable::new(1000);
        t.insert("a".into(), "1".into());
        t.insert("b".into(), "2".into());
        t.set_capacity(34); // room for exactly one entry
        assert_eq!(t.get(0), None);
        assert_eq!(t.get(1), Some(("b", "2")));
    }

    #[test]
    fn insert_mirrored_never_refuses() {
        let mut t = DynamicTable::new(70);
        t.insert_mirrored("a".into(), "1".into());
        t.insert_mirrored("b".into(), "2".into());
        t.insert_mirrored("c".into(), "3".into()); // silently evicts "a"
        assert_eq!(t.get(0), None);
        assert_eq!(t.get(2), Some(("c", "3")));
    }
}
