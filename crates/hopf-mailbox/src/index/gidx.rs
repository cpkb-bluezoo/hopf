// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! `.gidx` file format (big-endian, Gumdrop-compatible for v1).

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

use crate::error::{MailboxError, MailboxResult};
use crate::flag::flags_from_byte;

use super::entry::{
    IndexEntry, DESCRIPTOR_COUNT_BODY, DESCRIPTOR_COUNT_BODY_V1, DESCRIPTOR_COUNT_HEADERS,
    DESCRIPTOR_COUNT_HEADERS_V1,
};

/// Magic `GIDX`.
pub const INDEX_MAGIC: [u8; 4] = *b"GIDX";
/// Headers-only, pre-#407 layout (8 descriptors) — read-only; a file this
/// old is rewritten as [`INDEX_VERSION_THREADING`] (or `_BODY`) the next
/// time anything in it changes, since [`super::IndexBuilder`] no longer
/// produces entries this short. See [`DESCRIPTOR_COUNT_HEADERS_V1`].
pub const INDEX_VERSION_HEADERS: u16 = 1;
/// Headers-plus-body, pre-#407 layout (9 descriptors) — read-only, ditto.
pub const INDEX_VERSION_BODY: u16 = 2;
/// Adds `References` / `In-Reply-To` for RFC 5256 THREAD REFERENCES (issue
/// #407): 10 descriptors.
pub const INDEX_VERSION_THREADING: u16 = 3;
/// [`INDEX_VERSION_THREADING`] plus the optional body descriptor: 11.
pub const INDEX_VERSION_THREADING_BODY: u16 = 4;

const MAX_ENTRY_COUNT: i32 = 10_000_000;
const MAX_VAR: i32 = 10 * 1024 * 1024;

/// On-disk index image.
#[derive(Debug)]
pub struct IndexFile {
    /// Format version (`1` headers, `2` with body).
    pub version: u16,
    /// UIDVALIDITY.
    pub uid_validity: u64,
    /// UIDNEXT.
    pub uid_next: u64,
    /// Entries in file order.
    pub entries: Vec<IndexEntry>,
    /// Whether body descriptors are written.
    pub body_indexing: bool,
}

impl IndexFile {
    /// Load and validate.
    pub fn load(path: &Path) -> MailboxResult<Self> {
        let mut data = Vec::new();
        File::open(path)?.read_to_end(&mut data)?;
        Self::parse(&data)
    }

    /// Parse bytes.
    pub fn parse(data: &[u8]) -> MailboxResult<Self> {
        if data.len() < 32 {
            return Err(MailboxError::Corrupt("gidx truncated header".into()));
        }
        if data[0..4] != INDEX_MAGIC {
            return Err(MailboxError::Corrupt("gidx bad magic".into()));
        }
        let mut crc = crc32fast::Hasher::new();
        crc.update(&data[0..4]);

        let version = read_u16(data, 4);
        update_crc_u16(&mut crc, version);
        if version == 0 || version > INDEX_VERSION_THREADING_BODY {
            return Err(MailboxError::Corrupt(format!(
                "gidx unsupported version {version}"
            )));
        }
        let flags = read_u16(data, 6);
        update_crc_u16(&mut crc, flags);
        let uid_validity = read_u64(data, 8);
        update_crc_u64(&mut crc, uid_validity);
        let uid_next = read_u64(data, 16);
        update_crc_u64(&mut crc, uid_next);
        let entry_count = read_i32(data, 24);
        update_crc_i32(&mut crc, entry_count);
        if !(0..=MAX_ENTRY_COUNT).contains(&entry_count) {
            return Err(MailboxError::Corrupt(format!(
                "gidx bad entry count {entry_count}"
            )));
        }
        let stored = read_u32(data, 28);
        if stored != crc.finalize() {
            return Err(MailboxError::Corrupt("gidx header checksum".into()));
        }

        let body_indexing = matches!(
            version,
            INDEX_VERSION_BODY | INDEX_VERSION_THREADING_BODY
        );

        let mut offset = 32usize;
        let mut entries = Vec::with_capacity(entry_count as usize);
        let mut seen = std::collections::HashSet::new();
        for i in 0..entry_count as usize {
            // Each entry declares its own descriptor count, independent of
            // the file-level `version` — see `read_entry`. This lets an
            // entry an older hopf version indexed (fewer descriptors)
            // survive being re-saved alongside newer ones without silently
            // gaining zero-filled fields it was never actually indexed
            // with (`IndexEntry::references`/`in_reply_to` depend on this).
            let (entry, next) = read_entry(data, offset)?;
            if entry.uid == 0 || entry.uid >= uid_next {
                return Err(MailboxError::Corrupt(format!(
                    "gidx invalid uid at {i}"
                )));
            }
            if !seen.insert(entry.uid) {
                return Err(MailboxError::Corrupt(format!(
                    "gidx duplicate uid {}",
                    entry.uid
                )));
            }
            entries.push(entry);
            offset = next;
        }
        // Trailing section checksum (optional / discarded like Gumdrop).
        if offset + 4 <= data.len() {
            // ok
        }

        Ok(Self {
            version,
            uid_validity,
            uid_next,
            entries,
            body_indexing,
        })
    }

    /// Atomic save via `.tmp` rename.
    pub fn save(&self, path: &Path) -> MailboxResult<()> {
        let tmp = path.with_extension("gidx.tmp");
        // Prefer sibling name `file.gidx.tmp` when path ends with .gidx
        let tmp = if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
            path.with_file_name(format!("{name}.tmp"))
        } else {
            tmp
        };
        let bytes = self.serialize()?;
        {
            let mut f = File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, path)?;
        Ok(())
    }

    fn serialize(&self) -> MailboxResult<Vec<u8>> {
        let version = if self.body_indexing {
            INDEX_VERSION_THREADING_BODY
        } else {
            INDEX_VERSION_THREADING
        };

        let mut out = Vec::new();
        let mut crc = crc32fast::Hasher::new();
        out.extend_from_slice(&INDEX_MAGIC);
        crc.update(&INDEX_MAGIC);
        write_u16(&mut out, version);
        update_crc_u16(&mut crc, version);
        write_u16(&mut out, 0);
        update_crc_u16(&mut crc, 0);
        write_u64(&mut out, self.uid_validity);
        update_crc_u64(&mut crc, self.uid_validity);
        write_u64(&mut out, self.uid_next);
        update_crc_u64(&mut crc, self.uid_next);
        write_i32(&mut out, self.entries.len() as i32);
        update_crc_i32(&mut crc, self.entries.len() as i32);
        write_u32(&mut out, crc.finalize());

        let mut entry_crc = crc32fast::Hasher::new();
        for e in &self.entries {
            let eb = serialize_entry(e)?;
            entry_crc.update(&eb);
            out.extend_from_slice(&eb);
        }
        write_u32(&mut out, entry_crc.finalize());
        Ok(out)
    }
}

/// Serializes `e` with exactly the descriptor count it actually holds —
/// never coerced to some file-wide count. An entry built by an older hopf
/// version (fewer descriptors, still sitting in the in-memory map because
/// its UID was already indexed) round-trips as-is rather than being padded
/// with zero-length `References`/`In-Reply-To` fields it was never really
/// indexed with; it's upgraded in place the next time that message itself
/// is re-indexed (a UID's entry is only ever rebuilt, never patched).
fn serialize_entry(e: &IndexEntry) -> MailboxResult<Vec<u8>> {
    let desc_count = e.props().len();
    let props: Vec<&str> = (0..desc_count).map(|i| e.prop(i)).collect();

    let mut var = Vec::new();
    let mut descriptors = Vec::with_capacity(desc_count);
    for p in &props[..desc_count] {
        let bytes = p.as_bytes();
        let off = var.len() as u32;
        let len = bytes.len() as u32;
        descriptors.push((off, len));
        var.extend_from_slice(bytes);
    }
    if var.len() as i32 > MAX_VAR {
        return Err(MailboxError::Invalid("index entry too large".into()));
    }

    let mut out = Vec::with_capacity(48 + desc_count * 8 + var.len());
    write_u64(&mut out, e.uid);
    write_i32(&mut out, e.message_number as i32);
    write_u64(&mut out, e.size);
    write_i64(&mut out, e.internal_date);
    write_i64(&mut out, e.sent_date);
    out.push(e.flags_byte());
    out.extend_from_slice(&[0, 0, 0]);
    write_i32(&mut out, desc_count as i32);
    write_i32(&mut out, var.len() as i32);
    for (off, len) in descriptors {
        write_u32(&mut out, off);
        write_u32(&mut out, len);
    }
    out.extend_from_slice(&var);
    Ok(out)
}

/// Reads one entry starting at `offset`. The entry's own recorded
/// `descriptor_count` governs how many fields are read back — not
/// anything derived from the file-level `version` — so an entry any
/// supported hopf version could have written (8/9/10/11 descriptors)
/// round-trips exactly as stored; see `serialize_entry`.
fn read_entry(data: &[u8], offset: usize) -> MailboxResult<(IndexEntry, usize)> {
    if offset + 48 > data.len() {
        return Err(MailboxError::Corrupt("gidx truncated entry".into()));
    }
    let uid = read_u64(data, offset);
    let message_number = read_i32(data, offset + 8) as u32;
    let size = read_u64(data, offset + 12);
    let internal_date = read_i64(data, offset + 20);
    let sent_date = read_i64(data, offset + 28);
    let flags_byte = data[offset + 36];
    let descriptor_count = read_i32(data, offset + 40) as usize;
    let var_size = read_i32(data, offset + 44);
    if !matches!(
        descriptor_count,
        DESCRIPTOR_COUNT_HEADERS_V1 | DESCRIPTOR_COUNT_BODY_V1 | DESCRIPTOR_COUNT_HEADERS
            | DESCRIPTOR_COUNT_BODY
    ) {
        return Err(MailboxError::Corrupt(format!(
            "bad descriptor count {descriptor_count}"
        )));
    }
    if !(0..=MAX_VAR).contains(&var_size) {
        return Err(MailboxError::Corrupt("bad variable size".into()));
    }
    let mut o = offset + 48;
    let mut descs = Vec::with_capacity(descriptor_count);
    for _ in 0..descriptor_count {
        if o + 8 > data.len() {
            return Err(MailboxError::Corrupt("truncated descriptors".into()));
        }
        let off = read_u32(data, o) as usize;
        let len = read_u32(data, o + 4) as usize;
        if off.checked_add(len).map(|e| e > var_size as usize).unwrap_or(true) {
            return Err(MailboxError::Corrupt("descriptor OOB".into()));
        }
        descs.push((off, len));
        o += 8;
    }
    if o + var_size as usize > data.len() {
        return Err(MailboxError::Corrupt("truncated var data".into()));
    }
    let var = &data[o..o + var_size as usize];
    let mut props = Vec::with_capacity(descriptor_count);
    for (off, len) in descs {
        let s = String::from_utf8_lossy(&var[off..off + len])
            .into_owned();
        props.push(s);
    }
    let mut entry = IndexEntry::new(
        uid,
        message_number,
        size,
        internal_date,
        sent_date,
        &flags_from_byte(flags_byte),
        props,
    );
    entry.set_flags_byte(flags_byte);
    Ok((entry, o + var_size as usize))
}

fn read_u16(data: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([data[o], data[o + 1]])
}
fn read_u32(data: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]])
}
fn read_i32(data: &[u8], o: usize) -> i32 {
    read_u32(data, o) as i32
}
fn read_u64(data: &[u8], o: usize) -> u64 {
    u64::from_be_bytes([
        data[o],
        data[o + 1],
        data[o + 2],
        data[o + 3],
        data[o + 4],
        data[o + 5],
        data[o + 6],
        data[o + 7],
    ])
}
fn read_i64(data: &[u8], o: usize) -> i64 {
    read_u64(data, o) as i64
}

fn write_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn write_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn write_i32(out: &mut Vec<u8>, v: i32) {
    write_u32(out, v as u32);
}
fn write_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn write_i64(out: &mut Vec<u8>, v: i64) {
    write_u64(out, v as u64);
}

fn update_crc_u16(crc: &mut crc32fast::Hasher, v: u16) {
    crc.update(&[(v >> 8) as u8, v as u8]);
}
fn update_crc_i32(crc: &mut crc32fast::Hasher, v: i32) {
    let v = v as u32;
    crc.update(&[
        (v >> 24) as u8,
        (v >> 16) as u8,
        (v >> 8) as u8,
        v as u8,
    ]);
}
fn update_crc_u64(crc: &mut crc32fast::Hasher, v: u64) {
    crc.update(&[
        (v >> 56) as u8,
        (v >> 48) as u8,
        (v >> 40) as u8,
        (v >> 32) as u8,
        (v >> 24) as u8,
        (v >> 16) as u8,
        (v >> 8) as u8,
        v as u8,
    ]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use tempfile::tempdir;

    #[test]
    fn roundtrip_headers() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("box.gidx");
        let mut flags = BTreeSet::new();
        flags.insert(crate::flag::Flag::Seen);
        let entry = IndexEntry::new(
            1,
            1,
            100,
            1_700_000_000_000,
            0,
            &flags,
            vec![
                "0:100".into(),
                "a@b.c".into(),
                "c@d.e".into(),
                String::new(),
                String::new(),
                "hello".into(),
                "<id@x>".into(),
                String::new(),
            ],
        );
        let file = IndexFile {
            version: INDEX_VERSION_HEADERS,
            uid_validity: 42,
            uid_next: 2,
            entries: vec![entry],
            body_indexing: false,
        };
        file.save(&path).unwrap();
        let loaded = IndexFile::load(&path).unwrap();
        assert_eq!(loaded.uid_validity, 42);
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].prop(5), "hello");
    }

    fn entry_with_props(uid: u64, props: Vec<String>) -> IndexEntry {
        IndexEntry::new(uid, uid as u32, 100, 1_700_000_000_000, 0, &BTreeSet::new(), props)
    }

    /// Issue #407: a mailbox indexed by an older hopf version has entries
    /// with only 8 (or 9, with body) descriptors; once anything else in
    /// the same mailbox is re-indexed and the whole file is rewritten,
    /// those old entries must survive with their *own* descriptor count
    /// untouched — not silently padded to the new 10/11-descriptor layout,
    /// which would bake in "no References/In-Reply-To" for mail that was
    /// simply never re-indexed to capture it.
    #[test]
    fn old_and_new_generation_entries_coexist_in_one_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("box.gidx");

        let old_entry = entry_with_props(
            1,
            vec![
                "loc1".into(),
                "old@sender".into(),
                String::new(),
                String::new(),
                String::new(),
                "old subject".into(),
                "<old@x>".into(),
                String::new(),
            ],
        );
        let new_entry = entry_with_props(
            2,
            vec![
                "loc2".into(),
                "new@sender".into(),
                String::new(),
                String::new(),
                String::new(),
                "new subject".into(),
                "<new@x>".into(),
                String::new(),
                "<ref1@x> <ref2@x>".into(),
                "<ref2@x>".into(),
            ],
        );
        assert_eq!(old_entry.references(), None);
        assert_eq!(new_entry.references(), Some("<ref1@x> <ref2@x>"));

        let file = IndexFile {
            version: INDEX_VERSION_THREADING,
            uid_validity: 42,
            uid_next: 3,
            entries: vec![old_entry, new_entry],
            body_indexing: false,
        };
        file.save(&path).unwrap();

        let loaded = IndexFile::load(&path).unwrap();
        assert_eq!(loaded.entries.len(), 2);
        let reloaded_old = loaded.entries.iter().find(|e| e.uid == 1).unwrap();
        let reloaded_new = loaded.entries.iter().find(|e| e.uid == 2).unwrap();
        assert_eq!(
            reloaded_old.references(),
            None,
            "an old entry must not gain a fabricated empty References field on re-save"
        );
        assert_eq!(reloaded_new.references(), Some("<ref1@x> <ref2@x>"));
        assert_eq!(reloaded_new.in_reply_to(), Some("<ref2@x>"));
    }
}
