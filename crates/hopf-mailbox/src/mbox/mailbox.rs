// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Single-file mbox mailbox.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::config::IndexConfig;
use crate::error::{MailboxError, MailboxResult};
use crate::flag::Flag;
use crate::index::{IndexBuilder, MessageIndex};
use crate::search::SearchCriteria;
use crate::traits::{Mailbox, MessageDescriptor, MessageReadCallback};

use super::flags::MboxFlagsFile;
use super::lock::{DotLock, FileLock};

#[derive(Clone)]
struct MboxMsg {
    /// Byte offset of content (after From_ line).
    start: u64,
    /// Exclusive end offset of content.
    end: u64,
    size: u64,
    unique_id: String,
    uid: u64,
    /// POP session delete mark (in-memory until `close(true)`).
    session_deleted: bool,
}

/// mbox mailbox with `.flags` sidecar and optional `.gidx`.
pub struct MboxMailbox {
    path: PathBuf,
    name: String,
    read_only: bool,
    _lock: FileLock,
    // Held alongside `_lock`'s flock so hopf interoperates with
    // dotlock-only mbox tooling too — see `mbox::lock::DotLock`. Field
    // order matters here: dropped after `_lock` (Rust drops struct fields
    // in declaration order), releasing the flock before the dotlock.
    _dotlock: DotLock,
    messages: Vec<MboxMsg>,
    flags: MboxFlagsFile,
    index: MessageIndex,
    uid_validity: u64,
    uid_next: u64,
    append: Option<AppendState>,
    index_config: IndexConfig,
}

/// In-progress append — content is written to a tmp file as it arrives
/// (bounded memory regardless of message size), matching Maildir's own
/// `AppendState` pattern. Nothing touches the live mbox file until
/// `end_append` streams the tmp file's content across (escaped) and
/// deletes it — so `abort_append` (delete the tmp file) leaves the live
/// mailbox exactly as it was.
struct AppendState {
    flags: BTreeSet<Flag>,
    internal_millis: i64,
    size: u64,
    tmp_path: PathBuf,
    tmp_file: File,
}

impl MboxMailbox {
    /// Open an mbox file.
    pub fn open(
        path: impl Into<PathBuf>,
        name: impl Into<String>,
        read_only: bool,
        index_config: IndexConfig,
    ) -> MailboxResult<Self> {
        let path = path.into();
        let name = name.into();
        if !path.exists() {
            if read_only {
                return Err(MailboxError::NotFound(path.display().to_string()));
            }
            File::create(&path)?;
        }
        // Dotlock first: it fails fast (or times out cleanly) under
        // contention rather than blocking indefinitely like flock does,
        // and is the convention that actually works over NFS.
        let dotlock = DotLock::acquire(&path)?;
        let file = OpenOptions::new()
            .read(true)
            .write(!read_only)
            .open(&path)?;
        let lock = FileLock::exclusive(file)?;

        let uid_validity = file_uid_validity(&path)?;
        let flags_path = MboxFlagsFile::path_for_mbox(&path);
        let flags = MboxFlagsFile::load_or_empty(flags_path, uid_validity)?;

        let raw = {
            let mut buf = Vec::new();
            let mut f = File::open(&path)?;
            f.read_to_end(&mut buf)?;
            buf
        };

        let segments = scan_mbox(&raw);
        let gidx_path = gidx_path_for(&path);
        let mut index = MessageIndex::load(&gidx_path, index_config.clone())?
            .filter(|idx| idx.uid_validity() == uid_validity)
            .unwrap_or_else(|| {
                MessageIndex::new(&gidx_path, uid_validity, 1, index_config.clone())
            });

        let mut messages = Vec::new();
        let mut uid_next = index.uid_next().max(1);
        let builder = IndexBuilder::new(index_config.clone());
        let mut need_save_index = false;

        // Map existing index entries by location for reuse.
        let mut by_location: BTreeMap<String, u64> = BTreeMap::new();
        for e in index.entries() {
            by_location.insert(e.prop(0).to_string(), e.uid);
        }

        for (i, (_from_off, content_start, content_end)) in segments.iter().enumerate() {
            let slice = unescape_from(&raw[*content_start..*content_end]);
            let unique_id = sha256_hex(&slice);
            let size = slice.len() as u64;
            let location = format!("{content_start}:{content_end}");
            let loc_key = location.to_ascii_lowercase();

            let uid = if let Some(&u) = by_location.get(&loc_key) {
                u
            } else {
                let u = uid_next;
                uid_next += 1;
                need_save_index = true;
                u
            };

            let (sys, kw) = flags.get(&unique_id);
            if index.get(uid).is_none()
                || index
                    .get(uid)
                    .is_some_and(|e| e.prop(0) != loc_key.as_str())
            {
                let entry =
                    builder.build(uid, (i + 1) as u32, size, &location, &sys, &kw, 0, &slice);
                index.put(entry);
                need_save_index = true;
            }

            messages.push(MboxMsg {
                start: *content_start as u64,
                end: *content_end as u64,
                size,
                unique_id,
                uid,
                session_deleted: false,
            });
        }
        index.set_uid_next(uid_next);
        if need_save_index {
            index.save()?;
        }

        Ok(Self {
            path,
            name,
            read_only,
            _lock: lock,
            _dotlock: dotlock,
            messages,
            flags,
            index,
            uid_validity,
            uid_next,
            append: None,
            index_config,
        })
    }

    fn ensure_writable(&self) -> MailboxResult<()> {
        if self.read_only {
            Err(MailboxError::ReadOnly)
        } else {
            Ok(())
        }
    }

    fn msg(&self, n: u32) -> MailboxResult<&MboxMsg> {
        self.messages
            .get(n.wrapping_sub(1) as usize)
            .ok_or_else(|| MailboxError::NotFound(format!("message {n}")))
    }

    fn msg_mut(&mut self, n: u32) -> MailboxResult<&mut MboxMsg> {
        self.messages
            .get_mut(n.wrapping_sub(1) as usize)
            .ok_or_else(|| MailboxError::NotFound(format!("message {n}")))
    }

    fn read_raw(&self, msg: &MboxMsg) -> MailboxResult<Vec<u8>> {
        let mut f = File::open(&self.path)?;
        let len = (msg.end - msg.start) as usize;
        let mut buf = vec![0u8; len];
        f.seek(SeekFrom::Start(msg.start))?;
        f.read_exact(&mut buf)?;
        Ok(unescape_from(&buf))
    }

    fn rewrite_expunge(&mut self) -> MailboxResult<()> {
        let mut out = Vec::new();
        let now = SystemTime::now();
        let snapshot: Vec<MboxMsg> = self.messages.clone();
        for m in &snapshot {
            let (sys, _) = self.flags.get(&m.unique_id);
            if m.session_deleted || sys.contains(&Flag::Deleted) {
                self.flags.remove(&m.unique_id);
                self.index.remove(m.uid);
                continue;
            }
            let body = self.read_raw(m)?;
            write_mbox_message(&mut out, &body, now)?;
        }
        {
            let mut f = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&self.path)?;
            f.write_all(&out)?;
            f.sync_all()?;
        }
        self.flags.save()?;
        self.index.save()?;

        // Rescan in place (cannot re-open: exclusive flock is still held).
        let raw = {
            let mut buf = Vec::new();
            File::open(&self.path)?.read_to_end(&mut buf)?;
            buf
        };
        let segments = scan_mbox(&raw);
        let builder = IndexBuilder::new(self.index_config.clone());
        let mut messages = Vec::new();
        for (i, (_from, start, end)) in segments.iter().enumerate() {
            let slice = unescape_from(&raw[*start..*end]);
            let unique_id = sha256_hex(&slice);
            let (sys, kw) = self.flags.get(&unique_id);
            let uid = snapshot
                .iter()
                .find(|m| {
                    !m.session_deleted
                        && !self.flags.get(&m.unique_id).0.contains(&Flag::Deleted)
                        && m.unique_id == unique_id
                })
                .map(|m| m.uid)
                .or_else(|| {
                    snapshot
                        .iter()
                        .find(|m| m.unique_id == unique_id)
                        .map(|m| m.uid)
                })
                .unwrap_or_else(|| {
                    let u = self.uid_next;
                    self.uid_next += 1;
                    u
                });
            let location = format!("{start}:{end}");
            let entry = builder.build(
                uid,
                (i + 1) as u32,
                slice.len() as u64,
                &location,
                &sys,
                &kw,
                0,
                &slice,
            );
            self.index.put(entry);
            messages.push(MboxMsg {
                start: *start as u64,
                end: *end as u64,
                size: slice.len() as u64,
                unique_id,
                uid,
                session_deleted: false,
            });
        }
        self.index.set_uid_next(self.uid_next);
        self.messages = messages;
        Ok(())
    }
}

impl Mailbox for MboxMailbox {
    fn close(&mut self, expunge: bool) -> MailboxResult<()> {
        if expunge && !self.read_only {
            let _ = self.expunge()?;
        } else if !expunge {
            for m in &mut self.messages {
                m.session_deleted = false;
            }
        }
        self.flags.save()?;
        self.index.save()?;
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn is_read_only(&self) -> bool {
        self.read_only
    }

    fn message_count(&self) -> MailboxResult<u32> {
        Ok(self.messages.len() as u32)
    }

    fn mailbox_size(&self) -> MailboxResult<u64> {
        Ok(self.messages.iter().map(|m| m.size).sum())
    }

    fn undeleted_message_count(&self) -> MailboxResult<u32> {
        Ok(self.messages.iter().filter(|m| !m.session_deleted).count() as u32)
    }

    fn undeleted_mailbox_size(&self) -> MailboxResult<u64> {
        Ok(self
            .messages
            .iter()
            .filter(|m| !m.session_deleted)
            .map(|m| m.size)
            .sum())
    }

    fn messages(&self) -> MailboxResult<Vec<MessageDescriptor>> {
        let mut out = Vec::new();
        for (i, m) in self.messages.iter().enumerate() {
            out.push(MessageDescriptor {
                message_number: (i + 1) as u32,
                size: m.size,
                unique_id: m.unique_id.clone(),
                uid: Some(m.uid),
            });
        }
        Ok(out)
    }

    fn read_message(
        &mut self,
        message_number: u32,
        callback: &mut dyn MessageReadCallback,
    ) -> MailboxResult<()> {
        let msg = self.msg(message_number)?.clone();
        if msg.session_deleted {
            return Err(MailboxError::NotFound(format!("message {message_number}")));
        }
        callback.start_message(msg.size);
        stream_unescaped_range(&self.path, msg.start, msg.end, |chunk| {
            callback.message_content(chunk)
        })?;
        callback.end_message();
        Ok(())
    }

    fn unique_id(&self, message_number: u32) -> MailboxResult<String> {
        Ok(self.msg(message_number)?.unique_id.clone())
    }

    fn uid(&self, message_number: u32) -> MailboxResult<u64> {
        Ok(self.msg(message_number)?.uid)
    }

    fn uid_validity(&self) -> u64 {
        self.uid_validity
    }

    fn uid_next(&self) -> u64 {
        self.uid_next
    }

    fn flags(&self, message_number: u32) -> MailboxResult<BTreeSet<Flag>> {
        let msg = self.msg(message_number)?;
        let (f, _) = self.flags.get(&msg.unique_id);
        Ok(f)
    }

    fn keywords(&self, message_number: u32) -> MailboxResult<BTreeSet<String>> {
        let msg = self.msg(message_number)?;
        Ok(self.flags.get(&msg.unique_id).1)
    }

    fn highest_modseq(&self) -> u64 {
        self.flags.highest_modseq
    }

    fn modseq(&self, message_number: u32) -> MailboxResult<u64> {
        let msg = self.msg(message_number)?;
        Ok(self.flags.modseq_for(&msg.unique_id))
    }

    fn changed_since(&self, modseq: u64) -> MailboxResult<Vec<u64>> {
        Ok(self
            .messages
            .iter()
            .filter(|m| self.flags.modseq_for(&m.unique_id) > modseq)
            .map(|m| m.uid)
            .collect())
    }

    fn set_flags(
        &mut self,
        message_number: u32,
        flags: &BTreeSet<Flag>,
        add: bool,
    ) -> MailboxResult<()> {
        self.ensure_writable()?;
        let uid = self.msg(message_number)?.uid;
        let unique_id = self.msg(message_number)?.unique_id.clone();
        let (mut cur, kw) = self.flags.get(&unique_id);
        for f in flags {
            if *f == Flag::Recent {
                continue;
            }
            if add {
                cur.insert(*f);
            } else {
                cur.remove(f);
            }
        }
        self.flags.set(&unique_id, cur.clone(), kw);
        self.index.set_flags(uid, &cur);
        Ok(())
    }

    fn replace_flags(&mut self, message_number: u32, flags: &BTreeSet<Flag>) -> MailboxResult<()> {
        self.ensure_writable()?;
        let uid = self.msg(message_number)?.uid;
        let unique_id = self.msg(message_number)?.unique_id.clone();
        let (_, kw) = self.flags.get(&unique_id);
        let cur: BTreeSet<Flag> = flags
            .iter()
            .copied()
            .filter(|f| *f != Flag::Recent)
            .collect();
        self.flags.set(&unique_id, cur.clone(), kw);
        self.index.set_flags(uid, &cur);
        Ok(())
    }

    fn set_keywords(
        &mut self,
        message_number: u32,
        keywords: &BTreeSet<String>,
        add: bool,
    ) -> MailboxResult<()> {
        self.ensure_writable()?;
        let uid = self.msg(message_number)?.uid;
        let unique_id = self.msg(message_number)?.unique_id.clone();
        let (sys, mut kw) = self.flags.get(&unique_id);
        if add {
            for k in keywords {
                kw.insert(k.to_string());
            }
        } else {
            for k in keywords {
                kw.retain(|existing| !existing.eq_ignore_ascii_case(k));
            }
        }
        self.flags.set(&unique_id, sys, kw.clone());
        self.index.set_keywords(uid, &kw);
        Ok(())
    }

    fn replace_keywords(
        &mut self,
        message_number: u32,
        keywords: &BTreeSet<String>,
    ) -> MailboxResult<()> {
        self.ensure_writable()?;
        let uid = self.msg(message_number)?.uid;
        let unique_id = self.msg(message_number)?.unique_id.clone();
        let (sys, _) = self.flags.get(&unique_id);
        let kw = keywords.clone();
        self.flags.set(&unique_id, sys, kw.clone());
        self.index.set_keywords(uid, &kw);
        Ok(())
    }

    fn mark_deleted(&mut self, message_number: u32) -> MailboxResult<()> {
        self.ensure_writable()?;
        self.msg_mut(message_number)?.session_deleted = true;
        Ok(())
    }

    fn is_deleted(&self, message_number: u32) -> MailboxResult<bool> {
        Ok(self.msg(message_number)?.session_deleted)
    }

    fn undelete_all(&mut self) -> MailboxResult<()> {
        for m in &mut self.messages {
            m.session_deleted = false;
        }
        Ok(())
    }

    fn expunge(&mut self) -> MailboxResult<Vec<u32>> {
        self.ensure_writable()?;
        let mut removed = Vec::new();
        for (i, m) in self.messages.iter().enumerate() {
            let (sys, _) = self.flags.get(&m.unique_id);
            if m.session_deleted || sys.contains(&Flag::Deleted) {
                removed.push((i + 1) as u32);
            }
        }
        if !removed.is_empty() {
            self.rewrite_expunge()?;
        }
        Ok(removed)
    }

    fn start_append(
        &mut self,
        flags: &BTreeSet<Flag>,
        internal_date: Option<SystemTime>,
    ) -> MailboxResult<()> {
        self.ensure_writable()?;
        if self.append.is_some() {
            return Err(MailboxError::Invalid("append already in progress".into()));
        }
        let internal_millis = internal_date
            .unwrap_or_else(SystemTime::now)
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let tmp_path = append_tmp_path(&self.path);
        let tmp_file = File::create(&tmp_path)?;
        self.append = Some(AppendState {
            flags: flags
                .iter()
                .copied()
                .filter(|f| *f != Flag::Recent)
                .collect(),
            internal_millis,
            size: 0,
            tmp_path,
            tmp_file,
        });
        Ok(())
    }

    fn append_content(&mut self, data: &[u8]) -> MailboxResult<()> {
        let a = self
            .append
            .as_mut()
            .ok_or_else(|| MailboxError::Invalid("no append in progress".into()))?;
        a.tmp_file.write_all(data)?;
        a.size += data.len() as u64;
        Ok(())
    }

    fn abort_append(&mut self) -> MailboxResult<()> {
        // Nothing on the live mbox file is touched until `end_append` —
        // dropping the tmp file (which nothing else references yet) is the
        // whole rollback.
        if let Some(a) = self.append.take() {
            drop(a.tmp_file);
            let _ = fs::remove_file(&a.tmp_path);
        }
        Ok(())
    }

    fn end_append(&mut self) -> MailboxResult<u64> {
        self.ensure_writable()?;
        let AppendState {
            flags,
            internal_millis,
            size,
            tmp_path,
            tmp_file,
        } = self
            .append
            .take()
            .ok_or_else(|| MailboxError::Invalid("no append in progress".into()))?;
        tmp_file.sync_all()?;
        drop(tmp_file);

        let content_start_of_file = std::fs::metadata(&self.path)?.len();
        let from_line = format_from_line(SystemTime::now());
        let content_start = content_start_of_file + from_line.len() as u64;

        let mut live = OpenOptions::new().append(true).open(&self.path)?;
        live.write_all(from_line.as_bytes())?;

        let mut escaper = MboxFromEscaper::new();
        let mut hasher = TrimmedSha256::new();
        let mut escaped_written = 0u64;
        let mut ends_with_newline = size > 0;
        {
            let mut tmp_read = File::open(&tmp_path)?;
            let mut raw_buf = [0u8; 8192];
            let mut out = Vec::with_capacity(8192);
            loop {
                let n = tmp_read.read(&mut raw_buf)?;
                if n == 0 {
                    break;
                }
                let chunk = &raw_buf[..n];
                hasher.feed(chunk);
                ends_with_newline = chunk[n - 1] == b'\n';
                out.clear();
                escaper.feed(chunk, &mut out);
                if !out.is_empty() {
                    live.write_all(&out)?;
                    escaped_written += out.len() as u64;
                }
            }
        }
        let mut out = Vec::new();
        escaper.finish(&mut out);
        if !out.is_empty() {
            live.write_all(&out)?;
            escaped_written += out.len() as u64;
        }
        if !ends_with_newline {
            live.write_all(b"\n")?;
            escaped_written += 1;
        }
        live.sync_all()?;
        drop(live);

        let unique_id = hasher.finish();
        let uid = self.uid_next;
        self.uid_next += 1;
        self.flags.set(&unique_id, flags.clone(), BTreeSet::new());

        let content_end = content_start + escaped_written;
        let location = format!("{content_start}:{content_end}");
        let msg_num = (self.messages.len() + 1) as u32;
        // Index straight from the raw (unescaped) tmp file — still on
        // disk, still bounded, no second whole-buffer pass needed. Only
        // deleted once this (streaming) read is done with it.
        let entry = {
            let tmp_read = File::open(&tmp_path)?;
            IndexBuilder::new(self.index_config.clone()).build_streaming(
                uid,
                msg_num,
                size,
                &location,
                &flags,
                &BTreeSet::new(),
                internal_millis,
                tmp_read,
            )?
        };
        let _ = fs::remove_file(&tmp_path);
        self.index.put(entry);
        self.index.set_uid_next(self.uid_next);

        self.messages.push(MboxMsg {
            start: content_start,
            end: content_end,
            size,
            unique_id,
            uid,
            session_deleted: false,
        });
        Ok(uid)
    }

    fn copy_messages(
        &mut self,
        _message_numbers: &[u32],
        _destination_mailbox: &str,
    ) -> MailboxResult<BTreeMap<u32, u64>> {
        Err(MailboxError::Unsupported("COPY (mbox is a single mailbox)"))
    }

    fn search(&self, criteria: &SearchCriteria) -> MailboxResult<Vec<u32>> {
        self.index.search(
            criteria,
            |uid, needle_lower| {
                let msg = self
                    .messages
                    .iter()
                    .find(|m| m.uid == uid)
                    .ok_or_else(|| MailboxError::NotFound(format!("uid {uid}")))?;
                let mut matcher = crate::search::StreamingSubstringMatcher::new(needle_lower);
                stream_unescaped_range(&self.path, msg.start, msg.end, |chunk| {
                    !matcher.feed(chunk)
                })?;
                Ok(matcher.found())
            },
            |uid, name| {
                let msg = self
                    .messages
                    .iter()
                    .find(|m| m.uid == uid)
                    .ok_or_else(|| MailboxError::NotFound(format!("uid {uid}")))?;
                let mut extractor = crate::search::HeaderExtractor::new();
                stream_unescaped_range(&self.path, msg.start, msg.end, |chunk| {
                    extractor.feed(chunk)
                })?;
                Ok(extractor.value(name))
            },
            |uid| {
                self.messages
                    .iter()
                    .find(|m| m.uid == uid)
                    .map(|m| self.flags.modseq_for(&m.unique_id))
                    .unwrap_or(0)
            },
        )
    }
}

/// A unique tmp-file path alongside `mbox_path` to stream an in-progress
/// append into (mirrors Maildir's own `tmp/` staging convention, adapted
/// for mbox's single-file layout).
fn append_tmp_path(mbox_path: &Path) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut s = mbox_path.as_os_str().to_os_string();
    s.push(format!(".append-tmp-{}-{}-{}", std::process::id(), nanos, n));
    PathBuf::from(s)
}

fn gidx_path_for(mbox: &Path) -> PathBuf {
    let mut s = mbox.as_os_str().to_os_string();
    s.push(".gidx");
    PathBuf::from(s)
}

fn file_uid_validity(path: &Path) -> MailboxResult<u64> {
    let meta = std::fs::metadata(path)?;
    let secs = meta
        .created()
        .or_else(|_| meta.modified())
        .unwrap_or(SystemTime::UNIX_EPOCH)
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(1);
    Ok(secs.max(1))
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(trim_trailing_newlines(data));
    format!("{:x}", h.finalize())
}

fn trim_trailing_newlines(data: &[u8]) -> &[u8] {
    let mut end = data.len();
    while end > 0 && (data[end - 1] == b'\n' || data[end - 1] == b'\r') {
        end -= 1;
    }
    &data[..end]
}

/// Streaming equivalent of `sha256_hex` — bounded `Vec` (at most 2 bytes)
/// held back so trailing `\n`/`\r` bytes at the very end of the fed data
/// can be excluded from the digest, matching `sha256_hex`'s
/// `trim_trailing_newlines`. Differs from it only in the pathological case
/// of more than 2 consecutive trailing newline/CR bytes (accepted —
/// `unique_id` is an internal stability key, not a format others parse).
struct TrimmedSha256 {
    hasher: Sha256,
    holdback: Vec<u8>,
}

impl TrimmedSha256 {
    fn new() -> Self {
        Self {
            hasher: Sha256::new(),
            holdback: Vec::with_capacity(2),
        }
    }

    fn feed(&mut self, chunk: &[u8]) {
        for &b in chunk {
            self.holdback.push(b);
            if self.holdback.len() > 2 {
                self.hasher.update([self.holdback.remove(0)]);
            }
        }
    }

    fn finish(mut self) -> String {
        while matches!(self.holdback.last(), Some(b'\n') | Some(b'\r')) {
            self.holdback.pop();
        }
        self.hasher.update(&self.holdback);
        format!("{:x}", self.hasher.finalize())
    }
}

/// Returns list of (from_line_start, content_start, content_end).
fn scan_mbox(raw: &[u8]) -> Vec<(usize, usize, usize)> {
    let mut starts = Vec::new();
    let mut i = 0usize;
    while i < raw.len() {
        if is_from_line(raw, i) {
            starts.push(i);
            // skip line
            while i < raw.len() && raw[i] != b'\n' {
                i += 1;
            }
            if i < raw.len() {
                i += 1;
            }
            continue;
        }
        i += 1;
    }
    let mut out = Vec::new();
    for (idx, &from_start) in starts.iter().enumerate() {
        let mut content_start = from_start;
        while content_start < raw.len() && raw[content_start] != b'\n' {
            content_start += 1;
        }
        if content_start < raw.len() {
            content_start += 1;
        }
        let content_end = if idx + 1 < starts.len() {
            starts[idx + 1]
        } else {
            raw.len()
        };
        // trim trailing CR/LF
        let mut end = content_end;
        while end > content_start && (raw[end - 1] == b'\n' || raw[end - 1] == b'\r') {
            end -= 1;
        }
        out.push((from_start, content_start, end));
    }
    out
}

fn is_from_line(raw: &[u8], i: usize) -> bool {
    if i > 0 && raw[i - 1] != b'\n' {
        return false;
    }
    raw.get(i..i + 5) == Some(b"From ")
}

fn unescape_from(data: &[u8]) -> Vec<u8> {
    // Only unescape in body (after blank line)
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    let mut in_body = false;
    let mut line_start = true;
    while i < data.len() {
        if !in_body {
            out.push(data[i]);
            if line_start && data[i] == b'\n' {
                // blank line if previous was also newline — detect \n\n
            }
            if i > 0 && data[i] == b'\n' && data[i - 1] == b'\n' {
                in_body = true;
                line_start = true;
                i += 1;
                continue;
            }
            if i > 1 && data[i] == b'\n' && data[i - 1] == b'\r' && data[i - 2] == b'\n' {
                in_body = true;
            }
            line_start = data[i] == b'\n';
            i += 1;
            continue;
        }
        if line_start && data.get(i..).is_some_and(|s| s.starts_with(b">From ")) {
            out.extend_from_slice(b"From ");
            i += 6;
            line_start = false;
            continue;
        }
        let b = data[i];
        out.push(b);
        line_start = b == b'\n';
        i += 1;
    }
    out
}

fn escape_from(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    let mut in_body = false;
    let mut line_start = true;
    while i < data.len() {
        if !in_body {
            out.push(data[i]);
            if i > 0 && data[i] == b'\n' && data[i - 1] == b'\n' {
                in_body = true;
                line_start = true;
                i += 1;
                continue;
            }
            line_start = data[i] == b'\n';
            i += 1;
            continue;
        }
        if line_start && data.get(i..).is_some_and(|s| s.starts_with(b"From ")) {
            out.push(b'>');
        }
        let b = data[i];
        out.push(b);
        line_start = b == b'\n';
        i += 1;
    }
    out
}

/// Header/body-boundary scan shared by [`MboxFromEscaper`] and
/// [`MboxFromUnescaper`] — a blank line (bare `\n` or `\r\n`, zero content
/// bytes) ends the header block. Bounded, byte-at-a-time state; chunk
/// boundaries don't matter.
#[derive(Clone, Copy)]
enum HeaderLineState {
    AtStart,
    SawCr,
    HasContent,
}

struct HeaderBoundaryScanner {
    state: HeaderLineState,
    in_body: bool,
}

impl HeaderBoundaryScanner {
    fn new() -> Self {
        Self {
            state: HeaderLineState::AtStart,
            in_body: false,
        }
    }

    fn feed(&mut self, b: u8) {
        match self.state {
            HeaderLineState::AtStart => {
                if b == b'\n' {
                    self.in_body = true;
                } else if b == b'\r' {
                    self.state = HeaderLineState::SawCr;
                } else {
                    self.state = HeaderLineState::HasContent;
                }
            }
            HeaderLineState::SawCr => {
                if b == b'\n' {
                    self.in_body = true;
                } else {
                    self.state = HeaderLineState::HasContent;
                }
            }
            HeaderLineState::HasContent => {
                if b == b'\n' {
                    self.state = HeaderLineState::AtStart;
                }
            }
        }
    }
}

/// Feed one body byte through a line-prefix match against `target`,
/// emitting `replacement` in place of a full match, or the original
/// bytes otherwise — shared by [`MboxFromEscaper`] (`"From " -> ">From "`)
/// and [`MboxFromUnescaper`] (`">From " -> "From "`). `pending` holds a
/// tentative match in progress (at most `target.len()` bytes — bounded
/// regardless of chunk boundaries).
fn feed_line_prefix_match(
    pending: &mut Vec<u8>,
    at_line_start: &mut bool,
    target: &[u8],
    replacement: &[u8],
    b: u8,
    out: &mut Vec<u8>,
) {
    if *at_line_start || !pending.is_empty() {
        let idx = pending.len();
        if idx < target.len() && b == target[idx] {
            pending.push(b);
            if pending.len() == target.len() {
                out.extend_from_slice(replacement);
                pending.clear();
                *at_line_start = false;
            }
            return;
        }
        out.extend_from_slice(pending);
        pending.clear();
        out.push(b);
        *at_line_start = b == b'\n';
        return;
    }
    out.push(b);
    if b == b'\n' {
        *at_line_start = true;
    }
}

/// Streaming version of `escape_from` (body `"From "` lines -> `">From "`)
/// — fed one chunk at a time, with bounded state carried across calls (no
/// whole-message buffering).
struct MboxFromEscaper {
    header: HeaderBoundaryScanner,
    at_line_start: bool,
    pending: Vec<u8>,
}

impl MboxFromEscaper {
    fn new() -> Self {
        Self {
            header: HeaderBoundaryScanner::new(),
            at_line_start: true,
            pending: Vec::new(),
        }
    }

    fn feed(&mut self, chunk: &[u8], out: &mut Vec<u8>) {
        for &b in chunk {
            if !self.header.in_body {
                out.push(b);
                self.header.feed(b);
            } else {
                feed_line_prefix_match(
                    &mut self.pending,
                    &mut self.at_line_start,
                    b"From ",
                    b">From ",
                    b,
                    out,
                );
            }
        }
    }

    /// Flush any bytes still held back at end-of-message (an incomplete,
    /// never-matched `"From "` prefix at EOF didn't match — emit verbatim).
    fn finish(&mut self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.pending);
        self.pending.clear();
    }
}

/// Streaming version of `unescape_from` (body `">From "` -> `"From "`).
struct MboxFromUnescaper {
    header: HeaderBoundaryScanner,
    at_line_start: bool,
    pending: Vec<u8>,
}

impl MboxFromUnescaper {
    fn new() -> Self {
        Self {
            header: HeaderBoundaryScanner::new(),
            at_line_start: true,
            pending: Vec::new(),
        }
    }

    fn feed(&mut self, chunk: &[u8], out: &mut Vec<u8>) {
        for &b in chunk {
            if !self.header.in_body {
                out.push(b);
                self.header.feed(b);
            } else {
                feed_line_prefix_match(
                    &mut self.pending,
                    &mut self.at_line_start,
                    b">From ",
                    b"From ",
                    b,
                    out,
                );
            }
        }
    }

    fn finish(&mut self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.pending);
        self.pending.clear();
    }
}

/// Stream the raw byte range `[start, end)` of `path`, un-escaping
/// `">From "` body lines on the fly, handing each unescaped chunk to
/// `on_chunk` — never materializes the message whole. `on_chunk` returning
/// `false` stops the read early (the rest of the range is skipped).
fn stream_unescaped_range(
    path: &Path,
    start: u64,
    end: u64,
    mut on_chunk: impl FnMut(&[u8]) -> bool,
) -> MailboxResult<()> {
    let mut f = File::open(path)?;
    f.seek(SeekFrom::Start(start))?;
    let mut remaining = end.saturating_sub(start);
    let mut unescaper = MboxFromUnescaper::new();
    let mut raw_buf = [0u8; 8192];
    let mut out = Vec::with_capacity(8192);
    while remaining > 0 {
        let want = (raw_buf.len() as u64).min(remaining) as usize;
        let n = f.read(&mut raw_buf[..want])?;
        if n == 0 {
            break;
        }
        remaining -= n as u64;
        out.clear();
        unescaper.feed(&raw_buf[..n], &mut out);
        if !out.is_empty() && !on_chunk(&out) {
            return Ok(());
        }
    }
    out.clear();
    unescaper.finish(&mut out);
    if !out.is_empty() {
        on_chunk(&out);
    }
    Ok(())
}

fn write_mbox_message(out: &mut Vec<u8>, rfc822: &[u8], when: SystemTime) -> MailboxResult<()> {
    let line = format_from_line(when);
    out.extend_from_slice(line.as_bytes());
    out.extend_from_slice(&escape_from(rfc822));
    if !rfc822.ends_with(b"\n") {
        out.push(b'\n');
    }
    Ok(())
}

fn format_from_line(when: SystemTime) -> String {
    // Approximate: From MAILER-DAEMON@localhost {ctime-like}
    let secs = when
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    // Use a simple UTC formatting without chrono.
    let (y, m, d, hh, mm, ss, wday) = civil_parts(secs);
    let mon = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ][m as usize - 1];
    let wd = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"][wday as usize];
    format!("From MAILER-DAEMON@localhost {wd} {mon} {d:2} {hh:02}:{mm:02}:{ss:02} {y}\n")
}

fn civil_parts(secs: i64) -> (i32, u32, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400) as u32;
    let hh = tod / 3600;
    let mm = (tod % 3600) / 60;
    let ss = tod % 60;
    let (y, m, d) = crate_civil(days);
    // 1970-01-01 was Thursday = 4
    let wday = ((days + 4).rem_euclid(7)) as u32;
    (y, m, d, hh, mm, ss, wday)
}

fn crate_civil(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{MailboxFactory, MessageReadCallback};
    use crate::MboxFactory;
    use tempfile::tempdir;

    /// Test-only whole-message append, via the real streaming push triad
    /// ([`crate::traits::AppendGuard`]) — never bypasses it.
    fn append_whole(
        mb: &mut dyn Mailbox,
        data: &[u8],
        flags: &BTreeSet<Flag>,
        internal_date: Option<SystemTime>,
    ) -> MailboxResult<u64> {
        let mut guard = crate::traits::AppendGuard::start(mb, flags, internal_date)?;
        guard.append_content(data)?;
        guard.commit()
    }

    #[derive(Default)]
    struct VecReadCallback(Vec<u8>);
    impl MessageReadCallback for VecReadCallback {
        fn message_content(&mut self, chunk: &[u8]) -> bool {
            self.0.extend_from_slice(chunk);
            true
        }
    }

    /// Test-only whole-message read, via the real streaming
    /// [`Mailbox::read_message`] callback — never bypasses it.
    fn read_whole(mb: &mut dyn Mailbox, message_number: u32) -> MailboxResult<Vec<u8>> {
        let mut cb = VecReadCallback::default();
        mb.read_message(message_number, &mut cb)?;
        Ok(cb.0)
    }

    #[test]
    fn open_creates_dotlock_and_drop_removes_it() {
        let dir = tempdir().unwrap();
        let factory = MboxFactory::new(dir.path());
        let mut store = factory.create_store();
        store.open("dotlockuser").unwrap();
        let mbox_path = dir.path().join("dotlockuser");
        let mut lock_os = mbox_path.as_os_str().to_os_string();
        lock_os.push(".lock");
        let lock_path = PathBuf::from(lock_os);

        assert!(!lock_path.exists());
        let mb = store.open_mailbox("INBOX", false).unwrap();
        assert!(
            lock_path.exists(),
            "dotlock file should exist while the mailbox is open"
        );
        drop(mb);
        assert!(
            !lock_path.exists(),
            "dotlock file should be removed once the mailbox is dropped"
        );
    }

    #[test]
    fn abort_append_discards_the_buffer_and_leaves_no_message() {
        let dir = tempdir().unwrap();
        let factory = MboxFactory::new(dir.path());
        let mut store = factory.create_store();
        store.open("abortuser").unwrap();
        let mut mb = store.open_mailbox("INBOX", false).unwrap();

        mb.start_append(&BTreeSet::new(), None).unwrap();
        mb.append_content(b"From: a@b\r\n\r\npartial, never finished").unwrap();
        mb.abort_append().unwrap();

        assert_eq!(mb.message_count().unwrap(), 0, "aborted append must not deliver a message");

        // Immediately reusable for a fresh append afterward.
        let msg = b"From: a@b\r\nTo: c@d\r\nSubject: after-abort\r\n\r\nbody\r\n";
        let uid = append_whole(mb.as_mut(), msg, &BTreeSet::new(), None).unwrap();
        assert!(uid > 0);
        assert_eq!(mb.message_count().unwrap(), 1);
        mb.close(false).unwrap();
    }

    #[test]
    fn read_round_trips_a_body_line_that_looks_like_a_from_line() {
        let dir = tempdir().unwrap();
        let factory = MboxFactory::new(dir.path());
        let mut store = factory.create_store();
        store.open("fromlineuser").unwrap();
        let mut mb = store.open_mailbox("INBOX", false).unwrap();

        let msg = b"From: a@b\r\nSubject: x\r\n\r\nFrom the desk of someone\r\nplain line\r\n";
        append_whole(mb.as_mut(), msg, &BTreeSet::new(), None).unwrap();

        let got = read_whole(mb.as_mut(), 1).unwrap();
        assert_eq!(
            got, &msg[..],
            "a body line starting with \"From \" must round-trip byte-identical \
             through escape-on-write / unescape-on-read"
        );
        mb.close(false).unwrap();
    }

    #[test]
    fn read_round_trips_regardless_of_append_chunk_size() {
        let dir = tempdir().unwrap();
        let factory = MboxFactory::new(dir.path());
        let mut store = factory.create_store();
        store.open("chunkuser").unwrap();
        let mut mb = store.open_mailbox("INBOX", false).unwrap();

        let msg = b"From: a@b\r\nSubject: chunked\r\n\r\nFrom here to there\r\nsecond line\r\n";
        for chunk_size in [1usize, 2, 3, 7, 64] {
            mb.start_append(&BTreeSet::new(), None).unwrap();
            for chunk in msg.chunks(chunk_size) {
                mb.append_content(chunk).unwrap();
            }
            let uid = mb.end_append().unwrap();
            let seq = mb
                .messages()
                .unwrap()
                .into_iter()
                .find(|d| d.uid == Some(uid))
                .unwrap()
                .message_number;
            let got = read_whole(mb.as_mut(), seq).unwrap();
            assert_eq!(got, &msg[..], "chunk_size={chunk_size}");
        }
        mb.close(false).unwrap();
    }

    #[test]
    fn abort_append_with_nothing_in_progress_is_a_safe_no_op() {
        let dir = tempdir().unwrap();
        let factory = MboxFactory::new(dir.path());
        let mut store = factory.create_store();
        store.open("noopabortuser").unwrap();
        let mut mb = store.open_mailbox("INBOX", false).unwrap();
        assert!(mb.abort_append().is_ok());
        mb.close(false).unwrap();
    }

    #[test]
    fn modseq_increases_on_append_and_on_flag_change() {
        let dir = tempdir().unwrap();
        let factory = MboxFactory::new(dir.path());
        let mut store = factory.create_store();
        store.open("mboxmodsequser").unwrap();
        let mut mb = store.open_mailbox("INBOX", false).unwrap();

        append_whole(mb.as_mut(), b"From: a@b\r\nSubject: a\r\n\r\nbody a\r\n", &BTreeSet::new(), None).unwrap();
        append_whole(mb.as_mut(), b"From: a@b\r\nSubject: b\r\n\r\nbody b\r\n", &BTreeSet::new(), None).unwrap();
        assert_eq!(mb.modseq(1).unwrap(), 1);
        assert_eq!(mb.modseq(2).unwrap(), 2);
        assert_eq!(mb.highest_modseq(), 2);

        let mut seen = BTreeSet::new();
        seen.insert(Flag::Seen);
        mb.set_flags(1, &seen, true).unwrap();
        assert_eq!(mb.modseq(1).unwrap(), 3, "flag change must bump modseq");
        assert_eq!(mb.modseq(2).unwrap(), 2, "unrelated message untouched");
        assert_eq!(mb.highest_modseq(), 3);

        mb.close(false).unwrap();
    }

    #[test]
    fn mbox_changed_since_reports_only_messages_modified_after_the_given_modseq() {
        let dir = tempdir().unwrap();
        let factory = MboxFactory::new(dir.path());
        let mut store = factory.create_store();
        store.open("mboxchangeduser").unwrap();
        let mut mb = store.open_mailbox("INBOX", false).unwrap();

        append_whole(mb.as_mut(), b"From: a@b\r\nSubject: a\r\n\r\nbody a\r\n", &BTreeSet::new(), None).unwrap(); // uid 1
        append_whole(mb.as_mut(), b"From: a@b\r\nSubject: b\r\n\r\nbody b\r\n", &BTreeSet::new(), None).unwrap(); // uid 2
        let baseline = mb.highest_modseq();

        let mut flagged = BTreeSet::new();
        flagged.insert(Flag::Flagged);
        mb.set_flags(2, &flagged, true).unwrap(); // uid 2 -> new modseq

        let changed = mb.changed_since(baseline).unwrap();
        assert_eq!(changed, vec![2]);
        assert!(mb.changed_since(mb.highest_modseq()).unwrap().is_empty());
        assert_eq!(mb.changed_since(0).unwrap().len(), 2);

        mb.close(false).unwrap();
    }

    #[test]
    fn mbox_highest_modseq_survives_a_close_and_reopen() {
        let dir = tempdir().unwrap();
        let factory = MboxFactory::new(dir.path());
        let mut store = factory.create_store();
        store.open("mboxpersistuser").unwrap();
        let mut mb = store.open_mailbox("INBOX", false).unwrap();
        append_whole(mb.as_mut(), b"From: a@b\r\nSubject: a\r\n\r\nbody a\r\n", &BTreeSet::new(), None).unwrap();
        let mut flagged = BTreeSet::new();
        flagged.insert(Flag::Flagged);
        mb.set_flags(1, &flagged, true).unwrap();
        assert_eq!(mb.highest_modseq(), 2);
        mb.close(false).unwrap();
        drop(mb);

        let mb2 = store.open_mailbox("INBOX", false).unwrap();
        assert_eq!(
            mb2.highest_modseq(),
            2,
            "HIGHESTMODSEQ must be durable across a reopen, not reset to 0"
        );
        assert_eq!(mb2.modseq(1).unwrap(), 2);
    }
}
