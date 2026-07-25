// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Single-file mbox mailbox.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use md5::{Digest, Md5};

use crate::config::IndexConfig;
use crate::error::{MailboxError, MailboxResult};
use crate::flag::Flag;
use crate::index::{IndexBuilder, MessageIndex};
use crate::search::SearchCriteria;
use crate::traits::{Mailbox, MessageDescriptor};

use super::flags::MboxFlagsFile;
use super::lock::FileLock;

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
    messages: Vec<MboxMsg>,
    flags: MboxFlagsFile,
    index: MessageIndex,
    uid_validity: u64,
    uid_next: u64,
    append: Option<AppendState>,
    index_config: IndexConfig,
}

struct AppendState {
    flags: BTreeSet<Flag>,
    internal_millis: i64,
    buf: Vec<u8>,
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
            .unwrap_or_else(|| MessageIndex::new(&gidx_path, uid_validity, 1, index_config.clone()));

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
            let unique_id = md5_hex(&slice);
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
                || index.get(uid).is_some_and(|e| e.prop(0) != loc_key.as_str())
            {
                let entry = builder.build(
                    uid,
                    (i + 1) as u32,
                    size,
                    &location,
                    &sys,
                    &kw,
                    0,
                    &slice,
                );
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
            let unique_id = md5_hex(&slice);
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
            let any = self.messages.iter().any(|m| {
                m.session_deleted || self.flags.get(&m.unique_id).0.contains(&Flag::Deleted)
            });
            if any {
                self.rewrite_expunge()?;
            }
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
        Ok(self
            .messages
            .iter()
            .filter(|m| !m.session_deleted)
            .count() as u32)
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

    fn read_message(&self, message_number: u32) -> MailboxResult<Vec<u8>> {
        let msg = self.msg(message_number)?;
        if msg.session_deleted {
            return Err(MailboxError::NotFound(format!("message {message_number}")));
        }
        self.read_raw(msg)
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

    fn replace_flags(
        &mut self,
        message_number: u32,
        flags: &BTreeSet<Flag>,
    ) -> MailboxResult<()> {
        self.ensure_writable()?;
        let uid = self.msg(message_number)?.uid;
        let unique_id = self.msg(message_number)?.unique_id.clone();
        let (_, kw) = self.flags.get(&unique_id);
        let cur: BTreeSet<Flag> = flags.iter().copied().filter(|f| *f != Flag::Recent).collect();
        self.flags.set(&unique_id, cur.clone(), kw);
        self.index.set_flags(uid, &cur);
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
        self.append = Some(AppendState {
            flags: flags.iter().copied().filter(|f| *f != Flag::Recent).collect(),
            internal_millis,
            buf: Vec::new(),
        });
        Ok(())
    }

    fn append_content(&mut self, data: &[u8]) -> MailboxResult<()> {
        let a = self
            .append
            .as_mut()
            .ok_or_else(|| MailboxError::Invalid("no append in progress".into()))?;
        a.buf.extend_from_slice(data);
        Ok(())
    }

    fn end_append(&mut self) -> MailboxResult<u64> {
        self.ensure_writable()?;
        let AppendState {
            flags,
            internal_millis,
            buf,
        } = self
            .append
            .take()
            .ok_or_else(|| MailboxError::Invalid("no append in progress".into()))?;

        let mut out = Vec::new();
        write_mbox_message(&mut out, &buf, SystemTime::now())?;
        {
            let mut f = OpenOptions::new().append(true).open(&self.path)?;
            f.write_all(&out)?;
            f.sync_all()?;
        }

        let unique_id = md5_hex(&buf);
        let uid = self.uid_next;
        self.uid_next += 1;
        self.flags
            .set(&unique_id, flags.clone(), BTreeSet::new());

        let start = {
            let meta = std::fs::metadata(&self.path)?;
            meta.len().saturating_sub(out.len() as u64)
        };
        // Approximate content start after From_ line
        let from_line_end = out.iter().position(|&b| b == b'\n').map(|i| i + 1).unwrap_or(0);
        let content_start = start + from_line_end as u64;
        let content_end = start + out.len() as u64;
        let location = format!("{}:{}", content_start, content_end);
        let msg_num = (self.messages.len() + 1) as u32;
        let entry = IndexBuilder::new(self.index_config.clone()).build(
            uid,
            msg_num,
            buf.len() as u64,
            &location,
            &flags,
            &BTreeSet::new(),
            internal_millis,
            &buf,
        );
        self.index.put(entry);
        self.index.set_uid_next(self.uid_next);

        self.messages.push(MboxMsg {
            start: content_start,
            end: content_end,
            size: buf.len() as u64,
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
        Err(MailboxError::Unsupported(
            "COPY (mbox is a single mailbox)",
        ))
    }

    fn search(&self, criteria: &SearchCriteria) -> MailboxResult<Vec<u32>> {
        self.index.search(criteria, |uid| {
            let msg = self
                .messages
                .iter()
                .find(|m| m.uid == uid)
                .ok_or_else(|| MailboxError::NotFound(format!("uid {uid}")))?;
            let raw = self.read_raw(msg)?;
            Ok(String::from_utf8_lossy(&raw).to_ascii_lowercase())
        })
    }
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

fn md5_hex(data: &[u8]) -> String {
    let mut h = Md5::new();
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
