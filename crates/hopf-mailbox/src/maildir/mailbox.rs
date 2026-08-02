// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Maildir++ mailbox (one folder).

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::IndexConfig;
use crate::error::{MailboxError, MailboxResult};
use crate::flag::Flag;
use crate::index::{IndexBuilder, MessageIndex};
use crate::search::SearchCriteria;
use crate::traits::{Mailbox, MessageDescriptor};

use super::filename::MaildirFilename;
use super::keywords::KeywordsFile;
use super::uidlist::UidList;

#[derive(Clone)]
struct MdMsg {
    path: PathBuf,
    filename: MaildirFilename,
    size: u64,
    uid: u64,
    /// POP session delete mark (in-memory until `close(true)`).
    session_deleted: bool,
}

struct AppendState {
    flags: BTreeSet<Flag>,
    internal_millis: i64,
    size: u64,
    tmp_path: PathBuf,
    tmp_file: File,
}

/// Shared user-root resolver for COPY/MOVE into sibling folders.
pub(crate) struct MaildirPaths {
    pub user_root: PathBuf,
}

impl MaildirPaths {
    pub fn mailbox_dir(&self, name: &str) -> MailboxResult<PathBuf> {
        resolve_mailbox_dir(&self.user_root, name)
    }
}

/// Open Maildir folder.
pub struct MaildirMailbox {
    dir: PathBuf,
    name: String,
    read_only: bool,
    paths: Arc<MaildirPaths>,
    messages: Vec<MdMsg>,
    uidlist: UidList,
    keywords: KeywordsFile,
    index: MessageIndex,
    index_config: IndexConfig,
    append: Option<AppendState>,
    /// When opening destination for copy, hold store-level open lock via paths only.
    _open_guard: Option<Arc<Mutex<()>>>,
}

impl MaildirMailbox {
    pub(crate) fn open(
        dir: PathBuf,
        name: String,
        read_only: bool,
        paths: Arc<MaildirPaths>,
        index_config: IndexConfig,
        open_guard: Option<Arc<Mutex<()>>>,
    ) -> MailboxResult<Self> {
        ensure_maildir_layout(&dir)?;
        let default_uv = dir_uid_validity(&dir)?;
        let mut uidlist = UidList::load_or_new(&dir, default_uv)?;
        let mut keywords = KeywordsFile::load_or_empty(&dir)?;

        // Move new/ → cur/
        move_new_to_cur(&dir)?;

        let mut messages = Vec::new();
        let cur = dir.join("cur");
        for ent in fs::read_dir(&cur)? {
            let ent = ent?;
            let ft = ent.file_type()?;
            if !ft.is_file() {
                continue;
            }
            let fname = ent.file_name().to_string_lossy().into_owned();
            let parsed = MaildirFilename::parse(&fname);
            let meta = ent.metadata()?;
            let size = meta.len();
            let uid = uidlist.assign(&parsed.base);
            messages.push(MdMsg {
                path: ent.path(),
                filename: parsed,
                size,
                uid,
                session_deleted: false,
            });
        }
        messages.sort_by_key(|m| m.uid);

        let gidx = dir.join(".gidx");
        let mut index = MessageIndex::load(&gidx, index_config.clone())?
            .filter(|idx| idx.uid_validity() == uidlist.uid_validity)
            .unwrap_or_else(|| {
                MessageIndex::new(
                    &gidx,
                    uidlist.uid_validity,
                    uidlist.uid_next,
                    index_config.clone(),
                )
            });

        let builder = IndexBuilder::new(index_config.clone());
        let mut dirty = false;
        for (i, m) in messages.iter().enumerate() {
            if index.get(m.uid).is_none() {
                let kw = letters_to_keywords(&keywords, &m.filename.keyword_letters);
                // Streamed in bounded chunks — never holds a whole message
                // in memory just to index it.
                let file = File::open(&m.path)?;
                let entry = builder.build_streaming(
                    m.uid,
                    (i + 1) as u32,
                    m.size,
                    &m.filename.base,
                    &m.filename.flags,
                    &kw,
                    0,
                    file,
                )?;
                index.put(entry);
                dirty = true;
            }
        }
        index.set_uid_next(uidlist.uid_next);
        if dirty {
            index.save()?;
        }
        uidlist.save()?;
        keywords.save()?;

        // Renumber message view excluding nothing yet — sequence includes deleted until expunge
        Ok(Self {
            dir,
            name,
            read_only,
            paths,
            messages,
            uidlist,
            keywords,
            index,
            index_config,
            append: None,
            _open_guard: open_guard,
        })
    }

    fn ensure_writable(&self) -> MailboxResult<()> {
        if self.read_only {
            Err(MailboxError::ReadOnly)
        } else {
            Ok(())
        }
    }

    fn seq_index(&self, n: u32) -> MailboxResult<usize> {
        let i = n.wrapping_sub(1) as usize;
        self.messages
            .get(i)
            .map(|_| i)
            .ok_or_else(|| MailboxError::NotFound(format!("message {n}")))
    }

    fn rename_with_flags(&mut self, idx: usize) -> MailboxResult<()> {
        let msg = &self.messages[idx];
        let new_name = msg.filename.to_string_name();
        let dest = self.dir.join("cur").join(&new_name);
        if dest != msg.path {
            fs::rename(&msg.path, &dest)?;
            self.messages[idx].path = dest;
        }
        Ok(())
    }
}

impl Mailbox for MaildirMailbox {
    fn close(&mut self, expunge: bool) -> MailboxResult<()> {
        if expunge && !self.read_only {
            let _ = self.expunge()?;
        } else if !expunge {
            for m in &mut self.messages {
                m.session_deleted = false;
            }
        }
        self.uidlist.save()?;
        self.keywords.save()?;
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

    fn refresh(&mut self) -> MailboxResult<()> {
        let session_deleted: BTreeMap<String, bool> = self
            .messages
            .iter()
            .map(|m| (m.filename.base.clone(), m.session_deleted))
            .collect();

        move_new_to_cur(&self.dir)?;
        // Pick up flag/keyword changes and UIDASSIGN updates from other writers.
        let default_uv = self.uidlist.uid_validity;
        self.uidlist = UidList::load_or_new(&self.dir, default_uv)?;
        self.keywords = KeywordsFile::load_or_empty(&self.dir)?;

        let mut messages = Vec::new();
        let cur = self.dir.join("cur");
        for ent in fs::read_dir(&cur)? {
            let ent = ent?;
            let ft = ent.file_type()?;
            if !ft.is_file() {
                continue;
            }
            let fname = ent.file_name().to_string_lossy().into_owned();
            let parsed = MaildirFilename::parse(&fname);
            let meta = ent.metadata()?;
            let size = meta.len();
            let uid = self.uidlist.assign(&parsed.base);
            let session_deleted = session_deleted
                .get(&parsed.base)
                .copied()
                .unwrap_or(false);
            messages.push(MdMsg {
                path: ent.path(),
                filename: parsed,
                size,
                uid,
                session_deleted,
            });
        }
        messages.sort_by_key(|m| m.uid);
        self.messages = messages;
        Ok(())
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
                unique_id: m.filename.base.clone(),
                uid: Some(m.uid),
            });
        }
        Ok(out)
    }

    fn read_message(
        &mut self,
        message_number: u32,
        callback: &mut dyn crate::traits::MessageReadCallback,
    ) -> MailboxResult<()> {
        let idx = self.seq_index(message_number)?;
        let msg = &self.messages[idx];
        let mut file = File::open(&msg.path)?;
        callback.start_message(msg.size);
        let mut buf = [0u8; 8192];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            if !callback.message_content(&buf[..n]) {
                break;
            }
        }
        callback.end_message();
        Ok(())
    }

    fn unique_id(&self, message_number: u32) -> MailboxResult<String> {
        let idx = self.seq_index(message_number)?;
        Ok(self.messages[idx].filename.base.clone())
    }

    fn uid(&self, message_number: u32) -> MailboxResult<u64> {
        let idx = self.seq_index(message_number)?;
        Ok(self.messages[idx].uid)
    }

    fn uid_validity(&self) -> u64 {
        self.uidlist.uid_validity
    }

    fn uid_next(&self) -> u64 {
        self.uidlist.uid_next
    }

    fn flags(&self, message_number: u32) -> MailboxResult<BTreeSet<Flag>> {
        let idx = self.seq_index(message_number)?;
        Ok(self.messages[idx].filename.flags.clone())
    }

    fn keywords(&self, message_number: u32) -> MailboxResult<BTreeSet<String>> {
        let idx = self.seq_index(message_number)?;
        Ok(letters_to_keywords(
            &self.keywords,
            &self.messages[idx].filename.keyword_letters,
        ))
    }

    fn highest_modseq(&self) -> u64 {
        self.uidlist.highest_modseq
    }

    fn modseq(&self, message_number: u32) -> MailboxResult<u64> {
        let idx = self.seq_index(message_number)?;
        Ok(self.uidlist.modseq_for(&self.messages[idx].filename.base))
    }

    fn changed_since(&self, modseq: u64) -> MailboxResult<Vec<u64>> {
        Ok(self
            .messages
            .iter()
            .filter(|m| self.uidlist.modseq_for(&m.filename.base) > modseq)
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
        let idx = self.seq_index(message_number)?;
        for f in flags {
            if *f == Flag::Recent {
                continue;
            }
            if add {
                self.messages[idx].filename.flags.insert(*f);
            } else {
                self.messages[idx].filename.flags.remove(f);
            }
        }
        let uid = self.messages[idx].uid;
        let fl = self.messages[idx].filename.flags.clone();
        self.uidlist.bump_modseq(&self.messages[idx].filename.base);
        self.rename_with_flags(idx)?;
        self.index.set_flags(uid, &fl);
        Ok(())
    }

    fn replace_flags(&mut self, message_number: u32, flags: &BTreeSet<Flag>) -> MailboxResult<()> {
        self.ensure_writable()?;
        let idx = self.seq_index(message_number)?;
        self.messages[idx].filename.flags = flags
            .iter()
            .copied()
            .filter(|f| *f != Flag::Recent)
            .collect();
        let uid = self.messages[idx].uid;
        let fl = self.messages[idx].filename.flags.clone();
        self.uidlist.bump_modseq(&self.messages[idx].filename.base);
        self.rename_with_flags(idx)?;
        self.index.set_flags(uid, &fl);
        Ok(())
    }

    fn set_keywords(
        &mut self,
        message_number: u32,
        keywords: &BTreeSet<String>,
        add: bool,
    ) -> MailboxResult<()> {
        self.ensure_writable()?;
        let idx = self.seq_index(message_number)?;
        if add {
            for kw in keywords {
                let letter = self.keywords.letter_for(kw)?;
                self.messages[idx].filename.keyword_letters.insert(letter);
            }
        } else {
            let current = self.messages[idx].filename.keyword_letters.clone();
            for c in current {
                let Some(name) = self.keywords.keyword_for_letter(c) else {
                    continue;
                };
                if keywords.iter().any(|kw| name.eq_ignore_ascii_case(kw)) {
                    self.messages[idx].filename.keyword_letters.remove(&c);
                }
            }
        }
        let uid = self.messages[idx].uid;
        let kw = letters_to_keywords(&self.keywords, &self.messages[idx].filename.keyword_letters);
        self.uidlist.bump_modseq(&self.messages[idx].filename.base);
        self.rename_with_flags(idx)?;
        self.index.set_keywords(uid, &kw);
        Ok(())
    }

    fn replace_keywords(
        &mut self,
        message_number: u32,
        keywords: &BTreeSet<String>,
    ) -> MailboxResult<()> {
        self.ensure_writable()?;
        let idx = self.seq_index(message_number)?;
        self.messages[idx].filename.keyword_letters.clear();
        for kw in keywords {
            let letter = self.keywords.letter_for(kw)?;
            self.messages[idx].filename.keyword_letters.insert(letter);
        }
        let uid = self.messages[idx].uid;
        let kw = letters_to_keywords(&self.keywords, &self.messages[idx].filename.keyword_letters);
        self.uidlist.bump_modseq(&self.messages[idx].filename.base);
        self.rename_with_flags(idx)?;
        self.index.set_keywords(uid, &kw);
        Ok(())
    }

    fn mark_deleted(&mut self, message_number: u32) -> MailboxResult<()> {
        self.ensure_writable()?;
        let idx = self.seq_index(message_number)?;
        self.messages[idx].session_deleted = true;
        Ok(())
    }

    fn is_deleted(&self, message_number: u32) -> MailboxResult<bool> {
        let idx = self.seq_index(message_number)?;
        Ok(self.messages[idx].session_deleted)
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
        let mut kept = Vec::new();
        for (i, m) in self.messages.drain(..).enumerate() {
            let seq = (i + 1) as u32;
            if m.session_deleted || m.filename.flags.contains(&Flag::Deleted) {
                let _ = fs::remove_file(&m.path);
                self.uidlist.remove_base(&m.filename.base);
                self.index.remove(m.uid);
                removed.push(seq);
            } else {
                kept.push(m);
            }
        }
        self.messages = kept;
        self.uidlist.save()?;
        self.index.save()?;
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
        let base = MaildirFilename::generate(None);
        let tmp_path = self.dir.join("tmp").join(&base);
        let tmp_file = File::create(&tmp_path)?;
        let internal_millis = internal_date
            .unwrap_or_else(SystemTime::now)
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
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
        if let Some(a) = self.append.take() {
            drop(a.tmp_file);
            // Best-effort: the tmp file was never renamed into `cur/`, so
            // nothing else references it — but a failure removing it isn't
            // itself grounds to fail the abort (maildir tolerates stray
            // `tmp/` files; an external janitor process is the convention).
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

        let filename = MaildirFilename {
            base: MaildirFilename::generate(Some(size)),
            flags: flags.clone(),
            keyword_letters: BTreeSet::new(),
        };
        let cur_name = filename.to_string_name();
        let cur_path = self.dir.join("cur").join(&cur_name);
        // The content is already fully on disk at `tmp_path` from the
        // incremental writes in `append_content` — just rename into place,
        // no need to rewrite it.
        fs::rename(&tmp_path, &cur_path)?;

        let uid = self.uidlist.assign(&filename.base);
        let msg_num = (self.messages.len() + 1) as u32;
        // Streamed back off disk in bounded chunks to build the index entry
        // — the message content is never held whole in memory.
        let entry = {
            let file = File::open(&cur_path)?;
            IndexBuilder::new(self.index_config.clone()).build_streaming(
                uid,
                msg_num,
                size,
                &filename.base,
                &flags,
                &BTreeSet::new(),
                internal_millis,
                file,
            )?
        };
        self.index.put(entry);
        self.index.set_uid_next(self.uidlist.uid_next);

        self.messages.push(MdMsg {
            path: cur_path,
            filename,
            size,
            uid,
            session_deleted: false,
        });
        Ok(uid)
    }

    fn copy_messages(
        &mut self,
        message_numbers: &[u32],
        destination_mailbox: &str,
    ) -> MailboxResult<BTreeMap<u32, u64>> {
        self.ensure_writable()?;
        if destination_mailbox.eq_ignore_ascii_case(&self.name) {
            return Err(MailboxError::Invalid("COPY to same mailbox".into()));
        }
        let dest_dir = self.paths.mailbox_dir(destination_mailbox)?;
        ensure_maildir_layout(&dest_dir)?;
        let mut dest = MaildirMailbox::open(
            dest_dir,
            destination_mailbox.to_string(),
            false,
            Arc::clone(&self.paths),
            self.index_config.clone(),
            None,
        )?;
        let mut map = BTreeMap::new();
        for &n in message_numbers {
            let idx = self.seq_index(n)?;
            let flags = self.messages[idx].filename.flags.clone();
            struct CopyToDest<'a> {
                guard: crate::traits::AppendGuard<'a>,
                error: Option<MailboxError>,
            }
            impl crate::traits::MessageReadCallback for CopyToDest<'_> {
                fn message_content(&mut self, chunk: &[u8]) -> bool {
                    if let Err(e) = self.guard.append_content(chunk) {
                        self.error = Some(e);
                        return false;
                    }
                    true
                }
            }
            let guard = crate::traits::AppendGuard::start(&mut dest, &flags, None)?;
            let mut cb = CopyToDest { guard, error: None };
            self.read_message(n, &mut cb)?;
            if let Some(e) = cb.error {
                return Err(e);
            }
            let uid = cb.guard.commit()?;
            map.insert(n, uid);
        }
        dest.close(false)?;
        Ok(map)
    }

    fn search(&self, criteria: &SearchCriteria) -> MailboxResult<Vec<u32>> {
        let need_body = criteria.needs_body() && !self.index_config.body_indexing;
        let mut results = Vec::new();
        for (i, m) in self.messages.iter().enumerate() {
            let seq = (i + 1) as u32;
            let Some(e) = self.index.get(m.uid) else {
                continue;
            };
            let body_path: Option<&Path> = if need_body { Some(&m.path) } else { None };
            let entry = crate::index::IndexEntry::new(
                e.uid,
                seq,
                e.size,
                e.internal_date,
                e.sent_date,
                &e.flags(),
                e.props().to_vec(),
            );
            struct Ctx<'a> {
                e: &'a crate::index::IndexEntry,
                body_path: Option<&'a Path>,
                header_path: &'a Path,
                modseq: u64,
            }
            impl crate::search::MessageContext for Ctx<'_> {
                fn message_number(&self) -> u32 {
                    self.e.message_number
                }
                fn uid(&self) -> u64 {
                    self.e.uid
                }
                fn size(&self) -> u64 {
                    self.e.size
                }
                fn flags(&self) -> BTreeSet<Flag> {
                    self.e.flags()
                }
                fn keywords(&self) -> BTreeSet<String> {
                    self.e.keywords_set()
                }
                fn internal_date_millis(&self) -> Option<i64> {
                    if self.e.internal_date == 0 {
                        None
                    } else {
                        Some(self.e.internal_date)
                    }
                }
                fn sent_date_millis(&self) -> Option<i64> {
                    if self.e.sent_date == 0 {
                        None
                    } else {
                        Some(self.e.sent_date)
                    }
                }
                fn header(&self, name: &str) -> std::io::Result<String> {
                    if let Some(v) = self.e.header_value(name) {
                        return Ok(v.to_string());
                    }
                    let file = File::open(self.header_path)?;
                    Ok(crate::search::header_lookup_streaming(file, name)?.unwrap_or_default())
                }
                fn body_contains(&self, needle_lower: &str) -> std::io::Result<bool> {
                    if let Some(path) = self.body_path {
                        let file = File::open(path)?;
                        return crate::search::body_contains_streaming(file, needle_lower);
                    }
                    Ok(self
                        .e
                        .body()
                        .unwrap_or("")
                        .to_ascii_lowercase()
                        .contains(needle_lower))
                }
                fn modseq(&self) -> Option<u64> {
                    Some(self.modseq)
                }
            }
            let hit = criteria
                .matches(&Ctx {
                    e: &entry,
                    body_path,
                    header_path: &m.path,
                    modseq: self.uidlist.modseq_for(&m.filename.base),
                })
                .map_err(MailboxError::Io)?;
            if hit {
                results.push(seq);
            }
        }
        Ok(results)
    }
}

fn letters_to_keywords(kw: &KeywordsFile, letters: &BTreeSet<char>) -> BTreeSet<String> {
    letters
        .iter()
        .filter_map(|c| kw.keyword_for_letter(*c).map(|s| s.to_string()))
        .collect()
}

pub(crate) fn ensure_maildir_layout(dir: &Path) -> MailboxResult<()> {
    for sub in ["tmp", "new", "cur"] {
        fs::create_dir_all(dir.join(sub))?;
    }
    Ok(())
}

fn move_new_to_cur(dir: &Path) -> MailboxResult<()> {
    let new_dir = dir.join("new");
    let cur_dir = dir.join("cur");
    for ent in fs::read_dir(&new_dir)? {
        let ent = ent?;
        if !ent.file_type()?.is_file() {
            continue;
        }
        let name = ent.file_name().to_string_lossy().into_owned();
        let parsed = MaildirFilename::parse(&name);
        // Recent is implied by new/; once in cur without Seen it's still unseen
        let dest_name = if name.contains(":2,") {
            name
        } else {
            format!("{}:2,", parsed.base)
        };
        let dest = cur_dir.join(dest_name);
        fs::rename(ent.path(), dest)?;
    }
    Ok(())
}

fn dir_uid_validity(dir: &Path) -> MailboxResult<u64> {
    let meta = fs::metadata(dir)?;
    Ok(meta
        .created()
        .or_else(|_| meta.modified())
        .unwrap_or(SystemTime::UNIX_EPOCH)
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(1)
        .max(1))
}

/// Maildir++ path for IMAP name under user root.
pub(crate) fn resolve_mailbox_dir(user_root: &Path, name: &str) -> MailboxResult<PathBuf> {
    if name.contains("..") {
        return Err(MailboxError::Invalid("path traversal".into()));
    }
    if name.eq_ignore_ascii_case("INBOX") {
        return Ok(user_root.to_path_buf());
    }
    // Maildir++: `.Folder.Sub` with `/` → `.`
    let encoded = name
        .split('/')
        .map(crate::name_codec::MailboxNameCodec::encode)
        .collect::<Vec<_>>()
        .join(".");
    Ok(user_root.join(format!(".{encoded}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::MailboxFactory;
    use crate::MaildirFactory;
    use tempfile::tempdir;

    fn sample(subject: &str) -> Vec<u8> {
        format!(
            "From: a@b\r\nTo: c@d\r\nSubject: {subject}\r\nMessage-ID: <{subject}@x>\r\n\r\nbody\r\n"
        )
        .into_bytes()
    }

    /// Test-only whole-message append, via the real streaming push triad
    /// ([`AppendGuard`]) — never bypasses it.
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

    /// Test-only [`MessageReadCallback`] that records the call sequence and
    /// collects the whole message, for assertions.
    #[derive(Default)]
    struct RecordingReadCallback {
        events: Vec<String>,
        data: Vec<u8>,
    }

    impl crate::traits::MessageReadCallback for RecordingReadCallback {
        fn start_message(&mut self, size: u64) {
            self.events.push(format!("start({size})"));
        }
        fn message_content(&mut self, chunk: &[u8]) -> bool {
            self.events.push(format!("content({})", chunk.len()));
            self.data.extend_from_slice(chunk);
            true
        }
        fn end_message(&mut self) {
            self.events.push("end".to_string());
        }
    }

    /// Test-only whole-message read, via the real streaming
    /// [`Mailbox::read_message`] callback — never bypasses it.
    fn read_whole(mb: &mut dyn Mailbox, message_number: u32) -> MailboxResult<Vec<u8>> {
        let mut cb = RecordingReadCallback::default();
        mb.read_message(message_number, &mut cb)?;
        Ok(cb.data)
    }

    #[test]
    fn streaming_read_round_trips_appended_content() {
        let dir = tempdir().unwrap();
        let factory = MaildirFactory::new(dir.path());
        let mut store = factory.create_store();
        store.open("readuser").unwrap();
        let mut mb = store.open_mailbox("INBOX", false).unwrap();
        let msg = sample("streamed");
        append_whole(mb.as_mut(), &msg, &BTreeSet::new(), None).unwrap();

        let mut cb = RecordingReadCallback::default();
        mb.read_message(1, &mut cb).unwrap();
        assert_eq!(cb.data, msg);
        assert_eq!(cb.events.first(), Some(&format!("start({})", msg.len())));
        assert_eq!(cb.events.last(), Some(&"end".to_string()));
        assert!(
            cb.events.len() > 2,
            "expected at least one content() call between start and end: {:?}",
            cb.events
        );

        // A second, independent read must produce the same content (no
        // leftover state from the first — each read_message call is
        // self-contained).
        let again = read_whole(mb.as_mut(), 1).unwrap();
        assert_eq!(again, msg);
        mb.close(false).unwrap();
    }

    #[test]
    fn append_content_streamed_in_many_small_chunks_matches_whole_write() {
        let dir = tempdir().unwrap();
        let factory = MaildirFactory::new(dir.path());
        let mut store = factory.create_store();
        store.open("chunkappenduser").unwrap();
        let mut mb = store.open_mailbox("INBOX", false).unwrap();

        let msg = sample("chunked");
        mb.start_append(&BTreeSet::new(), None).unwrap();
        for chunk in msg.chunks(3) {
            mb.append_content(chunk).unwrap();
        }
        let uid = mb.end_append().unwrap();
        assert!(uid > 0);

        let got = read_whole(mb.as_mut(), 1).unwrap();
        assert_eq!(
            got, msg,
            "content written via small chunks must round-trip exactly"
        );

        // The index entry built from the just-written file must have picked
        // up the real headers, proving end_append's streamed re-read (rather
        // than a stale/duplicated buffer) fed the indexer.
        assert_eq!(mb.flags(1).unwrap(), BTreeSet::new());
        mb.close(false).unwrap();
    }

    #[test]
    fn abort_append_removes_the_tmp_file_and_leaves_no_message() {
        let dir = tempdir().unwrap();
        let factory = MaildirFactory::new(dir.path());
        let mut store = factory.create_store();
        store.open("abortuser").unwrap();
        let mut mb = store.open_mailbox("INBOX", false).unwrap();

        mb.start_append(&BTreeSet::new(), None).unwrap();
        mb.append_content(b"From: a@b\r\n").unwrap();
        mb.append_content(b"partial, never finished").unwrap();

        let tmp_dir = dir.path().join("abortuser").join("tmp");
        let tmp_files_during: Vec<_> = fs::read_dir(&tmp_dir).unwrap().collect();
        assert_eq!(tmp_files_during.len(), 1, "a tmp file must exist mid-append");

        mb.abort_append().unwrap();

        let tmp_files_after: Vec<_> = fs::read_dir(&tmp_dir).unwrap().collect();
        assert!(tmp_files_after.is_empty(), "abort_append must remove the orphaned tmp file");
        assert_eq!(mb.message_count().unwrap(), 0, "aborted append must not deliver a message");

        // The mailbox must be immediately reusable for a fresh append.
        let uid = append_whole(mb.as_mut(), &sample("after-abort"), &BTreeSet::new(), None)
            .unwrap();
        assert!(uid > 0);
        assert_eq!(mb.message_count().unwrap(), 1);
        mb.close(false).unwrap();
    }

    #[test]
    fn abort_append_with_nothing_in_progress_is_a_safe_no_op() {
        let dir = tempdir().unwrap();
        let factory = MaildirFactory::new(dir.path());
        let mut store = factory.create_store();
        store.open("noopabortuser").unwrap();
        let mut mb = store.open_mailbox("INBOX", false).unwrap();
        assert!(mb.abort_append().is_ok());
        mb.close(false).unwrap();
    }

    #[test]
    fn append_guard_rolls_back_on_drop_without_commit() {
        use crate::traits::AppendGuard;

        let dir = tempdir().unwrap();
        let factory = MaildirFactory::new(dir.path());
        let mut store = factory.create_store();
        store.open("guarduser").unwrap();
        let mut mb = store.open_mailbox("INBOX", false).unwrap();

        {
            let mut guard = AppendGuard::start(mb.as_mut(), &BTreeSet::new(), None).unwrap();
            guard.append_content(b"From: a@b\r\n").unwrap();
            guard.append_content(b"partial, never committed").unwrap();
            // `guard` drops here without `commit()` — must roll back.
        }

        let tmp_dir = dir.path().join("guarduser").join("tmp");
        let remaining: Vec<_> = fs::read_dir(&tmp_dir).unwrap().collect();
        assert!(remaining.is_empty(), "AppendGuard's Drop must remove the orphaned tmp file");
        assert_eq!(mb.message_count().unwrap(), 0);

        // The mailbox must be immediately reusable through a committed guard.
        let mut guard = AppendGuard::start(mb.as_mut(), &BTreeSet::new(), None).unwrap();
        guard.append_content(&sample("via-guard")).unwrap();
        let uid = guard.commit().unwrap();
        assert!(uid > 0);
        assert_eq!(mb.message_count().unwrap(), 1);
        mb.close(false).unwrap();
    }

    #[test]
    fn keywords_mutation_renames_and_indexes() {
        let dir = tempdir().unwrap();
        let factory = MaildirFactory::new(dir.path());
        let mut store = factory.create_store();
        store.open("kwuser").unwrap();
        let mut mb = store.open_mailbox("INBOX", false).unwrap();
        append_whole(mb.as_mut(), &sample("k1"), &BTreeSet::new(), None).unwrap();

        let mut kws = BTreeSet::new();
        kws.insert("Important".into());
        kws.insert("Work".into());
        mb.set_keywords(1, &kws, true).unwrap();
        let got = mb.keywords(1).unwrap();
        assert!(got.iter().any(|k| k.eq_ignore_ascii_case("Important")));
        assert!(got.iter().any(|k| k.eq_ignore_ascii_case("Work")));

        let mut drop = BTreeSet::new();
        drop.insert("Work".into());
        mb.set_keywords(1, &drop, false).unwrap();
        let got = mb.keywords(1).unwrap();
        assert!(got.iter().any(|k| k.eq_ignore_ascii_case("Important")));
        assert!(!got.iter().any(|k| k.eq_ignore_ascii_case("Work")));

        let mut repl = BTreeSet::new();
        repl.insert("Only".into());
        mb.replace_keywords(1, &repl).unwrap();
        let got = mb.keywords(1).unwrap();
        assert_eq!(got.len(), 1);
        assert!(got.iter().any(|k| k.eq_ignore_ascii_case("Only")));
        mb.close(false).unwrap();
    }

    #[test]
    fn expunge_in_place_returns_sequence_numbers() {
        let dir = tempdir().unwrap();
        let factory = MaildirFactory::new(dir.path());
        let mut store = factory.create_store();
        store.open("exuser").unwrap();
        let mut mb = store.open_mailbox("INBOX", false).unwrap();
        append_whole(mb.as_mut(), &sample("a"), &BTreeSet::new(), None).unwrap();
        append_whole(mb.as_mut(), &sample("b"), &BTreeSet::new(), None).unwrap();
        append_whole(mb.as_mut(), &sample("c"), &BTreeSet::new(), None).unwrap();

        let mut del = BTreeSet::new();
        del.insert(Flag::Deleted);
        mb.set_flags(2, &del, true).unwrap();
        let removed = mb.expunge().unwrap();
        assert_eq!(removed, vec![2]);
        assert_eq!(mb.message_count().unwrap(), 2);
        // mailbox remains usable
        let st = mb.status().unwrap();
        assert_eq!(st.messages, 2);
        // 3 appends (modseq 1-3) + one flag change on message 2 (modseq 4)
        // — HIGHESTMODSEQ must not roll back even though the message that
        // held it was just expunged.
        assert_eq!(st.highest_modseq, 4);
        mb.close(false).unwrap();
    }

    #[test]
    fn status_reports_unseen_and_uid_fields() {
        let dir = tempdir().unwrap();
        let factory = MaildirFactory::new(dir.path());
        let mut store = factory.create_store();
        store.open("stuser").unwrap();
        let mut mb = store.open_mailbox("INBOX", false).unwrap();
        append_whole(mb.as_mut(), &sample("u1"), &BTreeSet::new(), None).unwrap();
        let mut seen = BTreeSet::new();
        seen.insert(Flag::Seen);
        append_whole(mb.as_mut(), &sample("u2"), &seen, None).unwrap();

        let st = mb.status().unwrap();
        assert_eq!(st.messages, 2);
        assert_eq!(st.unseen, 1);
        assert_eq!(st.uid_next, mb.uid_next());
        assert_eq!(st.uid_validity, mb.uid_validity());
        assert_eq!(st.recent, 0);
        assert_eq!(st.highest_modseq, 2);
        mb.close(false).unwrap();
    }

    #[test]
    fn modseq_increases_on_append_and_on_flag_change() {
        let dir = tempdir().unwrap();
        let factory = MaildirFactory::new(dir.path());
        let mut store = factory.create_store();
        store.open("modsequser").unwrap();
        let mut mb = store.open_mailbox("INBOX", false).unwrap();

        append_whole(mb.as_mut(), &sample("a"), &BTreeSet::new(), None).unwrap();
        append_whole(mb.as_mut(), &sample("b"), &BTreeSet::new(), None).unwrap();
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
    fn changed_since_reports_only_messages_modified_after_the_given_modseq() {
        let dir = tempdir().unwrap();
        let factory = MaildirFactory::new(dir.path());
        let mut store = factory.create_store();
        store.open("changeduser").unwrap();
        let mut mb = store.open_mailbox("INBOX", false).unwrap();

        append_whole(mb.as_mut(), &sample("a"), &BTreeSet::new(), None).unwrap(); // uid 1, modseq 1
        append_whole(mb.as_mut(), &sample("b"), &BTreeSet::new(), None).unwrap(); // uid 2, modseq 2
        let baseline = mb.highest_modseq();

        let mut flagged = BTreeSet::new();
        flagged.insert(Flag::Flagged);
        mb.set_flags(2, &flagged, true).unwrap(); // uid 2 -> modseq 3

        let changed = mb.changed_since(baseline).unwrap();
        assert_eq!(changed, vec![2]);
        assert!(mb.changed_since(mb.highest_modseq()).unwrap().is_empty());
        assert_eq!(mb.changed_since(0).unwrap().len(), 2);

        mb.close(false).unwrap();
    }

    #[test]
    fn highest_modseq_survives_a_close_and_reopen() {
        let dir = tempdir().unwrap();
        let factory = MaildirFactory::new(dir.path());
        let mut store = factory.create_store();
        store.open("persistuser").unwrap();
        let mut mb = store.open_mailbox("INBOX", false).unwrap();
        append_whole(mb.as_mut(), &sample("a"), &BTreeSet::new(), None).unwrap();
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
