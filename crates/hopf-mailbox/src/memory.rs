// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! A mailbox store held in memory: no files, no sockets.
//!
//! For tests (and examples) of code that serves or reads mailboxes, where the
//! tests may not touch the file system. Every store a [`MemoryFactory`] makes
//! shares the factory's mailboxes, as the stores of a file factory share its
//! directory, so a message appended through one is seen by the next. A
//! message's UID is the number of messages the mailbox has ever held, and its
//! sequence number its place among those still there.
//!
//! It keeps what the mailbox traits need to be driven: messages, flags, UIDs,
//! append and search (any [`SearchCriteria`], through the same evaluation the
//! file stores use). It has no index, no keywords, no modification
//! sequences and no subscriptions to speak of.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::SystemTime;

use crate::error::{MailboxError, MailboxResult};
use crate::flag::Flag;
use crate::list;
use crate::search::{body_contains_streaming, MessageContext, SearchCriteria};
use crate::traits::{
    Mailbox, MailboxFactory, MailboxInfo, MailboxStore, MessageDescriptor, MessageReadCallback,
};

#[derive(Clone)]
struct Message {
    uid: u64,
    flags: BTreeSet<Flag>,
    bytes: Arc<Vec<u8>>,
}

#[derive(Default)]
struct Box_ {
    /// The UID the next message gets.
    next_uid: u64,
    messages: Vec<Message>,
}

type Boxes = Arc<Mutex<BTreeMap<String, Box_>>>;

fn lock(boxes: &Boxes) -> MutexGuard<'_, BTreeMap<String, Box_>> {
    boxes.lock().unwrap_or_else(|e| e.into_inner())
}

/// Makes stores over one set of in-memory mailboxes.
#[derive(Clone, Default)]
pub struct MemoryFactory {
    boxes: Boxes,
}

impl MemoryFactory {
    /// A factory with no mailboxes (`INBOX` is made when it is first opened).
    pub fn new() -> Self {
        Self::default()
    }
}

impl MailboxFactory for MemoryFactory {
    fn create_store(&self) -> Box<dyn MailboxStore> {
        Box::new(MemoryStore { boxes: Arc::clone(&self.boxes), open: false })
    }
}

/// A store over a [`MemoryFactory`]'s mailboxes. Names are separated by `/`.
pub struct MemoryStore {
    boxes: Boxes,
    open: bool,
}

impl MemoryStore {
    fn check_open(&self) -> MailboxResult<()> {
        if self.open {
            Ok(())
        } else {
            Err(MailboxError::Invalid("store not open".into()))
        }
    }
}

impl MailboxStore for MemoryStore {
    fn open(&mut self, _username: &str) -> MailboxResult<()> {
        self.open = true;
        Ok(())
    }

    fn close(&mut self) -> MailboxResult<()> {
        self.open = false;
        Ok(())
    }

    fn hierarchy_delimiter(&self) -> char {
        '/'
    }

    fn list(&self, reference: &str, pattern: &str) -> MailboxResult<Vec<MailboxInfo>> {
        self.check_open()?;
        let mut real: Vec<MailboxInfo> = vec![MailboxInfo { name: "INBOX".into(), attributes: BTreeSet::new() }];
        for name in lock(&self.boxes).keys() {
            if name != "INBOX" {
                real.push(MailboxInfo { name: name.clone(), attributes: BTreeSet::new() });
            }
        }
        Ok(list::rows(real, reference, pattern, '/'))
    }

    fn create_mailbox(&mut self, name: &str) -> MailboxResult<()> {
        self.check_open()?;
        let mut boxes = lock(&self.boxes);
        if boxes.contains_key(name) || name.eq_ignore_ascii_case("INBOX") {
            return Err(MailboxError::Invalid("mailbox exists".into()));
        }
        boxes.insert(name.to_string(), Box_::default());
        Ok(())
    }

    fn delete_mailbox(&mut self, name: &str) -> MailboxResult<()> {
        self.check_open()?;
        lock(&self.boxes).remove(name).map(|_| ()).ok_or_else(|| MailboxError::NotFound(name.into()))
    }

    fn rename_mailbox(&mut self, old: &str, new: &str) -> MailboxResult<()> {
        self.check_open()?;
        let mut boxes = lock(&self.boxes);
        let b = boxes.remove(old).ok_or_else(|| MailboxError::NotFound(old.into()))?;
        boxes.insert(new.to_string(), b);
        Ok(())
    }

    fn subscribe(&mut self, _name: &str) -> MailboxResult<()> {
        Ok(())
    }

    fn unsubscribe(&mut self, _name: &str) -> MailboxResult<()> {
        Ok(())
    }

    fn open_mailbox(&mut self, name: &str, read_only: bool) -> MailboxResult<Box<dyn Mailbox>> {
        self.check_open()?;
        let key = if name.eq_ignore_ascii_case("INBOX") { "INBOX" } else { name };
        {
            let mut boxes = lock(&self.boxes);
            if key == "INBOX" {
                boxes.entry("INBOX".to_string()).or_default();
            } else if !boxes.contains_key(key) {
                return Err(MailboxError::NotFound(name.into()));
            }
        }
        let mut mb = MemoryMailbox {
            boxes: Arc::clone(&self.boxes),
            name: key.to_string(),
            read_only,
            messages: Vec::new(),
            appending: None,
        };
        mb.reload();
        Ok(Box::new(mb))
    }
}

/// An open mailbox: a snapshot of the messages, as an open file mailbox has,
/// brought up to date by [`Mailbox::refresh`].
pub struct MemoryMailbox {
    boxes: Boxes,
    name: String,
    read_only: bool,
    messages: Vec<Message>,
    appending: Option<(BTreeSet<Flag>, Vec<u8>)>,
}

impl MemoryMailbox {
    fn reload(&mut self) {
        self.messages = lock(&self.boxes).get(&self.name).map(|b| b.messages.clone()).unwrap_or_default();
    }

    fn at(&self, message_number: u32) -> MailboxResult<&Message> {
        (message_number as usize)
            .checked_sub(1)
            .and_then(|i| self.messages.get(i))
            .ok_or_else(|| MailboxError::NotFound(format!("message {message_number}")))
    }

    fn at_mut(&mut self, message_number: u32) -> MailboxResult<&mut Message> {
        (message_number as usize)
            .checked_sub(1)
            .and_then(|i| self.messages.get_mut(i))
            .ok_or_else(|| MailboxError::NotFound(format!("message {message_number}")))
    }

    /// Writes a message's flags back to the shared mailbox.
    fn store_flags(&self, uid: u64, flags: &BTreeSet<Flag>) {
        if let Some(b) = lock(&self.boxes).get_mut(&self.name) {
            if let Some(m) = b.messages.iter_mut().find(|m| m.uid == uid) {
                m.flags = flags.clone();
            }
        }
    }
}

/// What the search evaluation needs of one message.
struct Context<'a> {
    number: u32,
    message: &'a Message,
}

impl MessageContext for Context<'_> {
    fn message_number(&self) -> u32 {
        self.number
    }
    fn uid(&self) -> u64 {
        self.message.uid
    }
    fn size(&self) -> u64 {
        self.message.bytes.len() as u64
    }
    fn flags(&self) -> BTreeSet<Flag> {
        self.message.flags.clone()
    }
    fn keywords(&self) -> BTreeSet<String> {
        BTreeSet::new()
    }
    fn internal_date_millis(&self) -> Option<i64> {
        None
    }
    fn sent_date_millis(&self) -> Option<i64> {
        None
    }
    fn header(&self, name: &str) -> io::Result<String> {
        // The values of every header of that name, folds undone.
        let text = String::from_utf8_lossy(&self.message.bytes);
        let mut out = String::new();
        let mut current = false;
        for line in text.split('\n') {
            let line = line.trim_end_matches('\r');
            if line.is_empty() {
                break;
            }
            if line.starts_with([' ', '\t']) {
                if current {
                    out.push(' ');
                    out.push_str(line.trim());
                }
                continue;
            }
            current = false;
            if let Some((n, v)) = line.split_once(':') {
                if n.eq_ignore_ascii_case(name) {
                    current = true;
                    if !out.is_empty() {
                        out.push(' ');
                    }
                    out.push_str(v.trim());
                }
            }
        }
        Ok(out)
    }
    fn body_contains(&self, needle_lower: &str) -> io::Result<bool> {
        let mut cursor = io::Cursor::new(self.message.bytes.as_slice());
        body_contains_streaming(&mut cursor, needle_lower)
    }
}

impl Mailbox for MemoryMailbox {
    fn close(&mut self, _expunge: bool) -> MailboxResult<()> {
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
        self.reload();
        Ok(())
    }

    fn mailbox_size(&self) -> MailboxResult<u64> {
        Ok(self.messages.iter().map(|m| m.bytes.len() as u64).sum())
    }

    fn messages(&self) -> MailboxResult<Vec<MessageDescriptor>> {
        Ok(self
            .messages
            .iter()
            .enumerate()
            .map(|(i, m)| MessageDescriptor {
                message_number: i as u32 + 1,
                size: m.bytes.len() as u64,
                unique_id: m.uid.to_string(),
                uid: Some(m.uid),
            })
            .collect())
    }

    fn read_message(&mut self, message_number: u32, callback: &mut dyn MessageReadCallback) -> MailboxResult<()> {
        let bytes = Arc::clone(&self.at(message_number)?.bytes);
        callback.start_message(bytes.len() as u64);
        for chunk in bytes.chunks(8192) {
            if !callback.message_content(chunk) {
                break;
            }
        }
        callback.end_message();
        Ok(())
    }

    fn unique_id(&self, message_number: u32) -> MailboxResult<String> {
        Ok(self.at(message_number)?.uid.to_string())
    }

    fn uid(&self, message_number: u32) -> MailboxResult<u64> {
        Ok(self.at(message_number)?.uid)
    }

    fn uid_validity(&self) -> u64 {
        1
    }

    fn uid_next(&self) -> u64 {
        lock(&self.boxes).get(&self.name).map_or(1, |b| b.next_uid + 1)
    }

    fn flags(&self, message_number: u32) -> MailboxResult<BTreeSet<Flag>> {
        Ok(self.at(message_number)?.flags.clone())
    }

    fn set_flags(&mut self, message_number: u32, flags: &BTreeSet<Flag>, add: bool) -> MailboxResult<()> {
        let (uid, new) = {
            let m = self.at_mut(message_number)?;
            if add {
                m.flags.extend(flags.iter().copied());
            } else {
                m.flags.retain(|f| !flags.contains(f));
            }
            (m.uid, m.flags.clone())
        };
        self.store_flags(uid, &new);
        Ok(())
    }

    fn replace_flags(&mut self, message_number: u32, flags: &BTreeSet<Flag>) -> MailboxResult<()> {
        let uid = {
            let m = self.at_mut(message_number)?;
            m.flags = flags.clone();
            m.uid
        };
        self.store_flags(uid, flags);
        Ok(())
    }

    fn mark_deleted(&mut self, message_number: u32) -> MailboxResult<()> {
        self.set_flags(message_number, &BTreeSet::from([Flag::Deleted]), true)
    }

    fn is_deleted(&self, message_number: u32) -> MailboxResult<bool> {
        Ok(self.at(message_number)?.flags.contains(&Flag::Deleted))
    }

    fn undelete_all(&mut self) -> MailboxResult<()> {
        for i in 1..=self.messages.len() as u32 {
            self.set_flags(i, &BTreeSet::from([Flag::Deleted]), false)?;
        }
        Ok(())
    }

    fn start_append(&mut self, flags: &BTreeSet<Flag>, _internal_date: Option<SystemTime>) -> MailboxResult<()> {
        if self.read_only {
            return Err(MailboxError::ReadOnly);
        }
        self.appending = Some((flags.clone(), Vec::new()));
        Ok(())
    }

    fn append_content(&mut self, data: &[u8]) -> MailboxResult<()> {
        match &mut self.appending {
            Some((_, bytes)) => {
                bytes.extend_from_slice(data);
                Ok(())
            }
            None => Err(MailboxError::Invalid("no append in progress".into())),
        }
    }

    fn end_append(&mut self) -> MailboxResult<u64> {
        let (flags, bytes) = self.appending.take().ok_or_else(|| MailboxError::Invalid("no append in progress".into()))?;
        let mut boxes = lock(&self.boxes);
        let b = boxes.entry(self.name.clone()).or_default();
        b.next_uid += 1;
        let uid = b.next_uid;
        let message = Message { uid, flags, bytes: Arc::new(bytes) };
        b.messages.push(message.clone());
        drop(boxes);
        self.messages.push(message);
        Ok(uid)
    }

    fn abort_append(&mut self) -> MailboxResult<()> {
        self.appending = None;
        Ok(())
    }

    fn search(&self, criteria: &SearchCriteria) -> MailboxResult<Vec<u32>> {
        let mut found = Vec::new();
        for (i, message) in self.messages.iter().enumerate() {
            let number = i as u32 + 1;
            if criteria.matches(&Context { number, message }).map_err(MailboxError::Io)? {
                found.push(number);
            }
        }
        Ok(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::AppendGuard;

    fn add(mb: &mut dyn Mailbox, text: &str) -> u64 {
        let mut guard = AppendGuard::start(mb, &BTreeSet::new(), None).unwrap();
        guard.append_content(text.as_bytes()).unwrap();
        guard.commit().unwrap()
    }

    #[test]
    fn what_one_store_appends_another_sees() {
        let factory = MemoryFactory::new();
        let mut a = factory.create_store();
        a.open("u").unwrap();
        a.create_mailbox("misc/test").unwrap();
        let mut mb = a.open_mailbox("misc/test", false).unwrap();
        assert_eq!(add(mb.as_mut(), "Subject: one\r\n\r\nx"), 1);
        assert_eq!(add(mb.as_mut(), "Subject: two\r\n\r\ny"), 2);
        let mut b = factory.create_store();
        b.open("u").unwrap();
        let other = b.open_mailbox("misc/test", true).unwrap();
        assert_eq!(other.message_count().unwrap(), 2);
        assert_eq!(other.messages().unwrap()[1].uid, Some(2));
    }

    #[test]
    fn an_open_mailbox_sees_a_later_message_only_when_refreshed() {
        let factory = MemoryFactory::new();
        let mut s = factory.create_store();
        s.open("u").unwrap();
        let mut reader = s.open_mailbox("INBOX", true).unwrap();
        let mut writer = s.open_mailbox("INBOX", false).unwrap();
        add(writer.as_mut(), "Subject: late\r\n\r\n");
        assert_eq!(reader.message_count().unwrap(), 0);
        reader.refresh().unwrap();
        assert_eq!(reader.message_count().unwrap(), 1);
    }

    #[test]
    fn search_finds_a_header() {
        let factory = MemoryFactory::new();
        let mut s = factory.create_store();
        s.open("u").unwrap();
        let mut mb = s.open_mailbox("INBOX", false).unwrap();
        add(mb.as_mut(), "Message-ID: <a@x>\r\nSubject: s\r\n\r\n");
        add(mb.as_mut(), "Message-ID: <b@x>\r\n\r\n");
        let hit = mb.search(&SearchCriteria::Header { name: "message-id".into(), pattern: "<b@x>".into() }).unwrap();
        assert_eq!(hit, vec![2]);
    }

    #[test]
    fn an_aborted_append_leaves_nothing_and_a_missing_mailbox_is_not_found() {
        let factory = MemoryFactory::new();
        let mut s = factory.create_store();
        s.open("u").unwrap();
        let mut mb = s.open_mailbox("INBOX", false).unwrap();
        {
            let mut guard = AppendGuard::start(mb.as_mut(), &BTreeSet::new(), None).unwrap();
            guard.append_content(b"half").unwrap();
        }
        assert_eq!(mb.message_count().unwrap(), 0);
        assert!(matches!(s.open_mailbox("no/such", true), Err(MailboxError::NotFound(_))));
    }

    #[test]
    fn a_read_only_mailbox_refuses_an_append() {
        let factory = MemoryFactory::new();
        let mut s = factory.create_store();
        s.open("u").unwrap();
        let mut mb = s.open_mailbox("INBOX", true).unwrap();
        assert!(matches!(mb.start_append(&BTreeSet::new(), None), Err(MailboxError::ReadOnly)));
    }
}
