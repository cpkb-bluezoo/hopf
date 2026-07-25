// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Core mailbox traits (IMAP-level).

use std::collections::{BTreeMap, BTreeSet};
use std::time::SystemTime;

use crate::error::MailboxResult;
use crate::flag::Flag;
use crate::search::SearchCriteria;

/// Lightweight message metadata.
#[derive(Clone, Debug)]
pub struct MessageDescriptor {
    /// 1-based sequence number.
    pub message_number: u32,
    /// Size in octets.
    pub size: u64,
    /// Persistent unique id (POP UIDL string / Maildir base name / mbox MD5).
    pub unique_id: String,
    /// IMAP UID when known.
    pub uid: Option<u64>,
}

/// IMAP LIST / LSUB attributes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MailboxAttribute {
    /// `\Noinferiors`
    NoInferiors,
    /// `\Noselect`
    NoSelect,
    /// `\Marked`
    Marked,
    /// `\Unmarked`
    Unmarked,
    /// `\HasChildren`
    HasChildren,
    /// `\HasNoChildren`
    HasNoChildren,
}

/// LIST row.
#[derive(Clone, Debug)]
pub struct MailboxInfo {
    /// Mailbox name (IMAP form).
    pub name: String,
    /// Attributes.
    pub attributes: BTreeSet<MailboxAttribute>,
}

/// Single mailbox (folder) — full IMAP surface.
///
/// All methods are blocking. **Indexing and [`search`](Self::search) must run
/// on the Runtime storage pool**, never on a reactor thread.
pub trait Mailbox: Send {
    /// Close; when `expunge` is true, permanently remove `\Deleted` messages.
    fn close(&mut self, expunge: bool) -> MailboxResult<()>;

    /// Mailbox name (typically `INBOX`).
    fn name(&self) -> &str;

    /// Opened read-only?
    fn is_read_only(&self) -> bool {
        false
    }

    /// Accessible message count (includes `\Deleted` / session marks until
    /// expunge — IMAP sequence model).
    fn message_count(&self) -> MailboxResult<u32>;

    /// Total size in octets (all sequence numbers, including deleted).
    fn mailbox_size(&self) -> MailboxResult<u64>;

    /// POP STAT count: messages not marked deleted in this session.
    fn undeleted_message_count(&self) -> MailboxResult<u32> {
        let n = self.message_count()?;
        let mut c = 0u32;
        for i in 1..=n {
            if !self.is_deleted(i)? {
                c += 1;
            }
        }
        Ok(c)
    }

    /// POP STAT size: octets of messages not session-deleted.
    fn undeleted_mailbox_size(&self) -> MailboxResult<u64> {
        let mut total = 0u64;
        for m in self.messages()? {
            if !self.is_deleted(m.message_number)? {
                total += m.size;
            }
        }
        Ok(total)
    }

    /// Enumerate message descriptors in sequence order.
    fn messages(&self) -> MailboxResult<Vec<MessageDescriptor>>;

    /// Read full RFC 822 bytes for sequence number.
    fn read_message(&self, message_number: u32) -> MailboxResult<Vec<u8>>;

    /// Unique id string for sequence number.
    fn unique_id(&self, message_number: u32) -> MailboxResult<String>;

    /// IMAP UID for sequence number.
    fn uid(&self, message_number: u32) -> MailboxResult<u64>;

    /// UIDVALIDITY.
    fn uid_validity(&self) -> u64;

    /// UIDNEXT.
    fn uid_next(&self) -> u64;

    /// Flags for a message.
    fn flags(&self, message_number: u32) -> MailboxResult<BTreeSet<Flag>>;

    /// Keywords for a message.
    fn keywords(&self, message_number: u32) -> MailboxResult<BTreeSet<String>> {
        let _ = message_number;
        Ok(BTreeSet::new())
    }

    /// Add or remove flags (`add == true` add, else remove).
    fn set_flags(
        &mut self,
        message_number: u32,
        flags: &BTreeSet<Flag>,
        add: bool,
    ) -> MailboxResult<()>;

    /// Replace flags entirely (system flags; `Recent` ignored if present).
    fn replace_flags(
        &mut self,
        message_number: u32,
        flags: &BTreeSet<Flag>,
    ) -> MailboxResult<()>;

    /// Session-local delete mark (POP DELE). In-memory until [`close`](Self::close)
    /// with `expunge = true`; discarded on `close(false)` or cleared by
    /// [`undelete_all`](Self::undelete_all). Does **not** rename / persist
    /// IMAP `\Deleted` — use [`set_flags`](Self::set_flags) for that.
    fn mark_deleted(&mut self, message_number: u32) -> MailboxResult<()>;

    /// Whether the message has a session delete mark (POP DELE).
    fn is_deleted(&self, message_number: u32) -> MailboxResult<bool>;

    /// Clear all session delete marks (POP RSET). Does not clear IMAP `\Deleted`.
    fn undelete_all(&mut self) -> MailboxResult<()>;

    /// Alias for [`mark_deleted`](Self::mark_deleted) (POP DELE).
    fn delete(&mut self, message_number: u32) -> MailboxResult<()> {
        self.mark_deleted(message_number)
    }

    /// Begin append (streaming).
    fn start_append(
        &mut self,
        flags: &BTreeSet<Flag>,
        internal_date: Option<SystemTime>,
    ) -> MailboxResult<()>;

    /// Append chunk of RFC 822 data.
    fn append_content(&mut self, data: &[u8]) -> MailboxResult<()>;

    /// Finish append; returns new UID.
    fn end_append(&mut self) -> MailboxResult<u64>;

    /// Convenience: append a complete message.
    fn append_message(
        &mut self,
        data: &[u8],
        flags: &BTreeSet<Flag>,
        internal_date: Option<SystemTime>,
    ) -> MailboxResult<u64> {
        self.start_append(flags, internal_date)?;
        self.append_content(data)?;
        self.end_append()
    }

    /// COPY to another mailbox (Maildir++). Mbox returns unsupported.
    fn copy_messages(
        &mut self,
        message_numbers: &[u32],
        destination_mailbox: &str,
    ) -> MailboxResult<BTreeMap<u32, u64>> {
        let _ = (message_numbers, destination_mailbox);
        Err(crate::error::MailboxError::Unsupported("COPY"))
    }

    /// MOVE = COPY then IMAP `\Deleted` via [`set_flags`](Self::set_flags).
    fn move_messages(
        &mut self,
        message_numbers: &[u32],
        destination_mailbox: &str,
    ) -> MailboxResult<BTreeMap<u32, u64>> {
        let map = self.copy_messages(message_numbers, destination_mailbox)?;
        let mut f = BTreeSet::new();
        f.insert(Flag::Deleted);
        for &n in message_numbers {
            self.set_flags(n, &f, true)?;
        }
        Ok(map)
    }

    /// IMAP SEARCH — **must** be invoked on the storage pool.
    fn search(&self, criteria: &SearchCriteria) -> MailboxResult<Vec<u32>>;
}

/// Multi-mailbox store for one user.
pub trait MailboxStore: Send {
    /// Open store for `username`.
    fn open(&mut self, username: &str) -> MailboxResult<()>;

    /// Close store.
    fn close(&mut self) -> MailboxResult<()>;

    /// Hierarchy delimiter.
    fn hierarchy_delimiter(&self) -> char;

    /// Personal namespace prefix.
    fn personal_namespace(&self) -> &str {
        ""
    }

    /// List mailboxes matching `pattern` (`*` / `%` wildcards).
    fn list(&self, reference: &str, pattern: &str) -> MailboxResult<Vec<MailboxInfo>>;

    /// Create mailbox.
    fn create_mailbox(&mut self, name: &str) -> MailboxResult<()>;

    /// Delete mailbox.
    fn delete_mailbox(&mut self, name: &str) -> MailboxResult<()>;

    /// Rename mailbox.
    fn rename_mailbox(&mut self, old: &str, new: &str) -> MailboxResult<()>;

    /// Subscribe.
    fn subscribe(&mut self, name: &str) -> MailboxResult<()>;

    /// Unsubscribe.
    fn unsubscribe(&mut self, name: &str) -> MailboxResult<()>;

    /// Open a mailbox (blocking). Prefer calling from the storage pool.
    fn open_mailbox(&mut self, name: &str, read_only: bool) -> MailboxResult<Box<dyn Mailbox>>;
}

/// Factory for per-session stores.
pub trait MailboxFactory: Send + Sync {
    /// Create a new store instance.
    fn create_store(&self) -> Box<dyn MailboxStore>;
}
