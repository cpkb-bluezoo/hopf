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

/// IMAP STATUS snapshot (RFC 9051 §6.3.11).
///
/// `unseen` is the 1-based sequence number of the first message without
/// `\Seen` (0 if none), matching the STATUS UNSEEN item.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MailboxStatus {
    /// MESSAGES — total accessible messages.
    pub messages: u32,
    /// RECENT — count of messages with `\Recent`.
    pub recent: u32,
    /// UNSEEN — first unseen sequence number, or 0.
    pub unseen: u32,
    /// UIDNEXT.
    pub uid_next: u64,
    /// UIDVALIDITY.
    pub uid_validity: u64,
    /// HIGHESTMODSEQ (0 when CONDSTORE is unsupported).
    pub highest_modseq: u64,
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

    /// Begin a streaming read of RFC 822 bytes for `message_number`. Exactly
    /// one read may be in progress on a given `Mailbox` handle at a time.
    fn start_read(&mut self, message_number: u32) -> MailboxResult<()>;

    /// Read the next chunk into `buf`, returning the number of bytes
    /// written. `0` signals end of message — call [`end_read`](Self::end_read) next.
    fn read_chunk(&mut self, buf: &mut [u8]) -> MailboxResult<usize>;

    /// Finish a streaming read.
    fn end_read(&mut self) -> MailboxResult<()>;

    /// Convenience: read a complete message via the streaming triad. Prefer
    /// [`start_read`](Self::start_read)/[`read_chunk`](Self::read_chunk)/[`end_read`](Self::end_read)
    /// directly when delivering to a socket or another streaming sink —
    /// this materializes the whole message in memory.
    fn read_message(&mut self, message_number: u32) -> MailboxResult<Vec<u8>> {
        self.start_read(message_number)?;
        let mut out = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = self.read_chunk(&mut buf)?;
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        self.end_read()?;
        Ok(out)
    }

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
    fn replace_flags(&mut self, message_number: u32, flags: &BTreeSet<Flag>) -> MailboxResult<()>;

    /// Add or remove user keywords (`add == true` add, else remove).
    fn set_keywords(
        &mut self,
        message_number: u32,
        keywords: &BTreeSet<String>,
        add: bool,
    ) -> MailboxResult<()> {
        let _ = (message_number, keywords, add);
        Err(crate::error::MailboxError::Unsupported("keywords"))
    }

    /// Replace user keywords entirely.
    fn replace_keywords(
        &mut self,
        message_number: u32,
        keywords: &BTreeSet<String>,
    ) -> MailboxResult<()> {
        let _ = (message_number, keywords);
        Err(crate::error::MailboxError::Unsupported("keywords"))
    }

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

    /// Permanently remove session-deleted and `\Deleted` messages, leaving the
    /// mailbox open. Returns the sequence numbers removed (ascending, pre-renumber).
    fn expunge(&mut self) -> MailboxResult<Vec<u32>> {
        Err(crate::error::MailboxError::Unsupported("EXPUNGE"))
    }

    /// IMAP STATUS snapshot. Default derives counts / UID values from other
    /// methods; `highest_modseq` comes from [`highest_modseq`](Self::highest_modseq).
    fn status(&self) -> MailboxResult<MailboxStatus> {
        let messages = self.message_count()?;
        let mut recent = 0u32;
        let mut unseen = 0u32;
        for i in 1..=messages {
            let flags = self.flags(i)?;
            if flags.contains(&Flag::Recent) {
                recent = recent.saturating_add(1);
            }
            if unseen == 0 && !flags.contains(&Flag::Seen) {
                unseen = i;
            }
        }
        Ok(MailboxStatus {
            messages,
            recent,
            unseen,
            uid_next: self.uid_next(),
            uid_validity: self.uid_validity(),
            highest_modseq: self.highest_modseq(),
        })
    }

    /// Highest CONDSTORE mod-sequence (0 = unsupported / unset).
    fn highest_modseq(&self) -> u64 {
        0
    }

    /// Mod-sequence for a message (0 = unsupported / unset).
    fn modseq(&self, message_number: u32) -> MailboxResult<u64> {
        let _ = message_number;
        Ok(0)
    }

    /// UIDs changed since `modseq` (exclusive). Empty when unsupported.
    fn changed_since(&self, modseq: u64) -> MailboxResult<Vec<u64>> {
        let _ = modseq;
        Ok(Vec::new())
    }

    /// UIDs expunged since `modseq` (exclusive). Empty when unsupported.
    fn expunged_since(&self, modseq: u64) -> MailboxResult<Vec<u64>> {
        let _ = modseq;
        Ok(Vec::new())
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

    /// LSUB — subscribed mailboxes matching `pattern`.
    ///
    /// Default returns [`list`](Self::list) when the backend does not track
    /// subscriptions separately.
    fn list_subscribed(&self, reference: &str, pattern: &str) -> MailboxResult<Vec<MailboxInfo>> {
        self.list(reference, pattern)
    }

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
