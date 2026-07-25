// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! IMAP-level mailbox storage (mbox + Maildir++).
//!
//! Indexing and searching must run on the Runtime storage pool — see [`pool`].

#![warn(missing_docs)]

mod config;
mod error;
mod flag;
mod message_set;
mod name_codec;
mod search;
mod traits;

pub mod index;
pub mod maildir;
pub mod mbox;
pub mod pool;

pub use config::IndexConfig;
pub use error::{MailboxError, MailboxResult};
pub use flag::Flag;
pub use maildir::{MaildirFactory, MaildirMailbox, MaildirStore};
pub use mbox::{MboxFactory, MboxFlagsFile, MboxMailbox, MboxStore};
pub use message_set::{MessageRange, MessageSet};
pub use name_codec::MailboxNameCodec;
pub use search::{MessageContext, SearchCriteria};
pub use traits::{
    Mailbox, MailboxAttribute, MailboxFactory, MailboxInfo, MailboxStatus, MailboxStore,
    MessageDescriptor,
};
