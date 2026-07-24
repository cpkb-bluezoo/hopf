// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Maildir++ backend (hierarchical folders, COPY/MOVE).

mod filename;
mod keywords;
mod mailbox;
mod store;
mod uidlist;

pub use mailbox::MaildirMailbox;
pub use store::{MaildirFactory, MaildirStore};
