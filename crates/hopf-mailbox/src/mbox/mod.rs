// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! mbox backend with `.flags` sidecar.

mod flags;
mod lock;
mod mailbox;
mod store;

pub use flags::MboxFlagsFile;
pub use mailbox::MboxMailbox;
pub use store::{MboxFactory, MboxStore};
