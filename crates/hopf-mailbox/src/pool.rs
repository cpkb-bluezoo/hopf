// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Run blocking mailbox index/search work on the storage pool.
//!
//! Reactor threads must not call [`crate::Mailbox::search`] or rebuild indexes
//! directly — use these helpers (or `StorageExecutor::submit_on` with your own
//! closure that owns the mailbox).

use std::error::Error as StdError;
use std::sync::{Arc, Mutex};

use hopf_core::{ConnHandle, StorageError, StorageExecutor};

use crate::error::MailboxError;
use crate::search::SearchCriteria;
use crate::traits::Mailbox;

/// Submit [`Mailbox::search`] on the storage pool; deliver results on `handle`'s reactor.
pub fn search_on_storage<M, Cb>(
    storage: &StorageExecutor,
    handle: ConnHandle,
    mailbox: Arc<Mutex<M>>,
    criteria: SearchCriteria,
    callback: Cb,
) where
    M: Mailbox + 'static,
    Cb: FnOnce(Result<Vec<u32>, StorageError>) + Send + 'static,
{
    storage.submit_on(
        handle,
        move || {
            let mb = mailbox
                .lock()
                .map_err(|_| MailboxError::Invalid("mailbox lock poisoned".into()).boxed())?;
            mb.search(&criteria).map_err(|e| e.boxed())
        },
        callback,
    );
}

/// Submit arbitrary blocking mailbox work on the storage pool.
pub fn run_on_storage<T, Op, Cb>(storage: &StorageExecutor, handle: ConnHandle, op: Op, callback: Cb)
where
    T: Send + 'static,
    Op: FnOnce() -> Result<T, Box<dyn StdError + Send + Sync>> + Send + 'static,
    Cb: FnOnce(Result<T, StorageError>) + Send + 'static,
{
    storage.submit_on(handle, op, callback);
}
