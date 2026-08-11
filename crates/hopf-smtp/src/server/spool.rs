// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! [`SpoolPipeline`] — spool a transaction body to a local temp file as
//! chunks arrive, instead of growing an in-memory buffer for the whole
//! message.
//!
//! Used by both [`crate::LocalDeliveryHandler`] and
//! [`crate::SimpleRelayHandler`]: peak memory during DATA reception is
//! O(chunk size), not O(message size), and delivery (to one mailbox, or
//! fanned out to several outbound MX connections) streams back off the
//! spooled file afterward rather than replaying an in-memory copy.
//!
//! This is *not* the "custody spool" a store-and-forward MTA uses for
//! cross-failure retry — it's a bounded, transient staging file for the
//! single already-in-flight transaction, deleted right after use. Neither
//! handler retries a failed delivery from it after the transaction ends.
//!
//! Chunk writes are offloaded to [`hopf_core::StorageExecutor`] (issue
//! #184) rather than done inline on the reactor thread — `message_content`
//! only enqueues and returns immediately. Writes to the same file must
//! land in order, and `StorageExecutor::submit_on` doesn't guarantee
//! same-thread/ordered execution across separate calls, so chunks are
//! drained one at a time: the next chunk's write is only submitted once
//! the previous one's completion callback confirms it landed (`drain_next`).

use std::collections::VecDeque;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use hopf_core::{ConnHandle, Runtime, StorageError};
use rmimeparser::EmailAddress;

use crate::server::pipeline::SmtpPipeline;

/// Shared, mutex-guarded spool state — separate from [`SpoolPipeline`]
/// itself so the storage-pool write callback (which only ever gets a
/// cloned `Arc`, never `&mut SpoolPipeline`) can safely reach it.
struct SpoolState {
    file: Option<File>,
    path: Option<PathBuf>,
    error: Option<String>,
    queue: VecDeque<Vec<u8>>,
    /// One write in flight at a time — set while a chunk is submitted to
    /// the storage pool, cleared once its callback lands and the queue is
    /// empty.
    draining: bool,
}

/// Spools message content to a local temp file, created lazily on first
/// content byte.
pub(crate) struct SpoolPipeline {
    state: Arc<Mutex<SpoolState>>,
    runtime: Arc<Runtime>,
    handle: ConnHandle,
}

impl SpoolPipeline {
    pub(crate) fn new(runtime: Arc<Runtime>, handle: ConnHandle) -> Self {
        Self {
            state: Arc::new(Mutex::new(SpoolState {
                file: None,
                path: None,
                error: None,
                queue: VecDeque::new(),
                draining: false,
            })),
            runtime,
            handle,
        }
    }

    /// The spool file path, once content has started arriving.
    pub(crate) fn path(&self) -> Option<PathBuf> {
        self.state.lock().unwrap().path.clone()
    }

    /// The first write error, if any (subsequent writes are dropped silently
    /// once set; callers must check this before trusting the spooled file).
    pub(crate) fn error(&self) -> Option<String> {
        self.state.lock().unwrap().error.clone()
    }
}

/// Drain the next queued chunk (if any) by submitting its write to the
/// storage pool; on completion, either drains the next one or clears
/// `draining` once the queue is empty. Free function (not a `SpoolPipeline`
/// method) since it needs to re-invoke itself from inside a `'static`
/// storage callback, which only has cloned `Arc`s/`ConnHandle`, not `&self`.
fn drain_next(state: Arc<Mutex<SpoolState>>, runtime: Arc<Runtime>, handle: ConnHandle) {
    let chunk = {
        let mut g = state.lock().unwrap();
        match g.queue.pop_front() {
            Some(c) => c,
            None => {
                g.draining = false;
                return;
            }
        }
    };
    let op_state = Arc::clone(&state);
    let cb_state = Arc::clone(&state);
    let cb_runtime = Arc::clone(&runtime);
    let cb_handle = handle.clone();
    runtime.storage().submit_on(
        handle.clone(),
        move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let mut g = op_state.lock().unwrap();
            if g.file.is_none() {
                let path = unique_spool_path();
                let f = File::create(&path)?;
                g.file = Some(f);
                g.path = Some(path);
            }
            g.file.as_mut().unwrap().write_all(&chunk)?;
            Ok(())
        },
        move |result: Result<(), StorageError>| {
            let ok = result.is_ok();
            {
                let mut g = cb_state.lock().unwrap();
                if let Err(e) = &result {
                    g.error = Some(e.to_string());
                    g.queue.clear();
                    g.draining = false;
                }
            }
            cb_handle.with_endpoint(|ep| {
                // Lets `SmtpControlHandler::sync_pending_finish` (issue
                // #184) re-check `is_pending()` promptly once this was the
                // last outstanding write, instead of waiting for the
                // client's next input to trigger another `receive()`.
                ep.poke_handler();
            });
            if ok {
                drain_next(cb_state, cb_runtime, cb_handle);
            }
        },
    );
}

impl SmtpPipeline for SpoolPipeline {
    fn mail_from(&mut self, _sender: Option<&EmailAddress>) {}
    fn rcpt_to(&mut self, _recipient: &EmailAddress) {}

    fn message_content(&mut self, chunk: &[u8]) -> bool {
        let mut g = self.state.lock().unwrap();
        if g.error.is_some() {
            return false;
        }
        g.queue.push_back(chunk.to_vec());
        let should_start = !g.draining;
        if should_start {
            g.draining = true;
        }
        drop(g);
        if should_start {
            drain_next(
                Arc::clone(&self.state),
                Arc::clone(&self.runtime),
                self.handle.clone(),
            );
        }
        true
    }

    fn end_data(&mut self) {}

    fn reset(&mut self) {
        let mut g = self.state.lock().unwrap();
        g.queue.clear();
        g.draining = false;
        g.file = None;
        g.error = None;
        let path = g.path.take();
        drop(g);
        if let Some(p) = path {
            let _ = std::fs::remove_file(p);
        }
    }

    fn is_pending(&self) -> bool {
        let g = self.state.lock().unwrap();
        g.draining || !g.queue.is_empty()
    }
}

fn unique_spool_path() -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "hopf-smtp-spool-{}-{}-{}.tmp",
        std::process::id(),
        nanos,
        n
    ))
}

/// Shares a [`SpoolPipeline`] as the transaction [`SmtpPipeline`] between a
/// handler (which reads `path()`/`error()` after `end_data`) and whatever
/// object is actually registered via `MailFromHandler::pipeline()`.
pub(crate) struct SpoolPipelineHandle(pub(crate) Arc<Mutex<SpoolPipeline>>);

impl SmtpPipeline for SpoolPipelineHandle {
    fn mail_from(&mut self, sender: Option<&EmailAddress>) {
        self.0.lock().unwrap().mail_from(sender);
    }
    fn rcpt_to(&mut self, recipient: &EmailAddress) {
        self.0.lock().unwrap().rcpt_to(recipient);
    }
    fn message_content(&mut self, chunk: &[u8]) -> bool {
        self.0.lock().unwrap().message_content(chunk)
    }
    fn end_data(&mut self) {
        self.0.lock().unwrap().end_data();
    }
    fn reset(&mut self) {
        self.0.lock().unwrap().reset();
    }
    fn is_pending(&self) -> bool {
        self.0.lock().unwrap().is_pending()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hopf_core::RuntimeConfig;

    fn test_runtime_and_handle() -> (Arc<Runtime>, ConnHandle) {
        let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
        let handle = ConnHandle::from_execute(Arc::new(|task| task()));
        (rt, handle)
    }

    /// Spin-wait up to `max_ms` for `pipeline.is_pending()` to clear.
    fn wait_drained(pipeline: &SpoolPipeline, max_ms: u64) {
        for _ in 0..(max_ms / 5).max(1) {
            if !pipeline.is_pending() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(!pipeline.is_pending(), "spool writes never drained within {max_ms}ms");
    }

    #[test]
    fn writes_content_to_a_temp_file_in_order_and_cleans_up_on_reset() {
        let (rt, handle) = test_runtime_and_handle();
        let mut pipeline = SpoolPipeline::new(rt, handle);
        assert!(pipeline.message_content(b"one"));
        assert!(pipeline.message_content(b"-two"));
        assert!(pipeline.message_content(b"-three"));
        wait_drained(&pipeline, 2000);
        let path = pipeline.path().expect("spool file created lazily");
        assert!(path.exists());
        assert_eq!(std::fs::read(&path).unwrap(), b"one-two-three");
        pipeline.reset();
        assert!(!path.exists(), "reset must remove the spool file");
    }

    #[test]
    fn message_content_reports_false_once_a_write_error_is_latched() {
        let (rt, handle) = test_runtime_and_handle();
        let mut pipeline = SpoolPipeline::new(rt, handle);
        assert!(pipeline.message_content(b"first chunk succeeds"));
        wait_drained(&pipeline, 2000);
        // Simulate an unrecoverable spool error without needing a real
        // full disk: latch it directly, exactly as a real write failure
        // would via `drain_next`'s callback `Err` branch.
        pipeline.state.lock().unwrap().error = Some("disk full".to_string());
        assert!(
            !pipeline.message_content(b"more"),
            "message_content must report false once the pipeline can no longer accept content"
        );
    }

    #[test]
    fn empty_message_never_creates_a_file() {
        let (rt, handle) = test_runtime_and_handle();
        let pipeline = SpoolPipeline::new(rt, handle);
        assert!(pipeline.path().is_none());
    }

    #[test]
    fn is_pending_reflects_outstanding_queued_writes() {
        let (rt, handle) = test_runtime_and_handle();
        let mut pipeline = SpoolPipeline::new(rt, handle);
        assert!(!pipeline.is_pending(), "nothing queued yet");
        pipeline.message_content(b"chunk");
        wait_drained(&pipeline, 2000);
        assert!(!pipeline.is_pending(), "must clear once the write lands");
    }
}
