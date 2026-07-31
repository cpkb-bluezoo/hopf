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

use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use rmimeparser::EmailAddress;

use crate::server::pipeline::SmtpPipeline;

/// Spools message content to a local temp file, created lazily on first
/// content byte.
pub(crate) struct SpoolPipeline {
    file: Option<File>,
    path: Option<PathBuf>,
    error: Option<String>,
}

impl SpoolPipeline {
    pub(crate) fn new() -> Self {
        Self {
            file: None,
            path: None,
            error: None,
        }
    }

    /// The spool file path, once content has started arriving.
    pub(crate) fn path(&self) -> Option<&std::path::Path> {
        self.path.as_deref()
    }

    /// The first write error, if any (subsequent writes are dropped silently
    /// once set; callers must check this before trusting the spooled file).
    pub(crate) fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
}

impl SmtpPipeline for SpoolPipeline {
    fn mail_from(&mut self, _sender: Option<&EmailAddress>) {}
    fn rcpt_to(&mut self, _recipient: &EmailAddress) {}

    fn message_content(&mut self, chunk: &[u8]) -> bool {
        if self.error.is_some() {
            return false;
        }
        if self.file.is_none() {
            let path = unique_spool_path();
            match File::create(&path) {
                Ok(f) => {
                    self.file = Some(f);
                    self.path = Some(path);
                }
                Err(e) => {
                    self.error = Some(e.to_string());
                    return false;
                }
            }
        }
        if let Some(f) = &mut self.file {
            if let Err(e) = f.write_all(chunk) {
                self.error = Some(e.to_string());
                return false;
            }
        }
        true
    }

    fn end_data(&mut self) {}

    fn reset(&mut self) {
        if let Some(p) = self.path.take() {
            let _ = std::fs::remove_file(p);
        }
        self.file = None;
        self.error = None;
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_content_to_a_temp_file_and_cleans_up_on_reset() {
        let mut pipeline = SpoolPipeline::new();
        assert!(pipeline.message_content(b"one"));
        assert!(pipeline.message_content(b"-two"));
        let path = pipeline.path().expect("spool file created lazily").to_path_buf();
        assert!(path.exists());
        assert_eq!(std::fs::read(&path).unwrap(), b"one-two");
        pipeline.reset();
        assert!(!path.exists(), "reset must remove the spool file");
    }

    #[test]
    fn message_content_reports_false_once_a_write_error_is_latched() {
        let mut pipeline = SpoolPipeline::new();
        assert!(pipeline.message_content(b"first chunk succeeds"));
        // Simulate an unrecoverable spool error without needing a real
        // full disk: latch it directly, exactly as a real write failure
        // would via `message_content`'s own `Err` branch.
        pipeline.error = Some("disk full".to_string());
        assert!(
            !pipeline.message_content(b"more"),
            "message_content must report false once the pipeline can no longer accept content"
        );
    }

    #[test]
    fn empty_message_never_creates_a_file() {
        let pipeline = SpoolPipeline::new();
        assert!(pipeline.path().is_none());
    }
}
