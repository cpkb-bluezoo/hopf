// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! [`SpoolHandle`] — a ref-counted spool-file reference (issue #187) that
//! deletes its file, off the reactor thread, once the last clone drops.
//!
//! Replaces ad hoc "whoever finishes last deletes it" bookkeeping and
//! `Drop`-based immediate deletion: once spool reads (deferred QoS-1/2
//! delivery, offline-queue tracking, retained-message snapshots) are
//! offloaded to [`hopf_core::StorageExecutor`], several independent async
//! jobs can be reading the same file at once, and any of them — or the
//! publish/retain path that created it — can be the one to drop the last
//! reference. `Arc`'s own refcounting already answers "is anyone still
//! using this file" correctly regardless of which of them finishes last;
//! [`SpoolHandle`] just makes the resulting deletion non-blocking.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use hopf_core::{ConnHandle, Runtime, StorageError};

/// Cloneable handle to a spooled file, deleted once the last clone drops.
///
/// Public because it appears in [`crate::server::broker::RetainedMessage`]/
/// [`crate::server::broker::RetainedSnapshot`]'s `path` field and
/// [`crate::server::broker::BrokerState::deliver_deferred`]/`retain`'s
/// signatures, which are themselves public API — not intended to be
/// constructed by callers outside this crate (the defining module is
/// private), just observed/passed through.
#[derive(Clone)]
pub struct SpoolHandle(Arc<SpoolHandleInner>);

impl std::fmt::Debug for SpoolHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpoolHandle").field("path", &self.0.path).finish()
    }
}

struct SpoolHandleInner {
    path: PathBuf,
    runtime: Arc<Runtime>,
    /// Routing target for the offloaded delete's `submit_on` callback —
    /// `submit_on`'s callback dispatch only ever calls `ConnHandle::execute`
    /// on this, never `with_endpoint`, so it doesn't need to still be a
    /// live connection (a task-only `ConnHandle::from_execute` handle,
    /// same construct this crate's own tests already build, works fine
    /// even long after the connection that created it is gone).
    handle: ConnHandle,
}

impl SpoolHandle {
    pub(crate) fn new(path: PathBuf, runtime: Arc<Runtime>, handle: ConnHandle) -> Self {
        Self(Arc::new(SpoolHandleInner { path, runtime, handle }))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0.path
    }
}

impl Drop for SpoolHandleInner {
    fn drop(&mut self) {
        let path = std::mem::take(&mut self.path);
        self.runtime.storage().submit_on(
            self.handle.clone(),
            move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                let _ = std::fs::remove_file(&path);
                Ok(())
            },
            |_: Result<(), StorageError>| {},
        );
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

    fn wait_for(pred: impl Fn() -> bool, max_ms: u64) -> bool {
        for _ in 0..(max_ms / 5).max(1) {
            if pred() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        pred()
    }

    #[test]
    fn deletes_file_only_once_the_last_clone_drops() {
        let (rt, handle) = test_runtime_and_handle();
        let path = std::env::temp_dir().join(format!(
            "hopf-mqtt-spoolhandle-test-{}-{}.tmp",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, b"hi").unwrap();

        let sh = SpoolHandle::new(path.clone(), rt, handle);
        let sh2 = sh.clone();
        let sh3 = sh.clone();

        drop(sh);
        drop(sh2);
        // Give any (incorrect) premature delete a chance to land before we
        // assert the file is still there.
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(path.exists(), "file must survive while a clone is still held");

        drop(sh3);
        assert!(
            wait_for(|| !path.exists(), 2000),
            "file must be removed once the last clone drops"
        );
    }

    #[test]
    fn path_accessor_returns_the_spooled_path() {
        let (rt, handle) = test_runtime_and_handle();
        let path = std::env::temp_dir().join("hopf-mqtt-spoolhandle-path-test.tmp");
        let sh = SpoolHandle::new(path.clone(), rt, handle);
        assert_eq!(sh.path(), path.as_path());
    }
}
