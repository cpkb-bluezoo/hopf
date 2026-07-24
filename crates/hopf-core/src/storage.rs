// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Bounded pool for blocking storage / filesystem work (Gumdrop `StorageExecutor`).

use std::error::Error as StdError;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvError, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use crate::endpoint::Endpoint;
use crate::handle::ConnHandle;

/// Failure from a storage submission or blocking operation.
#[derive(Debug)]
pub enum StorageError {
    /// The bounded queue was full — fail-fast backpressure (never block the reactor).
    Rejected,
    /// The blocking operation returned an error.
    Task(Box<dyn StdError + Send + Sync>),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected => write!(f, "storage executor queue is full"),
            Self::Task(e) => write!(f, "storage task failed: {e}"),
        }
    }
}

impl StdError for StorageError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Task(e) => Some(e.as_ref()),
            Self::Rejected => None,
        }
    }
}

/// Configuration for [`StorageExecutor`].
#[derive(Clone, Debug)]
pub struct StorageConfig {
    /// Fixed number of storage worker threads.
    pub threads: usize,
    /// Bounded queue capacity; submissions beyond this are rejected.
    pub queue_capacity: usize,
}

impl Default for StorageConfig {
    fn default() -> Self {
        let n = std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(4);
        Self {
            threads: n.max(4),
            queue_capacity: 4096,
        }
    }
}

type Job = Box<dyn FnOnce() + Send>;

/// Shared, bounded thread pool for blocking work that must not run on a reactor.
pub struct StorageExecutor {
    tx: SyncSender<Job>,
    joins: Vec<JoinHandle<()>>,
    /// Approximate queued + running jobs (for diagnostics / tests).
    pending: Arc<AtomicUsize>,
}

impl StorageExecutor {
    /// Create a pool with the given size and queue capacity.
    pub fn new(config: StorageConfig) -> Self {
        assert!(config.threads >= 1, "threads must be at least 1");
        assert!(
            config.queue_capacity >= 1,
            "queue_capacity must be at least 1"
        );
        let (tx, rx) = mpsc::sync_channel::<Job>(config.queue_capacity);
        let rx = Arc::new(std::sync::Mutex::new(rx));
        let pending = Arc::new(AtomicUsize::new(0));
        let mut joins = Vec::with_capacity(config.threads);
        for i in 0..config.threads {
            let rx = Arc::clone(&rx);
            let join = thread::Builder::new()
                .name(format!("hopf-storage-{}", i + 1))
                .spawn(move || storage_worker(rx))
                .expect("spawn storage worker");
            joins.push(join);
        }
        Self { tx, joins, pending }
    }

    /// Run `op` on a storage thread; deliver `callback` on `endpoint`'s reactor.
    ///
    /// On queue saturation, `callback` is invoked on the reactor with
    /// [`StorageError::Rejected`] — the blocking work is never run on the
    /// reactor thread.
    pub fn submit<T, Op, Cb>(&self, endpoint: &dyn Endpoint, op: Op, callback: Cb)
    where
        T: Send + 'static,
        Op: FnOnce() -> Result<T, Box<dyn StdError + Send + Sync>> + Send + 'static,
        Cb: FnOnce(Result<T, StorageError>) + Send + 'static,
    {
        self.submit_on(endpoint.handle(), op, callback);
    }

    /// Like [`submit`](Self::submit) but using an existing [`ConnHandle`].
    pub fn submit_on<T, Op, Cb>(&self, handle: ConnHandle, op: Op, callback: Cb)
    where
        T: Send + 'static,
        Op: FnOnce() -> Result<T, Box<dyn StdError + Send + Sync>> + Send + 'static,
        Cb: FnOnce(Result<T, StorageError>) + Send + 'static,
    {
        let pending = Arc::clone(&self.pending);
        let callback = Arc::new(std::sync::Mutex::new(Some(callback)));
        let handle_for_job = handle.clone();
        let callback_for_job = Arc::clone(&callback);
        let job: Job = Box::new(move || {
            let result = match op() {
                Ok(v) => Ok(v),
                Err(e) => Err(StorageError::Task(e)),
            };
            let cb = callback_for_job
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            if let Some(cb) = cb {
                handle_for_job.execute(Box::new(move || cb(result)));
            }
            pending.fetch_sub(1, Ordering::Relaxed);
        });

        match self.tx.try_send(job) {
            Ok(()) => {
                self.pending.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                let cb = callback
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take();
                if let Some(cb) = cb {
                    handle.execute(Box::new(move || {
                        cb(Err(StorageError::Rejected));
                    }));
                }
            }
        }
    }

    /// Approximate number of queued or running jobs.
    pub fn pending_count(&self) -> usize {
        self.pending.load(Ordering::Relaxed)
    }

    /// Shut down workers. Pending results may be dropped.
    pub fn shutdown(self) {
        drop(self.tx);
        for join in self.joins {
            let _ = join.join();
        }
    }
}

fn storage_worker(rx: Arc<std::sync::Mutex<Receiver<Job>>>) {
    loop {
        let job = {
            let guard = rx.lock().unwrap_or_else(|e| e.into_inner());
            match guard.recv() {
                Ok(job) => job,
                Err(RecvError) => break,
            }
        };
        job();
    }
}
