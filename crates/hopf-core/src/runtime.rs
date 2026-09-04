// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Process-wide runtime: worker reactors + accept loop + storage pool.

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use crate::accept::{AcceptHandle, AcceptLoop};
use crate::binding::BindingId;
use crate::cmd::ReactorCmd;
use crate::connector::{TcpConnectorConfig, UnixConnectorConfig};
use crate::listener::{TcpListenerConfig, UnixListenerConfig};
use crate::reactor::Reactor;
use crate::service::Service;
use crate::storage::{StorageConfig, StorageExecutor};
use crate::telemetry::TelemetryHook;

/// Runtime configuration.
#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    /// Number of worker reactor threads. `0` means `available_parallelism * 2` (min 2).
    pub worker_threads: usize,
    /// Blocking storage / filesystem pool.
    pub storage: StorageConfig,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            worker_threads: 0,
            storage: StorageConfig::default(),
        }
    }
}

impl RuntimeConfig {
    pub(crate) fn resolved_workers(&self) -> usize {
        if self.worker_threads > 0 {
            return self.worker_threads;
        }
        let n = std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(2);
        (n * 2).max(2)
    }
}

/// Owns worker reactors, the accept loop, and the storage executor.
pub struct Runtime {
    workers: Vec<crate::cmd::ReactorHandle>,
    accept: AcceptHandle,
    active: Arc<AtomicBool>,
    joins: Vec<JoinHandle<()>>,
    storage: Arc<StorageExecutor>,
    /// Round-robin index for dial affinity (peer of accept-loop RR).
    dial_rr: AtomicUsize,
    telemetry: Option<Arc<dyn TelemetryHook>>,
}

impl Runtime {
    /// Start worker reactors, accept loop, and storage pool.
    pub fn start(config: RuntimeConfig) -> io::Result<Self> {
        Self::start_with_telemetry(config, None)
    }

    /// Start with an optional telemetry hook.
    pub fn start_with_telemetry(
        config: RuntimeConfig,
        telemetry: Option<Arc<dyn TelemetryHook>>,
    ) -> io::Result<Self> {
        let n = config.resolved_workers();
        let active = Arc::new(AtomicBool::new(true));
        let storage = Arc::new(StorageExecutor::new(config.storage));
        let mut workers = Vec::with_capacity(n);
        let mut joins = Vec::with_capacity(n + 1);
        for id in 0..n {
            let (handle, join) = Reactor::spawn(id, Arc::clone(&active))?;
            workers.push(handle);
            joins.push(join);
        }
        let (accept, accept_join) =
            AcceptLoop::spawn(workers.clone(), Arc::clone(&active), telemetry.clone())?;
        joins.push(accept_join);
        Ok(Self {
            workers,
            accept,
            active,
            joins,
            storage,
            dial_rr: AtomicUsize::new(0),
            telemetry,
        })
    }

    /// Register a TCP listener; returns local address and binding id.
    pub fn add_tcp_listener(
        &self,
        config: TcpListenerConfig,
    ) -> io::Result<(SocketAddr, BindingId)> {
        let std_listener = std::net::TcpListener::bind(config.addr)?;
        std_listener.set_nonblocking(true)?;
        let addr = std_listener.local_addr()?;
        let listener = mio::net::TcpListener::from_std(std_listener);
        let id = BindingId::next();
        self.accept.add_listener(id, listener, config);
        Ok((addr, id))
    }

    /// Register a UNIX domain socket listener; returns the bound path and
    /// binding id. Removes a stale socket file left at `config.path` by an
    /// unclean previous shutdown before binding (only if it's actually a
    /// socket, never an unrelated file that happens to sit at that path).
    pub fn add_unix_listener(&self, config: UnixListenerConfig) -> io::Result<(PathBuf, BindingId)> {
        use std::os::unix::fs::FileTypeExt;
        if let Ok(meta) = std::fs::symlink_metadata(&config.path) {
            if meta.file_type().is_socket() {
                let _ = std::fs::remove_file(&config.path);
            }
        }
        let std_listener = std::os::unix::net::UnixListener::bind(&config.path)?;
        std_listener.set_nonblocking(true)?;
        let path = config.path.clone();
        let listener = mio::net::UnixListener::from_std(std_listener);
        let id = BindingId::next();
        self.accept.add_unix_listener(id, listener, config);
        Ok((path, id))
    }

    /// Remove a previously added listener binding — TCP or UNIX domain
    /// socket, whichever `id` refers to.
    pub fn remove_binding(&self, id: BindingId) {
        self.accept.remove_listener(id);
    }

    /// Dial a peer and register the Endpoint on a worker reactor (affinity).
    pub fn connect(&self, config: TcpConnectorConfig) -> io::Result<()> {
        if let Some(t) = &self.telemetry {
            t.on_dial(config.addr.into());
        }
        let stream = mio::net::TcpStream::connect(config.addr)?;
        let handler = config.create_handler();
        let params = config.conn_params();
        let idx = self.dial_rr.fetch_add(1, Ordering::Relaxed) % self.workers.len();
        self.workers[idx].send(ReactorCmd::Register {
            stream: stream.into(),
            handler,
            params,
            connecting: true,
            telemetry: self.telemetry.clone(),
        });
        Ok(())
    }

    /// Dial a UNIX domain socket peer and register the Endpoint on a worker
    /// reactor (affinity) — UNIX-domain counterpart of [`Self::connect`].
    pub fn connect_unix(&self, config: UnixConnectorConfig) -> io::Result<()> {
        if let Some(t) = &self.telemetry {
            t.on_dial(crate::PeerAddr::Unix(Some(config.path.clone())));
        }
        let stream = mio::net::UnixStream::connect(&config.path)?;
        let handler = config.create_handler();
        let params = config.conn_params();
        let idx = self.dial_rr.fetch_add(1, Ordering::Relaxed) % self.workers.len();
        self.workers[idx].send(ReactorCmd::Register {
            stream: stream.into(),
            handler,
            params,
            connecting: true,
            telemetry: self.telemetry.clone(),
        });
        Ok(())
    }

    /// Start a [`Service`]: `service.start` should register bindings itself.
    ///
    /// Still registers any [`Service::tcp_listeners`] for transitional callers.
    pub fn start_service<S: Service>(&self, service: &mut S) -> io::Result<()> {
        service.start(self)?;
        for listener in service.tcp_listeners() {
            let _ = self.add_tcp_listener(listener.clone())?;
        }
        Ok(())
    }

    /// Shared storage executor for blocking filesystem / mailbox work.
    pub fn storage(&self) -> &Arc<StorageExecutor> {
        &self.storage
    }

    /// Number of worker reactors.
    pub fn worker_count(&self) -> usize {
        self.workers.len()
    }

    /// Handle for worker reactor `index` (0-based).
    pub fn worker(&self, index: usize) -> Option<&crate::cmd::ReactorHandle> {
        self.workers.get(index)
    }

    /// Round-robin pick a worker for dial / DNS affinity.
    pub fn pick_worker(&self) -> &crate::cmd::ReactorHandle {
        let idx = self.dial_rr.fetch_add(1, Ordering::Relaxed) % self.workers.len();
        &self.workers[idx]
    }

    /// Process-wide telemetry hook, if one was supplied at
    /// [`Self::start_with_telemetry`].
    pub fn telemetry(&self) -> Option<&Arc<dyn TelemetryHook>> {
        self.telemetry.as_ref()
    }

    /// Schedule a timer on a specific worker (no TCP endpoint required).
    pub fn schedule_on_worker(
        &self,
        worker_index: usize,
        delay: std::time::Duration,
        callback: Box<dyn FnOnce() + Send>,
    ) -> Option<std::sync::Arc<std::sync::atomic::AtomicBool>> {
        let w = self.workers.get(worker_index)?;
        Some(w.schedule_timer(delay, callback))
    }

    /// Request shutdown of accept + reactors + storage and join threads.
    pub fn shutdown(self) {
        self.active.store(false, Ordering::Release);
        self.accept.shutdown();
        for w in &self.workers {
            w.send(ReactorCmd::Shutdown);
        }
        for join in self.joins {
            let _ = join.join();
        }
        if let Ok(storage) = Arc::try_unwrap(self.storage) {
            storage.shutdown();
        }
    }
}
