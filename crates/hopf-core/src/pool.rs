// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Generic, protocol-agnostic connection pool (issue #343).
//!
//! [`Pool`] hands out [`ConnHandle`]s keyed by a caller-supplied key
//! (host:port, a UNIX socket path, whatever identifies "the same remote"
//! for a given protocol crate) so a client facade can reuse a live
//! connection instead of dialing fresh every time. It knows nothing about
//! any particular wire protocol — HTTP keep-alive, SMTP pipelining, AMQP
//! channel reuse, and whether pooling even makes sense at all (probably
//! not for a stateful IMAP session) are all decisions that stay in each
//! protocol crate. This just needs to hand back the same live connection.
//!
//! # Usage
//!
//! ```ignore
//! let pool: Pool<SocketAddr> = Pool::new(PoolConfig::default());
//!
//! let pooled = match pool.checkout(&addr) {
//!     Some(pooled) => pooled,
//!     None => {
//!         let handle = dial_and_get_conn_handle(addr); // however this crate dials
//!         pool.adopt(addr, handle)
//!     }
//! };
//! pooled.send(request_bytes);
//! // `pooled` returns itself to the pool on drop, unless `mark_bad()` was
//! // called first (e.g. after an I/O error) — then it's closed instead.
//! ```

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::endpoint::TimerHandle;
use crate::handle::ConnHandle;

/// Pool tuning: how many idle connections to keep, and for how long.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    max_idle_per_key: usize,
    max_idle_total: usize,
    idle_timeout: Option<Duration>,
}

impl Default for PoolConfig {
    /// 4 idle connections per key, 64 total, evicted after 90s idle.
    fn default() -> Self {
        Self {
            max_idle_per_key: 4,
            max_idle_total: 64,
            idle_timeout: Some(Duration::from_secs(90)),
        }
    }
}

impl PoolConfig {
    /// Cap on idle connections kept for any single key.
    pub fn max_idle_per_key(mut self, n: usize) -> Self {
        self.max_idle_per_key = n;
        self
    }

    /// Cap on idle connections kept across all keys combined.
    pub fn max_idle_total(mut self, n: usize) -> Self {
        self.max_idle_total = n;
        self
    }

    /// How long an idle connection is kept before it's closed and evicted.
    /// `None` disables idle eviction (connections are only dropped by the
    /// per-key/total caps, or once [`ConnHandle::is_probably_open`] says
    /// they've died).
    pub fn idle_timeout(mut self, d: Option<Duration>) -> Self {
        self.idle_timeout = d;
        self
    }
}

struct Entry {
    id: u64,
    handle: ConnHandle,
    timer: Option<TimerHandle>,
}

struct State<K> {
    idle: HashMap<K, VecDeque<Entry>>,
    total_idle: usize,
    next_id: u64,
}

struct Shared<K> {
    config: PoolConfig,
    state: Mutex<State<K>>,
}

impl<K: Eq + Hash + Clone + Send + Sync + 'static> Shared<K> {
    fn return_idle(self: &Arc<Self>, key: K, handle: ConnHandle) {
        if !handle.is_probably_open() {
            handle.close();
            return;
        }
        let mut state = self.state.lock().unwrap();
        let per_key_len = state.idle.get(&key).map_or(0, VecDeque::len);
        if state.total_idle >= self.config.max_idle_total
            || per_key_len >= self.config.max_idle_per_key
        {
            drop(state);
            handle.close();
            return;
        }
        let id = state.next_id;
        state.next_id += 1;
        let timer = self.config.idle_timeout.map(|d| {
            let shared = Arc::clone(self);
            let key_for_timer = key.clone();
            handle.schedule_timer(
                d,
                Box::new(move || shared.evict(&key_for_timer, id)),
            )
        });
        state.idle.entry(key).or_default().push_back(Entry {
            id,
            handle,
            timer,
        });
        state.total_idle += 1;
    }

    fn evict(&self, key: &K, id: u64) {
        let mut state = self.state.lock().unwrap();
        let Some(entries) = state.idle.get_mut(key) else {
            return;
        };
        let Some(pos) = entries.iter().position(|e| e.id == id) else {
            return;
        };
        let entry = entries.remove(pos).unwrap();
        if entries.is_empty() {
            state.idle.remove(key);
        }
        state.total_idle -= 1;
        drop(state);
        entry.handle.close();
    }
}

/// A pool of idle [`ConnHandle`]s, keyed by `K`.
pub struct Pool<K> {
    shared: Arc<Shared<K>>,
}

impl<K> Clone for Pool<K> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<K: Eq + Hash + Clone + Send + Sync + 'static> Pool<K> {
    /// Build an empty pool with the given tuning.
    pub fn new(config: PoolConfig) -> Self {
        Self {
            shared: Arc::new(Shared {
                config,
                state: Mutex::new(State {
                    idle: HashMap::new(),
                    total_idle: 0,
                    next_id: 0,
                }),
            }),
        }
    }

    /// Take an idle connection for `key`, if one is available and still
    /// alive. Dead idle connections found along the way (their
    /// [`ConnHandle::is_probably_open`] says the peer is gone) are closed
    /// and dropped rather than returned — this keeps scanning the rest of
    /// that key's idle queue instead of giving up on the first dead one.
    pub fn checkout(&self, key: &K) -> Option<PooledConn<K>> {
        let mut guard = self.shared.state.lock().unwrap();
        let state = &mut *guard;
        let entries = state.idle.get_mut(key)?;
        while let Some(entry) = entries.pop_front() {
            state.total_idle -= 1;
            if let Some(timer) = &entry.timer {
                timer.cancel();
            }
            if entry.handle.is_probably_open() {
                if entries.is_empty() {
                    state.idle.remove(key);
                }
                return Some(PooledConn {
                    shared: Arc::clone(&self.shared),
                    key: key.clone(),
                    handle: Some(entry.handle),
                    bad: false,
                });
            }
            entry.handle.close();
        }
        state.idle.remove(key);
        None
    }

    /// Wrap a freshly-dialed connection as checked-out from this pool —
    /// used when [`checkout`](Self::checkout) found nothing idle and the
    /// caller dialed fresh. The caller gets the same drop-returns-it-to-
    /// the-pool guard as a real checkout.
    pub fn adopt(&self, key: K, handle: ConnHandle) -> PooledConn<K> {
        PooledConn {
            shared: Arc::clone(&self.shared),
            key,
            handle: Some(handle),
            bad: false,
        }
    }

    /// Number of idle connections currently held for `key` (for tests/metrics).
    pub fn idle_count(&self, key: &K) -> usize {
        self.shared
            .state
            .lock()
            .unwrap()
            .idle
            .get(key)
            .map_or(0, VecDeque::len)
    }
}

/// A checked-out connection. Returns itself to the pool on drop unless
/// [`mark_bad`](Self::mark_bad) was called first, in which case it's closed
/// instead. Derefs to [`ConnHandle`] for `send`/`close`/`with_endpoint`/etc.
pub struct PooledConn<K: Eq + Hash + Clone + Send + Sync + 'static> {
    shared: Arc<Shared<K>>,
    key: K,
    handle: Option<ConnHandle>,
    bad: bool,
}

impl<K: Eq + Hash + Clone + Send + Sync + 'static> PooledConn<K> {
    /// Flag this connection as unusable — on drop it's closed rather than
    /// returned to the pool. Call this after observing an I/O error or a
    /// protocol-level condition that means the connection shouldn't be
    /// reused (the caller's protocol crate is the one that knows what that
    /// means for its own wire format).
    pub fn mark_bad(&mut self) {
        self.bad = true;
    }
}

impl<K: Eq + Hash + Clone + Send + Sync + 'static> std::ops::Deref for PooledConn<K> {
    type Target = ConnHandle;

    fn deref(&self) -> &ConnHandle {
        self.handle.as_ref().expect("handle only taken on drop")
    }
}

impl<K: Eq + Hash + Clone + Send + Sync + 'static> Drop for PooledConn<K> {
    fn drop(&mut self) {
        let Some(handle) = self.handle.take() else {
            return;
        };
        if self.bad {
            handle.close();
            return;
        }
        self.shared.return_idle(self.key.clone(), handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handle::ConnHandleBackend;
    use crate::endpoint::Endpoint;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct FakeEndpoint;

    impl Endpoint for FakeEndpoint {
        fn send(&mut self, _data: &[u8]) {}
        fn is_open(&self) -> bool {
            true
        }
        fn is_closing(&self) -> bool {
            false
        }
        fn close(&mut self) {}
        fn local_addr(&self) -> std::io::Result<crate::PeerAddr> {
            Ok(crate::PeerAddr::Inet("127.0.0.1:0".parse().unwrap()))
        }
        fn remote_addr(&self) -> std::io::Result<crate::PeerAddr> {
            Ok(crate::PeerAddr::Inet("127.0.0.1:0".parse().unwrap()))
        }
        fn security_info(&self) -> &crate::security::SecurityInfo {
            static PLAINTEXT: std::sync::OnceLock<crate::security::SecurityInfo> =
                std::sync::OnceLock::new();
            PLAINTEXT.get_or_init(crate::security::SecurityInfo::plaintext)
        }
        fn start_tls(&mut self) -> Result<(), crate::error::StartTlsError> {
            Err(crate::error::StartTlsError::Unsupported)
        }
        fn pause_read(&mut self) {}
        fn resume_read(&mut self) {}
        fn on_write_ready(&mut self, _callback: Option<crate::endpoint::WriteReadyCallback>) {}
        fn execute(&self, task: Box<dyn FnOnce() + Send>) {
            task();
        }
        fn schedule_timer(&self, _delay: Duration, _callback: Box<dyn FnOnce() + Send>) -> TimerHandle {
            TimerHandle::new(|| {})
        }
        fn handle(&self) -> ConnHandle {
            unreachable!("not exercised by these tests")
        }
    }

    /// A [`ConnHandleBackend`] whose openness/close/timer behavior a test
    /// can observe and control directly — a real `hopf-core` TCP
    /// connection needs a live reactor thread, which these unit tests
    /// (pool bookkeeping only, not real I/O) shouldn't need to spin up.
    struct FakeBackend {
        open: Arc<AtomicBool>,
    }

    impl ConnHandleBackend for FakeBackend {
        fn with_endpoint(&self, task: Box<dyn FnOnce(&mut dyn Endpoint) + Send>) {
            let mut ep = FakeEndpoint;
            task(&mut ep);
        }
        fn execute(&self, task: Box<dyn FnOnce() + Send>) {
            task();
        }
        fn is_probably_open(&self) -> bool {
            self.open.load(Ordering::SeqCst)
        }
        fn schedule_timer(&self, delay: Duration, callback: Box<dyn FnOnce() + Send>) -> TimerHandle {
            let cancelled = Arc::new(AtomicBool::new(false));
            let flag = Arc::clone(&cancelled);
            std::thread::spawn(move || {
                std::thread::sleep(delay);
                if !flag.load(Ordering::SeqCst) {
                    callback();
                }
            });
            TimerHandle::new(move || cancelled.store(true, Ordering::SeqCst))
        }
    }

    fn fake_handle() -> (ConnHandle, Arc<AtomicBool>) {
        let open = Arc::new(AtomicBool::new(true));
        let backend = Arc::new(FakeBackend {
            open: Arc::clone(&open),
        });
        (ConnHandle::from_backend(backend), open)
    }

    #[test]
    fn checkout_on_empty_pool_returns_none() {
        let pool: Pool<u32> = Pool::new(PoolConfig::default());
        assert!(pool.checkout(&1).is_none());
    }

    #[test]
    fn adopted_connection_becomes_available_after_drop() {
        let pool: Pool<u32> = Pool::new(PoolConfig::default());
        let (handle, _open) = fake_handle();
        let pooled = pool.adopt(1, handle);
        assert!(pool.checkout(&1).is_none(), "not idle until dropped");
        drop(pooled);
        assert_eq!(pool.idle_count(&1), 1);
        let checked_out = pool.checkout(&1);
        assert!(checked_out.is_some());
        assert_eq!(
            pool.idle_count(&1),
            0,
            "checked-out connection must not still count as idle"
        );
    }

    #[test]
    fn checkout_skips_and_drops_a_dead_idle_connection() {
        let pool: Pool<u32> = Pool::new(PoolConfig::default());
        let (dead, dead_open) = fake_handle();
        dead_open.store(false, Ordering::SeqCst);
        drop(pool.adopt(1, dead));

        let (alive, _alive_open) = fake_handle();
        drop(pool.adopt(1, alive));

        // Both were "returned" idle, but the dead one shouldn't come back
        // out of checkout — only the live one should.
        let pooled = pool.checkout(&1).expect("the live connection should still be checked out");
        assert!(pooled.is_probably_open());
        assert!(pool.checkout(&1).is_none(), "dead entry must not be handed out twice");
    }

    #[test]
    fn mark_bad_closes_instead_of_returning_to_the_pool() {
        let pool: Pool<u32> = Pool::new(PoolConfig::default());
        let (handle, _open) = fake_handle();
        let mut pooled = pool.adopt(1, handle);
        pooled.mark_bad();
        drop(pooled);
        assert_eq!(pool.idle_count(&1), 0);
        assert!(pool.checkout(&1).is_none());
    }

    #[test]
    fn max_idle_per_key_closes_the_returned_connection_once_full() {
        let pool: Pool<u32> = Pool::new(PoolConfig::default().max_idle_per_key(1));
        let (h1, _o1) = fake_handle();
        let (h2, _o2) = fake_handle();
        drop(pool.adopt(1, h1));
        drop(pool.adopt(1, h2));
        assert_eq!(pool.idle_count(&1), 1, "cap of 1 per key must not be exceeded");
    }

    #[test]
    fn max_idle_total_is_enforced_across_keys() {
        let pool: Pool<u32> = Pool::new(PoolConfig::default().max_idle_total(1));
        let (h1, _o1) = fake_handle();
        let (h2, _o2) = fake_handle();
        drop(pool.adopt(1, h1));
        drop(pool.adopt(2, h2));
        let total = pool.idle_count(&1) + pool.idle_count(&2);
        assert_eq!(total, 1, "total cap of 1 across all keys must not be exceeded");
    }

    #[test]
    fn idle_timeout_evicts_after_the_configured_duration() {
        let pool: Pool<u32> = Pool::new(
            PoolConfig::default()
                .idle_timeout(Some(Duration::from_millis(30)))
                .max_idle_total(10),
        );
        let (handle, _open) = fake_handle();
        drop(pool.adopt(1, handle));
        assert_eq!(pool.idle_count(&1), 1);
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(pool.idle_count(&1), 0, "idle entry should have been evicted");
    }

    #[test]
    fn checkout_cancels_the_idle_timer_so_it_never_fires() {
        let pool: Pool<u32> = Pool::new(
            PoolConfig::default().idle_timeout(Some(Duration::from_millis(30))),
        );
        let (handle, _open) = fake_handle();
        drop(pool.adopt(1, handle));
        let pooled = pool.checkout(&1).unwrap();
        // Hold it checked out past the idle timeout — the timer that would
        // have evicted it must have been cancelled at checkout time, not
        // left free to fire against an entry that's no longer idle.
        std::thread::sleep(Duration::from_millis(150));
        drop(pooled);
        assert_eq!(
            pool.idle_count(&1),
            1,
            "checking out an entry must cancel its idle timer"
        );
    }
}
