// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! IDLE command helpers (RFC 2177).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_core::TimerHandle;

/// Default mailbox poll interval while IDLEing.
pub const IDLE_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Shared IDLE flags for timer callbacks.
#[derive(Clone, Default)]
pub struct IdleShared {
    /// True while waiting for `DONE`.
    pub active: Arc<AtomicBool>,
    /// Last EXISTS / RECENT reported.
    pub counts: Arc<Mutex<(u32, u32)>>,
    /// Current timer handle (for cancel / replace).
    pub timer: Arc<Mutex<Option<TimerHandle>>>,
}

impl IdleShared {
    /// Enter IDLE after sending the continuation.
    pub fn begin(&self, exists: u32, recent: u32) {
        self.active.store(true, Ordering::Relaxed);
        *self.counts.lock().unwrap() = (exists, recent);
    }

    /// Leave IDLE and cancel any poll timer.
    pub fn end(&self) {
        self.active.store(false, Ordering::Relaxed);
        if let Some(t) = self.timer.lock().unwrap().take() {
            t.cancel();
        }
    }

    /// Whether IDLE is active.
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }
}

/// Per-connection IDLE session state.
#[derive(Default)]
pub struct IdleState {
    /// Shared flags / timer slot.
    pub shared: IdleShared,
    /// Tag of the IDLE command (for the final tagged OK).
    pub tag: Option<String>,
    /// Last EXISTS (mirrored for NOOP).
    pub last_exists: u32,
    /// Last RECENT (mirrored for NOOP).
    pub last_recent: u32,
}

impl IdleState {
    /// Enter IDLE after sending the continuation.
    pub fn begin(&mut self, tag: String, exists: u32, recent: u32) {
        self.tag = Some(tag);
        self.last_exists = exists;
        self.last_recent = recent;
        self.shared.begin(exists, recent);
    }

    /// Leave IDLE; returns the original tag for the tagged OK.
    pub fn end(&mut self) -> Option<String> {
        self.shared.end();
        self.tag.take()
    }

    /// Sync last_* from shared counts.
    pub fn sync_from_shared(&mut self) {
        let (e, r) = *self.shared.counts.lock().unwrap();
        self.last_exists = e;
        self.last_recent = r;
    }
}

/// Whether a lexer-emitted verb is the IDLE termination token.
pub fn is_idle_done(verb: &str) -> bool {
    verb.eq_ignore_ascii_case("DONE")
}

/// Snapshot used to decide which untagged updates to emit.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IdleMailboxSnapshot {
    /// Current EXISTS.
    pub exists: u32,
    /// Current RECENT.
    pub recent: u32,
}

/// Format EXISTS / RECENT lines that changed since `prev`.
pub fn idle_update_lines(prev: &IdleState, snap: &IdleMailboxSnapshot) -> Vec<String> {
    let mut out = Vec::new();
    if snap.exists != prev.last_exists {
        out.push(format!("{} EXISTS", snap.exists));
    }
    if snap.recent != prev.last_recent {
        out.push(format!("{} RECENT", snap.recent));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn done_parsing() {
        assert!(is_idle_done("DONE"));
        assert!(is_idle_done("done"));
        assert!(!is_idle_done("IDLE"));
        assert!(!is_idle_done("NOOP"));
    }

    #[test]
    fn idle_lifecycle() {
        let mut s = IdleState::default();
        s.begin("a1".into(), 3, 1);
        assert!(s.shared.is_active());
        assert_eq!(s.tag.as_deref(), Some("a1"));
        let tag = s.end();
        assert_eq!(tag.as_deref(), Some("a1"));
        assert!(!s.shared.is_active());
    }

    #[test]
    fn update_lines_only_on_change() {
        let mut prev = IdleState::default();
        prev.last_exists = 2;
        prev.last_recent = 0;
        let lines = idle_update_lines(
            &prev,
            &IdleMailboxSnapshot {
                exists: 3,
                recent: 0,
            },
        );
        assert_eq!(lines, vec!["3 EXISTS".to_string()]);
    }
}
