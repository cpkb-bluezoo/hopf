// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! IDLE command helpers (RFC 2177).

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hopf_core::TimerHandle;
use hopf_mailbox::Flag;

use crate::server::fetch_format::format_flags;

/// Default mailbox poll interval while IDLEing.
pub const IDLE_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Default maximum IDLE duration before the server ends the command (RFC 2177).
///
/// Clients are advised to re-issue IDLE at least every 29 minutes; we terminate
/// at 29 minutes with a tagged OK so the client can restart cleanly.
pub const IDLE_MAX_DURATION: Duration = Duration::from_secs(29 * 60);

/// Shared IDLE flags for timer callbacks.
#[derive(Clone, Default)]
pub struct IdleShared {
    /// True while waiting for `DONE`.
    pub active: Arc<AtomicBool>,
    /// Tag of the outstanding IDLE (for auto-complete on max duration).
    pub tag: Arc<Mutex<Option<String>>>,
    /// Wall-clock start of the current IDLE (for max-duration enforcement).
    pub started: Arc<Mutex<Option<Instant>>>,
    /// Last EXISTS reported.
    pub exists: Arc<Mutex<u32>>,
    /// Last per-message snapshot (sequence order): `(uid, flags, keywords)`.
    pub messages: Arc<Mutex<Vec<IdleMsgSnap>>>,
    /// Current timer handle (for cancel / replace).
    pub timer: Arc<Mutex<Option<TimerHandle>>>,
}

/// One message's identity + flags for IDLE diffs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdleMsgSnap {
    /// IMAP UID.
    pub uid: u64,
    /// System flags.
    pub flags: BTreeSet<Flag>,
    /// User keywords.
    pub keywords: BTreeSet<String>,
}

impl IdleShared {
    /// Enter IDLE after sending the continuation.
    pub fn begin(&self, tag: String, exists: u32, messages: Vec<IdleMsgSnap>) {
        self.active.store(true, Ordering::Relaxed);
        *self.tag.lock().unwrap() = Some(tag);
        *self.started.lock().unwrap() = Some(Instant::now());
        *self.exists.lock().unwrap() = exists;
        *self.messages.lock().unwrap() = messages;
    }

    /// Leave IDLE and cancel any poll timer. Returns the IDLE tag if still set.
    pub fn end(&self) -> Option<String> {
        self.active.store(false, Ordering::Relaxed);
        *self.started.lock().unwrap() = None;
        if let Some(t) = self.timer.lock().unwrap().take() {
            t.cancel();
        }
        self.tag.lock().unwrap().take()
    }

    /// Whether IDLE is active.
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    /// Whether the IDLE has exceeded `max` duration.
    pub fn timed_out(&self, max: Duration) -> bool {
        self.started
            .lock()
            .unwrap()
            .map(|t| t.elapsed() >= max)
            .unwrap_or(false)
    }
}

/// Per-connection IDLE session state.
#[derive(Default)]
pub struct IdleState {
    /// Shared flags / timer slot.
    pub shared: IdleShared,
    /// Last EXISTS (mirrored for NOOP).
    pub last_exists: u32,
    /// Last per-message snapshot (mirrored for NOOP).
    pub last_messages: Vec<IdleMsgSnap>,
}

impl IdleState {
    /// Enter IDLE after sending the continuation.
    pub fn begin(&mut self, tag: String, exists: u32, messages: Vec<IdleMsgSnap>) {
        self.last_exists = exists;
        self.last_messages = messages.clone();
        self.shared.begin(tag, exists, messages);
    }

    /// Leave IDLE; returns the original tag for the tagged OK.
    pub fn end(&mut self) -> Option<String> {
        self.shared.end()
    }

    /// Whether IDLE is active.
    pub fn is_active(&self) -> bool {
        self.shared.is_active()
    }

    /// Sync last_* from shared state.
    pub fn sync_from_shared(&mut self) {
        self.last_exists = *self.shared.exists.lock().unwrap();
        self.last_messages = self.shared.messages.lock().unwrap().clone();
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
    /// Messages in sequence order.
    pub messages: Vec<IdleMsgSnap>,
}

/// Format untagged EXISTS / EXPUNGE / FETCH FLAGS lines that changed since `prev`.
///
/// Does **not** emit RECENT (removed in IMAP4rev2 / RFC 9051).
pub fn idle_update_lines(prev: &IdleState, snap: &IdleMailboxSnapshot) -> Vec<String> {
    idle_diff_lines(&prev.last_messages, prev.last_exists, snap)
}

/// Diff `prev_messages` / `prev_exists` against `snap`.
pub fn idle_diff_lines(
    prev_messages: &[IdleMsgSnap],
    prev_exists: u32,
    snap: &IdleMailboxSnapshot,
) -> Vec<String> {
    let mut out = Vec::new();

    // EXPUNGE for vanished UIDs (sequence numbers after prior expunges in this diff).
    let new_uids: BTreeSet<u64> = snap.messages.iter().map(|m| m.uid).collect();
    let mut seq = 1u32;
    for old in prev_messages {
        if new_uids.contains(&old.uid) {
            seq = seq.saturating_add(1);
        } else {
            out.push(format!("{seq} EXPUNGE"));
            // Do not advance seq — the next survivor takes this number.
        }
    }

    if snap.exists != prev_exists {
        out.push(format!("{} EXISTS", snap.exists));
    }

    // FETCH FLAGS for survivors whose flags/keywords changed.
    let old_by_uid: std::collections::BTreeMap<u64, &IdleMsgSnap> =
        prev_messages.iter().map(|m| (m.uid, m)).collect();
    for (i, msg) in snap.messages.iter().enumerate() {
        let seq = (i + 1) as u32;
        if let Some(old) = old_by_uid.get(&msg.uid) {
            if old.flags != msg.flags || old.keywords != msg.keywords {
                let fl = format_flags(&msg.flags, &msg.keywords);
                out.push(format!("{seq} FETCH (FLAGS {fl})"));
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(uid: u64, flags: &[Flag]) -> IdleMsgSnap {
        IdleMsgSnap {
            uid,
            flags: flags.iter().copied().collect(),
            keywords: BTreeSet::new(),
        }
    }

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
        s.begin("a1".into(), 3, vec![snap(1, &[]), snap(2, &[]), snap(3, &[])]);
        assert!(s.shared.is_active());
        let tag = s.end();
        assert_eq!(tag.as_deref(), Some("a1"));
        assert!(!s.shared.is_active());
    }

    #[test]
    fn update_lines_exists_only_on_change() {
        let mut prev = IdleState::default();
        prev.last_exists = 2;
        prev.last_messages = vec![snap(1, &[]), snap(2, &[])];
        let lines = idle_update_lines(
            &prev,
            &IdleMailboxSnapshot {
                exists: 3,
                messages: vec![snap(1, &[]), snap(2, &[]), snap(3, &[])],
            },
        );
        assert_eq!(lines, vec!["3 EXISTS".to_string()]);
    }

    #[test]
    fn update_lines_expunge_and_flags() {
        let prev_msgs = vec![
            snap(10, &[]),
            snap(20, &[]),
            snap(30, &[Flag::Seen]),
        ];
        let snap = IdleMailboxSnapshot {
            exists: 2,
            messages: vec![snap(10, &[]), snap(30, &[Flag::Seen, Flag::Flagged])],
        };
        let lines = idle_diff_lines(&prev_msgs, 3, &snap);
        assert_eq!(
            lines,
            vec![
                "2 EXPUNGE".to_string(),
                "2 EXISTS".to_string(),
                "2 FETCH (FLAGS (\\Seen \\Flagged))".to_string(),
            ]
        );
    }

    #[test]
    fn no_recent_in_updates() {
        let mut prev = IdleState::default();
        prev.last_exists = 1;
        prev.last_messages = vec![snap(1, &[])];
        let lines = idle_update_lines(
            &prev,
            &IdleMailboxSnapshot {
                exists: 1,
                messages: vec![snap(1, &[])],
            },
        );
        assert!(lines.is_empty());
    }
}
