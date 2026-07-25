// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Tag generator and pending-command map for pipelined IMAP.
//!
//! Untagged data is classified by prefix and routed to the **oldest** pending
//! command of a compatible [`PendingKind`]. There is no global-exclusive body
//! consumer, so pipelined `STATUS` + `LIST` (and similar) correlate correctly
//! even when replies arrive interleaved or out of tag order.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use hopf_core::TimerHandle;

/// IMAP command tag (`A000`, …).
pub type Tag = String;

/// Default maximum outstanding tagged commands.
pub const DEFAULT_MAX_PIPELINE: usize = 16;

/// Kind of outstanding command (drives untagged / continuation routing).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PendingKind {
    /// `CAPABILITY`
    Capability,
    /// `STARTTLS`
    Starttls,
    /// `LOGIN`
    Login,
    /// `AUTHENTICATE`
    Authenticate,
    /// `SELECT`
    Select,
    /// `EXAMINE`
    Examine,
    /// `FETCH` / `UID FETCH`
    Fetch,
    /// `SEARCH` / `UID SEARCH`
    Search,
    /// `LIST` / `LSUB`
    List,
    /// `STATUS`
    Status,
    /// `APPEND`
    Append,
    /// `STORE` / `UID STORE`
    Store,
    /// `COPY` / `UID COPY`
    Copy,
    /// `MOVE` / `UID MOVE`
    Move,
    /// `EXPUNGE` / `UID EXPUNGE`
    Expunge,
    /// `IDLE`
    Idle,
    /// `ENABLE`
    Enable,
    /// `NAMESPACE`
    Namespace,
    /// `ID`
    Id,
    /// `GETQUOTA` / `GETQUOTAROOT` / `SETQUOTA`
    Quota,
    /// `CLOSE`
    Close,
    /// `UNSELECT`
    Unselect,
    /// `LOGOUT`
    Logout,
    /// Other / generic tagged command (`NOOP`, …)
    Other,
}

impl PendingKind {
    /// Whether this kind exclusively owned untagged payload under the old
    /// single-owner model. Kept for diagnostics; routing uses [`UntaggedClass`].
    pub fn is_body_consumer(self) -> bool {
        matches!(
            self,
            Self::Fetch
                | Self::Search
                | Self::List
                | Self::Status
                | Self::Select
                | Self::Examine
                | Self::Store
                | Self::Expunge
                | Self::Enable
                | Self::Namespace
                | Self::Id
                | Self::Quota
        )
    }

    /// Whether continuations (`+`) are expected for this command.
    pub fn expects_continuation(self) -> bool {
        matches!(self, Self::Authenticate | Self::Append | Self::Idle)
    }

    /// Whether this kind may consume an untagged response of `class`.
    pub fn accepts(self, class: UntaggedClass) -> bool {
        match class {
            UntaggedClass::Capability => matches!(self, Self::Capability),
            UntaggedClass::List => matches!(self, Self::List),
            UntaggedClass::Status => matches!(self, Self::Status),
            UntaggedClass::Search => matches!(self, Self::Search),
            UntaggedClass::Fetch => matches!(self, Self::Fetch | Self::Store),
            UntaggedClass::Exists | UntaggedClass::Recent | UntaggedClass::FlagsList => {
                matches!(self, Self::Select | Self::Examine)
            }
            UntaggedClass::Expunge => matches!(self, Self::Expunge | Self::Select | Self::Examine),
            UntaggedClass::Enabled => matches!(self, Self::Enable),
            UntaggedClass::Namespace => matches!(self, Self::Namespace),
            UntaggedClass::Id => matches!(self, Self::Id),
            UntaggedClass::Quota | UntaggedClass::QuotaRoot => matches!(self, Self::Quota),
            UntaggedClass::MailboxEvent => false,
            UntaggedClass::Other => false,
        }
    }
}

/// Classification of an untagged (`* …`) payload (without the leading `* `).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UntaggedClass {
    /// `CAPABILITY …`
    Capability,
    /// `LIST` / `LSUB`
    List,
    /// `STATUS …`
    Status,
    /// `SEARCH …`
    Search,
    /// `n FETCH …`
    Fetch,
    /// `n EXISTS`
    Exists,
    /// `n RECENT`
    Recent,
    /// `n EXPUNGE`
    Expunge,
    /// `FLAGS (…)` (SELECT/EXAMINE)
    FlagsList,
    /// `ENABLED …`
    Enabled,
    /// `NAMESPACE …`
    Namespace,
    /// `ID …`
    Id,
    /// `QUOTA …`
    Quota,
    /// `QUOTAROOT …`
    QuotaRoot,
    /// Unsolicited mailbox noise routed via [`super::handlers::MailboxEventListener`]
    /// when no pending command claims it (also used as a sentinel).
    MailboxEvent,
    /// Unrecognised / status-only lines
    Other,
}

/// Classify an untagged payload line (text after `* `).
pub fn classify_untagged(raw: &str) -> UntaggedClass {
    let upper = raw.to_ascii_uppercase();
    if upper.starts_with("CAPABILITY") {
        return UntaggedClass::Capability;
    }
    if upper.starts_with("LIST ") || upper.starts_with("LSUB ") {
        return UntaggedClass::List;
    }
    if upper.starts_with("STATUS ") {
        return UntaggedClass::Status;
    }
    if upper.starts_with("SEARCH") {
        return UntaggedClass::Search;
    }
    if upper.starts_with("ENABLED") {
        return UntaggedClass::Enabled;
    }
    if upper.starts_with("NAMESPACE") {
        return UntaggedClass::Namespace;
    }
    if upper.starts_with("ID ") || upper == "ID" || upper.starts_with("ID(") {
        return UntaggedClass::Id;
    }
    if upper.starts_with("QUOTAROOT ") {
        return UntaggedClass::QuotaRoot;
    }
    if upper.starts_with("QUOTA ") {
        return UntaggedClass::Quota;
    }
    if upper.starts_with("FLAGS ") {
        return UntaggedClass::FlagsList;
    }
    if let Some((_, kind)) = parse_number_atom_local(raw) {
        return match kind.as_str() {
            "EXISTS" => UntaggedClass::Exists,
            "RECENT" => UntaggedClass::Recent,
            "EXPUNGE" => UntaggedClass::Expunge,
            "FETCH" => UntaggedClass::Fetch,
            _ => UntaggedClass::Other,
        };
    }
    UntaggedClass::Other
}

fn parse_number_atom_local(raw: &str) -> Option<(u32, String)> {
    let mut parts = raw.split_whitespace();
    let n: u32 = parts.next()?.parse().ok()?;
    let kind = parts.next()?.to_ascii_uppercase();
    Some((n, kind))
}

/// One in-flight tagged command.
pub struct PendingCommand {
    /// Tag issued for this command.
    pub tag: Tag,
    /// Command kind.
    pub kind: PendingKind,
    /// Stage timer armed for this command; cancelled on completion/error.
    pub timer: Option<TimerHandle>,
    /// Optional cancel flag used by unit tests (set when timer is cancelled).
    pub(crate) cancel_flag: Option<Arc<AtomicBool>>,
}

impl PendingCommand {
    /// Cancel the stage timer exactly once.
    pub fn cancel_timer(&mut self) {
        if let Some(t) = self.timer.take() {
            t.cancel();
        }
        if let Some(flag) = self.cancel_flag.take() {
            flag.store(true, Ordering::SeqCst);
        }
    }
}

/// Generates tags `A000` … `A999`, `B000` … (Gumdrop-compatible).
#[derive(Debug)]
pub struct ImapTagGenerator {
    prefix: u8,
    counter: u16,
}

impl Default for ImapTagGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl ImapTagGenerator {
    /// Create a generator starting at `A000`.
    pub fn new() -> Self {
        Self {
            prefix: b'A',
            counter: 0,
        }
    }

    /// Next tag.
    pub fn next(&mut self) -> Tag {
        let tag = format!("{}{:03}", self.prefix as char, self.counter);
        self.counter += 1;
        if self.counter > 999 {
            self.counter = 0;
            self.prefix += 1;
            if self.prefix > b'Z' {
                self.prefix = b'A';
            }
        }
        tag
    }
}

/// Pipelined pending-command table with insertion-order routing.
pub struct PendingMap {
    map: HashMap<Tag, PendingCommand>,
    /// Insertion order (oldest first) for deterministic consumer selection.
    order: Vec<Tag>,
    /// Tag waiting for a `+` continuation, if any.
    continuation_owner: Option<Tag>,
    /// Tag currently consuming FETCH literals (sticky until that FETCH completes
    /// or another FETCH line rebinds it).
    fetch_literal_owner: Option<Tag>,
    max_pipeline: usize,
}

impl PendingMap {
    /// Create an empty map with the given pipeline cap.
    pub fn new(max_pipeline: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: Vec::new(),
            continuation_owner: None,
            fetch_literal_owner: None,
            max_pipeline: max_pipeline.max(1),
        }
    }

    /// Current number of outstanding commands.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether no commands are outstanding.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Configured pipeline limit.
    pub fn max_pipeline(&self) -> usize {
        self.max_pipeline
    }

    /// Whether another command may be issued.
    pub fn can_issue(&self) -> bool {
        self.map.len() < self.max_pipeline
    }

    /// Insert a pending command. Returns `Err` if the pipeline is full.
    pub fn insert(&mut self, cmd: PendingCommand) -> Result<(), PendingCommand> {
        if !self.can_issue() {
            return Err(cmd);
        }
        let tag = cmd.tag.clone();
        if cmd.kind.expects_continuation() && self.continuation_owner.is_none() {
            self.continuation_owner = Some(tag.clone());
        }
        self.order.push(tag.clone());
        self.map.insert(tag, cmd);
        Ok(())
    }

    /// Oldest pending command of `kind`, if any.
    pub fn oldest_of_kind(&self, kind: PendingKind) -> Option<&PendingCommand> {
        self.order
            .iter()
            .find_map(|t| self.map.get(t).filter(|c| c.kind == kind))
    }

    /// Oldest pending command that [`PendingKind::accepts`] `class`.
    ///
    /// For [`UntaggedClass::Fetch`], prefers [`PendingKind::Fetch`] over
    /// [`PendingKind::Store`] so STORE and FETCH can coexist safely; callers
    /// may further disambiguate FLAGS-only lines.
    pub fn oldest_compatible(&self, class: UntaggedClass) -> Option<&PendingCommand> {
        if class == UntaggedClass::Fetch {
            if let Some(c) = self.oldest_of_kind(PendingKind::Fetch) {
                return Some(c);
            }
            return self.oldest_of_kind(PendingKind::Store);
        }
        self.order
            .iter()
            .find_map(|t| self.map.get(t).filter(|c| c.kind.accepts(class)))
    }

    /// Tag of the oldest body-style consumer (compat helper for tests).
    pub fn body_owner(&self) -> Option<&str> {
        self.order
            .iter()
            .find(|t| self.map.get(*t).map(|c| c.kind.is_body_consumer()) == Some(true))
            .map(|s| s.as_str())
    }

    /// Kind of [`Self::body_owner`], if any.
    pub fn body_owner_kind(&self) -> Option<PendingKind> {
        self.body_owner()
            .and_then(|t| self.map.get(t).map(|c| c.kind))
    }

    /// Tag currently owning FETCH literal octets.
    pub fn fetch_literal_owner(&self) -> Option<&str> {
        self.fetch_literal_owner.as_deref()
    }

    /// Bind FETCH literal ownership to `tag` (must be a pending FETCH).
    pub fn set_fetch_literal_owner(&mut self, tag: impl Into<Tag>) {
        self.fetch_literal_owner = Some(tag.into());
    }

    /// Tag expecting a continuation, if any.
    pub fn continuation_owner(&self) -> Option<&str> {
        self.continuation_owner.as_deref()
    }

    /// Clear continuation ownership after `+` has been handled (APPEND / IDLE
    /// may still wait for tagged OK).
    pub fn clear_continuation_owner(&mut self) {
        self.continuation_owner = None;
    }

    /// Complete a tagged reply: cancel its timer and remove it.
    ///
    /// Returns `None` if the tag is unknown (protocol error).
    pub fn complete(&mut self, tag: &str) -> Option<PendingCommand> {
        let mut cmd = self.map.remove(tag)?;
        cmd.cancel_timer();
        self.order.retain(|t| t != tag);
        if self.continuation_owner.as_deref() == Some(tag) {
            self.continuation_owner = None;
        }
        if self.fetch_literal_owner.as_deref() == Some(tag) {
            self.fetch_literal_owner = None;
        }
        Some(cmd)
    }

    /// Cancel and drain every pending command (connection error / disconnect).
    pub fn drain_all(&mut self) -> Vec<PendingCommand> {
        self.continuation_owner = None;
        self.fetch_literal_owner = None;
        self.order.clear();
        let mut out: Vec<_> = self.map.drain().map(|(_, c)| c).collect();
        for c in &mut out {
            c.cancel_timer();
        }
        out
    }

    /// Look up a pending command by tag.
    pub fn get(&self, tag: &str) -> Option<&PendingCommand> {
        self.map.get(tag)
    }

    /// Cancel the stage timer for `tag` without removing the pending command.
    ///
    /// Used when IDLE becomes active (`+`) so a long idle does not fire the
    /// original stage timeout; the same tag still awaits tagged completion.
    pub fn cancel_timer_for(&mut self, tag: &str) {
        if let Some(cmd) = self.map.get_mut(tag) {
            cmd.cancel_timer();
        }
    }

    /// Arm timers for pending commands that do not yet have one.
    ///
    /// The closure receives the command kind so callers can skip kinds
    /// (e.g. active IDLE should not carry a stage timeout).
    pub fn arm_missing_timers(&mut self, mut arm: impl FnMut(PendingKind) -> Option<TimerHandle>) {
        for cmd in self.map.values_mut() {
            if cmd.timer.is_none() {
                cmd.timer = arm(cmd.kind);
            }
        }
    }

    /// Tags currently outstanding, oldest first.
    pub fn tags_in_order(&self) -> &[Tag] {
        &self.order
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending(tag: &str, kind: PendingKind) -> PendingCommand {
        PendingCommand {
            tag: tag.into(),
            kind,
            timer: None,
            cancel_flag: None,
        }
    }

    fn pending_with_timer(tag: &str, kind: PendingKind) -> (PendingCommand, Arc<AtomicBool>) {
        let flag = Arc::new(AtomicBool::new(false));
        let flag2 = Arc::clone(&flag);
        let timer = TimerHandle::from_cancel(move || {
            flag2.store(true, Ordering::SeqCst);
        });
        (
            PendingCommand {
                tag: tag.into(),
                kind,
                timer: Some(timer),
                cancel_flag: Some(Arc::clone(&flag)),
            },
            flag,
        )
    }

    #[test]
    fn tags_a001_sequence() {
        let mut g = ImapTagGenerator::new();
        assert_eq!(g.next(), "A000");
        assert_eq!(g.next(), "A001");
        for _ in 0..998 {
            g.next();
        }
        assert_eq!(g.next(), "B000");
    }

    #[test]
    fn out_of_order_completion() {
        let mut m = PendingMap::new(16);
        assert!(m.insert(pending("A000", PendingKind::Status)).is_ok());
        assert!(m.insert(pending("A001", PendingKind::List)).is_ok());
        let c1 = m.complete("A001").unwrap();
        assert_eq!(c1.tag, "A001");
        let c0 = m.complete("A000").unwrap();
        assert_eq!(c0.tag, "A000");
        assert!(m.is_empty());
    }

    #[test]
    fn status_and_list_both_compatible_simultaneously() {
        let mut m = PendingMap::new(16);
        assert!(m.insert(pending("A000", PendingKind::Status)).is_ok());
        assert!(m.insert(pending("A001", PendingKind::List)).is_ok());
        // Both outstanding — no exclusive owner blocking the other.
        assert_eq!(
            m.oldest_compatible(UntaggedClass::Status)
                .map(|c| c.tag.as_str()),
            Some("A000")
        );
        assert_eq!(
            m.oldest_compatible(UntaggedClass::List)
                .map(|c| c.tag.as_str()),
            Some("A001")
        );
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn oldest_of_same_kind_is_deterministic() {
        let mut m = PendingMap::new(16);
        assert!(m.insert(pending("A000", PendingKind::Status)).is_ok());
        assert!(m.insert(pending("A001", PendingKind::Status)).is_ok());
        assert_eq!(
            m.oldest_compatible(UntaggedClass::Status)
                .map(|c| c.tag.as_str()),
            Some("A000")
        );
        m.complete("A000").unwrap();
        assert_eq!(
            m.oldest_compatible(UntaggedClass::Status)
                .map(|c| c.tag.as_str()),
            Some("A001")
        );
    }

    #[test]
    fn classify_prefixes() {
        assert_eq!(
            classify_untagged("STATUS INBOX (MESSAGES 1)"),
            UntaggedClass::Status
        );
        assert_eq!(
            classify_untagged("LIST (\\Noselect) \"/\" INBOX"),
            UntaggedClass::List
        );
        assert_eq!(classify_untagged("SEARCH 1 2 3"), UntaggedClass::Search);
        assert_eq!(classify_untagged("3 EXISTS"), UntaggedClass::Exists);
        assert_eq!(
            classify_untagged("1 FETCH (FLAGS (\\Seen))"),
            UntaggedClass::Fetch
        );
        assert_eq!(
            classify_untagged("ENABLED CONDSTORE"),
            UntaggedClass::Enabled
        );
    }

    #[test]
    fn unknown_tag_returns_none() {
        let mut m = PendingMap::new(16);
        assert!(m.insert(pending("A000", PendingKind::Other)).is_ok());
        assert!(m.complete("Z999").is_none());
    }

    #[test]
    fn max_pipeline_rejects() {
        let mut m = PendingMap::new(2);
        assert!(m.insert(pending("A000", PendingKind::Other)).is_ok());
        assert!(m.insert(pending("A001", PendingKind::Other)).is_ok());
        assert!(m.insert(pending("A002", PendingKind::Other)).is_err());
    }

    #[test]
    fn timer_cancelled_on_complete() {
        let mut m = PendingMap::new(16);
        let (cmd, flag) = pending_with_timer("A000", PendingKind::Fetch);
        assert!(m.insert(cmd).is_ok());
        assert!(!flag.load(Ordering::SeqCst));
        m.complete("A000").unwrap();
        assert!(flag.load(Ordering::SeqCst));
    }

    #[test]
    fn body_owner_fetch_not_confused_with_exists_routing() {
        let mut m = PendingMap::new(16);
        assert!(m.insert(pending("A000", PendingKind::Fetch)).is_ok());
        assert_eq!(m.body_owner(), Some("A000"));
        assert_eq!(m.body_owner_kind(), Some(PendingKind::Fetch));
        // EXISTS is not accepted by Fetch — mailbox-event path.
        assert!(m.oldest_compatible(UntaggedClass::Exists).is_none());
    }

    #[test]
    fn idle_expects_continuation() {
        assert!(PendingKind::Idle.expects_continuation());
    }

    #[test]
    fn drain_cancels_timers() {
        let mut m = PendingMap::new(16);
        let (cmd, flag) = pending_with_timer("A000", PendingKind::List);
        assert!(m.insert(cmd).is_ok());
        let drained = m.drain_all();
        assert_eq!(drained.len(), 1);
        assert!(flag.load(Ordering::SeqCst));
        assert!(m.is_empty());
    }
}
