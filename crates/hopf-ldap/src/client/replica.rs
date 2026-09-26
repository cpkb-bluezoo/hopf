// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! A local copy of a directory subtree kept up to date from RFC 4533 sync
//! events.
//!
//! The rules a replica must follow to converge (RFC 4533 sections 3.3 and
//! 3.4) are easy to get subtly wrong, so they live here once:
//!
//! - An entry is identified by its `entryUUID`, never its DN (which can change).
//! - `add` and `modify` replace the held entry; `delete` removes it.
//! - A *present* entry (an empty entry with state `present`, or a UUID in a
//!   `syncIdSet` with `refreshDeletes` false) is unchanged since the cookie:
//!   keep it, and adopt the DN it now carries.
//! - A refresh that ends with a **present phase** sends nothing for entries no
//!   longer in the content, so every held entry not confirmed present (or
//!   added or modified) in that refresh is removed.
//! - A refresh that ends with a **delete phase** names its deletions
//!   explicitly, so nothing is removed by omission.
//! - The newest cookie received is the one to resume from.

use std::collections::{HashMap, HashSet};
use std::fmt;

use super::sync::{SyncDone, SyncEvent, SyncState};
use super::types::{LdapResultCode, SearchEntry};

/// Why an event could not be applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplicaError {
    /// An entry or reference arrived with no readable Sync State Control, so
    /// its UUID - the only key a replica has - is unknown.
    MissingSyncState,
}

impl fmt::Display for ReplicaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSyncState => f.write_str("sync entry without a readable Sync State Control"),
        }
    }
}

impl std::error::Error for ReplicaError {}

/// The synchronised content and the cookie to resume from.
#[derive(Debug, Clone, Default)]
pub struct SyncReplica {
    entries: HashMap<Vec<u8>, SearchEntry>,
    references: HashMap<Vec<u8>, Vec<String>>,
    /// UUIDs confirmed still in the content during the current refresh.
    seen: HashSet<Vec<u8>>,
    cookie: Option<Vec<u8>>,
}

impl SyncReplica {
    /// An empty replica with no cookie: the next sync is an initial one.
    pub fn new() -> Self {
        Self::default()
    }

    /// The cookie to resume from ([`SyncRequest::with_cookie`](super::SyncRequest::with_cookie)),
    /// or `None` before the first synchronisation.
    pub fn cookie(&self) -> Option<&[u8]> {
        self.cookie.as_deref()
    }

    /// The held entries by UUID.
    pub fn entries(&self) -> &HashMap<Vec<u8>, SearchEntry> {
        &self.entries
    }

    /// The held entry with this UUID.
    pub fn get(&self, uuid: &[u8]) -> Option<&SearchEntry> {
        self.entries.get(uuid)
    }

    /// The held referral URLs by UUID.
    pub fn references(&self) -> &HashMap<Vec<u8>, Vec<String>> {
        &self.references
    }

    /// Number of held entries (references not counted).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no entries are held.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Forget everything, cookie included: what to do on
    /// `e-syncRefreshRequired`, or to start over.
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Mark the start of a sync operation. Call before each
    /// [`LdapSession::sync`](super::LdapSession::sync): it clears the record of
    /// which entries the previous refresh confirmed.
    pub fn begin_refresh(&mut self) {
        self.seen.clear();
    }

    fn adopt_cookie(&mut self, cookie: &Option<Vec<u8>>) {
        if let Some(c) = cookie {
            self.cookie = Some(c.clone());
        }
    }

    /// Remove every held entry and reference the current refresh did not confirm.
    fn prune_unseen(&mut self) {
        let seen = std::mem::take(&mut self.seen);
        self.entries.retain(|uuid, _| seen.contains(uuid));
        self.references.retain(|uuid, _| seen.contains(uuid));
    }

    fn remove(&mut self, uuid: &[u8]) {
        self.entries.remove(uuid);
        self.references.remove(uuid);
        self.seen.remove(uuid);
    }

    /// Apply one event from a sync operation.
    pub fn apply(&mut self, event: &SyncEvent) -> Result<(), ReplicaError> {
        match event {
            SyncEvent::Entry { entry, state } => {
                let state = state.as_ref().ok_or(ReplicaError::MissingSyncState)?;
                self.adopt_cookie(&state.cookie);
                let uuid = state.entry_uuid.clone();
                match state.state {
                    SyncState::Add | SyncState::Modify => {
                        self.seen.insert(uuid.clone());
                        self.entries.insert(uuid, entry.clone());
                    }
                    SyncState::Present => {
                        self.seen.insert(uuid.clone());
                        // The DN it now has (it may have been renamed).
                        if let Some(held) = self.entries.get_mut(&uuid) {
                            if !entry.dn.is_empty() {
                                held.dn = entry.dn.clone();
                            }
                        }
                    }
                    SyncState::Delete => self.remove(&uuid),
                }
            }
            SyncEvent::Reference { urls, state } => {
                let state = state.as_ref().ok_or(ReplicaError::MissingSyncState)?;
                self.adopt_cookie(&state.cookie);
                let uuid = state.entry_uuid.clone();
                match state.state {
                    SyncState::Add | SyncState::Modify => {
                        self.seen.insert(uuid.clone());
                        self.references.insert(uuid, urls.clone());
                    }
                    SyncState::Present => {
                        self.seen.insert(uuid);
                    }
                    SyncState::Delete => self.remove(&uuid),
                }
            }
            SyncEvent::NewCookie(c) => self.cookie = Some(c.clone()),
            SyncEvent::IdSet { cookie, refresh_deletes, entry_uuids } => {
                self.adopt_cookie(cookie);
                for uuid in entry_uuids {
                    if *refresh_deletes {
                        self.remove(uuid);
                    } else {
                        self.seen.insert(uuid.clone());
                    }
                }
            }
            SyncEvent::RefreshPresent { cookie, refresh_done } => {
                self.adopt_cookie(cookie);
                // Ending the refresh on a present phase: whatever it did not
                // confirm is gone. If a delete phase follows, it says so itself.
                if *refresh_done {
                    self.prune_unseen();
                }
            }
            SyncEvent::RefreshDelete { cookie, refresh_done } => {
                self.adopt_cookie(cookie);
                if *refresh_done {
                    self.seen.clear();
                }
            }
        }
        Ok(())
    }

    /// Apply the end of a sync operation (SearchResultDone plus its Sync Done
    /// Control): the end of a poll, or of a persistent sync the server closed.
    pub fn finish(&mut self, done: &SyncDone) {
        if done.result_code == LdapResultCode::SyncRefreshRequired {
            // The cookie is useless; reload from scratch.
            self.reset();
            return;
        }
        self.adopt_cookie(&done.cookie);
        if done.refresh_deletes {
            self.seen.clear();
        } else {
            self.prune_unseen();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::sync::SyncStateValue;

    fn uuid(n: u8) -> Vec<u8> {
        vec![n; 16]
    }

    fn entry(dn: &str) -> SearchEntry {
        SearchEntry { dn: dn.into(), attributes: HashMap::new() }
    }

    fn ev(state: SyncState, n: u8, dn: &str) -> SyncEvent {
        SyncEvent::Entry {
            entry: entry(dn),
            state: Some(SyncStateValue { state, entry_uuid: uuid(n), cookie: None }),
        }
    }

    fn done(refresh_deletes: bool, cookie: &str) -> SyncDone {
        SyncDone { result_code: LdapResultCode::Success, cookie: Some(cookie.into()), refresh_deletes, referrals: vec![] }
    }

    fn dns(r: &SyncReplica) -> Vec<String> {
        let mut v: Vec<String> = r.entries().values().map(|e| e.dn.clone()).collect();
        v.sort();
        v
    }

    /// An initial poll: adds, then a done with `refreshDeletes` false.
    #[test]
    fn an_initial_poll_fills_the_replica_and_stores_the_cookie() {
        let mut r = SyncReplica::new();
        r.begin_refresh();
        r.apply(&ev(SyncState::Add, 1, "cn=a")).unwrap();
        r.apply(&ev(SyncState::Add, 2, "cn=b")).unwrap();
        r.finish(&done(false, "c1"));
        assert_eq!(dns(&r), ["cn=a", "cn=b"]);
        assert_eq!(r.cookie(), Some(&b"c1"[..]));
    }

    /// Update ending in a present phase: changed entries arrive whole,
    /// unchanged ones are only confirmed, and everything else is gone.
    #[test]
    fn a_present_phase_removes_entries_it_does_not_confirm() {
        let mut r = SyncReplica::new();
        for (n, dn) in [(1, "cn=a"), (2, "cn=b"), (3, "cn=c")] {
            r.apply(&ev(SyncState::Add, n, dn)).unwrap();
        }
        r.begin_refresh();
        r.apply(&ev(SyncState::Modify, 1, "cn=a")).unwrap(); // changed
        r.apply(&SyncEvent::IdSet { cookie: None, refresh_deletes: false, entry_uuids: vec![uuid(2)] }).unwrap(); // b unchanged
        // c is neither: deleted server-side.
        r.finish(&done(false, "c2"));
        assert_eq!(dns(&r), ["cn=a", "cn=b"]);
    }

    /// Update ending in a delete phase names its deletions; an entry the
    /// server said nothing about must stay.
    #[test]
    fn a_delete_phase_removes_only_what_it_names() {
        let mut r = SyncReplica::new();
        for (n, dn) in [(1, "cn=a"), (2, "cn=b"), (3, "cn=c")] {
            r.apply(&ev(SyncState::Add, n, dn)).unwrap();
        }
        r.begin_refresh();
        r.apply(&ev(SyncState::Delete, 2, "")).unwrap();
        r.finish(&done(true, "c3"));
        assert_eq!(dns(&r), ["cn=a", "cn=c"], "a and c were not mentioned, so they stay");
    }

    #[test]
    fn a_sync_id_set_of_deletes_removes_them_in_bulk() {
        let mut r = SyncReplica::new();
        for (n, dn) in [(1, "cn=a"), (2, "cn=b"), (3, "cn=c")] {
            r.apply(&ev(SyncState::Add, n, dn)).unwrap();
        }
        r.begin_refresh();
        r.apply(&SyncEvent::IdSet { cookie: Some(b"mid".to_vec()), refresh_deletes: true, entry_uuids: vec![uuid(1), uuid(3)] }).unwrap();
        r.finish(&done(true, "end"));
        assert_eq!(dns(&r), ["cn=b"]);
        assert_eq!(r.cookie(), Some(&b"end"[..]));
    }

    /// A present phase followed by a delete phase (refreshPresent with
    /// refreshDone false): nothing is pruned at the boundary, because the
    /// delete phase that follows says what went.
    #[test]
    fn present_then_delete_phases_do_not_prune_by_omission() {
        let mut r = SyncReplica::new();
        for (n, dn) in [(1, "cn=a"), (2, "cn=b"), (3, "cn=c")] {
            r.apply(&ev(SyncState::Add, n, dn)).unwrap();
        }
        r.begin_refresh();
        r.apply(&ev(SyncState::Present, 1, "cn=a")).unwrap();
        r.apply(&SyncEvent::RefreshPresent { cookie: Some(b"p".to_vec()), refresh_done: false }).unwrap();
        r.apply(&ev(SyncState::Delete, 3, "")).unwrap();
        r.finish(&done(true, "d"));
        assert_eq!(dns(&r), ["cn=a", "cn=b"], "b was neither confirmed nor deleted, and stays");
    }

    /// In refreshAndPersist the refresh stage ends with a Sync Info Message,
    /// not a SearchResultDone: a present-terminated refresh prunes there.
    #[test]
    fn a_persist_refresh_ending_on_present_prunes_at_the_marker() {
        let mut r = SyncReplica::new();
        for (n, dn) in [(1, "cn=a"), (2, "cn=b")] {
            r.apply(&ev(SyncState::Add, n, dn)).unwrap();
        }
        r.begin_refresh();
        r.apply(&ev(SyncState::Present, 1, "cn=a")).unwrap();
        r.apply(&SyncEvent::RefreshPresent { cookie: Some(b"r".to_vec()), refresh_done: true }).unwrap();
        assert_eq!(dns(&r), ["cn=a"]);
        assert_eq!(r.cookie(), Some(&b"r"[..]));
    }

    /// The persist stage: changes arrive as they happen, with cookies.
    #[test]
    fn persist_stage_changes_apply_immediately() {
        let mut r = SyncReplica::new();
        r.apply(&ev(SyncState::Add, 1, "cn=a")).unwrap();
        r.apply(&SyncEvent::RefreshDelete { cookie: Some(b"r".to_vec()), refresh_done: true }).unwrap();
        r.apply(&ev(SyncState::Add, 2, "cn=b")).unwrap();
        r.apply(&ev(SyncState::Modify, 1, "cn=a2")).unwrap();
        r.apply(&SyncEvent::NewCookie(b"n".to_vec())).unwrap();
        r.apply(&ev(SyncState::Delete, 2, "")).unwrap();
        assert_eq!(dns(&r), ["cn=a2"]);
        assert_eq!(r.cookie(), Some(&b"n"[..]));
    }

    #[test]
    fn a_present_entry_keeps_its_content_but_adopts_a_renamed_dn() {
        let mut r = SyncReplica::new();
        let mut e = entry("cn=old");
        e.attributes.insert("mail".into(), vec![b"x@example.test".to_vec()]);
        r.apply(&SyncEvent::Entry { entry: e, state: Some(SyncStateValue { state: SyncState::Add, entry_uuid: uuid(1), cookie: None }) }).unwrap();
        r.apply(&ev(SyncState::Present, 1, "cn=new")).unwrap();
        let held = r.get(&uuid(1)).unwrap();
        assert_eq!(held.dn, "cn=new");
        assert_eq!(held.attributes["mail"], vec![b"x@example.test".to_vec()], "attributes are not touched by a present");
    }

    /// Cookies from any source count, and the newest wins.
    #[test]
    fn the_newest_cookie_is_kept() {
        let mut r = SyncReplica::new();
        r.apply(&SyncEvent::NewCookie(b"1".to_vec())).unwrap();
        r.apply(&SyncEvent::Entry {
            entry: entry("cn=a"),
            state: Some(SyncStateValue { state: SyncState::Add, entry_uuid: uuid(1), cookie: Some(b"2".to_vec()) }),
        })
        .unwrap();
        assert_eq!(r.cookie(), Some(&b"2"[..]));
        r.finish(&SyncDone { result_code: LdapResultCode::Success, cookie: None, refresh_deletes: true, referrals: vec![] });
        assert_eq!(r.cookie(), Some(&b"2"[..]), "a done without a cookie does not erase it");
    }

    /// e-syncRefreshRequired: the cookie is useless and the content stale.
    #[test]
    fn refresh_required_resets_the_replica() {
        let mut r = SyncReplica::new();
        r.apply(&ev(SyncState::Add, 1, "cn=a")).unwrap();
        r.apply(&SyncEvent::NewCookie(b"old".to_vec())).unwrap();
        r.finish(&SyncDone { result_code: LdapResultCode::SyncRefreshRequired, cookie: None, refresh_deletes: false, referrals: vec![] });
        assert!(r.is_empty());
        assert!(r.cookie().is_none());
    }

    #[test]
    fn an_entry_without_sync_state_is_an_error_not_a_guess() {
        let mut r = SyncReplica::new();
        assert_eq!(r.apply(&SyncEvent::Entry { entry: entry("cn=a"), state: None }), Err(ReplicaError::MissingSyncState));
        assert!(r.is_empty());
    }

    #[test]
    fn references_follow_the_same_rules() {
        let mut r = SyncReplica::new();
        let refr = |state, n, urls: &[&str]| SyncEvent::Reference {
            urls: urls.iter().map(|s| s.to_string()).collect(),
            state: Some(SyncStateValue { state, entry_uuid: uuid(n), cookie: None }),
        };
        r.apply(&refr(SyncState::Add, 7, &["ldap://other.test/dc=x"])).unwrap();
        assert_eq!(r.references()[&uuid(7)], vec!["ldap://other.test/dc=x".to_string()]);
        r.begin_refresh();
        r.finish(&done(false, "c")); // a present-terminated refresh that confirmed nothing
        assert!(r.references().is_empty(), "an unconfirmed reference is gone too");
        r.apply(&refr(SyncState::Add, 8, &["ldap://o.test/"])).unwrap();
        r.apply(&refr(SyncState::Delete, 8, &[])).unwrap();
        assert!(r.references().is_empty());
    }
}
