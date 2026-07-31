// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Integration tests for mbox + Maildir++.

use std::collections::BTreeSet;
use std::time::SystemTime;

use tempfile::tempdir;
use hopf_mailbox::{
    AppendGuard, Flag, IndexConfig, Mailbox, MailboxFactory, MailboxResult, MaildirFactory,
    MboxFactory, SearchCriteria,
};

fn sample_msg(subject: &str, body: &str) -> Vec<u8> {
    format!(
        "From: alice@example.com\r\n\
         To: bob@example.com\r\n\
         Subject: {subject}\r\n\
         Message-ID: <{subject}@example.com>\r\n\
         Date: Fri, 24 Jul 2026 12:00:00 +0000\r\n\
         \r\n\
         {body}\r\n"
    )
    .into_bytes()
}

/// Test-only whole-message append, via the real streaming push triad
/// ([`AppendGuard`]) — never bypasses it.
fn append_whole(
    mb: &mut dyn Mailbox,
    data: &[u8],
    flags: &BTreeSet<Flag>,
    internal_date: Option<SystemTime>,
) -> MailboxResult<u64> {
    let mut guard = AppendGuard::start(mb, flags, internal_date)?;
    guard.append_content(data)?;
    guard.commit()
}

#[test]
fn mbox_append_flags_sidecar_and_search() {
    let dir = tempdir().unwrap();
    let factory = MboxFactory::new(dir.path());
    let mut store = factory.create_store();
    store.open("alice").unwrap();
    let mut mb = store.open_mailbox("INBOX", false).unwrap();

    let mut flags = BTreeSet::new();
    flags.insert(Flag::Flagged);
    let uid = append_whole(mb.as_mut(), &sample_msg("hello", "plain body"), &flags, None).unwrap();
    assert_eq!(uid, 1);
    assert_eq!(mb.message_count().unwrap(), 1);
    assert!(mb.flags(1).unwrap().contains(&Flag::Flagged));

    let hits = mb.search(&SearchCriteria::subject("hello")).unwrap();
    assert_eq!(hits, vec![1]);

    mb.close(false).unwrap();
    drop(mb);

    let mut mb2 = store.open_mailbox("INBOX", false).unwrap();
    assert!(mb2.flags(1).unwrap().contains(&Flag::Flagged));
    mb2.close(false).unwrap();
}

#[test]
fn mbox_rejects_copy() {
    let dir = tempdir().unwrap();
    let factory = MboxFactory::new(dir.path());
    let mut store = factory.create_store();
    store.open("bob").unwrap();
    let mut mb = store.open_mailbox("INBOX", false).unwrap();
    append_whole(mb.as_mut(), &sample_msg("x", "y"), &BTreeSet::new(), None).unwrap();
    let err = mb.copy_messages(&[1], "Sent").unwrap_err();
    assert!(err.to_string().contains("COPY"));
    mb.close(false).unwrap();
}

#[test]
fn maildir_copy_move_and_body_index_option() {
    let dir = tempdir().unwrap();
    let factory =
        MaildirFactory::new(dir.path()).with_index_config(IndexConfig::with_body_indexing());
    let mut store = factory.create_store();
    store.open("carol").unwrap();
    store.create_mailbox("Archive").unwrap();

    let mut inbox = store.open_mailbox("INBOX", false).unwrap();
    append_whole(
        inbox.as_mut(),
        &sample_msg("secret", "needle in a haystack"),
        &BTreeSet::new(),
        None,
    )
    .unwrap();

    let hits = inbox.search(&SearchCriteria::text("needle")).unwrap();
    assert_eq!(hits, vec![1]);

    let map = inbox.copy_messages(&[1], "Archive").unwrap();
    assert_eq!(map.get(&1).copied(), Some(1));
    assert_eq!(inbox.message_count().unwrap(), 1);

    let map = inbox.move_messages(&[1], "Archive").unwrap();
    assert!(map.contains_key(&1));
    assert!(inbox.flags(1).unwrap().contains(&Flag::Deleted));
    inbox.close(true).unwrap();
    assert_eq!(
        store
            .open_mailbox("INBOX", false)
            .unwrap()
            .message_count()
            .unwrap(),
        0
    );

    let arch = store.open_mailbox("Archive", false).unwrap();
    assert!(arch.message_count().unwrap() >= 1);
}

#[test]
fn default_index_config_has_no_body_indexing() {
    assert!(!IndexConfig::default().body_indexing);
    assert!(IndexConfig::with_body_indexing().body_indexing);
}
