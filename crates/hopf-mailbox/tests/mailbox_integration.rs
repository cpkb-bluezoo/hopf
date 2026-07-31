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

fn msg_with_custom_header(header_name: &str, header_value: &str, subject: &str) -> Vec<u8> {
    format!(
        "From: alice@example.com\r\n\
         To: bob@example.com\r\n\
         Subject: {subject}\r\n\
         {header_name}: {header_value}\r\n\
         \r\n\
         body\r\n"
    )
    .into_bytes()
}

/// HEADER search on a name that isn't one of the six specifically-indexed
/// fields (From/Sender/To/Cc/Bcc/Subject/Message-ID) must fall back to a
/// raw per-message read instead of always reporting empty — issue #133.
#[test]
fn mbox_header_search_falls_back_to_raw_read_for_unindexed_header_names() {
    let dir = tempdir().unwrap();
    let factory = MboxFactory::new(dir.path());
    let mut store = factory.create_store();
    store.open("headeruser").unwrap();
    let mut mb = store.open_mailbox("INBOX", false).unwrap();

    append_whole(
        mb.as_mut(),
        &msg_with_custom_header("X-Spam-Flag", "YES", "spammy"),
        &BTreeSet::new(),
        None,
    )
    .unwrap();
    append_whole(
        mb.as_mut(),
        &msg_with_custom_header("X-Spam-Flag", "NO", "clean"),
        &BTreeSet::new(),
        None,
    )
    .unwrap();

    let hits = mb
        .search(&SearchCriteria::Header {
            name: "X-Spam-Flag".to_string(),
            pattern: "YES".to_string(),
        })
        .unwrap();
    assert_eq!(hits, vec![1]);

    // A header that's genuinely absent from every message must not match.
    let none_hits = mb
        .search(&SearchCriteria::Header {
            name: "List-Id".to_string(),
            pattern: "anything".to_string(),
        })
        .unwrap();
    assert!(none_hits.is_empty());

    mb.close(false).unwrap();
}

#[test]
fn maildir_header_search_falls_back_to_raw_read_for_unindexed_header_names() {
    let dir = tempdir().unwrap();
    let factory = MaildirFactory::new(dir.path());
    let mut store = factory.create_store();
    store.open("headeruser2").unwrap();
    let mut mb = store.open_mailbox("INBOX", false).unwrap();

    append_whole(
        mb.as_mut(),
        &msg_with_custom_header("List-Id", "announce.example.com", "listmail"),
        &BTreeSet::new(),
        None,
    )
    .unwrap();
    append_whole(
        mb.as_mut(),
        &sample_msg("no-custom-header", "plain"),
        &BTreeSet::new(),
        None,
    )
    .unwrap();

    let hits = mb
        .search(&SearchCriteria::Header {
            name: "List-Id".to_string(),
            pattern: "announce".to_string(),
        })
        .unwrap();
    assert_eq!(hits, vec![1]);

    // The already-indexed fields must still work unchanged (no regression
    // from the fallback path).
    let subj_hits = mb.search(&SearchCriteria::subject("listmail")).unwrap();
    assert_eq!(subj_hits, vec![1]);

    mb.close(false).unwrap();
}

/// SEARCH MODSEQ must actually match now that the backend tracks real
/// per-message mod-sequences — issue #132.
#[test]
fn maildir_modseq_search_criterion_matches_real_tracked_values() {
    let dir = tempdir().unwrap();
    let factory = MaildirFactory::new(dir.path());
    let mut store = factory.create_store();
    store.open("modseqsearchuser").unwrap();
    let mut mb = store.open_mailbox("INBOX", false).unwrap();

    append_whole(mb.as_mut(), &sample_msg("a", "x"), &BTreeSet::new(), None).unwrap(); // uid 1, modseq 1
    append_whole(mb.as_mut(), &sample_msg("b", "x"), &BTreeSet::new(), None).unwrap(); // uid 2, modseq 2
    let mut flagged = BTreeSet::new();
    flagged.insert(Flag::Flagged);
    mb.set_flags(1, &flagged, true).unwrap(); // uid 1 -> modseq 3

    // MODSEQ 3 matches only the message whose mod-sequence is >= 3.
    let hits = mb.search(&SearchCriteria::ModSeq(3)).unwrap();
    assert_eq!(hits, vec![1]);

    // MODSEQ 1 matches every message (both have modseq >= 1).
    let all = mb.search(&SearchCriteria::ModSeq(1)).unwrap();
    assert_eq!(all, vec![1, 2]);

    mb.close(false).unwrap();
}

#[test]
fn mbox_modseq_search_criterion_matches_real_tracked_values() {
    let dir = tempdir().unwrap();
    let factory = MboxFactory::new(dir.path());
    let mut store = factory.create_store();
    store.open("mboxmodseqsearchuser").unwrap();
    let mut mb = store.open_mailbox("INBOX", false).unwrap();

    append_whole(mb.as_mut(), &sample_msg("a", "x"), &BTreeSet::new(), None).unwrap(); // uid 1, modseq 1
    append_whole(mb.as_mut(), &sample_msg("b", "x"), &BTreeSet::new(), None).unwrap(); // uid 2, modseq 2
    let mut flagged = BTreeSet::new();
    flagged.insert(Flag::Flagged);
    mb.set_flags(1, &flagged, true).unwrap(); // uid 1 -> modseq 3

    let hits = mb.search(&SearchCriteria::ModSeq(3)).unwrap();
    assert_eq!(hits, vec![1]);
    let all = mb.search(&SearchCriteria::ModSeq(1)).unwrap();
    assert_eq!(all, vec![1, 2]);

    mb.close(false).unwrap();
}
