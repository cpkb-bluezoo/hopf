// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Integration tests for mbox + Maildir++.

use std::collections::BTreeSet;
use std::time::SystemTime;

use tempfile::tempdir;
use hopf_mailbox::{
    AppendGuard, Flag, IndexConfig, Mailbox, MailboxAttribute, MailboxError, MailboxFactory, MailboxInfo,
    MailboxResult, MailboxStore, MaildirFactory, MboxFactory, SearchCriteria,
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

// ── LIST, RENAME and COPY on the Maildir store ──────────────────────────────

/// A store for one user with `mailboxes` created.
fn store_with(dir: &std::path::Path, mailboxes: &[&str]) -> Box<dyn MailboxStore> {
    let factory = MaildirFactory::new(dir);
    let mut store = factory.create_store();
    store.open("u").unwrap();
    for name in mailboxes {
        store.create_mailbox(name).unwrap();
    }
    store
}

fn names(rows: &[MailboxInfo]) -> Vec<&str> {
    rows.iter().map(|r| r.name.as_str()).collect()
}

fn attrs<'a>(rows: &'a [MailboxInfo], name: &str) -> &'a std::collections::BTreeSet<MailboxAttribute> {
    &rows.iter().find(|r| r.name == name).unwrap_or_else(|| panic!("no {name} in {:?}", names(rows))).attributes
}

#[test]
fn list_matches_the_wildcards_and_honours_the_reference() {
    let dir = tempdir().unwrap();
    let store = store_with(dir.path(), &["Work", "Work/Reports", "Work/Reports/Q1", "Other"]);
    let list = |reference: &str, pattern: &str| {
        let mut n: Vec<String> = store.list(reference, pattern).unwrap().into_iter().map(|r| r.name).collect();
        n.sort();
        n
    };
    // `*` matches across the hierarchy, `%` stops at a delimiter.
    assert_eq!(list("", "*"), ["INBOX", "Other", "Work", "Work/Reports", "Work/Reports/Q1"]);
    assert_eq!(list("", "%"), ["INBOX", "Other", "Work"]);
    assert_eq!(list("", "Work/%"), ["Work/Reports"]);
    assert_eq!(list("", "Work/*"), ["Work/Reports", "Work/Reports/Q1"]);
    assert_eq!(list("", "Wo%"), ["Work"]);
    assert_eq!(list("", "W*"), ["Work", "Work/Reports", "Work/Reports/Q1"]);
    assert_eq!(list("", "%/Reports"), ["Work/Reports"]);
    assert_eq!(list("", "Work"), ["Work"]);
    assert_eq!(list("", "Nope"), Vec::<String>::new());
    // The reference is the context the pattern is read in.
    assert_eq!(list("Work/", "%"), ["Work/Reports"]);
    assert_eq!(list("Work/", "*"), ["Work/Reports", "Work/Reports/Q1"]);
    assert_eq!(list("Work/Reports/", "%"), ["Work/Reports/Q1"]);
    // INBOX is the one name that is not case-sensitive.
    assert_eq!(list("", "inbox"), ["INBOX"]);
    assert_eq!(list("", "work"), Vec::<String>::new());
}

#[test]
fn list_says_which_mailboxes_have_children_and_names_the_parents_that_are_implied() {
    let dir = tempdir().unwrap();
    // "Deep" and "Deep/Down" are not mailboxes of their own: only "Deep/Down/Here" is.
    let store = store_with(dir.path(), &["Work", "Work/Reports", "Other", "Deep/Down/Here"]);
    let rows = store.list("", "*").unwrap();
    assert!(attrs(&rows, "Work").contains(&MailboxAttribute::HasChildren), "{rows:?}");
    assert!(!attrs(&rows, "Work").contains(&MailboxAttribute::HasNoChildren));
    assert!(attrs(&rows, "Work/Reports").contains(&MailboxAttribute::HasNoChildren));
    assert!(attrs(&rows, "Other").contains(&MailboxAttribute::HasNoChildren));
    assert!(attrs(&rows, "INBOX").contains(&MailboxAttribute::HasNoChildren));
    // The names above a mailbox that exist only as the way to it are real as far as a client
    // walking the tree is concerned, but cannot be selected.
    for implied in ["Deep", "Deep/Down"] {
        let a = attrs(&rows, implied);
        assert!(a.contains(&MailboxAttribute::NoSelect) && a.contains(&MailboxAttribute::HasChildren), "{implied}: {a:?}");
    }
    assert!(!attrs(&rows, "Deep/Down/Here").contains(&MailboxAttribute::NoSelect));
    // So a client that lists one level at a time finds its way down.
    let top: Vec<_> = store.list("", "%").unwrap();
    assert!(names(&top).contains(&"Deep"), "{top:?}");
    let next = store.list("Deep/", "%").unwrap();
    assert_eq!(names(&next), ["Deep/Down"]);
}

#[test]
fn an_empty_pattern_asks_for_the_hierarchy_delimiter_and_root() {
    let dir = tempdir().unwrap();
    let store = store_with(dir.path(), &["Work"]);
    let rows = store.list("", "").unwrap();
    assert_eq!(names(&rows), [""]);
    assert!(rows[0].attributes.contains(&MailboxAttribute::NoSelect));
    assert_eq!(store.hierarchy_delimiter(), '/');
}

#[test]
fn rename_moves_the_inferior_names_with_it() {
    let dir = tempdir().unwrap();
    let mut store = store_with(dir.path(), &["Work", "Work/Reports", "Work/Reports/Q1", "Other"]);
    store.subscribe("Work/Reports").unwrap();
    store.rename_mailbox("Work", "Play").unwrap();
    let mut n: Vec<String> = store.list("", "*").unwrap().into_iter().map(|r| r.name).collect();
    n.sort();
    assert_eq!(n, ["INBOX", "Other", "Play", "Play/Reports", "Play/Reports/Q1"]);
    // Subscriptions follow the names.
    let subscribed: Vec<String> = store.list_subscribed("", "*").unwrap().into_iter().map(|r| r.name).collect();
    assert!(subscribed.contains(&"Play/Reports".to_string()), "{subscribed:?}");
    assert!(!subscribed.contains(&"Work/Reports".to_string()), "{subscribed:?}");
    // The renamed mailboxes open, and the old names are gone.
    assert!(store.open_mailbox("Play/Reports", true).is_ok());
    assert!(matches!(store.open_mailbox("Work/Reports", true), Err(MailboxError::NotFound(_))));
    assert!(matches!(store.rename_mailbox("Work", "Else"), Err(MailboxError::NotFound(_))));
}

#[test]
fn rename_can_move_a_mailbox_beneath_itself_and_a_parent_that_exists_only_by_implication() {
    let dir = tempdir().unwrap();
    let mut store = store_with(dir.path(), &["Work", "Work/Reports", "Implied/Child"]);
    store.rename_mailbox("Work", "Work/Old").unwrap();
    let mut n: Vec<String> = store.list("", "Work/*").unwrap().into_iter().map(|r| r.name).collect();
    n.sort();
    assert_eq!(n, ["Work/Old", "Work/Old/Reports"]);
    // "Implied" is only the way to "Implied/Child"; renaming it moves what is beneath.
    store.rename_mailbox("Implied", "Moved").unwrap();
    let n: Vec<String> = store.list("", "Moved/*").unwrap().into_iter().map(|r| r.name).collect();
    assert_eq!(n, ["Moved/Child"]);
}

#[test]
fn rename_refuses_to_land_on_a_name_that_is_taken_and_changes_nothing() {
    let dir = tempdir().unwrap();
    let mut store = store_with(dir.path(), &["Work", "Work/Reports", "Play/Reports"]);
    // "Play" itself is free, but "Play/Reports" is not.
    assert!(matches!(store.rename_mailbox("Work", "Play"), Err(MailboxError::Invalid(_))));
    let mut n: Vec<String> = store.list("", "*").unwrap().into_iter().map(|r| r.name).collect();
    n.sort();
    assert_eq!(n, ["INBOX", "Play", "Play/Reports", "Work", "Work/Reports"]);
    assert!(matches!(store.rename_mailbox("Work", "inbox"), Err(MailboxError::Invalid(_))));
}

#[test]
fn copy_to_a_mailbox_that_does_not_exist_is_not_found_and_creates_nothing() {
    let dir = tempdir().unwrap();
    let mut store = store_with(dir.path(), &[]);
    let mut inbox = store.open_mailbox("INBOX", false).unwrap();
    append_whole(inbox.as_mut(), &sample_msg("one", "body"), &BTreeSet::new(), None).unwrap();
    let err = inbox.copy_messages(&[1], "Nowhere").unwrap_err();
    assert!(matches!(err, MailboxError::NotFound(ref n) if n == "Nowhere"), "{err:?}");
    let err = inbox.move_messages(&[1], "Nowhere").unwrap_err();
    assert!(matches!(err, MailboxError::NotFound(_)), "{err:?}");
    inbox.close(false).unwrap();
    assert_eq!(store.list("", "*").unwrap().len(), 1, "no mailbox was made on the way");
}

#[test]
fn address_searches_match_the_display_names_as_well_as_the_addresses() {
    for maildir in [true, false] {
        let dir = tempdir().unwrap();
        let mut mb: Box<dyn Mailbox> = if maildir {
            let mut store = MaildirFactory::new(dir.path()).create_store();
            store.open("u").unwrap();
            store.open_mailbox("INBOX", false).unwrap()
        } else {
            let mut store = MboxFactory::new(dir.path()).create_store();
            store.open("u").unwrap();
            store.open_mailbox("INBOX", false).unwrap()
        };
        let raw = |from: &str, to: &str, cc: &str| {
            format!("From: {from}\r\nTo: {to}\r\nCc: {cc}\r\nSubject: s\r\nMessage-ID: <m@x.org>\r\n\r\nbody\r\n").into_bytes()
        };
        let none = BTreeSet::new();
        append_whole(mb.as_mut(), &raw("\"Bob Jones\" <bob@x.org>", "Carol <c@x.org>, dave@x.org", "Eve Adams <eve@x.org>"), &none, None).unwrap();
        append_whole(mb.as_mut(), &raw("zed@x.org", "\"Frank, Jr.\" <frank@x.org>", "g@x.org"), &none, None).unwrap();
        let found = |mb: &dyn Mailbox, c: SearchCriteria| mb.search(&c).unwrap();
        let header = |name: &str, pattern: &str| SearchCriteria::Header { name: name.into(), pattern: pattern.into() };
        let why = if maildir { "maildir" } else { "mbox" };
        assert_eq!(found(mb.as_ref(), SearchCriteria::from("jones")), vec![1], "{why}: a surname");
        assert_eq!(found(mb.as_ref(), SearchCriteria::from("BOB")), vec![1], "{why}: either case");
        assert_eq!(found(mb.as_ref(), SearchCriteria::from("bob@x.org")), vec![1], "{why}: the address still matches");
        assert_eq!(found(mb.as_ref(), SearchCriteria::from("zed")), vec![2], "{why}");
        assert_eq!(found(mb.as_ref(), header("To", "carol")), vec![1], "{why}: second kind of header");
        assert_eq!(found(mb.as_ref(), header("To", "dave")), vec![1], "{why}");
        assert_eq!(found(mb.as_ref(), header("To", "frank")), vec![2], "{why}: a quoted name with a comma");
        assert_eq!(found(mb.as_ref(), header("Cc", "adams")), vec![1], "{why}");
        assert_eq!(found(mb.as_ref(), SearchCriteria::text("jones")), vec![1], "{why}: TEXT covers the names");
        assert_eq!(found(mb.as_ref(), SearchCriteria::from("nobody")), Vec::<u32>::new(), "{why}");
        mb.close(false).unwrap();
    }
}

/// HIGHESTMODSEQ must never be behind a message's own modification sequence,
/// and what was reached must survive closing and opening the mailbox again.
#[test]
fn highest_modseq_follows_the_changes_and_survives_a_reopen() {
    let dir = tempdir().unwrap();
    let mut store = MaildirFactory::new(dir.path()).create_store();
    store.open("u").unwrap();
    let mut mb = store.open_mailbox("INBOX", false).unwrap();
    for subject in ["a", "b", "c"] {
        append_whole(mb.as_mut(), &sample_msg(subject, "x"), &BTreeSet::new(), None).unwrap();
    }
    let before = mb.status().unwrap().highest_modseq;
    let flags = BTreeSet::from([Flag::Flagged]);
    mb.set_flags(2, &flags, true).unwrap();
    mb.set_flags(2, &BTreeSet::from([Flag::Seen]), true).unwrap();
    let own = mb.modseq(2).unwrap();
    let highest = mb.status().unwrap().highest_modseq;
    assert!(own > before, "a change moves the message's own sequence on: {own} after {before}");
    assert!(highest >= own, "highest {highest} is behind the message's own {own}");
    mb.close(false).unwrap();
    drop(mb);

    let mb = store.open_mailbox("INBOX", true).unwrap();
    let reopened = mb.status().unwrap().highest_modseq;
    assert_eq!(mb.modseq(2).unwrap(), own, "the message's sequence was kept");
    assert!(reopened >= own, "after reopening, highest {reopened} is behind the message's own {own}");
    for seq in 1..=3 {
        assert!(mb.modseq(seq).unwrap() <= reopened, "message {seq} is ahead of the highest");
    }
}

/// A refresh picks up what other writers did; it must not lose what this
/// session did and has not yet been written out.
#[test]
fn a_refresh_keeps_the_modification_sequences_this_session_has_made() {
    let dir = tempdir().unwrap();
    let mut store = MaildirFactory::new(dir.path()).create_store();
    store.open("u").unwrap();
    let mut mb = store.open_mailbox("INBOX", false).unwrap();
    for subject in ["a", "b"] {
        append_whole(mb.as_mut(), &sample_msg(subject, "x"), &BTreeSet::new(), None).unwrap();
    }
    mb.set_flags(1, &BTreeSet::from([Flag::Flagged]), true).unwrap();
    mb.set_keywords(1, &BTreeSet::from(["$k".to_string()]), true).unwrap();
    let own = mb.modseq(1).unwrap();
    let highest = mb.status().unwrap().highest_modseq;
    assert!(highest >= own);

    mb.refresh().unwrap();
    assert_eq!(mb.modseq(1).unwrap(), own, "the message's own sequence went back");
    assert_eq!(mb.status().unwrap().highest_modseq, highest, "highest went back");
    assert!(mb.flags(1).unwrap().contains(&Flag::Flagged));
    assert!(mb.keywords(1).unwrap().contains("$k"), "the keyword was lost");
    // And the next change goes on from where it was, not from an older number.
    mb.set_flags(2, &BTreeSet::from([Flag::Seen]), true).unwrap();
    assert!(mb.modseq(2).unwrap() > highest, "sequences must not be reused");
    mb.close(false).unwrap();
}
