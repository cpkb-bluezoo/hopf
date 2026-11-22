// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The connection handler driven end to end with no sockets: a [`Peer`]
//! stands in for the connection and plays the reactor, over a Maildir under a
//! temporary directory.

use std::collections::BTreeSet;
use std::ops::{Deref, DerefMut};
use std::time::Duration;

use hopf_core::testing::Peer;
use hopf_core::{Runtime, RuntimeConfig};
use hopf_mailbox::{AppendGuard, MailboxFactory, MaildirFactory};

use super::*;
use crate::server::egress::{ArticlePart, NntpDotStuffer};
use crate::server::mailbox::DefaultNntpHandlerFactory;
use crate::server::handler::NntpHandlerFactory;

/// An article in canonical form.
pub(super) fn article(subject: &str, body: &str) -> String {
    format!(
        "From: a@x.org\r\nNewsgroups: misc.test\r\nSubject: {subject}\r\nMessage-ID: <{subject}@x.org>\r\nDate: Sat, 21 Nov 2026 10:00:00 +0000\r\n\r\n{body}"
    )
}

pub(super) struct Session {
    peer: Peer<NntpControlHandler>,
    pub(super) greeting: String,
    factory: Arc<MaildirFactory>,
    _root: tempfile::TempDir,
}

impl Deref for Session {
    type Target = Peer<NntpControlHandler>;
    fn deref(&self) -> &Self::Target {
        &self.peer
    }
}

impl DerefMut for Session {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.peer
    }
}

impl Session {
    /// A session over a news spool holding `groups`, each a name and the
    /// articles in it, greeted and waiting.
    pub(super) fn with_groups(groups: &[(&str, Vec<String>)]) -> Self {
        Self::with(groups, |c| c)
    }

    pub(super) fn with(groups: &[(&str, Vec<String>)], configure: impl FnOnce(NntpConfig) -> NntpConfig) -> Self {
        let root = tempfile::tempdir().unwrap();
        let factory = Arc::new(MaildirFactory::new(root.path()));
        {
            let mut store = factory.create_store();
            store.open("news").unwrap();
            for (group, articles) in groups {
                let mailbox_name = group.replace('.', "/");
                if !mailbox_name.eq_ignore_ascii_case("INBOX") {
                    store.create_mailbox(&mailbox_name).unwrap();
                }
                let mut mb = store.open_mailbox(&mailbox_name, false).unwrap();
                for text in articles {
                    let mut guard = AppendGuard::start(mb.as_mut(), &BTreeSet::new(), None).unwrap();
                    guard.append_content(text.as_bytes()).unwrap();
                    guard.commit().unwrap();
                }
                mb.close(false).unwrap();
            }
            store.close().unwrap();
        }
        let config = configure(NntpConfig::new("127.0.0.1:1119".parse().unwrap(), "news.example"));
        let (peer, greeting) = Self::connect(config, Arc::clone(&factory));
        Self { peer, greeting, factory, _root: root }
    }

    pub(super) fn factory_for_checks(&self) -> Arc<MaildirFactory> {
        Arc::clone(&self.factory)
    }

    /// Writes `wire` and returns everything the server answers, the client
    /// taking what it is given as soon as it is given.
    pub(super) fn run(&mut self, wire: &str) -> String {
        let mut out = self.peer.run(wire);
        self.settle(&mut out);
        out
    }

    /// As [`Self::run`], the wire arriving `chunk` bytes at a time.
    pub(super) fn run_chunked(&mut self, wire: &str, chunk: usize) -> String {
        let mut out = String::new();
        for piece in wire.as_bytes().chunks(chunk) {
            out.push_str(&self.peer.run(std::str::from_utf8(piece).unwrap()));
            self.settle(&mut out);
        }
        out
    }

    /// The client reads what is queued, until the command in progress is done.
    fn settle(&mut self, out: &mut String) {
        let started = std::time::Instant::now();
        while self.peer.handler.job.is_some() {
            self.peer.drain();
            out.push_str(&self.peer.take());
            assert!(started.elapsed() < Duration::from_secs(20), "a command never finished: {out:?}");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn connect(config: NntpConfig, factory: Arc<MaildirFactory>) -> (Peer<NntpControlHandler>, String) {
        let handlers = DefaultNntpHandlerFactory::new("ready", factory)
            .with_posting_allowed(config.posting_allowed)
            .with_hostname("news.example");
        let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
        let handler = NntpControlHandler::new(handlers.create(), NntpServerMetrics::shared(), config, rt);
        let mut peer = Peer::connect(handler, |h| h.busy());
        let greeting = peer.take();
        (peer, greeting)
    }
}

fn lines(out: &str) -> Vec<&str> {
    out.split("\r\n").filter(|l| !l.is_empty()).collect()
}

fn spool() -> Session {
    Session::with_groups(&[
        (
            "misc.test",
            vec![
                article("one", "first body\r\n"),
                article("two", "second\r\n.leading dot\r\nlast line\r\n"),
                article("three", ""),
            ],
        ),
        ("alt.empty", vec![]),
    ])
}

#[test]
fn a_client_is_greeted_and_told_whether_it_may_post() {
    let s = spool();
    assert_eq!(s.greeting, "200 ready\r\n");
    let s = Session::with(&[], |c| c.with_posting_allowed(false));
    assert_eq!(s.greeting, "201 ready\r\n");
}

#[test]
fn capabilities_name_what_the_server_does() {
    let mut s = spool();
    let out = s.run("CAPABILITIES\r\n");
    let l = lines(&out);
    assert_eq!(l[0], "101 Capability list follows");
    assert_eq!(l[1], "VERSION 2");
    assert!(l.contains(&"READER") && l.contains(&"OVER") && l.contains(&"HDR"));
    assert!(l.iter().any(|x| x.starts_with("LIST ACTIVE NEWSGROUPS OVERVIEW.FMT")));
    assert_eq!(*l.last().unwrap(), ".");
}

#[test]
fn mode_reader_date_help_and_quit() {
    let mut s = spool();
    assert!(s.run("MODE READER\r\n").starts_with("200 "));
    let date = s.run("DATE\r\n");
    assert!(date.starts_with("111 20") && date.len() == "111 20261122123456\r\n".len(), "{date}");
    let help = s.run("HELP\r\n");
    assert!(help.starts_with("100 ") && help.ends_with("\r\n.\r\n"));
    assert_eq!(s.run("QUIT\r\n"), "205 Connection closing\r\n");
    assert!(s.is_closed());
}

#[test]
fn unknown_malformed_and_overlong_commands_get_their_errors_and_the_connection_goes_on() {
    let mut s = spool();
    assert!(s.run("IHAVE <a@b>\r\n").starts_with("500 "));
    assert!(s.run("GROUP\r\n").starts_with("501 "));
    assert!(s.run(&format!("GROUP {}\r\n", "x".repeat(5000))).starts_with("501 "));
    assert!(s.run("DATE\r\n").starts_with("111 "));
    assert!(!s.is_closed());
}

#[test]
fn group_selects_and_reports_the_count_and_the_range() {
    let mut s = spool();
    assert_eq!(s.run("GROUP misc.test\r\n"), "211 3 1 3 misc.test\r\n");
    assert_eq!(s.run("GROUP alt.empty\r\n"), "211 0 0 0 alt.empty\r\n");
    assert!(s.run("GROUP no.such\r\n").starts_with("411 "));
}

#[test]
fn article_commands_need_a_group_and_a_current_article() {
    let mut s = spool();
    for cmd in ["ARTICLE 1", "HEAD 1", "BODY 1", "STAT 1", "ARTICLE", "LAST", "NEXT", "OVER 1-2", "HDR subject 1", "LISTGROUP"] {
        let out = s.run(&format!("{cmd}\r\n"));
        assert!(out.starts_with("412 "), "{cmd}: {out}");
    }
    s.run("GROUP alt.empty\r\n");
    for cmd in ["ARTICLE", "STAT", "LAST", "NEXT", "OVER"] {
        let out = s.run(&format!("{cmd}\r\n"));
        assert!(out.starts_with("420 "), "{cmd}: {out}");
    }
}

#[test]
fn article_head_body_and_stat_by_number() {
    let mut s = spool();
    s.run("GROUP misc.test\r\n");
    let out = s.run("ARTICLE 2\r\n");
    assert_eq!(
        out,
        "220 2 <two@x.org> Article follows\r\n\
         From: a@x.org\r\nNewsgroups: misc.test\r\nSubject: two\r\nMessage-ID: <two@x.org>\r\nDate: Sat, 21 Nov 2026 10:00:00 +0000\r\n\
         \r\nsecond\r\n..leading dot\r\nlast line\r\n.\r\n"
    );
    let head = s.run("HEAD 2\r\n");
    assert!(head.starts_with("221 2 <two@x.org> Headers follow\r\n") && head.ends_with("+0000\r\n.\r\n"), "{head}");
    assert!(!head.contains("second"));
    assert_eq!(s.run("BODY 2\r\n"), "222 2 <two@x.org> Body follows\r\nsecond\r\n..leading dot\r\nlast line\r\n.\r\n");
    assert_eq!(s.run("STAT 2\r\n"), "223 2 <two@x.org> Article exists\r\n");
    assert_eq!(s.run("BODY 3\r\n"), "222 3 <three@x.org> Body follows\r\n.\r\n");
    assert!(s.run("ARTICLE 9\r\n").starts_with("423 "));
}

#[test]
fn an_article_by_number_becomes_the_current_article_and_one_by_message_id_does_not() {
    let mut s = spool();
    s.run("GROUP misc.test\r\n");
    assert!(s.run("STAT 3\r\n").starts_with("223 3 "));
    assert!(s.run("STAT\r\n").starts_with("223 3 "));
    assert!(s.run("STAT <one@x.org>\r\n").starts_with("223 1 <one@x.org>"));
    assert!(s.run("STAT\r\n").starts_with("223 3 "), "a message-id lookup left the current article alone");
}

#[test]
fn an_article_by_message_id_is_found_with_or_without_a_group() {
    let mut s = spool();
    let out = s.run("ARTICLE <one@x.org>\r\n");
    assert!(out.starts_with("220 0 <one@x.org> Article follows\r\n"), "{out}");
    assert!(out.contains("first body\r\n.\r\n"));
    s.run("GROUP alt.empty\r\n");
    let out = s.run("STAT <two@x.org>\r\n");
    assert_eq!(out, "223 0 <two@x.org> Article exists\r\n", "found in a group that is not the selected one");
    assert!(s.run("STAT <absent@x.org>\r\n").starts_with("430 "));
}

#[test]
fn group_sets_the_current_article_to_the_first() {
    let mut s = spool();
    s.run("GROUP misc.test\r\n");
    assert!(s.run("STAT\r\n").starts_with("223 1 <one@x.org>"));
}

#[test]
fn next_and_last_walk_the_group() {
    let mut s = spool();
    s.run("GROUP misc.test\r\n");
    assert!(s.run("LAST\r\n").starts_with("422 "));
    assert_eq!(s.run("NEXT\r\n"), "223 2 <two@x.org> Article found\r\n");
    assert_eq!(s.run("NEXT\r\n"), "223 3 <three@x.org> Article found\r\n");
    assert!(s.run("NEXT\r\n").starts_with("421 "));
    assert_eq!(s.run("LAST\r\n"), "223 2 <two@x.org> Article found\r\n");
    assert_eq!(s.run("LAST\r\n"), "223 1 <one@x.org> Article found\r\n");
    assert!(s.run("LAST\r\n").starts_with("422 "));
}

#[test]
fn listgroup_lists_the_numbers_and_selects_the_group() {
    let mut s = spool();
    assert_eq!(s.run("LISTGROUP misc.test\r\n"), "211 3 1 3 misc.test list follows\r\n1\r\n2\r\n3\r\n.\r\n");
    assert_eq!(s.run("LISTGROUP misc.test 2-\r\n"), "211 3 1 3 misc.test list follows\r\n2\r\n3\r\n.\r\n");
    assert_eq!(s.run("LISTGROUP misc.test 2-2\r\n"), "211 3 1 3 misc.test list follows\r\n2\r\n.\r\n");
    assert_eq!(s.run("LISTGROUP\r\n"), "211 3 1 3 misc.test list follows\r\n1\r\n2\r\n3\r\n.\r\n");
    assert_eq!(s.run("LISTGROUP alt.empty\r\n"), "211 0 0 0 alt.empty list follows\r\n.\r\n");
    assert!(s.run("LISTGROUP no.such\r\n").starts_with("411 "));
}

#[test]
fn list_active_newsgroups_and_overview_format() {
    let mut s = spool();
    let out = s.run("LIST\r\n");
    assert!(out.starts_with("215 "), "{out}");
    assert!(out.contains("\r\nmisc.test 3 1 y\r\n") && out.contains("\r\nalt.empty 0 0 y\r\n"), "{out}");
    let out = s.run("LIST ACTIVE alt.*\r\n");
    assert!(out.contains("alt.empty") && !out.contains("misc.test"), "{out}");
    let out = s.run("LIST ACTIVE *,!alt.*\r\n");
    assert!(out.contains("misc.test") && !out.contains("alt.empty"), "{out}");
    let out = s.run("LIST NEWSGROUPS misc.*\r\n");
    assert!(out.contains("\r\nmisc.test\t\r\n") && !out.contains("alt"), "{out}");
    let out = s.run("LIST OVERVIEW.FMT\r\n");
    assert_eq!(out, "215 Order of fields in overview database\r\nSubject:\r\nFrom:\r\nDate:\r\nMessage-ID:\r\nReferences:\r\n:bytes\r\n:lines\r\n.\r\n");
    assert!(s.run("LIST ACTIVE a,,b\r\n").starts_with("501 "));
}

#[test]
fn newgroups_lists_nothing_for_a_store_that_keeps_no_creation_times() {
    let mut s = spool();
    assert_eq!(s.run("NEWGROUPS 20260101 000000 GMT\r\n"), "231 List of new newsgroups follows\r\n.\r\n");
}

#[test]
fn over_reports_the_overview_fields() {
    let mut s = spool();
    s.run("GROUP misc.test\r\n");
    let out = s.run("OVER 2\r\n");
    let l = lines(&out);
    assert_eq!(l[0], "224 Overview information follows");
    let fields: Vec<&str> = l[1].split('\t').collect();
    assert_eq!(fields[0], "2");
    assert_eq!(&fields[1..5], ["two", "a@x.org", "Sat, 21 Nov 2026 10:00:00 +0000", "<two@x.org>"]);
    assert_eq!(fields[5], "");
    let whole = article("two", "second\r\n.leading dot\r\nlast line\r\n");
    assert_eq!(fields[6], whole.len().to_string());
    assert_eq!(fields[7], "3");
    assert_eq!(l[2], ".");
}

#[test]
fn over_covers_a_range_and_leaves_out_what_is_not_there() {
    let mut s = spool();
    s.run("GROUP misc.test\r\n");
    let out = s.run("OVER 1-\r\n");
    let numbers: Vec<&str> = lines(&out)[1..4].iter().map(|l| l.split('\t').next().unwrap()).collect();
    assert_eq!(numbers, ["1", "2", "3"]);
    assert!(s.run("OVER 7-9\r\n").starts_with("423 "));
    assert!(s.run("OVER 3-1\r\n").starts_with("423 "));
    assert!(s.run("OVER <two@x.org>\r\n").starts_with("224 "));
    assert!(s.run("OVER <absent@x.org>\r\n").starts_with("430 "));
    s.run("STAT 2\r\n");
    assert!(lines(&s.run("OVER\r\n"))[1].starts_with("2\t"));
}

#[test]
fn hdr_returns_a_header_or_a_metadata_item_for_each_article() {
    let mut s = spool();
    s.run("GROUP misc.test\r\n");
    assert_eq!(s.run("HDR Subject 1-2\r\n"), "225 Headers follow\r\n1 one\r\n2 two\r\n.\r\n");
    assert_eq!(s.run("HDR subject 3\r\n"), "225 Headers follow\r\n3 three\r\n.\r\n");
    assert_eq!(s.run("HDR X-Missing 1\r\n"), "225 Headers follow\r\n1 \r\n.\r\n");
    assert_eq!(s.run("HDR :lines 1-3\r\n"), "225 Headers follow\r\n1 1\r\n2 3\r\n3 0\r\n.\r\n");
    let bytes = s.run("HDR :bytes 3\r\n");
    assert_eq!(bytes, format!("225 Headers follow\r\n3 {}\r\n.\r\n", article("three", "").len()));
    assert_eq!(s.run("HDR Subject <one@x.org>\r\n"), "225 Headers follow\r\n1 one\r\n.\r\n", "in the selected group, the article's number there");
    assert!(s.run("HDR :x-other 1\r\n").starts_with("503 "));
    assert!(s.run("HDR subject 8-9\r\n").starts_with("423 "));
}

#[test]
fn pipelined_commands_are_answered_in_order() {
    let mut s = spool();
    let out = s.run("GROUP misc.test\r\nSTAT 1\r\nARTICLE 2\r\nDATE\r\nNEXT\r\nLIST OVERVIEW.FMT\r\nSTAT 99\r\nQUIT\r\n");
    let codes: Vec<&str> = out.split("\r\n").filter(|l| l.len() > 3 && l.as_bytes()[..3].iter().all(u8::is_ascii_digit) && l.as_bytes()[3] == b' ').map(|l| &l[..3]).collect();
    assert_eq!(codes, ["211", "223", "220", "111", "223", "215", "423", "205"], "{out}");
    assert!(s.is_closed());
}

#[test]
fn commands_arriving_a_byte_at_a_time_are_answered_the_same() {
    let wire = "GROUP misc.test\r\nARTICLE 2\r\nOVER 1-\r\nLIST\r\nHDR subject 1-3\r\n";
    let whole = spool().run(wire);
    let chunked = spool().run_chunked(wire, 1);
    assert_eq!(chunked, whole);
}

#[test]
fn nothing_after_quit_is_read() {
    let mut s = spool();
    assert_eq!(s.run("QUIT\r\nDATE\r\n"), "205 Connection closing\r\n");
}

#[test]
fn a_large_article_is_sent_in_constant_memory_as_the_client_takes_it() {
    let body: String = (0..60_000).map(|i| format!("line {i} of a long article\r\n")).collect();
    let mut s = Session::with_groups(&[("misc.test", vec![article("big", &body)])]);
    s.run("GROUP misc.test\r\n");
    let expected = {
        let mut stuffer = NntpDotStuffer::new(ArticlePart::Full);
        let mut out = Vec::new();
        stuffer.feed(article("big", &body).as_bytes(), &mut out);
        stuffer.finish(&mut out);
        out
    };
    assert!(expected.len() > 1_500_000);
    s.write_and_receive_once(b"ARTICLE 1\r\n");
    let mut got = Vec::new();
    let mut most_unread = 0usize;
    let started = std::time::Instant::now();
    loop {
        // Let everything that can happen happen, then see what has been
        // handed to the connection that the client has not yet taken.
        s.pump();
        let unread = s.take_bytes();
        most_unread = most_unread.max(unread.len());
        got.extend_from_slice(&unread);
        if got.ends_with(b"\r\n.\r\n") && s.handler.job.is_none() {
            break;
        }
        s.drain();
        assert!(started.elapsed() < Duration::from_secs(60), "never finished");
    }
    let status_len = "220 1 <big@x.org> Article follows\r\n".len();
    assert_eq!(&got[status_len..], &expected[..]);
    // What the connection held at once was a few batches, not the article.
    assert!(most_unread <= 3 * BATCH, "{most_unread} bytes were queued at once");
}

#[test]
fn a_client_that_stops_reading_ends_the_connection_after_the_stall_limit() {
    let body: String = (0..60_000).map(|i| format!("line {i} of a long article\r\n")).collect();
    let mut s = Session::with(&[("misc.test", vec![article("big", &body)])], |mut c| {
        c.write_stall_timeout = Duration::from_millis(200);
        c
    });
    s.run("GROUP misc.test\r\n");
    s.write_and_receive_once(b"ARTICLE 1\r\n");
    // The client never drains. The answer is held to a bound, and after the
    // stall limit the connection is closed.
    let started = std::time::Instant::now();
    while !s.is_closed() {
        s.pump();
        assert!(started.elapsed() < Duration::from_secs(20), "the connection was never closed");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_client_that_goes_away_mid_article_lets_go_of_the_storage_thread() {
    let body: String = (0..60_000).map(|i| format!("line {i} of a long article\r\n")).collect();
    let mut s = Session::with_groups(&[("misc.test", vec![article("big", &body)])]);
    s.run("GROUP misc.test\r\n");
    s.write_and_receive_once(b"ARTICLE 1\r\n");
    s.pump();
    s.disconnect();
    // The job ends rather than waiting for ever on a pipe nobody empties; the
    // runtime's storage pool is then free for other work.
    let started = std::time::Instant::now();
    while s.handler.shared.reader.lock().unwrap().is_some() {
        assert!(started.elapsed() < Duration::from_secs(20), "the reader was never released");
        std::thread::sleep(Duration::from_millis(10));
    }
}

// ---- POST ----

/// An article as a client sends it: dot-stuffed and ended.
fn on_the_wire(article: &str) -> String {
    let mut out = String::new();
    for line in article.split_inclusive('\n') {
        if line.starts_with('.') {
            out.push('.');
        }
        out.push_str(line);
    }
    if !out.ends_with("\r\n") {
        out.push_str("\r\n");
    }
    out.push_str(".\r\n");
    out
}

fn post_text(subject: &str, groups: &str, body: &str) -> String {
    format!("From: p@x.org\r\nNewsgroups: {groups}\r\nSubject: {subject}\r\n\r\n{body}")
}

#[test]
fn a_posted_article_is_filed_and_can_be_read_back() {
    let mut s = spool();
    assert_eq!(s.run("POST\r\n"), "340 Input article; end with <CR-LF>.<CR-LF>\r\n");
    let out = s.run(&on_the_wire(&post_text("posted", "misc.test", "hello\r\n.dotted\r\n")));
    assert_eq!(out, "240 Article received OK\r\n");
    assert_eq!(s.run("GROUP misc.test\r\n"), "211 4 1 4 misc.test\r\n");
    let article = s.run("ARTICLE 4\r\n");
    assert!(article.starts_with("220 4 <"), "{article}");
    assert!(article.contains("@news.example> Article follows"), "a Message-ID was added: {article}");
    assert!(article.contains("\r\nSubject: posted\r\n") && article.contains("\r\nDate: "), "{article}");
    assert!(article.ends_with("\r\n\r\nhello\r\n..dotted\r\n.\r\n"), "{article}");
}

#[test]
fn a_message_id_and_a_date_the_client_gave_are_kept() {
    let mut s = spool();
    s.run("POST\r\n");
    let text = format!("Message-ID: <mine@x.org>\r\nDate: Sat, 21 Nov 2026 10:00:00 +0000\r\n{}", post_text("kept", "misc.test", "b\r\n"));
    assert_eq!(s.run(&on_the_wire(&text)), "240 Article received OK\r\n");
    s.run("GROUP misc.test\r\n");
    let head = s.run("HEAD <mine@x.org>\r\n");
    assert!(head.starts_with("221 4 <mine@x.org>"), "{head}");
    assert_eq!(head.matches("Message-ID:").count(), 1);
    assert_eq!(head.matches("Date:").count(), 1);
}

#[test]
fn an_article_is_filed_in_each_group_it_names_that_exists() {
    let mut s = spool();
    s.run("POST\r\n");
    assert_eq!(s.run(&on_the_wire(&post_text("many", "misc.test, alt.empty,no.such", "x\r\n"))), "240 Article received OK\r\n");
    assert_eq!(s.run("GROUP misc.test\r\n"), "211 4 1 4 misc.test\r\n");
    assert_eq!(s.run("GROUP alt.empty\r\n"), "211 1 1 1 alt.empty\r\n");
}

#[test]
fn an_article_that_cannot_be_filed_is_refused_and_nothing_is_kept() {
    let mut s = spool();
    for (article, reason) in [
        (post_text("s", "no.such", "x\r\n"), "No such newsgroup"),
        ("From: a@b\r\nSubject: s\r\n\r\nx\r\n".to_string(), "No Newsgroups header"),
        ("Newsgroups: misc.test\r\nSubject: s\r\n\r\nx\r\n".to_string(), "No From header"),
        ("Newsgroups: misc.test\r\nFrom: a@b\r\n\r\nx\r\n".to_string(), "No Subject header"),
        (format!("Message-ID: not-an-id\r\n{}", post_text("s", "misc.test", "x\r\n")), "Invalid Message-ID"),
        ("\r\nno headers at all\r\n".to_string(), "No Newsgroups header"),
    ] {
        assert!(s.run("POST\r\n").starts_with("340 "));
        let out = s.run(&on_the_wire(&article));
        assert_eq!(out, format!("441 {reason}\r\n"), "{article:?}");
    }
    assert_eq!(s.run("GROUP misc.test\r\n"), "211 3 1 3 misc.test\r\n");
    assert!(s.run("DATE\r\n").starts_with("111 "), "the connection carried on");
}

#[test]
fn an_article_with_headers_and_no_body_is_accepted_and_an_empty_one_is_not() {
    let mut s = spool();
    s.run("POST\r\n");
    assert_eq!(s.run(".\r\n"), "441 Empty article\r\n");
    s.run("POST\r\n");
    assert_eq!(s.run("From: a@b\r\nNewsgroups: misc.test\r\nSubject: s\r\n.\r\n"), "240 Article received OK\r\n");
    s.run("GROUP misc.test\r\n");
    let body = s.run("BODY 4\r\n");
    assert!(body.starts_with("222 4 <") && body.ends_with("> Body follows\r\n.\r\n"), "{body}");
}

#[test]
fn commands_pipelined_behind_an_article_wait_for_it() {
    let mut s = spool();
    let wire = format!("POST\r\n{}DATE\r\nGROUP misc.test\r\n", on_the_wire(&post_text("p", "misc.test", "b\r\n")));
    let out = s.run(&wire);
    let codes: Vec<&str> = out.split("\r\n").filter(|l| !l.is_empty()).map(|l| &l[..3]).collect();
    assert_eq!(codes, ["340", "240", "111", "211"], "{out}");
    assert!(out.contains("211 4 1 4 misc.test"));
}

#[test]
fn an_article_arriving_a_byte_at_a_time_is_the_same_article() {
    let mut s = spool();
    s.run("POST\r\n");
    let wire = on_the_wire(&post_text("slow", "misc.test", "line\r\n.dot\r\n..two\r\nlast\r\n"));
    assert_eq!(s.run_chunked(&wire, 1), "240 Article received OK\r\n");
    s.run("GROUP misc.test\r\n");
    assert!(s.run("BODY 4\r\n").ends_with("\r\nline\r\n..dot\r\n...two\r\nlast\r\n.\r\n"));
}

#[test]
fn an_article_over_the_size_limit_is_read_and_refused() {
    let mut s = Session::with(&[("misc.test", vec![article("one", "x\r\n")])], |mut c| {
        c.max_post_size = Some(2000);
        c
    });
    s.run("POST\r\n");
    let big = post_text("big", "misc.test", &"0123456789abcdef\r\n".repeat(5000));
    assert_eq!(s.run(&on_the_wire(&big)), "441 Article too large\r\n");
    assert_eq!(s.run("GROUP misc.test\r\n"), "211 1 1 1 misc.test\r\n");
    s.run("POST\r\n");
    assert_eq!(s.run(&on_the_wire(&post_text("small", "misc.test", "x\r\n"))), "240 Article received OK\r\n");
}

#[test]
fn posting_is_refused_when_it_is_not_allowed() {
    let mut s = Session::with(&[], |c| c.with_posting_allowed(false));
    assert_eq!(s.run("POST\r\n"), "440 Posting not permitted\r\n");
    let out = s.run("CAPABILITIES\r\n");
    assert!(!out.contains("\r\nPOST\r\n"));
    let mut s = spool();
    assert!(s.run("CAPABILITIES\r\n").contains("\r\nPOST\r\n"));
}

#[test]
fn a_client_that_goes_away_mid_article_leaves_nothing_behind() {
    let mut s = spool();
    s.run("POST\r\n");
    let wire = on_the_wire(&post_text("half", "misc.test", &"data\r\n".repeat(50_000)));
    s.write_and_receive_once(&wire.as_bytes()[..wire.len() / 2]);
    s.pump();
    s.disconnect();
    let started = std::time::Instant::now();
    while s.handler.shared.reader.lock().unwrap().is_some() {
        assert!(started.elapsed() < Duration::from_secs(20), "the connection was never cleaned up");
        std::thread::sleep(Duration::from_millis(10));
    }
    // The group still has its three articles and no partial one.
    let root_factory = s.factory_for_checks();
    let mut store = root_factory.create_store();
    store.open("news").unwrap();
    let mb = store.open_mailbox("misc/test", true).unwrap();
    assert_eq!(mb.message_count().unwrap(), 3);
}

// ---- a store that falls behind ----

mod slow_store {
    use super::*;
    use crate::server::handler::{
        ClientConnected, ConnectedState, GroupStatus, HandlerError, HandlerResult, Located, NewsgroupInfo,
        NntpConnectionMetadata, NntpHandlerFactory, PostSink, ReaderHandler,
    };
    use crate::server::wildmat::Wildmat;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Condvar;

    /// Lets a test hold the sink's writes.
    struct Gate {
        open: Mutex<bool>,
        changed: Condvar,
        received: AtomicUsize,
        committed: AtomicBool,
    }

    struct Sink(Arc<Gate>);

    impl PostSink for Sink {
        fn write(&mut self, piece: &[u8]) -> HandlerResult<()> {
            self.0.received.fetch_add(piece.len(), Ordering::SeqCst);
            let mut open = self.0.open.lock().unwrap();
            while !*open {
                open = self.0.changed.wait(open).unwrap();
            }
            Ok(())
        }
        fn commit(self: Box<Self>) -> HandlerResult<()> {
            self.0.committed.store(true, Ordering::SeqCst);
            Ok(())
        }
        fn abort(self: Box<Self>) {}
    }

    struct Reader(Arc<Gate>);

    impl ReaderHandler for Reader {
        fn select_group(&mut self, _: &str) -> HandlerResult<GroupStatus> {
            Err(HandlerError::NoSuchGroup)
        }
        fn article_numbers(&mut self, _: u32, _: u32, _: usize) -> HandlerResult<Vec<u32>> {
            Ok(Vec::new())
        }
        fn locate_number(&mut self, _: u32) -> HandlerResult<Option<Located>> {
            Ok(None)
        }
        fn locate_message_id(&mut self, _: &str) -> HandlerResult<Option<Located>> {
            Ok(None)
        }
        fn read_article(&mut self, _: &Located, _: &mut dyn FnMut(&[u8]) -> bool) -> HandlerResult<()> {
            Ok(())
        }
        fn groups(&mut self, _: &Wildmat, _: bool, _: &mut dyn FnMut(NewsgroupInfo) -> bool) -> HandlerResult<()> {
            Ok(())
        }
        fn begin_post(&mut self) -> HandlerResult<Box<dyn PostSink>> {
            Ok(Box::new(Sink(Arc::clone(&self.0))))
        }
    }

    struct Factory(Arc<Gate>);

    impl NntpHandlerFactory for Factory {
        fn create(&self) -> Box<dyn ClientConnected> {
            struct Connected(Arc<Gate>);
            impl ClientConnected for Connected {
                fn connected(&mut self, state: &mut dyn ConnectedState, _: &NntpConnectionMetadata) {
                    state.accept_connection("ready", true, Box::new(Reader(Arc::clone(&self.0))));
                }
            }
            Box::new(Connected(Arc::clone(&self.0)))
        }
    }

    #[test]
    fn a_store_that_falls_behind_holds_the_client_back_instead_of_the_article_piling_up() {
        let gate = Arc::new(Gate {
            open: Mutex::new(false),
            changed: Condvar::new(),
            received: AtomicUsize::new(0),
            committed: AtomicBool::new(false),
        });
        let config = NntpConfig::new("127.0.0.1:1119".parse().unwrap(), "news.example");
        let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
        let handler = NntpControlHandler::new(Factory(Arc::clone(&gate)).create(), NntpServerMetrics::shared(), config, rt);
        let mut peer = Peer::connect(handler, |h| h.busy());
        peer.take();
        let mut out = peer.run("POST\r\n");
        while peer.handler.job.is_some() {
            peer.drain();
            out.push_str(&peer.take());
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(out.starts_with("340 "), "{out}");

        let body = "0123456789abcdef\r\n".repeat(30_000);
        let wire = format!("From: a@b\r\nNewsgroups: x\r\nSubject: s\r\n\r\n{body}.\r\n");
        peer.write_and_receive_once(wire.as_bytes());
        std::thread::sleep(Duration::from_millis(300));
        let held = gate.received.load(Ordering::SeqCst);
        assert!(held > 0 && held <= POST_PIECE, "the sink was given {held} bytes while it was stuck on its first write");
        assert!(!gate.committed.load(Ordering::SeqCst));

        *gate.open.lock().unwrap() = true;
        gate.changed.notify_all();
        let started = std::time::Instant::now();
        let mut out = String::new();
        while !out.contains("240 ") {
            peer.drain();
            out.push_str(&peer.take());
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "the post never finished: {out:?}, received {} of {}, job {}, post {:?}, pending {}",
                gate.received.load(Ordering::SeqCst),
                wire.len(),
                peer.handler.job.is_some(),
                peer.handler.post.as_ref().map(|p| (p.bytes, p.finished, p.discarding)),
                peer.handler.write_pending.load(Ordering::SeqCst)
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(gate.received.load(Ordering::SeqCst), wire.len() - ".\r\n".len());
        assert!(gate.committed.load(Ordering::SeqCst));
    }
}
