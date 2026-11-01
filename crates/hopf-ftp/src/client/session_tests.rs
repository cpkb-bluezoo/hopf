// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! End-to-end tests of the FTP client's control channel.
//!
//! The test plays the server over an in-process [`Peer`]: it writes replies
//! and checks the commands the client sends back. Data connections need real
//! sockets, so only the control-channel side of a session is covered here.

use std::io;
use std::sync::{Arc, Mutex};

use hopf_core::testing::Peer;
use hopf_core::{Runtime, RuntimeConfig};

use super::handler::FtpControlHandler;
use super::{
    FtpAbortHandle, FtpClientDataMode, FtpClientTimeouts, FtpError, FtpPipeline, FtpSessionWrite,
};

/// What a pipeline saw, shared with the test.
#[derive(Default)]
struct Log {
    started: bool,
    done: bool,
    failed: Option<FtpError>,
    replies: Vec<Result<String, FtpError>>,
}

type Shared = Arc<Mutex<Log>>;

/// Queues whatever `script` asks for and records the outcome.
struct Script {
    log: Shared,
    script: Option<Box<dyn FnOnce(&mut dyn FtpSessionWrite, &Shared) + Send>>,
}

impl FtpPipeline for Script {
    fn start(&mut self, session: &mut dyn FtpSessionWrite, _abort: FtpAbortHandle) {
        self.log.lock().unwrap().started = true;
        if let Some(script) = self.script.take() {
            script(session, &self.log);
        }
    }

    fn done(&mut self) {
        self.log.lock().unwrap().done = true;
    }

    fn failed(&mut self, err: FtpError) {
        self.log.lock().unwrap().failed = Some(err);
    }
}

fn session(
    credentials: Option<(&str, &str)>,
    script: impl FnOnce(&mut dyn FtpSessionWrite, &Shared) + Send + 'static,
) -> (Peer<FtpControlHandler>, Shared) {
    let log = Shared::default();
    let pipeline = Script {
        log: Arc::clone(&log),
        script: Some(Box::new(script)),
    };
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let handler = FtpControlHandler::new(
        credentials.map(|(u, p)| (u.to_string(), p.to_string())),
        FtpClientDataMode::Passive,
        false,
        false,
        FtpClientTimeouts::default(),
        rt,
        Box::new(pipeline),
        None,
        None,
        None,
        false,
    );
    (Peer::connect(handler, |_| false), log)
}

/// A pipeline that records every reply to the commands it queues, then quits.
fn commands(
    credentials: Option<(&str, &str)>,
    cmds: &'static [(&'static str, Option<&'static str>, u16)],
) -> (Peer<FtpControlHandler>, Shared) {
    session(credentials, move |s, log| {
        for &(verb, arg, expect) in cmds {
            let log = Arc::clone(log);
            s.command_reply(
                verb,
                arg,
                expect,
                Box::new(move |r| log.lock().unwrap().replies.push(r)),
            );
        }
        s.quit();
    })
}

fn failed(log: &Shared) -> (Option<u16>, u16) {
    match log.lock().unwrap().failed.as_ref() {
        Some(FtpError::Protocol { expected, code, .. }) => (*expected, *code),
        other => panic!("expected a protocol failure, got {other:?}"),
    }
}

fn reply_text(log: &Shared, i: usize) -> String {
    log.lock().unwrap().replies[i].as_ref().unwrap().clone()
}

#[test]
fn with_no_credentials_the_pipeline_starts_after_the_banner() {
    let (mut peer, log) = commands(None, &[]);
    assert!(!log.lock().unwrap().started);
    assert_eq!(peer.run("220 hello\r\n"), "QUIT\r\n");
    assert!(log.lock().unwrap().started);
    assert_eq!(peer.run("221 bye\r\n"), "");
    assert!(log.lock().unwrap().done);
    assert!(peer.is_closed());
}

#[test]
fn credentials_are_sent_as_user_then_pass() {
    let (mut peer, log) = commands(Some(("alice", "secret")), &[]);
    assert_eq!(peer.run("220 hello\r\n"), "USER alice\r\n");
    assert_eq!(peer.run("331 password please\r\n"), "PASS secret\r\n");
    assert!(!log.lock().unwrap().started);
    assert_eq!(peer.run("230 welcome\r\n"), "QUIT\r\n");
    assert!(log.lock().unwrap().started);
}

#[test]
fn a_user_accepted_without_a_password_skips_pass() {
    let (mut peer, log) = commands(Some(("anonymous", "x")), &[]);
    peer.run("220 hello\r\n");
    assert_eq!(peer.run("230 no password needed\r\n"), "QUIT\r\n");
    assert!(log.lock().unwrap().started);
}

#[test]
fn a_refused_user_fails_the_pipeline() {
    let (mut peer, log) = commands(Some(("mallory", "x")), &[]);
    peer.run("220 hello\r\n");
    assert_eq!(peer.run("530 not allowed\r\n"), "");
    assert_eq!(failed(&log), (Some(331), 530));
    assert!(!log.lock().unwrap().started);
    assert!(peer.is_closed());
}

#[test]
fn a_refused_password_fails_the_pipeline() {
    let (mut peer, log) = commands(Some(("alice", "wrong")), &[]);
    peer.run("220 hello\r\n");
    peer.run("331 password please\r\n");
    assert_eq!(peer.run("530 login incorrect\r\n"), "");
    assert_eq!(failed(&log), (Some(230), 530));
    assert!(peer.is_closed());
}

#[test]
fn a_refusing_banner_fails_the_pipeline() {
    let (mut peer, log) = commands(None, &[]);
    assert_eq!(peer.run("421 too many users\r\n"), "");
    assert_eq!(failed(&log), (Some(220), 421));
    assert!(!log.lock().unwrap().started);
    assert!(peer.is_closed());
}

#[test]
fn a_multiline_banner_is_one_welcome() {
    let (mut peer, log) = commands(None, &[]);
    assert_eq!(
        peer.run("220-first line\r\nsecond line\r\n220 last line\r\n"),
        "QUIT\r\n"
    );
    assert!(log.lock().unwrap().started);
}

#[test]
fn commands_are_sent_one_at_a_time_as_each_reply_arrives() {
    let (mut peer, log) = commands(
        None,
        &[("NOOP", None, 200), ("CWD", Some("/pub"), 250), ("PWD", None, 257)],
    );
    assert_eq!(peer.run("220 hi\r\n"), "NOOP\r\n");
    assert_eq!(peer.run("200 ok\r\n"), "CWD /pub\r\n");
    assert_eq!(peer.run("250 done\r\n"), "PWD\r\n");
    assert_eq!(peer.run("257 \"/pub\" is the directory\r\n"), "QUIT\r\n");
    assert_eq!(reply_text(&log, 2), "\"/pub\" is the directory");
    peer.run("221 bye\r\n");
    assert!(log.lock().unwrap().done);
}

#[test]
fn an_expectation_of_zero_accepts_any_2xx() {
    let (mut peer, log) = commands(None, &[("SITE", Some("HELP"), 0)]);
    peer.run("220 hi\r\n");
    assert_eq!(peer.run("214 help text\r\n"), "QUIT\r\n");
    assert_eq!(reply_text(&log, 0), "help text");
}

#[test]
fn a_mismatched_reply_with_a_callback_does_not_fail_the_pipeline() {
    let (mut peer, log) = commands(None, &[("SIZE", Some("gone"), 213), ("NOOP", None, 200)]);
    peer.run("220 hi\r\n");
    assert_eq!(peer.run("550 no such file\r\n"), "NOOP\r\n");
    assert_eq!(peer.run("200 ok\r\n"), "QUIT\r\n");
    let g = log.lock().unwrap();
    assert!(g.failed.is_none());
    match &g.replies[0] {
        Err(FtpError::Protocol { expected, code, .. }) => {
            assert_eq!((*expected, *code), (Some(213), 550));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(g.replies[1].as_ref().unwrap(), "ok");
}

#[test]
fn a_mismatched_reply_without_a_callback_fails_the_pipeline() {
    let (mut peer, log) = session(None, |s, _| {
        s.command("CWD", Some("/nowhere"), 250);
        s.quit();
    });
    assert_eq!(peer.run("220 hi\r\n"), "CWD /nowhere\r\n");
    assert_eq!(peer.run("550 no such directory\r\n"), "");
    assert_eq!(failed(&log), (Some(250), 550));
    assert!(peer.is_closed());
}

#[test]
fn type_commands_ask_for_image_or_ascii() {
    let (mut peer, _log) = session(None, |s, _| {
        s.type_image();
        s.type_ascii();
        s.quit();
    });
    assert_eq!(peer.run("220 hi\r\n"), "TYPE I\r\n");
    assert_eq!(peer.run("200 binary\r\n"), "TYPE A\r\n");
    assert_eq!(peer.run("200 ascii\r\n"), "QUIT\r\n");
}

#[test]
fn a_multiline_reply_is_one_reply() {
    let (mut peer, log) = commands(None, &[("FEAT", None, 211), ("NOOP", None, 200)]);
    peer.run("220 hi\r\n");
    assert_eq!(
        peer.run("211-Extensions supported:\r\n MLST\r\n UTF8\r\n211 End\r\n"),
        "NOOP\r\n"
    );
    // Only the terminating line's text is kept (see reply.rs).
    assert_eq!(reply_text(&log, 0), "End");
    assert_eq!(peer.run("200 ok\r\n"), "QUIT\r\n");
}

#[test]
fn replies_to_two_commands_in_one_read_are_each_read_in_turn() {
    let (mut peer, log) = commands(None, &[("NOOP", None, 200), ("PWD", None, 257)]);
    peer.run("220 hi\r\n");
    assert_eq!(peer.take(), "");
    assert_eq!(peer.run("200 ok\r\n257 \"/\" is the root\r\n"), "PWD\r\nQUIT\r\n");
    assert_eq!(reply_text(&log, 1), "\"/\" is the root");
}

#[test]
fn a_whole_session_is_the_same_at_every_chunking() {
    let wire = "220-hi\r\n220 there\r\n331 pass\r\n230 in\r\n\
                200 ok\r\n550 nope\r\n257 \"/x\" here\r\n221 bye\r\n";
    let run = |chunk: usize| {
        let (mut peer, log) = commands(
            Some(("u", "p")),
            &[("NOOP", None, 200), ("SIZE", Some("f"), 213), ("PWD", None, 257)],
        );
        let sent = peer.run_chunked(wire, chunk);
        let g = log.lock().unwrap();
        let replies: Vec<String> = g
            .replies
            .iter()
            .map(|r| match r {
                Ok(t) => format!("ok {t}"),
                Err(FtpError::Protocol { code, .. }) => format!("err {code}"),
                Err(e) => panic!("{e}"),
            })
            .collect();
        (sent, replies, g.done, peer.is_closed())
    };
    let whole = run(wire.len());
    assert_eq!(
        whole.0,
        "USER u\r\nPASS p\r\nNOOP\r\nSIZE f\r\nPWD\r\nQUIT\r\n"
    );
    assert_eq!(whole.1, ["ok ok", "err 550", "ok \"/x\" here"]);
    assert!(whole.2 && whole.3);
    for chunk in [1, 2, 3, 7] {
        assert_eq!(run(chunk), whole, "chunk {chunk}");
    }
}

#[test]
fn any_reply_to_quit_ends_the_session() {
    let (mut peer, log) = commands(None, &[]);
    peer.run("220 hi\r\n");
    peer.run("500 whatever\r\n");
    assert!(log.lock().unwrap().done);
    assert!(log.lock().unwrap().failed.is_none());
    assert!(peer.is_closed());
}

#[test]
fn losing_the_connection_before_quit_fails_the_pipeline() {
    let (mut peer, log) = commands(None, &[("NOOP", None, 200)]);
    peer.run("220 hi\r\n");
    peer.disconnect();
    match log.lock().unwrap().failed.as_ref() {
        Some(FtpError::Io(e)) => assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof),
        other => panic!("{other:?}"),
    }
    assert!(!log.lock().unwrap().done);
}

#[test]
fn losing_the_connection_after_quit_is_not_a_second_outcome() {
    let (mut peer, log) = commands(None, &[]);
    peer.run("220 hi\r\n");
    peer.run("221 bye\r\n");
    peer.disconnect();
    assert!(log.lock().unwrap().done);
    assert!(log.lock().unwrap().failed.is_none());
}

#[test]
fn a_transfer_refused_at_the_data_setup_fails_the_pipeline() {
    let (mut peer, log) = session(None, |s, _| {
        s.list(None, Box::new(Sink));
        s.quit();
    });
    assert_eq!(peer.run("220 hi\r\n"), "PASV\r\n");
    assert_eq!(peer.run("425 can't open a data connection\r\n"), "");
    assert_eq!(failed(&log), (Some(227), 425));
    assert!(peer.is_closed());
}

/// A receiver that ignores what it is given.
struct Sink;

impl super::MessageReceiveCallback for Sink {
    fn message_content(&mut self, _chunk: &[u8]) -> bool {
        true
    }
    fn end_message(&mut self, _result: io::Result<()>) {}
}
