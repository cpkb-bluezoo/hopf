// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Opt-in POP3 integration smoke (not run in CI `--lib`).

use std::collections::BTreeSet;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use hopf_auth::PasswordStore;
use hopf_core::{Runtime, RuntimeConfig};
use hopf_mailbox::{MailboxFactory, MaildirFactory};

use crate::{Pop3Config, Pop3Service};

#[test]
fn pop3_user_pass_stat_retr_dele_quit() {
    let dir = tempfile::tempdir().unwrap();
    let factory = Arc::new(MaildirFactory::new(dir.path()));
    {
        let mut store = factory.create_store();
        store.open("alice").unwrap();
        let mut mb = store.open_mailbox("INBOX", false).unwrap();
        mb.append_message(
            b"From: a@b\r\nSubject: hi\r\n\r\nhello\r\n",
            &BTreeSet::new(),
            None,
        )
        .unwrap();
        mb.close(false).unwrap();
        store.close().unwrap();
    }

    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let store = Arc::new(PasswordStore::new().with_user("alice", "secret"));
    let config = Pop3Config::new("127.0.0.1:0".parse().unwrap(), "localhost", store, factory);
    let svc = Pop3Service::new(config, Arc::clone(&rt));
    let addr = svc.start().unwrap();

    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = vec![0u8; 4096];

    let greet = read_until(&mut stream, &mut buf, |s| s.starts_with("+OK"));
    assert!(greet.starts_with("+OK"), "{greet}");

    write_cmd(&mut stream, b"USER alice\r\n");
    assert!(read_until(&mut stream, &mut buf, |s| s.starts_with("+OK")).starts_with("+OK"));

    write_cmd(&mut stream, b"PASS secret\r\n");
    let opened = read_until(&mut stream, &mut buf, |s| s.contains("Mailbox opened"));
    assert!(opened.contains("Mailbox opened"), "{opened}");

    write_cmd(&mut stream, b"STAT\r\n");
    let resp = read_until(&mut stream, &mut buf, |s| s.starts_with("+OK"));
    assert!(resp.starts_with("+OK 1 "), "{resp}");

    write_cmd(&mut stream, b"RETR 1\r\n");
    let body = read_until(&mut stream, &mut buf, |s| s.contains("\r\n.\r\n"));
    assert!(body.contains("hello"), "{body}");

    write_cmd(&mut stream, b"DELE 1\r\n");
    assert!(read_until(&mut stream, &mut buf, |s| s.starts_with("+OK")).starts_with("+OK"));

    write_cmd(&mut stream, b"QUIT\r\n");
    let bye = read_until(&mut stream, &mut buf, |s| s.starts_with("+OK") || s.starts_with("-ERR"));
    assert!(bye.starts_with("+OK"), "{bye}");
    drop(rt);
}

fn write_cmd(stream: &mut TcpStream, cmd: &[u8]) {
    stream.write_all(cmd).unwrap();
    stream.flush().unwrap();
}

fn read_until(stream: &mut TcpStream, buf: &mut [u8], pred: impl Fn(&str) -> bool) -> String {
    let mut acc = String::new();
    for _ in 0..50 {
        match stream.read(buf) {
            Ok(0) => break,
            Ok(n) => {
                acc.push_str(std::str::from_utf8(&buf[..n]).unwrap_or(""));
                if pred(&acc) {
                    return acc;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                continue;
            }
            Err(e) => panic!("read failed: {e}"),
        }
    }
    acc
}
