// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Opt-in POP3 integration smoke (not run in CI `--lib`).

use std::collections::BTreeSet;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_auth::PasswordStore;
use hopf_core::{Runtime, RuntimeConfig};
use hopf_mailbox::{MailboxFactory, MaildirFactory};

use crate::{Pop3Client, Pop3ClientTimeouts, Pop3Config, Pop3Fetch, Pop3Service};

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
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => panic!("read failed: {e}"),
        }
    }
    acc
}

/// Spin-wait up to `max_ms` milliseconds for `pred` to return `true`.
#[cfg(test)]
fn wait_for(pred: impl Fn() -> bool, max_ms: u64) -> bool {
    for _ in 0..(max_ms / 10) {
        if pred() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    pred()
}

/// Start a Pop3Service with one message in alice's INBOX and return (rt, addr).
#[cfg(test)]
fn start_pop3_server_with_message(
    dir: &tempfile::TempDir,
) -> (Arc<Runtime>, std::net::SocketAddr) {
    let factory = Arc::new(MaildirFactory::new(dir.path()));
    {
        let mut store = factory.create_store();
        store.open("alice").unwrap();
        let mut mb = store.open_mailbox("INBOX", false).unwrap();
        mb.append_message(
            b"From: a@b\r\nSubject: client test\r\n\r\nhello pop3 client\r\n",
            &BTreeSet::new(),
            None,
        )
        .unwrap();
        mb.close(false).unwrap();
        store.close().unwrap();
    }
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let pass = Arc::new(PasswordStore::new().with_user("alice", "secret"));
    let config = Pop3Config::new("127.0.0.1:0".parse().unwrap(), "localhost", pass, factory);
    let svc = Pop3Service::new(config, Arc::clone(&rt));
    let addr = svc.start().unwrap();
    (rt, addr)
}

// ── Client integration tests ──────────────────────────────────────────────────

#[test]
fn client_fetch_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, addr) = start_pop3_server_with_message(&dir);

    let received: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let received2 = Arc::clone(&received);
    let done: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
    let done2 = Arc::clone(&done);

    let fetch = Pop3Fetch::new()
        .credentials("alice", "secret")
        .on_message(Box::new(move |_id, _uid, bytes| {
            received2.lock().unwrap().push(bytes);
        }))
        .on_complete(Box::new(move |ok| {
            *done2.lock().unwrap() = Some(ok);
        }));

    Pop3Client::from_addr(addr)
        .timeouts(Pop3ClientTimeouts { stage: Duration::from_secs(5), ..Default::default() })
        .connect(&rt, Arc::new(fetch))
        .unwrap();

    assert!(wait_for(|| done.lock().unwrap().is_some(), 5000));

    let ok = done.lock().unwrap().unwrap_or(false);
    assert!(ok, "pop3 fetch should succeed");

    let msgs = received.lock().unwrap();
    assert_eq!(msgs.len(), 1, "should receive exactly one message");
    assert!(
        msgs[0].windows(b"hello pop3 client".len()).any(|w| w == b"hello pop3 client"),
        "message body should contain expected content: {:?}",
        String::from_utf8_lossy(&msgs[0])
    );
}

#[test]
fn client_fetch_delete_after_fetch() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, addr) = start_pop3_server_with_message(&dir);

    let done: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
    let done2 = Arc::clone(&done);

    let fetch = Pop3Fetch::new()
        .credentials("alice", "secret")
        .delete_after_fetch(true)
        .on_complete(Box::new(move |ok| {
            *done2.lock().unwrap() = Some(ok);
        }));

    Pop3Client::from_addr(addr)
        .timeouts(Pop3ClientTimeouts { stage: Duration::from_secs(5), ..Default::default() })
        .connect(&rt, Arc::new(fetch))
        .unwrap();

    assert!(wait_for(|| done.lock().unwrap().is_some(), 5000));
    assert!(done.lock().unwrap().unwrap_or(false), "fetch+delete should succeed");
}

#[test]
fn client_greeting_timeout() {
    use std::net::TcpListener;

    // Bind a listener but never accept — greeting times out.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let done: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
    let done2 = Arc::clone(&done);

    let fetch = Pop3Fetch::new().on_complete(Box::new(move |ok| {
        *done2.lock().unwrap() = Some(ok);
    }));

    Pop3Client::from_addr(addr)
        .timeouts(Pop3ClientTimeouts {
            stage: Duration::from_millis(300),
            connect: Duration::from_millis(300),
            ..Default::default()
        })
        .connect(&rt, Arc::new(fetch))
        .unwrap();

    assert!(wait_for(|| done.lock().unwrap().is_some(), 3000));
    let ok = done.lock().unwrap().unwrap_or(true);
    assert!(!ok, "should fail on greeting timeout");
    drop(listener);
}

#[test]
fn client_empty_maildrop() {
    // Server with no messages — STAT returns 0, should complete successfully.
    let dir = tempfile::tempdir().unwrap();
    let factory = Arc::new(MaildirFactory::new(dir.path()));
    {
        let mut store = factory.create_store();
        store.open("bob").unwrap();
        store.close().unwrap();
    }
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let pass = Arc::new(PasswordStore::new().with_user("bob", "pw"));
    let config = Pop3Config::new("127.0.0.1:0".parse().unwrap(), "localhost", pass, factory);
    let svc = Pop3Service::new(config, Arc::clone(&rt));
    let addr = svc.start().unwrap();

    let done: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
    let done2 = Arc::clone(&done);

    let fetch = Pop3Fetch::new()
        .credentials("bob", "pw")
        .on_complete(Box::new(move |ok| {
            *done2.lock().unwrap() = Some(ok);
        }));

    Pop3Client::from_addr(addr)
        .timeouts(Pop3ClientTimeouts { stage: Duration::from_secs(5), ..Default::default() })
        .connect(&rt, Arc::new(fetch))
        .unwrap();

    assert!(wait_for(|| done.lock().unwrap().is_some(), 3000));
    assert!(done.lock().unwrap().unwrap_or(false), "empty maildrop should complete ok");
}

/// Hostname dial via `localhost` (hosts-file path) must not block the caller.
#[test]
fn client_localhost_hostname_dial() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, addr) = start_pop3_server_with_message(&dir);

    let done: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
    let done2 = Arc::clone(&done);
    let received: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let received2 = Arc::clone(&received);

    let fetch = Pop3Fetch::new()
        .credentials("alice", "secret")
        .prefer_apop(false)
        .on_message(Box::new(move |_id, _uid, bytes| {
            received2.lock().unwrap().push(bytes);
        }))
        .on_complete(Box::new(move |ok| {
            *done2.lock().unwrap() = Some(ok);
        }));

    let start = std::time::Instant::now();
    Pop3Client::new("localhost", addr.port())
        .timeouts(Pop3ClientTimeouts {
            stage: Duration::from_secs(5),
            ..Default::default()
        })
        .connect(&rt, Arc::new(fetch))
        .unwrap();
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "hostname connect must return immediately"
    );

    assert!(wait_for(|| done.lock().unwrap().is_some(), 5000));
    assert!(done.lock().unwrap().unwrap_or(false), "localhost dial should succeed");
    assert_eq!(received.lock().unwrap().len(), 1);
}

/// Explicit STLS upgrade against a TLS-capable Pop3Service.
#[test]
fn client_stls_fetch() {
    use hopf_tls::{acceptor_from_pem, connector};

    let dir = tempfile::tempdir().unwrap();
    let factory = Arc::new(MaildirFactory::new(dir.path()));
    {
        let mut store = factory.create_store();
        store.open("alice").unwrap();
        let mut mb = store.open_mailbox("INBOX", false).unwrap();
        mb.append_message(
            b"From: a@b\r\nSubject: stls\r\n\r\nstls-body\r\n",
            &BTreeSet::new(),
            None,
        )
        .unwrap();
        mb.close(false).unwrap();
        store.close().unwrap();
    }

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
    let acceptor = acceptor_from_pem(&cert_path, &key_path, &[]).unwrap();

    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let pass = Arc::new(PasswordStore::new().with_user("alice", "secret"));
    let config = Pop3Config::new("127.0.0.1:0".parse().unwrap(), "localhost", pass, factory)
        .with_tls(acceptor);
    let svc = Pop3Service::new(config, Arc::clone(&rt));
    let addr = svc.start().unwrap();

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let client_cfg = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let tls_connector = connector(client_cfg);

    let done: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
    let done2 = Arc::clone(&done);
    let received: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let received2 = Arc::clone(&received);

    let fetch = Pop3Fetch::new()
        .credentials("alice", "secret")
        .prefer_apop(false)
        .require_stls(true)
        .on_message(Box::new(move |_id, _uid, bytes| {
            received2.lock().unwrap().push(bytes);
        }))
        .on_complete(Box::new(move |ok| {
            *done2.lock().unwrap() = Some(ok);
        }));

    Pop3Client::from_addr(addr)
        .stls(tls_connector, "localhost")
        .timeouts(Pop3ClientTimeouts {
            stage: Duration::from_secs(5),
            ..Default::default()
        })
        .connect(&rt, Arc::new(fetch))
        .unwrap();

    assert!(wait_for(|| done.lock().unwrap().is_some(), 8000));
    assert!(done.lock().unwrap().unwrap_or(false), "STLS fetch should succeed");
    let msgs = received.lock().unwrap();
    assert_eq!(msgs.len(), 1);
    assert!(
        msgs[0]
            .windows(b"stls-body".len())
            .any(|w| w == b"stls-body"),
        "body={:?}",
        String::from_utf8_lossy(&msgs[0])
    );
}
