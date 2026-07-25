// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! IMAP fetch example (async client, auto-pilot pipeline).
//!
//! ```text
//! # Against a local server (e.g. the imap example):
//! cargo run -p imap-fetch -- 127.0.0.1 1143 alice secret
//!
//! # Against a real server (plain-text IMAP, port 143):
//! cargo run -p imap-fetch -- imap.example.com 143 user pass
//!
//! # Select a different mailbox / sequence set:
//! cargo run -p imap-fetch -- 127.0.0.1 1143 alice secret Archive 1:5
//! ```
//!
//! Messages are printed to stdout (truncated to 512 bytes each).

use std::env;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_core::{Runtime, RuntimeConfig};
use hopf_imap::{ImapClient, ImapClientTimeouts, ImapFetch};

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 5 {
        eprintln!("usage: imap-fetch <host> <port> <user> <pass> [mailbox] [sequence-set]");
        eprintln!("  mailbox       mailbox to SELECT (default INBOX)");
        eprintln!("  sequence-set  FETCH sequence set (default 1:*)");
        return Ok(());
    }

    let host = args[1].clone();
    let port: u16 = args[2]
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let user = args[3].clone();
    let pass = args[4].clone();
    let mailbox = args.get(5).cloned().unwrap_or_else(|| "INBOX".into());
    let sequence = args.get(6).cloned().unwrap_or_else(|| "1:*".into());

    let rt = Arc::new(Runtime::start(RuntimeConfig::default())?);
    let done: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
    let done2 = Arc::clone(&done);
    let msg_count = Arc::new(Mutex::new(0usize));
    let msg_count2 = Arc::clone(&msg_count);

    let fetch = ImapFetch::new()
        .credentials(user.clone(), pass)
        .mailbox(mailbox.clone())
        .sequence_set(sequence)
        .on_message(Box::new(move |seq, uid, bytes| {
            let count = {
                let mut c = msg_count2.lock().unwrap();
                *c += 1;
                *c
            };
            let preview_len = bytes.len().min(512);
            let preview = String::from_utf8_lossy(&bytes[..preview_len]);
            println!(
                "── message {seq} (uid={uid:?}) [{} bytes, #{count}] ──",
                bytes.len()
            );
            println!("{preview}");
            if bytes.len() > 512 {
                println!("... ({} bytes remaining)", bytes.len() - 512);
            }
            println!();
        }))
        .on_complete(Box::new(move |ok| {
            *done2.lock().unwrap() = Some(ok);
        }));

    eprintln!("connecting to {host}:{port} as {user}, mailbox {mailbox} ...");

    ImapClient::new(host, port)
        .timeouts(ImapClientTimeouts {
            dns: Duration::from_secs(5),
            connect: Duration::from_secs(10),
            stage: Duration::from_secs(30),
            message: Duration::from_secs(300),
        })
        .connect(&rt, Arc::new(fetch))?;

    // Spin-wait for completion (up to 30 s).
    for _ in 0..3000 {
        if done.lock().unwrap().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    let result = done.lock().unwrap();
    let count = *msg_count.lock().unwrap();

    match *result {
        Some(true) => {
            eprintln!("fetch complete — {count} message(s) received");
        }
        Some(false) => {
            eprintln!("fetch failed");
            return Err(io::Error::new(io::ErrorKind::Other, "IMAP fetch failed"));
        }
        None => {
            eprintln!("timeout — no response within 30 s");
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "IMAP fetch timed out",
            ));
        }
    }

    Ok(())
}
