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
use hopf_imap::client::MessageReceiveCallback;
use hopf_imap::{ImapClient, ImapClientTimeouts, ImapFetch};

/// Prints each message's seq/uid and a preview of its first 512 bytes,
/// without ever buffering the whole message — just the bounded preview
/// window.
struct PreviewPrinter {
    msg_count: Arc<Mutex<usize>>,
    seq: u32,
    preview: Vec<u8>,
    total_len: usize,
}

impl MessageReceiveCallback for PreviewPrinter {
    fn start_message(&mut self, seq: u32) {
        self.seq = seq;
        self.preview.clear();
        self.total_len = 0;
    }

    fn message_content(&mut self, chunk: &[u8]) -> bool {
        self.total_len += chunk.len();
        if self.preview.len() < 512 {
            let take = (512 - self.preview.len()).min(chunk.len());
            self.preview.extend_from_slice(&chunk[..take]);
        }
        true
    }

    fn end_message(&mut self, uid: Option<u32>) {
        let count = {
            let mut c = self.msg_count.lock().unwrap();
            *c += 1;
            *c
        };
        let preview = String::from_utf8_lossy(&self.preview);
        println!(
            "── message {} (uid={uid:?}) [{} bytes, #{count}] ──",
            self.seq, self.total_len
        );
        println!("{preview}");
        if self.total_len > self.preview.len() {
            println!("... ({} bytes remaining)", self.total_len - self.preview.len());
        }
        println!();
    }
}

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
        .on_message(Box::new(PreviewPrinter {
            msg_count: msg_count2,
            seq: 0,
            preview: Vec::new(),
            total_len: 0,
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
