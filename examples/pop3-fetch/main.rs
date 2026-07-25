// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! POP3 fetch example.
//!
//! ```text
//! # Against a local server (e.g. pop3 example):
//! cargo run -p pop3-fetch -- 127.0.0.1 1110 alice secret
//!
//! # Against a real server (plain-text POP3, port 110):
//! cargo run -p pop3-fetch -- pop3.example.com 110 user pass
//! ```
//!
//! Messages are printed to stdout (truncated to 512 bytes each).

use std::env;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_core::{Runtime, RuntimeConfig};
use hopf_pop3::{Pop3Client, Pop3ClientTimeouts, Pop3Fetch};

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 5 {
        eprintln!("usage: pop3-fetch <host> <port> <user> <pass> [--delete]");
        eprintln!("  --delete  delete messages from the server after fetching");
        return Ok(());
    }

    let host = args[1].clone();
    let port: u16 = args[2]
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let user = args[3].clone();
    let pass = args[4].clone();
    let delete = args.get(5).map(|s| s == "--delete").unwrap_or(false);

    let rt = Arc::new(Runtime::start(RuntimeConfig::default())?);
    let done: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
    let done2 = Arc::clone(&done);
    let msg_count = Arc::new(Mutex::new(0usize));
    let msg_count2 = Arc::clone(&msg_count);

    let fetch = Pop3Fetch::new()
        .credentials(user, pass)
        .delete_after_fetch(delete)
        .on_message(Box::new(move |id, uid, bytes| {
            let count = {
                let mut c = msg_count2.lock().unwrap();
                *c += 1;
                *c
            };
            let preview_len = bytes.len().min(512);
            let preview = String::from_utf8_lossy(&bytes[..preview_len]);
            println!(
                "── message {id} (uid={uid:?}) [{} bytes, #{count}] ──",
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

    let user_display = args[3].clone();
    eprintln!("connecting to {host}:{port} as {user_display} ...");

    Pop3Client::new(host, port)
        .timeouts(Pop3ClientTimeouts {
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
            if delete {
                eprintln!("messages deleted from server");
            }
        }
        Some(false) => {
            eprintln!("fetch failed");
            return Err(io::Error::new(io::ErrorKind::Other, "POP3 fetch failed"));
        }
        None => {
            eprintln!("timeout — no response within 30 s");
            return Err(io::Error::new(io::ErrorKind::TimedOut, "POP3 fetch timed out"));
        }
    }

    Ok(())
}
