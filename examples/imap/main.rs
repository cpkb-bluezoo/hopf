// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! IMAP server demo with Maildir++ storage.
//!
//! ```text
//! cargo run -p imap -- 127.0.0.1:1143 localhost ./mail
//! ```
//!
//! Default credentials: `alice` / `secret`.
//!
//! Try it with any IMAP client, or interactively:
//!
//! ```text
//! $ nc 127.0.0.1 1143
//! * OK [CAPABILITY ...] localhost IMAP4rev2 server ready
//! a1 LOGIN alice secret
//! a2 SELECT INBOX
//! a3 FETCH 1:* (FLAGS RFC822.SIZE)
//! a4 LOGOUT
//! ```

use std::env;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use hopf_auth::PasswordStore;
use hopf_core::{Runtime, RuntimeConfig};
use hopf_imap::{ImapConfig, ImapService};
use hopf_mailbox::MaildirFactory;

fn main() -> io::Result<()> {
    let addr: SocketAddr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:1143".into())
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let hostname = env::args().nth(2).unwrap_or_else(|| "localhost".into());
    let mail_root = PathBuf::from(env::args().nth(3).unwrap_or_else(|| "./mail".into()));

    std::fs::create_dir_all(&mail_root)?;

    let rt = Arc::new(Runtime::start(RuntimeConfig::default())?);
    let factory = Arc::new(MaildirFactory::new(&mail_root));
    let store = Arc::new(PasswordStore::new().with_user("alice", "secret"));
    let config = ImapConfig::new(addr, hostname.clone(), store, factory);
    let svc = ImapService::new(config, Arc::clone(&rt));
    let bound = svc.start()?;

    eprintln!(
        "imap on imap://{bound}/  hostname={hostname}  maildir={}  user=alice pass=secret",
        mail_root.display()
    );
    eprintln!("press Enter to stop");
    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);
    drop(rt);
    Ok(())
}
