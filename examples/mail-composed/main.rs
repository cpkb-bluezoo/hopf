// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SMTP local delivery + POP3 + IMAP composed in **one process**, sharing
//! one Maildir++ root and one credential store (see docs/composition.html).
//!
//! Only possible through `Composition` because all three services need
//! `Arc<Runtime>` at construction time (storage-pool offload for mailbox
//! I/O) — see `Composition::runtime()`. That also means they can't be named
//! in composition XML (registry factories are resolved before the Runtime
//! exists); this example uses the Rust builder instead.
//!
//! ```text
//! cargo run -p mail-composed -- 127.0.0.1:2525 127.0.0.1:1110 127.0.0.1:1143 localhost example.com ./mail
//! ```
//!
//! Default credentials: `alice` / `secret`. RCPT must be `user@<local_domain>`.

use std::env;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use hopf_auth::PasswordStore;
use hopf_core::{Composition, RuntimeConfig};
use hopf_imap::{ImapConfig, ImapService};
use hopf_mailbox::MaildirFactory;
use hopf_pop3::{Pop3Config, Pop3Service};
use hopf_smtp::{LocalDeliveryService, SmtpConfig};

fn parse_addr(s: String) -> io::Result<SocketAddr> {
    s.parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

fn main() -> io::Result<()> {
    let mut args = env::args().skip(1);
    let smtp_addr = parse_addr(args.next().unwrap_or_else(|| "127.0.0.1:2525".into()))?;
    let pop3_addr = parse_addr(args.next().unwrap_or_else(|| "127.0.0.1:1110".into()))?;
    let imap_addr = parse_addr(args.next().unwrap_or_else(|| "127.0.0.1:1143".into()))?;
    let hostname = args.next().unwrap_or_else(|| "localhost".into());
    let local_domain = args.next().unwrap_or_else(|| "localhost".into());
    let mail_root = PathBuf::from(args.next().unwrap_or_else(|| "./mail".into()));

    std::fs::create_dir_all(&mail_root)?;

    let mut comp = Composition::new(RuntimeConfig::default())?;
    let rt = Arc::clone(comp.runtime());

    let mailbox_factory = Arc::new(MaildirFactory::new(&mail_root));
    let credentials = Arc::new(PasswordStore::new().with_user("alice", "secret"));

    let smtp = LocalDeliveryService::new(
        SmtpConfig::new(smtp_addr, hostname.clone())
            .with_store(credentials.clone())
            .auth_required(true),
        Arc::clone(&rt),
        mailbox_factory.clone(),
        local_domain.clone(),
    );
    comp.listen_tcp(smtp.smtp().control_listener(Arc::clone(&rt)))?;

    let pop3 = Pop3Service::new(
        Pop3Config::new(pop3_addr, hostname.clone(), credentials.clone(), mailbox_factory.clone()),
        Arc::clone(&rt),
    );
    comp.listen_tcp(pop3.control_listener())?;

    let imap = ImapService::new(
        ImapConfig::new(imap_addr, hostname.clone(), credentials.clone(), mailbox_factory.clone()),
        Arc::clone(&rt),
    );
    comp.listen_tcp(imap.control_listener())?;

    eprintln!(
        "mail-composed: one process, one Runtime, one maildir at {}",
        mail_root.display()
    );
    eprintln!(
        "  smtp (local delivery) on smtp://{}/  RCPT must be user@{local_domain}",
        comp.listen_addrs[0]
    );
    eprintln!(
        "  pop3 on pop3://{}/  user=alice pass=secret",
        comp.listen_addrs[1]
    );
    eprintln!(
        "  imap on imap://{}/  user=alice pass=secret",
        comp.listen_addrs[2]
    );
    eprintln!("press Enter to stop");

    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);
    comp.shutdown();
    Ok(())
}
