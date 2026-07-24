// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Local-delivery SMTP → Maildir++ (Gumdrop `LocalDeliveryService` shape).
//!
//! ```text
//! cargo run -p smtp-local -- 127.0.0.1:2525 localhost example.com ./mail
//! ```

use std::env;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use hopf_core::{Runtime, RuntimeConfig};
use hopf_mailbox::MaildirFactory;
use hopf_smtp::{LocalDeliveryService, SmtpConfig};

fn main() -> io::Result<()> {
    let addr: SocketAddr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:2525".into())
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let hostname = env::args().nth(2).unwrap_or_else(|| "localhost".into());
    let local_domain = env::args().nth(3).unwrap_or_else(|| "localhost".into());
    let mail_root = PathBuf::from(env::args().nth(4).unwrap_or_else(|| "./mail".into()));

    std::fs::create_dir_all(&mail_root)?;

    let rt = Arc::new(Runtime::start(RuntimeConfig::default())?);
    let factory = Arc::new(MaildirFactory::new(&mail_root));
    let config = SmtpConfig::new(addr, hostname.clone());
    let svc = LocalDeliveryService::new(config, Arc::clone(&rt), factory, local_domain.clone());
    let bound = svc.start(Arc::clone(&rt))?;

    eprintln!(
        "smtp-local on smtp://{bound}/  hostname={hostname}  domain={local_domain}  maildir={}",
        mail_root.display()
    );
    eprintln!("RCPT must be user@{local_domain}  (APPENDs to {{maildir}}/{{user}}/)");
    eprintln!("press Enter to stop");
    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);
    drop(rt);
    Ok(())
}
