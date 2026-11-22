// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! NNTP news reader server demo: the mailboxes of a Maildir++ spool, served as
//! newsgroups. The group `misc.test` is made, with one article in it, if the
//! spool has none.
//!
//! ```text
//! cargo run -p nntp -- 127.0.0.1:1119 localhost ./news
//! ```
//!
//! Default credentials: `alice` / `secret`. Give a certificate chain and a key
//! (PEM files) as the fourth and fifth arguments to offer STARTTLS, and the
//! server then takes passwords only on an encrypted connection; without them it
//! accepts passwords in the clear, which a real server should not do.
//!
//! ```text
//! cargo run -p nntp -- 127.0.0.1:1119 localhost ./news cert.pem key.pem
//! ```

use std::collections::BTreeSet;
use std::env;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use hopf_auth::PasswordStore;
use hopf_core::{acceptor_from_pem, Runtime, RuntimeConfig};
use hopf_mailbox::{AppendGuard, MailboxFactory, MaildirFactory};
use hopf_nntp::{NntpConfig, NntpService, DEFAULT_STORE_USER};

fn main() -> io::Result<()> {
    let addr: SocketAddr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:1119".into())
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let hostname = env::args().nth(2).unwrap_or_else(|| "localhost".into());
    let root = PathBuf::from(env::args().nth(3).unwrap_or_else(|| "./news".into()));
    std::fs::create_dir_all(&root)?;

    let spool = Arc::new(MaildirFactory::new(&root));
    seed(&spool).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let rt = Arc::new(Runtime::start(RuntimeConfig::default())?);
    let credentials = Arc::new(PasswordStore::new().with_user("alice", "secret"));
    let mut config = NntpConfig::new(addr, hostname.clone()).with_credentials(credentials);
    match (env::args().nth(4), env::args().nth(5)) {
        (Some(cert), Some(key)) => config = config.with_tls(acceptor_from_pem(std::path::Path::new(&cert), std::path::Path::new(&key), &[])?),
        _ => config = config.allow_cleartext_auth(),
    }
    let service = NntpService::new(config, Arc::clone(&rt), spool);
    let bound = service.start()?;

    eprintln!(
        "nntp on nntp://{bound}/  hostname={hostname}  spool={}  user=alice pass=secret",
        root.display()
    );
    eprintln!("press Enter to stop");
    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);
    service.stop();
    drop(rt);
    Ok(())
}

/// Makes `misc.test`, with a welcome article, unless the spool has it.
fn seed(spool: &Arc<MaildirFactory>) -> hopf_mailbox::MailboxResult<()> {
    let mut store = spool.create_store();
    store.open(DEFAULT_STORE_USER)?;
    if store.open_mailbox("misc/test", true).is_ok() {
        return store.close();
    }
    store.create_mailbox("misc/test")?;
    let mut group = store.open_mailbox("misc/test", false)?;
    let mut guard = AppendGuard::start(group.as_mut(), &BTreeSet::new(), None)?;
    guard.append_content(
        b"From: news@localhost\r\nNewsgroups: misc.test\r\nSubject: Welcome\r\nMessage-ID: <welcome@localhost>\r\n\r\nThis is a test group.\r\n",
    )?;
    guard.commit()?;
    group.close(false)?;
    store.close()
}
