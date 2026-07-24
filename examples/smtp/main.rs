// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SMTP server using stock [`AcceptAllSmtpHandler`].
//!
//! ```text
//! cargo run -p smtp-server -- 127.0.0.1:2525
//! ```

use std::env;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use hopf_core::{Runtime, RuntimeConfig};
use hopf_smtp::{SmtpConfig, SmtpService};

fn main() -> io::Result<()> {
    let addr: SocketAddr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:2525".into())
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let hostname = env::args()
        .nth(2)
        .unwrap_or_else(|| "localhost".into());

    let config = SmtpConfig::new(addr, hostname.clone());
    let service = SmtpService::new(config);

    let rt = Arc::new(Runtime::start(RuntimeConfig::default())?);
    let bound = service.start(Arc::clone(&rt))?;

    eprintln!("smtp on smtp://{bound}/  hostname={hostname}  (accept-all)");
    eprintln!("press Enter to stop");
    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);
    drop(rt);
    Ok(())
}
