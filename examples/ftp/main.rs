// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! FTP server using stock [`FilesystemFtpHandler`].
//!
//! ```text
//! mkdir -p /tmp/ftp-root && cargo run -p ftp-server -- 127.0.0.1:2121 /tmp/ftp-root
//! ```

use std::env;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use hopf_auth::PasswordTrustPolicy;
use hopf_core::{Runtime, RuntimeConfig};
use hopf_ftp::{FtpConfig, FtpService};

fn main() -> io::Result<()> {
    let addr: SocketAddr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:2121".into())
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let root = PathBuf::from(env::args().nth(2).unwrap_or_else(|| "/tmp/ftp-root".into()));
    std::fs::create_dir_all(&root)?;

    let mut policy = PasswordTrustPolicy::default();
    policy = policy.with_user("ftp", "ftp");
    let policy = policy.shared();

    let config = FtpConfig::new(addr, root.clone(), policy);
    let service = FtpService::new(config);

    let rt = Arc::new(Runtime::start(RuntimeConfig::default())?);
    let bound = service.start(Arc::clone(&rt))?;

    eprintln!("ftp on ftp://{bound}/  root={root:?}  user=ftp pass=ftp");
    eprintln!("press Enter to stop");
    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);
    // Runtime is shared via Arc for PASV; process exit tears down threads.
    drop(rt);
    Ok(())
}
