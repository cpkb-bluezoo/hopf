// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Blocking FTP client example — twin of `ftp-server`.
//!
//! ```text
//! cargo run -p ftp-server -- 127.0.0.1:2121 /tmp/ftp-root
//! cargo run -p ftp-get -- 127.0.0.1:2121 /hello.txt
//! ```

use std::env;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::time::Duration;

use hopf_ftp::FtpClientBuilder;

fn main() -> io::Result<()> {
    let addr: SocketAddr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:2121".into())
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let remote = env::args().nth(2).unwrap_or_else(|| "/".into());
    let user = env::var("FTP_USER").unwrap_or_else(|_| "ftp".into());
    let pass = env::var("FTP_PASS").unwrap_or_else(|_| "ftp".into());

    let mut client = FtpClientBuilder::new()
        .timeout(Duration::from_secs(10))
        .connect(addr)
        .map_err(to_io)?;
    client.login(&user, &pass).map_err(to_io)?;
    client.type_image().map_err(to_io)?;

    if remote.ends_with('/') || remote.is_empty() {
        let listing = client.list(Some(remote.trim_end_matches('/')).filter(|s| !s.is_empty())).map_err(to_io)?;
        io::stdout().write_all(&listing)?;
    } else {
        let body = client.retr(&remote).map_err(to_io)?;
        io::stdout().write_all(&body)?;
    }
    let _ = client.quit();
    Ok(())
}

fn to_io(e: hopf_ftp::FtpError) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e.to_string())
}
