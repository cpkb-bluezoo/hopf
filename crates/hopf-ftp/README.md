# hopf-ftp

FTP / FTPS **server** and callback-driven **client** for Hopf — Gumdrop
`org.bluezoo.gumdrop.ftp` port.

## Server

Control and data connections, PASV via dynamic `Runtime` listeners, stock
`FilesystemFtpHandler` (chrooted root + storage API), and TrustPolicy auth.

## Async client

- `FtpClient` — builder + `connect(&Arc<Runtime>, pipeline)`; returns immediately
- `FtpClientTimeouts` — `dns` / `connect` / `stage` / `data`
- `FtpGet` / `FtpPut` — stock `FtpPipeline`s (TYPE I → data setup → RETR/STOR → QUIT)
- Data channel: passive `PASV`/`EPSV` (default) or active `PORT`/`EPRT` via `FtpClient::active_mode`
- FTPS: `FtpClient::auth_tls` (explicit `AUTH TLS` + `PBSZ`/`PROT P`) or `FtpClient::implicit_tls` (TLS from dial); active-mode PROT P also needs `data_tls_acceptor`
- Custom workflows implement `FtpPipeline` and issue ops via `FtpSessionWrite`

```rust
use std::sync::Arc;
use hopf_core::{Runtime, RuntimeConfig};
use hopf_ftp::{FtpClient, FtpGet};

let rt = Arc::new(Runtime::start(RuntimeConfig::default())?);
let pipeline = FtpGet::new("/readme.txt", |r| match r {
    Ok(bytes) => eprintln!("got {} bytes", bytes.len()),
    Err(e) => eprintln!("RETR failed: {e}"),
});
FtpClient::new("127.0.0.1")
    .port(2121)
    .credentials("ftp", "ftp")
    .connect(&rt, Box::new(pipeline))?;
```

RFC 2640 `OPTS UTF8 ON` is wired for inbound pathnames and outbound
replies / listings (ASCII substitution when UTF-8 is off).
