// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Blocking FTP / FTPS client.

mod error;
mod reply;
mod stream;

pub use error::{FtpError, FtpResult};
pub use reply::FtpReply;

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rustls::ClientConfig;

use crate::ascii::normalize_ascii_newlines;
use crate::client::stream::FtpStream;
use crate::session::TransferType;

use reply::{parse_epsv_port, parse_pasv_addr, read_reply};

/// How the client opens the data connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FtpDataMode {
    /// Client dials after `PASV` / `EPSV` (default).
    #[default]
    Passive,
    /// Server dials after `PORT` / `EPRT`.
    Active,
}

/// Builder for [`FtpClient`].
#[derive(Clone)]
pub struct FtpClientBuilder {
    timeout: Duration,
    data_mode: FtpDataMode,
    prefer_epsv: bool,
    tls: Option<Arc<ClientConfig>>,
    server_name: Option<String>,
    implicit_tls: bool,
}

impl Default for FtpClientBuilder {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            data_mode: FtpDataMode::Passive,
            prefer_epsv: true,
            tls: None,
            server_name: None,
            implicit_tls: false,
        }
    }
}

impl FtpClientBuilder {
    /// Create a builder with defaults (30s timeout, passive, prefer EPSV).
    pub fn new() -> Self {
        Self::default()
    }

    /// I/O timeout applied to control and data sockets.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Passive (default) or active data mode.
    pub fn data_mode(mut self, mode: FtpDataMode) -> Self {
        self.data_mode = mode;
        self
    }

    /// Prefer `EPSV` over `PASV` when the control peer is IPv4/IPv6 (default true).
    pub fn prefer_epsv(mut self, prefer: bool) -> Self {
        self.prefer_epsv = prefer;
        self
    }

    /// Trust roots / client identity for FTPS (implicit or `AUTH TLS`).
    pub fn tls(mut self, config: Arc<ClientConfig>, server_name: impl Into<String>) -> Self {
        self.tls = Some(config);
        self.server_name = Some(server_name.into());
        self
    }

    /// Dial with TLS from the first byte (implicit FTPS, typically port 990).
    pub fn implicit_tls(mut self, yes: bool) -> Self {
        self.implicit_tls = yes;
        self
    }

    /// Connect and read the welcome `220`.
    pub fn connect(self, addr: SocketAddr) -> FtpResult<FtpClient> {
        let mut stream = if self.implicit_tls {
            let tls = self.tls.as_ref().ok_or_else(|| {
                FtpError::Config("implicit FTPS requires FtpClientBuilder::tls".into())
            })?;
            let name = self.server_name.as_deref().unwrap_or("localhost");
            FtpStream::connect_tls(addr, Arc::clone(tls), name, self.timeout)?
        } else {
            FtpStream::connect_plain(addr, self.timeout)?
        };
        let welcome = read_reply(&mut stream)?;
        if welcome.code != 220 {
            return Err(FtpError::unexpected(Some(220), welcome));
        }
        Ok(FtpClient {
            stream,
            peer: addr,
            timeout: self.timeout,
            data_mode: self.data_mode,
            prefer_epsv: self.prefer_epsv,
            transfer_type: TransferType::Image,
            protected_data: false,
            tls: self.tls,
            server_name: self.server_name,
            welcome,
        })
    }
}

/// Blocking FTP control session.
pub struct FtpClient {
    stream: FtpStream,
    peer: SocketAddr,
    timeout: Duration,
    data_mode: FtpDataMode,
    prefer_epsv: bool,
    transfer_type: TransferType,
    protected_data: bool,
    tls: Option<Arc<ClientConfig>>,
    server_name: Option<String>,
    welcome: FtpReply,
}

impl FtpClient {
    /// Connect with default builder settings (cleartext).
    pub fn connect(addr: SocketAddr) -> FtpResult<Self> {
        FtpClientBuilder::new().connect(addr)
    }

    /// Welcome reply from the server (`220`).
    pub fn welcome(&self) -> &FtpReply {
        &self.welcome
    }

    /// Control peer address.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// Send a raw command and read one (possibly multiline) reply.
    pub fn command(&mut self, verb: &str, arg: Option<&str>) -> FtpResult<FtpReply> {
        let line = match arg {
            Some(a) if !a.is_empty() => format!("{verb} {a}\r\n"),
            _ => format!("{verb}\r\n"),
        };
        self.stream.write_all(line.as_bytes())?;
        self.stream.flush()?;
        read_reply(&mut self.stream)
    }

    /// Expect a reply whose code equals `code`.
    pub fn expect(&mut self, verb: &str, arg: Option<&str>, code: u16) -> FtpResult<FtpReply> {
        let r = self.command(verb, arg)?;
        if r.code != code {
            return Err(FtpError::unexpected(Some(code), r));
        }
        Ok(r)
    }

    /// `USER` / `PASS` (and optional `ACCT`).
    pub fn login(&mut self, user: &str, pass: &str) -> FtpResult<()> {
        self.login_acct(user, pass, None)
    }

    /// Login with optional account.
    pub fn login_acct(&mut self, user: &str, pass: &str, acct: Option<&str>) -> FtpResult<()> {
        let r = self.command("USER", Some(user))?;
        match r.code {
            230 => return Ok(()),
            331 => {}
            _ => return Err(FtpError::unexpected(Some(331), r)),
        }
        let r = self.command("PASS", Some(pass))?;
        match r.code {
            230 => Ok(()),
            332 => {
                let acct = acct.ok_or_else(|| FtpError::Protocol {
                    expected: Some(230),
                    reply: r,
                })?;
                self.expect("ACCT", Some(acct), 230)?;
                Ok(())
            }
            _ => Err(FtpError::unexpected(Some(230), r)),
        }
    }

    /// Explicit FTPS: `AUTH TLS` then rustls handshake, then `PBSZ 0` / `PROT P`.
    pub fn auth_tls(&mut self) -> FtpResult<()> {
        let tls = self
            .tls
            .as_ref()
            .map(Arc::clone)
            .ok_or_else(|| FtpError::Config("AUTH TLS requires FtpClientBuilder::tls".into()))?;
        let name = self
            .server_name
            .clone()
            .unwrap_or_else(|| "localhost".into());
        let r = self.command("AUTH", Some("TLS"))?;
        if r.code != 234 && r.code != 334 {
            return Err(FtpError::unexpected(Some(234), r));
        }
        self.stream.upgrade_tls(tls, &name)?;
        self.protect_data()?;
        Ok(())
    }

    /// `PBSZ 0` + `PROT P` (data channel TLS). Requires [`FtpClientBuilder::tls`].
    pub fn protect_data(&mut self) -> FtpResult<()> {
        if self.tls.is_none() {
            return Err(FtpError::Config(
                "PROT P requires FtpClientBuilder::tls".into(),
            ));
        }
        self.expect("PBSZ", Some("0"), 200)?;
        self.expect("PROT", Some("P"), 200)?;
        self.protected_data = true;
        Ok(())
    }

    /// `OPTS UTF8 ON` / `OFF` (RFC 2640).
    pub fn opts_utf8(&mut self, on: bool) -> FtpResult<()> {
        if on {
            self.expect("OPTS", Some("UTF8 ON"), 200)?;
        } else {
            self.expect("OPTS", Some("UTF8 OFF"), 200)?;
        }
        Ok(())
    }

    /// `PROT C` — clear data (after PBSZ if needed).
    pub fn clear_data_protection(&mut self) -> FtpResult<()> {
        let _ = self.command("PBSZ", Some("0"))?;
        self.expect("PROT", Some("C"), 200)?;
        self.protected_data = false;
        Ok(())
    }

    /// `TYPE I`.
    pub fn type_image(&mut self) -> FtpResult<()> {
        self.expect("TYPE", Some("I"), 200)?;
        self.transfer_type = TransferType::Image;
        Ok(())
    }

    /// `TYPE A`.
    pub fn type_ascii(&mut self) -> FtpResult<()> {
        self.expect("TYPE", Some("A"), 200)?;
        self.transfer_type = TransferType::Ascii;
        Ok(())
    }

    /// `CWD`.
    pub fn cwd(&mut self, path: &str) -> FtpResult<()> {
        self.expect("CWD", Some(path), 250)?;
        Ok(())
    }

    /// `CDUP`.
    pub fn cdup(&mut self) -> FtpResult<()> {
        self.expect("CDUP", None, 250)?;
        Ok(())
    }

    /// `PWD` — returns the path text from the 257 reply when parseable.
    pub fn pwd(&mut self) -> FtpResult<String> {
        let r = self.expect("PWD", None, 257)?;
        Ok(parse_pwd_path(&r.text()).unwrap_or_else(|| r.text().to_string()))
    }

    /// `MKD`.
    pub fn mkdir(&mut self, path: &str) -> FtpResult<()> {
        let r = self.command("MKD", Some(path))?;
        if r.code != 257 && r.code != 250 {
            return Err(FtpError::unexpected(Some(257), r));
        }
        Ok(())
    }

    /// `RMD`.
    pub fn rmdir(&mut self, path: &str) -> FtpResult<()> {
        self.expect("RMD", Some(path), 250)?;
        Ok(())
    }

    /// `DELE`.
    pub fn delete(&mut self, path: &str) -> FtpResult<()> {
        self.expect("DELE", Some(path), 250)?;
        Ok(())
    }

    /// `RNFR` / `RNTO`.
    pub fn rename(&mut self, from: &str, to: &str) -> FtpResult<()> {
        self.expect("RNFR", Some(from), 350)?;
        self.expect("RNTO", Some(to), 250)?;
        Ok(())
    }

    /// `SIZE`.
    pub fn size(&mut self, path: &str) -> FtpResult<u64> {
        let r = self.expect("SIZE", Some(path), 213)?;
        r.text()
            .trim()
            .parse()
            .map_err(|_| FtpError::Parse(format!("SIZE: {}", r.text())))
    }

    /// `MDTM`.
    pub fn mdtm(&mut self, path: &str) -> FtpResult<String> {
        let r = self.expect("MDTM", Some(path), 213)?;
        Ok(r.text().trim().to_string())
    }

    /// `NOOP`.
    pub fn noop(&mut self) -> FtpResult<()> {
        self.expect("NOOP", None, 200)?;
        Ok(())
    }

    /// `FEAT` multiline body lines (without the wrapping 211 codes).
    pub fn feat(&mut self) -> FtpResult<Vec<String>> {
        let r = self.command("FEAT", None)?;
        if r.code != 211 {
            return Err(FtpError::unexpected(Some(211), r));
        }
        Ok(r.lines.clone())
    }

    /// `SYST`.
    pub fn syst(&mut self) -> FtpResult<String> {
        let r = self.expect("SYST", None, 215)?;
        Ok(r.text().to_string())
    }

    /// `REST` restart marker.
    pub fn rest(&mut self, offset: u64) -> FtpResult<()> {
        self.expect("REST", Some(&offset.to_string()), 350)?;
        Ok(())
    }

    /// `LIST` → listing bytes.
    pub fn list(&mut self, path: Option<&str>) -> FtpResult<Vec<u8>> {
        self.data_retrieve("LIST", path)
    }

    /// `NLST`.
    pub fn nlst(&mut self, path: Option<&str>) -> FtpResult<Vec<u8>> {
        self.data_retrieve("NLST", path)
    }

    /// `MLSD`.
    pub fn mlsd(&mut self, path: Option<&str>) -> FtpResult<Vec<u8>> {
        self.data_retrieve("MLSD", path)
    }

    /// `RETR` path into a buffer.
    pub fn retr(&mut self, path: &str) -> FtpResult<Vec<u8>> {
        let mut buf = self.data_retrieve("RETR", Some(path))?;
        if self.transfer_type == TransferType::Ascii {
            buf = normalize_ascii_newlines(&buf);
        }
        Ok(buf)
    }

    /// `RETR` into a writer.
    pub fn retr_to<W: Write>(&mut self, path: &str, mut out: W) -> FtpResult<u64> {
        let data = self.retr(path)?;
        out.write_all(&data)?;
        Ok(data.len() as u64)
    }

    /// `STOR` from a buffer.
    pub fn stor(&mut self, path: &str, body: &[u8]) -> FtpResult<()> {
        let payload = if self.transfer_type == TransferType::Ascii {
            normalize_ascii_newlines(body)
        } else {
            body.to_vec()
        };
        self.data_store("STOR", path, &payload)
    }

    /// `STOR` from a reader (loads into memory for the transfer).
    pub fn stor_from<R: Read>(&mut self, path: &str, mut reader: R) -> FtpResult<u64> {
        let mut body = Vec::new();
        reader.read_to_end(&mut body)?;
        let n = body.len() as u64;
        self.stor(path, &body)?;
        Ok(n)
    }

    /// `APPE`.
    pub fn appe(&mut self, path: &str, body: &[u8]) -> FtpResult<()> {
        let payload = if self.transfer_type == TransferType::Ascii {
            normalize_ascii_newlines(body)
        } else {
            body.to_vec()
        };
        self.data_store("APPE", path, &payload)
    }

    /// Write a local file with `STOR`.
    pub fn upload_file(&mut self, remote: &str, local: impl AsRef<Path>) -> FtpResult<u64> {
        let body = std::fs::read(local.as_ref())?;
        let n = body.len() as u64;
        self.stor(remote, &body)?;
        Ok(n)
    }

    /// Download to a local file with `RETR`.
    pub fn download_file(&mut self, remote: &str, local: impl AsRef<Path>) -> FtpResult<u64> {
        let data = self.retr(remote)?;
        std::fs::write(local.as_ref(), &data)?;
        Ok(data.len() as u64)
    }

    /// `ABOR`.
    pub fn abort(&mut self) -> FtpResult<FtpReply> {
        self.command("ABOR", None)
    }

    /// `QUIT` and close the control connection.
    pub fn quit(mut self) -> FtpResult<()> {
        let _ = self.command("QUIT", None);
        self.stream.shutdown();
        Ok(())
    }

    fn data_retrieve(&mut self, verb: &str, arg: Option<&str>) -> FtpResult<Vec<u8>> {
        let pending = self.setup_data()?;
        self.write_command(verb, arg)?;
        // Active: accept before reading 150 so the server's dial can complete.
        let mut data = pending.complete(self)?;
        let r = read_reply(&mut self.stream)?;
        if r.code != 150 && r.code != 125 {
            return Err(FtpError::unexpected(Some(150), r));
        }
        let buf = read_data_to_end(&mut data)?;
        drop(data);
        let done = read_reply(&mut self.stream)?;
        if done.code != 226 && done.code != 250 {
            return Err(FtpError::unexpected(Some(226), done));
        }
        Ok(buf)
    }

    fn data_store(&mut self, verb: &str, path: &str, body: &[u8]) -> FtpResult<()> {
        let pending = self.setup_data()?;
        self.write_command(verb, Some(path))?;
        let mut data = pending.complete(self)?;
        let r = read_reply(&mut self.stream)?;
        if r.code != 150 && r.code != 125 {
            return Err(FtpError::unexpected(Some(150), r));
        }
        data.write_all(body)?;
        data.flush()?;
        // Half-close write so the server sees EOF even under TLS.
        data.shutdown_write();
        drop(data);
        let done = read_reply(&mut self.stream)?;
        if done.code != 226 && done.code != 250 {
            return Err(FtpError::unexpected(Some(226), done));
        }
        Ok(())
    }

    fn write_command(&mut self, verb: &str, arg: Option<&str>) -> FtpResult<()> {
        let line = match arg {
            Some(a) if !a.is_empty() => format!("{verb} {a}\r\n"),
            _ => format!("{verb}\r\n"),
        };
        self.stream.write_all(line.as_bytes())?;
        self.stream.flush()?;
        Ok(())
    }

    fn setup_data(&mut self) -> FtpResult<PendingData> {
        match self.data_mode {
            FtpDataMode::Passive => Ok(PendingData::Ready(self.open_passive()?)),
            FtpDataMode::Active => self.begin_active(),
        }
    }

    fn open_passive(&mut self) -> FtpResult<FtpStream> {
        let addr = if self.prefer_epsv {
            match self.try_epsv() {
                Ok(a) => a,
                Err(_) => self.pasv()?,
            }
        } else {
            self.pasv()?
        };
        self.connect_data(addr)
    }

    fn try_epsv(&mut self) -> FtpResult<SocketAddr> {
        let r = self.command("EPSV", None)?;
        if r.code != 229 {
            return Err(FtpError::unexpected(Some(229), r));
        }
        let port = parse_epsv_port(&r.text())?;
        Ok(SocketAddr::new(self.peer.ip(), port))
    }

    fn pasv(&mut self) -> FtpResult<SocketAddr> {
        let r = self.command("PASV", None)?;
        if r.code != 227 {
            return Err(FtpError::unexpected(Some(227), r));
        }
        parse_pasv_addr(&r.text())
    }

    fn begin_active(&mut self) -> FtpResult<PendingData> {
        let bind_ip = match self.stream.local_addr()?.ip() {
            IpAddr::V4(v) => IpAddr::V4(v),
            IpAddr::V6(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
        };
        let listener = TcpListener::bind(SocketAddr::new(bind_ip, 0))?;
        let local = listener.local_addr()?;
        match local.ip() {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                let p1 = local.port() / 256;
                let p2 = local.port() % 256;
                let arg = format!("{},{},{},{},{},{}", o[0], o[1], o[2], o[3], p1, p2);
                self.expect("PORT", Some(&arg), 200)?;
            }
            IpAddr::V6(v6) => {
                let arg = format!("|2|{}|{}|", v6, local.port());
                self.expect("EPRT", Some(&arg), 200)?;
            }
        }
        Ok(PendingData::Listening(listener))
    }

    fn connect_data(&self, addr: SocketAddr) -> FtpResult<FtpStream> {
        let sock = TcpStream::connect_timeout(&addr, self.timeout)?;
        sock.set_read_timeout(Some(self.timeout))?;
        sock.set_write_timeout(Some(self.timeout))?;
        self.wrap_data(sock)
    }

    fn wrap_data(&self, sock: TcpStream) -> FtpResult<FtpStream> {
        if self.protected_data {
            let tls = self.tls.as_ref().ok_or_else(|| {
                FtpError::Config("PROT P data requires FtpClientBuilder::tls".into())
            })?;
            let name = self.server_name.as_deref().unwrap_or("localhost");
            FtpStream::handshake_tls(sock, Arc::clone(tls), name)
        } else {
            Ok(FtpStream::Plain(sock))
        }
    }
}

enum PendingData {
    Ready(FtpStream),
    Listening(TcpListener),
}

impl PendingData {
    fn complete(self, client: &FtpClient) -> FtpResult<FtpStream> {
        match self {
            Self::Ready(s) => Ok(s),
            Self::Listening(listener) => {
                let (sock, _) = listener.accept()?;
                sock.set_read_timeout(Some(client.timeout))?;
                sock.set_write_timeout(Some(client.timeout))?;
                client.wrap_data(sock)
            }
        }
    }
}

fn parse_pwd_path(text: &str) -> Option<String> {
    let start = text.find('"')?;
    let end = text[start + 1..].find('"')? + start + 1;
    Some(text[start + 1..end].replace("\"\"", "\""))
}

/// FTP data peers often close TCP without a TLS `close_notify`.
fn read_data_to_end(data: &mut FtpStream) -> FtpResult<Vec<u8>> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        match data.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use reply::{parse_epsv_port, parse_pasv_addr};

    #[test]
    fn parse_pasv() {
        let a = parse_pasv_addr("Entering Passive Mode (192,168,1,2,4,5)").unwrap();
        assert_eq!(a, "192.168.1.2:1029".parse().unwrap());
    }

    #[test]
    fn parse_epsv() {
        assert_eq!(parse_epsv_port("Entering Extended Passive Mode (|||2121|)").unwrap(), 2121);
    }

    #[test]
    fn parse_pwd() {
        assert_eq!(parse_pwd_path("\"/tmp\" is current directory").as_deref(), Some("/tmp"));
    }
}
