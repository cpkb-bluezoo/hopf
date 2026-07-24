// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Plain or TLS duplex stream for control / data.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};

use super::error::{FtpError, FtpResult};

/// Control or data connection bytes.
pub enum FtpStream {
    /// Cleartext TCP.
    Plain(TcpStream),
    /// rustls over TCP.
    Tls(StreamOwned<ClientConnection, TcpStream>),
    /// Placeholder after move.
    Closed,
}

impl FtpStream {
    pub fn connect_plain(addr: SocketAddr, timeout: Duration) -> FtpResult<Self> {
        let sock = TcpStream::connect_timeout(&addr, timeout)?;
        sock.set_read_timeout(Some(timeout))?;
        sock.set_write_timeout(Some(timeout))?;
        Ok(Self::Plain(sock))
    }

    pub fn connect_tls(
        addr: SocketAddr,
        config: Arc<ClientConfig>,
        server_name: &str,
        timeout: Duration,
    ) -> FtpResult<Self> {
        let sock = TcpStream::connect_timeout(&addr, timeout)?;
        sock.set_read_timeout(Some(timeout))?;
        sock.set_write_timeout(Some(timeout))?;
        Self::handshake_tls(sock, config, server_name)
    }

    pub fn handshake_tls(
        sock: TcpStream,
        config: Arc<ClientConfig>,
        server_name: &str,
    ) -> FtpResult<Self> {
        let name = ServerName::try_from(server_name.to_string())
            .map_err(|e| FtpError::Config(format!("server name: {e}")))?;
        let conn = ClientConnection::new(config, name)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(Self::Tls(StreamOwned::new(conn, sock)))
    }

    /// Upgrade a plain stream to TLS in place (`AUTH TLS`).
    pub fn upgrade_tls(
        &mut self,
        config: Arc<ClientConfig>,
        server_name: &str,
    ) -> FtpResult<()> {
        let prev = std::mem::replace(self, Self::Closed);
        match prev {
            Self::Plain(sock) => {
                *self = Self::handshake_tls(sock, config, server_name)?;
                Ok(())
            }
            Self::Tls(s) => {
                *self = Self::Tls(s);
                Err(FtpError::Config("already TLS".into()))
            }
            Self::Closed => Err(FtpError::Config("stream closed".into())),
        }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Plain(s) => s.local_addr(),
            Self::Tls(s) => s.sock.local_addr(),
            Self::Closed => Err(io::Error::new(io::ErrorKind::NotConnected, "closed")),
        }
    }

    pub fn shutdown(&mut self) {
        match self {
            Self::Plain(s) => {
                let _ = s.shutdown(Shutdown::Both);
            }
            Self::Tls(s) => {
                let _ = s.sock.shutdown(Shutdown::Both);
            }
            Self::Closed => {}
        }
        *self = Self::Closed;
    }

    /// Half-close the write side after STOR/APPE.
    pub fn shutdown_write(&mut self) {
        match self {
            Self::Plain(s) => {
                let _ = s.shutdown(Shutdown::Write);
            }
            Self::Tls(s) => {
                // Best-effort: drop write interest; full close_notify needs session API.
                let _ = s.sock.shutdown(Shutdown::Write);
            }
            Self::Closed => {}
        }
    }
}

impl Read for FtpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(s) => s.read(buf),
            Self::Tls(s) => s.read(buf),
            Self::Closed => Err(io::Error::new(io::ErrorKind::NotConnected, "closed")),
        }
    }
}

impl Write for FtpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(s) => s.write(buf),
            Self::Tls(s) => s.write(buf),
            Self::Closed => Err(io::Error::new(io::ErrorKind::NotConnected, "closed")),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(s) => s.flush(),
            Self::Tls(s) => s.flush(),
            Self::Closed => Ok(()),
        }
    }
}
