// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! A connection's local/remote address — TCP/IP or UNIX domain socket.
//!
//! `std::net::TcpStream` and `std::os::unix::net::UnixStream` don't share a
//! common address type the way e.g. Java NIO's `SocketChannel` does (its
//! `getRemoteAddress()` returns the generic `java.net.SocketAddress`,
//! satisfied by both `InetSocketAddress` and `UnixDomainSocketAddress`) —
//! this type plays that role for [`crate::Endpoint::local_addr`] /
//! [`crate::Endpoint::remote_addr`].

use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// A connection's local or remote address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerAddr {
    /// A TCP/IP socket address.
    Inet(SocketAddr),
    /// A UNIX domain socket address. `None` for an unnamed or Linux
    /// abstract-namespace socket (no filesystem path) — matches
    /// [`std::os::unix::net::SocketAddr::as_pathname`]'s own convention.
    Unix(Option<PathBuf>),
}

impl PeerAddr {
    /// The TCP/IP address, if this is [`PeerAddr::Inet`].
    pub fn as_socket_addr(&self) -> Option<SocketAddr> {
        match self {
            PeerAddr::Inet(addr) => Some(*addr),
            PeerAddr::Unix(_) => None,
        }
    }

    /// The UNIX domain socket path, if this is [`PeerAddr::Unix`] and it
    /// has one (not unnamed/abstract).
    pub fn as_unix_path(&self) -> Option<&Path> {
        match self {
            PeerAddr::Unix(Some(path)) => Some(path),
            _ => None,
        }
    }

    /// Whether this is a UNIX domain socket address.
    pub fn is_unix(&self) -> bool {
        matches!(self, PeerAddr::Unix(_))
    }
}

impl From<SocketAddr> for PeerAddr {
    fn from(addr: SocketAddr) -> Self {
        PeerAddr::Inet(addr)
    }
}

impl fmt::Display for PeerAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerAddr::Inet(addr) => write!(f, "{addr}"),
            PeerAddr::Unix(Some(path)) => write!(f, "unix:{}", path.display()),
            PeerAddr::Unix(None) => write!(f, "unix:(unnamed)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inet_round_trips_through_as_socket_addr() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let p: PeerAddr = addr.into();
        assert_eq!(p.as_socket_addr(), Some(addr));
        assert_eq!(p.as_unix_path(), None);
        assert!(!p.is_unix());
    }

    #[test]
    fn unix_path_is_exposed_and_not_a_socket_addr() {
        let p = PeerAddr::Unix(Some(PathBuf::from("/tmp/hopf.sock")));
        assert_eq!(p.as_socket_addr(), None);
        assert_eq!(p.as_unix_path(), Some(Path::new("/tmp/hopf.sock")));
        assert!(p.is_unix());
    }

    #[test]
    fn unnamed_unix_has_no_path_but_is_still_unix() {
        let p = PeerAddr::Unix(None);
        assert_eq!(p.as_unix_path(), None);
        assert!(p.is_unix());
    }

    #[test]
    fn display_formats_each_variant_distinctly() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(PeerAddr::Inet(addr).to_string(), "127.0.0.1:8080");
        assert_eq!(
            PeerAddr::Unix(Some(PathBuf::from("/tmp/hopf.sock"))).to_string(),
            "unix:/tmp/hopf.sock"
        );
        assert_eq!(PeerAddr::Unix(None).to_string(), "unix:(unnamed)");
    }
}
