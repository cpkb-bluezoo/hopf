// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Peer credentials for a UNIX domain socket connection (`SO_PEERCRED` on
//! Linux, `getpeereid` on macOS/BSD) and an allowlist built on them — the
//! UNIX-domain analogue of [`crate::PeerAcl`], since IP/CIDR matching
//! doesn't apply to a filesystem-path socket.

use std::io;

use mio::net::UnixStream;

/// The connecting process's effective user/group id, as reported by the
/// kernel at accept time — not self-reported by the peer, so this is a
/// real (if coarse) authentication signal, unlike anything derivable from
/// the socket path alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentials {
    /// The connecting process's effective user id.
    pub uid: u32,
    /// The connecting process's effective group id.
    pub gid: u32,
}

/// Peer-credential allowlist for a UNIX domain socket listener — the
/// UNIX-domain analogue of [`crate::PeerAcl`].
#[derive(Debug, Clone, Default)]
pub struct PeerCredAllowlist {
    /// If either this or [`allow_gids`](Self::allow_gids) is non-empty, the
    /// peer's uid or gid must match one of the configured entries.
    pub allow_uids: Vec<u32>,
    /// See [`allow_uids`](Self::allow_uids).
    pub allow_gids: Vec<u32>,
}

impl PeerCredAllowlist {
    /// Empty allowlist (allow all — filesystem permissions on the socket
    /// path/directory are the only gate).
    pub fn open() -> Self {
        Self::default()
    }

    /// Evaluate peer credentials. An empty allowlist allows everyone;
    /// otherwise the peer's uid or gid must match one of the configured
    /// entries.
    pub fn allows(&self, creds: PeerCredentials) -> bool {
        if self.allow_uids.is_empty() && self.allow_gids.is_empty() {
            return true;
        }
        self.allow_uids.contains(&creds.uid) || self.allow_gids.contains(&creds.gid)
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn peer_credentials(stream: &UnixStream) -> io::Result<PeerCredentials> {
    use std::os::fd::AsRawFd;

    // Layout per `man 7 unix` (`SO_PEERCRED`) — `pid_t`/`uid_t`/`gid_t`,
    // all `i32`/`u32` on every Linux target `libc` supports.
    #[repr(C)]
    struct Ucred {
        pid: libc::pid_t,
        uid: libc::uid_t,
        gid: libc::gid_t,
    }

    let fd = stream.as_raw_fd();
    let mut cred = Ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<Ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut Ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(PeerCredentials {
        uid: cred.uid,
        gid: cred.gid,
    })
}

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
pub(crate) fn peer_credentials(stream: &UnixStream) -> io::Result<PeerCredentials> {
    use std::os::fd::AsRawFd;

    let fd = stream.as_raw_fd();
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let rc = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(PeerCredentials { uid, gid })
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
)))]
pub(crate) fn peer_credentials(_stream: &UnixStream) -> io::Result<PeerCredentials> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "peer credentials are not supported on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_allowlist_allows_any_credentials() {
        let acl = PeerCredAllowlist::open();
        assert!(acl.allows(PeerCredentials { uid: 12345, gid: 67890 }));
    }

    #[test]
    fn nonempty_allowlist_requires_a_uid_or_gid_match() {
        let acl = PeerCredAllowlist {
            allow_uids: vec![501],
            allow_gids: vec![],
        };
        assert!(acl.allows(PeerCredentials { uid: 501, gid: 999 }));
        assert!(!acl.allows(PeerCredentials { uid: 502, gid: 999 }));
    }

    #[test]
    fn gid_match_is_sufficient_even_without_a_uid_match() {
        let acl = PeerCredAllowlist {
            allow_uids: vec![501],
            allow_gids: vec![20],
        };
        assert!(acl.allows(PeerCredentials { uid: 999, gid: 20 }));
    }
}
