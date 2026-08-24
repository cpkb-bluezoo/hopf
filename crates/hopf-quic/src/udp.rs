// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! UDP socket setup and outbound send queueing for the QUIC driver.

use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use mio::net::UdpSocket;
use quinn_proto::Transmit;
use socket2::{Domain, Protocol, Socket, Type};

/// Bind a non-blocking UDP socket for QUIC, applying RFC 9000 §14 path-MTU
/// hardening (Do Not Fragment on IPv4; equivalent on IPv6 where supported).
pub fn bind_udp(addr: SocketAddr) -> io::Result<(UdpSocket, SocketAddr)> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    set_dont_fragment(&socket, domain)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    let std_sock: std::net::UdpSocket = socket.into();
    let local_addr = std_sock.local_addr()?;
    Ok((UdpSocket::from_std(std_sock), local_addr))
}

/// Unspecified ephemeral bind address matching `peer`'s family.
///
/// QUIC clients must bind IPv6 (`[::]:0`) when dialing an IPv6 peer;
/// binding `0.0.0.0` cannot send to IPv6 destinations.
pub fn unspecified_bind_addr(peer: SocketAddr) -> SocketAddr {
    match peer.ip() {
        IpAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        IpAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    }
}

/// Outbound QUIC datagram waiting for a writable UDP socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingUdpSend {
    pub destination: SocketAddr,
    pub data: Vec<u8>,
}

impl PendingUdpSend {
    fn from_transmit(transmit: &Transmit, data: &[u8]) -> Self {
        Self {
            destination: transmit.destination,
            data: data.to_vec(),
        }
    }
}

/// FIFO queue of datagrams that could not be sent immediately.
#[derive(Default, Debug)]
pub(crate) struct PendingUdpSends {
    queue: VecDeque<PendingUdpSend>,
}

impl PendingUdpSends {
    pub(crate) fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.queue.len()
    }

    pub(crate) fn enqueue_transmit(&mut self, transmit: &Transmit, data: &[u8]) {
        self.queue
            .push_back(PendingUdpSend::from_transmit(transmit, data));
    }

    pub(crate) fn enqueue(&mut self, send: PendingUdpSend) {
        self.queue.push_back(send);
    }

    /// Try to send every queued datagram. Stops at the first `WouldBlock`.
    pub(crate) fn flush<F>(&mut self, mut send_one: F) -> io::Result<()>
    where
        F: FnMut(&PendingUdpSend) -> io::Result<()>,
    {
        while let Some(pending) = self.queue.front() {
            match send_one(pending) {
                Ok(()) => {
                    self.queue.pop_front();
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

fn set_dont_fragment(socket: &Socket, domain: Domain) -> io::Result<()> {
    match domain {
        Domain::IPV4 => set_ipv4_dont_fragment(socket),
        Domain::IPV6 => set_ipv6_dont_fragment(socket),
        _ => Ok(()),
    }
}

#[cfg(unix)]
fn set_ipv4_dont_fragment(socket: &Socket) -> io::Result<()> {
    use std::os::raw::c_int;
    use std::os::unix::io::AsRawFd;

    #[cfg(target_os = "linux")]
    {
        const IP_MTU_DISCOVER: c_int = 10;
        const IP_PMTUDISC_DO: c_int = 2;
        setsockopt_i32(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            IP_MTU_DISCOVER,
            IP_PMTUDISC_DO,
        )
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))]
    {
        const IP_DONTFRAG: c_int = 28;
        setsockopt_i32(socket.as_raw_fd(), libc::IPPROTO_IP, IP_DONTFRAG, 1)
    }
    #[cfg(any(
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    {
        const IP_DONTFRAG: c_int = 67;
        setsockopt_i32(socket.as_raw_fd(), libc::IPPROTO_IP, IP_DONTFRAG, 1)
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )))]
    {
        let _ = socket;
        Ok(())
    }
}

#[cfg(windows)]
fn set_ipv4_dont_fragment(socket: &Socket) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    const IP_DONTFRAGMENT: i32 = 14;
    setsockopt_i32(
        socket.as_raw_socket() as _,
        libc::IPPROTO_IP as i32,
        IP_DONTFRAGMENT,
        1,
    )
}

#[cfg(not(any(unix, windows)))]
fn set_ipv4_dont_fragment(_socket: &Socket) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_ipv6_dont_fragment(socket: &Socket) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;

    #[cfg(target_os = "linux")]
    {
        use std::os::raw::c_int;
        const IPV6_MTU_DISCOVER: c_int = 23;
        const IPV6_PMTUDISC_DO: c_int = 2;
        setsockopt_i32(
            socket.as_raw_fd(),
            libc::IPPROTO_IPV6,
            IPV6_MTU_DISCOVER,
            IPV6_PMTUDISC_DO,
        )
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos",
        target_os = "freebsd"
    ))]
    {
        use std::os::raw::c_int;
        const IPV6_DONTFRAG: c_int = 62;
        setsockopt_i32(socket.as_raw_fd(), libc::IPPROTO_IPV6, IPV6_DONTFRAG, 1)
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos",
        target_os = "freebsd"
    )))]
    {
        let _ = socket;
        Ok(())
    }
}

#[cfg(windows)]
fn set_ipv6_dont_fragment(_socket: &Socket) -> io::Result<()> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn set_ipv6_dont_fragment(_socket: &Socket) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn setsockopt_i32(fd: std::os::unix::io::RawFd, level: i32, opt: i32, val: i32) -> io::Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            opt,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn setsockopt_i32(
    socket: std::os::windows::io::RawSocket,
    level: i32,
    opt: i32,
    val: i32,
) -> io::Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            socket as _,
            level,
            opt,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as i32,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn bind_udp_ephemeral_ipv4() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (_sock, local) = bind_udp(addr).unwrap();
        assert!(local.ip().is_ipv4());
        assert_ne!(local.port(), 0);
    }

    #[test]
    fn unspecified_bind_matches_peer_family() {
        let v4: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let bind4 = unspecified_bind_addr(v4);
        assert!(bind4.ip().is_unspecified());
        assert!(bind4.ip().is_ipv4());
        assert_eq!(bind4.port(), 0);

        let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let bind6 = unspecified_bind_addr(v6);
        assert!(bind6.ip().is_unspecified());
        assert!(bind6.ip().is_ipv6());
        assert_eq!(bind6.port(), 0);
    }

    #[test]
    fn bind_udp_ephemeral_ipv6_when_available() {
        let addr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0));
        match bind_udp(addr) {
            Ok((_sock, local)) => {
                assert!(local.ip().is_ipv6());
                assert_ne!(local.port(), 0);
            }
            Err(e) => {
                // Hosts without IPv6 still compile and run this test.
                let _ = e;
            }
        }
    }

    #[test]
    fn pending_queue_flushes_in_order() {
        let mut pending = PendingUdpSends::default();
        pending.enqueue(PendingUdpSend {
            destination: "127.0.0.1:1".parse().unwrap(),
            data: b"first".to_vec(),
        });
        pending.enqueue(PendingUdpSend {
            destination: "127.0.0.1:2".parse().unwrap(),
            data: b"second".to_vec(),
        });

        let seen = Arc::new(AtomicUsize::new(0));
        let seen2 = Arc::clone(&seen);
        pending
            .flush(|send| {
                let n = seen2.fetch_add(1, Ordering::SeqCst);
                match n {
                    0 => assert_eq!(send.data, b"first"),
                    1 => assert_eq!(send.data, b"second"),
                    _ => panic!("unexpected extra send"),
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(seen.load(Ordering::SeqCst), 2);
        assert!(pending.is_empty());
    }

    #[test]
    fn pending_queue_stops_on_would_block_and_retries() {
        let mut pending = PendingUdpSends::default();
        pending.enqueue(PendingUdpSend {
            destination: "127.0.0.1:1".parse().unwrap(),
            data: b"only".to_vec(),
        });

        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts2 = Arc::clone(&attempts);
        pending
            .flush(|_| {
                let n = attempts2.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    Err(io::ErrorKind::WouldBlock.into())
                } else {
                    Ok(())
                }
            })
            .unwrap();
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert_eq!(pending.len(), 1);

        pending
            .flush(|_| Ok(()))
            .unwrap();
        assert!(pending.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn ipv4_dont_fragment_is_set_when_supported() {
        use std::os::raw::c_int;
        use std::os::unix::io::AsRawFd;

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (sock, _) = bind_udp(addr).unwrap();
        let fd = sock.as_raw_fd();

        #[cfg(target_os = "linux")]
        {
            const IP_MTU_DISCOVER: c_int = 10;
            let mut val: c_int = 0;
            let mut len = std::mem::size_of::<c_int>() as libc::socklen_t;
            let rc = unsafe {
                libc::getsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    IP_MTU_DISCOVER,
                    &mut val as *mut _ as *mut libc::c_void,
                    &mut len,
                )
            };
            assert_eq!(rc, 0, "getsockopt failed: {}", io::Error::last_os_error());
            assert_eq!(val, 2, "IP_PMTUDISC_DO");
        }

        #[cfg(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd"
        ))]
        {
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            const IP_DONTFRAG: c_int = 28;
            #[cfg(target_os = "freebsd")]
            const IP_DONTFRAG: c_int = 67;
            #[cfg(any(target_os = "openbsd", target_os = "netbsd"))]
            const IP_DONTFRAG: c_int = 67;
            let mut val: c_int = 0;
            let mut len = std::mem::size_of::<c_int>() as libc::socklen_t;
            let rc = unsafe {
                libc::getsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    IP_DONTFRAG,
                    &mut val as *mut _ as *mut libc::c_void,
                    &mut len,
                )
            };
            assert_eq!(rc, 0, "getsockopt failed: {}", io::Error::last_os_error());
            assert_eq!(val, 1);
        }
    }
}
