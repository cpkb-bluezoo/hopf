// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! UDP socket setup and outbound send queueing for the QUIC driver.

use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use mio::net::UdpSocket;
use quinn_proto::{EcnCodepoint, Transmit};
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
    enable_recv_ecn(&std_sock);
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
    pub ecn: Option<u8>,
    pub segment_size: Option<usize>,
}

impl PendingUdpSend {
    fn from_transmit(transmit: &Transmit, data: &[u8]) -> Self {
        Self {
            destination: transmit.destination,
            data: data.to_vec(),
            ecn: transmit.ecn.map(|c| c as u8),
            segment_size: transmit.segment_size,
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

/// Max UDP datagrams quinn-proto may coalesce into one `Transmit` for GSO.
pub(crate) fn max_gso_segments() -> usize {
    #[cfg(target_os = "linux")]
    {
        64
    }
    #[cfg(not(target_os = "linux"))]
    {
        1
    }
}

/// Slice a transmit buffer into UDP payloads honouring `segment_size`.
pub(crate) fn udp_payloads<'a>(buf: &'a [u8], segment_size: Option<usize>) -> Vec<&'a [u8]> {
    match segment_size {
        Some(ss) if ss > 0 && buf.len() > ss => buf.chunks(ss).collect(),
        _ => vec![buf],
    }
}

/// Send one quinn [`Transmit`] (ECN TOS + GSO `segment_size` when the OS
/// supports them). Falls back to per-datagram `send_to` when GSO/ECN cmsgs
/// are unavailable.
pub(crate) fn send_transmit(socket: &UdpSocket, transmit: &Transmit, buf: &[u8]) -> io::Result<()> {
    send_udp(
        socket,
        transmit.destination,
        buf,
        transmit.ecn,
        transmit.segment_size,
    )
}

pub(crate) fn send_pending(socket: &UdpSocket, pending: &PendingUdpSend) -> io::Result<()> {
    send_udp(
        socket,
        pending.destination,
        &pending.data,
        pending.ecn.and_then(EcnCodepoint::from_bits),
        pending.segment_size,
    )
}

fn send_udp(
    socket: &UdpSocket,
    dest: SocketAddr,
    buf: &[u8],
    ecn: Option<EcnCodepoint>,
    segment_size: Option<usize>,
) -> io::Result<()> {
    if buf.is_empty() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        match send_msg(socket, dest, buf, ecn, segment_size) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Err(e),
            Err(_) => {}
        }
    }
    for payload in udp_payloads(buf, segment_size) {
        match socket.send_to(payload, dest) {
            Ok(n) if n == payload.len() => {}
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "short UDP send",
                ));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Receive one datagram, recovering ECN when `IP_RECVTOS` / `IPV6_RECVTCLASS`
/// is enabled.
pub(crate) fn recv_one(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, Option<EcnCodepoint>)> {
    #[cfg(unix)]
    {
        match recv_msg(socket, buf) {
            Ok(x) => return Ok(x),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Err(e),
            Err(_) => {}
        }
    }
    let (n, remote) = socket.recv_from(buf)?;
    Ok((n, remote, None))
}

fn enable_recv_ecn(sock: &std::net::UdpSocket) {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = sock.as_raw_fd();
        let one: libc::c_int = 1;
        match sock.local_addr() {
            Ok(SocketAddr::V4(_)) => {
                let _ = setsockopt_i32(fd, libc::IPPROTO_IP, libc::IP_RECVTOS, one);
            }
            Ok(SocketAddr::V6(_)) => {
                let _ = setsockopt_i32(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVTCLASS, one);
            }
            Err(_) => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = sock;
    }
}

#[cfg(unix)]
fn send_msg(
    socket: &UdpSocket,
    dest: SocketAddr,
    buf: &[u8],
    ecn: Option<EcnCodepoint>,
    segment_size: Option<usize>,
) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;

    let sock_addr = socket2::SockAddr::from(dest);
    let mut iov = libc::iovec {
        iov_base: buf.as_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };

    let gso = cfg!(target_os = "linux")
        && segment_size.map(|ss| ss > 0 && buf.len() > ss).unwrap_or(false);
    let mut cmsg_buf = [0u8; 128];
    let mut hdr = libc::msghdr {
        msg_name: sock_addr.as_ptr() as *mut libc::c_void,
        msg_namelen: sock_addr.len(),
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: std::ptr::null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
    };

    if ecn.is_some() || gso {
        hdr.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        hdr.msg_controllen = cmsg_buf.len() as _;
        let mut cursor = unsafe { libc::CMSG_FIRSTHDR(&hdr) };
        let mut used = 0usize;
        if let Some(code) = ecn {
            let tos = code as libc::c_int;
            let (level, opt) = match dest {
                SocketAddr::V4(_) => (libc::IPPROTO_IP, libc::IP_TOS),
                SocketAddr::V6(_) => (libc::IPPROTO_IPV6, libc::IPV6_TCLASS),
            };
            unsafe {
                if cursor.is_null() {
                    return Err(io::Error::other("cmsg space exhausted"));
                }
                (*cursor).cmsg_level = level;
                (*cursor).cmsg_type = opt;
                (*cursor).cmsg_len =
                    libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as _) as _;
                std::ptr::write(libc::CMSG_DATA(cursor) as *mut libc::c_int, tos);
                used += libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as _) as usize;
                cursor = libc::CMSG_NXTHDR(&hdr, cursor);
            }
        }
        #[cfg(target_os = "linux")]
        if gso {
            let ss = segment_size.unwrap() as u16;
            unsafe {
                if cursor.is_null() {
                    return Err(io::Error::other("cmsg space exhausted"));
                }
                (*cursor).cmsg_level = libc::SOL_UDP;
                (*cursor).cmsg_type = libc::UDP_SEGMENT;
                (*cursor).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u16>() as _) as _;
                std::ptr::write(libc::CMSG_DATA(cursor) as *mut u16, ss);
                used += libc::CMSG_SPACE(std::mem::size_of::<u16>() as _) as usize;
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = cursor;
        }
        hdr.msg_controllen = used as _;
    }

    let n = unsafe { libc::sendmsg(socket.as_raw_fd(), &hdr, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n as usize != buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short UDP sendmsg",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn recv_msg(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, Option<EcnCodepoint>)> {
    use std::os::unix::io::AsRawFd;

    let mut name: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let mut cmsg_buf = [0u8; 128];
    let mut hdr = libc::msghdr {
        msg_name: &mut name as *mut _ as *mut libc::c_void,
        msg_namelen: std::mem::size_of::<libc::sockaddr_storage>() as _,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: cmsg_buf.as_mut_ptr() as *mut libc::c_void,
        msg_controllen: cmsg_buf.len() as _,
        msg_flags: 0,
    };
    let n = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut hdr, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let remote = sockaddr_storage_to_socket_addr(&name, hdr.msg_namelen)?;

    let mut ecn = None;
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&hdr);
        while !cmsg.is_null() {
            let level = (*cmsg).cmsg_level;
            let ty = (*cmsg).cmsg_type;
            if (level == libc::IPPROTO_IP && (ty == libc::IP_TOS || ty == libc::IP_RECVTOS))
                || (level == libc::IPPROTO_IPV6 && ty == libc::IPV6_TCLASS)
            {
                let bits = *libc::CMSG_DATA(cmsg);
                ecn = EcnCodepoint::from_bits(bits);
            }
            cmsg = libc::CMSG_NXTHDR(&hdr, cmsg);
        }
    }
    Ok((n as usize, remote, ecn))
}

#[cfg(unix)]
fn sockaddr_storage_to_socket_addr(
    storage: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> io::Result<SocketAddr> {
    let _ = len;
    let family = storage.ss_family as i32;
    if family == libc::AF_INET {
        let v4 = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
        let ip = Ipv4Addr::from(u32::from_be(v4.sin_addr.s_addr));
        let port = u16::from_be(v4.sin_port);
        Ok(SocketAddr::from((ip, port)))
    } else if family == libc::AF_INET6 {
        let v6 = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
        let ip = Ipv6Addr::from(v6.sin6_addr.s6_addr);
        let port = u16::from_be(v6.sin6_port);
        Ok(SocketAddr::from((ip, port)))
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "recvmsg: not an IP address",
        ))
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
            ecn: None,
            segment_size: None,
        });
        pending.enqueue(PendingUdpSend {
            destination: "127.0.0.1:2".parse().unwrap(),
            data: b"second".to_vec(),
            ecn: None,
            segment_size: None,
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
            ecn: None,
            segment_size: None,
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

    #[test]
    fn udp_payloads_honours_segment_size() {
        let buf = b"aaaabbbbccccdd";
        assert_eq!(udp_payloads(buf, None), vec![&buf[..]]);
        assert_eq!(
            udp_payloads(buf, Some(4)),
            vec![&b"aaaa"[..], &b"bbbb"[..], &b"cccc"[..], &b"dd"[..]]
        );
        assert_eq!(udp_payloads(buf, Some(64)), vec![&buf[..]]);
    }

    #[test]
    fn pending_from_transmit_keeps_ecn_and_segment_size() {
        let tx = Transmit {
            destination: "127.0.0.1:443".parse().unwrap(),
            ecn: Some(EcnCodepoint::Ect0),
            size: 3,
            segment_size: Some(1200),
            src_ip: None,
        };
        let pending = PendingUdpSend::from_transmit(&tx, b"abc");
        assert_eq!(pending.ecn, Some(EcnCodepoint::Ect0 as u8));
        assert_eq!(pending.segment_size, Some(1200));
        assert_eq!(pending.data, b"abc");
    }
}
