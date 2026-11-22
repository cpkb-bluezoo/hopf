// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! DNS-over-TLS server listener — feature `server` + `dot`.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use hopf_core::{ProtocolHandler, Runtime, SharedTlsAcceptor, TcpListenerConfig};

use super::framed::FramedServerHandler;
use super::{DnsServiceHandle, DnsTransport};

/// DoT listen (TCP + TLS, length-prefixed DNS).
///
/// A connection may have at most [`DnsServiceHandle::max_in_flight`] queries
/// outstanding; past that it is not read until an answer is complete.
pub fn listen_dns_dot(
    rt: &Runtime,
    addr: SocketAddr,
    acceptor: SharedTlsAcceptor,
    service: DnsServiceHandle,
) -> io::Result<SocketAddr> {
    listen_dns_dot_with(rt, addr, acceptor, service, |config| config)
}

/// [`listen_dns_dot`] with a say in the listener's own settings: the peer allow
/// and deny lists, the accept rate limit, the buffer caps, the idle timeout and
/// PROXY protocol, which are those of [`TcpListenerConfig`]. `configure` is given
/// the listener's configuration, with its address, handler and TLS acceptor set,
/// and returns it.
pub fn listen_dns_dot_with(
    rt: &Runtime,
    addr: SocketAddr,
    acceptor: SharedTlsAcceptor,
    service: DnsServiceHandle,
    configure: impl FnOnce(TcpListenerConfig) -> TcpListenerConfig,
) -> io::Result<SocketAddr> {
    let svc = Arc::new(service);
    let config = TcpListenerConfig::new(addr, move || {
        Box::new(FramedServerHandler::new(Arc::clone(&svc), DnsTransport::Dot))
            as Box<dyn ProtocolHandler>
    })
    .with_tls(acceptor);
    let (bound, _) = rt.add_tcp_listener(configure(config))?;
    Ok(bound)
}
