// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! DNS-over-TLS server listener — feature `server` + `dot`.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use hopf_core::{ProtocolHandler, Runtime, SharedTlsAcceptor, TcpListenerConfig};

use super::framed::FramedServerHandler;
use super::{DnsServiceHandle, DnsTransport};

/// DoT listen (TCP + TLS, length-prefixed DNS).
pub fn listen_dns_dot(
    rt: &Runtime,
    addr: SocketAddr,
    acceptor: SharedTlsAcceptor,
    service: DnsServiceHandle,
) -> io::Result<SocketAddr> {
    let svc = Arc::new(service);
    let (bound, _) = rt.add_tcp_listener(
        TcpListenerConfig::new(addr, move || {
            Box::new(FramedServerHandler::new(Arc::clone(&svc), DnsTransport::Dot))
                as Box<dyn ProtocolHandler>
        })
        .with_tls(acceptor),
    )?;
    Ok(bound)
}
