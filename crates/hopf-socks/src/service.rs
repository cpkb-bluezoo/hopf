// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SOCKS listener registration.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use hopf_core::{PeerAcl, Runtime, SharedTlsAcceptor, TcpListenerConfig};

use crate::handler::SocksConnectionHandlerFactory;

/// A SOCKS listener bound to one address, built from a
/// [`SocksConnectionHandlerFactory`].
pub struct SocksService {
    listen: SocketAddr,
    factory: Arc<SocksConnectionHandlerFactory>,
    acl: PeerAcl,
    tls: Option<SharedTlsAcceptor>,
}

impl SocksService {
    /// Bind `listen` once [`start`](Self::start) is called, serving
    /// connections built by `factory`. Open to all source addresses and
    /// plaintext until [`with_acl`](Self::with_acl) / [`with_tls`](Self::with_tls)
    /// say otherwise.
    pub fn new(listen: SocketAddr, factory: SocksConnectionHandlerFactory) -> Self {
        Self {
            listen,
            factory: Arc::new(factory),
            acl: PeerAcl::open(),
            tls: None,
        }
    }

    /// Restrict which client source addresses may use this listener at
    /// all. This is in addition to, not a replacement for, the per-request
    /// [`crate::SocksPolicy`] passed to the connection handler factory:
    /// this ACL governs *who* may connect to the proxy in the first place,
    /// `SocksPolicy` governs *where* an already-accepted client may then
    /// relay to.
    pub fn with_acl(mut self, acl: PeerAcl) -> Self {
        self.acl = acl;
        self
    }

    /// Wrap this listener in TLS-from-accept ("SOCKS over TLS"). The
    /// protocol state machine needs no changes for this — it only ever
    /// sees already-decrypted bytes either way — so this is purely a
    /// transport-level listener option.
    pub fn with_tls(mut self, acceptor: SharedTlsAcceptor) -> Self {
        self.tls = Some(acceptor);
        self
    }

    /// Register the listener on `runtime`; returns the bound address.
    pub fn start(&self, runtime: &Runtime) -> io::Result<SocketAddr> {
        let factory = Arc::clone(&self.factory);
        let mut cfg = TcpListenerConfig::new(self.listen, move || factory.create_handler())
            .with_acl(self.acl.clone());
        if let Some(tls) = &self.tls {
            cfg = cfg.with_tls(Arc::clone(tls));
        }
        let (addr, _) = runtime.add_tcp_listener(cfg)?;
        Ok(addr)
    }
}
