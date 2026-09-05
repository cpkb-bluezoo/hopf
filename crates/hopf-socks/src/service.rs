// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SOCKS listener registration.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use hopf_core::{Runtime, TcpListenerConfig};

use crate::handler::SocksConnectionHandlerFactory;

/// A SOCKS listener bound to one address, built from a
/// [`SocksConnectionHandlerFactory`].
pub struct SocksService {
    listen: SocketAddr,
    factory: Arc<SocksConnectionHandlerFactory>,
}

impl SocksService {
    /// Bind `listen` once [`start`](Self::start) is called, serving
    /// connections built by `factory`.
    pub fn new(listen: SocketAddr, factory: SocksConnectionHandlerFactory) -> Self {
        Self {
            listen,
            factory: Arc::new(factory),
        }
    }

    /// Register the listener on `runtime`; returns the bound address.
    pub fn start(&self, runtime: &Runtime) -> io::Result<SocketAddr> {
        let factory = Arc::clone(&self.factory);
        let cfg = TcpListenerConfig::new(self.listen, move || factory.create_handler());
        let (addr, _) = runtime.add_tcp_listener(cfg)?;
        Ok(addr)
    }
}
