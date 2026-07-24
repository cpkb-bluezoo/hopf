// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Runtime extension: QUIC listen/dial peers of TCP listen/dial.
//!
//! QUIC I/O runs on a dedicated mio thread inside this crate (UDP stays out of
//! the TCP worker reactors). Handles are independent of [`hopf_core::Runtime`]
//! lifetime; shut them down explicitly or drop them.

use std::io;

use hopf_core::Runtime;

use crate::config::{QuicConnectConfig, QuicListenConfig, QuicListenHooksConfig};
use crate::driver::{connect_quic, listen_quic, listen_quic_hooks, QuicDriverHandle};

/// Peer of [`Runtime::add_tcp_listener`] / [`Runtime::connect`] for QUIC.
pub trait RuntimeQuicExt {
    /// Bind UDP and accept QUIC connections (one handler per bi-stream).
    fn add_quic_listener(&self, config: QuicListenConfig) -> io::Result<QuicDriverHandle>;

    /// Bind UDP with connection-level hooks (HTTP/3).
    fn add_quic_listener_hooks(
        &self,
        config: QuicListenHooksConfig,
    ) -> io::Result<QuicDriverHandle>;

    /// Dial a QUIC peer and open one bi-stream.
    fn connect_quic(&self, config: QuicConnectConfig) -> io::Result<QuicDriverHandle>;
}

impl RuntimeQuicExt for Runtime {
    fn add_quic_listener(&self, config: QuicListenConfig) -> io::Result<QuicDriverHandle> {
        let _ = self;
        listen_quic(config)
    }

    fn add_quic_listener_hooks(
        &self,
        config: QuicListenHooksConfig,
    ) -> io::Result<QuicDriverHandle> {
        let _ = self;
        listen_quic_hooks(config)
    }

    fn connect_quic(&self, config: QuicConnectConfig) -> io::Result<QuicDriverHandle> {
        let _ = self;
        connect_quic(config)
    }
}
