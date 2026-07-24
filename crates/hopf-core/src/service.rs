// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Service lifecycle seam (Gumdrop `Service`).

use crate::listener::TcpListenerConfig;

/// Application unit that may register bindings on a [`crate::Runtime`].
///
/// Prefer registering via [`crate::Runtime::add_tcp_listener`] inside
/// [`start`](Service::start) (or use [`crate::Composition`]).
/// [`tcp_listeners`](Service::tcp_listeners) remains for transitional static sets.
pub trait Service: Send {
    /// Initialise application resources; register bindings on `runtime`.
    fn start(&mut self, runtime: &crate::Runtime) -> std::io::Result<()>;

    /// Stop listeners and tear down application resources.
    fn stop(&mut self);

    /// Optional static TCP listeners (empty by default). Prefer Runtime APIs.
    fn tcp_listeners(&self) -> &[TcpListenerConfig] {
        &[]
    }
}
