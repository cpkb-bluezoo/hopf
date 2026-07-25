// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Canonical composition / script surface ([#8](https://github.com/cpkb-bluezoo/hopf/issues/8)).
//!
//! The Rust builder is canonical. Declarative XML (via tractrix) desugars into
//! the same builder through a closed [`CompositionRegistry`].

mod registry;
mod xml;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::binding::BindingId;
use crate::connector::TcpConnectorConfig;
use crate::listener::TcpListenerConfig;
use crate::runtime::{Runtime, RuntimeConfig};
use crate::telemetry::TelemetryHook;

pub use registry::CompositionRegistry;
pub use xml::{CompositionXmlError, CompositionXmlResult};

/// Starts a [`Runtime`] and applies listen/dial bindings against it.
///
/// The `Runtime` starts as soon as a `Composition` is created (`new` /
/// `new_with_telemetry` / `from_xml*`) — telemetry must be known up front
/// because [`Runtime::start_with_telemetry`] bakes it into each reactor at
/// spawn time. `listen_tcp` / `dial_tcp` apply immediately against the live
/// Runtime (fallible), rather than queueing for a later `build()`: this
/// matches the composition-root ordering in `PLAN.md`
/// (`main → Runtime::start → CompositionScript → add bindings`) and is what
/// lets bindings close over `Arc<Runtime>` — required by any protocol
/// service that offloads work to the storage pool (SMTP local delivery,
/// POP3, IMAP, ...).
pub struct Composition {
    runtime: Arc<Runtime>,
    /// Binding ids for every `listen_tcp` call so far, in call order.
    pub bindings: Vec<BindingId>,
    /// Local addresses for those listens, same order as `bindings`.
    pub listen_addrs: Vec<SocketAddr>,
}

impl Composition {
    /// Start a Runtime from `config`, with no telemetry hook.
    pub fn new(config: RuntimeConfig) -> io::Result<Self> {
        Self::new_with_telemetry(config, None)
    }

    /// Start a Runtime from `config` with a process-wide telemetry hook.
    pub fn new_with_telemetry(
        config: RuntimeConfig,
        telemetry: Option<Arc<dyn TelemetryHook>>,
    ) -> io::Result<Self> {
        let runtime = Arc::new(Runtime::start_with_telemetry(config, telemetry)?);
        Ok(Self {
            runtime,
            bindings: Vec::new(),
            listen_addrs: Vec::new(),
        })
    }

    /// The Runtime this composition is applying bindings against.
    ///
    /// Clone this to construct `Arc<Runtime>`-dependent protocol services
    /// (e.g. `LocalDeliveryService::new`, `Pop3Service::new`) before handing
    /// their listener config to [`listen_tcp`](Self::listen_tcp).
    pub fn runtime(&self) -> &Arc<Runtime> {
        &self.runtime
    }

    /// Add a TCP listen binding now.
    pub fn listen_tcp(&mut self, config: TcpListenerConfig) -> io::Result<BindingId> {
        let (addr, id) = self.runtime.add_tcp_listener(config)?;
        self.listen_addrs.push(addr);
        self.bindings.push(id);
        Ok(id)
    }

    /// Dial a TCP peer now.
    pub fn dial_tcp(&self, config: TcpConnectorConfig) -> io::Result<()> {
        self.runtime.connect(config)
    }

    /// Parse a composition XML document and apply it against a fresh Runtime.
    ///
    /// `handler` attributes are resolved through `registry` (closed map of
    /// [`crate::HandlerFactory`] values — not reflective DI). Only
    /// self-contained handlers can be named here: registry factories are
    /// resolved before this call returns a running `Composition`, so a
    /// factory that needs `Arc<Runtime>` (storage-offloading protocol
    /// services such as SMTP local delivery, POP3, IMAP) can't go through
    /// XML — wire those with the Rust builder instead, after `new()`.
    pub fn from_xml(bytes: &[u8], registry: &CompositionRegistry) -> CompositionXmlResult<Self> {
        Self::from_xml_with_telemetry(bytes, registry, None)
    }

    /// [`from_xml`](Self::from_xml) with a process-wide telemetry hook.
    pub fn from_xml_with_telemetry(
        bytes: &[u8],
        registry: &CompositionRegistry,
        telemetry: Option<Arc<dyn TelemetryHook>>,
    ) -> CompositionXmlResult<Self> {
        xml::parse_composition(bytes, registry, telemetry)
    }

    /// Parse composition XML from a UTF-8 string.
    pub fn from_xml_str(s: &str, registry: &CompositionRegistry) -> CompositionXmlResult<Self> {
        Self::from_xml(s.as_bytes(), registry)
    }

    /// [`from_xml_str`](Self::from_xml_str) with a process-wide telemetry hook.
    pub fn from_xml_str_with_telemetry(
        s: &str,
        registry: &CompositionRegistry,
        telemetry: Option<Arc<dyn TelemetryHook>>,
    ) -> CompositionXmlResult<Self> {
        Self::from_xml_with_telemetry(s.as_bytes(), registry, telemetry)
    }

    /// Read a composition XML file from `path` and apply it.
    pub fn from_xml_path(
        path: impl AsRef<std::path::Path>,
        registry: &CompositionRegistry,
    ) -> CompositionXmlResult<Self> {
        let bytes = std::fs::read(path.as_ref()).map_err(CompositionXmlError::Io)?;
        Self::from_xml(&bytes, registry)
    }

    /// [`from_xml_path`](Self::from_xml_path) with a process-wide telemetry hook.
    pub fn from_xml_path_with_telemetry(
        path: impl AsRef<std::path::Path>,
        registry: &CompositionRegistry,
        telemetry: Option<Arc<dyn TelemetryHook>>,
    ) -> CompositionXmlResult<Self> {
        let bytes = std::fs::read(path.as_ref()).map_err(CompositionXmlError::Io)?;
        Self::from_xml_with_telemetry(&bytes, registry, telemetry)
    }

    /// First listen address (convenience for port-`0` demos).
    pub fn primary_addr(&self) -> Option<SocketAddr> {
        self.listen_addrs.first().copied()
    }

    /// Remove a listen binding by id.
    pub fn remove_binding(&self, id: BindingId) {
        self.runtime.remove_binding(id);
    }

    /// Shut down.
    ///
    /// Best-effort: if nothing else holds a clone of the Runtime handle
    /// (true for compositions of self-contained handlers, e.g. the XML
    /// registry path), this fully joins reactor/accept/storage threads via
    /// [`Runtime::shutdown`]. If a registered service factory captured its
    /// own `Arc<Runtime>` clone (true for storage-offloading protocol
    /// services wired through [`runtime`](Self::runtime)), that clone
    /// outlives this call — the Runtime keeps running until the process
    /// exits or every clone drops, same as the standalone protocol examples
    /// that never call `Runtime::shutdown` at all and just drop their
    /// `Arc<Runtime>`.
    pub fn shutdown(self) {
        if let Ok(runtime) = Arc::try_unwrap(self.runtime) {
            runtime.shutdown();
        }
    }
}
