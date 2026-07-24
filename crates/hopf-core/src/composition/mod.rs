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

/// Builder that starts a [`Runtime`] and applies listen/dial bindings.
pub struct Composition {
    config: RuntimeConfig,
    listens: Vec<TcpListenerConfig>,
    dials: Vec<TcpConnectorConfig>,
    telemetry: Option<Arc<dyn TelemetryHook>>,
}

impl Composition {
    /// Start from a runtime config.
    pub fn new(config: RuntimeConfig) -> Self {
        Self {
            config,
            listens: Vec::new(),
            dials: Vec::new(),
            telemetry: None,
        }
    }

    /// Attach a process-wide telemetry hook.
    pub fn telemetry(mut self, hook: Arc<dyn TelemetryHook>) -> Self {
        self.telemetry = Some(hook);
        self
    }

    /// Queue a TCP listen binding.
    pub fn listen_tcp(mut self, config: TcpListenerConfig) -> Self {
        self.listens.push(config);
        self
    }

    /// Queue a TCP dial.
    pub fn dial_tcp(mut self, config: TcpConnectorConfig) -> Self {
        self.dials.push(config);
        self
    }

    /// Parse a composition XML document and desugar into this builder.
    ///
    /// `handler` attributes are resolved through `registry` (closed map of
    /// [`crate::HandlerFactory`] values — not reflective DI).
    pub fn from_xml(bytes: &[u8], registry: &CompositionRegistry) -> CompositionXmlResult<Self> {
        xml::parse_composition(bytes, registry)
    }

    /// Parse composition XML from a UTF-8 string.
    pub fn from_xml_str(s: &str, registry: &CompositionRegistry) -> CompositionXmlResult<Self> {
        Self::from_xml(s.as_bytes(), registry)
    }

    /// Read a composition XML file from `path` and parse it.
    pub fn from_xml_path(
        path: impl AsRef<std::path::Path>,
        registry: &CompositionRegistry,
    ) -> CompositionXmlResult<Self> {
        let bytes = std::fs::read(path.as_ref()).map_err(CompositionXmlError::Io)?;
        Self::from_xml(&bytes, registry)
    }

    /// Start the runtime and apply queued bindings.
    pub fn build(self) -> io::Result<CompositionRuntime> {
        let rt = Runtime::start_with_telemetry(self.config, self.telemetry)?;
        let mut bindings = Vec::new();
        let mut addrs = Vec::new();
        for cfg in self.listens {
            let (addr, id) = rt.add_tcp_listener(cfg)?;
            addrs.push(addr);
            bindings.push(id);
        }
        for dial in self.dials {
            rt.connect(dial)?;
        }
        Ok(CompositionRuntime {
            runtime: rt,
            bindings,
            listen_addrs: addrs,
        })
    }
}

/// Running composition: Runtime + recorded listen binding ids.
pub struct CompositionRuntime {
    /// Underlying runtime.
    pub runtime: Runtime,
    /// Binding ids for queued listens (same order as [`Composition::listen_tcp`]).
    pub bindings: Vec<BindingId>,
    /// Local addresses for those listens.
    pub listen_addrs: Vec<SocketAddr>,
}

impl CompositionRuntime {
    /// First listen address (convenience for port-`0` demos).
    pub fn primary_addr(&self) -> Option<SocketAddr> {
        self.listen_addrs.first().copied()
    }

    /// Remove a listen binding by id.
    pub fn remove_binding(&self, id: BindingId) {
        self.runtime.remove_binding(id);
    }

    /// Shut down.
    pub fn shutdown(self) {
        self.runtime.shutdown();
    }
}
