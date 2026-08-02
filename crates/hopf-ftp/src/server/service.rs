// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! FTP service configuration and control-listener factory.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use hopf_auth::TrustPolicy;
use hopf_core::tls::SharedTlsAcceptor;
use hopf_core::{ProtocolHandler, Runtime, SharedTlsConnector, TcpListenerConfig};

use crate::server::control::FtpControlHandler;
use crate::server::handler::{
    FtpConnectionHandlerFactory, FilesystemFtpHandlerFactory,
};
use crate::server::metrics::FtpServerMetrics;

/// FTP server configuration.
#[derive(Clone)]
pub struct FtpConfig {
    /// Control listen address (default 0.0.0.0:21).
    pub listen: SocketAddr,
    /// Filesystem root for the stock handler.
    pub root: PathBuf,
    /// Trust policy for USER/PASS.
    pub policy: Arc<dyn TrustPolicy>,
    /// Optional TLS acceptor (AUTH TLS / implicit / PROT P on PASV/EPSV
    /// data connections, where the server accepts).
    pub tls_acceptor: Option<SharedTlsAcceptor>,
    /// Optional TLS connector for PROT P on active-mode (PORT/EPRT) data
    /// connections — there the server dials out and so needs a client-role
    /// connector, not an acceptor. `None` means active-mode transfers can
    /// never be protected, even with PROT P in effect; `PROT P` transfers
    /// then only work in passive mode.
    pub data_tls_connector: Option<SharedTlsConnector>,
    /// TLS verification name (SNI / certificate name) passed to
    /// `data_tls_connector` for each active-mode dial. There's no real
    /// hostname for an arbitrary FTP client's data port, so this is a
    /// fixed, deployer-supplied string (e.g. a pinned name the connector's
    /// verifier is configured to accept) rather than derived per-peer;
    /// defaults to `"ftp-client"` when unset.
    pub data_tls_server_name: Option<String>,
    /// Implicit FTPS (TLS-from-accept on control).
    pub implicit_tls: bool,
    /// Require PROT P for data — a transfer attempted without it is
    /// rejected outright (RFC 4217 §2), not silently allowed in the clear.
    pub require_tls_for_data: bool,
    /// Allow PORT/EPRT to a different host than the control peer.
    pub allow_active_bounce: bool,
    /// Address advertised in PASV (NAT).
    pub pasv_advertised: Option<IpAddr>,
    /// Optional PASV port range min.
    pub pasv_port_min: Option<u16>,
    /// Optional PASV port range max.
    pub pasv_port_max: Option<u16>,
    /// Read-only filesystem.
    pub read_only: bool,
}

impl FtpConfig {
    /// Plain FTP with password policy and filesystem root.
    pub fn new(
        listen: SocketAddr,
        root: impl Into<PathBuf>,
        policy: Arc<dyn TrustPolicy>,
    ) -> Self {
        Self {
            listen,
            root: root.into(),
            policy,
            tls_acceptor: None,
            data_tls_connector: None,
            data_tls_server_name: None,
            implicit_tls: false,
            require_tls_for_data: false,
            allow_active_bounce: false,
            pasv_advertised: None,
            pasv_port_min: None,
            pasv_port_max: None,
            read_only: false,
        }
    }

    /// Attach TLS acceptor for AUTH TLS / PROT P (control + passive-mode
    /// data connections).
    pub fn with_tls(mut self, acceptor: SharedTlsAcceptor) -> Self {
        self.tls_acceptor = Some(acceptor);
        self
    }

    /// Attach a TLS connector so PROT P also protects active-mode
    /// (PORT/EPRT) data connections, where the server dials out.
    /// `server_name` is the fixed SNI/verification name used for every
    /// such dial (see [`FtpConfig::data_tls_server_name`]).
    pub fn with_data_tls_connector(
        mut self,
        connector: SharedTlsConnector,
        server_name: impl Into<String>,
    ) -> Self {
        self.data_tls_connector = Some(connector);
        self.data_tls_server_name = Some(server_name.into());
        self
    }

    /// Implicit FTPS on the control listener.
    pub fn implicit_ftps(mut self) -> Self {
        self.implicit_tls = true;
        self
    }

    /// Require secured data connections.
    pub fn require_data_tls(mut self) -> Self {
        self.require_tls_for_data = true;
        self
    }
}

/// Registers the control listener on a [`Runtime`].
///
/// Hold the runtime in an [`Arc`] so PASV can call `add_tcp_listener` later.
pub struct FtpService {
    config: FtpConfig,
    metrics: Arc<FtpServerMetrics>,
    handler_factory: Arc<dyn FtpConnectionHandlerFactory>,
    otel_metrics: Option<Arc<hopf_otel::FtpServerMetrics>>,
    export: Option<hopf_otel::ExportHandle>,
    traces_enabled: bool,
}

impl FtpService {
    /// Stock filesystem handler factory.
    pub fn new(config: FtpConfig) -> Self {
        let factory: Arc<dyn FtpConnectionHandlerFactory> = if config.read_only {
            Arc::new(FilesystemFtpHandlerFactory::read_only(
                config.root.clone(),
                Arc::clone(&config.policy),
            ))
        } else {
            Arc::new(FilesystemFtpHandlerFactory::new(
                config.root.clone(),
                Arc::clone(&config.policy),
            ))
        };
        Self {
            config,
            metrics: FtpServerMetrics::shared(),
            handler_factory: factory,
            otel_metrics: None,
            export: None,
            traces_enabled: false,
        }
    }

    /// Custom application handler factory.
    pub fn with_handler_factory(
        config: FtpConfig,
        factory: Arc<dyn FtpConnectionHandlerFactory>,
    ) -> Self {
        Self {
            config,
            metrics: FtpServerMetrics::shared(),
            handler_factory: factory,
            otel_metrics: None,
            export: None,
            traces_enabled: false,
        }
    }

    /// Wire OTLP/JSONL FTP metrics and connection/transfer traces from a pipeline.
    ///
    /// When traces are enabled, handlers see a W3C `traceparent` on
    /// [`FtpConnectionMetadata`](crate::FtpConnectionMetadata) for outbound
    /// HTTP via `hopf_otel::with_traceparent`.
    pub fn with_telemetry(mut self, pipeline: &hopf_otel::TelemetryPipeline) -> Self {
        let cfg = pipeline.config();
        if cfg.metrics_enabled {
            self.otel_metrics = Some(pipeline.ftp_metrics());
        }
        if cfg.traces_enabled {
            self.export = Some(pipeline.export_handle());
            self.traces_enabled = true;
        } else if cfg.metrics_enabled {
            self.export = Some(pipeline.export_handle());
        }
        self
    }

    /// Shared process-local metrics.
    pub fn metrics(&self) -> &Arc<FtpServerMetrics> {
        &self.metrics
    }

    /// Build a [`TcpListenerConfig`] for the control port (caller registers it).
    pub fn control_listener(&self, runtime: Arc<Runtime>) -> TcpListenerConfig {
        let factory = Arc::clone(&self.handler_factory);
        let metrics = Arc::clone(&self.metrics);
        let config = self.config.clone();
        let rt = Arc::clone(&runtime);
        let otel_metrics = self.otel_metrics.clone();
        let export = self.export.clone();
        let traces_enabled = self.traces_enabled;
        let mut cfg = TcpListenerConfig::new(self.config.listen, move || {
            // Peer/local filled in connected() via endpoint — use placeholders.
            let peer = SocketAddr::from(([0, 0, 0, 0], 0));
            let local = config.listen;
            Box::new(
                FtpControlHandler::new(
                    factory.create(),
                    Arc::clone(&rt),
                    Arc::clone(&metrics),
                    config.clone(),
                    peer,
                    local,
                )
                .with_telemetry(otel_metrics.clone(), export.clone(), traces_enabled),
            ) as Box<dyn ProtocolHandler>
        });
        if let Some(tls) = &self.config.tls_acceptor {
            if self.config.implicit_tls {
                cfg = cfg.with_tls(Arc::clone(tls));
            } else {
                cfg = cfg.with_starttls_acceptor(Arc::clone(tls));
            }
        }
        cfg
    }

    /// Register the control listener; returns bound address.
    pub fn start(&self, runtime: Arc<Runtime>) -> std::io::Result<SocketAddr> {
        let cfg = self.control_listener(Arc::clone(&runtime));
        let (addr, _) = runtime.add_tcp_listener(cfg)?;
        Ok(addr)
    }
}
