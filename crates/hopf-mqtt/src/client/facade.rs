// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! High-level async MQTT client facade.
//!
//! [`MqttClient`] is a builder + connect method. It resolves hostnames via
//! the hopf-dns [`DnsResolver`] (or skips DNS for literal IPs), then calls
//! [`Runtime::connect`] with a [`TcpConnectorConfig`] wrapping an
//! [`MqttClientEndpoint`].

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use hopf_core::{Runtime, SharedTlsConnector, TcpConnectorConfig, UnixConnectorConfig};
use hopf_dns::DnsResolver;

use crate::codec::packet::{ProtocolVersion, Will};

use super::endpoint::{MqttClientEndpoint, MqttClientParams};
use super::handlers::MqttClientHandlerFactory;
use super::timeout::MqttClientTimeouts;

/// Async MQTT client facade.
///
/// Build with [`MqttClient::new`] (hostname) or [`MqttClient::from_addr`]
/// (literal address), configure CONNECT parameters, then call
/// [`MqttClient::connect`] with an [`MqttClientHandlerFactory`].
///
/// # Example
///
/// ```no_run
/// use std::sync::Arc;
/// use hopf_core::{Runtime, RuntimeConfig};
/// use hopf_mqtt::client::MqttClient;
/// # use hopf_mqtt::client::{MqttClientControl, MqttClientDriver, MqttClientHandlerFactory};
/// # use hopf_mqtt::codec::{Properties, QoS};
/// # struct D; impl MqttClientDriver for D {
/// #   fn on_connack(&mut self, c: &mut dyn MqttClientControl, _: bool, _: u8, _: &Properties) { let _ = c.subscribe(&[]); }
/// #   fn on_message_start(&mut self, _: &str, _: QoS, _: bool, _: u16, _: &Properties, _: u32) {}
/// #   fn on_message_data(&mut self, _: &[u8]) {}
/// #   fn on_message_complete(&mut self, _: &mut dyn MqttClientControl) {}
/// #   fn on_suback(&mut self, _: &mut dyn MqttClientControl, _: u16, _: &[u8]) {}
/// #   fn on_unsuback(&mut self, _: &mut dyn MqttClientControl, _: u16, _: &[u8]) {}
/// #   fn on_publish_acked(&mut self, _: &mut dyn MqttClientControl, _: u16) {}
/// #   fn on_ping_resp(&mut self, _: &mut dyn MqttClientControl) {}
/// #   fn on_server_disconnect(&mut self, _: u8, _: &Properties) {}
/// #   fn on_error(&mut self, _: &std::io::Error) {}
/// #   fn on_disconnected(&mut self) {}
/// # }
/// # struct F; impl MqttClientHandlerFactory for F { fn create(&self) -> Box<dyn MqttClientDriver> { Box::new(D) } }
///
/// let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
/// MqttClient::new("broker.example.com", 1883, "my-client-id")
///     .connect(&rt, Arc::new(F))
///     .unwrap();
/// ```
pub struct MqttClient {
    host: Option<String>,
    port: u16,
    addr: Option<SocketAddr>,
    unix_path: Option<PathBuf>,
    client_id: String,
    version: ProtocolVersion,
    clean_start: bool,
    keep_alive: Duration,
    session_expiry_secs: u32,
    receive_maximum: Option<u16>,
    username: Option<String>,
    password: Option<Vec<u8>>,
    will: Option<Will>,
    timeouts: MqttClientTimeouts,
    tls_connector: Option<SharedTlsConnector>,
    tls_server_name: Option<String>,
    implicit_tls: bool,
    resolver: Option<Arc<DnsResolver>>,
}

impl MqttClient {
    /// Create a client that resolves `host` via DNS before connecting.
    pub fn new(host: impl Into<String>, port: u16, client_id: impl Into<String>) -> Self {
        Self {
            host: Some(host.into()),
            port,
            addr: None,
            unix_path: None,
            client_id: client_id.into(),
            version: ProtocolVersion::V5,
            clean_start: true,
            keep_alive: Duration::from_secs(60),
            session_expiry_secs: 0,
            receive_maximum: None,
            username: None,
            password: None,
            will: None,
            timeouts: MqttClientTimeouts::default(),
            tls_connector: None,
            tls_server_name: None,
            implicit_tls: false,
            resolver: None,
        }
    }

    /// Create a client with a pre-resolved [`SocketAddr`] (skips DNS).
    pub fn from_addr(addr: SocketAddr, client_id: impl Into<String>) -> Self {
        Self {
            host: None,
            port: addr.port(),
            addr: Some(addr),
            unix_path: None,
            client_id: client_id.into(),
            version: ProtocolVersion::V5,
            clean_start: true,
            keep_alive: Duration::from_secs(60),
            session_expiry_secs: 0,
            receive_maximum: None,
            username: None,
            password: None,
            will: None,
            timeouts: MqttClientTimeouts::default(),
            tls_connector: None,
            tls_server_name: None,
            implicit_tls: false,
            resolver: None,
        }
    }

    /// Create a client that dials a UNIX domain socket instead of TCP/IP —
    /// skips DNS entirely.
    pub fn from_unix_path(path: impl Into<PathBuf>, client_id: impl Into<String>) -> Self {
        Self {
            host: None,
            port: 0,
            addr: None,
            unix_path: Some(path.into()),
            client_id: client_id.into(),
            version: ProtocolVersion::V5,
            clean_start: true,
            keep_alive: Duration::from_secs(60),
            session_expiry_secs: 0,
            receive_maximum: None,
            username: None,
            password: None,
            will: None,
            timeouts: MqttClientTimeouts::default(),
            tls_connector: None,
            tls_server_name: None,
            implicit_tls: false,
            resolver: None,
        }
    }

    /// CONNECT with MQTT 3.1.1 instead of the default 5.0.
    pub fn v3_1_1(mut self) -> Self {
        self.version = ProtocolVersion::V311;
        self
    }

    /// Clean Session / Clean Start (default `true`).
    pub fn clean_start(mut self, clean_start: bool) -> Self {
        self.clean_start = clean_start;
        self
    }

    /// Keep Alive interval (default 60s; `Duration::ZERO` disables it).
    pub fn keep_alive(mut self, keep_alive: Duration) -> Self {
        self.keep_alive = keep_alive;
        self
    }

    /// MQTT 5.0 Session Expiry Interval (ignored on a v3.1.1 connection).
    pub fn session_expiry(mut self, seconds: u32) -> Self {
        self.session_expiry_secs = seconds;
        self
    }

    /// MQTT 5.0 Receive Maximum to advertise to the broker (ignored on v3.1.1).
    pub fn receive_maximum(mut self, max: u16) -> Self {
        self.receive_maximum = Some(max);
        self
    }

    /// CONNECT username/password.
    pub fn credentials(mut self, username: impl Into<String>, password: impl Into<Vec<u8>>) -> Self {
        self.username = Some(username.into());
        self.password = Some(password.into());
        self
    }

    /// Will Message, published by the broker if this connection drops
    /// without a clean DISCONNECT.
    pub fn will(mut self, will: Will) -> Self {
        self.will = Some(will);
        self
    }

    /// Override per-phase timeouts.
    pub fn timeouts(mut self, t: MqttClientTimeouts) -> Self {
        self.timeouts = t;
        self
    }

    /// Configure implicit TLS (MQTTS — TLS from the first byte, typically port 8883).
    pub fn implicit_tls(mut self, connector: SharedTlsConnector, server_name: impl Into<String>) -> Self {
        self.tls_connector = Some(connector);
        self.tls_server_name = Some(server_name.into());
        self.implicit_tls = true;
        self
    }

    /// Override the DNS resolver.
    pub fn resolver(mut self, resolver: Arc<DnsResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    fn params(&self) -> MqttClientParams {
        MqttClientParams {
            version: self.version,
            client_id: self.client_id.clone(),
            clean_start: self.clean_start,
            keep_alive: self.keep_alive,
            session_expiry_secs: self.session_expiry_secs,
            receive_maximum: self.receive_maximum,
            username: self.username.clone(),
            password: self.password.clone(),
            will: self.will.clone(),
            tls_connector: self.tls_connector.clone(),
            tls_server_name: self.tls_server_name.clone(),
            implicit_tls: self.implicit_tls,
            connack_timeout: self.timeouts.connack,
            pingresp_timeout: self.timeouts.pingresp,
        }
    }

    fn make_connector(&self, factory: Arc<dyn MqttClientHandlerFactory>, addr: SocketAddr) -> TcpConnectorConfig {
        let params = self.params();
        let tls_for_dial = self.tls_connector.clone();
        let sn_for_dial = self.tls_server_name.clone();
        let implicit = self.implicit_tls;

        let mut cfg = TcpConnectorConfig::new(addr, move || {
            Box::new(MqttClientEndpoint::new(factory.as_ref(), params.clone()))
        })
        .connect_timeout(Some(self.timeouts.connect));

        if implicit {
            if let (Some(c), Some(n)) = (tls_for_dial, sn_for_dial) {
                cfg = cfg.with_tls(c, n);
            }
        }
        cfg
    }

    /// UNIX-domain counterpart of [`Self::make_connector`].
    fn make_unix_connector(
        &self,
        factory: Arc<dyn MqttClientHandlerFactory>,
        path: PathBuf,
    ) -> UnixConnectorConfig {
        let params = self.params();
        let tls_for_dial = self.tls_connector.clone();
        let sn_for_dial = self.tls_server_name.clone();
        let implicit = self.implicit_tls;

        let mut cfg = UnixConnectorConfig::new(path, move || {
            Box::new(MqttClientEndpoint::new(factory.as_ref(), params.clone()))
        })
        .connect_timeout(Some(self.timeouts.connect));

        if implicit {
            if let (Some(c), Some(n)) = (tls_for_dial, sn_for_dial) {
                cfg = cfg.with_tls(c, n);
            }
        }
        cfg
    }

    /// Schedule DNS (if needed) then [`Runtime::connect`]. Returns immediately.
    /// [`Self::from_unix_path`] dials a UNIX domain socket instead — skips
    /// DNS and address resolution entirely.
    ///
    /// Takes [`Arc<Runtime>`] so hostname resolution can dial from the DNS
    /// callback without blocking the caller. Literal IPs and `from_addr`
    /// skip DNS.
    pub fn connect(&self, rt: &Arc<Runtime>, factory: Arc<dyn MqttClientHandlerFactory>) -> io::Result<()> {
        if let Some(path) = &self.unix_path {
            return rt.connect_unix(self.make_unix_connector(factory, path.clone()));
        }
        if let Some(addr) = self.addr {
            return rt.connect(self.make_connector(factory, addr));
        }

        let host = self
            .host
            .as_deref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no host or addr set"))?;

        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            let addr = SocketAddr::new(ip, self.port);
            return rt.connect(self.make_connector(factory, addr));
        }

        let resolver = match &self.resolver {
            Some(r) => Arc::clone(r),
            None => Arc::new(DnsResolver::for_runtime(rt.as_ref())?),
        };
        resolver.set_timeout(self.timeouts.dns);

        let port = self.port;
        let params = self.params();
        let tls_for_dial = self.tls_connector.clone();
        let sn_for_dial = self.tls_server_name.clone();
        let implicit_tls = self.implicit_tls;
        let connect_timeout = self.timeouts.connect;
        let rt2 = Arc::clone(rt);
        let host_for_err = host.to_owned();

        resolver.resolve(
            host,
            port,
            Box::new(move |result| {
                let addrs = match result {
                    Ok(a) => a,
                    Err(e) => {
                        eprintln!("hopf-mqtt: DNS error for {host_for_err}: {e}");
                        return;
                    }
                };
                let Some(addr) = addrs.into_iter().next() else {
                    eprintln!("hopf-mqtt: DNS returned no addresses for {host_for_err}");
                    return;
                };
                let factory2 = Arc::clone(&factory);
                let params2 = params.clone();
                let mut cfg = TcpConnectorConfig::new(addr, move || {
                    Box::new(MqttClientEndpoint::new(factory2.as_ref(), params2.clone()))
                })
                .connect_timeout(Some(connect_timeout));
                if implicit_tls {
                    if let (Some(c), Some(n)) = (tls_for_dial, sn_for_dial) {
                        cfg = cfg.with_tls(c, n);
                    }
                }
                if let Err(e) = rt2.connect(cfg) {
                    eprintln!("hopf-mqtt: connect error: {e}");
                }
            }),
        );
        Ok(())
    }
}
