// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Connection settings.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hopf_core::SharedTlsConnector;
use hopf_dns::DnsResolver;

use crate::resp::RespLimits;

/// How to reach one Redis or Valkey server, and what to say to it on
/// connecting. Built with [`RedisConfig::new`] and the methods below.
#[derive(Clone)]
pub struct RedisConfig {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) addr: Option<SocketAddr>,
    pub(crate) tls: Option<(SharedTlsConnector, String)>,
    pub(crate) username: Option<String>,
    pub(crate) password: Option<String>,
    pub(crate) database: u32,
    pub(crate) client_name: Option<String>,
    pub(crate) resp3: bool,
    pub(crate) resolver: Option<Arc<DnsResolver>>,
    pub(crate) connect_timeout: Duration,
    pub(crate) command_timeout: Option<Duration>,
    pub(crate) max_pending: usize,
    pub(crate) limits: RespLimits,
    pub(crate) backoff_initial: Duration,
    pub(crate) backoff_max: Duration,
    pub(crate) ping_interval: Option<Duration>,
}

impl RedisConfig {
    /// A server at `host:port`. `host` is a name (resolved through
    /// [`hopf_dns`](hopf_dns) when the client dials) or a literal address.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            addr: None,
            tls: None,
            username: None,
            password: None,
            database: 0,
            client_name: None,
            resp3: true,
            resolver: None,
            connect_timeout: Duration::from_secs(5),
            command_timeout: Some(Duration::from_secs(10)),
            max_pending: 0,
            limits: RespLimits::default(),
            backoff_initial: Duration::from_millis(100),
            backoff_max: Duration::from_secs(5),
            ping_interval: Some(Duration::from_secs(30)),
        }
    }

    /// A server at a known address, with no name lookup.
    pub fn from_addr(addr: SocketAddr) -> Self {
        let mut c = Self::new(addr.ip().to_string(), addr.port());
        c.addr = Some(addr);
        c
    }

    /// Speak TLS, presenting `server_name` and verifying the server's
    /// certificate against it with `connector`. Build the connector with
    /// [`hopf_core::ClientTlsBuilder`] (trust anchors, a client certificate for
    /// mutual TLS, pins).
    pub fn tls(mut self, connector: SharedTlsConnector, server_name: impl Into<String>) -> Self {
        self.tls = Some((connector, server_name.into()));
        self
    }

    /// Authenticate as `username` (Redis 6 ACLs) as well as with the password.
    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    /// Authenticate with this password on every connection.
    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// `SELECT` this database on every connection. Not for cluster mode, which
    /// has only database 0.
    pub fn database(mut self, database: u32) -> Self {
        self.database = database;
        self
    }

    /// Name the connection (`CLIENT SETNAME`), for `CLIENT LIST` and logs.
    pub fn client_name(mut self, name: impl Into<String>) -> Self {
        self.client_name = Some(name.into());
        self
    }

    /// Do not try `HELLO 3`: speak RESP2 only. By default RESP3 is negotiated
    /// and RESP2 is the fallback for a server that does not know `HELLO`.
    pub fn resp2_only(mut self) -> Self {
        self.resp3 = false;
        self
    }

    /// The resolver for a host name. By default the client makes one on the
    /// reactor it is bound to, from the system's nameservers.
    pub fn resolver(mut self, resolver: Arc<DnsResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// How long to wait for the TCP connect. Default 5 s.
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// How long a command may go unanswered, counted from when it is issued,
    /// the connect and handshake included. `None` waits for ever (a blocking
    /// command such as `BLPOP` needs it). Default 10 s.
    pub fn command_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.command_timeout = timeout;
        self
    }

    /// The most commands that may be sent and waiting for their replies, or
    /// waiting for the connection, at once; more fail with
    /// [`RedisError::Overloaded`](crate::RedisError::Overloaded). `0`, the
    /// default, is no limit.
    pub fn max_pending(mut self, max: usize) -> Self {
        self.max_pending = max;
        self
    }

    /// Bounds on what a reply may make the client hold.
    pub fn limits(mut self, limits: RespLimits) -> Self {
        self.limits = limits;
        self
    }

    /// After a failed connect, commands fail at once for a while rather than
    /// each dialling afresh: `initial`, doubling with each failure in a row up
    /// to `max`. Defaults 100 ms and 5 s.
    pub fn reconnect_backoff(mut self, initial: Duration, max: Duration) -> Self {
        self.backoff_initial = initial;
        self.backoff_max = max;
        self
    }

    /// For a [`RedisSubscriber`](crate::RedisSubscriber): how often to check the
    /// connection is alive. After this long with nothing received it sends a
    /// `PING`; after three times as long with nothing at all, it drops the
    /// connection and dials again (a connection can die without telling either
    /// end). `None` never checks. Default 30 s.
    pub fn ping_interval(mut self, interval: Option<Duration>) -> Self {
        self.ping_interval = interval;
        self
    }

    /// The host this config names.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port this config names.
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl std::fmt::Debug for RedisConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("tls", &self.tls.as_ref().map(|(_, name)| name))
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("database", &self.database)
            .field("client_name", &self.client_name)
            .field("resp3", &self.resp3)
            .field("command_timeout", &self.command_timeout)
            .finish_non_exhaustive()
    }
}
