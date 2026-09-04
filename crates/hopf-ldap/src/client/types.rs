// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! LDAP client types (RFC 4511).

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use hopf_core::SharedTlsConnector;

use crate::asn1::Asn1Error;

/// Default LDAP port (RFC 4511).
pub const DEFAULT_LDAP_PORT: u16 = 389;
/// Default LDAPS port (RFC 4513 §3.1.3).
pub const DEFAULT_LDAPS_PORT: u16 = 636;

/// LDAPv3 protocol version.
pub(crate) const LDAP_VERSION_3: i32 = 3;

/// Application tag numbers (RFC 4511 §4).
pub(crate) const APP_BIND_REQUEST: u8 = 0;
pub(crate) const APP_BIND_RESPONSE: u8 = 1;
pub(crate) const APP_UNBIND_REQUEST: u8 = 2;
pub(crate) const APP_SEARCH_REQUEST: u8 = 3;
pub(crate) const APP_SEARCH_RESULT_ENTRY: u8 = 4;
pub(crate) const APP_SEARCH_RESULT_DONE: u8 = 5;
pub(crate) const APP_SEARCH_RESULT_REFERENCE: u8 = 19;
/// ExtendedRequest — RFC 4511 §4.12 (APPLICATION 23).
pub(crate) const APP_EXTENDED_REQUEST: u8 = 23;
/// ExtendedResponse — RFC 4511 §4.12 (APPLICATION 24).
pub(crate) const APP_EXTENDED_RESPONSE: u8 = 24;

/// STARTTLS extended operation OID — RFC 4511 §4.14.
pub const OID_STARTTLS: &str = "1.3.6.1.4.1.1466.20037";

/// Context tag for Referral in LDAPResult (RFC 4511 §4.1.9).
pub(crate) const CTX_REFERRAL: u8 = 3;

/// Default maximum referral hops for chase.
pub const DEFAULT_MAX_REFERRAL_HOPS: u32 = 5;

/// LDAP result codes (RFC 4511 Appendix A).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LdapResultCode {
    /// The operation completed successfully.
    Success,
    /// An internal server error occurred.
    OperationsError,
    /// The server encountered a protocol error.
    ProtocolError,
    /// A time limit was exceeded.
    TimeLimitExceeded,
    /// A size limit was exceeded.
    SizeLimitExceeded,
    /// A referral was returned.
    Referral,
    /// The specified object does not exist.
    NoSuchObject,
    /// Invalid credentials provided.
    InvalidCredentials,
    /// An unknown or other error occurred.
    Other,
    /// Numeric code not mapped to a named variant.
    Unknown(i32),
}

impl LdapResultCode {
    /// Map a wire result code to an enum variant.
    pub fn from_code(code: i32) -> Self {
        match code {
            0 => Self::Success,
            1 => Self::OperationsError,
            2 => Self::ProtocolError,
            3 => Self::TimeLimitExceeded,
            4 => Self::SizeLimitExceeded,
            10 => Self::Referral,
            32 => Self::NoSuchObject,
            49 => Self::InvalidCredentials,
            80 => Self::Other,
            n => Self::Unknown(n),
        }
    }

    /// Wire numeric code.
    pub fn code(self) -> i32 {
        match self {
            Self::Success => 0,
            Self::OperationsError => 1,
            Self::ProtocolError => 2,
            Self::TimeLimitExceeded => 3,
            Self::SizeLimitExceeded => 4,
            Self::Referral => 10,
            Self::NoSuchObject => 32,
            Self::InvalidCredentials => 49,
            Self::Other => 80,
            Self::Unknown(n) => n,
        }
    }

    /// Whether this code indicates success (`0`).
    pub fn is_success(self) -> bool {
        matches!(self, Self::Success)
    }
}

impl fmt::Display for LdapResultCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "success (0)"),
            Self::OperationsError => write!(f, "operationsError (1)"),
            Self::ProtocolError => write!(f, "protocolError (2)"),
            Self::TimeLimitExceeded => write!(f, "timeLimitExceeded (3)"),
            Self::SizeLimitExceeded => write!(f, "sizeLimitExceeded (4)"),
            Self::Referral => write!(f, "referral (10)"),
            Self::NoSuchObject => write!(f, "noSuchObject (32)"),
            Self::InvalidCredentials => write!(f, "invalidCredentials (49)"),
            Self::Other => write!(f, "other (80)"),
            Self::Unknown(n) => write!(f, "unknown ({n})"),
        }
    }
}

/// LDAP client / protocol errors.
#[derive(Debug)]
pub enum LdapError {
    /// Underlying I/O failure.
    Io(io::Error),
    /// BER encode/decode failure.
    Asn1(Asn1Error),
    /// Protocol framing or message shape error.
    Protocol(String),
    /// Operation or connect timed out.
    Timeout,
    /// Connection closed before the operation completed.
    Closed,
    /// Bind completed with a non-success result code.
    BindFailed(LdapResultCode),
    /// Search completed with a non-success result code.
    SearchFailed(LdapResultCode),
    /// STARTTLS ExtendedResponse failed or TLS upgrade failed.
    StartTlsFailed(LdapResultCode),
    /// Referral chase exhausted or URL unusable.
    Referral(String),
    /// Invalid configuration (missing host/addr, etc.).
    Config(String),
}

impl fmt::Display for LdapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "LDAP I/O error: {e}"),
            Self::Asn1(e) => write!(f, "LDAP ASN.1 error: {e}"),
            Self::Protocol(m) => write!(f, "LDAP protocol error: {m}"),
            Self::Timeout => write!(f, "LDAP operation timed out"),
            Self::Closed => write!(f, "LDAP connection closed"),
            Self::BindFailed(c) => write!(f, "LDAP bind failed: {c}"),
            Self::SearchFailed(c) => write!(f, "LDAP search failed: {c}"),
            Self::StartTlsFailed(c) => write!(f, "LDAP STARTTLS failed: {c}"),
            Self::Referral(m) => write!(f, "LDAP referral error: {m}"),
            Self::Config(m) => write!(f, "LDAP config error: {m}"),
        }
    }
}

impl std::error::Error for LdapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Asn1(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for LdapError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<Asn1Error> for LdapError {
    fn from(e: Asn1Error) -> Self {
        Self::Asn1(e)
    }
}

/// Search scope (RFC 4511 §4.5.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SearchScope {
    /// Search only the base object.
    BaseObject = 0,
    /// Search the immediate children of the base object.
    SingleLevel = 1,
    /// Search the base object and all descendants.
    WholeSubtree = 2,
}

impl SearchScope {
    /// Wire enumerated value.
    pub fn value(self) -> i32 {
        self as i32
    }
}

/// Alias dereferencing policy (RFC 4511 §4.5.1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DerefAliases {
    /// Never dereference aliases.
    Never = 0,
    /// Dereference when searching subordinates.
    InSearching = 1,
    /// Dereference when finding the base object.
    FindingBaseObj = 2,
    /// Always dereference aliases.
    Always = 3,
}

impl DerefAliases {
    /// Wire enumerated value.
    pub fn value(self) -> i32 {
        self as i32
    }
}

/// Search request parameters (RFC 4511 §4.5.1).
#[derive(Debug, Clone)]
pub struct SearchRequest {
    /// Base DN.
    pub base_dn: String,
    /// Search scope.
    pub scope: SearchScope,
    /// RFC 4515 filter string.
    pub filter: String,
    /// Attribute names to return (empty = all user attributes).
    pub attributes: Vec<String>,
    /// Size limit (`0` = no client limit).
    pub size_limit: i32,
    /// Time limit in seconds (`0` = no client limit).
    pub time_limit: i32,
    /// Return attribute types only.
    pub types_only: bool,
    /// Alias dereference policy.
    pub deref_aliases: DerefAliases,
}

impl Default for SearchRequest {
    fn default() -> Self {
        Self {
            base_dn: String::new(),
            scope: SearchScope::WholeSubtree,
            filter: "(objectClass=*)".into(),
            attributes: Vec::new(),
            size_limit: 0,
            time_limit: 0,
            types_only: false,
            deref_aliases: DerefAliases::Never,
        }
    }
}

impl SearchRequest {
    /// Build a subtree search with the given base DN and filter.
    pub fn new(base_dn: impl Into<String>, filter: impl Into<String>) -> Self {
        Self {
            base_dn: base_dn.into(),
            filter: filter.into(),
            ..Self::default()
        }
    }
}

/// A SearchResultEntry (RFC 4511 §4.5.2).
#[derive(Debug, Clone)]
pub struct SearchEntry {
    /// Entry distinguished name.
    pub dn: String,
    /// Attribute name → list of octet-string values.
    pub attributes: HashMap<String, Vec<Vec<u8>>>,
}

/// Outcome of a simple bind (RFC 4511 §4.2).
#[derive(Debug, Clone)]
pub struct BindResult {
    /// Whether the bind succeeded (`resultCode == success`).
    pub success: bool,
    /// Server result code.
    pub result_code: LdapResultCode,
    /// Optional matched DN from the result.
    pub matched_dn: Option<String>,
    /// Optional diagnostic message.
    pub diagnostic: Option<String>,
    /// Referral URLs when `result_code` is [`LdapResultCode::Referral`].
    pub referrals: Vec<String>,
}

/// Outcome of a search (RFC 4511 §4.5.2 SearchResultDone + collected refs).
#[derive(Debug, Clone)]
pub struct SearchDone {
    /// Server result code from SearchResultDone.
    pub result_code: LdapResultCode,
    /// LDAP URLs from SearchResultReference messages and/or a referral result.
    pub referrals: Vec<String>,
}

/// Dial configuration for [`super::LdapClient`].
#[derive(Clone)]
pub struct LdapClientConfig {
    host: Option<String>,
    port: u16,
    addr: Option<SocketAddr>,
    unix_path: Option<PathBuf>,
    /// Implicit TLS (LDAPS) at dial time.
    tls_connector: Option<SharedTlsConnector>,
    tls_server_name: Option<String>,
    /// TLS material for mid-session STARTTLS (plaintext dial).
    starttls_connector: Option<SharedTlsConnector>,
    starttls_server_name: Option<String>,
    connect_timeout: Option<Duration>,
}

impl LdapClientConfig {
    /// Connect by hostname (resolved via `ToSocketAddrs` at dial time).
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: Some(host.into()),
            port,
            addr: None,
            unix_path: None,
            tls_connector: None,
            tls_server_name: None,
            starttls_connector: None,
            starttls_server_name: None,
            connect_timeout: Some(Duration::from_secs(30)),
        }
    }

    /// Connect to a pre-resolved address (skips name lookup).
    pub fn from_addr(addr: SocketAddr) -> Self {
        Self {
            host: None,
            port: addr.port(),
            addr: Some(addr),
            unix_path: None,
            tls_connector: None,
            tls_server_name: None,
            starttls_connector: None,
            starttls_server_name: None,
            connect_timeout: Some(Duration::from_secs(30)),
        }
    }

    /// Connect over a UNIX domain socket instead of TCP/IP — skips name
    /// resolution entirely.
    pub fn from_unix_path(path: impl Into<PathBuf>) -> Self {
        Self {
            host: None,
            port: 0,
            addr: None,
            unix_path: Some(path.into()),
            tls_connector: None,
            tls_server_name: None,
            starttls_connector: None,
            starttls_server_name: None,
            connect_timeout: Some(Duration::from_secs(30)),
        }
    }

    /// Enable LDAPS (implicit TLS from the first byte) with SNI name.
    ///
    /// Clears any [`with_starttls`](Self::with_starttls) configuration —
    /// LDAPS and STARTTLS are mutually exclusive on one dial.
    pub fn with_tls(
        mut self,
        connector: SharedTlsConnector,
        server_name: impl Into<String>,
    ) -> Self {
        self.tls_connector = Some(connector);
        self.tls_server_name = Some(server_name.into());
        self.starttls_connector = None;
        self.starttls_server_name = None;
        self
    }

    /// Configure STARTTLS (RFC 4511 §4.14): dial plaintext, then call
    /// [`LdapSession::start_tls`](super::LdapSession::start_tls) before bind.
    ///
    /// Clears LDAPS dial config. The connector/SNI are stored on the session.
    pub fn with_starttls(
        mut self,
        connector: SharedTlsConnector,
        server_name: impl Into<String>,
    ) -> Self {
        self.starttls_connector = Some(connector);
        self.starttls_server_name = Some(server_name.into());
        self.tls_connector = None;
        self.tls_server_name = None;
        self
    }

    /// Override TCP connect timeout (`None` disables).
    pub fn connect_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// UNIX domain socket path, if this config was built with
    /// [`Self::from_unix_path`].
    pub(crate) fn unix_path(&self) -> Option<&Path> {
        self.unix_path.as_deref()
    }

    pub(crate) fn resolve_addr(&self) -> Result<SocketAddr, LdapError> {
        if let Some(addr) = self.addr {
            return Ok(addr);
        }
        let host = self.host.as_deref().ok_or_else(|| {
            LdapError::Config("LdapClientConfig has neither host nor addr".into())
        })?;
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            return Ok(SocketAddr::new(ip, self.port));
        }
        let query = format!("{host}:{}", self.port);
        std::net::ToSocketAddrs::to_socket_addrs(&query)
            .map_err(LdapError::Io)?
            .next()
            .ok_or_else(|| {
                LdapError::Config(format!("no addresses resolved for {host}:{}", self.port))
            })
    }

    pub(crate) fn tls(&self) -> Option<(SharedTlsConnector, String)> {
        match (&self.tls_connector, &self.tls_server_name) {
            (Some(c), Some(n)) => Some((c.clone(), n.clone())),
            (Some(c), None) => {
                let name = self
                    .host
                    .clone()
                    .unwrap_or_else(|| self.addr.map(|a| a.ip().to_string()).unwrap_or_default());
                Some((c.clone(), name))
            }
            _ => None,
        }
    }

    pub(crate) fn starttls(&self) -> Option<(SharedTlsConnector, String)> {
        match (&self.starttls_connector, &self.starttls_server_name) {
            (Some(c), Some(n)) => Some((c.clone(), n.clone())),
            (Some(c), None) => {
                let name = self
                    .host
                    .clone()
                    .unwrap_or_else(|| self.addr.map(|a| a.ip().to_string()).unwrap_or_default());
                Some((c.clone(), name))
            }
            _ => None,
        }
    }

    /// Hostname used for dial / SNI defaults (if any).
    pub fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }

    /// Configured port.
    pub fn port(&self) -> u16 {
        self.port
    }

    pub(crate) fn connect_timeout_opt(&self) -> Option<Duration> {
        self.connect_timeout
    }

    /// Whether this dial uses implicit TLS (LDAPS).
    pub fn is_ldaps(&self) -> bool {
        self.tls_connector.is_some()
    }

    /// Whether STARTTLS material is configured on the session.
    pub fn has_starttls(&self) -> bool {
        self.starttls_connector.is_some()
    }
}
