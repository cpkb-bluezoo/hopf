// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! TLS Encrypted Client Hello (RFC 9849).
//!
//! * [`config`] - `ECHConfig` / `ECHConfigList` encoding, parsing, and HPKE
//!   cipher-suite selection.
//! * [`EchClientConfig`] / [`EchServerConfig`] - what a client or server
//!   handshake is configured with (see
//!   [`HandshakeConfig::ech_client`](crate::tls::HandshakeConfig::ech_client)
//!   and [`HandshakeConfig::ech_server`](crate::tls::HandshakeConfig::ech_server)).
//!
//! # What is implemented
//!
//! Shared-mode ECH (one endpoint is both client-facing and backend) on the
//! TLS 1.3 engine, for TCP and QUIC: the client encrypts a
//! `ClientHelloInner` to the server's `ECHConfig` key, the server decrypts it
//! (also across a `HelloRetryRequest`), and acceptance is confirmed through
//! `ServerHello.random` / the HelloRetryRequest extension. Rejection triggers
//! the RFC 9849 §6.1.6 flow: the handshake completes against the config's
//! `public_name`, then aborts with `ech_required` and hands the server's
//! `retry_configs` to the caller. GREASE ECH is sent when no config is
//! available. Split-mode topologies (a separate backend) are out of scope.
//!
//! # Trust model for configs
//!
//! An `ECHConfig` is only as trustworthy as where it came from. Configs from
//! static configuration are as trusted as the configuration. Configs from DNS
//! (HTTPS/SVCB `ech`) are only as trustworthy as that DNS answer: without
//! DNSSEC or an authenticated transport an on-path attacker can strip or
//! replace them, so pair them with [`EchClientConfig::required`] where ECH
//! is a security requirement. `retry_configs` from a server are different:
//! the engine reports them only after the handshake has authenticated the
//! server for the config's `public_name`, so they are safe to use for one
//! retry - see [`EchClientConfig::from_retry_configs`].
//!
//! A real ECH offer does not offer session resumption or 0-RTT: the PSK
//! machinery would need a GREASE PSK in the outer hello (RFC 9849 §6.1.2).

pub mod config;
mod keys;
pub(crate) mod wire;

use std::sync::Arc;

use crate::crypto::hpke::{Aead, HpkePrivateKey, Kdf};

pub use config::{
    select_config, usable_configs, EchConfig, EchConfigError, EchSelection, HpkeCipherSuite, ECH_VERSION,
    SUPPORTED_HPKE_SUITES,
};

/// Client-side ECH settings.
#[derive(Debug, Clone)]
pub struct EchClientConfig {
    /// The server's `ECHConfig`s, in the server's order of preference
    /// (from DNS, static configuration, or a previous `retry_configs`).
    /// Empty means "no config": the client sends GREASE ECH if
    /// [`Self::grease`] is set.
    pub configs: Vec<EchConfig>,
    /// Send a GREASE `encrypted_client_hello` (RFC 9849 §6.2) when no
    /// usable config is available, so ECH connections do not stand out.
    pub grease: bool,
    /// KDF/AEAD preference, most preferred first. Only pairs a config
    /// advertises are ever used.
    pub preference: Vec<(Kdf, Aead)>,
    /// Require ECH: with no usable config the handshake fails before
    /// anything is sent (no GREASE, no plain hello), with an `ech_required`
    /// error. A rejected offer already ends in `ech_required`
    /// (RFC 9849 §6.1.6) whatever this says; this flag additionally closes
    /// the "no config" gap, e.g. a DNS lookup that returned nothing. The
    /// caller must not fall back to a plain connection after such an error.
    pub required: bool,
    /// These configs came from a previous rejection's `retry_configs`
    /// (see [`Self::from_retry_configs`]). A server that rejects them too is
    /// misconfigured; its new `retry_configs` are not offered again
    /// (RFC 9849 §6.1.6: one retry per connection attempt).
    pub is_retry: bool,
}

impl EchClientConfig {
    /// Use these configs, greasing if none of them is usable.
    pub fn new(configs: Vec<EchConfig>) -> Self {
        Self {
            configs,
            grease: true,
            preference: SUPPORTED_HPKE_SUITES.to_vec(),
            required: false,
            is_retry: false,
        }
    }

    /// Require ECH; see [`Self::required`].
    pub fn require(mut self) -> Self {
        self.required = true;
        self
    }

    /// Build the configuration for the one retry that follows an ECH
    /// rejection, from the `ECHConfigList` in
    /// [`TlsProtocolError::ech_retry_configs`](crate::tls::TlsProtocolError::ech_retry_configs).
    /// Configs this stack cannot use (unsupported KEM or suites, invalid
    /// `public_name`, unsupported mandatory extension) are dropped; if none
    /// is left the server has effectively disabled ECH for us and this
    /// returns an error. Marks the result [`Self::is_retry`]. The retry must
    /// use a new transport connection, and only the addresses the original
    /// ECH configuration allowed (RFC 9849 §6.1.6).
    pub fn from_retry_configs(encoded: &[u8]) -> Result<Self, EchConfigError> {
        let usable = usable_configs(&EchConfig::parse_list(encoded)?, &SUPPORTED_HPKE_SUITES);
        if usable.is_empty() {
            return Err(EchConfigError::InvalidField("no usable retry config"));
        }
        let mut cfg = Self::new(usable);
        cfg.grease = false;
        cfg.is_retry = true;
        Ok(cfg)
    }

    /// Parse an encoded `ECHConfigList`.
    pub fn from_config_list(encoded: &[u8]) -> Result<Self, EchConfigError> {
        Ok(Self::new(EchConfig::parse_list(encoded)?))
    }

    /// No config: send GREASE ECH only.
    pub fn grease_only() -> Self {
        Self::new(Vec::new())
    }
}

/// A server ECH key: an `ECHConfig` and its HPKE private key.
#[derive(Clone)]
pub struct EchServerKey {
    pub(crate) config: EchConfig,
    pub(crate) key: Arc<HpkePrivateKey>,
    pub(crate) advertise: bool,
}

impl std::fmt::Debug for EchServerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EchServerKey")
            .field("config_id", &self.config.config_id)
            .field("advertise", &self.advertise)
            .finish_non_exhaustive()
    }
}

impl EchServerKey {
    /// Pair a config with its private key. The key must belong to the
    /// config's KEM and match its public key.
    pub fn new(config: EchConfig, key: HpkePrivateKey) -> Result<Self, EchConfigError> {
        let kem = config.kem().ok_or(EchConfigError::InvalidField("kem_id"))?;
        if key.kem() != kem || key.public_key()? != config.public_key {
            return Err(EchConfigError::InvalidField("public_key"));
        }
        Ok(Self {
            config,
            key: Arc::new(key),
            advertise: true,
        })
    }

    /// Keep accepting this key for decryption but stop publishing it in
    /// `retry_configs` - the previous key during a rotation overlap.
    pub fn retired(mut self) -> Self {
        self.advertise = false;
        self
    }

    /// The config.
    pub fn config(&self) -> &EchConfig {
        &self.config
    }
}

/// Server-side ECH settings: the set of known keys.
#[derive(Debug, Clone, Default)]
pub struct EchServerConfig {
    keys: Vec<EchServerKey>,
}

impl EchServerConfig {
    /// A server with these keys.
    pub fn new(keys: Vec<EchServerKey>) -> Self {
        Self { keys }
    }

    /// The encoded `ECHConfigList` of the currently advertised configs (for
    /// `retry_configs` and for publishing), in key order; `None` if nothing
    /// is advertised.
    pub fn retry_configs(&self) -> Option<Vec<u8>> {
        let configs: Vec<EchConfig> = self
            .keys
            .iter()
            .filter(|k| k.advertise)
            .map(|k| k.config.clone())
            .collect();
        if configs.is_empty() {
            return None;
        }
        EchConfig::encode_list(&configs).ok()
    }

    /// Keys whose `config_id` matches (RFC 9849 §7.1, method 1).
    pub(crate) fn candidates(&self, config_id: u8) -> impl Iterator<Item = &EchServerKey> {
        self.keys.iter().filter(move |k| k.config.config_id == config_id)
    }
}
