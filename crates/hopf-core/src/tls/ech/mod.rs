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
//! A real ECH offer does not offer session resumption or 0-RTT: the PSK
//! machinery would need a GREASE PSK in the outer hello (RFC 9849 §6.1.2).

pub mod config;
pub(crate) mod wire;

use std::sync::Arc;

use crate::crypto::hpke::{Aead, HpkePrivateKey, Kdf};

pub use config::{
    select_config, EchConfig, EchConfigError, EchSelection, HpkeCipherSuite, ECH_VERSION,
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
}

impl EchClientConfig {
    /// Use these configs, greasing if none of them is usable.
    pub fn new(configs: Vec<EchConfig>) -> Self {
        Self {
            configs,
            grease: true,
            preference: SUPPORTED_HPKE_SUITES.to_vec(),
        }
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
